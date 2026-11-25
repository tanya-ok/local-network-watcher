//! Optional loopback proxy with two profiles and one policy file: "open" passes everything except the deny lists, "strict" passes only the allow list.

use crate::control::{data_dir, iso_now};
use crate::geoip::is_non_public;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Hosted AI services. Always refused, in both profiles, with their subdomains.
pub const AI: &[&str] = &[
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "aistudio.google.com",
    "bard.google.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "mistral.ai",
    "x.ai",
    "grok.com",
    "deepseek.com",
    "cohere.com",
    "cohere.ai",
    "poe.com",
    "you.com",
    "meta.ai",
    "character.ai",
    "replicate.com",
    "together.ai",
    "groq.com",
    "openrouter.ai",
    "fireworks.ai",
    "elevenlabs.io",
    "midjourney.com",
    "stability.ai",
    "duck.ai",
];

/// Common trackers. Always refused, in both profiles.
pub const TRACKER: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "googlesyndication.com",
    "facebook.net",
    "hotjar.com",
    "segment.io",
    "mixpanel.com",
    "amplitude.com",
    "scorecardresearch.com",
];

const HEAD_LIMIT: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const RECENT: usize = 500;
const HOSTS: usize = 2000;

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub allow: bool,
    pub reason: String,
}

fn verdict(allow: bool, reason: impl Into<String>) -> Verdict {
    Verdict {
        allow,
        reason: reason.into(),
    }
}

#[derive(Serialize, Clone)]
struct Entry {
    time: String,
    profile: &'static str,
    method: String,
    host: String,
    port: u16,
    allowed: bool,
    reason: String,
    sent: u64,
    received: u64,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct HostStat {
    host: String,
    profile: &'static str,
    requests: u64,
    refused: u64,
    sent: u64,
    received: u64,
    last_seen: String,
    allowed: bool,
    reason: String,
}

#[derive(Default)]
struct Inner {
    policy: Policy,
    listeners: HashMap<&'static str, JoinHandle<()>>,
    errors: HashMap<&'static str, String>,
    recent: VecDeque<Entry>,
    hosts: HashMap<String, HostStat>,
}

struct Egress {
    inner: Mutex<Inner>,
    /// Bumped on pause and stop; open tunnels watch it and close.
    epoch: watch::Sender<u64>,
}

fn global() -> &'static Egress {
    static G: OnceLock<Egress> = OnceLock::new();
    G.get_or_init(|| Egress {
        inner: Mutex::new(Inner::default()),
        epoch: watch::channel(0).0,
    })
}

fn lock() -> std::sync::MutexGuard<'static, Inner> {
    global().inner.lock().unwrap_or_else(|e| e.into_inner())
}

fn env_port(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|p| p.parse().ok())
        .filter(|p| *p != 0)
        .unwrap_or(default)
}

pub fn profiles() -> [(&'static str, u16); 2] {
    [
        ("open", env_port("LOCAL_WATCH_EGRESS_OPEN_PORT", 4318)),
        ("strict", env_port("LOCAL_WATCH_EGRESS_STRICT_PORT", 4319)),
    ]
}

fn rules_file() -> PathBuf {
    data_dir().join("egress.json")
}

pub fn log_file() -> PathBuf {
    data_dir().join("egress.log")
}

pub fn clean_host(h: &str) -> String {
    let h = h.trim().to_ascii_lowercase();
    let h = h.strip_prefix('[').unwrap_or(&h);
    let h = h.strip_suffix(']').unwrap_or(h);
    h.strip_suffix('.').unwrap_or(h).to_string()
}

/// A domain name with at least one dot, letters, digits, hyphens and no empty labels.
pub fn valid_host(h: &str) -> bool {
    h.len() <= 253
        && h.contains('.')
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn matches<'a, I: IntoIterator<Item = &'a str>>(host: &str, list: I) -> Option<&'a str> {
    list.into_iter().find(|d| {
        host == *d
            || (host.len() > d.len()
                && host.ends_with(d)
                && host.as_bytes()[host.len() - d.len() - 1] == b'.')
    })
}

pub fn decide(policy: &Policy, host: &str, profile: &str) -> Verdict {
    if policy.paused {
        return verdict(false, "all traffic paused");
    }
    if let Some(d) = matches(host, policy.deny.iter().map(String::as_str)) {
        return verdict(false, format!("blocked by you ({d})"));
    }
    if let Some(d) = matches(host, AI.iter().copied()) {
        return verdict(false, format!("hosted AI service ({d})"));
    }
    if let Some(d) = matches(host, TRACKER.iter().copied()) {
        return verdict(false, format!("tracker ({d})"));
    }
    let allowed = matches(host, policy.allow.iter().map(String::as_str));
    match (profile, allowed) {
        (_, Some(d)) => verdict(true, format!("allowed by you ({d})")),
        ("strict", None) => verdict(false, "not on the allow list"),
        _ => verdict(true, "open profile"),
    }
}

/// Everything the proxy must never dial: the geoip non-public set plus documentation, benchmark and tunnelled forms.
pub fn blocked_address(ip: IpAddr) -> bool {
    if is_non_public(&ip.to_string()) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let embedded = |hi: u16, lo: u16| {
                blocked_address(IpAddr::V4(Ipv4Addr::from(((hi as u32) << 16) | lo as u32)))
            };
            if s[..6] == [0, 0, 0, 0, 0, 0] {
                return true; // IPv4-compatible, deprecated
            }
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
                return embedded(s[6], s[7]); // NAT64
            }
            if s[0] == 0x2002 {
                return embedded(s[1], s[2]); // 6to4
            }
            (s[0] == 0x2001 && (s[1] == 0x0db8 || s[1] == 0)) || (s[0] & 0xffc0) == 0xfec0
        }
    }
}

fn load() -> Policy {
    let Ok(text) = std::fs::read_to_string(rules_file()) else {
        return Policy::default();
    };
    let mut p: Policy = serde_json::from_str(&text).unwrap_or_default();
    let tidy = |v: Vec<String>| {
        let mut v: Vec<String> = v
            .iter()
            .map(|h| clean_host(h))
            .filter(|h| valid_host(h))
            .collect();
        v.sort();
        v.dedup();
        v
    };
    p.allow = tidy(p.allow);
    p.deny = tidy(p.deny);
    p
}

fn private_dir() -> std::io::Result<PathBuf> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn save(policy: &Policy) -> Result<(), String> {
    let write = || -> std::io::Result<()> {
        private_dir()?;
        let file = rules_file();
        let tmp = file.with_extension("json.tmp");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(
            serde_json::to_string_pretty(policy)
                .unwrap_or_default()
                .as_bytes(),
        )?;
        f.sync_all()?;
        std::fs::rename(&tmp, &file)
    };
    write().map_err(|e| format!("The egress policy could not be saved: {e}"))
}

fn append_log(entry: &Entry) {
    let _ = (|| -> std::io::Result<()> {
        private_dir()?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(log_file())?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        writeln!(f, "{}", serde_json::to_string(entry).unwrap_or_default())
    })();
}

fn record(entry: Entry) {
    {
        let mut g = lock();
        g.recent.push_back(entry.clone());
        while g.recent.len() > RECENT {
            g.recent.pop_front();
        }
        let key = format!("{} {}", entry.profile, entry.host);
        if !g.hosts.contains_key(&key)
            && g.hosts.len() >= HOSTS
            && let Some(oldest) = g
                .hosts
                .iter()
                .min_by(|a, b| a.1.last_seen.cmp(&b.1.last_seen))
                .map(|(k, _)| k.clone())
        {
            g.hosts.remove(&oldest);
        }
        let h = g.hosts.entry(key).or_insert_with(|| HostStat {
            host: entry.host.clone(),
            profile: entry.profile,
            requests: 0,
            refused: 0,
            sent: 0,
            received: 0,
            last_seen: String::new(),
            allowed: false,
            reason: String::new(),
        });
        h.requests += 1;
        if !entry.allowed {
            h.refused += 1;
        }
        h.sent += entry.sent;
        h.received += entry.received;
        h.last_seen = entry.time.clone();
        h.allowed = entry.allowed;
        h.reason = entry.reason.clone();
    }
    append_log(&entry);
}

/// The parsed proxy request head.
#[derive(Debug, PartialEq)]
pub struct Head {
    pub method: String,
    pub host: String,
    pub port: u16,
    /// origin-form path for plain HTTP, empty for CONNECT
    pub path: String,
    pub authority: String,
    pub headers: Vec<(String, String)>,
}

fn split_host_port(authority: &str, default: Option<u16>) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        match tail {
            "" => (h, None),
            t => (h, Some(t.strip_prefix(':')?)),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            p.parse::<u16>().ok()?
        }
        Some(_) => return None,
        None => default?,
    };
    let host = clean_host(host);
    if port == 0 || !(valid_host(&host) || host.parse::<IpAddr>().is_ok()) {
        return None;
    }
    Some((host, port))
}

/// Parses "CONNECT host:port" or "METHOD http://host[:port]/path"; anything else is refused as invalid.
pub fn parse_head(raw: &str) -> Option<Head> {
    let mut lines = raw.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || !version.starts_with("HTTP/1.")
        || method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
    {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || name.bytes().any(|b| b <= b' ' || b >= 0x7f) {
            return None;
        }
        headers.push((name.to_string(), value.trim().to_string()));
    }
    if method == "CONNECT" {
        let (host, port) = split_host_port(target, None)?;
        return Some(Head {
            method: method.into(),
            host,
            port,
            path: String::new(),
            authority: target.into(),
            headers,
        });
    }
    let rest = target
        .get(..7)
        .filter(|s| s.eq_ignore_ascii_case("http://"))
        .map(|_| &target[7..])?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    if authority.contains('@') {
        return None;
    }
    let path = match path.split_once('#').map_or(path, |(p, _)| p) {
        "" => "/".to_string(),
        p if p.starts_with('?') => format!("/{p}"),
        p => p.to_string(),
    };
    let (host, port) = split_host_port(authority, Some(80))?;
    Some(Head {
        method: method.into(),
        host,
        port,
        path,
        authority: authority.into(),
        headers,
    })
}

async fn read_head(client: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8(buf[..i].to_vec()).ok()?;
            return Some((head, buf[i + 4..].to_vec()));
        }
        if buf.len() > HEAD_LIMIT {
            return None;
        }
        let n = client.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn refuse(client: &mut TcpStream, code: u16, reason: &str) {
    let body = format!("Local Network Watcher: {reason}\n");
    let text = format!(
        "HTTP/1.1 {code} Refused\r\nconnection: close\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = client.write_all(text.as_bytes()).await;
    let _ = client.shutdown().await;
}

/// Resolves here so the client never needs its own DNS; only public addresses are returned.
async fn target(host: &str, port: u16) -> Result<Option<SocketAddr>, ()> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok((!blocked_address(ip)).then_some(SocketAddr::new(ip, port)));
    }
    let found = tokio::time::timeout(DIAL_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    Ok(found.into_iter().find(|a| !blocked_address(a.ip())))
}

async fn copy_one(
    r: &mut tokio::net::tcp::OwnedReadHalf,
    w: &mut tokio::net::tcp::OwnedWriteHalf,
    n: &std::sync::atomic::AtomicU64,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(k) => {
                if w.write_all(&buf[..k]).await.is_err() {
                    break;
                }
                n.fetch_add(k as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    let _ = w.shutdown().await;
}

/// Copies both ways until either side closes or the epoch changes; returns (sent, received).
async fn pipe(
    client: TcpStream,
    upstream: TcpStream,
    mut epoch: watch::Receiver<u64>,
    already_sent: u64,
) -> (u64, u64) {
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    let sent = std::sync::atomic::AtomicU64::new(already_sent);
    let received = std::sync::atomic::AtomicU64::new(0);
    let up = copy_one(&mut cr, &mut uw, &sent);
    let down = copy_one(&mut ur, &mut cw, &received);
    tokio::select! {
        _ = async { tokio::join!(up, down) } => {}
        _ = epoch.changed() => {}
    }
    (sent.into_inner(), received.into_inner())
}

fn entry(profile: &'static str, head: Option<&Head>, method: &str, v: &Verdict) -> Entry {
    Entry {
        time: iso_now(),
        profile,
        method: method.to_string(),
        host: head.map_or("invalid".into(), |h| h.host.clone()),
        port: head.map_or(0, |h| h.port),
        allowed: v.allow,
        reason: v.reason.clone(),
        sent: 0,
        received: 0,
    }
}

const HOP: &[&str] = &[
    "proxy-connection",
    "proxy-authorization",
    "connection",
    "keep-alive",
    "host",
    "te",
    "trailer",
    "upgrade",
];

async fn handle(profile: &'static str, mut client: TcpStream) {
    let epoch = global().epoch.subscribe();
    let Ok(Some((raw, leftover))) =
        tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client)).await
    else {
        return;
    };
    let method = raw
        .split(' ')
        .next()
        .unwrap_or("")
        .chars()
        .take(16)
        .collect::<String>();
    let Some(head) = parse_head(&raw) else {
        let v = verdict(
            false,
            if method == "CONNECT" {
                "invalid request"
            } else {
                "only proxy requests are accepted here"
            },
        );
        refuse(&mut client, 400, &v.reason).await;
        record(entry(profile, None, &method, &v));
        return;
    };
    let v = decide(&lock().policy, &head.host, profile);
    if !v.allow {
        refuse(&mut client, 403, &v.reason).await;
        record(entry(profile, Some(&head), &head.method, &v));
        return;
    }
    let address = match target(&head.host, head.port).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            let v = verdict(false, "local or unresolved address");
            refuse(&mut client, 403, &v.reason).await;
            record(entry(profile, Some(&head), &head.method, &v));
            return;
        }
        Err(()) => {
            let v = verdict(false, "name could not be resolved");
            refuse(&mut client, 502, &v.reason).await;
            record(entry(profile, Some(&head), &head.method, &v));
            return;
        }
    };
    let mut upstream = match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(s)) => s,
        _ => {
            let v = verdict(false, "destination did not answer");
            refuse(&mut client, 502, &v.reason).await;
            record(entry(profile, Some(&head), &head.method, &v));
            return;
        }
    };
    let mut first = Vec::new();
    if head.method == "CONNECT" {
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
    } else {
        first.extend_from_slice(
            format!(
                "{} {} HTTP/1.1\r\nhost: {}\r\n",
                head.method, head.path, head.authority
            )
            .as_bytes(),
        );
        for (name, value) in head
            .headers
            .iter()
            .filter(|(n, _)| !HOP.contains(&n.to_ascii_lowercase().as_str()))
        {
            first.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        first.extend_from_slice(b"connection: close\r\n\r\n");
    }
    first.extend_from_slice(&leftover);
    if !first.is_empty() && upstream.write_all(&first).await.is_err() {
        return;
    }
    let mut e = entry(profile, Some(&head), &head.method, &v);
    (e.sent, e.received) = pipe(client, upstream, epoch, first.len() as u64).await;
    record(e);
}

async fn accept_loop(profile: &'static str, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                tokio::spawn(handle(profile, socket));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

/// Starts any listener that is not running; a bind failure is kept as a per-profile error, not a crash.
async fn start() {
    for (profile, port) in profiles() {
        if lock().listeners.contains_key(profile) {
            continue;
        }
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => {
                let mut g = lock();
                g.errors.remove(profile);
                g.listeners
                    .insert(profile, tokio::spawn(accept_loop(profile, l)));
            }
            Err(e) => {
                let message = if e.kind() == std::io::ErrorKind::AddrInUse {
                    format!("port {port} is already in use")
                } else {
                    format!("port {port}: {e}")
                };
                eprintln!("Egress {profile} proxy did not start: {message}");
                lock().errors.insert(profile, message);
            }
        }
    }
}

fn stop() {
    let mut g = lock();
    for (_, task) in g.listeners.drain() {
        task.abort();
    }
    g.errors.clear();
    drop(g);
    global().epoch.send_modify(|n| *n += 1);
}

pub async fn init() {
    let mut policy = load();
    if std::env::var("LOCAL_WATCH_EGRESS").as_deref() == Ok("1") {
        policy.enabled = true;
    }
    let enabled = policy.enabled;
    lock().policy = policy;
    if enabled {
        start().await;
    }
}

pub async fn set_enabled(enabled: bool) -> Result<(), String> {
    if enabled {
        start().await;
    } else {
        stop();
    }
    let mut g = lock();
    g.policy.enabled = enabled;
    save(&g.policy)
}

pub fn set_paused(paused: bool) -> Result<(), String> {
    let result = {
        let mut g = lock();
        g.policy.paused = paused;
        save(&g.policy)
    };
    if paused {
        global().epoch.send_modify(|n| *n += 1);
    }
    result
}

pub fn change_rule(action: &str, raw: &str) -> Result<(), String> {
    let host = clean_host(raw);
    if !valid_host(&host) {
        return Err("Enter a domain such as example.com.".into());
    }
    let mut g = lock();
    g.policy.allow.retain(|h| *h != host);
    g.policy.deny.retain(|h| *h != host);
    match action {
        "allow" => g.policy.allow.push(host),
        "deny" => g.policy.deny.push(host),
        _ => {}
    }
    g.policy.allow.sort();
    g.policy.deny.sort();
    save(&g.policy)
}

pub fn status() -> Value {
    let g = lock();
    let ports = profiles();
    let mut hosts: Vec<&HostStat> = g.hosts.values().collect();
    hosts.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    let recent: Vec<&Entry> = g.recent.iter().rev().take(100).collect();
    json!({
        "enabled": g.policy.enabled,
        "running": ports.iter().all(|(p, _)| g.listeners.contains_key(p)),
        "paused": g.policy.paused,
        "ports": { "open": ports[0].1, "strict": ports[1].1 },
        "allow": g.policy.allow,
        "deny": g.policy.deny,
        "builtin": { "ai": AI.len(), "tracker": TRACKER.len() },
        "hosts": hosts,
        "recent": recent,
        "log": log_file().to_string_lossy(),
        "errors": g.errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(allow: &[&str], deny: &[&str], paused: bool) -> Policy {
        Policy {
            enabled: true,
            paused,
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn open_and_strict() {
        let p = policy(&["example.org"], &[], false);
        assert_eq!(
            decide(&p, "example.com", "open"),
            verdict(true, "open profile")
        );
        assert_eq!(
            decide(&p, "example.com", "strict"),
            verdict(false, "not on the allow list")
        );
        assert_eq!(
            decide(&p, "www.example.org", "strict"),
            verdict(true, "allowed by you (example.org)")
        );
        assert_eq!(
            decide(&p, "example.org", "open"),
            verdict(true, "allowed by you (example.org)")
        );
        assert!(
            !decide(&p, "badexample.org", "strict").allow,
            "suffix must be on a label boundary"
        );
    }

    #[test]
    fn deny_lists_win() {
        let p = policy(&["openai.com", "blocked.net"], &["blocked.net"], false);
        assert_eq!(
            decide(&p, "a.blocked.net", "open"),
            verdict(false, "blocked by you (blocked.net)")
        );
        assert_eq!(
            decide(&p, "api.openai.com", "strict"),
            verdict(false, "hosted AI service (openai.com)")
        );
        assert_eq!(
            decide(&p, "claude.ai", "open"),
            verdict(false, "hosted AI service (claude.ai)")
        );
        assert_eq!(
            decide(&p, "www.google-analytics.com", "open"),
            verdict(false, "tracker (google-analytics.com)")
        );
        assert!(decide(&p, "notopenai.com", "open").allow);
    }

    #[test]
    fn paused_refuses_all() {
        let p = policy(&["example.com"], &[], true);
        for profile in ["open", "strict"] {
            assert_eq!(
                decide(&p, "example.com", profile),
                verdict(false, "all traffic paused")
            );
        }
    }

    #[test]
    fn non_public_targets() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "192.0.2.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a00:1",
            "2002:c0a8:101::1",
            "2001:db8::1",
            "2001::1",
        ] {
            assert!(blocked_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "93.184.216.34",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "64:ff9b::5db8:d822",
            "::ffff:8.8.8.8",
        ] {
            assert!(!blocked_address(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn hosts_and_heads() {
        assert!(valid_host("example.com"));
        for bad in ["localhost", "a..b", "-a.com", "a_b.com", "exa mple.com", ""] {
            assert!(!valid_host(bad), "{bad}");
        }
        let h = parse_head("CONNECT Example.COM.:443 HTTP/1.1\r\nHost: x").unwrap();
        assert_eq!((h.host.as_str(), h.port), ("example.com", 443));
        let h = parse_head("GET http://example.com:8080/a?b HTTP/1.1\r\nHost: x").unwrap();
        assert_eq!(
            (h.host.as_str(), h.port, h.path.as_str()),
            ("example.com", 8080, "/a?b")
        );
        assert_eq!(
            parse_head("GET http://example.com HTTP/1.1").unwrap().path,
            "/"
        );
        assert_eq!(
            parse_head("CONNECT [::1]:443 HTTP/1.1").unwrap().host,
            "::1"
        );
        for bad in [
            "GET /x HTTP/1.1",
            "GET https://a.com/ HTTP/1.1",
            "CONNECT a.com HTTP/1.1",
            "CONNECT a.com:0 HTTP/1.1",
            "GET http://u@a.com/ HTTP/1.1",
            "CONNECT bad_host:443 HTTP/1.1",
        ] {
            assert!(parse_head(bad).is_none(), "{bad}");
        }
    }
}

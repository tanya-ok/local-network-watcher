//! Local baseline of what is normal on this Mac, and the attention markers it produces.
//! Metadata only: app names, destination groups, ports, times. Never packet contents.

use crate::collector::Snapshot;
use crate::known::{known_owner, severity_for};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

const COMMON_PORTS: &[&str] = &[
    "443", "80", "53", "853", "993", "995", "587", "465", "5223", "123", "3478", "3479", "22",
    "8443", "5228",
];
const MB: f64 = 1024.0 * 1024.0;
const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 24 * HOUR_MS;

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct App {
    pub first_seen: u64,
    pub last_seen: u64,
    #[serde(default)]
    pub night_samples: u32,
    #[serde(default)]
    pub dests: HashMap<String, u64>,
    #[serde(default)]
    pub ports: HashMap<String, u64>,
    #[serde(default)]
    pub rate: f64,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Marker {
    pub key: String,
    pub kind: String,
    pub app: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    pub text: String,
    pub at: u64,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub tier: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct State {
    created_at: u64,
    #[serde(default)]
    apps: HashMap<String, App>,
    #[serde(default)]
    accepted: HashMap<String, u64>,
    #[serde(default)]
    markers: Vec<Marker>,
}

pub struct History {
    dir: PathBuf,
    file: PathBuf,
    learning_ms: u64,
    state: State,
    dirty: bool,
    prev_totals: HashMap<u32, u64>,
}

fn fresh(now: u64) -> State {
    State {
        created_at: now,
        apps: HashMap::new(),
        accepted: HashMap::new(),
        markers: Vec::new(),
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Local hour of a millisecond timestamp, through the C library so time zones match macOS.
fn local_hour(ms: u64) -> i32 {
    let secs = (ms / 1000) as libc::time_t;
    // SAFETY: localtime_r writes only into the struct we pass and is thread safe.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&secs, &mut tm).is_null() {
            return 12;
        }
        tm.tm_hour
    }
}

fn host_of(endpoint: &str) -> &str {
    let host = endpoint.rfind(':').map_or(endpoint, |i| &endpoint[..i]);
    host.trim_start_matches('[').trim_end_matches(']')
}

fn port_of(endpoint: &str) -> &str {
    endpoint.rfind(':').map_or("", |i| &endpoint[i + 1..])
}

pub fn is_private(ip: &str) -> bool {
    let lower = ip.to_ascii_lowercase();
    if lower.starts_with("10.")
        || lower.starts_with("192.168.")
        || lower.starts_with("169.254.")
        || lower.starts_with("fe80:")
        || lower.starts_with("fc")
        || lower.starts_with("fd")
    {
        return true;
    }
    if let Some(rest) = lower.strip_prefix("172.")
        && let Some(second) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok())
    {
        return (16..=31).contains(&second);
    }
    false
}

/// Group a destination by its owner's domain when reverse DNS knows it, otherwise by network block.
pub fn dest_key(ip: &str, name: &str) -> String {
    if let Some(owner) = known_owner(ip) {
        return format!("org:{owner}");
    }
    if !name.is_empty() {
        let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
        let tail = |n: usize| labels[labels.len().saturating_sub(n)..].join(".");
        let two = tail(2);
        let second_level = ["co", "com", "net", "org", "gov", "ac"];
        let parts: Vec<&str> = two.split('.').collect();
        if parts.len() == 2 && second_level.contains(&parts[0]) && parts[1].len() == 2 {
            return tail(3);
        }
        return two;
    }
    if ip.contains(':') {
        return format!(
            "{}::/48",
            ip.split(':').take(3).collect::<Vec<_>>().join(":")
        );
    }
    format!(
        "{}.0/24",
        ip.split('.').take(3).collect::<Vec<_>>().join(".")
    )
}

fn dest_label(key: &str) -> String {
    key.strip_prefix("org:")
        .map_or_else(|| key.to_string(), |o| format!("owned by {o}"))
}

/// An older history grouped owner ranges by /24 or /48; treat those blocks as already known.
fn known_before_owner_grouping(dests: &HashMap<String, u64>, owner: &str) -> bool {
    dests.keys().any(|k| {
        let probe = if let Some(net) = k.strip_suffix(".0/24") {
            format!("{net}.1")
        } else if let Some(net) = k.strip_suffix("::/48") {
            format!("{net}::1")
        } else {
            return false;
        };
        known_owner(&probe) == Some(owner)
    })
}

impl History {
    pub fn load() -> History {
        let dir = std::env::var_os("LOCAL_WATCH_DATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_default();
                home.join("Library")
                    .join("Application Support")
                    .join("LocalWatch")
            });
        let learning_hours: u64 = std::env::var("LOCAL_WATCH_LEARNING_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(24);
        let file = dir.join("history.json");
        let state = fs::read(&file)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<State>(&bytes).ok())
            .unwrap_or_else(|| fresh(now_ms()));
        History {
            dir,
            file,
            learning_ms: learning_hours * HOUR_MS,
            state,
            dirty: false,
            prev_totals: HashMap::new(),
        }
    }

    pub fn file(&self) -> String {
        self.file.display().to_string()
    }

    pub fn learning_until(&self) -> u64 {
        self.state.created_at + self.learning_ms
    }

    /// First time this monitor saw an app name in local history.
    pub fn app_first_seen(&self, name: &str) -> Option<u64> {
        self.state.apps.get(name).map(|a| a.first_seen)
    }

    pub fn app_count(&self) -> usize {
        self.state.apps.len()
    }

    /// Atomic write: folder 0700, file 0600.
    pub fn save(&mut self) -> std::io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)?;
        let tmp = self.file.with_extension("json.tmp");
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        out.write_all(&serde_json::to_vec(&self.state).unwrap_or_default())?;
        out.sync_all()?;
        fs::rename(&tmp, &self.file)?;
        self.dirty = false;
        Ok(())
    }

    pub fn forget(&mut self) -> std::io::Result<()> {
        self.state = fresh(now_ms());
        self.dirty = true;
        let _ = fs::remove_file(&self.file);
        self.save()
    }

    pub fn accept(&mut self, key: &str) -> bool {
        if key.is_empty() || key.chars().count() > 300 {
            return false;
        }
        self.state.accepted.insert(key.to_string(), now_ms());
        self.dirty = true;
        true
    }

    pub fn current_markers(&self) -> Vec<Marker> {
        let now = now_ms();
        self.state
            .markers
            .iter()
            .filter(|m| {
                !self.state.accepted.contains_key(&m.key) && now.saturating_sub(m.at) < 7 * DAY_MS
            })
            .cloned()
            .collect()
    }

    fn add_marker(&mut self, mut marker: Marker, tier: &str) {
        if self.state.accepted.contains_key(&marker.key) {
            return;
        }
        let owner = marker.ip.as_deref().and_then(known_owner);
        let (severity, reason) = severity_for(&marker.kind, tier, &marker.app, owner);
        marker.severity = severity.to_string();
        marker.reason = reason;
        marker.tier = tier.to_string();
        if self
            .state
            .markers
            .iter()
            .any(|m| m.key == marker.key && marker.at.saturating_sub(m.at) < DAY_MS)
        {
            return;
        }
        self.state.markers.insert(0, marker);
        self.state.markers.truncate(300);
        self.dirty = true;
    }

    /// Markers saved before severity existed get it once a process with that name is seen again.
    fn backfill_severity(&mut self, by_name: &HashMap<String, &'static str>) {
        for m in self
            .state
            .markers
            .iter_mut()
            .filter(|m| m.severity.is_empty())
        {
            let Some(tier) = by_name.get(&m.app) else {
                continue;
            };
            let owner = m.ip.as_deref().and_then(known_owner);
            let (severity, reason) = severity_for(&m.kind, tier, &m.app, owner);
            m.severity = severity.to_string();
            m.reason = reason;
            m.tier = tier.to_string();
            self.dirty = true;
        }
    }

    /// One sample from the collector, reverse names for its addresses, and trust tiers by PID.
    pub fn observe(
        &mut self,
        snapshot: &Snapshot,
        names: &HashMap<String, String>,
        tiers: &HashMap<u32, &'static str>,
        now: u64,
    ) {
        let learning = now < self.learning_until();
        let hour = local_hour(now);
        let night = hour < 6;
        let mut seen_night: HashSet<String> = HashSet::new();
        for row in &snapshot.connections {
            let ip = host_of(&row.remote).to_string();
            if ip.is_empty() || is_private(&ip) {
                continue;
            }
            let app_name = if row.process.is_empty() {
                "unknown".to_string()
            } else {
                row.process.clone()
            };
            let port = port_of(&row.remote).to_string();
            let name = names.get(&ip).cloned().unwrap_or_default();
            let key = dest_key(&ip, &name);
            let tier = tiers.get(&row.pid).copied().unwrap_or("unknown");
            let mut new_markers = Vec::new();
            let app = match self.state.apps.get_mut(&app_name) {
                Some(app) => app,
                None => {
                    self.dirty = true;
                    if !learning {
                        new_markers.push(Marker {
                            key: format!("app:{app_name}"),
                            kind: "new-app".into(),
                            app: app_name.clone(),
                            ip: Some(ip.clone()),
                            dest: Some(key.clone()),
                            text: format!("{app_name} went online for the first time since this monitor started watching."),
                            at: now,
                            ..Marker::default()
                        });
                    }
                    self.state.apps.entry(app_name.clone()).or_insert(App {
                        first_seen: now,
                        last_seen: now,
                        ..App::default()
                    })
                }
            };
            app.last_seen = now;
            if !app.dests.contains_key(&key) {
                let migrated = key
                    .strip_prefix("org:")
                    .is_some_and(|o| known_before_owner_grouping(&app.dests, o));
                app.dests.insert(key.clone(), now);
                self.dirty = true;
                if !migrated && !learning && now.saturating_sub(app.first_seen) > HOUR_MS {
                    let shown = if name.is_empty() {
                        ip.clone()
                    } else {
                        name.clone()
                    };
                    new_markers.push(Marker {
                        key: format!("dest:{app_name}:{key}"),
                        kind: "new-destination".into(),
                        app: app_name.clone(),
                        ip: Some(ip.clone()),
                        dest: Some(key.clone()),
                        text: format!(
                            "{app_name} connected to {shown} ({}), a destination it has not used before.",
                            dest_label(&key)
                        ),
                        at: now,
                        ..Marker::default()
                    });
                }
            }
            if !port.is_empty() && !app.ports.contains_key(&port) {
                app.ports.insert(port.clone(), now);
                self.dirty = true;
                if !learning && !COMMON_PORTS.contains(&port.as_str()) {
                    new_markers.push(Marker {
                        key: format!("port:{app_name}:{port}"),
                        kind: "unusual-port".into(),
                        app: app_name.clone(),
                        ip: Some(ip.clone()),
                        dest: Some(key.clone()),
                        text: format!("{app_name} used port {port}, which is not a usual web, mail or system port."),
                        at: now,
                        ..Marker::default()
                    });
                }
            }
            if night && seen_night.insert(app_name.clone()) {
                if !learning && app.night_samples < 3 {
                    new_markers.push(Marker {
                        key: format!("night:{app_name}"),
                        kind: "night".into(),
                        app: app_name.clone(),
                        ip: Some(ip.clone()),
                        dest: Some(key.clone()),
                        text: format!(
                            "{app_name} was online at {hour:02}:00, and it rarely is at night."
                        ),
                        at: now,
                        ..Marker::default()
                    });
                }
                app.night_samples += 1;
                self.dirty = true;
            }
            for marker in new_markers {
                self.add_marker(marker, tier);
            }
        }
        // When several processes share a name, the least trusted one decides.
        let rank = |t: &str| match t {
            "apple-system" => 0,
            "signed" => 1,
            "unknown" => 2,
            _ => 3,
        };
        let mut by_name: HashMap<String, &'static str> = HashMap::new();
        let rows = snapshot
            .connections
            .iter()
            .map(|r| (r.pid, &r.process))
            .chain(snapshot.processes.iter().map(|p| (p.pid, &p.process)));
        for (pid, name) in rows {
            if let Some(&tier) = tiers.get(&pid) {
                let slot = by_name.entry(name.clone()).or_insert(tier);
                if rank(tier) > rank(slot) {
                    *slot = tier;
                }
            }
        }
        self.backfill_severity(&by_name);
        for proc_row in &snapshot.processes {
            let total = proc_row.received_bytes + proc_row.sent_bytes;
            let prev = self.prev_totals.insert(proc_row.pid, total);
            let Some(app) = self.state.apps.get_mut(&proc_row.process) else {
                continue;
            };
            let Some(prev) = prev else { continue };
            if total < prev {
                continue;
            }
            let delta = (total - prev) as f64;
            let burst = !learning && app.rate > 0.0 && delta > (50.0 * MB).max(app.rate * 20.0);
            app.rate = if app.rate > 0.0 {
                app.rate * 0.95 + delta * 0.05
            } else {
                delta
            };
            if burst {
                let name = proc_row.process.clone();
                self.add_marker(
                    Marker {
                        key: format!("volume:{name}:{}", now / HOUR_MS),
                        kind: "volume".into(),
                        app: name.clone(),
                        ip: None,
                        dest: None,
                        text: format!(
                            "{name} moved {:.0} MB in a few seconds, far more than usual for it.",
                            delta / MB
                        ),
                        at: now,
                        ..Marker::default()
                    },
                    tiers.get(&proc_row.pid).copied().unwrap_or("unknown"),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_destinations() {
        assert_eq!(dest_key("1.2.3.4", "edge.example.com."), "example.com");
        assert_eq!(dest_key("1.2.3.4", "a.b.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(dest_key("5.6.7.8", ""), "5.6.7.0/24");
        assert_eq!(dest_key("2001:db8:1:2::1", ""), "2001:db8:1::/48");
        assert_eq!(dest_key("17.157.64.66", "x.apple.com"), "org:Apple");
        assert_eq!(dest_label("org:Apple"), "owned by Apple");
    }

    #[test]
    fn backfills_old_markers_by_name() {
        let mut h = History {
            dir: PathBuf::new(),
            file: PathBuf::new(),
            learning_ms: 0,
            state: fresh(0),
            dirty: false,
            prev_totals: HashMap::new(),
        };
        let old = |app: &str, ip: &str| Marker {
            key: format!("dest:{app}"),
            kind: "new-destination".into(),
            app: app.into(),
            ip: Some(ip.into()),
            ..Marker::default()
        };
        h.state.markers = vec![old("akd", "17.157.64.66"), old("gone", "1.1.1.1")];
        let mut by_name = HashMap::new();
        by_name.insert("akd".to_string(), "apple-system");
        h.backfill_severity(&by_name);
        assert_eq!(h.state.markers[0].severity, "info");
        assert_eq!(h.state.markers[0].tier, "apple-system");
        assert!(h.state.markers[1].severity.is_empty());
        assert!(h.dirty);
    }

    #[test]
    fn old_blocks_count_as_known_owner() {
        let mut dests = HashMap::new();
        dests.insert("17.8.130.0/24".to_string(), 1);
        assert!(known_before_owner_grouping(&dests, "Apple"));
        assert!(!known_before_owner_grouping(&dests, "Google"));
    }

    #[test]
    fn private_ranges() {
        assert!(is_private("192.168.1.4"));
        assert!(is_private("172.20.0.1"));
        assert!(!is_private("172.32.0.1"));
        assert!(is_private("fe80::1"));
        assert!(!is_private("8.8.8.8"));
    }
}

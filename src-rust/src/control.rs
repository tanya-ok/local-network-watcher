//! Process and launchd control, trust facts and persistence listing.
//! Every tool runs with a fixed argument list and a timeout; no shell is involved.

use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use tokio::process::Command;

pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

pub async fn exec(program: &str, args: &[&str], timeout: Duration) -> Out {
    let child = Command::new(program).args(args).kill_on_drop(true).output();
    match tokio::time::timeout(timeout, child).await {
        Err(_) => Out {
            code: -1,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: true,
        },
        Ok(Err(e)) => Out {
            code: -1,
            stdout: String::new(),
            stderr: e.to_string(),
            timed_out: false,
        },
        Ok(Ok(o)) => Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            timed_out: false,
        },
    }
}

const SHORT: Duration = Duration::from_secs(5);

pub(crate) fn data_dir() -> PathBuf {
    std::env::var_os("LOCAL_WATCH_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            home()
                .join("Library")
                .join("Application Support")
                .join("LocalWatch")
        })
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

fn domain() -> String {
    format!("gui/{}", uid())
}

/// Append-only JSON lines; one entry per attempted action, including refusals.
pub fn log_action(mut entry: Value) {
    let dir = data_dir();
    let file = dir.join("actions.log");
    if let Value::Object(map) = &mut entry {
        map.insert("at".into(), Value::String(iso_now()));
    }
    let _ = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&file)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        writeln!(f, "{entry}")
    })();
}

pub(crate) fn iso_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[derive(Clone, Serialize)]
pub struct Row {
    pub pid: u32,
    pub ppid: u32,
    pub user: String,
    pub stat: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
}

pub async fn process_table() -> Vec<Row> {
    let out = exec(
        "/bin/ps",
        &["-axww", "-o", "pid=,ppid=,user=,stat=,command="],
        SHORT,
    )
    .await;
    out.stdout
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let pid = it.next()?.parse().ok()?;
            let ppid = it.next()?.parse().ok()?;
            let user = it.next()?.to_string();
            let stat = it.next()?.to_string();
            let command: String = it.collect::<Vec<_>>().join(" ").chars().take(300).collect();
            Some(Row {
                pid,
                ppid,
                user,
                stat,
                command,
                depth: None,
            })
        })
        .collect()
}

fn current_user() -> String {
    crate::facts::current_user()
}

/// PID 1, this server and its ancestors.
fn protected_pids(rows: &[Row]) -> HashSet<u32> {
    let me = std::process::id();
    let mut set = HashSet::from([1, me]);
    let mut ancestor = rows.iter().find(|r| r.pid == me).map_or(0, |r| r.ppid);
    for _ in 0..16 {
        if ancestor <= 1 {
            break;
        }
        set.insert(ancestor);
        ancestor = rows
            .iter()
            .find(|r| r.pid == ancestor)
            .map_or(0, |r| r.ppid);
    }
    set
}

pub async fn guard(pid: u32, verb: &str) -> Result<(Row, Vec<Row>), String> {
    if pid < 2 {
        return Err("A valid process ID is required.".into());
    }
    let rows = process_table().await;
    let Some(row) = rows.iter().find(|r| r.pid == pid).cloned() else {
        return Err("That process is no longer running.".into());
    };
    if protected_pids(&rows).contains(&pid) {
        return Err(format!(
            "The monitor or one of its parent processes cannot be {verb} here."
        ));
    }
    if row.user != current_user() {
        return Err(format!(
            "Only processes owned by your current macOS account can be {verb}."
        ));
    }
    Ok((row, rows))
}

/// Descendants, deepest first, so children are signalled before their parents.
pub fn descendants(rows: &[Row], pid: u32) -> Vec<Row> {
    fn walk(rows: &[Row], p: u32, depth: u32, out: &mut Vec<Row>) {
        if depth > 64 {
            return;
        }
        for r in rows.iter().filter(|x| x.ppid == p && x.pid != p) {
            walk(rows, r.pid, depth + 1, out);
            out.push(Row {
                depth: Some(depth),
                ..r.clone()
            });
        }
    }
    let mut out = Vec::new();
    walk(rows, pid, 1, &mut out);
    out.sort_by_key(|r| std::cmp::Reverse(r.depth));
    out
}

pub async fn tree_preview(pid: u32) -> Result<Value, String> {
    let (row, rows) = guard(pid, "stopped").await?;
    let children = descendants(&rows, pid);
    let user = current_user();
    let blocked = protected_pids(&rows);
    let refused: Vec<&Row> = children
        .iter()
        .filter(|c| c.user != user || blocked.contains(&c.pid))
        .collect();
    Ok(json!({ "root": row, "children": children, "refused": refused }))
}

pub fn is_paused(stat: &str) -> bool {
    stat.starts_with('T')
}

pub async fn launchd_label(pid: u32) -> Value {
    let domain = domain();
    let out = exec("/bin/launchctl", &["print", &domain], SHORT).await;
    if out.code != 0 {
        return json!({ "managed": false, "reason": "launchctl print failed for your user domain." });
    }
    let mut inside = false;
    let mut label = None;
    for line in out.stdout.lines() {
        if line == "\tservices = {" {
            inside = true;
            continue;
        }
        if inside {
            if line == "\t}" {
                break;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0].parse::<u32>().ok() == Some(pid) {
                label = Some(parts[2].to_string());
                break;
            }
        }
    }
    let Some(label) = label else {
        return json!({ "managed": false, "reason": "This process is not a launchd service in your user domain, so it cannot be restarted safely." });
    };
    // LaunchServices app instances are not relaunchable through kickstart.
    if label.starts_with("application.") {
        return json!({ "managed": false, "label": label, "reason": "This is a GUI app instance registered by LaunchServices, not a launchd job with a relaunch definition." });
    }
    json!({ "managed": true, "target": format!("{domain}/{label}"), "label": label, "domain": domain })
}

fn signal(pid: u32, sig: libc::c_int) -> bool {
    // SAFETY: plain kill(2) with a guarded pid and a fixed signal.
    unsafe { libc::kill(pid as libc::pid_t, sig) == 0 }
}

/// stop / pause / resume / restart, with tree stop. Err is a refusal message.
pub async fn control(action: &str, req: &serde_json::Map<String, Value>) -> Result<Value, String> {
    let pid = req
        .get("pid")
        .and_then(Value::as_u64)
        .filter(|p| *p >= 2 && *p <= i32::MAX as u64)
        .map(|p| p as u32);
    let Some(pid) = pid.filter(|_| req.get("confirm") == Some(&Value::Bool(true))) else {
        return Err("Explicit confirmation and a valid process ID are required.".into());
    };
    let verb = match action {
        "stop" => "stopped",
        "pause" => "paused",
        "resume" => "resumed",
        _ => "restarted",
    };
    let (row, _) = guard(pid, verb).await?;
    let name = row
        .command
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_string();
    if action == "stop" && req.get("tree") == Some(&Value::Bool(true)) {
        let preview = tree_preview(pid).await?;
        let refused = preview["refused"].as_array().map_or(0, Vec::len);
        if refused > 0 {
            return Err(format!(
                "The tree contains {refused} process(es) that cannot be stopped here (another account or the monitor itself)."
            ));
        }
        let kids: Vec<u32> = preview["children"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| c["pid"].as_u64().map(|p| p as u32))
                    .collect()
            })
            .unwrap_or_default();
        let mut now = kids.clone();
        now.sort_unstable();
        let seen: Option<Vec<u32>> = req.get("children").and_then(Value::as_array).map(|a| {
            let mut v: Vec<u32> = a
                .iter()
                .filter_map(|p| p.as_u64().map(|p| p as u32))
                .collect();
            v.sort_unstable();
            v
        });
        if seen.as_ref() != Some(&now) {
            return Err(
                "The process tree changed since the preview. Preview it again before stopping."
                    .into(),
            );
        }
        let mut signalled: Vec<u32> = kids
            .into_iter()
            .filter(|c| signal(*c, libc::SIGTERM))
            .collect();
        if !signal(pid, libc::SIGTERM) {
            return Err("The signal could not be sent.".into());
        }
        signalled.push(pid);
        log_action(
            json!({ "action": "stop-tree", "signal": "SIGTERM", "pid": pid, "process": name, "pids": signalled, "result": "signal-sent" }),
        );
        return Ok(
            json!({ "status": "signal-sent", "signal": "SIGTERM", "pid": pid, "process": name, "pids": signalled }),
        );
    }
    if action == "restart" {
        let lookup = launchd_label(pid).await;
        if lookup["managed"] != Value::Bool(true) {
            return Err(format!(
                "Restart unavailable: {}",
                lookup["reason"].as_str().unwrap_or("")
            ));
        }
        let target = lookup["target"].as_str().unwrap_or_default().to_string();
        let label = lookup["label"].clone();
        let out = exec(
            "/bin/launchctl",
            &["kickstart", "-k", &target],
            Duration::from_secs(10),
        )
        .await;
        if out.code != 0 {
            return Err(format!("launchctl kickstart failed: {}", out.stderr.trim()));
        }
        log_action(
            json!({ "action": "restart", "pid": pid, "process": name, "label": label, "target": target, "result": "kickstarted" }),
        );
        return Ok(json!({ "status": "kickstarted", "pid": pid, "process": name, "label": label }));
    }
    let (sig, sig_name) = match action {
        "stop" => (libc::SIGTERM, "SIGTERM"),
        "pause" => (libc::SIGSTOP, "SIGSTOP"),
        _ => (libc::SIGCONT, "SIGCONT"),
    };
    if !signal(pid, sig) {
        return Err("The signal could not be sent.".into());
    }
    log_action(
        json!({ "action": action, "signal": sig_name, "pid": pid, "process": name, "result": "signal-sent" }),
    );
    Ok(json!({ "status": "signal-sent", "signal": sig_name, "pid": pid, "process": name }))
}

// ---- Trust card ----

static TRUST: Mutex<Option<HashMap<String, Value>>> = Mutex::new(None);

/// Executable path of a running process, from the kernel's view (not argv).
pub async fn exe_path(pid: u32) -> Option<String> {
    let out = exec(
        "/bin/ps",
        &["-ww", "-o", "comm=", "-p", &pid.to_string()],
        SHORT,
    )
    .await;
    let p = out.stdout.trim().to_string();
    if p.is_empty() {
        return None;
    }
    if !p.starts_with('/') {
        return Some(p);
    }
    Some(std::fs::canonicalize(&p).map_or(p, |r| r.to_string_lossy().into_owned()))
}

fn location_notes(path: &str, signature: &str) -> Vec<&'static str> {
    let mut notes = Vec::new();
    let home = home().to_string_lossy().into_owned();
    if path.starts_with("/tmp/") || path.starts_with("/private/tmp/") {
        notes.push("Runs from /tmp, a temporary folder. Installed apps rarely live there.");
    }
    if path.starts_with("/var/folders/") || path.starts_with("/private/var/folders/") {
        notes.push("Runs from /private/var/folders, a per-user temporary area. Some installers and updaters use it.");
    }
    if !home.is_empty() && path.starts_with(&format!("{home}/Downloads/")) {
        notes.push("Runs from ~/Downloads. It may not have been moved to Applications yet.");
    }
    if signature == "not signed" {
        notes.push("No code signature was found. Self-built tools and scripts are often unsigned.");
    }
    if signature.starts_with("ad hoc") {
        notes.push("Ad hoc signature only, with no developer identity. Common for Homebrew and self-built tools.");
    }
    notes
}

fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|l| l.strip_prefix(key))
}

pub async fn trust_facts(path: &str) -> Value {
    if let Some(hit) = TRUST
        .lock()
        .ok()
        .and_then(|c| c.as_ref().and_then(|m| m.get(path).cloned()))
    {
        return hit;
    }
    let timeout = Duration::from_secs(8);
    let sig = exec("/usr/bin/codesign", &["-dv", "--verbose=2", path], timeout).await;
    let text = format!("{}{}", sig.stdout, sig.stderr);
    let authority: Vec<String> = text
        .lines()
        .filter_map(|l| l.strip_prefix("Authority="))
        .map(str::to_string)
        .collect();
    let team = field(&text, "TeamIdentifier=").unwrap_or("");
    let identifier = field(&text, "Identifier=").unwrap_or("");
    let signature = if text.to_ascii_lowercase().contains("not signed at all") {
        "not signed"
    } else if text.contains("Signature=adhoc") {
        "ad hoc (no developer identity)"
    } else if !authority.is_empty() {
        "signed"
    } else if sig.timed_out {
        "check timed out"
    } else {
        "unknown"
    };

    let gk = exec(
        "/usr/sbin/spctl",
        &["--assess", "--type", "execute", "-vv", path],
        timeout,
    )
    .await;
    let gk_text = format!("{}{}", gk.stdout, gk.stderr);
    let source = field(&gk_text, "source=").unwrap_or("").to_string();
    let gatekeeper = if gk.timed_out {
        "check timed out".to_string()
    } else if gk.code == 0 {
        "accepted".to_string()
    } else if gk_text.contains("rejected") {
        match gk_text
            .split_once("rejected (")
            .and_then(|(_, r)| r.split_once(')'))
        {
            Some((why, _)) => format!("not accepted ({why})"),
            None => "not accepted".to_string(),
        }
    } else {
        "not assessed".to_string()
    };
    let first = authority.first().map(String::as_str).unwrap_or("");
    let notarized = if source.to_ascii_lowercase().contains("notarized") {
        "yes"
    } else if source == "Apple System"
        || first == "Software Signing"
        || first == "macOS Software Signing"
    {
        "not applicable (part of macOS)"
    } else {
        "not shown"
    };
    let facts = json!({
        "path": path, "identifier": identifier, "signature": signature, "authority": authority,
        "teamId": if team == "not set" { "" } else { team },
        "gatekeeper": gatekeeper, "gatekeeperSource": source, "notarized": notarized,
        "notes": location_notes(path, signature),
        "checkedAt": crate::history::now_ms(),
    });
    if let Ok(mut c) = TRUST.lock() {
        c.get_or_insert_with(HashMap::new)
            .insert(path.to_string(), facts.clone());
    }
    facts
}

// ---- Persistence ----

struct ScanDir {
    dir: PathBuf,
    scope: &'static str,
    apple: bool,
}

fn override_dirs() -> Option<Vec<PathBuf>> {
    let v = std::env::var("LOCAL_WATCH_PERSISTENCE_DIRS").ok()?;
    Some(
        v.split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect(),
    )
}

fn scan_dirs() -> Vec<ScanDir> {
    if let Some(dirs) = override_dirs() {
        return dirs
            .into_iter()
            .map(|dir| ScanDir {
                dir,
                scope: "custom",
                apple: false,
            })
            .collect();
    }
    vec![
        ScanDir {
            dir: home().join("Library/LaunchAgents"),
            scope: "user agent",
            apple: false,
        },
        ScanDir {
            dir: "/Library/LaunchAgents".into(),
            scope: "global agent",
            apple: false,
        },
        ScanDir {
            dir: "/Library/LaunchDaemons".into(),
            scope: "global daemon",
            apple: false,
        },
        ScanDir {
            dir: "/System/Library/LaunchAgents".into(),
            scope: "system agent",
            apple: true,
        },
        ScanDir {
            dir: "/System/Library/LaunchDaemons".into(),
            scope: "system daemon",
            apple: true,
        },
    ]
}

async fn parse_plist(file: &Path) -> Option<Value> {
    let f = file.to_string_lossy();
    let out = exec(
        "/usr/bin/plutil",
        &["-convert", "json", "-o", "-", &f],
        Duration::from_secs(3),
    )
    .await;
    if out.code != 0 {
        return None;
    }
    serde_json::from_str(&out.stdout).ok()
}

async fn running_labels() -> HashMap<String, u32> {
    let out = exec("/bin/launchctl", &["list"], Duration::from_secs(3)).await;
    out.stdout
        .lines()
        .skip(1)
        .filter_map(|l| {
            let mut it = l.split('\t');
            let pid = it.next()?.parse().ok()?;
            it.next()?;
            Some((it.next()?.to_string(), pid))
        })
        .collect()
}

async fn executable_paths(pids: &[u32]) -> HashMap<u32, String> {
    if pids.is_empty() {
        return HashMap::new();
    }
    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let out = exec(
        "/bin/ps",
        &["-o", "pid=,comm=", "-p", &list],
        Duration::from_secs(3),
    )
    .await;
    out.stdout
        .lines()
        .filter_map(|l| {
            let (pid, path) = l.trim().split_once(char::is_whitespace)?;
            Some((pid.parse().ok()?, path.trim().to_string()))
        })
        .collect()
}

pub async fn user_disabled_labels() -> HashSet<String> {
    let out = exec(
        "/bin/launchctl",
        &["print-disabled", &domain()],
        Duration::from_secs(3),
    )
    .await;
    out.stdout
        .lines()
        .filter_map(|l| {
            let (name, state) = l.trim().split_once("=>")?;
            let state = state.trim();
            (state == "true" || state == "disabled")
                .then(|| name.trim().trim_matches('"').to_string())
        })
        .collect()
}

pub async fn persistence_items(connections: &[crate::collector::Connection]) -> Value {
    let mut pid_process: HashMap<u32, String> = HashMap::new();
    for c in connections {
        if c.pid > 0 {
            pid_process.insert(c.pid, c.process.clone());
        }
    }
    let pids: Vec<u32> = pid_process.keys().copied().collect();
    let (labels, paths, off) = tokio::join!(
        running_labels(),
        executable_paths(&pids),
        user_disabled_labels()
    );
    let path_to_pid: HashMap<&str, u32> = paths.iter().map(|(p, s)| (s.as_str(), *p)).collect();
    let mut items = Vec::new();
    let mut errors = Vec::new();
    for ScanDir { dir, scope, apple } in scan_dirs() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<String> = read
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.ends_with(".plist"))
            .collect();
        names.sort();
        // System folders hold hundreds of entries; only keep those tied to a networked process.
        for name in names {
            let file = dir.join(&name);
            let file_s = file.to_string_lossy().into_owned();
            let Some(plist) = parse_plist(&file).await else {
                errors.push(file_s);
                continue;
            };
            let args: Vec<String> = plist["ProgramArguments"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let program = plist["Program"]
                .as_str()
                .map(str::to_string)
                .or_else(|| args.first().cloned())
                .unwrap_or_default();
            let label = plist["Label"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| name.trim_end_matches(".plist").to_string());
            let launch_pid = labels.get(&label).copied();
            let mut network = Value::Null;
            if let Some(p) = launch_pid.filter(|p| pid_process.contains_key(p)) {
                network =
                    json!({ "pid": p, "process": pid_process[&p], "matchedBy": "launchctl pid" });
            } else if let Some(p) = path_to_pid
                .get(program.as_str())
                .filter(|_| !program.is_empty())
            {
                network = json!({ "pid": p, "process": pid_process.get(p).cloned().unwrap_or_default(), "matchedBy": "executable path" });
            }
            if apple && network.is_null() {
                continue;
            }
            items.push(json!({
                "file": file_s, "scope": scope, "apple": apple, "label": label, "program": program, "arguments": args,
                "runAtLoad": plist["RunAtLoad"] == Value::Bool(true),
                "keepAlive": if plist["KeepAlive"].is_null() { Value::Bool(false) } else { plist["KeepAlive"].clone() },
                "disabled": plist["Disabled"] == Value::Bool(true),
                "userDisabled": off.contains(&label),
                "controllable": scope == "user agent" || scope == "custom",
                "running": launch_pid.is_some(), "pid": launch_pid,
                "network": network,
            }));
        }
    }
    items.sort_by(|a, b| {
        a["network"]
            .is_null()
            .cmp(&b["network"].is_null())
            .then_with(|| {
                a["label"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["label"].as_str().unwrap_or(""))
            })
    });
    json!({ "sampledAt": iso_now(), "items": items, "unreadable": errors })
}

// ---- launchd job control ----

/// Only the user's own LaunchAgents are changed; system and global jobs need an administrator.
fn allowed_dirs() -> Vec<PathBuf> {
    override_dirs().unwrap_or_else(|| vec![home().join("Library/LaunchAgents")])
}

async fn inspect_job(file: &str) -> Result<(String, String), String> {
    let outside = || "Only plists in your own LaunchAgents folder can be changed here.".to_string();
    let real = std::fs::canonicalize(file).map_err(|_| outside())?;
    let inside = allowed_dirs()
        .iter()
        .filter_map(|d| std::fs::canonicalize(d).ok())
        .any(|d| real.parent() == Some(d.as_path()) || real.starts_with(&d));
    if real.extension().and_then(|e| e.to_str()) != Some("plist") || !inside {
        return Err(outside());
    }
    let meta = std::fs::metadata(&real).map_err(|e| e.to_string())?;
    if meta.uid() != uid() {
        return Err("This plist belongs to another account.".into());
    }
    let plist = parse_plist(&real)
        .await
        .ok_or("The plist could not be read.")?;
    let label = plist["Label"].as_str().unwrap_or("").to_string();
    if label.is_empty() {
        return Err("The plist has no Label.".into());
    }
    if label.starts_with("com.apple.") {
        return Err("Apple jobs are not changed here.".into());
    }
    let program = plist["Program"]
        .as_str()
        .or_else(|| plist["ProgramArguments"][0].as_str())
        .unwrap_or("");
    if let Ok(me) = std::env::current_exe().and_then(std::fs::canonicalize) {
        let prog = std::fs::canonicalize(program).unwrap_or_else(|_| PathBuf::from(program));
        if prog == me || me.parent().is_some_and(|d| prog.starts_with(d)) {
            return Err("This job runs Local Network Watcher itself.".into());
        }
    }
    Ok((real.to_string_lossy().into_owned(), label))
}

async fn launchctl(args: &[&str]) -> String {
    let out = exec("/bin/launchctl", args, Duration::from_secs(8)).await;
    if out.code == 0 {
        String::new()
    } else if out.timed_out {
        "launchctl timed out.".into()
    } else {
        format!("{}{}", out.stderr, out.stdout).trim().to_string()
    }
}

/// stop: unload until next login. disable: unload and keep it off. enable: allow and load again.
pub async fn change_job(action: &str, file: &str) -> Result<Value, String> {
    let (file, label) = match inspect_job(file).await {
        Ok(j) => j,
        Err(e) => {
            log_action(
                json!({ "action": format!("launchd-{action}"), "file": file, "result": "refused", "reason": e }),
            );
            return Err(e);
        }
    };
    let domain = domain();
    let target = format!("{domain}/{label}");
    let mut notes = Vec::new();
    let ignorable =
        |e: &str, words: &[&str]| words.iter().any(|w| e.to_ascii_lowercase().contains(w));
    match action {
        "stop" | "disable" => {
            let e = launchctl(&["bootout", &domain, &file]).await;
            if !e.is_empty()
                && !ignorable(
                    &e,
                    &[
                        "no such process",
                        "could not find",
                        "not find service",
                        "boot-out failed: 5",
                    ],
                )
            {
                notes.push(e);
            }
            if action == "disable" {
                let e = launchctl(&["disable", &target]).await;
                if !e.is_empty() {
                    notes.push(e);
                }
            }
        }
        "enable" => {
            let e = launchctl(&["enable", &target]).await;
            if !e.is_empty() {
                notes.push(e);
            }
            let e = launchctl(&["bootstrap", &domain, &file]).await;
            if !e.is_empty()
                && !ignorable(
                    &e,
                    &["already", "bootstrap failed: 5", "service already loaded"],
                )
            {
                notes.push(e);
            }
        }
        _ => return Err("Unknown action.".into()),
    }
    let result = if notes.is_empty() { "ok" } else { "partial" };
    log_action(
        json!({ "action": format!("launchd-{action}"), "label": label, "file": file, "result": result, "notes": notes }),
    );
    Ok(json!({ "action": action, "label": label, "result": result, "notes": notes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pid: u32, ppid: u32) -> Row {
        Row {
            pid,
            ppid,
            user: "u".into(),
            stat: "S".into(),
            command: String::new(),
            depth: None,
        }
    }

    #[test]
    fn descendants_deepest_first() {
        let rows = vec![row(10, 1), row(11, 10), row(12, 11), row(13, 10)];
        let d: Vec<u32> = descendants(&rows, 10).iter().map(|r| r.pid).collect();
        assert_eq!(d[0], 12);
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn paused_state() {
        assert!(is_paused("T"));
        assert!(!is_paused("S+"));
    }

    #[test]
    fn iso_format() {
        assert_eq!(iso_now().len(), 20);
    }
}

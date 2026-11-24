//! Read-only facts from macOS tools: names, owners, routes, process details.
//! Every tool runs with a fixed argument list; user input is validated before it reaches one.

use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;
use tokio::process::Command;

/// Runs a tool with a timeout and returns stdout, plus stderr when `both` is set.
pub async fn run(program: &str, args: &[&str], timeout: Duration, both: bool) -> Option<String> {
    let child = Command::new(program).args(args).kill_on_drop(true).output();
    let output = tokio::time::timeout(timeout, child).await.ok()?.ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if both || !output.status.success() {
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    Some(text)
}

pub fn valid_ip(ip: &str) -> bool {
    (3..=45).contains(&ip.len())
        && ip
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
}

#[derive(Default)]
pub struct Caches {
    names: Mutex<HashMap<String, String>>,
    owners: Mutex<HashMap<String, Owner>>,
}

impl Caches {
    pub fn names_snapshot(&self) -> HashMap<String, String> {
        self.names.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// Reverse DNS with a 1.5 s limit; failures are cached as an empty name.
    pub async fn reverse_name(&self, ip: &str) -> String {
        if let Some(name) = self.names.lock().ok().and_then(|m| m.get(ip).cloned()) {
            return name;
        }
        let name = match ip.parse::<IpAddr>() {
            Ok(addr) => {
                let lookup =
                    tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&addr).ok());
                match tokio::time::timeout(Duration::from_millis(1500), lookup).await {
                    // getnameinfo returns the address itself when there is no PTR record.
                    Ok(Ok(Some(found))) if found != ip => found,
                    _ => String::new(),
                }
            }
            Err(_) => String::new(),
        };
        if let Ok(mut m) = self.names.lock() {
            if m.len() > 5000 {
                m.clear();
            }
            m.insert(ip.to_string(), name.clone());
        }
        name
    }

    pub async fn owner(&self, ip: &str) -> Owner {
        if let Some(owner) = self.owners.lock().ok().and_then(|m| m.get(ip).cloned()) {
            return owner;
        }
        let text = run("/usr/bin/whois", &[ip], Duration::from_secs(8), false)
            .await
            .unwrap_or_default();
        let owner = Owner {
            org: pick(
                &text,
                &["OrgName", "org-name", "Organization", "owner", "descr"],
            ),
            country: pick(&text, &["Country", "country"])
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string(),
            network: pick(&text, &["NetName", "netname"]),
            reverse_dns: String::new(),
        };
        if let Ok(mut m) = self.owners.lock() {
            if m.len() > 2000 {
                m.clear();
            }
            m.insert(ip.to_string(), owner.clone());
        }
        owner
    }
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Owner {
    pub org: String,
    pub country: String,
    pub network: String,
    pub reverse_dns: String,
}

/// First value of any of the keys, case-insensitive, from `Key: value` lines.
fn pick(text: &str, keys: &[&str]) -> String {
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':')
            && keys.iter().any(|k| k.eq_ignore_ascii_case(key.trim()))
            && !value.trim().is_empty()
        {
            return value.trim().to_string();
        }
    }
    String::new()
}

#[derive(Serialize)]
pub struct Route {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub flags: String,
}

pub async fn route(ip: &str) -> Option<Route> {
    let text = run(
        "/sbin/route",
        &["-n", "get", ip],
        Duration::from_millis(2500),
        false,
    )
    .await?;
    let field = |name: &str| {
        text.lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix(&format!("{name}:"))
                    .map(|v| v.trim().to_string())
            })
            .unwrap_or_default()
    };
    let route = Route {
        destination: field("destination"),
        gateway: field("gateway"),
        interface: field("interface"),
        flags: field("flags"),
    };
    (!route.destination.is_empty() || !route.interface.is_empty()).then_some(route)
}

#[derive(Serialize)]
pub struct Parent {
    pub pid: u32,
    pub command: String,
}

#[derive(Serialize)]
pub struct ProcessFacts {
    pub pid: u32,
    pub ppid: u32,
    pub user: String,
    pub started: String,
    pub command: String,
    pub parents: Vec<Parent>,
    pub cwd: String,
    pub sockets: Vec<String>,
    pub signature: String,
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// Read-only facts about one process: command line, parents, folder, sockets, code signature.
pub async fn process_facts(pid: u32) -> Option<ProcessFacts> {
    let pid_s = pid.to_string();
    let quick = Duration::from_secs(5);
    let ps = run(
        "/bin/ps",
        &[
            "-ww",
            "-o",
            "pid=,ppid=,user=,lstart=,command=",
            "-p",
            &pid_s,
        ],
        quick,
        false,
    )
    .await?;
    let ps = ps.trim();
    if ps.is_empty() {
        return None;
    }
    // pid ppid user, then lstart as five words (Wed Nov 18 09:04:06 2026), then the command.
    let words: Vec<&str> = ps.split_whitespace().collect();
    if words.len() < 9 {
        return None;
    }
    let ppid = words[1].parse().unwrap_or(0);
    let user = words[2].to_string();
    let started = words[3..8].join(" ");
    let mut rest = ps;
    for _ in 0..8 {
        rest = rest.trim_start();
        rest = rest.find(char::is_whitespace).map_or("", |i| &rest[i..]);
    }
    let command = truncate(rest.trim(), 600);

    let mut parents = Vec::new();
    let mut parent = ppid;
    for _ in 0..6 {
        if parent == 0 {
            break;
        }
        let line = run(
            "/bin/ps",
            &["-ww", "-o", "ppid=,command=", "-p", &parent.to_string()],
            quick,
            false,
        )
        .await
        .unwrap_or_default();
        let line = line.trim();
        let Some((pp, cmd)) = line.split_once(char::is_whitespace) else {
            break;
        };
        parents.push(Parent {
            pid: parent,
            command: truncate(cmd.trim(), 200),
        });
        parent = pp.trim().parse().unwrap_or(0);
    }

    let cwd = run(
        "/usr/sbin/lsof",
        &["-a", "-p", &pid_s, "-d", "cwd", "-Fn"],
        quick,
        false,
    )
    .await
    .unwrap_or_default()
    .lines()
    .find_map(|l| l.strip_prefix('n').map(str::to_string))
    .unwrap_or_default();
    let sockets = run(
        "/usr/sbin/lsof",
        &["-nP", "-a", "-p", &pid_s, "-i"],
        quick,
        false,
    )
    .await
    .unwrap_or_default()
    .lines()
    .skip(1)
    .filter(|l| !l.trim().is_empty())
    .map(|l| l.split_whitespace().skip(7).collect::<Vec<_>>().join(" "))
    .take(30)
    .collect();

    let exe = command.split(' ').next().unwrap_or_default().to_string();
    let signature = if exe.starts_with('/') {
        let sig = run(
            "/usr/bin/codesign",
            &["-dv", "--verbose=2", &exe],
            quick,
            true,
        )
        .await
        .unwrap_or_default();
        let authority: Vec<&str> = sig
            .lines()
            .filter_map(|l| l.strip_prefix("Authority="))
            .collect();
        if !authority.is_empty() {
            authority.join(" \u{2192} ")
        } else if sig.to_ascii_lowercase().contains("not signed") {
            "not signed".into()
        } else if sig.contains("Signature=adhoc") {
            "ad hoc only (no developer identity; common for Homebrew and self-built tools)".into()
        } else {
            "unknown".into()
        }
    } else {
        String::new()
    };

    Some(ProcessFacts {
        pid,
        ppid,
        user,
        started,
        command,
        parents,
        cwd,
        sockets,
        signature,
    })
}

/// Parent of a process, or 0.
pub async fn parent_of(pid: u32) -> u32 {
    run(
        "/bin/ps",
        &["-o", "ppid=", "-p", &pid.to_string()],
        Duration::from_secs(2),
        false,
    )
    .await
    .and_then(|s| s.trim().parse().ok())
    .unwrap_or(0)
}

pub fn current_user() -> String {
    std::env::var("USER").unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_whois_fields() {
        let text =
            "NetName:        AMAZO-4\nOrganization:   Amazon.com, Inc. (AMAZO-4)\nCountry: US\n";
        assert_eq!(
            pick(text, &["OrgName", "Organization"]),
            "Amazon.com, Inc. (AMAZO-4)"
        );
        assert_eq!(pick(text, &["Country"]), "US");
        assert_eq!(pick(text, &["NetName"]), "AMAZO-4");
    }

    #[test]
    fn validates_ips() {
        assert!(valid_ip("99.86.159.45"));
        assert!(valid_ip("fe80::1"));
        assert!(!valid_ip("1.2.3.4; rm"));
        assert!(!valid_ip("-n"));
    }
}

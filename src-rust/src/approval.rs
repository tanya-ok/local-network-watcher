//! Egress changes from non-admin accounts wait here until an admin approves or denies them, or they expire.

use serde::Serialize;
use serde_json::{Value, json};
use std::path::Path;

pub const DEFAULT_TTL_SECS: u64 = 15 * 60;
const MAX_PENDING: usize = 50;
const MAX_PER_UID: usize = 10;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum Change {
    Enable { enabled: bool },
    Pause { paused: bool },
    Rule { rule: String, host: String },
    Ports { ports: String },
}

impl Change {
    /// Builds a change from the API action and body; the values are checked again when applied.
    pub fn parse(action: &str, input: &serde_json::Map<String, Value>) -> Result<Change, String> {
        match (
            action,
            input.get("enabled"),
            input.get("paused"),
            input.get("action"),
        ) {
            ("enable", Some(Value::Bool(on)), _, _) => Ok(Change::Enable { enabled: *on }),
            ("pause", _, Some(Value::Bool(p)), _) => Ok(Change::Pause { paused: *p }),
            ("rule", _, _, Some(Value::String(a)))
                if ["allow", "deny", "remove"].contains(&a.as_str()) =>
            {
                Ok(Change::Rule {
                    rule: a.clone(),
                    host: input
                        .get("host")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .chars()
                        .take(260)
                        .collect(),
                })
            }
            ("ports", _, _, _) => Ok(Change::Ports {
                ports: input
                    .get("ports")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .chars()
                    .take(200)
                    .collect(),
            }),
            _ => Err("Unknown egress change.".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    pub id: String,
    pub uid: u32,
    pub user: String,
    pub change: Change,
    pub created: u64,
    pub expires: u64,
}

#[derive(Debug, PartialEq)]
pub enum Submit {
    Apply,
    Queued(String),
}

#[derive(Default)]
pub struct Approvals {
    pending: Vec<Pending>,
}

impl Approvals {
    /// An admin change applies at once; any other becomes a pending entry with an id.
    pub fn submit(
        &mut self,
        now: u64,
        ttl: u64,
        who: (u32, String),
        admin: bool,
        change: Change,
        id: String,
    ) -> Result<Submit, String> {
        if admin {
            return Ok(Submit::Apply);
        }
        let (uid, user) = who;
        if self.pending.len() >= MAX_PENDING
            || self.pending.iter().filter(|p| p.uid == uid).count() >= MAX_PER_UID
        {
            return Err("Too many changes are waiting for approval.".into());
        }
        self.pending.push(Pending {
            id: id.clone(),
            uid,
            user,
            change,
            created: now,
            expires: now + ttl,
        });
        Ok(Submit::Queued(id))
    }

    /// Removes and returns the entry; only an admin may approve or deny.
    pub fn resolve(&mut self, now: u64, admin: bool, id: &str) -> Result<Pending, String> {
        if !admin {
            return Err("Only an admin account can approve or deny a change.".into());
        }
        let i = self
            .pending
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| {
                format!(
                    "No pending change {id}: it expired, was already handled, or never existed."
                )
            })?;
        if self.pending[i].expires <= now {
            self.pending.remove(i);
            return Err(format!("Pending change {id} has expired."));
        }
        Ok(self.pending.remove(i))
    }

    pub fn expire(&mut self, now: u64) -> Vec<Pending> {
        let (gone, keep) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|p| p.expires <= now);
        self.pending = keep;
        gone
    }

    pub fn list(&self) -> &[Pending] {
        &self.pending
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Admins {
    Uids(Vec<u32>),
    Group(String),
}

impl Admins {
    pub fn contains(&self, uid: u32) -> bool {
        match self {
            Admins::Uids(list) => list.contains(&uid),
            Admins::Group(g) => crate::peer::in_group(uid, g),
        }
    }

    pub fn describe(&self) -> Value {
        match self {
            Admins::Uids(list) => json!({ "uids": list }),
            Admins::Group(g) => json!({ "group": g }),
        }
    }
}

/// "501,0" is a uid list, "group:staff" a group; anything unparsable falls back to the admin group.
pub fn parse_admins(spec: &str) -> Admins {
    if let Some(g) = spec.trim().strip_prefix("group:") {
        return Admins::Group(g.trim().to_string());
    }
    let uids: Result<Vec<u32>, _> = spec
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::parse::<u32>)
        .collect();
    match uids {
        Ok(v) if !v.is_empty() => Admins::Uids(v),
        _ => Admins::Group("admin".into()),
    }
}

/// LOCAL_WATCH_EGRESS_ADMINS, then "admins" in daemon.json in the egress dir, then the admin group.
pub fn load_admins(dir: &Path) -> Admins {
    if let Ok(spec) = std::env::var("LOCAL_WATCH_EGRESS_ADMINS") {
        return parse_admins(&spec);
    }
    let file = std::fs::read_to_string(dir.join("daemon.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok());
    match file.as_ref().and_then(|v| v.get("admins")) {
        Some(Value::String(s)) => parse_admins(s),
        Some(Value::Array(a)) => {
            let uids: Vec<u32> = a
                .iter()
                .filter_map(Value::as_u64)
                .filter_map(|u| u32::try_from(u).ok())
                .collect();
            if uids.is_empty() {
                Admins::Group("admin".into())
            } else {
                Admins::Uids(uids)
            }
        }
        _ => Admins::Group("admin".into()),
    }
}

pub fn ttl() -> u64 {
    std::env::var("LOCAL_WATCH_EGRESS_PENDING_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_TTL_SECS)
}

pub fn new_id() -> String {
    let mut b = [0u8; 6];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut b);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(h: &str) -> Change {
        Change::Rule {
            rule: "allow".into(),
            host: h.into(),
        }
    }

    #[test]
    fn admin_applies_other_waits() {
        let mut a = Approvals::default();
        assert_eq!(
            a.submit(
                0,
                60,
                (501, "tanya".into()),
                true,
                rule("a.com"),
                "x".into()
            ),
            Ok(Submit::Apply)
        );
        assert!(a.list().is_empty());
        assert_eq!(
            a.submit(
                0,
                60,
                (504, "alice".into()),
                false,
                rule("a.com"),
                "p1".into()
            ),
            Ok(Submit::Queued("p1".into()))
        );
        assert_eq!(a.list().len(), 1);
    }

    #[test]
    fn only_admin_resolves() {
        let mut a = Approvals::default();
        a.submit(
            0,
            60,
            (504, "alice".into()),
            false,
            rule("a.com"),
            "p1".into(),
        )
        .unwrap();
        assert!(a.resolve(1, false, "p1").is_err());
        assert_eq!(a.list().len(), 1, "a refused approval keeps the entry");
        assert!(a.resolve(1, true, "nope").is_err());
        let p = a.resolve(1, true, "p1").unwrap();
        assert_eq!(p.change, rule("a.com"));
        assert!(a.resolve(1, true, "p1").is_err(), "approval is single use");
    }

    #[test]
    fn expiry() {
        let mut a = Approvals::default();
        a.submit(
            0,
            60,
            (504, "alice".into()),
            false,
            rule("a.com"),
            "p1".into(),
        )
        .unwrap();
        a.submit(
            30,
            60,
            (504, "alice".into()),
            false,
            rule("b.com"),
            "p2".into(),
        )
        .unwrap();
        assert!(
            a.resolve(60, true, "p1").is_err(),
            "expired at its deadline"
        );
        assert!(a.list().iter().all(|p| p.id != "p1"));
        let gone = a.expire(90);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].id, "p2");
        assert!(a.list().is_empty());
    }

    #[test]
    fn flood_limit() {
        let mut a = Approvals::default();
        for i in 0..MAX_PER_UID {
            a.submit(
                0,
                60,
                (504, "alice".into()),
                false,
                rule("a.com"),
                i.to_string(),
            )
            .unwrap();
        }
        assert!(
            a.submit(
                0,
                60,
                (504, "alice".into()),
                false,
                rule("a.com"),
                "x".into()
            )
            .is_err()
        );
        assert!(
            a.submit(0, 60, (505, "bob".into()), false, rule("a.com"), "y".into())
                .is_ok()
        );
    }

    #[test]
    fn admin_lists() {
        assert_eq!(parse_admins("501, 0"), Admins::Uids(vec![501, 0]));
        assert_eq!(parse_admins("group:staff"), Admins::Group("staff".into()));
        assert_eq!(parse_admins("junk"), Admins::Group("admin".into()));
        assert_eq!(parse_admins(""), Admins::Group("admin".into()));
        let l = parse_admins("501");
        assert!(l.contains(501));
        assert!(!l.contains(504));
        assert!(!l.contains(crate::peer::UNKNOWN_UID));
        assert!(Admins::Group("wheel".into()).contains(0));
        assert!(!Admins::Group("admin".into()).contains(crate::peer::UNKNOWN_UID));
    }

    #[test]
    fn parse_changes() {
        let m = |v: Value| v.as_object().unwrap().clone();
        assert_eq!(
            Change::parse("enable", &m(json!({"enabled": true}))),
            Ok(Change::Enable { enabled: true })
        );
        assert!(Change::parse("enable", &m(json!({"enabled": "yes"}))).is_err());
        assert!(Change::parse("rule", &m(json!({"action": "drop", "host": "a.com"}))).is_err());
        assert!(Change::parse("approve", &m(json!({}))).is_err());
    }
}

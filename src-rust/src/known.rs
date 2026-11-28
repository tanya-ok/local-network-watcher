//! Known destination owners, process trust tiers and marker severity.
//! Trust comes from the executable path and signature, never from the process name.

use serde_json::Value;
use std::net::IpAddr;

// First-party ranges only. Cloud and CDN ranges are left out: they host many unrelated customers.
const OWNERS: &[(&str, &[&str])] = &[
    ("Apple", &["17.0.0.0/8", "2620:149::/32", "2a01:b740::/32"]),
    (
        "Google",
        &[
            "8.8.4.0/24",
            "8.8.8.0/24",
            "64.233.160.0/19",
            "66.102.0.0/20",
            "66.249.64.0/19",
            "72.14.192.0/18",
            "74.125.0.0/16",
            "108.177.0.0/17",
            "142.250.0.0/15",
            "172.217.0.0/16",
            "172.253.0.0/16",
            "173.194.0.0/16",
            "209.85.128.0/17",
            "216.58.192.0/19",
            "216.239.32.0/19",
            "2001:4860::/32",
            "2404:6800::/32",
            "2607:f8b0::/32",
            "2800:3f0::/32",
            "2a00:1450::/32",
        ],
    ),
];

/// macOS services that sync accounts the user added in Internet Accounts.
const ACCOUNT_SYNC: &[&str] = &[
    "accountsd",
    "AddressBookSourceSync",
    "CalendarAgent",
    "dataaccessd",
    "remindd",
    "Mail",
];
/// macOS services that download from CDNs, often from caches inside the user's internet provider.
const DOWNLOADERS: &[&str] = &[
    "nsurlsessiond",
    "softwareupdated",
    "mobileassetd",
    "appstoreagent",
    "storedownloadd",
];
const SIP_PREFIXES: &[&str] = &[
    "/System/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/usr/bin/",
    "/sbin/",
    "/bin/",
];
const APPLE_LEAF: &[&str] = &["Software Signing", "macOS Software Signing"];

fn bits(ip: IpAddr) -> (u128, u32) {
    match ip {
        IpAddr::V4(v4) => (u32::from(v4) as u128, 32),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => (u32::from(v4) as u128, 32),
            None => (u128::from(v6), 128),
        },
    }
}

fn in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((addr, len)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(len)) = (addr.parse::<IpAddr>(), len.parse::<u32>()) else {
        return false;
    };
    let (a, width_a) = bits(ip);
    let (n, width_n) = bits(net);
    if width_a != width_n || len > width_n {
        return false;
    }
    let shift = width_n - len;
    len == 0 || (a >> shift) == (n >> shift)
}

/// Owner of an address when it falls inside a known first-party range.
pub fn known_owner(ip: &str) -> Option<&'static str> {
    let ip: IpAddr = ip
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()?;
    OWNERS
        .iter()
        .find(|(_, cidrs)| cidrs.iter().any(|c| in_cidr(ip, c)))
        .map(|(org, _)| *org)
}

/// Trust tier from the trust card facts of one executable.
pub fn tier_of(facts: &Value) -> &'static str {
    let path = facts["path"].as_str().unwrap_or("");
    if !path.starts_with('/') {
        return "unknown";
    }
    let chain: Vec<&str> = facts["authority"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let apple_chain = chain.first().is_some_and(|c| APPLE_LEAF.contains(c))
        && chain.last() == Some(&"Apple Root CA");
    if apple_chain && SIP_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return "apple-system";
    }
    let signature = facts["signature"].as_str().unwrap_or("");
    if signature == "not signed" {
        return "unsigned";
    }
    if signature.starts_with("ad hoc") {
        return "adhoc";
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let temp = [
        "/tmp/",
        "/private/tmp/",
        "/var/folders/",
        "/private/var/folders/",
    ]
    .iter()
    .any(|p| path.starts_with(p))
        || (!home.is_empty() && path.starts_with(&format!("{home}/Downloads/")));
    if temp {
        return "temp-location";
    }
    if facts["gatekeeper"].as_str() == Some("accepted") {
        return "signed";
    }
    "unknown"
}

fn tier_reason(tier: &str) -> &'static str {
    match tier {
        "apple-system" => "macOS system service: Apple signature, protected system folder.",
        "signed" => "Signed by an identified developer and accepted by Gatekeeper.",
        "unsigned" => "No code signature.",
        "adhoc" => "Ad hoc signature with no developer identity.",
        "temp-location" => "Runs from a temporary or Downloads folder.",
        _ => "Signature and folder could not be read for this process.",
    }
}

/// Severity (info, notice or attention) and the reason shown with the marker.
pub fn severity_for(
    kind: &str,
    tier: &str,
    app: &str,
    owner: Option<&str>,
) -> (&'static str, String) {
    let base = tier_reason(tier);
    match tier {
        "apple-system" => {
            if kind == "new-app" || kind == "night" {
                return ("info", base.to_string());
            }
            if kind == "new-destination" {
                if owner == Some("Apple") {
                    return ("info", format!("{base} The destination belongs to Apple."));
                }
                if ACCOUNT_SYNC.contains(&app) {
                    let which = owner
                        .map(|o| format!("; this one is {o}"))
                        .unwrap_or_default();
                    return (
                        "info",
                        format!("{base} It syncs accounts added in Internet Accounts{which}."),
                    );
                }
                if DOWNLOADERS.contains(&app) {
                    return (
                        "info",
                        format!(
                            "{base} Download services often use CDN caches, including ones at the internet provider."
                        ),
                    );
                }
            }
            ("notice", base.to_string())
        }
        "signed" => (
            if kind == "unusual-port" {
                "attention"
            } else {
                "notice"
            },
            base.to_string(),
        ),
        "unknown" => (
            if kind == "unusual-port" || kind == "volume" {
                "attention"
            } else {
                "notice"
            },
            base.to_string(),
        ),
        _ => ("attention", base.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn owners() {
        assert_eq!(known_owner("17.157.64.66"), Some("Apple"));
        assert_eq!(known_owner("172.217.116.4"), Some("Google"));
        assert_eq!(known_owner("2a00:1450:4001::1"), Some("Google"));
        assert_eq!(known_owner("::ffff:17.1.1.1"), Some("Apple"));
        assert_eq!(known_owner("195.23.111.144"), None);
        assert_eq!(known_owner("18.0.0.1"), None);
    }

    #[test]
    fn tiers_use_path_and_chain() {
        let apple = json!({"path": "/usr/libexec/nsurlsessiond", "signature": "signed",
            "authority": ["macOS Software Signing", "Apple Code Signing Certification Authority", "Apple Root CA"]});
        assert_eq!(tier_of(&apple), "apple-system");
        let moved = json!({"path": "/Users/x/Library/akd", "signature": "signed",
            "authority": ["macOS Software Signing", "Apple Code Signing Certification Authority", "Apple Root CA"], "gatekeeper": "rejected"});
        assert_eq!(tier_of(&moved), "unknown");
        assert_eq!(
            tier_of(
                &json!({"path": "/opt/homebrew/bin/node", "signature": "ad hoc (no developer identity)"})
            ),
            "adhoc"
        );
        assert_eq!(tier_of(&json!({"path": "node"})), "unknown");
    }

    #[test]
    fn severities() {
        assert_eq!(
            severity_for("new-destination", "apple-system", "akd", Some("Apple")).0,
            "info"
        );
        assert_eq!(
            severity_for(
                "new-destination",
                "apple-system",
                "AddressBookSourceSync",
                Some("Google")
            )
            .0,
            "info"
        );
        assert_eq!(
            severity_for("new-destination", "apple-system", "akd", None).0,
            "notice"
        );
        assert_eq!(
            severity_for("new-app", "adhoc", "evil", None).0,
            "attention"
        );
        assert_eq!(
            severity_for("unusual-port", "signed", "Chrome", None).0,
            "attention"
        );
    }
}

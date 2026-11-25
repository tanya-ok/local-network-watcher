//! Offline GeoIP from a local db-ip City Lite file. No network calls.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

pub struct Place {
    pub lat: f64,
    pub lon: f64,
    pub city: String,
    pub country: String,
}

pub struct Lookup {
    pub status: &'static str,
    pub error: Option<String>,
    pub places: HashMap<String, Place>,
}

pub fn path() -> PathBuf {
    std::env::var_os("LOCAL_WATCH_GEOIP")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join("Library/Application Support/LocalWatch/geoip/dbip-city-lite.mmdb")
        })
}

/// Private, loopback, link-local, CGNAT, multicast and unspecified addresses never get coordinates.
pub fn is_non_public(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let [a, b, ..] = v4.octets();
            a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..128).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..32).contains(&b))
                || (a == 192 && b == 168)
                || a >= 224
        }
        Ok(IpAddr::V6(v6)) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_non_public(&v4.to_string());
            }
            let first = v6.segments()[0];
            v6.is_unspecified()
                || v6.is_loopback()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || (first & 0xff00) == 0xff00
        }
        Err(_) => true,
    }
}

struct Loaded {
    reader: maxminddb::Reader<Vec<u8>>,
    mtime: SystemTime,
    checked: Instant,
}

static READER: Mutex<Option<Loaded>> = Mutex::new(None);

/// Reloads the file when its mtime changes; checks at most once a minute.
pub fn lookup(ips: &[String]) -> Lookup {
    let mut places = HashMap::new();
    let mut guard = match READER.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let fresh = guard
        .as_ref()
        .is_some_and(|l| l.checked.elapsed() < Duration::from_secs(60));
    if !fresh {
        let file = path();
        match std::fs::metadata(&file).and_then(|m| m.modified()) {
            Err(_) => *guard = None,
            Ok(mtime) => {
                if guard.as_ref().is_none_or(|l| l.mtime != mtime) {
                    match maxminddb::Reader::open_readfile(&file) {
                        Ok(reader) => {
                            *guard = Some(Loaded {
                                reader,
                                mtime,
                                checked: Instant::now(),
                            })
                        }
                        Err(e) => {
                            *guard = None;
                            return Lookup {
                                status: "error",
                                error: Some(format!("GeoIP file could not be read: {e}")),
                                places,
                            };
                        }
                    }
                } else if let Some(l) = guard.as_mut() {
                    l.checked = Instant::now();
                }
            }
        }
    }
    let Some(loaded) = guard.as_ref() else {
        return Lookup {
            status: "missing",
            error: None,
            places,
        };
    };
    for ip in ips {
        if is_non_public(ip) {
            continue;
        }
        let Ok(addr) = ip.parse::<IpAddr>() else {
            continue;
        };
        let Some(hit) = loaded
            .reader
            .lookup(addr)
            .ok()
            .and_then(|r| r.decode::<maxminddb::geoip2::City>().ok().flatten())
        else {
            continue;
        };
        let (Some(lat), Some(lon)) = (hit.location.latitude, hit.location.longitude) else {
            continue;
        };
        places.insert(
            ip.clone(),
            Place {
                lat,
                lon,
                city: hit.city.names.english.unwrap_or_default().to_string(),
                country: hit.country.iso_code.unwrap_or_default().to_string(),
            },
        );
    }
    Lookup {
        status: "ok",
        error: None,
        places,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_public_addresses() {
        for ip in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "224.0.0.251",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(is_non_public(ip), "{ip}");
        }
        for ip in ["8.8.8.8", "100.128.0.1", "2001:4860:4860::8888"] {
            assert!(!is_non_public(ip), "{ip}");
        }
    }

    #[test]
    fn local_file_lookup() {
        if !path().exists() {
            return;
        }
        let ips: Vec<String> = ["8.8.8.8", "192.168.1.1", "127.0.0.1", "fe80::1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let r = lookup(&ips);
        assert_eq!(r.status, "ok");
        assert!(r.places.contains_key("8.8.8.8"));
        assert_eq!(r.places.len(), 1);
    }
}

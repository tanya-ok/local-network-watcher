//! User settings in settings.json (0600) and an offline home estimate from the time zone.

use serde_json::{Map, Value, json};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

fn data_dir() -> PathBuf {
    std::env::var_os("LOCAL_WATCH_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join("Library/Application Support/LocalWatch")
        })
}

/// Reverse DNS is on unless LOCAL_WATCH_REVERSE_DNS=0; a saved choice wins.
pub fn load_reverse_dns() -> bool {
    let default = std::env::var("LOCAL_WATCH_REVERSE_DNS").as_deref() != Ok("0");
    fs::read(data_dir().join("settings.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Map<String, Value>>(&b).ok())
        .and_then(|m| m.get("reverseDns").and_then(Value::as_bool))
        .unwrap_or(default)
}

pub fn save_reverse_dns(enabled: bool) -> std::io::Result<()> {
    let dir = data_dir();
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    let file = dir.join("settings.json");
    let mut map = fs::read(&file)
        .ok()
        .and_then(|b| serde_json::from_slice::<Map<String, Value>>(&b).ok())
        .unwrap_or_default();
    map.insert("reverseDns".into(), Value::Bool(enabled));
    let tmp = file.with_extension("json.tmp");
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    out.write_all(&serde_json::to_vec(&map).unwrap_or_default())?;
    out.sync_all()?;
    fs::rename(&tmp, &file)
}

fn time_zone() -> String {
    if let Ok(tz) = std::env::var("TZ") {
        let tz = tz.trim_start_matches(':');
        if let Some((_, name)) = tz.split_once("zoneinfo/") {
            return name.to_string();
        }
        if !tz.is_empty() && !tz.starts_with('/') {
            return tz.to_string();
        }
    }
    fs::read_link("/etc/localtime")
        .ok()
        .and_then(|p| {
            p.to_str()
                .and_then(|s| s.split_once("zoneinfo/"))
                .map(|(_, n)| n.to_string())
        })
        .unwrap_or_default()
}

/// ISO 6709 `+DDMM[SS]` / `+DDDMM[SS]` part to decimal degrees.
fn degrees(part: &str, deg_len: usize) -> Option<f64> {
    let (sign, digits) = part.split_at(1);
    let sign = match sign {
        "+" => 1.0,
        "-" => -1.0,
        _ => return None,
    };
    if !digits.chars().all(|c| c.is_ascii_digit())
        || (digits.len() != deg_len + 2 && digits.len() != deg_len + 4)
    {
        return None;
    }
    let d: f64 = digits[..deg_len].parse().ok()?;
    let m: f64 = digits[deg_len..deg_len + 2].parse().ok()?;
    let s: f64 = digits
        .get(deg_len + 2..)
        .filter(|x| !x.is_empty())
        .map_or(Some(0.0), |x| x.parse().ok())?;
    Some(sign * (d + m / 60.0 + s / 3600.0))
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// Home estimate from the system time zone and zone.tab; nothing is looked up online.
pub fn home_estimate() -> Value {
    let tz = time_zone();
    let tab = fs::read_to_string("/usr/share/zoneinfo/zone.tab").unwrap_or_default();
    for line in tab.lines().filter(|l| !l.starts_with('#')) {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 3 || cols[2] != tz {
            continue;
        }
        let coords = cols[1];
        let Some(split) = coords[1..].find(['+', '-']).map(|i| i + 1) else {
            break;
        };
        let (lat, lon) = coords.split_at(split);
        if let (Some(lat), Some(lon)) = (degrees(lat, 2), degrees(lon, 3)) {
            let city = tz.rsplit('/').next().unwrap_or_default().replace('_', " ");
            return json!({ "tz": tz, "city": city, "lat": round2(lat), "lon": round2(lon), "source": "time zone" });
        }
        break;
    }
    json!({ "tz": tz, "source": "none" })
}

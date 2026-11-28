//! Residual DNS visibility: query names from a root tcpdump on pflog0, which sees resolver traffic the proxy never carries.

use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Query {
    pub time: String,
    pub source: String,
    pub server: String,
    pub qtype: String,
    pub name: String,
}

pub fn log_path() -> PathBuf {
    std::env::var_os("LOCAL_WATCH_EGRESS_DNS_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/log/local-watch-egress/dns.log"))
}

fn qtype_token(t: &str) -> Option<&str> {
    let q = t.strip_suffix('?')?;
    (!q.is_empty()
        && q.len() <= 10
        && q.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
    .then_some(q)
}

/// Parses one `tcpdump -l -n` line such as
/// `12:00:01.5 IP 10.0.0.5.53000 > 1.1.1.1.53: 4660+ A? example.com. (29)`.
/// Answers and anything else return None.
pub fn parse_line(line: &str) -> Option<Query> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let gt = tokens.iter().position(|t| *t == ">")?;
    let source = *tokens.get(gt.checked_sub(1)?)?;
    let server = tokens.get(gt + 1)?.strip_suffix(':')?;
    let q = (gt + 2..tokens.len()).find(|&i| qtype_token(tokens[i]).is_some())?;
    let qtype = qtype_token(tokens[q])?;
    let raw = tokens.get(q + 1)?;
    let name = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(Query {
        time: tokens.first()?.to_string(),
        source: source.to_string(),
        server: server.to_string(),
        qtype: qtype.to_string(),
        name,
    })
}

/// Follows the log from its current end, handling rotation and truncation; calls on_query for each new query line.
pub async fn follow(
    on_query: impl Fn(Query) + Send + 'static,
    on_seen: impl Fn(bool) + Send + 'static,
) {
    let path = log_path();
    let mut offset: Option<u64> = None;
    let mut inode = 0u64;
    let mut carry = String::new();
    loop {
        let step = (|| -> std::io::Result<Vec<String>> {
            use std::os::unix::fs::MetadataExt;
            let mut f = std::fs::File::open(&path)?;
            let meta = f.metadata()?;
            let len = meta.len();
            let start = match offset {
                None => len,
                Some(o) if meta.ino() != inode || o > len => 0,
                Some(o) => o,
            };
            inode = meta.ino();
            f.seek(SeekFrom::Start(start))?;
            let mut buf = Vec::new();
            f.take(1024 * 1024).read_to_end(&mut buf)?;
            offset = Some(start + buf.len() as u64);
            carry.push_str(&String::from_utf8_lossy(&buf));
            let mut lines: Vec<String> = carry.split('\n').map(str::to_string).collect();
            carry = lines.pop().unwrap_or_default();
            Ok(lines)
        })();
        match step {
            Ok(lines) => {
                on_seen(true);
                for q in lines.iter().filter_map(|l| parse_line(l)) {
                    on_query(q);
                }
            }
            Err(_) => {
                on_seen(false);
                offset = None;
                carry.clear();
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries() {
        let q = parse_line(
            "12:00:01.123456 IP 192.168.1.5.53000 > 1.1.1.1.53: 4660+ A? Example.COM. (29)",
        )
        .unwrap();
        assert_eq!(
            (
                q.source.as_str(),
                q.server.as_str(),
                q.qtype.as_str(),
                q.name.as_str()
            ),
            ("192.168.1.5.53000", "1.1.1.1.53", "A", "example.com")
        );
        let q = parse_line(
            "1700000000.1 rule 7/0(match): pass out on en0: 10.0.0.2.5000 > 9.9.9.9.53: 1+% [1au] AAAA? api.example.org. (44)",
        )
        .unwrap();
        assert_eq!(
            (q.qtype.as_str(), q.name.as_str()),
            ("AAAA", "api.example.org")
        );
        let q =
            parse_line("12:00 IP6 fd00::2.5000 > fd00::1.53: 2+ HTTPS? _dns.resolver.arpa. (36)")
                .unwrap();
        assert_eq!(q.name, "_dns.resolver.arpa");
    }

    #[test]
    fn non_queries() {
        for line in [
            "12:00:01 IP 1.1.1.1.53 > 192.168.1.5.53000: 4660 1/0/0 A 93.184.216.34 (45)",
            "tcpdump: listening on pflog0, link-type PFLOG",
            "",
            "12:00 IP 1.2.3.4.5 > 5.6.7.8.53: 1+ A? bad<name>. (3)",
            "12:00 IP 1.2.3.4.5 > 5.6.7.8.53 1+ A? x.com. (3)",
        ] {
            assert!(parse_line(line).is_none(), "{line}");
        }
    }
}

//! Manual TShark capture: decoded header fields only, kept in memory, never written to disk.

use serde::Serialize;
use serde_json::{Map, Value};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::oneshot;

pub const TSHARK: &str = "/Applications/Wireshark.app/Contents/MacOS/tshark";
const MAX_PACKETS: usize = 3000;

// No -w, -x or payload fields: the capture never writes a PCAP or exposes packet bytes.
const FIELDS: &[(&str, &str)] = &[
    ("frame.number", "frame"),
    ("frame.time_relative", "time"),
    ("frame.len", "len"),
    ("ip.src", "ipSrc"),
    ("ip.dst", "ipDst"),
    ("ipv6.src", "ipv6Src"),
    ("ipv6.dst", "ipv6Dst"),
    ("tcp.srcport", "tcpSrc"),
    ("tcp.dstport", "tcpDst"),
    ("udp.srcport", "udpSrc"),
    ("udp.dstport", "udpDst"),
    ("_ws.col.Protocol", "protocol"),
    ("dns.qry.name", "dnsQry"),
    ("tls.handshake.extensions_server_name", "tlsSNI"),
    ("http.host", "httpHost"),
    ("_ws.col.Info", "info"),
    ("eth.src", "ethSrc"),
    ("eth.dst", "ethDst"),
    ("ip.ttl", "ttl"),
    ("tcp.flags.str", "tcpFlags"),
    ("tls.record.version", "tlsVersion"),
    ("frame.protocols", "frameProtocols"),
    ("frame.cap_len", "capturedLength"),
    ("eth.type", "ethType"),
    ("ip.id", "ipId"),
    ("ip.flags", "ipFlags"),
    ("ip.proto", "ipProto"),
    ("ip.checksum", "ipChecksum"),
    ("ipv6.nxt", "ipv6Next"),
    ("ipv6.plen", "ipv6Length"),
    ("ipv6.hlim", "ipv6HopLimit"),
    ("tcp.seq_raw", "tcpSequence"),
    ("tcp.ack_raw", "tcpAck"),
    ("tcp.hdr_len", "tcpHeaderLength"),
    ("tcp.len", "tcpPayloadLength"),
    ("tcp.flags", "tcpFlagsRaw"),
    ("tcp.window_size_value", "tcpWindow"),
    ("tcp.checksum", "tcpChecksum"),
    ("tcp.analysis.retransmission", "tcpRetransmission"),
    ("udp.length", "udpLength"),
    ("udp.checksum", "udpChecksum"),
    ("dns.id", "dnsId"),
    ("dns.flags", "dnsFlags"),
    ("dns.qry.type", "dnsQueryType"),
    ("dns.resp.name", "dnsAnswerName"),
    ("dns.resp.ttl", "dnsTtl"),
    ("dns.a", "dnsA"),
    ("dns.aaaa", "dnsAAAA"),
    ("tls.record.content_type", "tlsContentType"),
    ("tls.record.length", "tlsRecordLength"),
    ("tls.handshake.type", "tlsHandshakeType"),
    ("tls.handshake.version", "tlsHandshakeVersion"),
    ("tls.handshake.ciphersuite", "tlsCipherSuite"),
];

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CaptureView {
    pub state: &'static str,
    pub started_at: Option<String>,
    pub seconds: Option<u32>,
    pub interface: Option<String>,
    pub packets: Vec<Value>,
    pub error: Option<String>,
}

struct Inner {
    view: CaptureView,
    generation: u64,
    cancel: Option<oneshot::Sender<()>>,
}

#[derive(Clone)]
pub struct Capture(Arc<Mutex<Inner>>);

#[derive(Serialize)]
pub struct Interface {
    pub name: String,
    pub description: String,
}

fn idle() -> CaptureView {
    CaptureView {
        state: "idle",
        started_at: None,
        seconds: None,
        interface: None,
        packets: Vec::new(),
        error: None,
    }
}

fn parse_packet(line: &str) -> Value {
    let mut fields = line.split('\t');
    let mut map = Map::new();
    for (_, key) in FIELDS {
        map.insert(
            (*key).to_string(),
            Value::String(fields.next().unwrap_or_default().trim().to_string()),
        );
    }
    Value::Object(map)
}

fn iso_now() -> String {
    let ms = crate::history::now_ms();
    // RFC 3339 in UTC without a date library.
    let secs = (ms / 1000) as libc::time_t;
    // SAFETY: gmtime_r writes only into the struct we pass.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::gmtime_r(&secs, &mut tm);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            ms % 1000
        )
    }
}

pub async fn interfaces() -> Result<Vec<Interface>, String> {
    let text = crate::facts::run(TSHARK, &["-D"], Duration::from_secs(5), false)
        .await
        .ok_or_else(|| "TShark did not answer".to_string())?;
    let list: Vec<Interface> = text
        .lines()
        .filter_map(|line| {
            let (number, rest) = line.split_once(". ")?;
            number.trim().parse::<u32>().ok()?;
            let rest = rest.trim();
            let (name, description) = match rest.split_once(" (") {
                Some((name, desc)) => (name.trim(), desc.trim_end_matches(')').trim()),
                None => (rest, ""),
            };
            (!name.is_empty() && !name.contains(char::is_whitespace)).then(|| Interface {
                name: name.to_string(),
                description: description.to_string(),
            })
        })
        .collect();
    if list.is_empty() {
        Err("no interfaces listed".into())
    } else {
        Ok(list)
    }
}

impl Capture {
    pub fn new() -> Capture {
        Capture(Arc::new(Mutex::new(Inner {
            view: idle(),
            generation: 0,
            cancel: None,
        })))
    }

    pub fn view(&self) -> CaptureView {
        self.0
            .lock()
            .map(|i| i.view.clone())
            .unwrap_or_else(|_| idle())
    }

    pub fn clear(&self) {
        if let Ok(mut inner) = self.0.lock() {
            if let Some(cancel) = inner.cancel.take() {
                let _ = cancel.send(());
            }
            inner.generation += 1;
            inner.view = idle();
        }
    }

    /// Validates everything before TShark starts; arguments are passed as a list, never through a shell.
    pub async fn start(
        &self,
        iface: &str,
        seconds: u32,
        display_filter: &str,
    ) -> Result<(), String> {
        if ![5, 10, 30].contains(&seconds) {
            return Err("Duration must be 5, 10 or 30 seconds.".into());
        }
        if display_filter.chars().count() > 500 || display_filter.contains(['\0', '\r', '\n']) {
            return Err("Display filter must be one line and 500 characters or fewer.".into());
        }
        if self.view().state == "running" {
            return Err("A capture is already running.".into());
        }
        let names = interfaces()
            .await
            .map_err(|_| "Unknown network interface.".to_string())?;
        if !names.iter().any(|i| i.name == iface) {
            return Err("Unknown network interface.".into());
        }
        let mut args: Vec<String> = vec![
            "-i".into(),
            iface.into(),
            "-a".into(),
            format!("duration:{seconds}"),
            "-c".into(),
            MAX_PACKETS.to_string(),
            "-l".into(),
            "-n".into(),
        ];
        if !display_filter.is_empty() {
            args.push("-Y".into());
            args.push(display_filter.into());
        }
        args.extend(["-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"].map(String::from));
        for (field, _) in FIELDS {
            args.push("-e".into());
            args.push((*field).into());
        }
        let mut child = Command::new(TSHARK)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("TShark could not start: {e}"))?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let mut stderr = child.stderr.take().ok_or("no stderr")?;
        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        let generation = {
            let mut inner = self.0.lock().map_err(|_| "state unavailable")?;
            if inner.view.state == "running" {
                return Err("A capture is already running.".into());
            }
            inner.generation += 1;
            inner.cancel = Some(cancel_tx);
            inner.view = CaptureView {
                state: "running",
                started_at: Some(iso_now()),
                seconds: Some(seconds),
                interface: Some(iface.to_string()),
                packets: Vec::new(),
                error: None,
            };
            inner.generation
        };
        let shared = self.0.clone();
        tokio::spawn(async move {
            let err_task = tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = stderr.read_to_end(&mut buf).await;
                let text = String::from_utf8_lossy(&buf).into_owned();
                text.chars()
                    .rev()
                    .take(2000)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<String>()
            });
            let mut lines = BufReader::new(stdout).lines();
            let mut cancelled = false;
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => { cancelled = true; let _ = child.kill().await; break; }
                    line = lines.next_line() => match line {
                        Ok(Some(line)) if !line.trim().is_empty() => {
                            if let Ok(mut inner) = shared.lock()
                                && inner.generation == generation
                                && inner.view.packets.len() < MAX_PACKETS
                            {
                                inner.view.packets.push(parse_packet(&line));
                            }
                        }
                        Ok(Some(_)) => {}
                        _ => break,
                    }
                }
            }
            let status = child.wait().await.ok();
            let stderr_text = err_task.await.unwrap_or_default();
            if cancelled {
                return;
            }
            if let Ok(mut inner) = shared.lock() {
                if inner.generation != generation || inner.view.state != "running" {
                    return;
                }
                inner.cancel = None;
                if status.is_some_and(|s| s.success()) {
                    inner.view.state = "done";
                } else {
                    inner.view.state = "error";
                    let code = status
                        .and_then(|s| s.code())
                        .map_or("unknown".into(), |c| c.to_string());
                    let hint = stderr_text
                        .lines()
                        .rfind(|l| {
                            let l = l.to_ascii_lowercase();
                            l.contains("error") || l.contains("permission") || l.contains("denied")
                        })
                        .map(str::to_string);
                    inner.view.error =
                        Some(hint.unwrap_or_else(|| format!("TShark stopped with code {code}")));
                }
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tab_fields_by_position() {
        let packet = parse_packet("1\t0.000\t66\t1.2.3.4\t5.6.7.8");
        assert_eq!(packet["frame"], "1");
        assert_eq!(packet["ipDst"], "5.6.7.8");
        assert_eq!(packet["tlsSNI"], "");
        assert_eq!(packet.as_object().map(|m| m.len()), Some(FIELDS.len()));
    }
}

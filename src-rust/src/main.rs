use std::collections::HashMap;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default, Clone)]
struct Socket {
    pid: u32,
    process: String,
    protocol: String,
    name: String,
    state: String,
}

#[derive(Clone)]
struct Connection {
    pid: u32,
    process: String,
    protocol: String,
    local: String,
    remote: String,
    state: String,
}

#[derive(Clone)]
struct ProcessTraffic {
    pid: u32,
    process: String,
    user: String,
    received_bytes: u64,
    sent_bytes: u64,
    received_packets: u64,
    sent_packets: u64,
}

fn is_loopback(endpoint: &str) -> bool {
    let Some(split) = endpoint.rfind(':') else {
        return false;
    };
    let host = endpoint[..split].trim_matches(['[', ']']);
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn flush_socket(socket: &Socket, rows: &mut Vec<Connection>) {
    if socket.name.is_empty() || socket.state == "LISTEN" || socket.state == "CLOSED" {
        return;
    }
    let Some(split) = socket.name.rfind("->") else {
        return;
    };
    let local = &socket.name[..split];
    let remote = &socket.name[split + 2..];
    if remote.is_empty() || remote == "*" || remote == "*:*" || is_loopback(remote) {
        return;
    }
    rows.push(Connection {
        pid: socket.pid,
        process: if socket.process.is_empty() {
            "Unknown process".into()
        } else {
            socket.process.clone()
        },
        protocol: socket.protocol.trim_start_matches('P').to_string(),
        local: local.to_string(),
        remote: remote.to_string(),
        state: if socket.state.is_empty() {
            "Open".into()
        } else {
            socket.state.clone()
        },
    });
}

fn parse_lsof(text: &str) -> Vec<Connection> {
    let mut rows = Vec::new();
    let mut socket: Option<Socket> = None;
    for line in text.lines() {
        if let Some(pid) = line.strip_prefix('p') {
            if let Some(current) = &socket {
                flush_socket(current, &mut rows);
            }
            socket = Some(Socket {
                pid: pid.parse().unwrap_or_default(),
                ..Socket::default()
            });
        } else if let Some(current) = socket.as_mut() {
            if let Some(process) = line.strip_prefix('c') {
                current.process = process.to_string();
            } else if line.starts_with('f') {
                flush_socket(current, &mut rows);
                current.name.clear();
                current.state.clear();
            } else if let Some(protocol) = line.strip_prefix('P') {
                current.protocol = protocol.to_string();
            } else if let Some(name) = line.strip_prefix('n') {
                current.name = name.to_string();
            } else if let Some(state) = line.strip_prefix("TST=") {
                current.state = state.to_string();
            }
        }
    }
    if let Some(current) = &socket {
        flush_socket(current, &mut rows);
    }
    rows.sort_by(|a, b| a.process.cmp(&b.process).then(a.remote.cmp(&b.remote)));
    rows.dedup_by(|a, b| {
        a.pid == b.pid
            && a.protocol == b.protocol
            && a.local == b.local
            && a.remote == b.remote
            && a.state == b.state
    });
    rows.truncate(500);
    rows
}

fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            _ => field.push(ch),
        }
    }
    fields.push(field);
    fields
}

fn process_names() -> HashMap<u32, (String, String)> {
    let Ok(output) = Command::new("/bin/ps")
        .args(["-axo", "pid=,comm=,user="])
        .output()
    else {
        return HashMap::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let (pid, rest) = line.trim().split_once(char::is_whitespace)?;
            let pid = pid.parse::<u32>().ok()?;
            let (command, user) = rest.trim().rsplit_once(char::is_whitespace)?;
            let name = command.trim().rsplit('/').next()?.to_string();
            Some((pid, (name, user.trim().to_string())))
        })
        .collect()
}

fn parse_nettop(text: &str, names: &HashMap<u32, (String, String)>) -> Vec<ProcessTraffic> {
    let mut header = Vec::new();
    let mut rows = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields = csv_fields(line);
        if fields.first().is_some_and(|field| field.trim().is_empty()) {
            header = fields;
            continue;
        }
        if header.is_empty() || fields.is_empty() {
            continue;
        }
        let Some((raw_name, pid)) = fields[0].trim().rsplit_once('.') else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        let value = |column: &str| -> u64 {
            header
                .iter()
                .position(|name| name == column)
                .and_then(|index| fields.get(index))
                .and_then(|field| field.trim().parse().ok())
                .unwrap_or_default()
        };
        let process = names
            .get(&pid)
            .map(|details| details.0.clone())
            .unwrap_or_else(|| raw_name.trim_end_matches('.').to_string());
        let user = names
            .get(&pid)
            .map(|details| details.1.clone())
            .unwrap_or_default();
        rows.push(ProcessTraffic {
            pid,
            process,
            user,
            received_bytes: value("bytes_in"),
            sent_bytes: value("bytes_out"),
            received_packets: value("packets_in"),
            sent_packets: value("packets_out"),
        });
    }
    rows.sort_by(|a, b| (b.received_bytes + b.sent_bytes).cmp(&(a.received_bytes + a.sent_bytes)));
    rows.dedup_by_key(|row| row.pid);
    rows
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c.is_control() => output.push_str(&format!("\\u{:04x}", c as u32)),
            c => output.push(c),
        }
    }
    output.push('"');
    output
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|_| format!("Could not run {program}."))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn main() {
    if !cfg!(target_os = "macos") {
        eprintln!("This first version reads macOS network activity only.");
        std::process::exit(2);
    }
    let names = process_names();
    let connections = match run("/usr/sbin/lsof", &["-nP", "-i", "-FpcPTn"]) {
        Ok(text) => parse_lsof(&text),
        Err(error) => {
            eprintln!("Could not read open network connections: {error}");
            std::process::exit(3);
        }
    };
    let (processes, metrics_warning) = match run(
        "/usr/bin/nettop",
        &[
            "-P",
            "-L",
            "1",
            "-n",
            "-x",
            "-J",
            "packets_in,bytes_in,packets_out,bytes_out",
        ],
    ) {
        Ok(text) => (parse_nettop(&text, &names), None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let sampled_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let connection_rows = connections
        .iter()
        .map(|row| {
            format!(
                "{{\"pid\":{},\"process\":{},\"protocol\":{},\"local\":{},\"remote\":{},\"state\":{}}}",
                row.pid,
                json_string(&row.process),
                json_string(&row.protocol),
                json_string(&row.local),
                json_string(&row.remote),
                json_string(&row.state)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let process_rows = processes
        .iter()
        .map(|row| {
            format!(
                "{{\"pid\":{},\"process\":{},\"user\":{},\"receivedBytes\":{},\"sentBytes\":{},\"receivedPackets\":{},\"sentPackets\":{}}}",
                row.pid,
                json_string(&row.process),
                json_string(&row.user),
                row.received_bytes,
                row.sent_bytes,
                row.received_packets,
                row.sent_packets
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let warning = metrics_warning
        .as_deref()
        .map(json_string)
        .unwrap_or_else(|| "null".to_string());
    println!(
        "{{\"sampledAt\":{},\"source\":\"macOS nettop + lsof · Rust core\",\"refreshSeconds\":3,\"connections\":[{}],\"processes\":[{}],\"metricsWarning\":{}}}",
        sampled_at, connection_rows, process_rows, warning
    );
}

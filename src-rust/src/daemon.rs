//! `egress-daemon`: the two proxy listeners plus a control endpoint on a Unix socket, run under a dedicated account. Also the `egress` CLI that talks to it.

use crate::approval::Change;
use crate::{egress, peer};
use serde_json::{Value, json};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

const REQUEST_LIMIT: u64 = 4096;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub fn socket_path() -> PathBuf {
    std::env::var_os("LOCAL_WATCH_EGRESS_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/run/local-watch-egress/control.sock"))
}

fn data_dir() -> PathBuf {
    std::env::var_os("LOCAL_WATCH_EGRESS_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/Library/Application Support/LocalWatchEgress"))
}

/// Whether a daemon answers on the socket right now.
pub fn available() -> bool {
    std::os::unix::net::UnixStream::connect(socket_path()).is_ok()
}

/// The uid the request acts as. Only an admin peer (the 4317 app) may speak for the TCP client it measured; anyone else acts as itself.
pub fn effective_uid(peer_uid: u32, peer_is_admin: bool, for_uid: Option<u32>) -> u32 {
    match for_uid {
        Some(u) if peer_is_admin => u,
        _ => peer_uid,
    }
}

async fn answer(req: Value, peer_uid: u32) -> Value {
    let for_uid = req
        .get("forUid")
        .and_then(Value::as_u64)
        .and_then(|u| u32::try_from(u).ok());
    let admin = crate::approval::load_admins(&data_dir()).contains(peer_uid);
    // The app may not see other accounts' sockets; it then passes the TCP ports and the daemon looks the client up itself.
    let for_uid = match (for_uid, req.get("forClient")) {
        (None, Some(c)) if admin => {
            let port = |k: &str| {
                c.get(k)
                    .and_then(Value::as_u64)
                    .and_then(|p| u16::try_from(p).ok())
            };
            match (port("port"), port("serverPort")) {
                (Some(p), Some(sp)) => Some(
                    tokio::task::spawn_blocking(move || {
                        let lo = std::net::Ipv4Addr::LOCALHOST;
                        peer::tcp_client_uid((lo, p).into(), (lo, sp).into())
                    })
                    .await
                    .unwrap_or(peer::UNKNOWN_UID),
                ),
                _ => Some(peer::UNKNOWN_UID),
            }
        }
        (u, _) => u,
    };
    let uid = effective_uid(peer_uid, admin, for_uid);
    let str_field = |k: &str| req.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let result = match str_field("op").as_str() {
        "status" => Ok(json!({})),
        "change" => {
            let input = req
                .get("input")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            match Change::parse(&str_field("action"), &input) {
                Ok(c) => egress::request(uid, c).await,
                Err(e) => Err(e),
            }
        }
        "approve" => egress::resolve(uid, &str_field("id"), true).await,
        "deny" => egress::resolve(uid, &str_field("id"), false).await,
        _ => Err("Unknown request.".into()),
    };
    let mut status = egress::status();
    status["mode"] = json!("daemon");
    status["socketTable"] = crate::peer::socket_table_diag();
    match result {
        Ok(r) => json!({ "ok": true, "result": r, "status": status }),
        Err(e) => json!({ "ok": false, "error": e, "status": status }),
    }
}

async fn serve_one(stream: UnixStream) {
    let peer_uid = peer::unix_peer_uid(stream.as_raw_fd());
    let (r, mut w) = stream.into_split();
    let mut line = String::new();
    let mut reader = BufReader::new(r.take(REQUEST_LIMIT));
    let read = tokio::time::timeout(IO_TIMEOUT, reader.read_line(&mut line)).await;
    let reply = match (read, serde_json::from_str::<Value>(line.trim())) {
        (Ok(Ok(_)), Ok(req)) => answer(req, peer_uid).await,
        _ => json!({ "ok": false, "error": "Send one JSON request line." }),
    };
    let mut text = serde_json::to_string(&reply).unwrap_or_default();
    text.push('\n');
    let _ = tokio::time::timeout(IO_TIMEOUT, w.write_all(text.as_bytes())).await;
}

fn bind() -> std::io::Result<UnixListener> {
    let path = socket_path();
    match std::fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(&path)?,
        Ok(_) => {
            return Err(std::io::Error::other(format!(
                "{} exists and is not a socket",
                path.display()
            )));
        }
        Err(_) => {}
    }
    let listener = UnixListener::bind(&path)?;
    // Any account may connect; what it may do is decided per request from its kernel uid.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

pub async fn run() {
    // SAFETY: umask only changes the mode of files this process creates.
    unsafe {
        libc::umask(0o077);
    }
    egress::set_dir(data_dir());
    if let Err(e) = egress::private_dir() {
        eprintln!(
            "Egress daemon could not prepare {}: {e}",
            data_dir().display()
        );
        std::process::exit(1);
    }
    let listener = match bind() {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "Egress daemon could not listen on {}: {e}",
                socket_path().display()
            );
            std::process::exit(1);
        }
    };
    egress::init().await;
    egress::start_dns();
    println!(
        "Egress daemon: control socket {}, data {}",
        socket_path().display(),
        data_dir().display()
    );
    let accept = async {
        loop {
            match listener.accept().await {
                Ok((s, _)) => {
                    tokio::spawn(serve_one(s));
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    };
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = accept => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending().await } } => {}
    }
    let _ = std::fs::remove_file(socket_path());
}

/// Sends one request to the daemon and returns its reply.
pub async fn call(req: Value) -> Result<Value, String> {
    let work = async {
        let mut s = UnixStream::connect(socket_path()).await?;
        let mut text = serde_json::to_string(&req).unwrap_or_default();
        text.push('\n');
        s.write_all(text.as_bytes()).await?;
        let mut out = String::new();
        BufReader::new(s.take(16 * 1024 * 1024))
            .read_line(&mut out)
            .await?;
        Ok::<String, std::io::Error>(out)
    };
    let out = tokio::time::timeout(IO_TIMEOUT, work)
        .await
        .map_err(|_| "The egress daemon did not answer in time.".to_string())?
        .map_err(|e| format!("The egress daemon is not reachable: {e}"))?;
    serde_json::from_str(out.trim()).map_err(|_| "The egress daemon sent an invalid reply.".into())
}

const USAGE: &str = "usage: local-network-watcher egress status | pending | approve <id> | deny <id> | request <enable|pause|rule|ports> '<json>'";

pub async fn cli(args: &[String]) -> i32 {
    let req = match args {
        [s] if s == "status" || s == "pending" => json!({ "op": "status" }),
        [op, id] if op == "approve" || op == "deny" => json!({ "op": op, "id": id }),
        [op, action, input] if op == "request" => match serde_json::from_str::<Value>(input) {
            Ok(v) => json!({ "op": "change", "action": action, "input": v }),
            Err(_) => {
                eprintln!("The change must be a JSON object.");
                return 2;
            }
        },
        _ => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    match call(req).await {
        Ok(reply) => {
            let shown = match args[0].as_str() {
                "status" => reply["status"].clone(),
                "pending" => reply["status"]["pending"].clone(),
                _ => {
                    json!({ "ok": reply["ok"], "result": reply["result"], "error": reply["error"] })
                }
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&shown).unwrap_or_default()
            );
            if reply["ok"] == json!(true) { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_admin_peers_speak_for_others() {
        assert_eq!(effective_uid(501, true, Some(504)), 504);
        assert_eq!(effective_uid(501, true, None), 501);
        assert_eq!(effective_uid(504, false, Some(501)), 504);
        assert_eq!(effective_uid(504, false, Some(0)), 504);
    }
}

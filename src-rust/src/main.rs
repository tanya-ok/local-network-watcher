//! Local Network Watcher: one binary that collects, serves the page and answers its API on 127.0.0.1.

mod ai;
mod capture;
mod collector;
mod control;
mod egress;
mod facts;
mod geoip;
mod history;
mod settings;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Clone)]
struct AppState {
    port: u16,
    history: Arc<Mutex<history::History>>,
    caches: Arc<facts::Caches>,
    capture: capture::Capture,
    explaining: Arc<AtomicBool>,
}

type Reply = Response;

fn reply(status: StatusCode, body: Value) -> Reply {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn error(status: StatusCode, message: &str) -> Reply {
    reply(status, json!({ "error": message }))
}

fn no_content() -> Reply {
    StatusCode::NO_CONTENT.into_response()
}

/// Only pages served by this app on this port may change state.
fn same_origin(headers: &HeaderMap, port: u16) -> bool {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    origin == format!("http://127.0.0.1:{port}") || origin == format!("http://localhost:{port}")
}

#[allow(clippy::result_large_err)] // the error is a ready HTTP response
fn json_body(body: &Bytes, limit: usize) -> Result<Map<String, Value>, Reply> {
    if body.len() > limit {
        return Err(error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request is too large.",
        ));
    }
    let text = if body.is_empty() {
        b"{}".as_slice()
    } else {
        body.as_ref()
    };
    match serde_json::from_slice::<Value>(text) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(error(StatusCode::BAD_REQUEST, "Expected a JSON object.")),
    }
}

/// DNS rebinding guard: the Host header must name this machine on loopback.
async fn host_guard(request: Request, next: Next) -> Reply {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let name = host.rsplit_once(':').map_or(host, |(n, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) {
            n
        } else {
            host
        }
    });
    if name != "localhost" && name != "127.0.0.1" {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "Local access only",
        )
            .into_response();
    }
    next.run(request).await
}

async fn collect() -> Result<collector::Snapshot, String> {
    tokio::task::spawn_blocking(collector::snapshot)
        .await
        .map_err(|_| "collector stopped".to_string())?
}

async fn connections() -> Reply {
    match collect().await {
        Ok(snapshot) => reply(
            StatusCode::OK,
            serde_json::to_value(snapshot).unwrap_or_default(),
        ),
        Err(message) => reply(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "error": message, "sampledAt": history::now_ms(), "connections": [] }),
        ),
    }
}

async fn settings(State(s): State<AppState>) -> Reply {
    let h = s.history.lock().await;
    reply(
        StatusCode::OK,
        json!({
            "learningUntil": h.learning_until(), "apps": h.app_count(), "file": h.file(),
            "explainModel": ai::model(), "sampleSeconds": 15, "port": s.port, "tshark": capture::TSHARK,
            "reverseDns": s.caches.reverse_dns(),
        }),
    )
}

async fn markers(State(s): State<AppState>) -> Reply {
    let h = s.history.lock().await;
    reply(
        StatusCode::OK,
        json!({
            "learningUntil": h.learning_until(), "apps": h.app_count(), "file": h.file(), "markers": h.current_markers(),
        }),
    )
}

async fn accept_marker(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Reply {
    if !same_origin(&headers, s.port) {
        return error(
            StatusCode::FORBIDDEN,
            "Only this page can change the history.",
        );
    }
    let map = match json_body(&body, 1024) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let mut h = s.history.lock().await;
    if !map
        .get("key")
        .and_then(Value::as_str)
        .is_some_and(|k| h.accept(k))
    {
        return error(StatusCode::BAD_REQUEST, "Unknown marker.");
    }
    let _ = h.save();
    no_content()
}

async fn forget_history(State(s): State<AppState>, headers: HeaderMap) -> Reply {
    if !same_origin(&headers, s.port) {
        return error(
            StatusCode::FORBIDDEN,
            "Only this page can change the history.",
        );
    }
    let _ = s.history.lock().await.forget();
    no_content()
}

async fn owner(State(s): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Reply {
    let ip = q.get("ip").map(String::as_str).unwrap_or("");
    if !facts::valid_ip(ip) {
        return reply(StatusCode::BAD_REQUEST, json!({}));
    }
    let (mut owner, name) = tokio::join!(s.caches.owner(ip), s.caches.reverse_name(ip));
    owner.reverse_dns = name;
    reply(
        StatusCode::OK,
        serde_json::to_value(owner).unwrap_or_default(),
    )
}

async fn names(State(s): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Reply {
    let ips: Vec<String> = q
        .get("ips")
        .map(|v| {
            v.split(',')
                .filter(|ip| facts::valid_ip(ip))
                .take(60)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let mut tasks = tokio::task::JoinSet::new();
    for ip in ips {
        let caches = s.caches.clone();
        tasks.spawn(async move {
            let name = caches.reverse_name(&ip).await;
            (ip, name)
        });
    }
    let mut out = Map::new();
    while let Some(Ok((ip, name))) = tasks.join_next().await {
        out.insert(ip, Value::String(name));
    }
    reply(StatusCode::OK, Value::Object(out))
}

async fn route(Query(q): Query<HashMap<String, String>>) -> Reply {
    let ip = q.get("ip").map(String::as_str).unwrap_or("");
    if ip.parse::<std::net::IpAddr>().is_err() {
        return error(StatusCode::BAD_REQUEST, "A numeric IP address is required.");
    }
    match facts::route(ip).await {
        Some(r) => reply(StatusCode::OK, serde_json::to_value(r).unwrap_or_default()),
        None => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "macOS route information is unavailable for this endpoint.",
        ),
    }
}

async fn process(Query(q): Query<HashMap<String, String>>) -> Reply {
    let pid = q
        .get("pid")
        .and_then(|p| p.parse::<u32>().ok())
        .filter(|p| *p > 0);
    match pid {
        Some(pid) => match facts::process_facts(pid).await {
            Some(f) => {
                let mut v = serde_json::to_value(f).unwrap_or_default();
                let stat = control::process_table()
                    .await
                    .into_iter()
                    .find(|r| r.pid == pid)
                    .map(|r| r.stat)
                    .unwrap_or_default();
                v["paused"] = Value::Bool(control::is_paused(&stat));
                v["launchd"] = control::launchd_label(pid).await;
                reply(StatusCode::OK, v)
            }
            None => error(StatusCode::NOT_FOUND, "Process not found."),
        },
        None => error(StatusCode::NOT_FOUND, "Process not found."),
    }
}

/// stop, pause, resume or restart a process the user owns, after an explicit confirmation in the page.
async fn process_control(
    State(s): State<AppState>,
    axum::extract::Path(action): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    if !["stop", "pause", "resume", "restart"].contains(&action.as_str()) {
        return error(StatusCode::NOT_FOUND, "Unknown process action.");
    }
    if !same_origin(&headers, s.port) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let map = match json_body(&body, 8192) {
        Ok(m) => m,
        Err(r) => return r,
    };
    match control::control(&action, &map).await {
        Ok(v) => reply(StatusCode::ACCEPTED, v),
        Err(message) => {
            control::log_action(json!({
                "action": action, "pid": map.get("pid").cloned().unwrap_or(Value::Null),
                "tree": map.get("tree") == Some(&Value::Bool(true)), "result": "refused", "error": message,
            }));
            error(StatusCode::BAD_REQUEST, &message)
        }
    }
}

async fn egress_status() -> Reply {
    reply(StatusCode::OK, egress::status())
}

/// enable, pause or rule: the same Origin check as every other change, a 1 KB body.
async fn egress_change(
    State(s): State<AppState>,
    axum::extract::Path(action): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    if !same_origin(&headers, s.port) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let map = match json_body(&body, 1024) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let result = match (
        action.as_str(),
        map.get("enabled"),
        map.get("paused"),
        map.get("action"),
    ) {
        ("enable", Some(Value::Bool(on)), _, _) => egress::set_enabled(*on).await,
        ("pause", _, Some(Value::Bool(p)), _) => egress::set_paused(*p),
        ("rule", _, _, Some(Value::String(a)))
            if ["allow", "deny", "remove"].contains(&a.as_str()) =>
        {
            egress::change_rule(a, map.get("host").and_then(Value::as_str).unwrap_or(""))
        }
        ("ports", _, _, _) => {
            egress::change_ports(map.get("ports").and_then(Value::as_str).unwrap_or(""))
        }
        _ => Err("Unknown egress change.".to_string()),
    };
    if let Err(message) = result {
        return error(StatusCode::BAD_REQUEST, &message);
    }
    control::log_action(
        json!({ "type": "egress", "path": format!("/api/egress/{action}"), "input": Value::Object(map) }),
    );
    reply(StatusCode::OK, egress::status())
}

fn query_pid(q: &HashMap<String, String>) -> u32 {
    q.get("pid")
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0)
}

async fn process_tree(Query(q): Query<HashMap<String, String>>) -> Reply {
    match control::tree_preview(query_pid(&q)).await {
        Ok(v) => reply(StatusCode::OK, v),
        Err(message) => error(StatusCode::BAD_REQUEST, &message),
    }
}

async fn process_trust(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Reply {
    let pid = query_pid(&q);
    let path = if pid > 0 {
        control::exe_path(pid).await
    } else {
        None
    };
    let Some(path) = path.filter(|p| p.starts_with('/')) else {
        return error(
            StatusCode::NOT_FOUND,
            "Executable path not visible for this process.",
        );
    };
    let mut facts = control::trust_facts(&path).await;
    let app = q.get("app").map(String::as_str).unwrap_or("");
    facts["firstSeen"] = json!(s.history.lock().await.app_first_seen(app));
    reply(StatusCode::OK, facts)
}

async fn persistence() -> Reply {
    let connections = collect().await.map(|s| s.connections).unwrap_or_default();
    reply(
        StatusCode::OK,
        control::persistence_items(&connections).await,
    )
}

async fn persistence_job(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Reply {
    if !same_origin(&headers, s.port) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let map = match json_body(&body, 4096) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let action = map.get("action").and_then(Value::as_str).unwrap_or("");
    if map.get("confirm") != Some(&Value::Bool(true))
        || !["stop", "disable", "enable"].contains(&action)
    {
        return error(
            StatusCode::BAD_REQUEST,
            "A confirmed action of stop, disable or enable is required.",
        );
    }
    let file = map.get("file").and_then(Value::as_str).unwrap_or("");
    match control::change_job(action, file).await {
        Ok(v) => reply(StatusCode::OK, v),
        Err(message) => error(StatusCode::BAD_REQUEST, &message),
    }
}

async fn explain(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Reply {
    if !same_origin(&headers, s.port) {
        return error(
            StatusCode::FORBIDDEN,
            "Explanations can only be requested from this page.",
        );
    }
    let map = match json_body(&body, 4096) {
        Ok(m) => m,
        Err(r) => return r,
    };
    if s.explaining.swap(true, Ordering::SeqCst) {
        return error(StatusCode::TOO_MANY_REQUESTS, "One explanation at a time.");
    }
    let facts = ai::facts_from(&map, None);
    let result =
        tokio::task::spawn_blocking(move || ai::chat(ai::EXPLAIN_SYSTEM, &facts, 400)).await;
    s.explaining.store(false, Ordering::SeqCst);
    match result {
        Ok(Ok(text)) => reply(
            StatusCode::OK,
            json!({ "text": text, "model": ai::model() }),
        ),
        Ok(Err(message)) => error(StatusCode::BAD_GATEWAY, &message),
        Err(_) => error(StatusCode::BAD_GATEWAY, "The local model did not answer"),
    }
}

async fn models() -> Reply {
    match tokio::task::spawn_blocking(ai::models).await {
        Ok(Ok(list)) => reply(
            StatusCode::OK,
            json!({ "models": list, "defaultModel": ai::model() }),
        ),
        _ => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Ollama is not reachable on this Mac.",
        ),
    }
}

async fn ask(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Reply {
    if !same_origin(&headers, s.port) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let map = match json_body(&body, 2048) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let question = map
        .get("question")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if question.is_empty() || question.chars().count() > 1200 {
        return error(
            StatusCode::BAD_GATEWAY,
            "Enter a question up to 1,200 characters.",
        );
    }
    let context = match map.get("context") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(c)) => c.clone(),
        Some(_) => {
            return error(
                StatusCode::BAD_GATEWAY,
                "Connection context must be an object.",
            );
        }
    };
    let facts = ai::facts_from(
        &context,
        Some(&["process", "pid", "protocol", "local", "remote", "state"]),
    );
    let user = if facts.is_empty() {
        format!("Question: {question}")
    } else {
        format!("Question: {question}\n\nSelected local connection facts:\n{facts}")
    };
    match tokio::task::spawn_blocking(move || ai::chat(ai::ASK_SYSTEM, &user, 350)).await {
        Ok(Ok(text)) => reply(
            StatusCode::OK,
            json!({ "text": text, "model": ai::model() }),
        ),
        Ok(Err(message)) => error(StatusCode::BAD_GATEWAY, &format!("{message}.")),
        Err(_) => error(StatusCode::BAD_GATEWAY, "The local model did not answer."),
    }
}

async fn capture_interfaces() -> Reply {
    match capture::interfaces().await {
        Ok(list) => reply(
            StatusCode::OK,
            serde_json::to_value(list).unwrap_or_default(),
        ),
        Err(message) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("TShark is not available: {message}"),
        ),
    }
}

async fn capture_get(State(s): State<AppState>) -> Reply {
    reply(
        StatusCode::OK,
        serde_json::to_value(s.capture.view()).unwrap_or_default(),
    )
}

async fn capture_start(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Reply {
    if !same_origin(&headers, s.port) {
        return error(
            StatusCode::FORBIDDEN,
            "Capture can only be controlled from this page.",
        );
    }
    let map = match json_body(&body, 2048) {
        Ok(m) => m,
        Err(r) => return r,
    };
    if map.get("confirm") != Some(&Value::Bool(true)) {
        return error(StatusCode::BAD_REQUEST, "Confirmation required.");
    }
    let iface = map.get("interface").and_then(Value::as_str).unwrap_or("");
    let seconds = map.get("seconds").and_then(Value::as_u64).unwrap_or(0) as u32;
    let filter = match map.get("displayFilter") {
        None | Some(Value::Null) => "",
        Some(Value::String(f)) => f.as_str(),
        Some(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "Display filter must be one line and 500 characters or fewer.",
            );
        }
    };
    match s.capture.start(iface, seconds, filter).await {
        Ok(()) => reply(StatusCode::ACCEPTED, json!({ "status": "started" })),
        Err(message) => error(StatusCode::BAD_REQUEST, &message),
    }
}

async fn capture_clear(State(s): State<AppState>, headers: HeaderMap) -> Reply {
    if !same_origin(&headers, s.port) {
        return error(
            StatusCode::FORBIDDEN,
            "Capture can only be controlled from this page.",
        );
    }
    s.capture.clear();
    no_content()
}

async fn set_reverse_dns(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Reply {
    if !same_origin(&headers, s.port) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let map = match json_body(&body, 1024) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let Some(enabled) = map.get("enabled").and_then(Value::as_bool) else {
        return error(StatusCode::BAD_REQUEST, "enabled must be true or false.");
    };
    s.caches.set_reverse_dns(enabled);
    // The setting still applies until restart when the file cannot be written.
    let _ = settings::save_reverse_dns(enabled);
    reply(StatusCode::OK, json!({ "reverseDns": enabled }))
}

async fn home_estimate() -> Reply {
    reply(StatusCode::OK, settings::home_estimate())
}

fn host_of_remote(remote: &str) -> &str {
    if let Some(rest) = remote.strip_prefix('[') {
        return rest.split(']').next().unwrap_or_default();
    }
    match (remote.find(':'), remote.rfind(':')) {
        (Some(a), Some(b)) if a == b && a > 0 => &remote[..a],
        _ => remote,
    }
}

fn domain_of(name: &str) -> String {
    let parts: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    parts[parts.len().saturating_sub(2)..].join(".")
}

/// Current destinations with offline coordinates for the Star Atlas.
async fn atlas(State(s): State<AppState>) -> Reply {
    let snapshot = match collect().await {
        Ok(snap) => snap,
        Err(message) => {
            return reply(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "error": message, "geoip": "unknown", "destinations": [] }),
            );
        }
    };
    struct Dest {
        processes: Vec<String>,
        pids: Vec<u32>,
        ports: Vec<String>,
        count: u32,
    }
    let mut order: Vec<String> = Vec::new();
    let mut by_ip: HashMap<String, Dest> = HashMap::new();
    for row in &snapshot.connections {
        let ip = host_of_remote(&row.remote).to_string();
        if ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let d = by_ip.entry(ip.clone()).or_insert_with(|| {
            order.push(ip.clone());
            Dest {
                processes: vec![],
                pids: vec![],
                ports: vec![],
                count: 0,
            }
        });
        let port = row
            .remote
            .rsplit(':')
            .next()
            .unwrap_or_default()
            .to_string();
        if !d.processes.contains(&row.process) {
            d.processes.push(row.process.clone());
        }
        if !d.pids.contains(&row.pid) {
            d.pids.push(row.pid);
        }
        if !d.ports.contains(&port) {
            d.ports.push(port);
        }
        d.count += 1;
    }
    let lookup_ips = order.clone();
    let geo = tokio::task::spawn_blocking(move || geoip::lookup(&lookup_ips))
        .await
        .unwrap_or(geoip::Lookup {
            status: "error",
            error: Some("GeoIP lookup stopped".into()),
            places: HashMap::new(),
        });
    let mut tasks = tokio::task::JoinSet::new();
    for ip in order.iter().filter(|ip| !geoip::is_non_public(ip)).cloned() {
        let caches = s.caches.clone();
        tasks.spawn(async move {
            let name = caches.reverse_name(&ip).await;
            (ip, name)
        });
    }
    let mut names = HashMap::new();
    while let Some(Ok((ip, name))) = tasks.join_next().await {
        names.insert(ip, name);
    }
    let destinations: Vec<Value> = order
        .iter()
        .map(|ip| {
            let d = &by_ip[ip];
            let name = names.get(ip).cloned().unwrap_or_default();
            let place = geo.places.get(ip);
            json!({
                "ip": ip, "domain": if name.is_empty() { String::new() } else { domain_of(&name) }, "name": name,
                "local": geoip::is_non_public(ip), "processes": d.processes, "pids": d.pids, "ports": d.ports,
                "connections": d.count, "lat": place.map(|p| p.lat), "lon": place.map(|p| p.lon),
                "city": place.map(|p| p.city.as_str()).unwrap_or(""), "country": place.map(|p| p.country.as_str()).unwrap_or(""),
            })
        })
        .collect();
    reply(
        StatusCode::OK,
        json!({
            "sampledAt": snapshot.sampled_at, "geoip": geo.status, "geoipError": geo.error,
            "attribution": { "text": "IP geolocation by DB-IP.com", "url": "https://db-ip.com", "license": "CC BY 4.0" },
            "destinations": destinations,
        }),
    )
}

// The page ships inside the binary: nothing is read from disk at request time.
const ASSETS: &[(&str, &str, &[u8])] = &[
    (
        "index.html",
        "text/html; charset=utf-8",
        include_bytes!("../../public/index.html"),
    ),
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../public/app.js"),
    ),
    (
        "howitworks.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../public/howitworks.js"),
    ),
    (
        "console.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../public/console.js"),
    ),
    (
        "flight-map.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../public/flight-map.js"),
    ),
    (
        "security.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../public/security.js"),
    ),
    (
        "persistence-view.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../public/persistence-view.js"),
    ),
    (
        "persistence.css",
        "text/css; charset=utf-8",
        include_bytes!("../../public/persistence.css"),
    ),
    (
        "styles.css",
        "text/css; charset=utf-8",
        include_bytes!("../../public/styles.css"),
    ),
    (
        "theme.css",
        "text/css; charset=utf-8",
        include_bytes!("../../public/theme.css"),
    ),
    (
        "console.css",
        "text/css; charset=utf-8",
        include_bytes!("../../public/console.css"),
    ),
    (
        "security.css",
        "text/css; charset=utf-8",
        include_bytes!("../../public/security.css"),
    ),
    (
        "packet-details.css",
        "text/css; charset=utf-8",
        include_bytes!("../../public/packet-details.css"),
    ),
    (
        "process-table.css",
        "text/css; charset=utf-8",
        include_bytes!("../../public/process-table.css"),
    ),
    (
        "egress-view.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../public/egress-view.js"),
    ),
    (
        "egress.css",
        "text/css; charset=utf-8",
        include_bytes!("../../public/egress.css"),
    ),
    (
        "star-atlas.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../../public/star-atlas.js"),
    ),
    (
        "star-atlas.css",
        "text/css; charset=utf-8",
        include_bytes!("../../public/star-atlas.css"),
    ),
];

async fn static_file(method: Method, request: Request) -> Reply {
    if method != Method::GET && method != Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET")],
            "Read-only monitor",
        )
            .into_response();
    }
    let path = request.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match ASSETS.iter().find(|(name, _, _)| *name == path) {
        Some((_, content_type, body)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, *content_type),
                (header::CACHE_CONTROL, "no-store"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            *body,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "Not found",
        )
            .into_response(),
    }
}

/// Background sampling builds the local baseline even when the page is closed.
async fn sampler(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    loop {
        tick.tick().await;
        let Ok(snapshot) = collect().await else {
            continue;
        };
        let mut ips: Vec<String> = snapshot
            .connections
            .iter()
            .map(|r| {
                let host = r
                    .remote
                    .rfind(':')
                    .map_or(r.remote.as_str(), |i| &r.remote[..i]);
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string()
            })
            .collect();
        ips.sort();
        ips.dedup();
        for ip in ips.iter().take(80) {
            state.caches.reverse_name(ip).await;
        }
        let names = state.caches.names_snapshot();
        let mut h = state.history.lock().await;
        h.observe(&snapshot, &names, history::now_ms());
        if let Err(e) = h.save() {
            eprintln!("Could not save history: {e}");
        }
    }
}

#[tokio::main]
async fn main() {
    if !cfg!(target_os = "macos") {
        eprintln!("Local Network Watcher reads macOS network activity only.");
        std::process::exit(2);
    }
    if std::env::args().any(|a| a == "--snapshot") {
        match collector::snapshot() {
            Ok(s) => println!("{}", serde_json::to_string(&s).unwrap_or_default()),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(3);
            }
        }
        return;
    }
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(4317);
    let state = AppState {
        port,
        history: Arc::new(Mutex::new(history::History::load())),
        caches: Arc::new(facts::Caches::default()),
        capture: capture::Capture::new(),
        explaining: Arc::new(AtomicBool::new(false)),
    };
    state.caches.set_reverse_dns(settings::load_reverse_dns());
    tokio::spawn(sampler(state.clone()));
    egress::init().await;

    let app = Router::new()
        .route("/api/connections", get(connections))
        .route("/api/settings", get(settings))
        .route("/api/settings/reverse-dns", post(set_reverse_dns))
        .route("/api/home-estimate", get(home_estimate))
        .route("/api/atlas", get(atlas))
        .route("/api/markers", get(markers))
        .route("/api/markers/accept", post(accept_marker))
        .route("/api/history", axum::routing::delete(forget_history))
        .route("/api/owner", get(owner))
        .route("/api/names", get(names))
        .route("/api/route", get(route))
        .route("/api/process", get(process))
        .route("/api/process/tree", get(process_tree))
        .route("/api/process/trust", get(process_trust))
        .route("/api/process/{action}", post(process_control))
        .route("/api/egress", get(egress_status))
        .route("/api/egress/{action}", post(egress_change))
        .route("/api/persistence", get(persistence))
        .route("/api/persistence/job", post(persistence_job))
        .route("/api/explain", post(explain))
        .route("/api/models", get(models))
        .route("/api/ask", post(ask))
        .route("/api/capture/interfaces", get(capture_interfaces))
        .route(
            "/api/capture",
            get(capture_get).post(capture_start).delete(capture_clear),
        )
        .fallback(static_file)
        .layer(DefaultBodyLimit::max(8 * 1024))
        .layer(middleware::from_fn(host_guard))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Could not listen on 127.0.0.1:{port}: {e}");
            std::process::exit(1);
        }
    };
    println!("Local Network Watcher is listening at http://127.0.0.1:{port}");
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        eprintln!("Server stopped: {e}");
    }
}

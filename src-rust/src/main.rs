//! Local Network Watcher: one binary that collects, serves the page and answers its API on 127.0.0.1.

mod ai;
mod capture;
mod collector;
mod facts;
mod history;

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
            Some(f) => reply(StatusCode::OK, serde_json::to_value(f).unwrap_or_default()),
            None => error(StatusCode::NOT_FOUND, "Process not found."),
        },
        None => error(StatusCode::NOT_FOUND, "Process not found."),
    }
}

/// Sends SIGTERM to a process the user owns, after an explicit confirmation in the page.
async fn stop_process(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Reply {
    if !same_origin(&headers, s.port) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let map = match json_body(&body, 1024) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let pid = map
        .get("pid")
        .and_then(Value::as_u64)
        .filter(|p| *p >= 2 && *p <= i32::MAX as u64)
        .map(|p| p as u32);
    let Some(pid) = pid.filter(|_| map.get("confirm") == Some(&Value::Bool(true))) else {
        return error(
            StatusCode::BAD_REQUEST,
            "Explicit confirmation and a valid process ID are required.",
        );
    };
    let me = std::process::id();
    if pid == me {
        return error(
            StatusCode::BAD_REQUEST,
            "The monitor itself cannot be stopped here.",
        );
    }
    let Some(target) = facts::process_facts(pid).await else {
        return error(
            StatusCode::BAD_REQUEST,
            "That process is no longer running.",
        );
    };
    if target.user != facts::current_user() {
        return error(
            StatusCode::BAD_REQUEST,
            "Only processes owned by your current macOS account can be stopped.",
        );
    }
    let mut ancestor = facts::parent_of(me).await;
    for _ in 0..12 {
        if ancestor <= 1 {
            break;
        }
        if ancestor == pid {
            return error(
                StatusCode::BAD_REQUEST,
                "A parent process of this monitor cannot be stopped here.",
            );
        }
        ancestor = facts::parent_of(ancestor).await;
    }
    // SAFETY: plain kill(2) with a validated pid and SIGTERM.
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } != 0 {
        return error(StatusCode::BAD_REQUEST, "The signal could not be sent.");
    }
    let name = target
        .command
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_string();
    reply(
        StatusCode::ACCEPTED,
        json!({ "status": "signal-sent", "signal": "SIGTERM", "pid": pid, "process": name }),
    )
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
    tokio::spawn(sampler(state.clone()));

    let app = Router::new()
        .route("/api/connections", get(connections))
        .route("/api/settings", get(settings))
        .route("/api/markers", get(markers))
        .route("/api/markers/accept", post(accept_marker))
        .route("/api/history", axum::routing::delete(forget_history))
        .route("/api/owner", get(owner))
        .route("/api/names", get(names))
        .route("/api/route", get(route))
        .route("/api/process", get(process))
        .route("/api/process/stop", post(stop_process))
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

# Local Network Watch

A local, read-only monitor for current network connections on macOS. The app polls `lsof` on this device and shows the process, local endpoint, remote endpoint, protocol, and socket state. It does not capture packet contents, count bytes, resolve hostnames, persist logs, or change firewall rules.

## Run

Requires Rust 1.85 or newer, Node.js 20 or newer, and macOS. The monitor and socket parser run in Rust; the local web preview is served by Node.js.

```sh
cargo build
npm start
```

Open <http://127.0.0.1:4317>. The server binds to loopback only. Set `PORT` to use another local port.

## Scope

- Read-only live connection snapshots, refreshed every three seconds.
- “First seen” means first observed since this page was opened; it is not a threat verdict.
- Recent events live in browser memory and disappear when the page closes.
- Blocking and app isolation are not implemented. Buttons that would make those changes are intentionally absent.
- `lsof` may not expose details for every protected macOS process. The app does not ask for administrator access.

No data is sent to a remote service.

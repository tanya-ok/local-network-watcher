# Local Network Watcher

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
## Capture

The application can optionally capture packet headers using the bundled TShark binary (`/Applications/Wireshark.app/Contents/MacOS/tshark`). Capture is **off by default** and can be started from the **Capture** tab in the UI. A confirmation dialog explains that:

* only packet **headers** are read,
* data lives **only in page memory**,
* nothing is written to disk or sent anywhere.

Capture runs for a configurable duration (5 – 30 seconds, default 10 s) and a maximum of 3000 packets. Only one capture may run at a time. Results are cleared when the page is closed or when the **Clear** button is used.

## Map and explanations

- **Map**: apps on the left, destinations on the right. Lines show live connections; after a capture their width follows captured bytes. Names come from reverse DNS and from TLS server names seen in a capture.
- **Owner lookup**: selecting a destination runs `whois` for that address. This asks the public internet registry about the address.
- **Explain with local AI**: sends the shown facts to a model in Ollama on this Mac (`127.0.0.1:11434`, default `gemma4:26b`, override with `EXPLAIN_MODEL`). Nothing goes to a cloud model.
- **Layers**: a selected packet is shown layer by layer (OSI 7, 4, 3, 2, 1) with a short explanation of each.

## Attention markers

The server samples connections every 15 seconds, also while the page is closed, and learns what is normal for 24 hours. After that it marks, with one plain sentence: an app online for the first time, a new destination for an app, an unusual port, night activity (00:00 to 06:00) from an app that is rarely online then, and a sudden traffic burst. "Looks normal" silences a marker for good.

History holds metadata only (app names, destination groups by reverse-DNS domain or network block, ports, times), never packet contents. It lives in `~/Library/Application Support/LocalWatch/history.json` (folder `0700`, file `0600`). Settings has a button to delete it. `LOCAL_WATCH_DATA` and `LOCAL_WATCH_LEARNING_HOURS` override the folder and the learning period.

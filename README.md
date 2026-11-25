# Local Network Watcher

![Where things go: an illustrative view of local network activity](docs/images/readme-hero.svg)

*Illustrative UI artwork with synthetic labels, not a live snapshot from a specific Mac.*

*A live view of connections open on this Mac.*

Site: <https://tanya-ok.github.io/local-network-watcher/> · Security: [SECURITY.md](SECURITY.md)

Local Network Watcher is a local-first macOS network observatory. It shows open process-to-endpoint connections, process-level traffic counters, connection changes, a live route diagram, and selected packet fields from an optional TShark capture. It is designed to help people understand and investigate network activity; a new connection or unusual pattern is a prompt to inspect, not proof of malicious behavior.

## Run

Requires macOS and Rust 1.85 or newer. It is one Rust binary: it collects, serves the page (built into the binary) and answers its API on `127.0.0.1` only.

```sh
cargo run --release
```

Open <http://127.0.0.1:4317>. The server binds to loopback only. Set `PORT` to use another local port.

### As a Dock app

```sh
./scripts/macos/install-app.sh --dock
```

This builds the release binary and installs `~/Applications/Local Network Watcher.app` with the binary inside it. The app starts the server if it is not running and opens the page in a Brave app window, or in the default browser. The server keeps running after the window closes; the log is `~/Library/Logs/LocalNetworkWatcher.log`. `--dock` adds the app to the Dock once. Rerun the script after pulling changes.

## What it observes

- Connection snapshots are refreshed every three seconds from `lsof`; process byte and packet totals come from `nettop` and are not attributed to individual sockets. The optional process inventory is assembled from `ps` and `nettop`; the checkbox can include zero-valued processes visible in that snapshot. This is not guaranteed to equal every row Activity Monitor can show. The connection map remains limited to observed open remote sockets.
- **Process traffic** lists 25 entries per page. Processes with a non-zero current rate appear first, followed by the highest observed rate. Search and the “include processes with no network counters” option apply to the full snapshot before paging.
- The server samples every 15 seconds to build a local baseline. It stores process names, destination groups, ports, and timestamps in `~/Library/Application Support/LocalWatch/history.json` with restrictive file permissions. The Settings view can delete this history.
- Reverse DNS requests use the Mac's configured resolver (often the router). Settings > Address names turns them off; addresses are then shown as numbers and no reverse DNS queries are sent. The choice is stored in `settings.json` in the data folder; `LOCAL_WATCH_REVERSE_DNS=0` sets the default to off. Selecting an external address for owner details can run `whois` against a public registry. Those lookups leave the Mac; the app does not upload its packet capture or connection history.
- “First seen” and other attention markers describe what this local baseline observed. They are investigation cues, not threat verdicts.
- macOS may hide details for protected processes. Normal monitoring does not request administrator access.
- Process control is limited to processes owned by your macOS account, never PID 1, the monitor or its parent processes, and never uses sudo. Each action needs a confirmation dialog:
  - Stop: SIGTERM. May close unsaved work.
  - Stop tree: previews child processes first, then sends SIGTERM to children (deepest first) and the parent. Refused if the tree changed since the preview or contains a process of another account.
  - Pause and resume: SIGSTOP and SIGCONT. Reversible. A paused GUI app freezes until resumed.
  - Restart: only for launchd jobs found in `launchctl print gui/<uid>`, using `launchctl kickstart -k`. Unavailable for other processes, including GUI app instances registered by LaunchServices.
- Every process action, including refusals, is appended as one JSON line to `actions.log` in the data folder (`LOCAL_WATCH_DATA` or `~/Library/Application Support/LocalWatch`), file mode 0600.
- Process control does not block network access. Network isolation is not implemented.
- **Egress** is an optional local proxy, off by default. It listens on loopback with two profiles: open (`127.0.0.1:4318`, everything passes except blocked domains) and strict (`127.0.0.1:4319`, only the allow list passes); `LOCAL_WATCH_EGRESS_OPEN_PORT` and `LOCAL_WATCH_EGRESS_STRICT_PORT` change the ports. Both always refuse a built-in list of hosted AI services and trackers, and refuse local network addresses. The policy is `egress.json` in the data folder. Each request is appended to `egress.log` in the data folder (host, port, result, reason, bytes), file mode 0600. Request contents are not read: HTTPS passes as an opaque tunnel. Only programs configured to use the proxy are covered; it does not force other traffic through itself. If a port is taken, the Egress tab shows which profile did not start. Only destination ports on the allowed list pass (80 and 443 by default, editable on the Egress tab). A direct IP address is refused unless that exact public address is on the allow list, because domain lists cannot judge a bare address. `egress.log` rotates at 5 MB and keeps the last 3 files.
- This version does not enforce firewall rules or identify a connection as malicious.

## Egress daemon

For a Mac where another account (for example an AI agent account) must reach the network only through the proxy, the proxy can run as a system service under its own hidden account.

- `local-network-watcher egress-daemon` runs only the two proxy listeners and a control socket (`/var/run/local-watch-egress/control.sock`, `LOCAL_WATCH_EGRESS_SOCKET`). Its data dir is `/Library/Application Support/LocalWatchEgress` (`LOCAL_WATCH_EGRESS_DATA`), mode 0700, with `egress.json` and `egress.log` at 0600, owned by the service account. Other accounts cannot read the journal files.
- Install: `sudo scripts/macos/install-egress-daemon.sh [--dns]` after `cargo build --release --locked`. It creates `_localwatch` (hidden, uid below 500, no shell), installs the binary root-owned to `/usr/local/libexec/local-watch-egress/`, and bootstraps `com.localwatch.egress` (RunAtLoad, KeepAlive). Remove with `sudo scripts/macos/uninstall-egress-daemon.sh [--purge]`.
- When the socket answers at startup, the app on 4317 does not open its own proxy listeners and shows the daemon's status. Without the daemon, the app runs the proxy in-process as before.
- Who may change rules is decided from the kernel uid, not from the Origin header. On the socket the daemon reads the peer uid with `getpeereid`. On 4317 the app finds the uid of the TCP client from the kernel socket table (`net.inet.tcp.pcblist_n`, exact local and remote ports) or, for its own account, from `lsof`; a client it cannot identify counts as uid unknown.
- Anyone may read the status. A change (enable, pause, rule, ports) applies at once only for an admin uid. Admins are the members of group `admin` by default; set `{"admins":[501]}` (uids) or `{"admins":"group:staff"}` in `daemon.json` in the daemon's data dir, or `LOCAL_WATCH_EGRESS_ADMINS`. A change from any other uid becomes a pending change with an id. It is applied only after an admin approves it: `local-network-watcher egress approve <id>` or `deny <id>`, or the Approve button on the Egress tab. Pending changes expire after 15 minutes (`LOCAL_WATCH_EGRESS_PENDING_TTL`, seconds). `local-network-watcher egress status` and `egress pending` read the daemon.
- The journal records the client account (uid and name) for each proxy connection, and each change as pending, applied, approved, denied or expired.
- DNS: the proxy resolves names itself, but a program that uses the system resolver sends DNS outside the proxy. `--dns` adds a root LaunchDaemon that runs `tcpdump -l -n -i pflog0 udp port 53` into `/var/log/local-watch-egress/dns.log` (root, group `_localwatch`, 0640, rotated by newsyslog). The daemon shows the query names as DNS entries marked "resolver, not proxied". pflog0 only sees packets that match a pf rule with the `log` keyword, so the pf rule that passes the agent account's DNS must carry `log`. That rule lives in the local OS configuration, not in this repository. Without pflog data the Egress tab says DNS visibility is off.

## Capture

The application can optionally capture decoded packet fields using TShark from an installed Wireshark app at `/Applications/Wireshark.app/Contents/MacOS/tshark`. The binary is a local dependency, not bundled with this repository. Capture is **off by default** and can be started from the **Capture** tab in the UI. A confirmation dialog explains that:

* TShark decodes selected frame, Ethernet, IP, TCP/UDP, DNS and TLS fields; packet payload and raw hex bytes are not requested,
* data stays **in the local app's memory** and is cleared by Clear, a new capture, or closing the page,
* capture data is not uploaded or written to a capture file by this app.

Capture runs for a configurable duration (5, 10 or 30 seconds; default 10) and stops after at most 3000 packets. Only one capture may run at a time. An optional Wireshark display filter (`-Y`, for example `dns` or `tcp.port == 443`) limits which decoded packets TShark returns to the UI; the short live capture can still observe packets that do not match the filter. The separate search box is plain text over displayed fields, not a display filter. Process names in the packet table are best-effort matches by local port against the current connection snapshot, not kernel-level packet attribution. Permission to capture depends on this Mac's Wireshark/dumpcap setup; invalid filters and TShark errors are shown in the tab.

## Map and explanations

- **Map**: apps on the left, destinations on the right. Lines show live connections; after a capture their width follows captured bytes. Names can come from reverse DNS and from TLS server names seen in a capture.
- Click a line, app or destination to open its inspector. The selected route stays highlighted while the live map refreshes.
- **Security**: review local baseline markers, inspect a process's signature, parent chain, folder and sockets, and stop, stop as a tree, pause, resume or (for launchd jobs) restart it after confirmation. These actions do not block network traffic.
- **Map console**: guided commands for live connections, process inspection, temporary TShark capture, local model questions and `stop`, `tree`, `pause`, `resume` and `restart` for a PID. It is not a general-purpose shell. `restart` works only for launchd jobs in your user domain.
- **Flight Map**: choose one currently open connection and follow its process, socket, transport, interface, next-hop gateway and remote endpoint. Process names, socket endpoints and macOS route lookup are real local observations. Intermediate internet routers and the remote socket are outside this laptop's view. Process traffic totals are aggregate counts, not per-socket measurements. Click a stop for a plain explanation and its exact evidence.
- **Map and Flight Map visuals**: the route plane and airport language are original reading aids. Animated paths do not claim to be packet-level traces. Packet evidence appears only after a TShark capture.
- **Owner lookup**: selecting a destination runs `whois` for that address. This asks the public internet registry about the address.
- **Explain with local AI**: sends the selected facts to Ollama on this Mac (`127.0.0.1:11434`, default `gemma4:26b`, override with `EXPLAIN_MODEL`). It does not call a cloud model.
- **Network console AI**: `models` lists locally installed Ollama models; `ask <question>` uses the configured model and, when one is selected, only that connection's process and endpoint fields.
- **Layers**: a selected packet shows a simple OSI explanation and expandable TShark-decoded fields. This is a curated field view, not Wireshark's complete protocol tree. The app does not decrypt TLS or show raw packet bytes. Plain-text protocol metadata, including some HTTP details, may be visible.

## License and authorship

Local Network Watcher is open source under the MIT License. Copyright and license notices must be retained in copies or substantial portions. The app credits its author, Tanya Babitskaya.

## Attention markers

The server samples connections every 15 seconds, also while the page is closed, and learns what is normal for 24 hours. After that it marks, with one plain sentence: an app online for the first time, a new destination for an app, an unusual port, night activity (00:00 to 06:00) from an app that is rarely online then, and a sudden traffic burst. "Looks normal" silences a marker for good.

History holds metadata only (app names, destination groups by reverse-DNS domain or network block, ports, times), never packet contents. It lives in `~/Library/Application Support/LocalWatch/history.json` (folder `0700`, file `0600`). Settings has a button to delete it. `LOCAL_WATCH_DATA` and `LOCAL_WATCH_LEARNING_HOURS` override the folder and the learning period.

## Process trust card

The Security view inspector shows a trust card for the selected process, served by `GET /api/process/trust?pid=<pid>&app=<name>`:

- Code signature status, signing authority chain and Team ID from `codesign -dv --verbose=2`.
- Gatekeeper result and notarization source from `spctl --assess --type execute -vv`.
- Binary path, with a neutral note when it lives in `/tmp`, `/private/var/folders` or `~/Downloads`, or is unsigned or ad hoc signed.
- First time the app name appeared in local history.

Results are cached per binary path while the server runs. The card reports facts and their limits; it is not a malware verdict.

## Persistence

The Persistence tab lists launchd plists from `~/Library/LaunchAgents`, `/Library/LaunchAgents` and `/Library/LaunchDaemons` via `GET /api/persistence`. Apple entries under `/System/Library` appear only when they match a networked process. Each entry shows Label, Program or ProgramArguments, RunAtLoad and KeepAlive, and is matched to processes with open connections by the PID from `launchctl list` or by executable path. Plists are parsed with `plutil` and never modified; only the actions below load or unload them. For testing, set `LOCAL_WATCH_PERSISTENCE_DIRS` to a colon-separated list of folders to scan instead.

For your own LaunchAgents (`~/Library/LaunchAgents`) each card offers **Stop until next login** (`launchctl bootout`), **Stop and keep off** (`bootout` plus `launchctl disable`) and **Turn back on** (`enable` plus `bootstrap`). Every action needs a confirmation and is written to `actions.log`. Global agents and daemons in `/Library` need an administrator and are not changed; Apple jobs are never changed. For Homebrew services, `brew services stop <name>` does the same as Stop and keep off.

## Star Atlas and offline GeoIP

The Star Atlas tab places open destinations on an equal-area world map. Locations come only from a local db-ip "IP to City Lite" file. The app never calls an online geolocation service and never looks up the public address of this Mac. Private, loopback, link-local, CGNAT and multicast addresses get no location.

The database file is not in this repository. To add it:

1. Download the current monthly `dbip-city-lite-YYYY-MM.mmdb.gz` from https://db-ip.com/db/download/ip-to-city-lite.
2. Unpack it and place it at the default path:

   ```fish
   mkdir -p ~/Library/Application\ Support/LocalWatch/geoip
   gunzip -c ~/Downloads/dbip-city-lite-*.mmdb.gz > ~/Library/Application\ Support/LocalWatch/geoip/dbip-city-lite.mmdb
   ```

3. Reload the tab. To use another path, start the server with `LOCAL_WATCH_GEOIP=/path/to/file.mmdb`.

Without the file, `/api/atlas` reports `geoip: "missing"` and the tab places destinations on a ring around home. Home is a marker you set in the tab; it is stored only in this browser. Dot size is approximate because byte counters are per process, not per connection.

IP geolocation by [DB-IP.com](https://db-ip.com), licensed under CC BY 4.0.

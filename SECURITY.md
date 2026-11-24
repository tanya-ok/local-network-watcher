# Security policy

Local Network Watcher reads network state on the Mac it runs on. It binds to `127.0.0.1` only, captures packets only after a confirmation in the page, keeps captures in memory, and stores connection metadata (app names, destination groups, ports, times) in `~/Library/Application Support/LocalWatch/`.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting: the **Report a vulnerability** button on the Security tab of this repository. Do not open a public issue for a security problem.

Useful in a report: the version or commit, macOS version, what you did, what you expected and what happened. Please do not include captures of real traffic.

## Scope

In scope: the local server and its API, the capture flow, the history store, the Rust collector, and the browser page.

Out of scope: macOS tools the project calls (`lsof`, `nettop`, `tshark`, `whois`), Ollama and local models, and anything that requires an attacker who already runs code as your user.

## Supported versions

Only the latest commit on `main` is supported.

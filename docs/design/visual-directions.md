# Visual directions

Three original directions for richer network visuals. Reference for the genre: Little Snitch Network Monitor (world map of destinations, per-process traffic history, process > domain > host list with inline bars, time-range scrubber). Its look, icons, colors and layout are not reused. The reference came from general knowledge of the product; the help pages were not fetched in this pass.

Mockups use synthetic data only (documentation range 203.0.113.0/24, example.* domains). Open `mockups/*.html` offline; light and dark follow `prefers-color-scheme`.

## Data available today

| Source | Gives | Limits |
|---|---|---|
| lsof snapshot | process, PID, socket, remote IP:port, state | presence only, no bytes |
| nettop counters | bytes in/out per process | not per socket or per host |
| history.json baseline | usual per-process range, first-seen destinations | coarse buckets |
| TShark capture | per-flow bytes, DNS names | only while a capture runs, needs privileges |

Not supported yet: per-host or per-socket bytes outside a capture; any geography. A map needs a local offline GeoIP DB (MaxMind GeoLite2 City/Country .mmdb or db-ip lite), read locally, never a web lookup.

## A. Flight Log (mockups/a-flight-log.html)

Extends the current Flight Map: departures board plus route fan.

- Palette: reuses `public/theme.css` tokens. Light `--paper #f3f0e6`, `--sheet #faf8f0`, `--ink #26342d`, `--moss #53725b` (received), `--rust #ad6046` (sent, first seen), `--blue #576f8d` (selection). Dark `--paper #171d20`, `--sheet #20282a`, `--ink #e7e5dc`, `--moss #9db99d`, `--rust #d58b69`, `--blue #9dbbd0`.
- Type: ui-monospace for labels and numbers, uppercase tracked headings; system sans for prose.
- Visuals: time scrubber with window brackets (nettop sampled into history buckets); process > domain > host tree with split in/out bars (process bytes from nettop; domain and host rows from lsof presence, bytes only during TShark); per-process sparkline (nettop series); route fan from this Mac to destinations (lsof).
- Support: supported now except host-level bytes.

## B. Tide Chart (mockups/b-tide-chart.html)

Traffic as water level against a baseline band. Calm, anomaly-first.

- Palette: light `--paper #eef1ee`, `--sheet #f8faf8`, `--ink #1f2b2a`, `--hi #2f6f73`, `--lo #8aa9a6`, `--warn #b0743c`, `--line #d3dbd8`. Dark `--paper #121a1c`, `--sheet #1a2426`, `--ink #e3ebe8`, `--hi #7cc0bf`, `--lo #3f6664`, `--warn #e0a36a`, `--line #2f3d3f`.
- Type: Georgia serif titles, monospace data.
- Visuals: stacked area of in/out (nettop) over a grey usual-range band (history.json); per-process sparkline inside its own baseline band; event strip of first-seen destinations (lsof diff against history.json), ring when outside baseline.
- Support: supported now; band quality depends on how much history exists.

## C. Star Atlas (mockups/c-star-atlas.html)

Destinations as stars on a graticule, no country fills or borders.

- Palette: light `--paper #f5f3ef`, `--sheet #fffdf9`, `--ink #2a2733`, `--a #5a5a9a`, `--b #9a6a3a`, `--c #4a7a6a`, `--line #e0dbe2`. Dark `--paper #14131a`, `--sheet #1c1b24`, `--ink #e8e4ef`, `--a #a6a6e0`, `--b #e0b07a`, `--c #8fc7b4`, `--line #33303e`.
- Type: light, widely tracked sans headings; monospace labels.
- Visuals: equal-area graticule with arcs from home (lsof remote IPs plus GeoIP); dot area from owning process share (nettop); dimmed dots for earlier in the window; process bar key (nettop).
- Support: needs a local GeoIP DB. Without it, place unknown IPs on a ring around home. Dot sizing is approximate because bytes are per process.

## Local model recommendation

`ollama list` (2026-11-25): all candidate models report the vision capability.

| Use | Model | Note |
|---|---|---|
| Screenshot critique, fast | gemma4:12b | tried, about a minute, useful output |
| Screenshot critique, deeper | gemma4:31b-it-q8_0, qwen3.8:27b-q8_0 | slower, for final passes |
| SVG/CSS iteration | qwen3.8:27b-q8_0, gpt-oss:120b | coding drafts; review every diff |
| Bulk, cheap | qwen3.5:9b, gemma4:26b (ask-local default) | first drafts |

Loop tried: headless Chrome `--headless --screenshot --window-size=1200,800` on `mockups/a-flight-log.html` to `screenshots/a-flight-log.png`, then the Ollama API on 127.0.0.1:11434 with gemma4:12b. Fully local. Its critique, summarized:

- Thin monospace metadata (IP:port, "first seen") is hard to scan.
- Route fan becomes a hairball with many destinations; needs aggregation.
- Muted moss and rust on the dark sheet and grey subtext may miss contrast targets; check WCAG.
- Process rows and host rows share weight; strengthen primary rows.
- List and route panel need more separation.

Next steps: raise subtext contrast, cap the route fan to top N plus "others", heavier process rows.

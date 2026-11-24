// Visual explanations: colored map, socket path, packet envelopes, TCP handshake.
// No motion: every diagram is static and stepped by clicks.

const PALETTE = ['#4f7a8c', '#7a6a9e', '#5f8a5a', '#b0704f', '#8a5d7a', '#3f8a86', '#9a7d3a', '#6b7fb0', '#a0607a', '#5a7f6e'];
function colorFor(name) {
  let h = 0;
  for (const ch of String(name)) h = (h * 31 + ch.codePointAt(0)) >>> 0;
  return PALETTE[h % PALETTE.length];
}

// Colour by role: system grey, apps blue, needs-a-look red (always with a label or "!").
const ROLE = { system: '#8a8f8a', app: '#3f6fa8', flag: '#b5473f' };
function roleOf(name) {
  return describeProcess(name).kind === 'Apple system' ? 'system' : 'app';
}
function roleColor(name) { return ROLE[roleOf(name)]; }

// 1. Colors on the map
const prevRenderMap = renderMap;
renderMap = function () {
  prevRenderMap();
  mapSvg.querySelectorAll('.map-line').forEach((p) => {
    const app = p.dataset.key.split('|')[0];
    p.style.stroke = p.classList.contains('flag') ? ROLE.flag : roleColor(app);
    p.style.strokeDasharray = roleOf(app) === 'system' ? '4 3' : '';
  });
  mapSvg.querySelectorAll('.map-node[data-app]').forEach((g) => {
    const flagged = g.classList.contains('flag');
    const c = flagged ? ROLE.flag : roleColor(g.dataset.app);
    const circle = g.querySelector('circle');
    circle.style.stroke = c;
    circle.style.fill = c;
    const label = g.querySelector('text');
    label.style.fill = 'var(--ink)';
    if (flagged && !label.textContent.startsWith('! ')) label.textContent = `! ${label.textContent}`;
  });
  mapSvg.querySelectorAll('.map-node[data-ip]').forEach((g) => {
    const circle = g.querySelector('circle');
    if (g.classList.contains('flag')) { circle.style.stroke = ROLE.flag; circle.style.fill = '#f6e1de'; const label = g.querySelector('text'); if (!label.textContent.startsWith('! ')) label.textContent = `! ${label.textContent}`; return; }
    circle.style.stroke = isPrivate(g.dataset.ip) ? 'var(--blue)' : 'var(--ink)';
    circle.style.fill = 'var(--sheet)';
  });
};

// Shared helpers for clickable diagrams
function diagram(container, { title, svg, parts, intro }) {
  const box = document.createElement('div');
  box.className = 'hiw';
  box.innerHTML = `<div class="hiw-head"><b>${esc(title)}</b><span class="hiw-steps"><button type="button" class="text-button hiw-prev">Previous</button><button type="button" class="text-button hiw-next">Next step</button></span></div><div class="hiw-canvas">${svg}</div><div class="hiw-card" aria-live="polite"><p>${esc(intro)}</p></div>`;
  container.append(box);
  const card = box.querySelector('.hiw-card');
  let current = -1;
  const show = (i) => {
    current = (i + parts.length) % parts.length;
    box.querySelectorAll('[data-part]').forEach((el) => el.classList.toggle('hiw-active', Number(el.dataset.part) === current));
    const p = parts[current];
    card.style.borderLeftColor = p.color;
    card.innerHTML = `<span class="hiw-tag" style="background:${p.color}">${esc(p.tag)}</span><h4>${esc(p.name)}</h4>${p.value ? `<code>${esc(p.value)}</code>` : ''}<p>${esc(p.text)}</p>`;
  };
  box.addEventListener('click', (e) => {
    const part = e.target.closest('[data-part]');
    if (part) show(Number(part.dataset.part));
    if (e.target.closest('.hiw-next')) show(current + 1);
    if (e.target.closest('.hiw-prev')) show(current - 1);
  });
  box.addEventListener('keydown', (e) => {
    const part = e.target.closest('[data-part]');
    if (part && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); show(Number(part.dataset.part)); }
  });
}
function wrapText(text, max) {
  const words = String(text).split(/\s+/);
  const lines = [''];
  for (const w of words) {
    if ((lines.at(-1) + ' ' + w).trim().length > max) lines.push(w);
    else lines[lines.length - 1] = (lines.at(-1) + ' ' + w).trim();
  }
  return lines.slice(0, 3);
}

// 2. Socket path: from the app to the server, hop by hop
function socketPath(row, ipLabel) {
  const c = roleColor(row.process);
  const parts = [
    { tag: 'Your Mac', name: row.process, value: `PID ${row.pid}`, color: c, text: 'The app wants to talk to a server. It does not touch the network itself; it asks macOS for a socket and writes bytes into it.' },
    { tag: 'Your Mac', name: 'Local socket', value: row.local, color: '#5f8a5a', text: 'A socket is one end of a conversation: your IP address plus a port number. macOS picked this port for the app, so every reply to this port goes back to this app.' },
    { tag: 'macOS kernel', name: `${row.protocol} / IP stack`, value: row.state, color: '#7a6a9e', text: row.protocol === 'TCP' ? 'The kernel splits the bytes into TCP segments, numbers them, waits for acknowledgements and resends what is lost. ESTABLISHED means the three-way handshake is done and data can flow.' : 'UDP sends each message as it is, without a connection, order or resends. Fast, used for DNS, calls and QUIC.' },
    { tag: 'Hardware', name: 'Wi-Fi card', value: 'en0', color: '#4f7a8c', text: 'The packet gets a Wi-Fi frame with MAC addresses for the next hop only, your router, and goes out as radio.' },
    { tag: 'Home network', name: 'Router', value: 'gateway', color: '#3f8a86', text: 'The router swaps your private address for its public one (NAT), remembers the pair so replies find their way back, and sends the packet to your provider.' },
    { tag: 'Internet', name: 'Many routers', value: 'TTL counts down', color: '#9a7d3a', text: 'Routers pass the packet along by its destination IP. Each hop lowers the TTL by one. The content stays encrypted if the app uses TLS.' },
    { tag: 'Server', name: 'Remote socket', value: row.remote, color: '#b0704f', text: `The server listens on this address and port. ${ipLabel} ${portOf(row.remote) === '443' ? 'Port 443 means HTTPS: encrypted web traffic.' : ''}`.trim() },
  ];
  const W = 900, y = 70, step = W / parts.length;
  const nodes = parts.map((p, i) => {
    const x = step * i + step / 2;
    const label = wrapText(p.name, 14).map((l, k) => `<text x="${x}" y="${y + 46 + k * 14}" text-anchor="middle" class="hiw-label">${esc(l)}</text>`).join('');
    return `<g data-part="${i}" tabindex="0" role="button" class="hiw-node"><text x="${x}" y="${y - 36}" text-anchor="middle" class="hiw-tagtext" fill="${p.color}">${esc(p.tag)}</text><circle cx="${x}" cy="${y}" r="22" fill="${p.color}" fill-opacity=".18" stroke="${p.color}" stroke-width="2"/><text x="${x}" y="${y + 5}" text-anchor="middle" class="hiw-num" fill="${p.color}">${i + 1}</text>${label}</g>`;
  }).join('');
  const links = parts.slice(1).map((p, i) => `<line x1="${step * i + step / 2 + 24}" y1="${y}" x2="${step * (i + 1) + step / 2 - 24}" y2="${y}" stroke="var(--line)" stroke-width="2" marker-end="url(#hiw-arrow)"/>`).join('');
  const svg = `<svg viewBox="0 0 ${W} 170" role="img" aria-label="Path of this connection"><defs><marker id="hiw-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="var(--muted)"/></marker></defs>${links}${nodes}</svg>`;
  return { title: 'How this connection works, step by step', svg, parts, intro: 'Press a circle or "Next step" to follow one message from the app to the server.' };
}

const prevSelectOnMap = selectOnMap;
selectOnMap = function (sel) {
  prevSelectOnMap(sel);
  if (!sel.app || !sel.ip) return;
  const row = activeRows.find((r) => r.process === sel.app && hostOf(r.remote) === sel.ip);
  if (!row) return;
  diagram(mapDetail, socketPath(row, `Its name here: ${destLabel(sel.ip)}.`));
};

// 3. Packet envelopes and the TCP handshake
const LAYER_COLORS = { link: '#4f7a8c', ip: '#7a6a9e', transport: '#5f8a5a', app: '#b0704f', data: '#9a7d3a' };
function packetEnvelope(p) {
  const transport = p.tcpSrc ? 'TCP segment' : p.udpSrc ? 'UDP datagram' : '';
  const app = p.protocol && !['TCP', 'UDP'].includes(p.protocol) ? p.protocol : '';
  const parts = [
    { key: 'link', tag: 'Layer 2', name: 'Wi-Fi / Ethernet frame', value: p.ethSrc ? `${p.ethSrc} → ${p.ethDst}` : '', text: 'The outer envelope. MAC addresses name the two devices on this one hop, your Mac and the router. A new frame is made at every hop.' },
    { key: 'ip', tag: 'Layer 3', name: p.src && p.src.includes(':') ? 'IPv6 packet' : 'IPv4 packet', value: [p.src && `${p.src} → ${p.dst}`, p.ttl && `TTL ${p.ttl}`].filter(Boolean).join(' · '), text: 'IP addresses name the two ends of the whole trip. Routers read only this envelope to pick the next hop.' },
  ];
  if (transport) parts.push({ key: 'transport', tag: 'Layer 4', name: transport, value: [p.sport && `port ${p.sport} → ${p.dport}`, p.tcpFlags && `flags ${p.tcpFlags}`].filter(Boolean).join(' · '), text: transport.startsWith('TCP') ? 'Ports pick the app on each side. TCP adds sequence numbers and flags (SYN, ACK, FIN, RST, PSH) to keep the conversation reliable.' : 'Ports pick the app on each side. UDP adds nothing else: no order, no resend.' });
  if (app) parts.push({ key: 'app', tag: 'Layer 7', name: app, value: [p.tlsSNI && `server ${p.tlsSNI}`, p.dnsQry && `asks ${p.dnsQry}`, p.httpHost && `host ${p.httpHost}`, p.tlsVersion && `version ${p.tlsVersion}`].filter(Boolean).join(' · '), text: (typeof APP_PROTOCOLS !== 'undefined' && APP_PROTOCOLS[app]) || `${app} is the language the two apps speak.` });
  parts.push({ key: 'data', tag: 'Payload', name: /TLS|QUIC|SSL/.test(app) ? 'Your data, encrypted' : 'Data', value: `${p.len} bytes in total`, text: /TLS|QUIC|SSL/.test(app) ? 'What the app actually says. Encrypted, so neither this monitor nor anyone on the path can read it.' : 'What the app actually says, or nothing at all if this packet only manages the connection.' });
  parts.forEach((x) => { x.color = LAYER_COLORS[x.key]; });
  const W = 900, pad = 26, H = 60 + parts.length * pad * 2;
  const boxes = parts.map((x, i) => {
    const inset = i * pad;
    return `<g data-part="${i}" tabindex="0" role="button" class="hiw-node"><rect x="${inset}" y="${inset}" width="${W - inset * 2}" height="${H - inset * 2}" rx="8" fill="${x.color}" fill-opacity="${0.08 + i * 0.04}" stroke="${x.color}" stroke-width="1.5"/><text x="${inset + 12}" y="${inset + 18}" class="hiw-label" fill="${x.color}">${esc(x.tag)} · ${esc(x.name)}</text><text x="${W - inset - 12}" y="${inset + 18}" text-anchor="end" class="hiw-value">${esc(String(x.value).slice(0, 60))}</text></g>`;
  }).join('');
  const svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Packet as nested envelopes">${boxes}</svg>`;
  return { title: 'This packet as nested envelopes', svg, parts, intro: 'Each layer wraps the one inside it. Press an envelope to see what it carries and who reads it.' };
}
function handshake(p) {
  const f = p.tcpFlags || '';
  const has = (ch) => f.includes(ch);
  const rows = [
    { name: 'SYN', dir: 1, text: 'Client asks to open a connection and picks a starting sequence number.', match: has('S') && !has('A') },
    { name: 'SYN + ACK', dir: -1, text: 'Server agrees and acknowledges.', match: has('S') && has('A') },
    { name: 'ACK', dir: 1, text: 'Client confirms. The connection is ESTABLISHED.', match: !has('S') && has('A') && !has('P') && !has('F') && !has('R') },
    { name: 'PSH + ACK (data)', dir: 0, text: 'Data flows both ways, every piece acknowledged.', match: has('P') },
    { name: 'FIN', dir: 0, text: 'One side says it has finished sending.', match: has('F') },
    { name: 'RST', dir: 0, text: 'The connection is cut off at once, often after an error or a timeout.', match: has('R') },
  ];
  const W = 900, rowH = 34, H = 50 + rows.length * rowH;
  const parts = rows.map((r) => ({ tag: 'TCP', name: r.name, value: r.match ? 'this packet' : '', text: r.text, color: r.match ? '#b0704f' : '#5f8a5a' }));
  const arrows = rows.map((r, i) => {
    const y = 40 + i * rowH;
    const color = r.match ? '#b0704f' : 'var(--muted)';
    const [x1, x2] = r.dir === -1 ? [700, 200] : [200, 700];
    const line = r.dir === 0 ? `<line x1="200" y1="${y}" x2="700" y2="${y}" stroke="${color}" stroke-width="${r.match ? 3 : 1.5}" stroke-dasharray="5 4"/>` : `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="${color}" stroke-width="${r.match ? 3 : 1.5}" marker-end="url(#hs-arrow)"/>`;
    return `<g data-part="${i}" tabindex="0" role="button" class="hiw-node">${line}<text x="450" y="${y - 7}" text-anchor="middle" class="hiw-label" fill="${color}">${esc(r.name)}${r.match ? ' · this packet' : ''}</text><rect x="200" y="${y - 22}" width="500" height="30" fill="transparent"/></g>`;
  }).join('');
  const svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="TCP conversation"><defs><marker id="hs-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="var(--muted)"/></marker></defs><text x="150" y="20" text-anchor="middle" class="hiw-tagtext">Your Mac</text><text x="750" y="20" text-anchor="middle" class="hiw-tagtext">Server</text><line x1="200" y1="26" x2="200" y2="${H - 6}" stroke="var(--line)" stroke-width="2"/><line x1="700" y1="26" x2="700" y2="${H - 6}" stroke="var(--line)" stroke-width="2"/>${arrows}</svg>`;
  return { title: 'Where this packet sits in a TCP conversation', svg, parts, intro: 'A TCP connection opens with a three-way handshake, carries data, then closes. The highlighted arrow is this packet.' };
}

const prevShowPacket = showPacket;
showPacket = function (i) {
  prevShowPacket(i);
  const p = capPackets[i];
  if (!p) return;
  cap.detail.querySelector('.layers')?.remove();
  diagram(cap.detail, packetEnvelope(p));
  if (p.tcpSrc) diagram(cap.detail, handshake(p));
};

// 4. Process traffic: what each process is, as bars with plain explanations
const KNOWN = [
  [/^rapportd$/, 'Apple system', 'Talks to your other Apple devices nearby for Handoff, Universal Clipboard and AirDrop.'],
  [/^mDNSResponder$/, 'Apple system', 'The DNS service of macOS. Every app asks it to turn names like apple.com into addresses.'],
  [/^apsd$/, 'Apple system', 'Apple Push Notification service. Keeps one connection to Apple open so notifications arrive.'],
  [/^(cloudd|bird|CloudKeychainProxy)$/, 'Apple system', 'iCloud sync: Drive, Photos, Keychain and app data.'],
  [/^nsurlsessiond$/, 'Apple system', 'Downloads and uploads in the background on behalf of apps and the system.'],
  [/^(trustd|ocspd)$/, 'Apple system', 'Checks that security certificates are valid and not revoked.'],
  [/^(identityservicesd|imagent)$/, 'Apple system', 'iMessage and FaceTime accounts and delivery.'],
  [/^sharingd$/, 'Apple system', 'AirDrop and sharing between your devices.'],
  [/^(softwareupdated|mobileassetd)$/, 'Apple system', 'Checks for and downloads macOS and system data updates.'],
  [/^timed$/, 'Apple system', 'Keeps the clock exact by asking time servers.'],
  [/^(akd|accountsd)$/, 'Apple system', 'Signs in to your Apple Account and keeps it valid.'],
  [/^(symptomsd|networkserviceproxy|netbiosd|configd)$/, 'Apple system', 'Network plumbing: watches link quality, proxies and local network names.'],
  [/^(assistantd|siriknowledged|parsecd)$/, 'Apple system', 'Siri and Spotlight suggestions.'],
  [/^com\.apple\.WebKit\.Networking$/, 'Apple system', 'The network part of Safari and of apps that show web pages.'],
  [/Helper/, 'App helper', 'A helper process of a larger app. Browsers and Electron apps split work into helpers so one crash does not take down the whole app; network traffic often goes through one of them.'],
  [/^(Brave Browser|Google Chrome|Safari|Firefox|Arc)$/, 'Browser', 'Your browser. Every open tab and extension can create connections.'],
  [/^(Mail|Messages|Calendar|Notes|Reminders|Photos|Music|News|Weather|Maps)$/, 'App', 'A built-in Apple app. It syncs with its servers or with iCloud.'],
  [/^1Password/, 'App', 'Password manager. Syncs your vault with its servers, mostly through Amazon CloudFront.'],
  [/^[Cc]laude$/, 'App', 'Claude app and Claude Code. Talks to Anthropic servers.'],
  [/^(node|Python|python3?|ruby|java)$/, 'Developer tool', 'A program run by a script or a local server, for example this monitor or a dev tool. Check which project started it if unsure.'],
  [/^(ollama|Ollama)/, 'Local AI', 'Runs AI models on this Mac. Should talk only to localhost, except when downloading models.'],
];
function describeProcess(name) {
  for (const [re, kind, text] of KNOWN) if (re.test(name)) return { kind, text };
  return { kind: 'Unknown here', text: 'This monitor has no note about this process yet. Ask the local AI, or look at which app it belongs to in Activity Monitor.' };
}
const KIND_COLORS = { 'Apple system': '#8a8f8a', 'App helper': '#3f6fa8', Browser: '#3f6fa8', App: '#3f6fa8', 'Developer tool': '#3f6fa8', 'Local AI': '#3f6fa8', 'Unknown here': '#3f6fa8' };

const processView = document.createElement('div');
processView.className = 'proc-visual';
document.querySelector('#processes .process-table-wrap').before(processView);
const processCard = document.createElement('div');
processCard.className = 'flow-inspector';
processCard.innerHTML = '<div class="inspector-empty">Select a process to see what it is and what its numbers mean.</div>';
processView.after(processCard);
let processRows = [];

const prevRenderProcesses = renderProcesses;
renderProcesses = function (processes, sampledAt) {
  prevRenderProcesses(processes, sampledAt);
  processRows = [...currentProcessStats.values()].sort((a, b) => (b.receivedBytes + b.sentBytes) - (a.receivedBytes + a.sentBytes)).slice(0, 14);
  const max = Math.max(1, ...processRows.map((r) => r.receivedBytes + r.sentBytes));
  const kinds = new Map();
  const flagged = new Set(markers.map((m) => m.app));
  processView.innerHTML = `<div class="proc-legend"><span><i style="background:${ROLE.system}"></i>Apple system</span><span><i style="background:${ROLE.app}"></i>Apps and helpers</span><span><i style="background:${ROLE.flag}"></i>! Needs a look</span><span><i class="solid"></i>received</span><span><i class="light"></i>sent</span></div>${processRows.map((r, i) => {
    const d = describeProcess(r.process);
    kinds.set(d.kind, (kinds.get(d.kind) || 0) + 1);
    const inW = (r.receivedBytes / max) * 100;
    const outW = (r.sentBytes / max) * 100;
    const col = flagged.has(r.process) ? ROLE.flag : KIND_COLORS[d.kind];
    return `<button type="button" class="proc-row" data-i="${i}"><span class="proc-name"><i style="background:${col}"></i>${flagged.has(r.process) ? '! ' : ''}${esc(r.process)}<small>${esc(d.kind)}</small></span><span class="proc-bar" title="received ${formatBytes(r.receivedBytes)}, sent ${formatBytes(r.sentBytes)}"><span style="width:${inW.toFixed(1)}%;background:${col}"></span><span style="width:${outW.toFixed(1)}%;background:${col};opacity:.45"></span></span><span class="proc-num">${formatBytes(r.receivedBytes + r.sentBytes)}${r.receivedRate + r.sentRate > 0 ? `<small>${formatRate(r.receivedRate + r.sentRate)}</small>` : ''}</span></button>`;
  }).join('')}`;
};
processView.addEventListener('click', (e) => {
  const btn = e.target.closest('.proc-row');
  if (!btn) return;
  const r = processRows[Number(btn.dataset.i)];
  if (!r) return;
  const d = describeProcess(r.process);
  const conns = activeRows.filter((c) => c.pid === r.pid);
  processCard.innerHTML = `<div class="proc-card-head" style="border-left-color:${KIND_COLORS[d.kind]}"><span class="hiw-tag" style="background:${KIND_COLORS[d.kind]}">${esc(d.kind)}</span><h4>${esc(r.process)} <small>PID ${esc(r.pid)}</small></h4><p>${esc(d.text)}</p></div>
  <div class="inspector-grid"><div><span>Received since it started</span><strong>${formatBytes(r.receivedBytes)} · ${Number(r.receivedPackets).toLocaleString()} packets</strong></div><div><span>Sent since it started</span><strong>${formatBytes(r.sentBytes)} · ${Number(r.sentPackets).toLocaleString()} packets</strong></div><div><span>Right now</span><strong>↓ ${formatRate(r.receivedRate)} · ↑ ${formatRate(r.sentRate)}</strong></div><div><span>Open internet connections</span><strong>${conns.length}</strong></div></div>
  ${conns.length ? `<ul class="proc-conns">${conns.slice(0, 6).map((c) => `<li><span>${esc(c.local)}</span><b>→</b><span>${esc(destLabel(hostOf(c.remote)))} <small>${esc(c.remote)}</small></span></li>`).join('')}</ul>` : ''}
  <p class="learn-note"><b>Process</b>: a running program. One app can run as several processes. <b>PID</b>: the number macOS gives each process while it runs. <b>Packets</b>: the small pieces data travels in, usually up to 1.5 KB each. These totals count since the process started.</p>${explainBlock()}`;
  bindExplain(processCard, { kind: 'process', process: r.process, category_here: d.kind, received: formatBytes(r.receivedBytes), sent: formatBytes(r.sentBytes), open_connections: conns.map((c) => destLabel(hostOf(c.remote))).slice(0, 8).join(', ') });
  if (conns[0]) diagram(processCard, socketPath(conns[0], `Its name here: ${destLabel(hostOf(conns[0].remote))}.`));
});


// 5. Recent events: a timeline with explanations
const eventSection = document.querySelector('#events');
const eventCard = document.createElement('div');
eventCard.className = 'flow-inspector';
eventCard.innerHTML = '<div class="inspector-empty">Select an event to see what opening or closing a connection means.</div>';
document.querySelector('#event-list').after(eventCard);
const eventIntro = document.createElement('p');
eventIntro.className = 'learn-note events-intro';
eventIntro.innerHTML = '<b>What is an event?</b> Every few seconds the monitor compares the list of open connections with the previous one. A new line means an app <b>opened</b> a connection (the TCP handshake finished); a missing line means it <b>closed</b> one (FIN or RST, or the app quit). Apps open and close connections all the time; this is normal.';
document.querySelector('#event-list').before(eventIntro);

const prevRenderEvents = renderEvents;
renderEvents = function () {
  prevRenderEvents();
  if (!history.length) return;
  const flaggedApps = new Set(markers.map((m) => m.app));
  const perMinute = new Map();
  for (const ev of history) {
    const k = ev.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const b = perMinute.get(k) || { open: 0, close: 0 };
    b[ev.kind === 'close' ? 'close' : 'open'] += 1;
    perMinute.set(k, b);
  }
  const minutes = [...perMinute.entries()].reverse().slice(-20);
  const maxN = Math.max(1, ...minutes.map(([, b]) => b.open + b.close));
  const chart = `<div class="ev-chart" aria-label="Events per minute">${minutes.map(([k, b]) => `<div class="ev-col" title="${esc(k)}: ${b.open} opened, ${b.close} closed"><span class="ev-open" style="height:${(b.open / maxN) * 100}%"></span><span class="ev-close" style="height:${(b.close / maxN) * 100}%"></span><small>${esc(k)}</small></div>`).join('')}</div><div class="proc-legend"><span><i style="background:${ROLE.app}"></i>opened</span><span><i style="background:${ROLE.system}"></i>closed</span><span><i style="background:${ROLE.flag}"></i>! app needs a look</span></div>`;
  eventList.innerHTML = chart + history.map((ev, i) => {
    const role = ev.process ? roleOf(ev.process) : 'app';
    const flagged = ev.process && flaggedApps.has(ev.process);
    const color = flagged ? ROLE.flag : ev.kind === 'close' ? ROLE.system : ROLE[role];
    const ip = ev.remote ? hostOf(ev.remote) : '';
    const verb = ev.kind === 'close' ? 'closed' : 'opened';
    return `<button type="button" class="ev-row" data-i="${i}"><span class="ev-time">${esc(ev.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }))}</span><span class="ev-dot" style="background:${color}"></span><span class="ev-text">${ev.process ? `${flagged ? '! ' : ''}<b>${esc(ev.process)}</b> ${verb} a connection to <b>${esc(ip ? destLabel(ip) : '')}</b>` : esc(ev.text)}</span><span class="ev-kind">${esc(ev.process ? describeProcess(ev.process).kind : '')}</span></button>`;
  }).join('');
};
eventList.addEventListener('click', (e) => {
  const btn = e.target.closest('.ev-row');
  if (!btn) return;
  const ev = history[Number(btn.dataset.i)];
  if (!ev || !ev.process) return;
  const d = describeProcess(ev.process);
  const ip = hostOf(ev.remote);
  const open = ev.kind !== 'close';
  eventCard.innerHTML = `<div class="proc-card-head" style="border-left-color:${open ? ROLE[roleOf(ev.process)] : ROLE.system}"><span class="hiw-tag" style="background:${open ? ROLE[roleOf(ev.process)] : ROLE.system}">${open ? 'Opened' : 'Closed'}</span><h4>${esc(ev.process)} <small>${esc(d.kind)}</small></h4><p>${esc(d.text)}</p></div>
  <div class="inspector-grid"><div><span>From (your socket)</span><strong>${esc(ev.local || '')}</strong></div><div><span>To</span><strong>${esc(destLabel(ip))} · ${esc(ev.remote)}</strong></div><div><span>Protocol</span><strong>${esc(ev.protocol || '')}</strong></div><div><span>When</span><strong>${esc(ev.time.toLocaleString())}</strong></div></div>
  <p class="learn-note">${open ? '<b>Opened</b>: the app and the server finished the TCP handshake (SYN, SYN+ACK, ACK) and can now send data. Short-lived connections are normal: apps open one, fetch something, and close it.' : '<b>Closed</b>: one side sent FIN to finish politely, or RST to cut it off, or the app quit. The socket port on your Mac is free again a little later.'}</p>${explainBlock()}`;
  bindExplain(eventCard, { kind: `connection ${open ? 'opened' : 'closed'}`, process: ev.process, category_here: d.kind, destination: destLabel(ip), remote: ev.remote, protocol: ev.protocol });
  const row = { pid: ev.pid, process: ev.process, protocol: ev.protocol || 'TCP', local: ev.local || '', remote: ev.remote, state: open ? 'ESTABLISHED' : 'CLOSED' };
  diagram(eventCard, socketPath(row, `Its name here: ${destLabel(ip)}.`));
});

// 6. Motion: traffic you can see. Speed follows the app's current traffic.
let motionOn = true;
try { motionOn = localStorage.getItem('lw-motion') !== 'off'; } catch { /* storage optional */ }
document.documentElement.classList.toggle('motion-off', !motionOn);
const motionToggle = document.createElement('button');
motionToggle.type = 'button';
motionToggle.className = 'text-button motion-toggle';
const setMotionLabel = () => { motionToggle.textContent = motionOn ? 'Motion on' : 'Motion off'; motionToggle.setAttribute('aria-pressed', String(motionOn)); };
setMotionLabel();
motionToggle.addEventListener('click', () => {
  motionOn = !motionOn;
  try { localStorage.setItem('lw-motion', motionOn ? 'on' : 'off'); } catch { /* storage optional */ }
  document.documentElement.classList.toggle('motion-off', !motionOn);
  setMotionLabel();
});
document.querySelector('.live-state').after(motionToggle);

// Faster flow for more bytes per second: 0.5 s per dash cycle at about 1 MB/s, 4 s when nearly idle.
function flowDuration(bytesPerSecond) {
  if (!bytesPerSecond) return 0;
  const d = 4 - Math.log10(1 + bytesPerSecond / 1000) * 1.2;
  return Math.max(0.5, Math.min(4, d));
}
function routeSvg(row) {
  const stats = currentProcessStats.get(row.pid);
  const out = stats ? stats.sentRate : 0;
  const inn = stats ? stats.receivedRate : 0;
  const color = markers.some((m) => m.app === row.process) ? ROLE.flag : roleColor(row.process);
  const lane = (y, rate, dir) => {
    const dur = flowDuration(rate);
    // A delay from the wall clock keeps the flow phase steady when the list re-renders.
    const delay = dur ? -((performance.now() / 1000) % dur) : 0;
    return `<line x1="4" y1="${y}" x2="156" y2="${y}" class="flow ${dur ? `flow-${dir}` : 'flow-idle'}" stroke="${color}" style="--dur:${dur || 0}s;animation-delay:${delay.toFixed(3)}s"/>`;
  };
  const title = `${row.process}: sending ${formatRate(out)}, receiving ${formatRate(inn)} (whole app)`;
  return `<svg class="route-svg" viewBox="0 0 160 26" preserveAspectRatio="none" role="img" aria-label="${esc(title)}"><title>${esc(title)}</title>${lane(8, out, 'out')}${lane(18, inn, 'in')}<path d="M152 4 L158 8 L152 12" class="flow-head" stroke="${color}"/><path d="M8 14 L2 18 L8 22" class="flow-head" stroke="${color}"/></svg>`;
}
const prevRenderConnections = renderConnections;
renderConnections = function (rows) {
  prevRenderConnections(rows);
  list.querySelectorAll('.connection-row').forEach((el) => {
    const row = rows[Number(el.dataset.index)];
    const route = el.querySelector('.route');
    if (row && route) { route.classList.add('route-live'); route.innerHTML = routeSvg(row); }
  });
};
const routeHelp = document.createElement('p');
routeHelp.className = 'learn-note route-help';
routeHelp.innerHTML = '<b>Reading the routes.</b> Upper lane: data your Mac <b>sends</b>, flowing right. Lower lane: data it <b>receives</b>, flowing left. Faster flow means more bytes per second. Still, faint lines are open connections with no traffic right now. macOS counts traffic per app, not per connection, so every line of one app moves at that app\'s speed. Colours: grey for Apple system, blue for apps, red for something that needs a look.';
document.querySelector('#activity .table-head').before(routeHelp);

// Map lines flow too, at the app's speed.
const prevRenderMap2 = renderMap;
renderMap = function () {
  prevRenderMap2();
  const rateByApp = new Map();
  for (const s of currentProcessStats.values()) rateByApp.set(s.process, (rateByApp.get(s.process) || 0) + s.sentRate + s.receivedRate);
  mapSvg.querySelectorAll('.map-line').forEach((p) => {
    const dur = flowDuration(rateByApp.get(p.dataset.key.split('|')[0]) || 0);
    p.classList.toggle('map-flow', dur > 0);
    p.style.setProperty('--dur', `${dur}s`);
  });
};

KNOWN.splice(KNOWN.length - 1, 0,
  [/^Codex/, 'App', 'OpenAI Codex, a coding assistant. Talks to OpenAI and Google cloud servers.'],
  [/^node_repl$/, 'Developer tool', 'A Node.js process started by a developer tool or assistant to run code. Check which app started it if unsure.']);

// 7. Events: open the detail right under the clicked event, and keep it open across refreshes.
let openEventId = null;
const eventId = (ev) => `${ev.time.getTime()}|${ev.kind}|${ev.pid}|${ev.remote}`;
const prevRenderEvents2 = renderEvents;
renderEvents = function () {
  prevRenderEvents2();
  if (!openEventId) return;
  const i = history.findIndex((ev) => eventId(ev) === openEventId);
  const btn = i >= 0 && eventList.querySelector(`.ev-row[data-i="${i}"]`);
  if (btn) { btn.classList.add('ev-open-row'); btn.after(eventCard); }
};
eventList.addEventListener('click', (e) => {
  const btn = e.target.closest('.ev-row');
  if (!btn) return;
  const ev = history[Number(btn.dataset.i)];
  if (!ev) return;
  const id = eventId(ev);
  eventList.querySelectorAll('.ev-open-row').forEach((b) => b.classList.remove('ev-open-row'));
  if (openEventId === id) { openEventId = null; eventCard.remove(); return; }
  openEventId = id;
  btn.classList.add('ev-open-row');
  btn.after(eventCard);
  eventCard.classList.add('ev-inline');
  eventCard.scrollIntoView({ block: 'nearest', behavior: motionOn ? 'smooth' : 'auto' });
});

// 8. Capture, made visual: timeline, protocol mix, hosts, colored rows, inline detail.
const PROTO_COLORS = { TLS: '#3f6fa8', QUIC: '#6b7fb0', TCP: '#7a8fa6', UDP: '#9aa7b6', DNS: '#5f8a5a', MDNS: '#8fb08a', ICMP: '#b0704f', ARP: '#9a7d3a', HTTP: '#b5473f', Other: '#c4c7c2' };
function protoFamily(p) {
  const x = String(p || '').toUpperCase();
  if (x.startsWith('TLS') || x === 'SSL') return 'TLS';
  if (x.startsWith('ICMP')) return 'ICMP';
  return PROTO_COLORS[x] ? x : 'Other';
}
const capIntro = document.createElement('p');
capIntro.className = 'learn-note events-intro';
capIntro.innerHTML = '<b>What is a capture?</b> For a few seconds TShark copies the <b>headers</b> of every packet that passes your Wi-Fi card: who sends, who receives, which protocol, how big. Encrypted content stays unreadable. Each packet is one small piece of a conversation; a web page is often hundreds of them.';
document.querySelector('#capture .capture-controls').before(capIntro);
const capVisual = document.createElement('div');
capVisual.className = 'cap-visual';
cap.summary.after(capVisual);
let openPacket = -1;

const prevRenderCapture = renderCapture;
renderCapture = function () {
  prevRenderCapture();
  if (!capPackets.length) { capVisual.innerHTML = ''; return; }
  // Timeline: packets per half second, split by who sent them.
  const last = Math.max(...capPackets.map((p) => Number(p.time) || 0), 0.5);
  const n = Math.min(60, Math.ceil(last / 0.5));
  const buckets = Array.from({ length: n }, () => ({ app: 0, system: 0, none: 0 }));
  for (const p of capPackets) {
    const b = buckets[Math.min(n - 1, Math.floor((Number(p.time) || 0) / 0.5))];
    b[p.process ? roleOf(p.process) : 'none'] += 1;
  }
  const maxB = Math.max(1, ...buckets.map((b) => b.app + b.system + b.none));
  const timeline = `<div class="cap-block"><b>Packets over time</b><div class="ev-chart cap-chart">${buckets.map((b, i) => `<div class="ev-col" title="${(i * 0.5).toFixed(1)} s: ${b.app} app, ${b.system} system, ${b.none} not matched"><span style="height:${(b.app / maxB) * 100}%;background:${ROLE.app}"></span><span style="height:${(b.system / maxB) * 100}%;background:${ROLE.system}"></span><span style="height:${(b.none / maxB) * 100}%;background:#d9dbd6"></span>${i % 4 === 0 ? `<small>${(i * 0.5).toFixed(0)} s</small>` : ''}</div>`).join('')}</div><div class="proc-legend"><span><i style="background:${ROLE.app}"></i>apps</span><span><i style="background:${ROLE.system}"></i>Apple system</span><span><i style="background:#d9dbd6"></i>not matched to an app (often local network chatter)</span></div></div>`;
  // Protocol mix as one stacked bar with direct labels.
  const fam = new Map();
  for (const p of capPackets) fam.set(protoFamily(p.protocol), (fam.get(protoFamily(p.protocol)) || 0) + 1);
  const famRows = [...fam.entries()].sort((a, b) => b[1] - a[1]);
  const total = capPackets.length;
  const mix = `<div class="cap-block"><b>Protocols</b><div class="mix-bar">${famRows.map(([k, v]) => `<span style="flex:${v};background:${PROTO_COLORS[k]}" title="${esc(k)}: ${v} packets"></span>`).join('')}</div><div class="proc-legend">${famRows.map(([k, v]) => `<span><i style="background:${PROTO_COLORS[k]}"></i>${esc(k)} ${Math.round((v / total) * 100)}%</span>`).join('')}</div><p class="learn-note">${famRows.slice(0, 3).map(([k]) => `<b>${esc(k)}</b>: ${esc((APP_PROTOCOLS[k] || ({ TCP: 'Reliable delivery: these packets open, acknowledge and close conversations.', UDP: 'Single messages without a connection.', Other: 'Everything else in this capture.' })[k] || ''))}`).join(' ')}</p></div>`;
  // Remote hosts by bytes.
  const hosts = new Map();
  for (const p of capPackets) {
    const remote = isPrivate(p.dst || '') ? p.src : p.dst;
    if (!remote || isPrivate(remote)) continue;
    const name = p.dstName || p.srcName || destLabel(remote);
    const h = hosts.get(name) || { bytes: 0, apps: new Set() };
    h.bytes += Number(p.len) || 0;
    if (p.process) h.apps.add(p.process);
    hosts.set(name, h);
  }
  const hostRows = [...hosts.entries()].sort((a, b) => b[1].bytes - a[1].bytes).slice(0, 6);
  const maxH = Math.max(1, ...hostRows.map(([, h]) => h.bytes));
  const hostsHtml = `<div class="cap-block"><b>Where the bytes went</b>${hostRows.map(([name, h]) => { const app = [...h.apps][0]; const col = app ? roleColor(app) : ROLE.system; return `<div class="host-row"><span class="host-name">${esc(name)}<small>${esc([...h.apps].join(', ') || 'no app matched')}</small></span><span class="host-bar"><span style="width:${(h.bytes / maxH) * 100}%;background:${col}"></span></span><span class="proc-num">${formatBytes(h.bytes)}</span></div>`; }).join('')}</div>`;
  capVisual.innerHTML = timeline + mix + hostsHtml;
  // Colored dots and protocol chips in the table.
  cap.rows.querySelectorAll('tr[data-i]').forEach((tr) => {
    const p = capPackets[Number(tr.dataset.i)];
    if (!p) return;
    const procCell = tr.children[2];
    const dot = p.process ? roleColor(p.process) : '#d9dbd6';
    procCell.innerHTML = `<span class="ev-dot cap-dot" style="background:${dot}"></span>${esc(p.process || 'not matched')}`;
    const protoCell = tr.children[5];
    protoCell.innerHTML = `<span class="proto-chip" style="background:${PROTO_COLORS[protoFamily(p.protocol)]}">${esc(p.protocol)}</span>`;
  });
  if (openPacket >= 0) attachPacketDetail(openPacket);
};
function attachPacketDetail(i) {
  const tr = cap.rows.querySelector(`tr[data-i="${i}"]`);
  if (!tr) return;
  let holder = cap.rows.querySelector('tr.detail-row');
  if (!holder) { holder = document.createElement('tr'); holder.className = 'detail-row'; holder.innerHTML = '<td colspan="8"></td>'; }
  tr.after(holder);
  holder.firstElementChild.append(cap.detail);
}
cap.rows.addEventListener('click', (e) => {
  const tr = e.target.closest('tr[data-i]');
  if (!tr) return;
  const i = Number(tr.dataset.i);
  if (openPacket === i) { openPacket = -1; cap.rows.querySelector('tr.detail-row')?.remove(); document.querySelector('#cap-table-wrap').after(cap.detail); return; }
  openPacket = i;
  attachPacketDetail(i);
}, true);

// 9. Investigate a process: who started it, from where, signed by whom, which sockets.
const TCP_STATES = {
  ESTABLISHED: 'Open and in use: both sides can send data.',
  LISTEN: 'Waiting for others to connect: a small server on this Mac.',
  SYN_SENT: 'This Mac asked to connect and waits for an answer.',
  CLOSE_WAIT: 'The server already closed its side; the app has not closed its own yet. Often a leftover from a finished download. Harmless, but a long-lived one means the app keeps an idle socket.',
  TIME_WAIT: 'Closed a moment ago; macOS keeps the port reserved for a short time.',
  FIN_WAIT_1: 'This Mac started closing the connection.',
  FIN_WAIT_2: 'This Mac closed its side and waits for the other side.',
  LAST_ACK: 'Closing: waiting for the final confirmation.',
  CLOSED: 'Fully closed.',
};
function chainHtml(f) {
  const chain = [...f.parents].reverse().map((p) => ({ name: p.command.split(' ')[0].split('/').pop() || p.command, pid: p.pid, cmd: p.command }));
  chain.push({ name: f.command.split(' ')[0].split('/').pop(), pid: f.pid, cmd: f.command, self: true });
  return `<div class="chain">${chain.map((c, i) => `${i ? '<span class="chain-arrow">→</span>' : ''}<span class="chain-node${c.self ? ' self' : ''}" title="${esc(c.cmd)}">${esc(c.name)}<small>PID ${esc(c.pid)}</small></span>`).join('')}</div>`;
}
async function investigate(container, pid) {
  const box = document.createElement('div');
  box.className = 'investigate';
  box.innerHTML = '<b>Investigate this process</b><p class="learn-note">Reading facts from macOS…</p>';
  container.append(box);
  try {
    const res = await fetch(`/api/process?pid=${encodeURIComponent(pid)}`, { cache: 'no-store' });
    const f = await res.json();
    if (!res.ok) throw new Error(f.error || 'Process not found');
    const sockets = f.sockets.map((s) => {
      const state = (s.match(/\((\w+)\)$/) || [])[1] || '';
      const listen = state === 'LISTEN';
      return `<li><span class="state-chip ${listen ? 'listen' : ''}" title="${esc(TCP_STATES[state] || '')}">${esc(state || 'UDP')}</span><code>${esc(s.replace(/\s*\(\w+\)$/, ''))}</code></li>`;
    }).join('');
    const states = [...new Set(f.sockets.map((s) => (s.match(/\((\w+)\)$/) || [])[1]).filter(Boolean))];
    box.innerHTML = `<b>Investigate this process</b>
      <div class="inv-grid"><div><span>Started</span><strong>${esc(f.started)}</strong></div><div><span>User</span><strong>${esc(f.user)}</strong></div><div><span>Working folder</span><strong>${esc(f.cwd || 'unknown')}</strong></div><div><span>Signed by</span><strong>${esc(f.signature || 'unknown')}</strong></div></div>
      <div class="inv-block"><span class="inv-label">Started by</span>${chainHtml(f)}<p class="learn-note">Every process has a parent that launched it. launchd is the root of macOS. A chain through a terminal, pm2 or an IDE means you or a tool you run started it.</p></div>
      <div class="inv-block"><span class="inv-label">Full command</span><code class="inv-cmd">${esc(f.command)}</code></div>
      <div class="inv-block"><span class="inv-label">All network sockets of this process</span><ul class="inv-sockets">${sockets || '<li>none right now</li>'}</ul>${states.length ? `<dl class="state-glossary">${states.map((s) => `<dt>${esc(s)}</dt><dd>${esc(TCP_STATES[s] || '')}</dd>`).join('')}</dl>` : ''}</div>
      <div class="inv-block"><span class="inv-label">Look deeper yourself</span><ul class="inv-tips"><li>Activity Monitor: select the process, then Info shows open files and ports.</li><li>Terminal, read-only: <code>lsof -nP -p ${esc(f.pid)}</code> lists every file and socket it holds.</li><li>Terminal: <code>ps -o ppid,command -p ${esc(f.pid)}</code> shows how it was started.</li><li>Unsigned or unexpected parent, or a folder you do not recognise: ask the local AI or check the project in that folder.</li></ul></div>`;
  } catch (e) {
    box.innerHTML = `<b>Investigate this process</b><p class="learn-note">${esc(e.message)}. It may have exited.</p>`;
  }
}
const prevSelectOnMap2 = selectOnMap;
selectOnMap = function (sel) {
  prevSelectOnMap2(sel);
  const row = sel.app && activeRows.find((r) => r.process === sel.app && (!sel.ip || hostOf(r.remote) === sel.ip));
  if (row) investigate(mapDetail, row.pid);
};
processView.addEventListener('click', (e) => {
  const btn = e.target.closest('.proc-row');
  const r = btn && processRows[Number(btn.dataset.i)];
  if (r) investigate(processCard, r.pid);
});
eventList.addEventListener('click', (e) => {
  const btn = e.target.closest('.ev-row');
  const ev = btn && history[Number(btn.dataset.i)];
  if (ev && ev.pid && openEventId) investigate(eventCard, ev.pid);
});

// 10. Settings, as a picture of what runs where.
async function renderSettings() {
  const section = document.querySelector('#settings');
  let s = {};
  try { s = await (await fetch('/api/settings', { cache: 'no-store' })).json(); } catch { /* offline */ }
  const learnStart = (s.learningUntil || Date.now()) - 24 * 3600 * 1000;
  const progress = Math.max(0, Math.min(1, (Date.now() - learnStart) / (24 * 3600 * 1000)));
  const local = '#3f6fa8', net = '#8a8f8a';
  const nodes = [
    ['lsof', 'which app owns which socket', local, 'macOS tool, read-only'],
    ['nettop', 'bytes and packets per app', local, 'macOS tool, read-only'],
    ['Rust core', 'joins both every 3 s', local, 'this project'],
    ['Server', `127.0.0.1:${s.port || 4317}`, local, 'answers only this Mac'],
    ['TShark', 'packet headers, on your click', local, 'Wireshark project'],
    ['Ollama', s.explainModel || 'local model', local, 'explanations, on your click'],
    ['DNS', 'names for addresses', net, 'asks your DNS resolver'],
    ['whois', 'owner of an address', net, 'asks the public registry'],
  ];
  const W = 900, colW = W / 4;
  const box = (n, i) => {
    const x = (i % 4) * colW + 10, y = Math.floor(i / 4) * 92 + 10;
    return `<g><rect x="${x}" y="${y}" width="${colW - 20}" height="72" rx="8" fill="${n[2]}" fill-opacity=".1" stroke="${n[2]}" stroke-width="1.5" ${n[2] === net ? 'stroke-dasharray="5 4"' : ''}/><text x="${x + 12}" y="${y + 22}" class="hiw-label" font-weight="600">${esc(n[0])}</text><text x="${x + 12}" y="${y + 40}" class="hiw-value">${esc(n[1])}</text><text x="${x + 12}" y="${y + 58}" class="hiw-tagtext">${esc(n[3])}</text></g>`;
  };
  const flowSvg = `<svg viewBox="0 0 ${W} 194" role="img" aria-label="What runs where">${nodes.map(box).join('')}</svg>`;
  const bar = section.querySelector('.section-bar');
  section.innerHTML = '';
  section.append(bar);
  section.insertAdjacentHTML('beforeend', `
    <div class="set-grid">
      <article class="set-card wide"><h3>What runs where</h3><div class="hiw-canvas">${flowSvg}</div><div class="proc-legend"><span><i style="background:${local}"></i>stays on this Mac</span><span><i style="background:${net}"></i>asks the network (only names and owners of addresses, never your data)</span></div></article>
      <article class="set-card"><h3>Learning what is normal</h3><div class="learn-bar"><span style="width:${(progress * 100).toFixed(0)}%"></span></div><p>${progress < 1 ? `Learning until ${esc(new Date(s.learningUntil).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' }))}. Markers start after that.` : 'Learning done. New apps, destinations, ports, night activity and traffic bursts are marked in red with a reason.'}</p><p class="set-num"><b>${esc(s.apps ?? '-')}</b> apps learned · sampled every ${esc(s.sampleSeconds || 15)} s</p></article>
      <article class="set-card"><h3>Stored on this Mac</h3><p id="history-info">${esc(s.file || '')}</p><p class="learn-note">Only metadata: app names, destination groups, ports and times. Never packet contents. Folder readable by you only.</p><button id="forget-history-2" class="cap-button" type="button">Delete the learned history</button></article>
      <article class="set-card"><h3>Display</h3><p>Animated traffic follows bytes per second.</p><button class="cap-button set-motion" type="button">${motionOn ? 'Turn motion off' : 'Turn motion on'}</button><p class="learn-note">Refreshes every 3 seconds.</p></article>
      <article class="set-card"><h3>Promises</h3><ul class="promise"><li>Listens on 127.0.0.1 only; other devices cannot open it.</li><li>Packet capture only after your click and confirmation, 5 to 30 seconds, memory only.</li><li>AI explanations from a model on this Mac only.</li><li>No admin rights. No firewall changes. Blocking is not built.</li></ul></article>
    </div>`);
  section.querySelector('.set-motion').addEventListener('click', () => { motionToggle.click(); renderSettings(); });
  const forget = section.querySelector('#forget-history-2');
  forget.addEventListener('click', async () => {
    if (forget.dataset.armed !== 'yes') { forget.dataset.armed = 'yes'; forget.textContent = 'Press again to delete. Learning starts over.'; return; }
    await fetch('/api/history', { method: 'DELETE' });
    loadMarkers();
    renderSettings();
  });
}
document.querySelector('a[href="#settings"]').addEventListener('click', () => renderSettings());
renderSettings();

const list = document.querySelector('#connection-list');
const processList = document.querySelector('#process-list');
const processShowAll = document.querySelector('#process-show-all');
const processSearch = document.querySelector('#process-search');
const processListCount = document.querySelector('#process-list-count');
const processPrev = document.querySelector('#process-prev');
const processNext = document.querySelector('#process-next');
const processPageLabel = document.querySelector('#process-page');
const eventList = document.querySelector('#event-list');
const count = document.querySelector('#connection-count');
const liveLabel = document.querySelector('#live-label');
const liveState = document.querySelector('.live-state');
const lastUpdated = document.querySelector('#last-updated');
const sampleState = document.querySelector('#sample-state');
const filter = document.querySelector('#filter');
const known = new Set();
const history = [];
const previousProcesses = new Map();
let firstSnapshot = true;
let activeRows = [];
let lastMetricSample = 0;
let currentProcessStats = new Map();
let networkProcessRows = [];
let allProcessRows = [];
let processPage = 1;
const processPageSize = 25;
let busy = false;

function esc(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
function stamp(process) {
  return Array.from(process || '?')[0].toUpperCase();
}
function renderConnections(rows) {
  activeRows = rows;
  count.textContent = String(rows.length);
  if (!rows.length) {
    list.innerHTML = '<div class="empty-state">No remote connections are visible in this snapshot. Local-only and protected sockets may not appear here.</div>';
    return;
  }
  list.innerHTML = rows.map((row) => {
    const key = [row.pid, row.protocol, row.local, row.remote].join('|');
    const fresh = !known.has(key);
    const label = `${row.protocol || 'Network'} · PID ${row.pid}`;
    return `<article class="connection-row${fresh ? ' first-seen' : ''}" data-first-seen="${fresh}" data-index="${rows.indexOf(row)}">
      <div class="process-cell"><span class="process-stamp">${esc(stamp(row.process))}</span><div><strong title="${esc(row.process)}">${esc(row.process)}</strong><small>${esc(label)}</small></div></div>
      <div class="route" aria-hidden="true"></div>
      <div class="remote-cell"><strong title="${esc(row.remote)}">${esc(row.remote)}</strong><small>Local ${esc(row.local)}</small></div>
      <span class="state">${esc(row.state || 'Open')}</span>
    </article>`;
    }).join('');
  applyFilter();
}
function formatBytes(value) {
  const amount = Number(value) || 0;
  if (amount < 1000) return `${amount} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let size = amount / 1000;
  let unit = units.shift();
  while (size >= 1000 && units.length) { size /= 1000; unit = units.shift(); }
  return `${size.toFixed(size >= 100 ? 0 : size >= 10 ? 1 : 2)} ${unit}`;
}
function formatRate(value) {
  const amount = Number(value) || 0;
  if (amount < 1000) return `${amount.toFixed(0)} B/s`;
  return `${formatBytes(amount)}/s`;
}
function renderProcessTable() {
  const source = processShowAll.checked ? allProcessRows : networkProcessRows;
  const query = processSearch.value.trim().toLowerCase();
  const shown = source.filter((row) => !query || `${row.process} ${row.pid} ${row.user}`.toLowerCase().includes(query));
  shown.sort((a, b) => {
    const rateA = (a.receivedRate || 0) + (a.sentRate || 0);
    const rateB = (b.receivedRate || 0) + (b.sentRate || 0);
    return Number(rateB > 0) - Number(rateA > 0) || rateB - rateA || ((b.receivedBytes + b.sentBytes) - (a.receivedBytes + a.sentBytes)) || String(a.process).localeCompare(String(b.process));
  });
  const activeCount = shown.filter((row) => (row.receivedRate || 0) + (row.sentRate || 0) > 0).length;
  const pageCount = Math.max(1, Math.ceil(shown.length / processPageSize));
  processPage = Math.min(processPage, pageCount);
  const start = (processPage - 1) * processPageSize;
  const pageRows = shown.slice(start, start + processPageSize);
  const end = Math.min(start + processPageSize, shown.length);
  processListCount.textContent = shown.length ? `${(start + 1).toLocaleString()}–${end.toLocaleString()} of ${shown.length.toLocaleString()} · ${activeCount.toLocaleString()} active now` : '0 processes';
  processPageLabel.textContent = `Page ${processPage} of ${pageCount}`;
  processPrev.disabled = processPage <= 1;
  processNext.disabled = processPage >= pageCount;
  processList.innerHTML = pageRows.length ? pageRows.map((row) => `<tr><th scope="row"><span class="process-name">${esc(row.process)}</span><small>PID ${esc(row.pid)}</small></th><td>${esc(row.user || 'Unknown')}</td><td>${formatBytes(row.receivedBytes)}</td><td>${formatBytes(row.sentBytes)}</td><td>${Number(row.receivedPackets).toLocaleString()}</td><td>${Number(row.sentPackets).toLocaleString()}</td><td><span class="rate-in">↓ ${formatRate(row.receivedRate)}</span><small class="rate-out">↑ ${formatRate(row.sentRate)}</small></td></tr>`).join('') : '<tr><td colspan="7" class="empty-cell">No processes match this view.</td></tr>';
}
processShowAll.addEventListener('change', () => { processPage = 1; renderProcessTable(); });
processSearch.addEventListener('input', () => { processPage = 1; renderProcessTable(); });
processPrev.addEventListener('click', () => { processPage = Math.max(1, processPage - 1); renderProcessTable(); });
processNext.addEventListener('click', () => { processPage += 1; renderProcessTable(); });

function renderProcesses(processes, sampledAt, inventory = processes) {
  const elapsed = lastMetricSample ? Math.max(0.1, (sampledAt - lastMetricSample) / 1000) : 0;
  const rows = inventory.map((process) => {
    const previous = previousProcesses.get(process.pid);
    const sameProcess = previous && previous.process === process.process;
    const receivedRate = sameProcess && elapsed ? Math.max(0, (process.receivedBytes - previous.receivedBytes) / elapsed) : 0;
    const sentRate = sameProcess && elapsed ? Math.max(0, (process.sentBytes - previous.sentBytes) / elapsed) : 0;
    previousProcesses.set(process.pid, process);
    return { ...process, receivedRate, sentRate };
  }).sort((a, b) => (b.receivedBytes + b.sentBytes) - (a.receivedBytes + a.sentBytes));
  const rowByPid = new Map(rows.map((row) => [row.pid, row]));
  networkProcessRows = processes.map((process) => rowByPid.get(process.pid) || { ...process, receivedRate: 0, sentRate: 0 });
  allProcessRows = rows;
  currentProcessStats = new Map(rows.map((row) => [row.pid, row]));
  document.querySelector('#process-count').textContent = String(networkProcessRows.length);
  document.querySelector('#live-rate').textContent = `${formatRate(networkProcessRows.reduce((sum, row) => sum + row.receivedRate, 0))} in · ${formatRate(networkProcessRows.reduce((sum, row) => sum + row.sentRate, 0))} out`;
  renderProcessTable();
  lastMetricSample = sampledAt;
}
function addEvent(text, date = new Date(), meta = {}) {
  history.unshift({ text, time: date, ...meta });
  history.splice(60);
  renderEvents();
}
function renderEvents() {
  eventList.innerHTML = history.length ? history.map((event) => `<div class="event-row"><span class="event-time">${esc(event.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }))}</span><span>${esc(event.text)}</span></div>`).join('') : '<div class="empty-state">No changes observed yet. Events stay in memory until this page closes.</div>';
}
function applyFilter() {
  const newOnly = filter.value === 'new';
  for (const row of list.querySelectorAll('.connection-row')) row.hidden = newOnly && row.dataset.firstSeen !== 'true';
}
async function refresh() {
  if (busy) return;
  busy = true;
  try {
    const response = await fetch('/api/connections', { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not read network connections.');
    const rows = data.connections || [];
    const sampleAt = Number(data.sampledAt) || Date.now();
    if (data.metricsWarning) lastUpdated.textContent = `Network paths available · process counters: ${data.metricsWarning}`;
    if (!firstSnapshot) {
      const now = new Set(rows.map((row) => [row.pid, row.protocol, row.local, row.remote].join('|')));
      const old = new Set(activeRows.map((row) => [row.pid, row.protocol, row.local, row.remote].join('|')));
      for (const row of rows) {
        const key = [row.pid, row.protocol, row.local, row.remote].join('|');
        if (!old.has(key)) addEvent(`${row.process} opened a connection to ${row.remote}`, new Date(), { kind: 'open', process: row.process, pid: row.pid, remote: row.remote, local: row.local, protocol: row.protocol });
      }
      for (const row of activeRows) {
        const key = [row.pid, row.protocol, row.local, row.remote].join('|');
        if (!now.has(key)) addEvent(`${row.process} connection to ${row.remote} is no longer open`, new Date(), { kind: 'close', process: row.process, pid: row.pid, remote: row.remote, local: row.local, protocol: row.protocol });
      }
    }
    renderConnections(rows);
    renderProcesses(data.processes || [], sampleAt, data.allProcesses || data.processes || []);
    for (const row of rows) known.add([row.pid, row.protocol, row.local, row.remote].join('|'));
    firstSnapshot = false;
    const date = new Date(data.sampledAt);
    liveState.classList.remove('error');
    liveLabel.textContent = 'Observing';
    sampleState.textContent = `Updated ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
    lastUpdated.textContent = data.metricsWarning ? `Connection paths live · process counters unavailable: ${data.metricsWarning}` : `${data.source} · refreshes every ${data.refreshSeconds} seconds`;
  } catch (error) {
    liveState.classList.add('error');
    liveLabel.textContent = 'Unavailable';
    sampleState.textContent = error.message;
    lastUpdated.textContent = 'Check that the local app is running on macOS';
    if (!activeRows.length) list.innerHTML = `<div class="error-state">${esc(error.message)}</div>`;
  } finally {
    busy = false;
  }
}

for (const link of document.querySelectorAll('.nav-item')) {
  link.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach((item) => { item.classList.remove('active'); item.removeAttribute('aria-current'); });
    link.classList.add('active');
    link.setAttribute('aria-current', 'page');
    document.querySelectorAll('.view').forEach((view) => view.classList.toggle('active-view', `#${view.id}` === link.hash));
  });
}
// Direct links such as /#map must activate the requested view on first load.
function syncViewToHash() {
  const target = document.querySelector(`.nav-item[href="${location.hash}"]`);
  if (!target) return;
  document.querySelectorAll('.nav-item').forEach((item) => { item.classList.remove('active'); item.removeAttribute('aria-current'); });
  target.classList.add('active');
  target.setAttribute('aria-current', 'page');
  document.querySelectorAll('.view').forEach((view) => view.classList.toggle('active-view', `#${view.id}` === target.hash));
  // Wait until the map filter and other page state have initialized below.
  if (target.hash === '#map') setTimeout(() => renderMap(), 0);
}
const themeToggle = document.querySelector('#theme-toggle');
function applyTheme(theme) {
  const selected = theme === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = selected;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', selected === 'dark' ? '#171d20' : '#f3f0e6');
  if (themeToggle) {
    const next = selected === 'dark' ? 'light' : 'dark';
    themeToggle.setAttribute('aria-label', `Switch to ${next} theme`);
    themeToggle.innerHTML = `<span aria-hidden="true">${next === 'light' ? '☼' : '◐'}</span><span>${next === 'light' ? 'Light' : 'Dark'} mode</span>`;
  }
}
applyTheme(document.documentElement.dataset.theme || 'dark');
themeToggle?.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  try { localStorage.setItem('local-watch-theme', next); } catch { /* Theme still works for this page. */ }
});
syncViewToHash();
window.addEventListener('hashchange', syncViewToHash);
document.querySelector('#refresh').addEventListener('click', refresh);
document.querySelector('#clear-events').addEventListener('click', () => { history.length = 0; renderEvents(); });
filter.addEventListener('change', applyFilter);
list.addEventListener('click', (event) => {
  const card = event.target.closest('.connection-row');
  if (!card) return;
  document.querySelectorAll('.connection-row').forEach((row) => row.classList.toggle('selected', row === card));
  const row = activeRows[Number(card.dataset.index)];
  if (!row) return;
  const stats = currentProcessStats.get(row.pid);
  document.querySelector('#flow-inspector').innerHTML = `<div class="inspector-grid"><div><span>Process</span><strong>${esc(row.process)} · PID ${esc(row.pid)}</strong></div><div><span>Protocol / state</span><strong>${esc(row.protocol)} · ${esc(row.state)}</strong></div><div><span>Local endpoint</span><strong>${esc(row.local)}</strong></div><div><span>Remote endpoint</span><strong>${esc(row.remote)}</strong></div>${stats ? `<div><span>Process traffic received</span><strong>${formatBytes(stats.receivedBytes)} · ${Number(stats.receivedPackets).toLocaleString()} packets</strong></div><div><span>Process traffic sent</span><strong>${formatBytes(stats.sentBytes)} · ${Number(stats.sentPackets).toLocaleString()} packets</strong></div>` : ''}</div><p class="inspector-caption">Counters belong to the whole process and cannot be attributed to this one socket.</p>`;
});
renderEvents();
refresh();
window.setInterval(refresh, 3000);
// Packet capture
const cap = {
  iface: document.querySelector('#cap-iface'), dur: document.querySelector('#cap-dur'), start: document.querySelector('#cap-start'), displayFilter: document.querySelector('#cap-display-filter'),
  clear: document.querySelector('#cap-clear'), status: document.querySelector('#cap-status'), summary: document.querySelector('#cap-summary'),
  filterWrap: document.querySelector('#cap-filter-wrap'), filter: document.querySelector('#cap-filter'), tableWrap: document.querySelector('#cap-table-wrap'),
  rows: document.querySelector('#cap-rows'), detail: document.querySelector('#cap-detail'), dialog: document.querySelector('#cap-dialog'), dialogText: document.querySelector('#cap-dialog-text'),
};
let capPackets = [];
let capPoll = null;

function portOf(endpoint) {
  const i = String(endpoint || '').lastIndexOf(':');
  return i < 0 ? '' : endpoint.slice(i + 1);
}
function localPortMap() {
  const map = new Map();
  for (const row of activeRows) { const p = portOf(row.local); if (p) map.set(p, row.process); }
  return map;
}
function enrich(packets) {
  const names = new Map();
  for (const p of packets) {
    const name = p.tlsSNI || p.httpHost;
    if (name && p.ipDst) names.set(p.ipDst, name);
    if (name && p.ipv6Dst) names.set(p.ipv6Dst, name);
  }
  const ports = localPortMap();
  return packets.map((p) => {
    const src = p.ipSrc || p.ipv6Src;
    const dst = p.ipDst || p.ipv6Dst;
    const sport = p.tcpSrc || p.udpSrc;
    const dport = p.tcpDst || p.udpDst;
    let process = '';
    if (ports.has(sport)) process = ports.get(sport);
    else if (ports.has(dport)) process = ports.get(dport);
    return { ...p, src, dst, sport, dport, process, srcName: names.get(src) || '', dstName: names.get(dst) || '' };
  });
}
function topCounts(items, n = 4) {
  const counts = new Map();
  for (const item of items) if (item) counts.set(item, (counts.get(item) || 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}
function renderCapture() {
  const has = capPackets.length > 0;
  cap.summary.hidden = cap.filterWrap.hidden = cap.tableWrap.hidden = !has;
  if (!has) { cap.rows.innerHTML = ''; return; }
  const bytes = capPackets.reduce((sum, p) => sum + (Number(p.len) || 0), 0);
  const protocols = topCounts(capPackets.map((p) => p.protocol));
  const hosts = topCounts(capPackets.flatMap((p) => [p.dstName || p.dst, p.srcName || p.src]).filter((h) => h && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|127\.)/.test(h)));
  const list = (pairs) => pairs.length ? pairs.map(([k, v]) => `<li><span>${esc(k)}</span><b>${v}</b></li>`).join('') : '<li><span>None seen</span></li>';
  cap.summary.innerHTML = `<div class="cap-card"><span>Packets</span><strong>${capPackets.length.toLocaleString()}</strong></div><div class="cap-card"><span>Bytes</span><strong>${formatBytes(bytes)}</strong></div><div class="cap-card"><span>Top protocols</span><ul>${list(protocols)}</ul></div><div class="cap-card"><span>Top remote hosts</span><ul>${list(hosts)}</ul></div>`;
  const q = cap.filter.value.trim().toLowerCase();
  const shown = capPackets.map((p, i) => [p, i]).filter(([p]) => !q || [p.protocol, p.src, p.dst, p.srcName, p.dstName, p.process, p.dnsQry, p.info].join(' ').toLowerCase().includes(q));
  cap.rows.innerHTML = shown.slice(0, 1500).map(([p, i]) => `<tr data-i="${i}" tabindex="0"><td>${esc(p.frame)}</td><td>${esc(Number(p.time).toFixed(3))}</td><td>${esc(p.process || '-')}</td><td>${esc(p.srcName || p.src || '-')}</td><td>${esc(p.dstName || p.dst || '-')}</td><td>${esc(p.protocol)}</td><td>${esc(p.len)}</td><td class="cap-info">${esc(p.info)}</td></tr>`).join('') || '<tr><td colspan="8" class="empty-cell">No packets match this filter.</td></tr>';
}
function packetLayerDetails(p) {
  const groups = [
    ['Frame', [['Protocol stack', p.frameProtocols], ['Captured length', p.capturedLength && `${p.capturedLength} bytes`]]],
    ['Ethernet', [['Source MAC', p.ethSrc], ['Destination MAC', p.ethDst], ['EtherType', p.ethType]]],
    ['IP', [['IPv4 TTL', p.ttl], ['IPv4 protocol', p.ipProto], ['IPv4 identification', p.ipId], ['IPv4 flags', p.ipFlags], ['IPv4 checksum', p.ipChecksum], ['IPv6 next header', p.ipv6Next], ['IPv6 payload length', p.ipv6Length], ['IPv6 hop limit', p.ipv6HopLimit]]],
    ['TCP', [['Sequence number', p.tcpSequence], ['Acknowledgment number', p.tcpAck], ['Header length', p.tcpHeaderLength && `${p.tcpHeaderLength} bytes`], ['Data length', p.tcpPayloadLength && `${p.tcpPayloadLength} bytes`], ['Flags', p.tcpFlags], ['Window size', p.tcpWindow], ['Checksum', p.tcpChecksum], ['Retransmission', p.tcpRetransmission && 'TShark marked this packet as a retransmission']]],
    ['UDP', [['Datagram length', p.udpLength && `${p.udpLength} bytes`], ['Checksum', p.udpChecksum]]],
    ['DNS', [['Transaction ID', p.dnsId], ['Flags', p.dnsFlags], ['Query type', p.dnsQueryType], ['Answer name', p.dnsAnswerName], ['Answer TTL', p.dnsTtl], ['IPv4 answers', p.dnsA], ['IPv6 answers', p.dnsAAAA]]],
    ['TLS', [['Record content type', p.tlsContentType], ['Record length', p.tlsRecordLength && `${p.tlsRecordLength} bytes`], ['Record version', p.tlsVersion], ['Handshake type', p.tlsHandshakeType], ['Handshake version', p.tlsHandshakeVersion], ['Cipher suite', p.tlsCipherSuite], ['Server name', p.tlsSNI]]],
  ];
  const visible = groups.map(([name, fields]) => [name, fields.filter(([, value]) => value)]).filter(([, fields]) => fields.length);
  if (!visible.length) return '';
  return `<section class="packet-deep"><h3>Decoded protocol fields</h3><p>These are fields TShark dissected from this packet's headers. Packet contents and raw bytes are not shown here.</p>${visible.map(([name, fields]) => `<details class="packet-layer"><summary>${esc(name)} <span>${fields.length} fields</span></summary><dl>${fields.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl></details>`).join('')}</section>`;
}
function showPacket(i) {
  const p = capPackets[i];
  if (!p) return;
  cap.rows.querySelectorAll('tr').forEach((tr) => tr.classList.toggle('selected', tr.dataset.i === String(i)));
  const rows = [['Frame', p.frame], ['Time', `${p.time} s`], ['Length', `${p.len} bytes`], ['Process', p.process || 'Not matched to an open connection'], ['Source', `${p.src || '-'}${p.sport ? ':' + p.sport : ''}${p.srcName ? ' (' + p.srcName + ')' : ''}`], ['Destination', `${p.dst || '-'}${p.dport ? ':' + p.dport : ''}${p.dstName ? ' (' + p.dstName + ')' : ''}`], ['Protocol', p.protocol], ['DNS question', p.dnsQry], ['TLS server name', p.tlsSNI], ['HTTP host', p.httpHost], ['Info', p.info]];
  cap.detail.innerHTML = `<div class="inspector-grid">${rows.filter(([, v]) => v).map(([k, v]) => `<div><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')}</div>${packetLayerDetails(p)}<p class="packet-limit-note">Process is a best-effort match by local port, not a kernel-level packet attribution. TShark can dissect only what this interface observed. TLS application data remains encrypted; port 443 alone does not prove TLS.</p>`;
}
async function loadInterfaces() {
  try {
    const res = await fetch('/api/capture/interfaces', { cache: 'no-store' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    cap.iface.innerHTML = data.map((i) => `<option value="${esc(i.name)}">${esc(i.description ? `${i.description} (${i.name})` : i.name)}</option>`).join('');
    const wifi = data.find((i) => /wi-?fi/i.test(i.description)) || data.find((i) => i.name === 'en0');
    if (wifi) cap.iface.value = wifi.name;
  } catch (e) {
    cap.iface.innerHTML = '<option value="">Unavailable</option>';
    cap.start.disabled = true;
    cap.status.textContent = e.message || 'TShark is not available';
  }
}
async function pollCapture() {
  try {
    const res = await fetch('/api/capture', { cache: 'no-store' });
    const data = await res.json();
    capPackets = enrich(data.packets || []);
    if (data.state === 'running') {
      cap.status.textContent = `Capturing on ${data.interface} · ${capPackets.length} packets so far`;
      renderCapture();
      return;
    }
    clearInterval(capPoll); capPoll = null; cap.start.disabled = false;
    cap.status.textContent = data.state === 'error' ? `Capture stopped: ${data.error}` : data.state === 'done' ? `Captured ${capPackets.length} packets in ${data.seconds} s on ${data.interface}` : 'No capture yet';
    renderCapture();
  } catch (e) {
    clearInterval(capPoll); capPoll = null; cap.start.disabled = false;
    cap.status.textContent = 'Lost contact with the local app';
  }
}
cap.start.addEventListener('click', () => {
  if (!cap.iface.value) return;
  const expression = cap.displayFilter.value.trim();
  cap.dialogText.textContent = `This reads packet headers on ${cap.iface.selectedOptions[0].textContent} for ${cap.dur.value} seconds${expression ? ` using the display filter “${expression}”` : ''}. Matching decoded fields stay only in this app's memory; nothing is saved to disk and nothing is sent anywhere. The filter limits displayed results; it does not prevent the interface from seeing other packets during this short capture.`;
  cap.dialog.showModal();
});
cap.dialog.addEventListener('close', async () => {
  if (cap.dialog.returnValue !== 'ok') return;
  cap.start.disabled = true;
  cap.status.textContent = 'Starting…';
  const res = await fetch('/api/capture', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ interface: cap.iface.value, seconds: Number(cap.dur.value), displayFilter: cap.displayFilter.value.trim(), confirm: true }) });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    cap.status.textContent = data.error || 'Capture could not start';
    cap.start.disabled = false;
    return;
  }
  capPoll = setInterval(pollCapture, 1000);
});
cap.clear.addEventListener('click', async () => {
  await fetch('/api/capture', { method: 'DELETE' });
  clearInterval(capPoll); capPoll = null;
  capPackets = []; cap.start.disabled = false; cap.filter.value = '';
  cap.status.textContent = 'Cleared';
  cap.detail.innerHTML = '<div class="inspector-empty">Start a capture, then select a packet to see all of its fields.</div>';
  renderCapture();
});
window.addEventListener('pagehide', () => {
  if (capPoll) clearInterval(capPoll);
  // Drop the in-memory capture and stop TShark when this local page closes.
  fetch('/api/capture', { method: 'DELETE', keepalive: true }).catch(() => {});
});
cap.filter.addEventListener('input', () => renderCapture());
cap.rows.addEventListener('click', (e) => { const tr = e.target.closest('tr[data-i]'); if (tr) showPacket(Number(tr.dataset.i)); });
cap.rows.addEventListener('keydown', (e) => { if (e.key === 'Enter') { const tr = e.target.closest('tr[data-i]'); if (tr) showPacket(Number(tr.dataset.i)); } });
loadInterfaces();
pollCapture();

// Map and local explanations
const mapSvg = document.querySelector('#map-svg');
const mapDetail = document.querySelector('#map-detail');
const mapScope = document.querySelector('#map-scope');
const names = new Map();
const PORTS = { 443: 'HTTPS', 80: 'HTTP', 53: 'DNS', 853: 'DNS over TLS', 993: 'IMAP mail', 587: 'SMTP mail', 22: 'SSH', 5223: 'Apple push', 123: 'Time sync', 3478: 'Calls and video' };
let mapModel = { apps: [], dests: [], links: [] };
let selectedMapSelection = null;

function hostOf(endpoint) {
  const s = String(endpoint || '');
  const i = s.lastIndexOf(':');
  return (i < 0 ? s : s.slice(0, i)).replace(/^\[|\]$/g, '');
}
function isPrivate(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fc|fd)/i.test(ip);
}
function sniNames() {
  const out = new Map();
  for (const p of capPackets) {
    const n = p.tlsSNI || p.httpHost;
    if (n && p.dst) out.set(p.dst, n);
  }
  return out;
}
function destLabel(ip) {
  if (isPrivate(ip)) return 'local network';
  return sniNames().get(ip) || names.get(ip) || ip;
}
async function lookupNames(ips) {
  const missing = ips.filter((ip) => !names.has(ip) && !isPrivate(ip)).slice(0, 60);
  if (!missing.length) return;
  try {
    const res = await fetch(`/api/names?ips=${encodeURIComponent(missing.join(','))}`, { cache: 'no-store' });
    const data = await res.json();
    for (const [ip, n] of Object.entries(data)) names.set(ip, n);
    renderMap();
  } catch { /* names are optional */ }
}
function buildMap() {
  const internetOnly = mapScope.value === 'internet';
  const capBytes = new Map();
  for (const p of capPackets) {
    if (!p.process) continue;
    for (const ip of [p.src, p.dst]) {
      if (!ip) continue;
      const key = `${p.process}|${ip}`;
      capBytes.set(key, (capBytes.get(key) || 0) + (Number(p.len) || 0));
    }
  }
  const links = new Map();
  for (const row of activeRows) {
    const ip = hostOf(row.remote);
    if (!ip || (internetOnly && isPrivate(ip))) continue;
    const key = `${row.process}|${ip}`;
    const link = links.get(key) || { app: row.process, ip, count: 0, ports: new Set(), protocols: new Set(), pids: new Set(), states: new Set() };
    link.count += 1;
    link.ports.add(portOf(row.remote));
    link.protocols.add(row.protocol);
    link.pids.add(row.pid);
    link.states.add(row.state);
    links.set(key, link);
  }
  const all = [...links.values()].map((l) => ({ ...l, bytes: capBytes.get(`${l.app}|${l.ip}`) || 0 }));
  const appTotals = new Map();
  const destTotals = new Map();
  for (const l of all) {
    appTotals.set(l.app, (appTotals.get(l.app) || 0) + l.count);
    destTotals.set(l.ip, (destTotals.get(l.ip) || 0) + l.count);
  }
  const apps = [...appTotals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 16).map(([name]) => name);
  const dests = [...destTotals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 18).map(([ip]) => ip);
  const shown = all.filter((l) => apps.includes(l.app) && dests.includes(l.ip));
  return { apps, dests, links: shown, hiddenApps: appTotals.size - apps.length, hiddenDests: destTotals.size - dests.length };
}
function svgEl(tag, attrs, text) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (text != null) el.textContent = text;
  return el;
}
function cut(text, n) {
  const s = String(text);
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}
function applyMapSelection() {
  if (!selectedMapSelection) return;
  const { app, ip } = selectedMapSelection;
  mapSvg.querySelectorAll('.map-line').forEach((path) => {
    const [lineApp, lineIp] = path.dataset.key.split('|');
    const match = (!app || lineApp === app) && (!ip || lineIp === ip);
    path.classList.toggle('dim', !match);
    path.classList.toggle('selected', match);
  });
  mapSvg.querySelectorAll('.map-node').forEach((node) => {
    node.classList.toggle('selected', (app && node.dataset.app === app) || (ip && node.dataset.ip === ip));
  });
}
function renderMap() {
  if (!document.querySelector('#map').classList.contains('active-view')) return;
  mapModel = buildMap();
  const { apps, dests, links } = mapModel;
  const rowH = 30;
  const rows = Math.max(apps.length, dests.length, 1);
  const height = rows * rowH + 40;
  const W = 900, leftX = 250, rightX = 650;
  mapSvg.setAttribute('viewBox', `0 0 ${W} ${height}`);
  mapSvg.replaceChildren();
  if (!links.length) {
    mapSvg.append(svgEl('text', { x: W / 2, y: 40, 'text-anchor': 'middle', class: 'map-empty' }, activeRows.length ? 'No internet connections right now.' : 'Waiting for the first snapshot…'));
    return;
  }
  const yApp = (i) => 30 + i * rowH + (rows - apps.length) * rowH / 2;
  const yDest = (i) => 30 + i * rowH + (rows - dests.length) * rowH / 2;
  const useBytes = links.some((l) => l.bytes > 0);
  const maxW = Math.max(...links.map((l) => (useBytes ? l.bytes : l.count)));
  const lineLayer = svgEl('g', { class: 'map-lines' });
  for (const l of links) {
    const y1 = yApp(apps.indexOf(l.app));
    const y2 = yDest(dests.indexOf(l.ip));
    const v = useBytes ? l.bytes : l.count;
    const w = 1.2 + 6 * Math.sqrt(v / maxW);
    const d = `M ${leftX + 8} ${y1} C ${leftX + 160} ${y1}, ${rightX - 160} ${y2}, ${rightX - 8} ${y2}`;
    const path = svgEl('path', { d, 'stroke-width': w.toFixed(1), class: 'map-line', tabindex: 0, role: 'button', 'aria-label': `${l.app} connection to ${destLabel(l.ip)}`, 'data-key': `${l.app}|${l.ip}` });
    path.append(svgEl('title', {}, `${l.app} to ${destLabel(l.ip)}: ${l.count} connection${l.count > 1 ? 's' : ''}`));
    lineLayer.append(path, svgEl('path', { d, class: 'map-hit', 'aria-hidden': 'true', 'data-key': `${l.app}|${l.ip}` }));
  }
  mapSvg.append(lineLayer);
  apps.forEach((a, i) => {
    const g = svgEl('g', { class: 'map-node', tabindex: 0, role: 'button', 'aria-label': `Select ${a}`, 'data-app': a });
    g.append(svgEl('circle', { cx: leftX, cy: yApp(i), r: 5 }), svgEl('text', { x: leftX - 14, y: yApp(i) + 4, 'text-anchor': 'end' }, cut(a, 30)));
    mapSvg.append(g);
  });
  dests.forEach((ip, i) => {
    const g = svgEl('g', { class: `map-node${isPrivate(ip) ? ' local' : ''}`, tabindex: 0, role: 'button', 'aria-label': `Select destination ${destLabel(ip)}`, 'data-ip': ip });
    g.append(svgEl('circle', { cx: rightX, cy: yDest(i), r: 5 }), svgEl('text', { x: rightX + 14, y: yDest(i) + 4 }, cut(destLabel(ip), 34)));
    mapSvg.append(g);
  });
  applyMapSelection();
  lookupNames(dests);
}
function selectOnMap({ app, ip }) {
  selectedMapSelection = { app: app || null, ip: ip || null };
  applyMapSelection();
  const related = mapModel.links.filter((l) => (!app || l.app === app) && (!ip || l.ip === ip));
  const item = { kind: app && ip ? 'connection' : app ? 'app' : 'destination' };
  if (app) item.app = app;
  if (ip) { item.address = ip; item.reverse_dns = names.get(ip) || ''; item.tls_server_name = sniNames().get(ip) || ''; }
  item.ports = [...new Set(related.flatMap((l) => [...l.ports]))].map((p) => (PORTS[p] ? `${p} (${PORTS[p]})` : p)).join(', ');
  item.protocols = [...new Set(related.flatMap((l) => [...l.protocols]))].join(', ');
  item.connections = related.reduce((s, l) => s + l.count, 0);
  if (!ip) item.destinations = related.map((l) => destLabel(l.ip)).slice(0, 12).join(', ');
  if (!app) item.apps = [...new Set(related.map((l) => l.app))].join(', ');
  const bytes = related.reduce((s, l) => s + l.bytes, 0);
  if (bytes) item.bytes_in_last_capture = bytes;
  const rows = Object.entries(item).filter(([k, v]) => k !== 'kind' && v !== '' && v != null);
  const socketRows = app && ip ? activeRows.filter((r) => r.process === app && hostOf(r.remote) === ip).slice(0, 4) : [];
  const socketHtml = socketRows.length ? `<div class="socket-diagram">${socketRows.map((r) => `<div class="socket-row"><span class="sock-end">${esc(r.process)}<small>${esc(r.local)}</small></span><span class="sock-pipe">${esc(r.protocol)} · ${esc(r.state)}</span><span class="sock-end">${esc(destLabel(ip))}<small>${esc(r.remote)}</small></span></div>`).join('')}<p class="learn-note"><b>What is a socket?</b> macOS creates a communication endpoint in its kernel and gives the app a file-descriptor handle to it. Once connected, the flow can be described by its protocol and the local and remote IP-address/port pairs shown above. The handle itself is not an IP address.</p></div>` : '';
  const judge = ip && !isPrivate(ip) ? `<div class="judge"><b>How to judge an address</b><ul><li>Who owns it: <span class="owner-line">looking up…</span></li><li>Does the owner fit the app? A password manager talking to Amazon CloudFront is normal; a calculator talking to an unknown host abroad is not.</li><li>Port 443 is ordinary encrypted web traffic. Unusual ports deserve a second look.</li><li>New, at night, or from an app that never went online before: worth a check, not proof of harm.</li></ul><small>Owner lookup asks the public internet registry (whois) about this address.</small></div>` : '';
  mapDetail.innerHTML = `<div class="inspector-grid">${rows.map(([k, v]) => `<div><span>${esc(k.replace(/_/g, ' '))}</span><strong>${esc(v)}</strong></div>`).join('')}</div>${socketHtml}${judge}${explainBlock()}`;
  bindExplain(mapDetail, item);
  if (judge) {
    fetch(`/api/owner?ip=${encodeURIComponent(ip)}`, { cache: 'no-store' }).then((r) => r.json()).then((o) => {
      const line = mapDetail.querySelector('.owner-line');
      if (!line) return;
      line.textContent = [o.org || o.network || 'unknown', o.country, o.reverseDns].filter(Boolean).join(' · ');
      item.owner = o.org || o.network || '';
      item.owner_country = o.country || '';
      item.reverse_dns = o.reverseDns || item.reverse_dns;
    }).catch(() => { const line = mapDetail.querySelector('.owner-line'); if (line) line.textContent = 'lookup failed'; });
  }
}
function explainBlock() {
  return '<div class="explain"><button class="cap-button explain-button" type="button">Explain with local AI</button><p class="explain-text" aria-live="polite"></p></div>';
}
function bindExplain(container, item) {
  const button = container.querySelector('.explain-button');
  const out = container.querySelector('.explain-text');
  button.addEventListener('click', async () => {
    button.disabled = true;
    out.textContent = 'Asking the model on this Mac…';
    try {
      const res = await fetch('/api/explain', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(item) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'The local model did not answer.');
      out.textContent = data.text;
      out.dataset.model = data.model;
    } catch (e) {
      out.textContent = `${e.message} Check that Ollama is running on this Mac.`;
    } finally {
      button.disabled = false;
    }
  });
}
mapSvg.addEventListener('click', (e) => {
  const line = e.target.closest('.map-line, .map-hit');
  if (line) { const [app, ip] = line.dataset.key.split('|'); selectOnMap({ app, ip }); mapDetail.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); return; }
  const node = e.target.closest('.map-node');
  if (node) { selectOnMap(node.dataset.app ? { app: node.dataset.app } : { ip: node.dataset.ip }); mapDetail.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }
});
mapSvg.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.target.dispatchEvent(new MouseEvent('click', { bubbles: true })); } });
mapScope.addEventListener('change', () => renderMap());
document.querySelector('a[href="#map"]').addEventListener('click', () => setTimeout(() => renderMap(), 0));
setInterval(() => renderMap(), 3000);

// Explain a captured packet too
const baseShowPacket = showPacket;
showPacket = function (i) {
  baseShowPacket(i);
  const p = capPackets[i];
  if (!p) return;
  cap.detail.insertAdjacentHTML('beforeend', layersHtml(p) + explainBlock());
  bindExplain(cap.detail, { kind: 'packet', process: p.process, source: p.srcName || p.src, destination: p.dstName || p.dst, source_port: p.sport, destination_port: p.dport, protocol: p.protocol, length: p.len, dns_question: p.dnsQry, tls_server_name: p.tlsSNI, info: p.info });
};

const APP_PROTOCOLS = {
  TLS: 'TLS wraps the conversation in encryption. You can see who it talks to (server name), not what it says.',
  'TLSv1.2': 'TLS 1.2 encryption. Content is hidden; the server name is often visible in the first message.',
  'TLSv1.3': 'TLS 1.3 encryption, the modern version. Content is hidden.',
  QUIC: 'QUIC is encrypted web traffic over UDP, used by browsers and Google, Apple and Cloudflare services.',
  DNS: 'DNS turns a name like apple.com into an IP address. It is how apps find servers.',
  HTTP: 'Plain HTTP, not encrypted. Anyone on the network path can read it.',
  MDNS: 'mDNS finds devices on the local network, like printers and AirPlay speakers.',
  ICMP: 'ICMP carries network status messages, such as ping replies.',
  ARP: 'ARP asks which device on the Wi-Fi owns an IP address.',
};
function layersHtml(p) {
  const transport = p.tcpSrc ? 'TCP' : p.udpSrc ? 'UDP' : '';
  const app = p.protocol && p.protocol !== transport ? p.protocol : '';
  const appText = APP_PROTOCOLS[app] || (app ? `${app} is the application protocol in this packet.` : 'No application data in this packet; it only manages the connection.');
  const layers = [
    ['7 Application', app || 'none', [p.tlsSNI && `server name ${p.tlsSNI}`, p.dnsQry && `asks for ${p.dnsQry}`, p.httpHost && `host ${p.httpHost}`, p.tlsVersion && `record ${p.tlsVersion}`].filter(Boolean).join(' · '), appText],
    ['4 Transport', transport || p.protocol, [p.sport && `port ${p.sport} → ${p.dport}`, p.tcpFlags && `flags ${p.tcpFlags}`].filter(Boolean).join(' · '), transport === 'TCP' ? 'TCP delivers bytes in order and resends what is lost. Flags like SYN, ACK and FIN open, confirm and close the conversation. Ports say which app on each side.' : transport === 'UDP' ? 'UDP sends single messages without a connection. Fast, used for DNS, calls and QUIC.' : 'No transport layer in this packet.'],
    ['3 Network', p.src && p.src.includes(':') ? 'IPv6' : 'IPv4', [p.src && `${p.src} → ${p.dst}`, p.ttl && `TTL ${p.ttl}`].filter(Boolean).join(' · '), 'IP addresses route the packet across networks, router by router. TTL counts down at each hop so lost packets do not loop forever.'],
    ['2 Link', 'Wi-Fi / Ethernet', [p.ethSrc && `${p.ethSrc} → ${p.ethDst}`].filter(Boolean).join(''), 'MAC addresses move the packet one hop, from your Mac to the router. They change at every hop; IP addresses do not.'],
    ['1 Physical', 'radio or cable', `${p.len} bytes on the wire`, 'The bits themselves: radio waves on Wi-Fi, light or voltage on a cable.'],
  ];
  return `<div class="layers"><b>This packet, layer by layer (OSI model)</b>${layers.map(([name, proto, values, text]) => `<details class="layer"><summary><span class="layer-name">${esc(name)}</span><span class="layer-proto">${esc(proto)}</span><span class="layer-values">${esc(values)}</span></summary><p>${esc(text)}</p></details>`).join('')}<p class="learn-note">Layers 5 and 6 of the OSI model (session, presentation) have no separate fields here: TLS does their work. Real networks follow the simpler TCP/IP model, the OSI numbers are a teaching map.</p></div>`;
}

// Attention markers from the local baseline
const attention = document.querySelector('#attention');
let markers = [];
let learningUntil = 0;
const KIND_LABEL = { 'new-app': 'New app online', 'new-destination': 'New destination', 'unusual-port': 'Unusual port', night: 'Night activity', volume: 'Unusual volume' };
const SEV_LABEL = { attention: 'Needs a look', notice: 'Worth knowing', info: 'Routine' };
const SEV_ORDER = { attention: 0, notice: 1, info: 2 };
const sevOf = (m) => m.severity || 'notice';
const isRoutine = (m) => sevOf(m) === 'info';
async function loadMarkers() {
  try {
    const res = await fetch('/api/markers', { cache: 'no-store' });
    const data = await res.json();
    markers = (data.markers || []).sort((a, b) => SEV_ORDER[sevOf(a)] - SEV_ORDER[sevOf(b)] || b.at - a.at);
    learningUntil = data.learningUntil || 0;
    const info = document.querySelector('#history-info');
    if (info) info.textContent = `${data.apps} apps learned · stored only on this Mac in ${data.file}`;
    renderAttention();
    renderMap();
    window.dispatchEvent(new CustomEvent('markers-updated'));
  } catch { /* markers are optional */ }
}
function renderAttention() {
  const learning = Date.now() < learningUntil;
  const head = learning ? `<p class="attention-learning">Learning what is normal for this Mac until ${new Date(learningUntil).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' })}. Markers start after that.</p>` : '';
  const indexed = markers.map((m, i) => [m, i]);
  const main = indexed.filter(([m]) => !isRoutine(m));
  const routine = indexed.filter(([m]) => isRoutine(m));
  const card = ([m, i]) => `<article class="attention-item" data-i="${i}" data-sev="${esc(sevOf(m))}"><span class="attention-kind">${esc(KIND_LABEL[m.kind] || m.kind)} · ${esc(SEV_LABEL[sevOf(m)])}</span><p>${esc(m.text)}</p>${m.reason ? `<p class="attention-reason">${esc(m.reason)}</p>` : ''}<small>${esc(new Date(m.at).toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }))}</small><div class="attention-actions"><button class="text-button attention-show" type="button">Show on map</button><button class="text-button attention-ok" type="button">Looks normal</button></div></article>`;
  const list = main.length ? `<div class="attention-list">${main.slice(0, 8).map(card).join('')}</div>` : '<p class="attention-quiet">Nothing needs a look right now.</p>';
  const folded = routine.length ? `<details class="attention-routine"><summary>${routine.length} routine ${routine.length === 1 ? 'event' : 'events'}: macOS services talking to Apple, account sync and downloads</summary><div class="attention-list">${routine.slice(0, 24).map(card).join('')}</div></details>` : '';
  attention.innerHTML = `${head}${list}${folded}`;
}
attention.addEventListener('click', async (e) => {
  const card = e.target.closest('.attention-item');
  if (!card) return;
  const m = markers[Number(card.dataset.i)];
  if (!m) return;
  if (e.target.closest('.attention-ok')) {
    await fetch('/api/markers/accept', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: m.key }) });
    loadMarkers();
    return;
  }
  if (e.target.closest('.attention-show')) {
    const inMap = m.ip && mapModel.dests.includes(m.ip);
    selectOnMap(inMap ? { app: m.app, ip: m.ip } : { app: m.app });
    const note = `<p class="attention-why"><b>${esc(KIND_LABEL[m.kind] || m.kind)}:</b> ${esc(m.text)}${inMap ? '' : ' The connection is not open right now.'}</p>`;
    mapDetail.insertAdjacentHTML('afterbegin', note);
  }
});
const baseRenderMap = renderMap;
renderMap = function () {
  baseRenderMap();
  const flagged = markers.filter((m) => !isRoutine(m));
  const flaggedApps = new Set(flagged.map((m) => m.app));
  const flaggedIps = new Set(flagged.map((m) => m.ip).filter(Boolean));
  mapSvg.querySelectorAll('.map-node').forEach((g) => g.classList.toggle('flag', flaggedApps.has(g.dataset.app) || flaggedIps.has(g.dataset.ip)));
  mapSvg.querySelectorAll('.map-line').forEach((p) => { const [a, ip] = p.dataset.key.split('|'); p.classList.toggle('flag', flagged.some((m) => m.app === a && m.ip === ip)); });
};
document.querySelector('#forget-history').addEventListener('click', async (e) => {
  const button = e.target;
  if (button.dataset.armed !== 'yes') { button.dataset.armed = 'yes'; button.textContent = 'Press again to delete. Learning starts over.'; return; }
  await fetch('/api/history', { method: 'DELETE' });
  button.dataset.armed = ''; button.textContent = 'Deleted. Learning started over.';
  loadMarkers();
});
loadMarkers();
setInterval(loadMarkers, 15000);

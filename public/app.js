const list = document.querySelector('#connection-list');
const processList = document.querySelector('#process-list');
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
function renderProcesses(processes, sampledAt) {
  const elapsed = lastMetricSample ? Math.max(0.1, (sampledAt - lastMetricSample) / 1000) : 0;
  const rows = processes.map((process) => {
    const previous = previousProcesses.get(process.pid);
    const receivedRate = previous && elapsed ? Math.max(0, (process.receivedBytes - previous.receivedBytes) / elapsed) : 0;
    const sentRate = previous && elapsed ? Math.max(0, (process.sentBytes - previous.sentBytes) / elapsed) : 0;
    previousProcesses.set(process.pid, process);
    return { ...process, receivedRate, sentRate };
  }).sort((a, b) => (b.receivedBytes + b.sentBytes) - (a.receivedBytes + a.sentBytes));
  currentProcessStats = new Map(rows.map((row) => [row.pid, row]));
  document.querySelector('#process-count').textContent = String(rows.length);
  document.querySelector('#live-rate').textContent = `${formatRate(rows.reduce((sum, row) => sum + row.receivedRate, 0))} in · ${formatRate(rows.reduce((sum, row) => sum + row.sentRate, 0))} out`;
  processList.innerHTML = rows.length ? rows.map((row) => `<tr><th scope="row"><span class="process-name">${esc(row.process)}</span><small>PID ${esc(row.pid)}</small></th><td>${formatBytes(row.receivedBytes)}</td><td>${formatBytes(row.sentBytes)}</td><td>${Number(row.receivedPackets).toLocaleString()}</td><td>${Number(row.sentPackets).toLocaleString()}</td><td><span class="rate-in">↓ ${formatRate(row.receivedRate)}</span><small class="rate-out">↑ ${formatRate(row.sentRate)}</small></td></tr>`).join('') : '<tr><td colspan="6" class="empty-cell">No process counters are visible right now.</td></tr>';
  lastMetricSample = sampledAt;
}
function addEvent(text, date = new Date()) {
  history.unshift({ text, time: date });
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
        if (!old.has(key)) addEvent(`${row.process} opened a connection to ${row.remote}`);
      }
      for (const row of activeRows) {
        const key = [row.pid, row.protocol, row.local, row.remote].join('|');
        if (!now.has(key)) addEvent(`${row.process} connection to ${row.remote} is no longer open`);
      }
    }
    renderConnections(rows);
    renderProcesses(data.processes || [], sampleAt);
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
  iface: document.querySelector('#cap-iface'), dur: document.querySelector('#cap-dur'), start: document.querySelector('#cap-start'),
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
function showPacket(i) {
  const p = capPackets[i];
  if (!p) return;
  cap.rows.querySelectorAll('tr').forEach((tr) => tr.classList.toggle('selected', tr.dataset.i === String(i)));
  const rows = [['Frame', p.frame], ['Time', `${p.time} s`], ['Length', `${p.len} bytes`], ['Process', p.process || 'Not matched to an open connection'], ['Source', `${p.src || '-'}${p.sport ? ':' + p.sport : ''}${p.srcName ? ' (' + p.srcName + ')' : ''}`], ['Destination', `${p.dst || '-'}${p.dport ? ':' + p.dport : ''}${p.dstName ? ' (' + p.dstName + ')' : ''}`], ['Protocol', p.protocol], ['DNS question', p.dnsQry], ['TLS server name', p.tlsSNI], ['HTTP host', p.httpHost], ['Info', p.info]];
  cap.detail.innerHTML = `<div class="inspector-grid">${rows.filter(([, v]) => v).map(([k, v]) => `<div><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')}</div>`;
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
  cap.dialogText.textContent = `This reads packet headers on ${cap.iface.selectedOptions[0].textContent} for ${cap.dur.value} seconds. They stay only in this app's memory, nothing is saved to disk and nothing is sent anywhere.`;
  cap.dialog.showModal();
});
cap.dialog.addEventListener('close', async () => {
  if (cap.dialog.returnValue !== 'ok') return;
  cap.start.disabled = true;
  cap.status.textContent = 'Starting…';
  const res = await fetch('/api/capture', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ interface: cap.iface.value, seconds: Number(cap.dur.value), confirm: true }) });
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
cap.filter.addEventListener('input', renderCapture);
cap.rows.addEventListener('click', (e) => { const tr = e.target.closest('tr[data-i]'); if (tr) showPacket(Number(tr.dataset.i)); });
cap.rows.addEventListener('keydown', (e) => { if (e.key === 'Enter') { const tr = e.target.closest('tr[data-i]'); if (tr) showPacket(Number(tr.dataset.i)); } });
loadInterfaces();
pollCapture();

const flightView = document.querySelector('#flight-map');
const flightSelector = document.querySelector('#flight-connection');
const flightGraphic = document.querySelector('#flight-graphic');
const flightDetail = document.querySelector('#flight-detail');
const flightCounts = document.querySelector('#flight-counts');
const flightRouteNote = document.querySelector('#flight-route-note');
let selectedFlightKey = '';
let selectedFlightStage = 0;
let routeDetails = null;
let routeForKey = '';
let renderedFlightSignature = '';

const stages = [
  { id:'app', short:'App', airport:'Departure gate', plain:'The process is the program that requested this network connection.', field:'Process and PID', status:'observed' },
  { id:'socket', short:'Socket', airport:'Boarding point', plain:'A socket is an endpoint the operating system gives the app. Local and remote ports identify the two ends.', field:'Local address · remote address · port', status:'observed' },
  { id:'stack', short:'TCP/IP', airport:'Runway control', plain:'macOS moves the app’s bytes through its network stack. This view sees the open endpoint and transport, not every byte on that one socket.', field:'Transport protocol · connection state', status:'observed' },
  { id:'interface', short:'Interface', airport:'Terminal link', plain:'The network interface sends frames over Wi-Fi or Ethernet. A short TShark capture can identify the interface and show packet headers.', field:'Interface · link-layer fields', status:'route' },
  { id:'gateway', short:'Gateway', airport:'Control tower', plain:'The gateway is the next hop chosen by macOS. Routers after that are outside this laptop’s local socket view.', field:'Next-hop gateway · interface', status:'route' },
  { id:'server', short:'Server', airport:'Arrival gate', plain:'The remote endpoint is visible here. A packet capture may reveal a DNS question or TLS server name; encrypted application contents remain sealed.', field:'Remote endpoint · captured protocol clues', status:'observed' },
];
const safe = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const flowKey = (row) => [row.pid, row.protocol, row.local, row.remote].join('|');

function showFlow(row) {
  if (!row) {
    renderedFlightSignature = '';
    flightSelector.innerHTML = '<option value="">No live connections</option>';
    flightGraphic.innerHTML = '<div class="flight-empty">No open remote sockets are visible right now. The map will update automatically.</div>';
    flightStages.innerHTML = '';
    flightDetail.innerHTML = '<div class="inspector-empty">When a connection appears, its observed path will be shown here.</div>';
    flightCounts.textContent = 'Waiting for a live socket';
    flightRouteNote.textContent = 'The map updates from the current macOS connection snapshot.';
    return;
  }
  const transport = row.protocol || 'Network';
  const processStats = currentProcessStats.get(Number(row.pid));
  const packetSet = typeof capPackets !== 'undefined' ? capPackets : [];
  const srcIp = String(row.local || '').replace(/^\[/, '').split(']')[0].split(':')[0];
  const dstIp = String(row.remote || '').replace(/^\[/, '').split(']')[0].split(':')[0];
  const packets = packetSet.filter((p) => [p.src, p.dst].some((ip) => ip && [srcIp, dstIp].includes(ip)));
  const tls = packets.find((p) => p.tlsSNI || /TLS/i.test(p.protocol || ''));
  const dns = packets.find((p) => p.dnsQry);
  const procBytes = processStats ? `${formatBytes(processStats.receivedBytes)} received · ${formatBytes(processStats.sentBytes)} sent` : 'Counters unavailable';
  const endpoint = `${row.remote || 'Remote endpoint'}${row.state ? ` · ${row.state}` : ''}`;
  const local = `${row.local || 'Local endpoint'}${row.protocol ? ` · ${transport}` : ''}`;
  const details = [
    { title:'Process', value:`${row.process || 'Unknown process'} · PID ${row.pid}`, note:`Process-level network counters: ${procBytes}. These totals include every connection owned by this process.` },
    { title:'Socket', value:`${local}  →  ${endpoint}`, note:'This exact pair of local and remote endpoints is reported by the live socket snapshot.' },
    { title:'macOS network stack', value:`${transport} · ${row.state || 'state not reported'}`, note:transport === 'TCP' ? 'TCP tracks a conversation and retransmits missing data. The connection list does not expose its packet contents.' : transport === 'UDP' ? 'UDP sends independent datagrams. It has no TCP-style connection handshake.' : 'The live snapshot reports the transport and endpoint shown above.' },
    { title:'Interface', value:routeDetails?.interface || (packets.length ? 'Seen in packet capture' : 'Not observed yet'), note:routeDetails?.interface ? `macOS selected this interface for the remote route. ${routeDetails.gateway ? 'The gateway below is its next hop.' : ''}` : 'Start a short TShark capture to see the interface and link-layer headers for packets that arrive during capture.' },
    { title:'Next-hop gateway', value:routeDetails?.gateway || 'Not visible in the socket snapshot', note:routeDetails?.gateway ? 'This is the first router macOS chose. Intermediate internet routers are not exposed by this local route lookup.' : 'Route lookup will appear here when available. The full internet route cannot be inferred from one laptop.' },
    { title:'Remote service', value:tls?.tlsSNI || dns?.dnsQry || row.remote || 'No remote endpoint', note:tls?.tlsSNI ? `TLS server name observed in ${packets.length} matching captured packet headers. Encrypted page or app content is still unreadable.` : dns?.dnsQry ? `DNS question observed in ${packets.length} matching captured packet headers. A DNS answer may not be in this short capture.` : packets.length ? `${packets.length} captured packet headers match this connection. Start with the packet table for timestamps, direction and protocol fields.` : 'Capture packet headers while this connection is active to look for DNS, TLS and transport details.' },
  ];
  const points = [80,285,490,695,900,1110];
  const signature = [flowKey(row), row.process, row.state, routeDetails?.interface, routeDetails?.gateway].join('|');
  if (signature !== renderedFlightSignature) {
    flightGraphic.innerHTML = `<div class="flight-canvas-scroll"><svg class="flight-canvas" viewBox="0 0 1180 220" role="img" aria-label="Observed connection from ${safe(row.process)} through the Mac network stack to ${safe(row.remote)}"><path class="flight-route-base" d="M64 111 C190 64 210 150 315 111 S420 72 520 111 625 150 725 111 835 72 930 111 1034 147 1118 103"/><path class="flight-route-dash" d="M64 111 C190 64 210 150 315 111 S420 72 520 111 625 150 725 111 835 72 930 111 1034 147 1118 103"/><g class="flight-plane"><animateMotion class="flight-motion" dur="9s" repeatCount="indefinite" rotate="auto"><mpath href="#flight-path"/></animateMotion><path d="M-12 0 5-3 12-11 15-11 12-3 26 0 12 3 15 11 12 11 5 3-12 0Z"/></g><path id="flight-path" d="M64 111 C190 64 210 150 315 111 S420 72 520 111 625 150 725 111 835 72 930 111 1034 147 1118 103" fill="none" stroke="transparent"/></svg><div class="flight-node-row">${stages.map((s,i)=>`<button class="flight-node ${s.status}" type="button" data-stage="${i}" aria-pressed="${i===selectedFlightStage}"><span class="flight-node-icon" aria-hidden="true">${['▣','◉','⇄','⌁','⌖','▤'][i]}</span><span class="flight-node-airport">${safe(s.airport)}</span><strong>${safe(s.short)}</strong><small>${i===0?safe(row.process||'Process'):i===1?`PID ${safe(row.pid)}`:i===2?safe(transport):i===3?(routeDetails?.interface||'Interface not seen'):i===4?(routeDetails?.gateway||'Next hop not seen'):safe(row.remote||'Endpoint')}</small><em>${s.status==='observed'?'Observed':routeDetails?.[i===3?'interface':'gateway']?'Route lookup':'Not in snapshot'}</em></button>`).join('')}</div></div>`;
    renderedFlightSignature = signature;
  }
  flightDetail.innerHTML = `<div class="flight-detail-main"><span class="flight-detail-kicker">${safe(stages[selectedFlightStage].airport)} · ${safe(stages[selectedFlightStage].field)}</span><h3>${safe(details[selectedFlightStage].title)}</h3><strong>${safe(details[selectedFlightStage].value)}</strong><p>${safe(stages[selectedFlightStage].plain)} ${safe(details[selectedFlightStage].note)}</p></div><div class="flight-detail-side"><span>Process traffic</span><b>↓ ${formatBytes(processStats?.receivedBytes || 0)}</b><b>↑ ${formatBytes(processStats?.sentBytes || 0)}</b><small>Since launch · process-wide counters</small><span>Packet evidence</span><b>${packets.length.toLocaleString()} headers</b><small>${tls?.tlsSNI ? `TLS name ${safe(tls.tlsSNI)}` : dns?.dnsQry ? `DNS ${safe(dns.dnsQry)}` : 'Only available during a TShark capture'}</small></div>`;
  flightCounts.textContent = `${row.process || 'Process'} · PID ${row.pid} · ${transport} · ${row.state || 'open'}`;
  flightRouteNote.textContent = routeDetails ? `Route selected by macOS: ${routeDetails.interface || 'interface unknown'}${routeDetails.gateway ? ` → next hop ${routeDetails.gateway}` : ''}. Routers beyond the first hop are not visible here.` : 'Known endpoints are solid. Dotted route segments are explanatory: this Mac does not observe every router or the far-end socket.';
  flightGraphic.querySelectorAll('.flight-node').forEach((node) => node.classList.toggle('selected', Number(node.dataset.stage) === selectedFlightStage));
}

async function inspectRoute(row) {
  const key = flowKey(row);
  if (routeForKey === key) return;
  routeForKey = key;
  routeDetails = null;
  try {
    const target = encodeURIComponent(String(row.remote || '').replace(/^\[/, '').split(']')[0].replace(/:\d+$/, ''));
    const response = await fetch(`/api/route?ip=${target}`, { cache:'no-store' });
    if (response.ok) routeDetails = await response.json();
  } catch { /* route lookup is an optional, local OS observation */ }
  if (flowKey(activeRows.find((item) => flowKey(item) === selectedFlightKey) || {}) === key) showFlow(row);
}

function refreshFlights() {
  if (!flightView) return;
  const rows = (activeRows || []).filter((row) => row.remote && row.pid);
  const oldKey = selectedFlightKey;
  if (!rows.some((row) => flowKey(row) === oldKey)) selectedFlightKey = rows[0] ? flowKey(rows[0]) : '';
  flightSelector.innerHTML = rows.length ? rows.map((row) => `<option value="${safe(flowKey(row))}" ${flowKey(row)===selectedFlightKey?'selected':''}>${safe(row.process)} · ${safe(row.remote)} · ${safe(row.protocol||'network')}</option>`).join('') : '<option value="">No live connections</option>';
  const selected = rows.find((row) => flowKey(row) === selectedFlightKey);
  if (!selected) { showFlow(null); return; }
  if (oldKey !== selectedFlightKey) { routeForKey = ''; routeDetails = null; selectedFlightStage = 0; }
  showFlow(selected);
  inspectRoute(selected);
}

flightSelector.addEventListener('change', () => { selectedFlightKey = flightSelector.value; selectedFlightStage = 0; routeForKey = ''; routeDetails = null; refreshFlights(); });
flightGraphic.addEventListener('click', (event) => {
  const button = event.target.closest('.flight-node');
  if (!button) return;
  selectedFlightStage = Number(button.dataset.stage) || 0;
  const row = (activeRows || []).find((item) => flowKey(item) === selectedFlightKey);
  showFlow(row);
});
document.querySelector('.nav-item[href="#flight-map"]').addEventListener('click', () => setTimeout(refreshFlights, 0));
setInterval(refreshFlights, 3000);
refreshFlights();

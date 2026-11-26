import { createServer } from 'node:http';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { reverse } from 'node:dns/promises';
import { readFile } from 'node:fs/promises';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { isIP } from 'node:net';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { guard, isPaused, launchdLabel, logAction, processTable, treePreview } from './process-control.js';
import { accept, appFirstSeen, currentMarkers, forgetHistory, loadHistory, observe, saveHistory, summary } from './history.js';
import { exePath, trustFacts } from './trust.js';
import { tierOf } from './known.js';
import { persistenceItems } from './persistence.js';
import { changeJob } from './launchd-control.js';
import { geoLookup, isNonPublic } from './geoip.js';
import { changeRule, egressStatus, initEgress, setEnabled, setPaused } from './egress.js';

const exec = promisify(execFile);
const root = join(fileURLToPath(new URL('.', import.meta.url)), 'public');
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };

// ---------- Capture state ----------
let captureState = {
  state: 'idle', // idle|running|done|error
  startedAt: null,
  seconds: null,
  interface: null,
  packets: [],
  error: null,
  // internal child process reference
  proc: null,
};

function resetCapture() {
  captureState = { state: 'idle', startedAt: null, seconds: null, interface: null, packets: [], error: null, proc: null };
}

const TSHARK = '/Applications/Wireshark.app/Contents/MacOS/tshark';
// Capture decoded header fields only. We deliberately do not request -w, -x,
// or application payload fields, so this prototype never writes a PCAP or
// presents packet bytes as if they were safely inspectable text.
const FIELDS = ['frame.number', 'frame.time_relative', 'frame.len', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', '_ws.col.Protocol', 'dns.qry.name', 'tls.handshake.extensions_server_name', 'http.host', '_ws.col.Info', 'eth.src', 'eth.dst', 'ip.ttl', 'tcp.flags.str', 'tls.record.version', 'frame.protocols', 'frame.cap_len', 'eth.type', 'ip.id', 'ip.flags', 'ip.proto', 'ip.checksum', 'ipv6.nxt', 'ipv6.plen', 'ipv6.hlim', 'tcp.seq_raw', 'tcp.ack_raw', 'tcp.hdr_len', 'tcp.len', 'tcp.flags', 'tcp.window_size_value', 'tcp.checksum', 'tcp.analysis.retransmission', 'udp.length', 'udp.checksum', 'dns.id', 'dns.flags', 'dns.qry.type', 'dns.resp.name', 'dns.resp.ttl', 'dns.a', 'dns.aaaa', 'tls.record.content_type', 'tls.record.length', 'tls.handshake.type', 'tls.handshake.version', 'tls.handshake.ciphersuite'];
const KEYS = ['frame', 'time', 'len', 'ipSrc', 'ipDst', 'ipv6Src', 'ipv6Dst', 'tcpSrc', 'tcpDst', 'udpSrc', 'udpDst', 'protocol', 'dnsQry', 'tlsSNI', 'httpHost', 'info', 'ethSrc', 'ethDst', 'ttl', 'tcpFlags', 'tlsVersion', 'frameProtocols', 'capturedLength', 'ethType', 'ipId', 'ipFlags', 'ipProto', 'ipChecksum', 'ipv6Next', 'ipv6Length', 'ipv6HopLimit', 'tcpSequence', 'tcpAck', 'tcpHeaderLength', 'tcpPayloadLength', 'tcpFlagsRaw', 'tcpWindow', 'tcpChecksum', 'tcpRetransmission', 'udpLength', 'udpChecksum', 'dnsId', 'dnsFlags', 'dnsQueryType', 'dnsAnswerName', 'dnsTtl', 'dnsA', 'dnsAAAA', 'tlsContentType', 'tlsRecordLength', 'tlsHandshakeType', 'tlsHandshakeVersion', 'tlsCipherSuite'];

function parsePacket(line) {
  const fields = line.split('\t');
  return Object.fromEntries(KEYS.map((k, i) => [k, (fields[i] || '').trim()]));
}

async function listInterfaces() {
  const { stdout } = await exec(TSHARK, ['-D'], { timeout: 5000 });
  return stdout.split('\n').map((line) => line.match(/^\d+\.\s+(\S+)(?:\s+\((.*)\))?\s*$/)).filter(Boolean).map((m) => ({ name: m[1], description: m[2] || '' }));
}

const SETTINGS_DIR = process.env.LOCAL_WATCH_DATA || join(homedir(), 'Library', 'Application Support', 'LocalWatch');
const SETTINGS_FILE = join(SETTINGS_DIR, 'settings.json');
const userSettings = { reverseDns: process.env.LOCAL_WATCH_REVERSE_DNS !== '0' };
try { Object.assign(userSettings, JSON.parse(readFileSync(SETTINGS_FILE, 'utf8'))); } catch { /* defaults */ }
function saveSettings() {
  mkdirSync(SETTINGS_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(SETTINGS_FILE, JSON.stringify(userSettings), { mode: 0o600 });
}
// Home estimate from the Mac's time zone and the system zone.tab; nothing is looked up online.
async function homeFromTimeZone() {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  try {
    const tab = await readFile('/usr/share/zoneinfo/zone.tab', 'utf8');
    const row = tab.split('\n').find((l) => !l.startsWith('#') && l.split('\t')[2] === tz);
    const m = row?.split('\t')[1].match(/^([+-])(\d{2})(\d{2})(\d{2})?([+-])(\d{3})(\d{2})(\d{2})?$/);
    if (m) {
      const deg = (sign, d, mi, se) => (sign === '-' ? -1 : 1) * (Number(d) + Number(mi) / 60 + Number(se || 0) / 3600);
      return { tz, city: tz.split('/').pop().replace(/_/g, ' '), lat: +deg(m[1], m[2], m[3], m[4]).toFixed(2), lon: +deg(m[5], m[6], m[7], m[8]).toFixed(2), source: 'time zone' };
    }
  } catch { /* fall through */ }
  return { tz, source: 'none' };
}
const nameCache = new Map();
async function reverseName(ip) {
  if (!userSettings.reverseDns) return '';
  if (nameCache.has(ip)) return nameCache.get(ip);
  let name = '';
  try {
    const names = await Promise.race([reverse(ip), new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1500))]);
    name = names[0] || '';
  } catch { name = ''; }
  nameCache.set(ip, name);
  return name;
}

// Explanations come only from a model on this Mac (Ollama on loopback).
const EXPLAIN_URL = 'http://127.0.0.1:11434/api/chat';
const EXPLAIN_MODEL = process.env.EXPLAIN_MODEL || 'gemma4:26b';
let explaining = false;
async function explain(item) {
  const facts = Object.entries(item).filter(([, v]) => v !== '' && v != null).map(([k, v]) => `${k}: ${String(v).slice(0, 200)}`).join('\n');
  const body = {
    model: EXPLAIN_MODEL,
    stream: false,
    think: false,
    options: { temperature: 0.2, num_predict: 400 },
    messages: [
      { role: 'system', content: 'You explain network activity on a personal Mac to its owner, calmly and plainly, in English, without long dashes. Use only the facts given. If you do not know who owns an address, say so. Never claim something is malicious without evidence. Answer in at most four short sentences: what this probably is, whether it looks normal, and one thing to check if unsure.' },
      { role: 'user', content: facts },
    ],
  };
  const res = await fetch(EXPLAIN_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(120000) });
  if (!res.ok) throw new Error(`Local model returned ${res.status}`);
  const data = await res.json();
  return { text: data.message?.content?.trim() || 'No answer.', model: EXPLAIN_MODEL };
}

const ownerCache = new Map();
async function ownerOf(ip) {
  if (ownerCache.has(ip)) return ownerCache.get(ip);
  let owner = { org: '', country: '', network: '' };
  try {
    const { stdout } = await exec('/usr/bin/whois', [ip], { timeout: 8000, maxBuffer: 1024 * 1024 });
    const pick = (re) => (stdout.match(re) || [])[1]?.trim() || '';
    owner = {
      org: pick(/^(?:OrgName|org-name|Organization|owner|descr):\s*(.+)$/im),
      country: pick(/^(?:Country|country):\s*(\S+)/im),
      network: pick(/^(?:NetName|netname):\s*(.+)$/im),
    };
  } catch { /* whois unavailable */ }
  ownerCache.set(ip, owner);
  return owner;
}

// Read-only facts about one process: command line, parents, folder, sockets, code signature.
async function processFacts(pid) {
  const run = async (cmd, args, both = false) => { try { const r = await exec(cmd, args, { timeout: 5000, maxBuffer: 2 * 1024 * 1024 }); return both ? `${r.stdout}${r.stderr}` : r.stdout; } catch (e) { return `${e.stdout || ''}${e.stderr || ''}`; } };
  const ps = (await run('/bin/ps', ['-ww', '-o', 'pid=,ppid=,user=,lstart=,command=', '-p', String(pid)])).trim();
  if (!ps) return null;
  const m = ps.match(/^(\d+)\s+(\d+)\s+(\S+)\s+(\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})\s+(.*)$/);
  const facts = { pid, ppid: m ? Number(m[2]) : 0, user: m?.[3] || '', started: m?.[4] || '', command: (m?.[5] || ps).slice(0, 600), parents: [], cwd: '', sockets: [], signature: '' };
  let parent = facts.ppid;
  for (let i = 0; i < 6 && parent > 0; i++) {
    const line = (await run('/bin/ps', ['-ww', '-o', 'ppid=,command=', '-p', String(parent)])).trim();
    if (!line) break;
    const [, pp, cmd] = line.match(/^(\d+)\s+(.*)$/) || [];
    facts.parents.push({ pid: parent, command: (cmd || '').slice(0, 200) });
    parent = Number(pp);
  }
  facts.cwd = ((await run('/usr/sbin/lsof', ['-a', '-p', String(pid), '-d', 'cwd', '-Fn'])).split('\n').find((l) => l.startsWith('n')) || '').slice(1);
  facts.sockets = (await run('/usr/sbin/lsof', ['-nP', '-a', '-p', String(pid), '-i'])).split('\n').slice(1).filter(Boolean).map((l) => l.split(/\s+/).slice(7).join(' ')).slice(0, 30);
  const exe = facts.command.split(' ')[0];
  if (exe.startsWith('/')) {
    const sig = await run('/usr/bin/codesign', ['-dv', '--verbose=2', exe], true);
    const authority = [...sig.matchAll(/^Authority=(.+)$/gm)].map((x) => x[1]);
    facts.signature = authority.length ? authority.join(' → ') : /not signed/i.test(sig) ? 'not signed' : /Signature=adhoc/.test(sig) ? 'ad hoc only (no developer identity; common for Homebrew and self-built tools)' : 'unknown';
  }
  return facts;
}

async function activeConnections() {
  const binary = join(fileURLToPath(new URL('.', import.meta.url)), 'target', 'debug', 'netwatch-core');
  try {
    const { stdout } = await exec(binary, [], { timeout: 5000, maxBuffer: 4 * 1024 * 1024 });
    return JSON.parse(stdout);
  } catch (error) {
    const message = error.code === 'ENOENT'
      ? 'Build the Rust monitor first with: cargo build'
      : error.stderr?.trim() || 'The Rust monitor could not read current macOS connections.';
    const unavailable = new Error(message);
    unavailable.statusCode = 503;
    throw unavailable;
  }
}

const atlasNames = new Map();
async function atlasName(ip) {
  if (!userSettings.reverseDns) return '';
  if (atlasNames.has(ip)) return atlasNames.get(ip);
  let name = '';
  try { name = (await Promise.race([reverse(ip), new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 800))]))[0] || ''; } catch {}
  atlasNames.set(ip, name);
  if (atlasNames.size > 2000) atlasNames.delete(atlasNames.keys().next().value);
  return name;
}
const hostOfRemote = (remote) => { const s = String(remote || ''); const m = s.match(/^\[([^\]]+)\]/); if (m) return m[1]; const i = s.lastIndexOf(':'); return s.indexOf(':') === i && i > 0 ? s.slice(0, i) : s; };
const domainOf = (name) => { const parts = name.replace(/\.$/, '').split('.'); return parts.length > 2 ? parts.slice(-2).join('.') : parts.join('.'); };

async function atlasData() {
  const snapshot = await activeConnections();
  const byIp = new Map();
  for (const row of snapshot.connections || []) {
    const ip = hostOfRemote(row.remote);
    if (!isIP(ip)) continue;
    const d = byIp.get(ip) || { ip, processes: new Set(), pids: new Set(), ports: new Set(), count: 0 };
    d.processes.add(row.process); d.pids.add(row.pid); d.ports.add(String(row.remote).split(':').pop()); d.count++;
    byIp.set(ip, d);
  }
  const ips = [...byIp.keys()];
  const geo = await geoLookup(ips);
  const names = await Promise.all(ips.map((ip) => (isNonPublic(ip) ? '' : atlasName(ip))));
  const destinations = ips.map((ip, i) => {
    const d = byIp.get(ip);
    const place = geo.places.get(ip) || null;
    return { ip, name: names[i], domain: names[i] ? domainOf(names[i]) : '', local: isNonPublic(ip), processes: [...d.processes], pids: [...d.pids], ports: [...d.ports], connections: d.count, lat: place?.lat ?? null, lon: place?.lon ?? null, city: place?.city || '', country: place?.country || '' };
  });
  return { sampledAt: snapshot.sampledAt, geoip: geo.status, geoipError: geo.error, attribution: { text: 'IP geolocation by DB-IP.com', url: 'https://db-ip.com', license: 'CC BY 4.0' }, destinations };
}

const server = createServer(async (req, res) => {
  const host = req.headers.host || '';
  if (!/^localhost(?::\d+)?$|^127\.0\.0\.1(?::\d+)?$/.test(host)) {
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' }).end('Local access only');
    return;
  }
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (req.method === 'GET' && pathname === '/api/connections') {
    try {
      const data = await activeConnections();
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(data));
    } catch (error) {
      res.writeHead(error.statusCode || 500, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify({ error: error.message, sampledAt: new Date().toISOString(), connections: [] }));
    }
    return;
  }
  if (req.method === 'GET' && pathname === '/api/atlas') {
    let code = 200;
    let body;
    try { body = await atlasData(); } catch (error) { code = error.statusCode || 500; body = { error: error.message, geoip: 'unknown', destinations: [] }; }
    const payload = JSON.stringify(body);
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(payload);
    return;
  }
  if (req.method === 'GET' && pathname === '/api/persistence') {
    let connections = [];
    try { connections = (await activeConnections()).connections || []; } catch {}
    const data = await persistenceItems(connections);
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(data));
    return;
  }
  if (req.method === 'POST' && pathname === '/api/settings/reverse-dns') {
    const origin = req.headers.origin || '';
    if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin) || !origin.endsWith(`:${port}`)) { res.writeHead(403).end(); return; }
    let body = '';
    for await (const chunk of req) { body += chunk; if (body.length > 1024) break; }
    let enabled;
    try { enabled = JSON.parse(body).enabled; } catch { /* invalid */ }
    if (typeof enabled !== 'boolean') { res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: 'enabled must be true or false.' })); return; }
    userSettings.reverseDns = enabled;
    if (!enabled) { nameCache.clear(); atlasNames.clear(); }
    try { saveSettings(); } catch { /* setting still applies until restart */ }
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify({ reverseDns: enabled }));
    return;
  }
  if (req.method === 'POST' && pathname === '/api/persistence/job') {
    const origin = req.headers.origin || '';
    if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin) || !origin.endsWith(`:${port}`)) { res.writeHead(403).end(); return; }
    let body = '';
    for await (const chunk of req) { body += chunk; if (body.length > 4096) break; }
    let input = {};
    try { input = JSON.parse(body); } catch { /* invalid */ }
    if (input.confirm !== true || !['stop', 'disable', 'enable'].includes(input.action)) { res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: 'A confirmed action of stop, disable or enable is required.' })); return; }
    let out;
    try { out = await changeJob(input.action, input.file); } catch (e) { res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: e.message })); return; }
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(out));
    return;
  }
  if (req.method === 'GET' && pathname === '/api/egress') {
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(egressStatus()));
    return;
  }
  if (req.method === 'POST' && pathname.startsWith('/api/egress/')) {
    const origin = req.headers.origin || '';
    if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin) || !origin.endsWith(`:${port}`)) { res.writeHead(403).end(); return; }
    let body = '';
    for await (const chunk of req) { body += chunk; if (body.length > 1024) break; }
    let input = {};
    try { input = JSON.parse(body); } catch { /* invalid */ }
    const fail = (message) => res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: message }));
    try {
      if (pathname === '/api/egress/enable' && typeof input.enabled === 'boolean') await setEnabled(input.enabled);
      else if (pathname === '/api/egress/pause' && typeof input.paused === 'boolean') setPaused(input.paused);
      else if (pathname === '/api/egress/rule' && ['allow', 'deny', 'remove'].includes(input.action)) changeRule(input.action, input.host);
      else { fail('Unknown egress change.'); return; }
    } catch (e) { fail(e.code === 'EADDRINUSE' ? 'The proxy port is already in use.' : e.message); return; }
    await logAction({ type: 'egress', path: pathname, input }).catch(() => {});
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(egressStatus()));
    return;
  }
  if (req.method === 'GET' && pathname === '/api/home-estimate') {
    const home = await homeFromTimeZone();
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(home));
    return;
  }
  if (req.method === 'GET' && pathname === '/api/settings') {
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify({ ...summary(), explainModel: EXPLAIN_MODEL, sampleSeconds: 15, port, tshark: TSHARK, reverseDns: userSettings.reverseDns }));
    return;
  }
  if (req.method === 'GET' && pathname === '/api/process') {
    const pid = Number(new URL(req.url, 'http://localhost').searchParams.get('pid'));
    const facts = Number.isInteger(pid) && pid > 0 ? await processFacts(pid) : null;
    if (facts) {
      const row = (await processTable()).find((r) => r.pid === pid);
      facts.paused = isPaused(row?.stat);
      facts.launchd = await launchdLabel(pid);
    }
    res.writeHead(facts ? 200 : 404, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(facts || { error: 'Process not found.' }));
    return;
  }
  if (req.method === 'GET' && pathname === '/api/process/trust') {
    const params = new URL(req.url, 'http://localhost').searchParams;
    const pid = Number(params.get('pid'));
    const path = Number.isInteger(pid) && pid > 0 ? await exePath(pid) : null;
    if (!path || !path.startsWith('/')) { res.writeHead(404, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify({ error: 'Executable path not visible for this process.' })); return; }
    const facts = await trustFacts(path);
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify({ ...facts, firstSeen: appFirstSeen(params.get('app') || '') }));
    return;
  }
  if (req.method === 'GET' && pathname === '/api/route') {
    const ip = new URL(req.url, 'http://localhost').searchParams.get('ip') || '';
    if (!isIP(ip)) { res.writeHead(400, { 'content-type':'application/json; charset=utf-8' }).end(JSON.stringify({ error:'A numeric IP address is required.' })); return; }
    try {
      const { stdout } = await exec('/sbin/route', ['-n', 'get', ip], { timeout:2500, maxBuffer:16384 });
      const field = (name) => stdout.match(new RegExp(`^\\s*${name}:\\s*(.+)$`, 'm'))?.[1]?.trim() || '';
      res.writeHead(200, { 'content-type':'application/json; charset=utf-8', 'cache-control':'no-store' }).end(JSON.stringify({ destination:field('destination'), gateway:field('gateway'), interface:field('interface'), flags:field('flags') }));
    } catch { res.writeHead(503, { 'content-type':'application/json; charset=utf-8' }).end(JSON.stringify({ error:'macOS route information is unavailable for this endpoint.' })); }
    return;
  }
  if (req.method === 'GET' && pathname === '/api/process/tree') {
    const pid = Number(new URL(req.url, 'http://localhost').searchParams.get('pid'));
    try {
      const preview = await treePreview(pid);
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(preview));
    } catch (e) { res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: e.message })); }
    return;
  }
  const control = pathname.match(/^\/api\/process\/(stop|pause|resume|restart)$/)?.[1];
  if (req.method === 'POST' && control) {
    const origin = req.headers.origin || '';
    if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin) || !origin.endsWith(`:${port}`)) { res.writeHead(403).end(); return; }
    let body = '';
    for await (const chunk of req) { body += chunk; if (body.length > 8192) break; }
    let request = {};
    const json = (code, data) => res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(data));
    try {
      request = JSON.parse(body || '{}');
      const { pid, confirm, tree, children } = request;
      if (confirm !== true || !Number.isSafeInteger(pid) || pid < 2) throw new Error('Explicit confirmation and a valid process ID are required.');
      const verb = { stop: 'stopped', pause: 'paused', resume: 'resumed', restart: 'restarted' }[control];
      const { row } = await guard(pid, verb);
      const name = row.command.split(' ')[0];
      if (control === 'stop' && tree === true) {
        const preview = await treePreview(pid);
        if (preview.refused.length) throw new Error(`The tree contains ${preview.refused.length} process(es) that cannot be stopped here (another account or the monitor itself).`);
        const now = preview.children.map((c) => c.pid).sort((a, b) => a - b);
        const seen = Array.isArray(children) ? [...children].sort((a, b) => a - b) : null;
        if (!seen || seen.join(',') !== now.join(',')) throw new Error('The process tree changed since the preview. Preview it again before stopping.');
        const signalled = [];
        for (const c of preview.children) { try { process.kill(c.pid, 'SIGTERM'); signalled.push(c.pid); } catch { /* already exited */ } }
        process.kill(pid, 'SIGTERM');
        signalled.push(pid);
        await logAction({ action: 'stop-tree', signal: 'SIGTERM', pid, process: name, pids: signalled, result: 'signal-sent' });
        json(202, { status: 'signal-sent', signal: 'SIGTERM', pid, process: name, pids: signalled });
        return;
      }
      if (control === 'restart') {
        const lookup = await launchdLabel(pid);
        if (!lookup.managed) throw new Error(`Restart unavailable: ${lookup.reason}`);
        await exec('/bin/launchctl', ['kickstart', '-k', lookup.target], { timeout: 10000 });
        await logAction({ action: 'restart', pid, process: name, label: lookup.label, target: lookup.target, result: 'kickstarted' });
        json(202, { status: 'kickstarted', pid, process: name, label: lookup.label });
        return;
      }
      const signal = { stop: 'SIGTERM', pause: 'SIGSTOP', resume: 'SIGCONT' }[control];
      process.kill(pid, signal);
      await logAction({ action: control, signal, pid, process: name, result: 'signal-sent' });
      json(202, { status: 'signal-sent', signal, pid, process: name });
    } catch (e) {
      await logAction({ action: control, pid: request.pid ?? null, tree: request.tree === true, result: 'refused', error: e.message });
      json(400, { error: e.message });
    }
    return;
  }
  if (req.method === 'GET' && pathname === '/api/markers') {
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify({ ...summary(), markers: currentMarkers() }));
    return;
  }
  if ((req.method === 'POST' && pathname === '/api/markers/accept') || (req.method === 'DELETE' && pathname === '/api/history')) {
    const origin = req.headers.origin || '';
    if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin) || !origin.endsWith(`:${port}`)) {
      res.writeHead(403, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: 'Only this page can change the history.' }));
      return;
    }
    if (req.method === 'DELETE') {
      await forgetHistory();
      res.writeHead(204).end();
      return;
    }
    let body = '';
    for await (const chunk of req) { body += chunk; if (body.length > 1024) break; }
    try {
      const { key } = JSON.parse(body || '{}');
      if (!accept(key)) throw new Error('Unknown marker.');
      await saveHistory();
      res.writeHead(204).end();
    } catch (e) {
      res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: e.message }));
    }
    return;
  }
  if (req.method === 'GET' && pathname === '/api/owner') {
    const ip = new URL(req.url, 'http://localhost').searchParams.get('ip') || '';
    if (!/^[0-9a-fA-F:.]{3,45}$/.test(ip)) { res.writeHead(400).end('{}'); return; }
    const [owner, name] = await Promise.all([ownerOf(ip), reverseName(ip)]);
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify({ ...owner, reverseDns: name }));
    return;
  }
  if (req.method === 'GET' && pathname === '/api/names') {
    const ips = (new URL(req.url, 'http://localhost').searchParams.get('ips') || '').split(',').filter((ip) => /^[0-9a-fA-F:.]{3,45}$/.test(ip)).slice(0, 60);
    const out = {};
    await Promise.all(ips.map(async (ip) => { out[ip] = await reverseName(ip); }));
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(out));
    return;
  }
  if (req.method === 'POST' && pathname === '/api/explain') {
    const origin = req.headers.origin || '';
    if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin) || !origin.endsWith(`:${port}`)) {
      res.writeHead(403, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: 'Explanations can only be requested from this page.' }));
      return;
    }
    let body = '';
    for await (const chunk of req) { body += chunk; if (body.length > 4096) break; }
    if (explaining) {
      res.writeHead(429, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: 'One explanation at a time.' }));
      return;
    }
    explaining = true;
    try {
      const item = JSON.parse(body || '{}');
      if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Nothing to explain.');
      const answer = await explain(item);
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(answer));
    } catch (e) {
      res.writeHead(502, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: e.message }));
    } finally {
      explaining = false;
    }
    return;
  }
  if (req.method === 'GET' && pathname === '/api/models') {
    try {
      const response = await fetch('http://127.0.0.1:11434/api/tags', { signal: AbortSignal.timeout(2500) });
      if (!response.ok) throw new Error('Ollama did not respond.');
      const data = await response.json();
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify({ models: (data.models || []).map((m) => m.name), defaultModel: EXPLAIN_MODEL }));
    } catch { res.writeHead(503, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: 'Ollama is not reachable on this Mac.' })); }
    return;
  }
  if (req.method === 'POST' && pathname === '/api/ask') {
    const origin = req.headers.origin || '';
    if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin) || !origin.endsWith(`:${port}`)) { res.writeHead(403).end(); return; }
    let body = '';
    for await (const chunk of req) { body += chunk; if (body.length > 2048) break; }
    try {
      const { question, context = {} } = JSON.parse(body || '{}');
      if (typeof question !== 'string' || !question.trim() || question.length > 1200) throw new Error('Enter a question up to 1,200 characters.');
      if (!context || typeof context !== 'object' || Array.isArray(context)) throw new Error('Connection context must be an object.');
      const allowed = ['process', 'pid', 'protocol', 'local', 'remote', 'state'];
      const facts = Object.entries(context).filter(([key, value]) => allowed.includes(key) && value != null).map(([key, value]) => `${key}: ${String(value).slice(0, 200)}`).join('\n');
      const response = await fetch('http://127.0.0.1:11434/api/chat', { method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(120000), body: JSON.stringify({ model: EXPLAIN_MODEL, stream: false, think: false, options: { temperature: 0.2, num_predict: 350 }, messages: [
        { role: 'system', content: 'You are a cautious network investigation helper for a Mac user. Explain concepts in plain English. Do not claim maliciousness without evidence, and do not suggest executing shell commands. State uncertainty.' },
        { role: 'user', content: `Question: ${question.trim()}${facts ? `\n\nSelected local connection facts:\n${facts}` : ''}` },
      ] }) });
      if (!response.ok) throw new Error(`Local model returned ${response.status}.`);
      const data = await response.json();
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify({ text: data.message?.content?.trim() || 'No answer.', model: EXPLAIN_MODEL }));
    } catch (e) { res.writeHead(502, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: e.message })); }
    return;
  }
  // Capture endpoints
  if (pathname.startsWith('/api/capture') && req.method !== 'GET') {
    const origin = req.headers.origin || '';
    if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin) || !origin.endsWith(`:${port}`)) {
      res.writeHead(403, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: 'Capture can only be controlled from this page.' }));
      return;
    }
  }
  if (req.method === 'GET' && pathname === '/api/capture/interfaces') {
    try {
      const interfaces = await listInterfaces();
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(interfaces));
    } catch (e) {
      res.writeHead(503, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: 'TShark is not available: ' + e.message }));
    }
    return;
  }

  if (req.method === 'POST' && pathname === '/api/capture') {
    let body = '';
    for await (const chunk of req) { body += chunk; if (body.length > 2048) break; }
    try {
      const { interface: iface, seconds, displayFilter = '', confirm } = JSON.parse(body || '{}');
      if (confirm !== true) throw new Error('Confirmation required.');
      if (captureState.state === 'running') throw new Error('A capture is already running.');
      const duration = Number(seconds);
      if (![5, 10, 30].includes(duration)) throw new Error('Duration must be 5, 10 or 30 seconds.');
      if (typeof displayFilter !== 'string' || displayFilter.length > 500 || /[\0\r\n]/.test(displayFilter)) throw new Error('Display filter must be one line and 500 characters or fewer.');
      const names = (await listInterfaces()).map((i) => i.name);
      if (typeof iface !== 'string' || !names.includes(iface)) throw new Error('Unknown network interface.');
      const args = ['-i', iface, '-a', `duration:${duration}`, '-c', '3000', '-l', '-n', ...(displayFilter ? ['-Y', displayFilter] : []), '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=f', ...FIELDS.flatMap((f) => ['-e', f])];
      const proc = spawn(TSHARK, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      captureState = { state: 'running', startedAt: new Date().toISOString(), seconds: duration, interface: iface, packets: [], error: null, proc };
      const mine = captureState;
      let buffer = '';
      let stderr = '';
      proc.stdout.on('data', (chunk) => {
        buffer += chunk.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (const line of lines) if (line.trim()) mine.packets.push(parsePacket(line));
      });
      proc.stderr.on('data', (chunk) => { stderr = (stderr + chunk.toString()).slice(-2000); });
      proc.on('error', (e) => { mine.state = 'error'; mine.error = e.message; mine.proc = null; });
      proc.on('close', (code) => {
        if (buffer.trim()) mine.packets.push(parsePacket(buffer));
        if (mine.state === 'running') {
          mine.state = code === 0 ? 'done' : 'error';
          mine.error = code === 0 ? null : (stderr.split('\n').filter((l) => /error|permission|denied/i.test(l)).pop() || `TShark stopped with code ${code}`);
        }
        mine.proc = null;
      });
      res.writeHead(202, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ status: 'started' }));
    } catch (e) {
      res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (req.method === 'GET' && pathname === '/api/capture') {
    const { proc, ...out } = captureState;
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(out));
    return;
  }

  if (req.method === 'DELETE' && pathname === '/api/capture') {
    if (captureState.proc) captureState.proc.kill('SIGTERM');
    resetCapture();
    res.writeHead(204).end();
    return;
  }
  if (req.method !== 'GET') {
    res.writeHead(405, { allow: 'GET', 'content-type': 'text/plain; charset=utf-8' }).end('Read-only monitor');
    return;
  }
  const relative = pathname === '/' ? 'index.html' : normalize(decodeURIComponent(pathname).replace(/^\/+/, ''));
  if (relative.startsWith('..') || relative.includes('\\')) {
    res.writeHead(400).end('Invalid path');
    return;
  }
  try {
    const body = await readFile(join(root, relative));
    res.writeHead(200, { 'content-type': types[extname(relative)] || 'application/octet-stream', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }).end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }).end('Not found');
  }
});


// Trust tier per PID, from the executable path and signature. Paths are cached per PID and name.
const pidPaths = new Map();
async function processTiers(rows) {
  const tiers = new Map();
  const pids = new Map();
  for (const r of rows) if (Number(r.pid) > 0) pids.set(Number(r.pid), r.process);
  await Promise.all([...pids].slice(0, 80).map(async ([pid, name]) => {
    const cacheKey = `${pid}:${name}`;
    let path = pidPaths.get(cacheKey);
    if (path === undefined) {
      path = await exePath(pid);
      pidPaths.set(cacheKey, path);
      if (pidPaths.size > 1000) pidPaths.delete(pidPaths.keys().next().value);
    }
    if (path) tiers.set(pid, tierOf(await trustFacts(path)));
  }));
  return tiers;
}

// Background sampling builds the local baseline even when the page is closed.
let sampling = false;
async function sample() {
  if (sampling) return;
  sampling = true;
  try {
    const data = await activeConnections();
    const ips = [...new Set((data.connections || []).map((r) => String(r.remote).replace(/:\d+$/, '').replace(/^\[|\]$/g, '')))];
    const [tiers] = await Promise.all([processTiers([...(data.connections || []), ...(data.processes || [])]), ...ips.slice(0, 80).map((ip) => reverseName(ip))]);
    observe(data, nameCache, tiers);
    await saveHistory();
  } catch { /* sampling is best effort */ } finally { sampling = false; }
}
await loadHistory();
setInterval(sample, 15000);
sample();

const port = Number(process.env.PORT || 4317);
initEgress().catch((e) => console.error(`Egress proxy did not start: ${e.message}`));
server.listen(port, '127.0.0.1', () => console.log(`Local Network Watcher is listening at http://127.0.0.1:${port}`));

import { createServer } from 'node:http';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { reverse } from 'node:dns/promises';
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { guard, isPaused, launchdLabel, logAction, processTable, treePreview } from './process-control.js';
import { accept, currentMarkers, forgetHistory, loadHistory, observe, saveHistory, summary } from './history.js';

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

const nameCache = new Map();
async function reverseName(ip) {
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
  if (req.method === 'GET' && pathname === '/api/settings') {
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify({ ...summary(), explainModel: EXPLAIN_MODEL, sampleSeconds: 15, port, tshark: TSHARK }));
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
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(await treePreview(pid)));
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
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(await explain(item)));
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
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(JSON.stringify(await listInterfaces()));
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


// Background sampling builds the local baseline even when the page is closed.
async function sample() {
  try {
    const data = await activeConnections();
    const ips = [...new Set((data.connections || []).map((r) => String(r.remote).replace(/:\d+$/, '').replace(/^\[|\]$/g, '')))];
    await Promise.all(ips.slice(0, 80).map((ip) => reverseName(ip)));
    observe(data, nameCache);
    await saveHistory();
  } catch { /* sampling is best effort */ }
}
await loadHistory();
setInterval(sample, 15000);
sample();

const port = Number(process.env.PORT || 4317);
server.listen(port, '127.0.0.1', () => console.log(`Local Network Watcher is listening at http://127.0.0.1:${port}`));

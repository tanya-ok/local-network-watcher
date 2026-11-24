import { createServer } from 'node:http';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

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
const FIELDS = ['frame.number', 'frame.time_relative', 'frame.len', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', '_ws.col.Protocol', 'dns.qry.name', 'tls.handshake.extensions_server_name', 'http.host', '_ws.col.Info'];
const KEYS = ['frame', 'time', 'len', 'ipSrc', 'ipDst', 'ipv6Src', 'ipv6Dst', 'tcpSrc', 'tcpDst', 'udpSrc', 'udpDst', 'protocol', 'dnsQry', 'tlsSNI', 'httpHost', 'info'];

function parsePacket(line) {
  const fields = line.split('\t');
  return Object.fromEntries(KEYS.map((k, i) => [k, (fields[i] || '').trim()]));
}

async function listInterfaces() {
  const { stdout } = await exec(TSHARK, ['-D'], { timeout: 5000 });
  return stdout.split('\n').map((line) => line.match(/^\d+\.\s+(\S+)(?:\s+\((.*)\))?\s*$/)).filter(Boolean).map((m) => ({ name: m[1], description: m[2] || '' }));
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
      const { interface: iface, seconds, confirm } = JSON.parse(body || '{}');
      if (confirm !== true) throw new Error('Confirmation required.');
      if (captureState.state === 'running') throw new Error('A capture is already running.');
      const duration = Number(seconds);
      if (![5, 10, 30].includes(duration)) throw new Error('Duration must be 5, 10 or 30 seconds.');
      const names = (await listInterfaces()).map((i) => i.name);
      if (typeof iface !== 'string' || !names.includes(iface)) throw new Error('Unknown network interface.');
      const args = ['-i', iface, '-a', `duration:${duration}`, '-c', '3000', '-l', '-n', '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=f', ...FIELDS.flatMap((f) => ['-e', f])];
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

const port = Number(process.env.PORT || 4317);
server.listen(port, '127.0.0.1', () => console.log(`Local Network Watch is listening at http://127.0.0.1:${port}`));

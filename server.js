import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const root = join(fileURLToPath(new URL('.', import.meta.url)), 'public');
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };

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

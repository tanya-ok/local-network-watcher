import { createServer, request as httpRequest } from 'node:http';
import { connect, isIP } from 'node:net';
import { lookup } from 'node:dns/promises';
import { appendFile, mkdir } from 'node:fs/promises';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { isNonPublic } from './geoip.js';

const DIR = process.env.LOCAL_WATCH_DATA || join(homedir(), 'Library', 'Application Support', 'LocalWatch');
const RULES = join(DIR, 'egress.json');
export const EGRESS_LOG = join(DIR, 'egress.log');

// Two listeners, one policy file. "open" lets everything through except the deny lists; "strict" lets only the allow list through.
export const PROFILES = {
  open: Number(process.env.LOCAL_WATCH_EGRESS_OPEN_PORT || 4318),
  strict: Number(process.env.LOCAL_WATCH_EGRESS_STRICT_PORT || 4319),
};

// Hosted AI services and common trackers. Always refused, in both profiles.
export const BUILTIN_DENY = {
  ai: ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'anthropic.com', 'claude.ai', 'claude.com', 'gemini.google.com', 'generativelanguage.googleapis.com', 'aistudio.google.com', 'bard.google.com', 'copilot.microsoft.com', 'perplexity.ai', 'mistral.ai', 'x.ai', 'grok.com', 'deepseek.com', 'cohere.com', 'cohere.ai', 'poe.com', 'you.com', 'meta.ai', 'character.ai', 'replicate.com', 'together.ai', 'groq.com', 'openrouter.ai', 'fireworks.ai', 'elevenlabs.io', 'midjourney.com', 'stability.ai', 'duck.ai'],
  tracker: ['google-analytics.com', 'googletagmanager.com', 'doubleclick.net', 'googlesyndication.com', 'facebook.net', 'hotjar.com', 'segment.io', 'mixpanel.com', 'amplitude.com', 'scorecardresearch.com'],
};

const state = { enabled: false, paused: false, allow: [], deny: [] };
const servers = new Map();
const recent = [];
const hosts = new Map();

const cleanHost = (h) => String(h || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
const validHost = (h) => /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/.test(h) && h.includes('.');
const matches = (host, list) => list.find((d) => host === d || host.endsWith(`.${d}`));

function load() {
  try {
    const saved = JSON.parse(readFileSync(RULES, 'utf8'));
    state.enabled = saved.enabled === true;
    state.paused = saved.paused === true;
    state.allow = (saved.allow || []).map(cleanHost).filter(validHost);
    state.deny = (saved.deny || []).map(cleanHost).filter(validHost);
  } catch { /* first run */ }
}

function save() {
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  writeFileSync(RULES, JSON.stringify(state, null, 2), { mode: 0o600 });
}

export function decide(host, profile) {
  if (state.paused) return { allow: false, reason: 'all traffic paused' };
  const user = matches(host, state.deny);
  if (user) return { allow: false, reason: `blocked by you (${user})` };
  for (const [kind, list] of Object.entries(BUILTIN_DENY)) {
    const hit = matches(host, list);
    if (hit) return { allow: false, reason: kind === 'ai' ? `hosted AI service (${hit})` : `tracker (${hit})` };
  }
  const allowed = matches(host, state.allow);
  if (profile === 'strict') return allowed ? { allow: true, reason: `allowed by you (${allowed})` } : { allow: false, reason: 'not on the allow list' };
  return { allow: true, reason: allowed ? `allowed by you (${allowed})` : 'open profile' };
}

async function record(entry) {
  recent.push(entry);
  if (recent.length > 500) recent.shift();
  const key = `${entry.profile} ${entry.host}`;
  const h = hosts.get(key) || { host: entry.host, profile: entry.profile, requests: 0, refused: 0, sent: 0, received: 0 };
  h.requests += 1;
  if (!entry.allowed) h.refused += 1;
  h.sent += entry.sent;
  h.received += entry.received;
  h.lastSeen = entry.time;
  h.allowed = entry.allowed;
  h.reason = entry.reason;
  hosts.set(key, h);
  try {
    await mkdir(DIR, { recursive: true, mode: 0o700 });
    await appendFile(EGRESS_LOG, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
  } catch { /* the in-memory view still has it */ }
}

// Resolves here so the client never needs its own DNS, and refuses local targets so the proxy is not a way into the LAN.
async function target(host) {
  if (isIP(host)) return isNonPublic(host) ? null : host;
  const found = await lookup(host, { all: true });
  const usable = found.map((a) => a.address).filter((a) => !isNonPublic(a));
  return usable[0] || null;
}

function entryFor(profile, host, port, verdict, method) {
  return { time: new Date().toISOString(), profile, method, host, port, allowed: verdict.allow, reason: verdict.reason, sent: 0, received: 0 };
}

function onConnect(profile, req, client, head) {
  const m = String(req.url || '').match(/^(.+):(\d+)$/);
  const host = cleanHost(m?.[1]);
  const port = Number(m?.[2]);
  const refuse = (verdict, code = 403) => {
    client.end(`HTTP/1.1 ${code} Refused\r\nconnection: close\r\ncontent-type: text/plain; charset=utf-8\r\n\r\nLocal Network Watcher: ${verdict.reason}\n`);
    record(entryFor(profile, host || 'invalid', port || 0, verdict, 'CONNECT'));
  };
  client.on('error', () => {});
  if (!host || !port) return refuse({ allow: false, reason: 'invalid request' }, 400);
  const verdict = decide(host, profile);
  if (!verdict.allow) return refuse(verdict);
  target(host).then((address) => {
    if (!address) return refuse({ allow: false, reason: 'local or unresolved address' });
    const entry = entryFor(profile, host, port, verdict, 'CONNECT');
    const upstream = connect(port, address, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      entry.sent = upstream.bytesWritten;
      entry.received = upstream.bytesRead;
      client.destroy();
      upstream.destroy();
      record(entry);
    };
    upstream.on('error', finish);
    upstream.on('close', finish);
    client.on('close', finish);
  }).catch(() => refuse({ allow: false, reason: 'name could not be resolved' }, 502));
}

function onRequest(profile, req, res) {
  let url;
  try { url = new URL(req.url); } catch { url = null; }
  const refuse = (verdict, code = 403) => {
    res.writeHead(code, { 'content-type': 'text/plain; charset=utf-8', connection: 'close' }).end(`Local Network Watcher: ${verdict.reason}\n`);
    record(entryFor(profile, url ? cleanHost(url.hostname) : 'invalid', url ? Number(url.port || 80) : 0, verdict, req.method));
  };
  if (!url || url.protocol !== 'http:') return refuse({ allow: false, reason: 'only proxy requests are accepted here' }, 400);
  const host = cleanHost(url.hostname);
  const port = Number(url.port || 80);
  const verdict = decide(host, profile);
  if (!verdict.allow) return refuse(verdict);
  target(host).then((address) => {
    if (!address) return refuse({ allow: false, reason: 'local or unresolved address' });
    const entry = entryFor(profile, host, port, verdict, req.method);
    const headers = { ...req.headers, host: url.host };
    delete headers['proxy-connection'];
    delete headers['proxy-authorization'];
    const upstream = httpRequest({ host: address, port, method: req.method, path: `${url.pathname}${url.search}`, headers }, (reply) => {
      res.writeHead(reply.statusCode, reply.headers);
      reply.pipe(res);
    });
    const finish = () => {
      entry.sent = upstream.socket?.bytesWritten || 0;
      entry.received = upstream.socket?.bytesRead || 0;
      record(entry);
    };
    upstream.on('close', finish);
    upstream.on('error', () => { if (!res.headersSent) res.writeHead(502, { connection: 'close' }); res.end(); });
    req.pipe(upstream);
  }).catch(() => refuse({ allow: false, reason: 'name could not be resolved' }, 502));
}

function listen(profile, port) {
  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => onRequest(profile, req, res));
    server.on('connect', (req, socket, head) => onConnect(profile, req, socket, head));
    server.on('clientError', (_e, socket) => socket.destroy());
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => { servers.set(profile, server); resolve(); });
  });
}

async function start() {
  for (const [profile, port] of Object.entries(PROFILES)) {
    if (!servers.has(profile)) await listen(profile, port);
  }
}

function stop() {
  for (const [profile, server] of servers) {
    server.close();
    server.closeAllConnections?.();
    servers.delete(profile);
  }
}

export async function initEgress() {
  load();
  if (process.env.LOCAL_WATCH_EGRESS === '1') state.enabled = true;
  if (state.enabled) await start();
}

export async function setEnabled(enabled) {
  if (enabled) await start(); else stop();
  state.enabled = enabled;
  save();
}

export function setPaused(paused) {
  state.paused = paused;
  save();
  if (paused) for (const server of servers.values()) server.closeAllConnections?.();
}

export function changeRule(action, rawHost) {
  const host = cleanHost(rawHost);
  if (!validHost(host)) throw new Error('Enter a domain such as example.com.');
  state.allow = state.allow.filter((h) => h !== host);
  state.deny = state.deny.filter((h) => h !== host);
  if (action === 'allow') state.allow.push(host);
  if (action === 'deny') state.deny.push(host);
  state.allow.sort();
  state.deny.sort();
  save();
}

export function egressStatus() {
  return {
    enabled: state.enabled,
    running: servers.size === Object.keys(PROFILES).length,
    paused: state.paused,
    ports: PROFILES,
    allow: state.allow,
    deny: state.deny,
    builtin: { ai: BUILTIN_DENY.ai.length, tracker: BUILTIN_DENY.tracker.length },
    hosts: [...hosts.values()].sort((a, b) => String(b.lastSeen).localeCompare(String(a.lastSeen))),
    recent: recent.slice(-100).reverse(),
    log: EGRESS_LOG,
  };
}

import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { knownOwner, severityFor } from './known.js';

// Metadata only: app names, destination groups, ports, times. Never packet contents.
const DIR = process.env.LOCAL_WATCH_DATA || join(homedir(), 'Library', 'Application Support', 'LocalWatch');
export const HISTORY_FILE = join(DIR, 'history.json');
const LEARNING_MS = Number(process.env.LOCAL_WATCH_LEARNING_HOURS || 24) * 3600 * 1000;
const COMMON_PORTS = new Set(['443', '80', '53', '853', '993', '995', '587', '465', '5223', '123', '3478', '3479', '22', '8443', '5228']);
const MB = 1024 * 1024;

let state = null;
let dirty = false;
const prevTotals = new Map();

function fresh() {
  return { createdAt: Date.now(), apps: {}, accepted: {}, markers: [], ai: {} };
}

export async function loadHistory() {
  try {
    state = JSON.parse(await readFile(HISTORY_FILE, 'utf8'));
    if (!state.apps || !state.markers) state = fresh();
    state.ai ||= {};
  } catch {
    state = fresh();
  }
  return state;
}

export async function saveHistory() {
  if (!dirty || !state) return;
  await mkdir(DIR, { recursive: true, mode: 0o700 });
  const tmp = `${HISTORY_FILE}.tmp`;
  await writeFile(tmp, JSON.stringify(state), { mode: 0o600 });
  await rename(tmp, HISTORY_FILE);
  dirty = false;
}

export async function forgetHistory() {
  state = fresh();
  dirty = true;
  await rm(HISTORY_FILE, { force: true });
  await saveHistory();
}

export function learningUntil() {
  return state.createdAt + LEARNING_MS;
}

function hostOf(endpoint) {
  const s = String(endpoint || '');
  const i = s.lastIndexOf(':');
  return (i < 0 ? s : s.slice(0, i)).replace(/^\[|\]$/g, '');
}
function portOf(endpoint) {
  const s = String(endpoint || '');
  const i = s.lastIndexOf(':');
  return i < 0 ? '' : s.slice(i + 1);
}
function isPrivate(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fc|fd)/i.test(ip);
}
// Group a destination by its owner's domain when reverse DNS knows it, otherwise by network block.
export function destKey(ip, name) {
  const owner = knownOwner(ip);
  if (owner) return `org:${owner}`;
  if (name) {
    const labels = name.replace(/\.$/, '').split('.');
    const two = labels.slice(-2).join('.');
    return /^(co|com|net|org|gov|ac)\.[a-z]{2}$/.test(two) ? labels.slice(-3).join('.') : two;
  }
  if (ip.includes(':')) return `${ip.split(':').slice(0, 3).join(':')}::/48`;
  return `${ip.split('.').slice(0, 3).join('.')}.0/24`;
}

function destLabel(key) {
  return key.startsWith('org:') ? `owned by ${key.slice(4)}` : key;
}

// An older history grouped owner ranges by /24; treat those blocks as already known.
function knownBeforeOwnerGrouping(dests, owner) {
  return Object.keys(dests).some((k) => {
    if (/^\d+\.\d+\.\d+\.0\/24$/.test(k)) return knownOwner(k.replace(/0\/24$/, '1')) === owner;
    if (k.endsWith('::/48')) return knownOwner(k.replace(/::\/48$/, '::1')) === owner;
    return false;
  });
}

function addMarker(marker, now, tier = 'unknown') {
  if (state.accepted[marker.key]) return;
  const [severity, reason] = severityFor(marker.kind, tier, marker.app, marker.ip ? knownOwner(marker.ip) : '');
  marker = { ...marker, tier, severity, reason };
  if (state.markers.some((m) => m.key === marker.key && now - m.at < 24 * 3600 * 1000)) return;
  state.markers.unshift({ ...marker, at: now });
  state.markers.splice(300);
  dirty = true;
}

// One sample from the Rust core, reverse names for its addresses, and trust tiers by PID.
export function observe(snapshot, names, tiers = new Map(), now = Date.now()) {
  if (!state) return;
  const learning = now < learningUntil();
  const hour = new Date(now).getHours();
  const night = hour < 6;
  const seenAppsThisSample = new Set();
  for (const row of snapshot.connections || []) {
    const ip = hostOf(row.remote);
    if (!ip || isPrivate(ip)) continue;
    const appName = row.process || 'unknown';
    const port = portOf(row.remote);
    const name = names.get(ip) || '';
    const key = destKey(ip, name);
    const tier = tiers.get(Number(row.pid)) || 'unknown';
    let app = state.apps[appName];
    if (!app) {
      app = state.apps[appName] = { firstSeen: now, lastSeen: now, nightSamples: 0, dests: {}, ports: {}, rate: 0 };
      dirty = true;
      if (!learning) addMarker({ key: `app:${appName}`, kind: 'new-app', app: appName, ip, dest: key, text: `${appName} went online for the first time since this monitor started watching.` }, now, tier);
    }
    app.lastSeen = now;
    if (!app.dests[key]) {
      const migrated = key.startsWith('org:') && knownBeforeOwnerGrouping(app.dests, key.slice(4));
      app.dests[key] = now;
      dirty = true;
      if (!migrated && !learning && now - app.firstSeen > 3600 * 1000) addMarker({ key: `dest:${appName}:${key}`, kind: 'new-destination', app: appName, ip, dest: key, text: `${appName} connected to ${name || ip} (${destLabel(key)}), a destination it has not used before.` }, now, tier);
    }
    if (port && !app.ports[port]) {
      app.ports[port] = now;
      dirty = true;
      if (!learning && !COMMON_PORTS.has(port)) addMarker({ key: `port:${appName}:${port}`, kind: 'unusual-port', app: appName, ip, dest: key, text: `${appName} used port ${port}, which is not a usual web, mail or system port.` }, now, tier);
    }
    if (night && !seenAppsThisSample.has(appName)) {
      seenAppsThisSample.add(appName);
      if (!learning && app.nightSamples < 3) addMarker({ key: `night:${appName}`, kind: 'night', app: appName, ip, dest: key, text: `${appName} was online at ${String(hour).padStart(2, '0')}:00, and it rarely is at night.` }, now, tier);
      app.nightSamples += 1;
      dirty = true;
    }
  }
  for (const proc of snapshot.processes || []) {
    const app = state.apps[proc.process];
    if (!app) continue;
    const total = (Number(proc.receivedBytes) || 0) + (Number(proc.sentBytes) || 0);
    const prev = prevTotals.get(proc.pid);
    prevTotals.set(proc.pid, total);
    if (prev == null || total < prev) continue;
    const delta = total - prev;
    if (!learning && app.rate > 0 && delta > Math.max(50 * MB, app.rate * 20)) {
      addMarker({ key: `volume:${proc.process}:${Math.floor(now / 3600000)}`, kind: 'volume', app: proc.process, text: `${proc.process} moved ${(delta / MB).toFixed(0)} MB in a few seconds, far more than usual for it.` }, now, tiers.get(Number(proc.pid)) || 'unknown');
    }
    app.rate = app.rate ? app.rate * 0.95 + delta * 0.05 : delta;
  }
}

export function currentMarkers(now = Date.now()) {
  return state.markers.filter((m) => !state.accepted[m.key] && now - m.at < 7 * 24 * 3600 * 1000).map((m) => (state.ai[m.key] ? { ...m, ai: state.ai[m.key] } : m));
}

// Stores a local model verdict. A "normal" verdict silences the marker the same way "Looks normal" does.
export function recordReview(key, review) {
  if (!state.markers.some((m) => m.key === key)) return false;
  state.ai[key] = { ...review, at: Date.now() };
  if (review.verdict === 'normal') state.accepted[key] = Date.now();
  dirty = true;
  return true;
}

// Markers the local model silenced in the last 7 days, so a person can review or restore them.
export function aiCleared(now = Date.now()) {
  return state.markers.filter((m) => state.ai[m.key]?.verdict === 'normal' && state.accepted[m.key] && now - m.at < 7 * 24 * 3600 * 1000).map((m) => ({ ...m, ai: state.ai[m.key] }));
}

export function restore(key) {
  if (!state.ai[key] || state.ai[key].verdict !== 'normal') return false;
  delete state.accepted[key];
  state.ai[key] = { ...state.ai[key], verdict: 'restored' };
  dirty = true;
  return true;
}

export function accept(key) {
  if (typeof key !== 'string' || key.length > 300) return false;
  state.accepted[key] = Date.now();
  dirty = true;
  return true;
}

export function summary() {
  return { learningUntil: learningUntil(), apps: Object.keys(state.apps).length, file: HISTORY_FILE };
}

// First time this monitor saw an app name in local history, or null.
export function appFirstSeen(name) {
  return state?.apps?.[name]?.firstSeen ?? null;
}

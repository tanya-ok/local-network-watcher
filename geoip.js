import { readFile, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Reader } from 'mmdb-lib';

export const geoipPath = process.env.LOCAL_WATCH_GEOIP || join(homedir(), 'Library', 'Application Support', 'LocalWatch', 'geoip', 'dbip-city-lite.mmdb');

let reader = null;
let loadedMtime = 0;
let lastCheck = 0;

export function isNonPublic(ip) {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b < 128) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) || a >= 224;
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s.startsWith('::ffff:')) return isNonPublic(s.slice(7));
    return s === '::' || s === '::1' || /^f[cd]/.test(s) || /^fe[89ab]/.test(s) || s.startsWith('ff');
  }
  return true;
}

async function getReader() {
  const now = Date.now();
  if (reader && now - lastCheck < 60000) return reader;
  lastCheck = now;
  let info;
  try { info = await stat(geoipPath); } catch { reader = null; return null; }
  if (!reader || info.mtimeMs !== loadedMtime) {
    reader = new Reader(await readFile(geoipPath));
    loadedMtime = info.mtimeMs;
  }
  return reader;
}

// Offline lookup only; no network calls.
export async function geoLookup(ips) {
  let r;
  try { r = await getReader(); } catch (e) { return { status: 'error', error: `GeoIP file could not be read: ${e.message}`, places: new Map() }; }
  const places = new Map();
  if (!r) return { status: 'missing', places };
  for (const ip of ips) {
    if (isNonPublic(ip)) continue;
    const hit = r.get(ip);
    const loc = hit?.location;
    if (!loc || typeof loc.latitude !== 'number') continue;
    places.set(ip, { lat: loc.latitude, lon: loc.longitude, city: hit.city?.names?.en || '', country: hit.country?.iso_code || '' });
  }
  return { status: 'ok', places };
}

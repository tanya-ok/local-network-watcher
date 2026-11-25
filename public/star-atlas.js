const atlasSvg = document.querySelector('#atlas-svg');
const atlasNote = document.querySelector('#atlas-note');
const atlasKey = document.querySelector('#atlas-key');
const atlasHomeForm = document.querySelector('#atlas-home');
const atlasW = 900, atlasH = 440, atlasCx = 450, atlasCy = 220, atlasR = 148;
let atlasData = null;
let atlasBusy = false;

const atlasEsc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const atlasHash = (s) => { let h = 0; for (const ch of String(s)) h = (h * 31 + ch.charCodeAt(0)) >>> 0; return h; };

function atlasHome() {
  try {
    const v = JSON.parse(localStorage.getItem('local-watch-atlas-home') || 'null');
    if (v && Number.isFinite(v.lat) && Number.isFinite(v.lon)) return v;
  } catch { /* Default home is used. */ }
  // No IP lookup: longitude is estimated from the time zone offset only.
  const lon = Math.max(-180, Math.min(180, (-new Date().getTimezoneOffset() / 60) * 15));
  return { lat: 30, lon, unset: true };
}

function mollweide(lat, lon, lon0) {
  const phi = (lat * Math.PI) / 180;
  let lam = (((lon - lon0 + 540) % 360) - 180) * Math.PI / 180;
  let t = phi;
  for (let i = 0; i < 20; i++) {
    const f = 2 * t + Math.sin(2 * t) - Math.PI * Math.sin(phi);
    const d = 2 + 2 * Math.cos(2 * t);
    if (Math.abs(d) < 1e-9) break;
    const step = f / d;
    t -= step;
    if (Math.abs(step) < 1e-7) break;
  }
  return [atlasCx + (2 * Math.SQRT2 / Math.PI) * atlasR * lam * Math.cos(t), atlasCy - Math.SQRT2 * atlasR * Math.sin(t)];
}

function graticule(lon0) {
  const paths = [];
  for (let lon = -180; lon <= 180; lon += 30) {
    const pts = [];
    for (let lat = -90; lat <= 90; lat += 5) pts.push(mollweide(lat, lon0 + lon - (lon === 180 ? 1e-6 : 0), lon0));
    paths.push(`<path class="atlas-grid${lon === 0 ? ' atlas-grid-main' : ''}" d="M${pts.map((p) => p.map((n) => n.toFixed(1)).join(' ')).join('L')}"/>`);
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const a = mollweide(lat, lon0 - 180 + 1e-6, lon0), b = mollweide(lat, lon0 + 180 - 1e-6, lon0);
    paths.push(`<path class="atlas-grid${lat === 0 ? ' atlas-grid-main' : ''}" d="M${a[0].toFixed(1)} ${a[1].toFixed(1)}L${b[0].toFixed(1)} ${b[1].toFixed(1)}"/>`);
  }
  paths.push(`<ellipse class="atlas-rim" cx="${atlasCx}" cy="${atlasCy}" rx="${2 * Math.SQRT2 * atlasR}" ry="${Math.SQRT2 * atlasR}"/>`);
  return paths.join('');
}

function processColor(name) { return `var(--atlas-${'abcdef'[atlasHash(name) % 6]})`; }

function renderAtlas() {
  if (!atlasData) return;
  const home = atlasHome();
  const lon0 = home.lon;
  const [hx, hy] = mollweide(home.lat, home.lon, lon0);
  const geoOk = atlasData.geoip === 'ok';
  const stats = typeof currentProcessStats !== 'undefined' ? currentProcessStats : new Map();
  const bytesOf = (d) => d.pids.reduce((s, pid) => { const p = stats.get(Number(pid)); return s + (p ? p.receivedBytes + p.sentBytes : 0); }, 0);
  const maxBytes = Math.max(1, ...atlasData.destinations.map(bytesOf));
  const flagged = new Set((typeof markers !== 'undefined' ? markers : []).filter((m) => m.kind === 'new-destination' && m.ip).map((m) => m.ip));
  const localCount = atlasData.destinations.filter((d) => d.local).length;
  const points = atlasData.destinations.filter((d) => !d.local).map((d) => {
    let x, y, placed = 'geo';
    if (geoOk && d.lat != null) [x, y] = mollweide(d.lat, d.lon, lon0);
    else {
      const ang = (atlasHash(d.ip) % 360) * Math.PI / 180;
      x = hx + Math.cos(ang) * 176; y = hy + Math.sin(ang) * 110;
      placed = 'ring';
    }
    const r = 2.5 + 8 * Math.sqrt(bytesOf(d) / maxBytes);
    return { ...d, x, y, r, placed, color: processColor(d.processes[0]), fresh: flagged.has(d.ip) };
  });
  const many = points.length > 25;
  const labels = new Map();
  for (const p of points) {
    const key = many ? (p.domain || p.ip) : p.ip;
    const g = labels.get(key) || { key, hosts: 0, best: p, fresh: false };
    g.hosts++; if (p.r > g.best.r) g.best = p; g.fresh ||= p.fresh;
    labels.set(key, g);
  }
  const arcs = points.map((p) => {
    const mx = (hx + p.x) / 2, my = (hy + p.y) / 2 - Math.min(80, Math.hypot(p.x - hx, p.y - hy) / 4);
    return `<path class="atlas-arc${p.placed !== 'geo' ? ' atlas-arc-unknown' : ''}" stroke="${p.color}" d="M${hx.toFixed(1)} ${hy.toFixed(1)}Q${mx.toFixed(1)} ${my.toFixed(1)} ${p.x.toFixed(1)} ${p.y.toFixed(1)}"/>`;
  }).join('');
  const dots = points.map((p) => `<g class="atlas-star${p.fresh ? ' atlas-new' : ''}" data-ip="${atlasEsc(p.ip)}" data-app="${atlasEsc(p.processes[0])}" tabindex="0" role="button" aria-label="${atlasEsc(`${p.name || p.ip}, ${p.processes.join(', ')}${p.city ? `, ${p.city}` : ''}${p.country ? ` ${p.country}` : ''}`)}"><title>${atlasEsc(`${p.name || p.ip}\n${p.processes.join(', ')}\n${p.city ? `${p.city}, ` : ''}${p.country || (p.local ? 'Local network, no location' : 'No location')}`)}</title>${p.fresh ? `<circle class="atlas-halo" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${(p.r + 5).toFixed(1)}"/>` : ''}<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${p.r.toFixed(1)}" fill="${p.color}"/></g>`).join('');
  // Labels are placed right, left, above or below the star; a label that fits nowhere is left to the tooltip.
  const boxes = [[hx - 4, hy - 18, hx + 80, hy + 2], ...points.map((p) => [p.x - p.r, p.y - p.r, p.x + p.r, p.y + p.r])];
  const hit = (b) => b[0] < 0 || b[2] > atlasW || b[1] < 0 || b[3] > atlasH || boxes.some((o) => b[0] < o[2] && b[2] > o[0] && b[1] < o[3] && b[3] > o[1]);
  const text = [...labels.values()].sort((a, b) => b.best.r - a.best.r).slice(0, 30).map((g) => {
    const p = g.best;
    const name = `${many ? `${g.key}${g.hosts > 1 ? ` (${g.hosts} hosts)` : ''}` : (p.domain || p.ip)}${g.fresh ? ' new' : ''}`;
    const w = name.length * 6.6, h = 12, gap = p.r + 4;
    const spots = [[p.x + gap, p.y + 4, 'start'], [p.x - gap, p.y + 4, 'end'], [p.x, p.y - gap - 2, 'middle'], [p.x, p.y + gap + 10, 'middle']];
    for (const [x, y, anchor] of spots) {
      const x0 = anchor === 'start' ? x : anchor === 'end' ? x - w : x - w / 2;
      const box = [x0 - 2, y - h + 2, x0 + w + 2, y + 3];
      if (hit(box)) continue;
      boxes.push(box);
      return `<text class="atlas-label${g.fresh ? ' atlas-label-new' : ''}" text-anchor="${anchor}" x="${x.toFixed(1)}" y="${y.toFixed(1)}">${atlasEsc(name)}</text>`;
    }
    return '';
  }).join('');
  const ring = geoOk ? '' : `<ellipse class="atlas-ring" cx="${hx.toFixed(1)}" cy="${hy.toFixed(1)}" rx="${110 * 1.6}" ry="110"/>`;
  atlasSvg.innerHTML = `${graticule(lon0)}${ring}<g class="atlas-arcs">${arcs}</g>${dots}<circle class="atlas-home" cx="${hx.toFixed(1)}" cy="${hy.toFixed(1)}" r="5"/><text class="atlas-label atlas-home-label" x="${(hx + 9).toFixed(1)}" y="${(hy - 6).toFixed(1)}">home${home.unset ? ' (time zone estimate)' : ''}</text>${text}`;
  const procs = new Map();
  for (const p of points) for (const name of p.processes) procs.set(name, (procs.get(name) || 0) + 1);
  atlasKey.innerHTML = [...procs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([name, n]) => `<span><i style="background:${processColor(name)}"></i>${atlasEsc(name)} <small>${n}</small></span>`).join('') || '<span>No remote destinations right now.</span>';
  const unplaced = points.filter((p) => p.placed === 'ring').length;
  atlasNote.innerHTML = atlasData.geoip === 'missing'
    ? 'No GeoIP file, so destinations sit on a ring around home. To place them, download the free db-ip City Lite mmdb and put it at <code>~/Library/Application Support/LocalWatch/geoip/dbip-city-lite.mmdb</code> (see README).'
    : atlasData.geoip === 'error' ? atlasEsc(atlasData.geoipError || 'The GeoIP file could not be read.')
    : atlasData.error ? atlasEsc(atlasData.error)
    : `${points.length} remote destinations · ${localCount} on the local network (not drawn) · ${unplaced} without a location. Locations are city-level estimates.`;
}

async function loadAtlas() {
  if (atlasBusy || !document.querySelector('#star-atlas')?.classList.contains('active-view')) return;
  atlasBusy = true;
  try {
    const res = await fetch('/api/atlas', { cache: 'no-store' });
    atlasData = await res.json();
    renderAtlas();
  } catch { atlasNote.textContent = 'The atlas could not reach the local server.'; }
  finally { atlasBusy = false; }
}

atlasSvg.addEventListener('click', (e) => {
  const star = e.target.closest('.atlas-star');
  if (!star) return;
  const app = star.dataset.app, ip = star.dataset.ip;
  location.hash = '#map';
  if (typeof selectOnMap === 'function') setTimeout(() => selectOnMap({ app, ip }), 60);
});
atlasSvg.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.closest('.atlas-star')) e.target.closest('.atlas-star').dispatchEvent(new MouseEvent('click', { bubbles: true })); });
atlasHomeForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const lat = Number(atlasHomeForm.lat.value), lon = Number(atlasHomeForm.lon.value);
  try {
    if (atlasHomeForm.lat.value === '' && atlasHomeForm.lon.value === '') localStorage.removeItem('local-watch-atlas-home');
    else if (Math.abs(lat) <= 90 && Math.abs(lon) <= 180) localStorage.setItem('local-watch-atlas-home', JSON.stringify({ lat, lon }));
  } catch { /* Home stays at the default for this page. */ }
  renderAtlas();
});
{ const h = atlasHome(); if (!h.unset) { atlasHomeForm.lat.value = h.lat; atlasHomeForm.lon.value = h.lon; } }
window.addEventListener('hashchange', () => { if (location.hash === '#star-atlas') loadAtlas(); });
window.addEventListener('markers-updated', renderAtlas);
loadAtlas();
setInterval(loadAtlas, 5000);

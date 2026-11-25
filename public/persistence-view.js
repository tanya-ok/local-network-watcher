(() => {
  const root = document.getElementById('persistence-body');
  const note = document.getElementById('persistence-note');
  const search = document.getElementById('persistence-search');
  let items = [];
  let seq = 0;
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const base = (p) => String(p || '').split('/').pop();
  const vendor = (label) => {
    const parts = String(label).split('.');
    return parts.length > 2 && ['com', 'org', 'io', 'net', 'dev', 'app', 'co'].includes(parts[0]) ? parts[1] : '';
  };
  const where = (i) => i.apple ? 'Apple, part of macOS' : i.scope.startsWith('user') ? 'Your account only' : i.scope.includes('daemon') ? 'All users, runs as system' : 'All users, at login';
  const badges = (i) => [
    i.runAtLoad && 'starts automatically',
    i.keepAlive && (typeof i.keepAlive === 'object' ? 'restarts on conditions' : 'restarts if stopped'),
    i.disabled && 'disabled',
  ].filter(Boolean).map((b) => `<span class="pers-badge">${esc(b)}</span>`).join('');
  const card = (i) => `<details class="pers-card${i.network ? ' pers-online' : ''}"><summary><span class="pers-dot"></span><span class="pers-name"><strong>${esc(base(i.program) || i.label)}</strong><small>${esc(vendor(i.label) || i.label)}</small></span><span class="pers-where">${esc(where(i))}</span><span class="pers-badges">${badges(i)}</span>${i.network ? `<span class="pers-net">online as ${esc(i.network.process)} · PID ${esc(i.network.pid)}</span>` : i.running ? `<span class="pers-run">running · PID ${esc(i.pid)}</span>` : ''}</summary><dl><dt>Label</dt><dd>${esc(i.label)}</dd><dt>Program</dt><dd>${esc([i.program, ...(i.arguments || []).slice(1)].join(' ') || 'not set')}</dd><dt>Plist</dt><dd>${(i.files || [i.file]).map(esc).join('<br>')}</dd>${i.network ? `<dt>Matched by</dt><dd>${esc(i.network.matchedBy)}</dd>` : ''}</dl>${i.network ? `<button class="text-button pers-map" type="button" data-app="${esc(i.network.process)}">Show on Map</button>` : ''}</details>`;
  const group = (title, hint, list) => list.length ? `<section class="pers-group"><h3>${esc(title)} <small>${list.length}</small></h3><p class="pers-hint">${esc(hint)}</p>${list.map(card).join('')}</section>` : '';
  function render() {
    const q = search.value.trim().toLowerCase();
    const shown = items.filter((i) => !q || [i.label, i.program, i.network?.process].join(' ').toLowerCase().includes(q));
    const online = shown.filter((i) => i.network);
    const running = shown.filter((i) => !i.network && i.running);
    const idle = shown.filter((i) => !i.network && !i.running);
    root.innerHTML = `<div class="pers-summary"><div><b>${items.filter((i) => i.network).length}</b><span>online now</span></div><div><b>${items.filter((i) => !i.network && i.running).length}</b><span>running, no connection</span></div><div><b>${items.filter((i) => !i.running).length}</b><span>installed, not running</span></div><div><b>${items.filter((i) => i.runAtLoad).length}</b><span>start automatically</span></div></div>`
      + group('Online now', 'Started by launchd and holding an open network connection. Start here.', online)
      + group('Running without a connection', 'Started by launchd, no open connection in the latest snapshot.', running)
      + group('Installed, not running', 'Registered to start later, at login or on demand.', idle)
      + (shown.length ? '' : '<p class="pers-hint">Nothing matches this search.</p>');
  }
  async function load() {
    const mine = ++seq;
    try {
      const data = await (await fetch('/api/persistence', { cache: 'no-store' })).json();
      if (mine !== seq) return;
      // The same job can ship as an agent and a daemon plist; show it once.
      const seen = new Map();
      for (const i of data.items || []) {
        const key = `${i.label}|${i.program}`;
        const prev = seen.get(key);
        if (!prev) seen.set(key, { ...i, files: [i.file] });
        else { prev.files.push(i.file); prev.network ||= i.network; prev.running ||= i.running; prev.runAtLoad ||= i.runAtLoad; }
      }
      items = [...seen.values()];
      render();
      note.textContent = `Read only. Apple entries appear only when they hold a connection.${data.unreadable?.length ? ` ${data.unreadable.length} plist files could not be read.` : ''}`;
    } catch { if (mine === seq) note.textContent = 'Persistence data is unavailable.'; }
  }
  search.addEventListener('input', render);
  root.addEventListener('click', (e) => {
    const b = e.target.closest('.pers-map');
    if (!b) return;
    location.hash = '#map';
    if (typeof selectOnMap === 'function') setTimeout(() => selectOnMap({ app: b.dataset.app }), 60);
  });
  document.getElementById('persistence-refresh').addEventListener('click', load);
  window.addEventListener('hashchange', () => { if (location.hash === '#persistence') load(); });
  if (location.hash === '#persistence') load();
})();

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
    i.disabled && 'disabled in plist',
    i.userDisabled && 'turned off by you',
  ].filter(Boolean).map((b) => `<span class="pers-badge">${esc(b)}</span>`).join('');
  const card = (i) => `<details class="pers-card${i.network ? ' pers-online' : ''}"><summary><span class="pers-dot"></span><span class="pers-name"><strong>${esc(base(i.program) || i.label)}</strong><small>${esc(vendor(i.label) || i.label)}</small></span><span class="pers-where">${esc(where(i))}</span><span class="pers-badges">${badges(i)}</span>${i.network ? `<span class="pers-net">online as ${esc(i.network.process)} · PID ${esc(i.network.pid)}</span>` : i.running ? `<span class="pers-run">running · PID ${esc(i.pid)}</span>` : ''}</summary><dl><dt>Label</dt><dd>${esc(i.label)}</dd><dt>Program</dt><dd>${esc([i.program, ...(i.arguments || []).slice(1)].join(' ') || 'not set')}</dd><dt>Plist</dt><dd>${(i.files || [i.file]).map(esc).join('<br>')}</dd>${i.network ? `<dt>Matched by</dt><dd>${esc(i.network.matchedBy)}</dd>` : ''}</dl><div class="pers-actions">${i.network ? `<button class="text-button pers-map" type="button" data-app="${esc(i.network.process)}">Show on Map</button>` : ''}${controls(i)}</div></details>`;
  const controls = (i) => {
    if (i.apple) return '';
    if (!i.controllable) return '<span class="pers-hint">Installed for all users. Changing it needs an administrator, so it is not changed here.</span>';
    const btn = (action, text) => `<button class="text-button pers-act" type="button" data-action="${action}" data-file="${esc(i.file)}" data-name="${esc(base(i.program) || i.label)}">${esc(text)}</button>`;
    return i.userDisabled || !i.running
      ? (i.userDisabled ? btn('enable', 'Turn back on') : btn('enable', 'Start now'))
      : `${btn('stop', 'Stop until next login')}${btn('disable', 'Stop and keep off')}`;
  };
  const confirmText = {
    stop: (n) => `Stop ${n} now?\n\nlaunchd unloads the job, so it is not restarted. It starts again at your next login.`,
    disable: (n) => `Stop ${n} and keep it off?\n\nlaunchd unloads the job and marks it disabled, so it stays off after login. You can turn it back on here.`,
    enable: (n) => `Turn ${n} back on?\n\nlaunchd enables and loads the job again.`,
  };
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
  root.addEventListener('click', async (e) => {
    const act = e.target.closest('.pers-act');
    if (act) {
      if (!window.confirm(confirmText[act.dataset.action](act.dataset.name))) return;
      act.disabled = true;
      try {
        const res = await fetch('/api/persistence/job', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: act.dataset.action, file: act.dataset.file, confirm: true }) });
        const out = await res.json();
        note.textContent = res.ok ? `${act.dataset.name}: ${out.result === 'ok' ? 'done' : `done with notes: ${out.notes.join('; ')}`}. Logged to actions.log.` : `${act.dataset.name}: ${out.error}`;
      } catch { note.textContent = 'The local server did not answer.'; }
      setTimeout(load, 800);
      return;
    }
    const b = e.target.closest('.pers-map');
    if (!b) return;
    location.hash = '#map';
    if (typeof selectOnMap === 'function') setTimeout(() => selectOnMap({ app: b.dataset.app }), 60);
  });
  document.getElementById('persistence-refresh').addEventListener('click', load);
  window.addEventListener('hashchange', () => { if (location.hash === '#persistence') load(); });
  if (location.hash === '#persistence') load();
})();

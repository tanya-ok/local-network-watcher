(() => {
  const root = document.getElementById('egress-body');
  const note = document.getElementById('egress-note');
  const form = document.getElementById('egress-form');
  let timer = null;
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const bytes = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
  const time = (t) => t ? new Date(t).toLocaleTimeString() : '';
  const btn = (action, host, text) => `<button class="text-button egress-rule" type="button" data-action="${action}" data-host="${esc(host)}">${esc(text)}</button>`;

  async function post(path, body) {
    const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || 'The change was not applied.');
    return data;
  }

  function render(d) {
    const status = !d.enabled ? 'Off' : d.paused ? 'Paused: everything is refused' : d.running ? 'On' : 'Not running';
    const hostRows = d.hosts.map((h) => `<tr class="${h.allowed ? '' : 'egress-refused'}"><td><strong>${esc(h.host)}</strong><small>${esc(h.reason)}</small></td><td>${esc(h.profile)}</td><td>${h.allowed ? 'let through' : 'refused'}</td><td>${h.requests}</td><td>${bytes(h.sent)}</td><td>${bytes(h.received)}</td><td>${esc(time(h.lastSeen))}</td><td>${btn('allow', h.host, 'Allow')}${btn('deny', h.host, 'Block')}</td></tr>`).join('');
    const list = (title, items, empty) => `<div class="egress-list"><h3>${esc(title)} <small>${items.length}</small></h3>${items.length ? items.map((h) => `<span class="egress-chip">${esc(h)}${btn('remove', h, 'Remove')}</span>`).join('') : `<p class="pers-hint">${esc(empty)}</p>`}</div>`;
    root.innerHTML = `
      <div class="egress-status"><span class="egress-state ${d.enabled && !d.paused ? 'on' : ''}">${esc(status)}</span>
        <button class="text-button" id="egress-toggle" type="button">${d.enabled ? 'Turn proxy off' : 'Turn proxy on'}</button>
        <button class="text-button" id="egress-pause" type="button"${d.enabled ? '' : ' disabled'}>${d.paused ? 'Resume traffic' : 'Pause all traffic'}</button></div>
      <dl class="egress-facts"><dt>Open profile</dt><dd>127.0.0.1:${d.ports.open}. Everything passes except blocked domains. Meant for the browser.</dd><dt>Strict profile</dt><dd>127.0.0.1:${d.ports.strict}. Only the allow list passes. Meant for everything else.</dd><dt>Always refused</dt><dd>${d.builtin.ai} hosted AI domains and ${d.builtin.tracker} tracker domains, with their subdomains.</dd></dl>
      <div class="egress-lists">${list('Allowed by you', d.allow, 'Nothing yet. The strict profile refuses everything.')}${list('Blocked by you', d.deny, 'Nothing yet.')}</div>
      <h3>Destinations since start <small>${d.hosts.length}</small></h3>
      ${d.hosts.length ? `<div class="egress-scroll"><table class="egress-table"><thead><tr><th>Destination</th><th>Profile</th><th>Result</th><th>Requests</th><th>Sent</th><th>Received</th><th>Last seen</th><th></th></tr></thead><tbody>${hostRows}</tbody></table></div>` : '<p class="pers-hint">No program has used the proxy yet.</p>'}`;
    note.textContent = `Only traffic sent through this proxy is listed. Programs that do not use it are not seen here. Journal: ${d.log}`;
    document.getElementById('egress-toggle').onclick = () => change('/api/egress/enable', { enabled: !d.enabled });
    document.getElementById('egress-pause').onclick = () => change('/api/egress/pause', { paused: !d.paused });
  }

  async function change(path, body) {
    try { render(await post(path, body)); } catch (e) { note.textContent = e.message; }
  }

  async function load() {
    try { render(await (await fetch('/api/egress', { cache: 'no-store' })).json()); } catch { note.textContent = 'Egress status could not be loaded.'; }
  }

  root.addEventListener('click', (event) => {
    const b = event.target.closest('.egress-rule');
    if (b) change('/api/egress/rule', { action: b.dataset.action, host: b.dataset.host });
  });
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const host = form.elements.host.value;
    const action = event.submitter?.value || 'allow';
    change('/api/egress/rule', { action, host }).then(() => { form.elements.host.value = ''; });
  });
  function sync() {
    clearInterval(timer);
    if (location.hash !== '#egress') return;
    load();
    timer = setInterval(load, 5000);
  }
  window.addEventListener('hashchange', sync);
  sync();
})();

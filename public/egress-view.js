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

  const describe = (c) => c.action === 'rule' ? `${c.rule} ${c.host}` : c.action === 'ports' ? `ports ${c.ports}` : c.action === 'enable' ? (c.enabled ? 'turn proxy on' : 'turn proxy off') : (c.paused ? 'pause all traffic' : 'resume traffic');

  function pendingBlock(d) {
    const rows = (d.pending || []).map((p) => `<tr><td><strong>${esc(describe(p.change))}</strong><small>id ${esc(p.id)}</small></td><td>${esc(p.user)} (uid ${p.uid})</td><td>${esc(new Date(p.expires * 1000).toLocaleTimeString())}</td><td><button class="text-button egress-resolve" type="button" data-op="approve" data-id="${esc(p.id)}">Approve</button><button class="text-button egress-resolve" type="button" data-op="deny" data-id="${esc(p.id)}">Deny</button></td></tr>`).join('');
    return `<h3>Waiting for approval <small>${(d.pending || []).length}</small></h3>${rows ? `<div class="egress-scroll"><table class="egress-table"><thead><tr><th>Change</th><th>Requested by</th><th>Expires</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="pers-hint">Nothing is waiting. Changes from accounts that are not admins wait here until an admin approves them.</p>'}`;
  }

  function dnsBlock(d) {
    const dns = d.dns || {};
    if (!dns.visible) return `<h3>DNS queries</h3><p class="pers-hint">DNS visibility is off. No pflog data at ${esc(dns.log || 'the DNS log')}.</p>`;
    const rows = (dns.recent || []).map((q) => `<tr><td><strong>${esc(q.name)}</strong></td><td>${esc(q.qtype)}</td><td>${esc(q.source)}</td><td>${esc(q.server)}</td><td>${esc(q.time)}</td></tr>`).join('');
    return `<h3>DNS queries <small>resolver, not proxied</small></h3>${rows ? `<div class="egress-scroll"><table class="egress-table"><thead><tr><th>Name</th><th>Type</th><th>From</th><th>Resolver</th><th>Time</th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="pers-hint">No queries logged since start.</p>'}`;
  }

  function recentBlock(d) {
    const rows = (d.recent || []).slice(0, 30).map((e) => `<tr class="${e.allowed ? '' : 'egress-refused'}"><td>${esc(time(e.time))}</td><td>${esc(e.user)} (uid ${e.uid})</td><td>${esc(e.profile)}</td><td><strong>${esc(e.host)}</strong><small>${esc(e.reason)}</small></td><td>${e.allowed ? 'let through' : 'refused'}</td></tr>`).join('');
    return rows ? `<h3>Recent connections</h3><div class="egress-scroll"><table class="egress-table"><thead><tr><th>Time</th><th>Account</th><th>Profile</th><th>Destination</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table></div>` : '';
  }

  function render(d) {
    if (d.unreachable) {
      root.innerHTML = `<p class="egress-error">The egress daemon is not reachable: ${esc(d.error)}</p>`;
      return;
    }
    const status = !d.enabled ? 'Off' : d.paused ? 'Paused: everything is refused' : d.running ? 'On' : 'Not running';
    const errors = Object.entries(d.errors || {}).map(([p, m]) => `<p class="egress-error">${esc(p)} profile did not start: ${esc(m)}</p>`).join('');
    const hostRows = d.hosts.map((h) => `<tr class="${h.allowed ? '' : 'egress-refused'}"><td><strong>${esc(h.host)}</strong><small>${esc(h.reason)}</small></td><td>${esc(h.profile)}</td><td>${h.allowed ? 'let through' : 'refused'}</td><td>${h.requests}</td><td>${bytes(h.sent)}</td><td>${bytes(h.received)}</td><td>${esc(time(h.lastSeen))}</td><td>${btn('allow', h.host, 'Allow')}${btn('deny', h.host, 'Block')}</td></tr>`).join('');
    const list = (title, items, empty) => `<div class="egress-list"><h3>${esc(title)} <small>${items.length}</small></h3>${items.length ? items.map((h) => `<span class="egress-chip">${esc(h)}${btn('remove', h, 'Remove')}</span>`).join('') : `<p class="pers-hint">${esc(empty)}</p>`}</div>`;
    root.innerHTML = `
      <div class="egress-status"><span class="egress-state ${d.enabled && !d.paused ? 'on' : ''}">${esc(status)}</span>
        <button class="text-button" id="egress-toggle" type="button">${d.enabled ? 'Turn proxy off' : 'Turn proxy on'}</button>
        <button class="text-button" id="egress-pause" type="button"${d.enabled ? '' : ' disabled'}>${d.paused ? 'Resume traffic' : 'Pause all traffic'}</button></div>${errors}
      <dl class="egress-facts"><dt>Runs in</dt><dd>${d.mode === 'daemon' ? 'The system egress daemon, under its own account.' : 'This app.'} Changes from accounts that are not admins wait for approval.</dd><dt>Open profile</dt><dd>127.0.0.1:${d.ports.open}. Everything passes except blocked domains. Meant for the browser.</dd><dt>Strict profile</dt><dd>127.0.0.1:${d.ports.strict}. Only the allow list passes. Meant for everything else.</dd><dt>Allowed ports</dt><dd><form id="egress-ports" class="egress-ports"><input name="ports" value="${(d.allowedPorts || []).join(', ')}" aria-label="Allowed destination ports"><button class="text-button" type="submit">Save ports</button></form>Other ports, such as 22 or 25, are refused.</dd><dt>Direct IP addresses</dt><dd>Refused unless you allow that exact address, because domain lists cannot judge a bare address.</dd><dt>Journal</dt><dd>Rotated at 5 MB, the last 3 files are kept.</dd><dt>Always refused</dt><dd>${d.builtin.ai} hosted AI domains and ${d.builtin.tracker} tracker domains, with their subdomains.</dd></dl>
      ${pendingBlock(d)}
      <div class="egress-lists">${list('Allowed by you', d.allow, 'Nothing yet. The strict profile refuses everything.')}${list('Blocked by you', d.deny, 'Nothing yet.')}</div>
      <h3>Destinations since start <small>${d.hosts.length}</small></h3>
      ${d.hosts.length ? `<div class="egress-scroll"><table class="egress-table"><thead><tr><th>Destination</th><th>Profile</th><th>Result</th><th>Requests</th><th>Sent</th><th>Received</th><th>Last seen</th><th></th></tr></thead><tbody>${hostRows}</tbody></table></div>` : '<p class="pers-hint">No program has used the proxy yet.</p>'}
      ${recentBlock(d)}${dnsBlock(d)}`;
    note.textContent = `Only traffic sent through this proxy is listed. Programs that do not use it are not seen here. Journal: ${d.log}`;
    document.getElementById('egress-ports').onsubmit = (event) => { event.preventDefault(); change('/api/egress/ports', { ports: event.target.elements.ports.value }); };
    document.getElementById('egress-toggle').onclick = () => change('/api/egress/enable', { enabled: !d.enabled });
    document.getElementById('egress-pause').onclick = () => change('/api/egress/pause', { paused: !d.paused });
  }

  async function change(path, body) {
    try {
      const d = await post(path, body);
      render(d);
      if (d.outcome?.outcome === 'pending') note.textContent = `Waiting for approval by an admin account: ${d.outcome.pendingId}`;
    } catch (e) { note.textContent = e.message; }
  }

  async function load() {
    try { render(await (await fetch('/api/egress', { cache: 'no-store' })).json()); } catch { note.textContent = 'Egress status could not be loaded.'; }
  }

  root.addEventListener('click', (event) => {
    const b = event.target.closest('.egress-rule');
    if (b) change('/api/egress/rule', { action: b.dataset.action, host: b.dataset.host });
    const r = event.target.closest('.egress-resolve');
    if (r) change(`/api/egress/${r.dataset.op}`, { id: r.dataset.id });
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

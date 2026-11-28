const securityMarkers = document.querySelector('#security-markers');
const securityProcess = document.querySelector('#security-process');
const securityDetail = document.querySelector('#security-detail');
let inspectedPid = '';
const securityEsc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function renderSecurityMarkers() {
  if (!securityMarkers) return;
  const all = (markers || []).map((m, i) => [m, i]);
  const items = all.filter(([m]) => !isRoutine(m));
  const routineCount = all.length - items.length;
  const routineNote = routineCount ? `<p class="security-routine">${routineCount} routine ${routineCount === 1 ? 'event' : 'events'} from macOS system services are folded on the Map tab.</p>` : '';
  if (!items.length) {
    const learning = Date.now() < (learningUntil || 0);
    securityMarkers.innerHTML = `${aiToolbar()}<div class="security-quiet"><span>NO CURRENT MARKERS</span><p>${learning ? 'The local baseline is still learning this Mac’s usual network activity.' : 'No attention markers are active. That is not a certificate that every connection is safe.'}</p></div>${routineNote}`;
    return;
  }
  securityMarkers.innerHTML = aiToolbar() + items.slice(0, 12).map(([m, i]) => `<article class="security-marker" data-index="${i}" data-sev="${securityEsc(sevOf(m))}"><div><span>${securityEsc(KIND_LABEL[m.kind] || m.kind)} · ${securityEsc(SEV_LABEL[sevOf(m)])}</span><small>${securityEsc(new Date(m.at).toLocaleString([], {month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'}))}</small></div><p>${securityEsc(m.text)}</p>${m.reason ? `<p class="security-reason">${securityEsc(m.reason)}</p>` : ''}${aiNote(m)}<div class="security-marker-actions"><button type="button" data-action="map">Show on Map</button><button type="button" data-action="accept">Looks normal</button></div></article>`).join('') + routineNote;
}

function renderSecurityProcesses() {
  if (!securityProcess) return;
  const rows = [...new Map((activeRows || []).filter((r) => r.pid).map((r) => [String(r.pid), r])).values()]
    .sort((a,b) => String(a.process).localeCompare(String(b.process)) || Number(a.pid)-Number(b.pid));
  const keep = rows.some((r) => String(r.pid) === securityProcess.value) ? securityProcess.value : '';
  securityProcess.innerHTML = rows.length ? `<option value="">Choose a connected process</option>${rows.map((r) => `<option value="${securityEsc(r.pid)}" ${String(r.pid)===keep?'selected':''}>${securityEsc(r.process)} · PID ${securityEsc(r.pid)} · ${securityEsc(r.protocol||'network')} · ${securityEsc(r.remote)}</option>`).join('')}` : '<option value="">No live network processes</option>';
}

async function inspectSecurityProcess(pid) {
  if (!pid) return;
  inspectedPid = String(pid);
  securityDetail.innerHTML = '<div class="loading-state">Reading local process facts…</div>';
  try {
    const response = await fetch(`/api/process?pid=${encodeURIComponent(pid)}`, {cache:'no-store'});
    const facts = await response.json();
    if (!response.ok) throw new Error(facts.error || 'Process not found.');
    const liveSockets = (activeRows || []).filter((r) => String(r.pid) === String(pid));
    securityDetail.innerHTML = `<div class="security-facts"><div class="security-executable"><span>EXECUTABLE</span><strong>${securityEsc(facts.command)}</strong></div><div><span>PID / parent</span><strong>${securityEsc(facts.pid)} / ${securityEsc(facts.ppid)}</strong></div><div><span>Account</span><strong>${securityEsc(facts.user)}</strong></div><div><span>Started</span><strong>${securityEsc(facts.started || 'Unknown')}</strong></div><div><span>Code signature</span><strong>${securityEsc(facts.signature || 'Unknown')}</strong></div><div><span>Working folder</span><strong>${securityEsc(facts.cwd || 'Not visible')}</strong></div><div class="security-executable"><span>Parent chain</span><strong>${securityEsc((facts.parents||[]).map((p)=>`${p.command} (${p.pid})`).join(' ← ') || 'No parent details available')}</strong></div><div class="security-executable"><span>Live socket endpoints</span><strong>${liveSockets.length ? liveSockets.map((r)=>`${r.protocol} ${r.local} → ${r.remote} · ${r.state}`).map(securityEsc).join('<br>') : 'No longer present in the latest connection snapshot.'}</strong></div><div class="security-trust security-executable" id="security-trust"><span>TRUST CARD</span><strong>Reading signature and Gatekeeper facts…</strong></div><div class="security-risk-note"><b>How to read this</b><p>A signature, parent and folder are clues to verify together. “Unsigned” or “unknown” alone does not prove a process is harmful.</p></div><div class="security-actions"><span>State</span><strong>${facts.paused ? 'Paused (SIGSTOP)' : 'Running'}</strong></div><button class="security-stop" data-act="stop" data-pid="${securityEsc(pid)}" type="button">Stop process (SIGTERM)</button><button class="security-stop" data-act="tree" data-pid="${securityEsc(pid)}" type="button">Preview and stop tree</button><button class="security-stop" data-act="${facts.paused ? 'resume' : 'pause'}" data-pid="${securityEsc(pid)}" type="button">${facts.paused ? 'Resume (SIGCONT)' : 'Pause (SIGSTOP)'}</button>${facts.launchd?.managed ? `<button class="security-stop" data-act="restart" data-pid="${securityEsc(pid)}" type="button">Restart launchd job</button>` : ''}<small class="security-stop-note">Restart: ${securityEsc(facts.launchd?.managed ? `launchd job ${facts.launchd.label}` : `unavailable. ${facts.launchd?.reason || ''}`)} These actions do not block or isolate network access.</small></div>`;
    loadTrustCard(pid, liveSockets[0]?.process || '');
  } catch (error) {
    securityDetail.innerHTML = `<p class="error-state">${securityEsc(error.message)}</p>`;
  }
}

async function loadTrustCard(pid, app) {
  const box = document.querySelector('#security-trust');
  if (!box) return;
  try {
    const response = await fetch(`/api/process/trust?pid=${encodeURIComponent(pid)}&app=${encodeURIComponent(app)}`, {cache:'no-store'});
    const t = await response.json();
    if (!response.ok) throw new Error(t.error || 'Trust facts unavailable.');
    if (String(pid) !== inspectedPid) return;
    const row = (k, v) => `<div><span>${securityEsc(k)}</span><strong>${securityEsc(v)}</strong></div>`;
    box.innerHTML = `<span>TRUST CARD</span><div class="security-trust-grid">${row('Binary', t.path)}${row('Code signature', t.signature)}${row('Signing authority', t.authority.join(' > ') || 'None reported')}${row('Team ID', t.teamId || 'None')}${row('Gatekeeper (execute)', `${t.gatekeeper}${t.gatekeeperSource ? ` · ${t.gatekeeperSource}` : ''}`)}${row('Notarized', t.notarized)}${row('First seen here', t.firstSeen ? new Date(t.firstSeen).toLocaleString() : 'Not in local history yet')}</div>${t.notes.length ? `<ul class="security-trust-notes">${t.notes.map((n) => `<li>${securityEsc(n)}</li>`).join('')}</ul>` : ''}<small>These are facts reported by codesign and spctl. They do not say whether the program is safe or harmful.</small>`;
  } catch (error) {
    box.innerHTML = `<span>TRUST CARD</span><strong>${securityEsc(error.message)}</strong>`;
  }
}

securityProcess.addEventListener('change', () => inspectSecurityProcess(securityProcess.value));
document.querySelector('#security-inspect').addEventListener('click', () => inspectSecurityProcess(securityProcess.value));
securityMarkers.addEventListener('click', async (event) => {
  const card = event.target.closest('.security-marker');
  if (!card) return;
  const marker = markers[Number(card.dataset.index)];
  if (!marker) return;
  const action = event.target.dataset.action;
  if (action === 'accept') {
    await fetch('/api/markers/accept', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key:marker.key})});
    await loadMarkers();
    return;
  }
  if (action === 'map') {
    document.querySelector('.nav-item[href="#map"]').click();
    setTimeout(() => {
      const found = marker.ip && mapModel.dests.includes(marker.ip);
      selectOnMap(found ? {app:marker.app,ip:marker.ip} : {app:marker.app});
      mapDetail.insertAdjacentHTML('afterbegin', `<p class="attention-why"><b>${securityEsc(KIND_LABEL[marker.kind] || marker.kind)}:</b> ${securityEsc(marker.text)}${found?'':' The exact destination is not open now.'}</p>`);
      mapDetail.scrollIntoView({block:'nearest',behavior:'smooth'});
    }, 0);
  }
});
async function processAction(act, pid) {
  const facts = await fetch(`/api/process?pid=${pid}`, {cache:'no-store'}).then((r)=>r.json());
  if (!facts || facts.error) throw new Error('That process is no longer running.');
  const name = facts.command.split(' ')[0];
  const gui = /\.app\/Contents\/MacOS\//.test(facts.command);
  const body = {pid, confirm:true};
  let question;
  if (act === 'stop') question = `Send SIGTERM to ${name} (PID ${pid})? It may close unsaved work. This will not block network access.`;
  if (act === 'pause') question = `Pause ${name} (PID ${pid}) with SIGSTOP? It stays in memory and can be resumed.${gui ? ' This is a GUI app: its windows will freeze and macOS may show it as not responding until you resume it.' : ''}`;
  if (act === 'resume') question = `Resume ${name} (PID ${pid}) with SIGCONT?`;
  if (act === 'restart') question = `Restart launchd job ${facts.launchd?.label} (PID ${pid}) with launchctl kickstart -k? The running instance is killed and launchd starts a new one.`;
  if (act === 'tree') {
    const preview = await fetch(`/api/process/tree?pid=${pid}`, {cache:'no-store'}).then((r)=>r.json());
    if (preview.error) throw new Error(preview.error);
    if (preview.refused.length) throw new Error(`Tree stop unavailable: ${preview.refused.length} child process(es) belong to another account or the monitor.`);
    const list = preview.children.map((c)=>`  ${c.pid}  ${c.command.slice(0,80)}`).join('\n') || '  (no child processes)';
    question = `Send SIGTERM to ${name} (PID ${pid}) and ${preview.children.length} child process(es)? Children are signalled first.\n${list}`;
    body.tree = true;
    body.children = preview.children.map((c)=>c.pid);
  }
  if (!window.confirm(question)) return null;
  const response = await fetch(`/api/process/${act === 'tree' ? 'stop' : act}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'The action failed.');
  return result;
}

securityDetail.addEventListener('click', async (event) => {
  const button = event.target.closest('[data-act]');
  if (!button) return;
  const pid = Number(button.dataset.pid);
  button.disabled = true;
  try {
    const result = await processAction(button.dataset.act, pid);
    if (!result) { button.disabled = false; return; }
    const what = result.status === 'kickstarted' ? `launchd restarted ${result.label}` : `${result.signal} sent to ${(result.pids || [pid]).length} process(es)`;
    button.insertAdjacentHTML('afterend',`<p class="security-stop-note">${securityEsc(what)}. Inspect again to see the current state.</p>`);
  } catch (error) {
    button.disabled = false;
    button.insertAdjacentHTML('afterend',`<p class="error-state">${securityEsc(error.message)}</p>`);
  }
});
document.querySelector('.nav-item[href="#security"]').addEventListener('click', () => { renderSecurityProcesses(); renderSecurityMarkers(); });
window.addEventListener('markers-updated', renderSecurityMarkers);
setInterval(renderSecurityProcesses, 3000);
renderSecurityProcesses();
renderSecurityMarkers();

(() => {
  const list = document.getElementById('persistence-list');
  const note = document.getElementById('persistence-note');
  const cell = (text) => { const td = document.createElement('td'); td.textContent = text; return td; };
  async function load() {
    list.replaceChildren();
    try {
      const data = await (await fetch('/api/persistence', { cache: 'no-store' })).json();
      for (const item of data.items) {
        const tr = document.createElement('tr');
        tr.title = item.file;
        tr.append(cell(item.label), cell(item.apple ? `${item.scope} (Apple)` : item.scope), cell([item.program, ...item.arguments.slice(1)].join(' ')), cell(item.runAtLoad ? 'yes' : 'no'), cell(typeof item.keepAlive === 'object' ? 'conditional' : item.keepAlive ? 'yes' : 'no'), cell(item.network ? `${item.network.process} (PID ${item.network.pid}, ${item.network.matchedBy})` : item.running ? `running, PID ${item.pid}` : ''));
        list.append(tr);
      }
      const networked = data.items.filter((i) => i.network).length;
      note.textContent = `${data.items.length} entries, ${networked} tied to a networked process.${data.unreadable.length ? ` ${data.unreadable.length} could not be parsed.` : ''} Apple system entries are listed only when they match a networked process.`;
    } catch { note.textContent = 'Persistence data is unavailable.'; }
  }
  document.getElementById('persistence-refresh').addEventListener('click', load);
  window.addEventListener('hashchange', () => { if (location.hash === '#persistence') load(); });
  if (location.hash === '#persistence') load();
})();

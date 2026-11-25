const consoleForm = document.querySelector('#console-form');
const consoleInput = document.querySelector('#console-input');
const consoleOutput = document.querySelector('#console-output');
const capConsole = document.querySelector('#cap-start');
const consoleEsc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function consolePrint(message, kind='result') {
  const line = document.createElement('div');
  line.className = `console-line ${kind}`;
  line.innerHTML = `<span class="console-prompt">${kind==='command'?'›':'·'}</span><pre>${consoleEsc(message)}</pre>`;
  consoleOutput.append(line);
  consoleOutput.scrollTop = consoleOutput.scrollHeight;
}

async function consoleRun(raw) {
  const input = raw.trim();
  if (!input) return;
  consolePrint(input, 'command');
  const [verb, ...args] = input.split(/\s+/);
  const arg = args.join(' ');
  try {
    if (verb === 'help') {
      consolePrint('Guided commands\n  connections [text]   list live paths, optionally filtered\n  process <pid>         inspect a process, parents, signature and sockets\n  capture [5|10|30]     start a temporary TShark header capture\n  packets              open the packet table for detailed inspection\n  models               show local Ollama models\n  ask <question>        ask the configured local model\n  stop <pid>            send SIGTERM after an explicit confirmation\n  tree <pid>            preview child processes, then SIGTERM children and parent\n  pause <pid>           send SIGSTOP (reversible) after confirmation\n  resume <pid>          send SIGCONT to a paused process\n  restart <pid>         launchctl kickstart -k, only for launchd jobs in your user domain\n\nThis is a guided investigation console, not a general-purpose shell.');
      return;
    }
    if (verb === 'connections') {
      const rows = (activeRows || []).filter((row) => !arg || `${row.process} ${row.pid} ${row.remote} ${row.protocol}`.toLowerCase().includes(arg.toLowerCase()));
      consolePrint(rows.length ? rows.slice(0,60).map((row) => `${row.process}  pid ${row.pid}  ${row.protocol||'network'}  ${row.local} → ${row.remote}  ${row.state||''}`).join('\n') : 'No live connections match that filter.');
      return;
    }
    if (['process', 'stop', 'tree', 'pause', 'resume', 'restart'].includes(verb)) {
      const pid = Number(args[0]);
      if (!Number.isSafeInteger(pid) || pid < 2) { consolePrint(`Usage: ${verb} <pid>`, 'error'); return; }
      const response = await fetch(`/api/process?pid=${pid}`, {cache:'no-store'});
      const facts = await response.json();
      if (!response.ok) throw new Error(facts.error || 'Process not found.');
      if (verb === 'process') {
        consolePrint([`${facts.command}`, `PID ${facts.pid} · parent ${facts.ppid} · user ${facts.user} · ${facts.paused ? 'paused' : 'running'}`, `Started ${facts.started || 'unknown'}`, `Signature ${facts.signature || 'unknown'}`, `Folder ${facts.cwd || 'not visible'}`, `Restart: ${facts.launchd?.managed ? `launchd job ${facts.launchd.label}` : `unavailable. ${facts.launchd?.reason || ''}`}`, `Parents: ${(facts.parents||[]).map((p)=>`${p.command} (${p.pid})`).join(' ← ') || 'none reported'}`, `Sockets:\n${(facts.sockets||[]).join('\n') || 'none visible'}`].join('\n'));
        return;
      }
      if (verb === 'restart' && !facts.launchd?.managed) { consolePrint(`Restart unavailable: ${facts.launchd?.reason || 'not a launchd job.'}`); return; }
      const result = await processAction(verb, pid);
      if (!result) { consolePrint(`Request cancelled for PID ${pid}.`); return; }
      consolePrint(result.status === 'kickstarted' ? `launchd restarted ${result.label}. Recheck the process list for the new PID.` : `${result.signal} sent to ${(result.pids || [pid]).join(', ')}. Recheck the process list to confirm the state.`);
      return;
    }
    if (verb === 'capture') {
      const seconds = args[0] ? Number(args[0]) : 10;
      if (![5,10,30].includes(seconds)) throw new Error('Use capture 5, capture 10, or capture 30.');
      document.querySelector('#cap-dur').value = String(seconds);
      consolePrint(`Opening the existing TShark confirmation for a ${seconds}-second capture. Captured headers remain in memory.`);
      capConsole.click();
      return;
    }
    if (verb === 'packets') {
      document.querySelector('.nav-item[href="#capture"]').click();
      consolePrint('Packet table opened. Select a row to inspect its fields; apply a display filter in the capture view.');
      return;
    }
    if (verb === 'models') {
      const response = await fetch('/api/models',{cache:'no-store'});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Local models are unavailable.');
      consolePrint(`Ollama on this Mac\nSelected model: ${data.defaultModel}\nInstalled models:\n${(data.models||[]).join('\n') || 'No models found'}`);
      return;
    }
    if (verb === 'ask') {
      if (!arg) throw new Error('Usage: ask <network question>');
      const chosen = typeof selectedFlightKey !== 'undefined' ? (activeRows || []).find((row) => [row.pid,row.protocol,row.local,row.remote].join('|') === selectedFlightKey) : null;
      const context = chosen ? { process:chosen.process, pid:chosen.pid, protocol:chosen.protocol, local:chosen.local, remote:chosen.remote, state:chosen.state } : {};
      const response = await fetch('/api/ask',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({question:arg,context})});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Local model request failed.');
      consolePrint(`${data.text}\n\nLocal model: ${data.model}`);
      return;
    }
    consolePrint(`Unknown command: ${verb}. Type help to see the guided commands.`, 'error');
  } catch (error) {
    consolePrint(error.message || 'The operation could not be completed.', 'error');
  }
}

consoleForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const value = consoleInput.value;
  consoleInput.value = '';
  await consoleRun(value);
});
document.querySelectorAll('.console-shortcuts button').forEach((button) => button.addEventListener('click', () => {
  const command = button.dataset.command;
  consoleInput.value = '';
  consoleRun(command);
}));

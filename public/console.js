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
      consolePrint('Guided commands\n  connections [text]   list live paths, optionally filtered\n  process <pid>         inspect a process, parents, signature and sockets\n  capture [5|10|30]     start a temporary TShark header capture\n  packets              open the packet table for detailed inspection\n  models               show local Ollama models\n  ask <question>        ask the configured local model\n  stop <pid>            send SIGTERM after an explicit confirmation\n  restart <pid>         not available yet; app relaunch needs a verified bundle mapping\n\nThis is a guided investigation console, not a general-purpose shell.');
      return;
    }
    if (verb === 'connections') {
      const rows = (activeRows || []).filter((row) => !arg || `${row.process} ${row.pid} ${row.remote} ${row.protocol}`.toLowerCase().includes(arg.toLowerCase()));
      consolePrint(rows.length ? rows.slice(0,60).map((row) => `${row.process}  pid ${row.pid}  ${row.protocol||'network'}  ${row.local} → ${row.remote}  ${row.state||''}`).join('\n') : 'No live connections match that filter.');
      return;
    }
    if (verb === 'process' || verb === 'stop' || verb === 'restart') {
      if (verb === 'restart') { consolePrint('Restart is not enabled yet. The monitor needs a verified app or service launcher for each process before it can safely relaunch one.'); return; }
      const pid = Number(args[0]);
      if (!Number.isSafeInteger(pid) || pid < 2) { consolePrint(`Usage: ${verb} <pid>`, 'error'); return; }
      const response = await fetch(`/api/process?pid=${pid}`, {cache:'no-store'});
      const facts = await response.json();
      if (!response.ok) throw new Error(facts.error || 'Process not found.');
      if (verb === 'process') {
        consolePrint([`${facts.command}`, `PID ${facts.pid} · parent ${facts.ppid} · user ${facts.user}`, `Started ${facts.started || 'unknown'}`, `Signature ${facts.signature || 'unknown'}`, `Folder ${facts.cwd || 'not visible'}`, `Parents: ${(facts.parents||[]).map((p)=>`${p.command} (${p.pid})`).join(' ← ') || 'none reported'}`, `Sockets:\n${(facts.sockets||[]).join('\n') || 'none visible'}`].join('\n'));
        return;
      }
      const accepted = window.confirm(`Send SIGTERM to ${facts.command.split(' ')[0]} (PID ${pid})? The process may close unsaved work. This does not block its network access.`);
      if (!accepted) { consolePrint(`Stopped request cancelled for PID ${pid}.`); return; }
      const stopped = await fetch('/api/process/stop', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({pid,confirm:true})});
      const result = await stopped.json().catch(()=>({}));
      if (!stopped.ok) throw new Error(result.error || 'The process could not be stopped.');
      consolePrint(`SIGTERM sent to ${result.process} (PID ${pid}). Recheck the process list to confirm it exited.`);
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

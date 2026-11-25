import { execFile } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

// Read-only: plists are only parsed, never loaded, unloaded or written.
const exec = promisify(execFile);

function scanDirs() {
  const override = process.env.LOCAL_WATCH_PERSISTENCE_DIRS;
  if (override) return override.split(':').filter(Boolean).map((dir) => ({ dir, scope: 'custom', apple: false }));
  return [
    { dir: join(homedir(), 'Library/LaunchAgents'), scope: 'user agent', apple: false },
    { dir: '/Library/LaunchAgents', scope: 'global agent', apple: false },
    { dir: '/Library/LaunchDaemons', scope: 'global daemon', apple: false },
    { dir: '/System/Library/LaunchAgents', scope: 'system agent', apple: true },
    { dir: '/System/Library/LaunchDaemons', scope: 'system daemon', apple: true },
  ];
}

async function parsePlist(file) {
  const { stdout } = await exec('/usr/bin/plutil', ['-convert', 'json', '-o', '-', file], { timeout: 3000, maxBuffer: 1024 * 1024 });
  return JSON.parse(stdout);
}

async function runningLabels() {
  const labels = new Map();
  try {
    const { stdout } = await exec('/bin/launchctl', ['list'], { timeout: 3000, maxBuffer: 2 * 1024 * 1024 });
    for (const line of stdout.split('\n').slice(1)) {
      const [pid, , label] = line.split('\t');
      if (label && /^\d+$/.test(pid)) labels.set(label, Number(pid));
    }
  } catch {}
  return labels;
}

async function executablePaths(pids) {
  const paths = new Map();
  if (!pids.length) return paths;
  try {
    const { stdout } = await exec('/bin/ps', ['-o', 'pid=,comm=', '-p', pids.join(',')], { timeout: 3000 });
    for (const line of stdout.split('\n')) {
      const m = line.match(/^\s*(\d+)\s+(.+)$/);
      if (m) paths.set(Number(m[1]), m[2].trim());
    }
  } catch {}
  return paths;
}

export async function persistenceItems(connections = []) {
  const pidProcess = new Map();
  for (const c of connections) if (c.pid) pidProcess.set(Number(c.pid), c.process);
  const [labels, paths] = await Promise.all([runningLabels(), executablePaths([...pidProcess.keys()])]);
  const pathToPid = new Map([...paths].map(([pid, path]) => [path, pid]));
  const items = [];
  const errors = [];
  for (const { dir, scope, apple } of scanDirs()) {
    let names;
    try { names = (await readdir(dir)).filter((n) => n.endsWith('.plist')); } catch { continue; }
    // System folders hold hundreds of entries; only keep those tied to a networked process.
    for (const name of names.sort()) {
      const file = join(dir, name);
      let plist;
      try { plist = await parsePlist(file); } catch { errors.push(file); continue; }
      const args = Array.isArray(plist.ProgramArguments) ? plist.ProgramArguments.map(String) : [];
      const program = typeof plist.Program === 'string' ? plist.Program : args[0] || '';
      const label = typeof plist.Label === 'string' ? plist.Label : name.replace(/\.plist$/, '');
      const launchPid = labels.get(label) ?? null;
      let networkPid = null;
      let matchedBy = null;
      if (launchPid && pidProcess.has(launchPid)) { networkPid = launchPid; matchedBy = 'launchctl pid'; }
      else if (program && pathToPid.has(program)) { networkPid = pathToPid.get(program); matchedBy = 'executable path'; }
      if (apple && !networkPid) continue;
      items.push({
        file, scope, apple, label, program, arguments: args,
        runAtLoad: plist.RunAtLoad === true,
        keepAlive: plist.KeepAlive === undefined ? false : plist.KeepAlive,
        disabled: plist.Disabled === true,
        running: launchPid !== null, pid: launchPid,
        network: networkPid ? { pid: networkPid, process: pidProcess.get(networkPid) || '', matchedBy } : null,
      });
    }
  }
  items.sort((a, b) => (b.network ? 1 : 0) - (a.network ? 1 : 0) || a.label.localeCompare(b.label));
  return { sampledAt: new Date().toISOString(), items, unreadable: errors };
}

import { execFile } from 'node:child_process';
import { appendFile, chmod, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const DIR = process.env.LOCAL_WATCH_DATA || join(homedir(), 'Library', 'Application Support', 'LocalWatch');
export const ACTION_LOG = join(DIR, 'actions.log');

// Append-only JSON lines; one entry per attempted action, including refusals.
export async function logAction(entry) {
  try {
    await mkdir(DIR, { recursive: true, mode: 0o700 });
    await appendFile(ACTION_LOG, `${JSON.stringify({ at: new Date().toISOString(), ...entry })}\n`, { mode: 0o600, flag: 'a' });
    await chmod(ACTION_LOG, 0o600);
  } catch { /* logging must not mask the action result */ }
}

let me = '';
async function currentUser() {
  if (!me) me = (await exec('/usr/bin/id', ['-un'])).stdout.trim();
  return me;
}

async function protectedPids() {
  const set = new Set([1, process.pid]);
  let ancestor = process.ppid;
  for (let i = 0; i < 16 && ancestor > 1; i++) {
    set.add(ancestor);
    const row = (await exec('/bin/ps', ['-o', 'ppid=', '-p', String(ancestor)])).stdout.trim();
    ancestor = Number(row) || 0;
  }
  return set;
}

export async function processTable() {
  const { stdout } = await exec('/bin/ps', ['-axww', '-o', 'pid=,ppid=,user=,stat=,command='], { maxBuffer: 8 * 1024 * 1024 });
  return stdout.split('\n').map((l) => l.match(/^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)$/)).filter(Boolean)
    .map((m) => ({ pid: Number(m[1]), ppid: Number(m[2]), user: m[3], stat: m[4], command: m[5].slice(0, 300) }));
}

// Same-user, not PID 1, not this server, not one of its ancestors.
export async function guard(pid, verb) {
  if (!Number.isSafeInteger(pid) || pid < 2) throw new Error('A valid process ID is required.');
  const rows = await processTable();
  const row = rows.find((r) => r.pid === pid);
  if (!row) throw new Error('That process is no longer running.');
  if ((await protectedPids()).has(pid)) throw new Error(`The monitor or one of its parent processes cannot be ${verb} here.`);
  if (row.user !== await currentUser()) throw new Error(`Only processes owned by your current macOS account can be ${verb}.`);
  return { row, rows };
}

// Descendants, deepest first, so children are signalled before their parents.
export function descendants(rows, pid) {
  const out = [];
  const walk = (p, depth) => {
    for (const r of rows.filter((x) => x.ppid === p)) { walk(r.pid, depth + 1); out.push({ ...r, depth }); }
  };
  walk(pid, 1);
  return out.sort((a, b) => b.depth - a.depth);
}

export async function treePreview(pid) {
  const { row, rows } = await guard(pid, 'stopped');
  const children = descendants(rows, pid);
  const user = await currentUser();
  const blocked = await protectedPids();
  const refused = children.filter((c) => c.user !== user || blocked.has(c.pid));
  return { root: row, children, refused };
}

export const isPaused = (stat) => /^T/.test(stat || '');

export async function launchdLabel(pid) {
  const uid = (await exec('/usr/bin/id', ['-u'])).stdout.trim();
  const domain = `gui/${uid}`;
  let stdout = '';
  try { ({ stdout } = await exec('/bin/launchctl', ['print', domain], { maxBuffer: 8 * 1024 * 1024, timeout: 5000 })); } catch { return { managed: false, reason: 'launchctl print failed for your user domain.' }; }
  const block = stdout.match(/\n\tservices = \{\n([\s\S]*?)\n\t\}/)?.[1] || '';
  const hit = block.split('\n').map((l) => l.trim().split(/\s+/)).find((p) => Number(p[0]) === pid);
  if (!hit) return { managed: false, reason: 'This process is not a launchd service in your user domain, so it cannot be restarted safely.' };
  const label = hit[2];
  // LaunchServices app instances are not relaunchable through kickstart.
  if (label.startsWith('application.')) return { managed: false, label, reason: 'This is a GUI app instance registered by LaunchServices, not a launchd job with a relaunch definition.' };
  return { managed: true, label, domain, target: `${domain}/${label}` };
}

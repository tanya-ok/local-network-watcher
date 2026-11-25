import { execFile } from 'node:child_process';
import { realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, sep } from 'node:path';
import { promisify } from 'node:util';
import { logAction } from './process-control.js';

const exec = promisify(execFile);
const uid = process.getuid();
const domain = `gui/${uid}`;
const APP_DIR = new URL('.', import.meta.url).pathname;

// Only the user's own LaunchAgents are changed; system and global jobs need an administrator.
function allowedDirs() {
  const override = process.env.LOCAL_WATCH_PERSISTENCE_DIRS;
  return override ? override.split(':').filter(Boolean) : [join(homedir(), 'Library/LaunchAgents')];
}

export async function userDisabledLabels() {
  const out = new Set();
  try {
    const { stdout } = await exec('/bin/launchctl', ['print-disabled', domain], { timeout: 3000, maxBuffer: 1024 * 1024 });
    for (const m of stdout.matchAll(/"([^"]+)"\s*=>\s*(true|disabled)/g)) out.add(m[1]);
  } catch {}
  return out;
}

async function inspect(file) {
  const real = await realpath(String(file || ''));
  const dirs = await Promise.all(allowedDirs().map((d) => realpath(d).catch(() => null)));
  if (!real.endsWith('.plist') || !dirs.some((d) => d && real.startsWith(d + sep))) throw new Error('Only plists in your own LaunchAgents folder can be changed here.');
  const st = await stat(real);
  if (st.uid !== uid) throw new Error('This plist belongs to another account.');
  const { stdout } = await exec('/usr/bin/plutil', ['-convert', 'json', '-o', '-', real], { timeout: 3000, maxBuffer: 1024 * 1024 });
  const plist = JSON.parse(stdout);
  const label = typeof plist.Label === 'string' ? plist.Label : '';
  if (!label) throw new Error('The plist has no Label.');
  if (label.startsWith('com.apple.')) throw new Error('Apple jobs are not changed here.');
  const program = String(plist.Program || plist.ProgramArguments?.[0] || '');
  if (program.startsWith(APP_DIR)) throw new Error('This job runs Local Network Watcher itself.');
  return { file: real, label, program };
}

async function launchctl(args) {
  try { await exec('/bin/launchctl', args, { timeout: 8000 }); return ''; }
  catch (e) { return String(e.stderr || e.message).trim(); }
}

// stop: unload until next login. disable: unload and keep it off. enable: allow and load again.
export async function changeJob(action, file) {
  let job;
  try { job = await inspect(file); } catch (e) { await logAction({ action: `launchd-${action}`, file, result: 'refused', reason: e.message }); throw e; }
  const target = `${domain}/${job.label}`;
  const notes = [];
  if (action === 'stop' || action === 'disable') {
    const err = await launchctl(['bootout', domain, job.file]);
    if (err && !/No such process|Could not find|not find service/i.test(err)) notes.push(err);
    if (action === 'disable') { const e2 = await launchctl(['disable', target]); if (e2) notes.push(e2); }
  } else if (action === 'enable') {
    const e1 = await launchctl(['enable', target]); if (e1) notes.push(e1);
    const e2 = await launchctl(['bootstrap', domain, job.file]);
    if (e2 && !/already|Bootstrap failed: 5|service already loaded/i.test(e2)) notes.push(e2);
  } else throw new Error('Unknown action.');
  const result = notes.length ? 'partial' : 'ok';
  await logAction({ action: `launchd-${action}`, label: job.label, file: job.file, result, notes });
  return { action, label: job.label, result, notes };
}

import { execFile } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const cache = new Map();

async function run(cmd, args) {
  try {
    const r = await exec(cmd, args, { timeout: 8000, maxBuffer: 1024 * 1024 });
    return { code: 0, out: `${r.stdout}${r.stderr}` };
  } catch (e) {
    return { code: typeof e.code === 'number' ? e.code : -1, out: `${e.stdout || ''}${e.stderr || ''}`, timedOut: e.killed === true };
  }
}

// Executable path of a running process, from the kernel's view (not argv).
export async function exePath(pid) {
  const { out } = await run('/bin/ps', ['-ww', '-o', 'comm=', '-p', String(pid)]);
  const p = out.trim();
  if (!p.startsWith('/')) return p || null;
  try { return await realpath(p); } catch { return p; }
}

function locationNotes(path, signature) {
  const notes = [];
  const home = homedir();
  if (/^\/(private\/)?tmp\//.test(path)) notes.push('Runs from /tmp, a temporary folder. Installed apps rarely live there.');
  if (/^\/(private\/)?var\/folders\//.test(path)) notes.push('Runs from /private/var/folders, a per-user temporary area. Some installers and updaters use it.');
  if (path.startsWith(`${home}/Downloads/`)) notes.push('Runs from ~/Downloads. It may not have been moved to Applications yet.');
  if (signature === 'not signed') notes.push('No code signature was found. Self-built tools and scripts are often unsigned.');
  if (signature.startsWith('ad hoc')) notes.push('Ad hoc signature only, with no developer identity. Common for Homebrew and self-built tools.');
  return notes;
}

export async function trustFacts(path) {
  if (cache.has(path)) return cache.get(path);
  const sig = await run('/usr/bin/codesign', ['-dv', '--verbose=2', path]);
  const authority = [...sig.out.matchAll(/^Authority=(.+)$/gm)].map((m) => m[1]);
  const team = sig.out.match(/^TeamIdentifier=(.+)$/m)?.[1];
  const identifier = sig.out.match(/^Identifier=(.+)$/m)?.[1] || '';
  let signature;
  if (/not signed at all/i.test(sig.out)) signature = 'not signed';
  else if (/Signature=adhoc/.test(sig.out)) signature = 'ad hoc (no developer identity)';
  else if (authority.length) signature = 'signed';
  else signature = sig.timedOut ? 'check timed out' : 'unknown';

  const gk = await run('/usr/sbin/spctl', ['--assess', '--type', 'execute', '-vv', path]);
  const source = gk.out.match(/^source=(.+)$/m)?.[1] || '';
  let gatekeeper;
  if (gk.timedOut) gatekeeper = 'check timed out';
  else if (gk.code === 0) gatekeeper = 'accepted';
  else if (/rejected/.test(gk.out)) gatekeeper = `not accepted${gk.out.match(/rejected \(([^)]+)\)/) ? ` (${gk.out.match(/rejected \(([^)]+)\)/)[1]})` : ''}`;
  else gatekeeper = 'not assessed';
  const notarized = /Notarized/i.test(source) ? 'yes' : (source === 'Apple System' || authority[0] === 'Software Signing' || authority[0] === 'macOS Software Signing') ? 'not applicable (part of macOS)' : 'not shown';

  const facts = {
    path, identifier, signature, authority,
    teamId: team && team !== 'not set' ? team : '',
    gatekeeper, gatekeeperSource: source, notarized,
    notes: locationNotes(path, signature),
    checkedAt: Date.now(),
  };
  cache.set(path, facts);
  return facts;
}

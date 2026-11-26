import { BlockList, isIP } from 'node:net';
import { homedir } from 'node:os';

// First-party ranges only. Cloud and CDN ranges are left out: they host many unrelated customers.
const OWNERS = {
  Apple: ['17.0.0.0/8', '2620:149::/32', '2a01:b740::/32'],
  Google: [
    '8.8.4.0/24', '8.8.8.0/24', '64.233.160.0/19', '66.102.0.0/20', '66.249.64.0/19', '72.14.192.0/18',
    '74.125.0.0/16', '108.177.0.0/17', '142.250.0.0/15', '172.217.0.0/16', '172.253.0.0/16', '173.194.0.0/16',
    '209.85.128.0/17', '216.58.192.0/19', '216.239.32.0/19',
    '2001:4860::/32', '2404:6800::/32', '2607:f8b0::/32', '2800:3f0::/32', '2a00:1450::/32',
  ],
};

const lists = Object.entries(OWNERS).map(([org, cidrs]) => {
  const list = new BlockList();
  for (const cidr of cidrs) {
    const [addr, bits] = cidr.split('/');
    list.addSubnet(addr, Number(bits), addr.includes(':') ? 'ipv6' : 'ipv4');
  }
  return [org, list];
});

export function knownOwner(address) {
  let ip = String(address || '');
  if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(ip)) ip = ip.slice(7);
  const v = isIP(ip);
  if (!v) return '';
  for (const [org, list] of lists) if (list.check(ip, v === 6 ? 'ipv6' : 'ipv4')) return org;
  return '';
}

// macOS services that sync accounts the user added in Internet Accounts.
export const ACCOUNT_SYNC = new Set(['accountsd', 'AddressBookSourceSync', 'CalendarAgent', 'dataaccessd', 'remindd', 'Mail']);
// macOS services that download from CDNs, often from caches inside the user's internet provider.
export const DOWNLOADERS = new Set(['nsurlsessiond', 'softwareupdated', 'mobileassetd', 'appstoreagent', 'storedownloadd']);

const SIP_PATH = /^\/(System|usr\/(libexec|sbin|bin)|sbin|bin)\//;
const APPLE_LEAF = new Set(['Software Signing', 'macOS Software Signing']);
const TEMP_PATH =/^\/(private\/)?(tmp|var\/folders)\//;

// Trust comes from the executable path and signature, never from the process name.
export function tierOf(facts) {
  const path = facts?.path || '';
  if (!path.startsWith('/')) return 'unknown';
  const chain = facts.authority || [];
  if (SIP_PATH.test(path) && APPLE_LEAF.has(chain[0]) && chain.at(-1) === 'Apple Root CA') return 'apple-system';
  if (facts.signature === 'not signed') return 'unsigned';
  if (String(facts.signature).startsWith('ad hoc')) return 'adhoc';
  if (TEMP_PATH.test(path) || path.startsWith(`${homedir()}/Downloads/`)) return 'temp-location';
  if (facts.gatekeeper === 'accepted') return 'signed';
  return 'unknown';
}

const TIER_REASON = {
  'apple-system': 'macOS system service: Apple signature, protected system folder.',
  signed: 'Signed by an identified developer and accepted by Gatekeeper.',
  unsigned: 'No code signature.',
  adhoc: 'Ad hoc signature with no developer identity.',
  'temp-location': 'Runs from a temporary or Downloads folder.',
  unknown: 'Signature and folder could not be read for this process.',
};

// Returns [severity, reason]. Severity is info, notice or attention.
export function severityFor(kind, tier, appName, owner) {
  const base = TIER_REASON[tier] || TIER_REASON.unknown;
  if (tier === 'apple-system') {
    if (kind === 'new-app' || kind === 'night') return ['info', base];
    if (kind === 'new-destination') {
      if (owner === 'Apple') return ['info', `${base} The destination belongs to Apple.`];
      if (ACCOUNT_SYNC.has(appName)) return ['info', `${base} It syncs accounts added in Internet Accounts${owner ? `; this one is ${owner}` : ''}.`];
      if (DOWNLOADERS.has(appName)) return ['info', `${base} Download services often use CDN caches, including ones at the internet provider.`];
    }
    return ['notice', base];
  }
  if (tier === 'signed') return [kind === 'unusual-port' ? 'attention' : 'notice', base];
  if (tier === 'unknown') return [kind === 'unusual-port' || kind === 'volume' ? 'attention' : 'notice', base];
  return ['attention', base];
}

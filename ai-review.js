// Asks the local model to sort attention markers into normal and suspicious. Nothing leaves this Mac.
const OLLAMA_URL = 'http://127.0.0.1:11434/api/chat';
// The model may clear a marker only for these tiers; unsigned, ad hoc and temp-folder apps always stay for a human.
const CLEARABLE_TIERS = new Set(['apple-system', 'signed', 'unknown']);

const SYSTEM = `You review network attention markers from a personal Mac for its owner.
Each marker has an id, the app, its trust tier (from code signature and folder), the kind of event, the destination and a reason.
For each marker decide:
- "normal": a well-known, expected pattern for this app and destination (for example a browser or system service reaching its vendor or a CDN).
- "suspicious": anything you cannot explain from the facts, unusual ports for the app, unknown destinations for a background tool, large uploads, or weak trust.
When unsure, answer "suspicious". Never invent facts.
Reply with JSON only: {"reviews":[{"id":"...","verdict":"normal"|"suspicious","reason":"one short plain English sentence, no long dashes"}]}`;

export function clearable(marker) {
  return CLEARABLE_TIERS.has(marker.tier || 'unknown');
}

export async function reviewMarkers(markers, { model, names = new Map() }) {
  const items = markers.slice(0, 20).map((m) => ({
    id: m.key, app: m.app, tier: m.tier || 'unknown', kind: m.kind, severity: m.severity,
    destination: m.dest || '', ip: m.ip || '', reverseDns: (m.ip && names.get(m.ip)) || '', event: m.text, reason: m.reason || '',
  }));
  if (!items.length) return [];
  const res = await fetch(OLLAMA_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    signal: AbortSignal.timeout(240000),
    body: JSON.stringify({
      model, stream: false, think: false, format: 'json',
      options: { temperature: 0.1, num_predict: 120 * items.length + 200 },
      messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: JSON.stringify({ markers: items }) }],
    }),
  });
  if (!res.ok) throw new Error(`Local model returned ${res.status}.`);
  const data = await res.json();
  let parsed;
  try { parsed = JSON.parse(data.message?.content || '{}'); } catch { throw new Error('The local model did not return valid JSON.'); }
  const ids = new Set(items.map((i) => i.id));
  return (Array.isArray(parsed.reviews) ? parsed.reviews : [])
    .filter((r) => r && ids.has(r.id) && (r.verdict === 'normal' || r.verdict === 'suspicious'))
    .map((r) => ({ id: r.id, verdict: r.verdict, reason: String(r.reason || '').replace(/[–—]/g, '-').slice(0, 300) }));
}

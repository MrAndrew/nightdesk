// Shared vocabulary for the Entities view (types, origins, bands, chips, exports).
// Contract: okf/architecture/web-client.md#entities-view
import { api } from '../../core/api.js';
import { esc, ago, toast, accentColor, tierWord, TYPE_COLORS, PAL } from '../../core/util.js';
import * as T from '../../core/time.js';

export { api, esc, ago, toast };

// type -> [label, colour, group]
// type -> [label, colour, group]; colours from the one shared map (core/util.js TYPE_COLORS)
const tc = (t) => TYPE_COLORS[t];
export const TYPES = {
  actor: ['Threat actor', tc('actor'), 'Threats'], campaign: ['Campaign', tc('campaign'), 'Threats'],
  malware: ['Malware', tc('malware'), 'Arsenal'], tool: ['Tool', tc('tool'), 'Arsenal'],
  technique: ['Technique', tc('technique'), 'Arsenal'],
  cve: ['CVE', tc('cve'), 'Vulnerabilities'], product: ['Product', tc('product'), 'Vulnerabilities'], vendor: ['Vendor', tc('vendor'), 'Vulnerabilities'],
  ip: ['IP address', tc('ip'), 'Observables'], domain: ['Domain', tc('domain'), 'Observables'], url: ['URL', tc('url'), 'Observables'],
  hash: ['File hash', tc('hash'), 'Observables'], asn: ['Network owner (ASN)', tc('asn'), 'Observables'], prefix: ['Address range', tc('prefix'), 'Observables'],
  org: ['Organisation', tc('org'), 'Context'], sector: ['Sector', tc('sector'), 'Context'], country: ['Country', tc('country'), 'Context'],
  device: ['Device', tc('device'), 'Context'], 'ip-group': ['IP group', tc('ip-group'), 'Observables'],
};
export const GROUPS = ['Threats', 'Arsenal', 'Vulnerabilities', 'Observables', 'Context'];
export const IOC_TYPES = ['ip', 'domain', 'url', 'hash'];
export const IOC = new Set([...IOC_TYPES, 'asn', 'prefix']);
export const tmeta = (t) => TYPES[t] || [t || 'Entity', '#a29d8f', 'Context'];
export const tcolor = (t) => tmeta(t)[1];
export const typeOf = (id) => String(id).split(':')[0];
export const nameOf = (id) => String(id).split(':').slice(1).join(':');
export const defang = (v, t) => {
  v = String(v ?? '');
  if (t === 'url') return v.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
  if (t === 'ip' || t === 'domain') return v.replace(/\./g, '[.]');
  return v;
};
export const shown = (name, t) => (IOC.has(t) ? defang(name, t) : name);

// Small monochrome glyphs per type (24px viewBox, stroked).
const ICON = {
  actor: 'M12 3l7 4v5c0 4.5-3 8-7 9-4-1-7-4.5-7-9V7l7-4z',
  campaign: 'M5 21V4h10l-1.5 3.5L15 11H5',
  malware: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 3v5M12 16v5M4 7l4 3M16 14l4 3M4 17l4-3M16 10l4-3',
  tool: 'M14.5 5.5a4 4 0 0 0-5 5L4 16l4 4 5.5-5.5a4 4 0 0 0 5-5l-2.5 2.5-3-1-1-3z',
  technique: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  cve: 'M12 3l9 16H3zM12 10v4M12 17v.5',
  product: 'M4 7l8-4 8 4v10l-8 4-8-4zM4 7l8 4 8-4M12 11v10', vendor: 'M3 21h18M5 21V8l7-5 7 5v13M9 21v-6h6v6',
  ip: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  domain: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  url: 'M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1',
  hash: 'M9 3L7 21M17 3l-2 18M4 8h17M3 16h17',
  asn: 'M5 5h5v5H5zM14 14h5v5h-5zM10 7.5h4.5v6.5', prefix: 'M5 5h5v5H5zM14 14h5v5h-5zM10 7.5h4.5v6.5',
  org: 'M4 21V5h10v16M14 9h6v12M7 9h4M7 13h4M7 17h4', sector: 'M4 20h16M6 20V10M10 20V6M14 20v-8M18 20V9',
  country: 'M5 21V4M5 4h11l-2 4 2 4H5', device: 'M3 5h18v11H3zM8 20h8M12 16v4', 'ip-group': 'M7 7a3 3 0 1 0 0 .1M17 7a3 3 0 1 0 0 .1M12 16a3 3 0 1 0 0 .1',
};
export const icon = (t, cls = 'en-ic') => `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true"><path d="${ICON[t] || ICON.org}"/></svg>`;

// Where a link comes from. Hypotheses (inferred, co-mention) are links the hub computed itself: labelled as such,
// ranked below anything a source said, and hidden from Related and the graph until the user asks for them.
// "local" is kept for links matched in your own network data; co-mentions have their own origin.
export const ORIGINS = {
  observed: { label: 'Observed', desc: 'seen directly in a data source or reference list', color: '#e9e3d4', dash: '' },
  // the most common origin carries the quietest mark: a warm-grey dash (--faint); colour marks the exceptions
  reported: { label: 'Reported', desc: 'a named source said it', color: '#8b8779', dash: '6 4' },
  // the theme accent (--accent, as in the app.css .o-user swatches), read live so legend, links and badges agree
  user: { label: 'Your links', desc: 'links only you have confirmed', get color() { return accentColor(); }, dash: '' },
  inferred: { label: 'Hypothesis', desc: 'computed by the hub from shared tools and infrastructure; no source has said it', color: PAL.violet, dash: '1.5 4', hypothesis: true },
  'co-mention': { label: 'Mentioned in the same article', desc: 'named in the same article or report; nobody said they are linked', color: '#a29d8f', dash: '2 3', hypothesis: true },
  local: { label: 'Seen on your network', desc: 'matched in your own network logs', color: PAL.olive, dash: '' },
};
export const ORIGIN_ORDER = ['observed', 'reported', 'user', 'inferred', 'co-mention', 'local'];
export const isHypothesis = (o) => !!ORIGINS[o]?.hypothesis;
export const HYPOTHESIS_WHY = 'A link the hub computed itself (shared tools or infrastructure, or named in the same article). No source has said it; treat it as a lead, not a fact.';
// The pill a hypothesis gets instead of a confidence band.
export const hypPill = (why = '') => `<span class="en-hyp" title="${esc(why || HYPOTHESIS_WHY)}">Hypothesis</span>`;

export const PRED = {
  uses: 'uses', targets: 'targets', 'attributed-to': 'attributed to', 'communicates-with': 'communicates with', 'linked-to': 'linked to',
  exploits: 'exploits', 'variant-of': 'variant of', drops: 'drops', 'part-of': 'part of', delivers: 'delivers', affects: 'affects',
  'made-by': 'made by', 'announced-by': 'announced by', 'in-prefix': 'in prefix', indicates: 'indicates', hosts: 'hosts',
  'hosts-malware': 'hosts malware', operates: 'operates', 'mentioned-with': 'mentioned with',
};
export const INV = {
  uses: 'used by', targets: 'targeted by', 'attributed-to': 'has attributed', exploits: 'exploited by', 'variant-of': 'has variant',
  drops: 'dropped by', 'part-of': 'includes', delivers: 'delivered by', affects: 'affected by', 'made-by': 'makes', 'announced-by': 'announces',
  'in-prefix': 'contains', indicates: 'indicated by', hosts: 'hosted on', 'hosts-malware': 'hosted on', operates: 'operated by',
  'communicates-with': 'contacted by', 'linked-to': 'linked from',
};
export const predText = (p, dir) => (dir === 'in' ? INV[p] || `← ${p}` : PRED[p] || String(p).replace(/-/g, ' '));

// confidence band -> [label, colour]: a neutral-to-amber scale, so "low" reads as quiet, not as a warning
export const BANDS = { high: ['high', '#e4a84c'], moderate: ['moderate', '#b4957b'], low: ['low', '#a29d8f'] };
export function bandOf(conf, band) {
  if (band && BANDS[band]) return band;
  if (conf == null) return null;
  return conf >= 0.65 ? 'high' : conf >= 0.35 ? 'moderate' : 'low'; // same cut-offs as scoring.band()
}
// The scorer's explanation for a claim's confidence, when the backend provides one, in plain words:
// the scorer writes "5 sources: B, B, B, B, C"; people read "5 sources: 4 research, 1 community".
const rawWhy = (c) => (c && (c.why || c.confidence_why || (Array.isArray(c.evidence) ? c.evidence.find((e) => e && typeof e.why === 'string')?.why : null))) || '';
export function plainWhy(why) {
  const m = /^(\d+) sources?: ((?:[A-D](?:, )?)+|none)(.*)$/.exec(String(why || ''));
  if (!m) return String(why || '');
  const n = {};
  for (const t of m[2].split(/,\s*/)) if (tierWord(t)) n[t] = (n[t] || 0) + 1;
  const parts = 'ABCD'.split('').filter((t) => n[t]).map((t) => `${n[t]} ${tierWord(t)}`);
  const rest = m[3].replace(' (model-extracted)', ' (read by the AI helper)').replace('; corroborated by an observed claim', '; backed by something observed directly');
  return `${m[1]} source${m[1] === '1' ? '' : 's'}${parts.length ? ': ' + parts.join(', ') : ''}${rest}`;
}
export const whyOf = (c) => plainWhy(rawWhy(c));
export function bandPill(conf, band, why = '') {
  const b = bandOf(conf, band);
  if (!b) return '<span class="en-band none" title="not scored yet">unscored</span>';
  const [l, c] = BANDS[b];
  return `<span class="en-band" style="--c:${c}" title="confidence ${conf != null ? Math.round(conf * 100) + ' / 100' : '—'}${why ? ` · ${esc(why)}` : ''}"><i style="width:${Math.round((conf ?? 0) * 100)}%"></i>${esc(l)}${conf != null ? ` <b>${Math.round(conf * 100)}</b>` : ''}</span>`;
}
const TIERS = { A: 'primary authority', B: 'established research or newsroom', C: 'community or aggregator list', D: 'unverified or crowd content' };
export const tierBadge = (t) => (t ? `<span class="en-tier t${esc(t)}" data-term="trust-tier" title="Source tier ${esc(t)}: ${esc(TIERS[t] || '')}">${esc(t)}${tierWord(t) ? ` · ${esc(tierWord(t))}` : ''}</span>` : '');

// Chip: a link to the entity page; hover shows the shared card (entity-panel.js).
export function chip(id, { type, name, n, cls = '' } = {}) {
  const t = type || typeOf(id);
  const nm = name || nameOf(id);
  const s = shown(nm, t);
  return `<a class="en-chip ${cls}" href="#entities/${encodeURIComponent(id)}" data-entity="${esc(id)}" style="--c:${tcolor(t)}">${icon(t)}<span>${esc(s.length > 48 ? s.slice(0, 46) + '…' : s)}</span>${n > 1 ? `<i>${n}</i>` : ''}</a>`;
}

export const fmtDate = (t) => (t ? T.date(t) : '—');   // the app's one clock (core/time.js)
export const fmtAgo = (t) => (t ? ago(t) : '—');

export function sparkSvg(vals, { w = 96, h = 22, color = 'var(--accent)' } = {}) {
  if (!vals || !vals.length) return '';
  const mx = Math.max(1, ...vals);
  const bw = w / vals.length;
  const total = vals.reduce((a, b) => a + b, 0);
  if (!total) return `<svg class="en-spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"><line x1="0" x2="${w}" y1="${h - 1}" y2="${h - 1}" stroke="var(--line-2)"/></svg>`;
  const bars = vals.map((v, i) => (v ? `<rect x="${(i * bw + 0.5).toFixed(1)}" y="${(h - 1 - (v / mx) * (h - 3)).toFixed(1)}" width="${Math.max(bw - 1, 1).toFixed(1)}" height="${((v / mx) * (h - 3)).toFixed(1)}" fill="${color}"/>` : '')).join('');
  return `<svg class="en-spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"><line x1="0" x2="${w}" y1="${h - 0.5}" y2="${h - 0.5}" stroke="var(--line-2)"/>${bars}</svg>`;
}

export function download(name, text, mime = 'application/json') {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
export function copy(text) {
  navigator.clipboard?.writeText(text).then(() => toast('Copied'), () => toast('Copy failed', true));
}
export const csvCell = (v) => { const s = String(v ?? ''); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };

// ---- STIX 2.1 export -------------------------------------------------------------
// Deterministic ids (UUIDv5-like from SHA-1 of a name) so re-exports dedupe in a TIP.
async function sid(type, key) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(`nightdesk:${type}:${key}`));
  const b = [...new Uint8Array(buf)].slice(0, 16);
  b[6] = (b[6] & 0x0f) | 0x50; b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${type}--${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
const SDO = { actor: 'intrusion-set', campaign: 'campaign', malware: 'malware', tool: 'tool', cve: 'vulnerability', technique: 'attack-pattern' };
const hashKey = (v) => (v.length === 32 ? 'MD5' : v.length === 40 ? "'SHA-1'" : "'SHA-256'");
export function stixPattern(t, v) {
  const q = String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  if (t === 'ip') return `[${v.includes(':') ? 'ipv6' : 'ipv4'}-addr:value = '${q}']`;
  if (t === 'domain') return `[domain-name:value = '${q}']`;
  if (t === 'url') return `[url:value = '${q}']`;
  if (t === 'hash') return `[file:hashes.${hashKey(v)} = '${q}']`;
  return null;
}
export async function stixBundle(entity, iocs) {
  const now = new Date().toISOString();
  const objs = [];
  const ident = await sid('identity', 'nightdesk');
  objs.push({ type: 'identity', spec_version: '2.1', id: ident, created: now, modified: now, name: 'Night Desk (local OSINT hub)', identity_class: 'system' });
  let root = null;
  const sdo = SDO[entity.type];
  if (sdo) {
    root = await sid(sdo, entity.id);
    const o = { type: sdo, spec_version: '2.1', id: root, created: now, modified: now, created_by_ref: ident, name: entity.name };
    if (entity.aliases?.length && sdo !== 'vulnerability' && sdo !== 'attack-pattern') o.aliases = entity.aliases.slice(0, 50);
    if (entity.attrs?.description) o.description = entity.attrs.description;
    if (sdo === 'malware') o.is_family = true;
    if (sdo === 'vulnerability') o.external_references = [{ source_name: 'cve', external_id: entity.name.toUpperCase() }];
    if (sdo === 'attack-pattern' && entity.attrs?.attack_id) o.external_references = [{ source_name: 'mitre-attack', external_id: entity.attrs.attack_id, url: entity.attrs.url }];
    if (entity.first_seen && (sdo === 'intrusion-set' || sdo === 'campaign')) o.first_seen = entity.first_seen;
    if (entity.last_seen && (sdo === 'intrusion-set' || sdo === 'campaign')) o.last_seen = entity.last_seen;
    objs.push(o);
  }
  for (const r of iocs) {
    const pat = stixPattern(r.type, r.value);
    if (!pat) continue;
    const iid = await sid('indicator', r.id);
    objs.push({
      type: 'indicator', spec_version: '2.1', id: iid, created: now, modified: now, created_by_ref: ident,
      name: r.value, pattern: pat, pattern_type: 'stix', valid_from: r.first_seen || now, indicator_types: ['malicious-activity'],
      ...(r.confidence != null ? { confidence: Math.round(r.confidence * 100) } : {}),
      description: `${r.how || 'related'} · ${r.origin || ''} · sources: ${(r.sources || []).join(', ')}`.trim(),
    });
    if (root) objs.push({ type: 'relationship', spec_version: '2.1', id: await sid('relationship', `${r.id}>${entity.id}`), created: now, modified: now, relationship_type: 'indicates', source_ref: iid, target_ref: root, created_by_ref: ident });
  }
  return { type: 'bundle', id: await sid('bundle', `${entity.id}:${now}`), objects: objs };
}

// ATT&CK enterprise tactics in kill-chain order (v18: Defense Evasion split into Stealth and Defense Impairment;
// older data saying 'defense-evasion' is shown under Stealth).
export const TACTIC_ALIAS = { 'defense-evasion': 'stealth' };
export const TACTICS = [
  ['reconnaissance', 'Recon'], ['resource-development', 'Resource dev'], ['initial-access', 'Initial access'], ['execution', 'Execution'],
  ['persistence', 'Persistence'], ['privilege-escalation', 'Priv. escalation'], ['stealth', 'Stealth'], ['defense-impairment', 'Defense impairment'],
  ['credential-access', 'Credential access'], ['discovery', 'Discovery'], ['lateral-movement', 'Lateral movement'],
  ['collection', 'Collection'], ['command-and-control', 'C2'], ['exfiltration', 'Exfiltration'], ['impact', 'Impact'],
];
let techCache = null;
export async function techniqueIndex() {
  if (techCache) return techCache;
  try {
    const r = await api.get('/api/entities/techniques');
    techCache = new Map(r.items.map((t) => [t.id, t]));
  } catch { techCache = new Map(); }
  return techCache;
}

export { LS } from '../../core/prefs.js';

// ---- placeholder filter (directory) -------------------------------------------------------------
// LLM extraction from articles creates generic placeholders ("unknown threat actor", "North Korean
// threat actors"), named individuals and companies typed as actors. Reference entities (which carry a
// description) are never hidden. Mirrors normalize.GENERIC plus descriptor words.
const GENERIC_W = new Set(('the group groups team gang crew apt actor actors threat hackers hacker operators operator affiliate affiliates '
  + 'cluster activity campaign campaigns operation ransomware malware trojan backdoor rat loader stealer infostealer botnet family variant implant '
  + 'dropper downloader framework toolkit kit tool worm wiper spyware banker banking miner payload beacon agent '
  + 'unknown unidentified unnamed unattributed undisclosed suspected several multiple other various new same this that a an of and '
  + 'chinese china prc russian russia iranian iran north south korean korea dprk nk vietnamese pakistani indian israeli western '
  + 'state sponsored backed aligned linked affiliated nexus speaking based nation cyber criminal criminals cybercriminals cybercriminal '
  + 'financially motivated espionage attackers attacker adversary adversaries intrusion set sets entity entities individual individuals '
  + 'researchers scammers fraudsters gangs members member people person users').split(' '));
const ORG_W = /\b(inc|ltd|llc|co|corp|corporation|company|technology|technologies|gmbh|plc|sa|ag)\.?$/i;
const ANIMAL = new Set('bear panda kitten spider chollima tiger jackal buffalo leopard ocelot typhoon blizzard sleet sandstorm tempest hail rain dust cyclone flood storm'.split(' '));
const PERSON = /^[A-Z][a-z'’-]+(?: [A-Z]\.)?(?: [A-Z][a-z'’-]+){1,2}$/;
export function placeholder(r) {
  if (!r || r.description) return null;
  if (!['actor', 'campaign', 'malware', 'tool'].includes(r.type)) return null;
  const toks = String(r.name || '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const rest = toks.filter((t) => !GENERIC_W.has(t) && !/^\d+$/.test(t));
  if (!rest.length) return 'generic name';
  if (r.type === 'actor' && ORG_W.test(r.name)) return 'company named as actor';
  if (r.type === 'actor' && !r.alias_count && PERSON.test(r.name) && !toks.some((t) => GENERIC_W.has(t) || ANIMAL.has(t))) return 'named individual';
  return null;
}

// Commodity tools: shared by many unrelated operations, so a shared one is weak evidence of a link.
// Mirrors osinthub/entities/scoring.py COMMODITY_TOOLS (weight 0.2); a backend `specificity` field wins.
export const COMMODITY = new Set(['tool:cobalt-strike', 'malware:cobalt-strike', 'tool:mimikatz', 'tool:psexec', 'tool:adfind',
  'tool:rclone', 'tool:anydesk', 'tool:ngrok', 'tool:plink', 'tool:impacket', 'tool:metasploit', 'tool:net', 'tool:cmd', 'tool:powershell',
  'tool:systeminfo', 'tool:ipconfig', 'tool:tasklist', 'tool:whoami', 'tool:netstat', 'tool:wmic', 'tool:reg', 'tool:at', 'tool:schtasks',
  'tool:7-zip', 'tool:winrar', 'tool:certutil', 'tool:bitsadmin', 'tool:sliver', 'tool:advanced-ip-scanner', 'tool:netscan',
  'tool:teamviewer', 'tool:screenconnect', 'tool:atera', 'tool:splashtop', 'tool:tor', 'tool:dsquery', 'tool:ping', 'tool:arp',
  'tool:nltest', 'tool:route', 'tool:rubeus', 'tool:procdump', 'tool:ntdsutil', 'tool:winscp', 'tool:putty', 'tool:rar',
  // living-off-the-land binaries and public offensive frameworks (client-side additions; not in the scorer's list)
  'tool:wevtutil', 'tool:netsh', 'tool:sdelete', 'tool:nbtscan', 'tool:empire', 'tool:powersploit', 'tool:bloodhound', 'tool:lazagne',
  'tool:responder', 'tool:quser', 'tool:query', 'tool:vssadmin', 'tool:esentutl', 'tool:rundll32', 'tool:regsvr32', 'tool:mshta',
  'tool:wmiexec', 'tool:chisel', 'tool:fast-reverse-proxy', 'tool:frp', 'tool:nmap', 'tool:masscan', 'tool:ping', 'tool:nslookup',
  'tool:cscript', 'tool:wscript', 'tool:forfiles', 'tool:taskkill', 'tool:sc', 'tool:dsquery', 'tool:csvde', 'tool:ldifde',
  'tool:hacktool-mimikatz', 'tool:brute-ratel-c4', 'tool:havoc', 'tool:mythic', 'tool:koadic', 'tool:pupy', 'tool:quasarrat',
  'malware:quasar-rat', 'malware:njrat', 'malware:asyncrat', 'malware:remcos', 'malware:gh0st-rat', 'malware:plugx', 'malware:china-chopper',
  'tool:china-chopper', 'tool:gh0st-rat', 'tool:plugx']);
export function specificity(s) {
  if (s && typeof s.specificity === 'number') return s.specificity;
  if (s && typeof s.weight === 'number') return s.weight;
  if (COMMODITY.has(s?.id)) return 0.2;
  // shared by most of the lines on screen: not distinctive either
  if (s?.lanes && s.total && s.lanes.length >= 4 && s.lanes.length / s.total > 0.5) return 0.3;
  return 1;
}

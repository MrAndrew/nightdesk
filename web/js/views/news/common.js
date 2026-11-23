// News view helpers: entity vocabulary, chips, the entity card popover, text highlighting and copy/export.
import { api } from '../../core/api.js';
import { esc, ago, toast, flag, tierWord } from '../../core/util.js';
import * as T from '../../core/time.js';

export { esc, ago, toast, flag, api };

// Entity types -> label, colour class and filter group. IoC types are grouped for the stream chips.
export const ETYPES = {
  cve:       { label: 'CVE',       cls: 'e-cve',  group: 'cve' },
  actor:     { label: 'Actor',     cls: 'e-act',  group: 'actor' },
  malware:   { label: 'Malware',   cls: 'e-mal',  group: 'malware' },
  campaign:  { label: 'Campaign',  cls: 'e-cmp',  group: 'campaign' },
  tool:      { label: 'Tool',      cls: 'e-mal',  group: 'malware' },
  vendor:    { label: 'Vendor',    cls: 'e-ven',  group: 'vendor' },
  product:   { label: 'Product',   cls: 'e-ven',  group: 'vendor' },
  org:       { label: 'Org',       cls: 'e-org',  group: 'org' },
  technique: { label: 'Technique', cls: 'e-ttp',  group: 'technique' },
  ip:        { label: 'IP',        cls: 'e-ioc',  group: 'ioc' },
  domain:    { label: 'Domain',    cls: 'e-ioc',  group: 'ioc' },
  url:       { label: 'URL',       cls: 'e-ioc',  group: 'ioc' },
  hash:      { label: 'Hash',      cls: 'e-ioc',  group: 'ioc' },
  country:   { label: 'Country',   cls: 'e-geo',  group: 'geo' },
  sector:    { label: 'Sector',    cls: 'e-geo',  group: 'geo' },
};
export const emeta = (t) => ETYPES[t] || { label: t || 'entity', cls: 'e-org', group: 'other' };
export const IOC_TYPES = new Set(['ip', 'domain', 'url', 'hash']);
export const isIoc = (t) => IOC_TYPES.has(t);

// Stream filter groups (entity type filter)
export const TYPE_FILTERS = [
  ['cve', 'CVE'], ['actor', 'Actor'], ['malware', 'Malware'], ['campaign', 'Campaign'], ['vendor', 'Vendor'], ['ioc', 'Indicator'],
];
// Chip priority on a story card (lower first)
const PRIO = { actor: 0, malware: 1, tool: 1, cve: 2, campaign: 3, vendor: 4, product: 5, technique: 6, org: 7 };

export const entType = (e) => e.type || String(e.id || '').split(':')[0];
export const entName = (e) => e.name || String(e.id || '').split(':').slice(1).join(':');

export function defang(v, type) {
  if (!v) return '';
  if (type === 'url') return v.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
  if (type === 'ip' || type === 'domain') return v.replace(/\./g, '[.]');
  return v;
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
export function iocSummary(list) {
  const c = {};
  for (const e of list) c[entType(e)] = (c[entType(e)] || 0) + 1;
  const parts = [];
  if (c.ip) parts.push(plural(c.ip, 'IP', 'IPs'));
  if (c.domain) parts.push(plural(c.domain, 'domain', 'domains'));
  if (c.url) parts.push(plural(c.url, 'URL', 'URLs'));
  if (c.hash) parts.push(plural(c.hash, 'hash', 'hashes'));
  return parts.join(', ');
}

const ICON = {
  cve: '<path d="M12 3 3 19h18L12 3Z M12 10v4 M12 16.5v.5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>',
  actor: '<path d="M5 20c.8-3.5 3.6-5.5 7-5.5s6.2 2 7 5.5M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z M7 7.5h10" fill="none" stroke="currentColor" stroke-width="1.6"/>',
  malware: '<path d="M12 6a5 5 0 0 1 5 5v3a5 5 0 0 1-10 0v-3a5 5 0 0 1 5-5Zm0-3v3M8 4l2 2.3M16 4l-2 2.3M3 12h4M17 12h4M4 18l3.4-1.6M20 18l-3.4-1.6" fill="none" stroke="currentColor" stroke-width="1.6"/>',
  campaign: '<path d="M5 21V4M5 4h11l-2 4 2 4H5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>',
  vendor: '<path d="M4 20V9l8-5 8 5v11M9 20v-6h6v6" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>',
  ioc: '<path d="M8 4c-2.5 2-3 5-3 8s1 6 3 8M16 4c2.5 2 3 5 3 8s-1 6-3 8M12 7v10M9 9.5h6M9 14.5h6" fill="none" stroke="currentColor" stroke-width="1.6"/>',
  technique: '<path d="M4 6h16M4 12h10M4 18h6M17 14l3 3-3 3" fill="none" stroke="currentColor" stroke-width="1.6"/>',
  org: '<path d="M4 20h16M6 20V8h5v12M13 20V4h5v16" fill="none" stroke="currentColor" stroke-width="1.6"/>',
};
export function eicon(type) {
  const g = emeta(type).group;
  const k = ICON[type] ? type : ICON[g] ? g : g === 'vendor' ? 'vendor' : 'org';
  return `<svg class="nw-ei" viewBox="0 0 24 24" aria-hidden="true">${ICON[k]}</svg>`;
}

export function chip(e, { count = false, cls = '' } = {}) {
  const t = entType(e), m = emeta(t), name = entName(e);
  const shown = isIoc(t) ? defang(name, t) : name;
  return `<a class="nw-chip ${m.cls} ${cls}" href="${esc(entityHref(e.id))}" data-eid="${esc(e.id)}" title="${esc(m.label)}: ${esc(name)}">${eicon(t)}<span class="nw-cn">${esc(shown.length > 46 ? shown.slice(0, 44) + '…' : shown)}</span>${count && e.articles > 1 ? `<span class="nw-cc">${e.articles}</span>` : ''}</a>`;
}

// Drop the same name seen under several types (an LLM may call "AppSalt" both actor and org); keep the
// highest-priority type.
export function dedupeByName(ents) {
  const order = (e) => PRIO[entType(e)] ?? 9;
  const best = new Map();
  for (const e of [...ents].sort((a, b) => order(a) - order(b))) {
    const k = entName(e).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!best.has(k)) best.set(k, e);
  }
  const keep = new Set(best.values());
  return ents.filter((e) => keep.has(e));
}

// Chip list that shows `max` and folds the rest behind a "+N more" toggle.
export function chipList(ents, max = 10, opts = {}) {
  const head = ents.slice(0, max).map((e) => chip(e, opts)).join('');
  const rest = ents.slice(max);
  if (!rest.length) return head;
  return head + `<span class="nw-fold" hidden>${rest.map((e) => chip(e, opts)).join('')}</span><button class="nw-morebtn" data-unfold>+${rest.length} more</button>`;
}

// The one name a phone card's meta line shows: the first named entity by the chip priority (techniques excluded).
export function topEntity(ents) {
  return (ents || []).filter((e) => PRIO[entType(e)] != null && entType(e) !== 'technique' && entName(e))
    .sort((a, b) => PRIO[entType(a)] - PRIO[entType(b)] || (b.articles || 0) - (a.articles || 0))[0] || null;
}

// Story card chips: named entities by priority, then one aggregated IoC chip (Feedly style), then flags. ATT&CK
// techniques are only a neutral count on the card: a card can't say how sure each one is (named, likely, possible:
// core/ttp.js), the story page does.
export function storyChips(ents, max = 5) {
  ents = ents || [];
  const named = ents.filter((e) => PRIO[entType(e)] != null && entType(e) !== 'technique')
    .sort((a, b) => PRIO[entType(a)] - PRIO[entType(b)] || (b.articles || 0) - (a.articles || 0));
  const seen = new Set();
  const pick = [];
  for (const e of named) {
    const k = entName(e).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (seen.has(k)) continue;           // "Videostrong" as actor and org: show once
    seen.add(k); pick.push(e);
    if (pick.length >= max) break;
  }
  const iocs = ents.filter((e) => isIoc(entType(e)));
  const geo = ents.filter((e) => entType(e) === 'country').slice(0, 3);
  let html = pick.map((e) => chip(e)).join('');
  if (iocs.length) html += `<button class="nw-chip e-ioc nw-iocagg" data-iocs="1" title="Addresses, domains and file hashes this story names as signs of an attack (indicators of compromise, IOCs)">${eicon('ioc')}<span class="nw-cn">Indicators › ${esc(iocSummary(iocs))}</span></button>`;
  const more = named.length - pick.length;
  if (more > 0) html += `<span class="nw-more">+${more}</span>`;
  const nT = ents.filter((e) => entType(e) === 'technique').length;
  if (nT) html += `<span class="nw-ttpn" title="ATT&amp;CK techniques read from the articles. Open the story to see how sure each one is and the sentence it came from.">${nT} technique${nT === 1 ? '' : 's'}</span>`;
  if (geo.length) html += `<span class="nw-geo" title="${esc(geo.map(entName).join(', '))}">${geo.map((g) => flag(String(g.id).split(':')[1] || '')).join(' ')}</span>`;
  return html;
}

// A trust tier in plain words ("Official", "Research", …). The letter only rides in the tooltip, for people who know it.
export const tierLabel = (t) => { const w = tierWord(t); return w ? w[0].toUpperCase() + w.slice(1) : 'Unrated'; };
export function tierBadge(t, extra = '', { focus = true } = {}) {
  t = (t || '?').toUpperCase();
  const w = tierWord(t);
  return `<span class="nw-tier t-${esc(t)}" data-term="trust-tier"${focus ? '' : ' tabindex="-1"'} title="Trust: ${esc(tierLabel(t))} sources (tier ${esc(t)})${extra ? ' · ' + esc(extra) : ''}">${esc(tierLabel(t))}</span>`;
}

export function fmtDate(t, withTime = true) {
  if (!t) return '—';
  return withTime ? T.stamp(t) : T.date(t);   // the app's one clock (core/time.js)
}
export const shortAgo = (t) => ago(t).replace(' ago', '');

export function decode(s) {
  if (!s) return '';
  const t = document.createElement('textarea');
  t.innerHTML = s;
  return t.value.replace(/\s+/g, ' ').trim();
}

export async function copy(text, label = 'Copied') {
  try { await navigator.clipboard.writeText(text); toast(label); }
  catch {
    const ta = document.createElement('textarea'); ta.value = text; document.body.append(ta); ta.select();
    try { document.execCommand('copy'); toast(label); } catch { toast('Copy failed', true); }
    ta.remove();
  }
}

export function download(name, text, type = 'text/csv') {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
const csvCell = (v) => /[",\n]/.test(String(v ?? '')) ? `"${String(v).replace(/"/g, '""')}"` : String(v ?? '');
export const toCsv = (rows) => rows.map((r) => r.map(csvCell).join(',')).join('\n');

// ATT&CK technique ids in text
export const TTP_RE = /\bT1\d{3}(?:\.\d{3})?\b/g;
export function techniques(text) { return [...new Set((text || '').match(TTP_RE) || [])].sort(); }

const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Highlight entity mentions (and ATT&CK ids) in plain text, return HTML paragraphs.
export function highlight(text, ents, { q = '' } = {}) {
  const pats = [];
  const byKey = new Map();
  for (const e of ents || []) {
    const t = entType(e), n = entName(e);
    if (!n || n.length < 3 || t === 'sector') continue;
    const variants = new Set([n]);
    if (isIoc(t)) variants.add(defang(n, t)).add(n.replace(/\./g, '[.]'));
    for (const v of variants) {
      const k = v.toLowerCase();
      if (byKey.has(k)) continue;
      byKey.set(k, e);
      pats.push(v);
    }
  }
  pats.sort((a, b) => b.length - a.length);
  const parts = [];
  if (pats.length) parts.push(`(?<![\\w-])(?:${pats.map(reEsc).join('|')})(?![\\w-])`);
  parts.push(TTP_RE.source);
  const qTerms = (q || '').toLowerCase().split(/\W+/).filter((w) => w.length > 3);
  const re = new RegExp(parts.join('|'), 'gi');
  const markQ = (s) => markRaw(s, qTerms);
  const out = [];
  const counts = {};
  for (const para of String(text || '').split(/\n+/)) {
    if (!para.trim()) continue;
    let html = '', last = 0;
    for (const m of para.matchAll(re)) {
      html += markQ(para.slice(last, m.index));
      const v = m[0];
      if (/^T1\d{3}/.test(v) && !byKey.has(v.toLowerCase())) {
        html += `<a class="nw-hl e-ttp" href="https://attack.mitre.org/techniques/${esc(v.replace('.', '/'))}/" target="_blank" rel="noopener" title="ATT&CK technique">${esc(v)}</a>`;
      } else {
        const e = byKey.get(v.toLowerCase());
        if (e) {
          counts[e.id] = (counts[e.id] || 0) + 1;
          html += `<a class="nw-hl ${emeta(entType(e)).cls}" href="${esc(entityHref(e.id))}" data-eid="${esc(e.id)}" title="${esc(emeta(entType(e)).label)}">${esc(v)}${counts[e.id] === 1 ? eicon(entType(e)) : ''}</a>`;
        } else html += esc(v);
      }
      last = m.index + v.length;
    }
    html += markQ(para.slice(last));
    const isHead = para.length < 90 && !/[.:;,]$/.test(para.trim()) && !/^[-•*]/.test(para);
    const isLi = /^\s*[-•*]\s+/.test(para);
    out.push(isLi ? `<p class="nw-li">${html.replace(/^\s*[-•*]\s+/, '')}</p>` : isHead ? `<h4>${html}</h4>` : `<p>${html}</p>`);
  }
  return out.join('');
}

export function markTerms(snippet, q) {
  return markRaw(snippet, (q || '').toLowerCase().split(/\W+/).filter((w) => w.length > 2));
}

// Match the query words on the raw text, then escape each piece (matching escaped HTML would mark inside
// entities: a query for 'amp' or 'quot' turned '&amp;' into '&<mark>amp</mark>;'). Same approach as core/search.js.
function markRaw(text, terms) {
  const s = String(text ?? '');
  if (!terms.length) return esc(s);
  const r = new RegExp(`(\\b(?:${terms.map(reEsc).join('|')})\\w*)`, 'gi');
  return s.split(r).map((part, i) => (i % 2 ? `<mark class="nw-q">${esc(part)}</mark>` : esc(part))).join('');
}

export const entityHref = (id) => `#entities/${encodeURIComponent(id)}`;

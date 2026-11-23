// App-wide entity chips. Turns IPs, CVEs, ASNs, domains and known actor, malware and tool names in rendered
// text into chips with data-entity="<type:value>", which the shared entity panel (core/entity-panel.js) turns
// into hover cards and, on click, its drawer. Contract: okf/architecture/web-client.md#entity-chips
//
//   chip(type, value, label?)  -> HTML for one chip
//   linkify(text)              -> escaped HTML with chips
//   decorate(root)             -> wraps matches in the text nodes under root (idempotent)
//   watch(root)                -> decorate(root) now and whenever its subtree changes
//
// "Seen on your network" (contract: okf/architecture/web-client.md#seen-on-your-network):
//   seenLookup(values)         -> Promise<Map(value -> item)> from /api/netlog/seen, batched and cached
//   seenChip(item, {quiet})    -> HTML: amber "Seen on your network · 2 devices · last Tue", red with an open incident
//   seenSlot(value, {quiet})   -> HTML placeholder; fillSeen(root) fills every placeholder under root in one lookup
//   seenLine(item)             -> one plain sentence for verdict strips ("seen on your network: no")
//   huntFor(value)             -> Network › Hunt filtered to the value, over all data
//
// Skipped: inputs, links, buttons, code/pre, svg/canvas, existing [data-entity], [data-nochips] and the entity
// panel itself. Network pivot values (.nv-v) keep their pivot menu on click and get the hover card only.
import { api } from './api.js';
import { esc, typeColor } from './util.js';
import * as T from './time.js';
import { live } from './live.js';
import { openEntity, closeEntity } from './entity-panel.js';
import { entityHref, newTab } from './open.js';

// Mirrors osinthub/entities/normalize.py entity_id for the types chips create.
export function entityId(type, value) {
  let v = String(value).trim().replace(/\[\.\]/g, '.');
  if (type === 'cve') return `cve:${v.toLowerCase().replace('–', '-')}`;
  if (type === 'asn') return `asn:as${v.replace(/\D/g, '')}`;
  if (type === 'ip' || type === 'domain' || type === 'hash' || type === 'prefix') return `${type}:${v.toLowerCase()}`;
  return `${type}:${slug(v)}`;
}
const fold = (s) => s.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase();
const slug = (s) => fold(s).replace(/[^a-z0-9.:/_@-]+/g, '-').replace(/-{2,}/g, '-').replace(/^-|-$/g, '');

export function chip(type, value, label) {
  const id = type.includes(':') && value == null ? type : entityId(type, value);
  const t = id.split(':')[0];
  // A real link (so Cmd/Ctrl- and middle-click open the full page in a new tab natively, core/open.js), never a
  // span: views style descendant spans (".x span { display: block }"). Chips are never placed inside links.
  return `<a class="vx-chip" href="${esc(entityHref(id))}" data-entity="${esc(id)}" style="--c:${typeColor(t)}">${esc(label ?? value ?? id.split(':').slice(1).join(':'))}</a>`;
}

// ------------------------------------------------------------------ patterns
const TLDS = 'com|net|org|io|info|biz|xyz|top|ru|cn|su|tk|ml|ga|cf|gq|pw|cc|co|me|online|site|club|shop|live|app|dev|cloud|link|click|icu|vip|store|tech|space|website|fun|pro|ir|kp|ua|de|uk|fr|nl|br|in|jp|kr|tw|hk|vn|id|tr|pl|it|es|ca|au|us|eu|gov|mil|edu|onion|zip|mov|lol|cyou|sbs|bond|run|ws|to|ly|is|ai|so';
const IP4 = String.raw`(?<!\b(?:[Vv]ersions?|[Rr]eleases?|[Bb]uild|[Pp]atch|[Vv]er\.?|v)\s?)(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:(?:\.|\[\.\])(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?:\/(?:3[0-2]|[12]?\d))?(?![\w/]|\.\d)`;
const IP6 = String.raw`(?<![\w:.])(?:[0-9a-f]{1,4}:){1,7}(?::|(?::[0-9a-f]{1,4}){1,6}|[0-9a-f]{1,4})(?:\/\d{1,3})?(?![\w]|:[0-9a-f])`;
const CVE = String.raw`\bCVE-\d{4}-\d{4,7}\b`;
const ASN = String.raw`\bAS\d{2,10}\b`;
const DOM = String.raw`(?<![\w@./-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.|\[\.\]))+(?:${TLDS})(?![\w-]|\.[a-z])`;
const BASE = [['ip', IP4], ['ip6', IP6], ['cve', CVE], ['asn', ASN], ['domain', DOM]];
let RE = build([]);
let names = new Map();          // exact name or alias -> entity id
function build(nameList) {
  const parts = BASE.map(([t, p]) => `(?<${t}>${p})`);
  if (nameList.length) parts.push(`(?<name>(?<![\\w-])(?:${nameList.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})(?![\\w-]))`);
  return new RegExp(parts.join('|'), 'gi');
}

// Common words and places that are also catalogued as actor or malware names; never chipped from free text.
const STOP = new Set(['royal', 'play', 'apex', 'grass', 'bird', 'rook', 'cuba', 'denis', 'lumen', 'gentlemen', 'font', 'quant', 'remus', 'agent',
  'information', 'unknown', 'go', 'koi', 'asin', 'moyu', 'popa', 'zard', 'rey', 'yoba', 'godz', 'haozi', 'volta', 'artex', 'grmsk', 'eicar',
  'conti', 'akira', 'qilin', 'konni', 'turla']);
const KEEP_SHORT = new Set(['conti', 'akira', 'qilin', 'konni', 'turla', 'lumma', 'vidar', 'xworm', 'njrat', 'clop', 'cl0p']);

function acceptName(n, e) {
  const k = n.toLowerCase();
  if (n.length < 4 || /^\d+$/.test(n)) return false;
  if (STOP.has(k) && !KEEP_SHORT.has(k)) return false;
  if (!/[A-Z0-9]/.test(n)) return false;                    // all lowercase: too likely an ordinary word
  const words = n.trim().split(/\s+/);
  if (words.length >= 3 && !e.description) return false;    // long unreferenced names are mostly people or companies
  if (/^[A-Z][a-z]+$/.test(n) && !KEEP_SHORT.has(k) && !e.description && (e.mentions || 0) < 3) return false;
  return true;
}

// Infrastructure and reference sites that appear in feed text but are not indicators.
const BENIGN = /(^|\.)(ripe\.net|arin\.net|apnic\.net|bsky\.app|bsky\.social|github\.com|google\.com|microsoft\.com|apple\.com|nist\.gov|cisa\.gov|mitre\.org|twitter\.com|x\.com|youtube\.com|linkedin\.com|wikipedia\.org|cloudflare\.com|amazon\.com|virustotal\.com|shodan\.io|abuse\.ch)$/i;

let dictLoading = null;
export function loadNames() {
  if (dictLoading) return dictLoading;
  dictLoading = api.get('/api/entities', { type: 'actor,malware,tool', limit: 2000 }).then((r) => {
    const m = new Map();
    for (const e of r.items || []) {
      for (const n of [e.name, ...(e.aliases || [])]) {
        if (n && acceptName(n, e) && !m.has(n.toLowerCase())) m.set(n.toLowerCase(), e.id);
      }
    }
    names = m;
    RE = build([...m.keys()].sort((a, b) => b.length - a.length));
    redecorate();
  }).catch(() => {});
  return dictLoading;
}

function idFor(groups, text) {
  if (groups.ip) return text.includes('/') ? entityId('prefix', text) : entityId('ip', text);
  if (groups.ip6) {
    // times (12:30:45) and MAC addresses look like IPv6 groups: require "::" or a hex letter, and not a MAC
    const g = text.split('/')[0].split(':');
    if (!(text.includes('::') || /[a-f]/i.test(text)) || (g.length === 6 && g.every((x) => x.length === 2)) || g.length < 3) return null;
    return text.includes('/') ? entityId('prefix', text) : entityId('ip', text);
  }
  if (groups.cve) return entityId('cve', text);
  if (groups.asn) return /^AS\d/.test(text) ? entityId('asn', text) : null;   // "as 2024" in prose is not an ASN
  if (groups.domain) return BENIGN.test(text.replace(/\[\.\]/g, '.')) ? null : entityId('domain', text);
  if (groups.name) return names.get(text.toLowerCase()) || null;
  return null;
}

export function linkify(text) {
  const s = String(text ?? '');
  let out = '', last = 0;
  RE.lastIndex = 0;   // matchAll copies lastIndex; a test() elsewhere must not make it skip the first match
  for (const m of s.matchAll(RE)) {
    const id = idFor(m.groups, m[0]);
    if (!id) continue;
    out += esc(s.slice(last, m.index)) + chip(id, null, m[0]);
    last = m.index + m[0].length;
  }
  return out + esc(s.slice(last));
}

// ------------------------------------------------------------------ DOM decoration
const SKIP = 'input,textarea,select,option,a,button,code,pre,svg,canvas,script,style,[contenteditable],[data-entity],[data-nochips],.ep,.ep-card,.vx-chip,.nv-v,.vx-w,.gs,.maplibregl-ctrl,[_echarts_instance_]';
// Entity id for a Network pivot value (data-nf field, data-nv value), or null.
export function pivotEntity(f, v) {
  if (!v) return null;
  if (f === 'ip' || f === 'indicator') {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(v)) return entityId('ip', v);
    if (/^[\d.:a-f]+\/\d+$/i.test(v)) return entityId('prefix', v);
  }
  if (f === 'asn' && /^AS?\d+$/i.test(v)) return entityId('asn', v);
  if (['indicator', 'query', 'server_name', 'host', 'domain'].includes(f) && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return entityId('domain', v);
  return null;
}

export function decorate(root) {
  if (!root || !root.isConnected) return;
  // Network pivot values: hover card only (the click stays the pivot menu).
  root.querySelectorAll?.('.nv-v[data-nf]:not([data-entity])').forEach((el) => {
    const id = pivotEntity(el.dataset.nf, el.dataset.nv || '');
    if (id) el.dataset.entity = id;
  });
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(n) {
      if (!n.nodeValue || n.nodeValue.length < 4 || !/[\d.A-Za-z]/.test(n.nodeValue)) return NodeFilter.FILTER_REJECT;
      const p = n.parentElement;
      if (!p || p.closest(SKIP)) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  const hits = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    RE.lastIndex = 0;
    if (RE.test(n.nodeValue)) hits.push(n);
  }
  RE.lastIndex = 0;
  for (const n of hits) {
    const html = linkify(n.nodeValue);
    if (!html.includes('vx-chip')) continue;
    // One wrapper element, so a text node that was a flex or grid item stays a single item.
    const w = document.createElement('ent-text');
    w.className = 'vx-w';
    w.innerHTML = html;
    n.replaceWith(w);
  }
}

const watched = new Set();
let queued = new Set(), raf = 0;
function flush() {
  raf = 0;
  const roots = [...queued]; queued = new Set();
  for (const r of roots) { try { decorate(r); } catch (e) { console.warn('chips', e); } }
}
function schedule(node) {
  queued.add(node);
  if (!raf) raf = (window.requestIdleCallback || requestAnimationFrame)(flush, { timeout: 300 });
}
function redecorate() { watched.forEach((r) => schedule(r)); }

export function watch(root) {
  if (!root || watched.has(root)) return;
  watched.add(root);
  loadNames();
  schedule(root);
  new MutationObserver((muts) => {
    for (const m of muts) {
      for (const n of m.addedNodes) {
        if (n.nodeType === 1 && !n.classList.contains('vx-chip') && !n.classList.contains('vx-w')) schedule(n);
        else if (n.nodeType === 3 && n.parentElement) schedule(n.parentElement);
      }
      if (m.type === 'characterData' && m.target.parentElement) schedule(m.target.parentElement);
    }
  }).observe(root, { childList: true, subtree: true, characterData: true });
}

// A chip inside a clickable row opens the entity, not the row: handled in the capture phase so the row's own
// click listener never sees it (Enter on the focused link clicks it). Network pivot values (.nv-v) are left to
// their pivot menu. Cmd/Ctrl/Shift- and middle-click are core/open.js's: the full page in a new tab.
document.addEventListener('click', (e) => {
  const c = e.target.closest?.('.vx-chip[data-entity]');
  if (!c || newTab(e)) return;
  e.preventDefault(); e.stopPropagation();
  openEntity(c.dataset.entity, { source: c });
}, true);


// ------------------------------------------------------------------ seen on your network
// One lookup for every view: values asked for in the same tick go out together as GET /api/netlog/seen (split so
// the URL stays short), answers are cached for a minute, and a failed request (no netlog tables, server down) leaves the
// slots empty rather than claiming "not seen".
const SEEN_TTL = 60e3;
const seenCache = new Map();        // value -> {at, item}
let seenMeta = null;                // {logs, demo_loaded, at}
let seenQueue = new Map();          // value -> [resolve...]
let seenTimer = 0;

async function seenFlush() {
  seenTimer = 0;
  const q = seenQueue; seenQueue = new Map();
  const vals = [...q.keys()];
  // GET (a read, cacheable and allowed by read-only harnesses), in parts that keep the URL short
  for (let i = 0; i < vals.length;) {
    const part = [];
    for (let len = 0; i < vals.length && part.length < 200 && len + vals[i].length < 3000; i++) { part.push(vals[i]); len += vals[i].length + 1; }
    if (!part.length) part.push(vals[i++]);
    let res = null;
    try { res = await api.get('/api/netlog/seen', { v: part.join(',') }); } catch { res = null; }
    if (res) seenMeta = { logs: res.logs, demo_loaded: res.demo_loaded, at: Date.now() };
    const by = new Map((res?.items || []).map((x) => [x.value, x]));
    for (const v of part) {
      const it = by.get(v) || null;
      if (it) seenCache.set(v, { at: Date.now(), item: it });
      for (const r of q.get(v)) r(it);
    }
  }
  if (seenCache.size > 5000) [...seenCache.keys()].slice(0, 1000).forEach((k) => seenCache.delete(k));
}

export function seenLookup(values) {
  const out = new Map();
  const wait = [];
  for (const v of new Set((values || []).map((x) => String(x || '').trim()).filter(Boolean))) {
    const c = seenCache.get(v);
    if (c && Date.now() - c.at < SEEN_TTL) { out.set(v, c.item); continue; }
    wait.push(new Promise((res) => {
      if (!seenQueue.has(v)) seenQueue.set(v, []);
      seenQueue.get(v).push((it) => { if (it) out.set(v, it); res(); });
    }));
  }
  if (wait.length && !seenTimer) seenTimer = setTimeout(seenFlush, 0);
  return Promise.all(wait).then(() => out);
}
export function seenForget() { seenCache.clear(); }

const whenShort = (t) => (t ? T.dayLabel(t) : '');
const dayText = (t) => (t ? T.date(t, { year: true }) : '');
const LOGT = { conn: 'connections', dns: 'DNS lookups', ssl: 'TLS sessions', http: 'web requests', files: 'file transfers', x509: 'certificates',
  notice: 'Zeek notices', weird: 'Zeek oddities', software: 'software seen', eve_alert: 'IDS alerts', eve_flow: 'flows', eve_dns: 'DNS lookups', eve_tls: 'TLS sessions' };

// Where a chip goes: the open incident, else Network › Hunt for the value.
const seenHref = (it) => (it.incident ? `#network/alerts/${encodeURIComponent(it.incident.id)}` : null);

export function seenChip(it, { quiet = false, compact = false } = {}) {
  if (!it || it.kind === 'unknown') return '';
  if (!it.seen) {
    if (!quiet) return '';
    const L = seenMeta?.logs;
    if (L && !L.rows) return '<a class="drawer-seen none" href="#network/import" title="Import Zeek or Suricata logs on the Network page to check indicators against your own traffic">No network logs to check yet</a>';
    const tip = L?.rows ? `Checked ${L.rows.toLocaleString()} log rows from ${dayText(L.first)} to ${dayText(L.last)}` : 'Checked your imported network logs';
    return `<span class="drawer-seen none" title="${esc(tip)}">Not seen on your network</span>`;
  }
  const inc = it.incident;
  const n = it.n_devices;
  const parts = ['Seen on your network'];
  if (n) parts.push(`${n} device${n === 1 ? '' : 's'}`);
  if (it.last) parts.push(`last ${whenShort(it.last)}`);
  const kinds = (it.log_types || []).map((k) => LOGT[k] || k).slice(0, 3).join(', ');
  const tip = [
    inc ? `Open ${inc.severity} incident: ${inc.title || inc.id}${inc.open > 1 ? ` (and ${inc.open - 1} more)` : ''}. Click to open it.` : 'No open incident. Click to see the matching rows in Network › Search logs.',
    it.rows ? `${it.rows.toLocaleString()} log row${it.rows === 1 ? '' : 's'}${kinds ? ` (${kinds})` : ''}, ${dayText(it.first)} to ${dayText(it.last)}.` : `Raised ${it.alerts} alert${it.alerts === 1 ? '' : 's'}; the log rows are no longer kept.`,
    it.devices?.length ? `Devices: ${it.devices.map((d) => d.name).join(', ')}${n > it.devices.length ? ` and ${n - it.devices.length} more` : ''}.` : '',
    it.demo ? 'This comes from the demo network, not your own.' : it.demo_also ? 'The demo network saw it too.' : '',
  ].filter(Boolean).join('\n');
  const cls = `drawer-seen ${inc ? 'hit' : 'seen'}${compact ? ' sm' : ''}`;
  // compact chips carry a short form too ("Seen · 2 devices"), shown on narrow screens by CSS
  const short = ['Seen', ...(n ? [`${n} device${n === 1 ? '' : 's'}`] : [])].join(' · ');
  const inner = `${it.demo ? '<em class="drawer-seen-demo">DEMO</em>' : ''}<span class="drawer-seen-l">${esc(parts.join(' · '))}</span>${compact ? `<span class="drawer-seen-s">${esc(short)}</span>` : ''}`;
  const href = seenHref(it);
  return href ? `<a class="${cls}" href="${esc(href)}" title="${esc(tip)}" data-seen-go>${inner}</a>`
    : `<button type="button" class="${cls}" data-seen-hunt="${esc(it.normalized || it.value)}" data-seen-kind="${esc(it.kind)}" title="${esc(tip)}">${inner}</button>`;
}

// One plain clause for a verdict line: "seen on your network: no" / "seen on your network: 2 devices, last Tue,
// open incident" (never "no" when an alert exists: the lookup counts alerts as sightings).
export function seenLine(it) {
  if (!it) return '';
  if (!it.seen) return seenMeta?.logs && !seenMeta.logs.rows ? 'no network logs to check yet' : 'seen on your network: no';
  const p = [];
  if (it.n_devices) p.push(`${it.n_devices} device${it.n_devices === 1 ? '' : 's'}`);
  if (it.last) p.push(`last ${whenShort(it.last)}`);
  if (it.incident) p.push(`open ${it.incident.severity} incident`);
  return `seen on your network${it.demo ? ' (demo)' : ''}: yes${p.length ? `, ${p.join(', ')}` : ''}`;
}

export const seenSlot = (value, { quiet = false, compact = false } = {}) =>
  (value ? `<span class="drawer-seen-slot" data-seen="${esc(value)}"${quiet ? ' data-seen-quiet' : ''}${compact ? ' data-seen-compact' : ''}></span>` : '');

export async function fillSeen(root) {
  const slots = [...(root?.querySelectorAll?.('[data-seen]:not([data-seen-done])') || [])];
  if (!slots.length) return new Map();
  slots.forEach((s) => (s.dataset.seenDone = '1'));
  const m = await seenLookup(slots.map((s) => s.dataset.seen));
  for (const s of slots) {
    const it = m.get(s.dataset.seen);
    s.innerHTML = it ? seenChip(it, { quiet: s.hasAttribute('data-seen-quiet'), compact: s.hasAttribute('data-seen-compact') }) : '';
  }
  return m;
}

// Alert triage, expected-traffic rules, new matches and demo changes all publish netlog_alerts: drop the cached
// answers and refill the chips on screen, so a dismissed incident does not stay red.
live.on('netlog_alerts', () => {
  seenForget();
  const slots = document.querySelectorAll('[data-seen][data-seen-done]');
  if (!slots.length) return;
  slots.forEach((x) => x.removeAttribute('data-seen-done'));
  fillSeen(document.body);
});

// Network › Hunt filtered to one value over all data: an address or range as ip:, anything else as text.
export async function huntFor(value, kind) {
  const k = kind || 'text';
  try {
    const net = await import('../views/net/common.js');
    net.S.filters = [{ f: k === 'ip' || k === 'cidr' ? 'ip' : 'q', v: value }];
    net.S.groupby = ['log_type'];
    try { localStorage.setItem('nd.network.range', '0'); } catch {}
    net.setRange({ h: 0 });
    net.emit('filters');
  } catch (e) { console.warn('hunt', e); }
  closeEntity();
  location.hash = '#network/hunt';
}

// A seen chip sits inside clickable rows (feeds, tables): it acts on its own and the row never sees the click.
document.addEventListener('click', (e) => {
  const b = e.target.closest?.('[data-seen-hunt], a[data-seen-go]');
  if (!b) return;
  e.stopPropagation();
  if (b.dataset.seenHunt != null) { e.preventDefault(); huntFor(b.dataset.seenHunt, b.dataset.seenKind); return; }
  closeEntity();   // the link navigates to Network › Alerts; the drawer must not stay over it
}, true);

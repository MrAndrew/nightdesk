// Shared state and helpers for the Network view (web/js/views/network.js).
// Contract and data model: okf/architecture/web-client.md, okf/data/netlog.md
import { api } from '../../core/api.js';
import * as T from '../../core/time.js';
import { esc, fmt, compact, toast, h, tierWord, shortcutBlocked, SEV as SEV_COLORS } from '../../core/util.js';
import { pivotEntity } from '../../core/chips.js';
import { entityHref } from '../../core/open.js';
import { emptyState } from '../../core/view.js';

export const SEV = ['high', 'medium', 'low', 'info'];
// severity colours: the one map in core/util.js (SEV), under the name the Network views use
export const SEVC = SEV_COLORS;
export const SEVTAG = { high: 'red', medium: 'orange', low: 'amber', info: 'blue' };

// Rule category -> human label. Rule ids are <category>_<direction>.
export const CATS = {
  c2: 'Botnet controller', drop: 'Hijacked network (DROP)', compromised: 'Compromised host', reputation: 'Bad reputation',
  listed: 'Threat list', attacker: 'Attacker', scanner: 'Scanner', tor: 'Tor exit', reported: 'Reported in news',
  kev: 'Exploited CVE', historical: 'Contact outside listing', sensor: 'Log sender',
  malware: 'Malware file', own: 'Your list', newdev: 'New device',
};
export const DIRS = {
  silent: 'stopped sending', outbound: 'outbound', dns: 'DNS lookup', inbound: 'inbound', unknown: 'unknown direction', ambiguous: 'ambiguous direction',
};
export function ruleLabel(rule) {
  if (!rule) return '—';
  if (rule === 'historical') return CATS.historical;
  const [cat, ...rest] = rule.split('_');
  const dir = rest.join('_');
  return `${CATS[cat] || cat} · ${DIRS[dir] || dir.replace('_', ' ')}`;
}

// Trust tiers A-D (okf/sources/trust-model.md). Alerts carry evidence.source_tier; this map is the
// fallback for rows matched before the backend recorded it.
export const TIER_INFO = {
  A: ['Primary authority', 'Government CERT, standards body or the operator of the measurement itself.'],
  B: ['Established research', 'Research group or vendor with a published method and a track record.'],
  C: ['Community list', 'Widely used, but curation varies: corroborate before acting.'],
  D: ['Unverified', 'Crowd or auto-extracted content: signal only, never ground truth.'],
  U: ['Your list', 'A list you uploaded (Network › Connect logs › Your own lists). Night Desk takes your word for it.'],
};
const TIER_FALLBACK = { spamhaus_drop: 'A', cisa_kev: 'A', tor_exits: 'A', feodo_c2: 'B', dshield_top: 'B', et_compromised: 'B',
  blocklist_de: 'C', cins_army: 'C', threatfox: 'B', urlhaus: 'B', sslbl: 'B', reported: 'D' };
export function tierOf(src, ev) {
  const t = ev?.source_tier || (String(src || '').startsWith('own:') ? 'U' : TIER_FALLBACK[src]) || 'C';
  return [t, ...(TIER_INFO[t] || TIER_INFO.C)];
}
export const tierChip = (src, ev) => { const [t, l, d] = tierOf(src, ev); return `<span class="nv-tier t${t}" data-term="trust-tier" title="Trust tier ${t}: ${esc(l)}. ${esc(d)}">${t}${tierWord(t) ? ` · ${tierWord(t)}` : ''}</span>`; };

export const CONF = {
  certain: ['green', 'DHCP lease or layer-2 address ties this MAC to the IP.'],
  derived: ['blue', 'MAC embedded in an EUI-64 IPv6 address.'],
  probable: ['amber', 'IPv6 address linked by matching DNS/SNI behaviour to a known device.'],
  'ip-only': ['', 'No MAC evidence: identified by IP address only.'],
};

export function bytes(n) {
  if (n == null) return '—';
  n = Number(n);
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (Math.abs(n) >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}
export const pad = (n) => String(n).padStart(2, '0');
// Times go through the app's one clock (core/time.js): local time or UTC as set in Settings › Display, 24-hour,
// "7 Nov 14:02:09". Z() is the zone's short name for labels ("UTC", "GMT", "CET").
export function ts(t, withSec = true) {
  if (!t) return '—';
  const d = new Date(t);
  if (isNaN(d)) return String(t);
  return T.stamp(d, { seconds: withSec });
}
export const tsShort = (t) => (t ? T.stamp(t, { seconds: true }) : '—');
export const Z = (t) => T.zoneName(t);
export const day = (t) => (t ? T.date(t) : '—');
// Compact duration ("45s", "3m 20s", "2h 5m", "6d 3h"). Rounds to the smaller unit first, so it never says "6d 24h".
export function dur(ms) {
  const s = Math.round(Math.abs(ms) / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  const m = Math.round(s / 60);
  if (m < 1440) return m % 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m / 60}h`;
  const h = Math.round(s / 3600);
  return h % 24 ? `${Math.floor(h / 24)}d ${h % 24}h` : `${h / 24}d`;
}
// The same in words for sentences: "40 seconds", "12 minutes", "5 hours", "1 day 6 hours", "7 days".
export function durWords(ms) {
  const s = Math.abs(ms) / 1000;
  const n = (x, u) => `${x} ${u}${x === 1 ? '' : 's'}`;
  if (s < 60) return n(Math.max(1, Math.round(s)), 'second');
  if (Math.round(s / 60) < 60) return n(Math.round(s / 60), 'minute');
  const h = Math.round(s / 3600);
  if (h < 24) return n(h, 'hour');
  if (s >= 3 * 86400) return n(Math.round(s / 86400), 'day');
  return h % 24 ? `${n(Math.floor(h / 24), 'day')} ${n(h % 24, 'hour')}` : n(h / 24, 'day');
}

// ------------------------------------------------------------------ shared state
const listeners = new Set();
export const S = {
  range: { h: 0 },          // {h} relative hours (0 = all) or {from, to} ms after a brush
  filters: [],              // [{f, v}] hunt filters
  groupby: ['log_type'],
  devices: new Map(),       // id -> device row
  sources: new Map(),       // id -> source row
  summary: null,
  lake: null,
};
export const onChange = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };
export const emit = (what) => listeners.forEach((fn) => { try { fn(what); } catch (e) { console.error(e); } });

export function setRange(r) { S.range = r; emit('range'); }
export function timeParams() {
  const r = S.range;
  if (r.from != null) return { since: new Date(r.from).toISOString(), until: new Date(r.to).toISOString() };
  return r.h ? { since_hours: r.h } : {};
}
export function rangeText() {
  const r = S.range;
  if (r.from != null) return `${ts(r.from, false)} → ${ts(r.to, false)} ${Z()}`;
  if (!r.h) {
    const s = S.summary;
    return s?.first ? `${ts(s.first, false)} → ${ts(s.last, false)} ${Z()} · all data` : 'All data';
  }
  return `Last ${r.h >= 24 ? r.h / 24 + 'd' : r.h + 'h'} · ${ts(Date.now() - r.h * 3600e3, false)} → now ${Z()}`;
}

export async function loadDevices() {
  try {
    const rows = await api.get('/api/netlog/devices', { limit: 2000 });
    S.devices = new Map(rows.map((d) => [d.id, d]));
  } catch {}
  return S.devices;
}
export async function loadSources() {
  try { S.sources = new Map((await api.sources()).map((s) => [s.id, s])); } catch {}
}
// What to call a device: the API's `name` (the user's label, else a readable name from the evidence, else
// "Unnamed device · hint · short id"). okf/data/netlog.md#device-names
export function devName(id) {
  if (!id) return 'unknown host';
  const d = S.devices.get(id);
  if (d?.name) return d.name;
  if (d?.hostnames?.length) return d.hostnames[0];
  return id.replace(/^(mac|ip):/, '');
}

// Device types the user can pick, with a small line icon each (16px grid, currentColor).
export const DEV_TYPES = {
  laptop: ['Laptop or computer', '<rect x="3" y="3.5" width="10" height="7.5" rx="1"/><path d="M1.5 13h13"/>'],
  phone: ['Phone or tablet', '<rect x="4.5" y="1.5" width="7" height="13" rx="1.5"/><path d="M7.3 12.3h1.4"/>'],
  tv: ['TV or streamer', '<rect x="1.5" y="2.5" width="13" height="9" rx="1"/><path d="M5.5 14h5"/>'],
  iot: ['Smart-home gadget', '<path d="M2.5 7.3 8 2.8l5.5 4.5V13.5h-11z"/><circle cx="8" cy="9.6" r="1.4"/>'],
  server: ['Server or NAS', '<rect x="2.5" y="2" width="11" height="5" rx="1"/><rect x="2.5" y="9" width="11" height="5" rx="1"/><path d="M5 4.5h1M5 11.5h1"/>'],
  console: ['Game console', '<path d="M4.6 4.5h6.8a3 3 0 0 1 3 3.4l-.4 2.4a1.7 1.7 0 0 1-3 .8L9.6 9.8H6.4L5 11.1a1.7 1.7 0 0 1-3-.8l-.4-2.4a3 3 0 0 1 3-3.4z"/><path d="M5 6.5v2.4M3.8 7.7h2.4"/>'],
  network: ['Network gear', '<rect x="1.5" y="8.5" width="13" height="5" rx="1"/><path d="M4.5 8.5V4M11.5 8.5V4M4.5 11h.8M7 11h.8"/>'],
  other: ['Other', '<circle cx="8" cy="8" r="5.5"/><circle cx="8" cy="8" r="1.2"/>'],
};
export function typeIcon(type, title) {
  const t = DEV_TYPES[type];
  const body = t ? t[1] : '<circle cx="8" cy="8" r="5.5" stroke-dasharray="2 2"/>';
  return `<svg class="devices-ico" viewBox="0 0 16 16" aria-hidden="${title ? 'false' : 'true'}"${title ? ` role="img" aria-label="${esc(title)}"` : ''}><g fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">${body}</g></svg>`;
}
export const typeLabel = (d) => d?.type ? `${DEV_TYPES[d.type]?.[0] || d.type}${d.type_source === 'guess' ? ' (guess)' : ''}` : 'Type not set';

// ------------------------------------------------------------------ clickable values
// Any element with data-nf (field) and data-nv (value) gets the pivot menu on click.
// A value that names an entity is a real link to its page (right-click or Cmd-click opens it in a new tab); a click
// still opens the pivot menu (core/open.js, okf/architecture/web-client.md#opening-things).
export const v = (field, value, label) => {
  if (value == null || value === '') return '<span class="nv-null">—</span>';
  const id = pivotEntity(field, String(value));
  return id ? `<a class="nv-v" href="${esc(entityHref(id))}" data-nf="${esc(field)}" data-nv="${esc(value)}" data-entity="${esc(id)}">${esc(label ?? value)}</a>`
    : `<span class="nv-v" data-nf="${esc(field)}" data-nv="${esc(value)}" tabindex="0">${esc(label ?? value)}</span>`;
};
export const devLink = (id) => id
  ? `<span class="nv-v nv-dev" data-nf="device" data-nv="${esc(id)}" tabindex="0" title="${esc(id)}">${esc(devName(id))}</span>`
  : '<span class="nv-null">—</span>';

export const isIp = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || (/:/.test(s) && /^[0-9a-f:.]+$/i.test(s));

export async function lookupIp(ip, openEvent) {
  if (S.feedHandler?.(ip)) return;
  try {
    const r = await api.events({ q: ip, limit: 1 });
    if (r?.length) openEvent(r[0].id);
    else toast(`${ip} is not on any collected list`);
  } catch (e) { toast(e.message, true); }
}

// Open the SQL console on the events matching a query or a country (Explorer's #explorer/find route).
export function toExplorer({ q = '', country = '' }) {
  const p = new URLSearchParams();
  if (q) p.set('q', q);
  if (country) p.set('country', country);
  location.hash = `#explorer/find?${p}`;
}

// ------------------------------------------------------------------ hunt query (okf/data/netlog.md "Hunt queries")
// A filter is {f, v, neg}: f is any hunt field (device, ip, port, log_type, text, a column or raw.<field>).
const quote = (x) => (/[\s",]/.test(String(x)) ? `"${String(x).replace(/"/g, '')}"` : x);
export function huntQuery(filters = S.filters) {
  return filters.map(({ f, v: val, neg }) => `${neg ? '-' : ''}${f === 'q' ? 'text' : f}:${quote(val)}`).join(' ');
}
export function logParams(filters = S.filters) {
  const q = huntQuery(filters);
  return { ...timeParams(), ...(q ? { query: q } : {}) };
}

// ------------------------------------------------------------------ CIDR helpers for hunt pivots
function ipNum(ip) {
  if (ip.includes('.') && !ip.includes(':')) {
    const p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some((x) => !(x >= 0 && x <= 255))) return null;
    return 0xffff00000000n + BigInt(((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]);
  }
  let [a, b] = ip.split('::');
  const A = a ? a.split(':') : [];
  const B = b != null ? (b ? b.split(':') : []) : null;
  const parts = B == null ? A : [...A, ...Array(8 - A.length - B.length).fill('0'), ...B];
  if (parts.length !== 8) return null;
  return parts.reduce((n, x) => (n << 16n) + BigInt(parseInt(x || '0', 16)), 0n);
}
export function cidrRange(c) {
  const [ip, bits] = c.split('/');
  const n = ipNum(ip);
  if (n == null) return null;
  const v4 = ip.includes('.') && !ip.includes(':');
  const len = v4 ? 96 + Number(bits) : Number(bits);
  const host = (1n << BigInt(128 - len)) - 1n;
  return [n & ~host, (n & ~host) | host];
}

// ------------------------------------------------------------------ small render helpers
export function barList(rows, { key = 'key', val = 'conns', label, fmtv = fmt, field, color = 'var(--accent)', sub } = {}) {
  if (!rows?.length) return emptyState({ why: 'Nothing in this range.', size: 'sm' });
  const max = Math.max(...rows.map((r) => Number(r[val]) || 0), 1);
  return `<div class="nv-bl">${rows.map((r, i) => `
    <div class="nv-bl-r">
      <span class="nv-bl-k">${i + 1}</span>
      <span class="nv-bl-l">${label ? label(r) : field ? v(field, r[key]) : esc(r[key])}${sub ? `<em>${sub(r) || ''}</em>` : ''}</span>
      <span class="nv-bl-t"><i style="width:${(100 * (Number(r[val]) || 0) / max).toFixed(1)}%;background:${typeof color === 'function' ? color(r) : color}"></i></span>
      <span class="nv-bl-n">${fmtv(r[val])}</span>
    </div>`).join('')}</div>`;
}

export function card(title, body, { badge = '', tools = '', cls = '' } = {}) {
  return `<section class="nv-card ${cls}"><div class="panel-head"><span class="panel-title">${title}</span>${badge ? `<span class="panel-badge">${badge}</span>` : ''}<div class="panel-tools">${tools}</div></div><div class="nv-cb">${body}</div></section>`;
}

export function jsonHtml(obj, field = true) {
  // Pretty JSON; every scalar is clickable and pivots on its column or on raw.<key>.
  const MAP = { 'id.orig_h': 'ip', 'id.resp_h': 'ip', 'id.orig_p': 'port', 'id.resp_p': 'port', uid: 'uid', proto: 'proto',
    service: 'service', query: 'query', server_name: 'server_name', host: 'host', conn_state: 'conn_state', _path: 'log_type', answers: 'ip' };
  const val = (k, x) => {
    if (x === null) return '<span class="nj-n">null</span>';
    if (Array.isArray(x)) return `[${x.map((y) => val(k, y)).join(', ')}]`;
    if (typeof x === 'object') return `<span class="nj-n">${esc(JSON.stringify(x))}</span>`;
    const s = typeof x === 'string' ? `"${esc(x)}"` : esc(String(x));
    const cls = typeof x === 'string' ? 'nj-s' : 'nj-d';
    const f = field && k !== 'ts' && (MAP[k] || `raw.${k}`);
    return f ? `<span class="${cls} nv-v" data-nf="${esc(f)}" data-nv="${esc(x)}">${s}</span>` : `<span class="${cls}">${s}</span>`;
  };
  const keys = Object.keys(obj || {});
  const tsLine = obj?.ts != null ? `  <span class="nj-c">// ts = ${esc(ts(typeof obj.ts === 'number' ? obj.ts * 1000 : obj.ts))} ${Z()}</span>\n` : '';
  return `<pre class="nj">{\n${tsLine}${keys.map((k, i) => `  <span class="nj-k">"${esc(k)}"</span>: ${val(k, obj[k])}${i < keys.length - 1 ? ',' : ''}`).join('\n')}\n}</pre>`;
}

export { esc, fmt, compact, toast, h };

// Esc closes a Network detail pane (an alert, the rules, a device): one Esc closes one layer. Whether something else
// was in front (a menu, the event drawer, the entity panel, the value pop-up) or the user was typing is read before
// any other handler runs, because those close themselves on the same key; a handler that stops the key (an edit
// form's own Esc) wins too.
export function escCloses(isOpen, close) {
  let blocked = false;
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') blocked = shortcutBlocked(e) || !!document.querySelector('.shell-menu.open, .bnav-sheet.open') || !!e.target.closest?.('.nv-v, .nv-pop');
  }, true);
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape' || blocked || e.defaultPrevented || !isOpen()) return;
    e.preventDefault();
    close();
  });
}

// Tables wider than their panel (a phone, a narrow detail pane) scroll sideways inside a box with a visible cue:
// shaded edges where columns are hidden, and a line saying so, instead of columns cut off at the panel's edge.
// hsCue(root) wraps every table under root once and repaints the cue; call it after rendering a table.
function paintCue(box) {
  const w = box.parentElement; if (!w) return;
  const more = box.scrollWidth > box.clientWidth + 1;
  w.toggleAttribute('data-more', more);
  w.toggleAttribute('data-end', !more || box.scrollLeft + box.clientWidth >= box.scrollWidth - 2);
  w.toggleAttribute('data-start', more && box.scrollLeft > 2);
}
export function hsCue(root, label = 'Table') {
  if (!root) return;
  root.querySelectorAll('table').forEach((t) => {
    if (t.parentElement?.classList.contains('netdetail-hs')) return;
    const w = document.createElement('div'); w.className = 'netdetail-hsw';
    const box = document.createElement('div'); box.className = 'netdetail-hs';
    box.tabIndex = 0; box.setAttribute('role', 'region'); box.setAttribute('aria-label', `${label}: scrolls sideways when it does not fit`);
    t.replaceWith(w); w.append(box); box.append(t);
    box.addEventListener('scroll', () => paintCue(box), { passive: true });
  });
  requestAnimationFrame(() => root.querySelectorAll('.netdetail-hs').forEach(paintCue));
}
let cueT = 0;
window.addEventListener('resize', () => { clearTimeout(cueT); cueT = setTimeout(() => document.querySelectorAll('.netdetail-hs').forEach(paintCue), 150); });

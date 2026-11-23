// Shared helpers and the visual vocabulary for event kinds.

// Categorical colours. One palette (PAL) of 11 warm, muted colours, found by search under every rule at once:
//  * every pair at least 15 apart in CIEDE2000 (steps in hue AND lightness);
//  * at least 12 from every colour of the v1 palette (no v1 cyan, blue, lavender, pink or mint coming back);
//  * blues, teals and cyans (HSL hue 160-270) at most 45% saturation; no green/mint neon;
//  * at least 4.5:1 as text on the panel, the lighter panel, and a 12% chip tint of itself; at least 3:1 on the map's land;
//  * red (#e2674a) only for known-exploited and severity, and nothing else near it.
// Eleven colours is the most those rules allow (a twelfth drops the minimum distance to 14). Twenty event kinds therefore
// share nine non-red hues in pairs, and the second kind of a pair is drawn as a RING (map markers, legend and toggles)
// and HATCHED or DASHED (charts) instead of a filled dot or solid fill: hue tells the family, the mark tells the member.
// Entity types share hues within their group and are told apart by their glyph (directory, chips, graph nodes).
// tests/test_v12_visual.py checks every rule.
export const PAL = {
  red: '#e2674a', amber: '#e4a84c', sage: '#9cb6ad',
  blush: '#ddb8b7', lime: '#a1c470', olive: '#9b9251', tan: '#b4957b', violet: '#b090bf', rose: '#bb818a', teal: '#4ea1b0', lilac: '#f1d2fb',
};
// v1.2 f-palette: blush, lilac and lime moved down from near-white (L* 82-92) so they no longer read as white on the dark map,
// and olive and rose moved to make room. blush, lilac, lime, rose and --text are >= 15 apart in CIEDE2000.
// Teal stays for data series and the IP/ASN type only (never chrome, links or chips).
// Entity types: one shared map for the Intel directory and graph, chips (core/chips.js) and the entity panel.
export const TYPE_COLORS = {
  actor: PAL.blush, campaign: PAL.lilac, malware: PAL.rose, tool: PAL.violet, technique: PAL.tan, cve: PAL.amber,   // cve = the kind's amber
  product: PAL.olive, vendor: PAL.olive, ip: PAL.teal, asn: PAL.teal, 'ip-group': PAL.teal, prefix: PAL.lime,
  domain: PAL.lime, url: PAL.lime, hash: PAL.lime, org: PAL.sage, sector: PAL.sage, country: PAL.sage, device: PAL.tan,
};
export const typeColor = (t) => TYPE_COLORS[t] || PAL.sage;
// The muted series palette for charts, led by the amber accent: the same colours (mirrors --vz-* in app.css).
export const SERIES = [PAL.amber, PAL.teal, PAL.tan, PAL.violet, PAL.olive, PAL.rose, PAL.blush, PAL.lilac, PAL.lime, PAL.sage];
// mark: 'ring' = the second member of a hue pair (see above).
export const KINDS = {
  kev:                  { label: 'Exploited vuln',    color: PAL.red,    tag: 'red',    group: 'Vulnerabilities' },
  cve:                  { label: 'New CVE',           color: PAL.amber,  tag: 'amber',  group: 'Vulnerabilities' },
  advisory:             { label: 'Advisory',          color: PAL.amber,  mark: 'ring', tag: 'amber',  group: 'Media' },
  attacker:             { label: 'Top scanner',       color: PAL.olive,  tag: 'amber',  group: 'Threat infrastructure' },
  bruteforce:           { label: 'Brute-forcer',      color: PAL.olive,  mark: 'ring', tag: 'amber',  group: 'Threat infrastructure' },
  malicious_ip:         { label: 'Bad reputation',    color: PAL.tan,    tag: 'amber',  group: 'Threat infrastructure' },
  compromised:          { label: 'Compromised host',  color: PAL.tan,    mark: 'ring', tag: 'violet', group: 'Threat infrastructure' },
  c2:                   { label: 'Botnet controller', color: PAL.violet, tag: 'violet', group: 'Threat infrastructure' },
  c2_cert:              { label: 'Botnet certificate', color: PAL.violet, mark: 'ring', tag: 'violet', group: 'Threat infrastructure' },
  malware_ioc:          { label: 'Malware indicator', color: PAL.rose,   tag: 'violet', group: 'Threat infrastructure' },
  malware_url:          { label: 'Malware URL',       color: PAL.rose,   mark: 'ring', tag: 'amber',  group: 'Threat infrastructure' },
  ransomware:           { label: 'Ransomware victim', color: PAL.lilac,  tag: 'violet', group: 'Threat infrastructure' },
  hijacked_netblock:    { label: 'Hijacked netblock', color: PAL.lilac,  mark: 'ring', tag: 'violet', group: 'Threat infrastructure' },
  // the two biggest kinds (BGP withdrawals, origin changes) get different hues, each as a filled dot
  bgp_withdrawal_burst: { label: 'BGP withdrawals',   color: PAL.blush,  tag: 'blue',   group: 'Internet infrastructure' },
  tor_exit:             { label: 'Tor exit',          color: PAL.blush,  mark: 'ring', tag: '',       group: 'Internet infrastructure' },
  bgp_origin_change:    { label: 'BGP origin change', color: PAL.teal,   tag: 'blue',   group: 'Internet infrastructure' },
  outage:               { label: 'Internet outage',   color: PAL.teal,   mark: 'ring', tag: 'blue',   group: 'Internet infrastructure' },
  news:                 { label: 'News',              color: PAL.lime,   tag: '',       group: 'Media' },
  social:               { label: 'Social',            color: PAL.lime,   mark: 'ring', tag: 'green',  group: 'Media' },
  indicator:            { label: 'Custom indicator',  color: PAL.sage,  tag: 'green',  group: 'Custom' },
};
export const isRing = (k) => KINDS[k]?.mark === 'ring';
// The legend swatch for a kind: a filled dot, or a ring for the second member of a hue pair.
export const kindSwatch = (k, size = 8) => { const m = kindMeta(k); return isRing(k)
  ? `<i class="kind-sw ring" style="display:inline-block;width:${size}px;height:${size}px;border-radius:50%;box-sizing:border-box;border:2px solid ${m.color};background:transparent"></i>`
  : `<i class="kind-sw" style="display:inline-block;width:${size}px;height:${size}px;border-radius:50%;background:${m.color}"></i>`; };
// ECharts: hatch a bar/area series (decal) and dash a line series for ring kinds, so pairs differ in charts too.
export const kindDecal = (k) => (isRing(k) ? { symbol: 'rect', symbolSize: 1, color: 'rgba(10,13,18,.55)', dashArrayX: [1, 0], dashArrayY: [2, 3], rotation: Math.PI / 4 } : undefined);
export const kindMeta = (k) => KINDS[k] || { label: k, color: PAL.sage, tag: '', group: 'Other' };

// Severity is a flag, so it may use orange and red; the low end is a quiet neutral, not a saturated blue.
// The one severity map for the whole client (Network, Alerts, Ops widgets, Cinema, feeds): net/common.js SEVC and
// panels/network.js use this object, and sevColor() buckets a 0-1 score onto it.
export const SEV = Object.freeze({ high: PAL.red, medium: '#f08a3c', low: '#f2c94c', info: PAL.sage });
export function sevColor(s) {
  if (s == null) return '#8a8578';
  if (s >= 0.85) return SEV.high;
  if (s >= 0.65) return SEV.medium;
  if (s >= 0.45) return SEV.low;
  return SEV.info;
}
// Zeek log types, the same colour wherever a log type is drawn (Search logs timeline, chips, event rows).
// Connections are the amber accent everywhere (Network Overview, Search logs, the Ops Network timeline).
// notice and weird are not red: red is only for flagged things.
export const LOG_TYPE_COLORS = Object.freeze({
  conn: PAL.amber, dns: PAL.teal, ssl: PAL.violet, http: PAL.tan, ntp: PAL.sage, dhcp: PAL.rose,
  x509: PAL.olive, files: PAL.lilac, notice: PAL.lime, weird: PAL.blush,
});

// Ages read the same everywhere: the one rule lives in core/time.js.
export { ago } from './time.js';
import { date as dateOf } from './time.js';

// Trust tiers in one word each, shown next to the letter so nobody has to remember what "B" means.
export const TIER_WORD = { A: 'official', B: 'research', C: 'community', D: 'unverified' };
export const tierWord = (t) => TIER_WORD[String(t || '').toUpperCase()] || '';

// v1.2 corroboration: how the dashboard counts addresses (osinthub/api.py _one_per_ip), and what "N feeds" means.
export const COUNT_RULE = 'Each address counts once, under the kind of its main listing, even when several feeds list it; events without an address count one each.';
// "12 addresses", "3 events" or "9 addresses + 3 events": n counted, a of them addresses (the API's `a`)
export const countWord = (n, a) => {
  const ad = `${Number(a).toLocaleString()} address${a === 1 ? '' : 'es'}`, ev = (x) => `${Number(x).toLocaleString()} event${x === 1 ? '' : 's'}`;
  return a == null || a <= 0 ? ev(n) : a >= n ? ad : `${ad} + ${ev(n - a)}`;
};
export const feedsNote = (n) => `Corroboration, not a confidence score: some feeds copy each other (ThreatFox and URLhaus repeat Feodo Tracker's C2s), so ${n} feeds is not always ${n} independent reports.`;
export const feedsWord = (n) => `${n} feed${n === 1 ? '' : 's'}`;

export const fmt = (n) => (n == null ? '—' : Number(n).toLocaleString());
export const compact = (n) => (n == null ? '—' : Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 }).format(n));

export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// A malformed %-escape in a pasted link (e.g. #news/…) is used as typed instead of throwing 'URI malformed'.
export const safeDecode = (x) => { try { return decodeURIComponent(x); } catch { return x; } };

export function h(html) {
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

export function debounce(fn, ms = 250) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

export function flag(cc) {
  if (!cc || cc.length !== 2) return '';
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

// FIRST EPSS: a probability (0-1) of exploitation activity in the next 30 days, and its percentile among all
// scored CVEs. Shown as a percentage, coloured on fixed cut-offs (10% is the threshold most often cited).
export function epssText(p) {
  if (p == null) return '—';
  const x = p * 100;
  return x >= 10 ? `${x.toFixed(1)}%` : `${x.toFixed(2)}%`;   // same as the server's epss_pct()
}
export const epssClass = (p) => (p == null ? '' : p >= 0.5 ? 'red' : p >= 0.1 ? 'orange' : p >= 0.01 ? 'amber' : '');
export function epssTitle(p, pct, prev = null, since = null) {
  if (p == null) return 'No EPSS score';
  let t = `FIRST EPSS: ${(p * 100).toFixed(2)}% probability of exploitation activity in the next 30 days`;
  if (pct != null) t += `; higher than ${(pct * 100).toFixed(1)}% of scored CVEs`;
  if (prev != null) t += `; was ${(prev * 100).toFixed(2)}% before ${since ? dateOf(since) : 'the last change'}`;
  return t;
}
// A small tag for lists and chips; '' when there is no score.
export function epssTag(p, pct = null, prev = null, since = null) {
  if (p == null) return '';
  const arrow = prev != null && p >= prev * 1.5 && p - prev >= 0.01 ? ' ↑' : prev != null && p <= prev / 1.5 && prev - p >= 0.01 ? ' ↓' : '';
  return `<span class="tag ${epssClass(p)} epss-tag" title="${esc(epssTitle(p, pct, prev, since))}">EPSS ${epssText(p)}${arrow}</span>`;
}

export function toast(msg, err = false) {
  const el = h(`<div class="toast${err ? ' err' : ''}">${esc(msg)}</div>`);
  document.getElementById('toasts').append(el);
  setTimeout(() => el.remove(), 4200);
}

// ECharts theme shared by all chart panels.
export const chartTheme = {
  backgroundColor: 'transparent',
  textStyle: { fontFamily: 'JetBrains Mono, monospace', color: '#a29d8f', fontSize: 11 },
  axisLine: '#2c3547', split: '#1a1f2a',
  // [0] is the Night Desk accent (--accent, the desk-lamp amber); charts read the live token via accentColor()
  palette: SERIES,
};
// The theme's accent colour from the CSS token, for canvas charts that cannot use var(); falls back to the palette.
export const accentColor = () => {
  try { return getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || chartTheme.palette[0]; } catch { return chartTheme.palette[0]; }
};

// Page-level single-key shortcuts (Cyber Cinema's arrows and Space, alert triage a/d/j/k) must not act on the page
// behind an overlay, while the user types, or as part of a browser/OS chord (Cmd+A, Ctrl+D).
// Overlays: the entity panel, the guided tour, the event drawer, an open deck/widget menu, the Network pivot menu.
export function overlayOpen() {
  return !!document.querySelector('.ep.open, .tour-root, #drawer.open, .menu.open, .nv-pop:not([hidden])');
}
export function isTyping(el = document.activeElement) {
  if (!el) return false;
  if (el.isContentEditable || /^(TEXTAREA|SELECT)$/.test(el.tagName)) return true;
  // a ticked checkbox, a radio or an input button takes no text: triage keys (j/k/a/d) still work after a click on one
  return el.tagName === 'INPUT' && !/^(checkbox|radio|button|submit|reset|image|range|color|file)$/i.test(el.type || 'text');
}
// The user asked the OS for less motion: JS-driven motion (globe auto-rotation, camera flights) stays still.
export const reducedMotion = () => !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
export function shortcutBlocked(e) {
  return e.metaKey || e.ctrlKey || e.altKey || isTyping() || overlayOpen();
}

// A feed- or upload-supplied URL as a link target: only http(s) (relative URLs resolve to the page's own http(s)).
// Returns the resolved absolute URL, or null for javascript:, data:, vbscript: and anything else; render those as text.
export function safeUrl(u) {
  if (u == null || u === '') return null;
  // only something written as a URL: absolute http(s), protocol-relative, or an explicit path ('/x', './x', '../x').
  // A bare word or sentence would otherwise resolve to a same-origin page; show it as text instead.
  if (!/^\s*(https?:\/\/|\/|\.{1,2}\/)/i.test(String(u))) return null;
  try {
    const x = new URL(String(u), location.href);
    return x.protocol === 'http:' || x.protocol === 'https:' ? x.href : null;
  } catch { return null; }
}

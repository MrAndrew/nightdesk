// Network on a phone (v1.2 mobile; okf/architecture/phone.md "Per view").
// Small shared pieces for the phone layout of the Network sub-tabs: the range chip and its sheet,
// severity words, short device ids, copy, and the zoom-out bar that the brushable charts share at every width.
// Everything that changes layout runs only when core/mobile.js isPhone() says so; the zoom bar is the one piece
// desktop sees too (a fix: a brushed window was only undone by the × in the header's range control).
import { S, setRange, onChange, esc, fmt, toast } from './common.js';
import { actionSheet } from '../../core/sheet.js';
import { isCustom, windowLabel } from '../../core/range.js';

export { isPhone, onPhoneChange } from '../../core/mobile.js';

export const DOTS = '<svg class="i" viewBox="0 0 20 20" aria-hidden="true"><circle cx="4" cy="10" r="1.7" fill="currentColor"/><circle cx="10" cy="10" r="1.7" fill="currentColor"/><circle cx="16" cy="10" r="1.7" fill="currentColor"/></svg>';
export const CARET = '<svg class="nv-m-caret" viewBox="0 0 10 10" aria-hidden="true"><path d="M2 3.5 5 6.5 8 3.5" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>';
export const FILTER = '<svg class="i" viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5h14M6 10h8M8.5 15h3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>';
export const SEV_WORD = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

// The last two octets of a MAC ("3a:98"), or the address itself when there is no MAC.
export function shortId(d) {
  const mac = d?.mac || (/^mac:/.test(d?.id || '') ? d.id.slice(4) : '');
  if (mac) return mac.toLowerCase().split(/[:-]/).slice(-2).join(':');
  return (d?.ips || [])[0] || String(d?.id || '').replace(/^ip:/, '');
}

export async function copyText(text, done = 'Copied') {
  try { await navigator.clipboard.writeText(text); toast(done); } catch { toast(text); }
}

// ---------------------------------------------------------------- the time range on a phone
const PRESETS = [[24, 'Last 24 hours', '24h'], [168, 'Last 7 days', '7d'], [720, 'Last 30 days', '30d'], [0, 'All time', 'All']];
export function rangeShort() {
  const r = S.range || {};
  if (isCustom(r)) return 'Zoomed';
  return PRESETS.find((p) => p[0] === (r.h || 0))?.[2] || `${fmt(r.h)}h`;
}
// The range sheet (the header's range control is hidden on a phone): the presets, plus "Zoom out" while a
// brushed window is active.
export async function openRangeSheet() {
  const r = S.range || {};
  const items = PRESETS.map(([h, label]) => ({ label, value: h, current: !isCustom(r) && (r.h || 0) === h }));
  if (isCustom(r)) items.unshift({ label: `Zoomed to ${zoomText()}`, hint: 'now', value: null, current: true, disabled: true });
  const it = await actionSheet({ id: 'nv-range', title: 'Time range', items });
  if (it && it.value != null) { S.zoomFrom = null; setRange({ h: it.value }); }
}
export const rangeChip = (cls = '') => `<button type="button" class="m-chip nv-m-rchip ${cls}" data-mrange aria-haspopup="menu" aria-label="Time range: ${esc(rangeShort())}">${esc(rangeShort())}${CARET}</button>`;

// ---------------------------------------------------------------- zoom (every width)
// A drag across a Network chart narrows the whole Network range to that window. The chart's card says so, shows
// the window while it is active, and offers "Zoom out", which goes back to the preset that was on before the drag.
export function zoomText() {
  const r = S.range || {};
  return isCustom(r) ? windowLabel(r.from, r.to) : '';
}
// remember the preset in force before the first drag, so Zoom out returns to it (a second drag keeps the first preset)
export function brushTo(from, to) {
  if (!isCustom(S.range)) S.zoomFrom = { h: S.range?.h || 0 };
  setRange({ from, to });
}
// the last preset this session used, however it was set (the range control, a sheet, a link's ?range=)
let lastPreset = null;
onChange((w) => { if (w === 'range' && !isCustom(S.range)) lastPreset = S.range?.h || 0; });
export function zoomOut() {
  // a window that came from a link: the last preset of this session, else the one Network saved
  // (network.js keeps it), else Network's 7 days
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem('nd.network.range')); } catch { /* private mode */ }
  const back = S.zoomFrom || { h: lastPreset ?? (Number.isFinite(+saved) && saved !== null ? +saved : 168) };
  S.zoomFrom = null;
  setRange({ ...back });
}
// the card's hint line: what a drag does, or the zoomed window and Zoom out (styled inline: every width sees it,
// and app.css's m: blocks are phone-only)
export function zoomBar() {
  if (!isCustom(S.range)) return '<span class="nv-zoom-h">drag to narrow the time range</span>';
  return `<span class="nv-zoom-on">Zoomed to <b>${esc(zoomText())}</b> · <button type="button" class="nv-zoom-out" data-zoom-out style="padding:0;border:0;background:none;color:var(--accent);font:inherit;cursor:pointer;text-decoration:underline;text-underline-offset:2px">Zoom out</button></span>`;
}

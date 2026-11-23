// One clock for the whole app. Every time a person reads goes through here, so the same moment reads the same on
// Watch, Network, News, Intel, Help, notes and the top bar. One setting (Settings › Display): local time (the
// default) or UTC. Always 24-hour, one date style ("7 Nov", "7 Nov 2025" in another year) and one "ago" rounding
// (whole units, rounded down: 59 s → "59s ago", 3 days 23 h → "3d ago").
// Machine-facing text (API parameters, file names, copied summaries for other people) keeps ISO/UTC on purpose.
const KEY = 'nd.timezone';
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const MONTH = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const WD = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const WEEKDAY = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const pad = (n) => String(n).padStart(2, '0');
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;   // a calendar date ("2026-11-04"), never shifted by the zone
const NOZONE_RE = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/;

let cur = null;
export function zone() {
  if (cur) return cur;
  try { cur = localStorage.getItem(KEY) === 'utc' ? 'utc' : 'local'; } catch { cur = 'local'; }
  return cur;
}
export function setZone(z) {
  cur = z === 'utc' ? 'utc' : 'local';
  try { localStorage.setItem(KEY, cur); } catch {}
  try { window.dispatchEvent(new CustomEvent('nd:timezone', { detail: cur })); } catch {}
}
export const isUTC = () => zone() === 'utc';

// The zone's short name: "UTC", or the browser's own abbreviation ("CET", "GMT+1"), or "local time".
export function zoneName(t = Date.now()) {
  if (isUTC()) return 'UTC';
  try {
    const p = new Intl.DateTimeFormat('en-US', { timeZoneName: 'short' }).formatToParts(new Date(t)).find((x) => x.type === 'timeZoneName');
    if (p?.value) return p.value;
  } catch {}
  return 'local time';
}
// The long form for sentences and Settings: "UTC" or "local time (Europe/London)".
export function zoneLong() {
  if (isUTC()) return 'UTC';
  try { const n = Intl.DateTimeFormat().resolvedOptions().timeZone; if (n) return `local time (${n.replace(/_/g, ' ')})`; } catch {}
  return 'local time';
}

const toDate = (t) => {
  if (t == null || t === '') return null;
  if (t instanceof Date) return Number.isNaN(t.getTime()) ? null : t;
  if (typeof t === 'number') return new Date(t < 1e11 ? t * 1000 : t);   // seconds or milliseconds
  const s = String(t).trim();
  // the server stores UTC: a timestamp without a zone ("2026-11-07 07:02:00") is UTC, never the browser's zone
  const d = new Date(DAY_RE.test(s) ? `${s}T00:00:00Z` : NOZONE_RE.test(s) ? `${s.replace(' ', 'T')}Z` : s);
  return Number.isNaN(d.getTime()) ? null : d;
};
// The parts of a moment in the chosen zone (or in UTC for a bare calendar date).
function parts(t) {
  const d = toDate(t);
  if (!d) return null;
  const u = isUTC() || (typeof t === 'string' && DAY_RE.test(t.trim()));
  return u
    ? { y: d.getUTCFullYear(), mo: d.getUTCMonth(), d: d.getUTCDate(), wd: d.getUTCDay(), h: d.getUTCHours(), mi: d.getUTCMinutes(), s: d.getUTCSeconds() }
    : { y: d.getFullYear(), mo: d.getMonth(), d: d.getDate(), wd: d.getDay(), h: d.getHours(), mi: d.getMinutes(), s: d.getSeconds() };
}
const thisYear = () => parts(Date.now()).y;

// "7 Nov" (this year) or "7 Nov 2025". opts.year: true to always show it; opts.weekday: 'short' | 'long'.
export function date(t, opts = {}) {
  const p = parts(t);
  if (!p) return t ? String(t) : '—';   // text the helper cannot read is shown as it came
  const yr = opts.year === true || (opts.year !== false && p.y !== thisYear());
  const wd = opts.weekday === 'long' ? `${WEEKDAY[p.wd]} ` : opts.weekday ? `${WD[p.wd]} ` : '';
  return `${wd}${p.d} ${opts.month === 'long' ? MONTH[p.mo] : MON[p.mo]}${yr ? ` ${p.y}` : ''}`;
}
// "Nov 2026": a calendar month ("2026-11") or the month of a moment.
export function monthYear(t) {
  const p = /^\d{4}-\d{2}$/.test(String(t)) ? parts(`${t}-01`) : parts(t);
  return p ? `${MON[p.mo]} ${p.y}` : '—';
}
// "Tuesday 10 November", for mastheads and day headings.
export const longDate = (t = Date.now()) => date(t, { weekday: 'long', month: 'long' });
// "14:02" (24-hour), or "14:02:09" with seconds.
export function time(t, opts = {}) {
  const p = parts(t);
  if (!p) return '—';
  return `${pad(p.h)}:${pad(p.mi)}${opts.seconds ? `:${pad(p.s)}` : ''}`;
}
// "7 Nov 14:02" (year added for another year); opts.zone adds the zone name ("7 Nov 14:02 UTC").
export function stamp(t, opts = {}) {
  const d = toDate(t);
  if (!d) return t ? String(t) : '—';
  return `${date(d, opts)} ${time(d, opts)}${opts.zone ? ` ${zoneName(d)}` : ''}`;
}
// The short form for lists: "14:02" today, "Sat 14:02" this week, "7 Nov 14:02" before that.
export function when(t, opts = {}) {
  const d = toDate(t);
  if (!d) return '—';
  const days = dayDiff(d);
  const tz = opts.zone ? ` ${zoneName(d)}` : '';
  if (days === 0) return `${time(d, opts)}${tz}`;
  if (days > 0 && days < 7) return `${WD[parts(d).wd]} ${time(d, opts)}${tz}`;
  return stamp(d, opts);
}
// Calendar-day label: "today", "yesterday", "Sat", or "7 Nov".
export function dayLabel(t) {
  const d = toDate(t);
  if (!d) return '';
  const days = dayDiff(d);
  if (days === 0) return 'today';
  if (days === 1) return 'yesterday';
  if (days > 1 && days < 7) return WD[parts(d).wd];
  return date(d);
}
// The calendar day a moment falls on in the chosen zone, as "YYYY-MM-DD" (for grouping by day).
export function dayKey(t) {
  const p = parts(t);
  return p ? `${p.y}-${pad(p.mo + 1)}-${pad(p.d)}` : '';
}
// Whole calendar days between a moment and today, in the chosen zone (0 = today, 1 = yesterday).
export function dayDiff(t, now = Date.now()) {
  const a = dayKey(t), b = dayKey(now);
  if (!a || !b) return NaN;
  return Math.round((Date.parse(`${b}T00:00:00Z`) - Date.parse(`${a}T00:00:00Z`)) / 864e5);
}
// "3m ago", "5h ago", "3d ago": whole units, rounded down, the same everywhere.
export function ago(t, now = Date.now()) {
  const d = toDate(t);
  if (!d) return '—';
  const s = (now - d.getTime()) / 1000;
  if (s < 0) return 'now';
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
// A tooltip that spells it out with the zone: "Sat 7 Nov 2026 14:02:09 UTC".
export const full = (t) => (toDate(t) ? `${date(t, { weekday: 'short', year: true })} ${time(t, { seconds: true })} ${zoneName(t)}` : '');
// A range "7 Nov 14:00–18:00" / "3 Nov – 5 Nov".
export function span(a, b) {
  const da = toDate(a), db = toDate(b);
  if (!da || !db) return '—';
  if (db - da >= 2 * 864e5) return `${date(da)} – ${date(db)}`;
  if (dayKey(da) === dayKey(db)) return `${date(da)} ${time(da)}–${time(db)}`;
  return `${stamp(da)} – ${stamp(db)}`;
}

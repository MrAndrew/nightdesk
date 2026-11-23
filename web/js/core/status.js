// The phone health pill and the Status sheet (v1.2 mobile, m-shell: design.md §3 "Top bar", §4.12).
//
//   health() -> Promise<{ state, label, aria, logs, sources, offline, alerts, demo }>
//     One state, in priority order (never an alert count):
//       'stale'   Logs stale       your newest log record is older than its stale threshold (/api/netlog/freshness)
//       'errors'  N source errors  sources that are on report an error or are reconnecting (/api/sources)
//       'offline' Offline          OSINTHUB_OFFLINE=1 (/api/health), or the live connection to the server is down
//       'ok'      Healthy
//     aria states it in full ("Logs stale: newest record 5 days ago").
//   mountPill(button, onPaint?) -> refresh()   keeps a pill painted (live events, page changes, a slow poll); a tap opens the sheet
//   openStatus(opener)               the Status sheet: Your logs, Sources, Offline mode, Demo data, Network alerts
// Phone only (the pill lives in the phone top bar, core/mshell.js); desktop keeps the top-bar feed dot and badge.
// Contract: okf/architecture/phone.md#phone-shell
import { api } from './api.js';
import { live } from './live.js';
import { esc, debounce } from './util.js';
import { openSheet, confirmSheet, navigateFromSheet } from './sheet.js';

const safe = (p) => p.then((v) => v, () => null);
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
// "5 days ago", "3 hours ago", "12 minutes ago" (whole units, rounded down, as everywhere else)
export function agoWords(s) {
  if (s == null || !Number.isFinite(+s)) return '';
  s = Math.max(0, +s);
  if (s < 3600) return `${plural(Math.max(1, Math.floor(s / 60)), 'minute')} ago`;
  if (s < 172800) return `${plural(Math.floor(s / 3600), 'hour')} ago`;
  return `${plural(Math.floor(s / 86400), 'day')} ago`;
}

export async function health() {
  const [hl, fresh, srcs, count] = await Promise.all([
    safe(api.get('/api/health')), safe(api.get('/api/netlog/freshness')), safe(api.sources()), safe(api.get('/api/netlog/alerts/count')),
  ]);
  const offline = !!hl?.offline;
  const down = !hl || live.status().state === 'offline' && !offline;
  const list = Array.isArray(srcs) ? srcs : srcs?.sources || [];
  const on = list.filter((s) => s.enabled && !s.unavailable);
  const bad = offline ? [] : on.filter((s) => ['error', 'reconnecting'].includes(s.status));
  const staleSrc = (fresh?.sources || []).filter((s) => s.stale);
  const logs = fresh ? {
    stale: staleSrc.length > 0,
    newest: fresh.newest || null,
    age: fresh.age_s ?? null,
    ago: agoWords(fresh.age_s),
    staleSources: staleSrc.map((s) => s.label),
    any: (fresh.sources || []).length > 0,
  } : null;
  const out = { logs, sources: { on: on.length, total: list.length, bad: bad.map((s) => s.name), paused: offline ? on.length : 0 }, offline, down,
    alerts: count, demo: !!(count?.demo_loaded || fresh?.demo?.loaded) };
  if (logs?.stale) Object.assign(out, { state: 'stale', label: 'Logs stale', aria: `Logs stale: newest record ${logs.ago || 'a while ago'}` });
  else if (bad.length) Object.assign(out, { state: 'errors', label: plural(bad.length, 'source error'), aria: `${plural(bad.length, 'source')} with an error: ${bad.slice(0, 3).map((s) => s.name).join(', ')}${bad.length > 3 ? ' and more' : ''}` });
  else if (offline || down) Object.assign(out, { state: 'offline', label: 'Offline', aria: down && !offline ? 'Offline: lost the connection to the Night Desk server' : 'Offline: Night Desk is not fetching sources' });
  else Object.assign(out, { state: 'ok', label: 'Healthy', aria: 'Healthy: logs current, no source errors' });
  return out;
}

// ------------------------------------------------------------------ the pill
let last = null;
export const lastHealth = () => last;
export function mountPill(btn, onPaint) {
  let seq = 0;
  async function refresh() {
    const my = ++seq;
    const h = await health();
    if (my !== seq) return;
    last = h;
    btn.dataset.state = h.state;
    btn.querySelector('.m-pill-t').textContent = h.label;
    btn.setAttribute('aria-label', `${h.aria}. Open the status`);
    onPaint?.(h);
  }
  const soon = debounce(refresh, 800);
  for (const t of ['netlog_alerts', 'source', 'marker']) { try { live.on(t, soon); } catch { /* no live hub */ } }
  live.onStatus?.(soon);
  window.addEventListener('hashchange', soon);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) soon(); });
  setInterval(() => { if (!document.hidden) refresh(); }, 60000);
  btn.addEventListener('click', (e) => { e.preventDefault(); openStatus(btn); });
  refresh();
  return refresh;
}

// ------------------------------------------------------------------ the Status sheet
const CHEV = '<svg class="i m-st-go" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const dot = (s) => `<span class="m-st-dot" data-s="${s}" aria-hidden="true"></span>`;
function row({ href, state, title, detail, extra = '' }) {
  const inner = `${dot(state)}<span class="m-st-main"><span class="m-st-t">${esc(title)}</span><span class="m-st-d">${detail}</span>${extra}</span>`;
  return href ? `<a class="m-st-row" href="${esc(href)}" data-go="${esc(href)}">${inner}${CHEV}</a>` : `<div class="m-st-row">${inner}</div>`;
}

export async function openStatus(opener) {
  const box = document.createElement('div');
  box.className = 'm-st';
  box.innerHTML = '<p class="m-st-wait">Checking…</p>';
  const sheet = openSheet({
    id: 'status', title: 'Status', body: box,
    footer: '<p class="m-st-foot">Night Desk runs on your home server. Away from home this page can\'t connect unless you use your own VPN.</p>',
  });
  const h = last = await health();
  if (!box.isConnected) return sheet;
  const L = h.logs, S = h.sources, A = h.alerts;
  const rows = [];
  rows.push(row({ href: '#network/overview', state: !L || !L.any ? 'off' : L.stale ? 'warn' : 'ok', title: 'Your logs',
    detail: !L ? 'Could not check your logs.' : !L.any ? 'No logs connected yet.' : `${L.stale ? 'Stale' : 'Current'} · newest record ${esc(L.ago || 'unknown')}` }));
  rows.push(row({ href: '#settings/sources', state: S.bad.length ? 'warn' : h.offline ? 'off' : 'ok', title: 'Sources',
    detail: S.bad.length ? `${esc(plural(S.bad.length, 'error'))}: ${esc(S.bad.slice(0, 3).join(', '))}${S.bad.length > 3 ? '…' : ''}`
      : h.offline ? `${S.paused} paused while offline` : `${S.on} on, none failing` }));
  rows.push(row({ state: h.offline ? 'off' : 'ok', title: 'Offline mode',
    detail: h.offline ? 'On: Night Desk isn\'t fetching anything new. Everything already collected still works.' : h.down ? 'Lost the connection to the server; retrying.' : 'Off: sources update on their schedules.',
    extra: h.offline ? '<details class="m-st-tech"><summary>Technical details</summary><p>The server was started with <code>OSINTHUB_OFFLINE=1</code>. Restart it without that setting to fetch again.</p></details>' : '' }));
  if (h.demo) {
    rows.push(row({ state: 'ok', title: 'Demo data', detail: 'Loaded. Its alerts are marked DEMO and never count as needing you.',
      extra: '<button type="button" class="m-btn m-st-rm" data-act="demo-remove">Remove…</button>' }));
  }
  const n = A?.needs_you ?? null;
  rows.push(row({ href: '#network/alerts', state: n ? 'warn' : 'ok', title: 'Network alerts',
    detail: A == null ? 'Could not check.' : n ? `${plural(n, 'alert')} need${n === 1 ? 's' : ''} you` : A.demo ? `None need you · ${A.demo} demo` : 'None need you' }));
  box.innerHTML = rows.join('');
  box.addEventListener('click', async (e) => {
    const a = e.target.closest('[data-go]');
    if (a) { e.preventDefault(); navigateFromSheet(a.dataset.go); return; }
    const rm = e.target.closest('[data-act="demo-remove"]');
    if (!rm) return;
    const ok = await confirmSheet({ title: 'Remove the demo data?', text: 'Its made-up devices, logs and alerts go away. Your own logs are not touched.', confirm: 'Remove demo', danger: true });
    if (!ok) return;
    rm.disabled = true; rm.textContent = 'Removing…';
    try {
      await api.del('/api/netlog/demo');
      rm.closest('.m-st-row')?.remove();
    } catch (err) { rm.disabled = false; rm.textContent = 'Remove…'; rm.after(Object.assign(document.createElement('p'), { className: 'm-st-err', textContent: `Couldn't remove it: ${err.message}` })); }
  });
  return sheet;
}

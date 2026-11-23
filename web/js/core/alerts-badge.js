// Top-bar badge (and the phone tab bar's Network badge): the one alert count, "needs you" (untriaged, not expected, non-demo incidents of high + medium
// severity), coloured by the worst of them, linking to Network > Alerts. Low, info, demo and expected are in the
// tooltip only and never turn it red. Updated by the live topic `netlog_alerts` (triage and rule changes publish
// it too), on view changes and by a slow poll. Hidden when the netlog package is not installed.
// Contract: okf/architecture/web-client.md#alerts-badge, count rule: okf/data/netlog.md#the-needs-you-count
import { api } from './api.js';
import { debounce } from './util.js';

// Only demo incidents are open (none of yours needs you): every count reads "Demo · N" / "No real alerts · N demo"
// in the neutral demo style, never red and never "No alerts" or "Nothing needs you" above visible demo rows. Real
// incidents always win. Used by the badge, the Network header, Alerts, Overview and the Ops network panel.
export const demoOnly = (n) => !!n && !n.needs_you && (n.demo || 0) > 0;
export const noRealText = (n) => `No real alerts · ${n.demo} demo`;

// The shared count words (okf/data/netlog.md#the-needs-you-count). Every place that shows an alert number says which
// of these it is, in visible text, unless it is the Alerts tab / list "New" number (open), which shows bare:
//   needs you  untriaged, not expected, not demo, high + medium   (badge, Network header, Overview card)
//   demo       untriaged demo alerts, any severity                 (badge and header when only the demo has some)
//   new        every untriaged alert, any severity, demo included  (Alerts tab = the list's "New" chip, same range)
// Watch's "Your network" number is the needs-you alerts new since the last visit, and says so.
export function badgeText(n) {
  if (n.needs_you) return `${n.needs_you} need${n.needs_you === 1 ? 's' : ''} you`;
  if (demoOnly(n)) return `${n.demo} demo`;
  return 'none need you';
}

// Devices: one split used by the Network header, Overview and the Devices list (net/devices.js does the same by
// hand): "known" = named or identified devices plus any address with an alert; "unidentified" = short-lived
// addresses with nothing to name them and no alert (Devices folds them away). known + unidentified = every device.
export function deviceSplit(devs) {
  let known = 0, unid = 0;
  for (const d of devs) { if (d.fragment && !d.alerts) unid++; else known++; }
  return { known, unid, total: known + unid };
}

// The last /api/netlog/alerts/count the badge read (null before the first, or when the network part is missing).
// The Help desk reads demo_loaded from it to offer "Remove demo data" instead of "Load demo data".
let last = null;
export const lastCount = () => last;

// The phone tab bar's Network badge (#m-tabbar, core/page.js): the same needs-you number (open high and medium
// alerts, demo and expected excluded); none when it is 0. Its tab says the number in its name.
function paintTab(n) {
  const tab = document.querySelector('#m-tabbar [data-tab="network"]');
  const b = tab?.querySelector('.m-tab-badge');
  if (!b) return;
  b.hidden = !n;
  b.textContent = n ? String(n) : '';
  tab.setAttribute('aria-label', n ? `Network, ${n} alert${n === 1 ? '' : 's'} need${n === 1 ? 's' : ''} you` : 'Network');
}

export function setupAlertsBadge({ live }) {
  const el = document.getElementById('al-badge');
  if (!el) return;
  let gone = false;
  async function load() {
    if (gone) return;
    try {
      const n = await api.get('/api/netlog/alerts/count');
      last = n;
      const top = n.high ? 'high' : n.medium ? 'medium' : 'none';
      const demo = demoOnly(n);
      el.hidden = false;
      el.dataset.top = top;
      // never a bare "0": a calm "No alerts" when nothing needs you, "Demo · N" when only the demo has alerts open
      el.classList.toggle('al-calm', !n.needs_you && !demo);
      el.classList.toggle('finisha-demo', demo);
      // "Alerts" stays visible (.al-l) and the number always carries its word: "3 need you", "14 demo", "none need you"
      el.querySelector('.al-sev').innerHTML = n.needs_you ? `<span class="al-n ${top}"><i></i>${badgeText(n)}</span>`
        : demo ? `<span class="al-n none finisha-demo-n">${badgeText(n)}</span>` : `<span class="al-n none al-none">${badgeText(n)}</span>`;
      const rest = [n.low && `${n.low} low`, n.info && `${n.info} info`, n.demo && `${n.demo} demo`, n.expected && `${n.expected} expected`].filter(Boolean);
      el.title = `${n.needs_you ? `${n.needs_you} alert${n.needs_you === 1 ? '' : 's'} need${n.needs_you === 1 ? 's' : ''} you` : demo ? `No real alerts: ${n.demo} open alert${n.demo === 1 ? ' comes' : 's come'} from the demo data` : 'Nothing needs you'} (untriaged high and medium: ${n.high} high, ${n.medium} medium)${rest.length ? `\nNot counted: ${rest.join(', ')}` : ''}${n.open != null ? `\n${n.open} new (untriaged) in all, as in Network › Alerts` : ''}\nClick to open Network › Alerts`;
      paintTab(n.needs_you || 0);
      el.setAttribute('aria-label', n.needs_you ? `${n.needs_you} network alert${n.needs_you === 1 ? '' : 's'} need${n.needs_you === 1 ? 's' : ''} you (${n.high} high, ${n.medium} medium)`
        : demo ? `No real network alerts; ${n.demo} demo alert${n.demo === 1 ? '' : 's'} open` : 'No network alerts need you');
    } catch (e) {
      if (/not found/i.test(e.message)) { gone = true; el.hidden = true; }
    }
  }
  const soon = debounce(load, 600);
  live.on('netlog_alerts', soon);
  live.on('status', (ok) => { if (ok) soon(); });
  window.addEventListener('hashchange', soon);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) soon(); });
  let tick = 0;
  setInterval(() => { tick++; if (!document.hidden && (document.body.classList.contains('nv-active') || tick % 2 === 0)) load(); }, 30000);
  el.addEventListener('click', (e) => {
    e.preventDefault();
    if (location.hash === '#network/alerts') window.dispatchEvent(new HashChangeEvent('hashchange'));
    else location.hash = '#network/alerts';
  });
  load();
}

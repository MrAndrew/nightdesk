// The phone shell (v1.2 mobile, m-shell: design.md §3, §4.12, mock-watch.png, mock-more.png). Phones only
// (core/mobile.js isPhone()); nothing here touches the desktop page: the phone parts of the top bar are created the
// first time the phone layout applies and are [hidden] whenever it does not.
//
//   initPhoneShell({ titles })   called once by core/shell.js boot()
//
// The top bar: root pages show [lamp] [view title] … [health pill] [search]; pushed pages (core/page.js isPushed)
// show [‹ Parent] [title]. The view's own header title and purpose (.vh) give way to it (CSS m:shell). The title and
// Back label come from page.setPhoneTitle() when a view sets them, else from the route (Alert, Device, Story…).
// The tab bar's More opens the More sheet (Ops, Notes, Cinema, SQL console; Sources & health, Settings, Help, the
// tour). The health pill and its Status sheet are core/status.js. Contract: okf/architecture/phone.md#phone-shell
import { isPhone, onPhoneChange } from './mobile.js';
import { back, onMore, parentOf, isPushed, phoneTitle, onRoute } from './page.js';
import { openSheet, navigateFromSheet } from './sheet.js';
import { mountPill, lastHealth } from './status.js';
import { esc } from './util.js';
import { sqlConsoleOn } from './api.js';

const svg = (d, cls = 'i') => `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true">${d}</svg>`;
const use = (id) => `<svg class="i" aria-hidden="true"><use href="#${id}"/></svg>`;
const CHEV_L = svg('<path d="M15 5l-7 7 7 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>');
const CHEV_R = svg('<path d="M9 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>', 'i m-more-go');
const BOOK = svg('<path d="M4 5.5C6.5 4.5 9.5 4.5 12 6c2.5-1.5 5.5-1.5 8-.5V19c-2.5-1-5.5-1-8 .5-2.5-1.5-5.5-1.5-8-.5z M12 6v13.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>');

const pathOf = (hash) => String(hash || '').replace(/^#\/?/, '').split('?')[0].replace(/\/+$/, '');
// the title of a pushed page when its view did not set one
function routeTitle(hash, titles) {
  const p = pathOf(hash).toLowerCase();
  if (/^network\/alerts\/rules$/.test(p)) return 'Expected traffic';
  if (/^network\/alerts\/[^/]+\/expected$/.test(p)) return 'Mark as expected';
  if (/^network\/alerts\/[^/]+$/.test(p)) return 'Alert';
  if (/^network\/devices\/[^/]+$/.test(p)) return 'Device';
  if (/^news\/story\//.test(p)) return 'Story';
  if (/^news\/article\//.test(p)) return 'Article';
  if (/^settings\/sources$/.test(p)) return 'Sources';
  if (/^settings\/.+$/.test(p)) {
    const sec = document.querySelector('#view-settings .set-nav [aria-current], #view-settings .set-sec:not([hidden]) h2');
    return sec?.textContent?.trim() || 'Settings';
  }
  if (/^ops$/.test(p) && /[?&]panel=/.test(hash)) return 'Ops';
  const v = p.split('/')[0];
  return titles[v] || titles[v === 'intel' ? 'entities' : ''] || 'Night Desk';
}
// the ‹ label for a parent route
export function parentLabel(hash, titles = {}) {
  const p = pathOf(hash).toLowerCase();
  if (p === 'network/alerts') return 'Alerts';
  if (p === 'network/devices') return 'Devices';
  if (/^network\/alerts\/[^/]+$/.test(p)) return 'Alert';
  if (p === 'entities') return 'Intel';
  return titles[p.split('/')[0]] || 'Back';
}

let T = {};
let bar = null, ttl = null, backBtn = null, pill = null, built = false;

function build() {
  if (built) return;
  built = true;
  const top = document.querySelector('.topbar');
  const brand = top?.querySelector('.brand');
  if (!top || !brand) return;
  backBtn = Object.assign(document.createElement('button'), { type: 'button', className: 'm-tb-back', hidden: true });
  backBtn.innerHTML = `${CHEV_L}<span class="m-tb-back-t"></span>`;
  backBtn.addEventListener('click', (e) => { e.preventDefault(); back(backBtn.dataset.href || undefined); });
  ttl = Object.assign(document.createElement('span'), { className: 'm-tb-title', hidden: true });
  ttl.setAttribute('role', 'heading');
  ttl.setAttribute('aria-level', '1');
  pill = Object.assign(document.createElement('button'), { type: 'button', className: 'm-pill', hidden: true });
  pill.setAttribute('aria-haspopup', 'dialog');
  pill.innerHTML = '<span class="m-pill-dot" aria-hidden="true"></span><span class="m-pill-t">Checking</span>';
  brand.after(backBtn, ttl);
  (top.querySelector('#gs') || brand).before(pill);
  mountPill(pill, () => paint());
  bar = top;
}

function paint() {
  const phone = isPhone();
  if (phone) build();
  if (!bar) return;
  const pushed = phone && isPushed();
  const t = phoneTitle();
  const parent = t?.back?.href || parentOf();
  backBtn.hidden = !pushed;
  if (pushed) {
    const label = t?.back?.label || parentLabel(parent, T);
    backBtn.dataset.href = parent || '';
    backBtn.querySelector('.m-tb-back-t').textContent = label;
    backBtn.setAttribute('aria-label', `Back to ${label}`);
  }
  ttl.hidden = !phone;
  ttl.textContent = t?.title || routeTitle(location.hash, T);
  pill.hidden = !phone || pushed || !pill.dataset.state;
}

// ------------------------------------------------------------------ the More sheet
const PLACES = [
  ['#ops', 'i-ops', 'Ops', 'summary'],
  ['#notes', 'i-note', 'Notes', ''],
  ['#cinema', 'i-globe', 'Cinema', 'last 24h'],
  ['#explorer', 'i-code', 'SQL console', 'examples'],
];
function sourcesHint() {
  const h = lastHealth();
  if (!h) return '';
  if (h.sources.bad.length) return `${h.sources.bad.length} error${h.sources.bad.length === 1 ? '' : 's'}`;
  if (h.offline && h.sources.paused) return `${h.sources.paused} paused`;
  return '';
}
function moreRow({ href, icon, label, hint = '', act = '', current = false, go = true }) {
  const inner = `${icon}<span class="m-act-l">${esc(label)}</span>${hint ? `<span class="m-act-h">${esc(hint)}</span>` : ''}${go ? CHEV_R : ''}`;
  return href
    ? `<a class="m-act m-more-row" href="${esc(href)}" data-go="${esc(href)}"${current ? ' aria-current="page"' : ''}>${inner}</a>`
    : `<button type="button" class="m-act m-more-row" data-act="${esc(act)}">${inner}</button>`;
}
function openMore(btn) {
  const here = pathOf(location.hash).toLowerCase();
  const cur = (href) => here === pathOf(href).toLowerCase();
  const body = document.createElement('div');
  body.className = 'm-moresheet';
  body.innerHTML = `<p class="m-more-h">Places</p><div class="m-acts">${PLACES.filter(([href]) => href !== '#explorer' || sqlConsoleOn()).map(([href, i, label, hint]) => moreRow({ href, icon: use(i), label, hint, current: cur(href) })).join('')}</div>
    <p class="m-more-h">Desk</p><div class="m-acts">
      ${moreRow({ href: '#settings/sources', icon: use('i-layers'), label: 'Sources & health', hint: sourcesHint(), current: cur('#settings/sources') })}
      ${moreRow({ href: '#settings', icon: use('i-gear'), label: 'Settings', current: cur('#settings') })}
      ${moreRow({ act: 'help', icon: use('i-help'), label: 'Help' })}
      ${moreRow({ act: 'tour', icon: BOOK, label: 'Take the tour', go: false })}
    </div>`;
  btn.setAttribute('aria-expanded', 'true');
  const sheet = openSheet({ id: 'more', label: 'More', body, footer: '<p class="m-more-foot">Night Desk 1.2 · your home server</p>',
    onClose: () => btn.setAttribute('aria-expanded', 'false') });
  sheet.el.classList.add('m-more-sheet');
  body.addEventListener('click', async (e) => {
    const a = e.target.closest('[data-go]');
    if (a) { e.preventDefault(); navigateFromSheet(a.dataset.go); return; }
    const b = e.target.closest('[data-act]');
    if (!b) return;
    await sheet.close('api');
    if (b.dataset.act === 'help') import('./help.js').then((m) => m.openHelp('page', { opener: btn }));
    else import('./tour.js').then((m) => { if (m.startTour('page') === false) import('./util.js').then((u) => u.toast('This page has no tour yet')); })
      .catch((err) => console.warn('tour not loaded:', err.message));
  });
}

export function initPhoneShell({ titles = {} } = {}) {
  T = titles;
  onMore(openMore);
  window.addEventListener('nd:page', paint);
  onRoute(() => paint());
  window.addEventListener('hashchange', () => requestAnimationFrame(paint));
  onPhoneChange(() => paint());
  paint();
  // a settings section's name is on screen only once the view painted it
  setTimeout(paint, 600);
}

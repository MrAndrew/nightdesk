// Pages, Back, the tab bar and the overlay stack (v1.2 mobile, Phase 0; contract: okf/architecture/web-client.md
// "Phone contract"). Loaded by index.html before main.js, so it sees every entry the app makes.
//
// The browser's Back and Forward move between URL pages only. Overlays (phone sheets, a maximised panel, the note
// sheet) never get a history entry of their own: they live on an in-memory stack here, close with their own ×, Esc
// (the top one only) or a tap outside, and all close when the page changes (Back, Forward, a link, code).
//
//   pushPage(hash)            open a page (a new entry; a different query on the same path replaces the entry)
//   replaceTo(hash)           show hash in the current entry (+ a hashchange); when the entry behind is that page,
//                             history.back() instead, so no two neighbouring entries show one page
//   back(parent?)             the ‹ Parent button: lands on the parent (default parentOf(location.hash)) and never
//                             leaves the app: history.back() when the entry behind (made in this page load) is the
//                             parent, otherwise the current entry is replaced by the parent (history.length unchanged)
//   parentOf(hash) / isPushed(hash) / addParentRule(re, parent) / tabOf(hash) / tabRoot(tab) / tabTap(tab)
//   depth()                   in-app entries behind this one (0 = a pasted link, a notification, a fresh tab)
//   setPhoneTitle(title, { back: { label, href } } | null) / phoneTitle() / setActionBar(nodes | null)
//   afterRender(viewId)       restore this entry's scrollY after Back/Forward (±10 px), once the view's rows exist
//   setEntryState(obj) / entryState()   per-entry UI state (e.g. a "Show more" count), restored before scrollY
//   onMore(fn)                the tab bar's More button calls fn(button) (core/mshell.js: the More sheet)
//   onRoute(cb) -> off        cb({ kind: 'new' | 'traverse' | 'replace', hash, depth }) after each page change
//   overlayOpened({ kind, close(reason), hash? }) -> token,  closeOverlay(token, reason, { run = true }),
//   topOverlay()              the overlay stack (Esc order, close on page change)
//   addLayer(selector, close) an in-view full-screen layer opened by a class (a maximised panel): it gets a visible
//                             Close button at every width, and on a phone sits on the overlay stack
//   addPopup(selector, isOpen(el), close(el))  a dialog or popover a module appends to <body> (Copy summary, the
//                             Intel "Same as…" popover, the deck-name dialog): on the overlay stack while open, at
//                             every width, so Esc closes it in order and a page change closes it
// Events on window: `nd:page` (detail: { title, back, actionBar, pushed }) whenever any of that changes.

import { isPhone, onPhoneChange } from './mobile.js';
import { reducedMotion as reduced } from './util.js';

const H = window.history;
const origPush = H.pushState.bind(H);
const origReplace = H.replaceState.bind(H);
const newKey = () => Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
const plain = (s) => (s && typeof s === 'object' && !Array.isArray(s) ? s : null);
// '#/network/alerts/x?range=7d' -> 'network/alerts/x'
const pathOf = (hash) => String(hash || '').replace(/^#\/?/, '').split('?')[0].replace(/\/+$/, '');
const queryOf = (hash) => { const i = String(hash || '').indexOf('?'); return i < 0 ? '' : hash.slice(i + 1); };
// one page = one path, except #ops?panel=<id>, a pushed page of its own over #ops (m-desk)
const pageKey = (hash) => { const p = pathOf(hash), m = /^ops$/i.test(p) && queryOf(hash).match(/(?:^|&)panel=([^&]*)/); return m ? `${p}?panel=${m[1]}` : p; };
const samePath = (a, b) => a != null && b != null && pageKey(a) === pageKey(b);

// ------------------------------------------------------------------ routes: parents, tabs, roots
const RULES = [
  [/^network\/alerts\/rules$/i, '#network/alerts'],
  [/^network\/alerts\/([^/]+)\/expected$/i, (m) => `#network/alerts/${m[1]}`],
  [/^network\/alerts\/[^/]+$/i, '#network/alerts'],
  [/^network\/devices\/[^/]+$/i, '#network/devices'],
  [/^news\/story\/.+$/i, '#news'],
  [/^news\/article\/.+$/i, '#news'],
  [/^entities\/(?!graph(?:\/|$)|review$|type\/|metro(?:[/?]|$)).+$/i, '#entities'],
  [/^settings\/.+$/i, '#settings'],
];
export function addParentRule(re, parent) { RULES.unshift([re, parent]); }
export function parentOf(hash = location.hash) {
  const p = pathOf(hash);
  if (p.toLowerCase() === 'ops' && /(?:^|&)panel=/.test(queryOf(hash))) return '#ops';
  for (const [re, to] of RULES) {
    const m = p.match(re);
    if (m) return typeof to === 'function' ? to(m, hash) : to;
  }
  return null;
}
export const isPushed = (hash = location.hash) => parentOf(hash) != null;

const TABS = new Set(['watch', 'network', 'news', 'entities']);
export function tabOf(hash = location.hash) {
  const v = pathOf(hash).split('/')[0].toLowerCase();
  if (v === 'help') return null;
  if (v === 'intel') return 'entities';
  if (TABS.has(v)) return v;
  return v ? 'more' : 'watch';
}
const NET_SUBS = new Set(['alerts', 'devices', 'overview', 'hunt', 'import']);
const SS = { get(k) { try { return sessionStorage.getItem(k); } catch { return null; } }, set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* private mode */ } } };
function rememberSubTab(hash) {
  const [v, sub, more] = pathOf(hash).toLowerCase().split('/');
  if (v === 'network' && NET_SUBS.has(sub) && !more) SS.set('nd.m.netTab', sub);
}
export function tabRoot(tab) {
  switch (tab) {
    case 'watch': return '#watch';
    case 'network': {
      const last = SS.get('nd.m.netTab');
      if (last && NET_SUBS.has(last)) return `#network/${last}`;
      return document.querySelector('#al-badge .al-n:not(.none)') ? '#network/alerts' : '#network/overview';
    }
    case 'news': return '#news';
    case 'entities': case 'intel': return '#entities';
    case 'more': return null;
    default: return tab ? `#${tab}` : '#watch';
  }
}

// ------------------------------------------------------------------ the entries of this page load
// Each entry carries ndKey (scroll and per-entry state are kept per key) and ndDepth in history.state; pushState
// and replaceState are wrapped so views keep calling them as before. `list` is this page load's own entries in
// history order: back() only steps onto an entry it knows is the parent.
let cur = { key: null, depth: 0, hash: location.hash };
const list = [];
let pos = -1;
const routeSubs = new Set();
export const depth = () => cur.depth;
export function onRoute(cb) { routeSubs.add(cb); return () => routeSubs.delete(cb); }
const stamp = (base, key, d, entry) => {
  const s = { ...(plain(base) || {}), ndKey: key, ndDepth: d };
  if (entry) s.ndEntry = entry; else delete s.ndEntry;
  return s;
};
function note(how) {
  if (how === 'push') { list.length = pos + 1; list.push({ key: cur.key, hash: location.hash }); pos = list.length - 1; }
  else if (how === 'traverse') { pos = list.findIndex((x) => x.key === cur.key); if (pos >= 0) list[pos].hash = location.hash; }
  else if (pos >= 0) list[pos] = { key: cur.key, hash: location.hash };
}
if (!H.__ndWrapped) {
  H.__ndWrapped = true;
  H.pushState = function (state, title, url) {
    saveScroll();
    cur = { key: newKey(), depth: cur.depth + 1 };
    origPush(stamp(state, cur.key, cur.depth), title ?? '', url);
    cur.hash = location.hash;
    note('push');
    urlMoved();
  };
  H.replaceState = function (state, title, url) {
    const now = plain(H.state) || {};
    const st = plain(state);
    const key = now.ndKey || cur.key || newKey();
    origReplace(stamp(state, key, now.ndDepth ?? cur.depth, st && 'ndEntry' in st ? st.ndEntry : now.ndEntry), title ?? '', url);
    cur = { key, depth: now.ndDepth ?? cur.depth, hash: location.hash };
    note('replace');
    urlMoved();
  };
}
try { H.scrollRestoration = 'manual'; } catch { /* old browsers */ }
(function adopt() {
  const s = plain(H.state);
  if (s?.ndKey) cur = { key: s.ndKey, depth: s.ndDepth | 0, hash: location.hash };
  else { cur = { key: newKey(), depth: 0, hash: location.hash }; origReplace(stamp(s, cur.key, 0), '', location.href); }
  list.push({ key: cur.key, hash: location.hash });
  pos = 0;
})();
// after a popstate or hashchange: which entry are we on now?
function track() {
  const s = plain(H.state);
  if (s?.ndKey && s.ndKey === cur.key) {
    if (location.hash === cur.hash) return null;
    cur.hash = location.hash; note('replace'); return 'replace';
  }
  if (s?.ndKey) { cur = { key: s.ndKey, depth: s.ndDepth | 0, hash: location.hash }; note('traverse'); return 'traverse'; }
  // a new entry made by a link or `location.hash = …`
  cur = { key: newKey(), depth: cur.depth + 1, hash: location.hash };
  origReplace(stamp(s, cur.key, cur.depth), '', location.href);
  note('push');
  return 'new';
}

// ------------------------------------------------------------------ scroll per entry (phone: the document scrolls)
const scrolls = new Map();
let pending = null;       // { key, y, view, until }
function saveScroll() { if (cur.key && !(pending && pending.key === cur.key)) scrolls.set(cur.key, Math.round(window.scrollY)); }
let scrollQueued = false;
window.addEventListener('scroll', () => {
  if (scrollQueued) return;
  scrollQueued = true;
  requestAnimationFrame(() => { scrollQueued = false; saveScroll(); });
}, { passive: true });
function tryRestore() {
  if (!pending) return;
  if (pending.key !== cur.key || performance.now() > pending.until) { pending = null; return; }
  window.scrollTo({ top: pending.y, left: 0, behavior: 'instant' });
  if (Math.abs(window.scrollY - pending.y) <= 2) pending = null;
}
// the user takes over: stop restoring
for (const ev of ['touchstart', 'wheel', 'keydown', 'pointerdown']) window.addEventListener(ev, () => { pending = null; }, { passive: true, capture: true });
// a view grows as its rows arrive: try again each time the page changes size, until the place is reached
if (typeof ResizeObserver === 'function') {
  const ro = new ResizeObserver(() => tryRestore());
  const watch = () => { if (document.body) ro.observe(document.body); };
  if (document.body) watch(); else document.addEventListener('DOMContentLoaded', watch, { once: true });
}
const viewOf = (hash) => pathOf(hash).split('/')[0].toLowerCase() || null;
function restoreFor(key) {
  const y = scrolls.get(key);
  if (y == null || !isPhone()) return;
  pending = { key, y, view: viewOf(location.hash), until: performance.now() + 4000 };
  requestAnimationFrame(() => requestAnimationFrame(tryRestore));
}
export function afterRender(viewId) {
  if (!pending || (viewId && pending.view && viewId !== pending.view)) return;
  tryRestore();
  requestAnimationFrame(tryRestore);
}
export function entryState() { return { ...(plain(plain(H.state)?.ndEntry) || {}) }; }
export function setEntryState(obj) {
  const s = plain(H.state) || {};
  origReplace({ ...s, ndEntry: { ...(plain(s.ndEntry) || {}), ...(plain(obj) || {}) } }, '', location.href);
}

// ------------------------------------------------------------------ title and action bar (the phone chrome)
let title = null;
let actNodes = null;
function emit() {
  const pushed = isPushed();
  // the body classes exist only on a phone: a desktop page's DOM stays exactly as v1.2's
  const phone = isPhone();
  document.body?.classList.toggle('m-pushed', phone && pushed);
  document.body?.classList.toggle('m-actbar-on', phone && !!actNodes);
  document.body?.classList.toggle('m-back', phone && !!title?.back);
  window.dispatchEvent(new CustomEvent('nd:page', { detail: { title: title?.title ?? null, back: title?.back ?? null, actionBar: !!actNodes, pushed } }));
}
export function setPhoneTitle(t, opts = null) {
  title = t == null ? null : { title: String(t), back: opts?.back ? { label: String(opts.back.label || ''), href: opts.back.href || parentOf() } : null };
  emit();
}
export const phoneTitle = () => (title ? { ...title } : null);
export function setActionBar(nodes) {
  const bar = document.getElementById('m-actbar');
  const l = nodes == null ? null : (Array.isArray(nodes) ? nodes : [nodes]).filter(Boolean);
  actNodes = l && l.length ? l : null;
  if (bar) { bar.replaceChildren(...(actNodes || [])); bar.hidden = !actNodes; }
  emit();
}

// ------------------------------------------------------------------ navigation
export function pushPage(hash) {
  if (!hash) return;
  const want = hash.startsWith('#') ? hash : `#${hash}`;
  // already on that page (the shell adds ?range= and the like): no new entry; a different query replaces it
  if (samePath(want, location.hash)) { if (queryOf(want) && want !== location.hash) replaceTo(want); return; }
  location.hash = want;
}
const behindIs = (hash) => pos > 0 && samePath(list[pos - 1].hash, hash);
export function replaceTo(hash) {
  const want = hash.startsWith('#') ? hash : `#${hash}`;
  if (behindIs(want) && !samePath(location.hash, want)) { H.back(); return; }
  const oldURL = location.href;
  saveScroll();
  cur = { key: newKey(), depth: cur.depth };
  origReplace(stamp(null, cur.key, cur.depth), '', want);
  cur.hash = location.hash;
  note('replace');
  routeChanged('replace');
  window.dispatchEvent(new HashChangeEvent('hashchange', { oldURL, newURL: location.href }));
}
export function back(parentHash) { replaceTo(parentHash || parentOf() || tabRoot(tabOf()) || '#watch'); }
export function tabTap(tab) {
  const root = tabRoot(tab);
  if (!root) return;
  const here = location.hash;
  if (tabOf(here) !== tab) pushPage(root);
  else if (isPushed(here)) back(parentOf(here) || root); // a pushed page in this tab: up to its parent
  else if (isPhone()) window.scrollTo({ top: 0, left: 0, behavior: reduced() ? 'instant' : 'smooth' });
}

// ------------------------------------------------------------------ the overlay stack (memory only, no history)
// Sheets (core/sheet.js) and, on a phone, maximised panels register here. Esc closes the top one (one per press);
// a page change closes every overlay opened on another page, top first. An overlay's own × calls closeOverlay.
const overlays = [];
export function overlayOpened({ kind, close, hash = location.hash }) {
  const o = { kind, close, hash };
  overlays.push(o);
  return o;
}
export function closeOverlay(o, reason = 'close', { run = true } = {}) {
  const i = overlays.indexOf(o);
  if (i < 0) return;
  overlays.splice(i, 1);
  if (run) { try { o.close?.(reason); } catch (e) { console.error(e); } }
}
export const topOverlay = () => overlays[overlays.length - 1] || null;
// The one Esc owner (window, capture phase: page.js loads first, so this runs before any view's own handler).
// Not while focus is in the search box / ⌘K palette (its own Esc closes it first); not while the Help desk is open
// unless a sheet is on top (Help keeps v1.2's own Esc handling); and not when the top overlay is a maximised panel
// with the entity panel or the event drawer over it (the view's own Esc closes those first).
window.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape' || !overlays.length || e.defaultPrevented) return;
  if (document.getElementById('gs')?.contains(document.activeElement)) return;
  const top = overlays[overlays.length - 1];
  if (document.body.classList.contains('help-open') && top.kind !== 'sheet') return;
  if (top.kind === 'layer' && document.querySelector('.ep.open, .drawer.open')) return;
  e.preventDefault();
  e.stopImmediatePropagation();
  closeOverlay(top, 'esc');
}, true);
if (window.__ndTest) window.__ndOverlays = () => overlays.map((o) => ({ kind: o.kind, hash: o.hash }));

function routeChanged(kind) {
  scanPopups(); // one opened since the last mutation callback is on the stack before the page change is judged
  for (const o of [...overlays].reverse()) if (!samePath(o.hash, location.hash)) closeOverlay(o, 'route');
  // hover cards and glossary tips belong to the page they were shown on
  document.querySelectorAll('body > .help-tip:not([hidden]), body > .ep-card:not([hidden])').forEach((t) => { t.hidden = true; });
  rememberSubTab(location.hash);
  title = null;
  if (actNodes) setActionBar(null); else emit();
  syncTabBar();
  shownHash = location.hash;
  routeSubs.forEach((cb) => { try { cb({ kind, hash: location.hash, depth: cur.depth }); } catch (e) { console.error(e); } });
}
// a routed sheet (…/expected) opens over its parent page: the page underneath keeps its place
const overSheet = () => /\/expected$/i.test(pathOf(location.hash)) && pos > 0 && samePath(list[pos - 1].hash, parentOf());
function onNav() {
  const before = cur.key, from = cur.hash;
  const kind = track();
  // no kind: nothing new; the same URL (an entry a view or Help pushed for its own state): not a page change
  if (!kind || (kind === 'traverse' && location.hash === from)) return;
  if (before && kind !== 'replace' && !scrolls.has(before)) scrolls.set(before, Math.round(window.scrollY));
  routeChanged(kind);
  if (kind === 'traverse') restoreFor(cur.key);
  else if (kind === 'new' && !overSheet() && isPhone() && window.scrollY) window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
}
// capture phase on window: before every other popstate/hashchange listener (they listen in the bubble phase)
window.addEventListener('popstate', onNav, true);
window.addEventListener('hashchange', onNav, true);

// ------------------------------------------------------------------ in-view full-screen layers (maximised panels)
// Today's views open them by a class, with no route. Each one gets a visible Close button in its head (every
// width), which uses the view's own Restore control so the view's state stays right. On a phone it is also on the
// overlay stack: Esc closes it, and leaving the page closes it.
const LAYERS = [
  { sel: '#grid .panel.maximized', close: (el) => el.querySelector('[data-act="max"]')?.click() },
  { sel: '#view-explorer .ex-pnl.max', close: (el) => el.querySelector('[data-act="max"]')?.click() },
];
export function addLayer(sel, close) { LAYERS.push({ sel, close }); scanLayers(); }
const open = new Map();   // el -> { L, ov }
function closeButton(L, el) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'm-layer-x';
  b.setAttribute('aria-label', 'Close full screen');
  b.title = 'Close full screen';
  b.innerHTML = '<svg class="i" aria-hidden="true"><use href="#i-x"/></svg><span>Close</span>';
  b.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); L.close(el); });
  (el.querySelector('.panel-head') || el).append(b);
}
function scanLayers() {
  const now = new Map();
  for (const L of LAYERS) for (const el of document.querySelectorAll(L.sel)) if (!now.has(el)) now.set(el, L);
  for (const [el, rec] of open) {
    if (now.get(el) === rec.L && document.contains(el)) continue;
    open.delete(el);
    const a = document.activeElement;
    const hadFocus = !a || a === document.body || !!a.closest?.('.m-layer-x');
    el.querySelectorAll(':scope .m-layer-x').forEach((b) => b.remove());
    if (rec.ov) closeOverlay(rec.ov, 'api', { run: false }); // closed by the view's own control
    // focus goes back to the panel's own Expand toggle (the Close button is gone)
    if (hadFocus && document.contains(el)) el.querySelector('[data-act="max"]')?.focus({ preventScroll: true });
  }
  for (const [el, L] of now) {
    let rec = open.get(el);
    if (!rec) { rec = { L, ov: null }; open.set(el, rec); closeButton(L, el); }
    if (isPhone() && !rec.ov) {
      rec.ov = overlayOpened({ kind: 'layer', close: () => { rec.ov = null; try { L.close(el); } catch (e) { console.error(e); } } });
    } else if (!isPhone() && rec.ov) { closeOverlay(rec.ov, 'api', { run: false }); rec.ov = null; }
  }
}
function watchLayers() {
  const v = document.getElementById('views');
  if (!v) return;
  let queued = false;
  new MutationObserver(() => { if (queued) return; queued = true; requestAnimationFrame(() => { queued = false; scanLayers(); }); })
    .observe(v, { subtree: true, attributes: true, attributeFilter: ['class'] });
  scanLayers();
}

// ------------------------------------------------------------------ dialogs and popovers appended to <body>
// Modules that show their own dialog on <body> (not a sheet) are on the overlay stack while it is open, at every
// width: Esc closes the top one through its own close control, and a page change closes it. Each is found by a
// selector, so the modules need no change; a lane adds its own with addPopup().
const POPUPS = [
  { sel: '.notes-dlg', isOpen: (el) => !el.hidden, close: (el) => el.querySelector('[data-x="close"]')?.click() },   // core/summary.js
  { sel: '.ix-pop', isOpen: () => true, close: (el) => el.querySelector('.ix-x')?.click() },                          // views/entities/intelx.js
  { sel: 'dialog.shell-dlg', isOpen: (el) => el.open, close: (el) => el.close() },                                    // core/shell.js deck name
  { sel: '.ep', isOpen: (el) => el.classList.contains('open'), close: (el) => el.querySelector('.ep-x')?.click() },      // core/entity-panel.js
  { sel: '#drawer', isOpen: (el) => el.classList.contains('open'), close: () => document.getElementById('drawer-close')?.click() }, // the event drawer
];
const popups = new Map();   // el -> overlay token
let shownHash = location.hash; // the page on screen (routeChanged and urlMoved update it): a popup belongs to it
function urlMoved() { // a view's own pushState (tapped row, story card) fires no hashchange: phones close the old page's overlays
  if (!samePath(shownHash, location.hash) && isPhone()) { scanPopups(); for (const o of [...overlays].reverse()) if (!samePath(o.hash, location.hash)) closeOverlay(o, 'route'); }
  shownHash = location.hash;
}
const popObs = typeof MutationObserver === 'function' ? new MutationObserver(() => queuePopups()) : null;
let popQueued = false;
function queuePopups() { if (popQueued) return; popQueued = true; requestAnimationFrame(() => { popQueued = false; scanPopups(); }); }
export function addPopup(sel, isOpen, close) { POPUPS.push({ sel, isOpen, close }); scanPopups(); }
function scanPopups() {
  if (!document.body) return;
  const now = new Map();
  for (const P of POPUPS) {
    for (const el of document.body.querySelectorAll(`:scope > ${P.sel}`)) {
      if (!el.__ndPop) { el.__ndPop = 1; popObs?.observe(el, { attributes: true, attributeFilter: ['hidden', 'open', 'class'] }); }
      if (P.isOpen(el)) now.set(el, P);
    }
  }
  for (const [el, ov] of popups) if (!now.has(el)) { popups.delete(el); closeOverlay(ov, 'api', { run: false }); }
  for (const [el, P] of now) {
    if (popups.has(el)) continue;
    popups.set(el, overlayOpened({ kind: 'popup', hash: shownHash, close: () => { popups.delete(el); try { P.close(el); } catch (e) { console.error(e); } } }));
  }
}

// ------------------------------------------------------------------ the phone tab bar (#m-tabbar in index.html)
function syncTabBar() {
  const bar = document.getElementById('m-tabbar');
  if (!bar) return;
  bar.hidden = !isPhone();
  const tab = tabOf();
  bar.querySelectorAll('[data-tab]').forEach((b) => {
    const on = b.dataset.tab === tab;
    b.classList.toggle('active', on);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
}
// The tab bar's More: core/mshell.js opens the designed More sheet (mock-more.png) through onMore(fn).
let moreFn = null;
export function onMore(fn) { moreFn = fn; }
function setup() {
  const bar = document.getElementById('m-tabbar');
  bar?.addEventListener('click', (e) => {
    const b = e.target.closest('[data-tab]');
    if (!b) return;
    e.preventDefault();
    if (b.dataset.tab === 'more') moreFn?.(b); else tabTap(b.dataset.tab);
  });
  syncTabBar();
  watchLayers();
  popObs?.observe(document.body, { childList: true });
  scanPopups();
  onPhoneChange(() => { syncTabBar(); emit(); scanLayers(); });
  emit();
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', setup, { once: true });
else setup();

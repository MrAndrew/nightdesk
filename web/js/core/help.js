// Help: the "?" button opens the Help desk (web/js/help/desk.js, loaded on first use): a side panel on desktop and a
// full sheet on phones, also at #help/<section>[/<item>], by the ? key and from ⌘K. This module keeps the shell's
// registry API so other modules can still add entries without touching the desk:
//   registerHelp({ id: 'docs', label: 'Read the docs', order: 30, run: () => … })   // listed under About
//   setHelpRenderer((container, { close, items }) => …)                           // replace the "?" contents
// and owns the desk's history entry: opening pushes an entry (same URL, desk state) so Back closes it, switching
// section replaces it, closing goes back, and a "Do it" that navigates replaces the desk's entry with its target.
// It also installs the app-wide data-term definition popovers (help/terms.js). Contract: okf/architecture/help.md
import { registerCommand } from './commands.js';

const ITEMS = new Map();
let renderer = null;

export function registerHelp(item) {
  if (!item || !item.id || typeof item.run !== 'function') throw new Error('registerHelp needs {id, label, run}');
  ITEMS.set(item.id, { order: 50, ...item });
}
export function setHelpRenderer(fn) { renderer = fn; }
export const helpItems = () => [...ITEMS.values()].filter((i) => !i.when || i.when()).sort((a, b) => a.order - b.order);

// Fill the phone More sheet's "?" part (the top-bar "?" opens the desk directly: core/shell.js).
export function renderHelp(container, close) {
  const items = helpItems();
  if (renderer) { renderer(container, { close, items }); return; }
  container.innerHTML = `<button class="mi" role="menuitem" data-help="desk">Help<small>this page, guides, glossary</small></button>
    <button class="mi" role="menuitem" data-help="status">Is everything working?</button>
    <button class="mi" role="menuitem" data-help="tour">Take the tour</button>`;
  container.querySelectorAll('[data-help]').forEach((b) => (b.onclick = (e) => {
    e.stopPropagation();
    close();
    const opener = document.getElementById('bnav-more');
    if (b.dataset.help === 'tour') ITEMS.get('tour')?.run();
    else openHelp(b.dataset.help === 'status' ? 'status' : 'page', { opener });
  }));
}

// The shell's "Keyboard shortcuts" entry and ⌘K command call this: it is a section of the desk now.
export function showShortcuts() { openHelp('keys'); }

// ------------------------------------------------------------------ history and the desk
// v1.2: Help is not a route. The URL always names the page underneath (#network/alerts stays #network/alerts), and
// the open desk lives in the history entry's state ({ndHelp: '<section>[/<item>]'}), so:
//  * opening pushes an entry with the same URL and that state, so Back (or Esc, or the close button) closes it;
//  * a reload keeps the page and reopens the desk on the same section (history.state survives a reload);
//  * Forward after closing reopens it; switching section replaces the state.
// The old #help/<section>[/<item>] links (okf guides, glossary links, bookmarks) still work: they are rewritten on
// sight to the page they were opened on plus the desk state (on first load: the landing page).
const HKEY = 'ndHelp';
const isHelp = (hash = location.hash) => /^#\/?help(\/|$|\?)/i.test(hash);
const pathOf = (hash = location.hash) => hash.replace(/^#\/?help\/?/i, '').replace(/\?.*$/, '');
const viewOf = (hash) => (hash || '').replace(/^#\/?/, '').split(/[/?]/)[0].toLowerCase();
const stateObj = (s = history.state) => (s && typeof s === 'object' && !Array.isArray(s) ? s : {});
const helpState = (s = history.state) => (typeof stateObj(s)[HKEY] === 'string' ? stateObj(s)[HKEY] : null);
const withHelp = (path, pushed) => ({ ...stateObj(), [HKEY]: path, [`${HKEY}Pushed`]: !!pushed });
function withoutHelp() { const o = { ...stateObj() }; delete o[HKEY]; delete o[`${HKEY}Pushed`]; return Object.keys(o).length ? o : null; }
let desk = null;                      // the loaded module
let st = null;                        // { ctxHash, opener, pushed, noEntry } while open

const loadDesk = () => import('../help/desk.js').then((m) => (desk = m));
// The "?" button says whether the desk is open (aria-haspopup="dialog", aria-expanded true while it is on screen).
export const isHelpOpen = () => !!desk?.isOpen();
function syncBtn() { document.getElementById('help-btn')?.setAttribute('aria-expanded', String(isHelpOpen())); }
// the entry now on screen is the desk's own (its state can be wiped by a view's replaceState(null, …) on the same page)
const ownsEntry = () => helpState() != null || (st?.pushed && viewOf(location.hash) === viewOf(st.ctxHash));

function ctl() {
  return {
    get ctxHash() { return st?.ctxHash || location.hash; },
    keepFocus: false,
    items: helpItems,
    section(path) { if (!st?.noEntry) history.replaceState(withHelp(path, st?.pushed), '', location.hash); desk?.show(path, { focus: false }); },
    close: () => closeHelp(),
    go(hash, opts) { leave(hash, opts); },
    refresh() { desk?.invalidate(); desk?.show(helpState() || 'page'); },
    invalidate() { desk?.invalidate(); },
    copyDiag() { return desk?.copyDiag(); },
  };
}

export async function openHelp(path = 'page', { opener, push = true } = {}) {
  if (!desk) await loadDesk();
  if (st && desk.isOpen()) {
    if (!st.noEntry) history.replaceState(withHelp(path, st.pushed), '', location.hash);
    desk.show(path, { focus: true });
    syncBtn();
    return;
  }
  if (path === 'page' && push) path = desk.resumeGuide() || path;   // back to the guide a step left
  const already = helpState() != null;   // a reload, Forward, or a converted #help link: the entry exists
  st = { ctxHash: location.hash, opener: opener || document.activeElement, pushed: already ? !!stateObj()[`${HKEY}Pushed`] : push };
  if (!already && push) history.pushState(withHelp(path, true), '', location.hash);
  else history.replaceState(withHelp(path, st.pushed), '', location.hash);
  desk.mount(path, ctl());
  syncBtn();
}

// After Help closes because the user went to another page (⌘K, a link, a Do it): focus lands in that page, on its
// heading once it is painted (not on the "?" button), so keyboard and screen-reader users start where they went.
function focusView(view) {
  let n = 0;
  const tick = () => {
    const sec = document.querySelector(`section.view[data-view="${view}"]`);
    const h1 = sec?.classList.contains('active') ? sec.querySelector('h1') : null;
    if (h1) {
      if (!h1.hasAttribute('tabindex')) h1.setAttribute('tabindex', '-1');
      h1.focus({ preventScroll: true });
    } else if (++n < 40) setTimeout(tick, 50);
    else sec?.querySelector('a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])')?.focus({ preventScroll: true });
  };
  setTimeout(tick, 0);
}
// The URL moved on while the desk was open (a link, ⌘K, Back to before the desk): close it without touching history.
function closeForNav() {
  const from = st?.ctxHash;
  desk.unmount();
  syncBtn();
  if (from != null && viewOf(location.hash) !== viewOf(from)) { st = null; focusView(viewOf(location.hash)); } else restoreFocus();
}

function restoreFocus() {
  const o = st?.opener;
  st = null;
  if (o?.isConnected && o !== document.body && o.offsetParent !== null) o.focus({ preventScroll: true });
  else document.querySelector('nav.views [aria-current="page"], .bnav [aria-current="page"], #views')?.focus?.({ preventScroll: true });
}

// Close and return to where Help was opened from (one Back).
export function closeHelp() {
  if (!desk?.isOpen()) return;
  desk.unmount();
  syncBtn();
  const pushed = st?.pushed, noEntry = st?.noEntry, owns = ownsEntry();
  restoreFocus();
  if (noEntry || !owns) return;
  // the entry before the desk's is the same page without the desk: going back to it undoes the desk's entry
  if (pushed && history.length > 1) history.back();
  else history.replaceState(withoutHelp(), '', location.hash);
}

// Close and go somewhere else: the desk's entry becomes the target, so Back returns to the page before Help.
function leave(hash, { keep = false } = {}) {
  if (keep && st) {
    // a guide step on a wide screen: go there underneath and keep the guide open beside it. The page now owns the
    // entry (no desk state), so closing Help afterwards changes no history.
    const owns = ownsEntry();
    st.ctxHash = hash;
    st.noEntry = true;
    if (owns) { history.replaceState(withoutHelp(), '', hash); window.dispatchEvent(new HashChangeEvent('hashchange')); }
    else if (location.hash !== hash) location.hash = hash;
    return;
  }
  if (hash === st?.ctxHash && !st?.noEntry) { closeHelp(); return; }
  const owns = ownsEntry();
  const from = st?.ctxHash;
  desk?.unmount();
  syncBtn();
  st = null;
  if (viewOf(hash) !== viewOf(from)) focusView(viewOf(hash));
  if (owns) {
    history.replaceState(withoutHelp(), '', hash);
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  } else if (location.hash !== hash) location.hash = hash;
}

// An old-style #help/<section> link: rewrite it before the shell or any view sees it (this listener is registered
// when help.js loads, before shell.js and the views add theirs), so the page underneath never changes.
window.addEventListener('hashchange', (e) => {
  if (!isHelp()) {
    if (desk?.isOpen() && !st?.noEntry && helpState() == null && location.hash !== st?.ctxHash) closeForNav();
    return;
  }
  e.stopImmediatePropagation();
  const path = pathOf() || 'page';
  let back = e.oldURL ? new URL(e.oldURL).hash : '';
  if (!back || isHelp(back)) back = st?.ctxHash || `#${document.body?.dataset.view || 'watch'}`;
  if (desk?.isOpen()) {
    history.replaceState(withHelp(path, st?.pushed), '', back);
    if (st) st.noEntry = false;
    desk.show(path, { focus: false });
    return;
  }
  // the link pushed an entry: it becomes the desk's entry over the page it was clicked on
  history.replaceState(withHelp(path, true), '', back);
  openHelp(path, { push: false });
});

// Back and Forward: an entry with desk state opens the desk on its section; one without closes it.
window.addEventListener('popstate', () => {
  if (isHelp()) return;   // an old #help link: the hashchange listener above turns it into desk state
  const p = helpState();
  if (p != null) {
    if (desk?.isOpen()) desk.show(p, { focus: false });
    else openHelp(p, { push: false });
  } else if (desk?.isOpen() && !st?.noEntry) closeForNav();
});

// First load: an old #help/... deep link (the shell boots onto the landing page first), or a reload with the desk
// open (its state is read now, before any view's own replaceState can drop it). Wait until a view is on screen.
const initial = isHelp() ? (pathOf() || 'page') : helpState();
const initialPushed = !isHelp() && !!stateObj()[`${HKEY}Pushed`];
if (initial) {
  const t0 = Date.now();
  const tick = () => {
    if (document.body?.dataset.view && !isHelp()) {
      history.replaceState(withHelp(initial, initialPushed), '', location.hash);
      openHelp(initial, { push: false });
    } else if (Date.now() - t0 < 15000) setTimeout(tick, 60);
  };
  setTimeout(tick, 60);
}

// The ? key opens Help from anywhere (not while typing, not over another overlay or the tour).
document.addEventListener('keydown', (e) => {
  if (e.key !== '?' || e.metaKey || e.ctrlKey || e.altKey) return;
  const a = document.activeElement;
  if (a && (/^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) || a.isContentEditable)) return;
  if (document.querySelector('.tour-root, .menu.open, .nv-pop:not([hidden]), .shell-kiosk')) return;   // over the entity panel is fine: Esc closes one layer at a time
  e.preventDefault();
  openHelp('page');
});

// ⌘K: the desk and each of its sections and guides.
registerCommand({ id: 'help.desk', label: 'Help: on this page', group: 'Help', keywords: 'help desk what is this question', order: 55, run: () => openHelp('page') });
registerCommand({ id: 'help.status', label: 'Help: is everything working?', group: 'Help', keywords: 'health status check setup diagnostics broken', order: 56, run: () => openHelp('status') });
registerCommand({ id: 'help.glossary', label: 'Help: glossary', group: 'Help', keywords: 'words terms definitions jargon', order: 57, run: () => openHelp('glossary') });
registerCommand({ id: 'help.sources', label: 'Help: data sources and terms', group: 'Help', keywords: 'licence license terms attribution feeds', order: 58, run: () => openHelp('sources') });
registerCommand({ id: 'help.about', label: 'Help: about and copy diagnostics', group: 'Help', keywords: 'version commit diagnostics bug docs', order: 59, run: () => openHelp('about') });
import('../help/guides.js').then(({ GUIDES }) => GUIDES.forEach((g, i) => registerCommand({ id: `help.guide.${g.id}`, label: `Guide: ${g.title}`, group: 'Help', keywords: `how to ${g.summary}`, order: 62 + i, run: () => openHelp(`guides/${g.id}`) }))).catch(() => {});

// Definition popovers for data-term, app-wide (loaded after first paint).
setTimeout(() => import('../help/terms.js').then((m) => m.install()).catch((e) => console.warn('help terms not loaded:', e.message)), 400);


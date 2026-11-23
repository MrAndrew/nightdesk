// Sheets (v1.2 mobile, Phase 0 contract: design.md §3 "Sheets", build-plan.md "Phase 0"). Phone UI: the styles
// are the `.m-sheet*` rules in app.css's m:base block, inside the phone media query, so call these behind
// isPhone() (confirmSheet falls back to window.confirm on desktop by itself).
//
//   openSheet({ id, title, body, footer, size = 'auto', route, parent, onClose, label }) -> handle
//     An opaque sheet over a scrim, with a handle, a 44 px Close and a footer pinned above the keyboard. It traps
//     Tab, makes everything behind it `inert`, closes on × / Esc (the top sheet only) / a scrim tap (swallowed: it
//     never reaches the page) / a handle drag down, and gives focus back to whatever had it. It has no history
//     entry: Back and Forward move between pages, and a page change closes it (core/page.js overlay stack).
//       body, footer  a Node, an array of Nodes, or an HTML string (the caller escapes any data in it)
//       size          'auto' (as tall as its content, at most the visible height) | 'full' (the visible height)
//       route         a hash: the sheet IS that page (e.g. '#network/alerts/<id>/expected'). Close / Esc / scrim /
//                     drag call page.back(parent || parentOf(route)); it closes by itself when the page changes.
//                     Without a route it belongs to the page it opened on and closes when that page is left.
//       onClose(reason)  reason: 'close' | 'esc' | 'scrim' | 'drag' | 'route' | 'navigate' | 'api'
//       label         aria-label when there is no visible title
//     handle: { el, body, footer, id, close(reason?) -> Promise (resolves once it is closed),
//               closed: Promise<reason>, setBusy(bool) }
//   confirmSheet({ title, text, confirm = 'OK', cancel = 'Cancel', danger = false }) -> Promise<boolean>
//     Replaces confirm(). danger: the confirm button is red (a destructive act). Desktop: window.confirm(text).
//   actionSheet({ id = 'actions', title, items: [{ label, hint, value, icon, href, run, danger, disabled, current }] })
//     -> Promise<item | null>. The ⋯ menu: 56 px rows. An item with href navigates with navigateFromSheet(href);
//     one with run() runs after the sheet is gone.
//   navigateFromSheet(hash)  close the sheet(s) and open hash as a page (page.pushPage; from a routed sheet the
//     sheet's page is replaced, so Back from the target returns to the page under it). A target whose path is the
//     page under the sheet (any query, e.g. ?range=) just closes it, no navigation.
//   topSheet() -> handle | null,  closeAllSheets(reason) -> Promise

import { back, parentOf, pushPage, replaceTo, overlayOpened, closeOverlay, topOverlay } from './page.js';
import { isPhone } from './mobile.js';
import { reducedMotion as reduced } from './util.js';

const stack = [];       // open sheets, bottom first
let uid = 0;
const inerted = new Set();
const KEEP = '#toasts, #sr-live, .m-toasts, .m-sheet-root';

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"]), [contenteditable="true"]';
const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
const focusables = (root) => [...root.querySelectorAll(FOCUSABLE)].filter((el) => visible(el) && !el.closest('[inert]'));

function fill(host, content) {
  host.replaceChildren();
  if (content == null) return;
  if (typeof content === 'string') { host.innerHTML = content; return; }
  for (const n of Array.isArray(content) ? content : [content]) if (n) host.append(n);
}

// everything outside the top sheet is inert (and stays as it was before: an element already inert is left alone)
function syncInert() {
  for (const el of inerted) el.inert = false;
  inerted.clear();
  const top = stack[stack.length - 1];
  document.documentElement.classList.toggle('m-sheet-open', !!top);
  if (!top) return;
  for (const el of document.body.children) {
    if (el === top.root || el.matches(KEEP) || el.inert || el.tagName === 'SCRIPT') continue;
    el.inert = true;
    inerted.add(el);
  }
  for (const s of stack) if (s !== top) { s.root.inert = true; inerted.add(s.root); }
}

const pathOf = (h) => String(h || '').replace(/^#\/?/, '').split('?')[0].replace(/\/+$/, '');
const samePath = (a, b) => pathOf(a) === pathOf(b);

// Tab stays inside the top sheet: window, capture phase, before any view's own handler. Esc is page.js's (its one
// Esc owner closes the top overlay of the stack).
window.addEventListener('keydown', (e) => {
  const top = stack[stack.length - 1];
  if (!top || e.key !== 'Tab' || topOverlay() !== top.ov) return; // the sheet is the top overlay: its Tab trap only
  e.stopImmediatePropagation();
  const f = focusables(top.sheet);
  if (!f.length) { e.preventDefault(); top.sheet.focus(); return; }
  const first = f[0], last = f[f.length - 1];
  const inside = top.sheet.contains(document.activeElement);
  if (e.shiftKey && (document.activeElement === first || !inside)) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && (document.activeElement === last || !inside)) { e.preventDefault(); first.focus(); }
}, true);
// focus never escapes to the page behind (a click on the scrim, a programmatic focus)
document.addEventListener('focusin', (e) => {
  const top = stack[stack.length - 1];
  if (top && topOverlay() === top.ov && !top.root.contains(e.target) && !e.target.closest?.(KEEP)) (focusables(top.sheet)[0] || top.sheet).focus({ preventScroll: true });
});

// remove a sheet from the screen
function finish(s, reason) {
  if (s.done) return;
  s.done = true;
  const i = stack.indexOf(s);
  if (i >= 0) stack.splice(i, 1);
  s.root.remove();
  syncInert();
  const back = s.opener;
  if (back && document.contains(back) && !stack.length) back.focus?.({ preventScroll: true });
  else if (stack.length) (focusables(stack[stack.length - 1].sheet)[0] || stack[stack.length - 1].sheet).focus({ preventScroll: true });
  try { s.onClose?.(reason); } catch (e) { console.error(e); }
  s.resolveClosed(reason);
}


export function openSheet(o = {}) {
  const n = ++uid;
  const id = o.id || `sheet${n}`;
  const root = document.createElement('div');
  root.className = 'm-sheet-root';
  root.innerHTML = `<div class="m-scrim" aria-hidden="true"></div>
    <div class="m-sheet${o.size === 'full' ? ' m-sheet-full' : ''}" role="dialog" aria-modal="true" tabindex="-1" data-sheet="${String(id).replace(/"/g, '')}">
      <div class="m-sheet-handle" aria-hidden="true"><span></span></div>
      <div class="m-sheet-head"><h2 class="m-sheet-title" id="m-sheet-t${n}"></h2>
        <button type="button" class="m-sheet-x" aria-label="Close"><svg class="i" aria-hidden="true"><use href="#i-x"/></svg></button></div>
      <div class="m-sheet-body"></div>
      <div class="m-sheet-foot" hidden></div>
    </div>`;
  const sheet = root.querySelector('.m-sheet');
  const titleEl = root.querySelector('.m-sheet-title');
  if (o.title) { titleEl.textContent = o.title; sheet.setAttribute('aria-labelledby', titleEl.id); }
  else { titleEl.hidden = true; sheet.setAttribute('aria-label', o.label || 'Dialog'); }
  const body = root.querySelector('.m-sheet-body');
  const foot = root.querySelector('.m-sheet-foot');
  fill(body, o.body);
  if (o.footer != null) { fill(foot, o.footer); foot.hidden = false; }
  if (reduced()) root.classList.add('m-sheet-still');

  let resolveClosed;
  const closed = new Promise((r) => { resolveClosed = r; });
  const s = { id, root, sheet, el: sheet, body, footer: foot, route: o.route || null, onClose: o.onClose,
    opener: document.activeElement instanceof HTMLElement && document.activeElement !== document.body ? document.activeElement : null,
    done: false, resolveClosed, closed };

  // close by the user (Close, Esc, scrim, drag) or by the API: one close path (page.js's overlay stack)
  s.dismiss = (reason = 'close') => { if (!s.done) closeOverlay(s.ov, reason); return Promise.resolve(); };
  const handle = { id, el: sheet, body, footer: foot, closed, close: (reason = 'api') => s.dismiss(reason), setBusy: (b) => sheet.toggleAttribute('aria-busy', !!b) };
  s.handle = handle;

  root.querySelector('.m-sheet-x').addEventListener('click', (e) => { e.preventDefault(); s.dismiss('close'); });
  const scrim = root.querySelector('.m-scrim');
  const swallow = (e) => { e.preventDefault(); e.stopPropagation(); };
  scrim.addEventListener('pointerdown', swallow);
  scrim.addEventListener('click', (e) => { swallow(e); s.dismiss('scrim'); });
  dragToClose(root.querySelector('.m-sheet-handle'), sheet, () => s.dismiss('drag'));
  // a plain in-app link inside the sheet: close the sheet, then go there
  root.addEventListener('click', (e) => {
    const a = e.target.closest('a[href^="#"]');
    if (!a || e.defaultPrevented || a.target || e.metaKey || e.ctrlKey || e.shiftKey) return;
    e.preventDefault();
    navigateFromSheet(a.getAttribute('href'));
  });

  // on page.js's overlay stack (no history entry). A routed sheet closed by its own control or Esc also goes back
  // to its parent page.
  s.ov = overlayOpened({ kind: 'sheet', hash: s.route || location.hash, close: (reason) => {
    finish(s, reason);
    if (s.route && !['route', 'navigate'].includes(reason)) back(o.parent || parentOf(s.route));
  } });
  stack.push(s);
  document.body.append(root);
  syncInert();
  requestAnimationFrame(() => {
    root.classList.add('m-sheet-in');
    const first = sheet.querySelector('[autofocus]') || focusables(body)[0] || sheet;
    first.focus({ preventScroll: true });
  });
  return handle;
}

// the handle: drag down past 80 px (or flick) to close; otherwise it springs back
function dragToClose(grip, sheet, close) {
  let y0 = null, t0 = 0, dy = 0, id = null;
  grip.addEventListener('pointerdown', (e) => {
    y0 = e.clientY; t0 = performance.now(); dy = 0; id = e.pointerId;
    grip.setPointerCapture?.(e.pointerId);
    sheet.style.transition = 'none';
  });
  grip.addEventListener('pointermove', (e) => {
    if (y0 == null || e.pointerId !== id) return;
    dy = Math.max(0, e.clientY - y0);
    sheet.style.transform = dy ? `translateY(${dy}px)` : '';
  });
  const end = (e) => {
    if (y0 == null || (e && e.pointerId !== id)) return;
    const v = dy / Math.max(1, performance.now() - t0);
    y0 = null;
    sheet.style.transition = '';
    if (dy > 80 || (dy > 24 && v > 0.6)) close();
    else sheet.style.transform = '';
  };
  grip.addEventListener('pointerup', end);
  grip.addEventListener('pointercancel', end);
}

export const topSheet = () => stack[stack.length - 1]?.handle || null;
export async function closeAllSheets(reason = 'api') {
  while (stack.length) await stack[stack.length - 1].dismiss(reason);
}

export async function navigateFromSheet(hash) {
  const want = hash.startsWith('#') ? hash : `#${hash}`;
  const sheets = [...stack];
  const routed = sheets.find((s) => s.route);
  const under = routed ? (parentOf(routed.route) || location.hash) : location.hash;
  for (const s of sheets.reverse()) closeOverlay(s.ov, 'navigate');
  // the target is the page under the sheets (same path; ?range= and other queries ignored): closing them is all
  // there is to do (More -> Ops while on Ops)
  if (samePath(want, under)) { if (routed) back(under); return; }
  if (routed) replaceTo(want); else pushPage(want);
}

export function confirmSheet({ title = 'Are you sure?', text = '', confirm = 'OK', cancel = 'Cancel', danger = false } = {}) {
  if (!isPhone()) return Promise.resolve(window.confirm([title, text].filter(Boolean).join('\n\n')));
  return new Promise((resolve) => {
    let answer = false;
    const p = document.createElement('p');
    p.className = 'm-sheet-text';
    p.textContent = text;
    const no = document.createElement('button');
    no.type = 'button'; no.className = 'm-btn'; no.textContent = cancel;
    const yes = document.createElement('button');
    yes.type = 'button'; yes.className = `m-btn ${danger ? 'm-btn-danger' : 'm-btn-primary'}`; yes.textContent = confirm;
    const sh = openSheet({ id: 'confirm', title, body: text ? p : null, footer: [no, yes], onClose: () => resolve(answer) });
    no.addEventListener('click', () => sh.close('close'));
    yes.addEventListener('click', () => { answer = true; sh.close('close'); });
    requestAnimationFrame(() => requestAnimationFrame(() => (danger ? no : yes).focus({ preventScroll: true })));
  });
}

export function actionSheet({ id = 'actions', title = '', items = [], label } = {}) {
  return new Promise((resolve) => {
    let chosen = null;
    const list = document.createElement('div');
    list.className = 'm-acts';
    list.setAttribute('role', 'menu');
    items.forEach((it, i) => {
      const b = document.createElement(it.href ? 'a' : 'button');
      if (it.href) b.href = it.href; else b.type = 'button';
      b.className = `m-act${it.danger ? ' m-act-danger' : ''}`;
      b.setAttribute('role', 'menuitem');
      b.dataset.i = i;
      if (it.disabled) { b.setAttribute('aria-disabled', 'true'); if (!it.href) b.disabled = true; }
      if (it.current) b.setAttribute('aria-current', 'page');
      if (it.icon) b.append(it.icon.cloneNode ? it.icon.cloneNode(true) : it.icon);
      const t = document.createElement('span');
      t.className = 'm-act-l';
      t.textContent = it.label;
      b.append(t);
      if (it.hint) { const hEl = document.createElement('span'); hEl.className = 'm-act-h'; hEl.textContent = it.hint; b.append(hEl); }
      list.append(b);
    });
    const sh = openSheet({ id, title, label: label || title || 'Actions', body: list, onClose: () => {} });
    list.addEventListener('click', async (e) => {
      const b = e.target.closest('.m-act');
      if (!b || b.getAttribute('aria-disabled') === 'true') { e.preventDefault(); return; }
      e.preventDefault();
      e.stopPropagation();
      chosen = items[+b.dataset.i];
      if (chosen.href) { await navigateFromSheet(chosen.href); resolve(chosen); return; }
      await sh.close('close');
      resolve(chosen);
      try { chosen.run?.(chosen); } catch (err) { console.error(err); }
    });
    sh.closed.then(() => { if (!chosen) resolve(null); });
  });
}

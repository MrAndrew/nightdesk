// One way to open things, app-wide (okf/architecture/web-client.md#opening-things):
//   click                         -> "Details": the one side panel (entity panel, or the event drawer for events)
//   Cmd/Ctrl/Shift-click, middle  -> "Open full page" in a new tab (real hrefs, so the browser does it natively)
// Every view, chip, table, search result and menu uses these helpers and these two labels, never its own.
//
//   LABELS.details / LABELS.full    'Details' / 'Open full page'
//   entityHref(id)                  '#entities/<id>'  (the full page of an entity)
//   newTab(event)                   true when the click or key asks for a new tab (Cmd, Ctrl, Shift, middle button)
//   openDetails(id, event?, opts?)  the side panel, or the full page in a new tab when event asks for one;
//                                   returns 'panel' | 'tab'
//   openFull(href, event?)          the full page: a new tab when event asks for one, else this tab (panels close)
//   fullLink(id, cls?)              HTML: <a href=... data-open-full>Open full page</a>
//
// Delegated here for the whole document: a modified or middle click on any entity reference that is not a real
// link ([data-entity], [data-eid], [data-ep] on a button or custom element) opens its full page in a new tab and
// never reaches the row it sits in; on a real link the browser does it. A plain click on a [data-open-full] link
// closes the side panel before navigating.
import { openEntity, closeEntity } from './entity-panel.js';

export const LABELS = Object.freeze({ details: 'Details', full: 'Open full page' });

export const entityHref = (id) => `#entities/${encodeURIComponent(String(id))}`;

export const newTab = (e) => !!e && !!(e.metaKey || e.ctrlKey || e.shiftKey || e.button === 1);

export function openFull(href, e) {
  if (!href) return;
  if (newTab(e)) { window.open(href, '_blank', 'noopener'); return; }
  closeEntity({ restore: false });
  if (location.hash !== href) location.hash = href;
}

export function openDetails(id, e, opts = {}) {
  if (!id) return null;
  if (newTab(e)) { openFull(entityHref(id), e); return 'tab'; }
  openEntity(id, opts);
  return 'panel';
}

export const fullLink = (id, cls = 'src-btn') =>
  `<a class="${cls}" href="${entityHref(id).replace(/"/g, '&quot;')}" data-open-full>${LABELS.full}</a>`;

const REF = '[data-entity], [data-eid], [data-ep]';
const refId = (el) => el.dataset.entity || el.dataset.eid || el.dataset.ep || '';
const isLink = (el) => el.tagName === 'A' && !!el.getAttribute('href');

if (!window.__ndOpenGrammar) {
  window.__ndOpenGrammar = true;
  document.addEventListener('click', (e) => {
    const full = e.target.closest?.('a[data-open-full]');
    if (full && !newTab(e) && e.button === 0) { closeEntity({ restore: false }); return; }
    if (!newTab(e)) return;
    const el = e.target.closest?.(REF);
    if (!el || el.closest('.ep-card') || !refId(el)) return;
    e.stopPropagation();                   // never the row, the pivot menu or the panel's own handler
    if (isLink(el)) return;                // the browser opens the real href in a new tab or window
    e.preventDefault();
    window.open(entityHref(refId(el)), '_blank', 'noopener');
  }, true);
  // A middle press on a reference that is not a link must not start the browser's autoscroll.
  document.addEventListener('mousedown', (e) => {
    if (e.button !== 1) return;
    const el = e.target.closest?.(REF);
    if (el && !isLink(el) && refId(el)) e.preventDefault();
  }, true);
  // Middle click fires auxclick, not click: links open natively, everything else is opened here.
  document.addEventListener('auxclick', (e) => {
    if (e.button !== 1) return;
    const el = e.target.closest?.(REF);
    if (!el || isLink(el) || !refId(el)) return;
    e.preventDefault(); e.stopPropagation();
    window.open(entityHref(refId(el)), '_blank', 'noopener');
  }, true);
}

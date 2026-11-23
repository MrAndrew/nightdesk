// One view header and one set of empty / error / loading states for every view (IA-14).
// Styles: web/css/app.css, block "lane:headers" (.vh-*, .vs-*). Contract: okf/architecture/web-client.md#view-headers
//
//   el.innerHTML = viewHeader({ title: 'Network', purpose: 'Your own logs, checked against threat lists',
//                               tabs: '<button data-tab="a" role="tab">A</button>…', tabsCls: 'nv-tabs',
//                               actions: '<button class="vh-btn">…</button>', range: { lead: '<span class="nv-rt"></span>' } });
//   const r = headerRange(el, { value, onChange });         // the ranges lane's control, at the header's right edge
//   box.innerHTML = emptyState({ title: 'No alerts', why: 'Nothing matched a threat list.', act: stateAct('Connect logs', { href: '#network/import' }) });
//   box.innerHTML = errorState({ title: "Couldn't load the alerts", why: 'The server did not answer.', err: e.message, retry: load });
//   box.innerHTML = loadingState('Reading alerts…');
//
// Header layout (one look everywhere): serif title with a one-line purpose under it on the left; sub-tabs beside it on
// wide screens and on their own row below 1180 px; actions, then the time range, flush right. Below 640 px the purpose
// takes its own line and the tabs scroll sideways. `overlay: true` is Cinema's variant: no band, floats over the globe.
//
// Every string except `title` is trusted HTML the caller built (escape data values with util.esc before passing them).
import { mount as mountRange } from './range.js';
import { scanLoader } from './loader.js';
import { esc } from './util.js';

export function viewHeader(o = {}) {
  const {
    title = '', purpose = '', status = '', tabs = '', tabsCls = '', tabsLabel = '', actions = '',
    range = null, cls = '', overlay = false, lead = '', titleCls = '',
  } = o;
  const sub = purpose || status
    ? `<p class="vh-sub">${purpose ? `<span class="vh-purpose">${purpose}</span>` : ''}${status ? `<span class="vh-status mono">${status}</span>` : ''}</p>` : '';
  const r = range ? `<div class="vh-range ${range.cls || ''}">${range.lead || ''}<div class="vh-rc"></div></div>` : '';
  const nav = tabs ? `<nav class="vh-tabs ${tabsCls}" role="tablist"${tabsLabel ? ` aria-label="${esc(tabsLabel)}"` : ''}>${tabs}</nav>` : '';
  return `<header class="vh${overlay ? ' vh-overlay' : ''}${tabs ? ' vh-has-tabs' : ''} ${cls}">
    ${lead ? `<div class="vh-lead">${lead}</div>` : ''}
    <h1 class="vh-title ${titleCls}">${esc(title)}</h1>${sub}
    ${nav}
    <div class="vh-end">${actions ? `<div class="vh-act">${actions}</div>` : ''}${r}</div>
  </header>`;
}

// The shared time range (core/range.js) mounted in a header built with `range: {...}`. Same options as range.mount.
export const headerRange = (root, opts) => mountRange(root.querySelector('.vh-rc'), opts);

// ---------------------------------------------------------------- states
// A small action for a state: a link (href) or a button carrying data attributes the view already listens for.
//   stateAct('Load the demo', { data: { act: 'demo' } })   stateAct('Open Sources', { href: '#settings/sources' })
export function stateAct(label, { href, data = {}, primary = false, title = '' } = {}) {
  const attrs = Object.entries(data).map(([k, v]) => ` data-${k}="${esc(v)}"`).join('') + (title ? ` title="${esc(title)}"` : '');
  const c = `vs-btn${primary ? ' primary' : ''}`;
  return href ? `<a class="${c}" href="${esc(href)}"${attrs}>${esc(label)}</a>` : `<button type="button" class="${c}"${attrs}>${esc(label)}</button>`;
}

const ICONS = {
  // the Network empty state's rings: nothing heard yet
  empty: '<svg class="vs-i" viewBox="0 0 48 48" aria-hidden="true"><circle cx="24" cy="24" r="6" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="24" cy="24" r="14" fill="none" stroke="currentColor" stroke-width="1" opacity=".5"/><circle cx="24" cy="24" r="22" fill="none" stroke="currentColor" stroke-width="1" opacity=".25"/><circle cx="24" cy="24" r="2" fill="currentColor"/></svg>',
  // a broken ring: something went wrong
  error: '<svg class="vs-i" viewBox="0 0 48 48" aria-hidden="true"><path d="M24 4a20 20 0 1 1-14.1 5.9" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><path d="M24 15v12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="24" cy="33" r="1.6" fill="currentColor"/></svg>',
};

// title: plain text. why: trusted HTML (one sentence: the cause). body: trusted HTML block after it (e.g. steps).
// act: trusted HTML (stateAct()s). err: plain text,
// the technical message, shown only under "Details". size: '' (a page or pane), 'sm' (centred inside a panel, list or
// card) or 'inline' (a left-aligned line inside a detail section, e.g. "No notes yet").
function state(kind, { title = '', why = '', body = '', act = '', err = '', size = '', cls = '', icon = true } = {}) {
  const sm = size === 'sm' || size === 'inline';
  return `<div class="vs vs-${kind}${sm ? ' vs-sm' : ''}${size === 'inline' ? ' vs-inline' : ''} ${cls}" role="${kind === 'error' ? 'alert' : 'status'}">
    ${!sm && icon ? ICONS[kind] : ''}
    ${title ? `<p class="vs-t">${esc(title)}</p>` : ''}${why ? `<p class="vs-why">${why}</p>` : ''}${body}
    ${act ? `<div class="vs-act">${act}</div>` : ''}${err ? `<details class="vs-detail"><summary>Details</summary><code>${esc(err)}</code></details>` : ''}
  </div>`;
}
export const emptyState = (o) => state('empty', o);

// Every error state has a next step that works. retry: a function that runs the failed load again; it becomes a
// "Try again" button (handled by one delegated listener below, so it works in markup built as a string). act: extra
// actions after it (e.g. "Clear filters"). With neither, the next step is reloading the page.
const RETRY = new Map(); // id -> fn; only the newest few are kept (each re-render makes a new id)
let retrySeq = 0;
function retryAct(fn, label) {
  const id = String(++retrySeq);
  RETRY.set(id, fn);
  if (RETRY.size > 300) RETRY.delete(RETRY.keys().next().value);
  return stateAct(label, { data: { 'vs-retry': id }, primary: true });
}
if (typeof document !== 'undefined') {
  document.addEventListener('click', (e) => {
    const b = e.target.closest?.('[data-vs-retry]');
    if (!b) return;
    e.preventDefault(); e.stopPropagation();
    const fn = RETRY.get(b.dataset.vsRetry);
    if (!fn) { location.reload(); return; }
    const box = b.closest('.vs');
    if (box) box.outerHTML = loadingState('Trying again…', { size: box.classList.contains('vs-sm') ? 'sm' : '' });
    try { const r = fn(); if (r?.catch) r.catch((err) => console.warn('retry failed:', err?.message)); } catch (err) { console.warn('retry failed:', err?.message); }
  }, true);
}
export function errorState(o = {}) {
  const { retry, retryLabel = 'Try again', act = '', ...rest } = o;
  const acts = (typeof retry === 'function' ? retryAct(retry, retryLabel) : '') + act;
  return state('error', { title: "Couldn't load this", ...rest, act: acts || stateAct('Reload the page', { data: { 'vs-retry': 'reload' } }) });
}
// The lamp loader (core/loader.js) in the same frame, so a pane keeps its place while it loads.
export const loadingState = (label = 'Loading…', { size = '', cls = '' } = {}) =>
  `<div class="vs vs-loading${size ? ' vs-sm' : ''} ${cls}" role="status" aria-live="polite">${scanLoader(esc(label))}</div>`;

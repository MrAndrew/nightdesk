// The Help desk: a modal side panel on desktop and a full sheet on phones, opened by "?" (and Help in the phone More
// sheet, the ? key, ⌘K and #help/<section>). One search box across every section; sections: On this page, Is
// everything working?, Guides, Glossary, Shortcuts, Sources and terms, About (with diagnostics and the local docs).
// core/help.js owns the route and history; this module owns the panel. Contract: okf/architecture/help.md
import { api, sqlConsoleOn } from '../core/api.js';
import { live } from '../core/live.js';
import * as T from '../core/time.js';
import { esc, h, toast, fmt } from '../core/util.js';
import { commands } from '../core/commands.js';
import { GLOSSARY, CATS, byId as termById } from './glossary.js';
import { GUIDES, guideById } from './guides.js';
import { KEY_GROUPS } from './keys.js';
import { PAGES, PAGE_ORDER, pageKey } from './pages.js';
import { run as runAction, label as actLabel, shownStepAct } from './actions.js';
import { checks, summary } from './status.js';
import { render as renderMd } from './md.js';
import { errorState, stateAct } from '../core/view.js';
import { isPhone } from '../core/mobile.js';

export const SECTIONS = [
  ['page', 'This page', 'On this page'],
  ['status', 'Health', 'Is everything working?'],
  ['guides', 'Guides', 'Guides'],
  ['glossary', 'Glossary', 'Glossary'],
  ['keys', 'Shortcuts', 'Keyboard shortcuts and commands'],
  ['sources', 'Sources', 'Data sources and terms'],
  ['about', 'About', 'About and diagnostics'],
];
// Views that have a guided tour (core/tour.js PAGES); others get no "Tour this page" button.
const TOURED = new Set(['watch', 'ops', 'news', 'entities', 'network', 'explorer', 'cinema', 'settings']);
const SEC_IDS = new Set([...SECTIONS.map((s) => s[0]), 'docs']);
// On a phone (a touch screen with no keyboard) there are no keyboard shortcuts to show: no Shortcuts tab, link or results.
const noKeys = () => isPhone();

const LAMP = '<svg viewBox="0 0 32 32" class="help-lamp" aria-hidden="true"><rect class="bm-emit" x="11" y="4" width="10" height="3" rx="1.5"/><path class="bm-beam" d="M12 7 H20 L25 23 H7 Z"/><path class="bm-edge" d="M12 7 H20 L25 23 H7 Z"/><path class="bm-desk" d="M6 23 H26"/><circle class="bm-dot" cx="16" cy="19" r="2.3"/></svg>';

let root = null, box = null, body = null, input = null;
let ctl = null;              // { ctxHash, go(hash), section(path), close(), items() }
let cur = { sec: 'page', arg: '' };
let acts = [];               // actions of the rendered content, by index
let health = null, healthAt = 0, healthP = null;
let srcData = null, docList = null, diag = null;

export const isOpen = () => !!root;
export const parsePath = (p) => {
  const [s, ...rest] = String(p || '').replace(/^#?help\/?/, '').split('/');
  const sec = SEC_IDS.has(s) ? s : 'page';
  return { sec, arg: SEC_IDS.has(s) ? decodeURIComponent(rest.join('/')) : '' };
};

// ------------------------------------------------------------------ open / close
// The health check is cached for 30 s while browsing sections; anything that can change it clears the cache:
// opening the desk, a fix button, and live events (alerts and demo changes, feed state, the marker).
export function invalidate() { health = null; healthAt = 0; healthP = null; diag = null; srcData = null; }
let liveT = 0;
function onLive() {
  clearTimeout(liveT);
  liveT = setTimeout(() => {
    health = null; healthAt = 0; healthP = null;
    if (root && !input.value.trim() && (cur.sec === 'status' || cur.sec === 'page')) paint(cur.sec, cur.arg);
  }, 600);
}
for (const t of ['netlog_alerts', 'source', 'marker']) { try { live.on(t, onLive); } catch {} }

export function mount(path, c) {
  ctl = c;
  invalidate();
  if (!root) build();
  show(path, { focus: !c.keepFocus });
  // a desk opened before /api/health answered painted the SQL console as off: paint again once it is known
  const was = sqlConsoleOn();
  api.health().then(() => { if (root && cur && sqlConsoleOn() !== was && !input.value.trim()) paint(cur.sec, cur.arg); });
}

export function unmount() {
  if (!root) return;
  removeEventListener('keydown', onKey, true);
  root.remove();
  root = box = body = input = null;
  document.body.classList.remove('help-open');
}

function build() {
  const where = PAGES[pageKey(ctl.ctxHash)]?.title || '';
  root = h(`<div class="help-back" role="presentation">
    <aside class="help-desk" role="dialog" aria-modal="true" aria-labelledby="help-title" tabindex="-1">
      <header class="help-head">
        <div class="help-top">${LAMP}<div class="help-tt"><h2 id="help-title" tabindex="-1">Help desk</h2>${where ? `<span class="help-where">You were on ${esc(where)}</span>` : ''}</div>
          <button class="icon-btn help-x" data-x title="Close (Esc)" aria-label="Close Help"><svg class="i"><use href="#i-x"/></svg></button></div>
        <div class="help-search"><svg class="i" aria-hidden="true"><use href="#i-search"/></svg>
          <input type="search" placeholder="Search help: a word, a task, a shortcut…" aria-label="Search help" autocomplete="off" spellcheck="false" aria-controls="help-body"><kbd class="mono" aria-hidden="true">/</kbd></div>
        <nav class="help-nav" aria-label="Help sections">${SECTIONS.filter(([id]) => !(id === 'keys' && noKeys())).map(([id, short, long]) => `<button data-sec="${id}" title="${esc(long)}">${esc(short)}</button>`).join('')}</nav>
      </header>
      <div class="help-body" id="help-body" tabindex="-1" aria-live="polite" aria-busy="false"></div>
    </aside></div>`);
  document.body.append(root);
  document.body.classList.add('help-open');
  box = root.querySelector('.help-desk');
  body = root.querySelector('.help-body');
  input = root.querySelector('input');
  root.addEventListener('mousedown', (e) => { if (e.target === root) { e.preventDefault(); ctl.close(); } });
  root.querySelector('[data-x]').onclick = () => ctl.close();
  root.querySelector('.help-nav').addEventListener('click', (e) => {
    const b = e.target.closest('[data-sec]');
    if (b) { input.value = ''; ctl.section(b.dataset.sec); }
  });
  input.addEventListener('input', () => paintSearch());
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); body.querySelector('.help-res')?.focus(); }
    else if (e.key === 'Enter') { e.preventDefault(); body.querySelector('.help-res')?.click(); }
  });
  body.addEventListener('keydown', (e) => {
    const r = e.target.closest?.('.help-res');
    if (!r || !['ArrowDown', 'ArrowUp'].includes(e.key)) return;
    e.preventDefault();
    const all = [...body.querySelectorAll('.help-res')];
    const i = all.indexOf(r) + (e.key === 'ArrowDown' ? 1 : -1);
    if (i < 0) input.focus(); else all[Math.min(i, all.length - 1)].focus();
  });
  box.addEventListener('click', onClick);
  addEventListener('keydown', onKey, true);
}

function onKey(e) {
  if (!root) return;
  if (e.key === 'Escape') {
    // a menu or palette opened on top of the desk closes first
    if (document.querySelector('.shell-cmdk-back')) return;
    e.preventDefault(); e.stopPropagation();
    ctl.close();
    return;
  }
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || '');
  if (e.key === '/' && !e.metaKey && !e.ctrlKey && !typing) {
    e.preventDefault(); e.stopPropagation(); input.focus(); input.select();
    return;
  }
  // The desk is modal: the page's single-key shortcuts (j, k, a, d, Space…) must not act behind it. This listener
  // runs first (window, capture), so stopping here keeps them from the page; the keys' own defaults still happen.
  if (!typing && (e.key.length === 1 || e.key === 'ArrowLeft' || e.key === 'ArrowRight') && !e.metaKey && !e.ctrlKey && !e.altKey) e.stopPropagation();
  if (e.key === 'Tab') {
    const f = [...box.querySelectorAll('a[href], button:not([disabled]), input, select, textarea, summary, [tabindex]:not([tabindex="-1"])')]
      .filter((x) => (x.checkVisibility ? x.checkVisibility({ visibilityProperty: true }) : x.offsetParent !== null) && !x.closest('details:not([open]) > :not(summary)'));
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (!box.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
    else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
}

function onClick(e) {
  const a = e.target.closest('[data-act]');
  if (a) {
    e.preventDefault();
    let c = ctl;
    const li = a.closest('[data-step]');
    if (li && cur.sec === 'guides' && guideById.has(cur.arg)) {
      // a guide keeps your place: the step is marked done; on a wide screen the guide stays open beside the page it
      // went to, on a phone it closes and the next Help opens back on the guide
      const gid = cur.arg;
      progress(gid, +li.dataset.step);
      li.classList.add('done');
      const wide = innerWidth > 760;
      c = { ...ctl, go: (h) => { if (wide) ctl.go(h, { keep: true }); else { progress(gid, null, true); ctl.go(h); } } };
    }
    runAction(acts[+a.dataset.act], c, a);
    return;
  }
  const link = e.target.closest('a[href^="#"]');
  if (link) {
    e.preventDefault();
    const href = link.getAttribute('href');
    if (/^#help(\/|$)/.test(href)) { input.value = ''; ctl.section(href.replace(/^#help\/?/, '') || 'page'); }
    else ctl.go(href);
    return;
  }
  const cmd = e.target.closest('[data-cmd]');
  if (cmd) {
    const c = commands().find((x) => x.id === cmd.dataset.cmd);
    ctl.close();
    setTimeout(() => { try { c?.run(); } catch (err) { console.error(err); } }, 80);
    return;
  }
  const it = e.target.closest('[data-item]');
  if (it) { const item = ctl.items().find((x) => x.id === it.dataset.item); ctl.close(); setTimeout(() => item?.run(), 80); return; }
  if (e.target.closest('[data-copy-diag]')) { copyDiag(); return; }
  const rs = e.target.closest('[data-restart]');
  if (rs) { try { sessionStorage.removeItem(PKEY); } catch {} paint('guides', rs.dataset.restart); return; }
  if (e.target.closest('[data-recheck]')) { health = null; healthAt = 0; show('status', { replaceOnly: true }); return; }
  const f = e.target.closest('[data-filter]');
  if (f) { box.querySelectorAll('[data-filter]').forEach((x) => x.setAttribute('aria-pressed', String(x === f))); filterSources(f.dataset.filter); return; }
  const gc = e.target.closest('[data-gcat]');
  if (gc) {
    box.querySelectorAll('[data-gcat]').forEach((x) => x.setAttribute('aria-pressed', String(x === gc)));
    box.querySelectorAll('.help-term').forEach((t) => { t.hidden = gc.dataset.gcat !== 'all' && t.dataset.cat !== gc.dataset.gcat; });
    box.querySelectorAll('.help-gl-letter').forEach((l) => { l.hidden = gc.dataset.gcat !== 'all'; });
  }
}

const act = (a) => { acts.push(a); return acts.length - 1; };
const doBtn = (a, cls = '') => (a ? `<button class="help-do ${cls}" data-act="${act(a)}">${esc(actLabel(a))}</button>` : '');

// ------------------------------------------------------------------ guide progress (this browser tab)
const PKEY = 'nd.help.guide';
function readProg() { try { const p = JSON.parse(sessionStorage.getItem(PKEY) || 'null'); return p && Date.now() - p.at < 3600e3 ? p : null; } catch { return null; } }
function progress(id, step, resume = false) {
  let p = readProg();
  if (!p || p.id !== id) p = { id, done: [] };
  if (step != null && !p.done.includes(step)) p.done.push(step);
  p.resume = resume || false;
  p.at = Date.now();
  try { sessionStorage.setItem(PKEY, JSON.stringify(p)); } catch {}
}
// The guide to reopen on, once, after a guide step closed Help on a phone.
export function resumeGuide() {
  const p = readProg();
  if (!p?.resume || !guideById.has(p.id)) return null;
  p.resume = false;
  try { sessionStorage.setItem(PKEY, JSON.stringify(p)); } catch {}
  return `guides/${p.id}`;
}

// ------------------------------------------------------------------ sections
export function show(path, { focus = false, replaceOnly = false } = {}) {
  if (!root) return;
  const { sec, arg } = parsePath(path);
  cur = { sec, arg };
  root.querySelectorAll('[data-sec]').forEach((b) => {
    const on = b.dataset.sec === sec || (sec === 'docs' && b.dataset.sec === 'about');
    if (on) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current');
  });
  if (input.value.trim()) { paintSearch(); return; }
  paint(sec, arg);
  if (!replaceOnly) body.scrollTop = 0;
  if (focus) focusIn();
}

// On a touch screen (or the phone sheet) focusing the search box raises the on-screen keyboard over half the sheet the user came to read:
// focus the heading there instead (screen readers still land in the desk). Keyboards and mice land in the search.
const touch = () => matchMedia('(hover: none), (pointer: coarse), (max-width: 760px)').matches;
function focusIn() {
  if (touch()) root.querySelector('#help-title').focus({ preventScroll: true });
  else input.focus({ preventScroll: true });
}

function paint(sec, arg) {
  acts = [];
  if (sec === 'keys' && noKeys()) sec = 'page';
  const fn = { page: pagePane, status: statusPane, guides: guidesPane, glossary: glossaryPane, keys: keysPane, sources: sourcesPane, about: aboutPane, docs: docPane }[sec] || pagePane;
  body.innerHTML = fn(arg);
  after(sec, arg);
}

function anchor(id) {
  if (!id) return;
  const el = body.querySelector(`[data-anchor="${CSS.escape(id)}"]`);
  if (!el) return;
  el.scrollIntoView({ block: 'start' });
  el.classList.add('help-flash');
  setTimeout(() => el.classList.remove('help-flash'), 1800);
}

function after(sec, arg) {
  if (['glossary', 'about', 'keys', 'sources'].includes(sec)) anchor(arg);
  if (sec === 'page') loadHealth().then(() => { const b = body?.querySelector('.help-hb'); if (b && cur.sec === 'page') b.outerHTML = healthBanner(); });
  if (sec === 'status') loadHealth().then(() => { if (cur.sec === 'status' && !input.value.trim()) { acts = []; body.innerHTML = statusPane(); } });
  if (sec === 'sources' && !srcData) loadSources().then(() => { if (cur.sec === 'sources' && !input.value.trim()) { paint('sources', arg); } });
  if (sec === 'about' && (!diag || !docList)) loadAbout().then(() => { if (cur.sec === 'about' && !input.value.trim()) paint('about', arg); });
  if (sec === 'docs') loadDoc(arg);
}

// ---- On this page
function pageHead(key) {
  return `<p class="help-kicker">On this page</p><h3 class="help-h" data-anchor="${esc(key)}">${esc(PAGES[key].title)}</h3>`;
}
function pagePane(arg) {
  const key = PAGES[arg] ? arg : pageKey(ctl.ctxHash);
  const p = PAGES[key];
  const others = PAGE_ORDER.filter((k) => k !== key);
  return `<section class="help-sec">
    ${healthBanner()}
    ${pageHead(key)}
    <p class="help-lede">${esc(p.lede)}</p>
    ${key === pageKey(ctl.ctxHash) && TOURED.has(key.split('/')[0]) ? `<div class="help-row"><button class="help-do ghost" data-act="${act({ fn: 'tour', label: 'Tour this page' })}">${LAMP}Tour this page</button></div>` : ''}
    ${p.tasks.length ? `<h4 class="help-h4">Common tasks</h4><ol class="help-tasks">${p.tasks.map((t) => `<li data-task><div class="help-task-b"><b>${esc(t.label)}</b><span>${esc(t.text)}</span></div>${doBtn({ ...t.act, label: t.act.label || (t.act.help ? 'Show me' : 'Do it') })}</li>`).join('')}</ol>` : ''}
    <h4 class="help-h4">What each part means</h4>
    <dl class="help-parts">${p.parts.map(([n, d]) => `<dt>${esc(n)}</dt><dd>${esc(d)}</dd>`).join('')}</dl>
    ${related(p)}
    <details class="help-other"><summary>Help for another page</summary><div class="help-chips">${others.map((k) => `<a class="help-chip" href="#help/page/${esc(k)}">${esc(PAGES[k].title)}</a>`).join('')}</div></details>
  </section>`;
}
function related(p) {
  const g = (p.guides || []).map((id) => guideById.get(id)).filter(Boolean);
  const t = (p.terms || []).map((id) => termById.get(id)).filter(Boolean);
  if (!g.length && !t.length) return '';
  return `<h4 class="help-h4">Related</h4>
    ${g.length ? `<div class="help-chips">${g.map((x) => `<a class="help-chip guide" href="#help/guides/${esc(x.id)}">Guide · ${esc(x.title)}</a>`).join('')}</div>` : ''}
    ${t.length ? `<div class="help-chips">${t.map((x) => `<a class="help-chip" href="#help/glossary/${esc(x.id)}">${esc(x.term)}</a>`).join('')}</div>` : ''}`;
}

// ---- Is everything working?
function loadHealth() {
  if (health && Date.now() - healthAt < 30000) return Promise.resolve(health);
  healthP ||= checks().then((r) => { health = r; healthAt = Date.now(); healthP = null; return r; }, () => { healthP = null; return null; });
  return healthP;
}
function healthBanner() {
  if (!health) return '<a class="help-hb" href="#help/status"><span class="help-dot" data-s="wait" aria-hidden="true"></span>Checking that everything is working…</a>';
  const s = summary(health.lines);
  return `<a class="help-hb" href="#help/status" data-s="${esc(s.state)}"><span class="help-dot" data-s="${esc(s.state)}" aria-hidden="true"></span>${esc(s.text)}<span class="help-hb-go">Is everything working? ›</span></a>`;
}
const STATE_WORD = { ok: 'Working', warn: 'Needs a look', off: 'Off or optional' };
function statusPane() {
  if (!health) return `<section class="help-sec"><p class="help-kicker">Live check</p><h3 class="help-h">Is everything working?</h3><p class="help-lede">Checking the server, sources, your logs and the AI helper…</p></section>`;
  const s = summary(health.lines);
  const n = (st) => health.lines.filter((l) => l.state === st).length;
  return `<section class="help-sec">
    <p class="help-kicker">Live check</p><h3 class="help-h">Is everything working?</h3>
    <div class="help-sum" data-s="${esc(s.state)}"><span class="help-dot big" data-s="${esc(s.state)}" aria-hidden="true"></span><div><b>${esc(s.text)}</b>
      <span>${n('ok')} working · ${n('warn')} to look at · ${n('off')} off or optional · checked ${esc(T.time(health.at))}</span></div>
      <button class="help-do ghost" data-recheck>Check again</button></div>
    <ul class="help-checks">${health.lines.map((l) => `<li class="help-check" data-s="${esc(l.state)}" data-task>
      <span class="help-dot" data-s="${esc(l.state)}" aria-hidden="true"></span>
      <div class="help-check-b"><b>${esc(l.title)}</b><span class="sr-only"> (${STATE_WORD[l.state]})</span><span${l.tech ? ` title="${esc(l.tech)}"` : ''}>${esc(l.detail)}</span></div>
      ${l.fix ? doBtn(l.fix, l.state === 'warn' ? 'sm' : 'sm ghost') : ''}</li>`).join('')}</ul>
    <p class="help-note"><span class="help-dot" data-s="ok" aria-hidden="true"></span>working <span class="help-dot" data-s="warn" aria-hidden="true"></span>needs a look <span class="help-dot" data-s="off" aria-hidden="true"></span>off, optional or not set up (not a fault)</p>
  </section>`;
}

// ---- Guides
function guidesPane(arg) {
  const g = guideById.get(arg);
  if (g) {
    return `<section class="help-sec">
      <a class="help-back-l" href="#help/guides">‹ All guides</a>
      <p class="help-kicker">Guide · about ${esc(g.time)}</p><h3 class="help-h">${esc(g.title)}</h3>
      <p class="help-lede">${esc(g.summary)}</p>
      ${(() => { const p = readProg(); const done = p?.id === g.id ? p.done : []; return `${done.length ? `<p class="help-dim help-prog">${done.length} of ${g.steps.length} steps done · <button class="help-link" data-restart="${esc(g.id)}">Start over</button></p>` : ''}
      <ol class="help-steps">${g.steps.map(sqlStep).map((s, i) => `<li data-task data-step="${i}" class="${done.includes(i) ? 'done' : ''}"><div class="help-step-t">${s.t}${done.includes(i) ? '<span class="sr-only"> (done)</span>' : ''}</div>${s.act ? (shownStepAct(s.act) ? doBtn(s.act, 'sm') : '<span class="help-dim help-step-note">The demo is already loaded.</span>') : ''}</li>`).join('')}</ol>`; })()}
      ${g.terms?.length ? `<h4 class="help-h4">Words used here</h4><div class="help-chips">${g.terms.map((id) => termById.get(id)).filter(Boolean).map((t) => `<a class="help-chip" href="#help/glossary/${esc(t.id)}">${esc(t.term)}</a>`).join('')}</div>` : ''}
    </section>`;
  }
  return `<section class="help-sec">
    <p class="help-kicker">Guides</p><h3 class="help-h">Do one thing, step by step</h3>
    <p class="help-lede">Short recipes. The buttons in each step do the step for you or take you there.</p>
    <div class="help-cards">${GUIDES.map((x, i) => `<a class="help-card" href="#help/guides/${esc(x.id)}"><span class="help-card-n mono">${String(i + 1).padStart(2, '0')}</span>
      <span class="help-card-b"><b>${esc(x.title)}</b><span>${esc(x.summary)}</span></span><span class="help-card-t mono">${esc(x.time)}</span></a>`).join('')}</div>
  </section>`;
}

// The SQL console is off unless the server says otherwise (OSINTHUB_SQL_CONSOLE=1): a guide step with `off` shows that
// text and no button instead, and a glossary "Where" link into the console is left out.
const sqlStep = (s) => (s.off && !sqlConsoleOn() ? { t: s.off } : s);
const sqlWhere = ([, href]) => sqlConsoleOn() || !/^#\/?explorer\b/.test(href);

// ---- Glossary
function glossaryPane() {
  const sorted = [...GLOSSARY].sort((a, b) => a.term.localeCompare(b.term, 'en', { sensitivity: 'base' }));
  let last = '';
  const items = sorted.map((g) => {
    const L = g.term[0].toUpperCase();
    const head = L !== last ? `<div class="help-gl-letter" aria-hidden="true">${esc((last = L))}</div>` : '';
    return `${head}<article class="help-term" data-anchor="${esc(g.id)}" data-cat="${esc(g.cat)}" id="help-g-${esc(g.id)}">
      <h4>${esc(g.term)}<span class="help-cat">${esc(CATS[g.cat] || '')}</span></h4>
      ${g.aka ? `<p class="help-aka">Also: ${esc(g.aka)}</p>` : ''}
      <p>${esc(g.short)}</p>
      <p class="help-why"><b>Why it matters here.</b> ${esc(g.why)}</p>
      <p class="help-wh"><span>Where:</span> ${g.where.filter(sqlWhere).map(([l, href]) => `<a href="${esc(href)}">${esc(l)}</a>`).join(' · ')}</p></article>`;
  }).join('');
  return `<section class="help-sec">
    <p class="help-kicker">Glossary · ${GLOSSARY.length} words</p><h3 class="help-h">The words Night Desk uses</h3>
    <p class="help-lede">In plain language. Dotted words around the app show these definitions when you hover, tap or focus them.</p>
    <div class="help-chips help-filter" role="group" aria-label="Show">${[['all', 'All'], ...Object.entries(CATS)].map(([id, l], i) => `<button class="help-chip" data-gcat="${id}" aria-pressed="${i === 0}">${esc(l)}</button>`).join('')}</div>
    <div class="help-gl">${items}</div></section>`;
}

// ---- Shortcuts and commands
function keysPane() {
  const groups = new Map();
  for (const c of commands().filter((x) => !x.when || x.when()).sort((a, b) => a.order - b.order || a.label.localeCompare(b.label))) {
    const g = c.group || 'Other';
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(c);
  }
  const kbd = (k) => k.map((x) => `<kbd class="mono">${esc(x)}</kbd>`).join('<span class="help-or">or</span>');
  return `<section class="help-sec">
    <p class="help-kicker">Shortcuts</p><h3 class="help-h">Keyboard shortcuts</h3>
    <p class="help-lede">Single-letter keys work when you are not typing and nothing is open over the page.</p>
    ${KEY_GROUPS.map((g) => `<h4 class="help-h4">${esc(g.where)}</h4><dl class="help-keys">${g.rows.map((r) => `<dt>${kbd(r.keys)}</dt><dd>${esc(r.label)}</dd>`).join('')}</dl>`).join('')}
    <h4 class="help-h4" data-anchor="commands">Command palette <kbd class="mono">⌘K</kbd></h4>
    <p class="help-dim">Everything you can type in the palette. Choose one to run it now.</p>
    <div class="help-row">${doBtn({ fn: 'palette', label: 'Open the palette' }, 'ghost')}</div>
    ${[...groups].map(([g, cs]) => `<div class="help-cmdg"><span class="help-cmdg-h">${esc(g)}</span><div class="help-cmds">${cs.map((c) => `<button class="help-cmd" data-cmd="${esc(c.id)}">${esc(c.label)}</button>`).join('')}</div></div>`).join('')}
  </section>`;
}

// ---- Data sources and terms
function loadSources() {
  return api.get('/api/help/sources').then((d) => { srcData = d; }, (e) => { srcData = { error: e.message }; });
}
const CAT_NAMES = { vuln: 'Vulnerabilities', threat: 'Threat lists', infra: 'Internet health', news: 'News', social: 'Social' };
function srcState(s) {
  if (s.unavailable) return ['key', 'Needs a key'];
  if (!s.enabled) return ['off', 'Off'];
  if (srcData?.offline) return ['paused', 'On · paused offline'];
  if (['error', 'reconnecting'].includes(s.status)) return ['err', 'On · has a problem'];
  return ['on', 'On'];
}
function sourcesPane() {
  if (!srcData) return '<section class="help-sec"><p class="help-kicker">Sources</p><h3 class="help-h">Data sources and terms</h3><p class="help-lede">Reading the source list…</p></section>';
  if (srcData.error) return `<section class="help-sec"><h3 class="help-h">Data sources and terms</h3>${errorState({ retry: () => location.reload(), retryLabel: 'Reload the page', title: "Couldn't read the source list", why: 'The Night Desk server did not answer. Reopen help to try again.', err: srcData.error, size: 'sm' })}</section>`;
  const list = srcData.sources || [];
  const on = list.filter((s) => s.enabled && !s.unavailable).length;
  const key = list.filter((s) => s.unavailable).length;
  const cats = new Map();
  for (const s of list) { const c = CAT_NAMES[s.category] || 'Other'; if (!cats.has(c)) cats.set(c, []); cats.get(c).push(s); }
  const row = (s) => {
    const [st, word] = srcState(s);
    return `<li class="help-src" data-state="${st === 'on' || st === 'paused' || st === 'err' ? 'on' : 'off'}" data-anchor="${esc(s.id)}">
      <div class="help-src-h"><b>${esc(s.name)}</b><span class="help-pill" data-s="${st}">${esc(word)}</span></div>
      <p>${esc(s.gives || s.description || '')}</p>
      <p class="help-terms"><span class="help-lic">${esc(s.licence || 'Terms')}</span>${s.badge ? `<span class="help-lic warn">${esc(s.badge)}</span>` : ''}${s.tier ? `<span class="help-lic" title="Trust tier ${esc(s.tier)}: ${esc(s.tier_words || '')}">Tier ${esc(s.tier)} · ${esc(s.tier_words || '')}</span>` : ''}</p>
      <p class="help-dim">${esc(s.terms)}${s.terms_more ? ` ${esc(s.terms_more)}` : ''}${s.terms_url ? ` <a href="${esc(s.terms_url)}" target="_blank" rel="noopener noreferrer" class="help-ext">Read the terms ↗</a>` : ''}</p></li>`;
  };
  return `<section class="help-sec">
    <p class="help-kicker">Sources · from the source registry</p><h3 class="help-h">Data sources and terms</h3>
    <p class="help-lede">Every source Night Desk can read, what it gives you and its terms in plain words. ${on} of ${list.length} on${key ? `, ${key} waiting for a key` : ''}${srcData.offline ? '; offline mode pauses them all' : ''}.</p>
    <div class="help-row"><div class="help-chips help-filter" role="group" aria-label="Show">${[['all', 'All'], ['on', 'On'], ['off', 'Off']].map(([id, l], i) => `<button class="help-chip" data-filter="${id}" aria-pressed="${i === 0}">${l}</button>`).join('')}</div>
      <a class="help-link" href="#settings/sources">Turn sources on or off ›</a></div>
    ${[...cats].map(([c, ss]) => `<h4 class="help-h4">${esc(c)} <span class="help-dim">${ss.length}</span></h4><ul class="help-srcs">${ss.map(row).join('')}</ul>`).join('')}
    <h4 class="help-h4">Reference data</h4><p class="help-dim">Shipped with Night Desk or downloaded once into the data folder.</p>
    <ul class="help-srcs">${(srcData.reference || []).map((r) => `<li class="help-src" data-state="on"><div class="help-src-h"><b>${esc(r.name)}</b></div><p>${esc(r.gives)}</p>
      <p class="help-terms"><span class="help-lic">${esc(r.licence)}</span></p><p class="help-dim">${esc(r.terms)} <a href="${esc(r.terms_url)}" target="_blank" rel="noopener noreferrer" class="help-ext">Read the terms ↗</a></p></li>`).join('')}</ul>
    <h4 class="help-h4" data-anchor="credits">Credits</h4>
    ${creditsList()}
    <p class="help-credits">abuse.ch's free tier is for not-for-profit use only, with no redistribution, no high-volume harvesting (at most one fetch every 5 minutes) and no use to train or improve AI models: Night Desk keeps its data on this machine and never gives it to the AI helper.</p>
  </section>`;
}
// Help › Sources › Credits: who the data comes from, with the credit lines their terms ask for. Static text: links
// open the provider's site in a new tab; nothing is fetched to draw this. Terms review: okf/project/pre-alpha-release.md
const ext = (href, text) => `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`;
const DBIP_CREDIT = ext('https://db-ip.com', 'IP Geolocation by DB-IP');
const CREDITS = [
  ['Vulnerabilities', `<b>CISA</b> (Known Exploited Vulnerabilities, advisories) and <b>NIST NVD</b>: this product uses the NVD API but is not endorsed or certified by the NVD. Exploit prediction scores: <b>FIRST EPSS</b> (${ext('https://www.first.org/epss/', 'first.org/epss')}).`],
  ['Threat lists', `<b>abuse.ch</b> (Feodo Tracker, SSL Blacklist, ThreatFox, URLhaus), <b>The Spamhaus Project</b>, <b>SANS Internet Storm Center</b> (DShield), <b>blocklist.de</b>, <b>CINS Army</b> (Sentinel IPS), <b>Proofpoint Emerging Threats</b>, the <b>Tor Project</b>.`],
  ['Ransomware', `Victim postings from <b>${ext('https://www.ransomware.live/', 'ransomware.live')}</b>, for non-commercial use.`],
  ['Routing and outages', `<b>RIPE NCC</b> (RIPEstat and RIS), <b>Cloudflare Radar</b> (CC BY-NC 4.0), RPKI files from Cloudflare and rpki-client, <b>IODA</b> (Georgia Tech).`],
  ['Geolocation', `${DBIP_CREDIT} (CC BY 4.0).`],
  ['Maps', `Country shapes from <b>Natural Earth</b>. Undersea cables (only once you turn the layer on): <b>TeleGeography</b> (submarinecablemap.com). Online basemaps (only with your own CARTO key): © OpenStreetMap contributors, © <b>CARTO</b>. Globe images: <b>NASA</b> Blue Marble and Black Marble (public domain).`],
  ['Actors and malware', `<b>MISP galaxy</b> (threat actors, tools) and <b>Malpedia</b> (Fraunhofer FKIE; the Malpedia cluster is CC BY-NC-SA 3.0).`],
  ['Techniques', `<b>MITRE ATT&amp;CK®</b>. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.`],
];
function creditsList() {
  return `<dl class="help-credits help-credit-list">${CREDITS.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
}
function filterSources(f) {
  box.querySelectorAll('.help-src').forEach((li) => { li.hidden = f !== 'all' && li.dataset.state !== f; });
}

// ---- About, diagnostics and docs
let aboutP = null;
function loadAbout() {
  aboutP ||= Promise.all([
    api.get('/api/help/diagnostics').then((d) => { diag = d; }, (e) => { diag = { error: e.message }; }),
    api.get('/api/help/docs').then((d) => { docList = d; }, () => { docList = { available: false, docs: [] }; }),
  ]).finally(() => { aboutP = null; });
  return aboutP;
}
const mb = (b) => (b == null ? '—' : b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : b >= 1e6 ? `${Math.round(b / 1e6)} MB` : b >= 1e3 ? `${Math.round(b / 1e3)} kB` : `${b} B`);
const dur = (s) => (s == null ? '—' : s < 3600 ? `${Math.round(s / 60)} min` : s < 86400 ? `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min` : `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`);
function browser() {
  const ua = navigator.userAgent;
  const m = ua.match(/(Firefox|Edg|OPR|Chrome|Version)\/(\d+)/);
  const name = !m ? 'Unknown browser' : m[1] === 'Version' ? `Safari ${m[2]}` : m[1] === 'Edg' ? `Edge ${m[2]}` : m[1] === 'OPR' ? `Opera ${m[2]}` : `${m[1]} ${m[2]}`;
  const os = /Mac OS X/.test(ua) ? (/iPhone|iPad/.test(ua) ? 'iOS' : 'macOS') : /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /Linux/.test(ua) ? 'Linux' : '';
  const rm = matchMedia('(prefers-reduced-motion: reduce)').matches;
  return `${name}${os ? ` on ${os}` : ''} · ${innerWidth}×${innerHeight} · ${navigator.language || ''} · reduced motion ${rm ? 'on' : 'off'}`;
}
function aiWord(a) { return !a || a.installed === false ? 'Not in this build' : a.up ? 'Running' : a.configured ? 'Expected but not answering' : 'Not running (optional)'; }
function facts() {
  const d = diag || {};
  const app = d.app || {}, lake = d.lake || {}, nl = d.network_logs || {}, f = d.feeds || {};
  const parts = Object.entries(lake.parts || {}).map(([k, v]) => `${k} ${mb(v.bytes)}`).join(', ');
  return [
    ['Version', `${app.version || '—'}${app.commit ? ` (commit ${app.commit})` : ''}`],
    ['Running for', `${dur(app.uptime_s)}${app.in_docker ? ' · in Docker' : ''}`],
    ['Offline mode', app.offline ? 'On: nothing is fetched' : 'Off: sources are fetched on schedule'],
    ['Data folder', lake.path || '—'],
    ['Data size', `${mb(lake.bytes)}${parts ? ` (${parts})` : ''}`],
    ['Records collected', d.data ? `${fmt(d.data.events)}${d.data.last_ingested ? ` · last ${T.stamp(d.data.last_ingested, { zone: true })}` : ''}` : '—'],
    ['Sources', f.known != null ? `${f.on} of ${f.known} on${f.needs_key?.length ? ` · waiting for their key (${f.needs_key.join(', ')})` : ''} · with errors: ${f.with_errors?.length ? f.with_errors.join(', ') : 'none'}` : '—'],
    ['Network logs', nl.installed === false ? 'Not in this build' : `${fmt(nl.files)} files · ${fmt(nl.rows)} rows · ${fmt(nl.devices)} devices${nl.demo_loaded ? ' · demo loaded' : ''}${nl.newest_record ? ` · newest ${T.stamp(nl.newest_record, { zone: true })}` : ''} · ${nl.home_prefixes_set ?? 0} home prefixes · ${nl.upload_devices ?? 0} upload devices · needs you ${nl.needs_you ?? '—'}`],
    ['Intel', d.intel ? `${fmt(d.intel.entities)} entities · ${fmt(d.intel.claims)} claims` : '—'],
    ['AI helper', aiWord(d.ai_helper)],
    ['System', d.system ? `${d.system.platform} ${d.system.machine} · Python ${d.system.python} · DuckDB ${d.system.duckdb || '?'} · vectors ${d.system.vectors}` : '—'],
    ['Extensions', d.extensions ? `${d.extensions.loaded.join(', ')}${d.extensions.failed?.length ? ` · failed: ${d.extensions.failed.join(', ')}` : ''}` : '—'],
    ['Browser', browser()],
    ['Live connection', live.isOffline?.() ? 'Connected (offline mode: sources paused)' : live.status().state === 'offline' ? 'Lost, retrying' : 'Connected'],
  ];
}
// The same rules as the server's redact(): no IP or MAC addresses, no key=value secrets, no long tokens.
export function redact(s) {
  return String(s)
    .replace(/\b([a-z0-9_]*?(?:key|token|secret|password|passwd)s?)\s*([=:])\s*\S+/gi, '$1$2[redacted]')
    .replace(/\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g, '[mac]')
    .replace(/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}/gi, '$1 [redacted]')
    .replace(/(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4})(?:\/\d{1,3})?(?![0-9A-Za-z:.])/g, (m) => (/^[0-9A-Fa-f:/.]+$/.test(m) && /[0-9A-Fa-f]/.test(m) && (m.match(/:/g).length >= 3 || m.includes('::')) && !/^\d{1,2}:\d{2}(:\d{2})?$/.test(m) ? '[ip]' : m))
    .replace(/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?(?![\d.])/g, '[ip]');
}
export function diagText() {
  return redact([
    'Night Desk diagnostics (redacted: no addresses, keys, device names or home prefixes)',
    `Generated: ${new Date().toISOString().slice(0, 19)}Z`,
    ...facts().map(([k, v]) => `${k}: ${v}`),
    ...(health ? ['', 'Health:', ...health.lines.map((l) => `  [${l.state}] ${l.title}`)] : []),
  ].join('\n'));
}
export async function copyDiag() {
  if (!diag) await loadAbout();
  await new Promise((r) => setTimeout(r, 0));
  if (cur.sec === 'about') paint('about', cur.arg);
  const text = diagText();
  const out = box.querySelector('.help-diag-out');
  try {
    await navigator.clipboard.writeText(text);
    toast('Diagnostics copied');
    if (out) { out.hidden = false; out.querySelector('textarea').value = text; }
  } catch {
    if (out) { out.hidden = false; const ta = out.querySelector('textarea'); ta.value = text; ta.focus(); ta.select(); }
    toast('Copy is blocked here: the text is selected below, press ⌘C or Ctrl+C.');
  }
}
function aboutPane() {
  const items = ctl.items().filter((i) => !['tour', 'keys', 'desk'].includes(i.id));
  const docs = docList?.docs || [];
  return `<section class="help-sec">
    <p class="help-kicker">About</p><h3 class="help-h">About Night Desk</h3>
    <p class="help-lede">A local-first security desk: sources, models and your data stay on this machine.</p>
    <div class="help-row">${doBtn({ fn: 'tour', label: 'Take the tour' }, 'ghost')}${noKeys() ? '' : '<a class="help-do ghost" href="#help/keys">Keyboard shortcuts</a>'}${items.map((i) => `<button class="help-do ghost" data-item="${esc(i.id)}">${esc(i.label)}</button>`).join('')}</div>
    <h4 class="help-h4">This install</h4>
    ${!diag ? '<p class="help-dim">Reading…</p>' : diag.error ? errorState({ retry: () => location.reload(), retryLabel: 'Reload the page', title: "Couldn't read the diagnostics", why: 'The Night Desk server did not answer. Reopen help to try again.', err: diag.error, size: 'sm' }) : `<dl class="help-kv">${facts().map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`}
    <div class="help-diag" data-anchor="diagnostics"><div><b>Copy diagnostics</b><span>A plain-text summary for a bug report. Addresses, MACs, keys, device names and home prefixes are left out.</span></div>
      <button class="help-do" data-copy-diag ${diag && !diag.error ? '' : 'disabled'}>Copy diagnostics</button></div>
    <div class="help-diag-out" hidden><label class="help-dim" for="help-diag-ta">What was copied</label><textarea id="help-diag-ta" class="mono" readonly rows="10"></textarea></div>
    <h4 class="help-h4" data-anchor="credits">Credits</h4>
    <p class="help-credits">${DBIP_CREDIT}. Threat lists, vulnerability data, routing, maps and ATT&amp;CK: see <a href="#help/sources/credits">every source's credit and terms</a>.</p>
    <h4 class="help-h4" data-anchor="docs">Local documentation</h4>
    ${docList && !docList.available ? '<p class="help-dim">The documentation folder is not part of this install.</p>' : `<ul class="help-docs">${docs.slice(0, 60).map((d) => `<li><a href="#help/docs/${esc(d.path)}"><b>${esc(d.title)}</b><span>${esc(d.description)}</span></a></li>`).join('') || '<li class="help-dim">Reading…</li>'}</ul>`}
  </section>`;
}
function docPane(path) {
  return `<section class="help-sec help-doc"><a class="help-back-l" href="#help/about/docs">‹ About and docs</a><div class="help-md" data-doc-path="${esc(path)}"><p class="help-dim">Opening ${esc(path)}…</p></div></section>`;
}
async function loadDoc(path) {
  let html;
  try {
    if (!/^[A-Za-z0-9_\-/.]+\.md$/.test(path) || path.split('/').some((x) => x === '..' || x === '.' || !x)) throw Object.assign(new Error('no such page'), { status: 404 });
    const d = await api.get(`/api/help/docs/${path.split('/').map(encodeURIComponent).join('/')}`);
    html = `<p class="help-kicker">Docs · ${esc(d.path)}</p><h3 class="help-h">${esc(d.title)}</h3>${d.description ? `<p class="help-lede">${esc(d.description)}</p>` : ''}${renderMd(d.markdown, d.path)}`;
  } catch (e) { html = e.status === 404 ? errorState({ act: stateAct('Open the guides', { href: '#help/guides' }), title: 'That page is not in the local docs', why: 'Pick another page from the list.', size: 'sm' }) : errorState({ retry: () => loadDoc(path), title: "Couldn't open this page", why: 'The Night Desk server did not answer. Try again in a moment.', err: e.message, size: 'sm' }); }
  const el = body?.querySelector(`.help-md[data-doc-path="${CSS.escape(path)}"]`);
  if (el) el.innerHTML = html;
}

// ------------------------------------------------------------------ search across everything
function index() {
  const ix = [];
  for (const [id, short, long] of SECTIONS) ix.push({ type: 'Section', title: long, sub: short, hay: `${long} ${short}`, path: id });
  for (const k of PAGE_ORDER) {
    const p = PAGES[k];
    ix.push({ type: 'Page help', title: p.title, sub: p.lede, hay: `${p.title} ${p.lede} ${p.parts.flat().join(' ')}`, path: `page/${k}` });
    for (const t of p.tasks) ix.push({ type: 'Task', title: t.label, sub: `${p.title}: ${t.text}`, hay: `${t.label} ${t.text} ${p.title}`, act: t.act });
  }
  for (const g of GLOSSARY) ix.push({ type: 'Glossary', title: g.term, sub: g.short, hay: `${g.term} ${g.aka || ''} ${g.short} ${g.why}`, path: `glossary/${g.id}`, w: 1 });
  for (const g of GUIDES) ix.push({ type: 'Guide', title: g.title, sub: g.summary, hay: `${g.title} ${g.summary} ${g.steps.map((s) => s.t.replace(/<[^>]+>/g, '')).join(' ')}`, path: `guides/${g.id}` });
  if (!noKeys()) for (const g of KEY_GROUPS) for (const r of g.rows) ix.push({ type: 'Shortcut', title: `${r.keys.join(' or ')}  ${r.label}`, sub: g.where, hay: `${r.keys.join(' ')} ${r.label} ${g.where} key keyboard shortcut`, path: 'keys' });
  for (const c of commands().filter((x) => !x.when || x.when())) ix.push({ type: 'Command', title: c.label, sub: c.group ? `⌘K · ${c.group}` : '⌘K', hay: `${c.label} ${c.group} ${c.keywords}`, cmd: c.id });
  for (const s of srcData?.sources || []) ix.push({ type: 'Source', title: s.name, sub: `${s.licence || ''} · ${s.gives || ''}`, hay: `${s.name} ${s.id.replace(/_/g, ' ')} ${s.provider} ${s.gives} ${s.terms} ${s.licence} licence terms`, path: 'sources' });
  for (const d of docList?.docs || []) ix.push({ type: 'Docs', title: d.title, sub: d.description, hay: `${d.title} ${d.description} ${d.path}`, path: `docs/${d.path}` });
  ix.push({ type: 'Section', title: 'Copy diagnostics', sub: 'About › for a bug report', hay: 'copy diagnostics bug report version commit about', path: 'about' });
  return ix;
}
const ORDER = ['Section', 'Page help', 'Task', 'Glossary', 'Guide', 'Shortcut', 'Command', 'Source', 'Docs'];
function mark(text, words) {
  let t = esc(text);
  for (const w of words) if (w.length > 1) t = t.replace(new RegExp(`(${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/&/g, '&amp;')})`, 'ig'), '<mark>$1</mark>');
  return t;
}
// Search words: lower case, split on anything that is not a letter or digit, stop words dropped, light stemming and a
// few spellings folded together, so "how do I back up", "backup", "quieting" and "license" find what they mean.
const STOP = new Set('a an the and or of to in on for with is are be it its this that these my me i do does did how what why when where can could should would will you your from by at as into about which who there here than then up out get make use using want need'.split(' '));
const SYN = { license: 'licence', licenses: 'licence', licensing: 'licence', licensed: 'licence', backups: 'backup', setup: 'set', ack: 'acknowledge', ip: 'address', ips: 'address', addresses: 'address', vuln: 'vulnerability', vulns: 'vulnerability', colour: 'color', recognise: 'recognize', organisation: 'organization' };
function stem(w) {
  w = SYN[w] || w;
  if (w.length <= 3) return w;
  let s = w;
  if (/ies$/.test(s)) s = `${s.slice(0, -3)}y`;
  else if (/(ing|ed)$/.test(s)) { s = s.replace(/(ing|ed)$/, ''); if (/([^aeiouls])\1$/.test(s)) s = s.slice(0, -1); }
  else if (/(ches|shes|sses|xes)$/.test(s)) s = s.slice(0, -2);
  else if (/[^su]s$/.test(s)) s = s.slice(0, -1);
  return s.length >= 3 ? s : w;
}
function tokens(text, doStem = true) {
  const t = String(text || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().split(' ').filter(Boolean);
  return doStem ? t.map(stem) : t;
}
function paintSearch() {
  const q = input.value.trim().toLowerCase();
  if (!q) { show(`${cur.sec}${cur.arg ? `/${cur.arg}` : ''}`); return; }
  if (!srcData) loadSources().then(() => input?.value.trim() && paintSearch());
  if (!docList) loadAbout().then(() => input?.value.trim() && paintSearch());
  acts = [];
  const raw = tokens(q, false);
  const words = raw.filter((w) => !STOP.has(w)).map(stem);
  const qw = words.length ? words : raw.map(stem);
  const hits = [];
  for (const it of index()) {
    const tk = tokens(`${it.title} ${it.hay}`), tt = tokens(it.title);
    const compact = tk.join('');
    const has = (w, list, c) => list.some((t) => t.startsWith(w)) || (w.length > 3 && c.includes(w));
    const n = qw.filter((w) => has(w, tk, compact)).length;
    if (!n) continue;
    const inTitle = qw.filter((w) => has(w, tt, tt.join(''))).length;
    const all = n === qw.length;
    if (!all && qw.length > 1 && n / qw.length < 0.5) continue;
    const sc = (all ? 100 : 40 * n / qw.length) + inTitle * 4 + (tt[0]?.startsWith(qw[0]) ? 5 : 0) + (it.w || 0);
    hits.push([it, sc]);
  }
  const markWords = [...new Set([...raw.filter((w) => !STOP.has(w)), ...qw])];
  hits.sort((a, b) => b[1] - a[1] || ORDER.indexOf(a[0].type) - ORDER.indexOf(b[0].type));
  if (!hits.length) {
    body.innerHTML = `<section class="help-sec"><p class="help-kicker">Search</p><h3 class="help-h">Nothing in Help matches “${esc(input.value.trim())}”</h3>
      <p class="help-lede">Try a shorter word, or search your data instead.</p><div class="help-row">${doBtn({ fn: 'search', label: 'Search everything in Night Desk' }, 'ghost')}<a class="help-do ghost" href="#help/glossary">Browse the glossary</a></div></section>`;
    return;
  }
  const groups = new Map(), best = new Map();
  for (const [it, sc] of hits) {
    if (!groups.has(it.type)) { groups.set(it.type, []); best.set(it.type, sc); }
    groups.get(it.type).push(it);
  }
  root.querySelectorAll('[data-sec]').forEach((b) => b.removeAttribute('aria-current'));
  const res = (it) => {
    const attrs = it.cmd ? `data-cmd="${esc(it.cmd)}"` : it.act ? `data-act="${act(it.act)}"` : `data-go="${esc(it.path)}"`;
    return `<button class="help-res" ${attrs}><b>${mark(it.title, markWords)}</b><span>${mark(it.sub || '', markWords)}</span></button>`;
  };
  body.innerHTML = `<section class="help-sec"><p class="help-kicker" role="status">${hits.length} result${hits.length === 1 ? '' : 's'}</p>
    ${[...groups].sort((a, b) => best.get(b[0]) - best.get(a[0]) || ORDER.indexOf(a[0]) - ORDER.indexOf(b[0])).map(([t, its]) => `<h4 class="help-h4">${esc(t)}</h4><div class="help-results">${its.slice(0, 6).map(res).join('')}${its.length > 6 ? `<details class="help-more"><summary>${its.length - 6} more</summary>${its.slice(6, 40).map(res).join('')}</details>` : ''}</div>`).join('')}</section>`;
  body.querySelectorAll('[data-go]').forEach((b) => (b.onclick = () => { input.value = ''; ctl.section(b.dataset.go); }));
}

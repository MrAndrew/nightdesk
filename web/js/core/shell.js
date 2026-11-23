// App shell: routes and views, the top bar (navigation, feed health, gear and help menus, clock), the phone bottom
// bar, the command palette, the deck grid and panel chrome, the drawer, and Cinema's kiosk mode.
// Contract: okf/architecture/web-client.md#top-bar
import { api, sqlConsoleOn } from './api.js';
import { live } from './live.js';
import { store } from './store.js';
import * as util from './util.js';
import { PANELS, VIEWS } from './panels.js';
import { setupSearch, closeSearch, searchRoute } from './search.js';
import { emptyState, errorState, loadingState, stateAct } from './view.js';
import { setupAlertsBadge } from './alerts-badge.js';
import { watch as watchChips, seenSlot, fillSeen } from './chips.js';
import { closeEntity, isEntityOpen, setEventHost, swapNow } from './entity-panel.js';
import { entityHref } from './open.js';
import { registerCommand } from './commands.js';
import { registerHelp, renderHelp, showShortcuts, openHelp, closeHelp, isHelpOpen } from './help.js';
import { landing, LS } from './prefs.js';
import * as T from './time.js';
import { mount as mountRange, hashRange, syncHash as rangeSyncHash, LIVE } from './range.js';
import { isPhone, onPhoneChange } from './mobile.js';
import { need } from './libs.js';
import { initPhoneShell } from './mshell.js';

const { h, esc, ago, kindMeta, flag, debounce } = util;

// Built-in deck templates. v1.1: Feed Health left the default decks (feed health is the top-bar dot and the Ops
// sub-bar link to Settings › Sources) and Threat Origins 3D left them too (a third globe); both stay in the widget
// catalogue. migrateDecks() moves untouched saved copies of the old templates onto these.
export const DECKS = {
  'Cyber Ops': [
    ['world-map', 0, 0, 8, 8], ['cyber-pulse', 8, 0, 4, 4], ['bgp-live', 8, 4, 4, 4],
    ['kev-tracker', 0, 8, 4, 7], ['social-feed', 4, 8, 4, 7], ['news-wire', 8, 8, 4, 7],
    ['activity-timeline', 0, 15, 12, 5],
    // your own network (panels/network.js)
    ['net-attention', 0, 20, 4, 6], ['net-devices', 4, 20, 4, 6], ['net-timeline', 8, 20, 4, 6],
  ],
  'Threat Infrastructure': [
    ['world-map', 0, 0, 12, 8], ['top-offenders', 0, 8, 12, 7],
    ['activity-timeline', 0, 15, 12, 5],
  ],
  'Vulnerabilities': [
    ['kev-tracker', 0, 0, 6, 9], ['cve-feed', 6, 0, 6, 9], ['activity-timeline', 0, 9, 8, 5], ['news-wire', 8, 9, 4, 5],
  ],
  'Internet Health': [
    ['world-map', 0, 0, 8, 8], ['outage-monitor', 8, 0, 4, 8], ['bgp-live', 0, 8, 6, 5], ['cyber-pulse', 6, 8, 6, 5],
  ],
};

// A deck name is a built-in template only if it is one of DECKS' own keys: a custom deck named 'constructor' or
// 'toString' must not pick up Object.prototype members.
const template = (name) => (Object.hasOwn(DECKS, name) ? DECKS[name] : null);


// The earlier templates, exactly (panel, x, y, w, h). A saved layout equal to one of them, in every panel, position
// and size, was never customised, so it follows the new template; a layout where anything was moved, resized, added
// or removed is the user's and is kept. Cyber Ops has two: v1.0, and v1.0 plus the network widgets added in v1.1
// (the new template keeps those widgets).
const NET_ROW = [['net-attention', 0, 20, 4, 6], ['net-devices', 4, 20, 4, 6], ['net-timeline', 8, 20, 4, 6]];
const CYBER_V10 = [
  ['world-map', 0, 0, 8, 8], ['cyber-pulse', 8, 0, 4, 4], ['bgp-live', 8, 4, 4, 4],
  ['kev-tracker', 0, 8, 4, 7], ['social-feed', 4, 8, 4, 7], ['news-wire', 8, 8, 4, 7],
  ['activity-timeline', 0, 15, 8, 5], ['source-health', 8, 15, 4, 5],
];
const OLD_DECKS = {
  'Cyber Ops': [CYBER_V10, [...CYBER_V10, ...NET_ROW]],
  'Threat Infrastructure': [[['world-map', 0, 0, 12, 8], ['attack-globe3d', 0, 8, 6, 7], ['top-offenders', 6, 8, 6, 7], ['activity-timeline', 0, 15, 12, 5]]],
};
export function isUntouchedTemplate(saved, olds) {
  if (!Array.isArray(saved)) return false;
  const key = (rows) => rows.map((r) => r.slice(0, 5).join(':')).sort().join('|');
  return olds.some((old) => saved.length === old.length && key(saved) === key(old));
}
function migrateDecks() {
  if (LS.get('nd.decks.v11', false)) return;
  for (const [name, olds] of Object.entries(OLD_DECKS)) {
    if (isUntouchedTemplate(LS.get(`nd.layout.${name}`, null), olds)) { try { localStorage.removeItem(`nd.layout.${name}`); } catch {} }
  }
  LS.set('nd.decks.v11', true);
}

// ------------------------------------------------------------------ routes
// The view a hash names: '#network/alerts' -> 'network', '#cinema?kiosk' -> 'cinema', '#/entities/x' -> 'entities'.
export const viewOf = (hash = location.hash) => hash.replace(/^#\/?/, '').split(/[/?]/)[0].toLowerCase();
// Old and alias routes, and where they live now. #intel is the Intel tab's alias for #entities (the canonical form,
// which the Entities view reads); Sources moved into Settings.
const ALIASES = [
  [/^#\/?intel(\/.*)?$/i, (m) => `#entities${m[1] || ''}`],
  [/^#\/?sources(?:\/.*)?$/i, () => '#settings/sources'],
];
const canonical = (hash) => { for (const [re, to] of ALIASES) { const m = hash.match(re); if (m) return to(m); } return null; };
// Rewritten in place (no extra history entry) before any view's own hashchange listener sees the alias: this
// listener is registered when shell.js loads, before main.js imports the views.
window.addEventListener('hashchange', (e) => {
  const c = canonical(location.hash);
  if (!c) return;
  e.stopImmediatePropagation();
  history.replaceState(null, '', c);
  window.dispatchEvent(new HashChangeEvent('hashchange'));
});
// What each view is called (tab label, document title, the visually hidden h1 of views that have none on screen).
const TITLES = { watch: 'Watch', network: 'Network', news: 'News', entities: 'Intel', ops: 'Ops', cinema: 'Cinema', explorer: 'SQL console', settings: 'Settings', notes: 'Notes' };
const HIDDEN_H1 = new Set(); // v1.1: every view has a visible header now (core/view.js; Ops' is #subbar)

let grid;
let currentDeck = LS.get('nd.deck', 'Cyber Ops');
const instances = new Map(); // gridstack node id -> {def, inst, ctx, el}
let uid = 0;

// ------------------------------------------------------------------ drawer
// Markup the drawer itself built (with every data value inside it escaped). Only a Trusted is rendered as
// HTML; a plain string is always escaped, whatever it starts with.
class Trusted { constructor(html) { this.html = html; } }
const trusted = (html) => new Trusted(html);

// Vulnerability events (CISA advisory, KEV, NVD, EPSS): their CVEs with CVSS / KEV / EPSS / other advisories, and
// the news stories covering them. Every value is escaped; ids only go into data attributes.
function vulnSection(e) {
  const cves = e.cves || [];
  const stories = e.stories || [];
  if (!cves.length && !stories.length) return '';
  const cvssTag = (c) => (c.cvss != null ? `<span class="tag ${c.cvss >= 9 ? 'red' : c.cvss >= 7 ? 'orange' : 'amber'}" title="${esc(c.cvss_status === 'ok' ? 'CVSS from NVD' : c.cvss_status)}">CVSS ${esc(Number(c.cvss).toFixed(1))}</span>` : '');
  const others = (c) => (c.advisories || []).filter((a) => a.id !== e.advisory_id);
  const rows = cves.slice(0, 30).map((c) => `<div class="row" data-entity="cve:${esc(String(c.id).toLowerCase())}" data-nocard style="padding:7px 0;cursor:pointer" title="Details (Cmd- or Ctrl-click: open full page)">
      <a class="row-title mono" style="font-size:12px" href="${esc(entityHref(`cve:${String(c.id).toLowerCase()}`))}" data-entity="cve:${esc(String(c.id).toLowerCase())}">${esc(c.id)}</a>
      <div class="row-meta" style="display:flex;gap:4px;flex-wrap:wrap">${c.kev ? `<span class="tag red" title="CISA KEV${c.kev_added ? `, added ${esc(T.date(c.kev_added))}` : ''}">KEV</span>` : ''}${c.ransomware ? '<span class="tag red">ransomware</span>' : ''}
        ${cvssTag(c)}${util.epssTag(c.epss, c.epss_percentile, c.epss_prev, c.epss_since)}
        ${others(c).slice(0, 3).map((a) => `<span class="tag amber" title="${esc(a.title || '')}">${esc(a.id)}</span>`).join('')}${seenSlot(c.id, { compact: true })}</div></div>`).join('');
  const more = cves.length > 30 ? `<div class="row-meta">+${cves.length - 30} more</div>` : '';
  const st = stories.map((s) => `<div class="row" data-story="${esc(s.id)}" style="padding:7px 0;cursor:pointer" title="Open the story">
      <div class="row-title" style="font-size:12px">${esc(s.title || s.id)}</div>
      <div class="row-meta">${esc(s.article_count)} article${s.article_count === 1 ? '' : 's'} · ${esc(s.source_count)} outlet${s.source_count === 1 ? '' : 's'} · ${ago(s.last_seen)} · names ${esc((s.matched || []).slice(0, 4).join(', '))}</div></div>`).join('');
  return `${cves.length ? `<div class="section"><div class="label">CVEs (${cves.length})</div>${rows}${more}</div>` : ''}
    ${stories.length ? `<div class="section"><div class="label">Covered in the news (${stories.length})</div>${st}</div>` : ''}`;
}

// Open and close the event drawer in one place, so assistive tech sees it exactly when it is on screen: hidden and
// inert (its off-screen close button and chips out of the Tab order) while closed. It is not modal (the page stays
// usable beside it), so focus is not trapped: opening moves focus to the drawer itself (announced by its label, and
// Tab continues into it), closing returns focus to what opened it. An event opened from inside the drawer keeps the
// original opener. If the opener is gone (a live list re-rendered), focus falls back to the same row by its event id,
// else to the active view tab, never to <body>.
let drawerOpener = null;
const shown = (el) => !!el && el.isConnected && el.getClientRects().length > 0;
// Most event rows are plain clickable rows that never take focus, so a click leaves focus on <body>. The last click
// (captured before any handler runs) tells which row opened the drawer, so Esc can return focus to that row.
let lastPress = null;
document.addEventListener('click', (e) => { lastPress = { el: e.target, t: Date.now() }; }, true);
function openerNow(drawer) {
  const a = document.activeElement;
  const p = lastPress && Date.now() - lastPress.t < 1500 && lastPress.el?.isConnected ? lastPress.el : null;
  const row = p?.closest?.('[data-id], [data-open], .row, button, a[href]');
  if (row && !drawer.contains(row) && (!a || a === document.body || a.contains(row))) return row;
  return a && a !== document.body && !drawer.contains(a) ? a : null;
}
// The drawer hangs below whatever header is on screen: the top bar, the offline notice and Ops' own header (#subbar)
// when it is showing, so it never covers the deck, Widget, Sources or the time range buttons. Where Ops' header has
// wrapped into a tall block (a tablet; more than a tenth of the window) the drawer starts right under the top bar
// instead, over that header, so the event keeps most of the screen (S2-14).
function placeDrawer() {
  const drawer = document.getElementById('drawer');
  const sub = document.getElementById('subbar');
  const subOn = sub && shown(sub) && getComputedStyle(sub).display !== 'none';
  const tall = subOn && sub.getBoundingClientRect().height > window.innerHeight / 10;
  let top = 0;
  const over = tall ? [document.querySelector('.topbar')] : [document.querySelector('.topbar'), document.getElementById('states-offline'), sub];
  for (const el of over) {
    if (el && shown(el) && getComputedStyle(el).display !== 'none') top = Math.max(top, el.getBoundingClientRect().bottom);
  }
  drawer.style.top = top ? `${Math.round(top)}px` : '';
}
let drawerRO = null;
function setDrawer(open, { restore = true } = {}) {
  const drawer = document.getElementById('drawer');
  if (open) { const o = openerNow(drawer); if (o || !drawer.classList.contains('open')) drawerOpener = o; } // an event opened from inside the drawer keeps the first opener
  if (open) {
    placeDrawer();
    if (!drawerRO && window.ResizeObserver) {
      drawerRO = new ResizeObserver(() => { if (drawer.classList.contains('open')) placeDrawer(); });
      for (const el of [document.querySelector('.topbar'), document.getElementById('subbar'), document.getElementById('views')]) if (el) drawerRO.observe(el);
    }
  }
  // one side panel at a time: an event opened while the entity panel is up takes its place
  if (open && isEntityOpen()) { swapNow(drawer, document.querySelector('.ep')); closeEntity({ restore: false }); }
  const wasOpen = drawer.classList.contains('open');
  drawer.classList.toggle('open', open);
  drawer.setAttribute('aria-hidden', String(!open));
  drawer.inert = !open;
  if (open) { drawer.focus({ preventScroll: true }); return; }
  if (!wasOpen) return;
  const opener = drawerOpener;
  drawerOpener = null;
  if (!restore) return;
  refocus(opener, eventNow?.id);
}
// Focus after the side panel closes: what opened it, else the same row by its event id, else the active view tab.
function refocus(opener, eventId = null) {
  const drawer = document.getElementById('drawer');
  let to = shown(opener) ? opener : null;
  const id = opener?.dataset?.id || eventId;
  if (!to && id) to = [...document.querySelectorAll(`[data-id="${CSS.escape(id)}"]`)].find((x) => !drawer.contains(x) && shown(x));
  // a plain row that cannot take focus gets tabindex=-1, so focus can land back on it (not on the view tab)
  if (to && to.tabIndex < 0 && !to.hasAttribute('tabindex')) to.setAttribute('tabindex', '-1');
  // the active tab: the top bar's on desktop, the bottom bar's on phones (the top navigation is hidden there)
  (to || [...document.querySelectorAll('.views button.active, .bnav button.active')].find(shown))?.focus({ preventScroll: true });
}

// The event drawer is the entity panel's event host: one side panel at a time (core/entity-panel.js#setEventHost).
setEventHost({
  el: () => document.getElementById('drawer'),
  isOpen: () => document.getElementById('drawer').classList.contains('open'),
  current: () => eventNow,
  close() { const o = drawerOpener; setDrawer(false, { restore: false }); return o; },
  refocus,
  open: (id, { opener } = {}) => openEvent(id, { opener }),
});

// The name a source goes by in Settings › Sources ('cisa_kev' -> 'CISA Known Exploited Vulnerabilities').
const sourceName = (sid) => feeds.find((s) => s.id === sid)?.name || sid;
// Severity (0..1) as a word a home-lab owner reads at a glance.
const severityWord = (v) => (v >= 0.85 ? 'Critical' : v >= 0.65 ? 'High' : v >= 0.4 ? 'Medium' : 'Low');

// "Listed by N feeds" for an event's address (GET /api/events/{id} reported_by: every feed that listed it in all the
// lake holds, newest listing first). Corroboration, not a confidence score, and it says so.
function feedsSection(e) {
  const fs = e.reported_by || [];
  if (!e.ip || !fs.length) return '';
  return `<div class="section drawer-feeds"><div class="label">Listed by ${util.feedsWord(fs.length)}</div>
    <ul>${fs.map((f) => `<li><span>${esc(f.name || sourceName(f.source))}</span><span class="mono" title="${esc(T.stamp(f.last, { year: true, zone: true }))}">last listed ${esc(ago(f.last))}</span></li>`).join('')}</ul>
    <p>${esc(fs.length > 1 ? util.feedsNote(fs.length) : 'Only this feed lists this address in what Night Desk holds.')}</p></div>`;
}

let eventSeq = 0; // only the most recently opened event may render: a slow earlier response is dropped
let eventNow = null; // {id, title} of the event on screen, for the entity panel's Back step
// opts.opener: where focus returns on close (the entity panel's Back passes the row that first opened the event).
export async function openEvent(id, { opener } = {}) {
  const body = document.getElementById('drawer-body');
  const kindEl = document.getElementById('drawer-kind');
  const my = ++eventSeq;
  eventNow = { id, title: '' };
  body.innerHTML = `<h2 class="sr-only" id="drawer-title">Event details</h2>${loadingState('Loading…', { size: 'sm' })}`;
  kindEl.textContent = ''; // never keep the previous event's kind over a load or an error
  setDrawer(true);
  if (opener !== undefined) drawerOpener = opener;
  try {
    const [e] = await Promise.all([api.event(id), feeds.length ? null : loadFeeds()]);
    if (my !== eventSeq) return;
    eventNow = { id, title: e.title || '' };
    const m = kindMeta(e.kind);
    document.getElementById('drawer-kind').textContent = m.label;
    document.getElementById('drawer-kind').style.color = m.color;
    // Plain words first (the source's name as Settings › Sources shows it, severity as a word); the ids, coordinates
    // and the raw file stay under "Technical details".
    const kv = [
      ['When', `${T.stamp(e.ts, { year: true, seconds: true, zone: true })} · ${ago(e.ts)}`],
      e.source && ['Source', sourceName(e.source)],
      e.severity != null && ['Severity', `${severityWord(e.severity)} (${Math.round(e.severity * 100)} out of 100)`],
      e.ip && ['IP', trusted(`<span class="mono">${esc(e.ip)}</span>`)], e.asn && ['Network', e.asn],
      e.country && ['Country', `${flag(e.country)} ${e.country}${e.city ? ' · ' + e.city : ''}`],
      e.value != null && ['Value', util.fmt(e.value)],
    ].filter(Boolean);
    const tech = [
      e.source && ['Source id', e.source],
      ['Event id', e.id || id],
      e.lat != null && ['Coordinates', `${e.lat.toFixed(3)}, ${e.lon.toFixed(3)}`],
      e.raw_path && ['Raw file', trusted(`<span class="mono" title="${esc(e.raw_path)}">${esc(e.raw_path.split('/').slice(-4).join('/'))}</span>`)],
    ].filter(Boolean);
    const dl = (rows) => rows.map(([k, v]) => `<dt>${k}</dt><dd>${v instanceof Trusted ? v.html : esc(v)}</dd>`).join('');
    // CVEs already get their own section (vulnSection), so they are not repeated as linked-entity chips.
    const linked = (e.entities || []).filter((x) => !(x.type === 'cve' && e.cves?.length));
    // "Seen on your network" for the event's own indicators (its IP, linked addresses, domains and hashes);
    // CVEs get a chip on their own rows in vulnSection.
    const seenVals = [...new Set([e.ip, ...linked.filter((x) => ['ip', 'domain', 'hash', 'prefix'].includes(x.type)).map((x) => x.name || String(x.id).split(':').slice(1).join(':'))].filter(Boolean))].slice(0, 6);
    // Event fields come from feeds and uploads: every value is escaped unless the drawer built it as trusted().
    body.innerHTML = `
      <h2 id="drawer-title">${esc(e.title || 'Event details')}</h2>
      <div style="display:flex;gap:6px;flex-wrap:wrap">${(e.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join('')}</div>
      <dl class="kv">${dl(kv)}</dl>
      ${seenVals.length ? `<div class="section drawer-seenrow"><div class="label">On your network</div>${seenVals.map((v) => `<div class="drawer-seenitem">${seenVals.length > 1 ? `<span class="mono">${esc(v)}</span>` : ''}${seenSlot(v, { quiet: true })}</div>`).join('')}</div>` : ''}
      ${e.summary ? `<p>${esc(e.summary)}</p>` : ''}
      ${e.url ? (util.safeUrl(e.url) ? `<a href="${esc(util.safeUrl(e.url))}" target="_blank" rel="noopener" class="chip" style="margin-top:6px">Open source <svg class="i"><use href="#i-ext"/></svg></a>`
        : `<dl class="kv"><dt>Source URL</dt><dd class="mono" title="Not a web link, shown as text">${esc(e.url)}</dd></dl>`) : ''}
      ${vulnSection(e)}
      ${linked.length ? `<div class="section"><div class="label">Linked entities (${linked.length})</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">${linked.map((x) => `<a class="chip" href="${esc(entityHref(x.id))}" data-entity="${esc(x.id)}" data-nocard title="${esc(`${x.type}${x.role ? ' · ' + x.role : ''}`)}">${esc(x.type)}: ${esc(String(x.name || x.id).slice(0, 80))}</a>`).join('')}</div></div>` : ''}
      ${feedsSection(e)}
      ${e.related?.length ? `<div class="section"><div class="label">Also seen as (${e.related.length})</div>
        ${e.related.map((r) => `<div class="row" data-id="${esc(r.id)}" style="padding:8px 0"><div class="row-title" style="font-size:12px">${esc(r.title)}</div><div class="row-meta"><span class="tag ${kindMeta(r.kind).tag}">${esc(kindMeta(r.kind).label)}</span>${esc(sourceName(r.source))} · ${ago(r.ts)}</div></div>`).join('')}</div>` : ''}
      <details class="shell-dr-tech"><summary>Technical details</summary><dl class="kv">${dl(tech)}</dl></details>
    `;
    body.querySelectorAll('[data-id]').forEach((r) => r.addEventListener('click', () => openEvent(r.dataset.id)));
    body.querySelectorAll('[data-story]').forEach((r) => r.addEventListener('click', () => {
      setDrawer(false, { restore: false }); // the story link moves on to News
      location.hash = `#news/story/${encodeURIComponent(r.dataset.story)}`;
    }));
    fillSeen(body);
  } catch (err) {
    if (my !== eventSeq) return;
    body.innerHTML = '<h2 class="sr-only" id="drawer-title">Event details</h2>' + errorState({ retry: () => openEvent(id), title: "Couldn't open this event", why: 'It may have aged out of the lake, or the server did not answer.', err: err.message, size: 'sm' });
  }
}

// ------------------------------------------------------------------ panel chrome
// The hover title of a panel's clock label ("3m ago"): what the time is and when it was, in the app's zone. `refresh`:
// the time handed over was "now" when the panel redrew (a refresh), not when its data last changed.
export const freshTitle = (t, refresh = false) => (refresh
  ? `Refreshed ${T.ago(t)} (${T.stamp(t, { zone: true })}): when this widget last checked for new data`
  : `Updated ${T.ago(t)} (${T.stamp(t, { zone: true })}): when this widget's newest data arrived`);
function buildPanel(def, node) {
  const el = h(`
    <div class="panel">
      <div class="panel-head">
        <span class="panel-grip" title="Drag"><svg class="i"><use href="#i-grip"/></svg></span>
        <span class="panel-title">${esc(def?.title || node.panel)}</span>
        <span class="panel-badge" hidden></span>
        <div class="panel-tools">
          <span class="panel-updated" hidden><svg class="i"><use href="#i-clock"/></svg><span></span></span>
          <span class="panel-xtools" style="display:flex;gap:2px"></span>
          <button class="icon-btn" data-act="max" title="Expand"><svg class="i"><use href="#i-expand"/></svg></button>
          <button class="icon-btn" data-act="close" title="Remove"><svg class="i"><use href="#i-x"/></svg></button>
        </div>
      </div>
      <div class="panel-body"></div>
    </div>`);
  return el;
}

function mountPanel(itemEl, node) {
  const def = PANELS.get(node.panel);
  const el = itemEl.querySelector('.grid-stack-item-content > .panel');
  const body = el.querySelector('.panel-body');
  const badge = el.querySelector('.panel-badge');
  const upd = el.querySelector('.panel-updated');
  const titleEl = el.querySelector('.panel-title');
  let updatedAt = null;
  let renderStamp = false; // the time handed over is "now" (when the panel re-rendered), not when its data last changed
  // The panel clock says how fresh the data is. While nothing new can arrive (offline mode, or the panel says OFFLINE
  // or STALE), a re-render time would read as fresh data ("6s ago"), so the clock is hidden then; a real data time
  // (e.g. a feed's newest item) still shows.
  const paintUpdated = () => {
    const quiet = live.isOffline() || (!badge.hidden && /^(OFFLINE|STALE)\b/i.test(badge.textContent.trim()));
    const show = !!updatedAt && !(renderStamp && quiet);
    upd.hidden = !show;
    if (show) upd.querySelector('span').textContent = ago(updatedAt);
    // The label drops out of a narrow header (container queries in app.css), so the panel title carries it too.
    const tip = show ? freshTitle(updatedAt, renderStamp) : '';
    upd.title = tip;
    if (tip) titleEl.title = `${def?.title || node.panel} · ${tip}`; else titleEl.removeAttribute('title');
  };
  const key = `nd.panel.${currentDeck}.${node.id}`;
  const ctx = {
    api, live, store, util, openEvent, panelEl: el,
    tools: el.querySelector('.panel-xtools'),
    setBadge(text, isLive = false) { badge.hidden = text == null; badge.textContent = text ?? ''; badge.classList.toggle('live', isLive); paintUpdated(); },
    setUpdated(t) {
      updatedAt = t;
      const ms = t ? new Date(t).getTime() : NaN;
      renderStamp = Number.isFinite(ms) && Math.abs(Date.now() - ms) < 5000;
      paintUpdated();
    },
    state: { get: () => LS.get(key, {}), set: (p) => LS.set(key, { ...LS.get(key, {}), ...p }) },
    _tick() { if (updatedAt) paintUpdated(); },
  };
  let inst = {};
  if (!def) {
    body.innerHTML = emptyState({ title: 'This widget is not available', why: 'Remove it from the deck, or add another one with + Widget.', err: node.panel, size: 'sm' });
  } else {
    try { inst = def.mount(body, ctx) || {}; } catch (err) { console.error(err); body.innerHTML = errorState({ retry: () => location.reload(), retryLabel: 'Reload the page', title: "This widget didn't start", why: 'Reload the page; the other widgets still work.', err: err.message, size: 'sm' }); }
  }
  el.querySelector('[data-act="close"]').onclick = () => { setMaximized(node.id, false); grid.removeWidget(itemEl); syncMaximized(); };
  el.querySelector('[data-act="max"]').onclick = () => setMaximized(node.id, !el.classList.contains('maximized'));
  instances.set(node.id, { def, inst, ctx, el, itemEl });
}

// Maximise is three pieces of state (panel class, grid item z-index, body.has-maximized, which stops the Ops view
// scrolling); set and clear them together, whether by the Expand button, Esc or removing the panel.
function setMaximized(id, on) {
  const rec = instances.get(id);
  if (!rec) return;
  rec.el.classList.toggle('maximized', on);
  rec.itemEl.style.zIndex = on ? '45' : '';
  syncMaximized();
  requestAnimationFrame(() => { try { rec.inst.resize?.(); } catch {} });
}
function syncMaximized() {
  document.body.classList.toggle('has-maximized', !!document.querySelector('#grid .panel.maximized'));
}

function unmountPanel(id) {
  const rec = instances.get(id);
  if (!rec) return;
  try { rec.inst.destroy?.(); } catch (e) { console.error(e); }
  instances.delete(id);
}

let loading = false;
function saveLayout() {
  if (loading || grid.getColumn() === 1) return; // never overwrite the desktop layout with the phone stack
  const items = grid.getGridItems()
    .map((it) => it.gridstackNode)
    .filter((n) => n && n.panel)
    .map((n) => [n.panel, n.x, n.y, n.w, n.h, n.id]);
  LS.set(`nd.layout.${currentDeck}`, items);
}

function addWidget(panelId, x, y, w, hh, id) {
  const def = PANELS.get(panelId);
  const node = {
    x, y, w: w ?? def?.w ?? 4, h: hh ?? def?.h ?? 5,
    minW: def?.minW ?? 2, minH: def?.minH ?? 3, id: id || `p${Date.now().toString(36)}${uid++}`,
    panel: panelId, autoPosition: x == null,
  };
  if (grid.getColumn() === 1) Object.assign(node, { x: 0, w: 1, autoPosition: true });
  // The panel's header is in the item before gridstack sees it: gridstack picks its drag handles (grip and title)
  // when the item is added, and with none there it makes the WHOLE item the handle. On a touch screen that handle
  // cancels every tap's click (touchstart preventDefault) and skips buttons, so Expand and Remove did nothing (S2-02)
  // and a finger on a panel could never scroll the page.
  const itemEl = h('<div class="grid-stack-item"><div class="grid-stack-item-content"></div></div>');
  itemEl.firstElementChild.append(buildPanel(def, node));
  grid.addWidget(itemEl, node);
  itemEl.gridstackNode.panel = panelId;
  mountPanel(itemEl, itemEl.gridstackNode);
  return itemEl;
}

function loadDeck(name, reset = false) {
  currentDeck = name;
  LS.set('nd.deck', name);
  document.getElementById('deck-name').textContent = name;
  loading = true;
  try {
    for (const id of [...instances.keys()]) unmountPanel(id);
    grid.removeAll(true);
    document.querySelectorAll('#grid > .grid-stack-item').forEach((el) => el.remove()); // belt and braces
    const saved = !reset && LS.get(`nd.layout.${name}`, null);
    // A custom deck resets to the layout it was saved with, never to a template.
    const base = !template(name) && LS.get(`nd.deckBase.${name}`, null);
    const items = (saved && saved.length ? saved : null) || (base && base.length ? base : null) ||
      (template(name) || DECKS['Cyber Ops']).map(([p, x, y, w, hh], i) => [p, x, y, w, hh, `${p}-${i}`]);
    items.sort((a, b) => a[2] - b[2] || a[1] - b[1]); // reading order (row, then column)
    grid.batchUpdate();
    for (const [p, x, y, w, hh, id] of items) addWidget(p, x, y, w, hh, id);
    grid.batchUpdate(false);
  } finally {
    loading = false;
    syncMaximized();
  }
  saveLayout();
  syncPhoneDeck();
  requestAnimationFrame(resizeAll);
}

// ------------------------------------------------------------------ Ops on a phone (≤760 px)
// The deck is a read-only stack there: no drag handles, no close buttons, nothing to knock over with a thumb, and
// your own network first (Needs attention, the newly exploited list, devices, then the rest in reading order).
// "Edit layout" brings the handles back until you press Done. The desktop layout is never touched.
const PHONE_FIRST = { 'net-attention': -40, 'kev-tracker': -30, 'net-devices': -20, 'net-timeline': -10 };
const phoneMQ = window.matchMedia?.('(max-width: 760px)');
let editLayout = false;
function syncPhoneDeck() {
  if (!grid) return;
  const phone = !!phoneMQ?.matches;
  const ro = phone && !editLayout;
  const gEl = document.getElementById('grid');
  gEl.classList.toggle('finishb-stack', ro);
  grid.enableMove(!ro); grid.enableResize(!ro);
  grid.getGridItems().forEach((el) => {
    const n = el.gridstackNode;
    el.style.order = ro && n ? String(PHONE_FIRST[n.panel] ?? (n.y * 12 + n.x)) : '';
  });
  const b = document.getElementById('ops-edit');
  if (b) {
    b.hidden = !phone;
    b.setAttribute('aria-pressed', String(editLayout));
    b.querySelector('span').textContent = editLayout ? 'Done' : 'Edit layout';
  }
}
function setupPhoneDeck() {
  document.getElementById('ops-edit')?.addEventListener('click', () => {
    editLayout = !editLayout;
    syncPhoneDeck();
    announce(editLayout ? 'Editing the layout: drag panels by their handle, or remove them' : 'Layout locked');
    requestAnimationFrame(resizeAll);
  });
  phoneMQ?.addEventListener?.('change', () => { if (!phoneMQ.matches) editLayout = false; syncPhoneDeck(); requestAnimationFrame(resizeAll); });
}

function resizeAll() {
  // Skip while the Ops view is hidden: panels would be resized to 0x0.
  const g = document.getElementById('grid');
  if (!g || g.offsetWidth === 0 || g.offsetHeight === 0) return;
  instances.forEach((r) => { try { r.inst.resize?.(); } catch {} });
}

// ------------------------------------------------------------------ menus
function setupMenus() {
  const deckMenu = document.getElementById('deck-menu');
  const widgetMenu = document.getElementById('widget-menu');
  const deckBtn = document.getElementById('deck-btn');
  const addBtn = document.getElementById('add-widget');
  const custom = () => LS.get('nd.customDecks', []);

  function renderDeckMenu() {
    const names = [...new Set([...Object.keys(DECKS), ...custom()])];
    const canReset = template(currentDeck) || LS.get(`nd.deckBase.${currentDeck}`, null);
    deckMenu.innerHTML = `<div class="mh" role="presentation">Decks</div>${names.map((n) => `<button class="mi" role="menuitem" data-deck="${esc(n)}"${n === currentDeck ? ' aria-current="true"' : ''}>${esc(n)}${n === currentDeck ? '<small>active</small>' : template(n) ? '<small>template</small>' : ''}</button>`).join('')}
      <div class="sep" role="separator"></div><button class="mi" role="menuitem" data-act="save">Save current as new deck…</button>${canReset ? `<button class="mi" role="menuitem" data-act="reset" title="${template(currentDeck) ? 'Back to the template layout' : 'Back to the layout this deck was saved with'}">Reset “${esc(currentDeck)}” layout</button>` : ''}`;
  }
  function renderWidgetMenu() {
    widgetMenu.innerHTML = `<div class="mh" role="presentation">Add widget</div>${[...PANELS.values()].map((p) => `<button class="mi" role="menuitem" data-panel="${esc(p.id)}" title="${esc(p.description || '')}">${esc(p.title)}<small>${p.w}×${p.h}</small></button>`).join('')}`;
  }
  // The same menus as the top bar's (openPop/menuKeys: focus moves in, arrows move, Esc returns to the button), placed
  // under their button and kept inside the window on a phone.
  const pop = (menu, btn, render) => {
    openPop(btn, menu, render);
    if (!menu.classList.contains('open')) return;
    menu.style.left = `${btn.offsetLeft}px`;
    menu.style.maxHeight = '';
    const r = menu.getBoundingClientRect();
    const vw = document.documentElement.clientWidth;
    let shift = 0;
    if (r.right > vw - 8) shift = vw - 8 - r.right;
    if (r.left + shift < 8) shift = 8 - r.left;
    if (shift) menu.style.left = `${btn.offsetLeft + shift}px`;
    menu.style.maxHeight = `${Math.max(160, window.innerHeight - r.top - 12)}px`;
  };
  deckBtn.onclick = (e) => { e.stopPropagation(); pop(deckMenu, deckBtn, renderDeckMenu); };
  addBtn.onclick = (e) => { e.stopPropagation(); pop(widgetMenu, addBtn, renderWidgetMenu); };
  menuKeys(deckMenu, deckBtn);
  menuKeys(widgetMenu, addBtn);
  document.addEventListener('click', () => document.querySelectorAll('.menu.open').forEach((m) => m.classList.remove('open')));
  deckMenu.onclick = (e) => {
    const b = e.target.closest('button'); if (!b) return;
    e.stopPropagation();
    closePops();
    if (b.dataset.act === 'save') { askDeckName(deckBtn, saveDeck); return; }
    if (b.dataset.deck) loadDeck(b.dataset.deck);
    else if (b.dataset.act === 'reset') loadDeck(currentDeck, true);
    deckBtn.focus({ preventScroll: true });
  };
  // Returns an error message to show in the dialog, or '' when the deck was saved.
  function saveDeck(name) {
    let n = name.trim();
    if (!n) return 'Type a name for the deck.';
    // names compare case-insensitively: 'cyber ops' is the 'Cyber Ops' template, 'mine' is the existing 'Mine'
    const same = (k) => k.toLowerCase() === n.toLowerCase();
    const tpl = Object.keys(DECKS).find(same);
    if (tpl) return `“${tpl}” is a built-in deck; choose another name.`;
    n = custom().find(same) || n; // saving under an existing deck's name (any case) updates that deck
    const layout = LS.get(`nd.layout.${currentDeck}`, []);
    LS.set(`nd.layout.${n}`, layout);
    LS.set(`nd.deckBase.${n}`, layout); // what Reset returns this deck to
    LS.set('nd.customDecks', [...new Set([...custom(), n])]);
    loadDeck(n);
    util.toast(`Saved the layout as “${n}”`);
    return '';
  }
  widgetMenu.onclick = (e) => {
    const b = e.target.closest('[data-panel]'); if (!b) return;
    e.stopPropagation();
    closePops();
    addWidget(b.dataset.panel); saveLayout();
    addBtn.focus({ preventScroll: true });
  };
}

// "Save current as new deck…": an in-page dialog (not window.prompt). onSave(name) returns '' when done, or a message
// to show under the field.
function askDeckName(returnTo, onSave) {
  let dlg = document.getElementById('shell-deck-dlg');
  if (!dlg) {
    dlg = h(`<dialog class="shell-dlg" id="shell-deck-dlg" aria-labelledby="shell-deck-dlg-t" aria-describedby="shell-deck-dlg-d">
      <form method="dialog" class="shell-dlg-f">
        <h2 class="shell-dlg-t" id="shell-deck-dlg-t">Save this layout as a new deck</h2>
        <p class="shell-dlg-d" id="shell-deck-dlg-d">Give it a name you'll recognise. It joins the deck list, and Reset brings it back to this layout.</p>
        <label class="shell-dlg-l" for="shell-deck-name">Deck name</label>
        <input class="shell-dlg-in" id="shell-deck-name" name="name" maxlength="60" autocomplete="off" spellcheck="false">
        <p class="shell-dlg-err" id="shell-deck-err" role="alert"></p>
        <div class="shell-dlg-act"><button type="button" class="src-btn" value="cancel" data-x>Cancel</button><button type="submit" class="src-btn primary" value="save">Save deck</button></div>
      </form></dialog>`);
    document.body.append(dlg);
    dlg.querySelector('[data-x]').onclick = () => dlg.close();
  }
  const input = dlg.querySelector('input'), err = dlg.querySelector('.shell-dlg-err');
  input.value = ''; err.textContent = '';
  input.removeAttribute('aria-invalid');
  dlg.querySelector('form').onsubmit = (e) => {
    e.preventDefault();
    const msg = onSave(input.value);
    if (msg) { err.textContent = msg; input.setAttribute('aria-invalid', 'true'); input.focus(); return; }
    dlg.close();
  };
  dlg.onclose = () => returnTo?.focus({ preventScroll: true });
  dlg.showModal();
  input.focus();
}

// Filtering the Ops panels is an explicit action (search dropdown: "Filter panels by …"), shown here while on and
// cleared when leaving Ops.
function paintOpsFilter() {
  const b = document.getElementById('ops-filter');
  if (!b) return;
  const q = store.get().opsQ;
  const onOps = document.querySelector('.views button.active')?.dataset.view === 'ops';
  b.style.display = q && onOps ? '' : 'none';
  b.classList.toggle('states-filter-on', !!q);
  b.title = 'Panels are filtered by this text. Click to clear the filter.';
  b.querySelector('span').textContent = `Filtering panels: “${q || ''}”`;
}
function setupOpsFilter() {
  const b = document.getElementById('ops-filter');
  if (!b) return;
  b.onclick = () => store.set({ opsQ: '' });
  store.subscribe(paintOpsFilter);
}

// A small dismissible banner while offline mode is on (OSINTHUB_OFFLINE=1; dismissed for this browser session). Primary
// text names no setting; the variable is in the hover title.
function paintOfflineBanner() {
  let el = document.getElementById('states-offline');
  let gone = false;
  try { gone = sessionStorage.getItem('nd.offlineBanner') === 'x'; } catch {}
  const show = live.isOffline() && !gone;
  if (!show) { el?.remove(); return; }
  if (el) return;
  el = h(`<div class="states-offline" id="states-offline" role="status">
    <span class="states-offline-dot" aria-hidden="true"></span>
    <span class="states-offline-t"><b>Offline mode:</b> not fetching sources<span class="states-offline-more">; everything already collected still works</span>. To fetch again, <span class="states-offline-how" title="Offline mode is the OSINTHUB_OFFLINE=1 setting in the command or file that starts Night Desk">restart Night Desk with offline mode turned off</span>.</span>
    <button class="icon-btn states-offline-x" title="Dismiss" aria-label="Dismiss the offline notice"><svg class="i"><use href="#i-x"/></svg></button></div>`);
  el.querySelector('.states-offline-x').onclick = () => { try { sessionStorage.setItem('nd.offlineBanner', 'x'); } catch {} el.remove(); };
  document.querySelector('.topbar')?.after(el);
}

// ------------------------------------------------------------------ views
const mountedViews = new Set();
// Every view the app has (a route not in this list is unknown and goes to the landing page), and the ones whose
// module failed to load, with why (main.js).
const KNOWN = new Set(Object.keys(TITLES));
const failedViews = new Map();
const failedState = (id) => errorState({
  title: "This page didn't load",
  why: `Part of Night Desk didn't arrive from the server (it may have been restarting), so ${esc(TITLES[id] || 'this page')} can't show. Reloading usually fixes it; the other pages still work.`,
  err: failedViews.get(id) || 'The page module is not registered.',
  act: stateAct('Reload the page', { data: { 'vs-retry': 'reload' }, primary: true }),
});
// The view to open when a route names none or an unknown one: the landing page from Settings › Display (Watch).
const landingView = () => { const l = landing(); return KNOWN.has(l) ? l : 'watch'; };
let deckLoaded = false;
const navButtons = () => document.querySelectorAll('.views [data-view], .bnav [data-view]');
export const currentView = () => document.body.dataset.view || null;
// opts.replace: rewrite the current history entry instead of adding one (boot). A user's tab click adds an entry,
// so browser Back and Forward step between views; a hash change (a link, Back/Forward) already set the URL.
function showView(id, { replace = false } = {}) {
  // the shared entity panel (and its page-dimming scrim) belongs to the view it was opened on
  const prev = currentView();
  if (prev !== id) {
    closeEntity();
    setDrawer(false, { restore: false }); // the event drawer belongs to the view it was opened on
    closeSearch();                         // and so does the search dropdown
    closePops();
    if (prev === 'ops' && store.get().opsQ) store.set({ opsQ: '' }); // the panel filter ends when leaving Ops
  }
  document.body.dataset.view = id;
  navButtons().forEach((b) => {
    const on = b.dataset.view === id;
    b.classList.toggle('active', on);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  document.getElementById('bnav-more')?.classList.toggle('active', ![...navButtons()].some((b) => b.closest('.bnav') && b.dataset.view === id));
  document.querySelectorAll('#views .view').forEach((v) => v.classList.toggle('active', v.dataset.view === id));
  // The sub-bar holds only Ops controls (decks, widgets, the deck's time range, feed health): Ops only.
  document.getElementById('subbar').style.display = id === 'ops' ? '' : 'none';
  if (id !== 'ops') document.querySelectorAll('#subbar .menu.open').forEach((m) => m.classList.remove('open'));
  for (const [vid, def] of VIEWS) {
    if (vid !== id) def.hide?.();
  }
  const def = VIEWS.get(id);
  const el = document.querySelector(`#views .view[data-view="${id}"]`);
  if (def) {
    try {
      if (!mountedViews.has(id)) { mountedViews.add(id); def.mount(el, { api, live, store, util, openEvent }); }
      def.show?.();
    } catch (err) {
      // a view that fails to mount is retried on its next visit instead of staying blank for the session
      console.error(err);
      mountedViews.delete(id);
      el.innerHTML = errorState({ retry: () => showView(id, { replace: true }), title: "This page didn't open", why: 'Part of the page did not load; the other tabs still work.', err: err.message });
    }
  } else if (id !== 'ops') {
    // the view's module did not load (main.js boot({ failed })): say so, with a Reload, never a spinner that waits forever
    el.innerHTML = failedState(id);
  }
  // one h1 per view: views with no heading on screen get a visually hidden one
  if (HIDDEN_H1.has(id) && el && !el.querySelector('h1')) el.prepend(h(`<h1 class="sr-only">${esc(TITLES[id])}</h1>`));
  if (id === 'ops') openOps(el);
  LS.set('nd.view', id);
  paintCurrent();
  document.title = `${TITLES[id] || id} · Night Desk`;
  paintOpsFilter();
  // keep a sub-route such as #network/alerts, #news/article/<id> or #cinema?kiosk for the view to read
  if (viewOf() !== id && viewOf() !== 'search') history[replace ? 'replaceState' : 'pushState'](null, '', `#${id}`);
  if (id === 'ops') syncOpsHash();
  syncKiosk();
  if (!replace && prev !== id) announceRoute();
}

// Say where a route change landed ("Network, Alerts"): the view's name, plus its sub-page as the page labels it
// (a tab or section with that id in the view), read after the view has painted.
let lastRoute = '';
function routeLabel() {
  const v = viewOf();
  const sub = location.hash.replace(/^#\/?/, '').split(/[?]/)[0].split('/')[1] || '';
  let subL = '';
  if (sub && !/[:.]|\d{4,}/.test(sub)) {
    const view = document.querySelector('#views .view.active');
    const el = view?.querySelector(`[data-tab="${CSS.escape(sub)}"], [data-sec="${CSS.escape(sub)}"]`);
    subL = (el?.textContent || sub.replace(/[-_]/g, ' ')).trim().replace(/\s+\d+$/, '');
    subL = subL.charAt(0).toUpperCase() + subL.slice(1);
  }
  return [TITLES[v] || v, subL].filter(Boolean).join(', ');
}
function announceRoute() {
  setTimeout(() => {
    const l = routeLabel();
    if (l && l !== lastRoute) { lastRoute = l; announce(l); }
  }, 350);
}

// ------------------------------------------------------------------ menus in the top bar and the phone "More" sheet
// A pop is a button (aria-haspopup="menu") plus its .menu; one open at a time; Esc or a click elsewhere closes it.
// The pops: the gear menu, the phone More sheet, and Ops' deck and widget menus.
const POPS = '.shell-menu.open, .bnav-sheet.open, #deck-menu.open, #widget-menu.open';
const POP_BTNS = '#gear-btn, #bnav-more, #deck-btn, #add-widget';
function closePops() {
  document.querySelectorAll(POPS).forEach((m) => m.classList.remove('open'));
  document.querySelectorAll(POP_BTNS).forEach((b) => b.setAttribute('aria-expanded', 'false'));
  const scrim = document.getElementById('shell-scrim');
  if (scrim) scrim.hidden = true;
}
function openPop(btn, menu, fill) {
  const was = menu.classList.contains('open');
  document.querySelectorAll('.menu.open').forEach((m) => m.classList.remove('open'));
  closePops();
  if (was) return;
  fill?.(menu);
  menu.classList.add('open');
  btn.setAttribute('aria-expanded', 'true');
  if (menu.id === 'bnav-sheet') document.getElementById('shell-scrim').hidden = false;
  menu.querySelector('[role="menuitem"]')?.focus({ preventScroll: true });
}
function menuKeys(menu, btn) {
  menu.addEventListener('keydown', (e) => {
    const items = [...menu.querySelectorAll('[role="menuitem"]')].filter((x) => x.getClientRects().length);   // shown ones
    const i = items.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); items[(i + 1) % items.length]?.focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); items[(i - 1 + items.length) % items.length]?.focus(); }
    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closePops(); btn.focus(); }
    else if (e.key === 'Tab') closePops();
  });
  menu.addEventListener('click', (e) => { if (e.target.closest('a[href]')) closePops(); });
}
// Help: the registry in core/help.js fills the "?" menu (the help lane can replace it). The shell's own items:
const startTour = () => import('./tour.js').then((m) => { if (m.startTour('page') === false) util.toast('This page has no tour yet'); })
  .catch((e) => util.toast(`The tour could not start: ${e.message}`, true));
registerHelp({ id: 'tour', label: 'Take the tour', order: 10, hint: 'this page', run: () => startTour() });
registerHelp({ id: 'keys', label: 'Keyboard shortcuts', order: 20, run: () => showShortcuts() });

// Where you are, in the menus that hold views without a nav tab (Settings, Sources, SQL console, Notes): the matching
// item gets aria-current, and the gear button (desktop) or More (phone) carries a "you are here" marker.
const MORE_ITEMS = [
  ['#notes', 'notes', 'i-note', 'Notes'],
  ['#cinema', 'cinema', 'i-globe', 'Cinema'],
  ['#settings', 'settings', 'i-gear', 'Settings'],
  ['#settings/sources', null, 'i-layers', 'Sources'],
  ['#explorer', 'explorer', 'i-code', 'SQL console'],
];
function paintCurrent() {
  const v = currentView();
  const sources = v === 'settings' && /^#\/?settings\/sources\b/i.test(location.hash);
  let inGear = false;
  document.querySelectorAll('#gear-menu .mi, #bnav-sheet .mi[href]').forEach((a) => {
    const href = a.getAttribute('href') || '';
    const on = href === '#settings/sources' ? sources : (a.dataset.view === v && !(v === 'settings' && sources));
    if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    if (on && a.closest('#gear-menu')) inGear = true;
  });
  const gearBtn = document.getElementById('gear-btn');
  if (gearBtn) {
    gearBtn.classList.toggle('shell-pop-cur', inGear);
    // the page you are on lives in this menu: assistive tech hears it on the button too, not only from the label
    if (inGear) gearBtn.setAttribute('aria-current', 'true'); else gearBtn.removeAttribute('aria-current');
    gearBtn.setAttribute('aria-label', inGear ? `Settings and tools (you are on ${TITLES[v]})` : 'Settings and tools');
  }
}

function setupMenus2() {
  const gearBtn = document.getElementById('gear-btn'), gear = document.getElementById('gear-menu');
  const helpBtn = document.getElementById('help-btn');
  const moreBtn = document.getElementById('bnav-more'), sheet = document.getElementById('bnav-sheet');
  gearBtn.onclick = (e) => { e.stopPropagation(); openPop(gearBtn, gear, paintCurrent); };
  // "?" opens the Help desk (a dialog-like side panel), or closes it when it is open; core/help.js keeps
  // aria-expanded in step with the desk.
  helpBtn.onclick = (e) => {
    e.stopPropagation();
    closePops();
    if (isHelpOpen()) closeHelp(); else openHelp('page', { opener: helpBtn });
  };
  moreBtn.onclick = (e) => {
    e.stopPropagation();
    openPop(moreBtn, sheet, (m) => {
      m.innerHTML = `${MORE_ITEMS.filter(([, view]) => view !== 'explorer' || sqlConsoleOn()).map(([href, view, icon, label]) => `<a class="mi" role="menuitem" href="${href}"${view ? ` data-view="${view}"` : ''}><svg class="i" aria-hidden="true"><use href="#${icon}"/></svg>${label}</a>`).join('')}
        <div class="sep" role="separator"></div><div class="bnav-help" role="none"></div>`;
      renderHelp(m.querySelector('.bnav-help'), closePops);
      paintCurrent();
    });
  };
  for (const [m, b] of [[gear, gearBtn], [sheet, moreBtn]]) { menuKeys(m, b); m.addEventListener('click', (e) => e.stopPropagation()); m.addEventListener('click', (e) => { if (e.target.closest('a[href]')) closePops(); }); }
  // The phone More sheet sits over a scrim: a tap outside the sheet lands on the scrim and only closes the sheet,
  // never also pressing what was underneath.
  const scrim = document.getElementById('shell-scrim');
  scrim?.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); closePops(); moreBtn.focus({ preventScroll: true }); });
  document.addEventListener('click', closePops);
  document.querySelectorAll('.bnav [data-view]').forEach((b) => (b.onclick = () => { closePops(); showView(b.dataset.view); }));
}

// ------------------------------------------------------------------ command palette (⌘K / Ctrl+K)
function setupCommands() {
  const go = (v) => () => (viewOf() === v ? null : (location.hash = `#${v}`));
  [['watch', 'Watch'], ['network', 'Network'], ['news', 'News'], ['entities', 'Intel'], ['ops', 'Ops'], ['cinema', 'Cinema']]
    .forEach(([v, l], i) => registerCommand({ id: `go.${v}`, label: `Go to ${l}`, group: 'Pages', order: 10 + i, run: go(v) }));
  registerCommand({ id: 'go.explorer', label: 'Open SQL console…', group: 'Tools', keywords: 'explorer query sql duckdb', order: 5, when: sqlConsoleOn, run: go('explorer') });
  registerCommand({ id: 'go.alerts', label: 'Open network alerts', group: 'Pages', keywords: 'alerts triage needs you', order: 20, run: () => { location.hash = '#network/alerts'; } });
  registerCommand({ id: 'go.kiosk', label: 'Cinema full screen (wall display)', group: 'Pages', keywords: 'kiosk wall tv', order: 40, run: () => { location.hash = '#cinema?kiosk'; } });
  registerCommand({ id: 'search', label: 'Search everything', group: 'Tools', keywords: 'find', order: 6, run: () => { document.getElementById('gs').classList.add('expanded'); document.getElementById('global-search').focus(); } });
  registerCommand({ id: 'help.tour', label: 'Take the tour of this page', group: 'Help', order: 60, run: () => startTour() });
  registerCommand({ id: 'help.keys', label: 'Keyboard shortcuts', group: 'Help', order: 61, run: () => showShortcuts() });

  // Every sub-page has its own entry, so ⌘K reaches anything in two keystrokes (deep links: okf web-client.md).
  const to = (hash) => () => { location.hash = hash; };
  [
    ['go.network.overview', 'Network › Overview', '#network/overview', 'home network summary logs current'],
    ['go.network.hunt', 'Network › Search logs', '#network/hunt', 'hunt query filter zeek rows find address'],
    ['go.network.devices', 'Network › Devices', '#network/devices', 'devices rename name phone laptop'],
    ['go.network.import', 'Network › Connect logs', '#network/import', 'import upload zeek suricata pi-hole adguard connect demo'],
    ['go.network.rules', 'Network › Expected traffic', '#network/alerts/rules', 'expected suppress quiet rules allow'],
    ['go.entities.graph', 'Intel › Graph', '#entities/graph', 'graph links relationships'],
    ['go.entities.review', 'Intel › Review', '#entities/review', 'review disagree aliases queue'],
    ['go.settings', 'Go to Settings', '#settings', 'preferences options configure'],
    ['go.help.guides', 'Help: guides', null, 'how to tutorial walkthrough'],
  ].forEach(([id, label, hash, keywords], i) => registerCommand({ id, label, group: 'Pages', keywords, order: 21 + i / 10,
    run: hash ? to(hash) : () => import('./help.js').then((m) => m.openHelp?.('guides')) }));

  // Common actions.
  registerCommand({ id: 'act.caught-up', label: 'Caught up: mark everything as read', group: 'Actions', keywords: 'read seen marker clear new watch news', order: 70,
    run: async () => { try { await api.put('/api/marker', {}); util.toast('Marked as read: Watch and News now count new from here'); if (viewOf() !== 'watch') location.hash = '#watch'; else showView('watch'); } catch (e) { util.toast(e.message, true); } } });
  registerCommand({ id: 'act.demo', label: 'Try the demo network (Connect logs)', group: 'Actions', keywords: 'demo try sample example data', order: 71, run: to('#network/import') });
  registerCommand({ id: 'act.follow', label: 'Follow what you run (vendors and products)', group: 'Actions', keywords: 'stack follow vendor product watchlist', order: 72, run: to('#settings/follow') });
  registerCommand({ id: 'act.home', label: 'Set your home network range', group: 'Actions', keywords: 'home prefix cidr subnet lan', order: 73, run: to('#settings/home') });
  registerCommand({ id: 'act.utc', label: 'Show times in UTC', group: 'Actions', keywords: 'time zone clock utc', order: 74, when: () => !T.isUTC(), run: () => { T.setZone('utc'); location.reload(); } });
  registerCommand({ id: 'act.local', label: 'Show times in local time', group: 'Actions', keywords: 'time zone clock local', order: 74, when: () => T.isUTC(), run: () => { T.setZone('local'); location.reload(); } });
  registerCommand({ id: 'act.widget', label: 'Add a widget to Ops', group: 'Actions', keywords: 'panel dashboard widget deck', order: 75,
    run: () => { showView('ops'); setTimeout(() => document.getElementById('add-widget')?.click(), 120); } });
  registerCommand({ id: 'act.edit-layout', label: 'Edit the Ops layout', group: 'Actions', keywords: 'move resize remove panels phone', order: 76, when: () => !!phoneMQ?.matches,
    run: () => { showView('ops'); if (!editLayout) document.getElementById('ops-edit')?.click(); } });
}

// ------------------------------------------------------------------ feed health (top-bar dot + Ops sub-bar link)
// Green: the live connection is up and no feed that is on reports a problem. Amber: one or more feeds report an
// error or are reconnecting. Grey: offline mode, the live connection is down, or every feed is off.
let feeds = [];
let lastFeed = null;
function feedState() {
  const st = live.status();
  if (st.state === 'offline') return { c: 'grey', label: 'Sources offline', title: st.title };
  const on = feeds.filter((s) => s.enabled && !s.unavailable);
  if (feeds.length && !on.length) return { c: 'grey', label: 'Every source is off', title: 'Every source is turned off. Turn some on in Settings › Sources.' };
  const bad = on.filter((s) => ['error', 'reconnecting'].includes(s.status));
  if (bad.length) return { c: 'amber', label: `${bad.length} source${bad.length === 1 ? '' : 's'} with a problem`, title: `${bad.length} of ${on.length} sources report a problem: ${bad.slice(0, 4).map((s) => s.name).join(', ')}${bad.length > 4 ? '…' : ''}` };
  if (!feeds.length) return { c: 'grey', label: 'Checking sources', title: st.title };
  return { c: 'green', label: 'Sources healthy', title: `${on.length} source${on.length === 1 ? '' : 's'} on, none reporting a problem. ${st.title}` };
}
function paintFeeds() {
  const f = feedState();
  for (const el of [document.getElementById('feed-dot'), document.getElementById('ops-feeds')]) {
    if (!el) continue;
    el.dataset.fh = f.c;
    el.title = `${f.title}\nOpen Settings › Sources`;
    el.setAttribute('aria-label', `${f.label}. Open Settings, Sources`);
  }
  const t = document.querySelector('.shell-ops-feeds-t');
  if (t) t.textContent = f.c === 'green' ? 'Sources healthy' : f.label;
  if (lastFeed && lastFeed !== f.c && f.c === 'amber') announce(`${f.label}.`);
  lastFeed = f.c;
}
async function loadFeeds() { try { const l = await api.sources(); feeds = Array.isArray(l) ? l : l.sources || []; } catch {} paintFeeds(); }

// ------------------------------------------------------------------ screen-reader announcements
let annT = 0;
export function announce(text) {
  const r = document.getElementById('sr-live');
  if (!r) return;
  clearTimeout(annT);
  r.textContent = '';
  annT = setTimeout(() => { r.textContent = text; }, 60);
}
// The needs-you badge (core/alerts-badge.js) says its count in aria-label; a rise is announced politely.
function watchBadge() {
  const b = document.getElementById('al-badge');
  if (!b) return;
  let last = null;
  new MutationObserver(() => {
    const lab = b.getAttribute('aria-label') || '';
    const n = /^No network alerts/.test(lab) ? 0 : Number(lab.match(/^(\d+) network alerts? need/)?.[1]);
    if (Number.isFinite(n)) { if (last != null && n > last) announce(`${n} network alert${n === 1 ? '' : 's'} need${n === 1 ? 's' : ''} you.`); last = n; }
  }).observe(b, { attributes: true, attributeFilter: ['aria-label'] });
}

// ------------------------------------------------------------------ Cinema kiosk (#cinema?kiosk): no chrome, Esc leaves
const kioskOn = () => viewOf() === 'cinema' && /[?&]kiosk\b/i.test(location.hash);
function syncKiosk() {
  const on = kioskOn();
  document.body.classList.toggle('shell-kiosk', on);
  const x = document.getElementById('kiosk-exit');
  if (x) x.hidden = !on;
}
// Leaving replaces the entry, so Back does not drop straight back into full screen.
const leaveKiosk = () => { history.replaceState(null, '', location.hash.replace(/([?&])kiosk\b&?/i, '$1').replace(/[?&]$/, '')); syncKiosk(); };

// ------------------------------------------------------------------ Ops time range (core/range.js), in #ops?range=
// The deck's range lives in the store (remembered as nd.range); a link's ?range= wins, and the URL follows it.
let opsRange = null;
const isOpsHash = (h) => viewOf(h) === 'ops';
const syncOpsHash = () => rangeSyncHash({ h: store.get().hours }, isOpsHash);
function setupOpsRange() {
  const fromUrl = isOpsHash(location.hash) ? hashRange(location.hash, LIVE) : null;
  if (fromUrl && !fromUrl.from && fromUrl.h !== store.get().hours) store.set({ hours: fromUrl.h });
  opsRange = mountRange(document.getElementById('range'), { live: true, value: { h: store.get().hours }, label: 'Ops time range', onChange: (v) => store.set({ hours: v.h }) });
  store.subscribe((st) => { if (opsRange.get().h !== st.hours) opsRange.set({ h: st.hours }); syncOpsHash(); });
  window.addEventListener('hashchange', () => {
    const r = isOpsHash(location.hash) ? hashRange(location.hash, LIVE) : null;
    if (r && !r.from && r.h !== store.get().hours) store.set({ hours: r.h }); else syncOpsHash();
  });
}

// ------------------------------------------------------------------ top bar
function setupTopbar() {
  const clock = document.getElementById('clock');
  const tick = () => {
    const d = new Date();
    clock.innerHTML = `<span class="cd">${esc(T.date(d, { weekday: 'short' }))} &nbsp;</span>${T.time(d, { seconds: true })}<span class="z">${esc(T.zoneName(d))}</span>`;
    instances.forEach((r) => r.ctx._tick());
  };
  const clockTitle = () => { clock.title = `Times are shown in ${T.zoneLong()}, 24-hour. Change it in Settings › Display.`; };
  clockTitle(); window.addEventListener('nd:timezone', () => { clockTitle(); tick(); });
  clock.addEventListener('click', () => { location.hash = 'settings/display'; });
  tick(); setInterval(tick, 1000);

  // Feed health: the one live-status primitive (live.status) plus each feed's own health. Offline banner too.
  live.onStatus(() => { paintFeeds(); paintOfflineBanner(); });
  live.on('source', debounce(loadFeeds, 1500));
  loadFeeds(); setInterval(loadFeeds, 60000);
  paintOfflineBanner();

  navButtons().forEach((b) => { if (b.closest('.views')) b.onclick = () => showView(b.dataset.view); });
  // The logo: its lamp icon starts the tour of the page on screen (the tour's lamp starts from that icon); the name
  // next to it goes home to Watch.
  document.querySelector('.brand').addEventListener('click', (e) => {
    e.preventDefault();
    if (e.target.closest('.brand-mark')) { startTour(); return; }
    showView('watch');
  });
  document.querySelector('[data-skip]')?.addEventListener('click', (e) => {
    e.preventDefault();
    const v = document.querySelector('#views .view.active');
    const t = v?.querySelector('h1') || v;
    if (t && !t.hasAttribute('tabindex')) t.setAttribute('tabindex', '-1');
    t?.focus();
  });
  setupOpsRange();
  document.getElementById('kiosk-exit').onclick = leaveKiosk;
  const search = document.getElementById('global-search');
  document.addEventListener('keydown', (e) => {
    // not behind the guided tour: it owns the keyboard until it ends (Esc ends it)
    if (e.key === '/' && !util.isTyping() && !document.querySelector('.tour-root') && !document.body.classList.contains('shell-kiosk')) { e.preventDefault(); document.getElementById('gs').classList.add('expanded'); search.focus(); }
    if (e.key === 'Escape') {
      if (document.querySelector(POPS)) {
        // Esc returns focus to the button that opened the menu (menuKeys does this when focus is inside the menu)
        const btn = document.querySelector(POP_BTNS.split(', ').map((b) => `${b}[aria-expanded="true"]`).join(', '));
        closePops(); btn?.focus({ preventScroll: true }); return;
      }
      if (document.body.classList.contains('shell-kiosk') && !document.querySelector('.tour-root')) { leaveKiosk(); return; }
      // one Esc closes one layer: the event drawer first, then a maximised panel
      const drawer = document.getElementById('drawer');
      if (drawer.classList.contains('open')) { setDrawer(false); return; }
      for (const [id, r] of instances) if (r.el.classList.contains('maximized')) setMaximized(id, false);
    }
  });
  document.getElementById('drawer-close').onclick = () => setDrawer(false);
}

// ------------------------------------------------------------------ the Ops deck's grid, and Ops on a phone
// GridStack is loaded on demand (core/libs.js need('gridstack')) and initialised once. On a phone Ops is the summary
// from views/ops-phone.js (m-desk): mount(section) -> a handle with destroy() (or the module's unmount(section)), or
// null when there is no phone summary, in which case the grid is used as before. Leaving the phone layout destroys the
// summary and initialises the grid once.
let gridP = null;
function ensureGrid() {
  return (gridP ||= need('gridstack').then((GS) => {
    grid = GS.init({
      column: 12, cellHeight: 62, margin: 0, float: false, animate: true,
      handle: '.panel-grip, .panel-title', resizable: { handles: 'se, e, s' },
      columnOpts: { breakpoints: [{ w: 760, c: 1, layout: 'list' }], layout: 'list' },
    }, '#grid');
    grid.on('change', () => { saveLayout(); if (!editLayout) syncPhoneDeck(); });
    setupPhoneDeck();
    grid.on('removed', (e, items) => { items.forEach((n) => unmountPanel(n.id)); syncMaximized(); saveLayout(); });
    grid.on('resizestop', (e, el) => { const r = instances.get(el.gridstackNode.id); setTimeout(() => r?.inst.resize?.(), 60); });
    new ResizeObserver(debounce(resizeAll, 120)).observe(document.getElementById('grid'));
    return grid;
  }).catch((e) => { gridP = null; throw e; }));
}
function gridOps() {
  ensureGrid().then(() => {
    if (!deckLoaded) { deckLoaded = true; loadDeck(template(currentDeck) || LS.get(`nd.layout.${currentDeck}`) ? currentDeck : 'Cyber Ops'); }
    requestAnimationFrame(resizeAll);
  }).catch((e) => {
    console.error(e);
    const sec = document.querySelector('#views .view[data-view="ops"]');
    if (sec && currentView() === 'ops' && !sec.querySelector('.vs-error')) sec.insertAdjacentHTML('beforeend', errorState({ title: "Ops didn't load", why: 'The dashboard library did not arrive from the server.', err: e.message, retry: () => gridOps() }));
  });
}
let phoneOps = null;      // { m, h } while the phone summary is mounted
let phoneOpsP = null;
function openOps(section) {
  if (!isPhone() || grid) { gridOps(); return; }
  phoneOpsP ||= import('../views/ops-phone.js')
    .then(async (m) => { const h = typeof m.mount === 'function' ? await m.mount(section) : null; if (h === null || h === false) return false; phoneOps = { m, h }; return true; })
    .catch((e) => { console.warn('the phone Ops summary is not available:', e.message); return false; });
  phoneOpsP.then((ok) => { if (!ok && currentView() === 'ops') gridOps(); });
}
function phoneSwitch(phone) {
  if (phone || !phoneOps) { if (!phone && !grid && currentView() === 'ops') gridOps(); return; }
  const { m, h } = phoneOps;
  phoneOps = null; phoneOpsP = null;
  try { if (typeof h?.destroy === 'function') h.destroy(); else m.unmount?.(document.querySelector('#views .view[data-view="ops"]')); } catch (e) { console.error(e); }
  if (currentView() === 'ops') gridOps();
}

// ------------------------------------------------------------------ boot
export function boot({ failed = {} } = {}) {
  for (const [v, why] of Object.entries(failed)) failedViews.set(v, why);
  migrateDecks();
  // The SQL console's entry points (.needs-sql) show only once /api/health says it is on (OSINTHUB_SQL_CONSOLE=1).
  api.health().then(() => { document.documentElement.dataset.sqlConsole = sqlConsoleOn() ? 'on' : 'off'; });
  live.connect();
  setupTopbar();
  setupMenus2();
  setupCommands();
  watchBadge();
  // the Ops deck's grid: at once on a computer; on a phone only if Ops needs it (ops-phone.js is not there)
  if (!isPhone()) ensureGrid();
  onPhoneChange(phoneSwitch);
  initPhoneShell({ titles: TITLES });
  store.subscribe(() => instances.forEach((r) => { try { r.inst.refresh?.(); } catch (e) { console.error(e); } }));
  setupMenus();
  setupSearch({ openEvent, store });
  setupOpsFilter();
  setupAlertsBadge({ live });
  // Entity chips (core/chips.js) in the deck panels and map popups, Explorer, Cinema, the event drawer and Network.
  for (const sel of ['#grid', '#view-explorer', '#view-cinema', '#view-network', '#drawer-body']) watchChips(document.querySelector(sel));
  // Any #<view>[/...] link switches view (the alerts badge, global search results, links between views).
  // An empty or unknown route (#, #nope) opens the landing page and the URL says so (no extra history entry); #help
  // is the Help desk's own route (core/help.js), shown over the current view.
  window.addEventListener('hashchange', () => {
    const v = viewOf();
    if (v === 'help') return;
    if (v === 'search') { searchRoute(); return; }
    if (!KNOWN.has(v)) {
      const to = landingView();
      history.replaceState(null, '', `#${to}`);
      showView(to, { replace: true });
      announceRoute();
      return;
    }
    if (v !== currentView()) showView(v);
    else { syncKiosk(); paintCurrent(); announceRoute(); }
    tidyRoute();
  });
  // the deck mounts lazily on first visit to Ops, so hidden panels never initialise at 0x0
  // A link opens its own view; otherwise Night Desk opens on the landing page from Settings › Display (Watch).
  const alias = canonical(location.hash);
  if (alias) history.replaceState(null, '', alias);
  const start = viewOf();
  showView(KNOWN.has(start) ? start : landingView(), { replace: true });
  if (start === 'search') searchRoute();
  tidyRoute();
  lastRoute = routeLabel();
}

// After a view has opened, the address says what is on screen (B2-09): the shell's own views have no sub-pages, so
// #ops/x and #watch/x read #ops and #watch (a ?range= is kept); #notes/<search> has filled in the Notes search, then
// reads #notes; a view named in capitals (#WATCH, #Network/alerts) is written in lower case. No extra history entry.
const FLAT_VIEWS = new Set(['ops', 'watch', 'notes']);
function tidyRoute() {
  const m = location.hash.match(/^(#\/?)([^/?]*)([^?]*)(\?.*)?$/);
  if (!m) return;
  const [, lead, name, sub, query = ''] = m;
  const v = name.toLowerCase();
  if (!KNOWN.has(v)) return;
  const want = `${lead}${v}${FLAT_VIEWS.has(v) ? '' : sub}${query}`;
  if (want !== location.hash) history.replaceState(history.state, '', want);
}

// Ops on a phone (design.md §4.5, mock-ops.png; lane m-desk). Contract (core/shell.js openOps): mount(section) ->
// a handle with destroy(). The shell calls it only on a phone, where GridStack is never initialised.
//
// #ops            four summary cards, in order: Needs attention (collapses to its content), Newly exploited (5 rows,
//                 All ›), Latest news (3 rows -> News), Source health; an "Open map" row; a footer saying decks,
//                 widgets and the map wall are arranged on a computer, with Copy link.
// #ops?panel=<id> a pushed page (page.js parentOf -> #ops): that deck panel full screen (any registered panel id,
//                 so a link copied on a computer opens the same panel). Each card's ⤢ is a link to it, so a tap and
//                 a pasted link give the same page, and Back returns to the summary.
// Nothing here loads maplibre or echarts-gl: the cards are plain HTML, and a panel page loads only its own library.
import { PANELS } from '../core/panels.js';
import { api } from '../core/api.js';
import { live } from '../core/live.js';
import * as util from '../core/util.js';
import { store } from '../core/store.js';
import { setPhoneTitle, setActionBar, afterRender } from '../core/page.js';
import { emptyState, errorState } from '../core/view.js';
import { demoOnly } from '../core/alerts-badge.js';
import { headline } from './net/alert-text.js';
import { openEvent, freshTitle } from '../core/shell.js';
import { healthSplit } from './sources.js';

const { esc, fmt, ago, toast } = util;
const CARDS = [
  { id: 'net-attention', title: 'Needs attention' },
  { id: 'kev-tracker', title: 'Newly exploited' },
  { id: 'news-wire', title: 'Latest news' },
  { id: 'source-health', title: 'Source health' },
];
const EXPAND = '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M14 4h6v6M20 4l-7 7M10 20H4v-6M4 20l7-7" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const panelOf = (hash = location.hash) => {
  const m = String(hash).match(/^#\/?ops\?(?:[^#]*&)?panel=([^&#]+)/i);
  return m ? decodeURIComponent(m[1]) : null;
};
const hrefFor = (id) => `#ops?panel=${encodeURIComponent(id)}`;

let S = null;   // { section, root, summary, page, timers, panel: { id, inst } }

export function mount(section) {
  if (S) return handle;
  const root = document.createElement('div');
  root.className = 'ops-m';
  root.innerHTML = `<div class="ops-m-sum">
      ${CARDS.map((c) => `<section class="ops-m-card" data-card="${c.id}" aria-labelledby="ops-m-h-${c.id}">
        <header class="ops-m-ch"><h2 class="ops-m-t" id="ops-m-h-${c.id}">${esc(c.title)}<span class="ops-m-n mono" hidden></span></h2>
          <a class="ops-m-max" href="${hrefFor(c.id)}" aria-label="Open ${esc(c.title)} full screen" title="Full screen">${EXPAND}</a></header>
        <div class="ops-m-cb"><div class="m-skel ops-m-skel"></div></div></section>`).join('')}
      <a class="ops-m-map" href="${hrefFor('world-map')}"><span><b>World map</b><small>Events with a place, on the map</small></span><span class="ops-m-go">Open map ›</span></a>
      <p class="ops-m-foot"><svg class="i" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M9 20h6M12 16v4" stroke="currentColor" stroke-width="1.6"/></svg>
        <span>Decks, widgets and the map wall are arranged on a computer.</span>
        <button type="button" class="ops-m-copy">Copy link</button></p>
    </div>
    <div class="ops-m-page" hidden></div>`;
  section.prepend(root);
  document.body.classList.add('ops-m-on');
  S = { section, root, summary: root.querySelector('.ops-m-sum'), page: root.querySelector('.ops-m-page'), timers: [], panel: null, offs: [] };
  root.querySelector('.ops-m-copy').addEventListener('click', copyLink);
  window.addEventListener('hashchange', route);
  S.offs.push(() => window.removeEventListener('hashchange', route));
  // live updates: the alert count and the sources' state change without a reload
  for (const topic of ['netlog_alerts', 'sources']) { try { const off = live.on?.(topic, () => S && !S.panel && loadCards([topic === 'sources' ? 'source-health' : 'net-attention'])); if (typeof off === 'function') S.offs.push(off); } catch { /* no such topic */ } }
  S.timers.push(setInterval(() => { if (S && !S.panel && !document.hidden && isOpsView()) loadCards(); }, 120e3));
  route();
  return handle;
}

export function unmount() { handle.destroy(); }
const handle = {
  destroy() {
    if (!S) return;
    closePanel();
    S.timers.forEach(clearInterval);
    S.offs.forEach((f) => { try { f(); } catch { /* gone */ } });
    S.root.remove();
    document.body.classList.remove('ops-m-on');
    if (isOpsView()) { setPhoneTitle(null); setActionBar(null); }
    S = null;
  },
};

const isOpsView = () => document.body.dataset.view === 'ops';

function route() {
  if (!S || !/^#\/?ops\b/i.test(location.hash || '#ops')) return;
  const id = panelOf();
  if (id) { openPanel(id); return; }
  closePanel();
  S.summary.hidden = false;
  S.page.hidden = true;
  setPhoneTitle(null);
  loadCards().finally(() => afterRender('ops'));
}

// ------------------------------------------------------------------ the cards
let seq = 0;
async function loadCards(only = null) {
  if (!S) return;
  const my = ++seq;
  const jobs = { 'net-attention': cardAttention, 'kev-tracker': cardKev, 'news-wire': cardNews, 'source-health': cardSources };
  await Promise.all(CARDS.filter((c) => !only || only.includes(c.id)).map(async (c) => {
    const card = S?.root.querySelector(`.ops-m-card[data-card="${c.id}"]`);
    if (!card) return;
    let html;
    try { html = await jobs[c.id](card); } catch (e) {
      html = errorState({ retry: () => loadCards([c.id]), title: `Couldn't load ${c.title.toLowerCase()}`, why: 'The Night Desk server did not answer. Try again in a moment.', err: e.message, size: 'sm' });
    }
    if (my !== seq && !only) return;
    if (S && card.isConnected) card.querySelector('.ops-m-cb').innerHTML = html;
  }));
}
const setN = (card, n) => { const b = card.querySelector('.ops-m-n'); b.hidden = !n; b.textContent = n ? fmt(n) : ''; };

async function cardAttention(card) {
  let n, rows;
  try {
    [n, rows] = await Promise.all([api.get('/api/netlog/alerts/count'), api.get('/api/netlog/incidents', { needs_you: true, limit: 1 })]);
  } catch (e) {
    if (e.status === 404) return '<p class="ops-m-line">Network logs are not set up on this Night Desk.</p>';
    throw e;
  }
  setN(card, 0);
  if (n.needs_you) {
    const w = rows?.[0];
    const worst = w ? `${headline(w).lead} (${w.severity})` : '';
    return `<a class="ops-m-big" href="#network/alerts"><span class="ops-m-num">${fmt(n.needs_you)}</span>
      <span class="ops-m-bt">${n.needs_you === 1 ? 'alert needs' : 'alerts need'} you${worst ? ` · worst: ${esc(worst)}` : ''}</span></a>`;
  }
  const demo = demoOnly(n);
  return `<a class="ops-m-big calm" href="#network/alerts"><span class="ops-m-num">0</span>
    <span class="ops-m-bt">${demo ? `No real alerts · ${fmt(n.demo)} demo alert${n.demo === 1 ? '' : 's'} open, made-up data` : 'Nothing needs you right now'}</span></a>`;
}

const KEV_SINCE = 24 * 7;
async function cardKev(card) {
  let rows = await api.events({ sources: ['cisa_kev'], since_hours: KEV_SINCE, limit: 400 });
  const recent = rows.length;
  let note = '';
  if (!rows.length) { rows = await api.events({ sources: ['cisa_kev'], limit: 5 }); note = rows.length ? '<p class="ops-m-note">None added this week. The latest entries:</p>' : ''; }
  setN(card, recent);
  if (!rows.length) return '<p class="ops-m-line">Nothing in the exploited-vulnerability catalogue yet.</p>';
  const items = rows.slice(0, 5).map((r) => {
    const [cve, ...rest] = String(r.title || '').split(' · ');
    const what = String(r.summary || '').split('. ')[0].replace(new RegExp(`^${(rest.join(' ') || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*`, 'i'), '');
    const kind = what.replace(/\s*vulnerability$/i, '').toLowerCase();
    return `<li><button type="button" class="ops-m-row" data-ev="${esc(r.id)}"><span class="ops-m-rt"><span class="mono">${esc(cve)}</span>${rest.length ? ` · ${esc(rest.join(' · '))}` : ''}</span>
      <span class="ops-m-rs mono">added ${esc(ago(r.ts))}${kind ? ` · ${esc(kind)}` : ''}</span></button></li>`;
  }).join('');
  return `${note}<ul class="ops-m-list">${items}</ul><a class="ops-m-all" href="${hrefFor('kev-tracker')}">${recent ? `All ${fmt(recent)} ›` : 'All ›'}</a>`;
}

async function cardNews() {
  const r = await api.get('/api/news/stories', { limit: 3 });
  const st = r?.stories || [];
  if (!st.length) return '<p class="ops-m-line">No stories yet. They appear here as the news sources are collected.</p>';
  return `<ul class="ops-m-list">${st.slice(0, 3).map((s) => `<li><a class="ops-m-row" href="#news/story/${encodeURIComponent(s.id)}"><span class="ops-m-rt">${esc(s.title || 'Untitled story')}</span>
    <span class="ops-m-rs mono">${fmt(+s.source_count || 1)} source${+s.source_count === 1 ? '' : 's'} · ${esc(ago(s.last_seen || s.first_seen))}</span></a></li>`).join('')}</ul>
    <a class="ops-m-all" href="#news">All news ›</a>`;
}

async function cardSources() {
  const rows = await api.sources();
  const n = healthSplit(rows);   // the Sources panel's own split: reconnecting is an error, 'paused' is paused
  const waiting = rows.filter((s) => s.needs === 'watchlist').length;
  const off = live.isOffline?.();
  const parts = [`${fmt(n.error)} error${n.error === 1 ? '' : 's'}`];
  if (n.live + n.ok) parts.push(`${fmt(n.live + n.ok)} working`);
  if (n.paused) parts.push(`${fmt(n.paused)} paused${off ? ' (offline mode)' : ''}`);
  if (waiting) parts.push(`${fmt(waiting)} waiting for a network to watch`);
  if (n.off - waiting > 0) parts.push(`${fmt(n.off - waiting)} off`);
  return `<a class="ops-m-src${n.error ? ' bad' : ''}" href="#settings/sources"><span class="mono">${esc(parts.join(' · '))}</span><span class="ops-m-go">Sources ›</span></a>`;
}

async function copyLink() {
  const url = `${location.origin}${location.pathname}#ops`;
  try { await navigator.clipboard.writeText(url); toast('Link copied. Open it on a computer to arrange the decks.'); } catch { toast(url); }
}

// ------------------------------------------------------------------ #ops?panel=<id>: one deck panel full screen
function closePanel() {
  if (!S?.panel) return;
  try { S.panel.inst?.destroy?.(); } catch (e) { console.error(e); }
  clearInterval(S.panel.tick);
  S.panel = null;
  S.page.replaceChildren();
}
function openPanel(id) {
  if (S.panel?.id === id) return;
  closePanel();
  S.summary.hidden = true;
  S.page.hidden = false;
  const def = PANELS.get(id);
  setPhoneTitle(def?.title || 'Panel', { back: { label: 'Ops', href: '#ops' } });
  if (!def) {
    S.page.innerHTML = emptyState({ title: 'This panel is not available', why: 'It may have been renamed. The Ops summary has the others.', act: '<a class="m-btn" href="#ops">Ops summary</a>' });
    S.panel = { id, inst: null };
    return;
  }
  S.page.innerHTML = `<div class="panel ops-m-pnl" data-panel="${esc(id)}"><div class="panel-head">
      <span class="panel-badge" hidden></span><div class="panel-tools"><span class="panel-updated" hidden><span></span></span><span class="panel-xtools"></span></div>
    </div><div class="panel-body"></div></div>`;
  const el = S.page.firstElementChild;
  const body = el.querySelector('.panel-body');
  const badge = el.querySelector('.panel-badge');
  const upd = el.querySelector('.panel-updated');
  let updatedAt = null, refresh = false;
  const paint = () => { upd.hidden = !updatedAt; upd.title = updatedAt ? freshTitle(updatedAt, refresh) : ''; if (updatedAt) upd.querySelector('span').textContent = ago(updatedAt); };
  const key = `nd.panel.phone.${id}`;
  const LS = { get: (d) => { try { return JSON.parse(localStorage.getItem(key)) ?? d; } catch { return d; } }, set: (v) => { try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* private mode */ } } };
  const ctx = {
    api, live, store, util, openEvent, panelEl: el, tools: el.querySelector('.panel-xtools'),
    setBadge(text, isLive = false) { badge.hidden = text == null; badge.textContent = text ?? ''; badge.classList.toggle('live', isLive); },
    setUpdated(t) { updatedAt = t; const ms = t ? new Date(t).getTime() : NaN; refresh = Number.isFinite(ms) && Math.abs(Date.now() - ms) < 5000; paint(); },
    state: { get: () => LS.get({}), set: (p) => LS.set({ ...LS.get({}), ...p }) },
  };
  S.panel = { id, inst: null, tick: setInterval(paint, 15000) };
  try { S.panel.inst = def.mount(body, ctx) || {}; } catch (err) {
    console.error(err);
    body.innerHTML = errorState({ retry: () => location.reload(), retryLabel: 'Reload the page', title: "This panel didn't start", why: 'Reload the page; the Ops summary still works.', err: err.message, size: 'sm' });
  }
  requestAnimationFrame(() => { try { S?.panel?.inst?.resize?.(); } catch { /* not sized yet */ } });
}

// a feed row on a card opens the event drawer, as on the deck
document.addEventListener('click', (e) => {
  const b = e.target.closest?.('.ops-m [data-ev]');
  if (b) openEvent(b.dataset.ev, { opener: b });
});

// News on a phone (v1.2 mobile, lane m-news; design.md §4.3, mock-news.png, mock-story.png). Created the first time
// the phone layout applies (views/news.js); nothing here runs or renders on a computer.
//
// The list (#news): a sticky sub-nav (Latest · Most covered · Following), a filter row that scrolls away
// ([Search] [7 days ▾] [Filter n]), then cards. Each card is ONE link (#news/story/<id>) with nothing interactive
// inside: an outlet line, a serif headline, a one-line summary cut at a word boundary and a plain meta line.
// "Titles only" density (outlet + headline) is set in the Filter sheet and kept per device (localStorage).
// A story or article (#news/story/<id>, #news/article/<id>) is a pushed page: the list is hidden (kept, so Back
// lands on the same rows and page.js restores the scroll), the top bar says ‹ News (or ‹ Story), and the page's
// action bar replaces the tab bar (views/news/detail.js renderStoryPhone / renderArticlePhone).
import { esc, ago, entName, tierLabel, decode, eicon, TYPE_FILTERS, topEntity } from './common.js';
import { renderStoryPhone, renderArticlePhone } from './detail.js';
import { tierWord, safeDecode as dec } from '../../core/util.js';
import * as T from '../../core/time.js';
import { pushPage, setPhoneTitle, setActionBar, afterRender, onRoute } from '../../core/page.js';
import { openSheet, actionSheet } from '../../core/sheet.js';
import { emptyState, errorState, stateAct } from '../../core/view.js';
import { openEntity } from '../../core/entity-panel.js';

const DENSITY = 'nd.news.density';
const LS = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};
const RANGES =[[24, '24 hours', '24h'], [168, '7 days', '7 days'], [720, '30 days', '30 days'], [0, 'All time', 'All time']];
const SHOWS = [['all', 'All stories'], ['new', 'New since your last visit'], ['multi', 'From 2 or more outlets']];
const ICON = {
  search: '<svg class="i" aria-hidden="true"><use href="#i-search"/></svg>',
  filter: '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M7 12h10M10 17h4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
  caret: '<svg class="i nw-m-caret" viewBox="0 0 24 24" aria-hidden="true"><path d="m7 10 5 5 5-5" fill="none" stroke="currentColor" stroke-width="1.7"/></svg>',
};

// The best trust tier a story has, in words ("official" before "research"…).
const bestTier = (s) => Object.keys(s.tier_counts || {}).map((t) => String(t).toUpperCase()).sort()[0] || '';
const plural = (n, w, many = `${w}s`) => `${n} ${n === 1 ? w : many}`;

// ------------------------------------------------------------------ one line, cut at a word boundary
// The summary under a card is the first sentence when it fits on one line, else as many whole words as fit plus
// "…" (never a cut inside a word). Measured with a canvas in the element's own font; redone on a width change and
// once the web fonts have loaded.
let canvas = null;
function fitLines(root) {
  const els = [...root.querySelectorAll('[data-full]')];
  if (!els.length) return;
  const w = els[0].clientWidth;
  if (!w) return;
  const cs = getComputedStyle(els[0]);
  const g = (canvas ||= document.createElement('canvas')).getContext('2d');
  g.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
  const room = w - 6;
  const fits = (t) => g.measureText(t).width <= room;
  for (const e of els) {
    const full = e.dataset.full;
    const first = (full.match(/^.+?[.!?](?=\s|$)/) || [full])[0];
    if (fits(first)) { e.textContent = first; continue; }
    const words = first.split(/\s+/).filter(Boolean);
    let lo = 1, hi = words.length - 1, best = 1;
    const at = (k) => `${words.slice(0, k).join(' ').replace(/[,;:–—-]+$/, '')}…`;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (fits(at(mid))) { best = mid; lo = mid + 1; } else hi = mid - 1; }
    e.textContent = at(best);
  }
}

export function phoneNews(host, D) {
  const { S } = D;
  const root = document.createElement('div');
  root.className = 'nw-m';
  root.innerHTML = `
    <div class="nw-m-list">
      <nav class="nw-m-sub" aria-label="Story lists">
        <button type="button" data-mv="latest">Latest</button><button type="button" data-mv="covered">Most covered</button><button type="button" data-mv="following">Following</button>
      </nav>
      <div class="nw-m-frow">
        <button type="button" class="m-chip nw-m-fchip" data-m="search">${ICON.search}<span>Search</span></button>
        <button type="button" class="m-chip nw-m-fchip" data-m="range" aria-haspopup="menu"></button>
        <button type="button" class="m-chip nw-m-fchip" data-m="filter" aria-haspopup="dialog"></button>
      </div>
      <div class="nw-m-sbar" hidden>
        <input type="search" class="nw-m-q" placeholder="Search stories" aria-label="Search stories" autocomplete="off" spellcheck="false" enterkeyhint="search">
        <button type="button" class="nw-m-qx" data-m="search-close">Cancel</button>
      </div>
      <div class="nw-m-stream"></div>
    </div>
    <div class="nw-m-page" hidden></div>`;
  host.append(root);
  const $ = (s) => root.querySelector(s);
  const list = $('.nw-m-list'), stream = $('.nw-m-stream'), page = $('.nw-m-page'), qIn = $('.nw-m-q');
  const M = { on: false, shown: null, seq: 0, rendered: false };
  const dense = () => LS.get(DENSITY) === 'titles';

  // ---------------------------------------------------------------- the list
  const mview = () => (S.feed === 'watch' ? 'following' : S.sort === 'size' ? 'covered' : 'latest');
  const nFilters = () => S.types.size + S.tiers.size + S.sources.size + (S.feed === 'new' || S.feed === 'multi' ? 1 : 0) + (S.entity ? 1 : 0);
  function chrome() {
    const v = mview();
    root.querySelectorAll('[data-mv]').forEach((b) => { const on = b.dataset.mv === v; b.classList.toggle('on', on); if (on) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current'); });
    const r = RANGES.find((x) => x[0] === D.hoursOf(S.range)) || RANGES[1];
    const rb = $('[data-m="range"]');
    rb.innerHTML = `<span>${esc(r[2])}</span>${ICON.caret}`;
    rb.setAttribute('aria-label', `Time range: ${r[1]}`);
    const n = nFilters();
    const fb = $('[data-m="filter"]');
    fb.innerHTML = `${ICON.filter}<span>Filter</span>${n ? `<b class="nw-m-fn">${n}</b>` : ''}`;
    fb.classList.toggle('on', n > 0);
    fb.setAttribute('aria-label', n ? `Filter, ${plural(n, 'filter')} on` : 'Filter');
  }

  function card(s) {
    const srcs = s.sources || [];
    const lead = s.lead_source || srcs[0] || '';
    const others = srcs.filter((x) => x !== lead);
    const out = others.length === 1 ? `${lead} + ${others[0]}` : others.length ? `${lead} + ${others.length} more` : lead;
    const fresh = D.isNew(s);
    const top = topEntity(s.top_entities);
    const meta = [plural(s.source_count || 1, 'source'), tierWord(bestTier(s)), top ? entName(top) : ''].filter(Boolean).join(' · ');
    const sum = String(s.summary || '').replace(/\s+/g, ' ').trim();
    return `<a class="nw-m-card${fresh ? ' new' : ''}" href="#news/story/${esc(encodeURIComponent(s.id))}" data-sid="${esc(s.id)}">
      <span class="nw-m-out">${fresh ? '<b class="nw-m-new">New</b> · ' : ''}<span class="nw-m-outn">${esc(out)}</span> · ${esc(T.ago(s.last_seen).replace(' ago', ''))}</span>
      <span class="nw-m-h">${esc(s.title)}</span>
      ${sum ? `<span class="nw-m-sum" data-full="${esc(sum)}">${esc(sum)}</span>` : ''}
      <span class="nw-m-meta">${esc(meta)}</span>
    </a>`;
  }
  function result(x) {
    const st = S.all.find((s) => s.id === x.story_id);
    const snip = decode(x.snippet || '').replace(/\s+/g, ' ').trim();
    const meta = [tierLabel(x.tier), st && st.source_count > 1 ? `part of a ${st.source_count}-source story` : ''].filter(Boolean).join(' · ');
    return `<a class="nw-m-card" href="#news/article/${esc(encodeURIComponent(x.id))}" data-aid="${esc(x.id)}">
      <span class="nw-m-out"><span class="nw-m-outn">${esc(x.source)}</span> · ${esc(ago(x.published).replace(' ago', ''))}</span>
      <span class="nw-m-h">${esc(decode(x.title))}</span>
      ${snip ? `<span class="nw-m-sum" data-full="${esc(snip)}">${esc(snip)}</span>` : ''}
      <span class="nw-m-meta">${esc(meta)}</span>
    </a>`;
  }
  const skel = () => `<div class="nw-m-skel" aria-hidden="true">${'<div class="m-skel m-skel-row"></div>'.repeat(5)}</div>`;

  function renderList() {
    if (!M.on) return;
    chrome();
    stream.classList.toggle('nw-m-dense', dense());
    if (S.q) return renderSearch();
    if (S.failed) {
      stream.innerHTML = errorState({ retry: D.reload, title: "Couldn't load the news", why: 'The Night Desk server did not answer. Stories already collected are safe; try again in a moment.' });
      return done();
    }
    if (!S.loaded) { stream.innerHTML = skel(); return; }
    const all = D.visible();
    if (!all.length) {
      const filtered = nFilters() > 0;
      const arts = S.meta ? (S.meta.outlets || []).reduce((a, o) => a + (o.ok || 0), 0) : null;
      const why = S.feed === 'watch' && !(S.watch.entities.length || S.watch.keywords.length || (S.watch.stack || []).length)
        ? 'You follow nothing yet. Open a story, tap a name under What it touches, then Follow.'
        : S.feed === 'watch' ? `Nothing you follow was in the news in ${D.rangeLabel()}.`
        : filtered ? 'No stories match these filters.'
        : S.meta?.offline ? 'Offline mode is on, so news outlets are not being read.'
        : arts === 0 ? 'News outlets are read every 20 minutes. On a new install the first stories appear a few minutes after start.'
        : `No stories in ${D.rangeLabel()}. Choose a longer time range.`;
      const act = filtered ? stateAct('Clear filters', { data: { m: 'clear' } }) : S.feed === 'watch' ? stateAct('What you follow', { href: '#settings/follow' }) : '';
      stream.innerHTML = emptyState({ title: filtered || arts !== 0 ? 'No stories' : 'No stories yet', why: esc(why), act });
      return done();
    }
    const shown = all.slice(0, S.shown);
    let html = '', last = '';
    for (const s of shown) {
      if (S.sort === 'last_seen') {
        const n = T.dayDiff(s.last_seen);
        const d = n === 0 ? 'Today' : n === 1 ? 'Yesterday' : T.longDate(s.last_seen);
        if (d !== last) { html += `<h2 class="nw-m-day">${esc(d)}</h2>`; last = d; }
      }
      html += card(s);
    }
    html += all.length > S.shown
      ? `<div class="nw-m-endw"><button type="button" class="m-btn nw-m-moreb" data-m="more">Show ${Math.min(D.PAGE, all.length - S.shown)} more of ${all.length - S.shown}</button></div>`
      : S.total > S.all.length
        ? `<p class="nw-m-end">The newest ${plural(S.all.length, 'story', 'stories')} of ${S.total} in ${esc(D.rangeLabel())}${all.length < S.all.length ? `, ${all.length} matching` : ''}. Choose a shorter range or a filter to see older ones.</p>`
        : `<p class="nw-m-end">${plural(all.length, 'story', 'stories')} · end of ${esc(D.rangeLabel())}</p>`;
    stream.innerHTML = html;
    done();
  }
  function renderSearch() {
    const r = S.search;
    if (S.searching || !r) { stream.innerHTML = skel(); return; }
    if (r.mode === 'error') { stream.innerHTML = errorState({ retry: () => D.search(S.q), title: "Couldn't search the news", why: 'Try other words in a moment.' }); return done(); }
    const seen = new Set();
    const rows = r.results.filter((x) => { const k = x.story_id || x.id; if (seen.has(k)) return false; seen.add(k); return true; });
    stream.innerHTML = `<p class="nw-m-sinfo">${plural(r.results.length, 'article')} for “${esc(S.q)}” · ${esc(D.rangeLabel())}${r.mode === 'keyword' ? ' · keyword match' : ''}</p>`
      + (rows.length ? rows.map(result).join('') : emptyState({ title: 'No matching articles', why: 'Try other words, or choose a longer time range.' }));
    done();
  }
  function done() {
    M.rendered = true;
    if (!list.hidden) { fitLines(stream); afterRender('news'); }
  }
  let lastW = 0;
  const refit = () => { if (M.on && !list.hidden && innerWidth !== lastW) { lastW = innerWidth; fitLines(stream); } };
  window.addEventListener('resize', refit);
  document.fonts?.ready?.then(() => { lastW = 0; refit(); });

  // ---------------------------------------------------------------- the range and filter sheets
  function rangeSheet() {
    const h = D.hoursOf(S.range);
    actionSheet({ id: 'news-range', title: 'Time range', items: RANGES.map(([v, l]) => ({ label: l, current: v === h, run: () => D.setRange(v) })) });
  }

  // The Filter sheet works on a copy: nothing changes until "Show N stories"; ×, Esc, a tap outside or Back
  // close it unchanged. N is the count the list will show (the server's answer for the chosen sources, trust and
  // followed name, then the "Show" and "Has" choices applied the way the list applies them).
  function filterSheet() {
    const d = { feed: S.feed === 'new' || S.feed === 'multi' ? S.feed : 'all', types: new Set(S.types), tiers: new Set(S.tiers), sources: new Set(S.sources),
      entity: S.entity, dense: dense() };
    const tiers = {};
    for (const o of S.outlets) { const t = String(o.tier || '?').toUpperCase(); tiers[t] = (tiers[t] || 0) + 1; }
    const outlets = [...S.outlets].sort((a, b) => String(a.source).localeCompare(String(b.source)));
    const follows = (S.watch.entities || []).map((id) => ({ id, name: D.watchName(id), type: id.split(':')[0] }));
    const body = document.createElement('div');
    body.className = 'nw-m-fs';
    const chipB = (attrs, label, on, extra = '') => `<button type="button" class="m-chip nw-m-fsc" ${attrs} aria-pressed="${on}">${extra}${esc(label)}</button>`;
    body.innerHTML = `
      <section class="nw-m-fsec"><h3 class="nw-m-k">Show</h3><div class="nw-m-fchips" role="group" aria-label="Show">
        ${SHOWS.map(([v, l]) => chipB(`data-f-feed="${v}"`, l, d.feed === v)).join('')}</div></section>
      <section class="nw-m-fsec"><h3 class="nw-m-k">Has</h3><div class="nw-m-fchips" role="group" aria-label="Stories that name">
        ${TYPE_FILTERS.map(([g, l]) => chipB(`data-f-type="${g}"`, l, d.types.has(g), eicon(g === 'ioc' ? 'ip' : g))).join('')}</div></section>
      <section class="nw-m-fsec"><h3 class="nw-m-k">Trust</h3><div class="nw-m-fchips" role="group" aria-label="Trust">
        ${['A', 'B', 'C', 'D'].filter((t) => tiers[t]).map((t) => chipB(`data-f-tier="${t}"`, `${tierLabel(t)} · ${tiers[t]}`, d.tiers.has(t))).join('') || '<p class="nw-m-fhint">No outlets yet.</p>'}</div>
        <p class="nw-m-fhint">Official: governments and vendors. Research: security labs. Community: blogs and trade press. Unverified: everything else.</p></section>
      ${follows.length || d.entity ? `<section class="nw-m-fsec"><h3 class="nw-m-k">Watchlist</h3><div class="nw-m-fchips" role="group" aria-label="Only stories that name">
        ${[...(d.entity && !follows.some((f) => f.id === d.entity.id) ? [{ id: d.entity.id, name: d.entity.name, type: d.entity.type }] : []), ...follows]
          .map((f) => chipB(`data-f-ent="${esc(f.id)}" data-f-name="${esc(f.name)}" data-f-etype="${esc(f.type)}"`, f.name, d.entity?.id === f.id, eicon(f.type))).join('')}</div></section>` : ''}
      <section class="nw-m-fsec"><h3 class="nw-m-k">Sources</h3>
        <input type="search" class="nw-m-fq" placeholder="Find a source" aria-label="Find a source" autocomplete="off" spellcheck="false">
        <div class="nw-m-srcs">${outlets.map((o) => `<label class="nw-m-src" data-name="${esc(String(o.source).toLowerCase())}">
          <input type="checkbox" data-f-src="${esc(o.source)}" ${d.sources.has(o.source) ? 'checked' : ''}>
          <span class="nw-m-srcn">${esc(o.source)}</span><span class="nw-m-srct">${esc(tierLabel(o.tier))} · ${o.ok}</span></label>`).join('') || '<p class="nw-m-fhint">No outlets yet.</p>'}</div></section>
      <section class="nw-m-fsec"><h3 class="nw-m-k">Density</h3><div class="nw-m-fchips" role="radiogroup" aria-label="Density">
        ${chipB('data-f-dense="0"', 'Comfortable', !d.dense)}${chipB('data-f-dense="1"', 'Titles only', d.dense)}</div></section>`;
    const clear = document.createElement('button');
    clear.type = 'button'; clear.className = 'm-btn m-btn-ghost nw-m-fclear'; clear.textContent = 'Clear';
    const show = document.createElement('button');
    show.type = 'button'; show.className = 'm-btn m-btn-primary nw-m-fshow'; show.textContent = 'Show stories';
    const sh = openSheet({ id: 'news-filter', title: 'Filter stories', size: 'full', body, footer: [clear, show] });

    let seq = 0, rows = null, rowsKey = '';
    const key = () => JSON.stringify([[...d.sources].sort(), [...d.tiers].sort(), d.entity?.id || '']);
    async function count() {
      const my = ++seq;
      const k = key();
      if (k !== rowsKey) {
        show.disabled = true;
        show.textContent = 'Counting…';
        try { rows = await D.preview(d); rowsKey = k; } catch { rows = null; }
        if (my !== seq) return;
      }
      show.disabled = false;
      if (!rows) { show.textContent = 'Show stories'; return; }
      const n = D.visible({ list: rows, feed: d.feed === 'all' && S.feed === 'watch' ? 'watch' : d.feed, types: d.types }).length;
      const capped = (rows.total ?? rows.length) > rows.length; // the newest 500 loaded: the count is a floor
      show.textContent = `Show ${n}${capped ? '+' : ''} ${n === 1 && !capped ? 'story' : 'stories'}`;
      show.dataset.n = n;
    }
    const sync = () => {
      body.querySelectorAll('[data-f-feed]').forEach((b) => b.setAttribute('aria-pressed', b.dataset.fFeed === d.feed));
      body.querySelectorAll('[data-f-type]').forEach((b) => b.setAttribute('aria-pressed', d.types.has(b.dataset.fType)));
      body.querySelectorAll('[data-f-tier]').forEach((b) => b.setAttribute('aria-pressed', d.tiers.has(b.dataset.fTier)));
      body.querySelectorAll('[data-f-ent]').forEach((b) => b.setAttribute('aria-pressed', d.entity?.id === b.dataset.fEnt));
      body.querySelectorAll('[data-f-dense]').forEach((b) => b.setAttribute('aria-pressed', (b.dataset.fDense === '1') === d.dense));
      count();
    };
    body.addEventListener('click', (e) => {
      const b = e.target.closest('button');
      if (!b) return;
      const t = (set, v) => (set.has(v) ? set.delete(v) : set.add(v));
      if (b.dataset.fFeed) d.feed = b.dataset.fFeed;
      else if (b.dataset.fType) t(d.types, b.dataset.fType);
      else if (b.dataset.fTier) t(d.tiers, b.dataset.fTier);
      else if (b.dataset.fEnt) d.entity = d.entity?.id === b.dataset.fEnt ? null : { id: b.dataset.fEnt, name: b.dataset.fName, type: b.dataset.fEtype };
      else if (b.dataset.fDense) d.dense = b.dataset.fDense === '1';
      else return;
      sync();
    });
    body.addEventListener('change', (e) => {
      const v = e.target.dataset?.fSrc;
      if (v == null) return;
      if (e.target.checked) d.sources.add(v); else d.sources.delete(v);
      count();
    });
    body.querySelector('.nw-m-fq').addEventListener('input', (e) => {
      const q = e.target.value.trim().toLowerCase();
      body.querySelectorAll('.nw-m-src').forEach((l) => { l.hidden = !!q && !l.dataset.name.includes(q); });
    });
    clear.addEventListener('click', () => {
      d.feed = 'all'; d.types.clear(); d.tiers.clear(); d.sources.clear(); d.entity = null;
      body.querySelectorAll('[data-f-src]').forEach((c) => { c.checked = false; });
      sync();
    });
    show.addEventListener('click', async () => {
      LS.set(DENSITY, d.dense ? 'titles' : 'comfortable');
      await sh.close('close');
      D.apply(d, rowsKey === key() ? rows : null);
    });
    sync();
  }

  // ---------------------------------------------------------------- events
  root.addEventListener('click', (e) => {
    const t = e.target;
    const ent = t.closest('[data-eid]');
    if (ent && root.contains(ent)) { e.preventDefault(); openEntity(ent.dataset.eid); return; }
    const a = t.closest('a.nw-m-card');
    if (a) { e.preventDefault(); pushPage(a.getAttribute('href')); return; }
    const mv = t.closest('[data-mv]');
    if (mv) { D.setView(mv.dataset.mv); window.scrollTo({ top: 0, behavior: 'instant' }); return; }
    const m = t.closest('[data-m]')?.dataset.m;
    if (m === 'range') rangeSheet();
    else if (m === 'filter') filterSheet();
    else if (m === 'search') { $('.nw-m-sbar').hidden = false; $('.nw-m-frow').hidden = true; qIn.value = S.q || ''; qIn.focus(); }
    else if (m === 'search-close') { qIn.value = ''; $('.nw-m-sbar').hidden = true; $('.nw-m-frow').hidden = false; if (S.q) D.clearSearch(); }
    else if (m === 'more') { S.shown += D.PAGE; renderList(); }
    else if (m === 'clear') D.apply({ feed: 'all', types: new Set(), tiers: new Set(), sources: new Set(), entity: null }, null);
  });
  let qt;
  const runQ = () => { clearTimeout(qt); const q = qIn.value.trim(); if (q) D.search(q); else if (S.q) D.clearSearch(); };
  qIn.addEventListener('input', () => { clearTimeout(qt); const q = qIn.value.trim(); if (q.length >= 3 || !q) qt = setTimeout(runQ, 450); });
  qIn.addEventListener('keydown', (e) => { e.stopPropagation(); if (e.key === 'Enter') { e.preventDefault(); runQ(); qIn.blur(); } });

  // ---------------------------------------------------------------- pages
  function showList() {
    M.shown = null; M.bar = null;
    M.seq++;
    page.hidden = true; page.replaceChildren();
    list.hidden = false;
    if (S.q) { $('.nw-m-sbar').hidden = false; $('.nw-m-frow').hidden = true; qIn.value = S.q; }
    if (M.rendered) { lastW = 0; refit(); afterRender('news'); } else renderList();
  }
  function showPage(kind, id) {
    const k = `${kind}:${id}`;
    // shown again (Back from an entity page or another view): page.js cleared the title and the action bar on the
    // way out, so put back exactly what the first open set
    if (M.shown === k && !page.hidden) { setTitle(kind, M.back); setActionBar(M.bar); afterRender('news'); return; }
    M.shown = k;
    M.bar = null;
    const my = ++M.seq;
    const alive = () => M.on && M.seq === my;
    list.hidden = true;
    page.hidden = false;
    M.back = null;
    setTitle(kind, null);
    const opts = { alive, setBack: (b) => { if (alive()) { M.back = b; setTitle(kind, b); } },
      setBar: (nodes) => { if (alive()) { M.bar = nodes; setActionBar(nodes); } }, after: () => alive() && afterRender('news') };
    if (kind === 'story') renderStoryPhone(page, id, D.ctx, opts);
    else renderArticlePhone(page, id, D.ctx, opts);
  }
  function setTitle(kind, b) {
    setPhoneTitle(kind === 'story' ? 'Story' : 'Article', { back: b || { label: 'News', href: '#news' } });
  }
  function route(hash = location.hash) {
    if (!M.on) return;
    const m = String(hash).match(/^#news\/(story|article)\/(.+)$/);
    if (m) showPage(m[1], dec(m[2]));
    else showList();
  }
  // every page change (including one with no hashchange, such as a link to the page already shown) cleared the title
  // and the action bar in core/page.js: show the URL's page again, which puts them back
  onRoute(({ hash }) => { if (M.on && /^#news(?:[/?]|$)/.test(hash)) route(hash); });
  function setOn(on) {
    M.on = on;
    root.hidden = !on;
    host.classList.toggle('nw-m-on', on);
    if (!on) {
      M.seq++; M.shown = null; page.replaceChildren();
      if (/^#news\b/.test(location.hash)) { setActionBar(null); setPhoneTitle(null); } // the action bar is a plain div off the phone
    }
  }
  return { renderList, route, setOn, get on() { return M.on; } };
}

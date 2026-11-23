// News view: clustered stories from research and news feeds, story detail, article reader,
// hybrid (semantic + keyword) search and watchlists. Contract: okf/architecture/web-client.md#news-view
import { registerView } from '../core/panels.js';
import { LS } from '../core/prefs.js';
import {
  api, esc, ago, toast, TYPE_FILTERS, emeta, entType, entName, isIoc, chip, storyChips, tierBadge, tierLabel, fmtDate,
  shortAgo, decode, markTerms, eicon, defang,
} from './news/common.js';
import { renderStory, renderArticle } from './news/detail.js';
import { tierWord, safeDecode as dec } from '../core/util.js';
import { seenLookup, seenChip } from '../core/chips.js';
import * as T from '../core/time.js';
import { openEntity } from '../core/entity-panel.js';
import { live } from '../core/live.js';
import * as stack from '../core/stack.js';
import { hashRange, withRange } from '../core/range.js';
import { viewHeader, headerRange, emptyState, errorState, stateAct } from '../core/view.js';
import { isPhone, onPhoneChange } from '../core/mobile.js';
import { phoneNews } from './news/phone.js';

const INITIAL_HASH = location.hash; // read before the shell rewrites it to '#news'
// The range is kept as the API's `since` ('24h', '7d', '30d', '' = all) and shown by the shared control (hours).
const SINCE = { 24: '24h', 168: '7d', 720: '30d', 0: '' };
const hoursOf = (since) => ({ '24h': 24, '7d': 168, '30d': 720 }[since] ?? 0);
// A saved range that is not one of the presets (an old '1h', junk) falls back to 24H; nothing saved yet means 7D.
const savedRange = (r) => (r == null ? '7d' : Object.values(SINCE).includes(r) ? r : '24h');
const isBase = (h) => /^#news(\?|$)/.test(h); // the list itself (not a story or article), where ?range= lives
const SORTS = [['last_seen', 'Latest'], ['size', 'Most covered']];
const PAGE = 60;
// The search box only promises meaning search once the local AI helper is known to be up (else it is keywords only).
const PH = { kw: 'Search stories by keyword…', sem: 'Search by meaning… e.g. “android tv boxes sold as proxies”' };

registerView({
  id: 'news',
  mount(el) {
    const saved = LS.get('nd.news', {});
    const urlR = isBase(INITIAL_HASH) ? hashRange(INITIAL_HASH) : null; // a link's ?range= wins over the saved one
    const S = {
      range: urlR && SINCE[urlR.h] != null ? SINCE[urlR.h] : savedRange(saved.range), sort: saved.sort || 'last_seen', feed: saved.feed || 'all',
      sources: new Set(saved.sources || []), tiers: new Set(saved.tiers || []), types: new Set(saved.types || []),
      entity: null, q: '', all: [], total: 0, shown: PAGE, newSince: null, firstVisit: false,
      watch: { entities: [], keywords: [] }, digestNew: null, digestRange: null, outlets: [], meta: null,
      sel: null, pane: 'digest', paneArg: null, search: null, searching: false, mountedAt: Date.now(),
    };
    const persist = () => LS.set('nd.news', { range: S.range, sort: S.sort, feed: S.feed, sources: [...S.sources], tiers: [...S.tiers], types: [...S.types] });
    let P = null; // the phone layout, made the first time a phone shows News

    el.innerHTML = `<div class="vh-frame">
      ${viewHeader({ title: 'News', cls: 'nw-vh', purpose: 'Security reporting, one story per event however many outlets cover it', range: { cls: 'nw-range' } })}
      <div class="vh-body">
      <div class="nw">
        <aside class="nw-rail">
          <div class="nw-rail-h"><span class="label">Views</span><button class="icon-btn nw-rail-x" title="Close"><svg class="i"><use href="#i-x"/></svg></button></div>
          <nav class="nw-feeds"></nav>
          <div class="nw-rail-sec">
            <div class="nw-rail-sh"><span class="label">Watchlist</span><button class="nw-link" data-act="digest">Digest</button></div>
            <div class="nw-watch"></div>
            <div class="nw-wadd">
              <input placeholder="Follow a product or word…" title="Follow a product you run, a threat group, malware, a CVE or any word" aria-label="Follow a product, group or word" autocomplete="off" spellcheck="false">
              <div class="nw-sugg" hidden></div>
            </div>
          </div>
          <div class="nw-rail-sec">
            <div class="nw-rail-sh"><span class="label">Trust tier</span></div>
            <div class="nw-tiers"></div>
          </div>
          <div class="nw-rail-sec">
            <div class="nw-rail-sh"><span class="label">Sources</span><button class="nw-link" data-act="src-clear" hidden>Clear</button></div>
            <div class="nw-srcs"></div>
          </div>
        </aside>
        <section class="nw-center">
          <header class="nw-head">
            <button class="nw-menu icon-btn" title="Views and filters"><svg viewBox="0 0 24 24" class="i"><path d="M4 7h16M4 12h16M4 17h10" stroke="currentColor" stroke-width="1.7"/></svg></button>
            <div class="nw-titles"><h2 class="nw-h1">All stories</h2><div class="nw-sub mono"></div></div>
            <div class="nw-fright">
              <div class="sb-range nw-seg nw-sort" title="Order">${SORTS.map(([v, l]) => `<button data-s="${v}">${l}</button>`).join('')}</div>
            </div>
            <div class="nw-sbox">
              <svg class="i"><use href="#i-search"/></svg>
              <input class="nw-q" placeholder="${PH.kw}" aria-label="Search stories" autocomplete="off" spellcheck="false">
              <span class="nw-mode" hidden></span>
              <kbd class="nw-kbd mono">/</kbd>
              <button class="nw-qx icon-btn" hidden title="Clear search"><svg class="i"><use href="#i-x"/></svg></button>
            </div>
          </header>
          <div class="nw-fbar">
            <div class="nw-types"></div>
            <div class="nw-active"></div>
          </div>
          <div class="nw-stream" tabindex="-1"></div>
        </section>
        <section class="nw-pane">
          <div class="nw-pane-bar">
            <button class="nw-back"><svg class="i" viewBox="0 0 24 24"><path d="m14 6-6 6 6 6" fill="none" stroke="currentColor" stroke-width="1.8"/></svg><span>Back</span></button>
            <span class="nw-crumb mono"></span>
            <button class="icon-btn nw-pane-x" title="Close (Esc)"><svg class="i"><use href="#i-x"/></svg></button>
          </div>
          <div class="nw-pane-body"></div>
        </section>
        <div class="nw-scrim"></div>
      </div></div></div>`;
    const root = el.querySelector('.nw');
    const $ = (s) => root.querySelector(s);
    const stream = $('.nw-stream'), paneBody = $('.nw-pane-body');
    const qInput = $('.nw-q');
    // News remembers its own range (nd.news); the list's URL carries it (#news?range=30d).
    const range = headerRange(el, { value: { h: hoursOf(S.range) }, label: 'News time range', onChange: (v) => setNewsRange(v.h) });
    const writeRange = () => { if (newsActive() && isBase(location.hash)) { const h = withRange('#news', { h: hoursOf(S.range) }); if (location.hash !== h) window.history.replaceState(window.history.state, '', h); } };
    function setNewsRange(h, write = true) {
      S.range = SINCE[h] ?? '';
      range.set({ h });
      persist(); reload(); loadDigest(); renderSub();
      if (write) writeRange();
    }

    // ---------------------------------------------------------------- data
    const setSearchMode = (semantic) => { qInput.placeholder = semantic ? PH.sem : PH.kw; };
    async function loadAi() {
      try { const a = await api.get('/api/settings/about'); setSearchMode(!!a?.ai?.up); } catch { /* keep the keyword wording */ }
    }
    async function loadMeta() {
      try {
        const m = await api.get('/api/news/sources');
        S.meta = m;
        S.outlets = (m.outlets || []).filter((o) => o.total > 0);
        S.metaFailed = false;
      } catch { S.meta = null; S.metaFailed = true; }
      renderRail(); renderSub();
      if (!S.q && stream.querySelector('.vs')) renderStream(); // the empty state's cause depends on the meta
    }

    async function loadMarker() {
      try {
        const m = await api.get('/api/news/marker');
        S.newSince = m.last_seen;
      } catch {}
      if (!S.newSince) { S.firstVisit = true; S.newSince = new Date(Date.now() - 864e5).toISOString(); }
    }

    async function loadWatch() {
      try { S.watch = await api.get('/api/news/watchlist'); S.watchFailed = false; } catch { S.watch = { entities: [], keywords: [], stack: [] }; S.watchFailed = true; }
      S.watch.stack ||= [];
      await loadDigest();
    }
    async function loadDigest() {
      const has = S.watch.entities.length || S.watch.keywords.length || S.watch.stack.length;
      if (!has) { S.digestNew = { stories: [] }; S.digestRange = { stories: [] }; }
      else {
        const [a, b] = await Promise.all([
          api.get('/api/news/watchlist/digest', { since: S.newSince, limit: 200 }).catch(() => ({ stories: [] })),
          api.get('/api/news/watchlist/digest', { since: S.range || '3650d', limit: 500 }).catch(() => ({ stories: [] })),
        ]);
        S.digestNew = a; S.digestRange = b;
      }
      renderRail();
      if (S.pane === 'digest') renderDigest();
      if (S.feed === 'watch') renderStream();
    }

    let loadSeq = 0;
    async function loadStories() {
      const seq = ++loadSeq;
      stream.classList.add('loading');
      try {
        const r = await api.get('/api/news/stories', {
          limit: 500, since: S.range || undefined, sources: [...S.sources], tiers: [...S.tiers],
          entity: S.entity?.id, order: S.sort, new_since: S.newSince,
        });
        if (seq !== loadSeq) return;
        S.all = r.stories.map((s) => ({ ...s, title: decode(s.title), summary: decode(s.summary) }));
        S.total = r.total;
        S.failed = false; S.loaded = true;
        S.shown = PAGE;
        renderStream(); renderRail(); renderSub();
      } catch (e) {
        if (seq !== loadSeq) return;
        S.failed = true;
        if (P?.on) P.renderList();
        stream.innerHTML = errorState({ retry: loadStories, title: "Couldn't load the news", why: 'The Night Desk server did not answer. Stories already collected are safe; try again in a moment.', err: e.message });
      } finally { stream.classList.remove('loading'); }
    }

    // ---------------------------------------------------------------- filtering
    const groupOf = (e) => emeta(entType(e)).group;
    const watchIds = () => new Set((S.digestRange?.stories || []).map((s) => s.id));
    const isNew = (s) => s.is_new || s.new_articles > 0;
    // o: the phone Filter sheet counts a draft ({ list, feed, types }) the same way
    function visible(o = {}) {
      let list = o.list || S.all;
      const feed = o.feed || S.feed, types = o.types || S.types;
      if (feed === 'new') list = list.filter(isNew);
      else if (feed === 'multi') list = list.filter((s) => s.source_count >= 2);
      else if (feed === 'watch') { const w = watchIds(); list = list.filter((s) => w.has(s.id)); }
      if (types.size) list = list.filter((s) => (s.top_entities || []).some((e) => types.has(groupOf(e))));
      return list;
    }

    // ---------------------------------------------------------------- rail
    function renderRail() {
      const nNew = S.all.filter(isNew).length, nMulti = S.all.filter((s) => s.source_count >= 2).length;
      const nWatch = (S.digestRange?.stories || []).filter((s) => S.all.some((x) => x.id === s.id)).length;
      const nWatchNew = (S.digestNew?.stories || []).length;
      const feeds = [
        ['all', 'All stories', S.all.length, '<path d="M4 6h16M4 12h16M4 18h16" stroke="currentColor" stroke-width="1.6"/>'],
        ['new', S.firstVisit ? 'New today' : 'New since last visit', nNew, '<circle cx="12" cy="12" r="4" fill="currentColor"/>'],
        ['multi', 'Multi-source', nMulti, '<path d="M5 8h10v10H5zM9 4h10v10" fill="none" stroke="currentColor" stroke-width="1.6"/>'],
        ['watch', 'Watchlist', nWatch, '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.6" fill="currentColor"/>'],
      ];
      $('.nw-feeds').innerHTML = feeds.map(([id, label, n, ic]) => `
        <button class="nw-feed ${S.feed === id ? 'on' : ''} ${id === 'new' && n ? 'hot' : ''}" data-feed="${id}">
          <svg class="i" viewBox="0 0 24 24">${ic}</svg><span>${label}</span>
          ${id === 'watch' && nWatchNew ? `<em class="nw-dotn" title="${nWatchNew} new since your last visit">${nWatchNew} new</em>` : ''}
          <b>${n || ''}</b></button>`).join('');

      const w = S.watch;
      const counts = {};
      for (const s of S.digestNew?.stories || []) for (const m of s.matched || []) counts[m] = (counts[m] || 0) + 1;
      const items = [
        ...w.entities.map((id) => ({ key: id, kind: 'entity', label: watchName(id), type: id.split(':')[0] })),
        ...(w.stack || []).map((x) => ({ key: `stack:${stack.stackLabel(x)}`, kind: 'stack', label: stack.stackLabel(x), type: 'vendor' })),
        ...w.keywords.map((k) => ({ key: `keyword:${k}`, kind: 'keyword', label: k, type: 'keyword' })),
      ];
      $('.nw-watch').innerHTML = items.length ? items.map((it) => `
        <div class="nw-witem ${S.entity?.id === it.key ? 'on' : ''}" data-wkey="${esc(it.key)}">
          <span class="nw-wic ${it.kind === 'keyword' ? 'e-kw' : emeta(it.type).cls}">${it.kind === 'keyword' ? '<b>“</b>' : eicon(it.type)}</span>
          <button class="nw-wl" data-wopen="${esc(it.key)}" title="${it.kind === 'keyword' ? 'Keyword' : it.kind === 'stack' ? 'Something you run' : esc(emeta(it.type).label)}: ${esc(it.label)}">${esc(it.label)}</button>
          ${counts[it.key] ? `<em class="nw-dotn">${counts[it.key]} new</em>` : ''}
          <button class="nw-wx" data-wrm="${esc(it.key)}" title="Unfollow"><svg class="i"><use href="#i-x"/></svg></button>
        </div>`).join('') : '<div class="nw-hint">Follow a product you run, an actor, malware, CVE or any keyword to get a digest of what is new. <a href="#settings/follow">What you follow ›</a></div>';

      const tiers = {};
      for (const o of S.outlets) tiers[o.tier || '?'] = (tiers[o.tier || '?'] || 0) + 1;
      $('.nw-tiers').innerHTML = ['A', 'B', 'C', 'D'].map((t) => `
        <button class="nw-tchip ${S.tiers.has(t) ? 'on' : ''}" data-tier="${t}" aria-pressed="${S.tiers.has(t)}" ${tiers[t] ? '' : 'disabled'} title="${tiers[t] ? `${tierLabel(t)} sources: ${tiers[t]} outlet${tiers[t] === 1 ? '' : 's'}` : `No ${tierLabel(t).toLowerCase()} outlets`}">${tierBadge(t)}<span class="nw-tn">${tiers[t] || 0}</span></button>`).join('');

      // Sources grouped under their trust tier in words, so each row keeps its width for the outlet's name.
      const order = ['A', 'B', 'C', 'D'];
      const groups = new Map();
      for (const o of S.outlets) {
        const t = order.includes(String(o.tier || '').toUpperCase()) ? String(o.tier).toUpperCase() : '?';
        if (!groups.has(t)) groups.set(t, []);
        groups.get(t).push(o);
      }
      const row = (o) => {
        const research = /talos|unit 42|microsoft threat|eset|elastic/i.test(o.source);
        const tip = `${o.source} · ${tierLabel(o.tier)} source${research ? ' · publishes its own research' : ''} · ${o.ok} article${o.ok === 1 ? '' : 's'}`;
        return `<label class="nw-src ${S.sources.has(o.source) ? 'on' : ''}" title="${esc(tip)}">
          <input type="checkbox" data-src="${esc(o.source)}" ${S.sources.has(o.source) ? 'checked' : ''}>
          <span class="nw-sn">${esc(o.source)}</span>${research ? '<i class="nw-role" title="Publishes its own primary research">lab</i>' : ''}
          <b>${o.ok}</b></label>`;
      };
      $('.nw-srcs').innerHTML = [...order, '?'].filter((t) => groups.has(t)).map((t) => `
        <div class="nw-sgrp" role="group" aria-label="${esc(tierLabel(t))} sources">
          <div class="nw-sgh t-${t}" aria-hidden="true">${esc(tierLabel(t))}</div>
          ${groups.get(t).map(row).join('')}
        </div>`).join('') || '<div class="nw-hint">No outlets yet.</div>';
      $('[data-act="src-clear"]').hidden = !S.sources.size;
    }

    // ---------------------------------------------------------------- header + filter bar
    function renderSub() {
      const m = S.meta;
      const arts = m ? m.outlets.reduce((a, o) => a + o.ok, 0) : null;
      const titles = { all: 'All stories', new: S.firstVisit ? 'New today' : 'New since your last visit', multi: 'Multi-source stories', watch: 'Watchlist' };
      $('.nw-h1').textContent = S.q ? 'Search' : S.entity ? S.entity.name : titles[S.feed];
      const off = m?.offline;
      const ai = m?.pipeline;
      $('.nw-sub').innerHTML = S.q
        ? `${S.search ? `${S.search.results.length} articles` : 'Searching…'} · ${esc(rangeLabel())}`
        // each part is one unbreakable span, so the wrapping line breaks only between parts (app.css .nw-si)
        : [(() => { const v = visible().length; return v !== S.total ? `${v} of ${S.total} stories` : `${S.total} stories`; })(), arts != null ? `${arts} articles` : '',
          `${S.outlets.length} outlets`, esc(rangeLabel()), off ? '<span class="nw-off" title="Offline mode is on (the OSINTHUB_OFFLINE=1 setting): no fetching, everything else works">offline</span>' : '']
          .filter(Boolean).map((x) => `<span class="nw-si">${x}</span>`).join(' · ');
      void ai;
    }
    const rangeLabel = () => ({ '24h': '24 h', '7d': '7 days', '30d': '30 days', '': 'all time' }[S.range]);

    function renderFbar() {
      range.set({ h: hoursOf(S.range) });
      root.querySelectorAll('.nw-sort button').forEach((b) => b.classList.toggle('active', b.dataset.s === S.sort));
      $('.nw-sort').hidden = !!S.q;
      $('.nw-types').innerHTML = S.q ? '' : `<span class="label nw-fl">Has</span>${TYPE_FILTERS.map(([g, l]) => `<button class="nw-tf ${S.types.has(g) ? 'on' : ''} ${g === 'ioc' ? 'e-ioc' : emeta(g).cls}" data-type="${g}">${eicon(g === 'ioc' ? 'ip' : g)}${l}</button>`).join('')}`;
      const act = [];
      if (S.entity) act.push(`<button class="nw-af" data-clear="entity">${eicon(S.entity.type)}${esc(S.entity.name)}<svg class="i"><use href="#i-x"/></svg></button>`);
      for (const s of S.sources) act.push(`<button class="nw-af" data-clear-src="${esc(s)}">${esc(s)}<svg class="i"><use href="#i-x"/></svg></button>`);
      for (const t of S.tiers) act.push(`<button class="nw-af" data-clear-tier="${t}" title="Trust tier ${t}">${esc(tierLabel(t))} sources<svg class="i"><use href="#i-x"/></svg></button>`);
      $('.nw-active').innerHTML = act.join('');
    }

    // ---------------------------------------------------------------- stream
    function dayLabel(t) {
      const n = T.dayDiff(t);
      if (n === 0) return 'Today';
      if (n === 1) return 'Yesterday';
      return T.longDate(t);
    }

    // "Seen on your network" on the card: the story's addresses, domains, CVEs and hashes go through the shared
    // batched lookup (core/chips.js seenLookup, one request for the whole page); a card shows its strongest hit
    // (an open incident first, then the most recent) in the compact form, and nothing when none was seen.
    const SEEN_TYPES = new Set(['ip', 'domain', 'cve', 'hash', 'url', 'prefix']);
    function seenStorySlot(s) {
      const vals = [...new Set((s.top_entities || []).filter((e) => SEEN_TYPES.has(e.type)).map((e) => e.name).filter(Boolean))].slice(0, 16);
      return vals.length ? `<div class="finishb-nseen" data-seen-story="${esc(vals.join('\n'))}" hidden></div>` : '';
    }
    async function fillStorySeen(root) {
      const slots = [...root.querySelectorAll('[data-seen-story]:not([data-seen-done])')];
      if (!slots.length) return;
      slots.forEach((x) => (x.dataset.seenDone = '1'));
      const lists = slots.map((x) => x.dataset.seenStory.split('\n').filter(Boolean));
      let m;
      try { m = await seenLookup(lists.flat()); } catch { return; }
      slots.forEach((x, i) => {
        const hits = lists[i].map((v) => [v, m.get(v)]).filter(([, it]) => it?.seen);
        if (!hits.length) return;
        hits.sort(([, a], [, b]) => (b.incident ? 1 : 0) - (a.incident ? 1 : 0) || String(b.last || '').localeCompare(String(a.last || '')));
        const [v, it] = hits[0];
        x.innerHTML = `${seenChip(it, { compact: true })}<span class="finishb-nseen-v mono" title="${esc(hits.map(([n]) => n).join(', '))}">${esc(v)}${hits.length > 1 ? ` +${hits.length - 1}` : ''}</span>`;
        x.hidden = false;
      });
    }

    function card(s) {
      const fresh = isNew(s);
      const tiers = Object.entries(s.tier_counts || {}).sort();
      const srcs = s.sources || [];
      const lead = s.lead_source || srcs[0] || '';
      const others = srcs.filter((x) => x !== lead);
      const span = s.first_seen !== s.last_seen;
      const big = s.source_count >= 3 ? 'big' : s.source_count >= 2 ? 'mid' : '';
      return `
        <article class="nw-card ${fresh ? 'new' : ''} ${S.sel === s.id ? 'sel' : ''}" data-sid="${esc(s.id)}" tabindex="0">
          <div class="nw-cov ${big}" title="${esc(s.source_count)} distinct outlet${s.source_count === 1 ? '' : 's'}${s.article_count > s.source_count ? ` · ${s.article_count} articles` : ''}">
            <b>${s.source_count}</b><span>${s.source_count === 1 ? 'source' : 'sources'}</span>
            <div class="nw-tstack" data-term="trust-tier">${tiers.map(([t, n]) => `<i class="t-${esc(t)}" title="Tier ${esc(t)} (${esc(tierWord(t))}): ${n} outlet${n === 1 ? '' : 's'}">${esc(tierWord(t) || 'unrated')}</i>`).join('')}</div>
          </div>
          <div class="nw-cmain">
            <div class="nw-cmeta">
              ${fresh ? `<span class="nw-new" title="${s.is_new ? 'New story' : `${s.new_articles} new article${s.new_articles === 1 ? '' : 's'}`} since ${esc(fmtDate(S.newSince))}">${s.is_new ? 'NEW' : `+${s.new_articles} NEW`}</span>` : ''}
              <span class="nw-outlets"><b>${esc(lead)}</b>${others.length ? ` <span>+ ${others.length === 1 ? esc(others[0]) : `${others.length} more`}</span>` : ''}</span>
              <span class="nw-dotsep"></span>
              <span class="nw-when" title="First seen ${esc(fmtDate(s.first_seen))} · last seen ${esc(fmtDate(s.last_seen))}">${span ? `${shortAgo(s.first_seen)} → <b>${shortAgo(s.last_seen)}</b>` : `<b>${ago(s.last_seen)}</b>`}</span>
            </div>
            <h3 class="nw-ctitle">${esc(s.title)}</h3>
            ${s.summary ? `<p class="nw-csum">${s.summary_by === 'llm' ? '<span class="nw-ai" title="Summary written by the local LLM from all articles in the story">AI</span>' : ''}${esc(s.summary)}</p>` : ''}
            <div class="nw-cents">${storyChips(s.top_entities)}</div>
            ${seenStorySlot(s)}
          </div>
        </article>`;
    }

    function renderStream() {
      if (P?.on) { P.renderList(); return; }
      renderFbar();
      if (S.q) return renderSearch();
      const list = visible();
      if (!list.length) {
        const filtered = !!(S.types.size || S.sources.size || S.tiers.size || S.entity);
        const arts = S.meta ? (S.meta.outlets || []).reduce((a, o) => a + (o.ok || 0), 0) : null;
        // no filter set: say why there is nothing (offline, outlets not read yet, a quiet window) and what to do
        const cause = S.meta?.offline
          ? 'Offline mode is on, so news outlets are not being read. Restart Night Desk with offline mode turned off to fetch stories.'
          : arts === 0 ? 'News outlets are read every 20 minutes. On a new install the first stories appear a few minutes after start.'
          : `No stories in ${rangeLabel()}. Choose a wider time range at the top right.`;
        const why = S.feed === 'watch' && !(S.watch.entities.length || S.watch.keywords.length || S.watch.stack.length)
          ? 'Your watchlist is empty. Follow an entity from any chip, or add a keyword in the left rail.'
          : S.feed === 'new' ? `Nothing new since ${fmtDate(S.newSince)}. Widen the time range or switch to All stories.`
          : filtered ? 'No stories match these filters.' : cause;
        const title = filtered || S.feed === 'watch' || S.feed === 'new' || arts !== 0 ? 'No stories' : 'No stories yet';
        const act = filtered ? stateAct('Clear filters', { data: { act: 'reset' } })
          : S.feed === 'all' && (S.meta?.offline || arts === 0) ? stateAct('See progress in Settings › Sources', { href: '#settings/sources' }) : '';
        stream.innerHTML = emptyState({ title, why: esc(why), act });
        return;
      }
      const page = list.slice(0, S.shown);
      let html = '', last = '';
      const nNew = list.filter(isNew).length;
      if (nNew && S.feed !== 'new') html += `<div class="nw-newbar"><span><b>${nNew}</b> ${nNew === 1 ? 'story is' : 'stories are'} new since ${S.firstVisit ? 'yesterday' : `your last visit · ${esc(fmtDate(S.newSince))}`}</span><button class="nw-link" data-act="markread" title="The same as Caught up on Watch: News, Watch and the KEV list count new from now">Mark all as read</button></div>`;
      for (const s of page) {
        if (S.sort === 'last_seen') {
          const d = dayLabel(s.last_seen);
          if (d !== last) { html += `<div class="nw-day">${esc(d)}</div>`; last = d; }
        }
        html += card(s);
      }
      if (list.length > S.shown) html += `<button class="nw-moreb" data-act="more">Show ${Math.min(PAGE, list.length - S.shown)} more of ${list.length - S.shown}</button>`;
      else html += `<div class="nw-end mono">${list.length} ${list.length === 1 ? 'story' : 'stories'} · end of ${esc(rangeLabel())}</div>`;
      stream.innerHTML = html;
      fillStorySeen(stream);
    }

    // ---------------------------------------------------------------- search
    let searchSeq = 0;
    async function runSearch() {
      const q = S.q;
      const seq = ++searchSeq;
      S.search = null; S.searching = true; renderStream(); renderSub();
      try {
        const r = await api.get('/api/news/search', { q, k: 40, since: S.range || undefined, sources: [...S.sources], tiers: [...S.tiers] });
        if (seq !== searchSeq) return;
        S.search = r;
      } catch (e) {
        if (seq !== searchSeq) return;
        S.search = { mode: 'error', results: [], error: e.message };
      }
      S.searching = false;
      const mode = $('.nw-mode');
      mode.hidden = !S.search || S.search.mode === 'error';
      if (S.search) {
        const kw = S.search.mode === 'keyword';
        setSearchMode(!kw);
        mode.className = `nw-mode ${kw ? 'kw' : 'sem'}`;
        mode.textContent = kw ? 'KEYWORD MODE' : 'SEMANTIC';
        mode.title = kw ? 'The local AI helper is unavailable, so results are ranked by keywords (BM25) only.' : 'Hybrid ranking: local embeddings + keyword (BM25)';
      }
      renderStream(); renderSub();
    }

    function renderSearch() {
      if (S.searching || !S.search) { stream.innerHTML = `<div class="nw-skel">${'<div></div>'.repeat(5)}</div>`; return; }
      const r = S.search;
      if (r.mode === 'error') { stream.innerHTML = errorState({ retry: () => runSearch(), title: "Couldn't search the news", why: 'Try other words in a moment; the stories below the search still work.', err: r.error }); return; }
      const kw = r.mode === 'keyword';
      const byStory = new Map();
      for (const x of r.results) if (x.story_id) byStory.set(x.story_id, (byStory.get(x.story_id) || 0) + 1);
      const storyOf = new Map(S.all.map((s) => [s.id, s]));
      const top = r.results[0]?.score || 1;
      let html = `<div class="nw-sinfo">
        <span>${r.results.length} articles for <b>“${esc(S.q)}”</b> · best passage shown · ${esc(rangeLabel())}${S.sources.size || S.tiers.size ? ' · filtered' : ''}</span>
        ${kw ? '<span class="nw-kwnote">AI helper offline: keyword ranking only. Paraphrases may miss.</span>' : '<span class="nw-kwnote ok">Meaning-based: local embeddings + keywords</span>'}
      </div>`;
      if (!r.results.length) html += emptyState({ title: 'No matching articles', why: 'Try other words, or widen the time range at the top right.' });
      // results stay per article, but further hits from an already-listed story nest under its first hit
      const groups = [];
      const gi = new Map();
      for (const x of r.results) {
        if (x.story_id && gi.has(x.story_id)) groups[gi.get(x.story_id)].sub.push(x);
        else { if (x.story_id) gi.set(x.story_id, groups.length); groups.push({ x, sub: [] }); }
      }
      const meta = (x) => `<div class="nw-cmeta"><b>${esc(x.source)}</b>${tierBadge(x.tier)}<span class="nw-dotsep"></span><span title="${esc(fmtDate(x.published))}">${ago(x.published)}</span>${Number.isInteger(+x.chunk) && +x.chunk >= 1 ? `<span class="nw-dotsep"></span><span title="The part of the article that matched best (passages count from 1)">passage ${+x.chunk + 1}</span>` : ''}${x.status && x.status !== 'ok' ? '<span class="nw-dotsep"></span><span title="Full text not fetched; matched on headline and the outlet&rsquo;s summary">headline only</span>' : ''}</div>`;
      for (const { x, sub } of groups) {
        const st = storyOf.get(x.story_id);
        const pct = Math.max(6, Math.round((x.score / top) * 100));
        html += `
          <div class="nw-rg">
          <article class="nw-res" data-aid="${esc(x.id)}" data-chunk="${x.chunk ?? ''}" tabindex="0">
            <div class="nw-rscore" title="Relevance ${esc(x.score)}"><i style="width:${pct}%"></i></div>
            ${meta(x)}
            <h3 class="nw-ctitle">${markTerms(decode(x.title), S.q)}</h3>
            <p class="nw-snip">${markTerms(decode(x.snippet || ''), S.q)}</p>
          </article>
          ${sub.length ? `<div class="nw-rsub"><div class="nw-rsubh mono">Same story · ${sub.length} more matching article${sub.length === 1 ? '' : 's'}${x.story_id ? ` · <button class="nw-instory" data-sid="${esc(x.story_id)}">open story${st ? ` (${st.source_count} sources)` : ''} ›</button>` : ''}</div>
            ${sub.map((y) => `<article class="nw-res sub" data-aid="${esc(y.id)}" data-chunk="${y.chunk ?? ''}" tabindex="0">${meta(y)}<div class="nw-subt">${markTerms(decode(y.title), S.q)}</div><p class="nw-snip">${markTerms(decode(y.snippet || ''), S.q)}</p></article>`).join('')}</div>`
            : st && st.source_count > 1 ? `<button class="nw-instory solo" data-sid="${esc(x.story_id)}">Part of a ${st.source_count}-source story ›</button>` : ''}
          </div>`;
      }
      stream.innerHTML = html;
    }

    // ---------------------------------------------------------------- pane (digest / story / article)
    // The pane follows browser history. `trail` lists the panes this one was opened from inside the pane (the
    // in-pane Back steps through it); `linked` says the browser entry before this one is the trail's last pane, so
    // the in-pane Back is simply the browser's Back. Both ride in history.state.nw with the pane's `why`, so Back,
    // Forward and reload restore them for the entry they land on, and the two Backs never drift apart.
    let trail = [], linked = false;
    const paneHash = (kind, arg) => (kind === 'story' ? `#news/story/${encodeURIComponent(arg)}` : kind === 'article' ? `#news/article/${encodeURIComponent(arg)}` : withRange('#news', { h: hoursOf(S.range) }));
    const newsActive = () => !!document.querySelector('#views .view[data-view="news"].active');
    const writeState = (h, push) => window.history[push ? 'pushState' : 'replaceState']({ nw: { why: S.paneWhy, trail, linked } }, '', h);
    // push: opened from the current pane, so the in-pane Back returns to it. nav: how the URL follows the pane:
    // 'push' (a user action) adds a history entry; 'replace' rewrites the current one; 'none' when the URL already
    // says this (a link, Back/Forward: only the pane's state is attached to that entry). from: a saved {trail, linked}.
    function openPane(kind, arg, { push = true, why = null, nav = 'push', from = null } = {}) {
      const h = paneHash(kind, arg);
      const active = newsActive();
      const pushes = nav === 'push' && active && location.hash !== h;
      if (from) { trail = Array.isArray(from.trail) ? from.trail : []; linked = !!from.linked && trail.length > 0; }
      else if (S.pane === kind && S.paneArg === arg) { /* the same pane again keeps its trail */ }
      else if (push && kind !== 'digest' && S.pane !== 'digest') { trail = [...trail, [S.pane, S.paneArg, S.paneWhy]].slice(-50); linked = pushes; }
      else { trail = []; linked = false; }
      S.pane = kind; S.paneArg = arg; S.paneWhy = why;
      if (kind === 'story') S.sel = arg;
      root.classList.toggle('pane-open', kind !== 'digest' || paneForced);
      root.classList.toggle('wide', kind !== 'digest');
      if (kind !== 'digest') root.classList.remove('dg-empty');
      root.querySelectorAll('.nw-card').forEach((c) => c.classList.toggle('sel', c.dataset.sid === S.sel));
      $('.nw-back').hidden = !trail.length;
      paneBody.scrollTop = 0;
      if (active && (pushes || nav === 'replace' || location.hash === h)) writeState(h, pushes);
      if (kind === 'digest') { $('.nw-crumb').textContent = 'WATCHLIST DIGEST'; renderDigest(); }
      else if (kind === 'story') { $('.nw-crumb').textContent = 'STORY'; renderStory(paneBody, arg, ctx); }
      else { $('.nw-crumb').textContent = 'ARTICLE'; renderArticle(paneBody, arg, ctx, why); }
    }
    let paneForced = false;
    function closePane(nav = 'push') {
      paneForced = false;
      root.classList.remove('wide');
      S.sel = null;
      openPane('digest', null, { push: false, nav });
      root.classList.remove('pane-open');
    }
    function back() {
      const prev = trail[trail.length - 1];
      if (!prev) return closePane();
      if (linked) return window.history.back(); // the hashchange handler below re-renders that entry
      // the entry before is something else (e.g. after a tab round-trip): step back in place, adding no entry
      openPane(prev[0], prev[1], { why: prev[2], nav: 'replace', from: { trail: trail.slice(0, -1), linked: false } });
    }

    function renderDigest() {
      const w = S.watch;
      const has = w.entities.length || w.keywords.length || (w.stack || []).length;
      root.classList.toggle('dg-empty', !has);
      const dn = S.digestNew?.stories || [];
      const dr = (S.digestRange?.stories || []).filter((s) => !dn.some((x) => x.id === s.id)).slice(0, 12);
      const row = (s, fresh) => `
        <button class="nw-drow ${fresh ? 'new' : ''}" data-sid="${esc(s.id)}">
          <span class="nw-dmeta mono">${fresh ? `<span class="nw-new">${s.is_new ? 'NEW' : `+${s.new_articles}`}</span>` : ''}${s.source_count} src · ${ago(s.last_seen)}</span>
          <span class="nw-dtitle">${esc(decode(s.title))}</span>
          <span class="nw-dmatch">${(s.matched || []).map((m) => m.startsWith('keyword:') ? `<i class="e-kw">“${esc(m.slice(8))}”</i>` : m.startsWith('stack:') ? `<i class="e-kw stack-dm">${esc(m.slice(6))}</i>` : `<i class="${emeta(m.split(':')[0]).cls}">${eicon(m.split(':')[0])}${esc(m.split(':').slice(1).join(':'))}</i>`).join('')}</span>
        </button>`;
      paneBody.innerHTML = `
        <div class="nw-dg">
          <div class="nw-dg-h">
            <div><h2>What’s new for you</h2>
            <div class="nw-dg-sub mono">since ${S.firstVisit ? 'yesterday (first visit)' : `your last visit · ${esc(fmtDate(S.newSince))}`}</div></div>
            ${has ? `<button class="src-btn" data-act="watchfeed">Open as a view</button>` : ''}
          </div>
          ${!has ? emptyState({ title: 'Nothing followed yet', why: 'Click any entity chip and choose <b>Follow</b>, or type a keyword under Watchlist in the rail.', size: 'sm' }) : `
            <div class="nw-dg-stats">
              <div><b>${dn.length}</b><span>stories with new articles</span></div>
              <div><b>${dn.reduce((a, s) => a + (s.new_articles || 0), 0)}</b><span>new articles</span></div>
              <div><b>${w.entities.length + w.keywords.length + (w.stack || []).length}</b><span>followed</span></div>
            </div>
            ${dn.length ? `<div class="nw-dg-list">${dn.map((s) => row(s, true)).join('')}</div>` : `<div class="nw-hint pad">Nothing new for your watchlist since ${esc(fmtDate(S.newSince))}.</div>`}
            ${dr.length ? `<div class="label nw-dg-l2">Earlier matches · ${esc(rangeLabel())}</div><div class="nw-dg-list">${dr.map((s) => row(s, false)).join('')}</div>` : ''}`}
          <div class="nw-dg-tip mono">j / k move · enter opens · esc closes · / searches</div>
        </div>`;
    }

    // ---------------------------------------------------------------- entity card
    // Display name of a followed entity: from the loaded stories or entities seen in this session, else fetched
    // once from /api/entities/<id> (the rail re-renders when it arrives); the id's slug only until then.
    const nameAsked = new Set();
    function watchName(id) {
      const e = findEntity(id);
      if (e.name && !e.guessed) return e.name;
      if (!nameAsked.has(id)) {
        nameAsked.add(id);
        api.get(`/api/entities/${encodeURIComponent(id)}`, { evidence: 0 })
          .then((d) => { if (d?.name) { ctx.known.set(id, { id, type: d.type || id.split(':')[0], name: d.name }); renderRail(); } })
          .catch(() => {});
      }
      return e.name || id;
    }
    function findEntity(id) {
      for (const s of S.all) for (const e of s.top_entities || []) if (e.id === id) return e;
      return ctx.known.get(id) || { id, type: id.split(':')[0], name: id.split(':').slice(1).join(':'), guessed: true };
    }
    function openEntityCard(anchor, id) {
      openEntity(id, {
        from: 'news',
        onArticle: (aid) => { paneForced = true; openPane('article', aid, { why: { entity: id } }); },
        actions: [   // Follow/Following is the drawer's own button (core/stack.js), shared with every view
          { label: 'Filter stories', close: true, onClick: (eid) => { const e = findEntity(eid); setEntityFilter(eid, entName(e), entType(e)); } },
        ],
      });
    }

    // ---------------------------------------------------------------- watchlist ops
    // follow/unfollow go through My stack (core/stack.js): an id merged into one already followed is not added
    // twice, and unfollowing either id of a merged pair removes the follow. 'nd:stack' then reloads the digest.
    const viaStack = (p) => p.then(() => true, (e) => { toast(`Not saved: ${e.message}`, true); return false; });
    const follow = (id) => viaStack(stack.follow({ entity: id }));
    const unfollow = (key) => viaStack(stack.unfollow({ key }));
    const onStack = () => { loadWatch(); };
    window.addEventListener('nd:stack', onStack);

    function setEntityFilter(id, name, type) {
      S.entity = id ? { id, name: name || id.split(':').slice(1).join(':'), type: type || id.split(':')[0] } : null;
      if (S.q) clearSearch(false);
      if (S.feed === 'watch' || S.feed === 'new') S.feed = 'all';
      loadStories(); renderSub();
      closeRail();
    }

    // ---------------------------------------------------------------- shared context for detail.js
    const ctx = {
      S, known: new Map(),
      openStory: (id, o) => openPane('story', id, o),
      setCrumb: (html) => { $('.nw-crumb').innerHTML = html; },
      openArticle: (id, why) => openPane('article', id, { why }),
      followed: (id) => stack.isFollowed(id),
      follow, unfollow, setEntityFilter,
      storyMeta: (id) => S.all.find((s) => s.id === id),
      watchMatch: (sid) => (S.digestRange?.stories || []).find((s) => s.id === sid)?.matched || [],
      watchNames: (sid) => (S.digestRange?.stories || []).find((s) => s.id === sid)?.matched_names || {},
    };

    // ---------------------------------------------------------------- events
    function closeRail() { root.classList.remove('rail-open'); }
    function clearSearch(reload = true) {
      S.q = ''; S.search = null; qInput.value = '';
      $('.nw-qx').hidden = true; $('.nw-mode').hidden = true;
      if (reload) { renderStream(); renderSub(); }
    }

    root.addEventListener('click', (e) => {
      const t = e.target;
      // entity chips / highlights anywhere
      const ent = t.closest('[data-eid]');
      if (ent) { e.preventDefault(); e.stopPropagation(); openEntityCard(ent, ent.dataset.eid); return; }
      const uf = t.closest('[data-unfold]');
      if (uf) { uf.previousElementSibling.hidden = false; uf.previousElementSibling.style.display = 'contents'; uf.remove(); return; }
      const agg = t.closest('[data-iocs]');
      if (agg) { const c = agg.closest('[data-sid]'); if (c) { paneForced = true; openPane('story', c.dataset.sid, { push: false }); setTimeout(() => paneBody.querySelector('.nw-iocs')?.scrollIntoView({ block: 'start' }), 350); } return; }
      const ins = t.closest('.nw-instory');
      if (ins) { paneForced = true; openPane('story', ins.dataset.sid, { push: false }); return; }
      const cardEl = t.closest('.nw-card');
      if (cardEl && !t.closest('a, [data-seen-hunt]')) { paneForced = true; openPane('story', cardEl.dataset.sid, { push: false }); return; }
      const res = t.closest('.nw-res');
      if (res) { paneForced = true; openPane('article', res.dataset.aid, { push: false, why: { search: S.q, chunk: res.dataset.chunk } }); return; }
      const dr = t.closest('.nw-drow');
      if (dr) { paneForced = true; openPane('story', dr.dataset.sid); return; }
      const feed = t.closest('[data-feed]');
      if (feed) { S.feed = feed.dataset.feed; S.shown = PAGE; if (S.q) clearSearch(false); persist(); renderRail(); renderStream(); renderSub(); stream.scrollTop = 0; closeRail(); return; }
      const wopen = t.closest('[data-wopen]');
      if (wopen) { const k = wopen.dataset.wopen; if (k.startsWith('keyword:') || k.startsWith('stack:')) { qInput.value = k.replace(/^(keyword|stack):/, ''); doSearch(); } else setEntityFilter(k); return; }
      const wrm = t.closest('[data-wrm]');
      if (wrm) { unfollow(wrm.dataset.wrm); return; }
      const tier = t.closest('[data-tier]');
      if (tier) { const v = tier.dataset.tier; S.tiers.has(v) ? S.tiers.delete(v) : S.tiers.add(v); persist(); reload(); renderRail(); return; }
      const ty = t.closest('[data-type]');
      if (ty) { const v = ty.dataset.type; S.types.has(v) ? S.types.delete(v) : S.types.add(v); S.shown = PAGE; persist(); renderStream(); renderSub(); return; }
      const ss = t.closest('[data-s]');
      if (ss) { S.sort = ss.dataset.s; persist(); loadStories(); return; }
      if (t.closest('[data-clear="entity"]')) { setEntityFilter(null); return; }
      const cs = t.closest('[data-clear-src]');
      if (cs) { S.sources.delete(cs.dataset.clearSrc); persist(); renderRail(); reload(); return; }
      const ct = t.closest('[data-clear-tier]');
      if (ct) { S.tiers.delete(ct.dataset.clearTier); persist(); renderRail(); reload(); return; }
      const act = t.closest('[data-act]')?.dataset.act;
      if (act === 'more') { S.shown += PAGE; renderStream(); }
      else if (act === 'reset') { S.types.clear(); S.sources.clear(); S.tiers.clear(); S.entity = null; persist(); renderRail(); loadStories(); }
      else if (act === 'close-pane') closePane();
      else if (act === 'markread') markRead();
      else if (act === 'digest') { paneForced = true; openPane('digest', null, { push: false }); root.classList.add('pane-open'); closeRail(); }
      else if (act === 'watchfeed') { S.feed = 'watch'; persist(); renderRail(); renderStream(); renderSub(); if (innerWidth < 1280) closePane(); }
      else if (act === 'src-clear') { S.sources.clear(); persist(); renderRail(); reload(); }
    });
    root.addEventListener('change', (e) => {
      const src = e.target.dataset?.src;
      if (src != null) { e.target.checked ? S.sources.add(src) : S.sources.delete(src); persist(); renderRail(); reload(); }
    });
    root.addEventListener('keydown', (e) => {
      if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('.nw-card, .nw-res')) { e.preventDefault(); e.target.click(); }
    });
    $('.nw-menu').onclick = () => root.classList.toggle('rail-open');
    $('.nw-rail-x').onclick = closeRail;
    $('.nw-scrim').onclick = () => { closeRail(); };
    $('.nw-pane-x').onclick = () => closePane();
    $('.nw-back').onclick = back;

    function reload() { if (S.q) runSearch(); else loadStories(); }

    async function markRead() {
      try {
        const r = await api.put('/api/news/marker', {});
        S.newSince = r.last_seen; S.firstVisit = false;
        toast('Marked all as read. Watch is caught up too.');
        loadStories(); loadDigest();
      } catch (e) { toast(e.message, true); }
    }
    // the one app-wide marker moved elsewhere ("Caught up" on Watch): count new from there
    live.on('marker', (m) => {
      if (!m?.last_seen || m.last_seen === S.newSince) return;
      S.newSince = m.last_seen; S.firstVisit = false;
      loadStories(); loadDigest();
    });

    // search box
    function doSearch() {
      const q = qInput.value.trim();
      $('.nw-qx').hidden = !q; $('.nw-kbd').hidden = !!q;
      if (!q) { clearSearch(); return; }
      S.q = q; runSearch();
    }
    let qt;
    qInput.addEventListener('input', () => { $('.nw-qx').hidden = !qInput.value; clearTimeout(qt); if (qInput.value.trim().length >= 3 || !qInput.value.trim()) qt = setTimeout(doSearch, 450); });
    qInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { clearTimeout(qt); doSearch(); } if (e.key === 'Escape') { clearSearch(); qInput.blur(); } });
    $('.nw-qx').onclick = () => { clearSearch(); qInput.focus(); };

    // watchlist add with entity suggestions
    const wIn = $('.nw-wadd input'), sugg = $('.nw-sugg');
    let sIdx = -1, sItems = [];
    const paintSugg = () => {
      sugg.hidden = !wIn.value.trim();
      sugg.innerHTML = sItems.map((x, i) => x.type === 'stack'
        ? `<button class="nw-sg ${i === sIdx ? 'on' : ''}" data-sg="${i}">${eicon('vendor')}<span>${esc(x.name)}</span><small>you run it${x.kev ? ` · ${x.kev} exploited` : ''}</small></button>`
        : `<button class="nw-sg ${i === sIdx ? 'on' : ''}" data-sg="${i}">${eicon(x.type)}<span>${esc(isIoc(x.type) ? defang(x.name, x.type) : x.name)}</span><small>${esc(emeta(x.type).label)} · ${x.mentions}</small></button>`).join('')
        + `<button class="nw-sg kw ${sIdx === sItems.length ? 'on' : ''}" data-sg="kw"><b>“</b><span>Follow keyword “${esc(wIn.value.trim())}”</span></button>`;
    };
    wIn.addEventListener('input', async () => {
      const q = wIn.value.trim(); sIdx = -1; sItems = []; paintSugg();
      if (q.length < 2) return;
      try {
        const [r, st] = await Promise.all([api.get('/api/entities', { q, limit: 7 }).catch(() => ({ items: [] })),
          api.get('/api/stack/suggest', { q, limit: 3 }).catch(() => ({ items: [] }))]);
        if (wIn.value.trim() !== q) return;
        sItems = [...(st.items || []).map((x) => ({ type: 'stack', id: `stack:${x.label}`, name: x.label, vendor: x.vendor, product: x.product, kev: x.kev })),
          ...(r.items || []).filter((x) => !['country', 'sector', 'asn', 'prefix', 'vendor', 'product'].includes(x.type)).slice(0, 5)];
        paintSugg();
      } catch {}
    });
    const pickSugg = (i) => {
      const q = wIn.value.trim();
      if (i === 'kw' || i === sItems.length || i < 0) { if (q) viaStack(stack.follow({ keyword: q })).then((ok) => ok && toast(`Following keyword “${q}”`)); }
      else if (sItems[i]?.type === 'stack') { const x = sItems[i]; viaStack(stack.follow({ vendor: x.vendor, product: x.product })).then((ok) => ok && toast(`Following ${x.name}`)); }
      else { const x = sItems[i]; ctx.known.set(x.id, x); follow(x.id).then((ok) => ok && toast(`Following ${x.name}`)); }
      wIn.value = ''; sItems = []; sugg.hidden = true;
    };
    wIn.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') { sIdx = Math.min(sItems.length, sIdx + 1); paintSugg(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { sIdx = Math.max(-1, sIdx - 1); paintSugg(); e.preventDefault(); }
      else if (e.key === 'Enter') { pickSugg(sIdx); }
      else if (e.key === 'Escape') { sugg.hidden = true; }
    });
    sugg.addEventListener('mousedown', (e) => { const b = e.target.closest('[data-sg]'); if (b) { e.preventDefault(); pickSugg(b.dataset.sg === 'kw' ? 'kw' : +b.dataset.sg); } });
    wIn.addEventListener('blur', () => setTimeout(() => { sugg.hidden = true; }, 150));

    // keyboard: j/k navigation, / search, esc
    function onKey(e) {
      if (isPhone()) return; // no single-key shortcuts on a phone
      if (!document.querySelector('#views .view[data-view="news"].active')) return;
      if (e.target.matches('input, textarea')) return;
      if (document.querySelector('.tour-root')) return; // the guided tour owns the keyboard (its Esc ends it)
      // one Esc closes one layer: an open event drawer sits above the story, so leave this Esc to the shell
      if (e.key === 'Escape' && document.getElementById('drawer')?.classList.contains('open')) return;
      if (e.key === 'Escape') { if (root.classList.contains('rail-open')) closeRail(); else if (S.pane !== 'digest') closePane(); return; }
      if (e.key === '/') { e.preventDefault(); e.stopImmediatePropagation(); qInput.focus(); qInput.select(); return; }
      if (e.key === 'j' || e.key === 'k') {
        const cards = [...stream.querySelectorAll('.nw-card, .nw-res')];
        if (!cards.length) return;
        let i = cards.findIndex((c) => c.classList.contains('sel') || c === document.activeElement);
        i = e.key === 'j' ? Math.min(cards.length - 1, i + 1) : Math.max(0, i - 1);
        cards[i].focus(); cards[i].scrollIntoView({ block: 'nearest' });
        if (innerWidth >= 1280) cards[i].click();
      }
    }
    document.addEventListener('keydown', onKey, true);

    // ---------------------------------------------------------------- boot
    renderFbar();
    stream.innerHTML = `<div class="nw-skel">${'<div></div>'.repeat(6)}</div>`;
    (async () => {
      await loadMarker();
      await Promise.all([loadMeta(), loadStories(), loadWatch(), loadAi()]);
      if (P?.on) { if (newsActive() && isBase(location.hash)) writeRange(); return; }
      const cur = location.hash.match(/^#news\/(story|article)\/(.+)$/);
      const m = cur || INITIAL_HASH.match(/^#news\/(story|article)\/(.+)$/);
      const st = (cur && window.history.state?.nw) || {}; // a reload keeps the entry's trail and why
      if (m) { paneForced = true; openPane(m[1], dec(m[2]), { push: false, nav: 'replace', why: st.why ?? null, from: st }); }
      else openPane('digest', null, { push: false, nav: 'replace' });
    })();

    // Links (the shell's global search opens articles with #news/article/<id>) and Back/Forward between panes: the
    // entry landed on carries its own trail and why (none for a fresh link).
    window.addEventListener('hashchange', () => {
      if (P?.on) { if (/^#news(?:[/?]|$)/.test(location.hash)) P.route(location.hash); return; }
      const m = location.hash.match(/^#news\/(story|article)\/(.+)$/);
      const st = window.history.state?.nw || {};
      if (m) { paneForced = true; openPane(m[1], dec(m[2]), { push: false, nav: 'none', why: st.why ?? null, from: st }); }
      else if (isBase(location.hash)) { // Back from a story, or a link to the list with ?range=
        const r = hashRange(location.hash);
        if (r && SINCE[r.h] != null && SINCE[r.h] !== S.range) setNewsRange(r.h, false);
        if (S.pane !== 'digest') closePane('none'); else if (newsActive()) writeRange();
      }
    });
    // Showing the view again (a tab click) leaves a bare '#news' that the shell writes after show(): put the open
    // pane's URL back once it has, so reload and Back/Forward keep the story. The entry before is now another view.
    const restoreHash = () => setTimeout(() => {
      if (P?.on) return; // a phone shows what the URL says (a story is its own page)
      if (!newsActive() || !isBase(location.hash)) return;
      if (S.pane === 'digest') { const r = hashRange(location.hash); if (r && SINCE[r.h] != null && SINCE[r.h] !== S.range) setNewsRange(r.h, false); writeRange(); return; }
      linked = false;
      writeState(paneHash(S.pane, S.paneArg), false);
    }, 0);
    const refresh = () => { loadMeta(); loadStories(); loadWatch(); loadAi(); };
    // A load that failed (the server was restarting) is tried again when the live connection comes back, and on show().
    const recover = () => { if (S.failed || S.metaFailed || S.watchFailed) refresh(); };
    live.on('status', (up) => { if (up) recover(); });

    // ---------------------------------------------------------------- the phone layout (views/news/phone.js)
    const D = {
      S, visible, isNew, hoursOf, rangeLabel, PAGE, ctx, watchName, reload,
      setRange: (h) => setNewsRange(h),
      setView(v) {
        const sort = v === 'covered' ? 'size' : v === 'latest' ? 'last_seen' : S.sort;
        const list = v === 'following' ? 'watch' : S.feed === 'watch' ? 'all' : S.feed;
        const resort = sort !== S.sort;
        S.sort = sort; S.feed = list; S.shown = PAGE;
        if (S.q) clearSearch(false);
        persist(); renderRail(); renderSub();
        if (resort) loadStories(); else renderStream();
      },
      preview: (d) => api.get('/api/news/stories', {
        limit: 500, since: S.range || undefined, sources: [...d.sources], tiers: [...d.tiers], entity: d.entity?.id, order: S.sort, new_since: S.newSince,
      }).then((r) => {
        // the list loads at most 500 stories; `total` is how many the server has for these filters
        const rows = r.stories.map((x) => ({ ...x, title: decode(x.title), summary: decode(x.summary) }));
        rows.total = r.total ?? rows.length;
        return rows;
      }),
      apply(d, rows) {
        S.feed = d.feed === 'all' && S.feed === 'watch' ? 'watch' : d.feed;
        S.types = new Set(d.types); S.tiers = new Set(d.tiers); S.sources = new Set(d.sources); S.entity = d.entity || null;
        S.shown = PAGE;
        persist(); renderRail();
        if (S.q) runSearch();
        else if (rows) { S.all = rows; S.total = rows.total ?? rows.length; S.failed = false; S.loaded = true; renderStream(); renderSub(); }
        else loadStories();
      },
      search: (q) => { S.q = q; runSearch(); },
      clearSearch: () => clearSearch(),
    };
    // a computer showing News after a phone layout: the pane follows the URL again
    function deskRoute() {
      renderStream(); renderSub();
      const m = location.hash.match(/^#news\/(story|article)\/(.+)$/);
      if (m) { paneForced = true; openPane(m[1], dec(m[2]), { push: false, nav: 'none' }); }
      else if (S.pane !== 'digest') closePane('none');
    }
    const phoneOn = (on) => {
      if (on && !P) P = phoneNews(el, D);
      if (!P) return;
      P.setOn(on);
      if (on) { P.renderList(); if (newsActive() || /^#news(?:[/?]|$)/.test(location.hash)) P.route(location.hash); }
      else deskRoute();
    };
    onPhoneChange(phoneOn);
    if (isPhone()) phoneOn(true);
    inst = { S, restoreHash, refresh, recover, route: () => { if (P?.on && /^#news(?:[/?]|$)/.test(location.hash)) P.route(location.hash); } };
  },
  show() {
    if (inst && Date.now() - inst.S.mountedAt > 5 * 60e3) { inst.S.mountedAt = Date.now(); inst.refresh(); }
    else inst?.recover();
    inst?.restoreHash();
    inst?.route();
  },
  hide() {},
});
let inst = null;

// Entities view: directory, entity page and graph over /api/entities.
// Routes: #entities, #entities/<id>, #entities/graph/<id>, #entities/review (also #/entities/<id> from older links).
// The campaign metro map is hidden (it drew co-mention noise as shared infrastructure): its code stays and is
// reachable only at #entities/metro?lab=1; a plain #entities/metro opens the directory.
// One search or filter box per screen: the app's global search (and its "/" key) finds entities; the directory
// has its filter, the graph its "Add or re-root" box and the entity page its indicator filter.
// Contract: okf/architecture/web-client.md#entities-view
import { registerView } from '../core/panels.js';
import { closeEntity } from '../core/entity-panel.js';
import {
  api, esc, TYPES, GROUPS, tmeta, tcolor, icon, chip, shown, sparkSvg, bandPill, fmtAgo, LS, typeOf, placeholder, ORIGINS,
} from './entities/common.js';
import { renderPage } from './entities/page.js';
import { showReview } from './entities/intelx.js';
import { hashRange, withRange, stripRange, phrase } from '../core/range.js';
import { safeDecode as dec } from '../core/util.js';
import { viewHeader, headerRange, emptyState, errorState, loadingState, stateAct } from '../core/view.js';
import * as T from '../core/time.js';
import { live } from '../core/live.js';
import { isPhone, onPhoneChange } from '../core/mobile.js';
import { setPhoneTitle } from '../core/page.js';
import { actionSheet } from '../core/sheet.js';
// heading for a one-type list: "IP addresses", "Malware", "Threat actors"
function plural(w) {
  const m = /^(.*?)( \(.*\))?$/.exec(w); const [head, tail = ''] = [m[1], m[2]];
  const p = /malware$/i.test(head) ? head : /[^aeiou]y$/i.test(head) ? `${head.slice(0, -1)}ies` : /(s|sh|ch|x)$/i.test(head) ? `${head}es` : `${head}s`;
  return p + tail;   // "IP addresses", "Countries", "Network owners (ASN)", "Malware"
}

// '#/entities/<id>' (the shared panel's link form) would boot the Ops view; normalise it before the shell reads the hash.
if (/^#\/entities/.test(location.hash)) history.replaceState(null, '', '#' + location.hash.slice(2));
const INITIAL_HASH = location.hash;

let R = null; // view instance

function parseRoute(hash) {
  const range = hashRange(hash || ''); // the directory's ?range=24h|7d|30d|all (other routes ignore it)
  const h = stripRange(hash || '').replace(/^#\/?/, '');
  if (!/^entities([/?]|$)/.test(h)) return null;
  const rest = h.slice('entities'.length).replace(/^\//, '');
  if (!rest || rest[0] === '?') return range ? { tab: 'directory', range } : { tab: 'directory' };
  if (rest.startsWith('type/')) return { tab: 'directory', type: dec(rest.slice(5)), ...(range ? { range } : {}) };
  if (/^metro(?:[/?]|$)/.test(rest)) return /[?&]lab=1(?:&|$)/.test(rest) ? { tab: 'metro' } : { tab: 'directory' };
  if (rest === 'graph' || rest.startsWith('graph/')) return { tab: 'graph', id: dec(rest.slice(6)) || null };
  if (rest === 'review') return { tab: 'review' };
  return { tab: 'page', id: dec(rest) };
}
const enc = (id) => encodeURIComponent(id).replace(/%3A/gi, ':');
// The directory's URL carries its time range (#entities?range=7d); dirRange is the open view's.
let dirRange = null;
export const routeHash = (r) => (r.tab === 'page' ? `#entities/${enc(r.id)}`
  : r.tab === 'graph' ? `#entities/graph${r.id ? '/' + enc(r.id) : ''}`
    : r.tab === 'metro' ? '#entities/metro?lab=1' : r.tab === 'review' ? '#entities/review' : withRange('#entities', r.range || dirRange));

// App-wide navigation: any link or hash change to #entities/... opens this view at that route.
let pending = null;
window.addEventListener('hashchange', () => {
  const r = parseRoute(location.hash);
  if (!r) return;
  closeEntity();
  const want = routeHash(r);
  // Rewrite the entry the link added to the canonical form first: the shell's tab switch then sees an '#entities…'
  // hash and adds no entry of its own, so one Back returns to where the link was clicked (also for '#/entities/…').
  if (location.hash !== want) history.replaceState(null, '', want);
  if (!document.body.classList.contains('en-active')) {
    pending = r;
    document.querySelector('.views button[data-view="entities"]')?.click();
  } else R?.go(r, false);
});

registerView({
  id: 'entities',
  mount(el) { R = mountView(el, pending || parseRoute(INITIAL_HASH) || { tab: 'directory' }); pending = null; },
  show() {
    document.body.classList.add('en-active');
    if (pending && R) { R.go(pending, false); pending = null; }
    R?.show();
  },
  hide() { document.body.classList.remove('en-active'); R?.hide(); },
});

function mountView(el, initial) {
  const saved = LS.get('nd.entities', {});
  const S = {
    route: initial, group: saved.group || 'Threats', types: saved.types || null, sort: saved.sort || 'mentions',
    q: '', offset: 0, items: [], total: 0, counts: {}, activity: {}, sem: null, loading: false, showHidden: false, hidden: {}, scanned: false,
    rangeH: initial.range?.h ?? saved.range ?? 0, // the directory lists entities seen in this window (0 = all, reference data too)
  };
  const persist = () => LS.set('nd.entities', { group: S.group, types: S.types, sort: S.sort, range: S.rangeH });
  if (initial.range) { initial = { ...initial }; delete initial.range; S.route = initial; }
  dirRange = { h: S.rangeH };
  el.innerHTML = `
    <div class="en">
      ${viewHeader({
        title: 'Intel', cls: 'en-top', purpose: 'Actors, malware, bugs and indicators, and the claims that tie them together',
        tabs: `<button data-tab="directory" role="tab">Directory</button>
          <button data-tab="graph" role="tab">Graph</button>
          <button data-tab="review" role="tab" title="Likely duplicates, contested attributions and claims you disagreed with">Review</button>
          <button data-tab="metro" role="tab" class="en-tab-lab" hidden>Campaign map (lab)</button>
          <button data-tab="page" role="tab" class="en-tab-page" hidden></button>`,
        tabsCls: 'en-tabs', tabsLabel: 'Intel sections', range: { cls: 'en-range' },
      })}
      <div class="en-body">
        <section class="en-pane" data-pane="directory"></section>
        <section class="en-pane" data-pane="page"></section>
        <section class="en-pane" data-pane="graph"></section>
        <section class="en-pane" data-pane="metro"></section>
        <section class="en-pane" data-pane="review"></section>
      </div>
    </div>`;
  const $ = (s) => el.querySelector(s);
  // Intel remembers its own range (nd.entities); the directory's URL carries it.
  const range = headerRange(el, { value: { h: S.rangeH }, label: 'Intel time range', onChange: (v) => setDirRange(v.h) });
  S.rangeH = range.get().h; dirRange = { h: S.rangeH };
  function setDirRange(h, write = true) {
    if (h === S.rangeH) return;
    S.rangeH = h; dirRange = { h }; S.scanned = false; S.hidden = {};
    range.set({ h }); persist();
    if (write && document.body.classList.contains('en-active') && S.route.tab === 'directory') history.replaceState(history.state, '', routeHash(S.route));
    loadList(true);
  }
  let graphMod = null, metroMod = null;

  // ---------------------------------------------------------------- routing
  el.querySelector('.en-tabs').onclick = (e) => {
    const b = e.target.closest('[data-tab]');
    if (!b) return;
    const t = b.dataset.tab;
    if (t === 'page') return go({ tab: 'page', id: S.lastPage });
    go(t === 'graph' ? { tab: 'graph', id: S.graphRoot || S.lastPage || null } : { tab: t });
  };
  function go(r, push = true) {
    if (r.tab === 'page' && !r.id) r = { tab: 'directory' };
    if (r.range) { const { range: rr, ...rest } = r; r = rest; if (rr.h != null) setDirRange(rr.h, false); }
    S.route = r;
    if (r.type) { const g = TYPES[r.type]?.[2]; if (g) { S.group = g; S.types = [r.type]; } }
    const h = routeHash(r);
    if (location.hash !== h) (push ? history.pushState : history.replaceState).call(history, null, '', h);
    render();
  }
  window.addEventListener('popstate', () => { const r = parseRoute(location.hash); if (r && document.body.classList.contains('en-active')) go(r, false); });

  function render() {
    const r = S.route;
    el.querySelectorAll('.en-tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === r.tab));
    $('.en-range').hidden = r.tab !== 'directory'; // the range filters the directory only
    $('.en-tab-lab').hidden = r.tab !== 'metro';
    el.querySelectorAll('.en-pane').forEach((p) => p.classList.toggle('active', p.dataset.pane === r.tab));
    // phone: an entity is a pushed page (‹ Intel, no sub-nav, no tab bar); the other tabs are Intel's root pages
    $('.en').classList.toggle('en-m-onpage', r.tab === 'page');
    if (isPhone() && r.tab === 'page') setPhoneTitle(shown(S.lastPageName || String(r.id).split(':').slice(1).join(':') || r.id, typeOf(r.id)), { back: { label: 'Intel', href: '#entities' } });
    const pt = $('.en-tab-page');
    if (r.tab === 'page') { if (S.lastPage !== r.id) S.lastPageName = null; S.lastPage = r.id; } // a new page must not keep the old name
    if (S.lastPage) { pt.hidden = false; pt.innerHTML = `${icon(typeOf(S.lastPage))}<span>${esc(shown(S.lastPageName || S.lastPage.split(':').slice(1).join(':'), typeOf(S.lastPage)))}</span>`; }
    if (r.tab === 'directory') showDirectory();
    else if (r.tab === 'page') {
      const pane = $('[data-pane="page"]');
      pane.scrollTop = 0;
      renderPage(pane, r.id, {
        go, onName: (n) => { S.lastPageName = n; if (isPhone() && S.route.tab === 'page') setPhoneTitle(shown(n, typeOf(r.id)), { back: { label: 'Intel', href: '#entities' } }); pt.querySelector('span') && (pt.querySelector('span').textContent = shown(n, typeOf(r.id))); },
      });
    } else if (r.tab === 'graph') {
      S.graphRoot = r.id || S.graphRoot;
      (graphMod ||= import('./entities/graph.js')).then((m) => m.showGraph($('[data-pane="graph"]'), S.graphRoot, { go, setRoot: (id) => { S.graphRoot = id; history.replaceState(null, '', routeHash({ tab: 'graph', id })); } }))
        .catch((e) => { $('[data-pane="graph"]').innerHTML = errorState({ retry: () => location.reload(), retryLabel: 'Reload the page', title: "Couldn't open the graph", why: 'Part of the page did not load. Reload to try again.', err: e.message }); });
    } else if (r.tab === 'review') {
      showReview($('[data-pane="review"]'));
    } else if (r.tab === 'metro') {
      (metroMod ||= import('./entities/metro.js')).then((m) => m.showMetro($('[data-pane="metro"]'), { go }))
        .catch((e) => { $('[data-pane="metro"]').innerHTML = errorState({ retry: () => location.reload(), retryLabel: 'Reload the page', title: "Couldn't open the campaign map", why: 'Part of the page did not load. Reload to try again.', err: e.message }); });
    }
  }

  // ---------------------------------------------------------------- directory
  const dir = $('[data-pane="directory"]');
  dir.innerHTML = `
    <aside class="en-rail">
      <div class="en-rail-h"><span class="label">Entity types</span><span class="mono en-total"></span></div>
      <nav class="en-types"></nav>
    </aside>
    <div class="en-dir">
      <div class="en-dir-h">
        <div><h2 class="en-h1"></h2><div class="en-sub mono"></div></div>
        <div class="en-dir-tools">
          <div class="en-filter"><svg class="i"><use href="#i-search"/></svg><input placeholder="Filter by name, alias or value" spellcheck="false" aria-label="Filter this list"><button class="icon-btn en-fx" hidden title="Clear filter"><svg class="i"><use href="#i-x"/></svg></button></div>
          <button type="button" class="en-m-range" hidden aria-haspopup="menu"></button>
          <label class="en-sortl"><span class="label">Sort</span><select class="en-sort">
            <option value="mentions">Most mentioned</option><option value="last_seen">Last seen</option><option value="claims">Most claims</option><option value="name">Name</option></select></label>
        </div>
      </div>
      <div class="en-tchips"></div>
      <div class="en-sem" hidden></div>
      <div class="en-list" role="table">
        <div class="en-row en-row-h" role="row"><span>Name</span><span>Activity · 26 wk</span><span class="r">Mentions</span><span class="r">Claims</span><span>Confidence</span><span class="r">Last seen</span></div>
        <div class="en-rows"></div>
      </div>
      <div class="en-more"></div>
    </div>`;
  const dq = (s) => dir.querySelector(s);
  const filt = dq('.en-filter input');
  let fTimer;
  filt.addEventListener('input', () => { clearTimeout(fTimer); fTimer = setTimeout(() => { S.q = filt.value.trim(); loadList(true); }, 260); });
  dq('.en-fx').onclick = () => { filt.value = ''; S.q = ''; loadList(true); };
  // phone: the header's range buttons give way to one chip in the filter row that opens a sheet (design.md §3)
  const RANGES = [[24, 'Last 24 hours', '24h'], [168, 'Last 7 days', '7d'], [720, 'Last 30 days', '30d'], [0, 'All time', 'All time']];
  const mRange = dq('.en-m-range');
  const syncRange = () => { mRange.hidden = !isPhone(); const r = RANGES.find((x) => x[0] === (S.rangeH || 0)); mRange.textContent = `${r ? r[2] : phrase({ h: S.rangeH })} ▾`; mRange.setAttribute('aria-label', `Time range: ${r ? r[1] : phrase({ h: S.rangeH })}`); };
  mRange.onclick = () => {
    mRange.setAttribute('aria-expanded', 'true');
    actionSheet({ id: 'intel-range', title: 'Time range', items: RANGES.map(([h, label]) => ({ label, value: h, current: (S.rangeH || 0) === h, run: () => { setDirRange(h); syncRange(); } })) })
      .finally(() => mRange.setAttribute('aria-expanded', 'false'));
  };
  syncRange();
  onPhoneChange(() => { syncRange(); render(); });
  dq('.en-sort').onchange = (e) => { S.sort = e.target.value; persist(); loadList(true); };
  dir.addEventListener('click', (e) => {
    const g = e.target.closest('[data-group]');
    if (g) { S.group = g.dataset.group; S.types = g.dataset.type ? [g.dataset.type] : null; persist(); loadList(true); return; }
    if (e.target.closest('[data-showhidden]')) { S.showHidden = !S.showHidden; dq('.en-types').innerHTML = railHtml(); dq('.en-tchips').innerHTML = chipsHtml(); drawRows(); return; }
    const m = e.target.closest('[data-more]');
    if (m) { S.offset += 60; loadList(false); }
  });

  const groupTypes = (g) => Object.entries(TYPES).filter(([k, v]) => v[2] === g && k !== 'ip-group' && k !== 'device').map(([k]) => k);
  const curTypes = () => S.types || groupTypes(S.group);

  const visCounts = () => Object.fromEntries(Object.entries(S.counts).map(([t, n]) => [t, Math.max(0, n - (S.showHidden ? 0 : S.hidden[t] || 0))]));
  function railHtml() {
    const c = visCounts();
    const tot = Object.values(c).reduce((a, b) => a + b, 0);
    dq('.en-total').textContent = tot.toLocaleString();
    return GROUPS.map((g) => {
      const ts = groupTypes(g).filter((t) => c[t]);
      const n = ts.reduce((a, t) => a + (c[t] || 0), 0);
      return `<div class="en-tg"><button class="en-tgh ${S.group === g && !S.types ? 'on' : ''}" data-group="${g}"><span>${g}</span><span class="mono">${n.toLocaleString()}</span></button>
        ${ts.map((t) => `<button class="en-ty ${S.types?.length === 1 && S.types[0] === t ? 'on' : ''}" data-group="${g}" data-type="${t}" style="--c:${tcolor(t)}">${icon(t)}<span>${esc(tmeta(t)[0])}</span><span class="mono">${(c[t] || 0).toLocaleString()}</span></button>`).join('')}</div>`;
    }).join('');
  }
  function chipsHtml() {
    // phone: the rail becomes one scrolling row of type chips
    const c = visCounts();
    return GROUPS.map((g) => `<button class="en-tc ${S.group === g && !S.types ? 'on' : ''}" data-group="${g}">${g}</button>`).join('')
      + Object.keys(TYPES).filter((t) => c[t]).map((t) => `<button class="en-tc ${S.types?.length === 1 && S.types[0] === t ? 'on' : ''}" data-group="${tmeta(t)[2]}" data-type="${t}" style="--c:${tcolor(t)}">${icon(t)}${esc(tmeta(t)[0])} <span class="mono">${c[t].toLocaleString()}</span></button>`).join('');
  }

  let lSeq = 0;
  async function loadList(reset) {
    if (reset) { S.offset = 0; S.items = []; }
    const my = ++lSeq;
    dq('.en-fx').hidden = !S.q;
    if (filt.value !== S.q) filt.value = S.q;
    dq('.en-sort').value = S.sort;
    const types = curTypes();
    dq('.en-h1').textContent = S.types?.length === 1 ? plural(tmeta(S.types[0])[0]) : S.group;
    if (reset) dq('.en-rows').innerHTML = loadingState('Loading…');
    let res;
    try { res = await api.get('/api/entities', { type: types.join(','), q: S.q, sort: S.sort, limit: 60, offset: S.offset, since_hours: S.rangeH || undefined }); }
    catch (e) {
      if (my !== lSeq) return;
      // v1.2: an outage no longer sticks. The directory tries again by itself (every 8 s while Intel is on screen,
      // on the next visit, and when the live stream reconnects); the rail says why it is empty meanwhile.
      if (reset) {
        S.failed = true;
        dq('.en-rows').innerHTML = errorState({ retry: () => loadList(true), title: "Couldn't load the directory", why: 'The Intel data did not answer. Trying again by itself; News and Network still work.', err: e.message });
        if (!Object.keys(S.counts).length) { dq('.en-types').innerHTML = '<p class="en-rail-note">The types show once the directory loads.</p>'; dq('.en-tchips').innerHTML = ''; }
        retrySoon();
      }
      return;
    }
    if (my !== lSeq) return;
    S.failed = false; clearTimeout(S.retryT);
    S.counts = res.counts || {}; S.total = res.total;
    S.items = reset ? res.items : S.items.concat(res.items);
    dq('.en-types').innerHTML = railHtml();
    dq('.en-tchips').innerHTML = chipsHtml();
    // activity sparklines and confidence come from one batched call (none for an empty page)
    const ids = res.items.map((r) => r.id);
    if (ids.length) {
      try {
        const a = await api.get('/api/entities/activity', { ids: ids.join(','), weeks: 26 });
        Object.assign(S.activity, a.items);
      } catch {}
    }
    if (my !== lSeq) return;
    drawRows();
    semantic();
    scanHidden();
  }
  function retrySoon() {
    clearTimeout(S.retryT);
    S.retryT = setTimeout(() => {
      if (S.failed && document.body.classList.contains('en-active') && S.route.tab === 'directory' && !document.hidden) loadList(true);
      else if (S.failed) retrySoon();
    }, 8000);
  }
  live.on('status', (ok) => { if (ok && S.failed && document.body.classList.contains('en-active') && S.route.tab === 'directory') loadList(true); });
  // Count placeholder entities per type once (background), so the rail counts exclude them.
  async function scanHidden() {
    if (S.scanned) return;
    S.scanned = true;
    const my = S.scanSeq = (S.scanSeq || 0) + 1; // a range change starts a new scan; the old one stops
    const h = {};
    for (let off = 0; off < 20000; off += 2000) {
      const r = await api.get('/api/entities', { type: 'actor,campaign,malware,tool', sort: 'name', limit: 2000, offset: off, since_hours: S.rangeH || undefined }).catch(() => null);
      if (!r || my !== S.scanSeq) return;
      for (const x of r.items) if (placeholder(x)) h[x.type] = (h[x.type] || 0) + 1;
      if (r.items.length < 2000) break;
    }
    if (my !== S.scanSeq) return;
    S.hidden = h;
    dq('.en-types').innerHTML = railHtml();
    dq('.en-tchips').innerHTML = chipsHtml();
    drawRows();
  }
  function drawRows() {
    const rows = dq('.en-rows');
    if (!S.items.length) {
      const none = !Object.values(S.counts).some((n) => n);
      const inWin = S.rangeH ? ` seen in ${phrase({ h: S.rangeH })}` : '';
      rows.innerHTML = S.q ? emptyState({ title: `Nothing named “${S.q}”`, why: `Not among ${esc(S.group.toLowerCase())}${inWin}. ${S.rangeH ? 'Choose a wider time range, or use the search at the top of the app, which also matches by meaning.' : 'The search at the top of the app also matches by meaning.'}` })
        : S.rangeH ? emptyState({ title: 'Nothing in this window', why: `Nothing of this type${inWin}. Choose a wider time range at the top right, or pick another type.` })
        : none ? emptyState({ title: 'No entities yet', why: 'They are built from news articles and the ATT&CK reference data, and appear a few minutes after the first news run.', act: stateAct('Open News', { href: '#news' }) })
          : emptyState({ title: 'None of this type yet', why: 'Pick another type on the left.' });
      dq('.en-more').innerHTML = ''; return;
    }
    const vis = S.showHidden ? S.items : S.items.filter((r) => !placeholder(r));
    const nHid = S.items.length - vis.length;
    const totHid = curTypes().reduce((a, t) => a + (S.hidden[t] || 0), 0);
    rows.innerHTML = vis.map((r) => {
      const why = placeholder(r);
      const a = S.activity[r.id] || {};
      const or = a.origins || {};
      const desc = r.description ? r.description.replace(/\s+/g, ' ') : '';
      const al = (r.aliases || []).filter((x) => x.toLowerCase() !== String(r.name).toLowerCase()).slice(0, 4);
      return `<a class="en-row" role="row" href="#entities/${encodeURIComponent(r.id)}" data-entity="${esc(r.id)}" data-nocard>
        <span class="en-nm"><span class="en-tic" style="--c:${tcolor(r.type)}">${icon(r.type)}</span>
          <span class="en-nmt"><b>${esc(shown(r.name, r.type))}</b>${why ? `<span class="en-ph" title="Probably not a real ${esc(r.type)}: created by article extraction">${esc(why)}</span>` : ''}${al.length ? `<small>aka ${esc(al.join(', '))}${r.alias_count > al.length + 1 ? ` +${r.alias_count - al.length - 1}` : ''}</small>` : ''}
          ${desc ? `<em title="${esc(desc.slice(0, 600))}">${esc(desc.slice(0, 150))}${desc.length > 150 ? '…' : ''}</em>` : ''}</span></span>
        <span class="en-act">${sparkSvg(a.spark, { color: tcolor(r.type) })}</span>
        <span class="r mono" data-l="Mentions">${r.mentions ? r.mentions.toLocaleString() : '<span class="en-dim">0</span>'}</span>
        <span class="r mono en-cl" data-l="Claims" title="${esc(Object.entries(or).map(([k, v]) => `${v} ${(ORIGINS[k]?.label || k).toLowerCase()}`).join(' · '))}">${r.claims ? r.claims.toLocaleString() : '<span class="en-dim">0</span>'}
          ${r.claims ? `<span class="en-ob">${['observed', 'reported', 'local'].filter((k) => or[k]).map((k) => `<i class="o-${k}" style="flex:${or[k]}"></i>`).join('')}</span>` : ''}</span>
        <span data-l="Confidence">${a.confidence != null ? bandPill(a.confidence, a.band) : '<span class="en-dim mono">—</span>'}</span>
        <span class="r mono en-ls" data-l="Last seen" title="${esc(r.last_seen ? T.full(r.last_seen) : '')}">${r.last_seen ? fmtAgo(r.last_seen) : '<span class="en-dim">reference</span>'}</span>
      </a>`;
    }).join('');
    const hidCount = S.showHidden ? 0 : S.q ? nHid : Math.max(nHid, totHid);
    dq('.en-sub').textContent = `${(S.total - hidCount).toLocaleString()} ${S.q ? `matching “${S.q}”` : 'entities'}${S.rangeH ? ` seen in ${phrase({ h: S.rangeH })}` : ''}${hidCount ? ` · ${hidCount.toLocaleString()} placeholders hidden` : ''} · sorted by ${dq('.en-sort').selectedOptions[0].textContent.toLowerCase()}`;
    const hidNote = (nHid || totHid) ? `<button class="en-hid" data-showhidden>${S.showHidden ? 'Hide' : 'Show'} ${S.showHidden ? '' : `${Math.max(nHid, totHid).toLocaleString()} `}placeholder names (generic labels, individuals, companies typed as actors)</button>` : '';
    dq('.en-more').innerHTML = hidNote + (S.items.length < S.total ? `<button class="src-btn" data-more>Show 60 more · ${S.items.length.toLocaleString()} of ${S.total.toLocaleString()}</button>` : `<span class="mono en-dim">${S.total.toLocaleString()} shown</span>`);
  }
  // When filtering by text, also show the entity searcher's best matches by meaning.
  let semSeq = 0;
  async function semantic() {
    const box = dq('.en-sem');
    if (!S.q || S.q.length < 3) { box.hidden = true; return; }
    const my = ++semSeq;
    const r = await api.get('/api/search/semantic', { q: S.q, types: 'entity', k: 8 }).catch(() => null);
    if (my !== semSeq || !r) return;
    const have = new Set(S.items.map((x) => x.id));
    const extra = r.filter((x) => !have.has(x.id));
    if (!extra.length) { box.hidden = true; return; }
    box.hidden = false;
    box.innerHTML = `<div class="en-semh"><span class="label">Also related by meaning</span><span class="mono en-dim">${esc(r[0]?.mode || '')} search</span></div>
      <div class="en-chips">${extra.map((x) => chip(x.id, { type: x.entity_type, name: x.title })).join('')}</div>`;
  }

  function showDirectory() {
    const r = S.route;
    if (r.type && TYPES[r.type]) { S.group = TYPES[r.type][2]; S.types = [r.type]; }
    if (!S.items.length || r.type || S.failed) loadList(true);
  }

  render();
  return {
    go,
    show() {
      const r = parseRoute(location.hash);
      if (r && routeHash(r) !== routeHash(S.route)) go(r, false);
      else if (S.failed && S.route.tab === 'directory') loadList(true);   // back after an outage: try again at once
      // the shell writes '#entities' after show(); put the full route back once it has
      setTimeout(() => { if (document.body.classList.contains('en-active')) history.replaceState(null, '', routeHash(S.route)); }, 0);
    },
    hide() {},
  };
}

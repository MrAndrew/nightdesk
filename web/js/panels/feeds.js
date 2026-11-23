// List panels: Exploited Vulns (KEV), New CVEs (NVD), Threat Newswire, Social OSINT,
// Internet Outages, Feed Health. All real data from the backend, all honour the global
// time range + search (store), chip filters with counts, incremental rendering so
// thousands of rows stay fast, and live updates from the SSE hub.
import { registerPanel } from '../core/panels.js';
import * as Tm from '../core/time.js';
import { SERIES, esc, flag, fmt, sevColor, debounce, safeUrl, toast, epssTag } from '../core/util.js';
import { api } from '../core/api.js';
import { seenSlot, fillSeen } from '../core/chips.js';
import { followButton } from '../core/stack.js';
import { emptyState, errorState, stateAct } from '../core/view.js';

// "Seen on your network" on KEV and CVE rows: each row carries a slot for its CVE, filled (or left empty when the
// CVE was never seen) by one batched lookup whenever rows are rendered.
function seenRows(body) {
  let t = 0;
  const mo = new MutationObserver(() => { clearTimeout(t); t = setTimeout(() => fillSeen(body), 150); });
  mo.observe(body, { childList: true, subtree: true });
  return mo;
}

// ------------------------------------------------------------------ small helpers
const P = 'stroke="currentColor" stroke-width="1.7" fill="none" stroke-linecap="round" stroke-linejoin="round"';
const ICONS = {
  all: `<path d="M4 6h16M4 12h16M4 18h10" ${P}/>`,
  lock: `<rect x="5" y="11" width="14" height="9" rx="1.5" ${P}/><path d="M8 11V8a4 4 0 0 1 8 0v3" ${P}/>`,
  cal: `<rect x="4" y="5" width="16" height="15" rx="1.5" ${P}/><path d="M4 10h16M9 3v4M15 3v4" ${P}/>`,
  build: `<path d="M5 20V6l7-3v17M12 9h7v11M8 9h1M8 13h1M8 17h1M15 13h1M15 17h1M3 20h18" ${P}/>`,
  bug: `<rect x="7" y="8" width="10" height="12" rx="5" ${P}/><path d="M12 8v12M9 5l1.5 2M15 5l-1.5 2M4 12h3M17 12h3M4 18l3-1.5M20 18l-3-1.5" ${P}/>`,
  db: `<ellipse cx="12" cy="6" rx="7" ry="2.6" ${P}/><path d="M5 6v12c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6V6M5 12c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6" ${P}/>`,
  zap: `<path d="M13 3 5 13.5h6L10 21l8-10.5h-6z" ${P}/>`,
  news: `<rect x="4" y="5" width="13" height="14" rx="1.5" ${P}/><path d="M17 9h3v8.5a1.5 1.5 0 0 1-3 0M7 9h7M7 12.5h7M7 16h4" ${P}/>`,
  globe: `<circle cx="12" cy="12" r="8.5" ${P}/><path d="M3.5 12h17M12 3.5c2.5 2.6 2.5 14.4 0 17M12 3.5c-2.5 2.6-2.5 14.4 0 17" ${P}/>`,
  pin: `<path d="M12 21s-6.5-6-6.5-11a6.5 6.5 0 0 1 13 0c0 5-6.5 11-6.5 11z" ${P}/><circle cx="12" cy="10" r="2.3" ${P}/>`,
  shield: `<path d="M12 3 5 6v5.5c0 4.4 3 7.9 7 9.5 4-1.6 7-5.1 7-9.5V6z" ${P}/>`,
  signal: `<path d="M3 12h3l2.5-6 4 12 2.5-6H21" ${P}/>`,
};
const ico = (n, cls = 'feeds-ci') => `<svg class="${cls}" viewBox="0 0 24 24">${ICONS[n] || ''}</svg>`;
const CLOCK = '<svg class="feeds-clk"><use href="#i-clock"/></svg>';
const EXT = (url) => (safeUrl(url) ? `<a class="feeds-ext" href="${esc(safeUrl(url))}" target="_blank" rel="noopener" title="Open source"><svg><use href="#i-ext"/></svg></a>` : '');

// The age without "ago", rounded the same way as everywhere else (core/time.js).
const age = (t) => (t ? Tm.ago(t).replace(' ago', '') : '—');
const ageSpan = (t) => `<span class="feeds-age">${CLOCK}<span data-t="${esc(t || '')}">${age(t)}</span></span>`;
const within = (t, hours) => Date.now() - new Date(t).getTime() <= hours * 3600e3;
const maxIngested = (rows) => rows.reduce((m, r) => (r.ingested_at && r.ingested_at > m ? r.ingested_at : m), '') || null;

function hash(s) { let x = 2166136261; for (const c of String(s)) { x ^= c.charCodeAt(0); x = Math.imul(x, 16777619); } return x >>> 0; }

const rangeLabel = (hrs) => (!hrs ? 'all time' : hrs < 24 ? `last ${hrs}h` : hrs === 24 ? 'last 24h' : `last ${Math.round(hrs / 24)}d`);

// An empty panel names the cause and the next step: the panel filter, offline mode, a feed that is off, one that
// has not delivered yet or is failing, or simply nothing in the time range. Feed states come from live.js.
function emptyFor(ctx, { what, sourceId, every, inRange = true }) {
  const { opsQ: q, hours } = ctx.store.get();
  if (q) return { title: `No ${what} match “${q}”`, why: 'The panel filter is on. Clear it in the bar above the panels.' };
  const title = inRange ? `No ${what} in the ${rangeLabel(hours)}` : `No ${what} yet`;
  const src = ctx.live.source(sourceId);
  const name = src?.name || 'This source';
  if (src?.withheld) return { title, why: src.withheld };   // left out of this release: nothing to turn on
  if (ctx.live.isOffline()) return { title, why: 'Offline mode is on, so sources are not fetched and nothing new arrives.' };
  if (src && (src.enabled === false || src.unavailable)) return { title, why: `${name} is turned off.`, href: '#sources', act: 'Turn it on in Sources' };
  if (src?.status === 'error') return { title, why: `${name} failed on its last check.`, href: '#sources', act: 'See why in Sources' };
  if (src && !src.status) return { title, why: `${name} has not delivered yet. It checks ${every}; the first data usually arrives within a few minutes.`, href: '#sources', act: 'Watch progress in Sources' };
  return { title, why: hours && hours < 168 ? `${name} is up to date; nothing new in this window. Try a wider time range (7D).` : `${name} is up to date; nothing new in this window.` };
}

// Text hygiene: strip URLs, boilerplate/copyright lines and feed artefacts.
const URL_RE = /\b(?:https?:\/\/|www\.)\S+/gi;
const BOILER = [
  /\(c\)[^.]*(?:\.|$)/gi, /©[^.]*(?:\.|$)/g, /copyright\b[^.]*(?:\.|$)/gi,
  /creative commons\b.*?(?:licen[sc]e\b\.?|$)/gi, /all rights reserved\.?/gi, /\blicensed under\b.*?(?:\.|$)/gi,
  /\bthe post .{3,160}? appeared first on .{2,80}?\.?$/i,
  /\b(?:read more|continue reading|click here)\b.*$/i,
];
function cleanText(s) {
  let t = String(s || '').replace(URL_RE, ' ');
  for (const re of BOILER) t = t.replace(re, ' ');
  return t
    .replace(/\s*\[(?:\.\.\.|…)\]\s*$/, '…')
    .replace(/\(\s*[,;]?\s*\)/g, ' ')          // empty parens left by stripped links
    .replace(/\s+([,.;:!?])/g, '$1')
    .replace(/(?:\s*[|·•\-–—,:;]\s*)+$/g, '')  // dangling separators at the end
    .replace(/^\s*[|·•\-–—,:;]+\s*/, '')
    .replace(/\s{2,}/g, ' ')
    .trim();
}
const toks = (s) => String(s).toLowerCase().replace(/[^\p{L}\p{N}\s]/gu, ' ').split(/\s+/).filter((w) => w.length > 1);
// true when b adds nothing over a (normalised prefix, or >80% of b's tokens already in a)
function isDup(a, b) {
  const na = toks(a).join(' '); const nb = toks(b).join(' ');
  if (!nb) return true;
  if (na.startsWith(nb) || nb.startsWith(na)) return true;
  const A = new Set(na.split(' ')); const B = nb.split(' ');
  return B.filter((w) => A.has(w)).length / B.length > 0.8;
}

// Bluesky profile resolution (public AppView, CORS-enabled, no key). did -> {handle, name, avatar} | null
// Opt-in per browser (click an avatar; localStorage nd.bsky.profiles = '1'): by default the client makes no
// requests beyond this server, so posts show initials. Never fetched in offline mode.
const PROF_KEY = 'nd.bsky.profiles';
const profOptIn = () => { try { return localStorage.getItem(PROF_KEY) === '1'; } catch { return false; } };
const PROFILES = new Map();
const profWant = new Set();
const profSubs = new Set();
let profTimer = null;
function wantProfile(did) {
  if (!did || PROFILES.has(did) || profWant.has(did)) return;
  profWant.add(did);
  clearTimeout(profTimer);
  profTimer = setTimeout(flushProfiles, 120);
}
async function flushProfiles() {
  const dids = [...profWant]; profWant.clear();
  // Avatars come from the public Bluesky API: only after the user opts in, never in offline mode (initials otherwise).
  if (!profOptIn() || (await api.health()).offline) { dids.forEach((d) => PROFILES.set(d, null)); profSubs.forEach((fn) => { try { fn(dids); } catch {} }); return; }
  for (let i = 0; i < dids.length; i += 25) {
    const batch = dids.slice(i, i + 25);
    batch.forEach((d) => PROFILES.set(d, PROFILES.get(d) ?? undefined));
    try {
      const u = 'https://public.api.bsky.app/xrpc/app.bsky.actor.getProfiles?' + batch.map((d) => `actors=${encodeURIComponent(d)}`).join('&');
      const r = await fetch(u);
      const j = r.ok ? await r.json() : { profiles: [] };
      const got = new Map((j.profiles || []).map((p) => [p.did, p]));
      for (const d of batch) {
        const p = got.get(d);
        PROFILES.set(d, p ? {
          handle: p.handle && p.handle !== 'handle.invalid' ? p.handle : null,
          name: (p.displayName || '').trim() || null,
          avatar: p.avatar ? p.avatar.replace('/img/avatar/plain/', '/img/avatar_thumbnail/plain/') : null,
        } : null);
      }
    } catch { batch.forEach((d) => PROFILES.set(d, null)); }
    profSubs.forEach((fn) => { try { fn(batch); } catch {} });
  }
}

// Shared, lazily loaded set of CVE ids that are in CISA KEV (used by the CVE feed).
let kevSetP = null;
let kevSetAt = 0;
function kevSet(api) {
  if (!kevSetP || Date.now() - kevSetAt > 10 * 60e3) {
    kevSetAt = Date.now();
    kevSetP = api.kevIds()
      .then((r) => new Set(r.ids || []))
      .catch(() => new Set());
  }
  return kevSetP;
}

// Latest FIRST EPSS per CVE id (shared by the vuln panels): {CVE: {epss, percentile, prev_epss, since}}.
// Asked for with GETs of at most 500 ids per panel load (a read, so read-only clients see no blocked POST);
// ids already known are cached for 10 minutes.
const EPSS = new Map();
let epssAt = 0;
const EPSS_CHUNK = 500;   // = EPSS_GET_MAX in osinthub/news/api.py
async function epssFor(api, cves) {
  if (Date.now() - epssAt > 10 * 60e3) { EPSS.clear(); epssAt = Date.now(); }
  const want = [...new Set(cves.filter((c) => c && !EPSS.has(c)))];
  const parts = [];
  for (let i = 0; i < want.length; i += EPSS_CHUNK) parts.push(want.slice(i, i + EPSS_CHUNK));
  await Promise.all(parts.map(async (part) => {
    try {
      const r = await api.epss(part);
      part.forEach((c) => EPSS.set(c, r.scores?.[c] || null));
    } catch { /* no badge rather than a broken panel */ }
  }));
  return EPSS;
}
const EPSS_HIGH = 0.1;   // the threshold most often cited (FIRST EPSS FAQ); ~4% of scored CVEs
const epssOf = (r) => r._epss?.epss ?? null;
const epssBadge = (r) => (r._epss ? epssTag(r._epss.epss, r._epss.percentile, r._epss.prev_epss, r._epss.since) : '');

// ------------------------------------------------------------------ generic list engine
// cfg: { sources:[...], load(ctx) -> {rows, note?}, chips(rows) -> [{key,label,n,icon?,sw?}],
//        match(row, chip), key(row), row(r, extra) -> html, empty(ctx) -> text,
//        badge?(rows, shown, ctx), extra?(bar, ctx, engine), sort?(rows, engine), live?(ctx, engine) }
function listEngine(body, ctx, cfg) {
  const st = ctx.state.get();
  const E = {
    rows: [], shown: [], chip: st.chip || 'all', seen: null, limit: 80, note: null, extra: {},
    ctx,
  };
  body.innerHTML = `
    <div class="feeds">
      <div class="feeds-bar"><div class="feeds-cwrap"><div class="feeds-chips"></div><button class="feeds-cmore" title="More filters" hidden>›</button></div><div class="feeds-xtra"></div></div>
      <div class="feeds-note" hidden></div>
      <div class="feeds-scroll"><div class="feeds-list"></div><div class="feeds-sentinel"></div></div>
    </div>`;
  const chipsEl = body.querySelector('.feeds-chips');
  const xtraEl = body.querySelector('.feeds-xtra');
  const noteEl = body.querySelector('.feeds-note');
  const scroll = body.querySelector('.feeds-scroll');
  const listEl = body.querySelector('.feeds-list');
  const sentinel = body.querySelector('.feeds-sentinel');

  E.renderChips = () => {
    const chips = cfg.chips(E.rows, E);
    if (!chips.some((c) => c.key === E.chip)) E.chip = 'all';
    chipsEl.innerHTML = chips.map((c) => `
      <button class="chip feeds-chip${c.key === E.chip ? ' on' : ''}" data-chip="${esc(c.key)}" title="${esc(c.title || c.label)}">
        ${c.sw ? `<span class="sw" style="background:${c.sw}"></span>` : c.icon ? ico(c.icon) : ''}${esc(c.label)}<span class="n">${fmt(c.n)}</span>
      </button>`).join('');
    requestAnimationFrame(fades);
  };
  const cwrap = body.querySelector('.feeds-cwrap');
  const cmore = body.querySelector('.feeds-cmore');
  function fades() {
    const max = chipsEl.scrollWidth - chipsEl.clientWidth;
    const l = chipsEl.scrollLeft > 2; const r = max - chipsEl.scrollLeft > 2;
    cwrap.classList.toggle('fl', l); cwrap.classList.toggle('fr', r);
    cmore.hidden = !r;
  }
  chipsEl.addEventListener('scroll', fades, { passive: true });
  chipsEl.addEventListener('wheel', (e) => {
    if (Math.abs(e.deltaY) > Math.abs(e.deltaX) && chipsEl.scrollWidth > chipsEl.clientWidth) { chipsEl.scrollLeft += e.deltaY; e.preventDefault(); }
  }, { passive: false });
  cmore.addEventListener('click', () => chipsEl.scrollBy({ left: chipsEl.clientWidth * 0.7, behavior: 'smooth' }));
  const ro = new ResizeObserver(fades); ro.observe(chipsEl);
  E.render = (freshKeys = new Set()) => {
    let shown = E.rows.filter((r) => E.chip === 'all' || cfg.match(r, E.chip, E));
    if (cfg.sort) shown = cfg.sort(shown, E);
    E.shown = shown;
    noteEl.hidden = !E.note;
    noteEl.innerHTML = E.note || '';
    if (!shown.length) {
      const em = cfg.empty(ctx, E);
      listEl.innerHTML = typeof em === 'string' ? emptyState({ why: esc(em), size: 'sm', cls: 'feeds-empty' })
        : emptyState({ title: em.title, why: em.why ? esc(em.why) : '', act: em.href ? stateAct(em.act, { href: em.href }) : '', size: 'sm', cls: 'feeds-empty' });
    } else {
      listEl.innerHTML = shown.slice(0, E.limit).map((r) => {
        const k = cfg.key(r);
        const html = cfg.row(r, E);
        return freshKeys.has(k) ? html.replace('class="row ', 'class="row fresh ') : html;
      }).join('');
    }
    cfg.badge ? cfg.badge(E.rows, shown, ctx, E) : ctx.setBadge(fmt(shown.length));
  };
  E.prepend = (r) => { // used by live streams for rows not yet persisted
    E.rows.unshift(r);
    if (E.rows.length > 3000) E.rows.length = 3000;
    E.seen?.add(cfg.key(r));
    E.renderChips();
    if (E.chip !== 'all' && !cfg.match(r, E.chip, E)) { cfg.badge ? cfg.badge(E.rows, E.shown, ctx, E) : null; return; }
    const empty = listEl.querySelector('.feeds-empty');
    if (empty) empty.remove();
    const tmp = document.createElement('template');
    tmp.innerHTML = cfg.row(r, E).replace('class="row ', 'class="row fresh ').trim();
    listEl.prepend(tmp.content.firstElementChild);
    E.shown.unshift(r);
    cfg.badge ? cfg.badge(E.rows, E.shown, ctx, E) : ctx.setBadge(fmt(E.shown.length));
  };

  let loading = false; let queued = false;
  E.refresh = async () => {
    if (loading) { queued = true; return; }
    loading = true;
    try {
      const res = await cfg.load(ctx, E);
      E.rows = res.rows;
      E.note = res.note || null;
      const keys = new Set(E.rows.map(cfg.key));
      const fresh = new Set();
      if (E.seen) for (const k of keys) if (!E.seen.has(k)) fresh.add(k);
      E.seen = keys;
      E.renderChips();
      E.render(fresh);
      ctx.setUpdated(res.updated || maxIngested(E.rows) || new Date().toISOString());
    } catch (err) {
      listEl.innerHTML = errorState({ retry: () => E.refresh(), title: "Couldn't load this source", why: 'The Night Desk server did not answer; this panel tries again on its own.', err: err.message, size: 'sm', cls: 'feeds-empty' });
    } finally {
      loading = false;
      if (queued) { queued = false; E.refresh(); }
    }
  };

  chipsEl.addEventListener('click', (e) => {
    const b = e.target.closest('[data-chip]'); if (!b) return;
    E.chip = b.dataset.chip; ctx.state.set({ chip: E.chip });
    E.limit = 80; scroll.scrollTop = 0;
    E.renderChips(); E.render();
    chipsEl.querySelector('.on')?.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'smooth' });
  });
  listEl.addEventListener('click', (e) => {
    if (e.target.closest('a')) return;
    const r = e.target.closest('.row'); if (!r) return;
    if (cfg.click) return cfg.click(r, e, E);
    if (r.dataset.id) ctx.openEvent(r.dataset.id);
    else if (safeUrl(r.dataset.url)) window.open(safeUrl(r.dataset.url), '_blank', 'noopener'); // feed data: http(s) only
  });
  // incremental rendering: grow the rendered window when the sentinel scrolls into view
  const io = new IntersectionObserver((ents) => {
    if (!ents.some((x) => x.isIntersecting) || E.limit >= E.shown.length) return;
    const from = E.limit; E.limit += 80;
    listEl.insertAdjacentHTML('beforeend', E.shown.slice(from, E.limit).map((r) => cfg.row(r, E)).join(''));
  }, { root: scroll, rootMargin: '300px' });
  io.observe(sentinel);

  const ticker = setInterval(() => {
    body.querySelectorAll('[data-t]').forEach((s) => { if (s.dataset.t) s.textContent = age(s.dataset.t); });
  }, 30e3);

  const offs = [];
  const soon = debounce(() => E.refresh(), 1200);
  if (cfg.sources?.length) {
    offs.push(ctx.live.on('events', (m) => { if (cfg.sources.includes(m?.source)) soon(); }));
  }
  if (cfg.extra) { const r = cfg.extra(xtraEl, ctx, E); if (Array.isArray(r)) offs.push(...r); }
  if (cfg.live) offs.push(...(cfg.live(ctx, E) || []));
  // an empty panel's cause can change (feed states load, offline mode, a stream drops): repaint it
  offs.push(ctx.live.onStatus(() => { if (!E.shown.length && E.seen) E.render(); }));
  E.refresh();

  return {
    refresh: () => { E.limit = 80; scroll.scrollTop = 0; E.seen = null; E.refresh(); },
    destroy: () => { io.disconnect(); ro.disconnect(); clearInterval(ticker); offs.forEach((f) => f && f()); },
    resize: () => {},
    engine: E,
  };
}

// ------------------------------------------------------------------ KEV tracker
function kevParse(e) {
  const cve = e.title.split(' ')[0];
  const [vendor = '', product = ''] = e.tags || [];
  const ransom = (e.tags || []).includes('ransomware');
  const s = e.summary || '';
  const dot = s.indexOf('. ');
  let name = dot > 0 ? s.slice(0, dot) : s;
  const desc = dot > 0 ? s.slice(dot + 2) : '';
  const pre = `${vendor} ${product} `;
  if (name.startsWith(pre)) name = name.slice(pre.length);
  return { cve, vendor, product, ransom, name, desc };
}

// Follow from a KEV row: the vendor's product when the row names one ("SonicWall SMA1000 Appliances"), and the
// whole vendor as a second choice. A catch-all product ("Multiple Products") offers only the vendor.
function followOffer(k) {
  if (!k.vendor) return '';
  const prod = k.product && !/^multiple\b/i.test(k.product) && k.product.toLowerCase() !== k.vendor.toLowerCase() ? k.product : '';
  const pname = prod.toLowerCase().startsWith(k.vendor.toLowerCase()) ? prod : `${k.vendor} ${prod}`;   // not "WordPress WordPress Core"
  return (prod ? followButton({ vendor: k.vendor, product: prod }, { cls: 'stack-fb-sm', name: pname }) : '')
    + followButton({ vendor: k.vendor }, { cls: 'stack-fb-sm', name: prod ? `all ${k.vendor}` : k.vendor });
}

registerPanel({
  id: 'kev-tracker', title: 'Newly exploited', w: 4, h: 7, minW: 3, minH: 4,
  description: 'CISA Known Exploited Vulnerabilities — newly added CVEs confirmed exploited in the wild, with ransomware flags.',
  mount(body, ctx) {
    let topVendor = null;
    const seenMo = seenRows(body);
    const eng = listEngine(body, ctx, {
      sources: ['cisa_kev'],
      async load(ctx) {
        const { opsQ: q } = ctx.store.get();
        const hrs = ctx.store.sinceHours();
        let rows = await ctx.api.events({ sources: ['cisa_kev'], since_hours: hrs, q, limit: 2000 });
        let note = null;
        if (!rows.length && hrs) {
          rows = await ctx.api.events({ sources: ['cisa_kev'], q, limit: 400 });
          if (rows.length) note = `No KEV additions in the ${rangeLabel(hrs)} — showing the latest catalogue entries`;
        }
        rows.forEach((r) => { r._k = kevParse(r); });
        // "new" is the app's one last-seen marker (Watch "Caught up", News "Mark all as read"); same rule as Watch
        const since = Date.parse((await ctx.api.get('/api/marker').catch(() => null))?.window?.since || '');
        rows.forEach((r) => { const t = Date.parse(r.ts), s = Date.parse(r.stored_at || ''); r._new = !!since && (t > since || (s > since && t > since - 3 * 864e5)); });
        const ep = await epssFor(ctx.api, rows.map((r) => r._k.cve));
        rows.forEach((r) => { r._epss = ep.get(r._k.cve) || null; });
        // what you follow (My stack): "You follow SonicWall" on the rows it touches
        try {
          const m = (await ctx.api.get('/api/stack/kev')).matches || {};
          rows.forEach((r) => { r._follow = (m[r._k.cve.toUpperCase()] || []).map((x) => x.name); });
        } catch { rows.forEach((r) => { r._follow = []; }); }
        const vc = {};
        rows.forEach((r) => { if (r._k.vendor) vc[r._k.vendor] = (vc[r._k.vendor] || 0) + 1; });
        topVendor = Object.entries(vc).sort((a, b) => b[1] - a[1])[0] || null;
        // the header's age is the newest catalogue entry's (when CISA added it), not when the catalogue was fetched
        const newest = rows.reduce((m, r) => (r.ts && r.ts > m ? r.ts : m), '') || null;
        return { rows, note, updated: newest };
      },
      chips(rows) {
        const c = [
          { key: 'all', label: 'All', n: rows.length, icon: 'all' },
          { key: 'ransom', label: 'Ransomware', n: rows.filter((r) => r._k.ransom).length, icon: 'lock' },
          { key: '7d', label: 'Last 7d', n: rows.filter((r) => within(r.ts, 168)).length, icon: 'cal' },
        ];
        const nn = rows.filter((r) => r._new).length;
        if (nn) c.push({ key: 'new', label: 'New', n: nn, icon: 'cal', title: 'Added since you last pressed Caught up on Watch (or Mark all as read in News)' });
        const hi = rows.filter((r) => epssOf(r) >= EPSS_HIGH).length;
        if (hi) c.push({ key: 'epss', label: 'EPSS ≥ 10%', n: hi, icon: 'zap', title: 'FIRST EPSS: at least a 10% probability of exploitation activity in the next 30 days' });
        if (topVendor) c.push({ key: 'vendor', label: topVendor[0], n: topVendor[1], icon: 'build', title: 'Top vendor in range' });
        const nf = rows.filter((r) => r._follow?.length).length;
        if (nf) c.splice(1, 0, { key: 'follow', label: 'You follow', n: nf, icon: 'zap', title: 'Entries for a vendor, product or CVE you follow' });
        return c;
      },
      sort: (rows, E) => (E.extra.sort === 'epss' ? [...rows].sort((a, b) => (epssOf(b) ?? -1) - (epssOf(a) ?? -1) || (b.ts > a.ts ? 1 : -1)) : rows),
      match(r, chip) {
        if (chip === 'epss') return epssOf(r) >= EPSS_HIGH;
        if (chip === 'ransom') return r._k.ransom;
        if (chip === '7d') return within(r.ts, 168);
        if (chip === 'new') return r._new;
        if (chip === 'vendor') return topVendor && r._k.vendor === topVendor[0];
        if (chip === 'follow') return !!r._follow?.length;
        return true;
      },
      key: (r) => r.id,
      empty: (ctx) => emptyFor(ctx, { what: 'exploited vulns', sourceId: 'cisa_kev', every: 'every 6 hours', inRange: false }),
      row(r) {
        const k = r._k;
        return `<div class="row feeds-row${k.ransom ? ' feeds-hot' : ''}" data-id="${esc(r.id)}">
          ${EXT(r.url)}
          <div class="feeds-l1"><span class="feeds-cve">${esc(k.cve)}</span><span class="feeds-vp">${esc(k.vendor)}${k.product ? ` <i>/</i> ${esc(k.product)}` : ''}</span></div>
          <div class="row-title feeds-t1" title="${esc(k.name)}">${esc(k.name)}</div>
          ${k.desc ? `<div class="row-sub" title="${esc(k.desc)}">${esc(k.desc)}</div>` : ''}
          <div class="feeds-meta">${r._new ? '<span class="tag green" title="Added since your last visit">NEW</span>' : ''}<span>CISA KEV</span>${ageSpan(r.ts)}<span class="feeds-dim">added ${esc(Tm.date(r.ts))}</span>
            ${k.ransom ? '<span class="tag red">Ransomware</span>' : ''}${epssBadge(r)}${r._follow?.length
              ? `<span class="tag stack-tag" title="Matches what you follow">You follow ${esc(r._follow.join(', '))}</span>`
              : `<span class="tag">${esc(k.vendor)}</span>${followOffer(k)}`}</div>
          <div class="drawer-feedseen">${seenSlot(k.cve, { compact: true })}</div>
        </div>`;
      },
      extra(bar, ctx, E) {
        E.extra.sort = ctx.state.get().sort || 'new';
        const seg = () => { bar.innerHTML = `<div class="feeds-seg">${[['new', 'Newest'], ['epss', 'EPSS']].map(([k, l]) => `<button data-sort="${k}" class="${E.extra.sort === k ? 'on' : ''}" title="${k === 'epss' ? 'Most likely to be exploited next (FIRST EPSS) first' : 'Newest additions first'}">${l}</button>`).join('')}</div>`; };
        seg();
        bar.addEventListener('click', (e) => {
          const b = e.target.closest('[data-sort]'); if (!b) return;
          E.extra.sort = b.dataset.sort; ctx.state.set({ sort: E.extra.sort }); seg(); E.limit = 80; E.render();
        });
        // 30-day additions sparkline in the panel header toolbar (independent of search, always last 30 days)
        const el = document.createElement('span');
        el.className = 'feeds-sparkwrap';
        ctx.tools.prepend(el);
        const draw = async () => {
          try {
            const rows = await ctx.api.events({ sources: ['cisa_kev'], since_hours: 720, limit: 2000 });
            const days = new Array(30).fill(0);
            const now = Date.now();
            rows.forEach((r) => { const d = Math.floor((now - new Date(r.ts).getTime()) / 86400e3); if (d >= 0 && d < 30) days[29 - d]++; });
            const mx = Math.max(1, ...days);
            const bars = days.map((n, i) => {
              const hh = n ? Math.max(2, Math.round((n / mx) * 18)) : 1;
              return `<rect x="${i * 3}" y="${20 - hh}" width="2" height="${hh}" rx=".5" fill="${n ? 'var(--red)' : 'var(--line-2)'}" opacity="${n ? 0.55 + 0.45 * (i / 29) : 1}"><title>${n} added · ${Tm.date(now - (29 - i) * 86400e3)}</title></rect>`;
            }).join('');
            el.innerHTML = `<div class="feeds-spark" title="KEV additions per day, last 30 days"><svg width="90" height="20" viewBox="0 0 90 20">${bars}</svg><span><b>${rows.length}</b>/30d</span></div>`;
          } catch { el.innerHTML = ''; }
        };
        draw();
        // the app-wide marker moved (Caught up on Watch, Mark all as read in News): re-read so "New" follows it
        const onStack = () => E.refresh();   // followed something here or elsewhere: re-match the rows
        window.addEventListener('nd:stack', onStack);
        return [ctx.live.on('events', (m) => { if (m?.source === 'cisa_kev') draw(); }), ctx.live.on('marker', () => E.refresh()),
          () => window.removeEventListener('nd:stack', onStack)];
      },
    });
    const destroy = eng.destroy;
    eng.destroy = () => { seenMo.disconnect(); destroy(); };
    return eng;
  },
});

// ------------------------------------------------------------------ NVD CVE feed
const SEV = {
  critical: { label: 'Critical', short: 'CRIT', color: '#f0524f' },
  high: { label: 'High', short: 'HIGH', color: '#f08a3c' },
  medium: { label: 'Medium', short: 'MED', color: '#f2c94c' },
  low: { label: 'Low', short: 'LOW', color: '#4ea1b0' },
  none: { label: 'Unscored', short: 'N/A', color: '#8a8578' },
};
function cveSev(r) {
  const t = (r.tags || []).map((x) => String(x).toLowerCase()).find((x) => SEV[x]);
  if (t) return t;
  const v = r.value;
  if (v == null) return 'none';
  return v >= 9 ? 'critical' : v >= 7 ? 'high' : v >= 4 ? 'medium' : v > 0 ? 'low' : 'none';
}

registerPanel({
  id: 'cve-feed', title: 'New CVEs', w: 6, h: 9, minW: 3, minH: 4,
  description: 'Newly published CVEs from NIST NVD with CVSS scores; CVEs already in CISA KEV are flagged.',
  mount(body, ctx) {
    let kev = new Set();
    const seenMo = seenRows(body);
    const eng = listEngine(body, ctx, {
      sources: ['nvd_recent', 'cisa_kev'],
      async load(ctx, E) {
        const { opsQ: q } = ctx.store.get();
        const [rows, ks] = await Promise.all([
          ctx.api.events({ sources: ['nvd_recent'], since_hours: ctx.store.sinceHours(), q, limit: 5000 }),
          kevSet(ctx.api),
        ]);
        kev = ks;
        rows.forEach((r) => { r._cve = r.title.split(' ')[0]; r._sev = cveSev(r); r._kev = kev.has(r._cve); });
        const ep = await epssFor(ctx.api, rows.map((r) => r._cve));
        rows.forEach((r) => { r._epss = ep.get(r._cve) || null; });
        return { rows };
      },
      chips(rows) {
        const n = (s) => rows.filter((r) => r._sev === s).length;
        const c = [{ key: 'all', label: 'All', n: rows.length, icon: 'all' }];
        for (const s of ['critical', 'high', 'medium', 'low']) c.push({ key: s, label: SEV[s].label, n: n(s), sw: SEV[s].color });
        const kn = rows.filter((r) => r._kev).length;
        if (kn) c.push({ key: 'kev', label: 'In KEV', n: kn, icon: 'shield' });
        const hi = rows.filter((r) => epssOf(r) >= EPSS_HIGH).length;
        if (hi) c.push({ key: 'epss', label: 'EPSS ≥ 10%', n: hi, icon: 'zap', title: 'FIRST EPSS: at least a 10% probability of exploitation activity in the next 30 days' });
        return c;
      },
      match: (r, chip) => (chip === 'kev' ? r._kev : chip === 'epss' ? epssOf(r) >= EPSS_HIGH : r._sev === chip),
      sort: (rows, E) => (E.extra.sort === 'score' ? [...rows].sort((a, b) => (b.value ?? -1) - (a.value ?? -1) || (b.ts > a.ts ? 1 : -1))
        : E.extra.sort === 'epss' ? [...rows].sort((a, b) => (epssOf(b) ?? -1) - (epssOf(a) ?? -1) || (b.value ?? -1) - (a.value ?? -1) || (b.ts > a.ts ? 1 : -1)) : rows),
      key: (r) => r.id,
      empty: (ctx) => emptyFor(ctx, { what: 'new CVEs', sourceId: 'nvd_recent', every: 'every 2 hours' }),
      row(r) {
        const s = SEV[r._sev];
        return `<div class="row feeds-row" data-id="${esc(r.id)}">
          ${EXT(r.url)}
          <div class="feeds-l1">
            <span class="feeds-score" style="--c:${s.color}">${r.value != null ? Number(r.value).toFixed(1) : '—'}<em>${s.short}</em></span>
            <span class="feeds-cve">${esc(r._cve)}</span>
            ${r._kev ? '<span class="tag red feeds-kev" title="Also in CISA Known Exploited Vulnerabilities">KEV · exploited</span>' : ''}
            ${epssBadge(r)}
          </div>
          <div class="feeds-desc">${esc(r.summary || '')}</div>
          <div class="drawer-feedseen">${seenSlot(r._cve, { compact: true })}</div>
          <div class="feeds-meta"><span>NVD</span>${ageSpan(r.ts)}<span class="feeds-dim">published ${esc(Tm.stamp(r.ts))}</span></div>
        </div>`;
      },
      extra(el, ctx, E) {
        E.extra.sort = ctx.state.get().sort || 'new';
        const draw = () => {
          el.innerHTML = `<div class="feeds-seg">${[['new', 'Newest'], ['score', 'CVSS'], ['epss', 'EPSS']].map(([k, l]) => `<button data-sort="${k}" class="${E.extra.sort === k ? 'on' : ''}">${l}</button>`).join('')}</div>`;
        };
        draw();
        el.addEventListener('click', (e) => {
          const b = e.target.closest('[data-sort]'); if (!b) return;
          E.extra.sort = b.dataset.sort; ctx.state.set({ sort: E.extra.sort }); draw(); E.limit = 80; E.render();
        });
      },
    });
    const destroy = eng.destroy;
    eng.destroy = () => { seenMo.disconnect(); destroy(); };
    return eng;
  },
});

// ------------------------------------------------------------------ Newswire
const outletOf = (r) => (r.kind === 'advisory' ? 'CISA' : (r.tags || [])[0] || r.source);
// one of the app's muted series hues per outlet (stable), not a rainbow
const outletColor = (o) => SERIES[hash(o) % SERIES.length];

registerPanel({
  id: 'news-wire', title: 'Latest news', w: 4, h: 7, minW: 3, minH: 4,
  description: 'Security news and advisories from major outlets, tagged with the countries they mention.',
  mount(body, ctx) {
    return listEngine(body, ctx, {
      sources: ['security_news', 'cisa_advisories'],
      async load(ctx) {
        const { opsQ: q } = ctx.store.get();
        const hrs = ctx.store.sinceHours();
        let rows = await ctx.api.events({ sources: ['security_news', 'cisa_advisories'], since_hours: hrs, q, limit: 1000 });
        let note = null;
        if (!rows.length && hrs && !q) {
          rows = await ctx.api.events({ sources: ['security_news', 'cisa_advisories'], limit: 200 });
          if (rows.length) note = `Nothing published in the ${rangeLabel(hrs)} — showing latest stories`;
        }
        rows.forEach((r) => {
          r._o = outletOf(r); r._cc = (r.tags || []).filter((t) => /^[A-Z]{2}$/.test(t));
          r._title = cleanText(r.title).replace(/,?\s*\((?:mon|tue|wed|thu|fri|sat|sun)[^)]*\)\s*$/i, '') || r.title;
          const sum = cleanText(r.summary);
          r._sum = sum.length > 24 && (sum.match(/\p{L}/gu) || []).length > sum.length * 0.5 && !isDup(r._title, sum) ? sum : '';
        });
        return { rows, note };
      },
      chips(rows) {
        const c = {};
        rows.forEach((r) => { c[r._o] = (c[r._o] || 0) + 1; });
        return [{ key: 'all', label: 'All', n: rows.length, icon: 'news' },
          ...Object.entries(c).sort((a, b) => b[1] - a[1]).map(([o, n]) => ({ key: o, label: o, n, sw: outletColor(o) }))];
      },
      match: (r, chip) => r._o === chip,
      key: (r) => r.id,
      empty: (ctx) => emptyFor(ctx, { what: 'stories', sourceId: 'security_news', every: 'every 20 minutes', inRange: false }),
      row(r) {
        return `<div class="row feeds-row" data-id="${esc(r.id)}">
          ${EXT(r.url)}
          <div class="row-title feeds-t2">${esc(r._title)}</div>
          ${r._sum ? `<div class="row-sub" title="${esc(r._sum)}">${esc(r._sum)}</div>` : ''}
          <div class="feeds-meta"><span class="feeds-outlet"><i style="background:${outletColor(r._o)}"></i>${esc(r._o)}</span>${ageSpan(r.ts)}
            ${r.kind === 'advisory' ? `<span class="tag amber">Advisory</span>${r.value != null ? `<span class="tag ${r.value >= 9 ? 'red' : r.value >= 7 ? 'orange' : 'amber'}" title="Highest CVSS among the advisory's CVEs">CVSS ${esc(Number(r.value).toFixed(1))}</span>` : ''}` : ''}
            ${r._cc.slice(0, 4).map((cc) => `<span class="tag feeds-flag">${flag(cc)} ${cc}</span>`).join('')}</div>
        </div>`;
      },
    });
  },
});

// ------------------------------------------------------------------ Social OSINT (Bluesky)
const SOC = {
  cve: { label: 'CVE mentions', icon: 'bug', test: (r) => (r.tags || []).some((t) => /^CVE-\d/i.test(t)) },
  ransom: { label: 'Ransomware', icon: 'lock', test: (r) => /ransom/i.test(r._text) || (r.tags || []).some((t) => /ransom/i.test(t)) },
  breach: { label: 'Breach', icon: 'db', test: (r) => /breach|leak(ed)?\b|exfiltrat|stolen data|data dump/i.test(r._text) },
  ddos: { label: 'DDoS', icon: 'zap', test: (r) => /\bddos\b|denial[- ]of[- ]service/i.test(r._text) },
};
const didOf = (url) => (String(url || '').match(/profile\/(did:[^/]+)/) || [])[1] || '';
function socPrep(r) {
  r._raw = r.summary || r.title || '';
  r._text = cleanText(r._raw) || r._raw;
  r._did = r._did || didOf(r.url);
  wantProfile(r._did);
  return r;
}
function avatar(did) {
  const p = PROFILES.get(did);
  const id = (p?.name || p?.handle || did.split(':').pop() || '?').replace(/^[^\p{L}\p{N}]+/u, '') || '?';
  const hh = hash(did);
  const hue = hh % 360;
  const tip = profOptIn() ? '' : ' title="Click to show Bluesky names and avatars (loads them from public.api.bsky.app)"';
  return `<span class="feeds-av"${tip} style="background:hsl(${hue} 14% 22%);color:hsl(${hue} 22% 82%);border-color:hsl(${hue} 14% 34%)">${esc([...id][0].toUpperCase())}${safeUrl(p?.avatar) ? `<img src="${esc(safeUrl(p.avatar))}" alt="" loading="lazy" referrerpolicy="no-referrer">` : ''}</span>`;
}
// An avatar that fails to load leaves the initial showing. A listener, not an inline onerror=: the page's
// Content-Security-Policy runs no inline handlers.
document.addEventListener('error', (e) => {
  const t = e.target;
  if (t instanceof HTMLImageElement && t.parentElement?.classList.contains('feeds-av')) t.remove();
}, true);
function who(did) {
  const p = PROFILES.get(did);
  const short = did.split(':').pop() || 'unknown';
  if (p && (p.name || p.handle)) {
    return `<b>${esc(p.name || p.handle.split('.')[0])}</b><span class="feeds-h">@${esc(p.handle || short.slice(0, 8))}</span>`;
  }
  return `<b class="feeds-anon">${p === null ? 'Bluesky user' : '···'}</b><span class="feeds-h">${esc(short.slice(0, 6))}…${esc(short.slice(-4))}</span>`;
}

registerPanel({
  id: 'social-feed', title: 'Social OSINT', w: 4, h: 7, minW: 3, minH: 4,
  description: 'Live Bluesky firehose filtered for cyber-security chatter: CVEs, ransomware, breaches, DDoS.',
  mount(body, ctx) {
    let rate = null;
    // the shared live status (Live / Idle / Offline / Off), with the cyber-post rate while live
    const badge = () => ctx.live.paintBadge(ctx, 'bluesky_cyber', (st) => (st.state === 'live' && rate != null ? `LIVE\u00a0·\u00a0${rate.toFixed(1)}/min` : null));
    const eng = listEngine(body, ctx, {
      sources: ['bluesky_cyber'],
      async load(ctx) {
        const { opsQ: q } = ctx.store.get();
        const rows = await ctx.api.events({ sources: ['bluesky_cyber'], since_hours: ctx.store.sinceHours(), q, limit: 1500 });
        rows.forEach(socPrep);
        return { rows };
      },
      chips(rows) {
        return [{ key: 'all', label: 'All', n: rows.length, icon: 'globe' },
          ...Object.entries(SOC).map(([k, d]) => ({ key: k, label: d.label, n: rows.filter(d.test).length, icon: d.icon }))];
      },
      match: (r, chip) => SOC[chip]?.test(r),
      key: (r) => r.url || r.id,
      badge,
      async click(r, e) {
        if (e.target.closest('.feeds-av') && !profOptIn()) {   // opt in to Bluesky profile lookups
          if ((await api.health()).offline) return toast('Offline mode: Bluesky names and avatars are not loaded');
          try { localStorage.setItem(PROF_KEY, '1'); } catch { return; }
          PROFILES.clear();
          body.querySelectorAll('.feeds-soc[data-did]').forEach((row) => wantProfile(row.dataset.did));
          return toast('Loading Bluesky names and avatars from public.api.bsky.app');
        }
        if (r.dataset.id) ctx.openEvent(r.dataset.id);
        else if (safeUrl(r.dataset.url)) window.open(safeUrl(r.dataset.url), '_blank', 'noopener');
      },
      empty: (ctx) => {
        const st = ctx.live.status('bluesky_cyber');
        if (ctx.store.get().opsQ || st.state === 'offline' || st.state === 'off') return emptyFor(ctx, { what: 'cyber posts', sourceId: 'bluesky_cyber', every: 'continuously' });
        return { title: `No cyber posts in the ${rangeLabel(ctx.store.get().hours)}`, why: st.state === 'live' ? 'Listening to Bluesky: matching posts appear here as they are written.' : `${st.title} Matching posts appear here as they are written.` };
      },
      row(r) {
        const did = r._did || '';
        const short = did.split(':').pop() || 'unknown';
        const tags = (r.tags || []);
        const cves = tags.filter((t) => /^CVE-/.test(t));
        const ccs = tags.filter((t) => /^[A-Z]{2}$/.test(t));
        const kws = [...new Set(tags.filter((t) => !/^cve-/i.test(t) && !/^[A-Z]{2}$/.test(t)))];
        const cls = Object.entries(SOC).filter(([, d]) => d.test(r)).map(([k]) => k);
        const typeTag = cls.includes('cve') ? '<span class="tag red feeds-tt">CVE</span>' : cls.includes('ransom') ? '<span class="tag red feeds-tt">RANSOM</span>'
          : cls.includes('breach') ? '<span class="tag orange feeds-tt">BREACH</span>' : cls.includes('ddos') ? '<span class="tag violet feeds-tt">DDOS</span>' : '<span class="tag feeds-tt">OSINT</span>';
        return `<div class="row feeds-row feeds-soc" ${r.id ? `data-id="${esc(r.id)}"` : ''} data-url="${esc(r.url || '')}" data-did="${esc(did)}">
          ${avatar(did || short)}
          <div class="feeds-sbody">
            ${EXT(r.url)}
            <div class="feeds-who">${who(did)}${ageSpan(r.ts)}${typeTag}</div>
            <div class="feeds-text">${esc(r._text)}</div>
            ${cves.length || kws.length || ccs.length ? `<div class="feeds-tags">${cves.slice(0, 3).map((c) => `<span class="tag red">${esc(c)}</span>`).join('')}${kws.slice(0, 3).map((k) => `<span class="tag green">#${esc(k)}</span>`).join('')}${ccs.slice(0, 3).map((c) => `<span class="tag">${flag(c)} ${c}</span>`).join('')}</div>` : ''}
          </div>
        </div>`;
      },
      live(ctx, E) {
        const onProf = (dids) => {
          const set = new Set(dids);
          body.querySelectorAll('.feeds-soc[data-did]').forEach((row) => {
            const d = row.dataset.did; if (!set.has(d)) return;
            row.querySelector('.feeds-av').outerHTML = avatar(d);
            const w = row.querySelector('.feeds-who');
            w.querySelectorAll('b, .feeds-h').forEach((x) => x.remove());
            w.insertAdjacentHTML('afterbegin', who(d));
          });
        };
        profSubs.add(onProf);
        ctx.api.metrics('bluesky.cyber_per_min', 15).then((m) => { if (m.length) { rate = m[m.length - 1].value; badge(); } }).catch(() => {});
        return [
          () => profSubs.delete(onProf),
          ctx.live.onStatus(badge),
          ctx.live.on('metric', (m) => { if (m?.name === 'bluesky.cyber_per_min') { rate = m.value; badge(); } }),
          ctx.live.on('social', (m) => {
            if (!m || !m.url || E.seen?.has(m.url)) return;
            const { opsQ: q } = ctx.store.get();
            const text = m.title || '';
            if (q && !text.toLowerCase().includes(q.toLowerCase()) && !(m.tags || []).includes(q)) return;
            E.prepend(socPrep({ id: null, url: m.url, title: text, summary: text, tags: m.tags || [], ts: m.ts, _did: m.author }));
          }),
        ];
      },
    });
    return eng;
  },
});

// ------------------------------------------------------------------ Internet outages (IODA)
const SIG = {
  bgp: { label: 'BGP', cls: 'blue' },
  'ping-slash24': { label: 'Active probing', cls: 'violet' },
  'merit-nt': { label: 'Telescope', cls: 'amber' },
  gtr: { label: 'Google traffic', cls: 'green' },
};
function outParse(r) {
  const [scope = 'country', sig = ''] = r.tags || [];
  const m = (r.summary || '').match(/([\d.]+)h/);
  return { scope, sig, dur: m ? parseFloat(m[1]) : null, name: r.title.replace(/^Outage · /, '') };
}
const durTxt = (h) => (h == null ? '—' : h < 1 ? `${Math.max(1, Math.round(h * 60))}m` : h < 48 ? `${h.toFixed(1)}h` : `${(h / 24).toFixed(1)}d`);

registerPanel({
  id: 'outage-monitor', title: 'Internet outages', w: 4, h: 8, minW: 3, minH: 4,
  description: 'Country and regional internet outages from IODA (BGP, active probing, telescope), ranked by severity.',
  mount(body, ctx) {
    return listEngine(body, ctx, {
      sources: ['ioda_outages'],
      async load(ctx) {
        const { opsQ: q } = ctx.store.get();
        const rows = await ctx.api.events({ sources: ['ioda_outages'], since_hours: ctx.store.sinceHours(), q, limit: 3000, order: 'severity' });
        rows.forEach((r) => { r._o = outParse(r); });
        return { rows };
      },
      chips(rows) {
        return [
          { key: 'all', label: 'All', n: rows.length, icon: 'signal' },
          { key: 'country', label: 'Country', n: rows.filter((r) => r._o.scope === 'country').length, icon: 'globe' },
          { key: 'region', label: 'Region', n: rows.filter((r) => r._o.scope === 'region').length, icon: 'pin' },
        ];
      },
      match: (r, chip) => r._o.scope === chip,
      key: (r) => r.id,
      empty: (ctx) => emptyFor(ctx, { what: 'outages detected', sourceId: 'ioda_outages', every: 'every 15 minutes' }),
      row(r) {
        const o = r._o;
        const s = SIG[o.sig] || { label: o.sig || 'signal', cls: '' };
        const sev = Math.max(0.04, Math.min(1, r.severity || 0));
        return `<div class="row feeds-row feeds-out" data-id="${esc(r.id)}">
          <span class="feeds-loc">${r.country ? `<span class="feeds-fl">${flag(r.country)}</span>` : ico('pin', 'feeds-pin')}</span>
          <div class="feeds-obody">
            <div class="feeds-oline"><span class="row-title feeds-oname">${esc(o.name)}</span>
              <span class="feeds-sev" title="Severity ${Math.round(sev * 100)}/100"><i style="width:${sev * 100}%;background:${sevColor(sev)}"></i></span></div>
            <div class="feeds-meta"><span class="tag ${s.cls}">${esc(s.label)}</span><span><span class="feeds-dim">dur</span> ${durTxt(o.dur)}</span><span class="feeds-dim">score ${r.value != null ? fmt(Math.round(r.value)) : '—'}</span>${ageSpan(r.ts)}${r.country ? `<span class="feeds-dim">${esc(r.country)}</span>` : '<span class="feeds-dim">region</span>'}</div>
          </div>
        </div>`;
      },
    });
  },
});

// ------------------------------------------------------------------ Feed health
const STATUS = {
  live: { c: 'var(--accent)', l: 'LIVE', pulse: true },
  running: { c: 'var(--blue)', l: 'RUNNING', pulse: true },
  ok: { c: 'var(--accent)', l: 'OK' },
  error: { c: 'var(--red)', l: 'ERROR' },
  disabled: { c: 'var(--faint)', l: 'OFF' },
  offline: { c: 'var(--muted)', l: 'OFFLINE' },
};
function srcStatus(s) {
  if (s.enabled === false || s.status === 'disabled') return 'disabled';
  if (s.status === 'live') return 'live';
  if (s.status === 'running') return 'running';
  if (s.status === 'error' || s.status === 'failed') return 'error';
  if (s.status === 'offline' || s.status === 'reconnecting') return 'offline'; // not fetching: never counted as up
  return 'ok';
}

registerPanel({
  id: 'source-health', title: 'Source health', w: 4, h: 5, minW: 3, minH: 3,
  description: 'Status of every data source: live streams, batch pulls, last run and record counts.',
  mount(body, ctx) {
    let byId = new Map();
    const eng = listEngine(body, ctx, {
      async load(ctx) {
        const rows = await ctx.api.sources();
        byId = new Map(rows.map((s) => [s.id, s]));
        const upd = rows.map((s) => s.last_ok || s.last_run).filter(Boolean).sort().pop();
        return { rows, updated: upd };
      },
      chips(rows) {
        const n = (k) => rows.filter((s) => srcStatus(s) === k).length;
        const c = [{ key: 'all', label: 'All', n: rows.length, icon: 'all' },
          { key: 'up', label: 'Healthy', n: n('live') + n('ok') + n('running'), sw: 'var(--accent)' }];
        if (n('error')) c.push({ key: 'error', label: 'Errors', n: n('error'), sw: 'var(--red)' });
        if (n('offline')) c.push({ key: 'offline', label: 'Offline', n: n('offline'), sw: 'var(--muted)' });
        c.push({ key: 'disabled', label: 'Off', n: n('disabled'), sw: 'var(--faint)' });
        return c;
      },
      match(s, chip) {
        const k = srcStatus(s);
        return chip === 'up' ? ['live', 'ok', 'running'].includes(k) : k === chip;
      },
      sort: (rows) => [...rows].sort((a, b) => {
        const o = { error: 0, live: 1, running: 2, ok: 3, offline: 4, disabled: 5 };
        return o[srcStatus(a)] - o[srcStatus(b)] || (b.items_total || 0) - (a.items_total || 0);
      }),
      key: (s) => s.id,
      badge(rows, shown, ctx) {
        const up = rows.filter((s) => ['live', 'ok', 'running'].includes(srcStatus(s))).length;
        const on = rows.filter((s) => srcStatus(s) !== 'disabled').length;
        const off = rows.filter((s) => srcStatus(s) === 'offline').length;
        ctx.setBadge(off && !up ? 'OFFLINE' : `${up}/${on} UP`, up === on && on > 0);
      },
      empty: () => 'No sources registered',
      click() { location.hash = 'sources'; document.querySelector('.views button[data-view="sources"]')?.click(); },
      row(s) {
        const k = srcStatus(s); const st = STATUS[k];
        return `<div class="row feeds-row feeds-src${k === 'disabled' ? ' feeds-off' : ''}" data-sid="${esc(s.id)}" title="${esc(s.description || '')}">
          <span class="feeds-dot${st.pulse ? ' pulse' : ''}" style="--c:${st.c}"></span>
          <div class="feeds-srcmain">
            <div class="feeds-srcname">${esc(s.name)}</div>
            <div class="feeds-meta"><span class="feeds-mode${s.mode === 'stream' ? ' stream' : ''}">${s.mode === 'stream' ? 'STREAM' : 'BATCH'}</span><span>${esc(s.provider || '')}</span>
              ${s.last_run ? `${ageSpan(s.last_run)}` : '<span class="feeds-dim">never run</span>'}
              ${k === 'error' && s.message ? `<span class="tag red" title="${esc(s.message)}">${esc(String(s.message).slice(0, 28))}</span>` : ''}</div>
          </div>
          <div class="feeds-srcn"><b>${s.items_total != null ? fmt(s.items_total) : '—'}</b><span style="color:${st.c}">${st.l}</span></div>
        </div>`;
      },
      live(ctx, E) {
        return [ctx.live.on('source', (m) => {
          if (!m?.id) return;
          const cur = byId.get(m.id);
          if (!cur) { E.refresh(); return; }
          Object.assign(cur, Object.fromEntries(Object.entries(m).filter(([, v]) => v !== undefined)));
          E.renderChips(); E.render(new Set([m.id]));
          const upd = E.rows.map((s) => s.last_ok || s.last_run).filter(Boolean).sort().pop();
          if (upd) ctx.setUpdated(upd);
        })];
      },
    });
    const t = setInterval(() => eng.engine.refresh(), 60e3);
    return { ...eng, refresh: () => {}, destroy: () => { clearInterval(t); eng.destroy(); } };
  },
});

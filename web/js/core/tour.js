// Guided tour. The lamp from the Night Desk mark leaves the logo, takes up a position on open ground
// OUTSIDE the component being explained and shines square-on at one face of it: the beam runs from the
// lamp's mouth to exactly that face's two corners, so it lands on the component's edge. The lit
// component pops slightly; everything else is grayed and darkened. "Take the tour" in the "?" menu (or ⌘K) tours
// the page you're on; the first visit gets three task steps on Watch (what Watch is for, where your network alerts
// are, where to connect logs or try the demo), ending on Watch's setup checklist.
// Styles in web/css/app.css (.tour-*). okf/architecture/web-client.md#guided-tour.
// On a phone (core/mobile.js isPhone()) the first visit and Watch's tour are the three-card phone tour (PHONE_INTRO),
// with the cards above the bottom layer (.tour-m; app.css m:shell).
import { isPhone } from './mobile.js';
import { sqlConsoleOn } from './api.js';

const DONE_KEY = 'nd.tour.done';
const S = 64;             // lamp box, px
const U = S / 32;         // one glyph unit, px
const PAD = 10;           // breathing room around the lit component
const MOUTH = 2.2 * U;    // mouth: the lit underside of the emitter bar, just past the box centre
const MOUTH_HW = 9 * U;
const DUR = 620;          // sweep duration, ms

// The light source is the Night Desk mark's own emitter bar, and the beam is its cone: every step
// re-enacts the logo, with the component as the desk. Shines along local +y.
const LAMP = `<svg viewBox="0 0 32 32" aria-hidden="true">
  <ellipse class="tl-halo" cx="16" cy="18.6" rx="10.5" ry="3"/>
  <rect class="tl-bar" x="7" y="13.4" width="18" height="4.6" rx="2.3"/>
  <path class="tl-mouth" d="M8.4 18.2 H23.6"/>
</svg>`;

// ---------------------------------------------------------------- what each tour says
// A nav entry: the top-bar tab on desktop, the bottom-bar item on a phone (whichever is on screen).
const tab = (v) => `.views [data-view="${v}"], .bnav [data-view="${v}"]`;
const panel = (title) => ({ sel: '.grid-stack-item', has: title, hasSel: '.panel-title' });

// The first visit: three task steps, all on Watch, ending on its setup checklist (or, once that is hidden, the
// link that brings it back).
// The ? button is hidden on phones (the bottom bar's More sheet holds "Take the tour"), so the pointer to "later"
// names whichever is on screen.
const helpBtnShown = () => visible(document.getElementById('help-btn'));
const laterHint = () => (helpBtnShown()
  ? 'The <b>?</b> button tours any page later.'
  : 'Later, <b>More&nbsp;›&nbsp;Take the tour</b> shows you around any page.');
const INTRO = [
  { sel: '.watch-mast', title: 'Watch: your morning briefing', body: 'Watch shows what changed since your last visit: alerts on your network, exploited bugs in what you run, and the news you follow. Press <b>Caught up</b> when you have read it.' },
  // Alternatives in order: the alerts badge when it is on screen, else the Network tab. Each says what it lights.
  { alt: [
    { sel: '#al-badge:not([hidden])', title: 'Your network alerts', body: 'This badge counts the alerts from your own network logs (the demo’s too, while it is loaded). Open it to see them under <b>Network&nbsp;›&nbsp;Alerts</b>.' },
    { sel: tab('network'), title: 'Your network alerts', body: 'Alerts from your own network logs live under <b>Network</b>, next to your devices and a search of your logs.' },
  ] },
  { sel: '.watch-setup, [data-act="show-setup"]', title: 'Connect your logs, or try the demo', body: () => `Start here: load the demo network to see what Night Desk finds, or connect your own Zeek, Suricata, Pi-hole or AdGuard logs (Network › Connect logs). ${laterHint()}` },
];

// The phone tour (design.md §4.13): three cards anchored above the bottom layer. Step 1 lights the answer card
// (the Watch briefing's first card), step 2 the Network tab, step 3 the health pill (with search and More).
const PHONE_INTRO = [
  { sel: '.watch-m-answer, #view-watch .watch > :first-child', title: 'Watch: your morning briefing', body: 'This card answers “is anything wrong at home?”: alerts on your network first, then what changed in the news you follow.' },
  { sel: '#m-tabbar [data-tab="network"]', title: 'Alerts live under Network', body: 'Your network’s alerts, devices and logs are under <b>Network</b>. In the list, swipe an alert right to acknowledge it.' },
  { sel: '.topbar .m-pill:not([hidden])', title: 'Health, search and More', body: 'The pill says whether your logs and sources are healthy; tap it for details. The magnifier searches everything, and <b>More</b> holds Ops, Notes, Settings, Help and this tour.' },
];
const phoneNow = () => isPhone();

const PAGES = {
  watch: INTRO,
  ops: [
    { sel: tab('ops'), title: 'Ops', body: 'You’re in Ops: a dashboard of live panels. Drag a panel by its title to move it, pull a corner to resize; layouts save per deck.' },
    { ...panel('World map'), title: 'World map', body: 'Every geolocated event, subsea cables and live BGP pulses. <b>Layers</b> filters what’s plotted; <b>Jump to</b> flies anywhere.' },
    { ...panel('Cyber pulse'), title: 'Cyber Pulse', body: 'A 0–100 index of how loud today is against the past week, split into exploitation, ransomware, connectivity, routing and chatter. It says “warming up” until enough sources report.' },
    { ...panel('BGP live'), title: 'BGP live', body: 'Routing updates per second for the networks you watch, when RIS Live is on (Settings › Sources › Routing watch).' },
    { ...panel('Newly exploited'), title: 'Newly exploited', body: 'CISA’s Known Exploited Vulnerabilities, newest first. Filter to ransomware use, the last week, or a vendor.' },
    { sel: '#deck-btn', title: 'Decks', body: 'Switch between saved panel layouts, or save the current one as your own deck.' },
    { sel: '#add-widget', title: 'Add a widget', body: 'Drop any panel onto the current deck.' },
    { sel: '#range', title: 'Time window', body: 'One range for every panel on the deck, from the last hour to everything.' },
    { sel: '#ops-feeds', title: 'Source health', body: 'Whether the sources behind these panels are healthy. Click it for Settings › Sources.' },
  ],
  news: [
    { sel: tab('news'), title: 'News', body: 'You’re in the News tab: security reporting clustered into stories, so one incident covered by five outlets reads as one card.' },
    { sel: '.nw-feeds', title: 'Views', body: 'All stories, what’s new today, stories with several sources, and your watchlist.' },
    { sel: '.nw-rail-sec', has: 'watchlist', title: 'Watchlist', body: 'Follow an actor, malware family, CVE or any keyword and get a digest of matching stories.' },
    { sel: '.nw-sbox', title: 'Search the news', body: 'Keyword and semantic search across every article on the desk.' },
    { sel: '.nw-fbar', tight: true, title: 'Filters', body: 'Narrow to stories that mention a CVE, an actor, malware, a campaign, a vendor or an address or domain named in the story (an <span data-term="ioc">IOC</span>).' },
    { sel: '.nw-card', title: 'A story', body: 'Sources and trust tiers on the left; the merged headline, timeline and summary on the right. Open it to read every article.' },
    { sel: '.nw-rail-sec', has: 'sources', title: 'Outlets', body: 'Every outlet with its trust tier (A–D) and article count. Click one to filter.' },
  ],
  entities: [
    { sel: tab('entities'), title: 'Intel', body: 'You’re in Intel: every actor, malware family, tool, campaign and indicator the desk has extracted, with the claims that tie them together.' },
    { sel: '.en-tabs', title: 'Views', body: 'The same data as a directory or a link graph, plus <b>Review</b>: likely duplicates, contested attributions and claims you disagreed with.' },
    { sel: '.en-types', title: 'Entity types', body: 'Browse by type: threats, infrastructure, vulnerabilities and more, with counts.' },
    { sel: '.en-dir-h', title: 'Sort and filter', body: 'Filter the directory by name, alias or value and change the sort. Generic placeholder names are hidden by default so real actors stay visible.' },
    { sel: '.en-rows .en-row', with: '.en-row-h', pop: false, title: 'An entity', body: '26 weeks of activity, mentions, claims and confidence at a glance. Open it for the full profile and evidence.' },
  ],
  network: [
    { sel: tab('network'), title: 'Network', body: 'You’re in Network: analysis of your own Zeek, Suricata and DNS logs. Import only; the desk never scans anything.' },
    { sel: '.nv-tabs', title: 'Sections', body: 'An overview, triaged alerts, searching your logs, the devices on your network, and <b>Connect logs</b>: import files, let a device upload, or try the demo.' },
    { sel: '.nv-kpis > :first-child', title: 'Untriaged alerts', body: 'Alerts waiting for a look in the selected range, by severity.' },
    { sel: '.nv-g-tl > :first-child', title: 'Connections and alerts', body: 'Traffic and alerts per hour. Drag across the chart to zoom into a window.' },
    { sel: '.nv-g3 > :first-child', title: 'Top talkers', body: 'The hosts on your network that moved the most data.' },
  ],
  // the SQL console while it is off (OSINTHUB_SQL_CONSOLE unset): Explorer only shows how to turn it on
  'explorer-off': [
    { sel: '.ex-off', title: 'SQL console', body: 'The SQL console is off. Start Night Desk with OSINTHUB_SQL_CONSOLE=1 to turn it on. It is a power tool for read-only SQL over the lake; nothing else in Night Desk needs it.' },
  ],
  explorer: [
    { sel: '#gear-btn', title: 'SQL console', body: 'You’re in the SQL console: an analyst workbench straight onto the DuckDB lake. Open it any time from the gear menu or with <kbd>⌘K</kbd>.' },
    { sel: '.ex-examples', tight: true, title: 'Examples', body: 'One-click starter queries to learn the tables.' },
    { sel: '.ex-editor', with: '.ex-actions', title: 'Write SQL', body: 'Query events, sources, entities and more. <kbd>⌘↵</kbd> runs it.' },
    { sel: '.ex-pnl-chart', title: 'Auto-chart', body: 'Results chart themselves when the shape fits: time series, bars or categories.' },
    { sel: '.ex-pnl-table', title: 'Results', body: 'The raw rows with typed columns, ready to export as CSV.' },
  ],
  cinema: [
    { sel: tab('cinema'), title: 'Cinema', body: 'You’re in Cinema: a lean-back globe that tours the most notable real events on autopilot. For a wall screen, use kiosk mode (add <b>?kiosk</b> to the Cinema link): no menus, Esc leaves it.' },
    { sel: '.cinema-focus', title: 'In focus', body: 'The event the globe is on right now: what happened, where, the source, address and network owner.' },
    { sel: '.cinema-stack', title: 'Up next', body: 'Recent notable events. Click one to fly straight to it.' },
    { sel: '.cinema-vh .vh-end', tight: true, pad: 5, title: 'Controls', body: 'Pause or resume autopilot, step to the previous or next event, and switch between the last 24 hours and 7 days.' },
    { sel: '.cinema-scrub', title: 'Timeline', body: 'Events across the window by severity. Drag to scrub through time.' },
  ],
  settings: [
    { sel: '.set-nav', title: 'Settings', body: 'One place for what Night Desk fetches, keeps and shows: sources, your home network, retention, display and version details.' },
    { sel: '#set-choose', title: 'Choose your sources', body: 'Each source with what it gives and its terms. Open ones are ticked; personal-use and unclear ones wait for you.' },
    { sel: '.src-kpis', title: 'At a glance', body: 'Records collected, which sources are healthy, disk used and the last update.' },
    { sel: '#src-pipeline-sec', title: 'Behind the scenes', body: 'The optional AI helper, the search index, article fetching, Intel and log matching, all running on this machine.' },
    { sel: '.src-card', title: 'A source', body: 'Health, cadence and run history. Switch it on or off, or run it now.' },
    { sel: '#src-upload-sec', title: 'Add your own file', body: 'Drop in a CSV or JSON of your own addresses or events.' },
  ],
};

// ---------------------------------------------------------------- geometry
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const ease = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
const lerp = (a, b, t) => a + (b - a) * t;
const lerpAngle = (a, b, t) => a + Math.atan2(Math.sin(b - a), Math.cos(b - a)) * t;
const rectArea = (a, b) => Math.max(0, Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x)) * Math.max(0, Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y));
const rectGap = (a, b) => Math.hypot(Math.max(b.x - (a.x + a.w), 0, a.x - (b.x + b.w)), Math.max(b.y - (a.y + a.h), 0, a.y - (b.y + b.h)));

// Shown and on screen sideways: an off-canvas element (the News rail behind its menu button on a phone, a closed
// drawer) counts as hidden, so its step is skipped instead of lighting a sliver at the screen edge. Vertical position
// is not checked: targets below the fold are scrolled into view.
function visible(el) {
  if (!el || !el.getClientRects().length) return false;
  const r = el.getBoundingClientRect();
  return r.width > 4 && r.height > 4 && Math.min(r.right, innerWidth) - Math.max(r.left, 0) > 4;
}

function findOne(step) {
  const want = step.has && step.has.toLowerCase();
  for (const el of document.querySelectorAll(step.sel)) {
    if (!visible(el)) continue;
    if (want) {
      const t = ((step.hasSel ? el.querySelector(step.hasSel)?.textContent : el.textContent) || '').toLowerCase();
      if (!t.includes(want)) continue;
    }
    return el;
  }
  return null;
}
// A step is one target, or (alt) a list of targets tried in order, each with its own copy.
function pick(step) {
  for (const v of step.alt || [step]) { const el = findOne(v); if (el) return { el, v: { ...step, ...v } }; }
  return null;
}
const find = (step) => pick(step)?.el || null;
// The copy of a step as it applies now (the alternative that is on screen; text that depends on the width).
const copyOf = (step) => { const v = pick(step)?.v || step; return { title: v.title, body: typeof v.body === 'function' ? v.body() : v.body }; };

// The lit area: the component's box, or (tight) the union of what's actually inside it, for wide bars
// that hold a few small controls. Padded, then kept fully on screen.
function litRect(el, tight, step = {}) {
  let r = el.getBoundingClientRect();
  const extra = step.with && document.querySelector(step.with);
  if (extra && visible(extra)) {
    const e = extra.getBoundingClientRect();
    r = { left: Math.min(r.left, e.left), top: Math.min(r.top, e.top), right: Math.max(r.right, e.right), bottom: Math.max(r.bottom, e.bottom) };
  }
  if (tight) {
    const kids = [...el.children].map((c) => c.getBoundingClientRect()).filter((k) => k.width > 2 && k.height > 2);
    if (kids.length) {
      r = { left: Math.min(...kids.map((k) => k.left)), top: Math.min(...kids.map((k) => k.top)),
            right: Math.max(...kids.map((k) => k.right)), bottom: Math.max(...kids.map((k) => k.bottom)) };
    }
  }
  const pad = step.pad ?? PAD;
  const x1 = Math.max(r.left - pad, 8), y1 = Math.max(r.top - pad, 8);
  const x2 = Math.min(r.right + pad, innerWidth - 8), y2 = Math.min(r.bottom + pad, innerHeight - 8);
  return { x: x1, y: y1, w: Math.max(12, x2 - x1), h: Math.max(12, y2 - y1) };
}

// How busy the page is under a point: text and controls count fully, maps/charts/canvas partly,
// bare panel and page background not at all. (The overlay is hidden while sampling.)
function clutterAt(x, y) {
  const el = document.elementFromPoint(x, y);
  if (!el || el === document.body || el === document.documentElement) return 0;
  if (el.closest('button, a, input, select, textarea, label, kbd, code, .vx-chip, ent-chip')) return 1;
  if (el.closest('canvas, svg, img, video')) return 0.5;
  for (const n of el.childNodes) if (n.nodeType === 3 && n.textContent.trim()) return 1;
  return 0;
}
function clutter(x, y) {
  const r = S * 0.42;
  let c = 0;
  for (const [dx, dy] of [[0, 0], [-r, -r], [r, -r], [-r, r], [r, r], [0, -r], [0, r], [-r, 0], [r, 0]]) c += clutterAt(x + dx, y + dy);
  return c;
}

// The face of R the lamp at (lx, ly) shines on, as its two corners (in order along the face).
function faceOf(lx, ly, R) {
  if (ly <= R.y) return [[R.x, R.y], [R.x + R.w, R.y]];
  if (ly >= R.y + R.h) return [[R.x, R.y + R.h], [R.x + R.w, R.y + R.h]];
  if (lx <= R.x) return [[R.x, R.y], [R.x, R.y + R.h]];
  return [[R.x + R.w, R.y], [R.x + R.w, R.y + R.h]];
}
const aimAt = (lx, ly, R) => { const [a, b] = faceOf(lx, ly, R); return Math.atan2((a[1] + b[1]) / 2 - ly, (a[0] + b[0]) / 2 - lx); };

// Where the lamp stands: square-on to one face of the component (above preferred, then the sides, then
// below), at the throw that spills least light outside it. Small components may slide a little along
// the face to find open ground; wide ones stay centered. Never in the top bar unless the component is
// below it; top-bar items are lit from the open space beneath them.
function placeLamp(R) {
  const vw = innerWidth, vh = innerHeight, m = S / 2 + 8;
  const sub = document.getElementById('subbar');
  const bar = Math.max(document.querySelector('.topbar')?.getBoundingClientRect().bottom || 46, sub && visible(sub) ? sub.getBoundingClientRect().bottom : 0);
  const inBar = R.y + R.h <= bar + PAD + 6;
  const compact = R.w < R.h * 2.6 && R.h < R.w * 2.6;
  const mouthW = 2 * MOUTH_HW;
  root.style.display = 'none';
  let best = null;
  for (const [nx, ny, pen] of [[0, -1, 0], [1, 0, 10], [-1, 0, 10], [0, 1, 18]]) {
    const span = nx ? R.h : R.w;
    for (const t of compact ? [88, 108, 130] : [76, 90]) {
      for (const slide of [0]) {
        const lx = nx ? (nx > 0 ? R.x + R.w + t : R.x - t) : R.x + R.w / 2 + slide * span;
        const ly = ny ? (ny > 0 ? R.y + R.h + t : R.y - t) : R.y + R.h / 2 + slide * span;
        if (lx < m || lx > vw - m || ly < m || ly > vh - m) continue;      // no room on this side
        const [f1, f2] = faceOf(lx, ly, R);
        const flen = Math.hypot(f2[0] - f1[0], f2[1] - f1[1]);
        const spill = (t - MOUTH) * (flen + mouthW) / 2 / 1000;
        const fan = Math.abs(Math.atan2(Math.sin(Math.atan2(f2[1] - ly, f2[0] - lx) - Math.atan2(f1[1] - ly, f1[0] - lx)), Math.cos(Math.atan2(f2[1] - ly, f2[0] - lx) - Math.atan2(f1[1] - ly, f1[0] - lx)))) * 180 / Math.PI;
        let score = pen + Math.abs(slide) * 20 + spill * 0.35 + t * 0.07;
        if (compact) score += Math.abs(fan - 55) * 0.35;
        if (fan < 18) score += 30;
        if (ly - S / 2 < bar) score += inBar ? 900 : 140;
        score += clutter(lx, ly) * 14;
        if (!best || score < best.score) best = { x: lx, y: ly, score };
      }
    }
  }
  root.style.display = '';
  // no open ground around the component (it fills the screen): the lamp would sit on the lit text, so it is hidden
  return best ? { x: best.x, y: best.y, room: true } : { x: clamp(R.x + R.w / 2, m, vw - m), y: clamp(R.y + R.h + 110, m, vh - m), room: false };
}

// Convex hull (monotone chain).
function hull(pts) {
  const p = pts.slice().sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const cross = (o, a, b) => (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0]);
  const lower = [], upper = [];
  for (const q of p) { while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], q) <= 0) lower.pop(); lower.push(q); }
  for (let i = p.length - 1; i >= 0; i--) { const q = p[i]; while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], q) <= 0) upper.pop(); upper.push(q); }
  return lower.slice(0, -1).concat(upper.slice(0, -1));
}

// Area of a convex polygon inside a rectangle (Sutherland-Hodgman, then shoelace).
function polyRectArea(poly, r) {
  let out = poly;
  const edges = [[(p) => p[0] >= r.x, (a, b) => { const t = (r.x - a[0]) / (b[0] - a[0]); return [r.x, a[1] + t * (b[1] - a[1])]; }],
    [(p) => p[0] <= r.x + r.w, (a, b) => { const t = (r.x + r.w - a[0]) / (b[0] - a[0]); return [r.x + r.w, a[1] + t * (b[1] - a[1])]; }],
    [(p) => p[1] >= r.y, (a, b) => { const t = (r.y - a[1]) / (b[1] - a[1]); return [a[0] + t * (b[0] - a[0]), r.y]; }],
    [(p) => p[1] <= r.y + r.h, (a, b) => { const t = (r.y + r.h - a[1]) / (b[1] - a[1]); return [a[0] + t * (b[0] - a[0]), r.y + r.h]; }]];
  for (const [inside, cut] of edges) {
    const src = out; out = [];
    for (let i = 0; i < src.length; i++) {
      const a = src[i], b = src[(i + 1) % src.length];
      if (inside(b)) { if (!inside(a)) out.push(cut(a, b)); out.push(b); } else if (inside(a)) out.push(cut(a, b));
    }
    if (!out.length) return 0;
  }
  let s = 0; for (let i = 0; i < out.length; i++) { const a = out[i], b = out[(i + 1) % out.length]; s += a[0] * b[1] - b[0] * a[1]; }
  return Math.abs(s) / 2;
}

function beamPoly(st) {
  const ux = Math.cos(st.a), uy = Math.sin(st.a);
  const mx = st.lx + ux * MOUTH * st.sc, my = st.ly + uy * MOUTH * st.sc, hw = MOUTH_HW * st.sc;
  const p1 = [mx - uy * hw, my + ux * hw], p2 = [mx + uy * hw, my - ux * hw];
  const [f1, f2] = faceOf(st.lx, st.ly, st.R);
  const far = Math.max(...[f1, f2].map(([x, y]) => (x - mx) * ux + (y - my) * uy));
  return { poly: hull([p1, p2, f1, f2]), mx, my, ux, uy, far, f1, f2 };
}

// The explanation card sits right beside the component, on the side that hides least of the
// component, the lamp and the beam. A detached card is the last resort.
function placeCard(st, pw, ph) {
  const vw = innerWidth, vh = innerHeight, g = 16, R = st.R;
  // a phone: the card sits above the bottom layer (or at the top when the lit part is down there and it would cover it)
  if (phoneNow()) {
    const layer = [...document.querySelectorAll('#m-tabbar, #m-actbar')].map((b) => b.getBoundingClientRect()).filter((r) => r.height > 0);
    const floor = Math.min(vh, ...layer.map((r) => r.top)) - 12;
    const low = { x: 12, y: Math.max(12, floor - ph) };
    if (rectArea({ ...low, w: pw, h: ph }, R) === 0) return low;
    const topY = Math.max(12, Math.min(R.y - ph - g, floor - ph));
    if (rectArea({ x: 12, y: topY, w: pw, h: ph }, R) === 0) return { x: 12, y: topY };
    // a tall lit part fills the screen: the card stays above the bottom layer, over the lit part's lower edge
    return low;
  }
  const { poly } = beamPoly(st);
  const lampBox = { x: st.lx - S * 0.75 * st.sc, y: st.ly - S * 0.75 * st.sc, w: S * 1.5 * st.sc, h: S * 1.5 * st.sc };
  const xs = [R.x + R.w / 2 - pw / 2, R.x, R.x + R.w - pw, R.x - pw * 0.6, R.x + R.w - pw * 0.4];
  const ys = [R.y + R.h / 2 - ph / 2, R.y, R.y + R.h - ph, R.y - ph * 0.6, R.y + R.h - ph * 0.4];
  const cand = [];
  for (const x of xs) { cand.push([x, R.y + R.h + g, 0]); cand.push([x, R.y - ph - g, 0]); }
  for (const y of ys) { cand.push([R.x + R.w + g, y, 0]); cand.push([R.x - pw - g, y, 0]); }
  cand.push([(vw - pw) / 2, vh - ph - 24, 4000], [(vw - pw) / 2, 70, 4000]);
  let best = null;
  for (const [x0, y0, pen] of cand) {
    const x = clamp(x0, 12, vw - pw - 12), y = clamp(y0, 12, vh - ph - 12);
    const box = { x, y, w: pw, h: ph };
    const score = pen + rectArea(box, R) * 3 + rectArea(box, lampBox) * 3 + polyRectArea(poly, box) * 0.6
      + rectGap(box, R) * 14 + Math.hypot(x - x0, y - y0) * 2;
    if (!best || score < best.score) best = { x, y, score };
  }
  return best;
}

// ---------------------------------------------------------------- rendering
let root = null, steps = [], idx = 0, st = null, raf = 0, popped = null, saved = null, reduce = false, card = null, ending = false;

// ---------------------------------------------------------------- modality
// The card is a modal dialog: while the tour runs everything else on the page is inert (out of the Tab order and
// deaf to clicks), Tab cycles the card's buttons, and the page's own single-key shortcuts do not act behind it.
// Only nodes this module made inert are restored, so a closed drawer or panel stays inert.
let inerted = [];
function setInert(on) {
  if (on) {
    inerted = [...document.body.children].filter((n) => n !== root && !n.inert && !/^(SCRIPT|STYLE|TEMPLATE)$/.test(n.tagName));
    for (const n of inerted) n.inert = true;
  } else {
    for (const n of inerted) n.inert = false;
    inerted = [];
  }
}
const cardButtons = () => [...card.querySelectorAll('button')].filter((b) => b.style.visibility !== 'hidden' && b.getClientRects().length);
function trapTab(e) {
  e.preventDefault(); e.stopPropagation();
  const f = cardButtons();
  if (!f.length) { card.focus({ preventScroll: true }); return; }
  const i = f.indexOf(document.activeElement);
  const n = i < 0 ? (e.shiftKey ? f.length - 1 : 0) : (i + (e.shiftKey ? -1 : 1) + f.length) % f.length;
  f[n].focus({ preventScroll: true });
}

// Where focus lands when the tour is closed by the user: the lit control when it takes focus, else the heading of
// the page the tour explained (made focusable for the moment), else where focus was before the tour.
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
let before = null;
function focusAfter(lit) {
  const ok = (el) => el && el.isConnected && !el.closest('[inert]') && el.getClientRects().length;
  if (ok(lit) && lit.matches(FOCUSABLE)) { lit.focus({ preventScroll: true }); return; }
  const h = [...document.querySelectorAll('.view.active h1, .view.active .vh-title, #subbar:not([hidden]) .vh-title, .view.active h2')].find(ok);
  if (h) {
    if (!h.matches(FOCUSABLE) && !h.hasAttribute('tabindex')) {
      h.tabIndex = -1;
      h.addEventListener('blur', () => h.removeAttribute('tabindex'), { once: true });
    }
    h.focus({ preventScroll: true });
    return;
  }
  if (ok(before)) before.focus({ preventScroll: true });
}

function build() {
  root = document.createElement('div');
  root.className = phoneNow() ? 'tour-root tour-m' : 'tour-root';
  root.innerHTML = `
    <div class="tour-dim"></div>
    <div class="tour-pool"></div>
    <svg class="tour-beam" aria-hidden="true">
      <defs>
        <linearGradient id="tour-beam-g" gradientUnits="userSpaceOnUse">
          <stop offset="0" stop-color="rgb(var(--accent-rgb))" stop-opacity=".55"/>
          <stop class="tour-beam-mid" offset=".22" stop-color="rgb(var(--accent-rgb))" stop-opacity=".22"/>
          <stop offset="1" stop-color="rgb(var(--accent-rgb))" stop-opacity=".2"/>
        </linearGradient>
        <filter id="tour-beam-f" x="-10%" y="-10%" width="120%" height="120%"><feGaussianBlur stdDeviation="4"/></filter>
        <mask id="tour-out" maskUnits="userSpaceOnUse"><rect class="tm-all" fill="#fff"/><rect class="tm-hole" rx="10" fill="#000"/></mask>
      </defs>
      <polygon class="tour-beam-base" mask="url(#tour-out)"/>
      <polygon class="tour-beam-p" fill="url(#tour-beam-g)" mask="url(#tour-out)" filter="url(#tour-beam-f)"/>
      <line class="tour-landing"/>
      <rect class="tour-lit" rx="10"/>
    </svg>
    <div class="tour-ring"></div>
    <div class="tour-lamp">${LAMP}</div>
    <div class="tour-card" role="dialog" aria-modal="true" aria-labelledby="tour-title" aria-describedby="tour-body" tabindex="-1">
      <div class="tour-step mono"></div>
      <h4 id="tour-title"></h4>
      <p class="tour-body" id="tour-body"></p>
      <div class="tour-nav">
        <div class="tour-dots"></div>
        <div class="tour-btns">
          <button class="tour-skip">Skip</button>
          <button class="tour-back">Back</button>
          <button class="tour-next">Next</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(root);
  card = root.querySelector('.tour-card');
  root.querySelector('.tour-skip').onclick = () => end({ refocus: true });
  root.querySelector('.tour-back').onclick = () => go(idx - 1);
  root.querySelector('.tour-next').onclick = () => (idx >= steps.length - 1 ? end({ refocus: true }) : go(idx + 1));
  root.querySelector('.tour-dots').innerHTML = steps.map((_, i) => `<i data-i="${i}"></i>`).join('');
  root.querySelectorAll('.tour-dots i').forEach((d) => (d.onclick = () => go(+d.dataset.i)));
}

function render(s) {
  const vw = innerWidth, vh = innerHeight, R = s.R, rr = 10;
  // grayed + darkened everywhere except a rounded window over the component
  root.querySelector('.tour-dim').style.clipPath = `path(evenodd, "M0 0H${vw}V${vh}H0Z M${R.x + rr} ${R.y}H${R.x + R.w - rr}A${rr} ${rr} 0 0 1 ${R.x + R.w} ${R.y + rr}V${R.y + R.h - rr}A${rr} ${rr} 0 0 1 ${R.x + R.w - rr} ${R.y + R.h}H${R.x + rr}A${rr} ${rr} 0 0 1 ${R.x} ${R.y + R.h - rr}V${R.y + rr}A${rr} ${rr} 0 0 1 ${R.x + rr} ${R.y}Z")`;
  Object.assign(root.querySelector('.tour-ring').style, { left: R.x + 'px', top: R.y + 'px', width: R.w + 'px', height: R.h + 'px', opacity: s.ring });
  // beam: lamp mouth -> component corners, drawn outside the component; inside, an even warm wash
  const b = beamPoly(s);
  const svg = root.querySelector('.tour-beam');
  svg.setAttribute('viewBox', `0 0 ${vw} ${vh}`);
  const far = Math.max(b.far, 1);
  const g = svg.querySelector('#tour-beam-g');
  g.setAttribute('x1', b.mx); g.setAttribute('y1', b.my);
  g.setAttribute('x2', b.mx + b.ux * far); g.setAttribute('y2', b.my + b.uy * far);
  svg.querySelector('.tour-beam-mid').setAttribute('offset', clamp(80 / Math.max(far, 1), 0.05, 0.5));
  const all = svg.querySelector('.tm-all'); all.setAttribute('width', vw); all.setAttribute('height', vh);
  for (const h of svg.querySelectorAll('.tm-hole, .tour-lit')) { h.setAttribute('x', R.x); h.setAttribute('y', R.y); h.setAttribute('width', R.w); h.setAttribute('height', R.h); }
  const pts = b.poly.map((q) => q.join(',')).join(' ');
  const over = s.beam * s.lamp;   // the cone, its landing line and the pool: lit on a step, unless the lamp has no room
  for (const el of svg.querySelectorAll('.tour-beam-p, .tour-beam-base')) { el.setAttribute('points', pts); el.style.opacity = over; }
  const ln = svg.querySelector('.tour-landing');
  ln.setAttribute('x1', b.f1[0]); ln.setAttribute('y1', b.f1[1]); ln.setAttribute('x2', b.f2[0]); ln.setAttribute('y2', b.f2[1]);
  ln.style.opacity = over;
  svg.querySelector('.tour-lit').style.opacity = s.beam;
  // a pool of shadow under the lamp lifts it off whatever UI it stands over
  Object.assign(root.querySelector('.tour-pool').style, { transform: `translate(${s.lx - 70}px, ${s.ly - 70}px) scale(${0.4 + 0.6 * s.sc})`, opacity: over });
  // lamp: rotate so its local +y (the way the mouth faces) points along the beam
  root.querySelector('.tour-lamp').style.transform =
    `translate(${s.lx - S / 2}px, ${s.ly - S / 2}px) rotate(${s.a - Math.PI / 2}rad) scale(${s.sc})`;
  root.querySelector('.tour-lamp').style.opacity = s.lamp;
}

function stateFor(el, step) {
  const R = litRect(el, step && step.tight, step || {});
  const L = placeLamp(R);
  return { R, lx: L.x, ly: L.y, a: aimAt(L.x, L.y, R), sc: clamp(Math.max(R.w, R.h) / 160, 0.72, 1), beam: 1, ring: 1, lamp: L.room ? 1 : 0 };
}

function tween(from, to, dur, done) {
  cancelAnimationFrame(raf);
  if (reduce || dur <= 0) { st = to; render(st); done && done(); return; }
  const t0 = performance.now();
  const frame = (now) => {
    const t = ease(Math.min(1, (now - t0) / dur));
    st = {
      R: { x: lerp(from.R.x, to.R.x, t), y: lerp(from.R.y, to.R.y, t), w: lerp(from.R.w, to.R.w, t), h: lerp(from.R.h, to.R.h, t) },
      lx: lerp(from.lx, to.lx, t), ly: lerp(from.ly, to.ly, t), a: lerpAngle(from.a, to.a, t),
      sc: lerp(from.sc, to.sc, t), beam: lerp(from.beam, to.beam, t), ring: lerp(from.ring, to.ring, t), lamp: lerp(from.lamp, to.lamp, t),
    };
    render(st);
    if (t < 1) raf = requestAnimationFrame(frame); else done && done();
  };
  raf = requestAnimationFrame(frame);
}

// Live components can shift while the lamp is moving; re-measure once it lands and snap the light to them.
function settle(el, step, done) {
  const R = litRect(el, step && step.tight, step || {});
  if (Math.abs(R.x - st.R.x) + Math.abs(R.y - st.R.y) + Math.abs(R.w - st.R.w) + Math.abs(R.h - st.R.h) < 3) return done();
  tween(st, stateFor(el, step), 240, done);
}

function unpop() {
  if (!popped) return;
  popped.style.transform = saved.transform;
  setTimeout(((el, tr) => () => { el.style.transition = tr; })(popped, saved.transition), 420);
  popped = null;
}
function pop(el) {
  if (steps[idx] && steps[idx].pop === false) return;
  const r = el.getBoundingClientRect();
  let k = clamp(1 + 14 / Math.max(r.width, r.height), 1.008, 1.05);
  // never grow past the lit window: the lit rect is clamped to the viewport margin, so a component near
  // the screen edge (the News rail) would otherwise scale under the ring and the dim, clipping its text
  const R = st && st.R, m = 4;
  if (R) {
    const cx = r.left + r.width / 2, cy = r.top + r.height / 2, hw = r.width / 2, hh = r.height / 2;
    k = Math.max(1, Math.min(k, (cx - R.x - m) / hw, (R.x + R.w - m - cx) / hw, (cy - R.y - m) / hh, (R.y + R.h - m - cy) / hh));
  }
  if (k <= 1.001) return;
  popped = el; saved = { transform: el.style.transform, transition: el.style.transition };
  el.style.transition = `${saved.transition ? saved.transition + ', ' : ''}transform .4s cubic-bezier(.3,.8,.3,1)`;
  el.style.transform = `${saved.transform} scale(${k})`.trim();
}

function showCard(s) {
  const step = steps[idx];
  root.querySelector('.tour-step').textContent = `${idx + 1} / ${steps.length}`;
  const copy = copyOf(step);
  root.querySelector('#tour-title').textContent = copy.title;
  root.querySelector('.tour-body').innerHTML = copy.body;
  root.querySelector('.tour-back').style.visibility = idx === 0 ? 'hidden' : 'visible';
  root.querySelector('.tour-next').textContent = idx >= steps.length - 1 ? 'Done' : 'Next';
  root.querySelectorAll('.tour-dots i').forEach((d, j) => d.classList.toggle('on', j === idx));
  const c = placeCard(s, card.offsetWidth, card.offsetHeight);
  Object.assign(card.style, { left: c.x + 'px', top: c.y + 'px' });
  card.classList.add('show');
  root.querySelector('.tour-next').focus({ preventScroll: true });
}

// Bring the component on screen by scrolling its own scroll container vertically (never sideways, and
// never the page itself): centred when it fits, top-aligned when it is taller than the view.
function reveal(el) {
  for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
    const oy = getComputedStyle(p).overflowY;
    if ((oy === 'auto' || oy === 'scroll') && p.scrollHeight > p.clientHeight + 2) {
      const pr = p.getBoundingClientRect(), r = el.getBoundingClientRect();
      const want = r.height < pr.height * 0.8 ? (pr.height - r.height) / 2 : 12;
      p.scrollTop += (r.top - pr.top) - want;
      return;
    }
  }
}

// The view this tour explains; if the page under it changes, the tour ends rather than lighting nothing.
const activeView = () => document.querySelector('.view.active')?.dataset.view;
let tourView = null;

function go(i) {
  if (!root || ending) return;
  if (activeView() !== tourView) { end(); return; }
  // walk (iteratively, bounded by the step count) to the nearest step in this direction whose target is on screen
  const dir = i < idx ? -1 : 1;
  let el = null;
  for (i = clamp(i, 0, steps.length - 1); i >= 0 && i < steps.length; i += dir) {
    el = find(steps[i]);
    if (el) break;
  }
  if (!el) { if (!find(steps[idx])) end(); return; } // nothing further this way: stay, or end if the current target is gone too
  idx = i;
  card.classList.remove('show');
  unpop();
  reveal(el);
  const to = stateFor(el, steps[i]);
  const from = st;
  tween(from, to, from ? DUR : 0, () => { if (root && !ending && idx === i) settle(el, steps[i], () => { if (root && !ending && idx === i) { pop(el); showCard(st); } }); });
}

function brandMark() {
  const m = document.querySelector('.brand-mark') || document.querySelector('.brand');
  const r = m.getBoundingClientRect();
  return { x: r.left + r.width / 2, y: r.top + r.height / 2, sc: clamp(r.width / S, 0.3, 1) };
}
const homeState = () => { const bm = brandMark(); return { R: { x: bm.x - 12, y: bm.y - 12, w: 24, h: 24 }, lx: bm.x, ly: bm.y, a: Math.PI / 2, sc: bm.sc, beam: 0, ring: 0, lamp: 1 }; };

// Window, capture phase: runs before the page's own key handlers.
let keyHeld = false;
function onKey(e) {
  if (e.key === 'Tab') { trapTab(e); return; }
  if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); end({ refocus: true }); return; }
  if (e.key === 'ArrowRight') { e.preventDefault(); e.stopPropagation(); (idx >= steps.length - 1 ? end({ refocus: true }) : go(idx + 1)); return; }
  if (e.key === 'ArrowLeft') { e.preventDefault(); e.stopPropagation(); go(idx - 1); return; }
  // keep focus in the card (a click on the dim leaves it on BODY), and keep the page's shortcuts from acting behind it;
  // the key's own default (Enter or Space on a card button) still happens
  if (!card.contains(document.activeElement)) { e.preventDefault(); card.focus({ preventScroll: true }); }
  if (!e.metaKey && !e.ctrlKey) e.stopPropagation();
  keyHeld = true;
}
const onKeyUp = () => { keyHeld = false; };
function onResize() {
  if (!root || ending) return;
  if (activeView() !== tourView) { end(); return; }
  const el = find(steps[idx]); if (!el) return;
  unpop(); st = stateFor(el, steps[idx]); render(st); pop(el); showCard(st);
}

export function startTour(kind = 'page') {
  if (root) return true;
  reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const view = activeView();
  const page = PAGES[view === 'explorer' && !sqlConsoleOn() ? 'explorer-off' : view] || [];
  // on a phone the first visit, and the tour of Watch, are the phone tour
  const wanted = phoneNow() && (kind === 'first' || view === 'watch') ? PHONE_INTRO : kind === 'first' ? INTRO : page;
  steps = wanted.filter((s) => find(s));
  if (!steps.length) return false;   // nothing on this page to show (callers say so)
  tourView = view;
  before = document.activeElement;
  build();
  setInert(true);
  card.focus({ preventScroll: true });
  // The lamp leaves the logo: it starts as the brand mark (pointing down, logo-sized, beam off).
  st = homeState();
  render(st);
  requestAnimationFrame(() => root.classList.add('show'));
  idx = 0;
  const first = find(steps[0]);
  reveal(first);
  tween(st, stateFor(first, steps[0]), reduce ? 0 : DUR + 180, () => { if (root && !ending && idx === 0) settle(first, steps[0], () => { if (root && !ending && idx === 0) { pop(first); showCard(st); } }); });
  addEventListener('keydown', onKey, true);
  addEventListener('keyup', onKeyUp, true);
  addEventListener('resize', onResize);
  addEventListener('hashchange', onNav);
  addEventListener('popstate', onNav);
  return true;
}

// Back/Forward or any #link changes what is under the tour: end it ("Take the tour" in "?" tours the new page).
function onNav() { end(); }

// refocus: the user closed it (Esc, Skip, Done), so focus moves to the lit control or the page heading. Ending
// because the page changed leaves focus to the router.
export function end({ refocus = false } = {}) {
  if (!root || ending) return;
  const lit = steps[idx] ? find(steps[idx]) : null;
  removeEventListener('keydown', onKey, true);
  removeEventListener('keyup', onKeyUp, true);
  removeEventListener('resize', onResize);
  removeEventListener('hashchange', onNav);
  removeEventListener('popstate', onNav);
  unpop();
  card.classList.remove('show');
  setInert(false);
  card.setAttribute('aria-hidden', 'true');
  if (refocus) {
    // after the key that closed it is released, so Space or Enter cannot also press what now has focus
    const go2 = () => focusAfter(lit);
    if (keyHeld) { let t = 0; const up = () => { clearTimeout(t); removeEventListener('keyup', up, true); setTimeout(go2); }; addEventListener('keyup', up, true); t = setTimeout(up, 700); }
    else go2();
  } else if (card.contains(document.activeElement)) document.activeElement.blur();
  keyHeld = false;
  try { localStorage.setItem(DONE_KEY, '1'); } catch (e) { /* private mode */ }
  ending = true;
  // the lamp flies home into the logo, then the overlay fades
  const r = root;
  tween(st, homeState(), reduce ? 0 : 480, () => {
    r.classList.remove('show');
    setTimeout(() => { r.remove(); if (root === r) { root = null; st = null; ending = false; } }, 280);
  });
}

// Debug view for tests: the current geometry and card box.
window.__ndTour = () => (root && st ? { idx, n: steps.length, title: copyOf(steps[idx]).title, st, card: card.getBoundingClientRect().toJSON(), cardShown: card.classList.contains('show') } : null);

// The first visit gets the three-step intro once, on Watch (now, or the first time Watch is opened).
export function initTour() {
  let seen = false;
  try { seen = localStorage.getItem(DONE_KEY) === '1'; } catch (e) { seen = false; }
  if (seen) return;
  const tryIntro = () => {
    if (activeView() !== 'watch' || document.body.classList.contains('shell-kiosk')) return false;
    // wait for the briefing to render (its masthead is the first step), at most ~6 s
    let n = 0;
    const wait = () => { if (root) return; if (document.querySelector('.watch-mast, .watch-m-answer') || ++n > 20) startTour('first'); else setTimeout(wait, 300); };
    setTimeout(wait, 1400);
    return true;
  };
  if (tryIntro()) return;
  const onHash = () => { if (activeView() === 'watch') { removeEventListener('hashchange', onHash); tryIntro(); } };
  addEventListener('hashchange', onHash);
}

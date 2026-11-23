// Entity graph (#entities/graph/<id>): start from one entity, click to expand. Edge style by origin
// (solid observed, dashed reported, dotted hypothesis, grey dashed same-article, teal your network), width by
// confidence, IP sets collapsed into ASN bubbles by the API, and an "as of" time slider over claim first-seen dates.
// Defaults (okf/architecture/web-client.md#entities-view): hypotheses off behind "Show hypotheses", techniques and
// tools not drawn until their legend group is switched on, no animation that runs by itself.
// Library: cytoscape@3.30.2, vendored in web/vendor/ (MIT). Loaded only from there: no CDN fallback (local-first).
import { api, esc, TYPES, tmeta, tcolor, typeOf, nameOf, shown, ORIGINS, predText, bandPill, hypPill, whyOf, fmtDate, GROUPS, HYPOTHESIS_WHY } from './common.js';
import { openEntity, VERDICT } from '../../core/entity-panel.js';
import { LABELS, fullLink, newTab } from '../../core/open.js';
import { accentColor } from '../../core/util.js';
import { emptyState as vEmpty, errorState as vError, stateAct as vAct } from '../../core/view.js';
import { isPhone } from '../../core/mobile.js';
import { addLayer } from '../../core/page.js';
import { openSheet, navigateFromSheet } from '../../core/sheet.js';

const CY_URLS = ['vendor/cytoscape@3.30.2/cytoscape.min.js'];
let cyLoad = null;
const loadCy = () => (window.cytoscape ? Promise.resolve(window.cytoscape) : (cyLoad ||= new Promise((ok, bad) => {
  const tryAt = (i) => {
    if (i >= CY_URLS.length) return bad(new Error('cytoscape could not be loaded (web/vendor/cytoscape@3.30.2 is missing)'));
    const s = document.createElement('script');
    s.src = CY_URLS[i]; s.onload = () => ok(window.cytoscape); s.onerror = () => { s.remove(); tryAt(i + 1); };
    document.head.append(s);
  };
  tryAt(0);
})));

// node glyphs (same paths as common.icon) as data-URI SVGs
const GLYPH = {
  actor: 'M12 3l7 4v5c0 4.5-3 8-7 9-4-1-7-4.5-7-9V7l7-4z', campaign: 'M5 21V4h10l-1.5 3.5L15 11H5',
  malware: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 3v5M12 16v5M4 7l4 3M16 14l4 3M4 17l4-3M16 10l4-3',
  tool: 'M14.5 5.5a4 4 0 0 0-5 5L4 16l4 4 5.5-5.5a4 4 0 0 0 5-5l-2.5 2.5-3-1-1-3z', technique: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  cve: 'M12 3l9 16H3zM12 10v4M12 17v.5', product: 'M4 7l8-4 8 4v10l-8 4-8-4zM4 7l8 4 8-4M12 11v10', vendor: 'M3 21h18M5 21V8l7-5 7 5v13M9 21v-6h6v6',
  ip: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18', domain: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  url: 'M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1', hash: 'M9 3L7 21M17 3l-2 18M4 8h17M3 16h17',
  asn: 'M5 5h5v5H5zM14 14h5v5h-5zM10 7.5h4.5v6.5', prefix: 'M5 5h5v5H5zM14 14h5v5h-5zM10 7.5h4.5v6.5', org: 'M4 21V5h10v16M14 9h6v12M7 9h4M7 13h4M7 17h4',
  sector: 'M4 20h16M6 20V10M10 20V6M14 20v-8M18 20V9', country: 'M5 21V4M5 4h11l-2 4 2 4H5', 'ip-group': 'M7 7a3 3 0 1 0 0 .1M17 7a3 3 0 1 0 0 .1M12 16a3 3 0 1 0 0 .1',
};
const glyph = (t) => `data:image/svg+xml;utf8,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="${GLYPH[t] || GLYPH.org}" fill="none" stroke="${tcolor(t)}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`)}`;
const GROUP_OF = (t) => (t === 'technique' ? 'Techniques' : t === 'tool' ? 'Tools' : t === 'ip-group' ? 'Observables' : TYPES[t]?.[2] || 'Context');
const FILTER_GROUPS = ['Threats', 'Arsenal', 'Tools', 'Techniques', 'Vulnerabilities', 'Observables', 'Context'];
// Techniques and tools turn an actor into a star of ATT&CK listings (the page's ATT&CK strip shows those): off until asked.
const DEFAULT_HIDDEN = ['Techniques', 'Tools'];
// Origin switches; hypotheses (inferred, same-article) have their own switch, off by default. Links seen on your
// network (origin local) are never hidden by a switch.
const ORIGIN_BTNS = ['observed', 'reported', 'user'];
const reduced = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

let G = null; // singleton state per pane

export async function showGraph(pane, rootId, ctx) {
  if (!G || G.pane !== pane) G = init(pane, ctx);
  G.ctx = ctx;
  pane.querySelector('.gr-none')?.remove();
  // a whole-pane state (nothing to graph, or the graph library did not load) over the canvas
  const paneState = (html) => { const d = document.createElement('div'); d.className = 'gr-none'; d.innerHTML = html; pane.append(d); };
  if (!rootId) {
    // default root: the most-mentioned actor
    const r = await api.get('/api/entities', { type: 'actor', sort: 'mentions', limit: 1 }).catch(() => null);
    rootId = r?.items?.[0]?.id;
    if (!rootId) {
      paneState(vEmpty({ title: 'No entities to graph yet', why: 'The graph links actors, malware, bugs and indicators. They are built from news articles and the ATT&CK reference data, and appear a few minutes after the first news run.', act: vAct('Open News', { href: '#news' }) + vAct('Open Sources', { href: '#settings/sources' }) }));
      return;
    }
    ctx.setRoot(rootId);
  }
  // a phone shows the root's connections as a list first; the canvas loads when "Open the graph" is tapped
  if (isPhone()) {
    G.want = rootId;
    phoneList(G, rootId);
    if (!G.$('.gr').classList.contains('gr-m-full')) return;
  } else {
    if (G.$('.gr').classList.contains('gr-m-full')) closeFull(G);
    pane.querySelector('.gr-m')?.remove();
  }
  if (G.root === rootId && G.cy) { G.cy.resize(); return; }
  let cytoscape;
  try { cytoscape = await loadCy(); } catch (e) { paneState(vError({ title: "Couldn't load the graph drawing library", why: 'It ships with Night Desk; a reload usually fixes this.', err: e.message, retry: () => location.reload(), retryLabel: 'Reload the page' })); return; }
  await setRoot(rootId, cytoscape);
}

function init(pane, ctx) {
  pane.innerHTML = `<div class="gr">
    <div class="gr-cv"></div>
    <div class="gr-msg mono" role="status" aria-live="polite"></div>
    <div class="gr-tl">
      <div class="gr-root"></div>
      <div class="gr-add"><svg class="i"><use href="#i-search"/></svg><input placeholder="Add or re-root on an entity…" spellcheck="false" aria-label="Add entity to graph"><div class="en-sugg" hidden></div></div>
      <button class="src-btn sm gr-ctl" type="button" aria-expanded="false" aria-controls="gr-fold" title="Layout, link filters, time and the type legend"><svg class="i"><use href="#i-layers"/></svg>Controls</button>
    </div>
    <aside class="gr-side" hidden></aside>
    <div class="gr-fold" id="gr-fold"><div class="gr-fold-h"><span class="label">Layout, links and types</span><button class="src-btn sm gr-fold-x" type="button">Done</button></div>
    <div class="gr-bar">
      <div class="gr-seg gr-lay" title="Layout"><button data-lay="cose" class="on">Force</button><button data-lay="concentric">Rings</button><button data-lay="breadthfirst">Tree</button></div>
      <button class="src-btn sm" data-a="fit" title="Fit to screen">Fit</button>
      <span class="gr-sep"></span>
      <div class="gr-origins">${ORIGIN_BTNS.map((o) => `<button class="on" data-o="${o}" title="${esc(ORIGINS[o].desc)}" aria-pressed="true"><svg width="26" height="8"><line x1="1" x2="25" y1="4" y2="4" class="gl o-${o}"/></svg>${esc(ORIGINS[o].label)}</button>`).join('')}</div>
      <span class="gr-sep"></span>
      <button class="gr-hyp" data-a="hyp" aria-pressed="false" title="${esc(HYPOTHESIS_WHY)}"><svg width="26" height="8"><line x1="1" x2="25" y1="4" y2="4" class="gl o-inferred"/></svg><span>Show hypotheses</span></button>
      <span class="gr-sep"></span>
      <label class="gr-conf" title="Hide links below this confidence"><span class="label">min conf</span><input type="range" min="0" max="0.9" step="0.05" value="0"><b class="mono">0</b></label>
      <span class="gr-sep"></span>
      <div class="gr-time"><input type="range" min="0" max="1000" value="1000" aria-label="Show links first seen up to" aria-valuetext="all time"><span class="mono gr-tv">all time</span></div>
    </div>
    <div class="gr-leg"></div></div>
  </div>`;
  const bar = pane.querySelector('.gr-bar');
  new ResizeObserver(() => pane.querySelector('.gr').style.setProperty('--gr-bar-h', `${bar.offsetHeight}px`)).observe(bar);
  // Short screens (200 % zoom, a phone on its side): the controls bar and the legend fold behind "Controls", so the
  // graph keeps the height; the button says whether they are shown (CSS hides it, and shows both, on taller screens).
  // Open, they lie over the graph below the search row (the graph keeps its size underneath); "Done", the Controls
  // button again or Esc fold them away and focus returns to Controls.
  const ctl = pane.querySelector('.gr-ctl');
  const fold = (on, refocus = false) => {
    ctl.setAttribute('aria-expanded', String(on));
    pane.querySelector('.gr').classList.toggle('gr-ctl-on', on);
    if (refocus) ctl.focus({ preventScroll: true });
  };
  ctl.addEventListener('click', () => fold(ctl.getAttribute('aria-expanded') !== 'true'));
  pane.querySelector('.gr-fold-x').addEventListener('click', () => fold(false, true));
  pane.querySelector('.gr-fold').addEventListener('keydown', (e) => { if (e.key === 'Escape' && ctl.getAttribute('aria-expanded') === 'true') { e.stopPropagation(); fold(false, true); } });
  const S = { pane, ctx, cy: null, root: null, expanded: new Set(), hiddenGroups: new Set(DEFAULT_HIDDEN), origins: new Set(ORIGIN_BTNS), hyp: false, minConf: 0, tCut: null, tMin: null, tMax: null, lay: 'cose', sel: null };
  const $ = (s) => pane.querySelector(s);
  S.$ = $;
  // the empty states' buttons ("Turn all link types on", "Show hypotheses", ...) in the canvas card
  $('.gr-msg').addEventListener('click', (e) => { const b = e.target.closest('[data-fix]'); if (b) fixFilter(S, b, 'graph'); });
  $('.gr-bar').addEventListener('click', (e) => {
    const l = e.target.closest('[data-lay]');
    if (l) { S.lay = l.dataset.lay; pane.querySelectorAll('[data-lay]').forEach((b) => b.classList.toggle('on', b === l)); layout(S, true); return; }
    const o = e.target.closest('[data-o]');
    if (o) { const k = o.dataset.o; S.origins.has(k) ? S.origins.delete(k) : S.origins.add(k); o.classList.toggle('on', S.origins.has(k)); o.setAttribute('aria-pressed', S.origins.has(k)); applyFilters(S); return; }
    const a = e.target.closest('[data-a]');
    if (a?.dataset.a === 'fit') { if (reduced()) S.cy?.fit(undefined, 40); else S.cy?.animate({ fit: { padding: 40 } }, { duration: 300 }); }
    if (a?.dataset.a === 'hyp') setHyp(S, !S.hyp);
  });
  const conf = $('.gr-conf input');
  conf.oninput = () => { S.minConf = +conf.value; $('.gr-conf b').textContent = conf.value; applyFilters(S); };
  const tr = $('.gr-time input');
  tr.oninput = () => { S.tCut = +tr.value >= 1000 || S.tMin == null ? null : S.tMin + (S.tMax - S.tMin) * (+tr.value / 1000); applyFilters(S); };
  $('.gr-leg').addEventListener('click', (e) => {
    const b = e.target.closest('[data-g]');
    if (!b) return;
    const g = b.dataset.g;
    S.hiddenGroups.has(g) ? S.hiddenGroups.delete(g) : S.hiddenGroups.add(g);
    applyFilters(S);
  });
  // add / re-root search
  const inp = $('.gr-add input'), sg = $('.gr-add .en-sugg');
  let t;
  inp.oninput = () => { clearTimeout(t); t = setTimeout(async () => {
    const q = inp.value.trim();
    if (q.length < 2) { sg.hidden = true; return; }
    const r = await api.get('/api/entities', { q, limit: 8 }).catch(() => ({ items: [] }));
    sg.innerHTML = r.items.map((x) => `<div class="en-sg gr-sg"><span class="en-tbadge" style="--c:${tcolor(x.type)}">${esc(tmeta(x.type)[0])}</span><span class="en-sg-n">${esc(shown(x.name, x.type))}</span>
      <button class="src-btn sm" data-add="${esc(x.id)}">Add</button><button class="src-btn sm" data-reroot="${esc(x.id)}">Re-root</button></div>`).join('') || vEmpty({ why: 'No match. Try part of a name or alias.', size: 'inline' });
    sg.hidden = false;
  }, 220); };
  sg.addEventListener('mousedown', async (e) => {
    const a = e.target.closest('[data-add]'), r = e.target.closest('[data-reroot]');
    if (!a && !r) return;
    e.preventDefault(); sg.hidden = true; inp.value = '';
    if (r) { S.ctx.setRoot(r.dataset.reroot); setRoot(r.dataset.reroot, window.cytoscape); }
    else await expand(S, a.dataset.add, true);
  });
  inp.onblur = () => setTimeout(() => (sg.hidden = true), 150);
  $('.gr-side').addEventListener('click', async (e) => {
    if (e.target.closest('a[data-open-full]') && !newTab(e)) { focusPageHeading(); return; }
    const f = e.target.closest('[data-fix]');
    if (f) { fixFilter(S, f, 'side'); return; }
    const b = e.target.closest('[data-s]');
    if (!b) return;
    const id = b.dataset.id;
    if (b.dataset.s === 'close') { $('.gr-side').hidden = true; S.sel = null; S.cy?.$(':selected').unselect(); }
    else if (b.dataset.s === 'expand') expand(S, id);
    else if (b.dataset.s === 'page') S.ctx.go({ tab: 'page', id });
    else if (b.dataset.s === 'peek') openEntity(id);
    else if (b.dataset.s === 'reroot') { S.ctx.setRoot(id); setRoot(id, window.cytoscape); }
    else if (b.dataset.s === 'hide') { S.cy.getElementById(id).remove(); $('.gr-side').hidden = true; S.sel = null; legend(S); }
    else if (b.dataset.s === 'ungroup') ungroup(S, id);
  });
  return S;
}

async function setRoot(id, cytoscape) {
  const S = G;
  S.root = id; S.expanded = new Set(); S.tCut = null; S.err = null; S.sel = null;
  S.$('.gr-time input').value = 1000;
  S.$('.gr-side').hidden = true;
  S.$('.gr-msg').textContent = 'Loading…';
  if (!S.cy) {
    S.cy = cytoscape({
      container: S.$('.gr-cv'), minZoom: 0.15, maxZoom: 3,
      style: [
        { selector: 'node', style: {
          width: 30, height: 30, 'background-color': '#111621', 'border-width': 1.6, 'border-color': 'data(color)',
          'background-image': 'data(img)', 'background-width': '58%', 'background-height': '58%',
          label: 'data(label)', color: 'data(color)', 'font-family': 'JetBrains Mono, monospace', 'font-size': () => 9.5 * (S.labelK || 1),
          'text-valign': 'bottom', 'text-margin-y': () => 4 * (S.labelK || 1), 'text-max-width': () => 120 * (S.labelK || 1), 'text-wrap': 'ellipsis', 'min-zoomed-font-size': 7,
          'text-background-color': '#0a0d12', 'text-background-opacity': 0.7, 'text-background-padding': 1.5,
        } },
        { selector: 'node[?root]', style: { width: 50, height: 50, 'border-width': 3, 'font-size': () => 12.5 * (S.labelK || 1), 'font-weight': 600, color: '#e9e3d4', 'z-index': 9 } },
        { selector: 'node[?expanded]', style: { 'border-style': 'double', 'border-width': 4 } },
        { selector: 'node[type="ip-group"]', style: { shape: 'round-rectangle', width: 'data(size)', height: 'data(size)', 'background-color': '#161c28', 'border-style': 'dashed' } },
        { selector: 'node:selected', style: { 'overlay-color': accentColor(), 'overlay-opacity': 0.14, 'overlay-padding': 6 } },
        { selector: 'node.faded, edge.faded', style: { opacity: 0.12 } },
        { selector: 'edge', style: {
          width: 'data(w)', 'line-color': '#5f5b52', 'target-arrow-color': '#5f5b52', 'target-arrow-shape': 'triangle', 'arrow-scale': 0.6,
          'curve-style': 'bezier', opacity: 0.85, label: '', 'font-size': 8, color: '#b7b1a2', 'text-rotation': 'autorotate',
          'text-background-color': '#0a0d12', 'text-background-opacity': 0.85, 'text-background-padding': 1,
        } },
        { selector: 'edge[origin="reported"]', style: { 'line-style': 'dashed', 'line-dash-pattern': [6, 4], 'line-color': ORIGINS.reported.color, 'target-arrow-color': ORIGINS.reported.color } },
        { selector: 'edge[origin="inferred"]', style: { 'line-style': 'dotted', 'line-color': ORIGINS.inferred.color, 'target-arrow-color': ORIGINS.inferred.color } },
        { selector: 'edge[origin="co-mention"]', style: { 'line-style': 'dashed', 'line-dash-pattern': [2, 4], 'line-color': '#8a8578', 'target-arrow-shape': 'none', opacity: 0.6 } },
        { selector: 'edge[origin="local"]', style: { 'line-color': ORIGINS.local.color, 'target-arrow-color': ORIGINS.local.color } },
        { selector: 'edge[origin="user"]', style: { 'line-color': ORIGINS.user.color, 'target-arrow-color': ORIGINS.user.color } },
        { selector: 'edge[origin="observed"]', style: { 'line-color': '#b7b1a2', 'target-arrow-color': '#b7b1a2' } },
        { selector: 'edge.hover, edge:selected, edge.lit', style: { label: 'data(label)', opacity: 1, 'z-index': 10 } },
      ],
    });
    S.cy.on('tap', 'node', (e) => select(S, e.target.id(), true));
    S.cy.on('tap', 'edge', (e) => selectEdge(S, e.target));
    S.cy.on('tap', (e) => { if (e.target === S.cy) { S.$('.gr-side').hidden = true; S.sel = null; S.cy.elements().removeClass('faded lit'); } });
    S.cy.on('mouseover', 'edge', (e) => e.target.addClass('hover'));
    S.cy.on('mouseout', 'edge', (e) => e.target.removeClass('hover'));
    S.cy.on('mouseover', 'node', (e) => { const n = e.target; S.cy.elements().addClass('faded'); n.closedNeighborhood().removeClass('faded'); n.connectedEdges().addClass('lit'); });
    S.cy.on('mouseout', 'node', () => { S.cy.elements().removeClass('faded lit'); });
    S.cy.on('zoom', () => labelScale(S));
    new ResizeObserver(() => S.cy?.resize()).observe(S.$('.gr-cv'));
  }
  S.cy.elements().remove();
  legend(S); timeDomain(S);
  const err = await expand(S, id, false, true);
  if (S.root !== id) return; // re-rooted meanwhile
  S.err = err ? (/unknown/i.test(err.message)
    ? `Nothing is known about <b>${esc(nameOf(id))}</b> yet, so there is no graph to draw. Search for another entity above.`
    : `Could not load the graph (${esc(err.message)}).`) : null;
  emptyState(S);
}

// Labels keep a readable size on screen: when the fit zoom is small (a phone, a narrow window, a zoomed-out graph)
// the label font grows in graph units, up to 2.4x, so labels stay at about 7.5 px instead of dropping below
// cytoscape's min-zoomed-font-size and vanishing. At normal zoom nothing changes.
const LABEL_PX = 7.5;
function labelScale(S) {
  const cy = S.cy;
  if (!cy) return;
  const k = Math.round(Math.min(2.4, Math.max(1, LABEL_PX / (9.5 * cy.zoom()))) * 20) / 20;
  if (k === S.labelK) return;
  S.labelK = k;
  cy.style().update(); // the label sizes are style functions of S.labelK
}

// The canvas never goes blank silently: an unknown/failed root, a root with no links, or links all filtered away.
// With no link drawn (every link type switched off, or every link filtered away) the canvas shows an empty-state card
// that names what hides the links and offers to undo it; the side panel's link list says the same (hiddenState).
function emptyState(S) {
  const m = S.$('.gr-msg');
  if (S.err) { m.innerHTML = S.err; return; }
  const shownLinks = S.cy.edges().filter((e) => e.visible()).length;
  m.innerHTML = !S.cy.nodes().length || shownLinks ? '' : hiddenState(S, S.cy.edges(), 'graph');
}

const andList = (a, w = 'and') => (a.length < 2 ? a.join('') : `${a.slice(0, -1).join(', ')} ${w} ${a[a.length - 1]}`);

// Why a link (an edge not drawn) is hidden: its origin switch ('type'), the hypotheses switch ('hyp'), minimum
// confidence, the time slider, or an end in a type group switched off under Show ('group'; 'dgroup' for a group that
// is off by default, Techniques and Tools).
function hiddenBy(S, e) {
  const d = e.data(), causes = [], groups = [];
  if (d.hypothesis) { if (!S.hyp) causes.push('hyp'); }
  else if (d.origin !== 'local' && !S.origins.has(d.origin)) causes.push('type');
  if (d.confidence != null && d.confidence < S.minConf) causes.push('conf');
  if (S.tCut != null && d.first != null && d.first > S.tCut) causes.push('time');
  for (const n of [e.source(), e.target()]) {
    const g = GROUP_OF(n.data('type'));
    if (n.data('root') || !S.hiddenGroups.has(g)) continue;
    causes.push(DEFAULT_HIDDEN.includes(g) ? 'dgroup' : 'group'); groups.push(g);
  }
  return { causes, groups };
}

// The empty state for a set of links none of which is drawn: the whole graph's (where 'graph', a card on the canvas)
// or one entity's (where 'side', the side panel's list; 'sheet', the phone's node sheet, which has no buttons).
function hiddenState(S, edges, where) {
  const size = where === 'graph' ? 'sm' : 'inline', cls = `gr-empty gr-empty-${where}`;
  if (!edges.length) {
    return vEmpty({ title: 'No links for this entity yet', why: where === 'graph' ? 'No claims or co-mentions connect it to anything. Search for another entity above to re-root the graph.' : 'No claims or co-mentions connect it to anything.', size, cls });
  }
  const all = new Set(), allGroups = new Set(), offTypes = new Set();
  let nHyp = 0;
  edges.forEach((e) => {
    if (e.data('hypothesis')) nHyp++;
    const h = hiddenBy(S, e);
    h.causes.forEach((c) => all.add(c));
    h.groups.forEach((g) => allGroups.add(g));
    if (h.causes.includes('type')) offTypes.add(e.data('origin'));
  });
  // Name what the user changed (link types, confidence, time, a group they switched off); only when nothing of that
  // hides a link, the defaults (hypotheses off, Techniques and Tools off) are the reason and are named instead.
  const changed = ['type', 'conf', 'time', 'group'].filter((c) => all.has(c));
  const causes = new Set(changed.length ? changed : ['hyp', 'dgroup'].filter((c) => all.has(c)));
  if (causes.delete('dgroup')) causes.add('group');
  const groups = new Set([...allGroups].filter((g) => DEFAULT_HIDDEN.includes(g) === !changed.length));
  const acts = [];
  const act = (label, fix, extra = {}) => acts.push(vAct(label, { data: { fix, ...extra }, primary: !acts.length }));
  if (causes.has('type')) act('Turn all link types on', 'type');
  if (causes.has('hyp')) act('Show hypotheses', 'hyp');
  if (causes.has('conf')) act('Reset minimum confidence', 'conf');
  if (causes.has('time')) act('Show all dates', 'time');
  if (causes.has('group')) act(`Show ${andList([...groups])}`, 'group', { groups: [...groups].join(',') });
  const typeNames = ORIGIN_BTNS.map((o) => ORIGINS[o].label);
  let title, why;
  if (causes.size === 1 && causes.has('hyp') && nHyp === edges.length) {
    title = 'Nothing a source stated links this entity yet';
    why = `${nHyp} hypothes${nHyp === 1 ? 'is is' : 'es are'} hidden: links the hub computed, or names from the same article.`;
  } else if (causes.size === 1 && causes.has('type') && !S.origins.size) {
    title = 'Every link type is switched off';
    why = `Turn ${andList(typeNames, 'or')} back on to see ${where === 'graph' ? 'the' : "this entity's"} links again.`;
  } else {
    title = !S.origins.size ? 'Every link type is switched off' : where === 'graph' ? 'Every link is hidden by the filters' : 'No links shown';
    const by = [];
    if (causes.has('type')) { const t = ORIGIN_BTNS.filter((o) => offTypes.has(o)).map((o) => ORIGINS[o].label); by.push(`the ${andList(t)} switch${t.length > 1 ? 'es' : ''}`); }
    if (causes.has('hyp')) by.push('the Show hypotheses switch');
    if (causes.has('conf')) by.push(`the minimum confidence (${S.minConf})`);
    if (causes.has('time')) by.push(`the time slider (links first seen after ${fmtDate(S.tCut)})`);
    if (causes.has('group')) by.push(`the ${andList([...groups])} group${groups.size > 1 ? 's' : ''} under Show`);
    why = `${where === 'graph' ? 'The links are' : "This entity's links are"} hidden by ${by.length ? andList(by) : 'the current filters'}.`;
  }
  return vEmpty({ title, why: esc(why), act: where === 'sheet' ? '' : acts.join(''), size, cls });
}

// An empty state's button: undo that one filter, then move focus off the button (the card it sat in is redrawn):
// to the first link now listed in the side panel, else the control that was changed, else Controls or the search box.
function fixFilter(S, b, from) {
  const k = b.dataset.fix;
  let to;
  if (k === 'type') {
    ORIGIN_BTNS.forEach((o) => S.origins.add(o));
    S.pane.querySelectorAll('.gr-origins [data-o]').forEach((x) => { x.classList.add('on'); x.setAttribute('aria-pressed', 'true'); });
    to = '.gr-origins [data-o]';
  } else if (k === 'conf') {
    S.minConf = 0; S.$('.gr-conf input').value = 0; S.$('.gr-conf b').textContent = '0';
    to = '.gr-conf input';
  } else if (k === 'time') {
    S.$('.gr-time input').value = 1000; S.tCut = null;
    to = '.gr-time input';
  } else if (k === 'group') {
    const gs = (b.dataset.groups || '').split(',').filter(Boolean);
    gs.forEach((g) => S.hiddenGroups.delete(g));
    to = `.gr-leg [data-g="${gs[0]}"]`;
  } else if (k === 'hyp') to = '.gr-hyp';
  if (k === 'hyp') setHyp(S, true); else applyFilters(S);
  const at = [from === 'side' ? S.$('.gr-side:not([hidden]) .gs-links a') : null, S.$(to), S.$('.gr-ctl'), S.$('.gr-add input')]
    .find((x) => x && x.getClientRects().length);
  at?.focus({ preventScroll: true });
}

function nodeData(n, rootId) {
  const t = n.type || typeOf(n.id);
  const label = t === 'ip-group' ? `${n.count} IPs · ${String(n.asn || '').toUpperCase()}` : shown(n.name || nameOf(n.id), t);
  return {
    id: n.id, type: t, name: n.name, label: label.length > 34 ? label.slice(0, 32) + '…' : label, color: tcolor(t), img: glyph(t),
    root: n.id === rootId, count: n.count, members: n.members, asn: n.asn, size: t === 'ip-group' ? Math.min(70, 26 + Math.sqrt(n.count || 1) * 5) : undefined,
  };
}
const edgeKey = (e) => e.id || `${e.source}|${e.predicate}|${e.target}`;
function edgeData(e) {
  return {
    id: `e:${edgeKey(e)}`, source: e.source, target: e.target, origin: e.origin, predicate: e.predicate, confidence: e.confidence, band: e.band,
    hypothesis: !!e.hypothesis, verdict: e.verdict || null,
    w: e.hypothesis ? (e.origin === 'co-mention' ? Math.min(2.4, 0.6 + (e.count || 1) * 0.25) : 1.2) : e.confidence != null ? 0.8 + e.confidence * 4.2 : 1,
    label: `${predText(e.predicate)}${e.count > 1 ? ` ×${e.count}` : ''}`, sources: e.sources || [], first: e.first_seen ? Date.parse(e.first_seen) : null,
    first_seen: e.first_seen, last_seen: e.last_seen, claim: e.id, count: e.count, why: whyOf(e),
  };
}

// True when id is an indicator (IP, domain...) with no entity row: the lookup answers with a 200 instead of a 404.
async function unknownIndicator(id) {
  if (!VERDICT.has(typeOf(id))) return false;
  const lk = await api.get('/api/entities/lookup', { values: nameOf(id) }).catch(() => null);
  return !!lk && !lk.results?.[0]?.found;
}

async function expand(S, id, select_ = false, isRoot = false) {
  if (S.expanded.has(id) && !isRoot) { if (select_) select(S, id, false); return; }
  const cy = S.cy;
  const at = cy.getElementById(id);
  const pos = at.nonempty() ? { ...at.position() } : { x: 0, y: 0 };
  let g;
  try {
    // an address or domain no feed or article has named has no node: ask first (a 200), never a logged 404
    if (isRoot && await unknownIndicator(id)) { const e = new Error('unknown entity'); e.status = 404; throw e; }
    g = await api.get('/api/entities/graph', { id, depth: 1, limit: isRoot ? 120 : 60 });
  }
  catch (e) { if (isRoot) return e; S.$('.gr-msg').textContent = `Could not expand: ${e.message}`; return; }
  if (isRoot && S.root !== id) return; // a newer root replaced this one while it loaded
  S.expanded.add(id);
  const add = [];
  for (const n of g.nodes) {
    if (cy.getElementById(n.id).nonempty()) continue;
    const a = Math.random() * Math.PI * 2, r = 80 + Math.random() * 90;
    add.push({ group: 'nodes', data: nodeData(n, S.root), position: { x: pos.x + Math.cos(a) * r, y: pos.y + Math.sin(a) * r } });
  }
  const have = new Set([...add.map((x) => x.data.id), ...cy.nodes().map((n) => n.id())]);
  for (const e of g.edges) {
    const d = edgeData(e);
    if (have.has(d.source) && have.has(d.target) && cy.getElementById(d.id).empty()) add.push({ group: 'edges', data: d });
  }
  cy.add(add);
  cy.getElementById(id).data('expanded', true);
  timeDomain(S);
  applyFilters(S, false);
  legend(S);
  layout(S, !isRoot, isRoot ? null : id);
  // the root's card opens by itself only where it sits beside the graph (wide, not short); where it is a sheet over
  // the graph (1000 px or narrower, or a short screen) the root is just selected and a tap opens its card
  if (select_ || (isRoot && matchMedia('(min-width: 1001px) and (min-height: 561px)').matches)) select(S, id, false);
  else if (isRoot) cy.getElementById(id).select();
}

function ungroup(S, gid) {
  const n = S.cy.getElementById(gid);
  const members = n.data('members') || [];
  const edge = n.connectedEdges()[0];
  if (!edge) return;
  const other = edge.source().id() === gid ? edge.target().id() : edge.source().id();
  const out = edge.source().id() === gid;
  const p = n.position();
  const add = members.map((m, i) => ({ group: 'nodes', data: nodeData({ id: m, type: 'ip', name: nameOf(m) }, S.root), position: { x: p.x + Math.cos(i) * 60, y: p.y + Math.sin(i) * 60 } }));
  members.forEach((m) => add.push({ group: 'edges', data: edgeData({ source: out ? m : other, target: out ? other : m, predicate: edge.data('predicate'), origin: edge.data('origin'), confidence: edge.data('confidence'), band: edge.data('band'), hypothesis: edge.data('hypothesis') }) }));
  n.remove();
  S.cy.add(add.filter((x) => S.cy.getElementById(x.data.id).empty()));
  applyFilters(S, false); legend(S); layout(S, true);
}

// What is drawn, as one string: applyFilters re-runs the layout when it changes (a link type, hypotheses, confidence,
// time or a type group switched), so the graph never keeps the old positions (a lone root left off-centre).
const visSig = (cy) => cy.elements(':visible').map((e) => e.id()).sort().join('\n');

function layout(S, animate, around) {
  const cy = S.cy;
  if (!cy) return;
  clearTimeout(S.layT);   // this run covers any re-layout applyFilters had queued
  S.visSig = visSig(cy);
  if (reduced()) animate = false;
  const vis = cy.elements(':visible');
  const opts = {
    cose: { name: 'cose', animate: animate ? 'end' : false, animationDuration: 400, randomize: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 90, gravity: 0.35, numIter: 900, nodeDimensionsIncludeLabels: true, padding: 40 },
    concentric: { name: 'concentric', animate, animationDuration: 400, concentric: (n) => (n.data('root') ? 10 : n.data('expanded') ? 6 : 6 - Math.min(5, GROUP_ORDER(n.data('type')))), levelWidth: () => 1, minNodeSpacing: 18, padding: 40 },
    breadthfirst: { name: 'breadthfirst', animate, animationDuration: 400, roots: cy.getElementById(S.root), directed: false, spacingFactor: 1.05, padding: 40 },
  }[S.lay];
  // a lone node (no links, or every link filtered away) is shown centred at normal size, not zoomed to the maximum
  if (vis.nodes().length <= 1) { cy.stop(); cy.zoom(1.2); cy.center(vis); clearCard(S); labelScale(S); return; }
  const l = vis.layout(opts);
  l.run();
  if (!animate) cy.fit(vis, 40);
  labelScale(S);
  void around;
}
// A lone node sits in the middle of the canvas; where the empty-state card covers the middle (a phone: the card spans
// the width under the search box), it moves down to the middle of the space below the card.
function clearCard(S) {
  const cy = S.cy, msg = S.$('.gr-msg');
  if (!msg || !msg.offsetParent || !msg.textContent.trim()) return;
  const box = cy.container().getBoundingClientRect(), m = msg.getBoundingClientRect();
  const cx = box.left + box.width / 2, cyMid = box.top + box.height / 2;
  if (!m.height || m.right < cx - 40 || m.left > cx + 40 || m.bottom < cyMid - 50) return;
  const room = box.bottom - m.bottom;
  if (room < 90) return;
  cy.panBy({ x: 0, y: m.bottom + room / 2 - cyMid });
}
const GROUP_ORDER = (t) => ['actor', 'campaign', 'malware', 'tool', 'cve', 'technique'].indexOf(t) + 1 || 5;

function timeDomain(S) {
  const ts = S.cy.edges().map((e) => e.data('first')).filter(Boolean);
  if (!ts.length) { S.tMin = S.tMax = null; S.$('.gr-time').classList.add('off'); setTv(S, 'no dated links'); return; }
  S.$('.gr-time').classList.remove('off');
  S.tMin = Math.min(...ts); S.tMax = Math.max(...ts, S.tMin + 864e5);
  if (S.tCut == null) setTv(S, `all · ${fmtDate(S.tMin)} → ${fmtDate(S.tMax)}`);
}

function applyFilters(S, relayout = false) {
  const cy = S.cy;
  if (!cy) return;
  let shownE = 0, totalDated = 0;
  cy.batch(() => {
    cy.edges().forEach((e) => {
      const d = e.data();
      const okO = d.hypothesis ? S.hyp : d.origin === 'local' || S.origins.has(d.origin);
      const okC = d.confidence == null || d.confidence >= S.minConf;
      const okT = S.tCut == null || d.first == null || d.first <= S.tCut;
      if (d.first != null) totalDated++;
      const ok = okO && okC && okT;
      e.style('display', ok ? 'element' : 'none');
      if (ok && d.first != null) shownE++;
    });
    cy.nodes().forEach((n) => {
      const d = n.data();
      const groupOk = !S.hiddenGroups.has(GROUP_OF(d.type));
      const hasEdge = n.connectedEdges().some((e) => e.style('display') !== 'none');
      n.style('display', d.root || (groupOk && (hasEdge || d.expanded)) ? 'element' : 'none');
    });
  });
  if (S.root && S.$('.gr-msg').textContent !== 'Loading…') emptyState(S);
  refreshSide(S); // the side panel lists exactly the links drawn
  legend(S); // the "n/N nodes" count follows what is drawn
  if (S.tCut != null) setTv(S, `as of ${fmtDate(S.tCut)} · ${shownE}/${totalDated} dated links`);
  else if (S.tMin != null) setTv(S, `all · ${fmtDate(S.tMin)} → ${fmtDate(S.tMax)}`);
  if (relayout) { layout(S, true); return; }
  // The drawn set changed: re-run the layout and fit once the control settles (a slider fires on every step). A change
  // that brings the set back to what was last laid out cancels it, and the timer checks again before it runs, so the
  // user's zoom and pan stay whenever the drawn set ends up the same. A caller that lays out right after this (load,
  // expand) cancels it too.
  clearTimeout(S.layT);
  if (S.visSig != null && visSig(cy) !== S.visSig) {
    S.layT = setTimeout(() => { if (S.cy === cy && visSig(cy) !== S.visSig) layout(S, true); }, 180);
  }
}

function setHyp(S, on) {
  S.hyp = on;
  const b = S.$('.gr-hyp');
  b.classList.toggle('on', on); b.setAttribute('aria-pressed', on);
  b.querySelector('span').textContent = on ? 'Hide hypotheses' : 'Show hypotheses';
  applyFilters(S, true);
}

function legend(S) {
  const cy = S.cy;
  const c = {};
  cy.nodes().forEach((n) => { const g = GROUP_OF(n.data('type')); c[g] = (c[g] || 0) + 1; });
  const types = {};
  cy.nodes().forEach((n) => { types[n.data('type')] = (types[n.data('type')] || 0) + 1; });
  S.$('.gr-leg').innerHTML = `<div class="gr-legh"><span class="label">Show</span><span class="mono en-dim">${cy.nodes(':visible').length}/${cy.nodes().length} nodes</span></div>`
    + FILTER_GROUPS.filter((g) => c[g]).map((g) => {
      const ts = Object.keys(types).filter((t) => GROUP_OF(t) === g);
      return `<button class="gr-lg ${S.hiddenGroups.has(g) ? 'off' : ''}" data-g="${g}">${ts.map((t) => `<i style="--c:${tcolor(t)}" title="${esc(tmeta(t)[0])}"></i>`).join('')}<span>${g}</span><b class="mono">${c[g]}</b></button>`;
    }).join('');
}

// The side panel's link list for a node: exactly the links the graph draws (cytoscape's visible() is false for an edge
// switched off and for one whose other end is hidden), grouped by predicate; none drawn, an empty state saying why.
function sideLinks(S, id) {
  const n = S.cy.getElementById(id);
  const all = n.connectedEdges(), edges = all.filter((e) => e.visible());
  if (!edges.length) return hiddenState(S, all, 'side');
  const byPred = {};
  edges.forEach((e) => { const k = `${e.source().id() === id ? predText(e.data('predicate')) : predText(e.data('predicate'), 'in')}`; (byPred[k] ||= []).push(e); });
  return Object.entries(byPred).sort((a, b) => b[1].length - a[1].length).map(([p, es]) => `<div class="gs-lg"><span class="label">${esc(p)}</span><span class="mono en-dim">${es.length}</span></div>
      ${es.slice(0, 8).map((e) => { const o = e.source().id() === id ? e.target() : e.source(); return `<div class="gs-l"><svg width="22" height="6"><line x1="0" x2="22" y1="3" y2="3" class="gl o-${e.data('origin')}"/></svg><a href="#entities/${encodeURIComponent(o.id())}" data-entity="${esc(o.id())}" style="color:${o.data('color')}">${esc(o.data('label'))}</a>${e.data('hypothesis') ? hypPill(e.data('why')) : e.data('confidence') != null ? bandPill(e.data('confidence'), e.data('band'), e.data('why')) : ''}${e.data('verdict') === 'confirm' ? '<span class="cl-voted confirm">✓ you</span>' : ''}</div>`; }).join('')}`).join('');
}

// After a filter change: the open side panel follows the graph. A node's link list is redrawn (its description stays);
// a card for a node or link the filters now hide closes, as if it had been deselected.
function refreshSide(S) {
  const side = S.$('.gr-side');
  if (side.hidden || !S.sel || !S.cy) return;
  const el = S.cy.getElementById(S.sel.id);
  if (el.empty() || !el.visible()) {
    const had = side.contains(document.activeElement);
    side.hidden = true; S.sel = null; el.unselect?.(); S.cy.elements().removeClass('lit');
    if (had) [S.$('.gr-ctl'), S.$('.gr-add input')].find((x) => x?.getClientRects().length)?.focus({ preventScroll: true });
    return;
  }
  const box = S.sel.kind === 'node' ? side.querySelector('.gs-links') : null;
  if (box) box.innerHTML = sideLinks(S, S.sel.id);
}

async function select(S, id, expandIt) {
  const cy = S.cy;
  const n = cy.getElementById(id);
  if (n.empty()) return;
  if (isPhone()) { nodeSheet(S, id); return; }
  cy.$(':selected').unselect(); n.select();
  S.sel = { kind: 'node', id };
  const d = n.data();
  const side = S.$('.gr-side');
  side.hidden = false;
  if (d.type === 'ip-group') {
    side.innerHTML = `<div class="gs-h"><span class="en-tbadge" style="--c:${tcolor('ip')}">IP group</span><button class="icon-btn" data-s="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button></div>
      <h3 class="gs-n">${esc(d.label)}</h3><p class="mono en-dim">${d.count} IP addresses collapsed by ASN. Showing up to 50.</p>
      <div class="gs-mem">${(d.members || []).map((m) => `<a class="mono" href="#entities/${encodeURIComponent(m)}" data-entity="${esc(m)}">${esc(shown(nameOf(m), 'ip'))}</a>`).join('')}</div>
      <div class="gs-act"><button class="src-btn sm" data-s="ungroup" data-id="${esc(id)}">Expand into ${Math.min(50, d.count)} nodes</button></div>`;
    return;
  }
  side.innerHTML = `<div class="gs-h"><span class="en-tbadge" style="--c:${d.color}">${esc(tmeta(d.type)[0])}</span><button class="icon-btn" data-s="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button></div>
    <h3 class="gs-n">${esc(shown(d.name || nameOf(id), d.type))}</h3>
    <div class="gs-act">
      ${S.expanded.has(id) ? '<span class="mono en-dim">expanded</span>' : `<button class="src-btn sm primary" data-s="expand" data-id="${esc(id)}">Expand</button>`}
      <button class="src-btn sm" data-s="peek" data-id="${esc(id)}">${LABELS.details}</button>${fullLink(id, 'src-btn sm')}
      ${id !== S.root ? `<button class="src-btn sm" data-s="reroot" data-id="${esc(id)}">Re-root</button><button class="src-btn sm" data-s="hide" data-id="${esc(id)}">Hide</button>` : ''}
    </div>
    <div class="gs-desc en-dim">Loading…</div>
    <div class="gs-links">${sideLinks(S, id)}</div>`;
  if (expandIt && !S.expanded.has(id)) expand(S, id);
  const info = await unknownIndicator(id) ? null : await api.get(`/api/entities/${encodeURIComponent(id)}`, { evidence: 1 }).catch(() => null);
  if (!info || cy.$(':selected').id() !== id) return;
  const desc = info.attrs?.description || '';
  const el = side.querySelector('.gs-desc');
  if (el) el.innerHTML = `${desc ? `<p>${esc(desc.slice(0, 260))}${desc.length > 260 ? '…' : ''}</p>` : ''}<div class="mono">${info.mentions?.refs || 0} mentions · ${Object.entries(info.claim_counts || {}).filter(([o]) => o !== 'inferred').reduce((a, [, b]) => a + b, 0)} claims${info.last_seen ? ` · last ${fmtDate(info.last_seen)}` : ''}</div>`;
}

// The time slider's label, also what a screen reader announces for its value (the raw 0-1000 means nothing).
function setTv(S, text) {
  // a date never breaks inside itself ("1 Sep 2013" stays on one line at any width)
  S.$('.gr-tv').textContent = text.replace(/\b\d{1,2} [A-Z][a-z]{2}(?: \d{4})?\b/g, (m) => m.replace(/ /g, '\u00a0'));
  S.$('.gr-time input').setAttribute('aria-valuetext', text.replace(/→/g, 'to').replace(/ · /g, ', '));
}

// "Open full page" from the card: once the entity page has drawn, keyboard focus goes to its heading (it would
// otherwise stay on the page's body, and the next Tab would start at the top bar).
function focusPageHeading() {
  const until = Date.now() + 5000;
  const tick = () => {
    const page = document.querySelector('#view-entities.active .enp-name, .view.active .enp-name');
    const done = page && !page.closest('.view')?.querySelector('.enp-wait');
    if (done) { page.tabIndex = -1; page.focus({ preventScroll: true }); return; }
    if (Date.now() < until) setTimeout(tick, 60);
  };
  setTimeout(tick, 0);
}

function selectEdge(S, e) {
  const d = e.data();
  const side = S.$('.gr-side');
  side.hidden = false;
  S.cy.elements().removeClass('lit'); e.addClass('lit');
  S.sel = { kind: 'edge', id: e.id() };
  side.innerHTML = `<div class="gs-h"><span class="en-tbadge" style="--c:${esc(ORIGINS[d.origin]?.color)}">${d.hypothesis ? 'Hypothesis' : `${esc(ORIGINS[d.origin]?.label || d.origin)} link`}</span><button class="icon-btn" data-s="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button></div>
    <h3 class="gs-n gs-e"><a href="#entities/${encodeURIComponent(d.source)}" data-entity="${esc(d.source)}">${esc(e.source().data('label'))}</a> <span class="en-dim">${esc(predText(d.predicate))}</span> <a href="#entities/${encodeURIComponent(d.target)}" data-entity="${esc(d.target)}">${esc(e.target().data('label'))}</a></h3>
    <div class="gs-desc">${d.hypothesis ? `${hypPill()}<p>${esc(d.origin === 'co-mention' ? `Named in the same article${d.count > 1 ? ` ${d.count} times` : ''}. Nobody said they are linked.` : HYPOTHESIS_WHY)}</p>` : d.confidence != null ? bandPill(d.confidence, d.band, d.why) : ''}${d.verdict === 'confirm' ? '<p><span class="cl-voted confirm">✓ You confirmed</span></p>' : ''}${d.why && !d.hypothesis ? `<p>${esc(d.why)}</p>` : ''}<p class="mono en-dim">${esc(ORIGINS[d.origin]?.desc || '')}</p>
    ${d.sources?.length ? `<p class="mono">Sources: ${esc(d.sources.join(', '))}</p>` : ''}${d.first_seen ? `<p class="mono en-dim">first ${fmtDate(d.first_seen)} · last ${fmtDate(d.last_seen)}</p>` : ''}</div>
    <div class="gs-act"><button class="src-btn sm" data-s="page" data-id="${esc(d.source === S.root ? d.target : d.source)}">Open the other end</button></div>`;
}
void GROUPS;


// ------------------------------------------------------------------------------------------------ phone (design.md §4.4)
// #entities/graph on a phone: the root's Connections grouped by relation, each row opening that entity's page. "Open the
// graph" shows the canvas full screen (pinch, + / − / Fit, the legend folded behind Controls); tapping a node opens a
// sheet with Open page and Re-root. The full-screen canvas is an overlay (core/page.js addLayer): its Close button,
// Esc or a page change closes it; it has no history entry.
addLayer('#view-entities .gr.gr-m-full', () => { if (G) closeFull(G); });
let listSeq = 0;
async function phoneList(S, rootId) {
  const pane = S.pane;
  let box = pane.querySelector('.gr-m');
  if (!box) {
    box = document.createElement('div');
    box.className = 'gr-m';
    pane.prepend(box);
    box.addEventListener('click', (e) => { if (e.target.closest('[data-gm="open"]')) openFull(S); });
  }
  if (box.dataset.root === rootId) return;
  box.dataset.root = rootId;
  const my = ++listSeq;
  const head = (name) => `<header class="gr-m-h"><p class="gr-m-eye">Connections of</p><h2 class="gr-m-name">${esc(name)}</h2>
    <button type="button" class="m-btn gr-m-open" data-gm="open">Open the graph</button></header>`;
  box.innerHTML = head(shown(nameOf(rootId), typeOf(rootId))) + '<span class="m-skel m-skel-row"></span><span class="m-skel m-skel-row"></span>';
  let g;
  try { g = await api.get('/api/entities/graph', { id: rootId, depth: 1, limit: 120 }); }
  catch (e) {
    if (my !== listSeq) return;
    box.innerHTML = head(shown(nameOf(rootId), typeOf(rootId))) + vError({ title: "Couldn't load the connections", why: 'The Intel data did not answer.', err: e.message, retry: () => { box.dataset.root = ''; phoneList(S, rootId); } });
    return;
  }
  if (my !== listSeq) return;
  const nodes = new Map((g.nodes || []).map((n) => [n.id, n]));
  const root = nodes.get(rootId);
  const groups = new Map();
  for (const e of g.edges || []) {
    if (e.hypothesis) continue;
    const out = e.source === rootId;
    if (!out && e.target !== rootId) continue;
    const o = nodes.get(out ? e.target : e.source);
    if (!o) continue;
    const tech = (o.type || typeOf(o.id)) === 'technique';
    const k = `${out ? predText(e.predicate) : predText(e.predicate, 'in')}${tech ? ' · ATT&CK techniques' : ''}`;
    const l = groups.get(k) || [];
    l.tech = tech;
    if (!l.some((x) => x.n.id === o.id)) l.push({ n: o, e });
    groups.set(k, l);
  }
  const row = ({ n, e }) => {
    const t = n.type || typeOf(n.id);
    if (t === 'ip-group') return `<div class="gr-m-row gr-m-static"><span class="gr-m-rn">${esc(`${n.count} IP addresses`)}</span><span class="gr-m-rm">${esc(String(n.asn || '').toUpperCase())}</span></div>`;
    return `<a class="gr-m-row" href="#entities/${encodeURIComponent(n.id)}"><span class="gr-m-rn" style="--c:${tcolor(t)}">${esc(shown(n.name || nameOf(n.id), t))}</span>
      <span class="gr-m-rm">${esc(tmeta(t)[0])}${e.confidence != null ? ` · ${esc(e.band || '')} ${Math.round(e.confidence * 100)}` : ''}</span></a>`;
  };
  const list = [...groups.entries()].sort((a, b) => (a[1].tech ? 1 : 0) - (b[1].tech ? 1 : 0) || b[1].length - a[1].length);
  box.innerHTML = head(shown(root?.name || nameOf(rootId), typeOf(rootId)))
    + (list.length ? list.map(([k, l]) => `<section class="gr-m-g"><h3 class="gr-m-gh">${esc(k)} <span>${l.length}</span></h3>${l.slice(0, 8).map(row).join('')}${l.length > 8 ? `<p class="gr-m-moreN">${l.length - 8} more in the graph</p>` : ''}</section>`).join('')
      : vEmpty({ why: 'Nothing a source stated links this entity yet.', size: 'inline' }));
}
function zoomBar(S) {
  const gr = S.$('.gr');
  if (gr.querySelector('.gr-m-zoom')) return;
  const z = document.createElement('div');
  z.className = 'gr-m-zoom';
  z.innerHTML = '<button type="button" data-z="in" aria-label="Zoom in">+</button><button type="button" data-z="out" aria-label="Zoom out">−</button><button type="button" data-z="fit">Fit</button>';
  z.addEventListener('click', (e) => {
    const b = e.target.closest('[data-z]');
    const cy = S.cy;
    if (!b || !cy) return;
    const c = { x: cy.width() / 2, y: cy.height() / 2 };
    if (b.dataset.z === 'fit') cy.fit(undefined, 30);
    else cy.zoom({ level: cy.zoom() * (b.dataset.z === 'in' ? 1.35 : 1 / 1.35), renderedPosition: c });
  });
  gr.append(z);
}
async function openFull(S) {
  const gr = S.$('.gr');
  gr.classList.add('gr-m-full');
  zoomBar(S);
  let cytoscape;
  try { cytoscape = await loadCy(); } catch (e) { S.$('.gr-msg').textContent = e.message; return; }
  if (S.root !== S.want || !S.cy) await setRoot(S.want, cytoscape);
  else { S.cy.resize(); S.cy.fit(undefined, 30); }
  S.$('.gr-m-zoom button')?.focus({ preventScroll: true });
}
function closeFull(S) {
  const gr = S.$('.gr');
  if (!gr.classList.contains('gr-m-full')) return;
  gr.classList.remove('gr-m-full', 'gr-ctl-on');
  S.$('.gr-ctl')?.setAttribute('aria-expanded', 'false');
  S.pane.querySelector('.gr-m-open')?.focus({ preventScroll: true });
}
async function nodeSheet(S, id) {
  const cy = S.cy;
  const n = cy.getElementById(id);
  cy.$(':selected').unselect(); n.select();
  const d = n.data();
  if (d.type === 'ip-group') {
    openSheet({ id: 'graph-node', title: d.label, body: `<p class="gr-m-sdesc">${d.count} IP addresses collapsed by network owner.</p>`,
      footer: `<button type="button" class="m-btn" data-gs="ungroup">Show them in the graph</button>` }).el.addEventListener('click', (e) => {
      if (e.target.closest('[data-gs="ungroup"]')) { ungroup(S, id); }
    });
    return;
  }
  const edges = n.connectedEdges(':visible');
  const byPred = {};
  edges.forEach((e) => { const k = e.source().id() === id ? predText(e.data('predicate')) : predText(e.data('predicate'), 'in'); (byPred[k] ||= []).push(e); });
  const links = Object.entries(byPred).sort((a, b) => b[1].length - a[1].length).slice(0, 4).map(([p, es]) => `<p class="gr-m-sl"><b>${esc(p)}</b> ${es.slice(0, 5).map((e) => { const o = e.source().id() === id ? e.target() : e.source(); return esc(o.data('label')); }).join(', ')}${es.length > 5 ? ` +${es.length - 5}` : ''}</p>`).join('')
    || hiddenState(S, n.connectedEdges(), 'sheet');
  const h = openSheet({
    id: 'graph-node', title: shown(d.name || nameOf(id), d.type),
    body: `<p class="gr-m-stype" style="--c:${d.color}">${esc(tmeta(d.type)[0])}</p><div class="gr-m-sdesc">Loading…</div>${links}`,
    footer: `${id !== S.root ? '<button type="button" class="m-btn" data-gs="reroot">Re-root</button>' : ''}${S.expanded.has(id) ? '' : '<button type="button" class="m-btn" data-gs="expand">Expand</button>'}<button type="button" class="m-btn m-btn-primary" data-gs="page">${LABELS.full}</button>`,
  });
  h.el.addEventListener('click', (e) => {
    const b = e.target.closest('[data-gs]');
    if (!b) return;
    if (b.dataset.gs === 'page') navigateFromSheet(`#entities/${encodeURIComponent(id)}`);
    else if (b.dataset.gs === 'expand') { h.close(); expand(S, id); }
    else if (b.dataset.gs === 'reroot') { h.close(); S.want = id; S.ctx.setRoot(id); phoneList(S, id); setRoot(id, window.cytoscape); }
  });
  const info = await unknownIndicator(id) ? null : await api.get(`/api/entities/${encodeURIComponent(id)}`, { evidence: 1 }).catch(() => null);
  const el = h.body?.querySelector?.('.gr-m-sdesc') || h.el.querySelector('.gr-m-sdesc');
  if (!el) return;
  const desc = info?.attrs?.description || '';
  el.innerHTML = info ? `${desc ? `<p>${esc(desc.slice(0, 260))}${desc.length > 260 ? '…' : ''}</p>` : ''}<p class="mono">${info.mentions?.refs || 0} mentions${info.last_seen ? ` · last ${fmtDate(info.last_seen)}` : ''}</p>` : '';
}

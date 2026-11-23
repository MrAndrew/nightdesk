// Entity page (#entities/<id>): header, what it is, per-source swimlane with brush, claims by origin with
// evidence and feedback, contested attributions, ATT&CK strip, IOC table with CSV/STIX export,
// "touches your network", related entities and references. Data: GET /api/entities/<id>.
// Trust rules (okf/data/entities.md#verdicts): a verdict annotates its claim ("You confirmed"); a rejected link
// leaves every list and count and waits in "You disagreed (n)" with Undo; hypotheses (links the hub computed) sit
// in their own collapsed group and join Related only after "Show hypotheses"; reference rows take no verdict.
import {
  api, esc, toast, tmeta, tcolor, icon, chip, shown, defang, typeOf, nameOf, IOC_TYPES, ORIGINS, ORIGIN_ORDER,
  predText, bandPill, whyOf as scorerWhy, tierBadge, isHypothesis, hypPill, HYPOTHESIS_WHY, LS, fmtDate, fmtAgo, download, copy, csvCell, stixBundle, TACTICS, TACTIC_ALIAS, techniqueIndex,
} from './common.js';
import { openEntity, assessShell, fillAssessment, VERDICT } from '../../core/entity-panel.js';
import { mountNotes } from '../../core/notes.js';
import { entitySummary } from '../../core/summary.js';
import { seenLookup, seenChip } from '../../core/chips.js';
import { followButton } from '../../core/stack.js';
import { safeUrl, epssText, epssTitle, epssClass } from '../../core/util.js';
import { disagreeCell, disagreePop, identityActs, identityHtml, identityAct, reasonLabel } from './intelx.js';
import { emptyState, errorState, loadingState } from '../../core/view.js';
import { isPhone } from '../../core/mobile.js';
import { actionSheet } from '../../core/sheet.js';
import { NAMED } from './intelx.js';
import { TTP_KINDS, TTP_HOW, ttpAttrs, ttpLinkKind, ttpQuote, ttpTag, ttpArticleCount, wireTtpTips } from '../../core/ttp.js';

let seq = 0;

export async function renderPage(pane, id, ctx) {
  const my = ++seq;
  // An id without a 'type:' prefix (e.g. #entities/lazarus) is a bare name: no type yet, and the name is the
  // whole id, so the header and the not-found message show what the user asked for.
  const typed = String(id).includes(':');
  const t = typed ? typeOf(id) : '';
  const nm = typed ? nameOf(id) : String(id);
  pane.innerHTML = `<div class="enp"><div class="enp-head"><div class="enp-hl"><div class="enp-kind" style="--c:${tcolor(t)}">${icon(t)}${esc(tmeta(t)[0])}</div>
    <h2 class="enp-name">${esc(shown(nm, t))}</h2></div></div><div class="enp-wait">${loadingState('Loading profile…', { size: 'sm' })}</div></div>`;
  let d;
  try {
    // An address or domain no feed or article has named has no profile: ask first (a 200, not a logged 404) and
    // show what is known anyway: the verdict, your network, the lists.
    if (typed && VERDICT.has(t)) {
      const lk = await api.get('/api/entities/lookup', { values: nm }).catch(() => null);
      if (lk && !lk.results?.[0]?.found) { if (my === seq) renderUnknown(pane, id, t, nm, my); return; }
    }
    d = await api.get(`/api/entities/${encodeURIComponent(id)}`, { evidence: 8, bucket: 'day' });
  }
  catch (e) {
    if (my !== seq) return;
    if (e.status === 404 && typed && VERDICT.has(t)) { renderUnknown(pane, id, t, nm, my); return; }
    // replace whatever the loading placeholder is (owned by this function, not by the loader's markup)
    pane.querySelector('.enp-wait').outerHTML = /unknown/i.test(e.message) ? emptyState({ title: 'Nothing known yet', why: `Nothing is known about <b>${esc(nm)}</b> yet. It has not appeared in any source, article or reference set.` })
      : errorState({ retry: () => renderPage(pane, id, ctx), title: "Couldn't load this entity", why: 'The Intel data did not answer. Try again in a moment.', err: e.message });
    return;
  }
  if (my !== seq) return;
  if (d.id !== id) history.replaceState(null, '', `#entities/${encodeURIComponent(d.id)}`);
  ctx.onName?.(d.name);
  const P = { d, pane, ctx, win: null, open: new Set(), more: new Set(), my, showHyp: !!LS.get(HYP_KEY, false) };
  draw(P);
}

// An indicator with no entity row: the drawer's verdict strip (lists, owner, seen on your network, what to do) and a
// plain line that nothing else is known. Data: GET /api/netlog/seen?context=1 (lists and owner) for the value.
async function renderUnknown(pane, id, t, nm, my) {
  let it = null;
  try { it = (await api.get('/api/netlog/seen', { v: nm, context: true })).items?.[0] || null; } catch {}
  if (my !== seq) return;
  const d0 = { id, type: t, name: it?.normalized || nm, listed_by: it?.listed_by || [], owner: it?.owner || null,
    mentions: { refs: 0 }, sources: [], claim_counts: {} };
  const wait = pane.querySelector('.enp-wait');
  if (!wait) return;
  wait.outerHTML = `<div class="enp-grid polish-unknown"><div class="enp-main">
    <section class="enp-card drawer-assess-card" id="enp-assess">${assessShell(d0)}</section>
    <section class="enp-card"><p class="polish-unknown-p">Nothing else is known about <b class="mono">${esc(shown(d0.name, t))}</b>. No news item, source or reference names it yet, so there is no profile, claims or graph beyond what is above.</p></section>
  </div></div>`;
  fillAssessment(pane, d0, { isCurrent: () => my === seq, brief: false });
}

// ------------------------------------------------------------------------------------------------ helpers
const HYP_KEY = 'nd.entities.hypotheses';
const allClaims = (d) => ORIGIN_ORDER.flatMap((o) => d.claims?.[o] || []);
// claims that count: everything but the Hypotheses group (a confirmed hypothesis sits under "user")
const counted = (d) => ORIGIN_ORDER.filter((o) => !isHypothesis(o)).flatMap((o) => d.claims?.[o] || []);
const originLabel = (o) => ORIGINS[o]?.label || o;
const isTech = (c) => (c.other_type || typeOf(c.other)) === 'technique';
// How a technique link was found (core/ttp.js ttpLinkKind): a link MITRE's catalogue states (even when articles
// report it too), a feed fact or the analyst's own link stays "confirmed"; only a link whose evidence is all article
// extraction gets a plain label: named (a quote prints the id), likely, possible.
const TECH_RANK = { confirmed: 0, named: 1, likely: 2, possible: 3 };
// the technique end of a claim on this page: the other end, or the page's own entity on a technique's page
const techEnd = (P, c) => (isTech(c) ? c.other : P.d.type === 'technique' ? P.d.id : null);
const tidOfId = (id) => String(id || '').split(':').slice(1).join(':').toUpperCase();
const techKind = (c, id = c.other) => ttpLinkKind(c, tidOfId(id)) || 'possible';
function techLabel(P, c) {
  const tech = techEnd(P, c);
  if (!tech) return c.suggested ? '<span class="cl-sug">possible</span>' : '';
  const k = ttpLinkKind(c, tidOfId(tech));
  if (k === 'confirmed') { const n = ttpArticleCount(c); return n ? `<span class="ttp-also" title="Also reported in article text">also in ${n} article${n === 1 ? '' : 's'}</span>` : ''; }
  if (!k) return '';
  const q = ttpQuote(c);
  return ttpTag({ id: tidOfId(tech), kind: k, name: tech === c.other ? c.other_name : P.d.name, quote: q?.quote, source: q?.source });
}
const inWin = (P, ts) => !P.win || (ts && new Date(ts) >= P.win[0] && new Date(ts) <= P.win[1]);
const claimInWin = (P, c) => !P.win || (c.evidence || []).some((e) => inWin(P, e.ts)) || inWin(P, c.last_seen) || inWin(P, c.first_seen);

// One noun per count on this page (D2-03):
//   "sources"             every data source, news outlet or reference set that mentions it (the Sources tile, "What it is")
//   "claim sources"       the sources behind its claims
//   "independent sources" the separate pieces of evidence the scorer counted for one claim's confidence
//   "news outlets"        the outlets of the articles that name it (the brief above, all time)
const whyOf = (c) => scorerWhy(c).replace(/^(\d+) sources?\b/, (m, n) => `${n} independent source${n === '1' ? '' : 's'}`);
function entityConfidence(d) {
  const cs = allClaims(d).filter((c) => c.origin !== 'inferred' && c.confidence != null);
  if (!cs.length) return null;
  const v = cs.map((c) => c.confidence).sort((a, b) => a - b);
  const top = cs.reduce((a, b) => (b.confidence > a.confidence ? b : a));
  return { max: v[v.length - 1], median: v[Math.floor(v.length / 2)], n: v.length, why: whyOf(top) };
}

function iocRows(d) {
  const m = new Map();
  for (const c of allClaims(d)) {
    const ot = c.other_type || typeOf(c.other);
    if (!IOC_TYPES.includes(ot)) continue;
    const r = m.get(c.other) || { id: c.other, type: ot, value: c.other_name || nameOf(c.other), how: predText(c.predicate, c.direction), origin: c.origin, confidence: c.confidence, band: c.band, sources: [], first_seen: c.first_seen, last_seen: c.last_seen, n: 0 };
    r.sources = [...new Set([...r.sources, ...(c.sources || [])])];
    r.n += c.evidence_count || 1;
    if ((c.confidence ?? -1) > (r.confidence ?? -1) && c.origin !== 'user') { r.confidence = c.confidence; r.band = c.band; r.why = whyOf(c); r.origin = c.origin; r.how = predText(c.predicate, c.direction); }
    m.set(c.other, r);
  }
  for (const r of [...(d.related || []), ...(d.related_hypotheses || [])]) {
    if (!IOC_TYPES.includes(r.type) || m.has(r.id) || r.how !== 'mentioned-with') continue;
    m.set(r.id, { id: r.id, type: r.type, value: r.name || nameOf(r.id), how: 'mentioned with', origin: 'co-mention', confidence: null, sources: [], n: r.n });
  }
  return [...m.values()].sort((a, b) => (b.confidence ?? -1) - (a.confidence ?? -1) || b.n - a.n);
}

// ------------------------------------------------------------------------------------------------ layout
function draw(P) {
  const { d, pane } = P;
  const t = d.type;
  const cc = d.claim_counts || {};
  const nClaims = counted(d).length;
  const nH = (cc.inferred || 0);
  const conf = entityConfidence(d);
  const tl = d.timeline || [];
  const now = Date.now();
  const last30 = tl.filter((x) => now - new Date(x.t) < 30 * 864e5).reduce((a, x) => a + x.n, 0);
  const iocs = iocRows(d);
  const techs = allClaims(d).filter((c) => isTech(c) && c.direction === 'out');
  const aliases = (d.aliases || []).filter((a) => a.toLowerCase() !== String(d.name).toLowerCase());
  const conflicts = allClaims(d).filter((c) => c.conflict);
  // a phone gets the page of design.md §4.4 (mock-entity.png): a short head (6 aliases, the description, Follow and
  // Copy summary, ⋯ for the rest), three tiles, then plain headed sections with a "Jump to" row. Desktop: unchanged.
  const phone = isPhone();
  const nAl = phone ? 6 : 14;
  const desc = String((d.attrs || {}).description || d.description || (d.attrs || {}).kev_name || '').replace(/\s+/g, ' ').trim();
  const mHead = phone ? `${desc ? `<p class="enp-m-desc">${esc(desc)}</p>` : ''}` : '';
  const mMore = phone ? '<button type="button" class="enp-m-more" data-act="m-menu" aria-haspopup="menu" aria-label="More actions"><svg class="i" aria-hidden="true" viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.7" fill="currentColor"/><circle cx="12" cy="12" r="1.7" fill="currentColor"/><circle cx="19" cy="12" r="1.7" fill="currentColor"/></svg></button>' : '';
  const mTiles = phone ? `<div class="enp-m-tiles">
      <div class="enp-m-tile"><span class="enp-m-k">Mentions</span><b>${(d.mentions?.refs ?? 0).toLocaleString()}</b><small>${last30 ? `${last30} in 30d` : 'none in 30d'}</small></div>
      <div class="enp-m-tile"><span class="enp-m-k">Sources</span><b>${(d.sources || []).length}</b><small>${(d.sources || []).length ? 'all time' : 'reference only'}</small></div>
      <div class="enp-m-tile"><span class="enp-m-k">Last seen</span><b>${d.last_seen ? esc(fmtAgo(d.last_seen).replace(' ago', '')) : '—'}</b><small>${d.last_seen ? esc(fmtDate(d.last_seen)) : 'reference data'}</small></div></div>` : '';
  const mJump = phone ? `<nav class="enp-m-jump" aria-label="Jump to a section"><span class="enp-m-k">Jump to</span>
      <a href="#enp-what" data-jump class="enp-m-chip">About</a><a href="#enp-activity" data-jump class="enp-m-chip">Activity</a>
      <a href="#enp-claims" data-jump class="enp-m-chip">Claims ${nClaims}</a><a href="#enp-related" data-jump class="enp-m-chip">Related ${(d.related || []).length}</a></nav>` : '';
  pane.innerHTML = `<div class="enp${phone ? ' enp-m' : ''}">
    <header class="enp-head">
      <div class="enp-hl">
        <div class="enp-kind" style="--c:${tcolor(t)}">${icon(t)}${esc(tmeta(t)[0])}${d.attrs?.country ? `<span class="enp-dot">·</span>${esc(String(d.attrs.country).toUpperCase())}` : ''}
          ${d.conflicting_attribution ? '<a class="enp-warn" href="#enp-contest">contested attribution</a>' : ''}</div>
        <h2 class="enp-name">${esc(shown(d.name, t))}</h2>${mMore}
        ${aliases.length ? `<div class="enp-al"><span class="label">Also known as</span>${aliases.slice(0, nAl).map((a) => `<span class="enp-alias">${esc(a)}</span>`).join('')}${aliases.length > nAl ? `<button class="enp-alias more" data-act="aliases">+${aliases.length - nAl}${phone ? ' more' : ''}</button>` : ''}</div>` : ''}
        ${mHead}${identityHtml(d)}
      </div>
      <div class="enp-acts">
        ${['country', 'sector', 'prefix', 'technique'].includes(d.type) ? '' : followButton({ entity: d.id }, { name: d.name || nameOf(d.id) })}
        ${identityActs(d)}
        <a class="src-btn" href="#entities/graph/${encodeURIComponent(d.id)}"><svg class="i" viewBox="0 0 24 24"><path d="M6 6a2 2 0 1 0 0 .1M18 8a2 2 0 1 0 0 .1M12 18a2 2 0 1 0 0 .1M7.5 7l9 1M7 8l4 8.5M17 10l-4 6.5" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>Graph</a>
        <button class="src-btn" data-act="stix" title="STIX 2.1 bundle: this entity and its indicators">STIX 2.1</button>
        <button class="src-btn" data-act="copy" title="Copy the value">Copy</button>
      </div>
      <div class="enp-kpis">
        <div class="enp-kpi" tabindex="0" title="Mentions: items (articles, source items, reference records) that name it, all time; the second line counts the last 30 days."><span class="label">Mentions</span><b class="mono">${(d.mentions?.refs ?? 0).toLocaleString()}</b><small class="mono">${last30 ? `<span class="up">▲ ${last30}</span> 30 days` : 'none in 30 days'}</small></div>
        <div class="enp-kpi" tabindex="0" title="${esc(`Sources: the ${(d.sources || []).length} data sources, news outlets and reference sets that mention ${d.name || nameOf(d.id)}, all time${(d.sources || []).length ? ` (${(d.sources || []).join(', ')})` : ''}.`)}"><span class="label">Sources</span><b class="mono">${(d.sources || []).length}</b><small class="mono">${esc((d.sources || []).slice(0, 2).join(', ') || 'reference data only')}</small></div>
        <div class="enp-kpi" tabindex="0" title="Claims: statements that tie it to something else, by where they come from. Hypotheses the hub computed are counted apart."><span class="label">Claims</span><b class="mono">${nClaims.toLocaleString()}</b>
          <span class="enp-obar">${ORIGIN_ORDER.filter((o) => cc[o] && !isHypothesis(o)).map((o) => `<i class="o-${o}" style="flex:${cc[o]}" title="${cc[o]} ${esc(originLabel(o).toLowerCase())}"></i>`).join('')}</span>
          ${((txt) => `<small class="mono enp-wrap" title="${esc(txt)}">${esc(txt)}</small>`)(`${ORIGIN_ORDER.filter((o) => cc[o] && !isHypothesis(o)).map((o) => `${cc[o]} ${originLabel(o).toLowerCase()}`).join(' · ') || 'none'}${nH ? ` · plus ${nH} hypothes${nH === 1 ? 'is' : 'es'}` : ''}`)}</div>
        <div class="enp-kpi" tabindex="0" title="${esc(`Confidence: the strongest of ${conf ? conf.n : 0} scored claims. Independent sources are the separate pieces of evidence the scorer counted for that one claim, so the number can differ from the Sources tile.`)}"><span class="label">Confidence</span>${conf ? `${bandPill(conf.max, null, conf.why)}<small class="mono enp-wrap">${conf.why ? `strongest claim: ${esc(conf.why)}` : `strongest of ${conf.n} scored claims · median ${Math.round(conf.median * 100)}`}</small>` : '<b class="mono en-dim">—</b><small class="mono">no scored claims</small>'}</div>
        <div class="enp-kpi" tabindex="0" title="First seen: the earliest item that names it."><span class="label">First seen</span><b class="mono">${fmtDate(d.first_seen)}</b><small class="mono">${d.first_seen ? fmtAgo(d.first_seen) : 'reference data only'}</small></div>
        <div class="enp-kpi" tabindex="0" title="Last seen: the newest item that names it."><span class="label">Last seen</span><b class="mono">${fmtDate(d.last_seen)}</b><small class="mono">${d.last_seen ? fmtAgo(d.last_seen) : '—'}</small></div>
      </div>
      ${mTiles}
      <nav class="enp-nav">
        <a href="#enp-what" data-jump>What it is</a><a href="#enp-activity" data-jump>Activity</a>
        ${conflicts.length ? '<a href="#enp-contest" data-jump class="warn">Contested</a>' : ''}
        <a href="#enp-claims" data-jump>Claims <i>${nClaims}</i></a>
        ${techs.length ? `<a href="#enp-attack" data-jump>Techniques <i>${techs.length}</i></a>` : ''}
        ${iocs.length ? `<a href="#enp-iocs" data-jump>Indicators <i>${iocs.length}</i></a>` : ''}
        <a href="#enp-related" data-jump>Related <i>${(d.related || []).length}</i></a>
      </nav>
    </header>
    <div class="enp-grid">${mJump}
      <div class="enp-main">
        <section class="enp-card drawer-assess-card" id="enp-assess">${assessShell(d)}</section>
        <section class="enp-card" id="enp-what">${whatItIs(d)}</section>
        <section class="enp-card" id="enp-activity"><div class="enp-ch"><h3>Activity by source</h3><span class="mono en-dim enp-winl">drag across the chart to focus claims and references on a time window</span><button class="src-btn sm enp-winx" hidden data-act="clearwin">Clear window</button></div><div class="enp-swim"></div></section>
        ${conflicts.length ? `<section class="enp-card enp-contest" id="enp-contest">${contested(P)}</section>` : ''}
        <section class="enp-card" id="enp-claims"></section>
        ${techs.length ? `<section class="enp-card" id="enp-attack"></section>` : ''}
        ${iocs.length ? `<section class="enp-card" id="enp-iocs"></section>` : ''}
      </div>
      <aside class="enp-side">
        <section class="enp-card enp-net" id="enp-net" hidden></section>
        ${(d.listed_by || []).length ? `<section class="enp-card" id="enp-lists">${threatLists(d)}</section>` : ''}
        <section class="enp-card" id="enp-related">${related(P)}</section>
        <section class="enp-card" id="enp-srcdist">${sourceDist(d)}</section>
        <section class="enp-card" id="enp-refs"></section>
      </aside>
    </div>
  </div>`;
  const $ = (s) => pane.querySelector(s);
  P.$ = $;
  swimlane(P, $('.enp-swim'));
  drawClaims(P);
  drawRefs(P);
  if (techs.length) attack(P, techs);
  if (iocs.length) iocTable(P, iocs);
  touches(P, iocs);
  fillAssessment(pane, d, { isCurrent: () => P.my === seq });
  mountNotes(pane.querySelector('.enp-side'), { kind: 'entity', item: d.id, title: d.name, at: 'prepend', cls: 'enp-card', actions: pane.querySelector('.enp-acts'), summary: () => entitySummary(d) });
  wire(P);
}

function wire(P) {
  const { pane, d } = P;
  pane.onclick = async (e) => {
    const j = e.target.closest('[data-jump]');
    if (j) { e.preventDefault(); pane.querySelector(j.getAttribute('href'))?.scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
    const w = e.target.closest('a.enp-warn');
    if (w) { e.preventDefault(); pane.querySelector('#enp-contest')?.scrollIntoView({ behavior: 'smooth' }); return; }
    const a = e.target.closest('[data-act]');
    if (!a) return;
    const act = a.dataset.act;
    if (act === 'copy') copy(d.name);
    else if (act === 'aliases') { a.parentElement.innerHTML = `<span class="label">Also known as</span>${d.aliases.map((x) => `<span class="enp-alias">${esc(x)}</span>`).join('')}`; }
    else if (act === 'stix') exportStix(P, iocRows(d));
    else if (act === 'clearwin') setWin(P, null);
    else if (act === 'ev') { const cid = a.dataset.cid; P.open.has(cid) ? P.open.delete(cid) : P.open.add(cid); a.closest('.enp-claim').classList.toggle('open'); }
    else if (act === 'more') { P.more.add(a.dataset.g); drawClaims(P); }
    else if (act === 'confirm' || act === 'clear') feedback(P, a.dataset.cid, act, a);
    else if (act === 'disagree') {
      const c = allClaims(d).concat(d.rejected || []).find((x) => x.id === a.dataset.cid);
      if (!c) return;
      const out = c.direction !== 'in';
      disagreePop(a, { id: c.id, subj: out ? d.id : c.other, subj_name: out ? d.name : (c.other_name || nameOf(c.other)), predicate: c.predicate,
        obj: out ? c.other : d.id, obj_name: out ? (c.other_name || nameOf(c.other)) : d.name }, (body) => feedback(P, c.id, 'reject', a, body));
    }
    else if (identityAct(act, a, d, { reload: () => refresh(P), open: (id) => P.ctx.go({ tab: 'page', id }) })) { /* identity: Same as…, Wrong type… */ }
    else if (act === 'hyp') setHyp(P, !P.showHyp);
    else if (act === 'peek') openEntity(a.dataset.id);
    else if (act === 'm-menu') phoneMenu(P, a);
    else if (act === 'allev') loadAllEvidence(P);
  };
}

// The phone page's ⋯: the header actions that do not fit beside Follow and Copy summary. Each runs the page's own
// (hidden) button, so the behaviour is the desktop one.
function phoneMenu(P, btn) {
  const { pane, d } = P;
  const run = (sel) => () => pane.querySelector(`.enp-acts ${sel}`)?.click();
  btn.setAttribute('aria-expanded', 'true');
  actionSheet({ id: 'entity', title: shown(d.name, d.type), items: [
    { label: 'Copy value', hint: shown(d.name, d.type), run: run('[data-act="copy"]') },
    ...(NAMED.includes(d.type) ? [{ label: 'Same as…', run: run('[data-act="ix-same"]') }, { label: 'Wrong type…', run: run('[data-act="ix-type"]') }] : []),
    { label: 'STIX 2.1', hint: 'download', run: run('[data-act="stix"]') },
    { label: 'Open in graph', href: `#entities/graph/${encodeURIComponent(d.id)}` },
  ] }).finally(() => btn.setAttribute('aria-expanded', 'false'));
}

// ------------------------------------------------------------------------------------------------ what it is
const SKIP = new Set(['description', 'ref', 'url', 'title', 'attack_id', 'tactics', 'kev_name',
  'epss', 'epss_percentile', 'epss_date', 'epss_since', 'epss_prev', 'epss_status', 'advisories', 'cvss_source']);
const LABELS = { state_sponsor: 'State sponsor', victims: 'Victims', targets: 'Targets', incident_type: 'Incident type', sectors: 'Sectors', country: 'Country', cvss: 'CVSS', kev: 'CISA KEV', kev_added: 'KEV added', ransomware_use: 'Ransomware use', cwes: 'Weakness', asn: 'Network owner (ASN)', as_name: 'AS name', cc: 'Country', prefix: 'Prefix', vendor: 'Vendor', product: 'Product', epss: 'EPSS', platforms: 'Platforms' };
function whatItIs(d) {
  const a = d.attrs || {};
  const desc = a.description || d.description || a.kev_name;
  const prim = (v) => v != null && v !== '' && typeof v !== 'object';
  const facts = Object.entries(a).filter(([k, v]) => !SKIP.has(k) && (prim(v) || (Array.isArray(v) && v.length && v.every(prim))))
    .slice(0, 12).map(([k, v]) => [LABELS[k] || k.replace(/_/g, ' '), Array.isArray(v) ? v.slice(0, 12).join(', ') : v === true ? 'yes' : String(v)]);
  const cc = d.claim_counts || {};
  const rep = allClaims(d).filter((c) => c.origin === 'reported' && !isTech(c));
  const outlets = new Set(rep.flatMap((c) => c.sources || []));
  const summary = [];
  if (d.mentions?.refs) summary.push(`mentioned in <b title="items that name it, all time">${d.mentions.refs}</b> item${d.mentions.refs === 1 ? '' : 's'} from <b title="data sources, news outlets and reference sets that mention it (the Sources tile)">${(d.sources || []).length}</b> source${(d.sources || []).length === 1 ? '' : 's'}`);
  if (cc.reported) summary.push(`<b>${cc.reported}</b> reported claim${cc.reported === 1 ? '' : 's'} from ${outlets.size ? `<b title="${esc(`the sources behind its reported claims: ${[...outlets].join(', ')}`)}">${outlets.size}</b> claim source${outlets.size === 1 ? '' : 's'}` : 'reference data'}`);
  if (cc.observed) summary.push(`<b>${cc.observed}</b> observed in data sources`);
  if (cc.inferred) summary.push(`linked by <b>${cc.inferred}</b> hypothes${cc.inferred === 1 ? 'is' : 'es'} the hub computed (not said by any source)`);
  const ref = a.url || (a.attack_id ? `https://attack.mitre.org/` : null);
  return `<div class="enp-ch"><h3>What it is</h3>${safeUrl(a.url) ? `<a class="enp-ext mono" href="${esc(safeUrl(a.url))}" target="_blank" rel="noopener">${esc(a.attack_id || 'reference')} ↗</a>` : a.attack_id ? `<span class="enp-ext mono">${esc(a.attack_id)}</span>` : ''}</div>
    ${desc ? `<p class="enp-desc">${esc(desc)}</p>` : `<p class="enp-desc en-dim">No description in the reference data. ${IOC_TYPES.includes(d.type) ? 'This is an indicator; its meaning comes from the claims below.' : ''}</p>`}
    ${summary.length ? `<p class="enp-sum">${esc(d.name)} is ${summary.join(', ')}.</p>` : ''}
    ${facts.length || d.type === 'cve' ? `<dl class="enp-facts">${cveFacts(d)}${facts.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v.length > 160 ? v.slice(0, 158) + '…' : v)}</dd></div>`).join('')}</dl>` : ''}
    ${d.type === 'cve' ? advisoryList(d.attrs || {}) : ''}`;
  void ref;
}

// CVE facts read live from the epss / advisory_cves tables (entities API), formatted rather than shown as raw attrs.
const day = (t) => (t ? fmtDate(t) : '');
function cveFacts(d) {
  if (d.type !== 'cve') return '';
  const a = d.attrs || {};
  let v;
  if (a.epss != null) {
    const pct = a.epss_percentile != null ? ` · higher than ${(a.epss_percentile * 100).toFixed(1)}% of scored CVEs` : '';
    const moved = a.epss_prev != null ? ` · was ${epssText(a.epss_prev)} until ${day(a.epss_since)}` : '';
    v = `<b class="enp-epss ${epssClass(a.epss)}" title="${esc(epssTitle(a.epss, a.epss_percentile, a.epss_prev, a.epss_since))}">${esc(epssText(a.epss))}</b>${esc(pct + moved)}<br><small class="en-dim">FIRST EPSS, scores of ${esc(day(a.epss_date))}</small>`;
  } else {
    v = esc(a.epss_status === 'not scored' ? 'not scored by EPSS' : 'EPSS not loaded');
  }
  return `<div><dt>EPSS · exploitation in 30 days</dt><dd>${v}</dd></div>`
    + (a.cvss_source && a.cvss_source !== 'NVD' ? `<div><dt>CVSS source</dt><dd>${esc(a.cvss_source)}</dd></div>` : '');
}
function advisoryList(a) {
  const adv = a.advisories || [];
  if (!adv.length) return '';
  return `<div class="enp-adv"><h4 class="label">CISA advisories (${adv.length})</h4>${adv.slice(0, 10).map((x) => `<div class="ep-adv">${safeUrl(x.url)
    ? `<a href="${esc(safeUrl(x.url))}" target="_blank" rel="noopener" class="mono">${esc(x.id)}</a>` : `<span class="mono">${esc(x.id)}</span>`} ${esc(x.title || '')} <small>${esc(x.kind || '')} · ${esc(day(x.updated))}${x.cvss != null ? ` · CVSS ${esc(x.cvss)}` : ''}</small></div>`).join('')}</div>`;
}

// ------------------------------------------------------------------------------------------------ swimlane
function swimlane(P, box) {
  const tl = P.d.timeline || [];
  if (!tl.length) {
    box.innerHTML = emptyState({ why: `No dated mentions. ${P.d.claim_counts?.reported ? 'Everything known comes from reference data (ATT&CK, MISP), which carries no dates.' : ''}`, size: 'inline' });
    box.closest('.enp-card').querySelector('.enp-winl').textContent = '';
    return;
  }
  const end = Date.now();
  let t0 = Math.min(...tl.map((x) => new Date(x.t).getTime()));
  t0 = Math.min(t0, end - 30 * 864e5);
  const span = end - t0;
  const bucket = span > 200 * 864e5 ? 7 * 864e5 : 864e5;
  const nb = Math.ceil(span / bucket) + 1;
  const lanes = new Map();
  for (const x of tl) {
    const k = x.source || 'other';
    const l = lanes.get(k) || { name: k, total: 0, b: new Array(nb).fill(0) };
    const i = Math.min(nb - 1, Math.floor((new Date(x.t).getTime() - t0) / bucket));
    l.b[i] += x.n; l.total += x.n;
    lanes.set(k, l);
  }
  let L = [...lanes.values()].sort((a, b) => b.total - a.total);
  if (L.length > 9) {
    const rest = { name: `${L.length - 8} more sources`, total: 0, b: new Array(nb).fill(0) };
    for (const l of L.slice(8)) { rest.total += l.total; l.b.forEach((v, i) => (rest.b[i] += v)); }
    L = [...L.slice(0, 8), rest];
  }
  const mx = Math.max(1, ...L.flatMap((l) => l.b));
  const draw = () => {
    const W = Math.max(280, box.clientWidth);
    const lw = W < 520 ? 92 : 150, pw = W - lw - 8, rh = 24, H = L.length * rh + 22;
    const x = (t) => lw + ((t - t0) / span) * pw;
    const bw = Math.max(1.5, (bucket / span) * pw - 1);
    const ticks = [];
    const step = span > 300 * 864e5 ? 60 : span > 120 * 864e5 ? 30 : span > 45 * 864e5 ? 14 : 7;
    for (let t = end; t >= t0; t -= step * 864e5) ticks.push(t);
    let svg = `<svg class="enp-swsvg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">`;
    L.forEach((l, i) => {
      const y = i * rh;
      svg += `<g><rect x="0" y="${y}" width="${W}" height="${rh}" class="sw-bg${i % 2 ? ' alt' : ''}"/>
        <text x="8" y="${y + 15.5}" class="sw-lab">${esc(l.name.length > (lw < 120 ? 11 : 20) ? l.name.slice(0, lw < 120 ? 10 : 19) + '…' : l.name)}</text>
        <text x="${lw - 6}" y="${y + 15.5}" class="sw-n" text-anchor="end">${l.total}</text>
        <title>${esc(l.name)}: ${l.total} mentions</title>`;
      l.b.forEach((v, j) => {
        if (!v) return;
        const h = 4 + (v / mx) * (rh - 8);
        svg += `<rect class="sw-bar" x="${x(t0 + j * bucket).toFixed(1)}" y="${(y + rh / 2 - h / 2).toFixed(1)}" width="${bw.toFixed(1)}" height="${h.toFixed(1)}" rx="1"><title>${esc(l.name)} · ${fmtDate(t0 + j * bucket)} · ${v}</title></rect>`;
      });
      svg += '</g>';
    });
    const ay = L.length * rh;
    svg += `<line x1="${lw}" x2="${W}" y1="${ay + 0.5}" y2="${ay + 0.5}" class="sw-axis"/>`;
    for (const t of ticks) svg += `<text x="${x(t)}" y="${ay + 15}" class="sw-tick" text-anchor="${t === end ? 'end' : 'middle'}">${t === end ? 'today' : fmtDate(t)}</text>`;
    svg += `<rect class="sw-brush" x="0" y="0" width="0" height="${ay}" visibility="hidden"/>`;
    svg += `<rect class="sw-hit" x="${lw}" y="0" width="${pw}" height="${ay}"/></svg>`;
    box.innerHTML = svg;
    const s = box.querySelector('svg'), br = s.querySelector('.sw-brush'), hit = s.querySelector('.sw-hit');
    const showWin = () => {
      if (!P.win) { br.setAttribute('visibility', 'hidden'); return; }
      const a = x(P.win[0].getTime()), b = x(P.win[1].getTime());
      br.setAttribute('x', a); br.setAttribute('width', Math.max(2, b - a)); br.setAttribute('visibility', 'visible');
    };
    showWin();
    let start = null;
    const tAt = (ev) => { const r = s.getBoundingClientRect(); return t0 + Math.max(0, Math.min(1, (ev.clientX - r.left - lw) / pw)) * span; };
    hit.addEventListener('pointerdown', (ev) => { start = tAt(ev); hit.setPointerCapture(ev.pointerId); });
    hit.addEventListener('pointermove', (ev) => {
      if (start == null) return;
      const t = tAt(ev);
      const a = Math.min(start, t), b = Math.max(start, t);
      br.setAttribute('x', x(a)); br.setAttribute('width', Math.max(1, x(b) - x(a))); br.setAttribute('visibility', 'visible');
    });
    hit.addEventListener('pointerup', (ev) => {
      if (start == null) return;
      const t = tAt(ev), a = Math.min(start, t), b = Math.max(start, t);
      start = null;
      if (b - a < bucket * 0.8) { // a click picks one bucket
        const i = Math.floor((a - t0) / bucket);
        setWin(P, [new Date(t0 + i * bucket), new Date(t0 + (i + 1) * bucket)]);
      } else setWin(P, [new Date(a), new Date(b)]);
    });
    hit.addEventListener('dblclick', () => setWin(P, null));
  };
  P.redrawSwim = draw;
  draw();
  const ro = new ResizeObserver(() => { if (box.isConnected) draw(); else ro.disconnect(); });
  ro.observe(box);
}

function setWin(P, w) {
  P.win = w;
  const c = P.$('#enp-activity');
  c.querySelector('.enp-winx').hidden = !w;
  c.querySelector('.enp-winl').innerHTML = w ? `focused on <b>${fmtDate(w[0])}</b> → <b>${fmtDate(w[1] - 1)}</b> · claims and references below are filtered` : 'drag across the chart to focus claims and references on a time window';
  P.redrawSwim?.();
  drawClaims(P);
  drawRefs(P);
}

// ------------------------------------------------------------------------------------------------ claims
function evidenceItem(e) {
  if (e.verdict) return `<li class="ev-user"><span class="ev-v ${esc(e.verdict)}">${e.verdict === 'confirm' ? 'You agreed' : `You disagreed${e.reason ? `: ${esc(reasonLabel(e.reason).toLowerCase())}` : ''}`}</span>${e.note ? ` “${esc(e.note)}”` : ''} <span class="mono en-dim">${fmtDate(e.ts)}</span></li>`;
  if (e.reasons) {
    return `<li class="ev-inf"><div class="ev-sc mono">score ${e.score ?? '—'} · ${e.features ?? '?'} shared features · ${esc(e.band || '')}</div>
      <ul class="ev-reasons">${e.reasons.slice(0, 8).map((r) => `<li><span class="ev-w"><i style="width:${Math.min(100, (r.weight || 0) * 45)}%"></i></span><span>${esc(r.text)}</span></li>`).join('')}</ul></li>`;
  }
  const src = safeUrl(e.url) ? `<a href="${esc(safeUrl(e.url))}" target="_blank" rel="noopener">${esc(e.source || 'source')}</a>` : esc(e.source || e.ref_type || 'source');
  const news = e.ref_type === 'article' && e.ref_id ? ` <a class="ev-open" href="#news/article/${encodeURIComponent(e.ref_id)}">open in News</a>` : '';
  return `<li>${e.quote ? `<blockquote>“${esc(e.quote)}”</blockquote>` : e.note ? `<div class="ev-note">${esc(e.note)}</div>` : ''}
    <div class="ev-meta">${tierBadge(e.tier)}<span class="ev-src">${src}</span>${e.ts ? `<span class="mono en-dim">${fmtDate(e.ts)}</span>` : ''}${news}</div></li>`;
}

// What the analyst can do on a row: nothing on reference listings and feed facts; one "Disagree…" with a reason on
// reported claims and hypotheses (intelx.js); Undo once a verdict is in.
const voteCell = disagreeCell;

function claimRow(P, c) {
  const ev = Array.isArray(c.evidence) ? c.evidence : [];
  const q = ev.find((e) => e.quote)?.quote;
  const tiers = [...new Set(ev.map((e) => e.tier).filter(Boolean))].sort();
  const n = c.evidence_count || ev.length;
  const otype = c.other_type || typeOf(c.other);
  const hyp = c.band === 'hypothesis';
  const src = c.origin === 'inferred' ? 'computed by the hub' : c.origin === 'user' ? 'you' : ((c.sources || []).length > 1 ? `${c.sources.length} claim sources` : ((c.sources || [])[0] || '').slice(0, 22));
  return `<div class="enp-claim${P.open.has(c.id) ? ' open' : ''}${c.verdict ? ' voted ' + c.verdict : ''}${hyp ? ' hyp' : ''}" data-cid="${esc(c.id)}">
    <div class="cl-row">
      <span class="cl-line o-${esc(c.origin)}" title="${esc(ORIGINS[c.origin]?.label)}: ${esc(ORIGINS[c.origin]?.desc)}"></span>
      <span class="cl-pred">${esc(predText(c.predicate, c.direction))}</span>
      ${chip(c.other, { type: otype, name: c.other_name })}
      ${c.conflict ? '<span class="cl-conf" title="Another source attributes this to a different entity of the same type">contested</span>' : ''}
      ${techLabel(P, c)}
      ${c.authoritative ? `<span class="cl-ref" title="${esc(c.origin === 'observed' ? 'A fact from a data source or threat list' : 'Listed by a reference set (MITRE ATT&CK, MISP galaxy)')}: nothing to judge">reference</span>` : ''}
      <span class="cl-sp"></span>
      ${hyp ? hypPill(whyOf(c)) : bandPill(c.confidence, c.band, whyOf(c))}
      <span class="cl-src mono" title="${esc((c.sources || []).join(', '))}">${tiers.map(tierBadge).join('')}${esc(src)}</span>
      <button class="cl-evb" data-act="ev" data-cid="${esc(c.id)}" aria-expanded="${P.open.has(c.id)}">${n} evidence <svg class="i caret"><use href="#i-caret"/></svg></button>
      ${voteCell(c)}
    </div>
    ${whyOf(c) ? `<div class="cl-why">${hyp ? '' : `<span class="mono">why ${c.confidence != null ? Math.round(c.confidence * 100) : '—'}</span> `}${esc(whyOf(c))}</div>` : ''}
    ${c.verdict_note ? `<div class="cl-why cl-note">Your note: “${esc(c.verdict_note)}”</div>` : ''}
    ${q && !P.open.has(c.id) ? `<div class="cl-q">“${esc(q.length > 200 ? q.slice(0, 198) + '…' : q)}”</div>` : ''}
    <div class="cl-ev"><ul>${ev.map(evidenceItem).join('')}</ul>${n > ev.length ? `<button class="src-btn sm" data-act="allev">Load all ${n} evidence items</button>` : ''}
      <div class="cl-when mono en-dim">${c.first_seen ? `first ${fmtDate(c.first_seen)} · last ${fmtDate(c.last_seen)}` : 'undated reference relation'} · ${esc(originLabel(c.origin).toLowerCase())} · id ${esc(c.id)}</div></div>
  </div>`;
}

// Rows of one origin, grouped by relationship and the other end's type.
function claimGroups(P, o, cs) {
  const groups = new Map();
  for (const c of cs) {
    const k = `${o}|${c.direction}|${c.predicate}|${c.other_type || typeOf(c.other)}`;
    (groups.get(k) || groups.set(k, []).get(k)).push(c);
  }
  // quoted (article) evidence first, then more evidence, then confidence
  const rank = (c) => ((Array.isArray(c.evidence) && c.evidence.some((e) => e.quote)) ? 1000 : 0) + (c.evidence_count || 0) * 10 + (c.confidence || 0);
  for (const l of groups.values()) l.sort((x, y) => rank(y) - rank(x));
  const gq = (l) => l.some((c) => rank(c) >= 1000);
  const gl = [...groups.entries()].sort((a, b) => (isTech(a[1][0]) - isTech(b[1][0])) || (gq(b[1]) - gq(a[1])) || b[1].length - a[1].length);
  return gl.map(([k, list]) => {
    const c0 = list[0];
    const ot = c0.other_type || typeOf(c0.other);
    const lim = P.more.has(k) ? list.length : isTech(c0) ? 3 : 6;
    return `<div class="cg"><div class="cg-h"><span>${esc(predText(c0.predicate, c0.direction))}</span><span class="cg-t" style="--c:${tcolor(ot)}">${icon(ot)}${esc(tmeta(ot)[0])}</span><span class="mono en-dim">${list.length}</span>${isTech(c0) ? '<a class="cg-l" href="#enp-attack" data-jump>see ATT&CK strip</a>' : ''}</div>
      ${list.slice(0, lim).map((c) => claimRow(P, c)).join('')}
      ${list.length > lim ? `<button class="cg-more" data-act="more" data-g="${esc(k)}">Show ${list.length - lim} more</button>` : ''}</div>`;
  }).join('') || emptyState({ why: 'None in the selected window.', size: 'inline' });
}

function drawClaims(P) {
  const box = P.$('#enp-claims');
  const d = P.d;
  const parts = [];
  for (const o of ['observed', 'reported', 'user', 'local']) {
    const all = d.claims?.[o] || [];
    if (!all.length && (o === 'user' || o === 'local')) continue;
    const cs = all.filter((c) => claimInWin(P, c));
    const meta = ORIGINS[o];
    const head = `<div class="og-h"><span class="og-sw o-${o}"></span><h4>${esc(meta.label)}</h4><span class="mono en-dim">${P.win ? `${cs.length} of ${all.length}` : all.length} · ${esc(meta.desc)}</span></div>`;
    parts.push(all.length ? `<div class="og">${head}${claimGroups(P, o, cs)}</div>` : `<div class="og og-empty">${head}</div>`);
  }
  // hypotheses: one collapsed group, opened by the same "Show hypotheses" switch as Related
  const hyp = d.claims?.inferred || [];
  if (hyp.length) {
    const cs = hyp.filter((c) => claimInWin(P, c));
    parts.push(`<div class="og og-hyp${P.showHyp ? ' open' : ''}"><div class="og-h"><span class="og-sw o-inferred"></span><h4>Hypotheses</h4>
      <span class="mono en-dim">${P.win ? `${cs.length} of ${hyp.length}` : hyp.length} · links the hub computed; no source has said them</span>
      <button class="src-btn sm og-tg" data-act="hyp" aria-expanded="${P.showHyp}">${P.showHyp ? 'Hide hypotheses' : `Show hypotheses (${hyp.length})`}</button></div>
      <p class="og-exp">${esc(HYPOTHESIS_WHY)} They never count as claims and always rank below what a named source reported.</p>
      ${P.showHyp ? claimGroups(P, 'inferred', cs) : ''}</div>`);
  }
  // rejected links: out of every list and count, waiting here to be undone
  const rej = d.rejected || [];
  if (rej.length) {
    parts.push(`<details class="og og-rej"${P.rejOpen ? ' open' : ''}><summary class="og-h"><span class="og-sw o-rej"></span><h4>You disagreed (${rej.length})</h4>
      <span class="mono en-dim">hidden from this page, Related and the graph · undo to bring one back</span></summary>
      ${rej.map((c) => claimRow(P, c)).join('')}</details>`);
  }
  const n = counted(d).length;
  box.innerHTML = `<div class="enp-ch"><h3>Claims</h3><span class="mono en-dim">${n} · grouped by where they come from</span>
    <span class="og-legend">${['observed', 'reported', 'user', 'inferred'].map((o) => `<span><i class="og-sw o-${o}"></i>${esc(ORIGINS[o].label)}</span>`).join('')}</span></div>${parts.join('')}`;
  const det = box.querySelector('.og-rej');
  if (det) det.addEventListener('toggle', () => { P.rejOpen = det.open; });
}

// "Show hypotheses" (remembered in this browser): the Hypotheses group on the page and the hub-computed entries in Related.
function setHyp(P, on) {
  P.showHyp = on;
  LS.set(HYP_KEY, on);
  drawClaims(P);
  P.$('#enp-related').innerHTML = related(P);
}

// One toast per message: a repeated verdict message replaces the one still showing instead of stacking.
function say(msg) {
  document.querySelectorAll('#toasts .toast').forEach((t) => { if (t.textContent === msg) t.remove(); });
  toast(msg);
}

async function feedback(P, cid, verdict, btn, body = {}) {
  if (P.busy) return;                      // one verdict at a time: a second click while one is saving is ignored
  P.busy = true;
  btn.disabled = true;
  try {
    await api.post(`/api/entities/claims/${encodeURIComponent(cid)}/feedback`, { verdict, ...body });
    say(verdict === 'confirm' ? 'Noted. You trust this claim; it is marked as yours.'
      : verdict === 'reject' ? 'Noted. The link is hidden; undo it under “You disagreed”.'
        : 'Undone. Your verdict is withdrawn.');
    await refresh(P);
  } catch (e) { toast(`Feedback failed: ${e.message}`, true); btn.disabled = false; if (body.reason) { e.toasted = true; throw e; } }
  finally { P.busy = false; }
}

// Redraw the whole page from fresh data (counts, Related, contested, claims, identity), keeping the scroll position.
async function refresh(P) {
  const fresh = await api.get(`/api/entities/${encodeURIComponent(P.d.id)}`, { evidence: 8, bucket: 'day' }).catch(() => null);
  if (!fresh || P.my !== seq) return;
  const top = P.pane.scrollTop;
  P.d = fresh;
  const win = P.win;
  draw(P);
  if (win) setWin(P, win);
  P.pane.scrollTop = top;
}

async function loadAllEvidence(P) {
  const fresh = await api.get(`/api/entities/${encodeURIComponent(P.d.id)}`, { evidence: 25, bucket: 'day' }).catch(() => null);
  if (!fresh || P.my !== seq) return;
  P.d.claims = fresh.claims;
  drawClaims(P);
}

// ------------------------------------------------------------------------------------------------ contested
function contested(P) {
  const d = P.d;
  const att = allClaims(d).filter((c) => c.predicate === 'attributed-to' && c.direction === 'out' && c.origin !== 'user' && !isHypothesis(c.origin));
  const byType = {};
  for (const c of att) (byType[c.other_type || typeOf(c.other)] ||= []).push(c);
  const sets = Object.entries(byType).filter(([, l]) => new Set(l.map((c) => c.other)).size > 1);
  if (!sets.length) return '';
  return `<div class="enp-ch"><h3>Contested attribution</h3><span class="mono en-dim">sources disagree · the hub never averages them</span></div>
    ${sets.map(([t, list]) => {
      const cand = new Map();
      for (const c of list) (cand.get(c.other) || cand.set(c.other, []).get(c.other)).push(c);
      const cols = [...cand.entries()].sort((a, b) => Math.max(...b[1].map((c) => c.confidence || 0)) - Math.max(...a[1].map((c) => c.confidence || 0)));
      return `<p class="ct-why">${cand.size} different ${esc(tmeta(t)[0].toLowerCase())}s are named for <b>${esc(d.name)}</b>. Compare the evidence, then pick the one you trust; disagreeing hides a claim until you undo it.</p>
      <div class="ct-cols">${cols.map(([oid, cs]) => {
        const best = cs.reduce((a, b) => ((b.confidence || 0) > (a.confidence || 0) ? b : a));
        const ev = cs.flatMap((c) => (Array.isArray(c.evidence) ? c.evidence : []));
        const q = ev.filter((e) => e.quote).slice(0, 2);
        const reasons = ev.find((e) => e.reasons)?.reasons || [];
        return `<div class="ct-col">
          <div class="ct-top">${chip(oid, { type: best.other_type, name: best.other_name })}<button class="icon-btn" data-act="peek" data-id="${esc(oid)}" title="Details" aria-label="Details">⤢</button></div>
          <div class="ct-m">${bandPill(best.confidence, best.band, whyOf(best))}<span class="mono en-dim">${cs.map((c) => esc(originLabel(c.origin).toLowerCase())).join(' + ')}</span></div>
          ${whyOf(best) ? `<div class="cl-why ct-why2">${esc(whyOf(best))}</div>` : ''}
          <div class="ct-src">${[...new Set(cs.flatMap((c) => c.sources || []))].slice(0, 4).map((s) => `<span>${esc(s)}</span>`).join('')}</div>
          ${q.map((e) => `<blockquote>“${esc(e.quote.slice(0, 180))}”<cite>${tierBadge(e.tier)}${safeUrl(e.url) ? `<a href="${esc(safeUrl(e.url))}" target="_blank" rel="noopener">${esc(e.source || 'source')}</a>` : esc(e.source || '')} ${fmtDate(e.ts)}</cite></blockquote>`).join('')}
          ${reasons.length ? `<ul class="ev-reasons">${reasons.slice(0, 3).map((r) => `<li><span class="ev-w"><i style="width:${Math.min(100, r.weight * 45)}%"></i></span><span>${esc(r.text)}</span></li>`).join('')}</ul>` : ''}
          <div class="ct-act">${best.verdict === 'confirm' ? `<span class="cl-voted confirm">✓ You trust this one</span><button class="cl-undo" data-act="clear" data-cid="${esc(best.id)}">Undo</button>`
            : best.authoritative ? '<span class="cl-ref">reference</span>'
              : `<button class="src-btn sm cl-yes2" data-act="confirm" data-cid="${esc(best.id)}" title="You trust this attribution">This one</button><button class="src-btn sm" data-act="disagree" data-cid="${esc(best.id)}">Disagree…</button>`}</div>
        </div>`;
      }).join('')}</div>`;
    }).join('')}`;
}

// ------------------------------------------------------------------------------------------------ ATT&CK strip
async function attack(P, techs) {
  const box = P.$('#enp-attack');
  const idx = await techniqueIndex();
  if (P.my !== seq) return;
  const by = new Map();
  for (const c of techs) {
    const kind = techKind(c);
    const cur = by.get(c.other);
    if (!cur || TECH_RANK[kind] < TECH_RANK[cur.kind]) by.set(c.other, { id: c.other, name: c.other_name, kind, confirmed: kind === 'confirmed', c });
  }
  const cols = TACTICS.map(([k, l]) => ({ k, l, items: [] }));
  const other = [];
  for (const t of by.values()) {
    const info = idx.get(t.id);
    const tac = info?.tactics || [];
    const tid = info?.attack_id || nameOf(t.id);
    const title = info?.title || String(t.name || '').replace(/^T[\d.]+\s*/, '');
    const it = { ...t, tid, title };
    let placed = false;
    for (const ta of tac) { const col = cols.find((c) => c.k === (TACTIC_ALIAS[ta] || ta)); if (col) { col.items.push(it); placed = true; } }
    if (!placed) other.push(it);
  }
  cols.forEach((c) => c.items.sort((a, b) => (TECH_RANK[a.kind] - TECH_RANK[b.kind]) || a.tid.localeCompare(b.tid)));
  const n = (k) => [...by.values()].filter((x) => x.kind === k).length;
  const fromArt = ['named', 'likely', 'possible'].filter((k) => n(k));
  // catalogue and analyst links keep their wording; a technique read from article text carries its label and, on
  // hover or focus, the sentence it came from (core/ttp.js evidence card) instead of a title
  const cell = (it) => {
    if (it.confirmed) {
      return `<a class="ak-c conf" href="#entities/${encodeURIComponent(it.id)}" data-entity="${esc(it.id)}" title="${esc(it.tid)} ${esc(it.title)} · confirmed (${esc(originLabel(it.c.origin).toLowerCase())})">
    <span class="mono">${esc(it.tid)}</span><span class="ak-n">${esc(it.title)}</span>${(() => { const na = ttpArticleCount(it.c); return na ? `<span class="ak-also">also in ${na} article${na === 1 ? '' : 's'}</span>` : ''; })()}</a>`;
    }
    const q = ttpQuote(it.c);
    return `<a class="ak-c ${it.kind === 'possible' ? 'sug' : 'art'} k-${esc(it.kind)}" href="#entities/${encodeURIComponent(it.id)}" data-entity="${esc(it.id)}" ${ttpAttrs({ id: it.tid, kind: it.kind, name: it.title, quote: q?.quote, source: q?.source, page: `#entities/${encodeURIComponent(it.id)}` })}>
    <span class="mono">${esc(it.tid)}</span><span class="ak-n">${esc(it.title)}</span><span class="ak-s">${esc(TTP_KINDS[it.kind].short)}</span></a>`;
  };
  const LIM = 6;
  const sw = { named: 'Named in an article', likely: 'Likely', possible: 'Possible' };
  box.innerHTML = `<div class="enp-ch"><h3>ATT&CK techniques</h3><span class="mono en-dim">${[`${n('confirmed')} confirmed`, ...fromArt.map((k) => `${n(k)} ${k === 'named' ? 'named in articles' : k}`)].join(' · ')} · ${cols.filter((c) => c.items.length).length} of ${TACTICS.length} tactics</span>
      <span class="ak-legend">${n('confirmed') ? '<span><i class="ak-sw conf"></i>confirmed</span>' : ''}${fromArt.map((k) => `<span title="${esc(TTP_KINDS[k].why)}"><i class="ak-sw ${k === 'possible' ? 'sug' : 'art'} k-${k}"></i>${esc(sw[k].toLowerCase())}</span>`).join('')}</span>
      <button class="src-btn sm" data-act2="nav" title="ATT&CK Navigator layer (JSON); possible techniques are left out">Navigator layer</button></div>
    ${fromArt.length ? `<p class="ak-cav">Named, likely and possible techniques were read automatically from article text and can be wrong. ${esc(TTP_HOW)}</p>` : ''}
    <div class="ak-strip">${cols.map((c) => `<div class="ak-col${c.items.length ? '' : ' empty'}"><div class="ak-h" title="${esc(c.l)}"><span>${esc(c.l)}</span><b class="mono">${c.items.length || ''}</b></div>
      ${c.items.slice(0, LIM).map(cell).join('')}${c.items.length > LIM ? `<button class="ak-more" data-k="${c.k}">+${c.items.length - LIM}</button><div class="ak-rest" hidden>${c.items.slice(LIM).map(cell).join('')}</div>` : ''}</div>`).join('')}</div>
    ${other.length ? `<div class="ak-other"><span class="label">No tactic in ATT&CK data</span>${other.map(cell).join('')}</div>` : ''}`;
  wireTtpTips();
  box.onclick = (e) => {
    const m = e.target.closest('.ak-more');
    if (m) { m.nextElementSibling.hidden = false; m.remove(); return; }
    if (e.target.closest('[data-act2="nav"]')) {
      const SCORE = { confirmed: 100, named: TTP_KINDS.named.confidence, likely: TTP_KINDS.likely.confidence };
      const layer = {
        name: `${P.d.name} (Night Desk)`, versions: { attack: '16', navigator: '5.1.0', layer: '4.5' }, domain: 'enterprise-attack',
        description: `Techniques for ${P.d.name} from Night Desk claims. Score 100 = confirmed (MITRE ATT&CK, a feed or you), 85 = named in an article, 50 = likely (found automatically in article text; it can be wrong). Possible ones are left out.`,
        techniques: [...by.values()].filter((t) => t.kind !== 'possible').map((t) => ({ techniqueID: idx.get(t.id)?.attack_id || nameOf(t.id), score: SCORE[t.kind],
          comment: `${t.kind === 'confirmed' ? originLabel(t.c.origin).toLowerCase() : TTP_KINDS[t.kind].comment} · ${(t.c.sources || []).join(', ')}` })),
        gradient: { colors: ['#f2c94c33', '#f2c94c'], minValue: 0, maxValue: 100 },
      };
      download(`${P.d.id.replace(/[^\w.-]+/g, '_')}-layer.json`, JSON.stringify(layer, null, 2));
    }
  };
}

// ------------------------------------------------------------------------------------------------ IOC table
function iocTable(P, rows) {
  const box = P.$('#enp-iocs');
  let f = '', ty = '';
  const types = [...new Set(rows.map((r) => r.type))];
  const drawT = () => {
    const list = rows.filter((r) => (!ty || r.type === ty) && (!f || r.value.toLowerCase().includes(f)));
    box.querySelector('tbody').innerHTML = list.slice(0, 300).map((r) => `<tr data-net="${esc(r.value)}">
      <td data-l="Type"><span class="en-tbadge" style="--c:${tcolor(r.type)}">${icon(r.type)}${esc(tmeta(r.type)[0])}</span></td>
      <td class="mono io-v" data-l="Indicator"><a href="#entities/${encodeURIComponent(r.id)}" data-entity="${esc(r.id)}">${esc(defang(r.value, r.type))}</a><span class="io-net" hidden title="Matched in your imported network logs">Seen on your network</span></td>
      <td data-l="Relationship">${esc(r.how)}</td>
      <td data-l="Origin" title="${esc(ORIGINS[r.origin]?.desc || '')}"><span class="cl-line o-${esc(r.origin)} sm"></span>${esc(originLabel(r.origin))}</td>
      <td data-l="Confidence">${r.confidence != null ? bandPill(r.confidence, r.band, r.why) : '<span class="en-dim mono">—</span>'}</td>
      <td class="mono" data-l="Sources" title="${esc(r.sources.join(', '))}">${r.sources.length ? esc(r.sources.length > 1 ? `${r.sources.length} claim sources` : r.sources[0]) : '<span class="en-dim">same article</span>'}</td>
      <td class="mono" data-l="First">${fmtDate(r.first_seen)}</td><td class="mono" data-l="Last">${fmtDate(r.last_seen)}</td>
      <td class="r"><button class="icon-btn" data-cp="${esc(r.value)}" title="Copy (not defanged)">⧉</button></td></tr>`).join('')
      + (list.length > 300 ? `<tr><td colspan="9" class="en-dim">+${list.length - 300} more in the export</td></tr>` : '');
    box.querySelector('.io-n').textContent = `${list.length} of ${rows.length}`;
    P.markNet?.();
  };
  box.innerHTML = `<div class="enp-ch"><h3>Indicators</h3><span class="mono en-dim io-n"></span>
      <div class="io-tools">
        <div class="io-types">${['', ...types].map((t) => `<button class="${t === ty ? 'on' : ''}" data-ty="${t}">${t ? esc(tmeta(t)[0]) : 'All'}</button>`).join('')}</div>
        <input class="io-f" placeholder="Filter" spellcheck="false" aria-label="Filter indicators">
        <button class="src-btn sm" data-x="csv">CSV</button><button class="src-btn sm" data-x="stix" title="STIX 2.1 bundle of the indicators a source tied to this entity; ones only named in the same article are left out">STIX 2.1</button><button class="src-btn sm" data-x="copy">Copy all</button>
      </div></div>
    <div class="io-wrap"><table class="io-t"><thead><tr><th>Type</th><th>Indicator</th><th>Relationship</th><th>Origin</th><th>Confidence</th><th>Sources</th><th>First</th><th>Last</th><th></th></tr></thead><tbody></tbody></table></div>`;
  box.querySelector('.io-f').oninput = (e) => { f = e.target.value.toLowerCase().trim(); drawT(); };
  box.addEventListener('click', (e) => {
    const b = e.target.closest('[data-ty]');
    if (b) { ty = b.dataset.ty; box.querySelectorAll('[data-ty]').forEach((x) => x.classList.toggle('on', x === b)); drawT(); return; }
    const cp = e.target.closest('[data-cp]');
    if (cp) { copy(cp.dataset.cp); return; }
    const x = e.target.closest('[data-x]');
    if (!x) return;
    const list = rows.filter((r) => (!ty || r.type === ty) && (!f || r.value.toLowerCase().includes(f)));
    const base = P.d.id.replace(/[^\w.-]+/g, '_');
    if (x.dataset.x === 'csv') {
      const head = ['type', 'value', 'relationship', 'origin', 'confidence', 'band', 'sources', 'first_seen', 'last_seen', 'entity'];
      download(`${base}-iocs.csv`, [head.join(','), ...list.map((r) => [r.type, r.value, r.how, originLabel(r.origin), r.confidence ?? '', r.band ?? '', r.sources.join('; '), r.first_seen ?? '', r.last_seen ?? '', P.d.name].map(csvCell).join(','))].join('\n'), 'text/csv');
    } else if (x.dataset.x === 'stix') exportStix(P, list);
    else copy(list.map((r) => r.value).join('\n'));
  });
  drawT();
}

// STIX says "indicates": only indicators a source or feed tied to this entity go in. Hypotheses (named in the same
// article, or computed by the hub) are left out of the bundle; the CSV keeps them with their origin spelled out.
async function exportStix(P, iocs) {
  const sourced = iocs.filter((r) => !isHypothesis(r.origin));
  const left = iocs.length - sourced.length;
  const b = await stixBundle(P.d, sourced.map((r) => ({ ...r })));
  download(`${P.d.id.replace(/[^\w.-]+/g, '_')}-stix21.json`, JSON.stringify(b, null, 2));
  toast(`STIX 2.1 bundle: ${b.objects.filter((o) => o.type === 'indicator').length} indicators${left ? ` (${left} only named in the same article left out)` : ''}`);
}

// ------------------------------------------------------------------------------------------------ touches your network
async function touches(P, iocs) {
  const box = P.$('#enp-net');
  let sum;
  try { sum = await api.get('/api/netlog/summary'); } catch { return; } // no netlog package: keep hidden
  if (P.my !== seq) return;
  const self = IOC_TYPES.includes(P.d.type) ? [{ type: P.d.type, value: P.d.name }] : [];
  const self2 = P.d.type === 'cve' || P.d.type === 'prefix' ? [{ type: P.d.type, value: P.d.name }] : [];
  const vals = [...self, ...self2, ...iocs].filter((r) => ['ip', 'domain', 'hash', 'cve', 'prefix'].includes(r.type)).slice(0, 300);
  box.hidden = false;
  const head = '<div class="enp-ch"><h3>Touches your network</h3></div>';
  if (!sum.rows) {
    box.innerHTML = `${head}${emptyState({ why: `No network logs imported yet. <a href="#network/import">Connect your logs</a> to check whether ${vals.length ? `these ${vals.length} indicators` : 'this entity'} touched your devices.`, size: 'inline' })}`;
    return;
  }
  if (!vals.length) { box.innerHTML = `${head}${emptyState({ why: `No address, domain, hash or CVE to match against ${(sum.rows || 0).toLocaleString()} imported log rows.`, size: 'inline' })}`; return; }
  // one lookup for the entity and its indicators (GET /api/netlog/seen): alerts count as sightings
  const seen = await seenLookup(vals.map((v) => v.value)).catch(() => null);
  if (P.my !== seq) return;
  if (!seen) { box.innerHTML = `${head}${errorState({ retry: () => touches(P, iocs), title: '', why: "Couldn't check your network logs just now.", size: 'inline' })}`; return; }
  const hitRows = vals.map((v) => ({ ...v, it: seen.get(v.value) })).filter((v) => v.it?.seen);
  const hits = new Set(hitRows.map((v) => v.value));
  const devs = new Map(hitRows.flatMap((v) => v.it.devices.map((x) => [x.id, x.name])));
  const nInc = new Set(hitRows.filter((v) => v.it.incident).map((v) => v.it.incident.id)).size;
  P.markNet = () => P.$('#enp-iocs')?.querySelectorAll('tr[data-net]').forEach((tr) => { const s = tr.querySelector('.io-net'); if (s) s.hidden = !hits.has(tr.dataset.net); });
  P.markNet();
  box.classList.toggle('hit', hitRows.length > 0);
  box.innerHTML = `${head}${hitRows.length ? `
    <div class="net-k"><b class="mono">${hitRows.length}</b><span>of ${vals.length} indicator${vals.length === 1 ? '' : 's'} seen on your network${nInc ? ` · ${nInc} open incident${nInc === 1 ? '' : 's'}` : ''}</span></div>
    ${devs.size ? `<div class="net-row"><span class="label">Devices</span>${[...devs.values()].slice(0, 6).map((d) => `<span class="mono">${esc(d)}</span>`).join('')}</div>` : ''}
    <ul class="drawer-netl">${hitRows.slice(0, 6).map((v) => `<li><span class="mono">${esc(defang(v.value, v.type))}</span>${seenChip(v.it, { compact: true })}</li>`).join('')}</ul>`
    : `<p class="net-ok"><span class="ok-dot"></span>None of ${vals.length} indicator${vals.length === 1 ? '' : 's'} appear in your ${(sum.rows || 0).toLocaleString()} imported log rows (${fmtDate(sum.first)} → ${fmtDate(sum.last)}).</p>`}`;
}

// ------------------------------------------------------------------------------------------------ related, sources, refs
// Related: entities a counted claim links to. Hypotheses (links the hub computed, names from the same article)
// join only after "Show hypotheses", drawn dashed so they never pass for stated links.
function related(P) {
  const d = P.d;
  const hyp = (d.related_hypotheses || []).map((r) => ({ ...r, hyp: true }));
  const pool = [...(d.related || []), ...(P.showHyp ? hyp : [])];
  const rel = pool.filter((r) => !IOC_TYPES.includes(r.type));
  const g = {};
  for (const r of rel) (g[r.type || typeOf(r.id)] ||= []).push(r);
  const order = ['actor', 'campaign', 'malware', 'tool', 'cve', 'product', 'vendor', 'technique', 'org', 'sector', 'country', 'asn', 'prefix'];
  const keys = [...order.filter((k) => g[k]), ...Object.keys(g).filter((k) => !order.includes(k))];
  const nIoc = pool.length - rel.length;
  const nh = hyp.filter((r) => !IOC_TYPES.includes(r.type)).length;
  const tip = (r) => (r.how === 'inferred' ? 'Hypothesis: computed by the hub from shared tools and infrastructure' : 'Hypothesis: named in the same article');
  return `<div class="enp-ch"><h3>Related</h3><a class="mono enp-ext" href="#entities/graph/${encodeURIComponent(d.id)}">open graph ›</a></div>
    ${keys.length ? keys.map((k) => `<div class="rl-g"><div class="rl-h" style="--c:${tcolor(k)}">${icon(k)}<span>${esc(tmeta(k)[0])}</span><span class="mono en-dim">${g[k].length}</span></div>
      <div class="en-chips">${g[k].slice(0, 14).map((r) => (r.hyp ? `<span class="rl-hyp" title="${esc(tip(r))}">${chip(r.id, { type: r.type, name: r.name })}</span>` : chip(r.id, { type: r.type, name: r.name, n: r.n }))).join('')}${g[k].length > 14 ? `<span class="en-dim mono">+${g[k].length - 14}</span>` : ''}</div></div>`).join('')
      : emptyState({ why: nh && !P.showHyp ? 'No source links this to anything yet.' : 'No related entities.', size: 'inline' })}
    ${nIoc ? `<a class="rl-ioc" href="#enp-iocs" data-jump>${nIoc} related indicators in the table ›</a>` : ''}
    ${nh ? `<div class="rl-hypbar"><button class="src-btn sm" data-act="hyp" aria-pressed="${P.showHyp}">${P.showHyp ? 'Hide hypotheses' : `Show hypotheses (${nh})`}</button>
      <span class="en-dim">${P.showHyp ? 'Dashed chips are links the hub computed or names from the same article, not links a source stated.' : 'Links the hub computed or names from the same article; no source has stated them.'}</span></div>` : ''}`;
}

function sourceDist(d) {
  const by = {};
  for (const x of d.timeline || []) by[x.source] = (by[x.source] || 0) + x.n;
  for (const c of counted(d)) for (const s of c.sources || []) if (!(s in by)) by[s] = 0;
  const claimsBy = {};
  for (const c of counted(d)) for (const s of c.sources || []) claimsBy[s] = (claimsBy[s] || 0) + 1;
  const keys = Object.keys(by).sort((a, b) => (by[b] + (claimsBy[b] || 0)) - (by[a] + (claimsBy[a] || 0))).slice(0, 10);
  if (!keys.length) return `<div class="enp-ch"><h3>Sources</h3></div>${emptyState({ why: 'No sources.', size: 'inline' })}`;
  const mx = Math.max(1, ...keys.map((k) => by[k] + (claimsBy[k] || 0)));
  return `<div class="enp-ch"><h3>Sources</h3><span class="mono en-dim">mentions · claims</span></div>
    <div class="sd">${keys.map((k) => `<div class="sd-r"><span class="sd-n" title="${esc(k)}">${esc(k)}</span>
      <span class="sd-b"><i class="m" style="width:${(by[k] / mx) * 100}%"></i><i class="c" style="width:${((claimsBy[k] || 0) / mx) * 100}%"></i></span>
      <span class="mono sd-v">${by[k] || ''}${claimsBy[k] ? `<em>${claimsBy[k]}</em>` : ''}</span></div>`).join('')}</div>`;
}

// Threat lists holding this indicator (GET /api/entities/{id} listed_by): corroboration (some lists copy each other).
function threatLists(d) {
  const ls = d.listed_by || [];
  return `<div class="enp-ch"><h3>Threat lists</h3><span class="mono en-dim">${ls.filter((l) => l.active).length} now · ${ls.length} ever</span></div>
    <div class="sd">${ls.map((l) => `<div class="sd-r" title="${esc(`${l.name || l.source} (tier ${l.tier || '?'}) lists ${l.value}${l.malware ? ` as ${l.malware}` : ''}`)}">
      <span class="sd-n">${esc(l.name || l.source)}</span>
      <span class="mono en-dim">${esc(l.malware || l.category || '')}</span>
      <span class="mono sd-v">${l.active ? '<b>now</b>' : esc(l.last_listed ? fmtDate(l.last_listed) : '')}</span></div>`).join('')}</div>`;
}

function drawRefs(P) {
  const box = P.$('#enp-refs');
  const refs = (P.d.refs || []).filter((r) => inWin(P, r.ts) || !P.win);
  const L = refs.filter((r) => !P.win || inWin(P, r.ts));
  box.innerHTML = `<div class="enp-ch"><h3>Latest references</h3><span class="mono en-dim">${L.length}${P.win ? ' in window' : ''}</span></div>
    ${L.length ? `<ul class="rf">${L.slice(0, 14).map((r) => {
      const href = r.ref_type === 'article' ? `#news/article/${encodeURIComponent(r.ref_id)}` : safeUrl(r.url); // feed URLs: http(s) only
      return `<li><span class="rf-k">${esc(r.ref_type === 'article' ? 'article' : r.source || r.ref_type)}</span>
        ${href ? `<a href="${esc(href)}"${r.ref_type === 'article' ? '' : ' target="_blank" rel="noopener"'}>${esc((r.title || r.ref_id).slice(0, 140))}</a>` : `<span>${esc((r.title || r.ref_id).slice(0, 140))}</span>`}
        <span class="rf-m mono">${r.ref_type === 'article' ? esc(r.source || '') + ' · ' : ''}${fmtDate(r.ts)} · ${esc(r.method || '')}</span></li>`;
    }).join('')}</ul>` : emptyState({ why: 'No dated references.', size: 'inline' })}`;
}

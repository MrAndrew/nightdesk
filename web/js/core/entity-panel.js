// Shared entity side panel (drawer). Any view can open it:
//   import { openEntity } from '../core/entity-panel.js'; openEntity('actor:apt29', { actions, onArticle });
// or call window.ndOpenEntity(id, opts). Contract: okf/architecture/web-client.md#entity-panel
// Data: GET /api/entities/<id> (profile, timeline, claims with quotes, related). Degrades to the id alone.
import { api } from './api.js';
import { esc, ago, toast, safeUrl, epssText, epssTitle, epssTag, tierWord, TYPE_COLORS, typeColor } from './util.js';
import * as T from './time.js';
import { seenLookup, seenChip, seenLine } from './chips.js';
import { mountNotes } from './notes.js';
import { entitySummary } from './summary.js';
import { followButton } from './stack.js';
import { entityHref, LABELS, newTab } from './open.js';
import { emptyState, errorState } from './view.js';
import { isPhone } from './mobile.js';
import { pushPage } from './page.js';
import { ttpLinkKind, ttpQuote, ttpTag, ttpArticleCount, ttpTipOpen, wireTtpTips } from './ttp.js';

const TC = TYPE_COLORS;   // entity-type colours: the one shared map in core/util.js
const TYPES = {
  cve: ['CVE', TC.cve], actor: ['Threat actor', TC.actor], malware: ['Malware', TC.malware], tool: ['Tool', TC.tool],
  campaign: ['Campaign', TC.campaign], vendor: ['Vendor', TC.vendor], product: ['Product', TC.product], org: ['Organisation', TC.org],
  technique: ['Technique', TC.technique], ip: ['IP address', TC.ip], domain: ['Domain', TC.domain], url: ['URL', TC.url],
  hash: ['File hash', TC.hash], country: ['Country', TC.country], sector: ['Sector', TC.sector], asn: ['Network owner (ASN)', TC.asn], prefix: ['Address range', TC.prefix],
};
const IOC = new Set(['ip', 'domain', 'url', 'hash', 'asn', 'prefix']);
const tmeta = (t) => TYPES[t] || [t || 'Entity', typeColor(t)];
const typeOf = (id) => String(id).split(':')[0];
const nameOf = (id) => String(id).split(':').slice(1).join(':');
const defang = (v, t) => (t === 'url' ? v.replace(/^http/i, 'hxxp').replace(/\./g, '[.]') : t === 'ip' || t === 'domain' ? v.replace(/\./g, '[.]') : v);
const PRED = {
  uses: 'uses', targets: 'targets', 'attributed-to': 'is attributed to', 'communicates-with': 'communicates with', 'linked-to': 'is linked to',
  exploits: 'exploits', 'variant-of': 'is a variant of', drops: 'drops', 'part-of': 'is part of', delivers: 'delivers', affects: 'affects',
  'made-by': 'is made by', 'announced-by': 'was announced by', 'in-prefix': 'is in prefix', indicates: 'indicates',
};
const predText = (p, dir) => (dir === 'in' ? `← ${p}` : PRED[p] || p.replace(/-/g, ' '));

let el, stack = [], cur = null, opts = {};

function ensure() {
  if (el) return el;
  el = document.createElement('aside');
  el.className = 'ep';
  el.setAttribute('aria-hidden', 'true');
  el.setAttribute('role', 'dialog');
  el.setAttribute('aria-label', 'Entity details');
  el.tabIndex = -1;
  el.inert = true;   // off screen: out of the Tab order until it opens
  el.innerHTML = `
    <div class="ep-bar">
      <button class="ep-back" hidden title="Back (Backspace)"><svg class="i" viewBox="0 0 24 24"><path d="m14 6-6 6 6 6" fill="none" stroke="currentColor" stroke-width="1.8"/></svg><span>Back</span></button>
      <span class="ep-crumb"></span>
      <a class="ep-full" href="#" data-open-full>${LABELS.full}</a>
      <button class="icon-btn ep-x" title="Close (Esc)"><svg class="i"><use href="#i-x"/></svg></button>
    </div>
    <div class="ep-body"></div>`;
  document.body.append(el);
  ensureScrim();
  el.querySelector('.ep-x').onclick = closeEntity;
  el.querySelector('.ep-back').onclick = back;
  el.addEventListener('click', (e) => {
    const c = e.target.closest('[data-ep]');
    if (c && newTab(e)) return;   // a real link: the browser opens the full page in a new tab
    if (c) { e.preventDefault(); e.stopPropagation(); render(c.dataset.ep, true); el.focus({ preventScroll: true }); return; }
    const cp = e.target.closest('[data-epcopy]');
    if (cp) { navigator.clipboard?.writeText(cp.dataset.epcopy).then(() => toast('Copied'), () => toast('Copy failed', true)); return; }
    const art = e.target.closest('[data-eparticle]');
    if (art && opts.onArticle) { e.preventDefault(); opts.onArticle(art.dataset.eparticle); }
    const act = e.target.closest('[data-epact]');
    if (act) { const a = (opts.actions || [])[+act.dataset.epact]; if (a) { a.onClick(cur); if (a.close) closeEntity(); else render(cur, false); } }
  });
  // The panel consumes its own Esc: listening on window in the capture phase runs before every document listener
  // (News registers its own capture listener on document earlier), so one Esc closes only the panel. The Help desk
  // (modal, drawn over the panel) is the top layer while it is open: its own Esc closes it and leaves the panel.
  window.addEventListener('keydown', (e) => {
    // an evidence card over the panel (core/ttp.js) is the top layer: its own Esc closes only the card
    if (!(e.key === 'Escape' && el.classList.contains('open')) || document.body.classList.contains('help-open') || ttpTipOpen()) return;
    e.stopPropagation(); e.preventDefault(); closeEntity();
  }, true);
  // Backspace (outside a text field) steps back like the Back control.
  el.addEventListener('keydown', (e) => {
    if (e.key === 'Backspace' && stack.length && !e.target.closest('input, textarea, select, [contenteditable]')) { e.preventDefault(); back(); }
  });
  return el;
}

// How the user last acted (pointer or keyboard), on <html data-modality>: the event drawer and this panel take focus
// when they open, and Chrome then shows :focus-visible even after a mouse click. CSS (f:desk block) keeps the full
// amber ring for keyboard users only.
for (const [t, m] of [['pointerdown', 'pointer'], ['keydown', 'key']]) {
  window.addEventListener(t, (e) => { if (t === 'keydown' && (e.metaKey || e.ctrlKey || e.altKey) && e.key.length === 1) return; document.documentElement.dataset.modality = m; }, true);
}

// ---------------------------------------------------------------------------------------------------------
// One side panel at a time (okf/architecture/web-client.md#opening-things). The event drawer (core/shell.js)
// registers itself as the event host. An entity opened from inside the event drawer takes its place: the drawer
// closes, the panel opens with Back, and Back reopens that event. An entity opened from anywhere else closes the
// drawer without a Back step. The back-stack holds entity ids and {kind: 'event', id, title} entries.
let host = null;
export function setEventHost(h) { host = h; }
export const isEntityOpen = () => !!el && el.classList.contains('open');

// Swap one side panel for the other without both sliding at once (each element's transition is off for a frame).
export function swapNow(...els) {
  for (const x of els) if (x) x.classList.add('grammar-swap');
  requestAnimationFrame(() => requestAnimationFrame(() => els.forEach((x) => x?.classList.remove('grammar-swap'))));
}

function backLabel(p) {
  if (!p) return 'Back';
  if (typeof p === 'object') return `Back to the event${p.title ? `: ${p.title}` : ''}`;
  return `Back to ${tmeta(typeOf(p))[0].toLowerCase()} ${nameOf(p)}`;
}

function back() {
  const p = stack.pop();
  if (!p) return;
  if (typeof p === 'object' && p.kind === 'event' && host) {
    // the event drawer comes back in the panel's place; focus will return to what opened the event
    const o = opener; opener = null; refocusTo = null;
    swapNow(el, host.el());
    hide();
    host.open(p.id, { opener: o });
    return;
  }
  render(typeof p === 'object' ? p.id : p, false);
  el.focus({ preventScroll: true });
}

function hide() {
  el.classList.remove('open');
  el.setAttribute('aria-hidden', 'true');
  el.inert = true;
  scrimToggle(false);
  stack = []; cur = null;
}

// Focus: opening moves it into the drawer, closing returns it to what opened the drawer (when still on screen).
let opener = null, refocusTo = null;
export function closeEntity({ restore = true } = {}) {
  if (!el) return;
  const wasOpen = el.classList.contains('open');
  hide();
  if (!wasOpen) return;
  const o = opener; opener = null;
  const rf = refocusTo; refocusTo = null;
  if (!restore) return;
  if (rf && (el.contains(document.activeElement) || document.activeElement === document.body)) { rf(); return; }
  if (el.contains(document.activeElement) || document.activeElement === document.body) {
    const t = liveOpener(o);
    if (t) t.focus({ preventScroll: true });
    else document.activeElement?.blur?.();
  }
}

// The opener itself, or (when a live panel re-rendered it while the panel was open) the same value's chip in the
// same place: the same data-entity inside the same Ops panel, list row or view.
function liveOpener(o) {
  const shown = (x) => x && x.isConnected && x.getClientRects().length && !x.closest('[inert]');
  if (!o) return null;
  if (shown(o)) return o;
  const id = openerKey?.id;
  if (!id) return null;
  const sel = `[data-entity="${CSS.escape(id)}"]`;
  const scope = (openerKey.box && document.querySelector(openerKey.box)) || document.querySelector('.view.active') || document;
  return [...scope.querySelectorAll(sel)].find(shown) || null;
}
let openerKey = null;
function keyOf(a) {
  if (!a || !a.dataset?.entity) return null;
  const gs = a.closest('.grid-stack-item[gs-id]');
  return { id: a.dataset.entity, box: gs ? `.grid-stack-item[gs-id="${CSS.escape(gs.getAttribute('gs-id'))}"]` : null };
}

// o.source: the element the open came from (decides whether the event drawer becomes a Back step).
// On a phone there is no side panel: every entity chip, row and card opens the entity's own page (#entities/<id>, a
// pushed page with ‹ Intel), so Back returns to where it was tapped (design.md §4.4).
export function openEntity(id, o = {}) {
  if (isPhone() && id) {
    if (el?.classList.contains('open')) closeEntity({ restore: false });
    hideCard(0);
    pushPage(entityHref(id));
    return;
  }
  ensure();
  opts = o;
  stack = [];
  const a = document.activeElement;
  const src = o.source || a;
  if (!el.classList.contains('open')) {
    // a chip clicked with the mouse may not take focus (Safari): the chip it came from is the opener then
    const src0 = o.source?.isConnected && !el.contains(o.source) ? o.source : null;
    opener = a && a !== document.body && !el.contains(a) ? a : src0;
    // the hover card's Details button goes away with the card: its chip is the opener
    if (opener?.closest?.('.ep-card')) opener = src0 && !src0.closest('.ep-card') ? src0 : cardAnchor;
    openerKey = keyOf(opener);
    refocusTo = null;
    noCardOn(o.source || opener);
  }
  if (host?.isOpen()) {
    const fromEvent = !!src && host.el().contains(src);
    const ev = host.current();
    if (fromEvent) swapNow(el, host.el());
    const o2 = host.close();              // the drawer's own opener (the feed row), not the chip inside it
    if (fromEvent) {
      opener = o2 || null;
      if (ev?.id) stack.push({ kind: 'event', id: ev.id, title: ev.title || '' });
      // a mouse-opened event has no focusable opener: on close, focus goes where closing the drawer would send it
      refocusTo = () => host.refocus?.(o2, ev?.id);
    }
  }
  render(id, false);
  el.classList.add('open');
  el.setAttribute('aria-hidden', 'false');
  el.inert = false;
  scrimToggle(true);
  el.focus({ preventScroll: true });
}
window.ndOpenEntity = openEntity;

function chip(r) {
  const t = r.type || typeOf(r.id);
  const nm = r.name || r.other_name || nameOf(r.id);
  return `<a class="ep-chip" href="${esc(entityHref(r.id))}" style="--c:${tmeta(t)[1]}" data-ep="${esc(r.id)}" title="${esc(tmeta(t)[0])}">${esc(IOC.has(t) ? defang(nm, t) : nm)}${r.n > 1 ? `<i>${r.n}</i>` : ''}</a>`;
}

function spark(timeline) {
  const days = {};
  for (const x of timeline || []) { const k = T.dayKey(x.t); days[k] = (days[k] || 0) + (x.n || 0); }
  const keys = Object.keys(days).sort();
  if (!keys.length) return '';
  // continuous day axis over the last 90 days of activity
  const end = new Date(keys[keys.length - 1]), start = new Date(Math.min(end.getTime() - 29 * 864e5, Math.max(new Date(keys[0]).getTime(), end.getTime() - 89 * 864e5)));
  const axis = [];
  for (let d = new Date(start); d <= end; d = new Date(d.getTime() + 864e5)) axis.push(d.toISOString().slice(0, 10));   // calendar day keys, labelled with T.date
  const mx = Math.max(1, ...axis.map((k) => days[k] || 0));
  const W = 100 / Math.max(axis.length, 1);
  const bars = axis.map((k, i) => (days[k] ? `<rect x="${(i * W).toFixed(3)}" y="${(100 - (days[k] / mx) * 100).toFixed(2)}" width="${Math.max(W * 0.72, 0.6).toFixed(3)}" height="${((days[k] / mx) * 100).toFixed(2)}"><title>${T.date(k)}: ${days[k]}</title></rect>` : '')).join('');
  const total = axis.reduce((a, k) => a + (days[k] || 0), 0);
  return `<div class="ep-trend"><div class="ep-trend-h"><span class="label">Mention trend</span><span class="mono">${total} mention${total === 1 ? '' : 's'} · last ${axis.length} days</span></div>
    <svg viewBox="0 0 100 100" preserveAspectRatio="none" class="ep-spark">${bars}</svg>
    <div class="ep-trend-x mono"><span>${T.date(axis[0])}</span><span>${T.date(axis[axis.length - 1])}</span></div></div>`;
}

// A link to an ATT&CK technique read from article text says how sure it is (core/ttp.js); a catalogue link does not.
function techTag(d, c) {
  const tech = (c.other_type || typeOf(c.other)) === 'technique' ? c.other : d.type === 'technique' ? d.id : null;
  if (!tech) return '';
  const tid = String(tech).split(':').slice(1).join(':').toUpperCase();
  const kind = ttpLinkKind(c, tid);
  if (kind === 'confirmed') { const n = ttpArticleCount(c); return n ? `<span class="ttp-also">also in ${n} article${n === 1 ? '' : 's'}</span>` : ''; }
  if (!kind) return '';
  const q = ttpQuote(c);
  wireTtpTips();
  return ttpTag({ id: tid, kind, name: tech === c.other ? c.other_name : d.name, quote: q?.quote, source: q?.source });
}

// Brief: the strongest reported/observed claims as sentences with numbered citations to their quotes.
function brief(d) {
  const all = [...(d.claims?.reported || []), ...(d.claims?.observed || []), ...(d.claims?.user || [])]
    .filter((c) => c.predicate !== 'announced-by' && c.predicate !== 'in-prefix');
  all.sort((a, b) => (b.evidence_count || b.evidence?.length || 0) - (a.evidence_count || a.evidence?.length || 0) || (b.confidence || 0) - (a.confidence || 0));
  const top = all.slice(0, 7);
  if (!top.length) return { html: '', refs: [] };
  const refs = [];
  const refIdx = (ev) => {
    const k = ev.url || ev.ref_id || ev.source;
    let i = refs.findIndex((r) => r.k === k);
    if (i < 0) { refs.push({ k, ...ev }); i = refs.length - 1; }
    return i + 1;
  };
  const me = esc(d.name);
  const lines = top.map((c) => {
    const other = c.other ? chip({ id: c.other, type: c.other_type, name: c.other_name }) : '';
    const s = c.direction === 'in' ? `${other} ${esc(PRED[c.predicate] || c.predicate)} <b>${me}</b>` : `<b>${me}</b> ${esc(PRED[c.predicate] || c.predicate)} ${other}`;
    const cites = [...new Set((c.evidence || []).slice(0, 3).map(refIdx))];
    const q = (c.evidence || []).find((e) => e.quote)?.quote;
    return `<li><div class="ep-cl">${s}${techTag(d, c)}${cites.map((n) => `<sup class="ep-cite" title="${esc(refs[n - 1].source || '')}">${n}</sup>`).join('')}
      ${confLabel(c)}</div>
      ${q ? `<blockquote>“${esc(q.length > 220 ? q.slice(0, 218) + '…' : q)}”</blockquote>` : ''}</li>`;
  });
  return { html: `<ol class="ep-brief">${lines.join('')}</ol>`, refs };
}

// What the shared assessment does not show for a CVE: ransomware use, weakness, the KEV name, affected products.
function cveExtra(d) {
  const a = d.attrs || {};
  const products = (d.related || []).filter((r) => r.type === 'product' || r.type === 'vendor').slice(0, 10);
  const affects = [...(d.claims?.observed || []), ...(d.claims?.reported || [])].filter((c) => c.predicate === 'affects' && c.other).map((c) => ({ id: c.other, type: c.other_type, name: c.other_name }));
  const prods = [...new Map([...affects, ...products].map((p) => [p.id, p])).values()].slice(0, 12);
  return `<div class="ep-cve">
    <div class="ep-cve-k"><span class="label">Ransomware use</span><b>${esc(a.ransomware_use || '—')}</b></div>
    <div class="ep-cve-k"><span class="label">Weakness</span><b class="mono">${esc((a.cwes || []).join(', ') || '—')}</b></div>
  </div>
  ${a.kev_name ? `<p class="ep-desc">${esc(a.kev_name)}</p>` : ''}
  <div class="ep-sec"><div class="ep-sh"><h4>Affected products</h4></div>${prods.length ? `<div class="ep-chips">${prods.map(chip).join('')}</div>` : emptyState({ why: 'No affected product recorded.', size: 'inline' })}</div>`;
}

function iocTable(d) {
  const rel = [];
  const seen = new Set();
  for (const c of [...(d.claims?.reported || []), ...(d.claims?.observed || [])]) {
    if (c.other && IOC.has(c.other_type) && !seen.has(c.other)) { seen.add(c.other); rel.push({ id: c.other, type: c.other_type, name: c.other_name, how: predText(c.predicate, c.direction), n: c.evidence_count || 1 }); }
  }
  // co-mentioned indicators moved from related to related_hypotheses in v1.1 (okf/data/entities.md#verdicts)
  for (const r of [...(d.related || []), ...(d.related_hypotheses || []).filter((x) => x.how === 'mentioned-with')]) if (IOC.has(r.type) && !seen.has(r.id)) { seen.add(r.id); rel.push({ ...r, how: (r.how || 'mentioned with').replace(/-/g, ' ') }); }
  if (!rel.length) return '';
  const rows = rel.slice(0, 25);
  return `<div class="ep-sec"><div class="ep-sh"><h4>Key indicators</h4><span class="mono">${rel.length}</span>
      <button class="src-btn" data-epcopy="${esc(rel.map((r) => r.name || nameOf(r.id)).join('\n'))}">Copy all</button></div>
    <table class="ep-t"><thead><tr><th>Indicator</th><th>Type</th><th>Relationship</th><th class="r">Seen</th><th></th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td class="mono"><a class="ep-iv" href="${esc(entityHref(r.id))}" data-ep="${esc(r.id)}">${esc(defang(r.name || nameOf(r.id), r.type))}</a></td><td>${esc({ ip: 'IP', domain: 'Domain', url: 'URL', hash: 'Hash', asn: 'ASN', prefix: 'Prefix' }[r.type] || tmeta(r.type)[0])}</td><td class="ep-how">${esc(r.how)}</td><td class="r mono">${r.n ?? ''}</td>
      <td class="r"><button class="icon-btn" data-epcopy="${esc(r.name || nameOf(r.id))}" title="Copy">⧉</button></td></tr>`).join('')}
    </tbody></table>${rel.length > rows.length ? `<div class="ep-none">+${rel.length - rows.length} more on the full profile</div>` : ''}</div>`;
}

async function render(id, push) {
  if (push && cur) stack.push(cur);
  cur = id;
  const body = el.querySelector('.ep-body');
  const t = typeOf(id);
  const bk = el.querySelector('.ep-back');
  bk.hidden = !stack.length;
  bk.title = `${backLabel(stack[stack.length - 1])} (Backspace)`;
  bk.setAttribute('aria-label', backLabel(stack[stack.length - 1]));
  el.querySelector('.ep-crumb').innerHTML = `<i style="background:${tmeta(t)[1]}"></i>${esc(tmeta(t)[0])}`;
  el.querySelector('.ep-full').href = entityHref(id);
  body.innerHTML = `<div class="ep-head"><h2>${esc(IOC.has(t) ? defang(nameOf(id), t) : nameOf(id))}</h2></div><div class="ep-load"></div>`;
  let d;
  try {
    // An indicator no feed or article has named has no profile: ask first (a 200), so it gets its verdict quietly.
    if (VERDICT.has(t)) {
      const lk = await api.get('/api/entities/lookup', { values: nameOf(id) }).catch(() => null);
      if (lk && !lk.results?.[0]?.found) { const e = new Error('unknown entity'); e.status = 404; throw e; }
    }
    d = await api.get(`/api/entities/${encodeURIComponent(id)}`, { evidence: 3 });
  }
  catch (e) {
    if (cur !== id) return;
    // An address, domain or hash no feed or article has named still gets its verdict and network answer.
    if (e.status === 404 && VERDICT.has(t)) {
      let it = null;
      try { it = (await api.get('/api/netlog/seen', { v: nameOf(id), context: true })).items?.[0] || null; } catch {}
      if (cur !== id) return;
      if (it && it.kind !== 'unknown') {
        const d0 = { id, type: t, name: it.normalized || nameOf(id), listed_by: it.listed_by || [], owner: it.owner, mentions: { refs: 0 }, sources: [], claim_counts: {} };
        body.innerHTML = `<div class="ep-head"><div class="ep-kind" style="color:${tmeta(t)[1]}">${esc(tmeta(t)[0])}</div><h2>${esc(defang(d0.name, t))}</h2></div>
          ${actions(d0.name)}${assessShell(d0)}${emptyState({ why: 'No news item, source or reference names it yet, so there is no profile beyond this.', size: 'inline' })}`;
        fillAssessment(body, d0, { isCurrent: () => cur === id, onArticle: opts.onArticle, drawer: true, brief: false });
        return;
      }
    }
    body.innerHTML = `<div class="ep-head"><h2>${esc(nameOf(id))}</h2></div>${errorState({ retry: () => render(id, false), title: "Couldn't load the details", why: 'The Intel data did not answer. Try again in a moment.', err: e.message, size: 'inline' })}${actions()}`;
    return;
  }
  if (cur !== id) return;
  const name = d.name || nameOf(id);
  const rel = (d.related || []).filter((r) => !IOC.has(r.type));
  const groups = {};
  for (const r of rel) (groups[r.type] ||= []).push(r);
  const order = ['actor', 'malware', 'tool', 'campaign', 'cve', 'technique', 'vendor', 'product', 'org', 'sector', 'country'];
  const cc = d.claim_counts || {};
  const nClaims = Object.entries(cc).filter(([o]) => o !== 'inferred').reduce((a, [, b]) => a + b, 0); // hypotheses are not claims
  const b = brief({ ...d, name });
  const desc = d.attrs?.description || d.description;
  body.innerHTML = `
    <div class="ep-head">
      <div class="ep-kind" style="color:${tmeta(d.type)[1]}">${esc(tmeta(d.type)[0])}${d.attrs?.country ? ` · ${esc(d.attrs.country)}` : ''}${d.conflicting_attribution ? ' · <span class="ep-warn">conflicting attribution</span>' : ''}</div>
      <h2>${esc(IOC.has(d.type) ? defang(name, d.type) : name)}</h2>
      ${d.aliases?.length ? `<div class="ep-al"><span class="label">Aliases</span>${d.aliases.slice(0, 12).map((a) => `<span class="ep-alias">${esc(a)}</span>`).join('')}${d.aliases.length > 12 ? `<span class="ep-none">+${d.aliases.length - 12}</span>` : ''}</div>` : ''}
      ${desc ? descBlock(desc) : ''}
    </div>
    <div class="ep-kpis mono"${VERDICT.has(d.type) ? ' hidden' : ''}>
      <div><b>${d.mentions?.refs ?? d.mentions?.n ?? 0}</b><span>${(d.mentions?.refs ?? d.mentions?.n ?? 0) === 1 ? 'mention' : 'mentions'}</span></div>
      <div><b>${(d.sources || []).length}</b><span>${(d.sources || []).length === 1 ? 'source' : 'sources'}</span></div>
      <div><b>${nClaims}</b><span>${nClaims === 1 ? 'claim' : 'claims'}</span></div>
      <div title="${esc(d.first_seen ? `First seen in your data: ${T.date(d.first_seen)}` : '')}"><b>${d.first_seen ? ago(d.first_seen).replace(' ago', '') : '—'}</b><span>first in your data</span></div>
      <div><b>${d.last_seen ? ago(d.last_seen).replace(' ago', '') : '—'}</b><span>last seen</span></div>
    </div>
    <div class="ep-dates mono" data-dates></div>
    ${actions(name)}
    ${assessShell(d)}
    ${d.type === 'cve' ? cveExtra(d) : ''}
    ${b.html ? `<div class="ep-sec"><div class="ep-sh"><h4>Reported claims</h4><span class="mono">top ${Math.min(7, nClaims)} of ${nClaims} · confidence and corroboration · cited</span></div>${b.html}
      <ol class="ep-refs">${b.refs.map((r, i) => `<li value="${i + 1}"><span class="mono">[${i + 1}]</span> ${r.ref_type === 'article' && opts.onArticle ? `<a href="#" data-eparticle="${esc(r.ref_id)}">${esc(r.source || 'source')}</a>` : safeUrl(r.url) ? `<a href="${esc(safeUrl(r.url))}" target="_blank" rel="noopener">${esc(r.source || 'source')}</a>` : esc(r.source || r.ref_type || 'source')}${r.tier ? ` <span class="ep-tier" data-term="trust-tier">${esc(r.tier)} · ${esc(tierWord(r.tier))}</span>` : ''}${r.ts ? ` <span class="mono">${esc(T.date(r.ts))}</span>` : ''}</li>`).join('')}</ol></div>`
      : `<div class="ep-sec"><div class="ep-sh"><h4>Reported claims</h4></div>${emptyState({ why: `No reported claims yet. ${d.mentions?.refs ? `Mentioned in ${d.mentions.refs} items.` : ''}`, size: 'inline' })}</div>`}
    ${iocTable(d)}
    ${(d.listed_by || []).length ? `<div class="ep-sec"><div class="ep-sh"><h4>Threat lists</h4><span class="mono" title="Corroboration, not a confidence score: some lists copy each other, so several lists are not always independent reports.">${d.listed_by.length} · corroboration</span></div>
      <table class="ep-t"><thead><tr><th>List</th><th>As</th><th>Family</th><th class="r">Listed</th></tr></thead><tbody>
      ${d.listed_by.map((l) => `<tr><td>${esc(l.name || l.source)} ${l.tier ? `<span class="ep-tier" data-term="trust-tier">${esc(l.tier)} · ${esc(tierWord(l.tier))}</span>` : ''}</td><td class="mono">${esc(l.value || '')}</td><td>${esc(l.malware || '—')}</td>
        <td class="r mono">${l.active ? `<b>now</b> · since ${esc(T.date(l.first_listed || ''))}` : `${esc(T.date(l.first_listed || ''))} → ${esc(T.date(l.last_listed || ''))}`}</td></tr>`).join('')}
      </tbody></table></div>` : ''}
    ${rel.length ? `<div class="ep-sec"><div class="ep-sh"><h4>Related entities</h4><span class="mono">${rel.length}</span></div>
      ${order.filter((k) => groups[k]).map((k) => `<div class="ep-rg"><span class="ep-rl">${esc(tmeta(k)[0])}</span><div class="ep-chips">${groups[k].slice(0, 12).map(chip).join('')}</div></div>`).join('')}</div>` : ''}
    ${(d.sources || []).length ? `<div class="ep-sec"><div class="ep-sh"><h4>Sources</h4></div><div class="ep-srcs">${d.sources.slice(0, 20).map((s) => `<span>${esc(s)}</span>`).join('')}</div></div>` : ''}`;   // "Open full page" lives once, in the header
  fillAssessment(body, d, { isCurrent: () => cur === id, onArticle: opts.onArticle, drawer: true });
  mountNotes(body, { kind: 'entity', item: d.id || id, title: name, actions: '.ep-act', summary: () => entitySummary({ ...d, name }) });
}

// One Follow/Following button (My stack, core/stack.js): it reads the id through the user's merges, so the kept
// id shows Following when the merged one is followed. Places, sectors and address blocks are not followable.
const NOFOLLOW = new Set(['country', 'sector', 'prefix', 'technique']);
function actions(name = null) {
  const a = opts.actions || [];
  const t = typeOf(cur);
  const fb = NOFOLLOW.has(t) ? '' : followButton({ entity: cur }, { name: name || nameOf(cur), cls: 'src-btn' });
  return `<div class="ep-act">${fb}${a.map((x, i) => `<button class="src-btn ${typeof x.primary === 'function' ? (x.primary(cur) ? 'primary' : '') : x.primary ? 'primary' : ''}" data-epact="${i}">${esc(typeof x.label === 'function' ? x.label(cur) : x.label)}</button>`).join('')}
    <button class="src-btn" data-epcopy="${esc(nameOf(cur))}">Copy value</button></div>`;
}

// ---------------------------------------------------------------------------------------------------------
// App-wide entity chips and hover cards (added by the Entities view; okf/architecture/web-client.md#entity-panel).
// Any element with data-entity="<type:value>" gets a hover card after a short delay (pointer devices only).
// A click on any element with data-entity (a link or not) opens this drawer ("Details"); Cmd/Ctrl/Shift- or
// middle-click opens the full page in a new tab (core/open.js). Opt out of the card with data-nocard.
const cardCache = new Map();
let card, cardFor = null, cardTimer = null, hideTimer = null, cardAnchor = null;
// The chip a panel was opened from, or whose card Esc dismissed: no hover card on it again until the pointer has left
// it (closing the panel uncovers the chip under a resting pointer, which would otherwise pop the card right back).
let noCard = null;
function noCardOn(a) { noCard = a?.closest?.('[data-entity]') || null; }

function ensureCard() {
  if (card) return card;
  card = document.createElement('div');
  card.className = 'ep-card';
  card.setAttribute('role', 'tooltip');
  card.hidden = true;
  document.body.append(card);
  card.addEventListener('mouseenter', () => clearTimeout(hideTimer));
  card.addEventListener('mouseleave', () => hideCard(120));
  card.addEventListener('click', (e) => {
    const b = e.target.closest('[data-card-open]');
    if (b) { e.preventDefault(); const id = b.dataset.cardOpen; hideCard(0); openEntity(id, { source: cardAnchor }); }
    if (e.target.closest('a[data-open-full]')) hideCard(0);
  });
  return card;
}
function hideCard(ms = 160) {
  clearTimeout(cardTimer); clearTimeout(hideTimer);
  hideTimer = setTimeout(() => { if (card) card.hidden = true; cardFor = null; }, ms);
}
// A menu opened from a value (the Network pivot menu, a deck menu) owns the pointer: no hover card over it.
const menuOpen = () => !!document.querySelector('.nv-pop:not([hidden]), .menu.open');
// A CVE card's facts: KEV, CVSS, latest EPSS and the newest CISA advisory (live from the entities API).
function cveCardLine(a) {
  const t = [];
  if (a.kev) t.push('<span class="tag red">KEV</span>');
  const cvss = a.cvss ?? a.cvss3 ?? a.base_score;
  if (cvss != null) t.push(`<span class="tag ${cvss >= 9 ? 'red' : cvss >= 7 ? 'orange' : 'amber'}">CVSS ${esc(cvss)}</span>`);
  if (a.epss != null) t.push(epssTag(a.epss, a.epss_percentile, a.epss_prev, a.epss_since));
  else if (a.epss_status === 'not scored') t.push('<span class="tag" title="FIRST EPSS has no score for this id">EPSS n/a</span>');
  const adv = (a.advisories || [])[0];
  if (adv) t.push(`<span class="tag amber" title="${esc(adv.title || '')}">${esc(adv.id)}</span>`);
  return t.length ? `<div class="ep-card-t" style="display:flex;gap:4px;flex-wrap:wrap;margin:6px 0">${t.join('')}</div>` : '';
}

async function showCard(anchor, id) {
  if (menuOpen() || !anchor.isConnected) return;
  ensureCard();
  cardFor = id; cardAnchor = anchor;
  const t = typeOf(id);
  const place = () => {
    const r = anchor.getBoundingClientRect();
    const w = Math.min(340, window.innerWidth - 16);
    card.style.width = `${w}px`;
    card.style.left = `${Math.max(8, Math.min(window.innerWidth - w - 8, r.left))}px`;
    const below = r.bottom + 8, h = card.offsetHeight || 160;
    card.style.top = `${below + h > window.innerHeight - 8 ? Math.max(8, r.top - h - 8) : below}px`;
  };
  card.innerHTML = `<div class="ep-card-k" style="color:${tmeta(t)[1]}">${esc(tmeta(t)[0])}</div><b class="ep-card-n">${esc(IOC.has(t) ? defang(nameOf(id), t) : nameOf(id))}</b><div class="ep-load"></div>`;
  card.hidden = false; place();
  let d = cardCache.get(id);
  if (!d) {
    // Only a real 404 is remembered as missing; a failed request (network, 5xx) is retried on the next hover.
    try {
      // an indicator no feed or article has named has no profile: ask first (a 200), as the drawer does, not a 404
      const lk = VERDICT.has(t) ? await api.get('/api/entities/lookup', { values: nameOf(id) }).catch(() => null) : null;
      if (lk && !lk.results?.[0]?.found) d = { missing: true };
      else d = await api.get(`/api/entities/${encodeURIComponent(id)}`, { evidence: 1 });
    } catch (e) { d = e.status === 404 ? { missing: true } : { failed: e.message || 'request failed' }; }
    if (!d.failed) {
      cardCache.set(id, d);
      if (cardCache.size > 200) cardCache.delete(cardCache.keys().next().value);
    }
  }
  if (cardFor !== id) return;
  if (d.failed) { card.querySelector('.ep-load').outerHTML = errorState({ retry: () => showCard(anchor, id), title: '', why: "Couldn't load the details.", err: String(d.failed), size: 'inline' }); place(); return; }
  if (d.missing) { card.querySelector('.ep-load').outerHTML = emptyState({ why: 'Not in Intel yet.', size: 'inline' }); place(); return; }
  const cc = d.claim_counts || {};
  const n = Object.entries(cc).filter(([o]) => o !== 'inferred').reduce((a, [, b]) => a + b, 0); // hypotheses are not claims
  const desc = d.attrs?.description || d.attrs?.kev_name || '';
  const al = (d.aliases || []).filter((a) => a.toLowerCase() !== String(d.name).toLowerCase()).slice(0, 5);
  card.innerHTML = `<div class="ep-card-k" style="color:${tmeta(d.type)[1]}">${esc(tmeta(d.type)[0])}${d.conflicting_attribution ? ' · <span class="ep-warn">contested</span>' : ''}</div>
    <b class="ep-card-n">${esc(IOC.has(d.type) ? defang(d.name, d.type) : d.name)}</b>
    ${al.length ? `<div class="ep-card-al">aka ${esc(al.join(', '))}${d.aliases.length > al.length + 1 ? ' …' : ''}</div>` : ''}
    ${desc ? `<p class="ep-card-d">${esc(desc.length > 220 ? desc.slice(0, 218) + '…' : desc)}</p>` : ''}
    ${d.type === 'cve' ? cveCardLine(d.attrs || {}) : ''}
    <div class="ep-card-s mono"><span><b>${d.mentions?.refs ?? 0}</b> mentions</span><span><b>${n}</b> claims</span><span><b>${(d.sources || []).length}</b> sources</span>${d.last_seen ? `<span>last ${esc(ago(d.last_seen))}</span>` : ''}</div>
    ${spark(d.timeline)}
    <div class="ep-card-a"><button class="src-btn sm" data-card-open="${esc(d.id)}">${LABELS.details}</button><a class="src-btn sm" href="${esc(entityHref(d.id))}" data-open-full>${LABELS.full}</a></div>`;
  place();
}

if (!window.__ndEntityChips) {
  window.__ndEntityChips = true;
  const fine = window.matchMedia?.('(hover: hover) and (pointer: fine)').matches;
  if (fine) {
    document.addEventListener('mouseover', (e) => {
      if (noCard && !noCard.contains(e.target) && !e.target.closest?.('.ep, .ep-scrim')) noCard = null;
      const a = e.target.closest?.('[data-entity]:not([data-nocard])');
      if (a && a === noCard) return;
      if (!a || a.closest('.ep-card') || menuOpen()) return;
      const id = a.dataset.entity;
      clearTimeout(hideTimer);
      if (cardFor === id && card && !card.hidden) return;
      clearTimeout(cardTimer);
      cardTimer = setTimeout(() => showCard(a, id), 380);
      a.addEventListener('mouseleave', () => { clearTimeout(cardTimer); hideCard(); }, { once: true });
    });
  }
  // Esc dismisses a shown card where the pointer is (WCAG 1.4.13). Window, capture: before the page's own Esc, which
  // it leaves alone unless the card was all Esc had to close.
  window.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    clearTimeout(cardTimer);
    if (!card || card.hidden) return;
    noCardOn(cardAnchor);
    hideCard(0);
    if (!isEntityOpen()) e.stopPropagation();
  }, true);
  // Pressing anywhere outside the card is an action, not a hover: cancel a pending card and hide a shown one (in the
  // capture phase, so a click handler that stops propagation, such as the Network pivot menu, cannot skip it).
  document.addEventListener('pointerdown', (e) => {
    if (card && card.contains(e.target)) return;
    clearTimeout(cardTimer);
    if (card && !card.hidden) hideCard(0);
  }, true);
  document.addEventListener('click', (e) => {
    const a = e.target.closest?.('[data-entity]');
    if (!a || a.closest('.ep-card') || e.defaultPrevented) return;
    hideCard(0);
    if (newTab(e)) return;        // core/open.js: the full page in a new tab
    e.preventDefault();
    openEntity(a.dataset.entity, { source: a });
  });
}


// ---------------------------------------------------------------------------------------------------------
// Executive brief (added by the News view): "why this matters now", "what to do", alias provenance and a
// long-range mention trend, from GET /api/news/entity-brief/<id> (osinthub/news/brief.py). The local-LLM
// wording is cached per entity server-side; until it exists the deterministic facts are shown. Self-contained:
// if the endpoint is missing the panel falls back to the timeline sparkline above.
let scrim;
function ensureScrim() {
  if (scrim) return;
  scrim = document.createElement('div');
  scrim.className = 'ep-scrim';
  scrim.addEventListener('click', () => closeEntity());
  document.body.append(scrim);
}
function scrimToggle(on) { if (scrim) scrim.classList.toggle('on', !!on); }

// Numeric confidence plus why: origin, distinct sources and their tiers. The stored score is shown as is.
function confLabel(c) {
  const srcs = [...new Set([...(c.sources || []), ...(c.evidence || []).map((e) => e.source)].filter(Boolean))];
  const tiers = [...new Set((c.evidence || []).map((e) => e.tier).filter(Boolean))].sort();
  const n = Math.max(srcs.length, c.evidence_count || 0);
  // Prefer the backend's band and `why` (entities scoring); derive from sources when absent.
  const band = c.band || (n >= 3 ? 'high' : n === 2 ? 'moderate' : 'low');
  const cls = { high: 'strong', strong: 'strong', moderate: 'moderate', low: 'weak', weak: 'weak' }[band] || 'weak';
  const why = c.why || `${n} source${n === 1 ? '' : 's'}${tiers.length ? `: ${tiers.join(', ')}` : ''}`;
  const tip = `confidence ${c.confidence ?? '—'} (${c.origin}) · ${why}${srcs.length ? ` · ${srcs.join(', ')}` : ''}`;
  return `<span class="ep-conf ${cls}" title="${esc(tip)}"><b>${c.confidence != null ? Number(c.confidence).toFixed(2) : '—'}</b><i>${esc(band)}</i><em>${esc(why)}</em></span>`;
}

const cites = (ns) => (ns || []).map((n) => `<sup class="ep-cite">${n}</sup>`).join('');

function trendBlock(tr, fallbackTimeline) {
  if (!tr) return spark(fallbackTimeline);
  const since = tr.since ? T.date(tr.since) : null;
  if (!tr.points.length) {
    return `<div class="ep-trend sparse"><div class="ep-trend-h"><span class="label">Mention trend</span></div>
      <div class="ep-trend-txt"><b>${tr.total}</b> mention${tr.total === 1 ? '' : 's'}${since ? ` since ${esc(since)}` : ''} · <b>${tr.last30}</b> in the last 30 days (previous 30: ${tr.prev30})</div>
      <div class="ep-ticks">${tr.points.map((p) => `<i title="week of ${esc(T.date(p.t))}: ${p.n}">${p.n}</i>`).join('')}</div></div>`;
  }
  // 52 weekly buckets ending now
  const now = Date.now(), W = 7 * 864e5;
  const buckets = new Array(52).fill(0);
  for (const p of tr.points) { const k = 51 - Math.floor((now - new Date(p.t).getTime()) / W); if (k >= 0 && k < 52) buckets[k] += p.n; }
  const mx = Math.max(1, ...buckets);
  const bars = buckets.map((v, i) => (v ? `<rect x="${(i * 100 / 52).toFixed(2)}" y="${(100 - v / mx * 100).toFixed(1)}" width="${(100 / 52 * 0.7).toFixed(2)}" height="${(v / mx * 100).toFixed(1)}"><title>${v}</title></rect>` : '')).join('');
  return `<div class="ep-trend"><div class="ep-trend-h"><span class="label">Mention trend · 12 months, weekly</span><span class="mono">${tr.total} mention${tr.total === 1 ? '' : 's'}${since ? ` since ${esc(since)}` : ''} · ${tr.last30} in the last 30 days (previous 30: ${tr.prev30})</span></div>
    <svg viewBox="0 0 100 100" preserveAspectRatio="none" class="ep-spark">${bars}</svg>
    <div class="ep-trend-x mono"><span>${T.date(now - 51 * W)}</span><span>now</span></div></div>`;
}

function aliasTable(rows) {
  if (!rows || rows.length < 2) return '';
  return `<div class="ep-sec"><div class="ep-sh"><h4>Aliases</h4><span class="mono">${rows.length - 1}</span></div>
    <table class="ep-t ep-alt"><thead><tr><th>Name</th><th>Listed by</th><th>Naming scheme</th></tr></thead><tbody>
    ${rows.slice(0, 16).map((r) => `<tr><td>${esc(r.alias)}${r.primary ? ' <span class="ep-tag">primary</span>' : ''}</td><td>${r.sources.length ? r.sources.map((x) => `<span class="ep-tag">${esc(x)}</span>`).join(' ') : '<span class="ep-none">reporting</span>'}</td><td class="ep-how">${esc(r.naming || '—')}</td></tr>`).join('')}
    </tbody></table>${rows.length > 16 ? `<div class="ep-none">+${rows.length - 16} more on the full profile</div>` : ''}</div>`;
}

function todoBlock(b, due = null) {
  const t = b.todo || {};
  const parts = [];
  if (t.cve) {
    const c = t.cve, x = t.exploitation || {};
    parts.push(`<div class="ep-todo-i"><span class="ep-todo-k">Patch</span><div>${c.kev ? `<b class="ep-red">Known exploited</b> · on CISA KEV since ${esc(T.date(c.kev_added || ''))}${x.ransomware ? ' · used by ransomware' : ''}. Patch now; ${due ? `CISA's remediation deadline ${new Date(due) < new Date() ? 'was' : 'is'} ${esc(T.date(due))}.` : 'KEV entries carry a federal remediation deadline.'}` : c.epss >= 0.1 ? `${esc(x.status || 'Not on KEV')}, but EPSS puts exploitation in the next 30 days at <b class="ep-red">${esc(epssText(c.epss))}</b>. Patch ahead of your normal cycle${c.cvss != null ? ` (CVSS ${esc(c.cvss)})` : ''}.` : `${esc(x.status || 'Not on KEV')}. Patch on your normal cycle${c.cvss != null ? ` (CVSS ${esc(c.cvss)})` : ''}${c.epss != null ? `; EPSS ${esc(epssText(c.epss))}` : ''}.`}
      ${x.by?.length ? `<div class="ep-todo-s">Exploited by ${x.by.map((a) => `${chip(a)}${cites(a.cites)}`).join(' ')}</div>` : ''}</div></div>`);
    if (t.products?.length) parts.push(`<div class="ep-todo-i"><span class="ep-todo-k">Check</span><div>Do you run any of these? ${t.products.map((p) => `${chip(p)}${cites(p.cites)}`).join(' ')}</div></div>`);
  }
  if (t.patch?.length) {
    parts.push(`<div class="ep-todo-i"><span class="ep-todo-k">Patch</span><div>${t.patch.map((c) => `<span style="white-space:nowrap"><a class="ep-chip" href="${esc(entityHref(`cve:${c.id.toLowerCase()}`))}" style="--c:${TC.cve}" data-ep="cve:${esc(c.id.toLowerCase())}">${esc(c.id)}</a>${c.kev ? '<span class="ep-tag red">KEV</span>' : ''}${c.epss != null ? `<span class="ep-tag${c.epss >= 0.1 ? ' red' : ''}" title="${esc(epssTitle(c.epss, c.epss_percentile))}">EPSS ${esc(epssText(c.epss))}</span>` : ''}${c.cvss != null ? `<span class="ep-tag">CVSS ${esc(c.cvss)}</span>` : ''}</span>`).join(' ')}
      <div class="ep-todo-s">${t.patch.filter((c) => c.kev).length} of ${t.patch.length} are known exploited; those first, then the most likely to be exploited (EPSS).</div></div></div>`);
  }
  if (t.mitigations?.length) {
    parts.push(`<div class="ep-todo-i"><span class="ep-todo-k">Harden</span><div><ol class="ep-mits">${t.mitigations.map((m) => `<li><a href="https://attack.mitre.org/mitigations/${esc(m.id)}/" target="_blank" rel="noopener" class="mono">${esc(m.id)}</a> <b>${esc(m.name)}</b> <span class="ep-todo-s">covers ${m.techniques.slice(0, 5).map((x) => `<span class="mono">${esc(x)}</span>`).join(', ')}${m.techniques.length > 5 ? ` +${m.techniques.length - 5}` : ''}</span></li>`).join('')}</ol>
      <div class="ep-todo-s">From ${t.techniques.length} ATT&amp;CK technique${t.techniques.length === 1 ? '' : 's'} in its reporting, mapped to MITRE mitigations.</div></div></div>`);
  }
  if (t.block?.length) {
    const vals = t.block.map((x) => x.value).join('\n');
    parts.push(`<div class="ep-todo-i"><span class="ep-todo-k">Block</span><div>${t.block.slice(0, 8).map((x) => `<a class="ep-iv" href="${esc(entityHref(x.id))}" data-ep="${esc(x.id)}">${esc(defang(x.value, x.type === 'ip' || x.type === 'domain' || x.type === 'url' ? x.type : 'hash'))}</a>${cites(x.cites)}`).join('<span class="ep-sep">·</span>')}${t.block.length > 8 ? ` <span class="ep-none">+${t.block.length - 8}</span>` : ''}
      <div class="ep-todo-s"><button class="src-btn" data-epcopy="${esc(vals)}">Copy ${t.block.length} indicators</button></div></div></div>`);
  }
  return parts.length ? parts.join('') : emptyState({ why: 'No specific action yet: no linked CVEs, techniques or indicators.', size: 'inline' });
}

function refsList(evs, onArticle = opts.onArticle) {
  if (!evs?.length) return '';
  const ref = (r) => (r.ref_type === 'article'
    ? (onArticle ? `<a href="#" data-eparticle="${esc(r.ref_id)}">${esc(r.source || 'source')}</a>` : `<a href="#news/article/${encodeURIComponent(r.ref_id)}">${esc(r.source || 'source')}</a>`)
    : safeUrl(r.url) ? `<a href="${esc(safeUrl(r.url))}" target="_blank" rel="noopener">${esc(r.source || 'source')}</a>` : esc(r.source || 'source'));
  return `<ol class="ep-refs">${evs.map((r, i) => `<li><span class="mono">[${i + 1}]</span> ${ref(r)}${r.tier ? ` <span class="ep-tier" data-term="trust-tier">${esc(r.tier)} · ${esc(tierWord(r.tier))}</span>` : ''}${r.ts ? ` <span class="mono">${esc(T.date(r.ts))}</span>` : ''}</li>`).join('')}</ol>`;
}

// Where the "why now" wording comes from. llm_unavailable (llm_status 'unavailable'): the AI helper is down, so
// the facts (or older cached wording) are shown and say so instead of promising a summary that will not come.
function briefSource(b) {
  const off = b.llm_unavailable || b.llm_status === 'unavailable';
  const tip = 'The local AI helper is not running, so no AI wording can be generated right now. The facts and citations come straight from the lake.';
  if (b.llm) return `<span class="mono"${off ? ` title="${esc(tip)}"` : ''}><span class="ep-ai">AI</span>local LLM${off ? ' · older wording, AI helper unavailable' : b.llm_stale ? ' · refreshing' : ''}</span>`;
  if (off) return `<span class="mono" title="${esc(tip)}">facts from the lake · AI wording unavailable</span>`;
  return `<span class="mono">${b.llm_pending ? 'facts from the lake · AI summary pending' : 'facts from the lake'}</span>`;
}

// ---------------------------------------------------------------------------------------------------------
// The shared assessment (okf/architecture/web-client.md#assessment): one component for the drawer and the
// entity page, so both say the same thing first.
//   * a verdict strip for indicators (IP, prefix, domain, URL, hash): the plain answer ("Listed as a botnet
//     controller by Feodo Tracker since 3 Nov · seen on your network: no"), the owner, which lists and since when
//     with their trust tier in words, then the counts;
//   * the patch facts for a CVE: CVSS, EPSS with percentile, KEV added and due, vendor/product, advisory links;
//   * "Seen on your network" from GET /api/netlog/seen (alerts count as sightings, so it is never a false "no");
//   * "Why this matters now" and "What to do" from GET /api/news/entity-brief/<id>.
//   assessShell(d) -> HTML with placeholders;  fillAssessment(root, d, {isCurrent, onArticle, drawer}) fills it.
export const VERDICT = new Set(['ip', 'prefix', 'domain', 'url', 'hash']);
const SEEN_TYPES = new Set(['ip', 'prefix', 'domain', 'hash', 'cve', 'url']);
export const TIER_WORDS = { A: 'primary authority', B: 'established research group', C: 'community list, corroborate first', D: 'unverified report' };
const CAT_WORDS = {
  c2: 'a botnet controller', drop: 'a hijacked or criminal network', compromised: 'a compromised host', reputation: 'a bad-reputation address',
  attacker: 'an attacking address', scanner: 'an internet scanner', tor: 'a Tor exit node', malware: 'malware infrastructure', listed: 'a listed address',
};
const TIER_RANK = { A: 0, B: 1, C: 2, D: 3 };
const dd = (t) => (t ? T.date(t) : '');
const iso = dd;
const regionName = (cc) => { try { return cc ? new Intl.DisplayNames(['en'], { type: 'region' }).of(String(cc).toUpperCase()) : ''; } catch { return cc || ''; } };

// A list's short name for the verdict sentence, which already says what it is listed as ("Listed as a botnet
// controller by Feodo Tracker", not "... by Feodo Tracker botnet C2"). The Lists rows keep the full name.
const LIST_SHORT = {
  feodo_c2: 'Feodo Tracker', dshield_top: 'DShield', tor_exits: 'the Tor Project', blocklist_de: 'blocklist.de',
  cins_army: 'CINS Army', et_compromised: 'Emerging Threats', spamhaus_drop: 'Spamhaus', threatfox: 'ThreatFox',
  urlhaus: 'URLhaus', sslbl: 'SSL Blacklist',
};
const LIST_TAIL = /\s+(?:botnet\s+C2|C2|top attacking IPs|exit nodes|attackers|bad actors|compromised hosts|hijacked netblocks|malware IOCs|malware URLs|\(C2 certificates\))$/i;
export const listShort = (l) => LIST_SHORT[l.source] || String(l.name || l.source || 'a threat list').replace(LIST_TAIL, '');
function verdictAnswer(d) {
  const ls = [...(d.listed_by || [])].sort((a, b) => (TIER_RANK[a.tier] ?? 9) - (TIER_RANK[b.tier] ?? 9));
  const now = ls.filter((l) => l.active), was = ls.filter((l) => !l.active);
  const what = (l) => `${CAT_WORDS[l.category] || 'a listed indicator'}${l.malware ? ` (${l.malware})` : ''}`;
  if (now.length) {
    const l = now[0];
    return `Listed as ${what(l)} by ${listShort(l)} since ${dd(l.first_listed)}${now.length > 1 ? `, and on ${now.length - 1} more list${now.length > 2 ? 's' : ''}` : ''}`;
  }
  if (was.length) return `Not listed now; ${listShort(was[0])} listed it as ${what(was[0])} until ${dd(was[0].last_listed)}`;
  if (d.mentions?.refs) return `On no threat list collected here; named in ${d.mentions.refs} news or source item${d.mentions.refs === 1 ? '' : 's'}`;
  return 'On no threat list collected here';
}

function verdictStrip(d) {
  const ls = [...(d.listed_by || [])].sort((a, b) => (b.active - a.active) || (TIER_RANK[a.tier] ?? 9) - (TIER_RANK[b.tier] ?? 9));
  const o = d.owner;
  const cc = d.attrs?.country || o?.country;
  const owner = o ? [o.name, o.asn].filter(Boolean).join(' · ') : '';
  const cc2 = regionName(cc);
  const nClaims = Object.entries(d.claim_counts || {}).filter(([k]) => k !== 'inferred').reduce((a, [, b]) => a + b, 0);
  const hot = ls.some((l) => l.active && (l.tier === 'A' || l.tier === 'B'));
  return `<div class="drawer-verdict${hot ? ' listed' : ''}" data-verdict>
    <p class="drawer-verdict-a"><span data-verdict-a>${esc(verdictAnswer(d))}</span><span class="drawer-verdict-sep"> · </span><span data-seen-line class="drawer-verdict-seen">checking your network…</span></p>
    <div class="drawer-verdict-seenchip" data-seen-chip></div>
    ${owner || cc2 ? `<div class="drawer-verdict-row"><span class="label">Owner</span><span>${esc(owner || 'unknown network')}${cc2 ? ` · ${esc(cc2)}` : ''}</span></div>` : ''}
    ${ls.length ? `<div class="drawer-verdict-row lists"><span class="label">Lists</span><ul>${ls.map((l) => `<li><b>${esc(l.name || l.source)}</b>
      <span class="drawer-verdict-tier" title="Trust tier ${esc(l.tier || '?')}">${esc(TIER_WORDS[l.tier] || 'unrated source')}</span>
      <span class="mono">${l.active ? `listed since ${esc(iso(l.first_listed))}` : `${esc(iso(l.first_listed))} → ${esc(iso(l.last_listed))}`}</span>${l.value && l.value !== d.name ? `<span class="mono drawer-dim">as ${esc(l.value)}</span>` : ''}</li>`).join('')}</ul></div>`
      : '<div class="drawer-verdict-row"><span class="label">Lists</span><span class="drawer-dim">none of the collected threat lists hold it</span></div>'}
    <div class="drawer-verdict-row mono drawer-dim"><span class="label">Counts</span><span>${d.mentions?.refs ?? 0} mention${(d.mentions?.refs ?? 0) === 1 ? '' : 's'} · ${(d.sources || []).length} source${(d.sources || []).length === 1 ? '' : 's'} · ${nClaims} claim${nClaims === 1 ? '' : 's'}${d.last_seen ? ` · last mentioned ${esc(ago(d.last_seen))}` : ''}</span></div>
  </div>`;
}

function cveFacts(d) {
  const a = d.attrs || {};
  const cvss = a.cvss ?? a.cvss3 ?? a.base_score;
  const vp = [a.kev_vendor, a.kev_product].filter(Boolean).join(' · ');
  const links = [
    ...(a.advisories || []).filter((x) => safeUrl(x.url)).slice(0, 4).map((x) => ({ url: x.url, text: x.id, tip: `CISA ${x.kind || 'advisory'}: ${x.title || ''}` })),
    ...(a.kev_links || []).filter((u) => safeUrl(u)).slice(0, 4).map((u) => ({ url: u, text: (() => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return 'link'; } })(), tip: u })),
  ];
  const name = d.name || nameOf(d.id);
  if (!links.some((l) => /nvd\.nist\.gov/.test(l.url))) links.push({ url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(String(name).toUpperCase())}`, text: 'nvd.nist.gov', tip: 'NVD entry' });
  const epssK = a.epss != null
    ? `<b class="${a.epss >= 0.5 ? 'crit' : a.epss >= 0.1 ? 'high' : a.epss >= 0.01 ? 'med' : ''}">${esc(epssText(a.epss))}</b><small>${a.epss_percentile != null ? `higher than ${esc((a.epss_percentile * 100).toFixed(1))}% of scored CVEs` : ''}${a.epss_prev != null ? ` · was ${esc(epssText(a.epss_prev))}` : ''}</small>`
    : `<b>—</b><small>${esc(a.epss_status === 'not scored' ? 'not scored by EPSS' : 'EPSS not loaded')}</small>`;
  return `<div class="drawer-cvefacts">
    <div class="drawer-cvek"><span class="label">CVSS</span><b class="${cvss >= 9 ? 'crit' : cvss >= 7 ? 'high' : cvss != null ? 'med' : ''}">${cvss ?? '—'}</b><small>${cvss == null ? 'no score in local data' : esc(a.cvss_source && a.cvss_source !== 'NVD' ? a.cvss_source : 'NVD')}</small></div>
    <div class="drawer-cvek" title="${esc(epssTitle(a.epss ?? null, a.epss_percentile ?? null, a.epss_prev ?? null, a.epss_since ?? null))}"><span class="label">EPSS · next 30 days</span>${epssK}</div>
    <div class="drawer-cvek"><span class="label">CISA KEV</span>${a.kev ? `<b class="crit">Exploited</b><small class="mono">added ${esc(iso(a.kev_added) || '—')}${a.kev_due ? ` · due ${esc(iso(a.kev_due))}` : ''}</small>` : '<b>Not listed</b><small>no known exploitation listed</small>'}</div>
    <div class="drawer-cvek"><span class="label">Vendor · product</span><b class="drawer-cvevp">${esc(vp || '—')}</b></div>
    ${a.kev_action ? `<div class="drawer-cvek wide a11y-cve-action"><span class="label">What CISA says to do</span><p>${esc(a.kev_action)}</p></div>` : ''}
    <div class="drawer-cvek wide"><span class="label">On your network</span><span data-seen-chip><span class="drawer-dim">checking…</span></span></div>
    <div class="drawer-cvek wide"><span class="label">Advisories</span><span class="drawer-cvelinks">${links.map((l) => `<a href="${esc(safeUrl(l.url))}" target="_blank" rel="noopener" class="mono" title="${esc(l.tip)}">${esc(l.text)} ↗</a>`).join('')}</span></div>
  </div>`;
}

export function assessShell(d) {
  return `<section class="drawer-assess" data-assess>
    ${VERDICT.has(d.type) ? verdictStrip(d) : d.type === 'cve' ? cveFacts(d) : ''}
    <div class="ep-nb" data-nb><div class="ep-load sm"></div></div>
  </section>`;
}

// What to do with an indicator when the brief derived nothing: from the lists and the network answer.
function indicatorTodo(d, it) {
  const now = (d.listed_by || []).filter((l) => l.active);
  const strong = now.some((l) => l.tier === 'A' || l.tier === 'B');
  const t = [];
  if (it?.incident) t.push(`Open the incident on the Network page and check ${it.n_devices === 1 ? 'the device' : `the ${it.n_devices || ''} devices`.replace('  ', ' ')} that talked to it.`);
  else if (it?.seen) t.push('It reached your network without an open incident. Check what talked to it in Network › Search logs.');
  if (strong && !it?.incident) t.push(`Block it on your router or DNS filter if you want to be safe; ${now.length > 1 ? 'the lists that hold it are' : 'the list that holds it is'} well run.`);
  else if (now.length && !strong) t.push('Only community lists hold it. Corroborate before acting; shared hosting and CDN addresses are listed often.');
  if (!now.length && !it?.seen) t.push('Nothing to do: no collected list holds it and your network has not seen it.');
  return t;
}

// What the counts in the brief's lines measure (one noun per measure, as on the entity page: D2-03).
const COUNT_TIPS = [
  [/mentions in the last 30 days/, 'Mentions: items that name it in the last 30 days, then in the 30 days before. News outlets: the outlets of every article that names it, all time.'],
];
export async function fillAssessment(root, d, { isCurrent = () => true, onArticle = null, drawer = false, tries = 0, brief = true } = {}) {
  const box = root.querySelector('[data-assess]');
  if (!box) return;
  const id = d.id;
  const val = d.name || nameOf(id);
  const seenP = SEEN_TYPES.has(d.type) ? seenLookup([val]).then((m) => m.get(val) || null).catch(() => null) : Promise.resolve(undefined);
  seenP.then((it) => {
    if (!isCurrent() || !root.contains(box) || it === undefined) return;
    const line = box.querySelector('[data-seen-line]');
    const chipEl = box.querySelector('[data-seen-chip]');
    if (it === null) {   // the lookup failed: say so, never "no"
      if (line) line.textContent = 'network check unavailable';
      if (chipEl) chipEl.innerHTML = '<span class="drawer-dim">Network check unavailable right now</span>';
      return;
    }
    if (line) { line.textContent = seenLine(it); line.classList.toggle('hit', !!it.incident); line.classList.toggle('seen', it.seen && !it.incident); }
    if (chipEl) chipEl.innerHTML = seenChip(it, { quiet: true });
  });
  let b;
  try {
    if (!brief) throw new Error('no profile');
    b = await api.get(`/api/news/entity-brief/${encodeURIComponent(id)}`);
  }
  catch {
    if (!VERDICT.has(d.type)) { if (isCurrent()) { const s = box.querySelector('[data-nb]'); if (s) s.innerHTML = drawer ? spark(d.timeline) : ''; } return; }
    b = { why: [], todo: {}, evidence: [], aliases: [] };   // an indicator: its verdict still says what to do
  }
  if (!isCurrent() || !root.contains(box)) return;
  const slot = box.querySelector('[data-nb]');
  const llm = b.llm;
  const why = llm?.why_now?.length ? llm.why_now : b.why;
  if (drawer) fillRefDates(root, b, d);
  const it = await seenP;
  const ind = VERDICT.has(d.type) ? indicatorTodo(d, it) : [];
  const t = b.todo || {};
  const derived = t.cve || t.patch?.length || t.mitigations?.length || t.block?.length;
  slot.innerHTML = `
    <div class="ep-exec">
      <div class="ep-sec first"><div class="ep-sh"><h4>Why this matters now</h4>${briefSource(b)}</div>
        ${why.length ? `<ul class="ep-why">${why.map((w) => `<li${COUNT_TIPS.find(([re]) => re.test(w.text)) ? ` tabindex="0" title="${esc(COUNT_TIPS.find(([re]) => re.test(w.text))[1])}"` : ''}>${esc(w.text)}${cites(w.cites)}</li>`).join('')}</ul>` : emptyState({ why: VERDICT.has(d.type) ? 'No recent reporting; the verdict above is what is known.' : 'Nothing recent.', size: 'inline' })}</div>
      <div class="ep-sec"><div class="ep-sh"><h4>What to do</h4></div>
        ${llm?.actions?.length ? `<ul class="ep-why act">${llm.actions.map((w) => `<li>${esc(w.text)}${cites(w.cites)}</li>`).join('')}</ul>` : ''}
        ${ind.length ? `<ul class="ep-why act">${ind.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
        ${derived || !ind.length ? todoBlock(b, d.attrs?.kev_due) : ''}</div>
      ${refsList(b.evidence, onArticle)}
    </div>
    ${drawer ? `${VERDICT.has(d.type) ? '' : trendBlock(b.trend, d.timeline)}${aliasTable(b.aliases)}` : ''}`;
  if (b.llm_pending && !llm && tries < 6) {
    setTimeout(() => { if (isCurrent() && root.contains(box)) fillAssessment(root, d, { isCurrent, onArticle, drawer, tries: tries + 1 }); }, 20000);
  }
}

// The assessment outside the drawer (entity page): its chips peek in the drawer and copy buttons copy (article
// citations there are plain links to the article).
document.addEventListener('click', (e) => {
  const box = e.target.closest?.('[data-assess]');
  if (!box || box.closest('.ep')) return;
  const c = e.target.closest('[data-ep]');
  if (c && newTab(e)) return;
  if (c) { e.preventDefault(); openEntity(c.dataset.ep, { source: c }); return; }
  const cp = e.target.closest('[data-epcopy]');
  if (cp) { navigator.clipboard?.writeText(cp.dataset.epcopy).then(() => toast('Copied'), () => toast('Copy failed', true)); return; }
});


// Description trimmed on a sentence (else word) boundary, with an expand control. The full ATT&CK text, when
// the brief endpoint has it, replaces the stored (length-capped) attribute text.
function trimText(t, n = 300) {
  t = String(t || '').trim();
  if (t.length <= n) return { short: t, cut: false };
  const head = t.slice(0, n);
  const sEnd = Math.max(head.lastIndexOf('. '), head.lastIndexOf('.\n'));
  const cut = sEnd > n * 0.5 ? head.slice(0, sEnd + 1) : head.slice(0, head.lastIndexOf(' ')).replace(/[,;:\s]+$/, '') + '…';
  return { short: cut, cut: true };
}
function descBlock(full) {
  const capped = String(full).length >= 590;            // stored descriptions are capped at 600 characters
  const clean = capped ? trimText(full, String(full).length - 1).short : full;
  const t = trimText(clean, 300);
  return `<div class="ep-desc-w" data-desc><p class="ep-desc">${esc(t.short)}</p>${t.cut ? `<button class="ep-more" data-full="${esc(clean)}" data-short="${esc(t.short)}">More</button>` : ''}</div>`;
}
document.addEventListener('click', (e) => {
  const b = e.target.closest?.('.ep-more');
  if (!b) return;
  const p = b.previousElementSibling, open = b.dataset.open === '1';
  p.textContent = open ? b.dataset.short : b.dataset.full;
  b.dataset.open = open ? '0' : '1';
  b.textContent = open ? 'More' : 'Less';
});
function fillRefDates(body, b, d) {
  const r = b.ref || {};
  if (r.description) {
    const w = body.querySelector('[data-desc]');
    if (w) w.outerHTML = descBlock(r.description);
  }
  const box = body.querySelector('[data-dates]');
  if (!box) return;
  const dd = (x) => (x ? T.date(x) : null);
  const parts = [];
  if (r.attack_created) parts.push(`<span><i>In MITRE ATT&amp;CK since</i> <b>${dd(r.attack_created)}</b>${r.attack_id ? ` <a href="https://attack.mitre.org/${/^S/.test(r.attack_id) ? 'software' : /^C/.test(r.attack_id) ? 'campaigns' : 'groups'}/${esc(r.attack_id)}/" target="_blank" rel="noopener">${esc(r.attack_id)}</a>` : ''}</span>`);
  if (r.earliest_claim) parts.push(`<span><i>Earliest reported claim</i> <b>${dd(r.earliest_claim)}</b></span>`);
  // the "first in your data" tile above already says this (its tooltip has the date); only say it here without the tile
  const tile = body.querySelector('.ep-kpis:not([hidden])') && d.first_seen;
  if ((r.data_first_seen || d.first_seen) && !tile) parts.push(`<span><i>First in your data</i> <b>${dd(r.data_first_seen || d.first_seen)}</b></span>`);
  box.innerHTML = parts.join('');
}

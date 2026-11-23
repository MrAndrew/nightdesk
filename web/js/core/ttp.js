// ATT&CK techniques read out of article text, in the same plain words wherever they show: the News story and article
// pages, the phone story, the Copy summary and the Intel entity page's ATT&CK strip. Three labels, most certain first:
//   named     "Named in the article"  the article itself prints the ATT&CK id (T1059.001)
//   likely    "Likely"                found automatically and backed by a second check (the extractor's confirmed tier)
//   possible  "Possible"              the local AI's guess alone (the suggested tier): often wrong, never exported
// A link MITRE's own catalogue states (any reference evidence, as "APT28 uses T1566.001"), a feed fact or the
// analyst's own link is not a guess from an article: it never gets these labels, even when articles report it too
// (they only add "also in N articles"). The labels apply only when all of a link's evidence is article extraction. Hovering, focusing or tapping a technique shows the sentence it was read from
// (GET /api/news/intel `techniques`, or a claim's evidence quote). Contract: okf/data/entities.md#technique-labels
import { esc } from './util.js';
import { overlayOpened, closeOverlay } from './page.js';

export const TTP_ORDER = ['named', 'likely', 'possible'];
export const TTP_KINDS = {
  named: { label: 'Named in the article', short: 'named', sub: 'the article gives the ATT&CK id',
    why: 'The article itself gives this ATT&CK id.', comment: 'Named in the article', confidence: 85 },
  likely: { label: 'Likely', short: 'likely', sub: 'found automatically, with some support beyond a guess',
    why: 'Found automatically from the text, with some support beyond the AI\'s guess (a tell-tale tool name, or a match with MITRE\'s own examples). Often right, but it can be wrong.', comment: 'Likely — found automatically', confidence: 50 },
  possible: { label: 'Possible', short: 'possible', sub: 'a guess by the local AI alone · often wrong · not exported',
    why: 'Guessed by the local AI from the text, with nothing to back it. Often wrong, so it is left out of exports.' },
};
export const TTP_CAVEAT = 'Found automatically from the text. They can be wrong; check the sentence each one came from.';
/** How to reach a technique's sentence, in words that work with a mouse, a keyboard and a touch screen. */
export const TTP_HOW = 'Click or tap one to see the sentence it came from.';
export const TTP_RE = /\bT1\d{3}(?:\.\d{3})?\b/g;

const tidOf = (eid) => String(eid).split(':').slice(1).join(':').toUpperCase();
/** A technique's own name without a leading id ("T1566.001 Spearphishing Attachment" -> "Spearphishing Attachment"). */
export const ttpName = (tid, name) => { const n = String(name || '').replace(/^T\d{4}(?:\.\d{3})?\s*/i, '').trim(); return n && n.toUpperCase() !== tid ? n : ''; };
export const mitreUrl = (tid) => `https://attack.mitre.org/techniques/${String(tid).replace('.', '/')}/`;

// The sentence of `text` around the span i..j (bounded by . ! ? or a line break). A sentence over 400 characters is
// cut to a window around the span, with an ellipsis on each cut side, so the printed id always shows (as the API does).
export function sentenceAt(text, i, j, max = 400) {
  const a0 = Math.max(...['. ', '! ', '? ', '\n'].map((c) => text.lastIndexOf(c, i - 1)));
  const ends = ['. ', '! ', '? ', '\n'].map((c) => text.indexOf(c, j)).filter((k) => k >= 0);
  let a = a0 < 0 ? 0 : a0 + 1, b = ends.length ? Math.min(...ends) + 1 : text.length;
  while (a < i && /\s/.test(text[a])) a++;
  while (b > j && /\s/.test(text[b - 1])) b--;
  if (b - a <= max) return text.slice(a, b);
  const w = max - 2;
  const start = Math.max(a, Math.min(i - Math.floor((w - (j - i)) / 2), b - w));
  const end = Math.min(b, start + w);
  return `${start > a ? '…' : ''}${text.slice(start, end).trim()}${end < b ? '…' : ''}`;
}

/**
 * The techniques of a story or article, labelled: [{id, name, kind, quote, source}] in label order, then id.
 * `intel` is GET /api/news/intel (its `techniques` list is the answer when present). Without it (the call failed) the
 * labels come from the entity chips (best mention confidence: 0.7 confirmed, 0.3 suggested) and the article texts.
 */
export function ttpList(intel, ents = [], texts = []) {
  if (Array.isArray(intel?.techniques)) return intel.techniques.map((t) => ({ ...t, id: String(t.id).toUpperCase() }));
  const by = new Map();
  for (const e of ents) {
    if ((e.type || String(e.id).split(':')[0]) !== 'technique') continue;
    const tid = tidOf(e.id);
    const kind = (e.confidence ?? 1) <= 0.35 ? 'possible' : 'likely';
    const cur = by.get(tid);
    if (!cur || kind === 'likely') by.set(tid, { id: tid, name: e.name, kind, quote: null, source: null });
  }
  for (const text of texts) {
    for (const m of String(text || '').matchAll(TTP_RE)) {
      const cur = by.get(m[0]);
      if (cur?.kind === 'named') continue;
      by.set(m[0], { id: m[0], name: cur?.name || null, kind: 'named', quote: sentenceAt(text, m.index, m.index + m[0].length), source: null });
    }
  }
  return [...by.values()].sort((a, b) => TTP_ORDER.indexOf(a.kind) - TTP_ORDER.indexOf(b.kind) || a.id.localeCompare(b.id));
}
/**
 * How sure a stored technique link (a claim from /api/entities or /api/news/intel) is, for the technique `tid`:
 * 'confirmed' when MITRE's catalogue states it (any reference evidence, `authoritative`, or intel's `catalogue`), a
 * feed observed it or the analyst confirmed it; else the article label: 'named' when a quote prints the id, 'possible'
 * when every article item is the suggested tier, otherwise 'likely'. null for a link that is not about a technique
 * read from text (an inferred hypothesis).
 */
export function ttpLinkKind(c, tid) {
  const ev = (Array.isArray(c.evidence) ? c.evidence : []).filter((e) => e && !e.verdict);
  if (c.authoritative || c.catalogue || ['observed', 'user'].includes(c.origin) || c.verdict === 'confirm' || ev.some((e) => e.ref_type === 'reference')) return 'confirmed';
  if (c.origin !== 'reported') return null;
  const T = String(tid || '').toUpperCase();
  if (T && ev.some((e) => String(e.quote || '').toUpperCase().includes(T))) return 'named';
  return c.suggested || (ev.length && ev.every((e) => e.suggested)) ? 'possible' : 'likely';
}
/** Articles reporting a link (for "also in N articles" on a catalogue link): the API's `article_count`, counted over
 * all of the claim's evidence on the server; the fetched evidence (cut to a few items) only as a fallback. */
export const ttpArticleCount = (c) => c.article_count ?? new Set((Array.isArray(c.evidence) ? c.evidence : []).filter((e) => e?.ref_type === 'article').map((e) => e.ref_id)).size;
/** The quote to show for a link: an unsuggested one first. */
export const ttpQuote = (c) => { const ev = (Array.isArray(c.evidence) ? c.evidence : []).filter((e) => e?.quote && e.ref_type !== 'reference'); return ev.find((e) => !e.suggested) || ev[0] || null; };
/**
 * A small label button for a technique link in prose and tables (relationship lists, claim rows): its text is the
 * label; a click or tap shows the evidence card. `t`: {id, kind, name, quote, source, page}.
 */
export function ttpTag(t) {
  const k = TTP_KINDS[t.kind];
  if (!k) return '';
  return `<button type="button" class="ttp-tag k-${esc(t.kind)}" ${ttpAttrs(t)} data-ttp-ev aria-expanded="false" aria-label="${esc(`${k.label}: where ${t.id} came from`)}">${esc(k.short)}</button>`;
}

/** The ones exports carry: named and likely, never possible. */
export const ttpExportable = (list) => list.filter((t) => t.kind !== 'possible');

/** Data attributes that let any element show a technique's evidence card (wireTtpTips). */
export function ttpAttrs(t) {
  return `data-ttp="${esc(t.id)}" data-ttp-kind="${esc(t.kind)}" data-ttp-name="${esc(ttpName(t.id, t.name))}"${t.quote ? ` data-ttp-q="${esc(t.quote)}"` : ''}${t.source ? ` data-ttp-src="${esc(t.source)}"` : ''}${t.page ? ` data-ttp-page="${esc(t.page)}"` : ''}`;
}

// ------------------------------------------------------------------ exports (named + likely only)
/** ATT&CK Navigator layer: a score and a comment per technique say how it was found. */
export function navigatorLayer(name, list) {
  const items = ttpExportable(list);
  return JSON.stringify({
    name, versions: { layer: '4.5', navigator: '4.9.1' }, domain: 'enterprise-attack',
    description: 'Exported from Night Desk News. Techniques read automatically from the article text: "Named in the article" means the text gives the ATT&CK id; "Likely" means found automatically, and it can be wrong. Possible ones are left out.',
    techniques: items.map((t) => ({ techniqueID: t.id, score: TTP_KINDS[t.kind].confidence, comment: TTP_KINDS[t.kind].comment })),
    gradient: { colors: ['#ffffff', '#3ddc97'], minValue: 0, maxValue: 100 },
  }, null, 2);
}
/** STIX 2.1 attack-pattern for one exportable technique: `confidence` (85 named, 50 likely) and a short description. */
export function stixAttackPattern(t, id, now) {
  const k = TTP_KINDS[t.kind] || TTP_KINDS.likely;
  return {
    type: 'attack-pattern', spec_version: '2.1', id, created: now, modified: now, name: t.id, confidence: k.confidence,
    description: t.kind === 'named' ? 'Named in the article: the text gives this ATT&CK id.' : 'Likely: found automatically in the article text by Night Desk; it can be wrong.',
    external_references: [{ source_name: 'mitre-attack', external_id: t.id, url: mitreUrl(t.id) }],
  };
}

// ------------------------------------------------------------------ evidence card
// One card for the whole app, kept simple on purpose (owner decision 2026-11-19): it opens only on a click or tap
// (Enter or Space from the keyboard) of a technique's label or quote button ([data-ttp-ev]) or of an Intel-strip cell
// ([data-ttp-page], whose card has the link to the technique's page), and it closes on Esc, a second click on the same
// thing, a click elsewhere, any scroll, a resize or a page change. No hover or focus opening, and the card never
// follows a scroll. Esc closes only the card (the view under it stays) and puts focus back on what opened it.
// "Any scroll" means one that moves the opener: a scroll event that lands just after the click (the scroll that brought
// the opener into view, still settling) moved nothing since the card was placed, so it leaves the card open.
let tip = null, cur = null, opener = null, ov = null, at = null;
const spot = (el) => { const r = el.getBoundingClientRect(); return [r.left, r.top]; };

function card() {
  if (tip) return tip;
  tip = document.createElement('div');
  tip.className = 'ttp-tip';
  tip.id = 'ttp-tip';
  tip.setAttribute('role', 'tooltip');
  tip.hidden = true;
  document.body.append(tip);
  return tip;
}
// The card opens inside the area where its opener can be seen: the window below the app's top bar (fixed on a phone,
// static on a desktop) and inside every ancestor that really scrolls (the story pane, the side panel). An element
// that is only styled overflow:auto but does not scroll (a phone card section) does not count. Under the opener if it
// fits, else above it, else on the roomier side with its own scroll bar. It never goes off screen or over the top bar
// (it closes on any scroll, so it has to fit where it opens).
function bounds(el) {
  let top = 0, bottom = innerHeight;
  for (const h of document.querySelectorAll('header.topbar, .m-topbar, header')) {
    const r = h.getBoundingClientRect(), st = getComputedStyle(h);
    if (r.height && st.display !== 'none' && st.visibility !== 'hidden' && r.top <= 1 && r.bottom > 0) top = Math.max(top, r.bottom);
  }
  for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
    const st = getComputedStyle(p);
    if (/(auto|scroll)/.test(st.overflowY) && p.scrollHeight > p.clientHeight + 1) {
      const r = p.getBoundingClientRect(); top = Math.max(top, r.top); bottom = Math.min(bottom, r.bottom);
    }
  }
  return { top, bottom };
}
function place(el) {
  const r = el.getBoundingClientRect(), pad = 8, gap = 6, b = bounds(el);
  const lo = b.top + pad, hi = Math.min(innerHeight, b.bottom) - pad;
  tip.style.maxHeight = ''; tip.style.overflowY = ''; tip.style.overscrollBehavior = 'contain';
  const h = tip.getBoundingClientRect().height, w = tip.getBoundingClientRect().width;
  const below = hi - (r.bottom + gap), above = r.top - gap - lo;
  let top;
  if (h <= below) top = r.bottom + gap;
  else if (h <= above) top = r.top - gap - h;
  else if (below >= above) { top = r.bottom + gap; tip.style.maxHeight = `${Math.max(80, below)}px`; tip.style.overflowY = 'auto'; }
  else { top = lo; tip.style.maxHeight = `${Math.max(80, above)}px`; tip.style.overflowY = 'auto'; }
  const hh = tip.getBoundingClientRect().height;
  tip.style.top = `${Math.max(lo, Math.min(top, hi - hh))}px`;
  tip.style.left = `${Math.max(pad, Math.min(innerWidth - w - pad, r.left))}px`;
}
function show(el, from) {
  card();
  const d = el.dataset, k = TTP_KINDS[d.ttpKind] || TTP_KINDS.likely;
  if (cur) unmark();
  cur = el; opener = from || el;
  tip.innerHTML = `<div class="ttp-tip-k k-${esc(d.ttpKind)}">${esc(k.label)}</div>
    <b class="ttp-tip-t"><span class="mono">${esc(d.ttp)}</span>${d.ttpName ? ` ${esc(d.ttpName)}` : ''}</b>
    <p class="ttp-tip-why">${esc(k.why)}</p>
    ${d.ttpQ ? `<blockquote class="ttp-tip-q">“${esc(d.ttpQ)}”</blockquote>${d.ttpSrc ? `<div class="ttp-tip-src">${esc(d.ttpKind === 'named' ? 'Printed by' : 'Read from')} ${esc(d.ttpSrc)}</div>` : ''}`
      : '<p class="ttp-tip-none">No sentence was kept for this one, so it can’t be checked here. Read the article before relying on it.</p>'}
    <div class="ttp-tip-links">${d.ttpPage ? `<a class="help-link" href="${esc(d.ttpPage)}">Open the technique’s page ›</a>` : ''}
    <a class="help-link" href="${esc(mitreUrl(d.ttp))}" target="_blank" rel="noopener">${esc(d.ttp)} on MITRE ATT&amp;CK ›</a></div>`;
  tip.hidden = false;
  // on the overlay stack at once (page.js, the app's one Esc owner): Esc closes the card before any panel under it
  ov = ov || overlayOpened({ kind: 'popup', close: (reason) => { ov = null; if (reason === 'esc') closeByEsc(); else hideTtpTip(); } });
  place(el);
  at = spot(el);
  opener.setAttribute('aria-describedby', 'ttp-tip');
  if (opener.matches('[data-ttp-ev]')) opener.setAttribute('aria-expanded', 'true');
}
function unmark() {
  if (!opener) return;
  opener.removeAttribute('aria-describedby');
  if (opener.matches('[data-ttp-ev]')) opener.setAttribute('aria-expanded', 'false');
}
export function hideTtpTip() {
  if (tip) tip.hidden = true;
  if (ov) { const o = ov; ov = null; closeOverlay(o, 'api', { run: false }); }
  unmark();
  cur = null; opener = null;
}
const isOpen = () => !!(cur && tip && !tip.hidden);
/** True while an evidence card is shown: a layer's own Esc (the entity side panel) leaves that Esc to the card. */
export const ttpTipOpen = isOpen;

function closeByEsc() {
  const back = opener;
  hideTtpTip();
  if (back?.isConnected) back.focus({ preventScroll: true });
}
addEventListener('keydown', (e) => {
  if (e.key !== 'Escape' || !isOpen()) return;
  e.preventDefault(); e.stopImmediatePropagation();
  closeByEsc();
}, true);

let installed = false;
/** Install the evidence card's listeners once (idempotent). It also runs when this module loads, so a page opened
 * straight from a link (a technique's own page) works without another view having set it up first. */
export function wireTtpTips() {
  if (installed) return;
  installed = true;
  document.addEventListener('click', (e) => {
    if (tip?.contains(e.target)) return;                       // the card's own links work as links
    const b = e.target.closest?.('[data-ttp-ev]');
    const t = b ? (b.closest('[data-ttp]') || b) : e.target.closest?.('[data-ttp][data-ttp-page]');
    if (t) {
      e.preventDefault(); e.stopPropagation();
      if (cur === t) hideTtpTip(); else show(t, b || t);
      return;
    }
    if (cur) hideTtpTip();
  }, true);
  addEventListener('scroll', (e) => {
    if (!cur || tip?.contains(e.target)) return;
    const now = cur.isConnected ? spot(cur) : null;
    if (!now || !at || Math.abs(now[0] - at[0]) > 1 || Math.abs(now[1] - at[1]) > 1) hideTtpTip();
  }, true);
  addEventListener('resize', () => { if (cur) hideTtpTip(); });
  addEventListener('hashchange', () => { if (cur) hideTtpTip(); });
}
wireTtpTips();

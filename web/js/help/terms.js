// Definition popovers for any element with data-term="<glossary id>", app-wide. Hover (after a short pause) or
// keyboard focus shows a small card with the plain definition and why it matters here; a tap or click toggles it;
// Enter on a focused term opens its glossary entry; Esc hides it. Terms get tabindex="0" (unless they sit inside a
// link or button) and aria-describedby while the card shows. On a phone a tap on a term inside a card link opens the
// term instead of the card. Loaded lazily by core/help.js.
// Contract: okf/architecture/help.md#definition-popovers
import { esc } from '../core/util.js';
import { byId, CATS } from './glossary.js';
import { isPhone } from '../core/mobile.js';

let tip = null, cur = null, showT = 0, hideT = 0, shownAt = 0, byClick = false;

function card() {
  if (tip) return tip;
  tip = document.createElement('div');
  tip.className = 'help-tip';
  tip.id = 'help-tip';
  tip.setAttribute('role', 'tooltip');
  tip.hidden = true;
  document.body.append(tip);
  tip.addEventListener('mouseenter', () => clearTimeout(hideT));
  tip.addEventListener('mouseleave', () => hideSoon());
  tip.addEventListener('click', (e) => { if (e.target.closest('a')) hide(); });
  return tip;
}

function place(el) {
  const r = el.getBoundingClientRect(), t = tip.getBoundingClientRect();
  const vw = innerWidth, vh = innerHeight, pad = 8;
  let top = r.bottom + 8;
  if (top + t.height > vh - pad && r.top - t.height - 8 > pad) top = r.top - t.height - 8;
  const left = Math.max(pad, Math.min(vw - t.width - pad, r.left + r.width / 2 - t.width / 2));
  tip.style.top = `${Math.max(pad, top)}px`;
  tip.style.left = `${left}px`;
}

export function show(el) {
  const g = byId.get(el?.dataset?.term);
  if (!g) return;
  clearTimeout(hideT); clearTimeout(showT);
  card();
  const fresh = tip.hidden || cur !== el;
  if (cur && cur !== el) cur.removeAttribute('aria-describedby');
  cur = el;
  tip.innerHTML = `<div class="help-tip-k">${esc(CATS[g.cat] || 'Glossary')}</div><b class="help-tip-t">${esc(g.term)}</b>
    <p>${esc(g.short)}</p><p class="help-tip-why">${esc(g.why)}</p>
    <a class="help-link" href="#help/glossary/${esc(g.id)}">More in the glossary ›</a>`;
  if (fresh) { shownAt = Date.now(); byClick = false; }
  tip.hidden = false;
  place(el);
  el.setAttribute('aria-describedby', 'help-tip');
}
export function hide() {
  clearTimeout(showT); clearTimeout(hideT);
  if (tip) tip.hidden = true;
  cur?.removeAttribute('aria-describedby');
  cur = null;
}
const hideSoon = () => { clearTimeout(hideT); hideT = setTimeout(hide, 220); };

// Make every [data-term] reachable by keyboard (once each).
function ready(root = document) {
  root.querySelectorAll?.('[data-term]:not([data-term-ready])').forEach((el) => {
    el.setAttribute('data-term-ready', '');
    if (!el.parentElement?.closest('a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])') && !el.hasAttribute('tabindex')) el.tabIndex = 0;
    if (!el.hasAttribute('title') && byId.has(el.dataset.term)) el.setAttribute('aria-label', `${el.textContent.trim()} (definition available)`);
  });
}

export function install() {
  ready();
  let pending = false;
  new MutationObserver(() => {
    if (pending) return;
    pending = true;
    (window.requestIdleCallback || setTimeout)(() => { pending = false; ready(); });
  }).observe(document.body, { childList: true, subtree: true });

  const termOf = (t) => t?.closest?.('[data-term]');
  document.addEventListener('mouseover', (e) => {
    const el = termOf(e.target);
    if (!el) { if (cur && !e.target.closest?.('.help-tip')) hideSoon(); return; }
    if (el === cur) { clearTimeout(hideT); return; }
    clearTimeout(showT);
    showT = setTimeout(() => show(el), 280);
  });
  document.addEventListener('mouseout', (e) => { if (termOf(e.target) && !termOf(e.relatedTarget)) { clearTimeout(showT); hideSoon(); } });
  document.addEventListener('focusin', (e) => { const el = termOf(e.target); if (el && el === e.target) show(el); else if (cur && !e.target.closest?.('.help-tip')) hide(); });
  // Capture phase: a term inside a clickable card or row (a News story card, an alert row) answers the tap itself, and
  // the card's own click (open the story) does not also run. A term inside a real link or button stays part of it.
  document.addEventListener('click', (e) => {
    const el = termOf(e.target);
    // A phone (S-09): a tap on a term opens the term, even inside a card that is itself a link or button (a story
    // card, an alert row); the card does not open and the address stays where it is. A second tap closes it.
    if (el && isPhone() && byId.has(el.dataset.term) && e.target.closest('a[href], button')) {
      e.preventDefault(); e.stopPropagation();
      clearTimeout(showT);
      if (cur === el && tip && !tip.hidden && byClick && Date.now() - shownAt > 300) hide(); else { show(el); byClick = true; shownAt = Date.now(); }
      return;
    }
    // One tap or click opens (the focus or hover it causes may already have shown it: keep it open); a second tap on
    // the same term, or a tap anywhere else, closes it.
    if (el && !e.target.closest('a[href], button')) {
      if (byId.has(el.dataset.term)) e.stopPropagation();
      clearTimeout(showT);
      if (cur === el && tip && !tip.hidden && byClick && Date.now() - shownAt > 300) hide(); else { show(el); byClick = true; shownAt = Date.now(); }
      return;
    }
    if (cur && !e.target.closest('.help-tip')) hide();
  }, true);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && cur && tip && !tip.hidden) { hide(); }
    if (e.key === 'Enter' && document.activeElement?.dataset?.term && byId.has(document.activeElement.dataset.term) && !document.activeElement.closest('a[href], button')) {
      e.preventDefault(); e.stopPropagation();   // the term's own Enter, not the card's around it
      const id = document.activeElement.dataset.term;
      hide();
      location.hash = `#help/glossary/${id}`;
    }
  }, true);
  addEventListener('scroll', () => { if (cur) hide(); }, true);
  addEventListener('resize', () => { if (cur) hide(); });
}

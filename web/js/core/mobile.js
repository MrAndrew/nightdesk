// The phone switch (v1.2 mobile, Phase 0 contract: okf/architecture/phone.md).
// The phone layout needs a COARSE primary pointer: a desktop window snapped to 700 px keeps today's <= 760 px
// layout. Every m: CSS rule sits inside the same media query (app.css `/* == m:base == */`), and every JS layout
// branch goes through isPhone(). Crossing the boundary (rotation, a split-screen resize on a tablet) calls the
// onPhoneChange() listeners, so a view can re-render for the other layout.
//
// Exports:
//   PHONE_MQ                      the media query string (identical to the one around the m: CSS blocks)
//   isPhone()                     true while PHONE_MQ matches
//   isShort()                     true on a phone held sideways / a short coarse screen (height <= 500 px)
//   onPhoneChange(cb) -> off      cb(isPhone) whenever isPhone() flips; returns an unsubscribe function
//   onShortChange(cb) -> off      cb(isShort) whenever isShort() flips
// Side effects (phone only): `--m-views-top` (where #views starts in the page); visualViewport keeps `--m-vvh` / `--m-vvt` (the visible height and its offset from the
// top of the layout viewport, in px, on <html>; sheets sit inside that box) and
// `body.m-kbd` (the on-screen keyboard is up: the visible height is more than 120 px under the layout height
// while a text field has focus); the focused field is scrolled to the centre when the keyboard opens.

export const PHONE_MQ = '(pointer: coarse) and (max-width: 760px), (pointer: coarse) and (max-height: 500px)';
const SHORT_MQ = '(pointer: coarse) and (max-height: 500px)';

const mq = (q) => (typeof window !== 'undefined' && window.matchMedia ? window.matchMedia(q) : null);
const phoneMQ = mq(PHONE_MQ);
const shortMQ = mq(SHORT_MQ);

export const isPhone = () => !!phoneMQ?.matches;
export const isShort = () => !!shortMQ?.matches;

function listen(m, cb) {
  if (!m || typeof cb !== 'function') return () => {};
  const fn = () => { try { cb(m.matches); } catch (e) { console.error(e); } };
  m.addEventListener?.('change', fn);
  return () => m.removeEventListener?.('change', fn);
}
export const onPhoneChange = (cb) => listen(phoneMQ, cb);
export const onShortChange = (cb) => listen(shortMQ, cb);

// ------------------------------------------------------------------ the keyboard (visualViewport)
const TEXT_SEL = 'input:not([type="checkbox"], [type="radio"], [type="range"], [type="button"], [type="submit"], [type="reset"], [type="file"], [type="color"]), textarea, select, [contenteditable="true"]';
const isText = (el) => !!el?.matches?.(TEXT_SEL);
let kbd = false;
// the tallest the screen has been at this width: the keyboard (or a cut-down viewport) is measured against it
let tall = { w: 0, h: 0 };
function syncViewport() {
  const root = document.documentElement;
  const vv = window.visualViewport;
  if (!isPhone() || !vv) {
    root.style.removeProperty('--m-vvh');
    root.style.removeProperty('--m-vvt');
    if (kbd) { kbd = false; document.body?.classList.remove('m-kbd'); }
    return;
  }
  root.style.setProperty('--m-vvh', `${Math.round(vv.height)}px`);
  root.style.setProperty('--m-vvt', `${Math.round(vv.offsetTop)}px`);
  // iOS keeps the layout viewport and shrinks the visual one; Android may shrink both. Either way the visible
  // height drops well under the tallest seen at this width while a text field has focus.
  const w = Math.round(window.innerWidth);
  if (w !== tall.w) tall = { w, h: 0 };
  tall.h = Math.max(tall.h, Math.round(window.innerHeight), Math.round(vv.height));
  const up = isText(document.activeElement) && tall.h - vv.height > 120;
  if (up !== kbd) {
    kbd = up;
    document.body?.classList.toggle('m-kbd', up);
    if (up) {
      const el = document.activeElement;
      requestAnimationFrame(() => el?.scrollIntoView?.({ block: 'center', behavior: 'instant' }));
    }
  }
}
// --m-views-top: where the views start in the page (the top bar, plus the offline notice while it is in the flow);
// the fixed-frame views subtract it so the page itself never scrolls under their inner scrollers.
function syncViewsTop() {
  const root = document.documentElement;
  const v = document.getElementById('views');
  if (!isPhone() || !v) { root.style.removeProperty('--m-views-top'); return; }
  const top = Math.round(v.getBoundingClientRect().top + window.scrollY);
  root.style.setProperty('--m-views-top', `${top}px`);
}
function watchViewsTop() {
  syncViewsTop();
  new MutationObserver(syncViewsTop).observe(document.body, { childList: true });
  if (typeof ResizeObserver === 'function') {
    const ro = new ResizeObserver(syncViewsTop);
    for (const el of document.body.children) if (el.id !== 'views') ro.observe(el);
  }
}
if (typeof window !== 'undefined') {
  window.addEventListener('resize', syncViewsTop);
  phoneMQ?.addEventListener?.('change', syncViewsTop);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', watchViewsTop, { once: true });
  else watchViewsTop();
  window.visualViewport?.addEventListener('resize', syncViewport);
  window.visualViewport?.addEventListener('scroll', syncViewport);
  window.addEventListener('resize', syncViewport);
  document.addEventListener('focusin', () => setTimeout(syncViewport, 60));
  document.addEventListener('focusout', () => setTimeout(syncViewport, 60));
  phoneMQ?.addEventListener?.('change', syncViewport);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', syncViewport, { once: true });
  else syncViewport();
}

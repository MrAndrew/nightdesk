// Row swipes (v1.2 mobile, Phase 0 contract: design.md §3 "Gestures", build-plan.md "Phase 0").
//   swipeRow(el, { right, left, guard, menu, threshold = 0.4 }) -> off()
//     A shortcut only (every swipe has a visible ⋯ equivalent). Rules:
//       * touch or pen only: a mouse never swipes; off under prefers-reduced-motion;
//       * the row gets `touch-action: pan-y`, so vertical scrolling stays the browser's;
//       * a pointerdown within 24 px of either screen edge is ignored (the browser's Back gesture lives there);
//       * a 24 px dead zone, then horizontal intent needs |dx| > 1.5 |dy| (otherwise the row lets go);
//       * it commits when released past `threshold` (40 %) of the row's width; otherwise it springs back.
//     right() / left() run on commit (a missing one means that direction does nothing).
//     guard(dir) runs first ('right' | 'left'): return false to cancel, or 'menu' to call menu() instead of the
//     action (a high alert's left swipe opens its ⋯ sheet and changes nothing).
//     While dragging the row has class `m-swiping` and data-swipe="right|left" (for the reveal styling); the click
//     that ends a drag is swallowed, so a swipe never also opens the row.
//     off() detaches everything and restores the row's touch-action.

import { reducedMotion as reduced } from './util.js';

const EDGE = 24, DEAD = 24, RATIO = 1.5;

export function swipeRow(el, o = {}) {
  if (!el) return () => {};
  const threshold = o.threshold ?? 0.4;
  const prevTouch = el.style.touchAction;
  el.style.touchAction = 'pan-y';
  let g = null; // { id, x0, y0, dx, dy, mode: null | 'h' | 'v' }

  const reset = () => {
    el.classList.remove('m-swiping');
    delete el.dataset.swipe;
    el.style.transform = '';
    el.style.transition = '';
    g = null;
  };
  const swallowClick = () => {
    const stop = (e) => { e.preventDefault(); e.stopPropagation(); };
    el.addEventListener('click', stop, { capture: true, once: true });
    setTimeout(() => el.removeEventListener('click', stop, { capture: true }), 400);
  };

  function down(e) {
    if (g || !e.isPrimary || e.pointerType === 'mouse' || reduced()) return;
    if (e.pointerType !== 'touch' && e.pointerType !== 'pen') return;
    if (e.clientX < EDGE || e.clientX > window.innerWidth - EDGE) return;
    g = { id: e.pointerId, x0: e.clientX, y0: e.clientY, dx: 0, dy: 0, mode: null };
  }
  function move(e) {
    if (!g || e.pointerId !== g.id) return;
    g.dx = e.clientX - g.x0;
    g.dy = e.clientY - g.y0;
    if (!g.mode) {
      if (Math.abs(g.dx) < DEAD && Math.abs(g.dy) < DEAD) return;
      if (Math.abs(g.dx) > RATIO * Math.abs(g.dy)) {
        g.mode = 'h';
        el.setPointerCapture?.(e.pointerId);
        el.classList.add('m-swiping');
        el.style.transition = 'none';
      } else { g = null; return; }
    }
    e.preventDefault();
    const dir = g.dx > 0 ? 'right' : 'left';
    el.dataset.swipe = dir;
    const can = dir === 'right' ? !!o.right : !!(o.left || o.menu);
    el.style.transform = `translateX(${can ? g.dx : g.dx / 4}px)`;
  }
  function up(e) {
    if (!g || e.pointerId !== g.id) return;
    const { mode, dx } = g;
    if (mode !== 'h') { g = null; return; }
    swallowClick();
    const w = el.getBoundingClientRect().width || window.innerWidth;
    const dir = dx > 0 ? 'right' : 'left';
    reset();
    if (Math.abs(dx) < threshold * w) return;
    const verdict = o.guard ? o.guard(dir) : true;
    if (verdict === false) return;
    if (verdict === 'menu') { o.menu?.(dir); return; }
    (dir === 'right' ? o.right : o.left)?.(dir);
  }
  function cancel(e) { if (g && e.pointerId === g.id) reset(); }

  el.addEventListener('pointerdown', down);
  el.addEventListener('pointermove', move);
  el.addEventListener('pointerup', up);
  el.addEventListener('pointercancel', cancel);
  return function off() {
    el.removeEventListener('pointerdown', down);
    el.removeEventListener('pointermove', move);
    el.removeEventListener('pointerup', up);
    el.removeEventListener('pointercancel', cancel);
    reset();
    el.style.touchAction = prevTouch;
  };
}

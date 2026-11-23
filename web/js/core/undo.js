// The Undo toast (v1.2 mobile, Phase 0 contract: design.md §3 "Toasts", build-plan.md "Phase 0").
//   undoToast(text, undo, ms = 6000) -> { close(), el, done: Promise<'undo' | 'timeout' | 'closed'> }
//     An opaque toast 8 px above the bottom layer (the tab bar or the page's action bar), with one Undo button.
//     It is the only thing allowed to take taps in its own box. A new one replaces the one on screen. The text is
//     announced in #sr-live ("Alert acknowledged. Undo available."). undo() may return a Promise; while it runs the
//     button is busy, and a failure is shown in the toast ("Couldn't undo: …").
//     Phone: `.m-toast` (app.css m:base). Desktop: the same toast in today's #toasts stack.
import { isPhone } from './mobile.js';

let current = null;

function announce(msg) {
  const live = document.getElementById('sr-live');
  if (!live) return;
  live.textContent = '';
  setTimeout(() => { live.textContent = msg; }, 30);
}

function host() {
  if (!isPhone()) return document.getElementById('toasts') || document.body;
  let h = document.querySelector('.m-toasts');
  if (!h) {
    h = document.createElement('div');
    h.className = 'm-toasts';
    document.body.append(h);
  }
  return h;
}

export function undoToast(text, undo, ms = 6000) {
  current?.close('replaced');
  const el = document.createElement('div');
  el.className = isPhone() ? 'm-toast' : 'toast m-toast-d';
  const t = document.createElement('span');
  t.className = 'm-toast-t';
  t.textContent = text;
  el.append(t);
  let btn = null;
  if (typeof undo === 'function') {
    btn = document.createElement('button');
    btn.type = 'button';
    btn.className = isPhone() ? 'm-toast-undo' : 'src-btn sm m-toast-undo';
    btn.textContent = 'Undo';
    el.append(btn);
  }
  host().append(el);
  announce(`${text}${btn ? '. Undo available.' : ''}`);

  let resolveDone;
  const done = new Promise((r) => { resolveDone = r; });
  let timer = setTimeout(() => close('timeout'), ms);
  function close(why = 'closed') {
    if (!el.isConnected) return;
    clearTimeout(timer);
    el.remove();
    if (current === api) current = null;
    resolveDone(why);
  }
  btn?.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    clearTimeout(timer);
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    try {
      await undo();
      announce('Undone.');
      close('undo');
    } catch (err) {
      t.textContent = `Couldn't undo: ${err?.message || err}`;
      btn.remove();
      timer = setTimeout(() => close('timeout'), ms);
    }
  });
  const api = { el, done, close };
  current = api;
  return api;
}

// "Night Desk was updated · Reload": a tab left open across a server upgrade keeps running the old modules, and any
// module it loads later comes from the new version, so the two can disagree (B2-02). The server names its copy of the
// web client in /api/health's `build` (and in the `nd_build` cookie it sets with the page). This module remembers the
// build the page was served as, re-checks every 5 minutes, when the tab becomes visible again and when the live
// connection comes back, and shows a one-line bar when the server now runs a different build.
// okf/architecture/web-client.md#updates
import { live } from './live.js';

const EVERY_MS = 5 * 60e3;
let base = null;        // the build this page runs
let dismissed = null;   // the build whose bar the user closed
let bar = null;
let checking = false;
let again = false;      // a trigger arrived while a check was running: check once more after it

async function serverBuild() {
  try {
    // a request caught by a server going down can hang; never let one block the next checks
    const r = await fetch('api/health', { cache: 'no-store', signal: AbortSignal.timeout(5000) });
    if (!r.ok) return null;
    return (await r.json())?.build || null;
  } catch { return null; }
}

function ensureBar() {
  if (bar) return bar;
  // the live region exists (empty) before it is filled, so screen readers announce the message
  bar = document.createElement('div');
  bar.className = 'upd-bar';
  bar.setAttribute('role', 'status');
  bar.hidden = true;
  document.body.appendChild(bar);
  return bar;
}

function show(build) {
  if (dismissed === build) return;
  const el = ensureBar();
  if (!el.hidden && el.dataset.build === build) return;
  el.dataset.build = build;
  el.innerHTML = `<span class="upd-t">Night Desk was updated</span><span class="upd-sep" aria-hidden="true">·</span>
    <button type="button" class="upd-reload">Reload</button>
    <button type="button" class="upd-x" aria-label="Dismiss" title="Dismiss (keep working on this copy)">×</button>`;
  el.hidden = false;
  el.querySelector('.upd-reload').addEventListener('click', () => location.reload());
  el.querySelector('.upd-x').addEventListener('click', () => { dismissed = build; el.hidden = true; el.innerHTML = ''; });
}

async function check() {
  if (checking) { again = true; return; }
  checking = true;
  try {
    const b = await serverBuild();
    if (!b) return;
    if (base == null) { base = b; return; }
    if (b !== base) show(b);
  } finally {
    checking = false;
    if (again) { again = false; check(); }
  }
}

// While the live connection is down, ask every few seconds, so the bar does not depend on the stream reconnecting.
let outage = null;
function watchOutage() {
  if (outage) return;
  const until = Date.now() + 10 * 60e3;
  outage = setInterval(async () => {
    const b = await serverBuild();
    if (b || Date.now() > until) { clearInterval(outage); outage = null; }
    if (b) check();
  }, 4000);
}

// pageBuild: the `nd_build` cookie as the page loaded (main.js reads it before booting). Without it (cookies blocked),
// the first /api/health answer is taken as this page's build.
export function initUpdate(pageBuild) {
  base = pageBuild || null;
  ensureBar();
  check();
  setInterval(check, EVERY_MS);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') check(); });
  live.on('status', (up) => { if (up) check(); else watchOutage(); });
}

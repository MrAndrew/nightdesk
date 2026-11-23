// Entry point. Each panel/view module self-registers on import; a module that fails to load is skipped so one broken
// panel never takes the app down, and the view it would have registered shows "This page didn't load" with a Reload
// button instead of waiting forever (core/shell.js boot({ failed })).
const MODULES = [
  './views/watch.js',
  './panels/world-map.js',
  './panels/pulse.js',
  './panels/charts.js',
  './panels/feeds.js',
  './panels/network.js',
  './views/cinema.js',
  './views/explorer.js',
  './views/settings.js',
  './views/network.js',
  './views/news.js',
  './views/entities.js',
  './core/notes.js',
];
// The view each module registers (panels register widgets, which Ops shows as "not available" on their own).
const VIEW_OF = {
  './views/watch.js': 'watch', './views/cinema.js': 'cinema', './views/explorer.js': 'explorer', './views/settings.js': 'settings',
  './views/network.js': 'network', './views/news.js': 'news', './views/entities.js': 'entities', './core/notes.js': 'notes',
};

// "This main.js is current": index.html's stale-code check looks for it once the page has loaded and, without it,
// offers "Clear cached files and reload" (an older main.js the browser kept never sets it). okf/architecture/web-client.md#updates
window.ndMain = 1;

// The build this page was served as: the server sets the build cookie (`nd_build_<port>`, or `nd_build` on a default
// port) with the document. core/update.js compares it with /api/health's `build` to offer "Night Desk was updated · Reload".
const BUILD_COOKIE = 'nd_build' + (location.port ? `_${location.port}` : '');
const PAGE_BUILD = (document.cookie.match(new RegExp(`(?:^|;\\s*)${BUILD_COOKIE}=([^;]+)`)) || [])[1] || null;

// "Clear cached files and reload": the browser may be pairing this page with older files it kept from an earlier
// version. Re-fetch every file this page has loaded past the cache (works on any origin), forget the build cookie so
// the next page load also carries the server's one-shot Clear-Site-Data, then reload. index.html defines the same
// (window.ndClearAndReload); this copy is the fallback.
async function clearAndReload() {
  if (typeof window.ndClearAndReload === 'function') { window.ndClearAndReload(); return; }
  const own = performance.getEntriesByType('resource').map((e) => e.name)
    .filter((u) => u.startsWith(location.origin) && !u.includes('/api/'));
  const urls = [...new Set([...own, new URL('js/core/shell.js', document.baseURI).href])];
  const timeout = new Promise((r) => setTimeout(r, 4000));
  await Promise.race([timeout, Promise.allSettled(urls.map((u) => fetch(u, { cache: 'reload' })))]);
  document.cookie = `${BUILD_COOKIE}=; Max-Age=0; Path=/; SameSite=Strict`;
  location.reload();
}

// The shell itself is loaded first (its alias route listener must run before the views'). If it cannot load, nothing
// else can work: say so in plain words on the page, with a way out that does work, instead of leaving it blank.
function fatal(err) {
  console.error('Night Desk could not start:', err);
  const host = document.querySelector('#views .view.active') || document.body;
  host.innerHTML = `<div class="vs vs-error" role="alert" style="padding:48px 16px;text-align:center">
    <p class="vs-t">Night Desk didn't load</p>
    <p class="vs-why">Part of the app is an older copy your browser kept.</p>
    <div class="vs-act"><button type="button" class="vs-btn primary" data-act="clear">Clear cached files and reload</button>
      <button type="button" class="vs-btn" data-act="reload">Reload</button></div></div>`;
  const clear = host.querySelector('[data-act="clear"]');
  clear?.addEventListener('click', () => { clear.disabled = true; clear.textContent = 'Clearing…'; clearAndReload(); });
  host.querySelector('[data-act="reload"]')?.addEventListener('click', () => location.reload());
}

try {
  const { boot } = await import('./core/shell.js');
  const failed = {};
  await Promise.all(MODULES.map((m) => import(m).catch((e) => {
    console.warn(`module ${m} not loaded:`, e.message);
    if (VIEW_OF[m]) failed[VIEW_OF[m]] = e.message;
  })));
  boot({ failed });
} catch (e) {
  fatal(e);
}
// Tour (a short first-visit tour on Watch): loaded lazily and non-fatally so it can never take the app down.
import('./core/tour.js').then((m) => m.initTour()).catch((e) => console.warn('tour not loaded:', e.message));
// Update check (a bar when the server now runs a newer web client): also lazy and non-fatal.
import('./core/update.js').then((m) => m.initUpdate(PAGE_BUILD)).catch((e) => console.warn('update check not loaded:', e.message));

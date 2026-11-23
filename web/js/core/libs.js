// Vendored libraries on demand (v1.2 mobile, Phase 0 contract: design.md §6, build-plan.md "Phase 0").
//   need(name) -> Promise<global>   name: 'echarts' | 'maplibre' | 'gridstack' | 'globe'
//     Resolves at once when the library's global already exists; otherwise injects the vendored <script> once
//     and resolves when it has loaded. Rejects (and forgets the attempt, so a later call retries) when the script
//     fails to load. index.html loads none of them (v1.2 m-perf): a phone's first screen needs none.
//     A table entry may name a dependency (`after`): it is injected right behind it and both run in order
//     (injected scripts with async=false execute in insertion order), so a dependency costs no extra round trip.
//     echarts-gl is no longer loaded (v1.2 pre-alpha auth): it compiles code with eval, which the page's
//     Content-Security-Policy refuses; Threat origins 3D draws with globe.gl instead.
//   preloadAll() -> Promise          injects all four in a fixed order (echarts -> maplibre -> gridstack -> globe):
//     fetched together, run one after another in that order; a failure is logged and the
//     rest go on. core/preload.js calls it on idle at startup on desktop (not on a phone), so the libraries are
//     there by the time a desktop view wants them, as when index.html loaded them in <head>.
//   LIBS                             the table below (read only)
// Every call site awaits it: `const echarts = await need('echarts');` (build-plan.md "Library call sites").
// No network beyond this server: every URL is the vendored copy next to this file (web/vendor/...).

const V = (p) => new URL(`../../vendor/${p}`, import.meta.url).href;

export const LIBS = Object.freeze({
  echarts: { src: V('echarts@5.5.1/echarts.min.js'), global: 'echarts' },
  maplibre: { src: V('maplibre-gl@5.24.1/maplibre-gl.js'), global: 'maplibregl' },
  gridstack: { src: V('gridstack@10.3.1/gridstack-all.js'), global: 'GridStack' },
  globe: { src: V('globe.gl@2.32.4/globe.gl.min.js'), global: 'Globe' },
});
export const PRELOAD_ORDER = Object.freeze(['echarts', 'maplibre', 'gridstack', 'globe']);

const pending = new Map();

function present(name) {
  const L = LIBS[name];
  if (L.ready) return L.ready();
  return window[L.global] != null;
}

function inject(name) {
  const L = LIBS[name];
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = L.src;
    s.async = false; // keep execution order when several are injected together
    s.dataset.ndLib = name;
    s.onload = () => { s.dataset.ndLoaded = '1'; resolve(window[L.global]); };
    s.onerror = () => { s.remove(); reject(new Error(`The ${name} library did not load from this server`)); };
    document.head.append(s);
  });
}

export function need(name) {
  const L = LIBS[name];
  if (!L) return Promise.reject(new Error(`Unknown library: ${name}`));
  if (present(name)) return Promise.resolve(window[L.global]);
  if (pending.has(name)) return pending.get(name);
  // a dependent is injected right behind its dependency (not after it has loaded): async=false keeps the order
  const p = (L.after ? Promise.all([need(L.after), present(name) ? null : inject(name)]).then(() => window[L.global])
    : inject(name))
    .catch((e) => { pending.delete(name); throw e; });
  pending.set(name, p);
  return p;
}

let all = null;
export function preloadAll() {
  return (all ||= Promise.all(PRELOAD_ORDER.map((name) => need(name).catch((e) => console.warn(e.message)))));
}

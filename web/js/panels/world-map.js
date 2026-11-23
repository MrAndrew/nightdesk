// World Map panel: MapLibre basemap + undersea cables + country heat + live event points.
import { registerPanel } from '../core/panels.js';
import * as Tm from '../core/time.js';
import { KINDS, kindMeta, esc, fmt, compact, ago, debounce, flag, toast, isRing, kindSwatch } from '../core/util.js';
import { emptyState } from '../core/view.js';
import { need } from '../core/libs.js';

// Glyphs for the cluster counts are vendored (web/vendor/glyphs), so labels render with no internet.
const PAGE_BASE = location.href.replace(/[#?].*$/, '').replace(/[^/]*$/, '');
const GLYPHS = PAGE_BASE + 'vendor/glyphs/{fontstack}/{range}.pbf';
const FONT = ['Montserrat SemiBold', 'Open Sans Bold', 'Noto Sans Regular'];
const CABLE = '#9cb6ad';   // dusty slate: cables are context, not the story (no teal)
const PULSE = '#e4a84c';
const RING_FILL = 'rgba(12,13,15,0.85)';   // live BGP pulses in the lamp amber
const GROUPS = ['Threat infrastructure', 'Vulnerabilities', 'Internet infrastructure', 'Media', 'Custom'];
const REFS = {
  cables: { label: 'Undersea cables', color: CABLE, line: true, def: false },   // opt-in: downloads TeleGeography's data
  landings: { label: 'Cable landing points', color: '#e9e3d4', def: false },
  choropleth: { label: 'Country heat', color: '#f08a3c', fill: true, def: false },
};
const MODES = [['dots', 'Dots'], ['cluster', 'Clusters'], ['heat', 'Heat']];

const GEO_CREDIT = '<a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a>';
// Credits shown on the map itself, never behind a click: CARTO's terms ask for that, and TeleGeography's cable map
// asks for credit wherever its data is drawn.
const CARTO_CREDIT = '© <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors, © <a href="https://carto.com/attribution/" target="_blank" rel="noopener noreferrer">CARTO</a>';
const CABLE_CREDIT = 'Cable data © <a href="https://www.submarinecablemap.com" target="_blank" rel="noopener noreferrer">TeleGeography (submarinecablemap.com)</a>';
// The user's own CARTO key (CARTO_API_KEY, from /api/geo/basemaps): CARTO's styles are offered only with it, and the
// key goes on the style URL, which CARTO adds to every tile URL inside the style.
let cartoKey = null;
const cartoStyle = (name) => `https://basemaps.cartocdn.com/gl/${name}-gl-style/style.json?key=${encodeURIComponent(cartoKey || '')}`;

// Offline basemap: land from the lake's own country polygons (/api/geo/countries) over dark water. Used when
// chosen, and automatically when the online basemap cannot be reached (no internet).
function localStyle() {
  return {
    version: 8, glyphs: GLYPHS,
    sources: { land: { type: 'geojson', data: PAGE_BASE + 'api/geo/countries', tolerance: 0.5 } },
    layers: [
      { id: 'background', type: 'background', paint: { 'background-color': '#0b0c0e' } },
      { id: 'land', type: 'fill', source: 'land', paint: { 'fill-color': '#1a1c20' } },
      { id: 'borders', type: 'line', source: 'land', paint: { 'line-color': '#34383f', 'line-width': ['interpolate', ['linear'], ['zoom'], 1, 0.4, 6, 1] } },
    ],
  };
}

// Online basemaps: CARTO's Dark Matter and Positron, only with the user's own key (CARTO's terms). The keyless CARTO
// styles and the Esri imagery and hillshade layers were removed in the pre-alpha terms review.
const BASEMAPS = {
  dark: { label: 'Dark Matter', swatch: '#121316', style: () => cartoStyle('dark-matter'), tone: toneDark, carto: true },
  positron: { label: 'Positron', swatch: '#e6e7e8', style: () => cartoStyle('positron'), light: true, carto: true },
  local: { label: 'Offline (local)', swatch: '#17191c', style: localStyle, offline: true },
};

// Re-tone CARTO dark-matter towards the reference: near-black land, neutral charcoal water, quiet labels.
function toneDark(map) {
  const set = (id, prop, v) => { if (map.getLayer(id)) try { map.setPaintProperty(id, prop, v); } catch {} };
  const lay = (id, prop, v) => { if (map.getLayer(id)) try { map.setLayoutProperty(id, prop, v); } catch {} };
  set('background', 'background-color', '#0c0d0f');
  for (const id of ['landcover', 'park_national_park', 'park_nature_reserve', 'landuse']) set(id, 'fill-color', '#0f1012');
  set('water', 'fill-color', '#1e2023');
  set('waterway', 'line-color', '#1e2023');
  set('boundary_country_outline', 'line-color', '#1a1c1f');
  set('boundary_country_outline', 'line-width', 3);
  set('boundary_country_inner', 'line-color', '#34373c');
  set('boundary_state', 'line-color', '#25282c');
  for (const l of map.getStyle().layers) {
    if (l.type !== 'symbol') continue;
    if (l.id.startsWith('place_country')) {
      set(l.id, 'text-color', '#8d9299'); set(l.id, 'text-halo-color', '#0a0b0c'); set(l.id, 'text-halo-width', 1.2);
      lay(l.id, 'text-transform', 'uppercase'); lay(l.id, 'text-letter-spacing', 0.06);
      try { map.setLayerZoomRange(l.id, l.id === 'place_country_1' ? 0.9 : 1.6, 24); } catch {}
    } else if (l.id.startsWith('place_continent')) {
      lay(l.id, 'visibility', 'none');
    } else if (l.id.startsWith('watername')) {
      set(l.id, 'text-color', '#3c4046');
    } else if (l.id.startsWith('place_')) {
      set(l.id, 'text-color', '#7b8087'); set(l.id, 'text-halo-color', '#0a0b0c');
    } else if (l.id.startsWith('roadname') || l.id.startsWith('poi')) {
      set(l.id, 'text-color', '#4a4e54');
    }
  }
}

const ICON = {
  layers: '<svg class="i" viewBox="0 0 24 24"><path d="M12 3 2 8l10 5 10-5-10-5Z M2 13l10 5 10-5 M2 17.5l10 5 10-5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>',
  caret: '<svg class="i wm-caret" viewBox="0 0 24 24"><path d="m7 10 5 5 5-5" fill="none" stroke="currentColor" stroke-width="2"/></svg>',
  map: '<svg class="i" viewBox="0 0 24 24"><path d="M9 4 3 6.5v13.5l6-2.5 6 2.5 6-2.5V4l-6 2.5L9 4Zm0 0v13.5m6-11v13.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>',
  clock: '<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M12 7.5V12l3 2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>',
  globe: '<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M3.5 12h17M12 3.5c2.6 2.4 3.6 5.3 3.6 8.5s-1 6.1-3.6 8.5c-2.6-2.4-3.6-5.3-3.6-8.5s1-6.1 3.6-8.5Z" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>',
  pulse: '<svg class="i" viewBox="0 0 24 24"><path d="M3 12h4l2.5-6 5 12 2.5-6h4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round"/></svg>',
  plus: '<svg class="i" viewBox="0 0 24 24"><path d="M12 6v12M6 12h12" stroke="currentColor" stroke-width="1.8"/></svg>',
  minus: '<svg class="i" viewBox="0 0 24 24"><path d="M6 12h12" stroke="currentColor" stroke-width="1.8"/></svg>',
  home: '<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M12 2.5v4M12 17.5v4M2.5 12h4M17.5 12h4" stroke="currentColor" stroke-width="1.6"/></svg>',
  search: '<svg class="i" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m16 16 4.5 4.5" stroke="currentColor" stroke-width="1.6"/></svg>',
  arrow: '<svg class="i" viewBox="0 0 24 24"><path d="M5 12h13m-5-5 5 5-5 5" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>',
};

function dms(v, pos, neg) {
  const a = Math.abs(v); const d = Math.floor(a); const mf = (a - d) * 60; const m = Math.floor(mf);
  return `${d}°${String(m).padStart(2, '0')}'${((mf - m) * 60).toFixed(1).padStart(4, '0')}"${v >= 0 ? pos : neg}`;
}

function bboxOf(geom) {
  let [x0, y0, x1, y1] = [180, 90, -180, -90];
  const walk = (c) => { if (typeof c[0] === 'number') { x0 = Math.min(x0, c[0]); x1 = Math.max(x1, c[0]); y0 = Math.min(y0, c[1]); y1 = Math.max(y1, c[1]); } else c.forEach(walk); };
  walk(geom.coordinates);
  return [x0, y0, x1, y1];
}

const iso2 = (p) => (p.ISO_A2 && p.ISO_A2 !== '-99' ? p.ISO_A2 : p.ISO_A2_EH && p.ISO_A2_EH !== '-99' ? p.ISO_A2_EH : null);

registerPanel({
  id: 'world-map', title: 'World map', w: 8, h: 8, minW: 4, minH: 5,
  description: 'Live geolocated threat events over undersea cables, country heat and switchable basemaps',
  mount(body, ctx) {
    const { api, live, store } = ctx;
    const saved = ctx.state.get();
    const layers = { ...Object.fromEntries(Object.keys(KINDS).map((k) => [k, true])), ...Object.fromEntries(Object.entries(REFS).map(([k, r]) => [k, r.def])), ...(saved.layers || {}) };
    // Private by default: the local basemap unless the user opted into an online one, and never online in offline mode.
    let basemap = BASEMAPS[saved.basemap] ? saved.basemap : 'local';
    let srvOffline = null;   // from /api/health; the map is not created until it is known
    // usable: the local basemap always; CARTO's only online and with the user's key
    const usable = (id) => !!BASEMAPS[id] && (BASEMAPS[id].offline || (!srvOffline && !!cartoKey));
    Promise.all([api.health(), api.basemaps().catch(() => ({}))]).then(([h, b]) => {
      srvOffline = !!h.offline;
      cartoKey = b?.carto_key || null;
      if (!usable(basemap)) basemap = 'local';
      renderBase(); renderCredit(); createMap();
    });
    let mode = MODES.some(([m]) => m === saved.mode) ? saved.mode : 'dots';
    let pulsesOn = saved.pulses !== false;

    body.classList.add('wm-body');
    body.innerHTML = `
      <div class="wm-bar">
        <div class="wm-dd"><button class="wm-btn wm-layers" data-dd="layers">${ICON.layers}<span class="wm-lbl">Layers</span><span class="wm-n">0</span>${ICON.caret}</button><div class="wm-menu wm-layer-menu"></div></div>
        <div class="wm-dd"><button class="wm-btn wm-base" data-dd="base">${ICON.map}<span class="wm-lbl wm-caps"></span>${ICON.caret}</button><div class="wm-menu wm-base-menu"></div></div>
        <div class="wm-quick"></div>
        <div class="wm-sp"></div>
        <button class="wm-btn wm-ico wm-live" title="Live BGP pulses">${ICON.pulse}</button>
        <div class="wm-qtip" hidden></div>
        <div class="wm-dd"><button class="wm-btn wm-jump" data-dd="jump">${ICON.globe}<span class="wm-lbl wm-caps">Jump to</span>${ICON.caret}</button><div class="wm-menu wm-jump-menu wm-right">
          <div class="wm-jump-in">${ICON.search}<input placeholder="Country, ISO code or lat, lon" spellcheck="false"></div><div class="wm-jump-list"></div></div></div>
      </div>
      <div class="wm-stage">
        <div class="wm-map"></div>
        <div class="wm-loading" hidden>Loading events…</div>
        <div class="wm-coords"><span class="wm-dec">—</span><span class="wm-sep"></span><span class="wm-dms"></span></div>
        <div class="wm-stat"></div>
        <div class="wm-legend"><button class="wm-leg-h" title="Toggle legend"><span>Legend</span><span class="wm-leg-n"></span>${ICON.caret}</button><div class="wm-leg-b"></div></div>
        <div class="wm-zoom"><button data-z="in" title="Zoom in">${ICON.plus}</button><button data-z="out" title="Zoom out">${ICON.minus}</button><button data-z="home" title="Reset view">${ICON.home}</button></div>
        <div class="wm-tip" hidden></div>
        <div class="wm-credit" hidden></div>
      </div>`;
    const $ = (s) => body.querySelector(s);
    const stage = $('.wm-stage');
    const tip = $('.wm-tip');

    // ---------------------------------------------------------------- data
    let rows = [];               // [lon,lat,sev,kind,id,title,country,t]
    let ids = new Set();
    let groups = [];             // aggregated sites
    let counts = {};             // kind -> events
    let countryStats = [];
    let cablesFC = null, landingsFC = null, countriesFC = null;
    let fetchingCables = false;   // the opt-in cable download is running
    let jumpList = [];
    let lastLoad = null;

    const homeBounds = [[-168, -52], [178, 74]];
    // The map is created lazily: a panel mounted while its box is 0x0 (deck switch, hidden view)
    // makes MapLibre throw "failed to invert matrix", so wait until the stage has a real size.
    let map = null;
    const mapHooks = [];
    const onMap = (fn) => mapHooks.push(fn);
    let userMoved = !!saved.view;   // until the user pans/zooms, keep refitting the world on resize
    // MapLibre itself arrives on demand (core/libs.js need('maplibre')); the map is created once it is there.
    let ml = null, mlP = null;
    function createMap() {
      if (map || destroyed || srvOffline === null) return;
      const el = $('.wm-map');
      if (el.clientWidth < 2 || el.clientHeight < 2) return;
      if (!ml) { mlP ||= need('maplibre').then((lib) => { ml = lib; createMap(); }, (e) => { mlP = null; console.error(e); }); return; }
      map = new ml.Map({
        container: el,
        style: styleFor(basemap),
        ...(saved.view ? { center: saved.view.c, zoom: saved.view.z } : { bounds: homeBounds }),
        minZoom: 0.3, maxZoom: 14, dragRotate: false, pitchWithRotate: false, touchPitch: false,
        attributionControl: false, fadeDuration: 0, renderWorldCopies: true,
      });
      map.touchZoomRotate.disableRotation();
      // No internet: an online basemap's style or tiles fail, so fall back to the local one (not saved).
      let fellBack = false, tileErrs = 0;
      const fallBack = () => {
        if (fellBack || destroyed || BASEMAPS[basemap].offline) return;
        fellBack = true;
        map.setStyle(localStyle(), { diff: false });
        $('.wm-base .wm-lbl').textContent = `${BASEMAPS.local.label}`;
        $('.wm-base').title = `${BASEMAPS[basemap].label} is unreachable (no internet, or the key was refused), so the local basemap is shown`;
        renderCredit();
      };
      map.on('error', (e) => {
        // never swallow a style or layer error silently: a bad paint expression hides every marker
        const baseSrc = !!e.sourceId && !e.sourceId.startsWith('wm-') && e.sourceId !== 'land';   // CARTO's own sources
        if (!baseSrc) console.warn('World map:', e.error?.message || e.error || e);
        if (fellBack) return;
        if (!map.isStyleLoaded() && !e.sourceId) fallBack();
        else if (baseSrc) { if (++tileErrs >= 4) fallBack(); }
      });
      setTimeout(() => { if (map && !map.isStyleLoaded() && !destroyed) fallBack(); }, 8000);
      ctx.panelEl.__wm = { map };   // handle for debugging / screenshots
      map.on('movestart', (e) => { if (e.originalEvent) userMoved = true; });
      // DB-IP Lite (CC BY 4.0) places the points: its licence asks for this link wherever its results show
      map.addControl(new ml.AttributionControl({ compact: true, customAttribution: GEO_CREDIT }), 'bottom-right');
      makePopup();
      mapHooks.forEach((fn) => fn());
    }
    function fitWorld() {
      if (!map) return;
      const w = map.getContainer().clientWidth || 800;
      map.setMinZoom(Math.max(0.3, Math.log2(w / 512) - 0.02));   // never show repeated worlds side by side
      if (!userMoved) map.fitBounds(homeBounds, { padding: 4, duration: 0 });
    }
    let destroyed = false;

    function styleFor(id) { const s = BASEMAPS[id].style; return typeof s === 'function' ? s() : s; }

    function aggregate() {
      const by = new Map();
      for (const r of rows) {
        if (!layers[r[3]]) continue;
        const key = `${r[0]},${r[1]},${r[3]}`;
        let g = by.get(key);
        if (!g) { g = { lon: r[0], lat: r[1], kind: r[3], n: 0, sev: 0, top: r, ev: [], t: 0, country: r[6] }; by.set(key, g); }
        g.n++;
        if (r[2] > g.sev || (r[2] === g.sev && r[7] > g.top[7])) { g.sev = r[2]; g.top = r; }
        if (r[7] > g.t) g.t = r[7];
        if (g.ev.length < 6) g.ev.push(r);
      }
      groups = [...by.values()];
      return {
        type: 'FeatureCollection',
        features: groups.map((g, i) => ({
          type: 'Feature', id: i,
          geometry: { type: 'Point', coordinates: [g.lon, g.lat] },
          properties: {
            g: i, n: g.n, sev: g.sev, color: kindMeta(g.kind).color, ring: isRing(g.kind) ? 1 : 0,
            r: 0.55 + g.sev * 0.9 + Math.min(2.4, Math.log2(g.n + 1) * 0.42),
            hot: g.sev >= 0.8 ? 1 : 0, fresh: g.t > Date.now() / 1000 - 900 ? 1 : 0,
          },
        })),
      };
    }

    function countriesData() {
      if (!countriesFC) return null;
      const by = Object.fromEntries(countryStats.map((c) => [c.country, c]));
      const max = Math.max(1, ...countryStats.map((c) => c.n));
      for (const f of countriesFC.features) {
        const c = by[iso2(f.properties)];
        f.properties.n = c?.n || 0;
        f.properties.v = c ? Math.log(c.n + 1) / Math.log(max + 1) : 0;
      }
      return countriesFC;
    }

    // ---------------------------------------------------------------- layers
    const vis = (on) => (on ? 'visible' : 'none');
    function overlaysReady() { return !!(map && map.style && map.getSource('wm-points')); }

    function addOverlays() {
      const style = map.getStyle();
      if (!style) return;
      if (BASEMAPS[basemap].tone) BASEMAPS[basemap].tone(map);
      const firstLabel = style.layers.find((l) => l.type === 'symbol' || l.id === 'labels')?.id;
      const light = !!BASEMAPS[basemap].light;
      const empty = { type: 'FeatureCollection', features: [] };
      const pts = aggregate();

      map.addSource('wm-countries', { type: 'geojson', data: countriesData() || empty });
      map.addSource('wm-cables', { type: 'geojson', data: cablesFC || empty, tolerance: 0.6 });
      map.addSource('wm-landings', { type: 'geojson', data: landingsFC || empty });
      map.addSource('wm-points', { type: 'geojson', data: pts, tolerance: 0, buffer: 32 });
      map.addSource('wm-clusters', {
        type: 'geojson', data: pts, cluster: true, clusterRadius: 34, clusterMaxZoom: 5,
        clusterProperties: { total: ['+', ['get', 'n']], smax: ['max', ['get', 'sev']] },
      });
      map.addSource('wm-pulse', { type: 'geojson', data: empty });

      // country heat (under labels)
      map.addLayer({ id: 'wm-choro', type: 'fill', source: 'wm-countries', layout: { visibility: vis(layers.choropleth) },
        paint: { 'fill-color': ['interpolate', ['linear'], ['get', 'v'], 0, 'rgba(240,138,60,0)', 0.35, 'rgba(242,201,76,0.03)', 0.6, 'rgba(240,138,60,0.12)', 0.8, 'rgba(240,82,79,0.24)', 1, 'rgba(255,77,109,0.38)'] } }, firstLabel);
      map.addLayer({ id: 'wm-choro-line', type: 'line', source: 'wm-countries', layout: { visibility: vis(layers.choropleth) },
        filter: ['>', ['get', 'n'], 0], paint: { 'line-color': 'rgba(240,138,60,0.35)', 'line-width': 0.5 } }, firstLabel);
      map.addLayer({ id: 'wm-country-hi', type: 'line', source: 'wm-countries', filter: ['==', ['get', 'ADMIN'], ''],
        paint: { 'line-color': '#f2c94c', 'line-width': 1.2, 'line-opacity': 0.8 } }, firstLabel);

      // cables
      map.addLayer({ id: 'wm-cables-glow', type: 'line', source: 'wm-cables', layout: { visibility: vis(layers.cables), 'line-join': 'round', 'line-cap': 'round' },
        paint: { 'line-color': CABLE, 'line-opacity': ['interpolate', ['linear'], ['zoom'], 1, light ? 0.03 : 0.04, 5, 0.08], 'line-blur': 2, 'line-width': ['interpolate', ['linear'], ['zoom'], 1, 2.5, 5, 5, 9, 9] } }, firstLabel);
      map.addLayer({ id: 'wm-cables', type: 'line', source: 'wm-cables', layout: { visibility: vis(layers.cables), 'line-join': 'round', 'line-cap': 'round' },
        paint: { 'line-color': light ? '#4ea1b0' : CABLE, 'line-opacity': ['interpolate', ['linear'], ['zoom'], 1, 0.3, 3, 0.4, 5, 0.6, 7, 0.75],
          'line-width': ['interpolate', ['linear'], ['zoom'], 1, 0.75, 4, 1.15, 8, 2] } }, firstLabel);
      map.addLayer({ id: 'wm-cables-hi', type: 'line', source: 'wm-cables', filter: ['==', ['get', 'id'], ''],
        paint: { 'line-color': '#e2c6c1', 'line-width': ['interpolate', ['linear'], ['zoom'], 1, 1.6, 8, 3.5], 'line-opacity': 0.95 } }, firstLabel);
      map.addLayer({ id: 'wm-landings', type: 'circle', source: 'wm-landings', layout: { visibility: vis(layers.landings) },
        paint: { 'circle-radius': ['interpolate', ['linear'], ['zoom'], 1, 1.3, 5, 2.6, 9, 4], 'circle-color': '#0c0d0f',
          'circle-stroke-color': '#b4957b', 'circle-stroke-width': ['interpolate', ['linear'], ['zoom'], 1, 0.7, 6, 1.3], 'circle-opacity': 0.9 } });

      // density heat
      map.addLayer({ id: 'wm-heat', type: 'heatmap', source: 'wm-points', maxzoom: 9,
        paint: {
          'heatmap-weight': ['*', ['+', 0.25, ['get', 'sev']], ['min', 1.5, ['/', ['ln', ['+', 1, ['get', 'n']]], 2.4]]],
          'heatmap-intensity': ['interpolate', ['linear'], ['zoom'], 0, 0.55, 5, 1.6, 8, 2.6],
          'heatmap-radius': ['interpolate', ['linear'], ['zoom'], 0, 9, 3, 18, 6, 30, 9, 44],
          'heatmap-color': ['interpolate', ['linear'], ['heatmap-density'], 0, 'rgba(0,0,0,0)', 0.12, 'rgba(78,161,176,0.18)', 0.3, 'rgba(180,149,123,0.38)', 0.55, 'rgba(242,201,76,0.6)', 0.78, 'rgba(240,138,60,0.78)', 1, 'rgba(240,82,79,0.92)'],
          'heatmap-opacity': 0.8,
        } });

      // clusters
      const clusterColor = ['step', ['get', 'smax'], '#4ea1b0', 0.45, '#f2c94c', 0.65, '#f08a3c', 0.85, '#f0524f'];
      const clusterR = ['interpolate', ['linear'], ['ln', ['get', 'total']], 0, 7, 3, 11, 6, 18, 9, 26];
      map.addLayer({ id: 'wm-cl-glow', type: 'circle', source: 'wm-clusters', filter: ['has', 'point_count'],
        paint: { 'circle-color': clusterColor, 'circle-radius': ['*', clusterR, 1.8], 'circle-blur': 1, 'circle-opacity': 0.32 } });
      map.addLayer({ id: 'wm-cl', type: 'circle', source: 'wm-clusters', filter: ['has', 'point_count'],
        paint: { 'circle-color': 'rgba(12,13,15,0.82)', 'circle-radius': clusterR, 'circle-stroke-color': clusterColor, 'circle-stroke-width': 1.4 } });
      map.addLayer({ id: 'wm-cl-n', type: 'symbol', source: 'wm-clusters', filter: ['has', 'point_count'],
        layout: { 'text-field': ['case', ['>=', ['get', 'total'], 1000], ['concat', ['to-string', ['round', ['/', ['get', 'total'], 100]]], '00+'], ['to-string', ['get', 'total']]],
          'text-font': FONT, 'text-size': 10, 'text-allow-overlap': true },
        paint: { 'text-color': '#e6e9ed' } });
      map.addLayer({ id: 'wm-cl-pts', type: 'circle', source: 'wm-clusters', filter: ['!', ['has', 'point_count']],
        paint: { 'circle-color': ['case', ['==', ['get', 'ring'], 1], RING_FILL, ['get', 'color']], 'circle-radius': ['interpolate', ['linear'], ['zoom'], 1, ['*', ['get', 'r'], 1.7], 6, ['*', ['get', 'r'], 3.2]],
          'circle-opacity': 0.9, 'circle-stroke-color': ['case', ['==', ['get', 'ring'], 1], ['get', 'color'], 'rgba(0,0,0,0.6)'], 'circle-stroke-width': ['case', ['==', ['get', 'ring'], 1], 1.8, 0.6] } });

      // points: soft halo + core + hot centre
      const Rf = (f, add = 0) => ['interpolate', ['linear'], ['zoom'], ...[[0.6, 1.25], [2, 1.9], [5, 3], [9, 4.6]].flatMap(([z, k]) => [z, ['+', add, ['*', ['get', 'r'], k * f]]])];
      // markers for ring kinds: at least 5 px across at world zoom so the hole reads
      const RR = ['interpolate', ['linear'], ['zoom'], ...[[0.6, 1.25], [2, 1.9], [5, 3], [9, 4.6]].flatMap(([z, k]) => [z, ['case', ['==', ['get', 'ring'], 1], ['max', 5, ['*', ['get', 'r'], k]], ['*', ['get', 'r'], k]]])];
      map.addLayer({ id: 'wm-pts-halo', type: 'circle', source: 'wm-points',
        layout: { 'circle-sort-key': ['get', 'sev'] },
        paint: { 'circle-color': ['get', 'color'], 'circle-radius': Rf(2.7), 'circle-blur': 1,
          // ring kinds get no filled halo, so the ring stays a ring
          'circle-opacity': ['case', ['==', ['get', 'ring'], 1], 0, ['interpolate', ['linear'], ['get', 'sev'], 0, 0.1, 1, light ? 0.3 : 0.42]] } });
      map.addLayer({ id: 'wm-pts', type: 'circle', source: 'wm-points',
        layout: { 'circle-sort-key': ['get', 'sev'] },
        paint: { 'circle-color': ['case', ['==', ['get', 'ring'], 1], RING_FILL, ['get', 'color']], 'circle-radius': RR, 'circle-opacity': 0.92,
          // ring kinds (the second member of a hue pair, core/util.js) are drawn as a ring: hue = family, mark = member
          'circle-stroke-color': ['case', ['==', ['get', 'ring'], 1], ['get', 'color'], light ? 'rgba(255,255,255,0.8)' : 'rgba(0,0,0,0.55)'],
          // zoom must be the top-level interpolate (MapLibre rejects it nested in a case): the case sits in each stop
          'circle-stroke-width': ['interpolate', ['linear'], ['zoom'], 1, ['case', ['==', ['get', 'ring'], 1], 1.6, 0.3], 6, ['case', ['==', ['get', 'ring'], 1], 2.2, 0.8]] } });
      map.addLayer({ id: 'wm-pts-hot', type: 'circle', source: 'wm-points', filter: ['==', ['get', 'hot'], 1],
        paint: { 'circle-color': '#fff4ec', 'circle-radius': Rf(0.36), 'circle-opacity': 0.85 } });
      map.addLayer({ id: 'wm-pts-sel', type: 'circle', source: 'wm-points', filter: ['==', ['get', 'g'], -1],
        paint: { 'circle-color': 'transparent', 'circle-radius': Rf(1, 5), 'circle-stroke-color': '#ffffff', 'circle-stroke-width': 1.3 } });

      // live rings
      map.addLayer({ id: 'wm-pulse', type: 'circle', source: 'wm-pulse',
        paint: { 'circle-radius': ['get', 'r'], 'circle-color': ['get', 'c'], 'circle-opacity': ['*', ['get', 'o'], 0.12],
          'circle-stroke-color': ['get', 'c'], 'circle-stroke-width': ['get', 'w'], 'circle-stroke-opacity': ['get', 'o'] } });
      map.addLayer({ id: 'wm-pulse-dot', type: 'circle', source: 'wm-pulse',
        paint: { 'circle-radius': 2.2, 'circle-color': ['get', 'c'], 'circle-opacity': ['min', 1, ['*', ['get', 'o'], 1.6]] } });
      // country names float above the data, like the reference
      for (const l of map.getStyle().layers) if (l.id.startsWith('place_country')) map.moveLayer(l.id);
      applyMode();
      updateBadge();
    }

    function applyMode() {
      if (!overlaysReady()) return;
      const lv = (id, on) => map.setLayoutProperty(id, 'visibility', vis(on));
      ['wm-cl-glow', 'wm-cl', 'wm-cl-n', 'wm-cl-pts'].forEach((id) => lv(id, mode === 'cluster'));
      ['wm-pts-halo', 'wm-pts', 'wm-pts-hot', 'wm-pts-sel'].forEach((id) => lv(id, mode !== 'cluster'));
      lv('wm-heat', mode !== 'cluster');
      if (mode === 'heat') {
        map.setPaintProperty('wm-heat', 'heatmap-opacity', ['interpolate', ['linear'], ['zoom'], 0, 0.95, 6, 0.85, 9, 0.2]);
        ['wm-pts-halo', 'wm-pts', 'wm-pts-hot'].forEach((id) => map.setLayerZoomRange(id, 4.5, 24));
      } else {
        // dots: faint density glow under the points at world zoom, fading out as sites separate
        map.setPaintProperty('wm-heat', 'heatmap-opacity', ['interpolate', ['linear'], ['zoom'], 0, 0.32, 3, 0.18, 4.5, 0]);
        ['wm-pts-halo', 'wm-pts', 'wm-pts-hot'].forEach((id) => map.setLayerZoomRange(id, 0, 24));
      }
    }

    function pushPoints() {
      renderQuick();
      if (!overlaysReady()) { aggregate(); updateBadge(); return; }
      const fc = aggregate();
      map.getSource('wm-points').setData(fc);
      map.getSource('wm-clusters').setData(fc);
      updateBadge();
    }
    const pushPointsSoon = debounce(pushPoints, 1200);

    onMap(() => map.on('style.load', () => { addOverlays(); }));

    // ---------------------------------------------------------------- loading
    async function loadRefs() {
      try {
        [cablesFC, landingsFC, countriesFC] = await Promise.all([api.cables(), api.landings(), api.countries()]);
        jumpList = countriesFC.features.map((f) => {
          const p = f.properties; const b = bboxOf(f.geometry);
          return { name: p.NAME || p.ADMIN, cc: iso2(p), b, c: [p.LABEL_X, p.LABEL_Y] };
        }).filter((c) => c.name).sort((a, b) => a.name.localeCompare(b.name));
        if (overlaysReady()) {
          map.getSource('wm-cables').setData(cablesFC);
          map.getSource('wm-landings').setData(landingsFC);
          map.getSource('wm-countries').setData(countriesData());
        }
        renderLayerMenu(); renderCredit();
      } catch (e) { console.warn('world-map refs', e); }
    }

    let loadSeq = 0;
    async function load() {
      const seq = ++loadSeq;
      const params = { since_hours: store.sinceHours(), q: store.get().opsQ || undefined };
      $('.wm-loading').hidden = false;
      try {
        const [pts, cs] = await Promise.all([api.points({ ...params, limit: 50000 }), api.byCountry(params).catch(() => [])]);
        if (seq !== loadSeq) return;
        rows = pts.rows; ids = new Set(rows.map((r) => r[4]));
        countryStats = cs;
        recount();
        pushPoints();
        if (overlaysReady() && countriesFC) map.getSource('wm-countries').setData(countriesData());
        lastLoad = new Date();
        ctx.setUpdated(lastLoad);
        renderLayerMenu(); renderJump();
      } catch (e) {
        if (seq === loadSeq) toast(`World map: ${e.message}`, true);
      } finally {
        if (seq === loadSeq) $('.wm-loading').hidden = true;
      }
    }

    function recount() {
      counts = {};
      for (const r of rows) counts[r[3]] = (counts[r[3]] || 0) + 1;
    }

    function updateBadge() {
      if (!map) return;
      const b = map.getBounds();
      const full = b.getEast() - b.getWest() >= 360;
      let n = 0, sites = 0;
      const per = {};
      const w = b.getWest(), e = b.getEast(), s = b.getSouth(), nn = b.getNorth();
      for (const g of groups) {
        if (g.lat < s || g.lat > nn) continue;
        if (!full) {
          let x = g.lon;
          while (x < w) x += 360;
          if (x > e) continue;
        }
        n += g.n; sites++; per[g.kind] = (per[g.kind] || 0) + g.n;
      }
      renderLegend(per);
      ctx.setBadge(fmt(n));
      const rate = liveCount ? ` · <b class="wm-g">+${fmt(liveCount)}</b> live` : '';
      $('.wm-stat').innerHTML = `<span>${fmt(n)}</span> events · <span>${fmt(sites)}</span> sites in view${rate}`;
    }

    // ---------------------------------------------------------------- toolbar
    const enabledCount = () => Object.keys(layers).filter((k) => layers[k] && (KINDS[k] || REFS[k])).length;
    function persist() { ctx.state.set({ layers, basemap, mode, pulses: pulsesOn }); }

    function renderLayerBtn() {
      const n = enabledCount();
      const b = $('.wm-layers'); b.classList.toggle('on', n > 0); b.querySelector('.wm-n').textContent = n;
    }

    function renderLayerMenu() {
      renderLayerBtn();
      const menu = $('.wm-layer-menu');
      const sw = (on, color, kind = 'dot') => `<span class="wm-sw wm-sw-${kind}${on ? ' on' : ''}" style="--c:${color}"></span>`;
      const kindsBy = {};
      for (const [k, m] of Object.entries(KINDS)) (kindsBy[m.group] ||= []).push(k);
      let html = '';
      for (const g of GROUPS) {
        const ks = kindsBy[g] || [];
        if (!ks.length) continue;
        const tot = ks.reduce((a, k) => a + (counts[k] || 0), 0);
        const allOn = ks.every((k) => layers[k]);
        html += `<div class="wm-mh"><span>${esc(g)}</span><span class="wm-mh-n">${compact(tot)}</span><button class="wm-mh-t" data-group="${esc(g)}">${allOn ? 'Hide' : 'Show'}</button></div>`;
        for (const k of ks) {
          const m = KINDS[k]; const c = counts[k] || 0;
          html += `<button class="wm-mi${c ? '' : ' zero'}${isRing(k) ? ' ring' : ''}" data-layer="${k}">${sw(layers[k], m.color)}<span class="wm-mi-l">${esc(m.label)}</span><span class="wm-mi-n">${c ? fmt(c) : '—'}</span></button>`;
        }
      }
      const refN = { cables: cablesFC?.features.length, landings: landingsFC?.features.length, choropleth: countryStats.length };
      // a new offline lake has no reference geometry yet: the server answers an empty layer flagged "missing"
      const refMissing = { cables: !!cablesFC?.missing, landings: !!landingsFC?.missing, choropleth: !!countriesFC?.missing };
      html += '<div class="wm-mh"><span>Reference</span></div>';
      for (const [k, r] of Object.entries(REFS)) {
        const optin = refMissing[k] && (k === 'cables' || k === 'landings');   // TeleGeography's data: on first use
        const tip = optin ? 'Turning this on downloads the cable map from TeleGeography (submarinecablemap.com) once'
          : 'Not downloaded yet: this reference map arrives with the first online run';
        html += `<button class="wm-mi" data-layer="${k}">${sw(layers[k], r.color, r.line ? 'line' : r.fill ? 'fill' : 'ring')}<span class="wm-mi-l">${r.label}</span><span class="wm-mi-n"${refMissing[k] ? ` title="${tip}"` : ''}>${fetchingCables && optin ? 'loading…' : optin ? 'download' : refMissing[k] ? 'not yet' : refN[k] != null ? fmt(refN[k]) : '…'}</span></button>`;
      }
      html += `<div class="wm-mh"><span>Point display</span></div><div class="wm-seg">${MODES.map(([m, l]) => `<button data-mode="${m}" class="${m === mode ? 'on' : ''}">${l}</button>`).join('')}</div>`;
      html += `<button class="wm-mi" data-pulses>${sw(pulsesOn, PULSE, 'ring')}<span class="wm-mi-l">Live BGP pulses</span><span class="wm-mi-n">${pulsesOn ? 'ON' : 'OFF'}</span></button>`;
      menu.innerHTML = html;
    }

    let legendOpen = saved.legend !== false;
    function renderLegend(per) {
      const ks = Object.keys(per).sort((a, b) => per[b] - per[a]);
      const leg = $('.wm-legend');
      leg.hidden = !ks.length;
      leg.classList.toggle('open', legendOpen);
      leg.querySelector('.wm-leg-n').textContent = ks.length;
      leg.querySelector('.wm-leg-b').innerHTML = ks.map((k) => { const m = kindMeta(k);
        return `<div class="wm-leg-r${isRing(k) ? ' ring' : ''}"><i style="--c:${m.color}"></i><span>${esc(m.label)}</span><em>${fmt(per[k])}</em></div>`; }).join('') +
        (layers.cables ? `<div class="wm-leg-r wm-leg-ref"><b style="--c:${CABLE}"></b><span>Undersea cable</span><em></em></div>` : '') +
        (pulsesOn ? `<div class="wm-leg-r wm-leg-ref"><u style="--c:${PULSE}"></u><span>Live BGP pulse</span><em></em></div>` : '');
    }
    $('.wm-leg-h').addEventListener('click', () => { legendOpen = !legendOpen; $('.wm-legend').classList.toggle('open', legendOpen); ctx.state.set({ legend: legendOpen }); });
    const qtip = $('.wm-qtip');
    $('.wm-quick').addEventListener('mouseover', (e) => {
      const b = e.target.closest('.wm-q'); if (!b) return;
      const k = b.dataset.layer; const m = KINDS[k];
      qtip.innerHTML = `${kindSwatch(k)}${esc(m.label)}<span>${fmt(counts[k] || 0)}</span>${layers[k] ? '' : '<em>hidden</em>'}`;
      qtip.hidden = false;
      const bar = body.querySelector('.wm-bar').getBoundingClientRect(); const r = b.getBoundingClientRect();
      qtip.style.left = `${Math.max(4, r.left - bar.left + r.width / 2 - qtip.offsetWidth / 2)}px`;
    });
    $('.wm-quick').addEventListener('mouseleave', () => { qtip.hidden = true; });

    function renderQuick() {
      const present = Object.keys(KINDS).filter((k) => counts[k]);
      $('.wm-quick').innerHTML = present.map((k) => {
        const m = KINDS[k];
        return `<button class="wm-q${layers[k] ? ' on' : ''}${isRing(k) ? ' ring' : ''}" data-layer="${k}" style="--c:${m.color}" aria-label="${esc(m.label)} · ${fmt(counts[k])}"><i></i></button>`;
      }).join('');
    }

    function renderBase() {
      $('.wm-base .wm-lbl').textContent = BASEMAPS[basemap].label;
      const why = (b) => (b.offline ? '' : srvOffline ? ' disabled title="Not loaded in offline mode"'
        : !cartoKey ? ' disabled title="Needs your own CARTO key: set CARTO_API_KEY in .env and restart Night Desk"' : '');
      $('.wm-base-menu').innerHTML = `<div class="wm-mh"><span>Basemap</span></div>${Object.entries(BASEMAPS).map(([id, b]) =>
        `<button class="wm-mi${id === basemap ? ' cur' : ''}" data-base="${id}"${why(b)}><span class="wm-bsw" style="background:${b.swatch}"></span><span class="wm-mi-l">${b.label}</span>${id === basemap ? '<span class="wm-mi-n wm-g">●</span>' : !b.offline && !srvOffline && !cartoKey ? '<span class="wm-mi-n">needs key</span>' : ''}</button>`).join('')}`;
    }

    // The visible credit line: CARTO's while one of its basemaps is shown, TeleGeography's while cables are drawn.
    function renderCredit() {
      const el = $('.wm-credit');
      const cartoOn = !!BASEMAPS[basemap]?.carto && $('.wm-base .wm-lbl').textContent === BASEMAPS[basemap].label;
      const cablesOn = (layers.cables && cablesFC?.features?.length) || (layers.landings && landingsFC?.features?.length);
      const parts = [cartoOn ? CARTO_CREDIT : '', cablesOn ? CABLE_CREDIT : ''].filter(Boolean);
      el.innerHTML = parts.join('<br>');
      el.hidden = !parts.length;
    }

    function renderJump(q = $('.wm-jump-in input').value.trim().toLowerCase()) {
      const cnt = Object.fromEntries(countryStats.map((c) => [c.country, c.n]));
      let list = jumpList;
      if (q) list = list.filter((c) => c.name.toLowerCase().includes(q) || (c.cc || '').toLowerCase() === q);
      else list = [...list].sort((a, b) => (cnt[b.cc] || 0) - (cnt[a.cc] || 0));
      const ll = q.match(/^\s*(-?\d+(?:\.\d+)?)\s*[, ]\s*(-?\d+(?:\.\d+)?)\s*$/);
      $('.wm-jump-list').innerHTML = (ll ? `<button class="wm-mi" data-ll="${ll[1]},${ll[2]}"><span class="wm-mi-l">Go to ${ll[1]}, ${ll[2]}</span>${ICON.arrow}</button>` : '') +
        list.slice(0, 60).map((c) => `<button class="wm-mi" data-cc="${esc(c.cc || '')}" data-name="${esc(c.name)}"><span class="wm-flag">${flag(c.cc)}</span><span class="wm-mi-l">${esc(c.name)}</span><span class="wm-mi-n">${cnt[c.cc] ? fmt(cnt[c.cc]) : ''}</span></button>`).join('') ||
        emptyState({ why: 'No place matches. Try a country name, or coordinates like 48.8, 2.3.', size: 'inline' });
    }

    function jumpTo(c) {
      closeMenus();
      if (!map) return;
      const [x0, y0, x1, y1] = c.b;
      if (x1 - x0 > 200) map.flyTo({ center: c.c, zoom: 2.4, speed: 1.6 });
      else map.fitBounds([[x0, y0], [x1, y1]], { padding: 40, maxZoom: 6, speed: 1.6 });
      const f = countriesFC.features.find((ff) => (ff.properties.NAME || ff.properties.ADMIN) === c.name);
      if (f && overlaysReady()) {
        map.setFilter('wm-country-hi', ['==', ['get', 'ADMIN'], f.properties.ADMIN]);
        clearTimeout(jumpTo.t); jumpTo.t = setTimeout(() => overlaysReady() && map.setFilter('wm-country-hi', ['==', ['get', 'ADMIN'], '']), 6000);
      }
    }

    function closeMenus() { body.querySelectorAll('.wm-dd.open').forEach((d) => d.classList.remove('open')); }

    // Cables are opt-in: the first time the layer is turned on with no data here, the server downloads it once.
    async function fetchCables() {
      if (fetchingCables) return;
      if (srvOffline) { toast('Offline mode: the cable map is not downloaded'); return; }
      fetchingCables = true; renderLayerMenu();
      toast('Downloading the cable map from TeleGeography…');
      try {
        await api.fetchCables();
        await loadRefs();
      } catch (e) {
        toast(e?.message || 'The cable map could not be downloaded');
      } finally { fetchingCables = false; renderLayerMenu(); renderCredit(); }
    }

    function setLayer(k, on) {
      if (on && (k === 'cables' || k === 'landings') && (k === 'cables' ? cablesFC : landingsFC)?.missing) fetchCables();
      layers[k] = on;
      if (KINDS[k]) pushPoints();
      else if (overlaysReady()) {
        const ids2 = { cables: ['wm-cables', 'wm-cables-glow'], landings: ['wm-landings'], choropleth: ['wm-choro', 'wm-choro-line'] }[k];
        ids2.forEach((id) => map.setLayoutProperty(id, 'visibility', vis(on)));
      }
      persist(); renderLayerMenu(); renderQuick(); updateBadge(); renderCredit();
    }

    body.querySelector('.wm-bar').addEventListener('click', (e) => {
      const ddBtn = e.target.closest('[data-dd]');
      if (ddBtn) {
        e.stopPropagation();
        const dd = ddBtn.parentElement; const open = !dd.classList.contains('open');
        closeMenus();
        if (open) {
          dd.classList.add('open');
          if (ddBtn.dataset.dd === 'jump') { renderJump(); setTimeout(() => dd.querySelector('input').focus(), 0); }
        }
        return;
      }
      if (e.target.closest('.wm-menu')) e.stopPropagation();
      const t = e.target.closest('button');
      if (!t) return;
      if (t.dataset.layer) setLayer(t.dataset.layer, !layers[t.dataset.layer]);
      else if (t.dataset.group) {
        const ks = Object.keys(KINDS).filter((k) => KINDS[k].group === t.dataset.group);
        const on = !ks.every((k) => layers[k]);
        ks.forEach((k) => (layers[k] = on));
        pushPoints(); persist(); renderLayerMenu();
      } else if (t.dataset.mode) { mode = t.dataset.mode; applyMode(); persist(); renderLayerMenu(); }
      else if (t.hasAttribute('data-pulses') || t.classList.contains('wm-live')) { pulsesOn = !pulsesOn; persist(); renderLayerMenu(); renderLive(); updateBadge(); }
      else if (t.dataset.base) {
        if (srvOffline && !BASEMAPS[t.dataset.base].offline) { toast('Offline mode: online basemaps are not loaded'); return; }
        if (!usable(t.dataset.base)) { toast('This basemap needs your own CARTO key (CARTO_API_KEY in .env)'); return; }
        if (t.dataset.base !== basemap) { basemap = t.dataset.base; persist(); renderBase(); renderCredit(); popup?.remove(); map?.setStyle(styleFor(basemap), { diff: false }); }
        closeMenus();
      } else if (t.dataset.ll) {
        const [la, lo] = t.dataset.ll.split(',').map(Number);
        closeMenus(); map?.flyTo({ center: [lo, la], zoom: Math.max(map.getZoom(), 6) });
      } else if (t.dataset.name) {
        const c = jumpList.find((x) => x.name === t.dataset.name); if (c) jumpTo(c);
      }
    });
    const jumpInput = $('.wm-jump-in input');
    jumpInput.addEventListener('input', () => renderJump());
    jumpInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { const b = $('.wm-jump-list button'); b?.click(); }
      if (e.key === 'Escape') closeMenus();
    });
    const docClick = () => closeMenus();
    document.addEventListener('click', docClick);

    function renderLive() { $('.wm-live').classList.toggle('on', pulsesOn); $('.wm-live').title = `Live BGP pulses: ${pulsesOn ? 'on' : 'off'}`; }

    // ---------------------------------------------------------------- zoom + coords
    stage.querySelector('.wm-zoom').addEventListener('click', (e) => {
      const z = e.target.closest('button')?.dataset.z;
      if (!map) return;
      if (z === 'in') map.zoomIn(); else if (z === 'out') map.zoomOut(); else if (z === 'home') { userMoved = false; map.fitBounds(homeBounds, { padding: 4 }); }
    });
    function showCoords(ll) {
      const { lng, lat } = ll.wrap ? ll.wrap() : ll;
      $('.wm-dec').textContent = `${lat.toFixed(5)}, ${lng.toFixed(5)}`;
      $('.wm-dms').textContent = `${dms(lat, 'N', 'S')} ${dms(lng, 'E', 'W')}`;
    }
    onMap(() => map.on('mousemove', (e) => showCoords(e.lngLat)));
    onMap(() => map.on('load', () => { showCoords(map.getCenter()); fitWorld(); updateBadge(); }));
    const onMoveEnd = debounce(() => { updateBadge(); if (tip.hidden) showCoords(map.getCenter()); const c = map.getCenter(); ctx.state.set({ view: { c: [+c.lng.toFixed(3), +c.lat.toFixed(3)], z: +map.getZoom().toFixed(2) } }); }, 200);
    onMap(() => map.on('moveend', onMoveEnd));

    // ---------------------------------------------------------------- hover + popup
    let popup = null;   // made with the map (makePopup), once MapLibre is there
    function makePopup() {
      popup = new ml.Popup({ closeButton: true, closeOnClick: true, maxWidth: '300px', className: 'wm-popup', offset: 12 });
      popup.on('close', () => overlaysReady() && map.setFilter('wm-pts-sel', ['==', ['get', 'g'], -1]));
      popup.on('open', () => {
        popup.getElement()?.addEventListener('click', (ev) => {
          const b = ev.target.closest('[data-open]'); if (b) ctx.openEvent(b.dataset.open);
        });
      });
    }
    const hoverable = ['wm-pts', 'wm-cl-pts', 'wm-cl', 'wm-landings', 'wm-cables', 'wm-choro'];

    function showTip(e, html) {
      tip.innerHTML = html; tip.hidden = false;
      const r = stage.getBoundingClientRect(); const tw = tip.offsetWidth;
      let x = e.point.x + 14; if (x + tw > r.width - 8) x = e.point.x - tw - 14;
      tip.style.transform = `translate(${Math.max(4, x)}px, ${Math.max(4, e.point.y - 12)}px)`;
    }
    onMap(() => map.on('mousemove', (e) => {
      if (!overlaysReady()) return;
      const lys = hoverable.filter((id) => map.getLayer(id) && map.getLayoutProperty(id, 'visibility') !== 'none');
      const f = map.queryRenderedFeatures([[e.point.x - 3, e.point.y - 3], [e.point.x + 3, e.point.y + 3]], { layers: lys })[0];
      map.getCanvas().style.cursor = f && f.layer.id !== 'wm-choro' && f.layer.id !== 'wm-cables' ? 'pointer' : '';
      if (!f) {
        tip.hidden = true;
        map.setFilter('wm-cables-hi', ['==', ['get', 'id'], '']);
        return;
      }
      const L = f.layer.id;
      map.setFilter('wm-cables-hi', ['==', ['get', 'id'], L === 'wm-cables' ? f.properties.id : '']);
      if (L === 'wm-pts' || L === 'wm-cl-pts') {
        const g = groups[f.properties.g]; if (!g) return;
        const m = kindMeta(g.kind);
        showTip(e, `<div class="wm-tip-k" style="color:${m.color}">${esc(m.label)}${g.n > 1 ? ` <span>· ${fmt(g.n)} events</span>` : ''}</div><div class="wm-tip-t">${esc(g.top[5])}</div>`);
      } else if (L === 'wm-cl') {
        showTip(e, `<div class="wm-tip-k">Cluster</div><div class="wm-tip-t">${fmt(f.properties.total)} events · click to expand</div>`);
      } else if (L === 'wm-landings') {
        showTip(e, `<div class="wm-tip-k" style="color:${CABLE}">Landing point</div><div class="wm-tip-t">${esc(f.properties.name)}</div>`);
      } else if (L === 'wm-cables') {
        showTip(e, `<div class="wm-tip-k" style="color:${CABLE}">Submarine cable</div><div class="wm-tip-t">${esc(f.properties.name)}</div>`);
      } else if (L === 'wm-choro') {
        const cc = iso2(f.properties); const st = countryStats.find((c) => c.country === cc);
        const top = st ? Object.entries(st.kinds || {}).sort((a, b) => b[1] - a[1]).slice(0, 3) : [];
        showTip(e, `<div class="wm-tip-k">${flag(cc)} ${esc(f.properties.NAME)}</div><div class="wm-tip-t">${st ? `${fmt(st.n)} events · sev ${Math.round(st.sev * 100)}` : 'No events'}</div>${top.map(([k, n]) => `<div class="wm-tip-r">${kindSwatch(k)}${esc(kindMeta(k).label)}<span>${fmt(n)}</span></div>`).join('')}`);
      }
    }));
    onMap(() => map.getCanvas().addEventListener('mouseleave', () => { tip.hidden = true; showCoords(map.getCenter()); }));

    function card(g) {
      const m = kindMeta(g.kind); const r = g.top;
      const sevPct = Math.round(g.sev * 100);
      const others = g.ev.filter((x) => x[4] !== r[4]).slice(0, 3);
      return `<div class="wm-card">
        <div class="wm-card-k" style="color:${m.color}">${esc(m.label)}</div>
        <div class="wm-card-t">${esc(r[5])}</div>
        <dl class="wm-kv">
          <dt>Severity</dt><dd><span class="wm-sev"><i style="width:${sevPct}%;background:${m.color}"></i></span>${sevPct}</dd>
          ${r[6] ? `<dt>Country</dt><dd>${flag(r[6])} ${esc(r[6])}</dd>` : ''}
          <dt>Seen</dt><dd>${ago(r[7] * 1000)} · ${Tm.when(r[7] * 1000)}</dd>
          <dt>Coords</dt><dd>${g.lat.toFixed(3)}, ${g.lon.toFixed(3)}</dd>
          ${g.n > 1 ? `<dt>At site</dt><dd>${fmt(g.n)} ${esc(m.label.toLowerCase())} events</dd>` : ''}
        </dl>
        ${others.length ? `<div class="wm-card-more">${others.map((x) => `<button data-open="${esc(x[4])}"><span>${esc(x[5])}</span><em>${ago(x[7] * 1000)}</em></button>`).join('')}</div>` : ''}
        <button class="wm-card-link" data-open="${esc(r[4])}">Details ${ICON.arrow}</button>
      </div>`;
    }

    onMap(() => map.on('click', (e) => {
      if (!overlaysReady()) return;
      const lys = ['wm-pts', 'wm-cl-pts', 'wm-cl'].filter((id) => map.getLayoutProperty(id, 'visibility') !== 'none');
      const f = map.queryRenderedFeatures([[e.point.x - 4, e.point.y - 4], [e.point.x + 4, e.point.y + 4]], { layers: lys })
        .sort((a, b) => (b.properties.sev || 0) - (a.properties.sev || 0))[0];
      if (!f) return;
      if (f.layer.id === 'wm-cl') {
        map.getSource('wm-clusters').getClusterExpansionZoom(f.properties.cluster_id).then((z) => map.easeTo({ center: f.geometry.coordinates, zoom: z + 0.2 }));
        return;
      }
      const g = groups[f.properties.g]; if (!g) return;
      tip.hidden = true;
      map.setFilter('wm-pts-sel', ['==', ['get', 'g'], f.properties.g]);
      setTimeout(() => popup.setLngLat([g.lon, g.lat]).setHTML(card(g)).addTo(map), 0);
    }));

    // ---------------------------------------------------------------- live
    let pulses = [];
    let raf = 0;
    let liveCount = 0;
    function addPulse(lon, lat, color, big = false) {
      if (document.hidden || !body.isConnected) return;
      pulses.push({ lon, lat, c: color, t0: performance.now(), big });
      if (pulses.length > 60) pulses.splice(0, pulses.length - 60);
      if (!raf) raf = requestAnimationFrame(animate);
    }
    function animate(now) {
      raf = 0;
      if (!overlaysReady()) { pulses = []; return; }
      pulses = pulses.filter((p) => now - p.t0 < (p.big ? 2600 : 1700));
      const feats = pulses.map((p) => {
        const life = p.big ? 2600 : 1700;
        const k = (now - p.t0) / life; const ease = 1 - (1 - k) ** 3;
        return { type: 'Feature', geometry: { type: 'Point', coordinates: [p.lon, p.lat] },
          properties: { r: (p.big ? 5 : 2) + ease * (p.big ? 34 : 20), o: (1 - k) * 0.95, c: p.c, w: p.big ? 1.8 : 1.2 } };
      });
      map.getSource('wm-pulse').setData({ type: 'FeatureCollection', features: feats });
      if (pulses.length) raf = requestAnimationFrame(animate);
    }
    const offPulse = live.on('bgp_pulse', (d) => { if (pulsesOn && d?.lat != null) addPulse(d.lon, d.lat, PULSE); });
    const offEvents = live.on('events', (d) => {
      const q = (store.get().opsQ || '').toLowerCase();
      let added = 0;
      for (const e of d?.latest || []) {
        if (e.lat == null || e.lon == null || ids.has(e.id)) continue;
        if (q && !`${e.title} ${e.ip || ''} ${e.asn || ''} ${e.country || ''}`.toLowerCase().includes(q)) continue;
        const t = Math.floor(new Date(e.ts).getTime() / 1000);
        const hrs = store.sinceHours();
        if (hrs && t < Date.now() / 1000 - hrs * 3600) continue;
        const r = [+e.lon.toFixed(3), +e.lat.toFixed(3), e.severity ?? 0.4, e.kind, e.id, e.title, e.country, t];
        rows.unshift(r); ids.add(e.id); counts[e.kind] = (counts[e.kind] || 0) + 1; added++;
        if (layers[e.kind] && added <= 12) addPulse(r[0], r[1], kindMeta(e.kind).color, true);
      }
      if (added) {
        liveCount += added;
        pushPointsSoon();
        ctx.setUpdated(new Date());
        if (body.querySelector('.wm-dd.open .wm-layer-menu')) renderLayerMenu();
      }
    });
    const reloadTimer = setInterval(() => { if (!document.hidden) { liveCount = 0; load(); } }, 5 * 60 * 1000);

    // ---------------------------------------------------------------- go
    // The time window is the global range in the sub-bar (refresh() reloads on a change); no second control here.
    renderBase(); renderLayerMenu(); renderLive();
    const ro = new ResizeObserver(() => { if (!map) createMap(); });
    ro.observe($('.wm-map'));
    createMap();
    loadRefs();
    load();

    return {
      resize() { if (!map) { createMap(); return; } map.resize(); fitWorld(); updateBadge(); },
      refresh() { liveCount = 0; load(); },
      destroy() {
        offPulse(); offEvents(); clearInterval(reloadTimer);
        cancelAnimationFrame(raf); document.removeEventListener('click', docClick);
        destroyed = true; ro.disconnect(); popup?.remove(); map?.remove();
      },
    };
  },
});

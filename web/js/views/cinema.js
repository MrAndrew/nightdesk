// Cyber Cinema: a full-page, autopiloted 3D globe of real geolocated events.
// Globe (globe.gl) + real-time solar terminator, undersea cables, severity dots, live BGP rings,
// a focused-event card rail with a per-frame leader line, a timeline scrubber and a live ticker.
import { registerView } from '../core/panels.js';
import * as Tm from '../core/time.js';
import { kindMeta, kindSwatch, sevColor, ago, esc, h, fmt, compact, flag, debounce, shortcutBlocked, safeUrl, reducedMotion } from '../core/util.js';
import { hashRange, syncHash as rangeSyncHash, phrase, snap, LIVE } from '../core/range.js';
import { viewHeader, headerRange, errorState } from '../core/view.js';
import { need } from '../core/libs.js';
import { isPhone, onPhoneChange } from '../core/mobile.js';

const TEX = 'vendor/nasa/'; // vendored NASA textures, public domain (web/vendor/nasa/SOURCES.md)
const DWELL = 8000;          // ms per focused event
const IDLE_RESUME = 15000;   // ms of no interaction before autopilot resumes
const QUEUE_MAX = 80;
const STACK_N = 6;
const MIN_NOTABLE = 0.45;    // kinds whose top severity is below this never get the spotlight

// Globe palette reads the Night Desk CSS tokens (--globe-*) rather than hardcoding colours (okf web-client).
const cssvar = (n, f) => (getComputedStyle(document.documentElement).getPropertyValue(n).trim() || f);
// Subsea cables are context: dusty slate at rest, warm lamplight when the focused event lands on them (no teal).
const CABLE_COLD = 'rgba(156,182,173,0.26)';
const CABLE_HOT = ['rgba(226,198,193,0.95)', 'rgba(228,168,76,0.8)'];

const GROUPS = [
  { id: 'threat', label: 'Threat infra', color: cssvar('--accent', '#e4a84c'), match: ['Threat infrastructure'] },
  { id: 'net', label: 'Internet', color: '#4ea1b0', match: ['Internet infrastructure'] },
  { id: 'media', label: 'News & social', color: cssvar('--globe-media', '#e9e3d4'), match: ['Media', 'Custom', 'Vulnerabilities', 'Other'] },
];
const groupOf = (kind) => {
  const g = kindMeta(kind).group;
  return (GROUPS.find((x) => x.match.includes(g)) || GROUPS[2]).id;
};
const ICON = {
  threat: '<svg viewBox="0 0 16 16"><path d="M8 1l1.6 3.7L13.5 3l-1.7 3.9L15.5 8l-3.7 1.1 1.7 3.9-3.9-1.7L8 15l-1.6-3.7L2.5 13l1.7-3.9L.5 8l3.7-1.1L2.5 3l3.9 1.7z" fill="currentColor"/></svg>',
  net: '<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="2" fill="currentColor"/><path d="M3.8 3.8a6 6 0 0 0 0 8.4M12.2 3.8a6 6 0 0 1 0 8.4M5.9 5.9a3 3 0 0 0 0 4.2M10.1 5.9a3 3 0 0 1 0 4.2" stroke="currentColor" stroke-width="1.4" fill="none"/></svg>',
  media: '<svg viewBox="0 0 16 16"><path d="M2.5 2.5h11v11h-11z M5 5.5h6M5 8h6M5 10.5h4" stroke="currentColor" stroke-width="1.4" fill="none"/></svg>',
};

// ------------------------------------------------------------------ geo helpers
const RAD = Math.PI / 180;
function haversineKm(a, b) {
  const dLat = (b.lat - a.lat) * RAD, dLng = (b.lng - a.lng) * RAD;
  const s = Math.sin(dLat / 2) ** 2 + Math.cos(a.lat * RAD) * Math.cos(b.lat * RAD) * Math.sin(dLng / 2) ** 2;
  return 12742 * Math.asin(Math.min(1, Math.sqrt(s)));
}
// Subsolar point (declination + equation of time) -> world-space unit vector in three-globe coords.
function sunVector(d = new Date()) {
  const start = Date.UTC(d.getUTCFullYear(), 0, 0);
  const doy = (d - start) / 864e5;
  const g = (2 * Math.PI / 365) * (doy - 1);
  const decl = 0.006918 - 0.399912 * Math.cos(g) + 0.070257 * Math.sin(g) - 0.006758 * Math.cos(2 * g)
    + 0.000907 * Math.sin(2 * g) - 0.002697 * Math.cos(3 * g) + 0.00148 * Math.sin(3 * g);
  const eot = 229.18 * (0.000075 + 0.001868 * Math.cos(g) - 0.032077 * Math.sin(g) - 0.014615 * Math.cos(2 * g) - 0.040849 * Math.sin(2 * g));
  const utcMin = d.getUTCHours() * 60 + d.getUTCMinutes() + d.getUTCSeconds() / 60;
  const lng = -((utcMin + eot) / 4 - 180);
  const lat = decl / RAD;
  return { lat, lng, v: [Math.cos(lat * RAD) * Math.sin(lng * RAD), Math.sin(lat * RAD), Math.cos(lat * RAD) * Math.cos(lng * RAD)] };
}
// Cheap polyline thinning: keep a vertex only when it is >= tol degrees from the last kept one.
function thin(coords, tol) {
  const out = [];
  let last = null;
  for (let i = 0; i < coords.length; i++) {
    const [lng, lat] = coords[i];
    if (!last || i === coords.length - 1 || Math.abs(lng - last[0]) + Math.abs(lat - last[1]) >= tol) {
      out.push([lat, lng]); last = [lng, lat];
    }
  }
  return out;
}
const fmtCoord = (lat, lng) => `${Math.abs(lat).toFixed(3)}°${lat >= 0 ? 'N' : 'S'}, ${Math.abs(lng).toFixed(3)}°${lng >= 0 ? 'E' : 'W'}`;
// Times through the app's one clock (core/time.js, Settings › Display).
const isoShort = (t) => Tm.stamp(t, { seconds: true, zone: true });
const hhmm = (t) => Tm.time(t);
const mmdd = (t) => Tm.date(t);

function dim(hex, k) {
  const n = parseInt(hex.slice(1), 16);
  const bg = [4, 8, 16];
  const ch = (v, i) => Math.round(bg[i] + (v - bg[i]) * k);
  return `rgb(${ch(n >> 16, 0)},${ch((n >> 8) & 255, 1)},${ch(n & 255, 2)})`;
}
function hexA(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
}

// ------------------------------------------------------------------ module state
let ctx, root, G, ro;
let visible = false;
let rows = [];             // all geo points in the window
let filtered = [];         // after group + brush filter
let queue = [];            // autopilot order
let qi = 0;
let focus = null;
let detail = null;
const detailCache = new Map();
let sourcesMeta = new Map();
let landings = [];
let cables = [];
let hotCables = new Set();
// The window (hours, 0 = all): Cinema remembers its own (nd.cinema.range) and its URL carries it (#cinema?range=7d).
const LSKEY = 'nd.cinema.range';
let rangeH = (() => { try { const v = JSON.parse(localStorage.getItem(LSKEY)); return v == null ? 24 : snap(v, LIVE); } catch { return 24; } })();
let rangeCtl = null;
let brush = [0, 1];
// A brushed window from a link (#cinema?range=<from>~<to>), applied once the points that set the axis are in.
let pendingWin = null;
// The window on the timeline: the last rangeH hours, or (ALL) from the oldest point loaded up to now.
function win() {
  const now = Date.now();
  if (rangeH) return { t0: now - rangeH * 3600e3, span: rangeH * 3600e3 };
  let t0 = now - 30 * 864e5;
  if (rows.length) { t0 = now; for (const r of rows) if (r.t < t0) t0 = r.t; }
  return { t0, span: Math.max(3600e3, now - t0) };
}
// Two windows are the same to the minute (the URL keeps whole seconds; the brush is fractional).
const sameWin = (a, b) => b.from != null && Math.abs(a.from - b.from) < 60e3 && Math.abs(a.to - b.to) < 60e3;
const winWords = () => (rangeH ? phrase({ h: rangeH }) : 'all time');
const activeGroups = new Set(GROUPS.map((g) => g.id));
let showCables = true;
// TeleGeography's cable data is opt-in (downloaded from the world map's Layers menu); while it is drawn, it is credited.
function cableCredit() { const el = document.querySelector('.cinema-credit'); if (el) el.hidden = !(showCables && cables.length); }
let showBgp = true;
let playing = true;
let lastInteract = -Infinity;
let elapsed = 0;
let lastTick = 0;
let tickTimer = null;
let raf = 0;
let soundOn = false;
let audioCtx = null;
let bgpRings = [];
let liveRings = [];
let bgpCount = [];
let relatedArcs = [];
let landingArc = null;
let nearest = null;
let tickerItems = [];
let sunTimer = null;
let sunU = null;
let dnU = null;
let loadSeq = 0;

const $ = (sel) => root.querySelector(sel);

// ------------------------------------------------------------------ DOM
function buildDom(el) {
  root = h(`
  <div class="cinema">
    <div class="cinema-globe"></div>
    <div class="cinema-vignette"></div>
    <svg class="cinema-lines">
      <defs>
        <filter id="cinema-glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      </defs>
      <g class="cl-minor"></g>
      <path class="cl-main" filter="url(#cinema-glow)"/>
      <g class="cl-ret">
        <circle class="cl-pulse" r="9"/>
        <circle class="cl-ring" r="11"/>
        <path class="cl-ticks" d="M0,-17V-8M0,8V17M-17,0H-8M8,0H17"/>
        <circle class="cl-core" r="2.6"/>
      </g>
    </svg>
    <div class="cinema-plabel" hidden></div>
    <div class="cinema-rail">
      <div class="cinema-focus-wrap"></div>
      <div class="cinema-stack"></div>
    </div>
    ${viewHeader({
      title: 'Cinema', overlay: true, cls: 'cinema-vh', purpose: '<span class="cinema-rec" aria-hidden="true"></span>A lean-back tour of real events on the globe',
      actions: `<button class="cinema-btn cinema-play" title="Play / pause autopilot (space)"></button>
        <button class="cinema-btn cinema-prev" title="Previous event (←)" aria-label="Previous event"><svg viewBox="0 0 16 16"><path d="M10 3 5 8l5 5" stroke="currentColor" stroke-width="1.6" fill="none"/></svg></button>
        <button class="cinema-btn cinema-next" title="Next event (→)" aria-label="Next event"><svg viewBox="0 0 16 16"><path d="m6 3 5 5-5 5" stroke="currentColor" stroke-width="1.6" fill="none"/></svg></button>
        <button class="cinema-btn cinema-sun on" title="Real-time day/night terminator" aria-label="Day and night shading"><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="3" fill="currentColor"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.4 1.4M11.6 11.6 13 13M3 13l1.4-1.4M11.6 4.4 13 3" stroke="currentColor" stroke-width="1.3"/></svg></button>
        <button class="cinema-btn cinema-sound" title="Audio blip on new high-severity events" aria-label="Sound on new high-severity events"></button>`,
      range: { cls: 'cinema-range' },
    })}
    <div class="cinema-hud">
      <div class="cinema-chips"></div>
      <div class="cinema-stats"></div>
      <div class="cinema-credit" hidden>Cable data © <a href="https://www.submarinecablemap.com" target="_blank" rel="noopener noreferrer">TeleGeography (submarinecablemap.com)</a></div>
    </div>
    <div class="cinema-bottom">
      <div class="cinema-scrub">
        <div class="cinema-scrub-head">
          <span class="label">Timeline</span>
          <span class="cinema-scrub-sel mono"></span>
          <button class="cinema-scrub-reset" hidden>reset</button>
          <div class="cinema-legend"><span><i style="background:${sevColor(0.9)}"></i>CRITICAL</span><span><i style="background:${sevColor(0.7)}"></i>HIGH</span><span><i style="background:${sevColor(0.5)}"></i>ELEVATED</span><span><i style="background:${sevColor(0.2)}"></i>LOW</span><span><i class="ln"></i>SUBSEA CABLE</span><span><i class="rg"></i>BGP LIVE</span></div>
        </div>
        <div class="cinema-scrub-body"><canvas></canvas><div class="cinema-brush"><i class="hl"></i><i class="hr"></i></div></div>
        <div class="cinema-scrub-axis mono"></div>
      </div>
      <div class="cinema-ticker"><span class="cinema-ticker-tag" data-ls="waiting"><i></i><span class="states-tt">…</span></span><div class="cinema-ticker-vp"><div class="cinema-ticker-track"></div></div></div>
    </div>
    <div class="cinema-status" hidden></div>
  </div>`);
  el.append(root);
}

// ------------------------------------------------------------------ globe
function initGlobe(GlobeLib) {
  const box = $('.cinema-globe');
  G = GlobeLib({ rendererConfig: { antialias: true, alpha: false, powerPreference: 'high-performance' }, animateIn: false })(box)
    .width(box.clientWidth).height(box.clientHeight)
    .backgroundColor(cssvar('--globe-bg', '#06080d'))
    .globeImageUrl(TEX + 'blue-marble.jpg')
    .bumpImageUrl(TEX + 'topography.png')
    .showAtmosphere(true).atmosphereColor(cssvar('--globe-atmo', '#c98f3a')).atmosphereAltitude(0.2)
    .enablePointerInteraction(false)
    // events
    .pointLat('lat').pointLng('lng')
    .pointColor((d) => d.c)
    .pointAltitude((d) => d.alt)
    .pointRadius((d) => d.r)
    .pointResolution(6)
    .pointsMerge(true)
    .pointsTransitionDuration(0)
    // rings
    .ringLat('lat').ringLng('lng')
    .ringColor((d) => d.colorFn)
    .ringMaxRadius((d) => d.max)
    .ringPropagationSpeed((d) => d.speed)
    .ringRepeatPeriod((d) => d.period)
    .ringAltitude(0.004)
    // arcs
    .arcStartLat('sLat').arcStartLng('sLng').arcEndLat('eLat').arcEndLng('eLng')
    .arcColor((d) => d.color)
    .arcStroke((d) => d.stroke)
    .arcDashLength((d) => d.dash).arcDashGap((d) => d.gap).arcDashAnimateTime((d) => d.anim)
    .arcAltitudeAutoScale(0.28)
    .arcsTransitionDuration(0)
    // cables
    .pathPoints('pts').pathPointLat((p) => p[0]).pathPointLng((p) => p[1]).pathPointAlt(0.0015)
    .pathColor((d) => (hotCables.has(d.id) ? CABLE_HOT : CABLE_COLD))
    .pathStroke(null)
    .pathTransitionDuration(0);

  const c = G.controls();
  c.autoRotate = !reducedMotion(); // reduced motion: the globe only turns by hand
  c.autoRotateSpeed = 0.28;
  c.enableDamping = true;
  c.dampingFactor = 0.08;
  c.minDistance = 130;
  c.maxDistance = 900;
  G.pointOfView({ lat: 30, lng: 15, altitude: 2.1 }, 0);

  installDayNight();

  // user interaction pauses the autopilot until idle
  const touch = () => { lastInteract = performance.now(); c.autoRotate = false; updatePlayBtn(); };
  box.addEventListener('pointerdown', touch);
  box.addEventListener('wheel', touch, { passive: true });
  let down = null;
  box.addEventListener('pointerdown', (e) => { down = [e.clientX, e.clientY]; });
  box.addEventListener('pointerup', (e) => {
    if (!down || Math.hypot(e.clientX - down[0], e.clientY - down[1]) > 4) return;
    pickAt(e);
  });
}

// Blend the city-lights texture onto the night hemisphere using the real subsolar point.
function installDayNight() {
  const mat = G.globeMaterial();
  sunU = { value: sunVector().v };
  dnU = { value: 1 };
  const img = new Image();
  img.crossOrigin = 'anonymous';
  img.src = TEX + 'black-marble.jpg';
  img.onload = () => {
    const wait = () => {
      if (!mat.map || !mat.map.image) return setTimeout(wait, 250);
      // a brand-new Texture (own Source) built with the bundled THREE's Texture class
      const night = new mat.map.constructor(img);
      night.colorSpace = mat.map.colorSpace;
      night.anisotropy = mat.map.anisotropy;
      night.needsUpdate = true;
      night.needsUpdate = true;
      mat.onBeforeCompile = (shader) => {
        shader.uniforms.nightMap = { value: night };
        shader.uniforms.sunDir = sunU;
        shader.uniforms.dnOn = dnU;
        shader.vertexShader = shader.vertexShader
          .replace('#include <common>', '#include <common>\nvarying vec3 vWN;')
          .replace('#include <begin_vertex>', '#include <begin_vertex>\nvWN = normalize(mat3(modelMatrix) * objectNormal);');
        shader.fragmentShader = shader.fragmentShader
          .replace('#include <common>', '#include <common>\nuniform sampler2D nightMap;\nuniform vec3 sunDir;\nuniform float dnOn;\nvarying vec3 vWN;')
          .replace('#include <opaque_fragment>', `#include <opaque_fragment>
            #ifdef USE_MAP
            float sd = dot(normalize(vWN), normalize(sunDir));
            float dayAmt = smoothstep(-0.10, 0.22, sd);
            vec3 nTex = texture2D(nightMap, vMapUv).rgb;
            float lit = clamp((nTex.r + nTex.g * 0.5 - nTex.b * 1.3) * 7.0, 0.0, 1.0);
            vec3 nightC = nTex * vec3(0.16, 0.2, 0.28) + lit * vec3(1.0, 0.68, 0.32) * (0.35 + nTex.r * 2.6) + gl_FragColor.rgb * 0.035;
            vec3 dayRaw = gl_FragColor.rgb;
            float dl = dot(dayRaw, vec3(0.299, 0.587, 0.114));
            vec3 dayC = mix(vec3(dl), dayRaw, 0.4) * vec3(0.74, 0.84, 1.0) * (0.38 + 0.14 * clamp(sd, 0.0, 1.0));
            vec3 twilight = vec3(0.35, 0.16, 0.05) * (1.0 - abs(sd * 6.0)) * step(abs(sd), 0.16);
            gl_FragColor.rgb = mix(gl_FragColor.rgb, mix(nightC, dayC, dayAmt) + twilight * 0.12, dnOn);
            #endif`);
      };
      mat.needsUpdate = true;
    };
    wait();
  };
  clearInterval(sunTimer);
  sunTimer = setInterval(() => { sunU.value = sunVector().v; }, 60000);
}

function pickAt(e) {
  if (typeof G.toGlobeCoords !== 'function' || !filtered.length) return;
  const r = $('.cinema-globe').getBoundingClientRect();
  const g = G.toGlobeCoords(e.clientX - r.left, e.clientY - r.top);
  if (!g) return;
  let best = null, bd = 2.5;
  for (const p of filtered) {
    const d = Math.abs(p.lat - g.lat) + Math.abs(p.lng - g.lng) * Math.cos(g.lat * RAD);
    if (d < bd || (best && d === bd && p.sev > best.sev)) { bd = d; best = p; }
  }
  if (!best) return;
  const i = queue.findIndex((q) => q.id === best.id);
  if (i >= 0) qi = i; else { queue.splice(qi + 1, 0, best); qi += 1; }
  focusEvent(queue[qi], { fly: false });
}

// ------------------------------------------------------------------ data
let loadErr = null;   // the last load's failure, until a load succeeds: the empty-map message must not replace it
const errStatus = () => ({ title: "Couldn't load the events", why: 'The Night Desk server did not answer with them. Try again in a moment.', acts: [['retry', 'Try again']], details: loadErr });
async function loadPoints() {
  const seq = ++loadSeq;
  setStatus(rows.length ? null : 'Loading events…');
  try {
    // spread: past the cap, every k-th point across the window (ALL and 30D keep their whole span, not the newest days)
    const res = await ctx.api.points({ since_hours: rangeH || undefined, limit: 40000, spread: 1 });
    if (seq !== loadSeq) return;
    loadErr = null;
    rows = res.rows.map((r) => ({ lng: r[0], lat: r[1], sev: r[2] ?? 0.4, kind: r[3], id: r[4], title: r[5], country: r[6], t: r[7] * 1000 }));
    if (pendingWin) { brushTo(pendingWin); pendingWin = null; paintRangeCtl(); }
    applyFilters(true);
  } catch (err) {
    if (seq !== loadSeq) return;
    // plain words on screen; the server's own message only under Details and in the console (B2-11)
    console.warn('Cinema: events did not load:', err.message);
    loadErr = err.message || 'error';
    setStatus(errStatus());
  }
}

async function loadStatic() {
  try {
    const src = await ctx.api.sources();
    sourcesMeta = new Map((Array.isArray(src) ? src : src.sources || []).map((s) => [s.id, s]));
  } catch {}
  try {
    const lp = await ctx.api.landings();
    landings = lp.features.filter((f) => f.geometry?.coordinates).map((f) => ({ name: f.properties.name, lng: f.geometry.coordinates[0], lat: f.geometry.coordinates[1] }));
  } catch {}
  try {
    const gj = await ctx.api.cables();
    const out = [];
    for (const f of gj.features) {
      const g = f.geometry;
      if (!g) continue;
      const lines = g.type === 'MultiLineString' ? g.coordinates : g.type === 'LineString' ? [g.coordinates] : [];
      lines.forEach((ln, i) => {
        const pts = thin(ln, 0.9);
        if (pts.length >= 2) out.push({ id: f.properties.id, name: f.properties.name, pts, k: `${f.properties.id}-${i}` });
      });
    }
    cables = out;
    if (showCables) G.pathsData(cables);
    cableCredit();
    renderChips();
    renderStats();
  } catch {}
}

function applyFilters(rebuildQueue = false) {
  const { t0, span } = win();
  const a = t0 + brush[0] * span, b = brush[1] >= 0.999 ? Infinity : t0 + brush[1] * span;
  filtered = rows.filter((r) => activeGroups.has(groupOf(r.kind)) && r.t >= a && r.t <= b);
  drawPoints();
  if (rebuildQueue || !queue.length || !filtered.find((f) => f.id === focus?.id)) {
    buildQueue();
    qi = 0;
    if (queue.length) focusEvent(queue[0]); else clearFocus();
  } else {
    buildQueue(focus);
    qi = Math.max(0, queue.findIndex((q) => q.id === focus.id));
    renderStack();
  }
  renderChips();
  renderStats();
  drawScrub();
  setStatus(filtered.length ? null : rows.length ? 'No events match the current filters' : loadErr ? errStatus() : emptyStatus());
}

function drawPoints() {
  const focusId = focus?.id;
  const data = filtered.map((r) => {
    if (r.id === focusId) return { lat: r.lat, lng: r.lng, c: '#ffffff', alt: 0.14, r: 0.32 };
    const c = sevColor(r.sev);
    const hi = r.sev >= 0.65;
    // while something is focused, every other marker drops to ~30% (darkened toward the background)
    return { lat: r.lat, lng: r.lng, c: focusId ? dim(c, 0.3) : hi ? c : hexA(c, 0.75), alt: hi ? 0.0025 + r.sev * 0.004 : 0.0015, r: 0.1 + r.sev * r.sev * 0.42 };
  });
  G.pointsData(data);
}

// Round-robin across kinds (each sorted by severity, de-duplicated by place) so the tour varies.
function buildQueue(keep) {
  const byKind = new Map();
  for (const r of filtered) {
    if (!byKind.has(r.kind)) byKind.set(r.kind, []);
    byKind.get(r.kind).push(r);
  }
  const lists = [];
  for (const [k, list] of byKind) {
    list.sort((x, y) => y.sev - x.sev || y.t - x.t);
    if (list[0].sev < MIN_NOTABLE) continue;
    const picked = [];
    for (const r of list) {
      if (picked.length >= 25) break;
      if (r.sev < MIN_NOTABLE * 0.9 && picked.length) break;
      if (picked.some((p) => Math.abs(p.lat - r.lat) < 3 && Math.abs(p.lng - r.lng) < 3)) continue;
      picked.push(r);
    }
    lists.push({ k, top: list[0].sev, picked });
  }
  lists.sort((x, y) => y.top - x.top);
  const out = [];
  for (let i = 0; out.length < QUEUE_MAX; i++) {
    let any = false;
    for (const l of lists) if (l.picked[i]) { out.push(l.picked[i]); any = true; }
    if (!any) break;
  }
  if (keep && !out.find((o) => o.id === keep.id)) out.unshift(keep);
  queue = out.slice(0, QUEUE_MAX);
}

// ------------------------------------------------------------------ focus + autopilot
function focusEvent(ev, { fly = true } = {}) {
  if (!ev) return;
  focus = ev;
  elapsed = 0;
  detail = detailCache.get(ev.id) || null;
  computeNearest();
  renderFocusCard();
  renderStack();
  drawPoints();
  if (fly) flyTo(ev);
  updateRings();
  updateArcs();
  if (!detail) {
    ctx.api.event(ev.id).then((d) => {
      detailCache.set(ev.id, d);
      if (focus?.id === ev.id) { detail = d; renderFocusCard(); loadRelated(d); }
    }).catch(() => {});
  } else loadRelated(detail);
  // prefetch the next card's detail so the swap is instant
  const nx = queue[(qi + 1) % queue.length];
  if (nx && !detailCache.has(nx.id)) ctx.api.event(nx.id).then((d) => detailCache.set(nx.id, d)).catch(() => {});
}

function clearFocus() {
  focus = null; detail = null;
  $('.cinema-focus-wrap').innerHTML = '';
  $('.cinema-stack').innerHTML = '';
  relatedArcs = []; landingArc = null; hotCables = new Set();
  updateArcs(); updateRings();
}

function mobile() { return root.clientWidth < 720; }

function flyTo(ev) {
  const m = mobile();
  const lat = Math.max(-55, Math.min(68, ev.lat + (m ? -6 : 4)));
  const off = m ? 0 : 5 / Math.max(0.45, Math.cos(ev.lat * RAD));
  G.pointOfView({ lat, lng: ev.lng - off, altitude: m ? 2.3 : 1.55 }, reducedMotion() ? 0 : 2400); // reduced motion: cut, don't fly
}

function step(dir) {
  if (!queue.length) return;
  qi = (qi + dir + queue.length) % queue.length;
  focusEvent(queue[qi]);
}

function autopilotActive() {
  return playing && visible && performance.now() - lastInteract > IDLE_RESUME;
}

function tick() {
  const now = performance.now();
  const dt = lastTick ? now - lastTick : 0;
  lastTick = now;
  const active = autopilotActive();
  if (active && !G.controls().autoRotate && !reducedMotion()) G.controls().autoRotate = true;
  if (active && focus) {
    elapsed += dt;
    if (elapsed >= DWELL) step(1);
  }
  const bar = root.querySelector('.cf-progress i');
  if (bar) bar.style.width = `${Math.min(100, (elapsed / DWELL) * 100)}%`;
  updatePlayBtn();
  // expire transient rings
  const t = Date.now();
  const nb = bgpRings.filter((r) => r.until > t), nl = liveRings.filter((r) => r.until > t);
  if (nb.length !== bgpRings.length || nl.length !== liveRings.length) { bgpRings = nb; liveRings = nl; updateRings(); }
}

let lastPlayState = '';
function updatePlayBtn() {
  const idle = playing && performance.now() - lastInteract <= IDLE_RESUME;
  const state = !playing ? 'paused' : idle ? 'hold' : 'play';
  if (state === lastPlayState) {
    if (state === 'hold') root.querySelector('.cinema-play .t').textContent = `RESUME ${Math.ceil((IDLE_RESUME - (performance.now() - lastInteract)) / 1000)}s`;
    return;
  }
  lastPlayState = state;
  const b = $('.cinema-play');
  b.classList.toggle('on', state === 'play');
  b.innerHTML = state === 'paused'
    ? '<svg viewBox="0 0 16 16"><path d="M4.5 3v10l8-5z" fill="currentColor"/></svg><span class="t">AUTOPILOT</span>'
    : state === 'hold'
      ? '<svg viewBox="0 0 16 16"><path d="M5 3.5v9M11 3.5v9" stroke="currentColor" stroke-width="2"/></svg><span class="t">RESUME</span>'
      : '<svg viewBox="0 0 16 16"><path d="M5 3.5v9M11 3.5v9" stroke="currentColor" stroke-width="2"/></svg><span class="t">AUTOPILOT</span>';
  $('.cinema-rec').classList.toggle('on', state === 'play');
}

// ------------------------------------------------------------------ rings / arcs
function ringFn(hex, base = 1) {
  const r = parseInt(hex.slice(1, 3), 16), g = parseInt(hex.slice(3, 5), 16), b = parseInt(hex.slice(5, 7), 16);
  return (t) => `rgba(${r},${g},${b},${Math.max(0, (1 - t) * base)})`;
}

function updateRings() {
  if (!G) return;
  const rings = [];
  if (focus) {
    const col = kindMeta(focus.kind).color;
    rings.push({ lat: focus.lat, lng: focus.lng, colorFn: ringFn(cssvar('--globe-ring', '#e4a84c')), max: 7.5, speed: 2.6, period: 1100 });
    rings.push({ lat: focus.lat, lng: focus.lng, colorFn: ringFn('#ffffff', 0.9), max: 3, speed: 1.4, period: 1100 });
  }
  // persistent slow rings on the most severe events in view
  const hot = filtered.filter((r) => r.sev >= 0.85 && r.id !== focus?.id).sort((a, b) => b.sev - a.sev);
  const seen = [];
  for (const r of hot) {
    if (seen.length >= 14) break;
    if (seen.some((s) => Math.abs(s.lat - r.lat) < 4 && Math.abs(s.lng - r.lng) < 4)) continue;
    seen.push(r);
    rings.push({ lat: r.lat, lng: r.lng, colorFn: ringFn(sevColor(r.sev), focus ? 0.28 : 0.7), max: 2.6, speed: 1.1, period: 2600 });
  }
  for (const r of liveRings) rings.push(r);
  if (showBgp) for (const r of bgpRings) rings.push(r);
  G.ringsData(rings);
}

function computeNearest() {
  nearest = null; landingArc = null; hotCables = new Set();
  if (!focus || !landings.length) { refreshCableColors(); return; }
  let best = null, bd = Infinity;
  for (const l of landings) {
    const d = haversineKm(focus, l);
    if (d < bd) { bd = d; best = l; }
  }
  if (!best) return;
  nearest = { ...best, km: bd };
  if (bd > 40 && bd < 4000) {
    landingArc = { sLat: focus.lat, sLng: focus.lng, eLat: best.lat, eLng: best.lng, color: ['rgba(233,227,212,0.9)', 'rgba(228,168,76,0.95)'], stroke: 0.35, dash: 0.25, gap: 0.12, anim: 1800 };
  }
  // cables that land at that station (any vertex within ~0.25 deg)
  for (const c of cables) {
    if (hotCables.has(c.id)) continue;
    for (const p of c.pts) {
      if (Math.abs(p[0] - best.lat) < 0.25 && Math.abs(p[1] - best.lng) < 0.25) { hotCables.add(c.id); break; }
    }
  }
  refreshCableColors();
}

function refreshCableColors() {
  if (!G || !showCables) return;
  // re-assigning the accessor makes globe.gl re-evaluate colours without rebuilding geometry
  G.pathColor((d) => (hotCables.has(d.id) ? CABLE_HOT : CABLE_COLD));
}

async function loadRelated(d) {
  relatedArcs = [];
  if (!d?.asn) { updateArcs(); return; }
  try {
    const list = await ctx.api.events({ q: d.asn, geo: true, since_hours: rangeH, limit: 30 });
    if (focus?.id !== d.id) return;
    const seen = [];
    for (const e of list) {
      if (e.id === d.id || e.asn !== d.asn || e.lat == null) continue;
      if (Math.abs(e.lat - d.lat) + Math.abs(e.lon - d.lon) < 1.5) continue;
      if (seen.some((s) => Math.abs(s.lat - e.lat) + Math.abs(s.lon - e.lon) < 1.5)) continue;
      seen.push(e);
      if (seen.length >= 6) break;
    }
    const col = kindMeta(d.kind).color;
    relatedArcs = seen.map((e) => ({ sLat: d.lat, sLng: d.lon, eLat: e.lat, eLng: e.lon, color: [hexA(col, 0.95), 'rgba(255,255,255,0.15)'], stroke: 0.22, dash: 0.45, gap: 0.15, anim: 2600 }));
    detail.relatedAsn = seen;
    renderFocusCard();
  } catch {}
  updateArcs();
}

function updateArcs() {
  if (!G) return;
  G.arcsData([...(landingArc ? [landingArc] : []), ...relatedArcs]);
}

// ------------------------------------------------------------------ cards
function sourceLink(d, ev) {
  if (safeUrl(d?.url)) return { href: safeUrl(d.url), text: 'Source' }; // feed data: http(s) links only
  const s = sourcesMeta.get(d?.source || ev.source);
  if (safeUrl(s?.homepage)) return { href: safeUrl(s.homepage), text: 'Source' };
  return null;
}

function renderFocusCard() {
  const wrap = $('.cinema-focus-wrap');
  if (!focus) { wrap.innerHTML = ''; return; }
  const ev = focus, d = detail;
  const m = kindMeta(ev.kind);
  const g = groupOf(ev.kind);
  const t = d?.ts ? new Date(d.ts).getTime() : ev.t;
  const recent = Date.now() - t < 6 * 3600e3;
  const src = d ? sourcesMeta.get(d.source)?.name || d.source : '…';
  const link = sourceLink(d, ev);
  const cc = d?.country || ev.country;
  const place = [d?.city, cc].filter(Boolean).join(', ');
  const rowsKv = [
    ['TYPE', m.label],
    ['SOURCE', src],
    ['COUNTRY', cc ? `${flag(cc)} ${cc}${d?.city ? ' · ' + d.city : ''}` : '—'],
    d?.ip && ['IP', d.ip],
    d?.asn && ['ASN', d.asn],
    d?.related?.length && ['ALSO SEEN', [...new Set(d.related.map((r) => kindMeta(r.kind).label))].slice(0, 3).join(', ')],
    d?.relatedAsn?.length && ['SAME ASN', `${d.relatedAsn.length} other location${d.relatedAsn.length > 1 ? 's' : ''} · arcs`],
    nearest && ['SUBSEA', `${nearest.name} · ${fmt(Math.round(nearest.km))} km`],
  ].filter(Boolean);
  wrap.innerHTML = `
    <div class="cinema-focus" style="--k:${m.color}">
      <div class="cf-head">
        <span class="cf-ico">${ICON[g]}</span>
        <span class="cf-kind">${esc(m.label.toUpperCase())}</span>
        ${recent ? '<span class="cf-recent">RECENT</span>' : ''}
        <span class="cf-sev" style="--s:${sevColor(ev.sev)}">SEV ${Math.round(ev.sev * 100)}</span>
        <span class="cf-ago">${ago(t)}</span>
      </div>
      <div class="cf-title" title="Open details">${esc(d?.title || ev.title)}</div>
      <div class="cf-meta">Source: ${esc(src)} | ${esc(place || '—')} | ${isoShort(t)}</div>
      ${d?.summary && d.summary !== d.title ? `<div class="cf-sum">${esc(d.summary)}</div>` : ''}
      <dl class="cf-kv">${rowsKv.map(([k, v]) => `<dt>${k}:</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      <div class="cf-foot">
        <span>${fmtCoord(ev.lat, ev.lng)}${d?.tags?.length ? ' · ' + esc(d.tags.slice(0, 2).join(' · ')) : ''}</span>
        <span class="cf-links"><button class="cf-open">Details</button>${link ? `<a href="${esc(link.href)}" target="_blank" rel="noopener">${link.text} ↗</a>` : ''}</span>
      </div>
      <div class="cf-progress"><i></i></div>
    </div>`;
  wrap.querySelector('.cf-title').onclick = () => ctx.openEvent(ev.id);
  wrap.querySelector('.cf-open').onclick = () => ctx.openEvent(ev.id);
  updatePlabel();
}

function renderStack() {
  const st = $('.cinema-stack');
  if (!queue.length) { st.innerHTML = ''; return; }
  const items = [];
  for (let i = 1; i <= Math.min(STACK_N, queue.length - 1); i++) items.push(queue[(qi + i) % queue.length]);
  st.innerHTML = items.map((r, i) => {
    const m = kindMeta(r.kind);
    return `<div class="cinema-mini" data-id="${esc(r.id)}" style="--k:${m.color};--o:${(1 - i * 0.15).toFixed(2)}">
      <div class="cm-top"><span class="cm-ico">${ICON[groupOf(r.kind)]}</span><span class="cm-title">${esc(r.title)}</span><span class="cm-ago">${ago(r.t)}</span></div>
      <div class="cm-sub"><span>${r.lat.toFixed(3)}°, ${r.lng.toFixed(3)}°</span> · <span class="cm-kind">${esc(m.label)}</span>${r.country ? ` · ${esc(r.country)}` : ''}</div>
    </div>`;
  }).join('');
  st.querySelectorAll('.cinema-mini').forEach((c) => (c.onclick = () => {
    const i = queue.findIndex((q) => q.id === c.dataset.id);
    if (i >= 0) { qi = i; lastInteract = performance.now(); focusEvent(queue[qi]); }
  }));
}

function updatePlabel() {
  const pl = $('.cinema-plabel');
  if (!focus) { pl.hidden = true; return; }
  const sub = nearest && landingArc ? `<div class="pl-sub2">↳ subsea landing ${esc(nearest.name)} · ${fmt(Math.round(nearest.km))} km</div>` : '';
  pl.innerHTML = `<div class="pl-t">${esc(detail?.title || focus.title)}</div><div class="pl-s">${mmdd(focus.t)} ${hhmm(focus.t)} · ${focus.lat.toFixed(2)}°, ${focus.lng.toFixed(2)}°</div>${sub}`;
  pl.style.setProperty('--k', kindMeta(focus.kind).color);
}

// ------------------------------------------------------------------ overlay (per frame)
function onFront(lat, lng) {
  const c = G.getCoords(lat, lng, 0);
  const cam = G.camera().position;
  const cl = Math.hypot(cam.x, cam.y, cam.z);
  const R = 100;
  return (c.x * cam.x + c.y * cam.y + c.z * cam.z) / (R * cl) > R / cl + 0.03;
}

function frame() {
  if (!visible) return;
  raf = requestAnimationFrame(frame);
  if (!G) return;
  const main = $('.cl-main'), ret = $('.cl-ret'), pl = $('.cinema-plabel'), minor = $('.cl-minor');
  const rb = root.getBoundingClientRect();
  const card = root.querySelector('.cinema-focus');
  const m = mobile();
  let mainVis = false;
  let elbowX = null;
  if (focus && card) {
    const sc = G.getScreenCoords(focus.lat, focus.lng, 0.01);
    const front = onFront(focus.lat, focus.lng);
    const cr = card.getBoundingClientRect();
    const px = sc.x, py = sc.y;
    const inView = px > 0 && py > 0 && px < rb.width && py < rb.height;
    if (front && inView) {
      mainVis = true;
      const col = kindMeta(focus.kind).color;
      if (!m && px > cr.right - rb.left + 30) {
        // gentle curve leaving the card edge horizontally and landing just outside the reticle
        const x0 = cr.right - rb.left, y0 = cr.top - rb.top + Math.min(88, cr.height * 0.5);
        const dx = px - x0, dy = py - y0, len = Math.hypot(dx, dy) || 1;
        const ex = px - (dx / len) * 19, ey = py - (dy / len) * 19;
        main.setAttribute('d', `M${x0},${y0} C${x0 + dx * 0.45},${y0} ${ex - dx * 0.25},${ey - dy * 0.15} ${ex},${ey}`);
      } else if (!m) {
        const x0 = cr.right - rb.left, y0 = cr.top - rb.top + 40;
        main.setAttribute('d', `M${x0},${y0} L${px},${py}`);
      } else {
        const x0 = Math.min(px, cr.right - rb.left - 20), y0 = cr.bottom - rb.top;
        main.setAttribute('d', `M${x0},${y0} V${py - 8} H${px}`);
      }
      main.style.stroke = col;
      ret.setAttribute('transform', `translate(${px.toFixed(1)},${py.toFixed(1)})`);
      pl.hidden = false;
      const w = pl.offsetWidth;
      let left = px + 24 + w > rb.width - 12 ? px - 24 - w : px + 24;
      left = Math.max(8, Math.min(rb.width - w - 8, left));
      const top = m && left < px && left + w > px ? py + 14 : py - 26;
      pl.style.transform = `translate(${Math.round(left)}px, ${Math.round(top)}px)`;
    }
  }
  main.style.display = mainVis ? '' : 'none';
  ret.style.display = mainVis ? '' : 'none';
  if (!mainVis) pl.hidden = true;

  // dashed stubs from the queued cards into the main leader's vertical run (as in a patch bay)
  const minis = m ? [] : root.querySelectorAll('.cinema-mini');
  let html = '';
  const busX = mainVis && elbowX ? elbowX : null;
  minis.forEach((c, i) => {
    const r = queue[(qi + i + 1) % queue.length];
    if (!r) return;
    const cr = c.getBoundingClientRect();
    const x0 = cr.right - rb.left, y0 = cr.top - rb.top + cr.height / 2;
    const x1 = busX && busX > x0 + 20 ? busX : x0 + 34;
    html += `<path d="M${x0},${y0} H${x1}" style="stroke:${kindMeta(r.kind).color};opacity:${(0.55 - i * 0.08).toFixed(2)}"/>`;
  });
  minor.innerHTML = html;
}

// ------------------------------------------------------------------ chips / stats
function renderChips() {
  const counts = Object.fromEntries(GROUPS.map((g) => [g.id, 0]));
  for (const r of rows) counts[groupOf(r.kind)]++;
  const box = $('.cinema-chips');
  box.innerHTML = GROUPS.map((g) => `<button class="cinema-chip${activeGroups.has(g.id) ? ' on' : ''}" data-g="${g.id}" style="--k:${g.color}"><i></i>${g.label}<span>${compact(counts[g.id])}</span></button>`).join('')
    + `<button class="cinema-chip${showCables ? ' on' : ''}" data-x="cables" style="--k:#9cb6ad"><i class="ln"></i>Cables<span>${cables.length ? compact(new Set(cables.map((c) => c.id)).size) : '…'}</span></button>`
    + `<button class="cinema-chip${showBgp ? ' on' : ''}" data-x="bgp" style="--k:#e2c6c1"><i class="rg"></i>BGP live</button>`;
  box.querySelectorAll('[data-g]').forEach((b) => (b.onclick = () => {
    const id = b.dataset.g;
    if (activeGroups.has(id)) { if (activeGroups.size > 1) activeGroups.delete(id); } else activeGroups.add(id);
    applyFilters(true);
  }));
  box.querySelector('[data-x="cables"]').onclick = () => { showCables = !showCables; G.pathsData(showCables ? cables : []); renderChips(); cableCredit(); };
  box.querySelector('[data-x="bgp"]').onclick = () => { showBgp = !showBgp; updateRings(); renderChips(); };
}

function renderStats() {
  const now = Date.now();
  bgpCount = bgpCount.filter((t) => now - t < 60000);
  const kinds = new Set(filtered.map((r) => r.kind)).size;
  $('.cinema-stats').innerHTML = `
    <div><b>${fmt(filtered.length)}</b><span>events plotted</span></div>
    <div><b>${kinds}</b><span>kinds</span></div>
    <div><b>${fmt(queue.length)}</b><span>in tour</span></div>
    <div><b class="bgp">${bgpCount.length}</b><span>BGP / min</span></div>`;
}

// ------------------------------------------------------------------ timeline scrubber
function drawScrub() {
  const body = $('.cinema-scrub-body');
  const cv = body.querySelector('canvas');
  const W = body.clientWidth, H = body.clientHeight;
  if (!W || !H) return;
  const dpr = window.devicePixelRatio || 1;
  cv.width = W * dpr; cv.height = H * dpr; cv.style.width = W + 'px'; cv.style.height = H + 'px';
  const g = cv.getContext('2d');
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, W, H);
  const { t0, span } = win();
  const nb = { 1: 60, 6: 72, 24: 96, 168: 168 }[rangeH] || 120;
  const bins = Array.from({ length: nb }, () => ({ threat: 0, net: 0, media: 0 }));
  for (const r of rows) {
    const gid = groupOf(r.kind);
    if (!activeGroups.has(gid)) continue;
    const i = Math.floor(((r.t - t0) / span) * nb);
    if (i >= 0 && i < nb) bins[i][gid]++;
    else if (i >= nb) bins[nb - 1][gid]++;
  }
  const max = Math.max(1, ...bins.map((b) => b.threat + b.net + b.media));
  const bw = W / nb;
  bins.forEach((b, i) => {
    const tot = b.threat + b.net + b.media;
    if (!tot) return;
    const hTot = Math.max(2, Math.sqrt(tot / max) * (H - 4));
    const f = i / nb;
    const inSel = f + 1 / nb > brush[0] && f < brush[1];
    let y = H;
    for (const gr of GROUPS) {
      const v = b[gr.id];
      if (!v) continue;
      const hh = (v / tot) * hTot;
      g.globalAlpha = inSel ? 0.85 : 0.22;
      g.fillStyle = gr.color;
      g.fillRect(i * bw + 0.5, y - hh, Math.max(1, bw - 1.2), hh);
      y -= hh;
    }
  });
  g.globalAlpha = 1;
  // axis labels
  const ax = $('.cinema-scrub-axis');
  ax.innerHTML = axisTicks(t0, span).map(([frac, lbl]) => `<span style="left:${(frac * 100).toFixed(2)}%">${lbl}</span>`).join('');
  positionBrush();
}

// [fraction, label] ticks: relative for a preset (-6h … NOW), dates for ALL.
function axisTicks(t0, span) {
  if (!rangeH) return [0, 1, 2, 3, 4].map((i) => [i / 4, i === 4 ? 'NOW' : mmdd(t0 + (span * i) / 4)]);
  const [n, step, suf] = { 1: [60, 15, 'm'], 6: [6, 1, 'h'], 24: [24, 6, 'h'], 168: [7, 1, 'd'] }[rangeH] || [30, 5, 'd'];
  const out = [];
  for (let k = n; k >= 0; k -= step) out.push([1 - k / n, k ? `-${k}${suf}` : 'NOW']);
  return out;
}

// The brushed part of the timeline shows in the range control as its window ("Nov 3 14:00 – Nov 4 02:00 ×") and goes
// into the URL like Network's (#cinema?range=2026-11-03T14:00:00Z~2026-11-04T02:00:00Z).
function rangeValue() {
  const full = brush[0] <= 0.001 && brush[1] >= 0.999;
  if (full) return { h: rangeH };
  const { t0, span } = win();
  return { from: Math.round(t0 + brush[0] * span), to: Math.round(brush[1] >= 0.999 ? Date.now() : t0 + brush[1] * span) };
}
function paintRangeCtl() {
  if (!rangeCtl) return;
  rangeCtl.set(rangeValue());
  syncRangeHash();
}
// The narrowest preset whose window holds `from` (else ALL), for a window that arrives by link.
const presetFor = (from) => LIVE.find((h) => h && Date.now() - h * 3600e3 <= from) ?? 0;
// Set the brush to a {from, to} window on the current axis.
function brushTo(w) {
  const { t0, span } = win();
  const a = Math.max(0, Math.min(1, (w.from - t0) / span)), b = Math.max(0, Math.min(1, (w.to - t0) / span));
  brush = b - a >= 0.01 ? [a, b >= 0.995 ? 1 : b] : [0, 1];
}
// A link or Back/Forward carrying a window: pick the preset that holds it, then brush to it.
function applyWindow(w) {
  const h = presetFor(w.from);
  pendingWin = w;
  if (h !== rangeH) { setCinemaRange(h, true); return; }
  if (rows.length) { brushTo(w); pendingWin = null; applyFilters(false); paintRangeCtl(); }
}
function setCinemaRange(hours, keepPending = false) {
  if (!keepPending) pendingWin = null;
  if (hours === rangeH) { brush = [0, 1]; applyFilters(false); paintRangeCtl(); return; }
  rangeH = hours;
  try { localStorage.setItem(LSKEY, JSON.stringify(rangeH)); } catch {}
  brush = [0, 1];
  paintRangeCtl();
  loadPoints();
  loadTicker();
}
const syncRangeHash = () => rangeSyncHash(pendingWin || rangeValue(), (hh) => /^#\/?cinema\b/i.test(hh) && visible);

function positionBrush() {
  const b = $('.cinema-brush');
  b.style.left = `${brush[0] * 100}%`;
  b.style.width = `${(brush[1] - brush[0]) * 100}%`;
  const full = brush[0] <= 0.001 && brush[1] >= 0.999;
  b.classList.toggle('full', full);
  $('.cinema-scrub-reset').hidden = full;
  const { t0, span } = win();
  const a = t0 + brush[0] * span, z = t0 + brush[1] * span;
  const f = (t) => (rangeH && rangeH <= 24 ? hhmm(t) : `${mmdd(t)} ${hhmm(t)}`);
  $('.cinema-scrub-sel').innerHTML = `${f(a)} → ${brush[1] >= 0.999 ? 'NOW' : f(z)} ${Tm.zoneName()} · <b>${fmt(filtered.length)}</b> events`;
}

function setupScrub() {
  const body = $('.cinema-scrub-body');
  let drag = null;
  const apply = debounce(() => applyFilters(false), 120);
  body.addEventListener('pointerdown', (e) => {
    const r = body.getBoundingClientRect();
    const f = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width));
    const px = 8 / r.width;
    if (Math.abs(f - brush[0]) < px) drag = { mode: 'l' };
    else if (Math.abs(f - brush[1]) < px) drag = { mode: 'r' };
    else if (f > brush[0] && f < brush[1] && !(brush[0] <= 0.001 && brush[1] >= 0.999)) drag = { mode: 'm', f0: f, b0: [...brush] };
    else { drag = { mode: 'n', a: f }; brush = [f, Math.min(1, f + 0.002)]; }
    body.setPointerCapture(e.pointerId);
    positionBrush();
  });
  body.addEventListener('pointermove', (e) => {
    if (!drag) return;
    const r = body.getBoundingClientRect();
    const f = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width));
    if (drag.mode === 'l') brush[0] = Math.min(f, brush[1] - 0.01);
    else if (drag.mode === 'r') brush[1] = Math.max(f, brush[0] + 0.01);
    else if (drag.mode === 'm') {
      const w = drag.b0[1] - drag.b0[0];
      let a = drag.b0[0] + (f - drag.f0);
      a = Math.max(0, Math.min(1 - w, a));
      brush = [a, a + w];
    } else brush = [Math.min(drag.a, f), Math.max(drag.a, f, Math.min(drag.a, f) + 0.01)];
    positionBrush();
    apply();
  });
  const end = () => { if (!drag) return; drag = null; if (brush[1] - brush[0] < 0.012) brush = [0, 1]; applyFilters(false); paintRangeCtl(); };
  body.addEventListener('pointerup', end);
  body.addEventListener('pointercancel', end);
  $('.cinema-scrub-reset').onclick = () => { brush = [0, 1]; applyFilters(false); paintRangeCtl(); };
}

// ------------------------------------------------------------------ ticker
function pushTicker(items, front = true) {
  const fresh = items.filter((it) => !tickerItems.some((x) => x.key === it.key));
  tickerItems = front ? [...fresh, ...tickerItems] : [...tickerItems, ...fresh];
  tickerItems = tickerItems.slice(0, 40);
  renderTicker();
}
const renderTicker = debounce(() => {
  const tr = $('.cinema-ticker-track');
  if (!tickerItems.length) {
    const st = ctx.live.status();
    const msg = st.state === 'offline' ? `${st.title} ${rangeH ? `No new events in ${winWords()}.` : 'No events yet.'}`
      : st.state === 'live' ? 'Waiting for the next event…' : rangeH ? `No events in ${winWords()} yet.` : 'No events yet.';
    tr.innerHTML = `<span class="ct-item ct-muted">${esc(msg)}</span>`; return;
  }
  const one = tickerItems.map((it) => `<span class="ct-item" ${it.id ? `data-id="${esc(it.id)}"` : ''}><b style="color:${it.color}">${esc(it.kind)}</b>${esc(it.title)}<i>${esc(it.meta)}</i></span>`).join('');
  tr.innerHTML = one + one;
  const w = tr.scrollWidth / 2;
  tr.style.animationDuration = `${Math.max(40, w / 55)}s`;
  tr.querySelectorAll('[data-id]').forEach((s) => (s.onclick = () => ctx.openEvent(s.dataset.id)));
}, 600);

function evToTicker(e) {
  const m = kindMeta(e.kind);
  return { key: e.id, id: e.id, kind: m.label.toUpperCase(), color: m.color, title: e.title, meta: `${e.country ? e.country + ' · ' : ''}${hhmm(e.ts)}` };
}

// The ticker shows the same window as the globe and counters (rangeH): older items never scroll by.
const inWindow = (t) => t && (!rangeH || new Date(t).getTime() >= Date.now() - rangeH * 3600e3);
let tickerSeq = 0;
async function loadTicker() {
  const my = ++tickerSeq;
  try {
    const list = await ctx.api.events({ limit: 40, order: 'ts', since_hours: rangeH || undefined });
    if (my !== tickerSeq) return;
    tickerItems = [];
    pushTicker(list.filter((e) => inWindow(e.ts)).map(evToTicker), false);
  } catch {}
}

function paintTickerTag() {
  const tag = $('.cinema-ticker-tag');
  if (!tag) return;
  const st = ctx.live.status();
  tag.dataset.ls = st.state;
  tag.title = st.title;
  tag.querySelector('.states-tt').textContent = st.label.toUpperCase();
  if (!tickerItems.length) renderTicker();
}

// ------------------------------------------------------------------ live
function blip(sev) {
  if (!soundOn) return;
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    const o = audioCtx.createOscillator(), gn = audioCtx.createGain();
    const t = audioCtx.currentTime;
    o.type = 'sine';
    o.frequency.setValueAtTime(sev >= 0.85 ? 1320 : 990, t);
    o.frequency.exponentialRampToValueAtTime(sev >= 0.85 ? 660 : 495, t + 0.18);
    gn.gain.setValueAtTime(0.0001, t);
    gn.gain.exponentialRampToValueAtTime(0.12, t + 0.015);
    gn.gain.exponentialRampToValueAtTime(0.0001, t + 0.28);
    o.connect(gn).connect(audioCtx.destination);
    o.start(t); o.stop(t + 0.3);
  } catch {}
}

let ringFlush = null;
function scheduleRings() {
  if (ringFlush) return;
  ringFlush = setTimeout(() => { ringFlush = null; if (visible) updateRings(); }, 500);
}

function setupLive() {
  ctx.live.on('bgp_pulse', (p) => {
    bgpCount.push(Date.now());
    if (!visible || !showBgp || p.lat == null) return;
    bgpRings.push({ lat: p.lat, lng: p.lon, colorFn: ringFn('#e2c6c1', 0.9), max: 2.2, speed: 1.6, period: 0, until: Date.now() + 1800 });
    if (bgpRings.length > 30) bgpRings.shift();
    scheduleRings();
  });
  ctx.live.on('events', ({ latest }) => {
    if (!latest?.length) return;
    pushTicker(latest.slice(0, 12).filter((e) => inWindow(e.ts)).map(evToTicker));
    let added = false;
    for (const e of latest) {
      if (e.lat == null || e.lon == null || rows.some((r) => r.id === e.id)) continue;
      const r = { lng: e.lon, lat: e.lat, sev: e.severity ?? 0.4, kind: e.kind, id: e.id, title: e.title, country: e.country, t: new Date(e.ts).getTime() };
      rows.unshift(r);
      detailCache.set(e.id, e);
      added = true;
      if (r.sev >= 0.75 && activeGroups.has(groupOf(r.kind))) {
        liveRings.push({ lat: r.lat, lng: r.lng, colorFn: ringFn(sevColor(r.sev)), max: 7, speed: 3, period: 700, until: Date.now() + 12000 });
        if (!queue.find((q) => q.id === r.id)) queue.splice(qi + 1, 0, r);
        blip(r.sev);
      }
    }
    if (added && visible) { applyFilters(false); scheduleRings(); }
  });
  ctx.live.on('social', (s) => {
    pushTicker([{ key: s.url || s.title, kind: 'SOCIAL', color: kindMeta('social').color, title: s.title, meta: `${s.author ? '@' + s.author + ' · ' : ''}${hhmm(s.ts || Date.now())}` }]);
  });
}

// ------------------------------------------------------------------ controls
function setupControls() {
  $('.cinema-play').onclick = () => {
    const holding = playing && performance.now() - lastInteract <= IDLE_RESUME;
    if (holding) { lastInteract = 0; } else playing = !playing;
    G.controls().autoRotate = playing && !reducedMotion();
    updatePlayBtn();
  };
  $('.cinema-prev').onclick = () => { lastInteract = performance.now(); step(-1); };
  $('.cinema-next').onclick = () => { lastInteract = performance.now(); step(1); };
  rangeCtl = headerRange(root, { live: true, value: { h: rangeH }, label: 'Cinema time range', onChange: (v) => setCinemaRange(v.h) });
  const sb = $('.cinema-sound');
  const paintSound = () => {
    sb.classList.toggle('on', soundOn);
    sb.innerHTML = `<svg viewBox="0 0 16 16"><path d="M2.5 6h2.5l3.5-3v10L5 10H2.5z" fill="currentColor"/>${soundOn ? '<path d="M11 5.5a3.5 3.5 0 0 1 0 5M12.8 3.6a6 6 0 0 1 0 8.8" stroke="currentColor" stroke-width="1.3" fill="none"/>' : '<path d="m11 6 3.5 4M14.5 6 11 10" stroke="currentColor" stroke-width="1.3"/>'}</svg>`;
  };
  sb.onclick = () => { soundOn = !soundOn; paintSound(); if (soundOn) blip(0.9); };
  paintSound();
  $('.cinema-sun').onclick = (e) => {
    dnU.value = dnU.value ? 0 : 1;
    e.currentTarget.classList.toggle('on', !!dnU.value);
  };
  document.addEventListener('keydown', (e) => {
    if (!visible || shortcutBlocked(e)) return; // not behind the tour, drawer or entity panel, nor while typing
    if (e.key === ' ' && document.activeElement?.closest?.('button, a, [role="button"]')) return; // Space presses the focused control
    if (e.key === 'ArrowRight') { lastInteract = performance.now(); step(1); }
    else if (e.key === 'ArrowLeft') { lastInteract = performance.now(); step(-1); }
    else if (e.key === ' ') { e.preventDefault(); $('.cinema-play').click(); }
  });
}

// msg: plain text, or {title, why, acts: [[data-act, label]]} for the empty state (cause and next step).
function setStatus(msg) {
  const s = $('.cinema-status');
  s.hidden = !msg;
  s.classList.toggle('states-cin-empty', !!msg && typeof msg === 'object');
  if (!msg || typeof msg === 'string') { s.textContent = msg || ''; return; }
  s.innerHTML = `<b>${esc(msg.title)}</b><span>${esc(msg.why)}</span>${msg.acts.length ? `<span class="states-cin-acts">${msg.acts.map(([a, l]) => `<button class="src-btn" data-cact="${esc(a)}">${esc(l)}</button>`).join('')}</span>` : ''}${msg.details ? `<details class="fdesk-cin-det"><summary>Details</summary><span class="mono">${esc(msg.details)}</span></details>` : ''}`;
  s.querySelectorAll('[data-cact]').forEach((b) => (b.onclick = () => {
    if (b.dataset.cact === 'week') setCinemaRange(168);
    else if (b.dataset.cact === 'sources') location.hash = '#sources';
    else if (b.dataset.cact === 'retry') loadPoints();
  }));
}

// No geolocated events in the window: say why (offline, feeds still starting, or just a quiet window) and what to do.
function emptyStatus() {
  const st = ctx.live.status();
  const acts = [];
  if (rangeH && rangeH < 168) acts.push(['week', 'Show 7 days']);
  acts.push(['sources', 'Open Sources']);
  const why = st.state === 'offline' && ctx.live.isOffline()
    ? 'Offline mode is on, so no sources are fetched and nothing new arrives.'
    : 'Events with a location (attacks, outages, botnet servers) appear here as sources deliver them. On a new install the first ones arrive within a few minutes.';
  return { title: rangeH ? `No events on the map for ${winWords()}` : 'No events on the map yet', why, acts };
}

function resize() {
  if (!G || !root) return;
  const box = $('.cinema-globe');
  G.width(box.clientWidth).height(box.clientHeight);
  drawScrub();
}

// ------------------------------------------------------------------ view contract
registerView({
  id: 'cinema',
  mount(el, c) {
    ctx = c;
    const fromUrl = /^#\/?cinema\b/i.test(location.hash) ? hashRange(location.hash, LIVE) : null; // a link's ?range= wins
    if (fromUrl && !fromUrl.from) rangeH = fromUrl.h;
    else if (fromUrl?.from) { rangeH = presetFor(fromUrl.from); pendingWin = fromUrl; }
    buildDom(el);
    viewEl = el;
    // On a phone Cinema opens as a list of the day's events, and globe.gl loads only for "Open the globe" or
    // #cinema?kiosk (design.md §4.6). On a computer the globe starts at once, as before.
    if (isPhone()) mountPhone(el);
    onPhoneChange(phoneSync);
    if (!isPhone() || kioskHash()) startGlobe();
    else syncPhone();
    window.addEventListener('hashchange', () => { if (/^#\/?cinema\b/i.test(location.hash)) syncPhone(); });
  },
  show() { visible = true; syncPhone(); showGlobe(); },
  hide() {
    visible = false;
    if (!G) return;
    G.pauseAnimation();
    clearInterval(tickTimer);
    cancelAnimationFrame(raf);
  },
});

// ------------------------------------------------------------------ starting the globe (globe.gl on demand)
let viewEl = null;
let globeP = null;
function startGlobe() {
  return (globeP ||= need('globe').then((GlobeLib) => {
    if (isPhone()) playing = false;   // a phone's globe: no autopilot (and no sound unless turned on)
    startGlobeWith(GlobeLib);
    if (visible) showGlobe();
  }, (e) => { globeP = null; console.error(e); setStatus('3D globe library failed to load'); }));
}
function startGlobeWith(GlobeLib) {
  initGlobe(GlobeLib);
  setupControls();
  setupScrub();
  setupLive();
  renderChips();
  updatePlayBtn();
  ro = new ResizeObserver(debounce(resize, 80));
  ro.observe(root);
  loadStatic().then(() => { if (focus) { computeNearest(); updateArcs(); renderFocusCard(); } });
  loadPoints();
  loadTicker();
  paintTickerTag();
  ctx.live.onStatus(() => { paintTickerTag(); if (!rows.length && !loadErr && $('.cinema-status').classList.contains('states-cin-empty')) setStatus(emptyStatus()); });
  setInterval(() => { if (visible) renderStats(); }, 5000);
  window.addEventListener('hashchange', () => {
    const r = visible && /^#\/?cinema\b/i.test(location.hash) ? hashRange(location.hash, LIVE) : null;
    if (r && !r.from && (r.h !== rangeH || !(brush[0] <= 0.001 && brush[1] >= 0.999))) setCinemaRange(r.h);
    else if (r?.from && !sameWin(r, rangeValue())) applyWindow(r);
    else syncRangeHash();
  });
}
function showGlobe() {
  if (!visible) return;
  const r = hashRange(location.hash, LIVE);
  if (r && !r.from && r.h !== rangeH && G) setCinemaRange(r.h);
  else if (r?.from && G && !sameWin(r, rangeValue())) applyWindow(r);
  setTimeout(syncRangeHash, 0); // after the shell's own '#cinema'
  if (!G || (isPhone() && !kioskHash())) return;   // a phone's list: the globe stays paused until it is opened
  G.resumeAnimation();
  resize();
  lastTick = 0;
  clearInterval(tickTimer);
  tickTimer = setInterval(tick, 200);
  cancelAnimationFrame(raf);
  raf = requestAnimationFrame(frame);
  if (sunU) sunU.value = sunVector().v;
}

// ------------------------------------------------------------------ Cinema on a phone (design.md §4.6)
// A "Last 24 hours" list of the events on the map: the kind as a word with its dot or ring, the title, the place, the
// time and a 64x40 mini map. "Open the globe" opens #cinema?kiosk (a page of its own, so Back returns to the list),
// which loads globe.gl and shows it full screen with no autopilot.
const kioskHash = () => /^#\/?cinema\b/i.test(location.hash) && /[?&]kiosk\b/i.test(location.hash);
let phoneEl = null, phoneH = 24, phoneSeq = 0;
function mountPhone(el) {
  if (phoneEl) return;
  phoneEl = h(`<div class="cin-m">
    <div class="cin-m-head"><h2 class="cin-m-h">Last 24 hours</h2>
      <button type="button" class="m-btn m-btn-primary cin-m-open">Open the globe</button></div>
    <p class="cin-m-sub">Events with a place on the map, newest first. Tap one for its details.</p>
    <div class="cin-m-list" aria-busy="true"><div class="m-skel" style="height:72px"></div><div class="m-skel" style="height:72px"></div><div class="m-skel" style="height:72px"></div></div>
  </div>`);
  el.prepend(phoneEl);
  phoneEl.querySelector('.cin-m-open').addEventListener('click', () => { location.hash = '#cinema?kiosk'; });
  phoneEl.addEventListener('click', (e) => {
    const r = e.target.closest('[data-cin-id]');
    if (r) { ctx.openEvent?.(r.dataset.cinId, { opener: r }); return; }
    const a = e.target.closest('[data-cin-act]');
    if (a?.dataset.cinAct === 'week') { phoneH = 168; loadPhone(); }
    else if (a?.dataset.cinAct === 'day') { phoneH = 24; loadPhone(); }
  });
  loadPhone();
}
const miniMap = (lng, lat, color) => {
  const x = (((lng + 180) / 360) * 64).toFixed(1), y = (((90 - lat) / 180) * 40).toFixed(1);
  return `<svg class="cin-m-map" viewBox="0 0 64 40" width="64" height="40" aria-hidden="true"><rect width="64" height="40" rx="4" class="cin-m-map-bg"/>
    <path d="M0 20H64M16 0V40M32 0V40M48 0V40" class="cin-m-map-grid"/><circle cx="${x}" cy="${y}" r="5" fill="none" stroke="${color}" stroke-opacity=".5"/><circle cx="${x}" cy="${y}" r="2.4" fill="${color}"/></svg>`;
};
async function loadPhone() {
  if (!phoneEl) return;
  const my = ++phoneSeq;
  const list = phoneEl.querySelector('.cin-m-list');
  phoneEl.querySelector('.cin-m-h').textContent = phoneH === 24 ? 'Last 24 hours' : 'Last 7 days';
  let res;
  try { res = await ctx.api.points({ since_hours: phoneH, limit: 400 }); } catch (err) {
    if (my !== phoneSeq) return;
    list.removeAttribute('aria-busy');
    list.innerHTML = errorState({ retry: () => loadPhone(), title: "Couldn't load the events", why: 'The Night Desk server did not answer. Try again in a moment.', err: err.message, size: 'sm' });
    return;
  }
  if (my !== phoneSeq) return;
  list.removeAttribute('aria-busy');
  const ev = (res.rows || []).map((r) => ({ lng: r[0], lat: r[1], sev: r[2] ?? 0.4, kind: r[3], id: r[4], title: r[5], country: r[6], t: r[7] * 1000 }))
    .sort((a, b) => b.t - a.t).slice(0, 60);
  if (!ev.length) {
    list.innerHTML = `<div class="cin-m-empty"><p class="cin-m-et">No events on the map for the last ${phoneH === 24 ? '24 hours' : '7 days'}</p>
      <p class="cin-m-ew">${ctx.live?.isOffline?.() ? 'Offline mode is on, so no sources are fetched and nothing new arrives.' : 'Nothing with a place on the map arrived in this window.'}</p>
      ${phoneH === 24 ? '<button type="button" class="m-btn cin-m-act" data-cin-act="week">Show 7 days</button>' : '<button type="button" class="m-btn cin-m-act" data-cin-act="day">Show 24 hours</button>'}</div>`;
    return;
  }
  list.innerHTML = ev.map((e) => {
    const m = kindMeta(e.kind);
    const place = e.country ? `${flag(e.country)} ${esc(e.country)}` : `${e.lat.toFixed(1)}, ${e.lng.toFixed(1)}`;
    return `<button type="button" class="cin-m-row" data-cin-id="${esc(e.id)}">
      <span class="cin-m-txt"><span class="cin-m-kind">${kindSwatch(e.kind, 9)}${esc(m.label)}</span>
        <span class="cin-m-title">${esc(e.title || m.label)}</span>
        <span class="cin-m-meta mono">${place} · ${esc(ago(new Date(e.t)))}</span></span>
      ${miniMap(e.lng, e.lat, m.color || sevColor(e.sev))}</button>`;
  }).join('');
}
// which of the two shows: the list, or (on #cinema?kiosk, or on a computer) the globe
function syncPhone() {
  if (!viewEl) return;
  const phone = isPhone();
  const globe = !phone || kioskHash();
  viewEl.classList.toggle('cin-m-on', phone && !globe);
  viewEl.classList.toggle('cin-m-globe', phone && globe);
  if (phoneEl) phoneEl.hidden = !phone || globe;
  if (globe) startGlobe();
  else if (G) { G.pauseAnimation(); clearInterval(tickTimer); cancelAnimationFrame(raf); }
}
function phoneSync(phone) {
  if (phone) mountPhone(viewEl);
  syncPhone();
}


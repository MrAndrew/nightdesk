// Analytic chart panels: Activity Timeline, Threat Origins 3D, Top Offenders, BGP Live.
import { registerPanel } from '../core/panels.js';
import * as Tm from '../core/time.js';
import { chartTheme as T, SERIES, KINDS, kindMeta, isRing, kindDecal, kindSwatch, esc, fmt, compact, ago, flag, reducedMotion, accentColor, COUNT_RULE, countWord, feedsNote, feedsWord } from '../core/util.js';
import { emptyState, errorState } from '../core/view.js';
import { need } from '../core/libs.js';

// ------------------------------------------------------------------ shared chart vocabulary
const MONO = 'JetBrains Mono, monospace';
const C = { text: '#e9e3d4', text2: '#b7b1a2', muted: '#a29d8f', faint: '#5f5b52', line: '#222a39', panel: '#111621', panel2: '#161c28' };
const TOOLTIP = {
  backgroundColor: 'rgba(22,28,40,.97)', borderColor: '#2c3547', borderWidth: 1, padding: [8, 10],
  textStyle: { color: C.text, fontFamily: MONO, fontSize: 11 },
  extraCssText: 'box-shadow:0 14px 34px rgba(0,0,0,.65);border-radius:6px;',
};
const axisLabel = (o = {}) => ({ color: C.muted, fontFamily: MONO, fontSize: 10, ...o });
const splitLine = { lineStyle: { color: T.split, width: 1 } };
const THREAT_KINDS = Object.entries(KINDS).filter(([k, m]) => m.group === 'Threat infrastructure' && k !== 'ransomware').map(([k]) => k);
const regionName = (() => { try { const d = new Intl.DisplayNames(['en'], { type: 'region' }); return (c) => { try { return d.of(c); } catch { return c; } }; } catch { return (c) => c; } })();
const swatch = (c) => `<span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${c};margin-right:6px"></span>`;

// echarts.init is deferred until the element has a real size (panels mount before layout settles);
// calls made before then are queued and replayed in order.
function makeChart(el) {
  let chart = null;
  let q = [];
  // v1.2: also while the chart is hidden (its view or tab not on screen): drawing at 0x0 only logs "Dom has no
  // width or height", so calls wait in the queue and replay when it is shown again.
  const sized = () => el.isConnected && el.clientWidth >= 2 && el.clientHeight >= 2;
  const flush = () => { const qq = q; q = []; for (const [m, a] of qq) { if (m === 'zr') chart.getZr().on(...a); else chart[m](...a); } };
  // the library arrives on demand (core/libs.js); calls made before then wait in the queue like the unsized ones
  let dead = false;
  const init = () => {
    if (chart || !sized()) return;
    need('echarts').then((echarts) => {
      if (chart || dead || !sized()) return;
      chart = echarts.init(el, null, { renderer: 'canvas' });
      flush();
    }, (e) => console.error(e));
  };
  const ro = new ResizeObserver(() => { if (!chart) init(); else if (sized()) { flush(); chart.resize(); } });
  ro.observe(el);
  init();
  const call = (m) => (...a) => {
    if (chart && (sized() || m === 'on')) return chart[m](...a);
    if (m === 'setOption' && a[1] === true) q = q.filter(([x]) => x !== 'setOption' && x !== 'dispatchAction');
    else if (m === 'setOption' && a[1]?.replaceMerge) q = q.filter(([x, b]) => !(x === 'setOption' && b[1]?.replaceMerge));   // a full redraw: the hidden queue keeps only the newest
    q.push([m, a]);
  };
  return {
    setOption: call('setOption'), on: call('on'), dispatchAction: call('dispatchAction'),
    resize: () => { if (!chart) init(); else if (sized()) { flush(); chart.resize(); } },
    convertFromPixel: (...a) => chart?.convertFromPixel(...a),
    containPixel: (...a) => chart?.containPixel(...a) ?? false,
    getZr: () => (chart ? chart.getZr() : { on: (...a) => q.push(['zr', a]) }),
    dispose() { dead = true; ro.disconnect(); chart?.dispose(); chart = null; q = []; },
  };
}
function killChart(chart) { chart?.dispose(); }
// A load error is shown beside the chart element, never written into it: replacing its content would delete the
// ECharts DOM, and every later (successful) load would then draw into a detached chart.
function chartError(el, msg, why = 'The Night Desk server did not answer; this panel tries again on its own.') {
  let box = el.nextElementSibling;
  if (!box?.classList.contains('chart-err')) { box = document.createElement('div'); box.className = 'chart-err'; el.after(box); }
  box.innerHTML = errorState({ retry: () => location.reload(), retryLabel: 'Reload the page', title: "Couldn't draw this chart", why, err: msg, size: 'sm' });
  el.style.display = 'none';
}
function chartOk(el) {
  const box = el.nextElementSibling;
  if (box?.classList.contains('chart-err')) box.remove();
  el.style.display = '';
}
function hoursOf(store) { const h = store.get().hours; return h > 0 ? h : 24 * 90; }

// ------------------------------------------------------------------ countries GeoJSON (shared, registered once)
let geoPromise = null;
function loadGeo(api) {
  if (!geoPromise) {
    geoPromise = Promise.all([api.countries(), need('echarts')]).then(([gj, echarts]) => {
      const byIso = {};
      for (const f of gj.features) {
        const p = f.properties;
        p.name = p.NAME;
        const iso = p.ISO_A2_EH && p.ISO_A2_EH !== '-99' ? p.ISO_A2_EH : p.ISO_A2;
        if (iso && iso !== '-99') byIso[iso] = { name: p.NAME, lon: p.LABEL_X, lat: p.LABEL_Y };
      }
      echarts.registerMap('nd-countries', gj);
      echarts.registerMap('nd-countries-flat', { ...gj, features: gj.features.filter((f) => f.properties.ISO_A3 !== 'ATA') });
      return { gj, byIso };
    }).catch((e) => { geoPromise = null; throw e; });
  }
  return geoPromise;
}

// ================================================================== Activity Timeline
registerPanel({
  id: 'activity-timeline', title: 'Activity timeline', w: 8, h: 5, minW: 4, minH: 4,
  description: 'Addresses and events per hour by kind, stacked, each address counted once; brush to zoom',
  mount(body, ctx) {
    body.innerHTML = `<div class="at-root">
      <div class="at-bar"><div class="at-chips"></div><div class="at-right"><span class="at-sum"></span>
        <button class="chip at-reset" style="display:none">Reset zoom</button>
        <div class="at-mode at-scale" title="Y scale. Auto switches to log when the peak is &gt;20x the median bucket"><button data-s="lin">Lin</button><button data-s="log">Log</button></div>
        <div class="at-mode"><button data-m="bar">Bars</button><button data-m="area">Area</button></div></div></div>
      <div class="at-chart"></div></div>`;
    const $ = (s) => body.querySelector(s);
    $('.at-sum').title = COUNT_RULE;
    const chart = makeChart($('.at-chart'));
    const st = ctx.state.get();
    let hidden = new Set(st.hidden || []);
    let mode = st.mode || 'bar';
    let scale = st.scale || null; // null = auto
    let effScale = 'lin';
    body.querySelectorAll('.at-scale button').forEach((b) => (b.onclick = () => { scale = scale === b.dataset.s ? null : b.dataset.s; ctx.state.set({ scale }); render(); }));
    let model = null; // {times, kinds:[{kind,total,data}], bucketMs}
    let zoom = null;
    let reqN = 0;

    const setMode = (m) => { mode = m; ctx.state.set({ mode }); body.querySelectorAll('.at-mode:not(.at-scale) button').forEach((b) => b.classList.toggle('on', b.dataset.m === m)); render(); };
    body.querySelectorAll('.at-mode:not(.at-scale) button').forEach((b) => (b.onclick = () => setMode(b.dataset.m)));
    body.querySelectorAll('.at-mode:not(.at-scale) button').forEach((b) => b.classList.toggle('on', b.dataset.m === mode));
    const showReset = (on) => { $('.at-reset').style.display = on ? '' : 'none'; };
    $('.at-reset').onclick = () => { zoom = null; showReset(false); render(); };

    async function load() {
      const hours = hoursOf(ctx.store);
      const bucket = hours <= 6 ? 'minute' : hours <= 24 * 8 ? 'hour' : 'day';
      const my = ++reqN;
      let rows;
      try { await need('echarts'); rows = await ctx.api.timeline({ hours, bucket, q: ctx.store.get().opsQ || undefined }); } catch (e) { if (my === reqN) chartError($('.at-chart'), e.message); return; }
      if (my !== reqN) return;
      chartOk($('.at-chart'));
      // minute buckets at 6h get folded to 5-minute bins
      const bucketMs = bucket === 'minute' ? (hours <= 1 ? 60e3 : 300e3) : bucket === 'hour' ? 3600e3 : 86400e3;
      const end = Math.floor(Date.now() / bucketMs) * bucketMs;
      let start = end - Math.ceil((hours * 3600e3) / bucketMs) * bucketMs + bucketMs;
      if (ctx.store.get().hours === 0 && rows.length) start = Math.max(start, Math.floor(new Date(rows[0].t).getTime() / bucketMs) * bucketMs);
      const n = Math.max(1, Math.round((end - start) / bucketMs) + 1);
      const times = Array.from({ length: n }, (_, i) => start + i * bucketMs);
      const per = {}, adr = {};   // per kind and bucket: everything counted, and how many of those are addresses
      for (const r of rows) {
        const i = Math.floor((new Date(r.t).getTime() - start) / bucketMs);
        if (i < 0 || i >= n) continue;
        (per[r.kind] ||= new Array(n).fill(0))[i] += r.n;
        (adr[r.kind] ||= new Array(n).fill(0))[i] += r.a ?? 0;
      }
      const kinds = Object.entries(per).map(([kind, data]) => ({ kind, data, adata: adr[kind], total: data.reduce((a, b) => a + b, 0) })).sort((a, b) => b.total - a.total);
      model = { times, kinds, bucketMs };
      zoom = null; showReset(false);
      drawChips();
      render();
      ctx.setUpdated(new Date());
    }

    function drawChips() {
      const el = $('.at-chips');
      el.innerHTML = model.kinds.map(({ kind, total }) => {
        const m = kindMeta(kind);
        return `<button class="at-chip${hidden.has(kind) ? ' off' : ''}" data-k="${esc(kind)}" title="Click to toggle · double-click to solo"><span class="sw${isRing(kind) ? ' ring' : ''}" style="background:${isRing(kind) ? 'transparent' : m.color};${isRing(kind) ? `box-shadow:inset 0 0 0 2px ${m.color};` : ''}"></span>${esc(m.label)}<span class="n">${compact(total)}</span></button>`;
      }).join('') || '<span class="label">No events in range</span>';
      el.querySelectorAll('.at-chip').forEach((b) => {
        b.onclick = () => { const k = b.dataset.k; hidden.has(k) ? hidden.delete(k) : hidden.add(k); ctx.state.set({ hidden: [...hidden] }); b.classList.toggle('off'); render(); };
        b.ondblclick = () => { const k = b.dataset.k; hidden = new Set(model.kinds.map((x) => x.kind).filter((x) => x !== k)); ctx.state.set({ hidden: [...hidden] }); drawChips(); render(); };
      });
    }

    function fmtT(t) {
      if (model.bucketMs >= 86400e3) return Tm.date(t);
      return Tm.stamp(t);
    }

    function render() {
      if (!model) return;
      const vis = model.kinds.filter((k) => !hidden.has(k.kind));
      const totals = model.times.map((_, i) => vis.reduce((a, k) => a + k.data[i], 0));
      const sum = totals.reduce((a, b) => a + b, 0);
      const asum = vis.reduce((a, k) => a + k.adata.reduce((x, y) => x + y, 0), 0);
      const peakI = totals.indexOf(Math.max(...totals));
      const unit = model.bucketMs === 60e3 ? 'min' : model.bucketMs === 300e3 ? '5m' : model.bucketMs === 3600e3 ? 'h' : 'day';
      $('.at-sum').innerHTML = `<b>${esc(countWord(sum, asum))}</b> · peak <b>${fmt(totals[peakI] || 0)}</b>/${unit}${sum ? ` <span>@ ${fmtT(model.times[peakI]).slice(-6)}</span>` : ''}`;
      const inView = model.times.map((t, i) => [t, totals[i]]).filter(([t]) => !zoom || (t >= zoom[0] && t <= zoom[1]));
      const nz = inView.map(([, v]) => v).filter((v) => v > 0).sort((a, b) => a - b);
      const median = nz.length ? nz[Math.floor(nz.length / 2)] : 0;
      const autoLog = nz.length >= 2 && nz.at(-1) / Math.max(1, median) > 20;
      effScale = scale || (autoLog ? 'log' : 'lin');
      const isLog = effScale === 'log';
      body.querySelectorAll('.at-scale button').forEach((b) => { b.classList.toggle('on', b.dataset.s === effScale); b.classList.toggle('auto', !scale && b.dataset.s === effScale); });
      const yMax = zoom && !isLog ? Math.max(4, Math.ceil((nz.at(-1) || 0) * 1.1)) : null;
      const q = ctx.store.get().opsQ;
      if (q) $('.at-sum').innerHTML += ` <span>· “${esc(q)}”</span>`;
      if (isLog) $('.at-sum').innerHTML += ` <span>· log${scale ? '' : ' (auto)'}</span>`;
      const isBar = mode === 'bar';
      const barW = Math.max(1, Math.min(22, (($('.at-chart').clientWidth - 60) / Math.max(1, inView.length)) * 0.62));
      chart.setOption({
        useUTC: Tm.isUTC(),
        animationDuration: 500,
        grid: { left: 44, right: 14, top: 12, bottom: 24 },
        tooltip: {
          ...TOOLTIP, trigger: 'axis', axisPointer: { type: isBar ? 'shadow' : 'line', shadowStyle: { color: 'rgba(255,255,255,.035)' }, lineStyle: { color: '#2c3547' } },
          formatter(ps) {
            const items = ps.filter((p) => p.value[2] > 0).sort((a, b) => b.value[2] - a.value[2]);
            const tot = items.reduce((a, p) => a + p.value[2], 0);
            return `<div style="color:${C.muted};margin-bottom:5px">${fmtT(ps[0].value[0])}</div>` +
              (items.length ? items.map((p) => `<div style="display:flex;gap:14px;justify-content:space-between"><span>${kindSwatch(p.seriesId)} ${esc(kindMeta(p.seriesId).label)}</span><b>${fmt(p.value[2])}</b></div>`).join('') : '<span style="color:#6b727d">no events</span>') +
              `<div style="border-top:1px solid #2c3547;margin-top:5px;padding-top:4px;display:flex;justify-content:space-between"><span style="color:${C.muted}">TOTAL</span><b>${fmt(tot)}</b></div>`;
          },
        },
        brush: { toolbox: [], xAxisIndex: 0, brushType: 'lineX', brushMode: 'single', transformable: false, throttleType: 'debounce', throttleDelay: 300,
          brushStyle: { color: echarts.color.modifyAlpha(accentColor(), 0.08), borderColor: echarts.color.modifyAlpha(accentColor(), 0.5), borderWidth: 1 }, outOfBrush: { colorAlpha: 0.35 } },
        toolbox: { show: false },
        xAxis: {
          type: 'time', min: zoom ? zoom[0] : model.times[0] - model.bucketMs / 2, max: zoom ? zoom[1] : model.times.at(-1) + model.bucketMs / 2,
          axisLine: { lineStyle: { color: T.axisLine } }, axisTick: { show: false }, splitLine: { show: false },
          axisLabel: axisLabel({ hideOverlap: true, formatter: { day: '{MMM} {d}', hour: '{HH}:{mm}', minute: '{HH}:{mm}', month: '{MMM}' } }),
        },
        yAxis: isLog
          ? { type: 'value', min: 0, max: Math.max(1, Math.ceil(Math.log10(1 + Math.max(1, ...inView.map(([, v]) => v))))), interval: 1, axisLabel: axisLabel({ formatter: (v) => (v ? compact(10 ** v) : '0') }), splitLine, axisLine: { show: false } }
          : { type: 'value', min: 0, interval: null, minInterval: 1, splitNumber: 3, max: yMax, axisLabel: axisLabel({ formatter: (v) => compact(v) }), splitLine, axisLine: { show: false } },
        series: vis.map((k) => {
          const col = kindMeta(k.kind).color;
          return {
            id: k.kind, name: kindMeta(k.kind).label, type: isBar ? 'bar' : 'line', stack: 'all',
            data: k.data.map((v, i) => [model.times[i], isLog ? (totals[i] ? (Math.log10(1 + totals[i]) * v) / totals[i] : 0) : v, v]),
            barWidth: barW, barCategoryGap: '20%', large: false,
            // ring kinds (second of a hue pair) are hatched as bars and dashed as lines
            itemStyle: { color: col, borderColor: C.panel, borderWidth: isBar && barW > 3 ? 0.5 : 0, decal: kindDecal(k.kind) },
            emphasis: { focus: 'series' },
            symbol: 'none', smooth: 0.25, lineStyle: { width: 1.2, color: col, type: isRing(k.kind) ? [4, 3] : 'solid' },
            areaStyle: isBar ? undefined : { color: col, opacity: isRing(k.kind) ? 0.1 : 0.22 },
            clip: true,
          };
        }),
      }, { replaceMerge: ['series'] });
      chart.dispatchAction({ type: 'takeGlobalCursor', key: 'brush', brushOption: { brushType: 'lineX', brushMode: 'single' } });
    }

    chart.on('brushEnd', (e) => {
      const r = e.areas?.[0]?.coordRange;
      chart.dispatchAction({ type: 'brush', areas: [] });
      if (!r || Math.abs(r[1] - r[0]) < (model?.bucketMs || 0) * 1.5) return;
      zoom = [Math.min(...r), Math.max(...r)];
      showReset(true);
      render();
    });

    load();
    const timer = setInterval(load, 5 * 60e3);
    return {
      refresh: load,
      resize() { chart.resize(); if (model) render(); },
      destroy() { clearInterval(timer); killChart(chart); },
    };
  },
});

// ================================================================== Threat Origins 3D
// Drawn with globe.gl (vendored, as Cinema), not echarts-gl: echarts-gl compiles code with eval (new Function), which the
// page's Content-Security-Policy refuses (okf/architecture/deployment.md#content-security-policy).
const G3_RAMP = ['#5f5b52', '#4ea1b0', '#b4957b', '#e4a84c', '#f08a3c'];
function lerpHex(t, stops) {
  const x = Math.min(1, Math.max(0, t)) * (stops.length - 1), i = Math.min(stops.length - 2, Math.floor(x)), f = x - i;
  const c = (h) => [1, 3, 5].map((k) => parseInt(h.slice(k, k + 2), 16));
  const [a, b] = [c(stops[i]), c(stops[i + 1])];
  return '#' + a.map((v, k) => Math.round(v + (b[k] - v) * f).toString(16).padStart(2, '0')).join('');
}
registerPanel({
  id: 'attack-globe3d', title: 'Threat origins 3D', w: 6, h: 7, minW: 4, minH: 5,
  description: 'Malicious-IP origins per country as 3D bars or raised countries on a globe',
  mount(body, ctx) {
    body.innerHTML = `<div class="g3-root">
      <div class="g3-chart"></div>
      <div class="g3-tl"><div class="g3-mode"><button data-m="globe">Bars</button><button data-m="map">Raised countries</button></div>
        <button class="g3-spin on" title="Auto-rotate">⟳ Rotate</button></div>
      <div class="g3-side"><div class="label">Top origins</div><div class="g3-list"></div></div>
      <div class="g3-legend"><div class="label">Avg severity</div><div class="g3-ramp"></div><div class="g3-ramp-l"><span></span><span></span></div>
        <div class="g3-note"></div></div>
    </div>`;
    const $ = (s) => body.querySelector(s);
    const el = $('.g3-chart');
    let mode = ctx.state.get().mode === 'map' ? 'map' : 'globe';
    // reduced motion: start still whatever was saved; the Rotate button can still turn it on
    let spin = reducedMotion() ? false : (ctx.state.get().spin ?? true);
    let geo = null, rows = [], byCc = new Map(), max = 1, G = null, hover = null, disposed = false, reqN = 0, aimed = false;
    let sevRange = [0, 1];
    const sevCol = (s) => { const [a, b] = sevRange; return lerpHex(b > a ? (s - a) / (b - a) : 0.5, G3_RAMP); };
    const isoOf = (f) => { const p = f.properties; return p.ISO_A2_EH && p.ISO_A2_EH !== '-99' ? p.ISO_A2_EH : p.ISO_A2; };
    const setModeBtns = () => body.querySelectorAll('.g3-mode button').forEach((b) => b.classList.toggle('on', b.dataset.m === mode));
    setModeBtns();
    $('.g3-spin').classList.toggle('on', spin);
    body.querySelectorAll('.g3-mode button').forEach((b) => (b.onclick = () => { mode = b.dataset.m; ctx.state.set({ mode }); setModeBtns(); render(); }));
    $('.g3-spin').onclick = () => { spin = !spin; ctx.state.set({ spin }); $('.g3-spin').classList.toggle('on', spin); if (G) G.controls().autoRotate = spin; };

    function tipHtml(r) {
      const ks = Object.entries(r.kinds || {}).sort((a, b) => b[1] - a[1]);
      return `<div class="g3-tip"><div style="font-weight:600;margin-bottom:5px">${flag(r.country)} ${esc(geo.byIso[r.country]?.name || regionName(r.country))} <span style="color:${C.muted}">${esc(r.country)}</span></div>
        <div style="display:flex;justify-content:space-between;gap:16px"><span style="color:${C.muted}">EVENTS</span><b>${fmt(r.n)}</b></div>
        <div style="display:flex;justify-content:space-between;gap:16px;margin-bottom:5px"><span style="color:${C.muted}">AVG SEV</span><b style="color:${sevCol(r.sev)}">${Math.round((r.sev || 0) * 100)}</b></div>
        ${ks.map(([k, n]) => `<div style="display:flex;justify-content:space-between;gap:16px"><span>${kindSwatch(k)} ${esc(kindMeta(k).label)}</span><span>${fmt(n)}</span></div>`).join('')}</div>`;
    }
    const sized = () => el.isConnected && el.clientWidth >= 2 && el.clientHeight >= 2;
    const h = (r) => Math.sqrt(r.n / max);
    const pointCol = (r) => (hover === r ? '#ffffff' : sevCol(r.sev));
    const capCol = (f) => { const r = byCc.get(isoOf(f)); return r && hover === r ? '#ffffff' : !r ? '#161c28' : mode === 'map' ? sevCol(r.sev) : lerpHex(h(r), ['#1d2230', '#4a3f2a']); };

    function makeGlobe(GlobeLib) {
      G = GlobeLib({ rendererConfig: { antialias: true, alpha: true }, animateIn: false })(el)
        .width(el.clientWidth).height(el.clientHeight).backgroundColor('rgba(0,0,0,0)')
        .showAtmosphere(true).atmosphereColor('#c98f3a').atmosphereAltitude(0.16)
        .polygonCapColor(capCol).polygonSideColor(() => 'rgba(58,63,74,.55)').polygonStrokeColor(() => '#3a3f4a')
        .polygonAltitude((f) => { const r = byCc.get(isoOf(f)); return mode === 'map' && r ? 0.01 + h(r) * 0.12 : 0.004; })
        .polygonLabel((f) => { const r = byCc.get(isoOf(f)); return r ? tipHtml(r) : `<div class="g3-tip">${esc(f.properties.NAME || '')}</div>`; })
        .onPolygonHover((f) => { hover = f ? byCc.get(isoOf(f)) || null : null; G.polygonCapColor((x) => capCol(x)); })
        .polygonsTransitionDuration(400)
        .pointLat((r) => geo.byIso[r.country].lat).pointLng((r) => geo.byIso[r.country].lon)
        .pointAltitude((r) => 0.01 + h(r) * 0.35).pointRadius(0.9).pointResolution(8)
        .pointColor(pointCol).pointLabel(tipHtml)
        .onPointHover((r) => { hover = r || null; G.pointColor((x) => pointCol(x)); })
        .pointsTransitionDuration(400);
      G.globeMaterial().color.set('#0a0d12');
      const c = G.controls();
      c.autoRotate = spin; c.autoRotateSpeed = 0.6; c.enableDamping = true; c.minDistance = 140; c.maxDistance = 600;
    }

    function render() {
      if (!geo || !G) return;
      max = Math.max(1, ...rows.map((r) => r.n));
      byCc = new Map(rows.filter((r) => geo.byIso[r.country]).map((r) => [r.country, r]));
      G.polygonsData(geo.gj.features).pointsData(mode === 'globe' ? [...byCc.values()] : []);
      if (!aimed) { aimed = true; G.pointOfView({ lat: 25, lng: 20, altitude: 2.5 }, 0); }
      // side ranking + legend
      $('.g3-list').innerHTML = rows.slice(0, 8).map((r, i) => `<div class="g3-item" title="${esc(Object.entries(r.kinds || {}).map(([k, n]) => `${kindMeta(k).label}: ${n}`).join('\n'))}">
        <span class="g3-rk">${String(i + 1).padStart(2, '0')}</span><span class="g3-cc">${flag(r.country)} ${esc(r.country)}</span>
        <span class="g3-bar"><span style="width:${(r.n / max) * 100}%;background:${sevCol(r.sev)}"></span></span><span class="g3-n">${compact(r.n)}</span></div>`).join('') || '<div class="label">No data</div>';
      $('.g3-ramp').style.background = `linear-gradient(90deg, ${G3_RAMP.join(',')})`;
      const [a, b] = sevRange;
      const ls = body.querySelectorAll('.g3-ramp-l span'); ls[0].textContent = Math.round(a * 100); ls[1].textContent = Math.round(b * 100);
      const total = rows.reduce((s, r) => s + r.n, 0);
      $('.g3-note').textContent = `${fmt(total)} events · ${rows.length} countries · ${mode === 'globe' ? 'bar' : 'height'} ∝ √count`;
    }

    // the globe is made once the panel has a real size (panels mount before layout settles, and hidden ones stay 0x0)
    let lib = null;
    const ro = new ResizeObserver(() => {
      if (!sized() || disposed) return;
      if (!G && lib) { try { makeGlobe(lib); render(); } catch (e) { libError(e); } } else if (G) G.width(el.clientWidth).height(el.clientHeight);
    });
    ro.observe(el);
    const libError = (e) => chartError(el, e.message || String(e), "The 3D globe couldn't be drawn here: the globe library didn't load, or this browser can't draw 3D (WebGL is off).");

    async function load() {
      const my = ++reqN;
      try {
        lib ||= await need('globe');
      } catch (e) { if (!disposed) libError(e); return; }
      try {
        const [g, data] = await Promise.all([loadGeo(ctx.api), ctx.api.byCountry({ since_hours: ctx.store.sinceHours(), kinds: THREAT_KINDS })]);
        if (my !== reqN || disposed) return;
        chartOk(el);
        geo = g; rows = data;
        const sevs = rows.filter((r) => r.sev != null).map((r) => r.sev);
        sevRange = sevs.length ? [Math.min(...sevs), Math.max(...sevs)] : [0, 1];
        if (sevRange[1] - sevRange[0] < 0.05) sevRange = [Math.max(0, sevRange[0] - 0.05), Math.min(1, sevRange[1] + 0.05)];
        ctx.setBadge(`${rows.length} CC`);
        if (!G && sized()) makeGlobe(lib);
        render();
        ctx.setUpdated(new Date());
      } catch (e) {
        if (my === reqN && !disposed) chartError(el, e.message);
      }
    }

    load();
    const timer = setInterval(load, 5 * 60e3);
    return {
      refresh: load,
      resize() { if (G && sized()) G.width(el.clientWidth).height(el.clientHeight); },
      destroy() {
        disposed = true; clearInterval(timer); ro.disconnect();
        if (G) { G.pauseAnimation(); G.renderer().dispose(); G.renderer().forceContextLoss?.(); G._destructor?.(); G = null; }
        el.replaceChildren();
      },
    };
  },
});

// ================================================================== Top Offenders
const sameColor = (a, b) => String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
const TABS = [
  { id: 'asn', label: 'ASN', field: 'asn', color: SERIES[1] },
  { id: 'country', label: 'Country', field: 'country', color: SERIES[0] },
  { id: 'tags', label: 'Tag', field: 'tags', color: SERIES[2] },
  { id: 'ip', label: 'IP', field: 'ip', color: SERIES[3] },
];
const sevWord = (v) => (v == null ? '' : v >= 0.85 ? 'Critical' : v >= 0.65 ? 'High' : v >= 0.4 ? 'Medium' : 'Low');
// The IP tab's "N feeds" detail: every feed that listed the address in the window, newest listing first.
const feedsTip = (r) => `<b>Listed by ${feedsWord(r.feeds)}</b>${(r.sources || []).map((x) => `<div class="to-tip-r"><span>${esc(x.name || x.source)}</span><span class="mono">${x.last ? `last listed ${esc(ago(x.last))}` : ''}</span></div>`).join('')}<div class="to-tip-n">${esc(r.feeds > 1 ? feedsNote(r.feeds) : 'Only one feed lists this address in the window.')}</div>`;
const orgCache = new Map();
async function asnOrgs(api, keys) {
  const need = keys.filter((k) => /^AS\d+$/.test(k) && !orgCache.has(k));
  if (need.length) {
    try {
      for (let i = 0; i < need.length; i += 200) {
        const r = await api.asnOrgs(need.slice(i, i + 200));
        for (const [asn, org] of Object.entries(r.orgs || {})) orgCache.set(asn, org || '');
      }
    } catch {}
    need.forEach((k) => { if (!orgCache.has(k)) orgCache.set(k, ''); });
  }
}
registerPanel({
  id: 'top-offenders', title: 'Top offenders', w: 6, h: 7, minW: 3, minH: 4,
  description: 'Ranked ASNs, countries, tags and addresses, each address counted once; click a row to search',
  mount(body, ctx) {
    body.innerHTML = `<div class="to-root">
      <div class="to-bar"><div class="to-tabs">${TABS.map((t) => `<button data-t="${t.id}">${t.label}</button>`).join('')}</div>
        <div class="to-scope"><button data-s="threat" title="Threat-infrastructure kinds only">Threat</button><button data-s="all">All events</button></div></div>
      <div class="to-head"><span>#</span><span class="to-hk">ASN</span><span class="to-hn">Counted · share</span>
        <div class="to-sort" role="group" aria-label="Rank addresses by"><span>Rank by</span><button data-o="n" title="The highest severity any feed gives the address first">Severity</button><button data-o="feeds" title="The address most feeds list first">Feeds</button></div></div>
      <div class="to-chart"></div><div class="to-list" hidden></div><div class="to-foot"></div></div>`;
    const $ = (s) => body.querySelector(s);
    const chart = makeChart($('.to-chart'));
    $('.to-hn').title = COUNT_RULE;
    let tab = TABS.some((t) => t.id === ctx.state.get().tab) ? ctx.state.get().tab : 'asn';
    let scope = ctx.state.get().scope || 'threat';
    let ipSort = ctx.state.get().ipSort === 'feeds' ? 'feeds' : 'n';   // the IP tab: severity first (as the API ranks), or by feeds
    let rows = [], total = 0, totalA = 0, reqN = 0;
    // one hover/focus card for the IP tab's "N feeds" chips, in <body> so the scrolling list never clips it
    const tip = document.createElement('div');
    tip.className = 'to-tip'; tip.id = `to-tip-${Math.random().toString(36).slice(2, 8)}`; tip.setAttribute('role', 'tooltip'); tip.hidden = true;
    document.body.append(tip);
    // Hover (mouse) or keyboard focus shows it for a moment; a click or tap pins it open, and a second click or tap on
    // the same chip, a tap anywhere else, Escape, Tab away or a scroll closes it. (Hover and focus never toggle, so the
    // first tap on a phone, which also focuses the chip, opens the card rather than closing it.)
    let owner = null, pinned = false;
    const hideTip = () => { tip.hidden = true; owner = null; pinned = false; };
    $('.to-list').addEventListener('scroll', hideTip, { passive: true });
    const outside = (e) => { if (!tip.hidden && !e.target.closest?.('.to-fn')) hideTip(); };
    const onEsc = (e) => { if (e.key === 'Escape' && !tip.hidden) { e.stopPropagation(); hideTip(); } };   // closes only the card
    document.addEventListener('pointerdown', outside, true);
    document.addEventListener('keydown', onEsc, true);
    const showTip = (btn) => {
      const r = rows[Number(btn.dataset.i)]; if (!r) return;
      if (owner !== btn) pinned = false;
      owner = btn;
      tip.innerHTML = feedsTip(r); tip.hidden = false;
      const b = btn.getBoundingClientRect(), w = tip.offsetWidth, hh = tip.offsetHeight;
      const left = Math.max(8, Math.min(innerWidth - w - 8, b.right - w));
      const top = b.bottom + 6 + hh > innerHeight - 8 ? Math.max(8, b.top - hh - 6) : b.bottom + 6;
      tip.style.left = `${left}px`; tip.style.top = `${top}px`;
    };
    const sync = () => {
      body.querySelectorAll('.to-tabs button').forEach((b) => b.classList.toggle('on', b.dataset.t === tab));
      body.querySelectorAll('.to-scope button').forEach((b) => b.classList.toggle('on', b.dataset.s === scope));
      body.querySelectorAll('.to-sort button').forEach((b) => { b.classList.toggle('on', b.dataset.o === ipSort); b.setAttribute('aria-pressed', String(b.dataset.o === ipSort)); });
      $('.to-hk').textContent = tab === 'ip' ? 'Address' : TABS.find((t) => t.id === tab).label;
      $('.to-hn').textContent = tab === 'ip' ? 'Feeds' : 'Counted · share';
      $('.to-root').classList.toggle('to-ipmode', tab === 'ip');
      $('.to-chart').hidden = tab === 'ip'; $('.to-list').hidden = tab !== 'ip';
      hideTip();
    };
    body.querySelectorAll('.to-tabs button').forEach((b) => (b.onclick = () => { tab = b.dataset.t; ctx.state.set({ tab }); rows = []; sync(); load(); }));
    body.querySelectorAll('.to-scope button').forEach((b) => (b.onclick = () => { scope = b.dataset.s; ctx.state.set({ scope }); sync(); load(); }));
    body.querySelectorAll('.to-sort button').forEach((b) => (b.onclick = () => { ipSort = b.dataset.o; ctx.state.set({ ipSort }); sync(); load(); }));
    sync();

    const lim = () => Math.max(5, Math.min(25, Math.floor(($('.to-chart').clientHeight || 300) / 31)));
    const labelOf = (k) => {
      if (tab === 'country') return `${flag(k)} ${k}  ${regionName(k)}`;
      if (tab === 'asn') { const o = orgCache.get(k); return o ? `${k}  ${o.length > 34 ? o.slice(0, 33) + '…' : o}` : k; }
      return k;
    };
    const share = (n) => (total ? (n / total) * 100 : 0);
    const pct = (n) => { const v = share(n); return v >= 10 ? v.toFixed(0) + '%' : v >= 0.1 ? v.toFixed(1) + '%' : '<0.1%'; };

    // The IP tab is a plain list (focusable rows; the feed names on hover or focus of the "N feeds" chip).
    function renderIps() {
      const q = (ctx.store.get().opsQ || '').toLowerCase();
      const max = Math.max(1, ...rows.map((r) => r.feeds || 0));
      const list = $('.to-list');
      list.innerHTML = rows.length ? rows.map((r, i) => `<div class="to-ip${q && r.key.toLowerCase() === q ? ' sel' : ''}">
          <span class="to-rk mono">${String(i + 1).padStart(2, '0')}</span>
          <button class="to-a mono" data-k="${esc(r.key)}" title="Search for ${esc(r.key)}">${esc(r.key)}</button>
          <span class="to-cc mono">${r.country ? `${flag(r.country)} ${esc(r.country)}` : ''}</span>
          <span class="to-sv" title="${r.sev == null ? '' : `The highest severity any feed gives it: ${Math.round(r.sev * 100)} out of 100`}">${esc(sevWord(r.sev))}</span>
          <span class="to-fb" aria-hidden="true"><i style="width:${((100 * (r.feeds || 0)) / max).toFixed(0)}%"></i></span>
          <button class="to-fn mono" data-i="${i}" aria-describedby="${tip.id}" aria-label="${esc(`${feedsWord(r.feeds)}: ${(r.sources || []).map((x) => x.name || x.source).join(', ')}`)}">${esc(feedsWord(r.feeds))}</button>
        </div>`).join('') : '';
      list.querySelectorAll('.to-a').forEach((b) => (b.onclick = () => pick(b.dataset.k)));
      list.querySelectorAll('.to-fn').forEach((b) => {
        b.onpointerenter = (e) => { if (e.pointerType === 'mouse' && !pinned) showTip(b); };
        b.onpointerleave = (e) => { if (e.pointerType === 'mouse' && !pinned && document.activeElement !== b) hideTip(); };
        b.onfocus = () => { if (owner !== b) showTip(b); };
        b.onblur = () => { if (owner === b) hideTip(); };
        b.onclick = () => { if (owner === b && pinned && !tip.hidden) hideTip(); else { showTip(b); pinned = true; } };
        b.onkeydown = (e) => { if (e.key === 'Escape' && !tip.hidden) { e.stopPropagation(); hideTip(); } };
      });
      const hrs = ctx.store.get().hours;
      $('.to-foot').textContent = rows.length
        ? `${rows.length} addresses, each counted once · ranked by ${ipSort === 'feeds' ? 'feeds' : 'severity'} · ${scope === 'threat' ? 'threat infrastructure' : 'all kinds'} · ${hrs ? hrs + 'h' : 'all time'}`
        : 'no addresses in range';
    }

    function render() {
      if (tab === 'ip') return renderIps();
      const t = TABS.find((x) => x.id === tab);
      const q = (ctx.store.get().opsQ || '').toLowerCase();
      const max = Math.max(1, ...rows.map((r) => r.n));
      const w = $('.to-chart').clientWidth;
      const h = $('.to-chart').clientHeight;
      const rowH = Math.max(18, Math.min(30, h / Math.max(rows.length, 1)));
      const trackW = Math.max(120, Math.min(w - 120, 440));
      // The row your search matches: an amber bar among teal, tan or violet ones; on the Country tab, whose bars are
      // the amber accent themselves, the near-white text colour (13:1 on the panel, clearly apart from amber, not red).
      const matchC = sameColor(t.color, accentColor()) ? C.text : accentColor();
      chart.setOption({
        animationDuration: 500,
        grid: { left: 8, top: 18, bottom: 4, width: trackW, containLabel: false },
        tooltip: { ...TOOLTIP, trigger: 'item', formatter: (p) => `<b>${esc(labelOf(rows[p.dataIndex].key))}</b><br><span style="color:${C.muted}">${esc(countWord(p.value, rows[p.dataIndex].a))} · ${pct(p.value)} of ${esc(countWord(total, totalA))} in scope</span><br><span style="color:${C.faint}">click to search</span>` },
        xAxis: { type: 'value', max, show: false },
        yAxis: {
          type: 'category', inverse: true, data: rows.map((r) => r.key), axisLine: { show: false }, axisTick: { show: false },
          axisLabel: {
            inside: true, verticalAlign: 'bottom', padding: [0, 0, 9, 24], color: C.text, fontFamily: MONO, fontSize: 11, align: 'left',
            formatter: (k, i) => {
              const lbl = labelOf(k); const sp = lbl.indexOf('  ');
              const main = sp > 0 && tab === 'asn' ? lbl.slice(0, sp) : lbl, rest = sp > 0 && tab === 'asn' ? lbl.slice(sp) : '';
              const sel = q && k.toLowerCase() === q;
              return `{rk|${String(i + 1).padStart(2, '0')}}{${sel ? 'ks' : 'k'}|${main}}${rest ? `{o|${rest}}` : ''}`;
            },
            rich: {
              rk: { color: C.faint, fontFamily: MONO, fontSize: 10, width: 24, padding: [0, 0, 0, -24] },
              k: { color: C.text, fontFamily: MONO, fontSize: 11 }, ks: { color: accentColor(), fontFamily: MONO, fontSize: 11, fontWeight: 600 },
              o: { color: C.muted, fontFamily: MONO, fontSize: 10.5 },
            },
          },
          z: 10,
        },
        series: [{
          type: 'bar', barWidth: Math.max(3, Math.min(5, rowH * 0.2)), barCategoryGap: 0, cursor: 'pointer',
          // hover lifts a bar's own colour a little, so a hovered bar never looks like the match
          data: rows.map((r) => { const c = q && r.key.toLowerCase() === q ? matchC : t.color;
            return { value: r.n, itemStyle: { color: c, borderRadius: 2 }, emphasis: { itemStyle: { color: echarts.color.lift(c, 0.15) } } }; }),
          showBackground: true, backgroundStyle: { color: '#161c28', borderRadius: 2 },
          label: {
            show: true, position: 'right', distance: 8, fontFamily: MONO,
            formatter: (p) => `{v|${fmt(p.value)}}  {s|${pct(p.value)}}`,
            rich: { v: { color: C.text, fontFamily: MONO, fontSize: 11, fontWeight: 600 }, s: { color: C.muted, fontFamily: MONO, fontSize: 10 } },
          },
          labelLayout: { hideOverlap: false },
        }],
      }, true);
      const top = rows.reduce((a, r) => a + r.n, 0);
      const hrs = ctx.store.get().hours;
      $('.to-foot').textContent = rows.length
        ? `top ${rows.length} = ${tab === 'tags' ? 'tag hits' : pct(top) + ' of'} ${tab === 'tags' ? fmt(top) + ' on ' + countWord(total, totalA) : countWord(total, totalA)} · ${scope === 'threat' ? 'threat infrastructure' : 'all kinds'} · ${hrs ? hrs + 'h' : 'all time'}`
        : 'no data in range';
    }

    async function load() {
      const my = ++reqN;
      const kinds = scope === 'threat' ? THREAT_KINDS : undefined;
      const since_hours = ctx.store.sinceHours();
      try {
        await need('echarts');
        const [data, byKind] = await Promise.all([
          ctx.api.top({ field: TABS.find((t) => t.id === tab).field, kinds, since_hours, limit: tab === 'ip' ? 25 : lim(), ...(tab === 'ip' ? { sort: ipSort } : {}) }),
          ctx.api.top({ field: 'kind', kinds, since_hours, limit: 100 }),
        ]);
        if (tab === 'asn') await asnOrgs(ctx.api, data.map((r) => r.key));
        if (my !== reqN) return;
        hideTip();
        rows = data;
        total = byKind.reduce((a, r) => a + r.n, 0);
        totalA = byKind.reduce((a, r) => a + (r.a ?? 0), 0);
        render();
        ctx.setUpdated(new Date());
      } catch (e) { $('.to-foot').textContent = e.message; }
    }

    const pick = (key) => {
      const next = (ctx.store.get().opsQ || '').toLowerCase() === key.toLowerCase() ? '' : key;
      const inp = document.getElementById('global-search'); if (inp) inp.value = next;
      ctx.store.set({ opsQ: next });
    };
    chart.on('click', (p) => { if (p.componentType === 'series') { const key = rows[p.dataIndex]?.key; if (key) pick(key); } });
    chart.getZr().on('click', (e) => {
      if (e.target) return;
      const pt = [e.offsetX, e.offsetY];
      const idx = chart.convertFromPixel({ yAxisIndex: 0 }, pt);
      const key = rows[Math.round(idx)]?.key; if (key && e.offsetY > 10) pick(key);
    });

    load();
    const timer = setInterval(load, 5 * 60e3);
    let lastHours = ctx.store.get().hours;
    return {
      refresh() { if (ctx.store.get().hours !== lastHours) { lastHours = ctx.store.get().hours; load(); } else render(); },
      resize() { chart.resize(); if (rows.length) render(); },
      destroy() {
        clearInterval(timer); killChart(chart); tip.remove();
        document.removeEventListener('pointerdown', outside, true); document.removeEventListener('keydown', onEsc, true);
      },
    };
  },
});

// ================================================================== BGP Live
const BGP_SERIES = [
  { name: 'bgp.updates_per_s', label: 'Updates', color: SERIES[0] },
  { name: 'bgp.announcements_per_s', label: 'Announce', color: SERIES[5] },
  { name: 'bgp.withdrawals_per_s', label: 'Withdraw', color: SERIES[1] },
];
const BGP_KINDS = ['bgp_origin_change', 'bgp_withdrawal_burst'];
registerPanel({
  id: 'bgp-live', title: 'BGP live', w: 4, h: 4, minW: 3, minH: 4,
  description: 'Live routing update rates for the networks in Routing watch (RIS Live, off unless you turn it on); older data may also list origin changes and withdrawal bursts',
  mount(body, ctx) {
    body.innerHTML = `<div class="bg-root">
      <div class="bg-kpis">${BGP_SERIES.map((s) => `<div class="bg-kpi" data-n="${s.name}"><div class="bg-kl"><span class="sw" style="background:${s.color}"></span>${s.label}<span class="u">/s</span></div><div class="bg-kv">—</div><div class="bg-kd"></div></div>`).join('')}</div>
      <div class="bg-cw"><div class="bg-chart"></div><div class="bg-nodata mono" hidden>No BGP update rates in the last hour</div></div>
      <div class="bg-list"></div></div>`;
    const $ = (s) => body.querySelector(s);
    const chart = makeChart($('.bg-chart'));
    const offBadge = ctx.live.badge(ctx, 'ris_live'); // shared Live / Idle / Offline status, never a bare LIVE
    const series = Object.fromEntries(BGP_SERIES.map((s) => [s.name, []]));
    let events = [], pending = false, disposed = false;
    const WINDOW = 60 * 60e3;

    function drawChart() {
      pending = false;
      if (disposed) return;
      if (BGP_SERIES.some((s) => series[s.name].length)) chartOk($('.bg-chart')); // live metrics arrived after a failed history load
      const now = Date.now();
      for (const k in series) { const a = series[k]; while (a.length && a[0][0] < now - WINDOW) a.shift(); }
      // fit the x-domain to what exists (metrics only go back to the last server start)
      const first = Math.min(...BGP_SERIES.map((s) => series[s.name][0]?.[0] ?? now));
      const xMin = Math.min(Math.max(now - WINDOW, first), now - 5 * 60e3);
      // robust upper bound so a reconnect burst doesn't flatten the trace; tooltip shows true values
      const robust = (names) => {
        const v = names.flatMap((n) => series[n].map((p) => p[1])).sort((x, y) => x - y);
        if (!v.length) return 10;
        const p = Math.max(v[Math.floor(v.length * 0.95)] * 1.1, v[Math.floor(v.length / 2)] * 2);
        const m = 10 ** Math.floor(Math.log10(Math.max(1, p * 1.2)));
        return Math.ceil((p * 1.2) / m) * m;
      };
      const top = ['bgp.updates_per_s', 'bgp.announcements_per_s'];
      const yTop = robust(top), yBot = robust(['bgp.withdrawals_per_s']);
      const H = $('.bg-chart').clientHeight;
      const botH = Math.max(18, Math.round((H - 44) * 0.32));
      // An empty chart draws no axis or grid lines, so its "no data" text (centred over both grids) has none through it.
      const xAx = (i) => ({ gridIndex: i, type: 'time', min: xMin, max: now, axisLine: { show: !empty, lineStyle: { color: T.axisLine } }, axisTick: { show: false }, splitLine: { show: false },
        axisLabel: i === 1 ? axisLabel({ fontSize: 9, hideOverlap: true, formatter: '{HH}:{mm}' }) : { show: false }, splitNumber: 4 });
      // An empty grid gets no scale label (both would read the default "10"); an empty chart says so instead.
      const has = (names) => names.some((n) => series[n].length);
      const hasTop = has(top), hasBot = has(['bgp.withdrawals_per_s']);
      const empty = !(hasTop || hasBot);
      $('.bg-nodata').hidden = !empty;
      if (empty) { const st = ctx.live.status('ris_live'); $('.bg-nodata').textContent = `No BGP update rates in the last hour${st.state === 'live' ? '' : ` · ${st.title}`}`; }
      const yAx = (i, max, name, show) => ({ gridIndex: i, type: 'value', min: 0, max, interval: max, axisLine: { show: false }, splitLine: empty ? { show: false } : splitLine,
        axisLabel: axisLabel({ show, fontSize: 9, formatter: (v) => (v ? compact(v) : '') }),
        name, nameLocation: 'end', nameGap: 4, nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 8.5, align: 'left', padding: [0, 0, 0, -30] } });
      chart.setOption({
        useUTC: Tm.isUTC(),
        animation: false,
        legend: { top: 0, right: 8, itemWidth: 10, itemHeight: 2, itemGap: 10, icon: 'rect', selectedMode: false,
          textStyle: { color: C.muted, fontFamily: MONO, fontSize: 9 }, data: BGP_SERIES.map((s) => s.label) },
        grid: [{ left: 36, right: 16, top: 16, bottom: botH + 26 }, { left: 36, right: 16, height: botH, bottom: 16 }],
        tooltip: { ...TOOLTIP, trigger: 'axis', axisPointer: { type: 'line', link: [{ xAxisIndex: 'all' }], lineStyle: { color: '#2c3547' } },
          formatter: (ps) => `<div style="color:${C.muted};margin-bottom:4px">${Tm.time(ps[0].value[0], { seconds: true })} ${Tm.zoneName(ps[0].value[0])}</div>` + ps.map((p) => `<div style="display:flex;justify-content:space-between;gap:14px"><span>${swatch(p.color)}${p.seriesName}</span><b>${p.value[1].toFixed(1)}/s</b></div>`).join('') },
        axisPointer: { link: [{ xAxisIndex: 'all' }] },
        xAxis: [xAx(0), xAx(1)],
        yAxis: [yAx(0, yTop, '', hasTop), yAx(1, yBot, '', hasBot)],
        series: BGP_SERIES.map((s, i) => ({
          id: s.name, name: s.label, type: 'line', showSymbol: false, symbol: 'circle', symbolSize: 5, sampling: 'lttb', clip: true,
          xAxisIndex: i === 2 ? 1 : 0, yAxisIndex: i === 2 ? 1 : 0,
          data: series[s.name], lineStyle: { width: i === 1 ? 1 : 1.3, color: s.color, opacity: i === 0 ? 0.9 : 1 }, itemStyle: { color: s.color },
          areaStyle: i !== 1 ? { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: echarts.color.modifyAlpha(s.color, 0.15) }, { offset: 1, color: echarts.color.modifyAlpha(s.color, 0) }]) } : undefined,
        })),
      }, true);
      for (const s of BGP_SERIES) {
        const a = series[s.name];
        const el = body.querySelector(`.bg-kpi[data-n="${s.name}"]`);
        if (!a.length) continue;
        const cur = a.at(-1)[1];
        const vs = a.map((p) => p[1]).sort((x, y) => x - y);
        const avg = vs[Math.floor(vs.length / 2)];
        const d = avg ? ((cur - avg) / avg) * 100 : 0;
        el.querySelector('.bg-kv').textContent = cur >= 100 ? Math.round(cur).toLocaleString() : cur.toFixed(1);
        el.querySelector('.bg-kd').innerHTML = `<span class="${d >= 0 ? 'up' : 'down'}">${d >= 0 ? '▲' : '▼'}${Math.abs(d).toFixed(0)}%</span> vs 1h median`;
      }
      const last = Math.max(...BGP_SERIES.map((s) => series[s.name].at(-1)?.[0] || 0));
      if (last) ctx.setUpdated(new Date(last));
    }
    const schedule = () => { if (!pending) { pending = true; need('echarts').then(() => { if (!disposed) requestAnimationFrame(drawChart); }, (e) => { pending = false; console.error(e); }); } };

    function drawList(freshIds = new Set()) {
      const el = $('.bg-list');
      el.innerHTML = events.length ? events.slice(0, 30).map((e) => {
        const m = kindMeta(e.kind);
        const short = e.kind === 'bgp_origin_change' ? 'ORIGIN' : 'WDRAW';
        const title = e.kind === 'bgp_origin_change' ? (e.title || '').replace(/^Origin change\s*/, '') : (e.title || '').replace(/^Withdrawal burst\s*·\s*/, '') + (e.value ? ` · ${e.value} pfx/60s` : '');
        return `<div class="bg-ev${freshIds.has(e.id) ? ' fresh' : ''}" data-id="${esc(e.id)}"><span class="bg-et" style="color:${m.color};border-color:${m.color}40">${short}</span>
          <span class="bg-tt">${esc(title)}</span><span class="bg-cc">${e.country ? flag(e.country) + ' ' + esc(e.country) : ''}</span><span class="bg-ag">${ago(e.ts)}</span></div>`;
      }).join('') : emptyState({ why: 'No BGP anomalies in this time range.', size: 'sm' });
      el.querySelectorAll('.bg-ev').forEach((r) => (r.onclick = () => ctx.openEvent(r.dataset.id)));
    }

    // The last hour of history; a failed load is retried (15 s apart, a few times) and merged with any live points.
    let histTimer = null;
    async function loadHistory(tries = 0) {
      try {
        const rows = await ctx.api.metrics(BGP_SERIES.map((s) => s.name), 60);
        if (disposed) return;
        for (const r of rows) series[r.name]?.push([new Date(r.ts).getTime(), r.value]);
        if (tries) for (const k in series) series[k].sort((a, b) => a[0] - b[0]);
        chartOk($('.bg-chart'));
      } catch (e) {
        if (disposed) return;
        if (!BGP_SERIES.some((s) => series[s.name].length)) chartError($('.bg-chart'), e.message);
        if (tries < 5) histTimer = setTimeout(() => loadHistory(tries + 1), 15000);
      }
      schedule();
    }
    async function init() {
      await loadHistory();
      loadEvents();
    }
    let evReq = 0; // range changes can overlap: only the newest response is drawn
    async function loadEvents() {
      const my = ++evReq;
      try {
        const rows = await ctx.api.events({ kinds: BGP_KINDS, limit: 40, since_hours: ctx.store.sinceHours() });
        if (my !== evReq || disposed) return;
        events = rows;
        drawList();
      } catch {}
    }

    const offs = [
      ctx.live.on('metric', (m) => { if (series[m.name]) { series[m.name].push([new Date(m.ts).getTime(), m.value]); schedule(); } }),
      ctx.live.on('events', (d) => {
        if (d.source !== 'ris_live') return;
        const add = (d.latest || []).filter((e) => BGP_KINDS.includes(e.kind) && !events.some((x) => x.id === e.id));
        if (!add.length) return;
        events = [...add, ...events].sort((a, b) => new Date(b.ts) - new Date(a.ts)).slice(0, 60);
        drawList(new Set(add.map((e) => e.id)));
      }),
      offBadge,
    ];
    init();
    const ageTimer = setInterval(() => { body.querySelectorAll('.bg-ev').forEach((r, i) => { const e = events[i]; if (e) r.querySelector('.bg-ag').textContent = ago(e.ts); }); schedule(); }, 15000);
    return {
      refresh: loadEvents,
      resize() { chart.resize(); },
      destroy() { disposed = true; clearTimeout(histTimer); offs.forEach((f) => f()); clearInterval(ageTimer); killChart(chart); },
    };
  },
});

// Cyber Pulse: composite threat gauge + sub-index bars + drill-down sparkline.
import { registerPanel } from '../core/panels.js';
import * as Tm from '../core/time.js';
import { chartTheme as T, esc, fmt } from '../core/util.js';
import { errorState } from '../core/view.js';
import { need } from '../core/libs.js';

const LEVELS = [
  [25, 'LOW', '#a29d8f'], [45, 'GUARDED', '#b4957b'], [65, 'ELEVATED', '#e4a84c'], [80, 'HIGH', '#f08a3c'], [101, 'SEVERE', '#e2674a'],
];
const levelOf = (v) => LEVELS.find(([t]) => v < t) || LEVELS[4];
// one continuous 0–100 scale shared by every sub-index bar
// neutral -> amber -> red: only the top of the scale (a real alarm) turns red
// (called only from the draws, which run after load() has awaited need('echarts'))
const RAMP = ['#a29d8f', '#b4957b', '#e4a84c', '#f08a3c', '#e2674a'];
const rampCol = (v) => echarts.color.lerp(Math.min(1, Math.max(0, v / 100)), RAMP);
const LEVEL_COLOR = Object.fromEntries(LEVELS.map(([, n, c]) => [n, c]));

// event kinds behind each sub-index (for the drill-down sparkline)
const INDEX_KINDS = {
  exploitation: ['kev', 'cve'],
  ransomware: ['ransomware'],
  connectivity: ['outage'],
  routing: ['bgp_origin_change', 'bgp_withdrawal_burst'],
  chatter: ['social'],
};

const MONO = 'JetBrains Mono, monospace';
const TOOLTIP = {
  backgroundColor: '#161c28', borderColor: '#2c3547', borderWidth: 1, padding: [6, 9],
  textStyle: { color: '#e9e3d4', fontFamily: MONO, fontSize: 11 },
  extraCssText: 'box-shadow:0 12px 30px rgba(0,0,0,.6);border-radius:6px;',
};

function delta(v, digits = 1) {
  if (v == null || Math.abs(v) < 0.05) return `<span class="cp-d flat">— 0.0</span>`;
  const up = v > 0;
  return `<span class="cp-d ${up ? 'up' : 'down'}" title="${up ? 'Rising vs 24h ago = worse' : 'Falling vs 24h ago = better'}">${up ? '▲' : '▼'} ${Math.abs(v).toFixed(digits)}</span>`;
}

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

registerPanel({
  id: 'cyber-pulse', title: 'Cyber Pulse', w: 4, h: 4, minW: 3, minH: 4,
  description: 'Composite cyber threat level with sub-index breakdown',
  mount(body, ctx) {
    const uid = `cp${Math.random().toString(36).slice(2, 8)}`;   // ids tying the sub-index tabs to their panel
    body.innerHTML = `
      <div class="cp-root">
        <div class="cp-top">
          <div class="cp-gauge">
            <div class="cp-gauge-chart"></div>
            <div class="cp-center"><div class="cp-score">--</div><div class="cp-level">—</div><div class="cp-delta"></div></div>
          </div>
          <div class="cp-bars"><div class="cp-bars-head"><span class="label" data-term="pulse-subindex">Sub-index</span><span class="label">Value</span><span class="label" title="Change vs 24h ago. ▲ red = worse, ▼ amber = better">24h Δ</span></div><div class="cp-rows" role="tablist" aria-orientation="vertical" aria-label="Sub-indices"></div>
            <div class="cp-legend"><span class="up">▲ worse</span><span class="down">▼ better</span><span class="cp-ramp"></span><span>0–100</span></div></div>
        </div>
        <div class="cp-detail" role="tabpanel" id="${uid}-panel">
          <div class="cp-detail-text"></div>
          <div class="cp-spark"></div>
        </div>
      </div>`;
    const $ = (s) => body.querySelector(s);
    const gauge = makeChart($('.cp-gauge-chart'));
    const spark = makeChart($('.cp-spark'));
    let data = null;
    let selected = ctx.state.get().sel || null;
    let sparkReq = 0;
    let disposed = false;

    // No score (too few current inputs): an empty grey ring and the state in words, never a number.
    const STATE_WORD = { warming: 'Warming up', stale: 'Stale', off: 'Too few sources' };
    function drawGauge(p) {
      const scored = p.score != null;
      if (!scored) p = { ...p, score: 0 };
      const col = scored ? (LEVEL_COLOR[p.level] || levelOf(p.score)[2]) : '#8a8578';
      gauge.setOption({
        animationDuration: 900,
        series: [
          { // outer tick ring
            type: 'gauge', startAngle: 225, endAngle: -45, min: 0, max: 100, radius: '100%', splitNumber: 10,
            axisLine: { lineStyle: { width: 0 } }, progress: { show: false }, pointer: { show: false },
            axisTick: { distance: 0, length: 3, splitNumber: 5, lineStyle: { color: '#2c3547', width: 1 } },
            splitLine: { distance: 0, length: 6, lineStyle: { color: '#3a3f4a', width: 1 } },
            axisLabel: { show: false }, detail: { show: false }, data: [{ value: p.score }],
          },
          { // level bands (thin) + progress
            type: 'gauge', startAngle: 225, endAngle: -45, min: 0, max: 100, radius: '90%',
            axisLine: { roundCap: false, lineStyle: { width: 3, color: LEVELS.map(([t, , c]) => [Math.min(t, 100) / 100, echarts.color.modifyAlpha(c, 0.25)]) } },
            progress: { show: false }, pointer: { show: false }, axisTick: { show: false }, splitLine: { show: false },
            axisLabel: { show: false }, detail: { show: false }, data: [{ value: p.score }],
          },
          { // the score arc; none without a score (its round cap at 0 sat on the "0/5 current" line)
            type: 'gauge', startAngle: 225, endAngle: -45, min: 0, max: 100, radius: '81%',
            axisLine: { lineStyle: { width: 7, color: [[1, '#1d2230']] } },
            progress: { show: scored, width: 7, roundCap: true, itemStyle: { color: col, shadowColor: echarts.color.modifyAlpha(col, 0.4), shadowBlur: 10 } },
            pointer: { show: false }, axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false },
            detail: { show: false }, data: [{ value: p.score }],
          },
        ],
      }, true);
      $('.cp-score').textContent = scored ? p.score.toFixed(1) : '—';
      $('.cp-level').textContent = scored ? p.level : (STATE_WORD[p.state] || 'No data');
      $('.cp-level').style.color = scored ? col : 'var(--text-2)';
      $('.cp-delta').innerHTML = scored ? `${delta(p.change_24h)}<span class="cp-dl">24h</span>`
        : `<span class="cp-dl states-cp-why" title="${esc(p.label || '')}">${esc(p.current)}/${esc(p.total)} current</span>`;
      if (scored && p.state === 'partial') $('.cp-delta').insertAdjacentHTML('beforeend', `<span class="cp-dl states-cp-part" title="Scored from the current inputs only">${esc(p.current)}/${esc(p.total)} inputs</span>`);
      ctx.setBadge(scored ? null : (p.state === 'warming' ? 'WARMING UP' : p.state === 'stale' ? 'STALE' : 'TOO FEW FEEDS'));
    }

    const SHORT_WHY = { stale: 'Stale', waiting: 'No data yet', off: 'Source off' };
    const STATUS_WORD = { stale: 'stale', waiting: 'no data yet', off: 'source off' };
    const sinceTxt = (t) => (t ? ` · last data ${Tm.stamp(t, { zone: true })}` : '');
    function drawRows(p) {
      const rows = $('.cp-rows');
      rows.innerHTML = p.indices.map((ix) => {
        const on = ix.value != null;
        const col = on ? rampCol(ix.value) : '#5f5b52';
        const why = on ? ix.help : `${ix.help}. ${ix.note || 'No recent data'}${sinceTxt(ix.last_data)}`;
        // a sub-index row picks what the detail below shows: a vertical tab list (rows, not buttons, so they keep their compact size)
        return `<div class="cp-row${on ? '' : ' off'}${ix.id === selected ? ' sel' : ''}" role="tab" id="${uid}-tab-${esc(ix.id)}" aria-controls="${uid}-panel" aria-selected="${ix.id === selected}" tabindex="${ix.id === selected ? 0 : -1}" data-id="${esc(ix.id)}" title="${esc(why)}">
          <span class="cp-name">${esc(ix.label)}${on && ix.weight ? `<i>${Math.round(ix.weight * 100)}%</i>` : ""}</span>
          ${on ? `<span class="cp-track"><span class="cp-fill" style="width:${Math.max(1.5, ix.value)}%;background:${col}"></span>
            ${[25, 45, 65, 80].map((t) => `<span class="cp-tick" style="left:${t}%"></span>`).join('')}</span>` : `<span class="cp-off states-cp-${esc(ix.status)}">${esc(STATUS_WORD[ix.status] || 'no data')}</span>`}
          <span class="cp-val">${on ? ix.value.toFixed(1) : '—'}</span>
          ${on ? delta(ix.change_24h) : '<span class="cp-d flat">—</span>'}
        </div>`;
      }).join('');
      const tabs = [...rows.querySelectorAll('.cp-row')];
      if (selected) $('.cp-detail').setAttribute('aria-labelledby', `${uid}-tab-${selected}`);
      if (tabs.length && !tabs.some((t) => t.tabIndex === 0)) tabs[0].tabIndex = 0;
      tabs.forEach((b, i) => {
        b.onclick = () => select(b.dataset.id);
        b.onkeydown = (e) => {
          const go = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
          if (go != null) { e.preventDefault(); const t = tabs[(go + tabs.length) % tabs.length]; select(t.dataset.id); t.focus(); }
          else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(b.dataset.id); }
        };
      });
    }

    function select(id) {
      selected = id;
      ctx.state.set({ sel: id });
      $('.cp-detail').setAttribute('aria-labelledby', `${uid}-tab-${id}`);
      body.querySelectorAll('.cp-row').forEach((b) => { const on = b.dataset.id === id; b.classList.toggle('sel', on); b.setAttribute('aria-selected', on); b.tabIndex = on ? 0 : -1; });
      drawDetail();
    }

    async function drawDetail() {
      const ix = data?.indices.find((i) => i.id === selected);
      if (!ix) return;
      const kinds = INDEX_KINDS[ix.id] || [];
      const txt = $('.cp-detail-text');
      txt.innerHTML = `<div class="cp-dt-head"><span class="cp-dt-name">${esc(ix.label)}</span><span class="cp-dt-k">${kinds.join(' · ')}</span></div>
        <div class="cp-dt-help" title="${esc(ix.value != null ? ix.help : `${ix.help}. ${ix.note || 'No recent data'}, so it is left out of the score${sinceTxt(ix.last_data)}`)}">${ix.value != null ? esc(ix.help) : `<em>${esc(SHORT_WHY[ix.status] || 'No data')}: left out of the score.</em> ${esc(ix.help)}`}</div>
        <div class="cp-dt-stat">48h <b>…</b></div>`;
      const my = ++sparkReq;
      let rows = [];
      try { rows = await ctx.api.timeline({ hours: 48, bucket: 'hour', kinds }); } catch {}
      if (my !== sparkReq || disposed) return;
      const now = new Date(); now.setMinutes(0, 0, 0);
      const start = now.getTime() - 47 * 3600e3;
      const buckets = new Array(48).fill(0);
      for (const r of rows) {
        const i = Math.round((new Date(r.t).getTime() - start) / 3600e3);
        if (i >= 0 && i < 48) buckets[i] += r.n;
      }
      const total = buckets.reduce((a, b) => a + b, 0);
      const last24 = buckets.slice(24).reduce((a, b) => a + b, 0);
      const prev24 = total - last24;
      const col = ix.value != null ? rampCol(ix.value) : '#8a8578';
      txt.querySelector('.cp-dt-stat').innerHTML = `48h <b>${fmt(total)}</b> evts · 24h <b>${fmt(last24)}</b> <span class="cp-dl">vs ${fmt(prev24)} prior</span>`;
      spark.setOption({
        animation: false,
        grid: { left: 2, right: 2, top: 6, bottom: 12 },
        tooltip: { ...TOOLTIP, trigger: 'axis', axisPointer: { type: 'line', lineStyle: { color: '#3a3f4a' } },
          formatter: (ps) => { const p = ps[0]; const d = new Date(start + p.dataIndex * 3600e3); return `<span style="color:#a29d8f">${Tm.stamp(d)}</span><br>${fmt(p.value)} events`; } },
        xAxis: { type: 'category', data: buckets.map((_, i) => i), boundaryGap: false, axisLine: { lineStyle: { color: T.axisLine } }, axisTick: { show: false },
          axisLabel: { interval: 23, color: '#8a8578', fontFamily: MONO, fontSize: 9, margin: 3, formatter: (v) => (v === 0 ? '-48h' : v === 24 ? '-24h' : '') } },
        yAxis: { type: 'value', show: false, min: 0 },
        series: [{
          type: 'line', data: buckets, smooth: 0.3, symbol: 'none', lineStyle: { width: 1.5, color: col },
          areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: echarts.color.modifyAlpha(col, 0.33) }, { offset: 1, color: echarts.color.modifyAlpha(col, 0) }]) },
          markLine: { silent: true, symbol: 'none', label: { show: false }, lineStyle: { color: '#2c3547', type: 'dashed', width: 1 }, data: [{ xAxis: 24 }] },
        }],
      }, true);
    }

    async function load() {
      try {
        [data] = await Promise.all([ctx.api.pulse(), need('echarts')]);
      } catch (e) {
        if (!data) $('.cp-rows').innerHTML = errorState({ retry: load, title: "Couldn't compute the pulse", why: 'The Night Desk server did not answer; this panel tries again on its own.', err: e.message, size: 'sm' });
        return;
      }
      if (disposed) return;
      if (!selected || !data.indices.some((i) => i.id === selected)) {
        selected = [...data.indices].filter((i) => i.value != null).sort((a, b) => b.value - a.value)[0]?.id || data.indices[0]?.id;
      }
      drawGauge(data);
      drawRows(data);
      drawDetail();
      ctx.setUpdated(new Date());
    }

    load();
    const timer = setInterval(load, 60000);
    return {
      resize() { gauge.resize(); spark.resize(); },
      destroy() { disposed = true; clearInterval(timer); gauge.dispose(); spark.dispose(); },
    };
  },
});

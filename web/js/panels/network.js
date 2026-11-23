// Your network on the Ops wall: Needs attention (the one "needs you" count and its incidents), Devices (active,
// new, unidentified) and the Network timeline (connections and alerts). Every widget opens the Network view.
// Backend: /api/netlog/* (okf/data/netlog.md). Contract: okf/architecture/web-client.md#panel-contract
import { registerPanel } from '../core/panels.js';
import * as Tm from '../core/time.js';
import { chartTheme as T, esc, fmt, compact, ago, debounce, reducedMotion, SEV as SEVC, PAL } from '../core/util.js';
import { headline, rowValue } from '../views/net/alert-text.js';
import { emptyState, errorState, stateAct } from '../core/view.js';
import { need } from '../core/libs.js';
import { demoOnly } from '../core/alerts-badge.js';

const MONO = 'JetBrains Mono, monospace';
const pl = (n, w, many) => `${fmt(n)} ${n === 1 ? w : many || `${w}s`}`;
const go = (hash) => { if (location.hash === hash) window.dispatchEvent(new HashChangeEvent('hashchange')); else location.hash = hash; };

// No network logs yet, or the netlog package is missing: one plain line and a way in.
function emptyHtml(gone) {
  return gone
    ? emptyState({ title: 'Network logs are not available', why: 'This Night Desk was installed without the network-log part.', size: 'sm' })
    : emptyState({ title: 'No network logs yet', why: 'Import logs from Zeek, Suricata, Pi-hole or AdGuard Home, or try the demo, and your own network shows up here.',
      act: stateAct('Open Network › Connect logs', { data: { go: '#network/import' } }), size: 'sm' });
}

// Refresh on alert changes (live topic), when the tab comes back, and slowly on a timer.
function keepFresh(ctx, load, ms = 60e3) {
  const soon = debounce(load, 800);
  const off = ctx.live.on('netlog_alerts', soon);
  const vis = () => { if (!document.hidden) soon(); };
  document.addEventListener('visibilitychange', vis);
  const t = setInterval(() => { if (!document.hidden) load(); }, ms);
  return () => { off?.(); document.removeEventListener('visibilitychange', vis); clearInterval(t); };
}
function wireClicks(body) {
  body.addEventListener('click', (e) => {
    const g = e.target.closest('[data-go]');
    if (g) { e.preventDefault(); go(g.dataset.go); }
  });
  body.addEventListener('keydown', (e) => {
    const g = e.target.closest('[data-go]');
    if (g && (e.key === 'Enter' || e.key === ' ') && g.tagName !== 'BUTTON') { e.preventDefault(); go(g.dataset.go); }
  });
}

// ================================================================== Needs attention
registerPanel({
  id: 'net-attention', title: 'Needs attention', w: 4, h: 6, minW: 3, minH: 4,
  description: 'Your network: the alerts that need you, worst first (Network › Alerts)',
  mount(body, ctx) {
    body.innerHTML = '<div class="netx-root netx-att"></div>';
    const root = body.firstChild;
    wireClicks(body);
    let gone = false;
    async function load() {
      if (gone) return;
      let n, rows, sum;
      try {
        [n, rows, sum] = await Promise.all([
          ctx.api.get('/api/netlog/alerts/count'),
          ctx.api.get('/api/netlog/incidents', { needs_you: true, limit: 6 }),
          ctx.api.get('/api/netlog/summary'),
        ]);
      } catch (e) {
        if (e.status === 404) { gone = true; root.innerHTML = emptyHtml(true); return; }
        root.innerHTML = errorState({ retry: load, title: "Couldn't read your network alerts", why: 'The Night Desk server did not answer; this panel tries again on its own.', err: e.message, size: 'sm' }); return;
      }
      ctx.setUpdated(new Date());
      ctx.setBadge(n.needs_you ? String(n.needs_you) : null);
      if (!sum.rows && !n.incidents) { root.innerHTML = emptyHtml(false); return; }
      const top = n.high ? 'high' : n.medium ? 'medium' : 'none';
      const demo = demoOnly(n);   // only demo alerts open: say so, never "Nothing needs you" next to demo counts
      const rest = [n.low + n.info && `${fmt(n.low + n.info)} low or info`, n.demo && `${fmt(n.demo)} demo`, n.expected && `${fmt(n.expected)} expected`].filter(Boolean);
      root.innerHTML = `
        <a class="netx-big ${top}" href="#network/alerts" data-go="#network/alerts" title="Open Network › Alerts">
          <span class="netx-num">${fmt(n.needs_you)}</span>
          <span class="netx-big-t">${n.needs_you ? `${n.needs_you === 1 ? 'alert needs' : 'alerts need'} you` : demo ? 'No real alerts' : 'Nothing needs you'}<small>${n.needs_you ? `${fmt(n.high)} high · ${fmt(n.medium)} medium, not yet looked at` : demo ? `${fmt(n.demo)} demo alert${n.demo === 1 ? '' : 's'} open, made-up data` : 'no untriaged high or medium alerts'}</small></span>
        </a>
        ${rows.length ? `<ul class="netx-list" aria-label="Alerts that need you">${rows.slice(0, 5).map((a) => {
          const h = headline(a);
          return `<li><a class="netx-row" href="#network/alerts/${encodeURIComponent(a.id)}" data-go="#network/alerts/${encodeURIComponent(a.id)}">
            <i class="netx-dot" style="background:${SEVC[a.severity] || SEVC.info}" title="${esc(a.severity)}"></i>
            <span class="netx-rt"><b>${esc(h.lead)}</b> ${esc(h.what)}<small class="mono">${esc(rowValue(a))}${a.days > 1 ? ` · ${a.days} days` : ''}</small></span>
            <span class="netx-ago mono" title="last contact">${ago(a.last_ts)}</span></a></li>`;
        }).join('')}</ul>` : `<p class="netx-calm">${demo ? 'None of yours: the open alerts come from the demo data.' : n.incidents ? 'Everything open is low, info, expected or already looked at.' : 'No alerts: nothing in your logs matched a threat list while it was listed.'}</p>`}
        <div class="netx-foot"><span class="netx-dim">${rest.length ? `Not counted: ${esc(rest.join(' · '))}` : ''}</span><button class="chip" data-go="#network/alerts">All alerts ›</button></div>`;
    }
    load();
    const stop = keepFresh(ctx, load);
    return { refresh: load, destroy: stop };
  },
});

// ================================================================== Devices
registerPanel({
  id: 'net-devices', title: 'Devices', w: 4, h: 6, minW: 3, minH: 4,
  description: 'Your network: devices active today, new ones and ones without a name (Network › Devices)',
  mount(body, ctx) {
    body.innerHTML = '<div class="netx-root netx-dev"></div>';
    const root = body.firstChild;
    wireClicks(body);
    let gone = false;
    async function load() {
      if (gone) return;
      let devs, news, nd;
      try {
        [devs, news, nd] = await Promise.all([
          ctx.api.get('/api/netlog/devices', { sort: 'last_seen', limit: 2000 }),
          ctx.api.get('/api/netlog/incidents', { rule: 'new_device', limit: 50 }),
          ctx.api.get('/api/netlog/newdev').catch(() => null),
        ]);
      } catch (e) {
        if (e.status === 404) { gone = true; root.innerHTML = emptyHtml(true); return; }
        root.innerHTML = errorState({ retry: load, title: "Couldn't read your network alerts", why: 'The Night Desk server did not answer; this panel tries again on its own.', err: e.message, size: 'sm' }); return;
      }
      ctx.setUpdated(new Date());
      if (!devs.length) { root.innerHTML = emptyHtml(false); ctx.setBadge(null); return; }
      const day = Date.now() - 24 * 3600e3, week = Date.now() - 7 * 24 * 3600e3;
      const real = devs.filter((d) => !d.fragment);
      const active = real.filter((d) => Date.parse(d.last_seen) >= day);
      const fresh = news.filter((i) => i.state === 'new');
      const recent = news.filter((i) => Date.parse(i.ts) >= week);
      const unnamed = real.filter((d) => d.name_source === 'fallback');
      const frags = devs.length - real.length;
      const last = devs.reduce((m, d) => (d.last_seen > m ? d.last_seen : m), '');
      ctx.setBadge(fresh.length ? `${fresh.length} NEW` : null);
      const tile = (n, label, sub, hash, cls = '') => `<a class="netx-tile ${cls}" href="${hash}" data-go="${hash}"><span class="netx-num">${fmt(n)}</span><span class="netx-tl">${label}</span><small>${sub}</small></a>`;
      const listRows = fresh.length ? fresh.slice(0, 4).map((i) => {
        const h = headline(i);
        return `<li><a class="netx-row" href="#network/alerts/${encodeURIComponent(i.id)}" data-go="#network/alerts/${encodeURIComponent(i.id)}"><i class="netx-dot new"></i>
          <span class="netx-rt"><b>${esc(h.what)}</b><small>joined ${esc(ago(i.ts))}</small></span><span class="netx-ago mono">new</span></a></li>`;
      }).join('') : active.slice(0, 4).map((d) => `<li><a class="netx-row" href="#network/devices" data-go="#network/devices"><i class="netx-dot on"></i>
          <span class="netx-rt"><b>${esc(d.name)}</b><small class="mono">${esc((d.ips || [])[0] || '')}</small></span><span class="netx-ago mono">${ago(d.last_seen)}</span></a></li>`).join('');
      root.innerHTML = `
        <div class="netx-tiles">
          ${tile(active.length, 'active', 'in the last 24 hours', '#network/devices')}
          ${tile(fresh.length, 'new', fresh.length ? 'not yet looked at' : `${pl(recent.length, 'joined', 'joined')} this week`, fresh.length ? '#network/alerts' : '#network/devices', fresh.length ? 'hot' : '')}
          ${tile(unnamed.length, 'unidentified', 'no name yet', '#network/devices')}
        </div>
        ${listRows ? `<div class="netx-sub">${fresh.length ? 'New on your network' : 'Most recently active'}</div><ul class="netx-list">${listRows}</ul>`
          : `<p class="netx-calm">Nothing active in the last 24 hours. Your newest logs are from ${esc(ago(last))}.</p>`}
        <div class="netx-foot"><span class="netx-dim">${pl(real.length, 'device')}${frags ? ` · ${pl(frags, 'loose IPv6 address', 'loose IPv6 addresses')}` : ''}${nd && !nd.enabled ? ' · new-device alerts off' : nd?.learning && nd.baseline_at ? ' · still learning your devices' : ''}</span><button class="chip" data-go="#network/devices">All devices ›</button></div>`;
    }
    load();
    const stop = keepFresh(ctx, load, 120e3);
    return { refresh: load, destroy: stop };
  },
});

// ================================================================== Network timeline
function makeChart(el) {
  let chart = null, q = [];
  // v1.2: calls made while hidden (0x0) wait and replay when shown, so a hidden chart never logs "Dom has no width or height"
  const sized = () => el.isConnected && el.clientWidth >= 2 && el.clientHeight >= 2;
  const flush = () => { const qq = q; q = []; for (const [m, a] of qq) chart[m](...a); };
  // the library arrives on demand (core/libs.js); calls made before then wait in the queue
  let dead = false;
  const init = () => {
    if (chart || !sized()) return;
    need('echarts').then((echarts) => {
      if (chart || dead || !sized()) return;
      chart = echarts.init(el, null, { renderer: 'canvas' });
      flush();
    }, (e) => console.error(e));
  };
  const show = () => { if (!chart) init(); else if (sized()) { flush(); chart.resize(); } };
  const ro = new ResizeObserver(show);
  ro.observe(el);
  init();
  const call = (m) => (...a) => { if (chart && (sized() || m === 'on')) return chart[m](...a); if (m === 'setOption') q = q.filter(([x]) => x !== 'setOption'); q.push([m, a]); };
  return { setOption: call('setOption'), on: call('on'), resize: show, dispose() { dead = true; ro.disconnect(); chart?.dispose(); chart = null; } };
}

registerPanel({
  id: 'net-timeline', title: 'Network timeline', w: 4, h: 6, minW: 3, minH: 4,
  description: 'Your network: connections per hour with the alerts they raised (Network › Overview)',
  mount(body, ctx) {
    body.innerHTML = `<div class="netx-root netx-time">
      <div class="netx-tlh"><span class="netx-tsum mono"></span><button class="chip" data-go="#network/overview">Open ›</button></div>
      <div class="netx-chart" role="img" aria-label="Connections per hour and alerts"></div><div class="netx-tmsg"></div></div>`;
    const $ = (s) => body.querySelector(s);
    wireClicks(body);
    const chart = makeChart($('.netx-chart'));
    chart.on('click', () => go('#network/overview'));
    let gone = false, seq = 0;
    async function load() {
      if (gone) return;
      const my = ++seq;
      const hours = ctx.store.get().hours || 0;
      let sum, rows, latest = false;
      try {
        sum = await ctx.api.get('/api/netlog/summary');
        if (!sum.rows) { $('.netx-chart').hidden = true; $('.netx-tmsg').innerHTML = emptyHtml(false); $('.netx-tsum').textContent = ''; return; }
        const span = hours > 0 ? hours : Math.max(1, (Date.parse(sum.last) - Date.parse(sum.first)) / 3600e3);
        const bucket = span <= 8 ? '15m' : span <= 24 * 10 ? 'hour' : 'day';
        const params = { bucket };
        if (hours > 0) params.since_hours = hours;
        rows = await ctx.api.get('/api/netlog/stats/timeline', params);
        // nothing in the chosen range: show the last day the logs cover, and say so
        if (!rows.some((r) => r.conns || r.rows) && sum.last) {
          const end = Date.parse(sum.last);
          rows = await ctx.api.get('/api/netlog/stats/timeline', { bucket: 'hour', since: new Date(end - 24 * 3600e3).toISOString(), until: new Date(end + 1).toISOString() });
          latest = true;
        }
        await need('echarts');
        if (my !== seq) return;
        draw(rows, bucket, latest, sum, hours);
      } catch (e) {
        if (e.status === 404) { gone = true; $('.netx-chart').hidden = true; $('.netx-tmsg').innerHTML = emptyHtml(true); return; }
        $('.netx-tmsg').innerHTML = errorState({ retry: load, title: "Couldn't draw the timeline", why: 'The Night Desk server did not answer; this panel tries again on its own.', err: e.message, size: 'sm' });
      }
    }
    function draw(rows, bucket, latest, sum, hours) {
      $('.netx-chart').hidden = false;
      const conns = rows.map((r) => [Date.parse(r.t), r.conns || r.rows || 0]);
      const sevs = ['high', 'medium', 'low', 'info'];
      const al = sevs.map((s) => rows.map((r) => [Date.parse(r.t), r.alerts?.[s] || 0]));   // aligned, so the stack starts at 0
      const totC = conns.reduce((a, [, v]) => a + v, 0), totA = al.flat().reduce((a, [, v]) => a + v, 0);
      const upto = esc(Tm.stamp(sum.last, { zone: true }));
      $('.netx-tsum').innerHTML = `<b>${compact(totC)}</b> connections · <b>${fmt(totA)}</b> alerts${latest ? ` · <span class="netx-warn" title="Nothing in the selected time range, so this is the last day your logs cover">last day of your logs, to ${upto}</span>` : hours ? '' : ' · all time'}`;
      $('.netx-tmsg').innerHTML = '';
      const peakA = Math.max(1, ...rows.map((r) => sevs.reduce((x, s) => x + (r.alerts?.[s] || 0), 0)));
      chart.setOption({
        animation: !reducedMotion(),
        grid: { left: 40, right: 10, top: 12, bottom: 22 },
        tooltip: { trigger: 'axis', backgroundColor: 'rgba(17,22,33,.97)', borderColor: '#2c3547', textStyle: { color: '#e9e3d4', fontFamily: MONO, fontSize: 11 },
          formatter: (ps) => {
            const t = Tm.stamp(ps[0].value[0], { zone: true });
            return `<span style="color:#a29d8f">${t}</span><br>${ps.map((p) => `${p.marker}${esc(p.seriesName)} <b>${fmt(p.value[1])}</b>`).join('<br>')}`;
          } },
        xAxis: { type: 'time', axisLine: { lineStyle: { color: T.axisLine } }, axisTick: { show: false }, splitLine: { show: false },
          axisLabel: { color: '#a29d8f', fontFamily: MONO, fontSize: 10, hideOverlap: true } },
        yAxis: [
          { type: 'value', min: 0, splitLine: { lineStyle: { color: T.split } }, axisLabel: { color: '#a29d8f', fontFamily: MONO, fontSize: 10, formatter: (v) => compact(v) } },
          { type: 'value', min: 0, max: peakA * 4, show: false },
        ],
        series: [
          { name: 'connections', type: bucket === 'day' ? 'bar' : 'line', data: conns, showSymbol: false, smooth: 0.2, barMaxWidth: 12,
            lineStyle: { width: 1.4, color: PAL.amber }, itemStyle: { color: PAL.amber },
            areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(228,168,76,.28)' }, { offset: 1, color: 'rgba(228,168,76,0)' }]) } },
          ...sevs.map((s, i) => ({ name: `${s} alerts`, type: 'bar', yAxisIndex: 1, stack: 'al', data: al[i], barMaxWidth: 6, itemStyle: { color: SEVC[s] } })),
        ],
      }, true);
      ctx.setUpdated(new Date());
    }
    load();
    const stop = keepFresh(ctx, load, 120e3);
    return { refresh: load, resize: () => chart.resize(), destroy() { stop(); chart.dispose(); } };
  },
});

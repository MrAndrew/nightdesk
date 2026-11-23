// Network → Overview: a status page. What needs you, whether the logs are current, active devices, the timeline;
// talkers, geography, ports and services fold under "More detail".
import { S, SEV, onChange, setRange, timeParams, barList, card, v, devLink, typeIcon, pad,
  bytes, ts, esc, fmt, compact, ruleLabel, Z } from './common.js';
import * as T from '../../core/time.js';
import { flag, ago, chartTheme, debounce, accentColor } from '../../core/util.js';
import { PAL, SEV as SEVCOL } from '../../core/util.js';   // the shared palette and the one severity map
import { headline, rowValue, serverWhy } from './alert-text.js';
import { emptyState, errorState, stateAct } from '../../core/view.js';
import { demoOnly, noRealText, deviceSplit } from '../../core/alerts-badge.js';
import { isPhone, brushTo, zoomOut, zoomBar } from './m.js';
import { afterRender } from '../../core/page.js';
import { scopeText } from './alert-text.js';
import { isCustom } from '../../core/range.js';
import { need } from '../../core/libs.js';

export const PORTS = { 20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 67: 'dhcp', 68: 'dhcp', 80: 'http', 110: 'pop3',
  123: 'ntp', 137: 'netbios', 143: 'imap', 161: 'snmp', 443: 'https', 445: 'smb', 465: 'smtps', 514: 'syslog', 587: 'submission',
  853: 'dns-over-tls', 993: 'imaps', 995: 'pop3s', 1194: 'openvpn', 1900: 'ssdp', 3074: 'xbox', 3389: 'rdp', 3478: 'stun', 5223: 'apns',
  5228: 'gcm', 5353: 'mdns', 5355: 'llmnr', 8080: 'http-alt', 8443: 'https-alt', 9001: 'tor', 51820: 'wireguard' };

export function bucketFor(spanMs) {
  const h = spanMs / 3600e3;
  if (h <= 3) return ['minute', 60e3];
  if (h <= 12) return ['5m', 300e3];
  if (h <= 48) return ['15m', 900e3];
  if (h <= 24 * 45) return ["hour", 3600e3];
  return ['day', 86400e3];
}
export function spanOf() {
  const r = S.range;
  if (r.from != null) return [r.from, r.to];
  const last = S.summary?.last ? Date.parse(S.summary.last) : Date.now();
  if (r.h) return [Date.now() - r.h * 3600e3, Date.now()];
  return [S.summary?.first ? Date.parse(S.summary.first) : last - 86400e3, last];
}

// Brushable time chart shared by Overview and Hunt. series: [{name, color, data:[[t,n]], grid:0|1, stack}]
// xMin/xMax: the axis spans the selected range (a 24H chart ends at now, so a gap with no logs shows as a gap),
// not just the data; without them the axis follows the data (Search logs).
export function timeChart(node, { series, grids = 1, onBrush, bucketMs, yNames = [], xMin, xMax }) {
  const chart = echarts.init(node, null, { renderer: 'canvas' });
  const two = grids === 2;
  const gridDefs = two
    ? [{ left: 46, right: 26, top: 12, bottom: '38%' }, { left: 46, right: 26, top: '68%', bottom: 26 }]
    : [{ left: 46, right: 26, top: 12, bottom: 26 }];   // right: room for the last date label
  const axisCommon = { axisLine: { lineStyle: { color: chartTheme.axisLine } }, axisTick: { show: false }, axisLabel: { color: '#9aa1ab', fontSize: 10 }, splitLine: { show: false } };
  chart.setOption({
    animation: false,
    useUTC: T.isUTC(), // ticks and labels in the app's one clock (Settings › Display), like the tooltip
    textStyle: chartTheme.textStyle,
    grid: gridDefs,
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, backgroundColor: '#14171c', borderColor: '#262b33', textStyle: { color: '#d7dbe0', fontSize: 11 },
      formatter: (ps) => `<div style="font-family:JetBrains Mono,monospace;font-size:11px"><b>${ts(ps[0].value[0], false)} ${Z()}</b><br>${ps.filter((p) => p.value[1]).map((p) => `${p.marker}${p.seriesName} <b style="float:right;margin-left:14px">${fmt(p.value[1])}</b>`).join('<br>') || '<span style="color:#9aa1ab">nothing</span>'}</div>` },
    xAxis: gridDefs.map((g, i) => ({ type: 'time', gridIndex: i, ...(xMin != null ? { min: xMin } : {}), ...(xMax != null ? { max: xMax } : {}), ...axisCommon, axisLabel: { ...axisCommon.axisLabel, show: i === gridDefs.length - 1, hideOverlap: true,
      // day boundaries read as dates ('Nov 4'), not ECharts' bare day number ('4'), as on the Ops Activity Timeline
      formatter: { year: '{yyyy}', month: '{MMM}', day: '{MMM} {d}', hour: '{HH}:{mm}', minute: '{HH}:{mm}' } } })),
    yAxis: gridDefs.map((g, i) => ({ type: 'value', gridIndex: i, name: yNames[i], nameTextStyle: { color: '#7f8792', fontSize: 9, align: 'left' }, minInterval: 1, splitNumber: i ? 2 : 3, ...axisCommon, axisLine: { show: false },
      axisLabel: { ...axisCommon.axisLabel, formatter: (x) => compact(x) }, splitLine: { show: true, lineStyle: { color: chartTheme.split } } })),
    axisPointer: { link: [{ xAxisIndex: 'all' }] },
    toolbox: { show: false },
    brush: { xAxisIndex: 'all', brushLink: 'all', brushType: 'lineX', brushMode: 'single', throttleType: 'debounce', outOfBrush: { colorAlpha: 0.25 },
      // drag-to-zoom selection in the theme accent (--accent), like every other selection in the app
      brushStyle: { color: echarts.color.modifyAlpha(accentColor(), 0.08), borderColor: echarts.color.modifyAlpha(accentColor(), 0.5), borderWidth: 1 } },
    series: series.map((s) => ({ type: 'bar', name: s.name, xAxisIndex: s.grid || 0, yAxisIndex: s.grid || 0, stack: s.stack || `g${s.grid || 0}`,
      itemStyle: { color: s.color }, barMaxWidth: 18, barMinWidth: 1, barCategoryGap: '20%', data: s.data, large: s.data.length > 800 })),
  });
  // A phone's chart never takes a drag (the page scrolls under the finger; the range chip sets the range there)
  const phone = isPhone();
  if (phone) node.style.touchAction = 'pan-y';
  else chart.dispatchAction({ type: 'takeGlobalCursor', key: 'brush', brushOption: { brushType: 'lineX', brushMode: 'single' } });
  // a double-click zooms back out of a brushed window (the card's "Zoom out" does the same)
  chart.getZr().on('dblclick', () => { if (isCustom(S.range)) zoomOut(); });
  chart.on('brushEnd', (p) => {
    const a = p.areas?.[0];
    if (!a?.coordRange) return;
    let [x0, x1] = Array.isArray(a.coordRange[0]) ? a.coordRange[0] : a.coordRange;
    chart.dispatchAction({ type: 'brush', areas: [] });
    if (x1 - x0 < (bucketMs || 60e3)) return; // a click, not a drag
    onBrush?.(Math.floor(x0), Math.ceil(x1));
  });
  const ro = new ResizeObserver(debounce(() => chart.resize(), 60));
  ro.observe(node);
  return { chart, dispose() { ro.disconnect(); chart.dispose(); } };
}

// Plain words for a span of seconds ("3 days", "5 hours", "20 minutes").
export function span(sec) {
  if (sec == null) return '—';
  // whole units, rounded down: the same rounding as every "ago" in the app (core/time.js)
  const m = Math.floor(sec / 60), h = Math.floor(sec / 3600), d = Math.floor(sec / 86400);
  if (sec < 5400) return `${Math.max(1, m)} minute${m === 1 ? '' : 's'}`;
  if (sec < 172800) return `${h} hour${h === 1 ? '' : 's'}`;
  return `${d} day${d === 1 ? '' : 's'}`;
}
const dayTime = (t) => (t ? T.when(t) : '—');
const MORE_KEY = 'nd.network.overview.more';
// Connections are the accent amber everywhere (Overview, device timeline, the Ops "Network timeline" widget).
const CONN = PAL.amber;

// "Logs cover up to …" per source, with a plain warning for each source that went quiet. GET /api/netlog/freshness.
export function freshnessHtml(f) {
  if (!f) return errorState({ retry: () => location.reload(), retryLabel: 'Reload the page', why: 'Could not read how current the logs are.', size: 'inline' });
  const src = f.sources || [];
  if (!f.newest) {
    return `<div class="devices-fresh-h">${f.demo?.loaded ? 'Only demo data is loaded.' : 'No logs of your own yet.'}</div>
      <p class="nv-dim">Freshness counts your own logs only${f.demo?.loaded ? '; the demo day is left out' : ''}.</p>`;
  }
  const stale = src.filter((x) => x.stale);
  const head = `<div class="devices-fresh-h ${stale.length ? 'warn' : ''}">Logs cover up to <b>${esc(dayTime(f.newest))}</b> <span class="nv-dim">(${esc(T.ago(f.newest))})</span></div>`;
  const warn = stale.map((x) => `<div class="nv-warnbox devices-stale" role="status"><b>${esc(x.label)}: no new records for ${esc(span(x.age_s))}.</b>
      The newest is from ${esc(dayTime(x.newest))}. Anything that happened on your network after that has not been checked.
      If you expected newer logs, check that ${x.kind === 'sender' ? 'this sender is still running' : 'your log export is still running and copy the new files in'}.</div>`).join('');
  const rows = src.length > 1 || stale.length ? `<ul class="devices-fresh">${src.map((x) => `<li>
      <span class="devices-fdot ${x.waiting ? 'wait' : x.stale ? 'stale' : 'ok'}"></span>
      <span class="devices-fl">${esc(x.label)}</span>
      <span class="mono nv-dim" title="Newest record ${x.newest ? esc(ts(x.newest)) + ' ' + Z() : 'none yet'} · last import ${x.last_import ? esc(ts(x.last_import)) + ' ' + Z() : '—'}">${x.waiting ? 'no logs yet' : `${esc(span(x.age_s))} old`}</span>
      <span class="devices-fs">${x.waiting ? 'waiting' : x.stale ? 'stale' : 'current'}</span></li>`).join('')}</ul>` : '';
  const th = stale[0] || src[0];
  const foot = `<p class="nv-dim devices-fnote">Times are the newest record in the logs, not when they were imported. Called stale after ${esc(span((th?.threshold_from === 'sender' ? th.threshold_s : f.stale_hours * 3600)))} without anything newer${th?.threshold_from === 'sender' ? ' (learned from the sender\u2019s usual rhythm)' : ''}.${f.demo?.loaded ? ' Demo data is not counted.' : ''}</p>`;
  return head + warn + rows + foot;
}

export function mount(el, ctx) {
  const { api } = ctx;
  let charts = [];
  let seq = 0;
  let visible = false, stale = true;
  let moreOpen = false;
  let showAll = false;   // "Draw everything": the chart's x-axis includes stray old records
  try { moreOpen = localStorage.getItem(MORE_KEY) === '1'; } catch {}

  // Status first: what needs you, whether the logs are current, which devices are active. The analyst panels
  // (traffic totals, talkers, destinations, ports, services, names) load only when "More detail" is opened.
  async function load() {
    const my = ++seq;
    stale = false;
    charts.forEach((c) => c.dispose()); charts = [];
    const s = S.summary;
    // the summary failed to load: an error with Try again (network.js retries by itself too), never "no logs yet"
    if (!s && S.summaryErr) { renderError(); return; }
    if (!s || !s.rows) { renderEmpty(); return; }
    el.innerHTML = `<div class="nv-ov nv-loading">${skeleton()}</div>`;
    const tp = timeParams();
    // "All data": the chart starts where the data is dense (summary.dense_first, okf/data/netlog.md#chart-start), so
    // one stray old record cannot squeeze the real traffic into a sliver; a note says what is left out and undoes it.
    const trim = !S.range.h && S.range.from == null && s.before_dense > 0 && !showAll;
    const [span0, span1] = trim ? [Date.parse(s.dense_first), Date.parse(s.last)] : spanOf();
    const [bucket, bucketMs] = bucketFor(span1 - span0);
    const [tl, hosts, akpi, attention, fresh] = await Promise.all([
      api.get('/api/netlog/stats/timeline', { bucket, ...tp, ...(trim ? { since: s.dense_first } : {}) }).catch(() => []),
      api.get('/api/netlog/aggregate', { ...tp, group: 'device', query: 'log_type:conn', limit: 5000 }).catch(() => null),
      // the one count (okf/data/netlog.md#the-needs-you-count), the same as the badge: not limited to the range
      // the card counts the selected range, as the Network header does (all time on "All": the badge's number)
      api.get('/api/netlog/alerts/count', tp).catch(() => null),
      api.get('/api/netlog/incidents', { needs_you: true, limit: 8, ...tp }).catch(() => []),
      api.get('/api/netlog/freshness').catch(() => null),
    ]);
    const rules = isPhone() ? await api.get('/api/netlog/rules').catch(() => null) : null;
    if (my !== seq) return;
    // Active devices: named or MAC-identified ones; short-lived IPv6 fragments are counted apart (Devices folds them away).
    const act = (hosts?.groups || []).filter((g) => g.key && (!String(g.key).startsWith('ip:') || S.devices.has(g.key)));
    const known = act.filter((g) => !S.devices.get(g.key)?.fragment);
    // every device, split as the Devices list does (core/alerts-badge.js deviceSplit): the header's total
    const split = deviceSplit(S.devices.values());
    const cnt = akpi || { needs_you: 0, high: 0, medium: 0, low: 0, info: 0, demo: 0, expected: 0 };
    const inR = S.range.h || S.range.from != null ? ' in this range' : '';   // the card's period, in words
    if (!tl.length && !hosts?.total) {
      el.innerHTML = `<div class="nv-ov"><div class="devices-status devices-status-1"><section class="nv-card devices-fresh-c"><div class="panel-head"><span class="panel-title">Are my logs current?</span></div><div class="nv-cb nv-pad">${freshnessHtml(fresh)}</div></section></div>
        ${emptyState({ title: 'No log rows in this range', why: `Your imported logs span ${ts(s.first, false)} → ${ts(s.last, false)} ${Z()}.`, act: (isCustom(S.range) ? stateAct('Zoom out', { data: { act: 'zoomout' }, primary: true }) : '') + stateAct('Show all data', { data: { act: 'all' }, primary: !isCustom(S.range) }) })}</div>`;
      el.querySelector('[data-act="all"]').onclick = () => setRange({ h: 0 });
      // a drag into an empty window: Zoom out goes back to the preset before it (m.js zoomOut)
      el.querySelector('[data-act="zoomout"]')?.addEventListener('click', zoomOut);
      return;
    }

    const needs = cnt.needs_you;
    const lowInfo = cnt.low + cnt.info;
    // The chips count YOUR untriaged alerts over all time (the needs-you rule); demo alerts get a chip of their own,
    // so the row says in words what it leaves out. Network › Alerts' severity chips count demo in (D-06).
    const sevChips = ['high', 'medium'].map((x) => `<button class="devices-sevc" data-sev="${x}" title="${fmt(cnt[x])} untriaged ${x} of yours (demo and expected left out)"><i style="background:${SEVCOL[x]}"></i>${fmt(cnt[x])} ${x}</button>`).join('')
      + (lowInfo ? `<button class="devices-sevc" data-sev="low" title="Not counted in “needs you”: ${fmt(cnt.low)} low, ${fmt(cnt.info)} info">+${fmt(lowInfo)} low/info</button>` : '')
      + (cnt.demo ? `<button class="devices-sevc fnet-democ" data-demo title="Untriaged demo alerts, any severity: counted apart from yours">+${fmt(cnt.demo)} demo</button>` : '');
    const top = [...known].sort((a, b) => b.count - a.count).slice(0, 6);
    const cut = trim ? `<p class="nv-dim counts-cut">The chart starts ${esc(ts(s.dense_first, false))} ${Z()}, where your logs get going: ${fmt(s.before_dense)} older row${s.before_dense === 1 ? '' : 's'} (from ${esc(ts(s.first, false))}) ${s.before_dense === 1 ? 'is' : 'are'} not drawn. <button class="watch-btnlink" data-act="chart-all">Draw everything</button></p>` : '';
    if (isPhone()) { await phoneCards({ my, cnt, attention, fresh, known, split, rules, tl, inR, span0, span1, bucket, bucketMs }); return; }
    // one grid: what needs you, then the chart right under it on the left; logs and devices on the right (D-04)
    el.innerHTML = `<div class="nv-ov devices-ov">
      <div class="devices-status counts-ov">
        ${card(!akpi ? 'Alerts' : needs ? `${fmt(needs)} thing${needs === 1 ? '' : 's'} need${needs === 1 ? 's' : ''} you${inR}` : demoOnly(cnt) ? `${noRealText(cnt)}${inR}` : `Nothing needs you${inR}`,
          // the count could not be read: say so, never a false all-clear
          !akpi ? `<div class="nv-calm fnet-cnterr">Night Desk couldn\u2019t read the alert count. Network › Alerts has the list.</div>` : attentionList(attention, cnt, inR), { cls: 'devices-need', badge: '', tools: `<span class="devices-sevs">${sevChips}</span><button class="chip" data-act="alerts">All alerts</button>` })}
        <div class="devices-side">
          ${card('Are my logs current?', `<div class="nv-pad">${freshnessHtml(fresh)}</div>`, { cls: 'devices-fresh-c' })}
          ${card('Active devices', `<div class="nv-pad"><div class="devices-act-h"><b class="kpi">${fmt(known.length)}</b> <span class="nv-dim">active in this range</span></div>
            <p class="nv-dim counts-devs" title="The same split as the Devices list: unidentified = short-lived addresses with nothing to name them and no alert">${fmt(split.total)} device${split.total === 1 ? '' : 's'} in all: ${fmt(split.known)} known · ${fmt(split.unid)} unidentified</p>
            ${top.length ? `<ul class="devices-act">${top.map((g) => `<li>${typeIcon(S.devices.get(g.key)?.type)}${devLink(g.key)}<span class="mono nv-dim">${compact(g.count)} conns</span></li>`).join('')}</ul>` : ''}
            <a href="#" class="devices-more-l" data-act="devices">All devices ›</a></div>`, { cls: 'devices-act-c' })}
        </div>
        ${card('Connections and alerts', `<div class="nv-chart nv-tl" title="${isPhone() ? '' : 'Drag across the chart to narrow the Network time range to that window; double-click to zoom out'}"></div>${cut}`, { cls: 'counts-ov-chart', badge: `per ${bucket} · ${zoomBar()}`, tools: `<span class="nv-legend mono"><i style="background:${CONN}"></i>conns ${SEV.map((x) => `<i style="background:${SEVCOL[x]}"></i>${x === 'medium' ? 'med' : x}`).join(' ')}</span>` })}
      </div>
      <details class="devices-more" ${moreOpen ? 'open' : ''}><summary><b>More detail</b><span class="nv-dim">Traffic totals, top talkers, destinations by country and network, ports, services and names looked up</span></summary>
        <div class="devices-more-b"></div></details>
    </div>`;

    el.querySelectorAll('[data-sev]').forEach((b) => (b.onclick = () => ctx.goto('alerts', { severity: b.dataset.sev })));
    el.querySelector('[data-act="alerts"]').onclick = () => ctx.goto('alerts', {});
    el.querySelector('[data-demo]')?.addEventListener('click', () => ctx.goto('alerts', {}));
    el.querySelector('[data-act="devices"]').onclick = (e) => { e.preventDefault(); ctx.goto('devices'); };
    el.querySelector('[data-act="chart-all"]')?.addEventListener('click', () => { showAll = true; load(); });
    el.querySelector('[data-zoom-out]')?.addEventListener('click', zoomOut);
    el.querySelectorAll('[data-alert]').forEach((r) => (r.onclick = (e) => { if (!e.target.closest('.nv-v')) ctx.goto('alerts', { alert: r.dataset.alert }); }));
    const det = el.querySelector('.devices-more');
    det.addEventListener('toggle', () => {
      moreOpen = det.open;
      try { localStorage.setItem(MORE_KEY, moreOpen ? '1' : '0'); } catch {}
      if (det.open && !det.dataset.loaded) loadMore(my);
    });
    if (moreOpen) loadMore(my);

    await need('echarts');   // the chart library on demand (core/libs.js)
    if (my !== seq) return;
    const t = (r) => Date.parse(r.t);
    const series = [
      { name: 'connections', color: CONN, data: tl.map((r) => [t(r), r.conns]), grid: 0 },
      { name: 'other rows', color: echarts.color.modifyAlpha(CONN, 0.3), data: tl.map((r) => [t(r), r.rows - r.conns]), grid: 0 },
      ...SEV.map((x) => ({ name: `${x} alerts`, color: SEVCOL[x], data: tl.filter((r) => r.alerts?.[x]).map((r) => [t(r), r.alerts[x]]), grid: 1, stack: 'al' })),
      // an empty bar at every bucket of the alerts grid: ECharts widens each time axis by half a bar, and a bar's width
      // follows the closest two points of its grid, so without this the sparse alerts grid drew minutes out of step
      // with the connections above it. With the same buckets in both, the two time axes line up exactly.
      { name: '', color: 'transparent', data: tl.map((r) => [t(r), 0]), grid: 1, stack: 'al', silent: true },
    ];
    // the axis covers the selected range (24H, 7D: up to now; a brushed window: its own ends), so hours with no logs
    // show as an empty stretch; "All data" spans the data itself
    const ranged = S.range.h || S.range.from != null;
    charts.push(timeChart(el.querySelector('.nv-tl'), { series, grids: 2, bucketMs, onBrush: brushTo,
      ...(ranged ? { xMin: span0, xMax: span1 } : {}) }));
  }

  // A phone: status cards, no tables (design §4.2 "Overview"): Anything wrong? · Are my logs current? · Active devices
  // · Expected traffic rules · Traffic (one 140 px chart). Each card leads to its page.
  async function phoneCards({ my, cnt, attention, fresh, known, split, rules, tl, inR, span0, span1, bucketMs }) {
    const need0 = cnt.needs_you;
    const head = need0 ? `${fmt(need0)} thing${need0 === 1 ? '' : 's'} need${need0 === 1 ? 's' : ''} you${inR}` : demoOnly(cnt) ? `${noRealText(cnt)}${inR}` : `Nothing needs you${inR}`;
    const att = attention.slice(0, 3).map((a) => `<a class="nv-m-ovrow" href="#network/alerts/${encodeURIComponent(a.id)}"><span class="nv-m-ovdot" style="background:${SEVCOL[a.severity]}"></span>
      <span class="nv-m-ovt">${esc(a.rule === 'sensor_silent' ? `${a.indicator} stopped sending logs` : headline(a).text)}</span><span class="nv-m-ovw">${esc(String(ago(a.last_ts)).replace(/ ago$/, ''))}</span></a>`).join('');
    const top = [...known].sort((a, b) => b.count - a.count).slice(0, 3);
    const rs = Array.isArray(rules) ? rules : [];
    const active = rs.filter((r) => r.active !== false);
    const newest = [...rs].sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')))[0];
    const mcard = (title, body, link, cls = '') => `<section class="nv-m-card ${cls}"><h3 class="nv-m-ch">${title}</h3>${body}${link ? `<a class="nv-m-clink" href="${link[0]}">${link[1]} ›</a>` : ''}</section>`;
    el.innerHTML = `<div class="nv-m-ov">
      ${mcard('Anything wrong?', `<p class="nv-m-big">${esc(head)}</p>${att ? `<div class="nv-m-ovrows">${att}</div>` : ''}`, ['#network/alerts', 'All alerts'])}
      ${mcard('Are my logs current?', `<div class="nv-m-fresh">${freshnessHtml(fresh)}</div>`, ['#network/import', 'Connect logs'])}
      ${mcard('Active devices', `<p class="nv-m-big">${fmt(known.length)} <span>active${inR || ' in all your logs'}</span></p>
        <p class="nv-m-sub">${fmt(split.total)} in all: ${fmt(split.known)} known · ${fmt(split.unid)} unidentified</p>
        ${top.length ? `<ul class="nv-m-ovlist">${top.map((g) => `<li><span data-nochips>${esc(S.devices.get(g.key)?.name || g.key)}</span><span>${compact(g.count)} conns</span></li>`).join('')}</ul>` : ''}`, ['#network/devices', 'Devices'])}
      ${mcard('Expected traffic rules', rules == null ? '<p class="nv-m-sub">Couldn’t read the rules.</p>'
        : `<p class="nv-m-big">${fmt(active.length)} <span>rule${active.length === 1 ? '' : 's'} in force</span></p>${newest ? `<p class="nv-m-sub">Newest: ${scopeText(newest)}</p>` : '<p class="nv-m-sub">None yet. Open an alert and choose “This is expected…” to add one.</p>'}`, ['#network/alerts/rules', 'Rules'])}
      ${mcard('Traffic', `<p class="nv-m-zoom">${zoomBar()}</p><div class="nv-chart nv-m-ovchart" role="img" aria-label="Connections over time"></div>`, null, 'nv-m-trafc')}
    </div>`;
    el.querySelector('[data-zoom-out]')?.addEventListener('click', zoomOut);
    afterRender('network');
    if (!tl.length) return;
    await need('echarts');
    if (my !== seq) return;
    const ranged = S.range.h || S.range.from != null;
    charts.push(timeChart(el.querySelector('.nv-m-ovchart'), { bucketMs, series: [{ name: 'connections', color: CONN, data: tl.map((r) => [Date.parse(r.t), r.conns]), grid: 0 }],
      ...(ranged ? { xMin: span0, xMax: span1 } : {}) }));
  }

  async function loadMore(my) {
    const det = el.querySelector('.devices-more');
    const box = el.querySelector('.devices-more-b');
    if (!det || !box) return;
    det.dataset.loaded = '1';
    box.innerHTML = `<div class="nv-pad">${'<div class="nv-sk" style="width:60%;margin:8px 0"></div>'.repeat(3)}</div>`;
    const s = S.summary || {};
    const tp = timeParams();
    const top = (field, limit = 10) => api.get('/api/netlog/stats/top', { field, limit, ...tp }).catch(() => []);
    const agg = (p) => api.get('/api/netlog/aggregate', { ...tp, ...p }).catch(() => null);
    const [talkers, countries, asns, ports, services, dests, names, out, inn, ind, lastFile] = await Promise.all([
      top('talkers'), top('countries'), top('asns'), top('ports'), top('services'), top('dests'), top('names'),
      agg({ group: 'log_type', metric: 'bytes_out', limit: 50 }),
      agg({ group: 'log_type', metric: 'bytes_in', limit: 50 }),
      api.get('/api/netlog/indicators').catch(() => []),
      s.files ? api.get('/api/netlog/files', { limit: 1 }).catch(() => []) : [],
    ]);
    if (my !== seq) return;
    const conn = out?.groups?.find((g) => g.key === 'conn');
    const k = { rows: out?.total || 0, conns: conn?.count || 0, out_b: conn?.bytes_out || 0, in_b: inn?.groups?.find((g) => g.key === 'conn')?.bytes_in || 0 };
    const activeInd = (ind || []).reduce((a, r) => a + (r.active || 0), 0);
    box.innerHTML = `
      <div class="nv-kpis devices-kpis">
        <div class="nv-kpi"><div class="label">Connections</div><div class="kpi">${compact(k.conns)}</div><div class="nv-kpi-s mono">${fmt(k.rows)} log rows</div></div>
        <div class="nv-kpi"><div class="label">Traffic</div><div class="kpi">${bytes(Number(k.in_b) + Number(k.out_b))}</div><div class="nv-kpi-s mono">↑ ${bytes(k.out_b)} · ↓ ${bytes(k.in_b)}</div></div>
        <div class="nv-kpi"><div class="label">Watched indicators</div><div class="kpi">${compact(activeInd)}</div><div class="nv-kpi-s mono">${(ind || []).length} lists, matched by listing time</div></div>
        <div class="nv-kpi"><div class="label">Last import</div><div class="kpi nv-kpi-txt">${lastFile[0] ? ago(lastFile[0].imported_at) : '—'}</div><div class="nv-kpi-s mono">${fmt(s.files)} files · <a href="#" data-act="import">connect more</a></div></div>
      </div>
      <div class="nv-g nv-g3">
        ${card('Top talkers', barList(talkers, { val: 'bytes', fmtv: bytes, label: (r) => devLink(r.key), sub: (r) => `↑${bytes(r.bytes_out)} ↓${bytes(r.bytes_in)} · ${fmt(r.conns)} conns` }), { badge: 'by bytes' })}
        ${card('Destinations by country', barList(countries, { val: 'bytes', fmtv: bytes, color: PAL.teal, label: (r) => r.key === '??' ? '<span class="nv-null">unknown</span>' : `${flag(r.key)} ${v('country', r.key)}`, sub: (r) => `${fmt(r.ips)} IPs · ${fmt(r.conns)} conns` }), { badge: 'outbound bytes' })}
        ${card('Destinations by <span data-term="asn">network owner</span>', barList(asns, { val: 'bytes', fmtv: bytes, color: PAL.violet, label: (r) => `${v('asn', r.key)} <span class="nv-dim">${esc(r.name || '')}</span>`, sub: (r) => `${fmt(r.ips)} IPs · ${fmt(r.conns)} conns` }), { badge: 'outbound bytes' })}
      </div>
      <div class="nv-g nv-g4">
        ${card('Ports', barList(ports, { field: 'port', color: PAL.tan, sub: (r) => PORTS[r.key] || '' }), { badge: 'conns' })}
        ${card('Services', barList(services, { label: (r) => r.key === '(none)' ? '<span class="nv-null">unidentified</span>' : v('service', r.key), color: PAL.tan }), { badge: 'conns' })}
        ${card('Destination IPs', barList(dests, { field: 'ip', val: 'bytes', fmtv: bytes, color: PAL.teal, sub: (r) => `${fmt(r.conns)} conns` }), { badge: 'bytes' })}
        ${card('Names looked up', barList(names, { field: 'q', color: PAL.olive }), { badge: 'DNS · SNI · Host' })}
      </div>`;
    box.querySelector('[data-act="import"]')?.addEventListener('click', (e) => { e.preventDefault(); ctx.goto('import'); });
  }

  function attentionList(rows, cnt, inR = '') {
    if (!rows.length) return `<div class="nv-calm"><svg viewBox="0 0 24 24" class="i"><path d="M5 12.5 10 17l9-10" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>${demoOnly(cnt) ? `None of yours: the ${fmt(cnt.demo)} open alert${cnt.demo === 1 ? '' : 's'}${inR} ${cnt.demo === 1 ? 'is' : 'are'} made-up demo data.` : `No untriaged high or medium alerts${inR}.`}</div>`;
    return `<div class="nv-att">${rows.map((a) => `
      <div class="nv-att-r" data-alert="${esc(a.id)}">
        <span class="nv-bell" style="background:${SEVCOL[a.severity]}"></span>
        <div class="nv-att-m">
          ${a.rule === 'sensor_silent' ? `<div class="nv-att-t"><b>${esc(a.indicator)}</b> <span class="nv-dim">${a.evidence?.state === 'resolved' ? 'was silent, then resumed' : 'stopped sending logs'}</span></div>
          <div class="nv-att-s mono">${esc(ruleLabel(a.rule))} · device uploads</div>` : `<div class="nv-att-t"><b>${esc(headline(a).lead)}</b> <span class="nv-dim">${esc(headline(a).what)}</span></div>
          <div class="nv-att-s mono">${v('ip', rowValue(a))}${a.days > 1 ? ` · ${a.days} days` : ''} · ${fmt(a.count)} contact${a.count === 1 ? '' : 's'}</div>`}
        </div>
        <span class="nv-att-w mono" title="${ts(a.last_ts)} ${Z()}">${ago(a.last_ts)}</span>
      </div>`).join('')}</div>`;
  }

  function skeleton() {
    return `<div class="devices-status counts-ov"><section class="nv-card devices-need" style="height:160px"></section><div class="devices-side"><section class="nv-card" style="height:120px"></section><section class="nv-card" style="height:120px"></section></div>
      <section class="nv-card counts-ov-chart" style="min-height:260px"></section></div>`;
  }

  function renderError() {
    el.innerHTML = `<div class="nv-ov">${errorState({ retry: () => ctx.refreshSummary(), title: S.summaryErrStatus ? 'Night Desk couldn\u2019t read the network logs' : 'Couldn\u2019t load your network logs',
      why: `${serverWhy({ status: S.summaryErrStatus })} Your logs are still stored. Night Desk tries again by itself every few seconds.`, err: S.summaryErr })}</div>`;
  }

  function renderEmpty() {
    if (S.lake?.where === undefined) api.get('/api/paths').then((l) => { S.lake = { path: l.lake, where: l.inbox_where || null }; if (!S.summary?.rows) renderEmpty(); }).catch(() => {});
    // the inbox as the user can reach it: in Docker the host folder (LAKE_DIR) or a docker compose cp command
    const w = S.lake?.where;
    const inbox = w?.path ? `copy them to <code class="nv-path">${esc(w.path)}</code>` : w?.copy_cmd ? `copy them in with <code class="nv-path">${esc(w.copy_cmd)}</code>`
      : `copy them to <code class="nv-path">${esc(S.lake?.path ? `${S.lake.path}/inbox/zeek/` : '<lake>/inbox/zeek/')}</code>`;
    el.innerHTML = `<div class="nv-ov">${emptyState({ title: 'No network logs yet', cls: 'nv-first', why: `Night Desk reads logs you export from your own network (Zeek, Suricata, or the DNS log of a Pi-hole or AdGuard Home) and checks every connection and lookup against the threat lists it collects, <em>as they were at the time of the connection</em>. It never captures or scans traffic.`, body: `<ol class="nv-steps">
        <li><b>Pick your logs</b><span>Zeek JSON logs (turn on with <code>@load policy/tuning/json-logs.zeek</code>), Suricata <code>eve.json</code>, Pi-hole’s <code>pihole.log</code> or query export, or AdGuard Home’s <code>querylog.json</code></span></li>
        <li><b>Connect them</b><span>Connect logs shows the steps for OPNsense, pfSense, Security Onion, Zeek, Suricata, Pi-hole and AdGuard Home. Or drag files onto it, or ${inbox}</span></li>
        <li><b>Confirm your home prefix</b><span>So inbound and outbound are told apart. Night Desk suggests one after the first import.</span></li>
      </ol>`, act: `${stateAct('Connect logs', { data: { act: 'import' }, primary: true })}${stateAct('Try it with demo data', { data: { act: 'demo' }, title: 'A day of invented home-network logs with contacts planted against your current threat lists' })}` })}</div>`;
    el.querySelector('[data-act="import"]').onclick = () => ctx.goto('import');
    el.querySelector('[data-act="demo"]').onclick = () => ctx.goto('import', { demo: 'load' });
  }

  onChange((w) => { if (w === 'range' || w === 'data' || w === 'devices') { stale = true; if (visible) load(); } });
  return {
    show() { visible = true; if (stale) load(); else charts.forEach((c) => c.chart.resize()); },
    hide() { visible = false; },
  };
}

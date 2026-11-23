// Explorer view: analyst workbench over DuckDB. SQL console with auto-chart + CSV export,
// schema sidebar, and a filterable event search table.
import { registerView } from '../core/panels.js';
import { LS } from '../core/prefs.js';
import { viewHeader, emptyState, errorState, stateAct } from '../core/view.js';
import { need } from '../core/libs.js';
import { isPhone } from '../core/mobile.js';
import { openSheet } from '../core/sheet.js';
import * as Tm from '../core/time.js';

const EXAMPLES = [
  ['Top ASNs · malicious IPs', `SELECT asn, count(DISTINCT ip) AS malicious_ips, list(DISTINCT kind) AS kinds
FROM events
WHERE asn IS NOT NULL AND ip IS NOT NULL
GROUP BY asn
ORDER BY malicious_ips DESC
LIMIT 25`],
  ['Malicious IPs by country', `SELECT country, count(DISTINCT ip) AS ips
FROM events
WHERE category = 'threat' AND country IS NOT NULL
GROUP BY country
ORDER BY ips DESC
LIMIT 25`],
  ['KEV vendors · ransomware', `SELECT tags[1] AS vendor,
       count(*) AS kev_cves,
       count(*) FILTER (WHERE list_contains(tags, 'ransomware')) AS ransomware_use
FROM events
WHERE kind = 'kev'
GROUP BY vendor
HAVING ransomware_use > 0
ORDER BY ransomware_use DESC
LIMIT 25`],
  ['KEV by EPSS · likeliest next', `SELECT k.cve, e.epss, e.percentile, e.prev_epss, e.since, k.vendor
FROM (SELECT split_part(title, ' ', 1) AS cve, tags[1] AS vendor FROM events WHERE kind = 'kev') k
JOIN epss e USING (cve)
ORDER BY e.epss DESC
LIMIT 25`],
  ['CISA advisories · CVEs', `SELECT a.advisory, a.kind, a.cve, a.cvss, e.epss, a.vendors, a.updated
FROM advisory_cves a LEFT JOIN epss e USING (cve)
ORDER BY a.updated DESC, a.cvss DESC NULLS LAST
LIMIT 50`],
  ['Outages by country · 7d', `SELECT coalesce(country, regexp_replace(title, '^Outage · ', '')) AS place,
       count(*) AS outages,
       round(max(value)) AS peak_score
FROM events
WHERE kind = 'outage' AND ts > now() - INTERVAL 7 DAY
GROUP BY place
ORDER BY outages DESC
LIMIT 25`],
  ['RIS Live update rate / hour', `SELECT date_trunc('hour', ts) AS hour, round(avg(value), 2) AS updates_per_s
FROM metrics
WHERE name = 'bgp.updates_per_s'
GROUP BY hour
ORDER BY hour`],
  ['Events per hour by kind', `SELECT date_trunc('hour', ts) AS hour, kind, count(*) AS n
FROM events
WHERE ts > now() - INTERVAL 48 HOUR
GROUP BY ALL
ORDER BY hour`],
  ['Ingest runs', `SELECT source, count(*) AS runs, sum(items) AS items,
       count(*) FILTER (WHERE NOT ok) AS failures, max(started) AS last_run
FROM runs
GROUP BY source
ORDER BY items DESC`],
];

const KW = /\b(SELECT|FROM|WHERE|GROUP|BY|ORDER|LIMIT|HAVING|WITH|AS|AND|OR|NOT|IN|IS|NULL|ON|JOIN|LEFT|RIGHT|INNER|OUTER|DISTINCT|COUNT|SUM|AVG|MIN|MAX|CASE|WHEN|THEN|ELSE|END|DESC|ASC|INTERVAL|FILTER|ALL|UNION|LIKE|ILIKE|BETWEEN|OVER|PARTITION|QUALIFY|PIVOT|UNPIVOT|DESCRIBE|SUMMARIZE|SHOW|TABLES|HOUR|DAY|MINUTE|NOW|EXCLUDE|USING|NULLS|LAST|FIRST|TRUE|FALSE)\b/gi;

function highlight(src, esc) {
  // Tokenise strings / comments / numbers / keywords without touching HTML escapes.
  const out = [];
  const re = /('(?:[^']|'')*'?)|(--[^\n]*)|(\b\d+(?:\.\d+)?\b)|([A-Za-z_][A-Za-z0-9_]*)|([\s\S])/g;
  let m;
  while ((m = re.exec(src))) {
    if (m[1]) out.push(`<span class="ex-s">${esc(m[1])}</span>`);
    else if (m[2]) out.push(`<span class="ex-c">${esc(m[2])}</span>`);
    else if (m[3]) out.push(`<span class="ex-n">${m[3]}</span>`);
    else if (m[4]) out.push(KW.test(m[4]) ? `<span class="ex-k">${m[4]}</span>` : esc(m[4]));
    else out.push(esc(m[5]));
    KW.lastIndex = 0;
  }
  return out.join('') + '\n';
}

const isNum = (v) => typeof v === 'number' || typeof v === 'bigint';
// The Results table shows a time column as the SQL value, which is UTC; the chart reads like the rest of the app.
const TIME_COL_TIP = 'Times here are the raw SQL values, in UTC. The chart shows them in your display time zone (Settings › Display).';
const ISO = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/;

function analyse(cols, rows) {
  const sample = rows.slice(0, 200);
  return cols.map((c, i) => {
    const vals = sample.map((r) => r[i]).filter((v) => v !== null && v !== undefined);
    const num = vals.length > 0 && vals.every(isNum);
    const time = !num && vals.length > 0 && vals.every((v) => typeof v === 'string' && ISO.test(v));
    const str = !num && !time && vals.length > 0 && vals.every((v) => typeof v === 'string');
    return { name: c, i, num, time, str };
  });
}

function csvCell(v) {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const LIT = (s) => `'${String(s).replace(/'/g, "''")}'`;

let unsubscribe = null, inst = null; // the store subscription and lifecycle of the one mounted Explorer

// The SQL console is off unless the server was started with OSINTHUB_SQL_CONSOLE=1 (/api/health says which): then
// this page only says so and how to turn it on, and nothing here asks the server anything.
const OFF_TEXT = 'The SQL console is off. Start Night Desk with OSINTHUB_SQL_CONSOLE=1 to turn it on.';
function mountOff(el) {
  el.innerHTML = `<div class="vh-frame">${viewHeader({ title: 'SQL console', cls: 'ex-vh', purpose: 'Read-only SQL over the lake, for power users' })}
    <div class="vh-body"><div class="ex-off">${emptyState({ title: 'A power tool, off by default',
      why: OFF_TEXT + ' Nothing else in Night Desk needs it.' })}</div></div></div>`;
  if (/^#\/?explorer\//.test(location.hash)) history.replaceState(null, '', '#explorer');   // a pivot link: no query to keep
}

registerView({
  id: 'explorer',
  mount(el, ctx) {
    el.innerHTML = `<div class="vh-frame">${viewHeader({ title: 'SQL console', cls: 'ex-vh' })}<div class="vh-body"></div></div>`;
    ctx.api.health().then((h) => {
      if (h?.sql_console !== true) return mountOff(el);
      mountConsole(el, ctx);
      inst?.show();   // the view was shown while /api/health was on its way
    }).catch((err) => { console.error(err); mountOff(el); });
  },
  show() { inst?.show(); },
});

function mountConsole(el, ctx) {
    const { api, store, util, openEvent } = ctx;
    const { esc, fmt, compact, ago, kindMeta, flag, toast, debounce, chartTheme, accentColor, sevColor, KINDS } = util;
    // a ring kind (second of a hue pair, core/util.js) gets a ring swatch, a hatched bar and a dashed line
    const swStyle = (k, c) => (util.isRing(k) ? `background:transparent;box-shadow:inset 0 0 0 2px ${c}` : `background:${c}`);

    // v1.1: the SQL console is the whole of Explorer (its "Event search" tab duplicated global search and Hunt).
    let result = null;      // {columns, rows, ms, sql}
    let chart = null;
    let chartMode = 'auto'; // auto | off
    let yScale = 'auto';    // auto | linear | log
    let sort = null;        // {i, dir}
    let hours = store.get?.().hours ?? 24;   // the global range, for the event-kind counts in the side rail

    // touch screens get no keyboard hints (⌘↵, shift-click); a phone edits the query in a full-screen sheet
    const coarse = !!window.matchMedia?.('(pointer: coarse)').matches;
    el.innerHTML = `<div class="vh-frame">
      ${viewHeader({ title: 'SQL console', cls: 'ex-vh', purpose: 'Ask the lake anything in read-only SQL; results chart themselves',
        actions: '<button class="vh-btn ex-schema-btn" data-act="schema" title="Tables and event kinds"><svg class="i"><use href="#i-layers"/></svg>Schema</button>' })}
      <div class="vh-body">
      <div class="ex-wrap">
        <nav class="ex-rail">
          <button class="ex-rail-b" data-act="rail" title="Schema & event kinds"><svg class="i"><use href="#i-layers"/></svg></button>
          <span class="ex-rail-l">SCHEMA</span>
        </nav>
        <aside class="ex-side">
          <div class="ex-side-sec">
            <div class="ex-side-h"><span class="label">Tables</span><span class="ex-db mono" title="DuckDB">duckdb</span></div>
            <div class="ex-tables"><div class="ex-muted mono">Loading schema…</div></div>
          </div>
          <div class="ex-side-sec">
            <div class="ex-side-h"><span class="label">Event kinds</span><span class="ex-muted mono ex-kinds-tot"></span></div>
            <div class="ex-kinds"></div>
          </div>
        </aside>
        <div class="ex-main">
          <div class="ex-pane" data-pane="sql">
            <div class="ex-examples"></div>
            <div class="ex-m-q" hidden><pre class="ex-m-qt mono" aria-label="The query"></pre><button type="button" class="m-btn ex-m-edit" data-act="edit-sql">Edit query</button></div>
            <div class="ex-editor">
              <pre class="ex-hl" aria-hidden="true"></pre>
              <textarea class="ex-ta" aria-label="SQL query" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
            </div>
            <div class="ex-actions">
              <button class="ex-run" data-act="run"><svg class="i" viewBox="0 0 24 24"><path d="M8 5v14l11-7L8 5Z" fill="currentColor"/></svg>Run${coarse ? '' : '<kbd title="Run with Cmd+Enter (Ctrl+Enter on Windows and Linux)">⌘↵</kbd>'}</button>
              <span class="ex-status mono"></span>
              <span class="ex-sp"></span>
              <button class="chip on" data-act="chart" title="Toggle auto chart"><svg class="i" viewBox="0 0 24 24"><path d="M4 20V10m6 10V4m6 16v-7m4 7H3" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>Chart</button>
            </div>
            <div class="ex-results no-chart">
              <section class="ex-pnl ex-pnl-chart" hidden>
                <div class="panel-head"><span class="panel-title">Chart</span><span class="panel-badge ex-ser"></span>
                  <div class="panel-tools">
                    <span class="panel-updated"><svg class="i"><use href="#i-clock"/></svg><span></span></span>
                    <div class="ex-seg ex-share-seg" title="Absolute counts or share of each bucket (100% stacked)"><button data-share="0">Abs</button><button data-share="1">Share %</button></div>
                    <div class="ex-seg" title="Y axis scale"><button data-scale="auto">Auto</button><button data-scale="linear">Lin</button><button data-scale="log">Log</button></div>
                    <button class="icon-btn" data-act="max" title="Expand"><svg class="i"><use href="#i-expand"/></svg></button>
                  </div></div>
                <div class="ex-kpis"></div>
                <div class="ex-legend-row"><div class="ex-legend"></div><button class="ex-lg-more" data-act="lg-more" title="Scroll legend">›</button>${coarse ? '' : '<span class="ex-lg-hint mono" title="Click a chip to toggle it · Shift-click to isolate it"><kbd>shift</kbd>-click isolates</span>'}</div>
                <div class="ex-chart-sub mono"></div>
                <div class="ex-chart"></div>
              </section>
              <section class="ex-pnl ex-pnl-table">
                <div class="panel-head"><span class="panel-title">Results</span><span class="panel-badge">—</span>
                  <button class="ex-filt chip" data-lg-reset="1" hidden title="Clear legend filter">Filtered by legend ✕</button>
                  <div class="panel-tools">
                    <span class="panel-updated" hidden><svg class="i"><use href="#i-clock"/></svg><span></span></span>
                    <button class="icon-btn" data-act="csv" title="Export CSV" disabled><svg class="i" viewBox="0 0 24 24"><path d="M12 4v11m0 0-4-4m4 4 4-4M5 19h14" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></button>
                    <button class="icon-btn" data-act="max" title="Expand"><svg class="i"><use href="#i-expand"/></svg></button>
                  </div></div>
                <div class="ex-grid">${emptyState({ title: 'No query run yet', why: 'Write one above or pick an example, then press Run. Read-only (SELECT, WITH, PIVOT, DESCRIBE, SUMMARIZE), up to 5,000 rows. A PIVOT lists its values: ON kind IN (\'a\', \'b\').', size: 'sm' })}</div>
              </section>
            </div>
          </div>

        </div>
      </div></div></div>`;

    const $ = (s) => el.querySelector(s);
    const ta = $('.ex-ta');
    const hl = $('.ex-hl');

    // ---------------------------------------------------------------- tabs
    function setTab() {
      el.querySelectorAll('.ex-pane').forEach((p) => p.classList.toggle('on', p.dataset.pane === 'sql'));
      requestAnimationFrame(() => chart?.resize());
    }

    // ---------------------------------------------------------------- editor
    const editor = $('.ex-editor');
    const fitEditor = () => { const n = Math.min(14, Math.max(4, ta.value.split('\n').length)); editor.style.height = `${n * 20 + 24}px`; };
    const syncHl = () => { const qt = el.querySelector('.ex-m-qt'); if (qt) qt.textContent = ta.value.trim(); hl.innerHTML = highlight(ta.value, esc); hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft; fitEditor(); el.querySelectorAll('[data-ex]').forEach((b) => b.classList.toggle('on', EXAMPLES[+b.dataset.ex][1] === ta.value.trim())); };
    ta.addEventListener('input', () => { syncHl(); LS.set('nd.explorer.sql', ta.value); });
    ta.addEventListener('scroll', () => { hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft; });
    ta.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); runSql(); }
      else if (e.key === 'Tab') {
        e.preventDefault();
        const { selectionStart: a, selectionEnd: b } = ta;
        ta.setRangeText('  ', a, b, 'end'); syncHl();
      }
    });
    $('.ex-examples').innerHTML = '<span class="label">Examples</span>' + EXAMPLES.map(([l], i) => `<button class="chip" data-ex="${i}">${esc(l)}</button>`).join('');
    $('.ex-m-q').hidden = !isPhone();
    ta.value = LS.get('nd.explorer.sql', EXAMPLES[5][1]);
    syncHl();


    function insertAtCursor(text) {
      ta.focus();
      ta.setRangeText(text, ta.selectionStart, ta.selectionEnd, 'end');
      syncHl(); LS.set('nd.explorer.sql', ta.value);
    }

    // ---------------------------------------------------------------- the phone's editor (design.md §4.7)
    // A full-screen sheet: 16 px (no iOS zoom), soft wrap, Run in the footer (no ⌘↵). Cancel keeps the old query.
    function editSheet() {
      const box = document.createElement('textarea');
      box.className = 'ex-m-ta mono';
      box.value = ta.value;
      box.wrap = 'soft';
      box.spellcheck = false;
      box.setAttribute('autocapitalize', 'off'); box.setAttribute('autocomplete', 'off'); box.setAttribute('autocorrect', 'off');
      box.setAttribute('aria-label', 'SQL query');
      const hint = document.createElement('p');
      hint.className = 'ex-m-hint';
      hint.textContent = 'Read-only: SELECT, WITH, PIVOT, DESCRIBE or SUMMARIZE, up to 5,000 rows. A PIVOT lists its values: ON kind IN (\'a\', \'b\').';
      const body = document.createElement('div');
      body.className = 'ex-m-edbody';
      body.append(box, hint);
      const cancel = Object.assign(document.createElement('button'), { type: 'button', className: 'm-btn', textContent: 'Cancel' });
      const run = Object.assign(document.createElement('button'), { type: 'button', className: 'm-btn m-btn-primary', textContent: 'Run' });
      const sh = openSheet({ id: 'ex-edit', title: 'Edit query', body, footer: [cancel, run], size: 'full' });
      cancel.addEventListener('click', () => sh.close('close'));
      run.addEventListener('click', () => { const q = box.value; sh.close('close'); runSql(q); });
      requestAnimationFrame(() => box.focus({ preventScroll: true }));
    }

    // ---------------------------------------------------------------- SQL run
    // Each run takes a sequence number; a response that lands after a newer run started is dropped, so the
    // grid, chart and status always belong to the last query run (the one in the editor).
    let runSeq = 0;
    async function runSql(sqlText) {
      if (sqlText != null) { ta.value = sqlText; syncHl(); LS.set('nd.explorer.sql', sqlText); }
      const q = ta.value.trim();
      if (!q) return;
      const status = $('.ex-status');
      const btn = $('.ex-run');
      const seq = ++runSeq;
      btn.disabled = true; btn.classList.add('busy');
      status.innerHTML = '<span class="ex-spin"></span>running…';
      const t0 = performance.now();
      try {
        const [r] = await Promise.all([api.sql(q), need('echarts')]);   // the chart library arrives on demand (core/libs.js)
        if (seq !== runSeq) return;
        const ms = performance.now() - t0;
        result = { ...r, ms, sql: q, at: new Date().toISOString() };
        sort = null;
        status.innerHTML = `<b>${fmt(r.rows.length)}</b> row${r.rows.length === 1 ? '' : 's'}${r.rows.length >= 5000 ? ' <span class="ex-warn">(capped)</span>' : ''} · ${r.columns.length} col${r.columns.length === 1 ? '' : 's'} · <b>${ms < 1000 ? ms.toFixed(0) + ' ms' : (ms / 1000).toFixed(2) + ' s'}</b>`;
        $('[data-act="csv"]').disabled = !r.rows.length;
        renderResult(true);
      } catch (err) {
        if (seq !== runSeq) return;
        result = null;
        status.innerHTML = '<span class="ex-err">error</span>';
        $('[data-act="csv"]').disabled = true;
        model = null; renderChart();
        $('.ex-pnl-table .panel-badge').textContent = 'error';
        $('.ex-grid').innerHTML = errorState({ act: stateAct('Edit the query', { data: { act: 'edit-sql' }, primary: true }), title: 'The query failed', why: `<code class="ex-errmsg">${esc(err.message)}</code>`, size: 'sm' });
      } finally {
        if (seq === runSeq) { btn.disabled = false; btn.classList.remove('busy'); }
      }
    }

    function cell(v, c) {
      if (v === null || v === undefined) return '<span class="ex-null">NULL</span>';
      if (c.num) return Number.isInteger(v) ? fmt(v) : Number(v).toLocaleString(undefined, { maximumFractionDigits: 4 });
      if (typeof v === 'boolean') return `<span class="${v ? 'ex-t' : 'ex-f'}">${v}</span>`;
      if (Array.isArray(v)) return v.map((x) => `<span class="ex-li">${esc(typeof x === 'object' ? JSON.stringify(x) : x)}</span>`).join('');
      if (typeof v === 'object') return esc(JSON.stringify(v));
      if (c.time) return esc(v.replace('T', ' ').replace(/(\.\d+)?(\+00:00|Z)$/, ''));
      if (c.name === 'kind' && KINDS[v]) return `<span class="ex-kind"><i style="${swStyle(v, model?.series?.find((s) => s.name === v)?.color || kindMeta(v).color)}"></i>${esc(v)}</span>`;
      return esc(v);
    }

    // ---------------------------------------------------------------- results: model -> KPIs, legend, chart, table
    let model = null;          // derived chart model for the current result
    let hidden = new Set();    // legend keys toggled off
    let expandOther = false;   // show all series instead of top 5 + Other
    let share = false;         // 100% stacked view
    // Chart times read like the rest of the app (core/time.js: local time or UTC per Settings › Display); a bare
    // calendar date ("2026-11-04") stays that date. The Results table keeps the raw SQL value.
    const isDay = (t) => /^\d{4}-\d{2}-\d{2}$/.test(String(t).trim());
    const fmtT = (t) => (isDay(t) ? Tm.date(t) : Tm.stamp(t));
    const fmtTz = (t) => (isDay(t) ? Tm.date(t) : Tm.stamp(t, { zone: true }));
    // Series colours: an event kind keeps its own kind colour (as in the Results table), the first measure
    // takes the theme accent, further measures the rest of the shared palette.
    const measureColor = (i) => (i ? chartTheme.palette[i % chartTheme.palette.length] : accentColor());
    const colorFor = (k, i) => KINDS[k]?.color || measureColor(i);
    const fmtV = (v) => (v == null ? '—' : Math.abs(v) >= 10000 ? compact(v) : Number.isInteger(v) ? fmt(v) : Number(v).toLocaleString(undefined, { maximumFractionDigits: 2 }));

    function buildModel(meta, rows) {
      const numCols = meta.filter((c) => c.num && !/^(lat|lon|id)$/i.test(c.name));
      const timeCol = meta.find((c) => c.time);
      const catCol = meta.find((c) => c.str && c !== timeCol);
      if (chartMode === 'off' || !numCols.length || !(timeCol || catCol) || rows.length < 2) return null;
      const v = numCols[0];
      if (timeCol && catCol) {
        const x = [...new Set(rows.map((r) => r[timeCol.i]))].sort();
        const xi = new Map(x.map((t, i) => [t, i]));
        const g = new Map();
        for (const r of rows) {
          const k = String(r[catCol.i] ?? 'null');
          if (!g.has(k)) g.set(k, new Array(x.length).fill(0));
          g.get(k)[xi.get(r[timeCol.i])] += Number(r[v.i] || 0);
        }
        let series = [...g.entries()].map(([name, data]) => ({ name, data, total: data.reduce((a, b) => a + b, 0) })).sort((a, b) => b.total - a.total);
        // rank for the top-5 by how much of each bucket a series covers (so steady kinds beat one-off batch dumps)
        const bt = x.map((_, i) => series.reduce((a, s) => a + s.data[i], 0));
        series.forEach((s) => (s.presence = s.data.reduce((a, v, i) => a + (bt[i] ? v / bt[i] : 0), 0)));
        series.sort((a, b) => b.presence - a.presence);
        const keepN = expandOther ? 11 : 5;
        const nAll = series.length;
        let otherS = null;
        if (series.length > keepN + 1) {
          const rest = series.slice(keepN);
          const data = x.map((_, i) => rest.reduce((a, s) => a + s.data[i], 0));
          otherS = { name: `Other (${rest.length})`, data, total: data.reduce((a, b) => a + b, 0), other: rest.map((s) => s.name), isOther: true };
          series = series.slice(0, keepN);
        }
        const used = new Set();
        series.forEach((s, i) => {
          // a kind's own colour, unless taken; a ring kind shares its pair's hue (it is hatched, so the key includes the mark)
          const mk = util.isRing(s.name) ? ' ring' : '';
          let c = colorFor(s.name, i);
          if (used.has(c + mk)) c = [accentColor(), ...chartTheme.palette.slice(1)].find((x) => !used.has(x + mk)) || c;
          used.add(c + mk); s.color = c;
        });
        if (otherS) { otherS.color = '#5f5b52'; series.push(otherS); }
        series.nAll = nAll;
        return { type: 'timecat', x, labels: x.map(fmtT), series, nAll, timeCol, catCol, v, filterable: true };
      }
      if (timeCol) {
        const sorted = [...rows].sort((a, b) => (a[timeCol.i] > b[timeCol.i] ? 1 : -1));
        const x = sorted.map((r) => r[timeCol.i]);
        const series = numCols.slice(0, 3).map((c, i) => {
          const data = sorted.map((r) => Number(r[c.i] || 0));
          return { name: c.name, data, total: data.reduce((a, b) => a + b, 0), color: measureColor(i) };
        });
        return { type: 'time', x, labels: x.map(fmtT), series, timeCol, v, filterable: false };
      }
      const top = rows.slice(0, 30);
      const series = numCols.slice(0, 3).map((c, i) => {
        const data = top.map((r) => Number(r[c.i] || 0));
        return { name: c.name, data, total: data.reduce((a, b) => a + b, 0), color: measureColor(i) };
      });
      const x = top.map((r) => String(r[catCol.i] ?? 'null'));
      // one measure over event kinds: each bar (and its legend chip) in that kind's colour, as in the table
      const catColors = series.length === 1 && x.some((k) => KINDS[k]) ? x.map((k) => KINDS[k]?.color || series[0].color) : null;
      return { type: 'cat', x, labels: x, series, catColors, catCol, v, filterable: true, cats: true };
    }

    // legend keys: series names for time models, x categories for category models
    const legendItems = (m) => (m.cats
      ? m.x.map((name, i) => ({ name, total: m.series[0].data[i], color: m.catColors?.[i] || m.series[0].color }))
      : m.series.map((s) => ({ name: s.name, total: s.total, color: s.color })));

    function visibleModel(m) {
      if (!m.cats) return { ...m, series: m.series.filter((s) => !hidden.has(s.name)) };
      const keep = m.x.map((k, i) => (hidden.has(k) ? -1 : i)).filter((i) => i >= 0);
      return { ...m, x: keep.map((i) => m.x[i]), labels: keep.map((i) => m.labels[i]), catColors: m.catColors && keep.map((i) => m.catColors[i]),
        series: m.series.map((s) => ({ ...s, data: keep.map((i) => s.data[i]) })) };
    }

    function renderKpis(vm) {
      const box = $('.ex-kpis');
      const s0 = vm.series[0];
      const cells = [];
      if (!s0 || !vm.x.length) { box.innerHTML = ''; return; }
      if (vm.type === 'cat') {
        const vals = s0.data; const tot = vals.reduce((a, b) => a + b, 0);
        const mi = vals.indexOf(Math.max(...vals));
        const med = [...vals].sort((a, b) => a - b)[Math.floor(vals.length / 2)];
        cells.push(['Total ' + s0.name, fmtV(tot), `${vm.x.length} ${vm.catCol.name} values`]);
        cells.push(['Top ' + vm.catCol.name, esc(vm.x[mi]), `${fmtV(vals[mi])} · ${tot ? Math.round(100 * vals[mi] / tot) : 0}% of total`, 'txt']);
        cells.push(['Median', fmtV(med), `mean ${fmtV(tot / vals.length)}`]);
        cells.push(['Rows', fmt(result.rows.length), `${result.columns.length} columns`]);
      } else {
        const totals = vm.x.map((_, i) => vm.series.reduce((a, s) => a + (s.data[i] || 0), 0));
        const tot = totals.reduce((a, b) => a + b, 0);
        const pi = totals.indexOf(Math.max(...totals));
        const last = totals[totals.length - 1], prev = totals[totals.length - 2];
        const d = prev ? (last - prev) / prev : null;
        const span = vm.x.length > 1 ? `${fmtT(vm.x[0])} → ${fmtT(vm.x[vm.x.length - 1])}` : '';
        cells.push([`Total ${vm.v.name}`, fmtV(tot), `${vm.x.length} buckets · ${span}`]);
        cells.push([vm.type === 'timecat' ? `Distinct ${vm.catCol.name}` : 'Series', String(vm.nAll || vm.series.length), vm.type === 'timecat' ? `largest: ${esc([...vm.series].filter((x) => !x.isOther).sort((a, b) => b.total - a.total)[0]?.name || '—')} · steadiest: ${esc(vm.series[0]?.name || '—')}` : vm.series.map((s) => esc(s.name)).join(', ')]);
        cells.push(['Peak bucket', fmtV(totals[pi]), `${fmtTz(vm.x[pi])} · ${tot ? Math.round(100 * totals[pi] / tot) : 0}% of total`, 'peak']);
        cells.push(['Latest bucket', fmtV(last), d == null ? 'no previous bucket' : `<span class="${d >= 0 ? 'ex-up' : 'ex-down'}">${d >= 0 ? '▲' : '▼'} ${d >= 9 ? '×' + fmtV(Math.round(last / prev)) : Math.abs(d * 100).toFixed(0) + '%'}</span> vs prev bucket (${fmtV(prev)})`]);
      }
      box.innerHTML = cells.map(([l, v, s, cls]) => `<div class="ex-kpi"><div class="label">${esc(l)}</div><div class="ex-kpi-v ${cls || ''}">${v}</div><div class="ex-kpi-s mono">${s}</div></div>`).join('');
      box.querySelectorAll('.ex-kpi').forEach((e) => { e.title = [...e.children].map((c) => c.textContent.trim()).filter(Boolean).join(' · '); });
    }

    function renderLegend(m) {
      const items = legendItems(m);
      const oth = m.series?.find((x) => x.isOther);
      $('.ex-legend').innerHTML = items.map((it) => {
        const isO = oth && it.name === oth.name;
        return `<button class="ex-lg${hidden.has(it.name) ? ' off' : ''}${isO ? ' other' : ''}" data-lg="${esc(it.name)}" title="${isO ? esc(oth.other.join(', ')) + ' · ' : ''}Click to toggle · Shift-click to isolate"><i style="${swStyle(it.name, it.color)}"></i>${esc(it.name)}<span>${fmtV(it.total)}</span></button>${isO ? '<button class="ex-lg expand" data-lg-expand="1" title="Split Other into its kinds">Expand ▸</button>' : ''}`;
      }).join('')
        + (expandOther && m.type === 'timecat' && m.nAll > 6 ? '<button class="ex-lg expand" data-lg-expand="0" title="Group small series into Other">◂ Top 5</button>' : '')
        + (hidden.size ? '<button class="ex-lg reset" data-lg-reset="1">Show all</button>' : '');
      const lg = $('.ex-legend');
      requestAnimationFrame(() => $('.ex-legend-row').classList.toggle('overflow', lg.scrollWidth > lg.clientWidth + 2 && lg.scrollLeft + lg.clientWidth < lg.scrollWidth - 2));
    }

    function chartOption(vm, useLog, cap, shr) {
      const rawVm = vm;
      if (shr) {
        const tt = vm.x.map((_, i) => vm.series.reduce((a, s) => a + (s.data[i] || 0), 0));
        vm = { ...vm, series: vm.series.map((s) => ({ ...s, raw: s.data, data: s.data.map((v, i) => (tt[i] ? (100 * v) / tt[i] : 0)) })) };
        useLog = false; cap = null;
      }
      const ax = { axisLine: { lineStyle: { color: chartTheme.axisLine } }, axisTick: { show: false }, axisLabel: { color: '#a29d8f', fontSize: 10, fontFamily: 'JetBrains Mono', hideOverlap: true }, splitLine: { lineStyle: { color: chartTheme.split } } };
      const n = vm.x.length;
      const stacked = (vm.type === 'timecat' && !useLog) || shr;
      const asLine = useLog ? vm.type !== 'cat' : vm.type === 'time' && n > 120;
      const totals = rawVm.x.map((_, i) => rawVm.series.reduce((a, s) => a + (s.data[i] || 0), 0));
      const series = vm.series.map((s) => ({
        name: s.name, type: asLine ? 'line' : 'bar', stack: stacked ? 't' : undefined,
        data: s.data.map((v, i) => { const y = useLog && !(v > 0) ? null : v; return vm.catColors ? { value: y, itemStyle: { color: vm.catColors[i], decal: util.kindDecal(vm.x?.[i]) } } : y; }), color: s.color, itemStyle: { color: s.color, borderRadius: stacked ? 0 : [2, 2, 0, 0], decal: util.kindDecal(s.name) },
        barMaxWidth: 26, showSymbol: asLine && n < 60, symbolSize: 4, connectNulls: true, lineStyle: { width: 1.6, type: util.isRing(s.name) ? [4, 3] : 'solid' },
        areaStyle: asLine && vm.series.length === 1 ? { opacity: 0.12 } : undefined, emphasis: { focus: 'series' },
      }));
      // peak annotation
      let pi, pv;
      if (stacked || vm.series.length === 1) { pv = Math.max(...totals); pi = totals.indexOf(pv); }
      else { pv = -Infinity; vm.series.forEach((s) => s.data.forEach((v, i) => { if (v > pv) { pv = v; pi = i; } })); }
      const narrow = (chart?.getWidth?.() || 800) < 600;
      const lbl = { show: true, position: 'top', distance: 4, color: '#e2c6c1', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono' };
      if (shr) { /* no peak marker in share view */ } else if (cap) {
        const pts = totals.map((t, i) => (t > cap ? [i, cap, t] : null)).filter(Boolean);
        series.push({ name: '__peak', type: 'scatter', data: pts, symbol: 'path://M0,4 L4,0 L8,4 L12,0 L16,4 L16,7 L12,3 L8,7 L4,3 L0,7 Z', symbolSize: [16, 7], z: 10, silent: true, tooltip: { show: false },
          itemStyle: { color: '#e2c6c1' }, label: { ...lbl, formatter: (p) => (p.data[2] === pv ? `${compact(p.data[2])} peak` : narrow ? '' : compact(p.data[2])) } });
      } else if (pi != null && pv > 0) {
        series.push({ name: '__peak', type: 'scatter', data: [[pi, pv]], symbol: 'circle', symbolSize: 7, z: 10, silent: true, tooltip: { show: false },
          itemStyle: { color: '#e2c6c1', borderColor: '#111621', borderWidth: 2 }, label: { ...lbl, formatter: () => `peak ${compact(pv)}` } });
      }
      return {
        backgroundColor: 'transparent', textStyle: chartTheme.textStyle, animationDuration: 300,
        // rotated category labels hang left of their tick; leave room so the first one is not cut at the edge
        grid: { left: vm.type === 'cat' && n > 8 ? 60 : 10, right: 24, top: 30, bottom: 6, containLabel: true },
        tooltip: {
          trigger: 'axis', axisPointer: { type: asLine ? 'line' : 'shadow', lineStyle: { color: '#5f5b52' }, shadowStyle: { color: 'rgba(255,255,255,.03)' } },
          backgroundColor: '#161c28', borderColor: '#2c3547', padding: [8, 10], textStyle: { color: '#e9e3d4', fontSize: 11, fontFamily: 'JetBrains Mono' }, confine: true,
          formatter: (ps) => {
            const list = ps.filter((p) => p.seriesName !== '__peak' && p.value != null && Number(p.value) !== 0).sort((a, b) => b.value - a.value);
            const i = ps[0]?.dataIndex; const tot = totals[i] || 0;
            const head = `<div style="color:#b7b1a2;margin-bottom:5px">${esc(vm.type !== 'cat' ? fmtTz(vm.x[i]) : (vm.labels[i] ?? ''))}</div>`;
            const rowsH = list.slice(0, 12).map((p) => `<div style="display:flex;gap:14px;justify-content:space-between"><span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${p.color};margin-right:6px"></i>${esc(p.seriesName)}</span><b style="font-weight:500">${shr ? fmt(rawVm.series[p.seriesIndex]?.data[i]) : fmt(p.value)}${tot && list.length > 1 ? ` <span style="color:#a29d8f">${shr ? p.value.toFixed(1) : Math.round(100 * p.value / tot)}%</span>` : ''}</b></div>`).join('');
            const more = list.length > 12 ? `<div style="color:#a29d8f">+${list.length - 12} more</div>` : '';
            const foot = list.length > 1 ? `<div style="display:flex;justify-content:space-between;border-top:1px solid #2c3547;margin-top:5px;padding-top:5px"><span style="color:#b7b1a2">Total</span><b>${fmt(tot)}</b></div>` : '';
            return head + rowsH + more + foot;
          },
        },
        xAxis: { type: 'category', data: vm.labels, ...ax, splitLine: { show: false }, axisLabel: { ...ax.axisLabel, rotate: vm.type === 'cat' && n > 8 ? 30 : 0, width: 96, overflow: 'truncate' } },
        yAxis: useLog ? { type: 'log', logBase: 10, min: 1, ...ax, axisLine: { show: false }, axisLabel: { ...ax.axisLabel, formatter: (v) => compact(v) } }
          : { type: 'value', max: shr ? 100 : cap || null, ...ax, axisLine: { show: false }, axisLabel: { ...ax.axisLabel, formatter: (v) => (shr ? `${v}%` : compact(v)) } },
        series,
      };
    }

    function renderChart() {
      const pnl = $('.ex-pnl-chart');
      $('.ex-results').classList.toggle('no-chart', !model);
      if (!model) { pnl.hidden = true; chart?.clear(); return; }
      pnl.hidden = false;
      const vm = visibleModel(model);
      renderKpis(vm); renderLegend(model);
      $('.ex-ser').textContent = `${model.cats ? vm.x.length + ' cats' : vm.series.length + ' series'} · ${vm.x.length} pts`;
      // auto scale: ratio of biggest bucket to the median bucket
      const totals = vm.x.map((_, i) => vm.series.reduce((a, s) => a + (s.data[i] || 0), 0)).filter((v) => v > 0).sort((a, b) => a - b);
      const ratio = totals.length > 2 ? totals[totals.length - 1] / Math.max(1e-9, totals[Math.floor(totals.length / 2)]) : 1;
      let useLog = yScale === 'log' || (yScale === 'auto' && ratio > 20);
      // Auto + stacked categories: never stack on log. Clip the outlier bucket(s) on a linear axis instead.
      let cap = null, clipped = 0;
      if (yScale === 'auto' && useLog && model.type === 'timecat' && totals.length > 3) {
        const p85 = totals[Math.floor(totals.length * 0.85)];
        const raw = Math.max(p85 * 3, totals[Math.floor(totals.length / 2)] * 4);
        const mag = 10 ** Math.floor(Math.log10(raw));
        cap = Math.ceil(raw / mag) * mag;
        clipped = totals.filter((v) => v > cap).length;
        if (clipped && clipped <= Math.max(3, totals.length * 0.1)) useLog = false; else { cap = null; clipped = 0; }
      }
      // dominance: median over buckets of the largest series' share
      const domArr = vm.x.map((_, i) => { const t = vm.series.reduce((a, s) => a + (s.data[i] || 0), 0); return t ? Math.max(...vm.series.map((s) => s.data[i] || 0)) / t : 0; }).filter((v) => v > 0).sort((a, b) => a - b);
      const dom = domArr.length ? domArr[Math.floor(domArr.length / 2)] : 0;
      const canShare = model.type === 'timecat' && vm.series.length > 1;
      const shr = share && canShare;
      const sseg = $('.ex-share-seg');
      sseg.hidden = !canShare;
      sseg.classList.toggle('hint', canShare && !shr && dom > 0.85);
      sseg.title = canShare && dom > 0.85 && !shr ? `One series is ${Math.round(dom * 100)}% of a typical bucket — Share % makes the minority kinds readable` : 'Absolute counts or share of each bucket (100% stacked)';
      el.querySelectorAll('[data-share]').forEach((b) => b.classList.toggle('on', (b.dataset.share === '1') === shr));
      if (shr) { useLog = false; cap = null; clipped = 0; }
      el.querySelectorAll('[data-scale]').forEach((b) => b.classList.toggle('on', b.dataset.scale === yScale));
      el.querySelector('[data-scale="auto"]').textContent = yScale === 'auto' ? `Auto · ${useLog ? 'log' : cap ? 'clip' : 'lin'}` : 'Auto';
      const shape = shr ? '100% stacked share per bucket' : model.type === 'timecat' ? (useLog ? 'lines, overlaid (not stacked)' : 'stacked bars') : model.type === 'cat' ? 'grouped bars' : (useLog || vm.x.length > 120 ? 'line' : 'bars');
      $('.ex-chart-sub').innerHTML = `${esc(model.v.name)} by ${esc(model.timeCol ? model.timeCol.name : model.catCol.name)}${model.type === 'timecat' ? ` × ${esc(model.catCol.name)}` : ''} · <b>${shr ? 'share %' : useLog ? 'log scale' : 'linear'}</b> · ${shape}${model.nAll > vm.series.length + (hidden.size ? 0 : 0) && model.series.some((x) => x.isOther) ? ` · top 5 of ${model.nAll} + Other` : ''}`
        + (cap ? ` · <span class="ex-clip">axis capped at ${compact(cap)} — ${clipped} outlier bucket${clipped > 1 ? 's' : ''} clipped (peak ${compact(totals[totals.length - 1])}, ${Math.round(ratio)}× median)</span>` : useLog && yScale === 'auto' ? ` — auto: peak is ${Math.round(ratio)}× the median bucket` : '');
      $('.ex-chart-sub').title = $('.ex-chart-sub').textContent;
      { const t = model.type === 'cat' ? `${model.v.name} by ${model.catCol.name}` : `${model.v.name} per ${model.timeCol.name}${model.catCol ? ' · by ' + model.catCol.name : ''}`;
        $('.ex-pnl-chart .panel-title').textContent = t.charAt(0).toUpperCase() + t.slice(1); }   // sentence case, like every panel title
      if (!chart) chart = window.echarts.init(   // loaded: runSql awaited need('echarts') before any result renders
        $('.ex-chart'), null, { renderer: 'canvas' });
      chart.setOption(chartOption(vm, useLog, cap, shr), true);
      requestAnimationFrame(() => chart.resize());
    }

    function tableRows() {
      if (!model?.filterable || !hidden.size) return result.rows;
      const ci = model.catCol.i;
      const hid = new Set([...hidden].flatMap((k) => model.series.find((s) => s.name === k)?.other || [k]));
      return result.rows.filter((r) => !hid.has(String(r[ci] ?? 'null')));
    }

    function renderTable() {
      const grid = $('.ex-grid');
      const { columns } = result;
      const meta = analyse(columns, result.rows);
      let data = tableRows();
      if (sort) {
        const { i, dir } = sort;
        data = [...data].sort((a, b) => { const x = a[i], y = b[i]; if (x === y) return 0; if (x === null) return 1; if (y === null) return -1; return (x > y ? 1 : -1) * dir; });
      }
      const filt = data.length !== result.rows.length;
      $('.ex-pnl-table .panel-badge').textContent = `${fmt(data.length)}${filt ? ' / ' + fmt(result.rows.length) : ''} rows · ${result.ms < 1000 ? result.ms.toFixed(0) + ' ms' : (result.ms / 1000).toFixed(2) + ' s'}`;
      $('.ex-filt').hidden = !filt;
      if (!data.length) { grid.innerHTML = result.rows.length ? emptyState({ title: 'Every row is filtered out', why: 'Clear the legend filter to see them again.', size: 'sm' }) : emptyState({ title: 'No rows', why: 'The query ran but matched nothing. Loosen its WHERE clause or widen its time window.', size: 'sm' }); return; }
      const MAXR = 1000;
      const shown = data.slice(0, MAXR);
      const idI = columns.indexOf('id');
      grid.innerHTML = `<table class="ex-table${columns.length <= 4 ? ' fit' : ''}"><thead><tr><th class="ex-rn">#</th>${meta.map((c) =>
        `<th data-sort="${c.i}" class="${c.num ? 'r' : ''}${sort?.i === c.i ? ' sorted' : ''}"${c.time ? ` title="${esc(TIME_COL_TIP)}"` : ''}><span>${esc(c.name)}</span><em>${c.num ? 'num' : c.time ? 'time · UTC' : c.str ? 'text' : ''}</em>${sort?.i === c.i ? (sort.dir > 0 ? ' ▲' : ' ▼') : ''}</th>`).join('')}</tr></thead>
        <tbody>${shown.map((r, ri) => `<tr${idI >= 0 && columns.includes('kind') && r[idI] ? ` data-id="${esc(r[idI])}"` : ''}><td class="ex-rn">${ri + 1}</td>${meta.map((c) => `<td class="${c.num ? 'r' : ''}"${!c.num && r[c.i] != null && String(r[c.i]).length > 24 ? ` title="${esc(String(r[c.i]).slice(0, 500))}"` : ''}>${cell(r[c.i], c)}</td>`).join('')}</tr>`).join('')}</tbody></table>
        ${data.length > MAXR ? `<div class="ex-more mono">Showing first ${fmt(MAXR)} of ${fmt(data.length)} rows · export CSV for all</div>` : ''}`;
    }

    function renderResult(fresh = false) {
      if (!result) return;
      if (fresh) { hidden = new Set(); expandOther = false; share = false; model = buildModel(analyse(result.columns, result.rows), result.rows); }
      else model = buildModel(analyse(result.columns, result.rows), result.rows);
      $('.ex-pnl-table .panel-updated').hidden = false;
      $('.ex-pnl-table .panel-updated span').textContent = ago(result.at);
      $('.ex-pnl-chart .panel-updated span').textContent = ago(result.at);
      renderChart(); renderTable();
    }

    function exportCsv() {
      if (!result?.rows.length) return;
      const lines = [result.columns.map(csvCell).join(','), ...result.rows.map((r) => r.map(csvCell).join(','))];
      const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `nightdesk-query-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '')}.csv`;
      a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      toast(`Exported ${fmt(result.rows.length)} rows`);
    }

    // ---------------------------------------------------------------- schema
    // Lists the lake's own tables from information_schema, not SHOW TABLES: SHOW TABLES also returns
    // per-connection TEMP tables (the netlog matcher's _nl_*) that exist on only one pooled server
    // connection, so DESCRIBE/count on them 400s at random. Names starting with '_' are internal too.
    // Columns come from one information_schema query; counts from one UNION, falling back to a count per
    // table if it fails, so one unreadable table never blanks the whole rail.
    // settings is left out: the console refuses it (it holds secrets such as the notification address; api.SQL_PRIVATE_TABLES)
    const SCOPE = `table_catalog = current_database() AND table_schema = 'main' AND table_name <> 'settings'`;
    async function loadSchema() {
      try {
        const t = await api.sql(`SELECT table_name FROM information_schema.tables WHERE ${SCOPE} ORDER BY table_name`);
        const names = t.rows.map((r) => r[0]).filter((n) => typeof n === 'string' && !n.startsWith('_'));
        const qi = (n) => `"${n.replace(/"/g, '""')}"`;
        const colRows = await api.sql(`SELECT table_name, column_name, data_type FROM information_schema.columns WHERE ${SCOPE} ORDER BY table_name, ordinal_position`).catch(() => ({ rows: [] }));
        const cols = new Map(names.map((n) => [n, []]));
        for (const [tn, cn, dt] of colRows.rows) cols.get(tn)?.push([cn, dt]);
        const descs = names.map((n) => ({ rows: cols.get(n) }));
        const countOne = (n) => api.sql(`SELECT count(*) FROM ${qi(n)}`).then((r) => [[n, r.rows[0][0]]]).catch(() => []);
        const counts = names.length
          ? await api.sql(names.map((n) => `SELECT ${LIT(n)} AS t, count(*) AS n FROM ${qi(n)}`).join(' UNION ALL '))
            .then((r) => r.rows).catch(() => Promise.all(names.map(countOne)).then((a) => a.flat()))
          : [];
        const cnt = Object.fromEntries(counts);
        const openT = LS.get('nd.explorer.openTables', ['events']);
        $('.ex-tables').innerHTML = names.map((n, i) => `
          <details class="ex-tbl"${openT.includes(n) ? ' open' : ''} data-t="${esc(n)}">
            <summary><svg class="i caret"><use href="#i-caret"/></svg><span class="ex-tn">${esc(n)}</span><span class="ex-tc mono">${cnt[n] != null ? compact(cnt[n]) : ''}</span><button class="ex-peek" data-peek="${esc(n)}" title="SELECT * FROM ${esc(n)}">▸</button></summary>
            ${descs[i].rows.map((c) => `<button class="ex-col" data-col="${esc(c[0])}" title="Insert ${esc(c[0])}"><span>${esc(c[0])}</span><em>${esc(String(c[1]).replace('TIMESTAMP WITH TIME ZONE', 'TIMESTAMPTZ').toLowerCase())}</em></button>`).join('')}
          </details>`).join('');
        el.querySelectorAll('.ex-tbl').forEach((d) => d.addEventListener('toggle', () => {
          LS.set('nd.explorer.openTables', [...el.querySelectorAll('.ex-tbl[open]')].map((x) => x.dataset.t));
        }));
      } catch (err) {
        $('.ex-tables').innerHTML = errorState({ retry: loadSchema, title: "Couldn't read the tables", why: 'The database did not answer.', err: err.message, size: 'inline' });
      }
    }

    // Event kinds: all-time totals, plus "+N" new within the sub-bar's time range (none for All time).
    const RANGE_L = { 1: '1h', 6: '6h', 24: '24h', 168: '7d', 720: '30d' };
    async function loadKinds() {
      try {
        const h = Number(store.get?.().hours ?? 24);
        const rl = RANGE_L[h] || (h > 0 ? `${h}h` : '');
        const s = await api.summary({ since_hours: h > 0 ? h : 24 });
        const max = Math.max(1, ...s.kinds.map((k) => k.total));
        // the dashboard's count (each address once, v1.2 corroboration), not stored rows: a query can return more
        const tot = $('.ex-kinds-tot');
        tot.textContent = `${compact(s.kinds.reduce((a, k) => a + (k.total || 0), 0))} total${rl ? ` · +${compact(s.kinds.reduce((a, k) => a + (k.recent || 0), 0))} in ${rl}` : ''}`;
        tot.title = `${util.COUNT_RULE} A query can return more rows (${fmt(s.totals.events)} records stored).`;
        $('.ex-kinds').innerHTML = s.kinds.map((k) => {
          const m = kindMeta(k.kind);
          return `<button class="ex-kd" data-kind="${esc(k.kind)}" title="${esc(m.label)} · ${fmt(k.total)} total${rl ? ` · ${fmt(k.recent)} in ${rl}` : ''}. ${esc(util.COUNT_RULE)}">
            <i style="${swStyle(k.kind, m.color)}"></i><span class="ex-kn">${esc(k.kind)}</span><span class="ex-kr mono">${rl && k.recent ? '+' + compact(k.recent) : ''}</span><span class="ex-kc mono">${compact(k.total)}</span>
            <b style="width:${(100 * k.total / max).toFixed(1)}%;background:${m.color}"></b></button>`;
        }).join('');
      } catch {}
    }

    // #explorer/find?q=<text>&country=<CC>: the old "Open in Explorer" links (Network's pivots) open the matching
    // events as SQL. Read once, then the hash goes back to #explorer so a reload does not re-run it.
    function fromHash() {
      const m = location.hash.match(/^#\/?explorer\/find\?(.*)$/);
      if (!m) return false;
      const p = new URLSearchParams(m[1]);
      const q = (p.get('q') || '').trim(), cc = (p.get('country') || '').trim().toUpperCase();
      const c = [];
      if (q) c.push(`(title ILIKE ${LIT('%' + q + '%')} OR summary ILIKE ${LIT('%' + q + '%')} OR ip = ${LIT(q)} OR asn ILIKE ${LIT(q)} OR list_contains(tags, ${LIT(q)}))`);
      if (/^[A-Z]{2}$/.test(cc)) c.push(`country = ${LIT(cc)}`);
      history.replaceState(null, '', '#explorer');
      if (!c.length) return false;
      ta.value = `SELECT ts, kind, source, title, country, ip, asn, severity, id\nFROM events\nWHERE ${c.join(' AND ')}\nORDER BY ts DESC\nLIMIT 1000`;
      syncHl(); LS.set('nd.explorer.sql', ta.value);
      runSql();
      return true;
    }

    // ---------------------------------------------------------------- events wiring
    el.addEventListener('click', (e) => {
      const t = e.target.closest('[data-share],[data-lg-expand],[data-lg],[data-lg-reset],[data-scale],[data-tab],[data-act],[data-ex],[data-col],[data-peek],[data-kind],[data-sort],tr[data-id]');
      if (!t) return;
      if (t.dataset.tab) return setTab();
      if (t.dataset.share !== undefined) { share = t.dataset.share === '1'; if (model) renderChart(); return; }
      if (t.dataset.lgExpand !== undefined) { expandOther = t.dataset.lgExpand === '1'; hidden = new Set(); renderResult(); return; }
      if (t.dataset.lgReset) { hidden = new Set(); renderChart(); renderTable(); return; }
      if (t.dataset.lg !== undefined) {
        const k = t.dataset.lg;
        if (e.shiftKey) { const all = legendItems(model).map((x) => x.name); hidden = new Set(all.filter((x) => x !== k)); }
        else if (hidden.has(k)) hidden.delete(k); else hidden.add(k);
        renderChart(); renderTable(); return;
      }
      if (t.dataset.scale) { yScale = t.dataset.scale; if (model) renderChart(); return; }
      if (t.dataset.ex !== undefined) { setTab('sql'); return runSql(EXAMPLES[+t.dataset.ex][1]); }
      if (t.dataset.peek) { e.preventDefault(); setTab('sql'); return runSql(`SELECT *\nFROM ${t.dataset.peek}\nLIMIT 200`); }
      if (t.dataset.col) { setTab('sql'); return insertAtCursor(t.dataset.col); }
      if (t.dataset.kind) {
        setTab('sql');
        return runSql(`SELECT ts, source, title, country, ip, asn, severity, id, kind\nFROM events\nWHERE kind = '${t.dataset.kind.replace(/'/g, "''")}'\nORDER BY ts DESC\nLIMIT 500`);
      }
      if (t.dataset.sort !== undefined) {
        const i = +t.dataset.sort;
        sort = sort?.i === i ? (sort.dir > 0 ? { i, dir: -1 } : null) : { i, dir: 1 };
        return renderTable();
      }
      if (t.matches('tr[data-id]')) return openEvent(t.dataset.id);
      const act = t.dataset.act;
      if (act === 'run') runSql();
      else if (act === 'csv') exportCsv();
      else if (act === 'chart') { chartMode = chartMode === 'off' ? 'auto' : 'off'; t.classList.toggle('on', chartMode !== 'off'); if (result) renderResult(); }
      else if (act === 'lg-more') { const lg = $('.ex-legend'); lg.scrollBy({ left: lg.clientWidth * 0.7, behavior: 'smooth' }); }
      else if (act === 'max') { const p = t.closest('.ex-pnl'); p.classList.toggle('max'); requestAnimationFrame(() => chart?.resize()); }
      else if (act === 'rail') el.querySelector('.ex-wrap').classList.toggle('side-open');
      else if (act === 'schema') el.querySelector('.ex-wrap').classList.toggle('side-open');
      else if (act === 'edit-sql' && isPhone()) editSheet();
      else if (act === 'edit-sql') { ta.focus(); ta.scrollIntoView({ block: 'nearest' }); }
    });
    // Explorer depends only on the global range (its text search is its own). Other store changes, such as the
    // Ops panel filter, are ignored, and while Explorer is hidden a range change waits until it is shown again.
    const visible = () => el.classList.contains('active');
    const syncHours = () => {
      const h = store.get?.().hours;
      if (h == null || h === hours) return;
      hours = h; loadKinds();
    };
    unsubscribe?.(); // a re-mount (after a failed first mount) never leaves a second subscriber behind
    unsubscribe = store.subscribe?.(() => { if (visible()) syncHours(); }) || null;

    const ro = new ResizeObserver(debounce(() => { const c = $('.ex-chart'); if (c.clientWidth > 1 && c.clientHeight > 1) chart?.resize(); }, 80));   // not while hidden (0x0)
    ro.observe($('.ex-chart'));

    $('.ex-legend').addEventListener('scroll', debounce(() => { const lg = $('.ex-legend'); $('.ex-legend-row').classList.toggle('overflow', lg.scrollLeft + lg.clientWidth < lg.scrollWidth - 2); }, 50));
    const tick = setInterval(() => { if (result?.at) el.querySelectorAll('.ex-pnl .panel-updated span').forEach((n) => (n.textContent = ago(result.at))); }, 15000);
    setTab();
    loadSchema(); loadKinds();
    if (!fromHash()) runSql();

    inst = {
      show() { syncHours(); fromHash(); requestAnimationFrame(() => chart?.resize()); },
      destroy() { ro.disconnect(); clearInterval(tick); chart?.dispose(); unsubscribe?.(); unsubscribe = null; },
    };
    return inst;
}

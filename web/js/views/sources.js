// Sources: the ingest catalog, shown inside Settings › Sources (views/settings/sources.js; the old #sources route
// redirects there). Pick prebuilt batch / stream sources, watch their health, run them on demand, inspect run
// history (raw files in the lake) and upload custom batches. Retention moved to Settings › Data and retention.
import { mountPipelineStatus } from './sources-status.js';
import { safeUrl } from '../core/util.js';
import * as T from '../core/time.js';
import { emptyState, errorState, loadingState } from '../core/view.js';

const CATS = [
  ['threat', 'Threat intelligence', 'Bad-reputation addresses, botnet controllers, scanners, hijacked networks'],
  ['vuln', 'Vulnerabilities', 'Exploited and newly published CVEs'],
  ['infra', 'Internet infrastructure', 'Routing, outages and anonymity networks'],
  ['news', 'News & advisories', 'Security press and government advisories'],
  ['social', 'Social', 'Live posts from the security community'],
  ['advanced', 'Advanced', 'Heavy live sources, off unless you turn them on. RIS Live follows only the networks in Routing watch.'],
];
// The routing watch sources: set up in the Routing watch section above the catalog (settings/routing.js).
const ROUTING_IDS = new Set(['rpki_roas', 'cf_radar_bgp', 'ripestat', 'ris_live']);
// Source names keep the publisher's own words; the jargon in them gets the glossary popover (help/glossary.js).
const GLOSS = [[/\bC2\b/g, 'c2'], [/\bIOCs?\b/g, 'ioc'], [/\bnetblocks?\b/gi, 'cidr'], [/\bKEV\b/g, 'kev'], [/\bEPSS\b/g, 'epss'], [/\bBGP\b/g, 'bgp']];
function glossName(name) {
  let out = String(name ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  for (const [re, id] of GLOSS) out = out.replace(re, (m) => `<span data-term="${id}">${m}</span>`);
  return out;
}
const STATUS = {
  live: ['ok', 'Live'], ok: ['ok', 'OK'], idle: ['ok', 'Scheduled'], running: ['run', 'Running'],
  error: ['err', 'Error'], reconnecting: ['warn', 'Reconnecting'], disabled: ['off', 'Off'],
  needs_key: ['off', 'Needs key'], offline: ['off', 'Paused'], paused: ['warn', 'Paused'],
};
// The health split: every source in exactly one bucket, so the numbers add up to the number of sources. Help ›
// Health (help/status.js) counts "on" the same way: enabled and not missing a key.
export function healthSplit(list) {
  const b = { live: 0, ok: 0, paused: 0, error: 0, off: 0 };
  for (const s of list) {
    if (!s.enabled || s.unavailable) b.off++;
    else if (s.status === 'live') b.live++;
    else if (['error', 'reconnecting'].includes(s.status)) b.error++;
    else if (s.status === 'offline' || s.status === 'paused') b.paused++;
    else b.ok++;   // ok, scheduled, running, or waiting for a first run
  }
  return b;
}

function every(sec) {
  if (!sec) return '';
  if (sec % 86400 === 0) return `${sec / 86400}d`;
  if (sec % 3600 === 0) return `${sec / 3600}h`;
  if (sec >= 3600) return `${(sec / 3600).toFixed(1)}h`;
  return `${Math.round(sec / 60)}m`;
}
function until(t) {
  const d = (new Date(t).getTime() - Date.now()) / 1000;
  if (d <= 0) return 'due';
  if (d < 3600) return `in ${Math.ceil(d / 60)}m`;
  return `in ${(d / 3600).toFixed(1)}h`;
}
function bytes(b) {
  if (b == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}
function dur(a, b) {
  if (!a || !b) return '—';
  const ms = new Date(b) - new Date(a);
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

// Mount the catalog into el. Returns { reload, destroy }.
export function mountSources(el, ctx) {
  {
    const { api, live, util } = ctx;
    const { h, esc, ago, fmt, compact, toast, debounce } = util;
    let sources = [];
    let summary = null;
    let lake = null;
    let loadErr = null;   // the last /api/sources failure; cleared by the next good load
    let retryT = null;
    let filter = { cat: 'all', mode: 'all', q: '' };
    const runsCache = new Map();   // id -> runs[]
    const open = new Set();        // expanded history
    const busy = new Set();        // run-now in flight

    el.innerHTML = `
      <div class="src-wrap">
        <div class="src-head">
          <div>
            <h3 class="src-h1">Every source</h3>
            <div class="src-sub">Public lists and news that Night Desk collects for you. Most are checked on a schedule; a few stay connected and send updates as they happen. Only what changed is saved.</div>
          </div>
          <div class="src-head-act">
            <button class="chip" data-act="refresh"><svg class="i"><use href="#i-clock"/></svg>Refresh</button>
            <button class="chip on" data-act="to-upload"><svg class="i"><use href="#i-plus"/></svg>Add your own file</button>
          </div>
        </div>
        <div class="src-kpis"></div>
        <section class="src-group ps-sec" id="src-pipeline-sec"></section>
        <div class="src-bar">
          <div class="src-cats"></div>
          <div class="src-modes"></div>
          <label class="src-search"><svg class="i"><use href="#i-search"/></svg><input placeholder="Filter sources…" aria-label="Filter sources" autocomplete="off"></label>
        </div>
        <div class="src-groups"></div>
        <section class="src-group" id="src-upload-sec">
          <div class="src-group-head"><span class="src-gname">Add your own file</span><span class="src-gdesc">Bring your own list of addresses or events: CSV, JSON, NDJSON or one IP per line. Night Desk works out the columns (ip, lat/lon, country, time, title, severity…).</span></div>
          <div class="src-upload">
            <label class="src-drop" tabindex="0">
              <input type="file" accept=".csv,.tsv,.json,.ndjson,.jsonl,.txt,.list" hidden>
              <svg viewBox="0 0 24 24" class="src-drop-ico"><path d="M12 16V4m0 0-4.5 4.5M12 4l4.5 4.5M4 15v3.5A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5V15" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
              <div class="src-drop-t">Drop a file here or <u>browse</u></div>
              <div class="src-drop-s mono">.csv · .json · .ndjson · .txt (one IP per line)</div>
              <div class="src-drop-f mono" hidden></div>
            </label>
            <div class="src-up-form">
              <div class="label">Label</div>
              <input class="src-input mono" name="label" placeholder="e.g. honeypot-oct" maxlength="40">
              <div class="src-up-hint">Tagged on every row so you can filter it later (source = <span class="mono">upload</span>).</div>
              <button class="src-btn primary" data-act="upload" disabled>Add file</button>
              <div class="src-up-res"></div>
            </div>
          </div>
        </section>
      </div>`;

    const $ = (s) => el.querySelector(s);
    const groupsEl = $('.src-groups');

    // ---------------------------------------------------------------- KPIs
    function renderKpis() {
      // nothing could be read: dashes, never zeros that look like real counts
      const failed = loadErr && !sources.length;
      const n = (v) => (failed || v == null ? '—' : fmt(v));
      const b = healthSplit(sources);
      const t = summary?.totals || {};
      // stored records in the last 24 h (totals.recent); the kind totals count each address once, so they can be fewer
      const recent = summary ? (summary.totals?.recent ?? (summary.kinds || []).reduce((a, k) => a + (k.recent || 0), 0)) : null;
      const lastIngest = t.last_ingest;
      const sub = summary ? `${n(recent)} in last 24h · ${n(t.ips)} IPs · ${n(t.countries)} countries` : (failed ? 'could not be read' : '—');
      const bucket = (v, word, color, title) => `<span title="${esc(title)}"><b class="kpi"${color ? ` style="color:${color}"` : ''}>${failed ? '—' : v}</b><i>${word}</i></span>`;
      $('.src-kpis').innerHTML = `
        <div class="src-kpi"><div class="label">Records collected</div><div class="kpi">${n(t.events)}</div>
          <div class="src-kpi-s counts-wrap" title="${esc(sub)}">${sub}</div></div>
        <div class="src-kpi"><div class="label">Sources healthy</div>
          <div class="src-kpi-split counts-split" ${failed ? '' : `title="${esc(`${sources.length} sources: ${b.live} live, ${b.ok} ok, ${b.paused} paused by offline mode, ${b.error} with an error, ${b.off} off`)}"`}>
            ${bucket(b.live, 'live', b.live ? 'var(--accent)' : '', 'Connected and receiving updates')}
            ${bucket(b.ok, 'ok', '', 'On, and the last check worked (or the first one is still to come)')}
            ${b.paused ? bucket(b.paused, 'paused', 'var(--muted)', 'On, but paused: offline mode, or the routing watch’s daily data limit') : ''}
            ${bucket(b.error, 'error', b.error ? 'var(--red)' : 'var(--faint)', 'On, and the last check failed')}
            ${bucket(b.off, 'off', 'var(--faint)', 'Turned off, or needs a key')}
          </div>
          <div class="src-health">${sources.map((s) => `<span class="src-hb ${(STATUS[s.status] || ['off'])[0]}" title="${esc(s.name)} · ${esc(s.status || '')}"></span>`).join('')}</div></div>
        <div class="src-kpi"><div class="label">Disk used</div><div class="kpi">${lake ? bytes(lake.bytes) : '—'}</div>
          <div class="src-kpi-s">${lake ? `${fmt(lake.files)} files` : 'size not available'}</div>
          ${lake ? `<div class="src-lakebar">${['raw', 'uploads', 'ref'].map((k) => `<span class="lk-${k}" style="flex:${Math.max(lake.parts[k].bytes, 1)}" title="${k}: ${bytes(lake.parts[k].bytes)} · ${lake.parts[k].files} files"></span>`).join('')}<span class="lk-db" style="flex:${Math.max(lake.db_bytes, 1)}" title="duckdb: ${bytes(lake.db_bytes)}"></span></div>
          <div class="src-lakeleg mono"><span><i class="lk-raw"></i>collected ${bytes(lake.parts.raw.bytes)}</span><span><i class="lk-db"></i>database ${bytes(lake.db_bytes)}</span><span><i class="lk-ref"></i>reference ${bytes(lake.parts.ref.bytes)}</span><span><i class="lk-uploads"></i>your files ${bytes(lake.parts.uploads.bytes)}</span></div>
          <details class="finishb-tech"><summary>Technical details</summary><p>Data folder <span class="mono">${esc(lake.path)}</span>. Raw downloads are kept as compressed files there (the "lake"); everything is loaded into a DuckDB database for searching.</p></details>` : ''}</div>
        <div class="src-kpi"><div class="label">Last update</div><div class="kpi" data-ago="${esc(lastIngest || '')}">${lastIngest ? ago(lastIngest) : '—'}</div>
          <div class="src-kpi-s mono">${lastIngest ? esc(T.stamp(lastIngest, { zone: true })) : '—'}</div></div>`;
    }

    // ---------------------------------------------------------------- filters
    function renderBar() {
      const cnt = (c) => sources.filter((s) => c === 'all' || s.category === c).length;
      $('.src-cats').innerHTML = [['all', 'All'], ...CATS.map(([id, l]) => [id, l.split(' ')[0]])]
        .map(([id, l]) => `<button class="chip${filter.cat === id ? ' on' : ''}" data-cat="${id}">${esc(l)}<span class="n">${cnt(id)}</span></button>`).join('');
      $('.src-modes').innerHTML = [['all', 'All'], ['batch', 'On a schedule'], ['stream', 'Live']]
        .map(([id, l]) => `<button class="${filter.mode === id ? 'on' : ''}" data-mode="${id}">${l}</button>`).join('');
    }

    // ---------------------------------------------------------------- cards
    function visible(s) {
      if (filter.cat !== 'all' && s.category !== filter.cat) return false;
      if (filter.mode !== 'all' && s.mode !== filter.mode) return false;
      if (filter.q) {
        const q = filter.q.toLowerCase();
        if (![s.name, s.provider, s.description, s.id].join(' ').toLowerCase().includes(q)) return false;
      }
      return true;
    }

    function spark(id) {
      const runs = (runsCache.get(id) || []).slice(0, 24).reverse();
      const N = 24;
      const max = Math.max(1, ...runs.map((r) => r.items || 0));
      const okN = runs.filter((r) => r.ok).length;
      const bars = Array.from({ length: N - runs.length }, () => '<i class="nil"></i>').join('') + runs.map((r) =>
        `<i class="${r.ok ? '' : 'bad'}" style="height:${r.ok ? Math.max(12, Math.round(100 * (r.items || 0) / max)) : 100}%" title="${esc(T.stamp(r.started, { zone: true }))} · ${r.ok ? fmt(r.items) + ' items' : 'failed'}"></i>`).join('');
      return `<div class="src-c-run"><div class="src-spark" title="Items per run, last ${runs.length} runs">${bars}</div>
        <span class="mono">${runs.length ? `${runs.length} run${runs.length > 1 ? 's' : ''} · <b class="${okN === runs.length ? 'src-ok' : 'src-err'}">${okN}/${runs.length} ok</b>` : 'no runs logged'}</span></div>`;
    }

    const rel = (p) => (lake?.path && p.startsWith(lake.path + '/') ? p.slice(lake.path.length + 1) : p);
    function stored(r) {
      if (!r.ok || r.records_changed == null) return '—';
      if (!r.records_changed && !r.records_removed) return '<span class="src-dim">no change</span>';
      return `+${fmt(r.records_changed)}${r.records_removed ? ` <span class="src-err">−${fmt(r.records_removed)}</span>` : ''}`;
    }
    function historyHtml(s) {
      const runs = runsCache.get(s.id);
      if (!runs) return loadingState('Loading run history…', { size: 'sm' });
      if (!runs.length) return emptyState({ why: s.mode === 'stream' ? 'Live sources send updates as they happen, so there are no separate runs to list.' : 'No runs recorded yet.', size: 'sm' });
      return `<table class="src-hist"><thead><tr><th>Started (${esc(T.zoneName())})</th><th>Took</th><th class="r">Items</th><th class="r" title="Records saved: new or changed, and removed">Saved</th><th>Result</th></tr></thead><tbody>
        ${runs.map((r) => `<tr>
          <td>${esc(T.stamp(r.started, { seconds: true }))}</td>
          <td>${dur(r.started, r.finished)}</td>
          <td class="r">${r.ok ? fmt(r.items) : '—'}</td>
          <td class="r">${stored(r)}</td>
          <td>${r.ok ? '<span class="src-ok">ok</span>' : `<span class="src-err" title="${esc(r.error || '')}">${esc((r.error || 'error').slice(0, 60))}</span>`}</td>
        </tr><tr class="src-hist-p"><td colspan="5" class="src-path" title="Click to copy · ${esc(r.raw_path || '')}" data-copy="${esc(r.raw_path || '')}">${r.raw_path ? `<span><em>lake/</em>${esc(rel(r.raw_path))}&lrm;</span>` : `<span class="src-dim">${r.ok ? 'nothing changed, nothing stored' : 'no raw file'}</span>`}</td></tr>`).join('')}</tbody></table>`;
    }

    function cardHtml(s) {
      const [cls, label] = s.needs === 'watchlist' ? ['off', 'Waiting'] : (STATUS[s.status] || ['off', s.status || 'Unknown']);
      const off = !s.enabled;
      const desc = s.description || '';
      const cut = desc.search(/Off by default:/i);
      const body = cut >= 0 ? desc.slice(0, cut).trim() : desc;
      const blocked = cut >= 0 ? desc.slice(cut).replace(/^Off by default:\s*/i, '').replace(/^enable in Sources\.\s*/i, 'Turn it on to try anyway. ').trim().replace(/^./, (c) => c.toUpperCase()) : '';
      const nextRun = s.mode === 'batch' && s.enabled && s.last_run && s.interval
        ? until(new Date(new Date(s.last_run).getTime() + s.interval * 1000)) : null;
      const isBusy = busy.has(s.id) || s.status === 'running';
      const neverRun = !s.last_ok && !s.items_total && !(runsCache.get(s.id) || []).length && s.status !== 'live' && !isBusy;
      const needsKey = s.unavailable || '';   // keyed source with no key: never fetched, can't be switched on
      const msg = s.status === 'error' || s.status === 'reconnecting' ? s.message : (off ? (blocked ? 'Off: the provider blocks automated clients' : 'Off') : s.message);
      return `
      <article class="src-card${off ? ' off' : ''}${cls === 'err' ? ' bad' : ''}" data-id="${esc(s.id)}">
        <div class="src-c-top">
          <span class="src-dot ${cls}" title="${esc(label)}"></span>
          <div class="src-c-title">
            <div class="src-c-name">${glossName(s.name)}</div>
            <div class="src-c-prov mono" title="id ${esc(s.id)}">${esc(s.provider || '')}</div>
          </div>
          ${s.mode === 'stream'
            ? `<span class="src-mode stream${s.status === 'live' ? ' on' : ''}"><i></i>LIVE</span>`
            : `<span class="src-mode batch">EVERY ${every(s.interval).toUpperCase()}</span>`}
        </div>
        <p class="src-c-desc" title="${esc(body)}">${esc(body)}</p>
        ${blocked ? `<div class="src-blocked"><svg viewBox="0 0 24 24" class="i"><path d="M12 3 2 20h20L12 3Zm0 6v5m0 3v.01" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg><span><b>The provider blocks automated clients.</b> ${esc(blocked)}</span></div>` : ''}
        ${needsKey ? `<div class="src-blocked src-needs-key"><svg viewBox="0 0 24 24" class="i"><path d="M15 7a4 4 0 1 1-3.9 4.9L4 19v-3h2v-2h2l1.1-1.1A4 4 0 0 1 15 7Zm1 3h.01" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg><span><b>${s.needs === 'watchlist' ? 'Waiting for a network to watch.' : 'Needs a free key.'}</b> ${esc(needsKey)}${s.needs_key && s.needs !== 'watchlist' ? `<details class="src-key-tech"><summary>Technical details</summary>The setting is <code>${esc(s.needs_key)}</code>.</details>` : ''}</span></div>` : ''}
        ${s.ai_ok === false ? `<div class="src-c-note mono" title="The provider's terms forbid using this data with AI models">Kept out of AI features (provider terms)</div>` : ''}
        ${neverRun ? `<div class="src-never"><span class="src-never-t">Never run</span><span>${needsKey ? (ROUTING_IDS.has(s.id) ? 'Set it up in Routing watch above' : 'Add its key as the card says above, then toggle on') : off ? (blocked ? 'The provider has to allow access before it can collect anything' : 'Turn on to start collecting') : 'Waiting for its first scheduled check'}${s.mode === 'batch' && s.interval ? ` · checks every ${every(s.interval)}` : ''}</span></div>` : `<div class="src-c-stats">
          <div><div class="label">Status</div><div class="src-sv ${cls}">${esc(label)}</div></div>
          <div><div class="label">${s.mode === 'stream' ? 'Connected' : 'Last run'}</div><div class="src-sv" data-ago="${esc(s.last_run || '')}">${ago(s.last_run)}</div></div>
          <div><div class="label">${s.mode === 'stream' ? 'Mode' : 'Next run'}</div><div class="src-sv">${s.mode === 'stream' ? 'live' : (nextRun || '—')}</div></div>
          <div><div class="label">Last run got</div><div class="src-sv">${s.items_last != null ? compact(s.items_last) : '—'}</div></div>
          <div><div class="label">Kept</div><div class="src-sv">${s.items_total != null ? compact(s.items_total) : '—'}</div></div>
        </div>
        ${s.mode === 'batch' ? spark(s.id) : ''}`}
        ${msg && !off && !/^[\d,]+ records$/.test(msg) && msg !== 'connected' ? `<div class="src-c-msg mono${cls === 'err' || cls === 'warn' ? ' err' : ''}" title="${esc(msg)}">${esc(msg)}</div>` : ''}
        <div class="src-c-foot">
          <label class="src-toggle" title="${needsKey ? esc(needsKey) : `${off ? 'Enable' : 'Disable'} this source`}">
            <input type="checkbox" data-act="toggle"${off ? '' : ' checked'}${needsKey && off ? ' disabled' : ''}><span class="src-sw"></span><span class="mono">${off ? 'Off' : 'On'}</span>
          </label>
          ${s.mode === 'batch' ? `<button class="src-btn" data-act="run"${isBusy || off || needsKey ? ' disabled' : ''}>${isBusy ? '<span class="src-spin"></span>Running' : '<svg class="i" viewBox="0 0 24 24"><path d="M8 5v14l11-7L8 5Z" fill="currentColor"/></svg>Run now'}</button>` : ''}
          <button class="src-btn ghost${open.has(s.id) ? ' on' : ''}" data-act="hist"><svg class="i caret"><use href="#i-caret"/></svg>History</button>
          <span class="src-c-lic mono" title="License">${esc(s.license || '')}</span>
          ${safeUrl(s.homepage) ? `<a class="icon-btn" href="${esc(safeUrl(s.homepage))}" target="_blank" rel="noopener" title="${esc(s.homepage)}"><svg class="i"><use href="#i-ext"/></svg></a>` : ''}
        </div>
        ${open.has(s.id) ? `<div class="src-hist-wrap">${historyHtml(s)}</div>` : ''}
      </article>`;
    }

    function renderGroups() {
      const out = [];
      for (const [cat, name, gdesc] of CATS) {
        const list = sources.filter((s) => s.category === cat && visible(s));
        if (!list.length) continue;
        const items = list.reduce((a, s) => a + (s.items_total || 0), 0);
        out.push(`<section class="src-group">
          <div class="src-group-head"><span class="src-gname">${esc(name)}</span><span class="src-gcount mono">${list.length} source${list.length > 1 ? 's' : ''} · ${compact(items)} records</span><span class="src-gdesc">${esc(gdesc)}</span></div>
          <div class="src-grid">${list.map(cardHtml).join('')}</div></section>`);
      }
      const other = sources.filter((s) => !CATS.some(([c]) => c === s.category) && visible(s));
      if (other.length) out.push(`<section class="src-group"><div class="src-group-head"><span class="src-gname">Other</span></div><div class="src-grid">${other.map(cardHtml).join('')}</div></section>`);
      groupsEl.innerHTML = out.join('') || emptyState({ title: 'No sources match this filter', why: 'Clear the filter to see every source.', size: 'sm' });
    }

    function rerenderCard(id) {
      const s = sources.find((x) => x.id === id);
      const old = groupsEl.querySelector(`.src-card[data-id="${CSS.escape(id)}"]`);
      if (!s || !old) return;
      const scrollers = [...old.querySelectorAll('.src-hist-wrap')].map((x) => x.scrollTop);
      const nu = h(cardHtml(s));
      old.replaceWith(nu);
      const w = nu.querySelector('.src-hist-wrap'); if (w && scrollers[0]) w.scrollTop = scrollers[0];
    }

    function renderAll() {
      const failed = loadErr && !sources.length;
      $('.src-bar').hidden = !!failed;
      renderKpis(); renderBar();
      if (failed) groupsEl.innerHTML = errorState({ retry: loadAll, title: "Couldn't load the sources", why: 'The Night Desk server did not answer. Nothing is lost; Night Desk tries again by itself.', err: loadErr });
      else renderGroups();
    }

    // ---------------------------------------------------------------- data
    async function loadRuns(id) {
      try { runsCache.set(id, await api.sourceRuns(id)); } catch { runsCache.set(id, []); }
    }
    // A failed load shows "Couldn't load the sources" with Try again (never "No sources match this filter"), and
    // tries again by itself every 10 s while the page is open and when the live connection comes back.
    async function loadAll() {
      clearTimeout(retryT);
      const [s, sm, lk] = await Promise.allSettled([api.sources(), api.summary({ since_hours: 24 }), api.get('/api/lake')]);
      if (s.status === 'fulfilled') { sources = s.value; loadErr = null; }
      else loadErr = s.reason?.message || 'no answer';
      if (sm.status === 'fulfilled') summary = sm.value;
      if (lk.status === 'fulfilled') lake = lk.value;
      renderAll();
      if (loadErr) {
        if (!sources.length) retryT = setTimeout(() => { if (el.isConnected && el.offsetParent) loadAll(); else retryT = null; }, 10000);
        else toast(`Couldn't refresh the sources: ${loadErr}`, true);
        return;
      }
      await Promise.all(sources.filter((x) => x.mode === 'batch').map((x) => loadRuns(x.id)));
      renderGroups();
    }
    const refreshTotals = debounce(async () => {
      try { summary = await api.summary({ since_hours: 24 }); renderKpis(); } catch {}
    }, 1500);
    const refreshLake = debounce(async () => {
      try { lake = await api.get('/api/lake'); renderKpis(); } catch {}
    }, 5000);

    // ---------------------------------------------------------------- interactions
    el.addEventListener('click', async (e) => {
      const t = e.target.closest('[data-act],[data-cat],[data-mode],[data-copy]');
      if (!t) return;
      if (t.dataset.cat) { filter.cat = t.dataset.cat; renderBar(); renderGroups(); return; }
      if (t.dataset.mode) { filter.mode = t.dataset.mode; renderBar(); renderGroups(); return; }
      if (t.dataset.copy !== undefined) {
        if (!t.dataset.copy) return;
        try { await navigator.clipboard.writeText(t.dataset.copy); toast('Raw path copied'); } catch { toast(t.dataset.copy); }
        return;
      }
      const act = t.dataset.act;
      const card = t.closest('.src-card');
      const id = card?.dataset.id;
      if (act === 'refresh') { runsCache.clear(); loadAll(); return; }
      if (act === 'to-upload') { $('#src-upload-sec').scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
      if (act === 'upload') { doUpload(); return; }
      if (act === 'hist' && id) {
        if (open.has(id)) open.delete(id); else open.add(id);
        rerenderCard(id);
        if (open.has(id)) { await loadRuns(id); rerenderCard(id); }
        return;
      }
      if (act === 'run' && id) {
        const s = sources.find((x) => x.id === id);
        busy.add(id); rerenderCard(id);
        try {
          const r = await api.runSource(id);
          if (r && r.ok === false) toast(`${s.name}: ${r.error || 'run failed'}`, true);
          else toast(`${s.name}: ${r?.items != null ? fmt(r.items) + ' records collected' : 'run complete'}`);
        } catch (err) {
          toast(`${s.name}: ${err.message}`, true);
        } finally {
          busy.delete(id);
          await loadRuns(id);
          try { const fresh = (await api.sources()).find((x) => x.id === id); if (fresh) Object.assign(s, fresh); } catch {}
          rerenderCard(id); refreshTotals(); refreshLake();
        }
      }
    });

    el.addEventListener('change', async (e) => {
      if (e.target.dataset.act !== 'toggle') return;
      const id = e.target.closest('.src-card').dataset.id;
      const s = sources.find((x) => x.id === id);
      const want = e.target.checked;
      try {
        await api.setSourceEnabled(id, want);
        s.enabled = want;
        if (!want) s.status = 'disabled';
        toast(`${s.name} ${want ? 'enabled' : 'disabled'}`);
      } catch (err) {
        e.target.checked = !want;
        toast(`${s.name}: ${err.message}`, true);
      }
      rerenderCard(id); renderKpis();
    });

    $('.src-search input').addEventListener('input', debounce((e) => { filter.q = e.target.value.trim(); renderGroups(); }, 150));

    // ---------------------------------------------------------------- upload
    const drop = $('.src-drop');
    const fileIn = drop.querySelector('input');
    const labelIn = $('.src-up-form input[name="label"]');
    const upBtn = $('[data-act="upload"]');
    let file = null;
    function setFile(f) {
      file = f || null;
      const fEl = drop.querySelector('.src-drop-f');
      fEl.hidden = !file;
      if (file) {
        fEl.textContent = `${file.name} · ${bytes(file.size)}`;
        if (!labelIn.value) labelIn.value = file.name.replace(/\.[^.]+$/, '').replace(/[^\w\- ]/g, '-').slice(0, 40);
      }
      drop.classList.toggle('has', !!file);
      upBtn.disabled = !file;
    }
    fileIn.addEventListener('change', () => setFile(fileIn.files[0]));
    drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileIn.click(); } });
    ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
    drop.addEventListener('drop', (e) => setFile(e.dataTransfer.files[0]));

    async function doUpload() {
      if (!file) return;
      const res = $('.src-up-res');
      upBtn.disabled = true; upBtn.innerHTML = '<span class="src-spin"></span>Adding…';
      res.innerHTML = '';
      try {
        const r = await api.upload(file, labelIn.value || 'custom');
        res.innerHTML = `<div class="src-up-ok">
          <div class="src-up-n"><div><div class="label">Rows loaded</div><div class="kpi">${fmt(r.rows)}</div></div>
          <div><div class="label">Geolocated</div><div class="kpi">${fmt(r.geolocated)}</div></div>
          <div><div class="label">Geo rate</div><div class="kpi">${r.rows ? Math.round(100 * r.geolocated / r.rows) : 0}%</div></div></div>
          ${r.note ? `<div class="src-up-note">${esc(r.note)}</div>` : ''}
          <div class="label" style="margin-top:10px">Stored at</div><div class="src-path mono" data-copy="${esc(r.file)}" title="Click to copy"><span><em>lake/</em>${esc(r.file)}&lrm;</span></div>
          <a class="src-link mono needs-sql" href="#explorer" data-x="1">Query it in the SQL console →</a></div>`;
        toast(r.note ? `Added ${fmt(r.rows)} rows from ${file.name}: the file had ${fmt(r.total)}` : `Added ${fmt(r.rows)} rows from ${file.name}`);
        setFile(null); fileIn.value = '';
        refreshTotals(); refreshLake();
      } catch (err) {
        res.innerHTML = errorState({ retry: doUpload, title: 'Nothing was added', why: esc(err.message), size: 'inline' });
        toast(err.message, true);
      } finally {
        upBtn.innerHTML = 'Add file'; upBtn.disabled = !file;
      }
    }
    el.addEventListener('click', (e) => {
      const a = e.target.closest('a[data-x]');
      if (a) { e.preventDefault(); location.hash = '#explorer'; }
    });

    // ---------------------------------------------------------------- live
    live.on('source', (st) => {
      const s = sources.find((x) => x.id === st.id);
      if (!s) return;
      for (const [k, v] of Object.entries(st)) if (v !== null && v !== undefined) s[k] = v;
      if (st.status === 'ok' && open.has(s.id)) loadRuns(s.id).then(() => rerenderCard(s.id));
      if (st.status === 'ok' && s.mode === 'batch' && !open.has(s.id)) loadRuns(s.id).then(() => rerenderCard(s.id));
      rerenderCard(s.id); renderKpis();
    });
    live.on('events', () => refreshTotals());
    live.on('status', (ok) => { if (ok && loadErr && !sources.length) loadAll(); });

    const tick = setInterval(() => {
      el.querySelectorAll('[data-ago]').forEach((n) => { if (n.dataset.ago) n.textContent = ago(n.dataset.ago); });
    }, 15000);

    loadAll();
    const pipeline = mountPipelineStatus($('#src-pipeline-sec'), api);
    return { reload() { runsCache.clear(); return loadAll(); }, destroy() { clearInterval(tick); pipeline.destroy(); } };
  }
}

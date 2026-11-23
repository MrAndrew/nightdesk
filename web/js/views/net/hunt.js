// Network → Hunt: query bar with field filters, group-by pivots, brushable histogram, raw Zeek rows.
import { S, onChange, emit, logParams, v, devLink, bytes, ts, tsShort, esc, fmt, card, jsonHtml, toast, Z, day, hsCue } from './common.js';
import { bucketFor, spanOf, timeChart, PORTS } from './overview.js';
import { emptyState, errorState, loadingState, stateAct } from '../../core/view.js';
import { LOG_TYPE_COLORS } from '../../core/util.js';
import { brushTo, zoomOut, zoomBar, isPhone } from './m.js';
import { openSheet } from '../../core/sheet.js';
import { afterRender } from '../../core/page.js';
import { need } from '../../core/libs.js';
const CLEAR = stateAct('Clear filters', { data: { 'hunt-clear': '1' } });

const FIELDS = ['device', 'ip', 'port', 'log_type', 'proto', 'service', 'conn_state', 'uid', 'q', 'resp_p', 'orig_h', 'resp_h', 'query', 'server_name', 'host', 'orig_bytes', 'duration'];
const FLABEL = { q: 'text' };
const GB = [
  ['', '—'], ['log_type', 'log type'], ['device', 'device'], ['orig_h', 'source IP'], ['resp_h', 'destination IP'], ['resp_p', 'destination port'],
  ['proto', 'protocol'], ['service', 'service'], ['conn_state', 'conn state'], ['query', 'DNS query'], ['server_name', 'TLS SNI'], ['host', 'HTTP host'],
  ['hour', 'hour'], ['day', 'day'], ['raw.qtype_name', 'raw.qtype_name'], ['raw.version', 'raw.version (TLS)'], ['raw.ja3', 'raw.ja3'], ['raw.user_agent', 'raw.user_agent'],
];
const GBF = { device: 'device', orig_h: 'ip', resp_h: 'ip', resp_p: 'port', log_type: 'log_type', proto: 'proto', service: 'service', conn_state: 'conn_state', query: 'query', server_name: 'server_name', host: 'host' };
const PRESETS = [
  ['DNS by name', [{ f: 'log_type', v: 'dns' }], ['query']],
  ['Failed outbound (S0)', [{ f: 'log_type', v: 'conn' }, { f: 'conn_state', v: 'S0' }], ['resp_h', 'resp_p']],
  ['Non-web traffic', [{ f: 'log_type', v: 'conn' }, { f: 'port', v: '443', neg: true }, { f: 'port', v: '80', neg: true }, { f: 'port', v: '53', neg: true }, { f: 'port', v: '123', neg: true }], ['resp_p', 'device']],
  ['Big uploads (>10 MB)', [{ f: 'log_type', v: 'conn' }, { f: 'orig_bytes', v: '>10000000' }], ['device', 'resp_h']],
  ['Old TLS', [{ f: 'log_type', v: 'ssl' }, { f: 'raw.version', v: 'TLSv10,TLSv11,SSLv3' }], ['server_name']],
  ['TLS by SNI', [{ f: 'log_type', v: 'ssl' }], ['server_name']],
  ['HTTP hosts', [{ f: 'log_type', v: 'http' }], ['host']],
  ['Who talks where', [{ f: 'log_type', v: 'conn' }], ['device', 'resp_p']],
  ['Remote access ports', [{ f: 'port', v: '22,23,3389,5900' }], ['device', 'resp_h']],
];
const LTC = LOG_TYPE_COLORS;   // core/util.js: the same log-type colours everywhere (conn = amber)
const PAGE = 100;

export function mount(el, ctx) {
  const { api } = ctx;
  let page = 0, visible = false, stale = true, seq = 0, hist = null, rows = [], openRows = new Set();
  el.innerHTML = `
    <div class="nv-hunt">
      <div class="nv-qbar">
        <svg class="i"><use href="#i-search"/></svg>
        <div class="nv-qchips"><input class="mono" placeholder="ip:203.0.113.0/24  -port:443  raw.version:TLSv10  or any text — Enter" spellcheck="false" autocomplete="off"></div>
        <select class="nv-sel mono" data-add title="Add a field filter"><option value="">+ field</option>${FIELDS.map((f) => `<option value="${f}">${FLABEL[f] || f}</option>`).join('')}</select>
        <button class="src-btn primary nv-go">Search</button>
      </div>
      <div class="nv-m-qline" hidden></div>
      <div class="nv-qerr" hidden></div>
      <div class="nv-presets"><span class="label">Try</span>${PRESETS.map((p, i) => `<button class="chip" data-preset="${i}">${esc(p[0])}</button>`).join('')}<span class="nv-total mono"></span></div>
      ${card('Timeline', '<div class="nv-chart nv-hh"></div>', { cls: 'nv-hist', badge: '·', tools: '' })}
      <div class="nv-g nv-g-hunt">
        ${card('Group metrics', '<div class="nv-grp-b"></div>', { cls: 'nv-gm', tools: `<datalist id="nv-gbl">${GB.slice(1).map(([k, l]) => `<option value="${k}">${l}</option>`).join('')}</datalist><span class="mono nv-dim">by</span><input class="nv-sel mono nv-gbi" data-gb="0" list="nv-gbl" placeholder="field" title="Any column, device, hour, day or raw.<field>"><span class="mono nv-dim">then</span><input class="nv-sel mono nv-gbi" data-gb="1" list="nv-gbl" placeholder="— (optional)">` })}
        ${card('Events', '<div class="nv-ev"></div><div class="nv-pager"><button class="chip" data-pg="-1">‹ Newer</button><span class="mono nv-pg"></span><button class="chip" data-pg="1">Older ›</button></div>', { cls: 'nv-evc', tools: '<span class="nv-hint mono">click a row for its raw Zeek JSON · click any value to pivot</span>' })}
      </div>
    </div>`;
  const $ = (s) => el.querySelector(s);
  const input = $('.nv-qchips input');

  function paintChips() {
    $('.nv-qchips').querySelectorAll('.nv-fc').forEach((c) => c.remove());
    S.filters.forEach((f, i) => input.insertAdjacentHTML('beforebegin',
      `<span class="nv-fc ${f.neg ? 'neg' : ''}" data-i="${i}" title="Click to edit · ${f.neg ? 'excluded' : 'included'}"><b>${f.neg ? 'NOT ' : ''}${esc(FLABEL[f.f] || f.f)}</b>${esc(f.f === 'device' ? (S.devices.get(f.v)?.name || S.devices.get(f.v)?.hostnames?.[0] || f.v) : f.v)}<button title="Remove">✕</button></span>`));
    input.placeholder = S.filters.length ? 'add more filters, or Backspace to remove' : 'ip:203.0.113.0/24  -port:443  raw.version:TLSv10  or any text — Enter';
    $('[data-gb="0"]').value = S.groupby[0] || 'log_type';
    $('[data-gb="1"]').value = S.groupby[1] || '';
    paintLine();
  }
  // a phone: the query as one line of chips, with Edit query (a full-screen editor sheet)
  const qtext = () => S.filters.map((f) => `${f.neg ? '-' : ''}${f.f === 'q' ? 'text' : f.f}:${/\s/.test(f.v) ? `"${f.v}"` : f.v}`).join(' ');
  function paintLine() {
    const box = $('.nv-m-qline');
    box.hidden = !isPhone();   // desktop: no box at all (an empty one takes a gap in the column)
    if (box.hidden) { box.innerHTML = ''; return; }
    const gb = S.groupby.filter(Boolean).map((k) => (GB.find((g) => g[0] === k) || [k, k])[1]).join(', then ');
    box.innerHTML = `<div class="nv-m-qchips">${S.filters.length ? S.filters.map((f) => `<span class="nv-m-qc${f.neg ? ' neg' : ''}" data-nochips>${f.neg ? 'not ' : ''}${esc(FLABEL[f.f] || f.f)} ${esc(f.f === 'device' ? (S.devices.get(f.v)?.name || f.v) : f.v)}</span>`).join('') : '<span class="nv-m-qc none">Every log row</span>'}${gb ? `<span class="nv-m-qc gb">grouped by ${esc(gb)}</span>` : ''}</div>
      <div class="nv-m-qacts"><button type="button" class="m-btn" data-medit>Edit query</button>${S.filters.length ? '<button type="button" class="m-btn m-btn-ghost" data-hunt-clear="1">Clear</button>' : ''}</div>`;
  }
  function editSheet() {
    const body = document.createElement('div');
    body.className = 'nv-m-qedit';
    body.innerHTML = `<label class="nv-m-fl"><span>Search</span><textarea class="nv-m-qta" rows="4" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="ip:203.0.113.0/24 -port:443 or any text">${esc(qtext())}</textarea></label>
      <p class="nv-m-sub">Words like <b>device:</b>, <b>ip:</b>, <b>port:</b>, <b>log_type:</b> or <b>text:</b> pick a field; a minus leaves rows out.</p>
      <label class="nv-m-fl"><span>Group by</span><select class="nv-m-qsel">${GB.map(([k, l]) => `<option value="${esc(k)}" ${(S.groupby[0] || '') === k ? 'selected' : ''}>${esc(l === '—' ? 'Nothing' : l)}</option>`).join('')}</select></label>`;
    const go = document.createElement('button');
    go.type = 'button'; go.className = 'm-btn m-btn-primary'; go.textContent = 'Search';
    const h = openSheet({ id: 'nv-qedit', title: 'Edit query', size: 'full', body, footer: [go] });
    go.addEventListener('click', () => {
      S.filters = parse(body.querySelector('textarea').value.trim());
      const g = body.querySelector('select').value;
      S.groupby = g ? [g] : [];
      page = 0; h.close('close'); emit('filters');
    });
  }

  function parse(text) {
    const out = [];
    const re = /([-!]?)([\w.]+):("([^"]*)"|\S+)|([-!]?)"([^"]+)"|(\S+)/g;
    let m; const free = [];
    while ((m = re.exec(text))) {
      if (m[2]) {
        const f0 = m[2].toLowerCase();
        const f = f0 === 'text' ? 'q' : f0 === 'type' ? 'log_type' : f0;
        out.push({ f, v: m[4] ?? m[3], neg: !!m[1] });
      } else if (m[6]) out.push({ f: 'q', v: m[6], neg: !!m[5] });
      else if (/^[-!]./.test(m[7])) out.push({ f: 'q', v: m[7].slice(1), neg: true });
      else free.push(m[7]);
    }
    if (free.length) out.push({ f: 'q', v: free.join(' ') });
    return out;
  }
  function commit() {
    const t = input.value.trim();
    if (t) { S.filters.push(...parse(t)); input.value = ''; }
    page = 0; emit('filters');
  }

  async function load() {
    const my = ++seq;
    stale = false;
    paintChips();
    const [s0, s1] = spanOf();
    const [bucket, bucketMs] = bucketFor(s1 - s0);
    // what a drag does, or the zoomed window with Zoom out (in the badge, which takes clicks at every width)
    $('.nv-hist .panel-badge').innerHTML = `per ${bucket} · by log type · ${zoomBar()}`;
    $('.nv-ev').innerHTML = loadingState('Searching your logs…', { size: 'sm' });
    $('.nv-qerr').hidden = true;
    await need('echarts');   // the chart library on demand (core/libs.js)
    if (my !== seq) return;
    try {
      const tl = await api.get('/api/netlog/stats/timeline', { bucket, split: 'log_type', ...logParams() });
      if (my !== seq) return;
      const data = [];
      tl.forEach((r) => Object.entries(r.by || {}).forEach(([k, n]) => data.push([r.t, k, n])));
      drawHist(data, bucketMs);
    } catch (e) {
      if (my !== seq) return;
      $('.nv-qerr').hidden = false; $('.nv-qerr').innerHTML = errorState({ retry: load, act: CLEAR, title: "Couldn't draw the timeline for this search", why: 'Check the filters; a value may not fit its field.', err: e.message, size: 'inline' });
      drawHist([], bucketMs);
    }
    loadGroups(my);
    loadRows(my);
  }

  function drawHist(data, bucketMs) {
    hist?.dispose();
    const types = [...new Set(data.map((r) => r[1]))];
    const series = types.map((t) => ({ name: t, color: LTC[t] || '#8a8578', stack: 'a', data: data.filter((r) => r[1] === t).map((r) => [Date.parse(r[0]), r[2]]) }));
    hist = timeChart($('.nv-hh'), { series, bucketMs, onBrush: brushTo });
    // an empty chart says so, like the cards below it
    const host = $('.nv-hh').parentElement;
    host.querySelector('.nv-hh-none')?.remove();
    if (!data.length && $('.nv-qerr').hidden) host.insertAdjacentHTML('beforeend', `<div class="nv-hh-none">${emptyState({ title: 'Nothing to chart', why: 'No log rows match in this time range. Remove a filter or widen the range.', size: 'sm' })}</div>`);
  }

  const devByIp = () => { const m = new Map(); for (const d of S.devices.values()) for (const ip of d.ips || []) m.set(ip, d.id); return m; };
  function cell(k, val) {
    if (val == null || val === '') return '<span class="nv-null">(none)</span>';
    if (k === 'device') return devLink(val);
    if (k === 'resp_p') return `${v('port', val)} <span class="nv-dim">${PORTS[val] || ''}</span>`;
    if (k === 'log_type') return `<i class="nv-lt" style="background:${LTC[val] || '#8a8578'}"></i>${v('log_type', val)}`;
    if (k === 'hour' || k === 'day') return esc(k === 'day' ? day(val) : ts(val, false));
    return v(GBF[k] || k, val);
  }

  async function loadGroups(my) {
    const box = $('.nv-grp-b');
    const gb = S.groupby.filter(Boolean);
    box.innerHTML = loadingState('Grouping…', { size: 'sm' });
    try {
      const r = await api.get('/api/netlog/aggregate', { group: gb.join(','), limit: 50, sublimit: 6, ...logParams() });
      if (my !== seq) return;
      const flat = [];
      for (const g of r.groups) {
        if (gb.length > 1 && g.children?.length) g.children.forEach((c, i) => flat.push({ k: [g.key, c.key], n: c.count, b: c.bytes, first: i === 0, gn: g.count, last: c.last }));
        else flat.push({ k: [g.key], n: g.count, b: g.bytes, first: true, last: g.last });
      }
      if (!flat.length) { box.innerHTML = emptyState({ title: 'No rows match', why: 'Remove a filter or widen the time range.', size: 'sm' }); return; }
      const max = Math.max(...flat.map((x) => x.n));
      if (isPhone()) {
        const txt = (k, val) => (val == null || val === '' ? '(none)' : k === 'device' ? (S.devices.get(val)?.name || val) : k === 'day' ? day(val) : k === 'hour' ? ts(val, false) : String(val));
        box.innerHTML = `<ol class="nv-m-rank">${flat.map((x) => `<li><span class="nv-m-rk" data-nochips>${x.k.map((val, i) => esc(txt(gb[i], val))).join(' · ')}</span><span class="nv-m-rn">${fmt(x.n)}</span><i style="width:${(100 * x.n / max).toFixed(1)}%"></i></li>`).join('')}</ol>
          <div class="nv-none">${fmt(r.total)} rows in ${fmt(r.groups.length)}${r.groups.length === 50 ? '+' : ''} groups</div>`;
        return;
      }
      box.innerHTML = `<table class="nv-gt"><thead><tr><th class="r">Count</th><th></th>${gb.map((k) => `<th>${esc((GB.find((g) => g[0] === k) || [k, k])[1])}</th>`).join('')}<th class="r">Bytes</th><th>Last seen</th></tr></thead><tbody>
        ${flat.map((x) => `<tr class="${x.first && gb.length > 1 ? 'nv-gfirst' : ''}"><td class="r mono">${fmt(x.n)}</td><td class="nv-gbar"><i style="width:${(100 * x.n / max).toFixed(1)}%"></i></td>${gb.map((k, i) => `<td class="mono">${i === 0 && gb.length > 1 && !x.first ? '' : cell(k, x.k[i])}${i === 0 && gb.length > 1 && x.first ? ` <span class="nv-dim">${fmt(x.gn)}</span>` : ''}</td>`).join('')}<td class="r mono nv-dim">${x.b ? bytes(x.b) : ''}</td><td class="mono nv-dim">${x.last ? tsShort(x.last) : ''}</td></tr>`).join('')}
      </tbody></table><div class="nv-none">${fmt(r.total)} rows in ${fmt(r.groups.length)}${r.groups.length === 50 ? '+' : ''} groups${gb.length > 1 ? ' · top 6 per group' : ''}</div>`;
      hsCue(box, 'Group metrics');
    } catch (e) { box.innerHTML = errorState({ retry: load, act: CLEAR, title: "Couldn't group these rows", why: 'Check the filters, or group by another field.', err: e.message, size: 'sm' }); }
  }

  async function loadRows(my) {
    const box = $('.nv-ev');
    let total = 0;
    try {
      const r = await api.get('/api/netlog/connections', { ...logParams(), limit: PAGE, offset: page * PAGE, raw: true });
      if (my !== seq) return;
      rows = r.rows; total = r.total;
      const dm = devByIp();
      rows.forEach((x) => { x.device = dm.get(x.orig_h) || dm.get(x.resp_h) || null; });
      $('.nv-total').innerHTML = `Total found <b>${fmt(total)}</b>`;
    } catch (e) { box.innerHTML = errorState({ retry: load, act: CLEAR, title: "Couldn't run this search", why: 'Check the filters; a value may not fit its field.', err: e.message, size: 'sm' }); return; }
    openRows = new Set();
    $('.nv-pg').textContent = total ? `${fmt(page * PAGE + 1)}–${fmt(Math.min(total, (page + 1) * PAGE))} of ${fmt(total)}` : '';
    el.querySelector('[data-pg="-1"]').disabled = page === 0;
    el.querySelector('[data-pg="1"]').disabled = (page + 1) * PAGE >= total;
    if (!rows.length) { box.innerHTML = emptyState({ title: 'No rows match', why: 'Remove a filter or widen the time range.', size: 'sm' }); return; }
    if (isPhone()) {
      box.innerHTML = `<ul class="nv-m-recs">${rows.map((r, i) => {
        const what = r.log_type === 'dns' ? r.query : r.server_name || r.host || r.hostname || '';
        const dev = r.device ? (S.devices.get(r.device)?.name || r.device) : '';
        return `<li class="nv-m-rec"><button type="button" class="nv-m-recb" data-i="${i}" aria-expanded="false">
          <span class="nv-m-rec1"><span><i class="nv-lt" style="background:${LTC[r.log_type] || '#8a8578'}"></i>${esc(r.log_type)}</span><span>${esc(tsShort(r.ts))}</span></span>
          <span class="nv-m-rec2" data-nochips>${esc(dev ? `${dev} · ` : '')}${esc(r.orig_h || '')} → ${esc(r.resp_h || '')}${r.resp_p != null ? `:${esc(r.resp_p)}` : ''}</span>
          ${what ? `<span class="nv-m-rec3" data-nochips>${esc(what)}</span>` : ''}</button><div class="nv-m-recraw" hidden></div></li>`;
      }).join('')}</ul>`;
      afterRender('network');
      return;
    }
    box.innerHTML = `<table class="nv-et"><thead><tr><th></th><th>Time (${Z()})</th><th>Type</th><th>Device</th><th>Source → destination</th><th>Proto · service</th><th>Detail</th><th class="r">Bytes ↑/↓</th><th>State</th></tr></thead><tbody>
      ${rows.map((r, i) => {
        const det = r.log_type === 'dns' ? `${v('query', r.query)}${r.answers?.length ? ` <span class="nv-dim">→</span> ${r.answers.slice(0, 2).map((a) => v('ip', a)).join(' ')}${r.answers.length > 2 ? ` <span class="nv-dim">+${r.answers.length - 2}</span>` : ''}` : ''}`
          : r.server_name ? v('server_name', r.server_name) : r.host ? `${v('host', r.host)}<span class="nv-dim">${esc((r.uri || '').slice(0, 40))}</span>` : r.hostname ? esc(r.hostname) : r.mac ? `<span class="nv-dim">${esc(r.mac)}</span>` : '';
        return `<tr class="nv-er" data-i="${i}"><td class="nv-chev">›</td><td class="mono nv-t">${tsShort(r.ts)}</td><td><i class="nv-lt" style="background:${LTC[r.log_type] || '#8a8578'}"></i>${v('log_type', r.log_type)}</td>
          <td>${r.device ? devLink(r.device) : ''}</td>
          <td class="mono nv-5t">${v('ip', r.orig_h)}<span class="nv-dim">:${esc(r.orig_p ?? '')}</span> <span class="nv-dim">→</span> ${v('ip', r.resp_h)}<span class="nv-dim">:</span>${r.resp_p != null ? v('port', r.resp_p) : ''}</td>
          <td class="mono">${r.proto ? v('proto', r.proto) : ''}${r.service ? ` <span class="nv-dim">·</span> ${v('service', r.service)}` : ''}</td>
          <td class="mono nv-det">${det}</td>
          <td class="r mono nv-dim">${r.orig_bytes != null ? `${bytes(r.orig_bytes)} / ${bytes(r.resp_bytes)}` : ''}</td>
          <td class="mono">${r.conn_state ? v('conn_state', r.conn_state) : ''}</td></tr>
          <tr class="nv-raw" data-raw="${i}" hidden><td colspan="9"></td></tr>`;
      }).join('')}</tbody></table>`;
  }

  // ---------------------------------------------------------------- events
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') commit();
    if (e.key === 'Backspace' && !input.value && S.filters.length) { S.filters.pop(); page = 0; emit('filters'); }
  });
  $('.nv-go').onclick = commit;
  $('.nv-hist').addEventListener('click', (e) => { if (e.target.closest('[data-zoom-out]')) zoomOut(); });
  el.addEventListener('click', (e) => { if (e.target.closest('[data-hunt-clear]')) { S.filters = []; page = 0; emit('filters'); } });
  $('.nv-qchips').addEventListener('click', (e) => {
    const x = e.target.closest('.nv-fc button');
    if (x) { S.filters.splice(+x.parentElement.dataset.i, 1); page = 0; emit('filters'); return; }
    const c = e.target.closest('.nv-fc');
    if (c) { const f = S.filters.splice(+c.dataset.i, 1)[0]; input.value = `${f.neg ? '-' : ''}${f.f === 'q' ? 'text' : f.f}:${/\s/.test(f.v) ? `"${f.v}"` : f.v} ${input.value}`.trim(); paintChips(); input.focus(); return; }
    input.focus();
  });
  $('[data-add]').onchange = (e) => { const f = e.target.value; e.target.value = ''; if (!f) return; input.value = `${input.value ? input.value + ' ' : ''}${f === 'q' ? 'text' : f}:`; input.focus(); };
  el.querySelectorAll('[data-gb]').forEach((s) => (s.onchange = () => {
    const a = $('[data-gb="0"]').value, b = $('[data-gb="1"]').value;
    S.groupby = [a, b && b !== a ? b : ''].filter(Boolean);
    loadGroups(seq);
  }));
  el.querySelectorAll('[data-preset]').forEach((b) => (b.onclick = () => { const p = PRESETS[+b.dataset.preset]; S.filters = p[1].map((x) => ({ ...x })); S.groupby = [...p[2]]; page = 0; emit('filters'); }));
  el.querySelectorAll('[data-pg]').forEach((b) => (b.onclick = () => { page = Math.max(0, page + +b.dataset.pg); loadRows(seq); $('.nv-evc').scrollIntoView({ block: 'start' }); }));
  $('.nv-m-qline').addEventListener('click', (e) => { if (e.target.closest('[data-medit]')) editSheet(); });
  $('.nv-ev').addEventListener('click', (e) => {
    const rb = e.target.closest('.nv-m-recb');
    if (rb) {
      const raw = rb.nextElementSibling, r = rows[+rb.dataset.i];
      raw.hidden = !raw.hidden; rb.setAttribute('aria-expanded', String(!raw.hidden));
      if (!raw.hidden && !raw.innerHTML) raw.innerHTML = r.raw ? `<div class="nv-rawbox">${jsonHtml(r.raw)}</div>` : emptyState({ why: 'No raw JSON was kept for this row.', size: 'inline' });
      return;
    }
    if (e.target.closest('.nv-v')) return;
    const tr = e.target.closest('.nv-er'); if (!tr) return;
    const i = +tr.dataset.i, raw = el.querySelector(`[data-raw="${i}"]`);
    raw.hidden = !raw.hidden; tr.classList.toggle('open', !raw.hidden);
    if (!raw.hidden && !raw.firstElementChild.innerHTML) raw.firstElementChild.innerHTML = rows[i].raw ? `<div class="nv-rawbox">${jsonHtml(rows[i].raw)}<div class="nv-rawact"><button class="chip" data-copy="${i}">Copy JSON</button>${rows[i].uid ? `<span class="nv-v chip" data-nf="uid" data-nv="${esc(rows[i].uid)}">All rows for uid ${esc(rows[i].uid)}</span>` : ''}</div></div>` : emptyState({ why: 'No raw JSON was kept for this row.', size: 'inline' });
  });
  $('.nv-ev').addEventListener('click', async (e) => {
    const c = e.target.closest('[data-copy]'); if (!c) return;
    try { await navigator.clipboard.writeText(JSON.stringify(rows[+c.dataset.copy].raw)); toast('JSON copied'); } catch { toast('Copy failed', true); }
  });

  onChange((w) => { if (w === 'range' || w === 'filters' || w === 'data') { if (w !== 'filters') page = 0; stale = true; if (visible) load(); } });
  return {
    show() { visible = true; if (stale) load(); else hist?.chart.resize(); },
    hide() { visible = false; },
  };
}

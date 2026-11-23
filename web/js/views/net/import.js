// Network → Connect logs (the tab id stays "import" for deep links): the guided setup (connect.js), drag-and-drop
// with per-file progress and results, imported files, device uploads under Advanced (push.js), the demo and the
// home-prefix setting with suggestions. Reference: okf/data/netlog.md#connect-logs
import { serverWhy } from './alert-text.js';
import { emit, cidrRange, bytes, ts, esc, fmt, toast, loadDevices, Z } from './common.js';
import { ago } from '../../core/util.js';
import { isPhone, copyText } from './m.js';
import { afterRender } from '../../core/page.js';
import * as push from './push.js';
import * as demo from './demo.js';
import * as connect from './connect.js';

const LS_ADV = 'nd.connect.advanced';
import { mountLists, mountNewDev } from './lists.js';
import { emptyState, errorState, stateAct } from '../../core/view.js';

// Count non-blank lines and sniff the format client-side, so the result can say how many lines
// the server skipped as not-JSON (it ignores malformed lines). Gzip is read with DecompressionStream.
async function sniff(file) {
  if (file.size > 400e6) return null;
  try {
    const head = new Uint8Array(await file.slice(0, 2).arrayBuffer());
    let stream = file.stream();
    if (head[0] === 0x1f && head[1] === 0x8b) {
      if (typeof DecompressionStream === 'undefined') return null;
      stream = stream.pipeThrough(new DecompressionStream('gzip'));
    }
    const reader = stream.pipeThrough(new TextDecoderStream()).getReader();
    let lines = 0, first = null, tail = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      const chunk = tail + value;
      const parts = chunk.split('\n');
      tail = parts.pop();
      for (const p of parts) { const t = p.trim(); if (t) { lines++; if (first == null) first = t[0]; } }
    }
    if (tail.trim()) { lines++; if (first == null) first = tail.trim()[0]; }
    return { lines, first };
  } catch { return null; }
}

function upload(file, onProgress) {
  return new Promise((resolve, reject) => {
    const fd = new FormData();
    fd.append('files', file, file.name);
    const x = new XMLHttpRequest();
    x.open('POST', 'api/netlog/import');
    x.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    x.upload.onload = () => onProgress(1);
    x.onload = () => {
      let body = null;
      try { body = JSON.parse(x.responseText); } catch {}
      if (x.status >= 200 && x.status < 300 && body) resolve(body.files?.[0] || body);
      else reject(new Error(body?.detail || `${x.status} ${x.statusText}`));
    };
    x.onerror = () => reject(new Error('network error'));
    x.send(fd);
  });
}

export function mount(el, ctx) {
  const { api } = ctx;
  let settings = null, prefixes = [], dirty = false, visible = false;
  el.innerHTML = `
    <div class="nv-imp">
      <div class="nv-m-imp" hidden></div>
      <input type="file" class="nv-imp-file" multiple hidden aria-hidden="true">
      <div class="nv-imp-main">
        <section class="nv-card connect-card"></section>
        <div class="nv-ires"></div>
        <section class="nv-card connect-files"><div class="panel-head"><span class="panel-title">Imported files</span><span class="panel-badge nv-fcount"></span></div><div class="nv-cb nv-files"></div></section>
        <details class="connect-adv">
          <summary><span class="connect-adv-t">Advanced: device uploads</span><span class="nv-dim">the upload port, who can reach it, its certificate, and every device token</span></summary>
          <section class="nv-card nv-push"></section>
        </details>
      </div>
      <div class="nv-imp-side">
        <section class="nv-card nv-demo"></section>
        <section class="nv-card connect-home"><div class="panel-head"><span class="panel-title">Home network</span><span class="panel-badge nv-from"></span></div>
          <div class="nv-cb nv-pad">
            <p class="nv-dim">Addresses inside these prefixes are yours. They decide whether a contact is outbound (your device reached out: high or medium) or inbound (someone knocked: low or info).</p>
            <div class="nv-pfx"></div>
            <div class="nv-row"><input class="src-input mono nv-pin" placeholder="192.0.2.0/24 or 2001:db8:1::/48" aria-label="Home prefix"><button class="src-btn" data-act="add">Add</button></div>
            <div class="nv-sugg"></div>
            <div class="nv-row nv-save-row"><span class="mono nv-dim nv-eff"></span><button class="src-btn primary" data-act="save" disabled>Save and re-match</button></div>
            <div class="netx-ndbox"></div>
          </div></section>
        <section class="nv-card netx-lcard" id="netx-lists"></section>
      </div>
    </div>`;
  const $ = (s) => el.querySelector(s);
  const input = $('.nv-imp-file');
  const adv = $('.connect-adv');
  const connectView = connect.mount($('.connect-card'), ctx, {
    pickFiles: () => input.click(),
    showDemo: () => { const d = $('.nv-demo'); d.scrollIntoView({ block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' }); d.querySelector('button, a')?.focus({ preventScroll: true }); },
    openAdvanced: () => { adv.open = true; adv.scrollIntoView({ block: 'start' }); },
    scanInbox: () => scanInbox(),
    onNewData: async () => { loadFiles(); await loadDevices(); ctx.refreshSummary(); emit('data'); },
  });
  const pushView = push.mount($('.nv-push'), ctx, { onImported: () => { loadFiles(); connectView.dataChanged(); }, onChange: (d) => connectView.setIngest(d) });
  connectView.onChanged(() => { if (adv.open) pushView.reload(); });
  const listsView = mountLists($('.netx-lcard'), ctx);
  const ndView = mountNewDev($('.netx-ndbox'), ctx);
  const demoView = demo.mount($('.nv-demo'), { ...ctx, refreshSummary: () => { ctx.refreshSummary(); loadFiles(); loadSettings(); } });
  try { adv.open = localStorage.getItem(LS_ADV) === '1'; } catch {}
  adv.addEventListener('toggle', () => {
    try { localStorage.setItem(LS_ADV, adv.open ? '1' : '0'); } catch {}
    if (adv.open && visible) pushView.show(); else pushView.hide();
  });

  // ---------------------------------------------------------------- uploads
  async function handle(files) {
    files = [...files];
    if (!files.length) return;
    const box = $('.nv-ires');
    const cards = files.map((f) => {
      const c = document.createElement('div');
      c.className = 'nv-fr';
      c.innerHTML = `<div class="nv-fr-h"><span class="nv-fr-n mono">${esc(f.name)}</span><span class="mono nv-dim">${bytes(f.size)}</span><span class="nv-fr-s mono">queued</span></div><div class="nv-prog"><i></i></div><div class="nv-fr-b"></div>`;
      return c;
    });
    box.prepend(...cards);
    let inserted = 0;
    for (let i = 0; i < files.length; i++) {
      const f = files[i], c = cards[i];
      const bar = c.querySelector('.nv-prog i'), s = c.querySelector('.nv-fr-s');
      c.classList.add('run');
      const sn = sniff(f);
      s.textContent = 'uploading 0%';
      try {
        const res = await upload(f, (p) => { bar.style.width = `${(p * 100).toFixed(0)}%`; s.textContent = p < 1 ? `uploading ${(p * 100).toFixed(0)}%` : 'importing and matching…'; c.classList.toggle('match', p >= 1); });
        const info = await sn;
        inserted += res.inserted || 0;
        c.classList.remove('run', 'match');
        renderResult(c, res, info);
      } catch (e) {
        c.classList.remove('run', 'match'); c.classList.add('err');
        s.textContent = 'failed';
        c.querySelector('.nv-fr-b').innerHTML = errorState({ retry: () => handle([f]), title: 'This file was not imported', why: 'The upload stopped before Night Desk could read it. Try it again.', err: e.message, size: 'inline' });
      }
    }
    if (inserted) { await loadDevices(); ctx.refreshSummary(); emit('data'); }
    loadFiles(); loadSettings(); connectView.dataChanged();
  }

  function renderResult(c, r, info) {
    const s = c.querySelector('.nv-fr-s'), b = c.querySelector('.nv-fr-b');
    c.querySelector('.nv-prog i').style.width = '100%';
    if (r.duplicate) {
      c.classList.add('dup'); s.textContent = 'already imported';
      b.innerHTML = `<div class="nv-dim">The same content (sha256 ${esc(r.file_id.slice(0, 12))}…, plain or gzipped) was imported before. Nothing was stored.</div>`;
      return;
    }
    if (r.error) {
      c.classList.add('err'); s.textContent = 'rejected';
      const hint = /TSV/.test(r.error) ? 'Add <code>@load policy/tuning/json-logs.zeek</code> to local.zeek (or set <code>LogAscii::use_json=T</code>) and export again.'
        : /not a Zeek JSON/.test(r.error) ? 'Night Desk reads Zeek JSON logs (one object per line, or one JSON array), Suricata eve.json, Pi-hole’s pihole.log or a query export from its web interface, and AdGuard Home’s querylog.json. Gzip is fine.' : '';
      b.innerHTML = errorState({ act: stateAct('See which logs work', { href: '#help/guides' }), title: 'This file was not imported', why: `${esc(r.error.replace(/^\w+Error: /, ''))}${hint ? ` ${hint}` : ''}`, size: 'inline' });
      return;
    }
    c.classList.add('ok');
    const skipped = r.skipped_lines ?? (info && r.format === 'ndjson' && info.lines > r.rows ? info.lines - r.rows : 0);
    const warns = (r.warnings || []).filter((w) => !/not JSON objects|were not DNS queries/.test(w));
    const sk = r.sinkhole;   // a Pi-hole or AdGuard Home log: every row is a DNS query with the sinkhole's verdict
    const m = r.match || {};
    const sev = m.by_severity || {};
    const types = Object.entries(r.log_types || {});
    s.textContent = `done in ${r.seconds}s`;
    b.innerHTML = `
      <div class="nv-fr-types">${types.map(([t, n]) => `<span class="tag ${t === 'unknown' ? 'amber' : ''}">${esc(t)} <b>${fmt(n)}</b></span>`).join('')}${r.format ? `<span class="mono nv-dim">${esc(sk ? sk.label : r.format === 'ndjson' ? 'JSON lines' : 'JSON array')}</span>` : ''}</div>
      ${sk ? `<div class="nv-dim">${fmt(sk.queries)} DNS lookup${sk.queries === 1 ? '' : 's'} from ${sk.source === 'adguard' ? 'AdGuard Home' : 'Pi-hole'}, ${fmt(sk.blocked)} blocked by it. Blocked lookups are still checked against your threat lists.</div>` : ''}
      <div class="nv-fr-n4">
        <div><span class="label">Rows</span><b class="mono">${fmt(r.rows)}</b></div>
        <div><span class="label">New</span><b class="mono">${fmt(r.inserted)}</b></div>
        <div><span class="label">Duplicates</span><b class="mono ${r.duplicates ? 'nv-warn' : ''}">${fmt(r.duplicates)}</b></div>
        <div><span class="label">Rejected</span><b class="mono ${skipped ? 'nv-bad' : ''}">${fmt(skipped)}</b></div>
      </div>
      <div class="mono nv-dim nv-fr-foot">${r.ts_min ? `${ts(r.ts_min, false)} → ${ts(r.ts_max, false)} ${Z()}` : ''}${skipped ? ` · ${fmt(skipped)} line${skipped === 1 ? '' : 's'} ${sk ? 'were not DNS queries' : 'were not JSON objects'} and were skipped` : ''}${r.duplicates ? ` · ${fmt(r.duplicates)} rows were already imported (same id, type and time)` : ''}${types.some(([t]) => t === 'unknown') ? ' · unknown rows are kept with their raw JSON but not matched' : ''}${r.bad_ts ? ` · ${fmt(r.bad_ts)} rows had no usable timestamp` : ''}</div>
      ${warns.length ? `<div class="nv-warnbox">${warns.map(esc).join('<br>')}</div>` : ''}
      ${m.matches != null ? `<div class="nv-fr-m">${m.matches ? `<b>${fmt(m.matches)}</b> indicator matches → ${Object.entries(sev).map(([k, n]) => `<span class="tag ${({ high: 'red', medium: 'orange', low: 'amber', info: 'blue' })[k]}">${k} ${n}</span>`).join(' ')} <button class="chip" data-go="alerts">Review alerts</button>` : 'No threat-list matches in this file.'}</div>` : ''}`;
    b.querySelector('[data-go]')?.addEventListener('click', () => ctx.goto('alerts', {}));
  }

  input.onchange = () => { handle(input.files); input.value = ''; };
  // dropping anywhere on the tab works, whichever setup is picked; the drop zone (Just files) lights up
  const zone = () => el.querySelector('.connect-drop');
  ['dragenter', 'dragover'].forEach((t) => el.addEventListener(t, (e) => { e.preventDefault(); zone()?.classList.toggle('over', !!e.target.closest?.('.connect-drop')); }));
  el.addEventListener('dragleave', (e) => { if (!el.contains(e.relatedTarget)) zone()?.classList.remove('over'); });
  el.addEventListener('drop', (e) => { e.preventDefault(); zone()?.classList.remove('over'); if (e.dataTransfer?.files?.length) handle(e.dataTransfer.files); });

  async function scanInbox() {
    try {
      const r = await api.post('/api/netlog/inbox/scan');
      const n = r.files?.length || 0;
      const bad = (r.files || []).filter((f) => f.error).length;
      const files = `${n} file${n === 1 ? '' : 's'} from the inbox`;
      const writing = r.still_writing ? ` ${r.still_writing} still being written: ${r.still_writing === 1 ? 'it is' : 'they are'} read once ${r.still_writing === 1 ? 'it settles' : 'they settle'}.` : '';
      if (r.stopped) toast(r.stopped, true);
      else toast(`${!n ? 'No new files in the inbox.' : bad ? `Read ${files}; ${bad} could not be imported.` : `Imported ${files}.`}${writing}`, !!n && bad === n);
      if (n) { await loadDevices(); ctx.refreshSummary(); emit('data'); loadFiles(); }
    } catch (err) { toast(err.message, true); }
  }

  // ---------------------------------------------------------------- files
  async function loadFiles() {
    try {
      const fs = await api.get('/api/netlog/files', { limit: 100 });
      $('.nv-fcount').textContent = fmt(fs.length);
      $('.nv-files').innerHTML = fs.length ? `<table class="nv-ft"><thead><tr><th>File</th><th>Via</th><th>Imported</th><th>Types</th><th class="r">Rows</th><th class="r">New</th><th class="r">Dupes</th><th>Covers (${Z()})</th><th>Status</th></tr></thead><tbody>
        ${fs.map((f) => `<tr class="${f.status !== 'ok' ? 'bad' : ''}"><td class="mono nv-fn" title="${esc(f.name)}${f.path ? `\n${esc(f.path)}` : ''}">${fileName(f.name)}</td><td class="mono nv-dim">${esc(f.origin)}</td><td class="mono nv-dim" title="${ts(f.imported_at)}">${ago(f.imported_at)}</td>
          <td>${Object.entries(f.log_types || {}).map(([t, n]) => `<span class="tag">${esc(t)} ${compactN(n)}</span>`).join(' ')}</td>
          <td class="r mono">${fmt(f.rows)}</td><td class="r mono">${fmt(f.inserted)}</td><td class="r mono nv-dim">${fmt(f.duplicates)}</td>
          <td class="mono nv-dim">${f.ts_min ? `${ts(f.ts_min, false)} → ${ts(f.ts_max, false)}` : ''}</td>
          <td class="mono">${f.status === 'ok' ? '<span class="nv-okc">ok</span>' : `<span class="nv-bad" title="${esc(f.error || '')}">${esc((f.error || f.status).replace(/^\w+Error: /, '').slice(0, 60))}</span>`}</td></tr>`).join('')}
      </tbody></table>` : emptyState({ title: 'No files imported yet', why: 'Drop log files above, or load the demo.', size: 'inline' });
    } catch (e) { $('.nv-files').innerHTML = errorState({ retry: loadFiles, title: "Couldn't list the imported files", why: serverWhy(e), err: e.message, size: 'sm' }); }
  }
  // A file from an archive shows its own name first ("ssl.log", then "night-desk-demo.tar.gz" dimmed), so the seven
  // demo files read apart instead of seven identical cut-off archive paths (D2-10)
  const fileName = (name) => {
    const parts = String(name || '').split('/');
    if (parts.length < 2) return esc(name);
    return `<span class="fnet-fin">${esc(parts.pop())}</span> <span class="nv-dim fnet-farch">${esc(parts[0])}</span>`;
  };
  const compactN = (n) => (n >= 1000 ? `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k` : n);

  // ---------------------------------------------------------------- settings
  async function loadSettings() {
    try {
      settings = await api.get('/api/netlog/settings');
      if (!dirty) prefixes = [...(settings.home_prefixes || [])];
      paintSettings();
    } catch (e) { $('.nv-pfx').innerHTML = errorState({ retry: loadSettings, title: "Couldn't read your network settings", why: serverWhy(e), err: e.message, size: 'sm' }); }
    connectView.setPoll(settings?.inbox_poll_seconds);
  }
  const covered = (p) => {
    const r = cidrRange(p);
    return r && prefixes.some((q) => { const s = cidrRange(q); return s && s[0] <= r[0] && s[1] >= r[1]; });
  };
  function paintSettings() {
    $('.nv-from').textContent = settings.effective_from === 'settings' ? 'set by you' : 'automatic';
    $('.nv-pfx').innerHTML = prefixes.length
      ? prefixes.map((p, i) => `<span class="nv-fc"><b>home</b>${esc(p)}<button data-rm="${i}" title="Remove">✕</button></span>`).join('')
      : '<div class="nv-warnbox">No home prefix set. Night Desk is guessing: private ranges plus your busiest /24 and /64. Add yours for reliable direction.</div>';
    const sug = (settings.suggested || []).filter((s) => !prefixes.includes(s.prefix));
    $('.nv-sugg').innerHTML = sug.length ? `<div class="label">Suggested from your logs</div>${sug.map((s) => `
      <div class="nv-sg"><span class="mono">${esc(s.prefix)}</span><span class="nv-sg-bar"><i style="width:${(s.share * 100).toFixed(0)}%"></i></span><span class="mono nv-dim">${(s.share * 100).toFixed(0)}% of conns</span>
      ${covered(s.prefix) ? '<span class="mono nv-okc" title="Already inside a home prefix">✓ inside home</span>' : `<button class="chip" data-addp="${esc(s.prefix)}">+ Add</button>`}</div>`).join('')}` : '';
    $('.nv-eff').textContent = `in effect: ${(settings.effective_prefixes || []).join(', ')}`;
    $('[data-act="save"]').disabled = !dirty;
  }
  function addPrefix(p) {
    p = p.trim();
    if (!p) return;
    if (!p.includes('/')) p += p.includes(':') ? '/64' : '/32';
    if (!cidrRange(p)) { toast(`Not a prefix: ${p}`, true); return; }
    if (!prefixes.includes(p)) prefixes.push(p);
    dirty = true; paintSettings();
  }
  el.addEventListener('click', async (e) => {
    const rm = e.target.closest('[data-rm]');
    if (rm) { prefixes.splice(+rm.dataset.rm, 1); dirty = true; paintSettings(); return; }
    const ap = e.target.closest('[data-addp]');
    if (ap) { addPrefix(ap.dataset.addp); return; }
    const act = e.target.closest('[data-act]')?.dataset.act;
    if (act === 'add') { addPrefix($('.nv-pin').value); $('.nv-pin').value = ''; }
    if (act === 'save') {
      const b = e.target.closest('button'); b.disabled = true; b.textContent = 'Re-matching…';
      try {
        const r = await api.put('/api/netlog/settings', { home_prefixes: prefixes });
        dirty = false; settings = r;
        const m = r.applied?.rehunt;
        toast(m ? `Saved. Re-matched: ${fmt(m.matches)} matches, ${fmt(m.alerts_touched)} alerts updated.` : 'Saved.');
        await loadDevices(); ctx.refreshSummary(); emit('data');
      } catch (err) { toast(err.message, true); }
      b.textContent = 'Save and re-match';
      paintSettings();
    }
  });
  $('.nv-pin').addEventListener('keydown', (e) => { if (e.key === 'Enter') { addPrefix(e.target.value); e.target.value = ''; } });

  // A phone: a summary (is each source still sending?), the Demo card, and a link to finish setup on a computer
  async function phoneSummary() {
    const box = el.querySelector('.nv-m-imp');
    box.hidden = !isPhone();
    if (!isPhone()) return;
    box.innerHTML = `<section class="nv-m-card"><h3 class="nv-m-ch">Is each source still sending?</h3><div class="nv-m-srcs"><span class="m-skel" style="width:70%"></span></div></section>
      <section class="nv-m-card"><h3 class="nv-m-ch">Connect a new source</h3><p class="nv-m-sub">Connecting a new source is easier on a computer: the steps show commands to copy and files to upload.</p>
        <button type="button" class="m-btn" data-mcopy>Copy link to this page</button></section>`;
    box.querySelector('[data-mcopy]').onclick = () => copyText(`${location.origin}${location.pathname}#network/import`, 'Link copied');
    const f = await api.get('/api/netlog/freshness').catch(() => null);
    const list = box.querySelector('.nv-m-srcs');
    if (!f) { list.innerHTML = errorState({ retry: phoneSummary, title: 'Couldn’t read your sources', size: 'inline' }); return; }
    const src = f.sources || [];
    list.innerHTML = src.length ? `<ul class="nv-m-srcl">${src.map((x) => `<li><span class="nv-m-srcn">${esc(x.label)}</span>
        <span class="nv-m-srcs-s ${x.waiting ? 'wait' : x.stale ? 'stale' : 'ok'}">${x.waiting ? 'Waiting' : x.stale ? 'Stale' : 'Current'}</span>
        <span class="nv-m-srct">${x.waiting ? 'no logs yet' : `newest record ${esc(ago(x.newest))}`}</span></li>`).join('')}</ul>`
      : `<p class="nv-m-sub">${f.demo?.loaded ? 'Only demo data is loaded: no source of your own is sending yet.' : 'No logs of your own yet.'}</p>`;
    afterRender('network');
  }

  return {
    show(opts) {
      visible = true;
      phoneSummary();
      if (opts?.advanced) adv.open = true;   // e.g. from a "device went quiet" alert
      loadFiles(); loadSettings(); connectView.show(); demoView.show(opts); listsView.show(); ndView.show();
      if (adv.open) pushView.show();
      if (opts?.advanced) requestAnimationFrame(() => adv.scrollIntoView({ block: 'start' }));
    },
    hide() { visible = false; pushView.hide(); connectView.hide(); },
  };
}

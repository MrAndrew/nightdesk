// Settings › Data and retention: where the data lives, how big it is, moving it (Change…), and the retention windows
// (off by default: nothing is deleted unless a limit is set). GET /api/lake, POST/DELETE /api/lake/move,
// GET /api/settings, PUT /api/settings/retention. Moving: osinthub/lakeloc.py (native) or install.sh --move-data (Docker).
import { registerSettingsSection } from './registry.js';
import { confirmSheet } from '../../core/sheet.js';

function bytes(b) {
  if (b == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

registerSettingsSection({
  id: 'data',
  label: 'Data and retention',
  order: 30,
  description: 'Everything Night Desk collects stays in one folder on this machine. Nothing is deleted unless you set a limit here.',
  mount(el, ctx) {
    const { api, util } = ctx;
    const { esc, fmt, ago, toast } = util;
    el.innerHTML = `
      <div class="set-card">
        <h3 class="set-h3">Where it lives</h3>
        <dl class="set-kv set-lake"><dt>Folder</dt><dd class="mono">…</dd></dl>
        <div class="set-move"></div>
      </div>
      <div class="set-card" id="src-retention-sec">
        <h3 class="set-h3">Retention</h3>
        <p class="set-p">Leave a box empty to keep that data forever.</p>
        <form class="src-ret">
          <label class="src-ret-f"><span class="label">Lake files</span>
            <span class="src-ret-in"><input class="src-input mono" name="lake_days" type="number" min="1" max="36500" step="1" placeholder="Keep forever"><i class="mono">days</i></span>
            <span class="src-ret-h">Deletes raw record and event files older than this. Records still active are stored again, so the window stays complete.</span></label>
          <label class="src-ret-f"><span class="label">Database events</span>
            <span class="src-ret-in"><input class="src-input mono" name="db_days" type="number" min="1" max="36500" step="1" placeholder="Keep forever"><i class="mono">days</i></span>
            <span class="src-ret-h">Deletes events not seen again in this many days, plus older run history and metrics. Your own uploads are never purged.</span></label>
          <div class="src-ret-act"><button class="src-btn primary" type="submit">Save</button><div class="src-ret-res mono" role="status"></div></div>
        </form>
      </div>
      <div class="set-card">
        <h3 class="set-h3">Bring your own data</h3>
        <p class="set-p">Upload a CSV or JSON of your own indicators in <a href="#settings/sources">Sources</a> (Add your own file)<span class="needs-sql">, or query everything in the <a href="#explorer">SQL console</a></span>.</p>
      </div>`;
    const form = el.querySelector('.src-ret');

    async function loadLake() {
      try {
        const l = await api.get('/api/lake');
        const host = l.location?.change === 'docker' && l.location.host_path;   // in Docker, the folder on your computer
        el.querySelector('.set-lake').innerHTML = `<dt>Folder</dt><dd class="mono">${esc(host || l.path)}${host ? ` <span class="set-move-why" title="Inside the container it is ${esc(l.path)}">(on this computer)</span>` : ''}</dd>
          <dt>Database</dt><dd class="mono">${esc(host && l.db_path.startsWith(l.path + '/') ? host + l.db_path.slice(l.path.length) : l.db_path)} · ${bytes(l.db_bytes)}</dd>
          <dt>Raw files</dt><dd class="mono">${bytes(l.parts.raw.bytes)} in ${fmt(l.parts.raw.files)} files</dd>
          <dt>Uploads</dt><dd class="mono">${bytes(l.parts.uploads.bytes)}</dd>
          <dt>Reference data</dt><dd class="mono">${bytes(l.parts.ref.bytes)}</dd>
          ${l.parts.cache ? `<dt>Working cache</dt><dd class="mono">${bytes(l.parts.cache.bytes)}${l.parts.cache.bytes ? ' (the routing watch’s signed-route file)' : ''}</dd>` : ''}
          <dt>Total</dt><dd class="mono">${bytes(l.bytes)}</dd>`;
        showMove(l);
      } catch (e) { el.querySelector('.set-lake').innerHTML = `<dt>Folder</dt><dd>${esc(e.message)}</dd>`; }
    }

    // ---- moving the data folder
    const mv = el.querySelector('.set-move');
    const shq = (p) => `'${String(p).replace(/'/g, `'\\''`)}'`;   // one shell word
    function lastMoveNote(r) {
      if (!r) return '';
      const body = r.ok
        ? `Moved to <span class="mono">${esc(r.to)}</span> ${ago(r.at)}. The old folder <span class="mono">${esc(r.from)}</span> is still there; delete it when you no longer need it.`
        : `The move to <span class="mono">${esc(r.to)}</span> did not finish: ${esc(r.error || 'unknown reason')}. Night Desk is still using <span class="mono">${esc(r.from)}</span>.`;
      return `<p class="set-p set-move-note">${body} <button class="src-btn set-move-ok" type="button">OK</button></p>`;
    }
    function showMove(l) {
      const loc = l.location || {};
      let html = lastMoveNote(loc.last_move);
      if (loc.pending) {
        html += `<p class="set-p">Night Desk will copy its data to <span class="mono">${esc(loc.pending.to)}</span> the next time it starts. <button class="src-btn set-move-cancel" type="button">Don’t move</button></p>`;
      } else if (loc.change === 'fixed') {
        html += `<p class="set-p">This folder is named by the command that starts Night Desk, so it can’t be changed here. Start Night Desk with another folder to use one. <span class="set-move-why">(Set by OSINTHUB_LAKE, OSINTHUB_DB or <span class="mono">nightdesk --lake</span>.)</span></p>`;
      } else if (loc.change) {
        html += `<button class="src-btn set-move-open" type="button">Change…</button>`;
      }
      mv.innerHTML = html;
      mv.querySelector('.set-move-ok')?.addEventListener('click', async () => { await api.del('/api/lake/move').catch(() => {}); loadLake(); });
      mv.querySelector('.set-move-cancel')?.addEventListener('click', async () => { await api.del('/api/lake/move').catch(() => {}); loadLake(); });
      mv.querySelector('.set-move-open')?.addEventListener('click', () => openMove(l));
    }
    function openMove(l) {
      const loc = l.location;
      const docker = loc.change === 'docker';
      const size = bytes(l.bytes);
      mv.innerHTML = `
        <form class="set-move-form">
          <label class="src-ret-f"><span class="label">${docker ? 'New folder on the computer running Docker' : 'New folder'}</span>
            <input class="src-input mono set-move-path" name="path" type="text" autocomplete="off" spellcheck="false" placeholder="/Volumes/MyDrive/Night Desk">
            <span class="src-ret-h">${docker
              ? 'Night Desk runs in Docker here, so the folder is changed from outside the app. Type the folder, then run the command below in a terminal on that computer: it stops Night Desk, copies the data, and starts it again on the new folder.'
              : `Night Desk copies all its data (${size}) into this folder, checks the copy and then uses it. ${loc.change === 'here' ? 'It restarts to do this, so the page is away for a moment (longer for a lot of data).' : 'This happens the next time you start Night Desk.'} Choose a new or empty folder. The old folder stays as it is until you delete it.`}</span></label>
          ${docker ? `<pre class="mono set-move-cmd" aria-live="polite"></pre>` : ''}
          <div class="src-ret-act">
            ${docker ? `<button class="src-btn primary set-move-copy" type="button" disabled>Copy command</button>`
                     : `<button class="src-btn primary" type="submit">${loc.change === 'here' ? 'Copy and restart' : 'Move at next start'}</button>`}
            <button class="src-btn set-move-close" type="button">Cancel</button>
            <div class="src-ret-res mono" role="status"></div>
          </div>
        </form>`;
      const f = mv.querySelector('.set-move-form'), res = f.querySelector('.src-ret-res'), input = f.path;
      input.focus();
      f.querySelector('.set-move-close').addEventListener('click', () => showMove(l));
      if (docker) {
        const dir = loc.install_dir || '~/.nightdesk';
        const cmdOf = (p) => `sh ${dir.startsWith('~') ? dir : shq(dir)}/app/deploy/install.sh --move-data ${shq(p)}`;
        const pre = f.querySelector('.set-move-cmd'), copy = f.querySelector('.set-move-copy');
        const upd = () => { const p = input.value.trim(); pre.textContent = p ? cmdOf(p) : ''; copy.disabled = !p; };
        input.addEventListener('input', upd); upd();
        copy.addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(pre.textContent); toast('Command copied'); } catch { toast('Copy failed: select the command and copy it', true); }
        });
        f.addEventListener('submit', (e) => e.preventDefault());
        return;
      }
      f.addEventListener('submit', async (e) => {
        e.preventDefault();
        res.textContent = 'Checking the folder…';
        let r;
        try { r = await api.post('/api/lake/move', { path: input.value }); } catch (err) { res.textContent = err.message; return; }
        if (!r.restarting) { toast('The data moves the next time Night Desk starts'); loadLake(); return; }
        waitForRestart(r);
      });
    }
    function waitForRestart(r) {
      const t0 = Date.now();
      mv.innerHTML = `<p class="set-p set-move-wait" role="status">Copying ${bytes(r.bytes)} to <span class="mono">${esc(r.to)}</span> and restarting. This page reloads when Night Desk is back. <span class="mono set-move-t"></span></p>`;
      const tick = mv.querySelector('.set-move-t');
      let away = false;
      const poll = async () => {
        tick.textContent = `${Math.round((Date.now() - t0) / 1000)} s`;
        try {
          const h = await fetch('api/health', { cache: 'no-store' });
          if (h.ok && away) { location.reload(); return; }
          if (!h.ok) away = true;
        } catch { away = true; }
        setTimeout(poll, 2000);
      };
      setTimeout(poll, 1500);
    }
    function purgeText(p) {
      if (!p) return '';
      const parts = [];
      if (p.lake_days) parts.push(`${fmt(p.lake_files)} saved source files (${bytes(p.lake_bytes)})`);
      if (p.db_days) parts.push(`${fmt(p.events)} events`);
      return `Last purge ${ago(p.at)}: removed ${parts.join(' and ')}.`;
    }
    function showRet(r) {
      form.lake_days.value = r.retention.lake_days ?? '';
      form.db_days.value = r.retention.db_days ?? '';
      const on = r.retention.lake_days || r.retention.db_days;
      form.querySelector('.src-ret-res').textContent = on ? (purgeText(r.last_purge) || 'Runs hourly.') : 'Retention is off. All data is kept.';
    }
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const body = { lake_days: form.lake_days.value || null, db_days: form.db_days.value || null };
      if ((body.lake_days || body.db_days) && !(await confirmSheet({ title: 'Delete older data?', text: 'Data older than the limit will be deleted now and every hour after.', confirm: 'Delete older data', danger: true }))) return;
      try {
        showRet(await api.put('/api/settings/retention', body));
        toast(body.lake_days || body.db_days ? 'Retention saved' : 'Retention off: all data is kept');
        loadLake();
      } catch (err) { form.querySelector('.src-ret-res').textContent = err.message; toast(err.message, true); }
    });
    const load = () => { loadLake(); api.get('/api/settings').then(showRet).catch(() => {}); };
    load();
    return { show: load };
  },
});

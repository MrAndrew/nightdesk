// Network → Import: "Your own lists" (upload a CSV or text file of IPs, ranges or domains as a named list; rename,
// replace, delete) and the new-device switch in the Home network card.
// Backend: osinthub/netlog/ownlists.py, osinthub/netlog/newdev.py. Reference: okf/data/netlog.md#your-own-lists
import { serverWhy } from './alert-text.js';
import { emit, esc, fmt, toast, ts, Z, day } from './common.js';
import { ago } from '../../core/util.js';
import { emptyState, errorState } from '../../core/view.js';

const EXPIRY = [['', 'Never'], ['30', '30 days'], ['90', '90 days'], ['365', '1 year']];
const pl = (n, w) => `${fmt(n)} ${w}${n === 1 ? '' : /(s|sh|ch|x)$/.test(w) ? 'es' : 's'}`;
const kindsText = (k = {}) => [k.ip && pl(k.ip, 'address'), k.cidr && pl(k.cidr, 'range'), k.domain && pl(k.domain, 'domain')]
  .filter(Boolean).join(' · ') || 'empty';

async function send(method, path, fd) {
  const r = await fetch(path.replace(/^\//, ''), { method, body: fd });
  let body = null;
  try { body = await r.json(); } catch {}
  if (!r.ok) throw new Error(body?.detail || `${r.status} ${r.statusText}`);
  return body;
}

export function mountLists(el, ctx) {
  const { api } = ctx;
  let lists = [], editing = null, busy = false;
  el.innerHTML = `<div class="panel-head"><span class="panel-title">Your own lists</span><span class="panel-badge netx-lcount"></span></div>
    <div class="nv-cb nv-pad netx-lists">
      <p class="nv-dim" data-nochips>Add a blocklist of your own: a text or CSV file of IP addresses, ranges (like <span class="mono">203.0.113.0/24</span>) or domains, one per line. Night Desk checks your logs against it like its other lists, including the logs you already imported, and alerts say <i>on your list</i>.</p>
      <form class="netx-add" autocomplete="off">
        <label class="al-fl">Name<input class="src-input" name="name" maxlength="60" required placeholder="e.g. Router blocklist"></label>
        <label class="al-fl">File<input type="file" name="file" accept=".txt,.csv,.list,.gz,text/plain,text/csv" required></label>
        <label class="al-fl">Note (optional)<input class="src-input" name="note" maxlength="500" placeholder="where it came from"></label>
        <label class="al-fl">Ends<select name="expires_days">${EXPIRY.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}</select></label>
        <div class="nv-row"><span class="nv-dim netx-add-msg" role="status"></span><button class="src-btn primary" type="submit">Add list</button></div>
      </form>
      <div class="netx-items"></div>
    </div>`;
  const $ = (s) => el.querySelector(s);

  async function load() {
    try { lists = await api.get('/api/netlog/lists'); } catch (e) { $('.netx-items').innerHTML = errorState({ retry: load, title: "Couldn't read your lists", why: serverWhy(e), err: e.message, size: 'sm' }); return; }
    paint();
  }

  function item(l) {
    const hits = l.hits || {};
    const exp = l.expires_at ? (l.active ? `ends ${day(l.expires_at)}` : `ended ${day(l.expires_at)}`) : 'never ends';
    if (editing === l.id) {
      return `<form class="netx-item netx-edit" data-id="${esc(l.id)}">
        <label class="al-fl">Name<input class="src-input" name="name" maxlength="60" required value="${esc(l.name)}"></label>
        <label class="al-fl">Note<input class="src-input" name="note" maxlength="500" value="${esc(l.note || '')}"></label>
        <label class="al-fl">Ends<select name="expires_days"><option value="keep" selected>${esc(exp.replace(/^./, (c) => c.toUpperCase()))}</option>${EXPIRY.map(([v, x]) => `<option value="${v || 0}">${v ? `In ${x}` : 'Never'}</option>`).join('')}</select></label>
        <div class="nv-row"><button class="src-btn" type="button" data-la="cancel">Cancel</button><button class="src-btn primary" type="submit">Save</button></div></form>`;
    }
    return `<div class="netx-item" data-id="${esc(l.id)}">
      <div class="netx-ih"><b class="netx-iname">${esc(l.name)}</b>${l.active ? '' : '<span class="tag">ended</span>'}<span class="mono nv-dim">${esc(kindsText(l.kinds))}</span></div>
      ${l.note ? `<div class="nv-dim netx-inote">${esc(l.note)}</div>` : ''}
      <div class="mono nv-dim netx-imeta">added ${ago(l.created_at)} · ${esc(exp)}${l.file_name ? ` · from ${esc(l.file_name)}` : ''}${l.skipped?.count ? ` · <span title="${esc((l.skipped.sample || []).map((s) => `line ${s.line}: ${s.value} (${s.why})`).join('\n'))}">${pl(l.skipped.count, 'line')} skipped</span>` : ''}</div>
      <div class="nv-row netx-iact">
        ${hits.incidents ? `<button class="chip" data-la="alerts">${pl(hits.incidents, 'alert')}${hits.open ? `, ${fmt(hits.open)} new` : ''}</button>` : '<span class="nv-dim">no matches in your logs</span>'}
        <span class="netx-sp"></span>
        <button class="src-btn" data-la="edit">Rename…</button>
        <label class="src-btn netx-repl" tabindex="0">Replace file<input type="file" hidden accept=".txt,.csv,.list,.gz,text/plain,text/csv" data-la="replace"></label>
        <button class="src-btn" data-la="delete">Delete</button>
      </div></div>`;
  }

  function paint() {
    $('.netx-lcount').textContent = lists.length ? fmt(lists.length) : '';
    $('.netx-items').innerHTML = lists.length ? lists.map(item).join('') : emptyState({ why: 'No lists of your own yet.', size: 'inline' });
  }

  const afterChange = () => { ctx.refreshSummary?.(); emit('data'); emit('alerts'); };
  const matchLine = (m) => (m && m.matches != null ? ` Re-checked your logs: ${pl(m.matches, 'match')}.` : '');

  $('.netx-add').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (busy) return;
    const f = e.target, fd = new FormData(f), msg = $('.netx-add-msg'), btn = f.querySelector('[type="submit"]');
    if (!fd.get('expires_days')) fd.delete('expires_days');
    if (!fd.get('note')) fd.delete('note');
    busy = true; btn.disabled = true; msg.textContent = 'Adding and checking your logs…';
    try {
      const r = await send('POST', '/api/netlog/lists', fd);
      msg.textContent = '';
      toast(`Added “${r.name}”: ${kindsText(r.kinds)}${r.skipped?.count ? ` (${pl(r.skipped.count, 'line')} skipped)` : ''}.${matchLine(r.match)}`);
      f.reset();
      await load(); afterChange();
    } catch (err) { msg.textContent = err.message; }
    busy = false; btn.disabled = false;
  });

  el.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-la]'); if (!b || b.tagName === 'INPUT') return;
    const id = b.closest('[data-id]')?.dataset.id, l = lists.find((x) => x.id === id);
    const a = b.dataset.la;
    if (a === 'edit') { editing = id; paint(); el.querySelector('.netx-edit input')?.focus(); }
    if (a === 'cancel') { editing = null; paint(); }
    if (a === 'alerts') ctx.goto('alerts', {});
    if (a === 'delete' && l) {
      if (b.dataset.sure !== '1') { b.dataset.sure = '1'; b.textContent = `Delete “${l.name}” and its alerts?`; b.classList.add('danger'); return; }
      try { await api.del(`/api/netlog/lists/${encodeURIComponent(id)}`); toast(`Deleted “${l.name}”`); await load(); afterChange(); } catch (err) { toast(err.message, true); }
    }
  });
  // a file dropped on this card is a list, not network logs (the Import tab takes drops anywhere else)
  el.addEventListener('dragover', (e) => { e.preventDefault(); e.stopPropagation(); el.classList.add('netx-over'); });
  el.addEventListener('dragleave', () => el.classList.remove('netx-over'));
  el.addEventListener('drop', (e) => {
    e.preventDefault(); e.stopPropagation(); el.classList.remove('netx-over');
    const f = e.dataTransfer?.files; if (!f?.length) return;
    const inp = $('.netx-add input[type="file"]');
    try { inp.files = f; } catch { return; }
    const nm = $('.netx-add input[name="name"]');
    if (!nm.value) nm.value = f[0].name.replace(/\.(txt|csv|list|gz)$/i, '').slice(0, 60);
    nm.focus();
  });
  el.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target.classList.contains('netx-repl')) { e.preventDefault(); e.target.querySelector('input').click(); } });
  el.addEventListener('change', async (e) => {
    const inp = e.target.closest('input[data-la="replace"]'); if (!inp || !inp.files[0]) return;
    const id = inp.closest('[data-id]').dataset.id;
    const fd = new FormData(); fd.append('file', inp.files[0], inp.files[0].name);
    try {
      const r = await send('PUT', `/api/netlog/lists/${encodeURIComponent(id)}/file`, fd);
      toast(`Replaced “${r.name}”: ${fmt(r.added)} added, ${fmt(r.removed)} removed.${matchLine(r.match)}`);
      await load(); afterChange();
    } catch (err) { toast(err.message, true); }
  });
  el.addEventListener('submit', async (e) => {
    const f = e.target.closest('.netx-edit'); if (!f) return;
    e.preventDefault();
    const fd = new FormData(f), body = { name: fd.get('name'), note: fd.get('note') };
    if (fd.get('expires_days') !== 'keep') body.expires_days = +fd.get('expires_days') || null;
    try { await api.patch(`/api/netlog/lists/${encodeURIComponent(f.dataset.id)}`, body); editing = null; toast('Saved'); await load(); afterChange(); } catch (err) { toast(err.message, true); }
  });

  return { show: load };
}

// The new-device switch and what it has learned, inside the Home network card.
export function mountNewDev(el, ctx) {
  const { api } = ctx;
  el.innerHTML = `<label class="netx-nd"><input type="checkbox" class="netx-nd-on"><span><b>Tell me when a new device joins</b>
    <small class="nv-dim netx-nd-s">…</small></span></label>`;
  const box = el.querySelector('.netx-nd-on'), line = el.querySelector('.netx-nd-s');
  function paint(s) {
    box.checked = !!s.enabled;
    const n = s.known || 0;
    const wall = s.learn_until_wall ? `${ts(s.learn_until_wall, false)} ${Z()}` : '';
    const wallLeft = s.learn_until_wall && Date.parse(s.learn_until_wall) > Date.now();
    const daysLeft = (s.logs_days || 0) < s.learn_log_days;
    line.textContent = !s.baseline_at ? 'It starts with your first import: every device in it is taken as yours, so nothing floods in.'
      : s.learning ? `Learning your devices until ${[wallLeft ? wall : '', daysLeft ? `your logs cover ${s.learn_log_days} days (now ${fmt(s.logs_days || 0)})` : ''].filter(Boolean).join(' and ')}: devices seen meanwhile are taken as yours. ${pl(n, 'device')} known so far.`
        : `${pl(n, 'device')} known. A device seen for the first time in the last ${s.recent_hours / 24} days opens an info alert; it never counts as needing you.`;
  }
  async function load() { try { paint(await api.get('/api/netlog/newdev')); } catch { el.hidden = true; } }
  box.addEventListener('change', async () => {
    try { paint(await api.put('/api/netlog/newdev', { enabled: box.checked })); toast(box.checked ? 'New-device alerts on' : 'New-device alerts off: devices are still recorded'); } catch (err) { toast(err.message, true); box.checked = !box.checked; }
  });
  return { show: load };
}

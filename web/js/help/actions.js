// The actions behind "Do it" buttons in the Help desk (tasks, guide steps, health fixes). An action is data:
//   { go: '#hash' }                                   close Help and go there
//   { help: 'section[/arg]' }                         switch the desk to that section
//   { api: '/api/…', method: 'POST', then?, done? }    call the server, toast `done`, then optionally go to `then`
//   { fn: 'follow' | 'first-alert' | 'expect' | 'search' | 'palette' | 'tour' | 'choose-sources' | 'click', … }
// run(act, desk) returns a promise; desk = { go(hash), section(s), close() , inline(el, html) }.
// Contract: okf/architecture/help.md#actions
import { api } from '../core/api.js';
import { esc, toast } from '../core/util.js';
import { lastCount } from '../core/alerts-badge.js';

// "Load demo data" is offered only while the demo is not loaded; once it is, the same task slot offers removing it
// (Connect logs holds the removal, with its "what goes, what stays" check). The badge's last count says whether the
// demo is in (alerts/count demo_loaded), so this needs no request of its own. help/pages.js runs every page's tasks
// through this.
const isDemoLoad = (t) => t?.act?.api === '/api/netlog/demo' && (t.act.method || 'POST').toUpperCase() === 'POST';
const REMOVE_DEMO = { label: 'Remove demo data', text: 'The demo is loaded. Remove it when you are done; your own logs are not touched.', act: { go: '#network/import', label: 'Open Connect logs' } };
export const demoLoaded = () => !!lastCount()?.demo_loaded;
// A guide step's button: none for "Load demo data" while the demo is in (the step says so instead).
export const shownStepAct = (act) => (act && demoLoaded() && isDemoLoad({ act }) ? null : act);
export function shownTasks(tasks) {
  if (!demoLoaded()) return tasks;
  return tasks.map((t) => (isDemoLoad(t) ? REMOVE_DEMO : t)).filter((t, i, a) => t !== REMOVE_DEMO || a.indexOf(REMOVE_DEMO) === i);
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(sel, ms = 5000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    const el = document.querySelector(sel);
    if (el && el.offsetParent !== null) return el;
    await wait(120);
  }
  return null;
}

export function label(act) {
  if (act.label) return act.label;
  if (act.api) return 'Do it';
  if (act.help) return 'Show me';
  return 'Do it';
}

export async function run(act, desk, btn) {
  if (!act) return;
  if (act.help) { desk.section(act.help); return; }
  if (act.go) { desk.go(act.go); return; }
  if (act.api) {
    if (btn) { btn.disabled = true; btn.dataset.was = btn.textContent; btn.textContent = 'Working…'; }
    try {
      if (act.api === '/api/netlog/demo') {
        // already loaded: say so and open it, instead of the server's 409
        const st = await api.get('/api/setup/status').catch(() => null);
        if (st?.demo) { toast('Demo data is already loaded: opening its alerts'); desk.invalidate?.(); desk.go(act.then || '#network/alerts'); return; }
      }
      await api.post(act.api);
      desk.invalidate?.();
      toast(act.done || 'Done');
      if (act.then) desk.go(act.then);
      else desk.refresh?.();
    } catch (e) {
      toast(e.message, true);
    } finally {
      if (btn?.isConnected) { btn.disabled = false; btn.textContent = btn.dataset.was || 'Do it'; }
    }
    return;
  }
  switch (act.fn) {
    case 'follow': return follow(desk, btn);
    case 'caught-up': {
      try {
        await api.put('/api/marker', {});
        toast('Marked as read: Watch and News now show only what is new from here');
        desk.go('#watch');
      } catch (e) { toast(e.message, true); }
      return;
    }
    case 'hunt': return huntPrompt(desk, btn);
    case 'name-device': {
      let dev = null;
      try {
        const r = await api.get('/api/netlog/devices', { limit: 500 });
        const rows = Array.isArray(r) ? r : r?.devices || r?.rows || [];
        dev = rows.find((d) => d.name_source === 'fallback' && !d.fragment) || null;
      } catch {}
      desk.go('#network/devices');
      if (!dev) { toast('Every device already has a name. Open one to rename it.'); return; }
      const row = await waitFor(`#view-network .nv-drow[data-id="${CSS.escape(dev.id)}"]`, 6000);
      if (!row) { toast('Open a device and choose “Rename or set type”.'); return; }
      row.scrollIntoView({ block: 'center' });
      row.click();
      const b = await waitFor('#view-network [data-act="rename"]', 4000);
      if (b) { b.click(); await wait(80); document.querySelector('#view-network form input[name="name"]')?.focus(); }
      return;
    }
    case 'copy-diag': desk.section('about/diagnostics'); await desk.copyDiag?.(); return;
    case 'first-alert': {
      let id = null;
      try {
        const rows = await api.get('/api/netlog/incidents', { status: 'new', limit: 1 });
        id = rows?.[0]?.id || null;
        if (!id) id = (await api.get('/api/netlog/incidents', { limit: 1 }))?.[0]?.id || null;
      } catch { /* the network part may be missing: fall back to the list */ }
      if (!id) { desk.go('#network/alerts'); if (act.then === 'expect') toast('No alerts yet: load the demo or connect your logs first.'); return; }
      desk.go(`#network/alerts/${encodeURIComponent(id)}`);
      if (act.then === 'expect') expectForm();
      return;
    }
    case 'expect': desk.close(); expectForm(); return;
    case 'search': desk.close(); await wait(60); document.getElementById('gs')?.classList.add('expanded'); document.getElementById('global-search')?.focus(); return;
    case 'palette': desk.close(); await wait(60); (await import('../core/commands.js')).openPalette(); return;
    case 'tour': {
      // a view without a tour of its own gets the Watch tour (the first-visit one)
      const toured = ['watch', 'ops', 'news', 'entities', 'network', 'explorer', 'cinema', 'settings'].includes(document.body.dataset.view);
      if (toured) desk.close(); else desk.go('#watch');
      await wait(toured ? 250 : 900);
      (await import('../core/tour.js')).startTour('page');
      return;
    }
    case 'choose-sources': {
      let to = '#settings/sources';
      try { const s = await api.get('/api/setup/status'); to = s.items?.find((i) => i.id === 'feeds')?.action?.href || to; } catch {}
      desk.go(to.replace(/^#sources$/, '#settings/sources')); return;
    }
    case 'reload': location.reload(); return;
    case 'click': desk.close(); (await waitFor(act.sel, 2000))?.click(); return;
    default: break;
  }
}

// Open the alert detail's "This is expected…" form once the detail has loaded.
async function expectForm() {
  const b = await waitFor('#view-network [data-act="expect"]', 6000);
  if (!b) { toast('Open an alert, then choose “This is expected…”.'); return; }
  b.scrollIntoView({ block: 'center' });
  b.click();
  (await waitFor('#view-network [data-form="expect"]', 1500))?.querySelector('input, select, textarea, button')?.focus();
}

// One-click follow: the vendors most often in CISA KEV, as chips under the button (from the setup checklist).
async function follow(desk, btn) {
  const host = btn?.closest('[data-task]') || btn?.parentElement;
  let sugg = [];
  try { sugg = (await api.get('/api/setup/status')).items?.find((i) => i.id === 'watchlist')?.suggest || []; } catch {}
  if (!host) return;
  host.querySelector('.help-follow')?.remove();
  const box = document.createElement('div');
  box.className = 'help-follow';
  box.setAttribute('role', 'group');
  box.setAttribute('aria-label', 'Follow a vendor');
  box.innerHTML = (sugg.length
    ? `<span class="help-dim">Follow one of the vendors most often on the exploited list:</span><div class="help-chips">${sugg.map((v) => `<button class="help-chip" data-v="${esc(v)}">+ ${esc(v)}</button>`).join('')}</div>`
    : '<span class="help-dim">No suggestions right now.</span>')
    + '<a class="help-link" href="#news">Add your own in News ›</a>';
  host.append(box);
  box.querySelector('button')?.focus();
  box.addEventListener('click', async (e) => {
    const c = e.target.closest('[data-v]');
    if (!c) return;
    c.disabled = true;
    try {
      const w = await api.get('/api/news/watchlist');
      const kw = w.keywords || [];
      if (!kw.some((k) => k.toLowerCase() === c.dataset.v.toLowerCase())) await api.put('/api/news/watchlist', { entities: w.entities || [], keywords: [...kw, c.dataset.v] });
      c.textContent = `✓ ${c.dataset.v}`;
      c.classList.add('on');
      toast(`Following ${c.dataset.v}`);
    } catch (err) { c.disabled = false; toast(err.message, true); }
  });
}

// Hunt one address: ask for it here (prefilled from the alert Help was opened on, if any), then run it in Hunt.
async function huntPrompt(desk, btn) {
  const host = btn?.closest('[data-task]') || btn?.parentElement;
  if (!host) { desk.go('#network/hunt'); return; }
  host.querySelector('.help-follow')?.remove();
  let pre = '';
  const m = (desk.ctxHash || '').match(/^#network\/alerts\/([^/?]+)/);
  if (m) { try { const a = await api.get(`/api/netlog/alerts/${m[1]}`); pre = a?.indicator && !/^sid:/.test(a.indicator) ? a.indicator : ''; } catch {} }
  const f = document.createElement('form');
  f.className = 'help-follow help-hunt';
  f.innerHTML = `<label class="help-dim" for="help-hunt-v">Address, range or name to search your logs for</label>
    <div class="help-row"><input id="help-hunt-v" class="mono" placeholder="203.0.113.7, 198.51.100.0/24 or example.com" value="${esc(pre)}" autocomplete="off" spellcheck="false"><button class="help-do sm">Search logs</button></div>`;
  host.append(f);
  const inp = f.querySelector('input');
  inp.focus(); inp.select();
  f.addEventListener('submit', async (e) => {
    e.preventDefault();
    const v = inp.value.trim();
    desk.go('#network/hunt');
    const q = await waitFor('#view-network .nv-qchips input', 6000);
    if (!q) return;
    if (v) {
      const term = /^[\d.:a-f]+(\/\d+)?$/i.test(v) && /[.:]/.test(v) && !/[g-z]/i.test(v) ? `ip:${v}` : v.includes('.') && !/\s/.test(v) ? `q:${v}` : v;
      q.value = term;
      q.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    }
    q.focus();
  });
}

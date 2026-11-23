// Settings › Home network: the netlog settings that exist today, in one place. Home prefixes (which addresses are
// yours), when logs count as stale, and how long a log-sending device may stay silent before an alert, plus a link
// to the expected-traffic rules. Reads and writes /api/netlog/settings and /api/netlog/ingest/senders/<id>.
import { registerSettingsSection } from './registry.js';
import { errorState } from '../../core/view.js';

const looksLikePrefix = (p) => /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]*)\/\d{1,3}$/i.test(p);

registerSettingsSection({
  id: 'home',
  label: 'Home network',
  order: 20,
  description: 'Tell Night Desk which addresses are yours, so it can tell your devices reaching out from strangers knocking.',
  mount(el, ctx) {
    const { api, util } = ctx;
    const { esc, toast } = util;
    let settings = null, prefixes = [], dirty = false, senders = null;
    el.innerHTML = `
      <div class="set-card">
        <h3 class="set-h3">Your home network (<span data-term="home-prefix">home prefixes</span>) <span class="set-dim set-from"></span></h3>
        <p class="set-p">Addresses inside these ranges are yours, written like 192.168.1.0/24 (<span data-term="cidr">a range</span>). They decide whether a contact is outbound (your device reached out: high or medium) or inbound (someone knocked: low or info).</p>
        <div class="set-pfx"></div>
        <div class="set-row">
          <input class="src-input mono set-pin" placeholder="e.g. 192.168.1.0/24" aria-label="Add a home prefix" autocomplete="off" spellcheck="false">
          <button class="src-btn" data-h="add">Add</button>
          <button class="src-btn primary" data-h="save" disabled>Save and re-match</button>
        </div>
        <div class="set-sugg"></div>
        <p class="set-dim mono set-eff"></p>
      </div>
      <div class="set-card">
        <h3 class="set-h3">When logs count as stale</h3>
        <p class="set-p">Network shows your logs as stale when nothing newer than this has arrived. Devices that upload on their own learn their own rhythm instead.</p>
        <div class="set-row"><label class="set-num"><input class="src-input mono" type="number" min="1" max="8760" step="1" data-h-stale aria-label="Stale after, in hours"><i class="mono">hours</i></label>
          <button class="src-btn" data-h="stale">Save</button></div>
      </div>
      <div class="set-card">
        <h3 class="set-h3">Silent devices</h3>
        <p class="set-p">A device that uploads logs (a router, a Pi-hole) raises an alert when it stops checking in. Leave a box empty to learn the gap from the device's usual rhythm; 0 turns the alert off.</p>
        <div class="set-senders"></div>
      </div>
      <div class="set-card">
        <h3 class="set-h3">Expected traffic</h3>
        <p class="set-p">Traffic you have marked as expected (a backup job, a game console) never raises an alert. Rules are made from an alert with "This is expected".</p>
        <a class="src-btn" href="#network/alerts/rules">See the expected-traffic rules ›</a>
      </div>`;
    const $ = (s) => el.querySelector(s);

    function paintPrefixes() {
      if (!settings) return;
      $('.set-from').textContent = settings.effective_from === 'settings' ? '· set by you' : '· automatic for now';
      $('.set-pfx').innerHTML = prefixes.length
        ? `<ul class="set-chips">${prefixes.map((p, i) => `<li class="set-chip mono">${esc(p)}<button class="icon-btn" data-rm="${i}" aria-label="Remove ${esc(p)}" title="Remove"><svg class="i"><use href="#i-x"/></svg></button></li>`).join('')}</ul>`
        : '<p class="set-warn">No home prefix set. Night Desk is guessing from private ranges and your busiest networks. Add yours for reliable direction.</p>';
      const sug = (settings.suggested || []).filter((s) => !prefixes.includes(s.prefix));
      $('.set-sugg').innerHTML = sug.length ? `<div class="label">Suggested from your logs</div><ul class="set-chips">${sug.map((s) => `<li class="set-chip mono set-chip-s">${esc(s.prefix)} <span class="set-dim">${(s.share * 100).toFixed(0)}% of connections</span><button class="chip" data-addp="${esc(s.prefix)}">+ Add</button></li>`).join('')}</ul>` : '';
      $('.set-eff').textContent = settings.effective_prefixes?.length ? `In effect: ${settings.effective_prefixes.join(', ')}` : '';
      $('[data-h="save"]').disabled = !dirty;
      $('[data-h-stale]').value = settings.stale_hours ?? '';
    }
    function paintSenders() {
      const box = $('.set-senders');
      if (senders === null) { box.innerHTML = '<p class="set-dim">Loading…</p>'; return; }
      if (!senders.length) { box.innerHTML = '<p class="set-dim">No device uploads logs yet. Set one up in <a href="#network/import">Network › Connect logs</a>.</p>'; return; }
      box.innerHTML = `<ul class="set-senders-l">${senders.map((s) => `<li class="set-row"><span class="set-sn">${esc(s.name)}</span>
        <label class="set-num"><input class="src-input mono" type="number" min="0" step="1" data-sid="${esc(s.id)}" value="${s.alert_after_min == null ? '' : esc(s.alert_after_min)}" placeholder="auto" aria-label="Alert after how many silent minutes for ${esc(s.name)}"><i class="mono">min</i></label>
        <button class="src-btn" data-ssave="${esc(s.id)}">Save</button></li>`).join('')}</ul>`;
    }

    async function load() {
      try {
        settings = await api.get('/api/netlog/settings');
        if (!dirty) prefixes = [...(settings.home_prefixes || [])];
        paintPrefixes();
      } catch (e) {
        el.innerHTML = /not found/i.test(e.message)
          ? '<p class="set-p">The network log package is not installed in this build, so there is nothing to set here.</p>'
          : errorState({ retry: load, title: "Couldn't read your home network settings", why: 'The Night Desk server did not answer.', err: e.message, size: 'sm' });
        return;
      }
      paintSenders();
      try { senders = (await api.get('/api/netlog/ingest')).senders || []; } catch { senders = []; }
      paintSenders();
    }

    function addPrefix(p) {
      p = (p || '').trim();
      if (!p) return;
      if (!p.includes('/')) p += p.includes(':') ? '/64' : '/32';
      if (!looksLikePrefix(p)) { toast(`Not a prefix: ${p}`, true); return; }
      if (!prefixes.includes(p)) prefixes.push(p);
      dirty = true; paintPrefixes();
    }

    el.addEventListener('click', async (e) => {
      const rm = e.target.closest('[data-rm]');
      if (rm) { prefixes.splice(+rm.dataset.rm, 1); dirty = true; paintPrefixes(); return; }
      const ap = e.target.closest('[data-addp]');
      if (ap) { addPrefix(ap.dataset.addp); return; }
      const ss = e.target.closest('[data-ssave]');
      if (ss) {
        const inp = el.querySelector(`[data-sid="${CSS.escape(ss.dataset.ssave)}"]`);
        const v = inp.value.trim();
        try {
          await api.patch(`/api/netlog/ingest/senders/${encodeURIComponent(ss.dataset.ssave)}`, { alert_after_min: v === '' ? null : v });
          toast(v === '' ? 'Learning the gap automatically' : v === '0' ? 'Silence alerts off for this device' : `Alert after ${v} silent minutes`);
        } catch (err) { toast(err.message, true); }
        return;
      }
      const act = e.target.closest('[data-h]')?.dataset.h;
      if (act === 'add') { addPrefix($('.set-pin').value); $('.set-pin').value = ''; }
      if (act === 'save') {
        const b = $('[data-h="save"]'); b.disabled = true; b.textContent = 'Re-matching…';
        try {
          settings = await api.put('/api/netlog/settings', { home_prefixes: prefixes });
          dirty = false;
          const m = settings.applied?.rehunt;
          toast(m ? `Saved. Re-matched your logs: ${util.fmt(m.matches)} matches.` : 'Saved.');
        } catch (err) { toast(err.message, true); }
        b.textContent = 'Save and re-match';
        paintPrefixes();
      }
      if (act === 'stale') {
        const v = $('[data-h-stale]').value.trim();
        try { settings = await api.put('/api/netlog/settings', { stale_hours: Number(v) }); toast(`Logs count as stale after ${v} hours`); paintPrefixes(); }
        catch (err) { toast(err.message, true); }
      }
    });
    $('.set-pin').addEventListener('keydown', (e) => { if (e.key === 'Enter') { addPrefix(e.target.value); e.target.value = ''; } });
    load();
    return { show() { if (!dirty) load(); } };
  },
});

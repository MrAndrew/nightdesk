// Settings › Notifications: an opt-in webhook (ntfy, Gotify, Home Assistant, Discord-compatible or plain JSON) for a new
// alert that needs you, a log sender going quiet and a daily summary. Off by default; local destinations only unless
// "Send to an internet service" is ticked. The saved address is never shown in full (it can hold a token).
// GET/PUT /api/notify, POST /api/notify/test, POST /api/notify/digest. Backend: osinthub/notify.py.
// Docs: okf/architecture/notifications.md
import { registerSettingsSection } from './registry.js';
import { confirmSheet } from '../../core/sheet.js';
import * as T from '../../core/time.js';

const TRIGGER = { incident: 'Alert', sensor: 'Log sender quiet', digest: 'Daily summary', test: 'Test', quiet: 'After quiet hours' };
const STATUS = { sent: 'Sent', failed: 'Failed', held: 'Held', blocked: 'Blocked', dropped: 'Dropped' };

registerSettingsSection({
  id: 'notifications',
  label: 'Notifications',
  order: 50,
  description: 'Get told about a serious alert when you are away from the desk. Off until you turn it on; nothing is sent before that.',
  mount(el, ctx) {
    const { api, util } = ctx;
    const { esc, toast } = util;
    let st = null;
    el.innerHTML = `
      <form class="notify-form" novalidate>
        <div class="set-card">
          <label class="notify-switch"><input type="checkbox" name="enabled"><span><b>Send notifications</b>
            <span class="set-dim notify-state" role="status"></span></span></label>
        </div>
        <fieldset class="set-card set-fs">
          <legend class="set-h3">Where to send</legend>
          <p class="set-p">Night Desk posts to one webhook address on your network, such as an ntfy or Gotify server, or a Home Assistant automation that forwards to your phone.</p>
          <label class="notify-f"><span class="label">Format</span>
            <select class="src-input notify-sel" name="preset"></select></label>
          <p class="set-dim notify-hint"></p>
          <label class="notify-f"><span class="label">Address</span>
            <input class="src-input mono" name="url" type="text" inputmode="url" autocomplete="off" spellcheck="false"></label>
          <p class="set-dim notify-saved"></p>
          <label class="notify-check"><input type="checkbox" name="allow_public"><span><b>Send to an internet service</b>
            <span class="set-dim">Needed for an address outside your network, such as ntfy.sh or Discord.</span></span></label>
          <p class="set-warn notify-warn" hidden>With this on, each message leaves this machine for that service: the alert's title (for example “High alert: a device contacted a known command-and-control server”), its severity and a link back to Night Desk. With “Include device names” on, the device's name goes too. No addresses, hardware IDs or log lines are ever sent.</p>
          <p class="set-warn notify-offline" hidden title="Offline mode is the OSINTHUB_OFFLINE=1 setting">Offline mode is on: messages to an internet service are held and not sent. Addresses on your network still work.</p>
        </fieldset>
        <fieldset class="set-card set-fs">
          <legend class="set-h3">What to send</legend>
          <div class="set-radios" role="radiogroup" aria-label="Which alerts">
            <label class="set-radio"><input type="radio" name="min_severity" value="high"><span><b>High alerts only</b><span class="set-dim">The ones worth a look right away. Recommended.</span></span></label>
            <label class="set-radio"><input type="radio" name="min_severity" value="medium"><span><b>High and medium alerts</b><span class="set-dim">Everything that counts as “needs you”.</span></span></label>
          </div>
          <p class="set-dim">One message per alert, however long it goes on, and again only if it gets more serious. Alerts you marked as expected, demo data and alerts already open when you turn this on are not sent.</p>
          <label class="notify-check"><input type="checkbox" name="sensor"><span><b>A log sender goes quiet</b>
            <span class="set-dim">When a sensor or router that pushes its logs stops sending.</span></span></label>
          <div class="notify-check notify-inline"><label><input type="checkbox" name="digest_on"> <b>Daily summary</b></label>
            <label class="notify-time">at <input class="src-input mono" type="time" name="digest_time" required></label>
            <span class="set-dim notify-full">Counts from Watch: alerts that need you, newly exploited bugs, big stories, with a link to Watch. No headlines or names.</span></div>
          <div class="notify-check notify-inline"><label><input type="checkbox" name="quiet_on"> <b>Quiet hours</b></label>
            <label class="notify-time">from <input class="src-input mono" type="time" name="quiet_start" required></label>
            <label class="notify-time">to <input class="src-input mono" type="time" name="quiet_end" required></label>
            <span class="set-dim notify-full">Alerts wait and go out when quiet hours end (several at once arrive as one message). Uses this computer's clock.</span></div>
          <label class="notify-check"><input type="checkbox" name="device_names"><span><b>Include device names</b>
            <span class="set-dim">“High alert: … (Living room TV)”. Off: the message says only what happened.</span></span></label>
          <label class="notify-f"><span class="label">Links open at</span>
            <input class="src-input mono" name="link_base" type="text" inputmode="url" autocomplete="off" spellcheck="false">
            <span class="set-dim">The address of Night Desk as your phone reaches it. Every message links here.</span></label>
          <div class="set-warn notify-linkwarn" role="note" hidden></div>
        </fieldset>
        <div class="notify-act">
          <button class="src-btn primary" type="submit">Save</button>
          <button class="src-btn notify-test" type="button">Send test</button>
          <button class="src-btn notify-dig" type="button">Send a summary now</button>
          <span class="notify-res mono" role="status" aria-live="polite"></span>
        </div>
      </form>
      <div class="set-card">
        <h3 class="set-h3">Recent deliveries</h3>
        <ol class="notify-log"></ol>
      </div>`;
    const f = el.querySelector('.notify-form');
    const res = el.querySelector('.notify-res');

    function preset() { return (st?.presets || []).find((p) => p.id === f.preset.value) || {}; }
    function paintHint() {
      const p = preset();
      el.querySelector('.notify-hint').innerHTML = `${esc(p.hint || '')}${p.docs ? ` <a href="${esc(p.docs)}" target="_blank" rel="noopener noreferrer">${esc(p.label)} docs</a>` : ''}`;
      f.url.placeholder = st?.config.url_set ? 'Saved. Type a new address to replace it.' : (p.example || 'http://…');
    }
    const LOOP = /^(localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)$/i;
    function loopback(u) { try { const h = new URL(u).hostname; return LOOP.test(h) || h.endsWith('.localhost'); } catch { return false; } }
    function paintLink() {
      const w = el.querySelector('.notify-linkwarn');
      const v = f.link_base.value.trim();
      if (!loopback(v)) { w.hidden = true; return; }
      const host = (() => { try { return new URL(v).hostname; } catch { return v; } })();
      const hint = st?.config.link_hint || {};
      const sug = (hint.suggestions || []).map((u) => `<button type="button" class="set-linkbtn notify-sug mono" data-u="${esc(u)}">${esc(u)}</button>`).join(' or ');
      w.innerHTML = `Your phone can't open ${esc(host)}: that name means the phone itself. Use this computer's address on your network or its name, for example https://nightdesk.lan:8443.`
        + (sug ? ` Try ${sug}.` : '')
        + (hint.listening_local_only ? ' Night Desk only accepts connections from this computer right now, so a phone also needs a way in: a reverse proxy, or OSINTHUB_HOST set to listen on your network (see the deployment guide).' : '');
      w.hidden = false;
    }
    function paintState() {
      const c = st.config;
      const where = c.host ? `${c.host} (${c.host_kind === 'internet' ? 'on the internet' : 'on your network'})` : '';
      el.querySelector('.notify-state').textContent = !c.enabled
        ? 'Off. Nothing is sent from this machine.'
        : `On. Messages go to ${where}.${st.held ? ` ${st.held} waiting for quiet hours to end.` : ''}`;
      el.querySelector('.notify-saved').innerHTML = c.url_set
        ? `Saved address: <span class="mono">${esc(c.url_masked)}</span> (the rest is hidden; it may hold a token). <button type="button" class="set-linkbtn notify-clear">Remove</button>`
        : 'No address saved yet.';
      el.querySelector('.notify-offline').hidden = !st.offline;
    }
    function paintLog() {
      const rows = st.log || [];
      el.querySelector('.notify-log').innerHTML = rows.length ? rows.map((r) => `<li class="notify-li">
          <span class="notify-st notify-st-${esc(r.status)}">${esc(STATUS[r.status] || r.status)}</span>
          <span class="notify-lb"><b>${esc(TRIGGER[r.trigger] || r.trigger || '')}</b> ${esc(r.title || '')}
            <span class="set-dim">${esc(T.stamp(r.at, { seconds: true }))}${r.host ? ` · ${esc(r.host)}` : ''} · ${esc(r.detail || '')}</span></span></li>`).join('')
        : '<li class="set-dim">Nothing sent yet.</li>';
    }
    function fill(s) {
      st = s;
      const c = s.config;
      f.preset.innerHTML = s.presets.map((p) => `<option value="${esc(p.id)}">${esc(p.label)}</option>`).join('');
      f.preset.value = c.preset;
      f.enabled.checked = c.enabled;
      f.allow_public.checked = c.allow_public;
      f.sensor.checked = c.sensor;
      f.device_names.checked = c.device_names;
      for (const r of f.min_severity) r.checked = r.value === c.min_severity;
      f.digest_on.checked = c.digest.on; f.digest_time.value = c.digest.time;
      f.quiet_on.checked = c.quiet.on; f.quiet_start.value = c.quiet.start; f.quiet_end.value = c.quiet.end;
      f.link_base.value = c.link_base || (location.origin + location.pathname).replace(/\/$/, '');
      f.url.value = '';
      paintHint(); paintState(); paintLog(); paintLink(); paintPublic();
    }
    function body() {
      const b = {
        enabled: f.enabled.checked, preset: f.preset.value, allow_public: f.allow_public.checked,
        sensor: f.sensor.checked, device_names: f.device_names.checked,
        min_severity: [...f.min_severity].find((r) => r.checked)?.value || 'high',
        digest: { on: f.digest_on.checked, time: f.digest_time.value },
        quiet: { on: f.quiet_on.checked, start: f.quiet_start.value, end: f.quiet_end.value },
        link_base: f.link_base.value.trim(),
      };
      if (f.url.value.trim()) b.url = f.url.value.trim();
      return b;
    }
    const say = (msg, err = false) => { res.textContent = msg; res.classList.toggle('notify-err', err); };
    async function load() {
      try { fill(await api.get('/api/notify')); } catch (e) { say(e.message, true); }
    }
    function outcome(r) {
      const x = r.result || {};
      const text = (x.status === 'sent' ? `Sent (${x.detail}).` : `${STATUS[x.status] || 'Not sent'}: ${x.detail}`)
        + (r.link ? ` Its link: ${r.link}${loopback(r.link) ? ' (a phone can’t open this; see “Links open at”)' : ''}` : '');
      say(text, x.status !== 'sent');
      return text;
    }

    function paintPublic() { el.querySelector('.notify-warn').hidden = !f.allow_public.checked; }
    f.preset.addEventListener('change', paintHint);
    f.allow_public.addEventListener('change', paintPublic);
    f.link_base.addEventListener('input', paintLink);
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      say('Saving…');
      try {
        fill(await api.put('/api/notify', body()));
        say((st.config.enabled ? 'Saved. Notifications are on.' : 'Saved. Notifications are off.')
          + (loopback(f.link_base.value) ? ' Links still point at this computer only; see “Links open at”.' : ''), loopback(f.link_base.value));
        toast('Notification settings saved');
      } catch (err) { say(err.message, true); }
    });
    el.querySelector('.notify-test').addEventListener('click', async (e) => {
      const b = body();
      const btn = e.currentTarget;
      btn.disabled = true;
      say('Sending a test…');
      try {
        const r = await api.post('/api/notify/test', { url: b.url, preset: b.preset, allow_public: b.allow_public, link_base: b.link_base });
        st = { ...st, log: r.log }; paintLog(); toast(outcome(r), r.result?.status !== 'sent');
      } catch (err) { say(err.message, true); } finally { btn.disabled = false; }
    });
    el.querySelector('.notify-dig').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      say('Sending the summary…');
      try {
        const r = await api.post('/api/notify/digest');
        st = { ...st, log: r.log }; paintLog(); outcome(r);
      } catch (err) { say(err.message, true); } finally { btn.disabled = false; }
    });
    el.addEventListener('click', async (e) => {
      const sg = e.target.closest('.notify-sug');
      if (sg) { f.link_base.value = sg.dataset.u; paintLink(); f.link_base.focus(); return; }
      if (!e.target.closest('.notify-clear')) return;
      if (!(await confirmSheet({ title: 'Remove the saved address?', text: 'Notifications turn off.', confirm: 'Remove', danger: true }))) return;
      try { fill(await api.put('/api/notify', { clear_url: true })); say('Address removed. Notifications are off.'); } catch (err) { say(err.message, true); }
    });
    load();
    return { show: load };
  },
});

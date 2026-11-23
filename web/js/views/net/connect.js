// Network → Connect logs: a guided setup. Pick what you have (a firewall, a sensor, a DNS filter or just files), get
// the steps for it (the token, the exact commands, where the files land), then watch "Waiting for the first check-in…"
// turn green when its logs arrive (GET /api/netlog/freshness). The device-upload internals stay in push.js, shown
// under Advanced by import.js. Reference: okf/data/netlog.md#connect-logs
import { esc, fmt, toast, ts, Z } from './common.js';
import { ago } from '../../core/util.js';
import { KINDS, bindHtml, setupHtml, copyBtn } from './push.js';
import { errorState } from '../../core/view.js';

const LS_PICK = 'nd.connect.pick';
const LS_MADE = 'nd.connect.made';   // {kind: sender id} of the token last made here
const ls = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
};

const ICO = {
  fw: '<path d="M4 6h16v5H4zM4 13h16v5H4z" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="7" cy="8.5" r="1" fill="currentColor"/><circle cx="7" cy="15.5" r="1" fill="currentColor"/>',
  eye: '<path d="M2 12s3.6-6 10-6 10 6 10 6-3.6 6-10 6S2 12 2 12z" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="12" cy="12" r="2.6" fill="none" stroke="currentColor" stroke-width="1.5"/>',
  dns: '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z" fill="none" stroke="currentColor" stroke-width="1.5"/>',
  file: '<path d="M7 3h7l4 4v14H7z M14 3v4h4" fill="none" stroke="currentColor" stroke-width="1.5"/>',
};

// What you can pick, and the steps for each. `kinds` are push.js KINDS (several = a choice inside the path).
// `prep` is what to do on the device first. Paths and menus follow the projects' own docs (they move between versions).
const PICKS = {
  opnsense: { label: 'OPNsense', sub: 'firewall', ico: 'fw', kinds: ['opnsense'], name: 'Firewall',
    what: 'Night Desk gets the events of OPNsense’s built-in intrusion detection (Suricata).',
    prep: [
      'Turn on intrusion detection: <b>Services › Intrusion Detection › Administration</b>, tick <b>Enabled</b>, pick the interfaces to watch (LAN is a good start) and press Apply.',
      'Open a root shell on the firewall: the console menu (option 8, Shell) or SSH (<b>System › Settings › Administration › Secure Shell</b>).',
    ] },
  pfsense: { label: 'pfSense', sub: 'firewall', ico: 'fw', kinds: ['pfsense'], name: 'Firewall',
    what: 'Night Desk gets the events of the Suricata package on every interface you run it on.',
    prep: [
      'Install Suricata: <b>System › Package Manager › Available Packages</b>, search for suricata. Install the <b>Cron</b> package too: the 5-minute schedule is added there.',
      'Under <b>Services › Suricata › Interfaces</b>, edit each interface, tick <b>EVE JSON Log</b> (output type FILE), save, and start it.',
      'Open a root shell: the console menu (option 8, Shell) or SSH (<b>System › Advanced › Admin Access › Secure Shell</b>).',
    ] },
  securityonion: { label: 'Security Onion', sub: 'sensor', ico: 'eye', kinds: ['securityonion'], name: 'Security Onion',
    what: 'Night Desk gets Zeek’s finished hourly logs, which Security Onion already writes as JSON.',
    prep: [
      'Nothing to change on Security Onion: Zeek writes JSON to <code>/nsm/zeek/logs</code>.',
      'Open a shell on the sensor (or the standalone box) and become root: <code>sudo -i</code>.',
    ] },
  sensor: { label: 'Zeek or Suricata', sub: 'Linux sensor', ico: 'eye', kinds: ['zeek', 'suricata'], name: 'Sensor',
    what: { zeek: 'Night Desk gets each finished hourly Zeek archive once.', suricata: 'Night Desk gets new lines of eve.json every 5 minutes.' },
    prep: {
      zeek: ['Make Zeek write JSON: add <code>@load policy/tuning/json-logs.zeek</code> to <code>local.zeek</code>, then <code>zeekctl deploy</code>.',
        'Open a shell on the sensor and become root: <code>sudo -i</code>.'],
      suricata: ['Check that Suricata writes <code>eve.json</code> (on by default in <code>suricata.yaml</code>, usually in <code>/var/log/suricata/</code>).',
        'Open a shell on the sensor and become root: <code>sudo -i</code>.'],
    } },
  pihole: { label: 'Pi-hole', sub: 'DNS filter', ico: 'dns', kinds: ['pihole'], name: 'Pi-hole', fileToo: true,
    what: 'Night Desk gets every DNS lookup and whether Pi-hole blocked it, and checks the names against your threat lists.',
    prep: [
      'Keep Pi-hole’s query logging on (the default). Pi-hole v6 writes the log to <code>/var/log/pihole/pihole.log</code> unless you changed it.',
      'Open a shell on the Pi-hole machine and become root: <code>sudo -i</code>.',
    ] },
  adguard: { label: 'AdGuard Home', sub: 'DNS filter', ico: 'dns', kinds: ['adguard'], name: 'AdGuard Home', fileToo: true,
    what: 'Night Desk gets every DNS lookup and whether AdGuard Home blocked it. AdGuard keeps recent lookups in memory and writes them to its log file in batches (the <code>size_memory</code> setting), so on a quiet network the first ones can take a while.',
    prep: [
      'Make sure the query log is on and written to a file: in <code>AdGuardHome.yaml</code>, <code>querylog</code> has <code>enabled: true</code> and <code>file_enabled: true</code> (usually the defaults).',
      'Open a shell on the AdGuard Home machine and become root: <code>sudo -i</code>.',
    ] },
  files: { label: 'Just files', sub: 'upload or copy', ico: 'file', kinds: [], name: '' },
};
const PICK_ORDER = ['opnsense', 'pfsense', 'securityonion', 'sensor', 'pihole', 'adguard', 'files'];
const FILE_ORIGINS = ['upload', 'inbox', 'api'];

export function mount(el, ctx, { pickFiles, showDemo, openAdvanced, scanInbox, onNewData } = {}) {
  const { api } = ctx;
  let pick = PICKS[ls.get(LS_PICK)] ? ls.get(LS_PICK) : null;
  let made = {};
  try { made = JSON.parse(ls.get(LS_MADE) || '{}') || {}; } catch { made = {}; }
  let sub = {};                 // pick → chosen kind inside it (sensor: zeek | suricata)
  let ing = null, fresh = null, where = null, inbox = null, lastInbox = null, reveal = null, urlPick = 0, visible = false, timer = null, busy = false, pollSec = 0;
  const $ = (s) => el.querySelector(s);

  el.innerHTML = `
    <div class="panel-head"><span class="panel-title">Connect logs</span><span class="connect-badge"></span></div>
    <div class="nv-pad connect">
      <p class="connect-lede">Tell Night Desk what you have and it shows the exact steps. Your firewall or sensor sends its logs here; Night Desk never logs in to it.</p>
      <div class="connect-h"><span class="connect-n">1</span>What do you have?</div>
      <div class="connect-picks" role="radiogroup" aria-label="What do you have?">${PICK_ORDER.map((k) => { const p = PICKS[k]; return `
        <button class="connect-pick" role="radio" data-pick="${k}" aria-checked="false"><svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">${ICO[p.ico]}</svg><span><b>${esc(p.label)}</b><small>${esc(p.sub)}</small></span></button>`; }).join('')}
      </div>
      <div class="connect-alt"><span>Have a log file already?</span><button class="nv-link" data-c="pickfiles">Upload files</button><span class="connect-sep" aria-hidden="true">·</span><span>No logs yet?</span><button class="nv-link" data-c="demo">Try the demo</button></div>
      <div class="connect-body"></div>
    </div>`;

  // ------------------------------------------------------------------ data
  async function loadIngest() { try { ing = await api.get('/api/netlog/ingest'); } catch (e) { ing = { error: e.message }; } }
  async function loadFresh() { try { fresh = await api.get('/api/netlog/freshness'); } catch { fresh = null; } }
  async function loadWhere() {
    if (where) return;
    try { const p = await api.get('/api/paths'); where = p.inbox_where || { path: `${p.lake}/inbox/zeek/` }; } catch { where = { path: null }; }
  }
  // the watched folder, its delete setting and counts (GET /api/netlog/inbox; okf/data/netlog.md#inbox)
  async function loadInbox() {
    try { inbox = await api.get('/api/netlog/inbox'); lastInbox = inbox; if (inbox.where) where = inbox.where; } catch (e) { inbox = { error: e.message }; }
  }

  // ------------------------------------------------------------------ paint
  let paints = 0;
  function paint() {
    paints++;
    el.querySelectorAll('[data-pick]').forEach((b) => { const on = b.dataset.pick === pick; b.classList.toggle('on', on); b.setAttribute('aria-checked', on); });
    const body = $('.connect-body');
    if (!pick) { body.innerHTML = ''; paintBadge(); return; }
    body.innerHTML = pick === 'files' ? filesHtml() : pushHtml();
    paintStatus();
  }

  function kindOf(p = pick) { const k = PICKS[p].kinds; return sub[p] && k.includes(sub[p]) ? sub[p] : k[0]; }

  function step(n, title, inner, cls = '') {
    return `<div class="connect-step ${cls}"><div class="connect-h"><span class="connect-n">${n}</span>${title}</div><div class="connect-sb">${inner}</div></div>`;
  }

  function pushHtml() {
    const p = PICKS[pick], kind = kindOf();
    const choose = p.kinds.length > 1 ? `<div class="connect-seg" role="radiogroup" aria-label="Which logs?">${p.kinds.map((k) => `<button role="radio" aria-checked="${k === kind}" class="${k === kind ? 'on' : ''}" data-kind="${k}">${esc(KINDS[k].label.replace(/ \(.*\)/, ''))}</button>`).join('')}</div>` : '';
    const what = typeof p.what === 'object' ? p.what[kind] : p.what;
    const prep = Array.isArray(p.prep) ? p.prep : p.prep[kind];
    let s = step(2, 'Get it ready', `${choose}<p class="connect-what">${what}</p><ol class="connect-ol">${prep.map((x) => `<li>${x}</li>`).join('')}</ol>
      ${p.fileToo ? `<p class="nv-dim connect-small">Rather send a file once? Copy the log off the machine and <button class="nv-link" data-c="pickfiles">upload it</button>.</p>` : ''}`);
    s += step(3, 'Turn on device uploads', '<div class="connect-up"></div>');
    s += step(4, 'Give it a name and run the commands', tokenHtml());
    s += step(5, 'Waiting for the first check-in…', '<div class="connect-wait" role="status" aria-live="polite"></div>', 'connect-step-wait');
    return s;
  }

  function tokenHtml() {
    const kind = kindOf();
    if (reveal && reveal.sender.kind === kind && ing && !ing.error) {
      return `<p class="connect-what">Run these as root on the device. They save the token, install a small script (<code>hlta-push.sh</code>) and set it to run every 5 minutes. New logs land in Night Desk under the device’s name.</p>
        ${setupHtml(ing, reveal, urlPick, { title: false })}
        <div class="nv-row"><span class="nv-dim">The token is not shown again once you close this.</span><button class="src-btn" data-c="closetoken">I have copied it</button></div>`;
    }
    const p = PICKS[pick], nf = nameField(p.name);
    return `<p class="connect-what">Each device gets its own token, so you can pause or revoke one without touching the others.${nf.taken ? ` You already have a device called ${esc(p.name)}: give this one its own name.` : ''}</p>
      <div class="nv-row connect-name"><label class="nv-pu-f"><span class="label">Device name</span><input class="src-input" data-c="name" maxlength="60" value="${esc(nf.value)}" placeholder="${esc(nf.placeholder)}"></label><button class="src-btn primary" data-c="create">Create token and commands</button></div>`;
  }

  // The kind's plain name when it is free; otherwise nothing (no auto-numbering that changes on every visit).
  function nameField(base) {
    const taken = (ing?.senders || []).some((x) => x.name.toLowerCase() === base.toLowerCase());
    return { value: taken ? '' : base, placeholder: taken ? `${base} in the garage` : base, taken };
  }

  function filesHtml() {
    const w = where || {};
    const inboxHtml = `<p class="connect-what finbox-intro">Copy or rsync log files into this folder. Night Desk imports each file once it has stopped changing and keeps a gzipped copy in its lake.</p>
      <div class="finbox-where">${whereHtml(w)}</div>
      <div class="finbox-live"></div>
      ${inboxControls()}`;
    let s = step(2, 'Drop the files here', `<div class="src-drop nv-drop connect-drop" tabindex="0" role="button" aria-label="Choose log files to upload">
        <svg class="src-drop-ico" viewBox="0 0 24 24" width="28" height="28" aria-hidden="true"><path d="M12 15V4m0 0-4 4m4-4 4 4M5 15v3a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-3" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>
        <div class="src-drop-t">Drop network logs here or <u>choose files</u></div>
        <div class="src-drop-s">Zeek JSON logs (conn, dns, ssl, http, dhcp…), Suricata <code>eve.json</code>, a Pi-hole query log (<code>pihole.log</code>) or query export, or an AdGuard Home <code>querylog.json</code></div>
        <div class="src-drop-s mono">plain or .gz · .zip or .tar bundles · several at once</div>
      </div>`);
    s += step(3, 'Or let Night Desk pick them up', `${inboxHtml}<div class="nv-row"><span class="mono nv-dim connect-poll">${pollSec ? `checked every ${pollSec}s` : ''}</span><button class="src-btn" data-c="scan">Scan inbox now</button></div>`);
    s += step(4, 'Waiting for your first file…', '<div class="connect-wait" role="status" aria-live="polite"></div>', 'connect-step-wait');
    return s;
  }

  // The inbox folder as the user reaches it: the path (with a copy button), or in Docker the host folder / a copy command.
  function whereHtml(w) {
    if (w.path) {
      return `<div class="nv-pathbox"><code class="nv-path">${esc(w.path)}</code>${copyBtn(w.path)}</div>
        ${w.docker ? '<p class="nv-dim connect-small">This is the folder on this computer that Docker shares with Night Desk (LAKE_DIR).</p>' : ''}`;
    }
    if (w.docker) {
      return `<p class="connect-what">${esc(w.note || '')}</p>
        <div class="nv-pathbox"><code class="nv-path">${esc(w.copy_cmd || '')}</code>${copyBtn(w.copy_cmd || '')}</div>`;
    }
    return '<div class="nv-dim">Loading where the inbox is…</div>';
  }

  // The delete toggle and "Change folder". Painted with the step, not on every refresh, so typing and focus survive.
  function inboxControls() {
    const ib = inbox && !inbox.error ? inbox : null;
    const del = !!ib?.delete_after_import;
    const docker = ib?.docker || where?.docker;
    // "Change folder" and "Use the default folder" stay usable when the status could not be read (inbox.error)
    const known = ib || lastInbox;
    const failed = !!inbox?.error;
    const change = !ib && !failed ? '' : known?.from_env
      ? `<p class="nv-dim connect-small finbox-env">This folder was set when Night Desk was started (<code title="environment variable">OSINTHUB_INBOX</code>), so it can only be changed there.</p>`
      : `<details class="finbox-change"><summary>Change folder</summary>
          <form class="finbox-form" novalidate>
            <label class="finbox-label" for="finbox-path">Folder Night Desk watches</label>
            <div class="finbox-fields">
              <input class="src-input finbox-input" id="finbox-path" name="path" autocomplete="off" spellcheck="false" aria-describedby="finbox-err finbox-hint" value="${esc(known?.path || '')}">
              <button type="submit" class="src-btn primary">Save folder</button>
            </div>
            <p class="finbox-err" id="finbox-err" aria-live="assertive"></p>
            <p class="nv-dim connect-small" id="finbox-hint">The full path of an existing folder${docker ? ' <b>inside the Night Desk container</b> (mount your folder there in docker-compose.yml first)' : ''}. Files already imported from the old folder stay in the lake.${!known?.is_default ? ` <button type="button" class="nv-link" data-fi="reset">Use the default folder</button>` : ''}</p>
          </form>
        </details>`;
    return `<div class="finbox-opts">
        <label class="finbox-toggle"><input type="checkbox" data-fi="delete" ${del ? 'checked' : ''} ${ib ? '' : 'disabled'} aria-describedby="finbox-del-why"><span>Delete files after import</span></label>
        <p class="nv-dim connect-small" id="finbox-del-why">${del
          ? 'On: each log file is deleted from the folder once it is safely in the lake, after it has not changed for 2 minutes. Logs that cannot be read move to <code>failed/</code>; other files are left alone. Use it only for a folder that receives finished files (rsync, Zeek’s rotated logs), not one a program is still writing to.'
          : 'Off: Night Desk copies each file into its lake and leaves yours where it is. A file is read again only if it changes.'}</p>
      </div>${change}`;
  }

  // waiting · imported · failed, and the names of the files that failed
  function inboxLive() {
    if (!inbox) return '<span class="nv-dim">Checking the folder…</span>';
    if (inbox.error) return `<div class="nv-warnbox finbox-staterr">Couldn't read the inbox status: ${esc(inbox.error)}. You can still change the folder or go back to the default one below.</div>`;
    if (inbox.problem) return `<div class="nv-warnbox">${esc(inbox.problem)} Night Desk is not reading this folder, and deletes nothing in it.</div>`;
    const del = inbox.delete_after_import;
    const imp = del ? inbox.imported_total : inbox.imported;
    const nf = inbox.failed_count ?? inbox.failed.length;
    const n = (v, label, cls = '') => `<span class="finbox-n ${cls}"><b class="mono">${fmt(v)}</b> ${label}</span>`;
    const counts = `<div class="finbox-counts" role="status">${n(inbox.waiting, 'waiting')}${inbox.writing ? n(inbox.writing, 'still being written') : ''}${n(imp, del ? 'imported so far' : 'imported')}${n(nf, 'failed', nf ? 'bad' : '')}</div>`;
    // a list of names: the first three, the rest behind "Show N more" (its open state survives repaints, by data-k)
    const list = (k, items, total, label, li) => {
      const first = items.slice(0, 3), rest = items.slice(3);
      const beyond = total > items.length ? `<li class="nv-dim">and ${fmt(total - items.length)} more</li>` : '';
      return `<ul class="finbox-failed" aria-label="${label}">${first.map(li).join('')}</ul>
        ${rest.length || beyond ? `<details class="finbox-more" data-k="${k}"><summary>Show ${fmt(total - first.length)} more</summary><ul class="finbox-failed">${rest.map(li).join('')}${beyond}</ul></details>` : ''}`;
    };
    const name = (p) => `<li class="finbox-quietli"><code>${esc(p)}</code></li>`;
    let html = counts;
    if (nf) {
      const moved = inbox.failed.some((f) => f.moved);
      const hint = [moved ? 'Files in <code>failed/</code> are skipped: fix one and copy it back into the folder to try again.' : '',
        !del && inbox.failed.some((f) => !f.moved) ? 'A failed file is tried again when it changes.' : ''].filter(Boolean).join(' ');
      html += list('failed', inbox.failed, nf, 'Files that could not be imported', (f) => `<li><code>${esc(f.path)}</code><span>${esc(f.error)}</span></li>`);
      if (hint) html += `<p class="nv-dim connect-small">${hint}</p>`;
    }
    if (inbox.not_logs_count) {
      html += `<p class="nv-dim connect-small finbox-quiet">${fmt(inbox.not_logs_count)} file${inbox.not_logs_count === 1 ? ' is' : 's are'} not a log, so Night Desk leaves ${inbox.not_logs_count === 1 ? 'it' : 'them'} alone:</p>`
        + list('notlogs', inbox.not_logs || [], inbox.not_logs_count, 'Files that are not logs', name);
    }
    if (inbox.links_count) {
      html += `<p class="nv-dim connect-small finbox-quiet">${fmt(inbox.links_count)} link${inbox.links_count === 1 ? ' was' : 's were'} skipped: Night Desk does not follow links. Copy the file itself into the folder, or point the inbox at the real folder.</p>`
        + list('links', inbox.links || [], inbox.links_count, 'Links that were skipped', name);
    }
    if (inbox.earlier_failed) html += `<p class="nv-dim connect-small finbox-quiet">${fmt(inbox.earlier_failed)} in <code>failed/</code> from earlier imports.</p>`;
    return html;
  }

  let liveHtml = '';
  function paintInbox() {
    const live = $('.finbox-live');
    const html = inboxLive();
    if (live && (html !== liveHtml || !live.innerHTML)) {   // repaint only on change, so an open list keeps its place
      const open = [...live.querySelectorAll('.finbox-more[open]')].map((d) => d.dataset.k);
      live.innerHTML = html; liveHtml = html;
      open.forEach((k) => live.querySelector(`.finbox-more[data-k="${k}"]`)?.setAttribute('open', ''));
    }
    const wh = $('.finbox-where');
    if (wh && where) wh.innerHTML = whereHtml(where);
    // a folder Night Desk refuses: no "copy files into this folder" over it
    const bad = !!inbox?.problem;
    if (wh) wh.hidden = bad;
    const intro = $('.finbox-intro');
    if (intro) intro.hidden = bad;
  }

  // re-render the inbox controls after a save; `revert` puts the toggle back when the save failed
  function paintFiles(revert = null) {
    const opts = $('.finbox-opts'), ch = $('.finbox-change');
    if (!opts) return;
    const wrap = document.createElement('div');
    wrap.innerHTML = inboxControls();
    ch?.remove();
    opts.replaceWith(...wrap.childNodes);
    if (revert != null) { const t = $('[data-fi="delete"]'); if (t) t.checked = revert; }
    paintInbox();
  }

  async function saveInbox(body, done) {
    try {
      inbox = await api.put('/api/netlog/inbox', body);
      if (inbox.where) where = inbox.where;
      toast(done);
      return true;
    } catch (err) { toast(err.message, true); return err; }
  }

  // the parts that change while the page is open: uploads on/off, the waiting state, the badge
  function paintStatus() {
    paintBadge();
    paintInbox();
    const up = $('.connect-up');
    if (up) up.innerHTML = upHtml();
    const w = $('.connect-wait');
    if (w) {
      const r = pick === 'files' ? waitFiles() : waitPush();
      w.innerHTML = r.html;
      w.className = `connect-wait ${r.state}`;
      const h = w.closest('.connect-step')?.querySelector('.connect-h');
      if (h) h.lastChild.textContent = r.title;
    }
  }

  function upHtml() {
    if (!ing) return '<div class="nv-dim">Checking…</div>';
    if (ing.error) return errorState({ retry: refresh, title: "Couldn't read the upload settings", why: 'The Night Desk server did not answer.', err: ing.error, size: 'sm' });
    const c = ing.config, st = ing.status;
    if (c.enabled && st.running) {
      const u = st.urls[0];
      return `<div class="connect-ok"><span class="connect-dot ok" aria-hidden="true"></span><span>Uploads are on${u ? `: devices send to <code>${esc(u)}</code>` : ''}.</span></div>
        ${bindHtml(ing, { compact: true })}
        <p class="nv-dim connect-small">The upload port accepts logs with a device token and nothing else; the rest of Night Desk stays private. <button class="nv-link" data-c="advanced">Change in Advanced</button></p>`;
    }
    if (c.enabled && st.error) return `<div class="nv-warnbox nv-bad">${esc(st.error)}</div><div class="nv-row"><span></span><button class="src-btn" data-c="advanced">Open Advanced</button></div>`;
    if (c.enabled) return '<div class="nv-dim">Starting the upload port…</div>';
    return `<p class="connect-what">Night Desk opens a separate upload port (${esc(c.port)}) that accepts logs with a device token and nothing else. The rest of Night Desk stays private to this machine.</p>
      ${bindHtml(ing, { compact: true })}
      <div class="nv-row"><button class="nv-link" data-c="advanced">Address, port and certificate</button><span></span><button class="src-btn primary" data-c="enable">Turn on uploads</button></div>`;
  }

  const srcOf = (name) => fresh?.sources?.find((s) => s.source === `push:${name}`);

  // Only the token made here (remembered per kind across reloads); older tokens are listed under Advanced.
  function madeSender(kind) {
    const id = made[kind];
    return id ? (ing?.senders || []).find((s) => s.id === id) : null;
  }

  function waitPush() {
    const kind = kindOf();
    const s = madeSender(kind);
    const others = (ing?.senders || []).filter((x) => x.kind === kind && x.id !== s?.id).length;
    const more = others ? ` <span class="nv-dim">${others} other ${esc(KINDS[kind].label)} device${others === 1 ? '' : 's'}: see <button class="nv-link" data-c="advanced">Advanced</button>.</span>` : '';
    if (!s) return { state: 'idle', title: 'Waiting for the first check-in…', html: `<p class="nv-dim">Create a token above and run the commands on the device. This turns green when its first logs arrive.${more}</p>` };
    const off = ing && !ing.config.enabled;
    const f = srcOf(s.name);
    let state, line;
    if (s.paused) { state = 'idle'; line = 'paused: its uploads are refused'; }
    else if (f?.newest) { state = f.stale ? 'late' : 'ok'; line = `${f.stale ? 'Quiet: newest logs are from' : 'Connected. Logs up to'} ${ago(f.newest)}`; }
    else if (s.last_seen) { state = 'seen'; line = `checked in ${ago(s.last_seen)}, waiting for its first logs`; }
    else { state = 'wait'; line = off ? 'waiting: turn on uploads first' : 'waiting for the first check-in'; }
    const row = `<li class="${state}"><span class="connect-dot ${state}" aria-hidden="true"></span><b>${esc(s.name)}</b><span>${esc(line)}</span>${f?.newest ? `<span class="mono nv-dim" title="Newest record time (${Z()})">${esc(ts(f.newest, false))}</span>` : ''}</li>`;
    const ok = state === 'ok';
    const hint = ok ? '<div class="nv-row"><span class="nv-dim">New logs keep arriving every few minutes. Night Desk alerts you if the device goes quiet.</span><button class="src-btn primary" data-c="overview">See your network</button></div>'
      : '<p class="nv-dim connect-small">Running <code>hlta-push.sh --check</code> on the device counts as a check-in. Logs follow on the next scheduled run, within 5 minutes. Night Desk checks for them every few seconds.</p>';
    return { state: ok ? 'ok' : 'wait', title: ok ? 'Connected' : 'Waiting for the first check-in…', html: `<ul class="connect-list">${row}</ul>${hint}${more ? `<p class="connect-small">${more}</p>` : ''}` };
  }

  function waitFiles() {
    const fs = (fresh?.sources || []).filter((s) => FILE_ORIGINS.includes(s.source) && s.newest);
    if (!fs.length) return { state: 'wait', title: 'Waiting for your first file…', html: '<p class="nv-dim"><span class="connect-dot wait" aria-hidden="true"></span> Nothing yet. Drop a file above or copy one into the inbox. This turns green when Night Desk has read it.</p>' };
    const rows = fs.map((s) => `<li class="${s.stale ? 'late' : 'ok'}"><span class="connect-dot ${s.stale ? 'late' : 'ok'}" aria-hidden="true"></span><b>${esc(s.label)}</b><span>${fmt(s.files)} file${s.files === 1 ? '' : 's'}, logs up to ${ago(s.newest)}</span><span class="mono nv-dim">${esc(ts(s.newest, false))}</span></li>`).join('');
    return { state: 'ok', title: 'Logs arrived', html: `<ul class="connect-list">${rows}</ul><div class="nv-row"><span class="nv-dim">Files are a snapshot: send new ones when you want fresh results, or set up a device above to send them on its own.</span><button class="src-btn primary" data-c="overview">See your network</button></div>` };
  }

  function paintBadge() {
    const b = $('.connect-badge');
    const live = (fresh?.sources || []).filter((s) => s.newest);
    const ok = live.filter((s) => !s.stale);
    b.className = `panel-badge connect-badge ${ok.length ? 'ok' : live.length ? 'bad' : ''}`;
    b.textContent = ok.length ? `${ok.length} source${ok.length === 1 ? '' : 's'} current` : live.length ? 'logs are old' : 'no logs yet';
    b.title = ok.length ? 'Sources with recent logs (see Network › Overview, “Are my logs current?”)' : '';
  }

  // ------------------------------------------------------------------ actions
  function setPick(k) {
    pick = k; ls.set(LS_PICK, k);
    if (reveal && !PICKS[k].kinds.includes(reveal.sender.kind)) reveal = null;
    paint();
    el.querySelector('.connect-body .connect-step')?.scrollIntoView({ block: 'nearest', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
  }

  el.addEventListener('click', async (e) => {
    if (e.target.closest('[data-fi="reset"]')) {
      if (await saveInbox({ reset: true }, 'Back to the default inbox folder') === true) { paintFiles(); $('.finbox-change summary')?.focus(); }
      return;
    }
    const cp = e.target.closest('[data-copy]');
    if (cp) { e.preventDefault(); try { await navigator.clipboard.writeText(cp.dataset.copy); toast('Copied'); } catch { toast('Copy failed: select the text instead', true); } return; }
    const pk = e.target.closest('[data-pick]');
    if (pk) { setPick(pk.dataset.pick); return; }
    const kd = e.target.closest('[data-kind]');
    if (kd) { sub[pick] = kd.dataset.kind; paint(); return; }
    const pa = e.target.closest('[data-pa="homeonly"]');
    if (pa) { e.stopPropagation(); await put({ host: 'auto' }, 'Uploads now reach your home network only'); return; }
    if (e.target.closest('.connect-drop')) { e.preventDefault(); pickFiles?.(); return; }
    const b = e.target.closest('[data-c]');
    if (!b || b.tagName === 'INPUT') return;
    const a = b.dataset.c;
    if (a === 'pickfiles') pickFiles?.();
    else if (a === 'demo') showDemo?.();
    else if (a === 'advanced') openAdvanced?.();
    else if (a === 'overview') ctx.goto('overview');
    else if (a === 'scan') { b.disabled = true; b.textContent = 'Scanning…'; await scanInbox?.(); b.disabled = false; b.textContent = 'Scan inbox now'; refresh(); }
    else if (a === 'enable') await put({ enabled: true }, null);
    else if (a === 'create') await create();
    else if (a === 'closetoken') {
      if (!confirm('Close the token? It will not be shown again. You can rotate it under Advanced if it is lost.')) return;
      reveal = null; paint();
    }
  });
  el.addEventListener('change', async (e) => {
    if (e.target.dataset.pf === 'urlpick') { urlPick = +e.target.value; paint(); return; }
    if (e.target.dataset.fi === 'delete') {
      const on = e.target.checked;
      if (on && !confirm('Delete each file from the inbox folder once it is safely in Night Desk’s lake? Files that cannot be read move to failed/.')) { e.target.checked = false; return; }
      e.target.disabled = true;
      const ok = await saveInbox({ delete_after_import: on }, on ? 'Files will be deleted after import' : 'Files will be kept after import');
      paintFiles(ok === true ? null : !on);
      $('[data-fi="delete"]')?.focus();
    }
  });
  el.addEventListener('submit', async (e) => {
    if (!e.target.classList.contains('finbox-form')) return;
    e.preventDefault();
    const input = e.target.querySelector('.finbox-input'), err = e.target.querySelector('.finbox-err');
    const btn = e.target.querySelector('[type="submit"]');
    btn.disabled = true;
    let r;
    try {   // checked first (always a 200), so a refused folder shows its reason here without a failed request
      const c = await api.get('/api/netlog/inbox/check', { path: input.value });
      r = c.ok ? await saveInbox({ path: input.value }, 'Inbox folder saved. New files there are imported on the next check.') : new Error(c.error);
    } catch (e2) { r = e2; }
    btn.disabled = false;
    if (r === true) { paintFiles(); $('.finbox-change summary')?.focus(); return; }
    err.textContent = r.message; input.setAttribute('aria-invalid', 'true'); input.focus();
  });
  el.addEventListener('input', (e) => {
    if (!e.target.classList.contains('finbox-input')) return;
    e.target.removeAttribute('aria-invalid');
    const err = e.target.form?.querySelector('.finbox-err');
    if (err) err.textContent = '';
  });

  el.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.dataset.c === 'name') { e.preventDefault(); create(); }
    if ((e.key === 'Enter' || e.key === ' ') && e.target.classList.contains('connect-drop')) { e.preventDefault(); pickFiles?.(); }
  });

  async function put(body, msg) {
    if (busy) return;
    busy = true;
    try {
      ing = await api.put('/api/netlog/ingest', body);
      toast(ing.status.error ? ing.status.error : msg || (ing.status.running ? 'Uploads are on' : 'Could not start the upload port'), !!ing.status.error);
    } catch (err) { toast(err.message, true); }
    busy = false;
    const name = $('[data-c="name"]')?.value;   // a full repaint keeps what was typed
    paint();
    if (name != null && $('[data-c="name"]')) $('[data-c="name"]').value = name;
    onChanged?.();
  }

  async function create() {
    const name = $('[data-c="name"]')?.value.trim();
    if (!name) { toast('Give the device a name', true); return; }
    const btn = $('[data-c="create"]');
    if (btn) btn.disabled = true;
    try {
      reveal = await api.post('/api/netlog/ingest/senders', { name, kind: kindOf(), allow_cidrs: '' });
      made[reveal.sender.kind] = reveal.sender.id; ls.set(LS_MADE, JSON.stringify(made));
      await loadIngest();
      paint(); onChanged?.();
    } catch (err) { toast(err.message, true); if (btn) btn.disabled = false; }
  }

  let onChanged = null;
  async function refresh() {
    const before = fresh?.newest;
    await Promise.all([loadIngest(), loadFresh(), pick === 'files' ? loadInbox() : null]);
    paintStatus();
    if (fresh?.newest && fresh.newest !== before && before !== undefined) onNewData?.();   // a device's logs just landed
  }

  return {
    // push.js calls this with its fresh /api/netlog/ingest data, so both stay in step
    setIngest(d) { ing = d; paintStatus(); },
    onChanged(fn) { onChanged = fn; },
    dataChanged() { loadFresh().then(paintStatus); },
    async show() {
      visible = true;
      const n = paints;
      await Promise.all([loadIngest(), loadFresh(), loadWhere(), loadInbox()]);
      // a pick made while this loaded already drew the page: fill in the fresh numbers and leave what the person
      // opened alone (a slow load used to redraw everything, closing "Change folder" as they typed in it)
      if (paints === n) paint();
      else { paintStatus(); if (!$('.finbox-change')?.open) paintFiles(); }
      clearInterval(timer);
      timer = setInterval(() => { if (visible && pick && !document.hidden) refresh(); }, 4000);
    },
    hide() { visible = false; clearInterval(timer); },
    setPoll(sec) { pollSec = sec; const p = $('.connect-poll'); if (p) p.textContent = sec ? `checked every ${sec}s` : ''; },
  };
}

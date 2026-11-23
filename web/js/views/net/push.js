// Network → Connect logs → Advanced: device uploads. Firewalls and sensors push logs to a separate, token-protected
// upload port. Night Desk never logs in to them. The guided setup (connect.js) reuses KINDS, setupHtml and bindHtml.
// Backend: osinthub/netlog/ingest.py; device script: osinthub/netlog/hlta-push.sh. Reference: okf/data/netlog.md#push-uploads
import { serverWhy } from './alert-text.js';
import { esc, fmt, bytes, dur, toast, loadDevices, emit } from './common.js';
import * as T from '../../core/time.js';
import { ago } from '../../core/util.js';
import { emptyState, errorState } from '../../core/view.js';

// Where each kind of device keeps its logs. Paths differ between versions: the setup text says so.
export const KINDS = {
  zeek: { label: 'Zeek sensor', conf: { HLTA_FILES: '/opt/zeek/logs', HLTA_MATCH: '*.log.gz', HLTA_TAIL: '', HLTA_STATE: '/var/lib/hlta-push' },
    note: 'Sends each finished hourly archive (logs/YYYY-MM-DD/*.log.gz) once. Zeek must write JSON: add <code>@load policy/tuning/json-logs.zeek</code> to local.zeek. If Zeek lives elsewhere (/usr/local/zeek, /nsm/zeek), change HLTA_FILES.' },
  securityonion: { label: 'Security Onion', conf: { HLTA_FILES: '/nsm/zeek/logs', HLTA_MATCH: '*.log.gz', HLTA_TAIL: '', HLTA_STATE: '/var/lib/hlta-push' },
    note: 'Sends Zeek’s finished archives (JSON by default on Security Onion). Check the folder on your sensor with <code>ls /nsm/zeek/logs</code> and adjust HLTA_FILES if it differs.' },
  opnsense: { label: 'OPNsense', conf: { HLTA_FILES: '', HLTA_MATCH: '*.log.gz', HLTA_TAIL: '/var/log/suricata/eve.json', HLTA_STATE: '/var/db/hlta-push' },
    schedule: 'opnsense',
    note: 'Sends new events of the intrusion detection (Services › Intrusion Detection) every 5 minutes. They are written to <code>/var/log/suricata/eve.json</code> while the service is enabled and running on at least one interface: check with <code>ls -l /var/log/suricata/</code>. (“Enable eve syslog output” only copies alerts to syslog; it is not needed.) OPNsense writes root’s crontab itself, so the commands register a backend action and the schedule lives in System › Settings › Cron.' },
  pfsense: { label: 'pfSense', conf: { HLTA_FILES: '', HLTA_MATCH: '*.log.gz', HLTA_TAIL: '/var/log/suricata/suricata_*/eve.json', HLTA_STATE: '/var/db/hlta-push' },
    schedule: 'pfsense',
    note: 'Sends new events from every Suricata interface. Enable “EVE JSON Log” on each interface. Each interface usually logs to its own folder, <code>/var/log/suricata/suricata_&lt;interface&gt;&lt;number&gt;/eve.json</code>: check with <code>ls /var/log/suricata/</code>.' },
  suricata: { label: 'Suricata (Linux)', conf: { HLTA_FILES: '', HLTA_MATCH: '*.log.gz', HLTA_TAIL: '/var/log/suricata/eve.json', HLTA_STATE: '/var/lib/hlta-push' },
    note: 'Sends new eve.json lines every 5 minutes and follows logrotate.' },
  pihole: { label: 'Pi-hole', conf: { HLTA_FILES: '', HLTA_MATCH: '*.log.gz', HLTA_TAIL: '/var/log/pihole/pihole.log', HLTA_STATE: '/var/lib/hlta-push' },
    note: 'Sends new DNS lookups from Pi-hole’s log every 5 minutes and follows its rotation. Pi-hole v6 writes it to <code>/var/log/pihole/pihole.log</code> by default (the <code>files.log.dnsmasq</code> setting); older versions usually use <code>/var/log/pihole.log</code>. Check with <code>ls /var/log/pihole*</code> and change HLTA_TAIL if yours differs. If Pi-hole runs in Docker, use the folder you mounted for its logs.' },
  adguard: { label: 'AdGuard Home', conf: { HLTA_FILES: '', HLTA_MATCH: '*.log.gz', HLTA_TAIL: '/opt/AdGuardHome/data/querylog.json', HLTA_STATE: '/var/lib/hlta-push' },
    note: 'Sends new lines of AdGuard Home’s query log every 5 minutes. The log is usually <code>data/querylog.json</code> in AdGuard Home’s folder (<code>/opt/AdGuardHome</code> for the standard install; the snap uses <code>/var/snap/adguard-home/common/data/</code>). Check with <code>ls</code> and change HLTA_TAIL if yours differs.' },
  custom: { label: 'Other / curl', conf: null,
    note: 'Any tool that can make an HTTPS POST works: send one Zeek JSON or Suricata EVE file per request (plain, .gz, .zip or .tar) with the token in an Authorization header.' },
};

// How the 5-minute run is scheduled. OPNsense regenerates root's crontab, so it gets a configd action (a backend
// command the GUI Cron can run: docs.opnsense.org/development/backend/configd.html, manual/settingsmenu.html#cron);
// pfSense keeps the job in its own settings through the Cron package; everything else uses root's crontab.
function scheduleCmds(kind) {
  if (kind === 'opnsense') return [
    "cat > /usr/local/opnsense/service/conf/actions.d/actions_nightdesk.conf <<'EOF'",
    '[push]', 'command:/usr/local/bin/hlta-push.sh', 'parameters:', 'type:script', 'message:Night Desk log push',
    'description:Night Desk: send logs', 'EOF',
    'service configd restart',
    'configctl nightdesk push',
  ];
  if (kind === 'pfsense') return ['# then add the schedule in Services › Cron (see below)'];
  return [`(crontab -l 2>/dev/null; echo '*/5 * * * * /usr/local/bin/hlta-push.sh') | crontab -`];
}
const SCHEDULE_TEXT = {
  opnsense: '<b>Then schedule it:</b> System › Settings › Cron › <b>+</b>, Minutes <code>*/5</code> (Hours, Day of the month, Months and Days of the week <code>*</code>), Command <b>Night Desk: send logs</b>, Save and Apply. The action file and script live in <code>/usr/local</code>; after a major upgrade check that the job is still listed.',
  pfsense: '<b>Then schedule it:</b> install the <b>Cron</b> package (System › Package Manager), open Services › Cron › Add: Minute <code>*/5</code>, the other time fields <code>*</code>, User <code>root</code>, Command <code>/usr/local/bin/hlta-push.sh</code>, Save. The job is then kept with pfSense’s own settings instead of a hand-edited crontab.',
};

const sh1 = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

export const copyBtn = (text) => `<button class="icon-btn" data-copy="${esc(text)}" title="Copy" aria-label="Copy"><svg class="i" viewBox="0 0 24 24"><rect x="8" y="8" width="11" height="11" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M5 15V6a1 1 0 0 1 1-1h9" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></button>`;
const copyBtnBlock = (text) => `<div class="nv-row nv-pu-cp"><span></span><button class="src-btn" data-copy="${esc(text)}">Copy commands</button></div>`;
const uploadUrl = (data, pick) => { const u = data.status.urls; return u[Math.min(pick, u.length - 1)] || `https://<this-machine>:${data.config.port}`; };

// Who can reach the upload port, in plain words (GET /api/netlog/ingest → bind), with a warning when it listens
// beyond this machine or the home network, and a one-click way back to "home network only".
export function bindHtml(data, { compact = false } = {}) {
  const b = data.bind;
  if (!b) return '';
  const envSet = data.env_overrides.includes('OSINTHUB_INGEST_HOST');
  const fix = b.warn && !b.docker && !envSet ? '<button class="src-btn" data-pa="homeonly">Home network only</button>' : '';
  return `<div class="connect-bind ${b.warn ? 'warn' : ''}">
    <div class="connect-bind-t"><b>${b.docker ? 'Through Docker.' : b.scope === 'lan' ? 'Home network only.' : b.scope === 'loopback' ? 'This machine only.' : 'Beyond your home network.'}</b> ${esc(b.explain)}${compact || b.docker ? '' : ` <span class="nv-dim mono" title="The address the upload port listens on">(${esc(b.bound)})</span>`}</div>
    ${b.warn ? `<div class="nv-warnbox"><span>${esc(b.warn)}</span>${fix}</div>` : ''}
  </div>`;
}

// The one-time token and the per-kind install commands for a new (or rotated) device token.
export function setupHtml(data, { sender, token }, urlPick = 0, { title = true } = {}) {
  const k = KINDS[sender.kind] || KINDS.custom, u = uploadUrl(data, urlPick), pin = data.tls?.pin;
  const tlsOpt = data.config.tls ? `-k --pinnedpubkey ${sh1(pin)} ` : '';
  const curlOne = `curl -fsS ${tlsOpt}-H ${sh1(`Authorization: Bearer ${token}`)} \\\n  -H 'X-HLTA-Name: conn.log.gz' --data-binary @conn.log.gz ${u}/ingest`;
  const urls = data.status.urls.length > 1 ? `<label class="nv-pu-f nv-pu-wide"><span class="label">Address the device should use</span><select class="src-input mono" data-pf="urlpick">${data.status.urls.map((x, i) => `<option value="${i}" ${i === urlPick ? 'selected' : ''}>${esc(x)}</option>`).join('')}</select></label>` : '';
  let steps;
  if (!k.conf) {
    steps = `<div class="label">Send a file</div><pre class="nv-pu-pre">${esc(curlOne)}</pre>${copyBtnBlock(curlOne)}
      <div class="nv-dim nv-pu-small">Replies <code>202</code> with an upload id. Add <code>?wait=1</code> to the address to wait for the import result (<code>200</code> imported, <code>422</code> rejected and why). <code>curl -T file ${esc(u)}/ingest/</code> also works.</div>`;
  } else {
    const conf = { HLTA_URL: u, HLTA_TOKEN_FILE: '/usr/local/etc/hlta-push.token', ...(data.config.tls ? { HLTA_PIN: pin } : {}), ...k.conf, HLTA_NAME: sender.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'device' };
    const confText = Object.entries(conf).map(([a, b]) => `${a}=${sh1(b)}`).join('\n');
    const cmds = [
      '# run as root on the device',
      'mkdir -p /usr/local/etc /usr/local/bin',
      `(umask 077; printf '%s\\n' ${sh1(token)} > /usr/local/etc/hlta-push.token)`,
      `curl -fsS ${tlsOpt}-o /usr/local/bin/hlta-push.sh ${u}/hlta-push.sh && chmod 755 /usr/local/bin/hlta-push.sh`,
      `cat > /usr/local/etc/hlta-push.conf <<'EOF'\n${confText}\nEOF`,
      '/usr/local/bin/hlta-push.sh --check',
      ...scheduleCmds(k.schedule),
    ].join('\n');
    steps = `<pre class="nv-pu-pre">${esc(cmds)}</pre>${copyBtnBlock(cmds)}
      ${SCHEDULE_TEXT[k.schedule] ? `<div class="nv-pu-small connect-sched">${SCHEDULE_TEXT[k.schedule]}</div>` : ''}
      <div class="nv-dim nv-pu-small">${k.note}</div>
      <div class="nv-dim nv-pu-small"><code>--check</code> should print <code>ok</code> with this device’s name. <code>--dry-run</code> lists what would be sent. Its uploads appear within a few seconds.</div>`;
  }
  return `<div class="nv-pu-setup">
    ${title ? `<div class="nv-pu-sh"><b>Set up ${esc(sender.name)}</b><span class="tag">${esc(k.label)}</span><button class="src-btn ghost" data-pa="done">Done</button></div>` : ''}
    <div class="nv-warnbox">This is the only time the token is shown. Night Desk keeps only a hash of it. If it is lost, rotate it.</div>
    <div class="nv-pathbox"><code class="nv-path">${esc(token)}</code>${copyBtn(token)}</div>
    ${urls}
    ${!data.config.enabled ? '<div class="nv-warnbox">Uploads are off. Turn them on before running this on the device.</div>' : ''}
    ${steps}
  </div>`;
}

export function mount(el, ctx, { onImported, onChange } = {}) {
  const { api } = ctx;
  let data = null, visible = false, timer = null, adding = false, reveal = null, urlPick = 0, lastDone = null;
  const $ = (s) => el.querySelector(s);

  // full: redraw everything; otherwise only the badge and the device/upload lists (keeps forms intact)
  async function load(full = true) {
    try {
      data = await api.get('/api/netlog/ingest');
      onChange?.(data);
      if (full || !$('.nv-pu-live')) paint();
      else { $('.nv-pu-live').innerHTML = senders() + uploads(); $('.panel-head .panel-badge').outerHTML = badge(); }
      const done = data.uploads.find((u) => u.status !== 'queued')?.id;
      if (lastDone && done && done !== lastDone) { onImported?.(); loadDevices().then(() => { ctx.refreshSummary(); emit('data'); }); }
      lastDone = done || lastDone;
    } catch (e) { el.innerHTML = errorState({ retry: load, title: "Couldn't read the device uploads", why: serverWhy(e), err: e.message, size: 'sm' }); }
  }

  function badge() {
    const st = data.status, c = data.config;
    if (st.error) return '<span class="panel-badge nv-bad">error</span>';
    if (!c.enabled) return '<span class="panel-badge">off</span>';
    return st.running ? `<span class="panel-badge live">listening :${c.port}</span>` : '<span class="panel-badge">starting…</span>';
  }

  function paint() {
    const c = data.config, st = data.status, tls = data.tls;
    const envHost = data.env_overrides.includes('OSINTHUB_INGEST_HOST');
    const hostOpts = [['auto', 'Home network only'], ['127.0.0.1', 'This machine only'], ['0.0.0.0', 'Every network (0.0.0.0)'], ['custom', 'A specific address…']];
    const pick = hostOpts.some(([v]) => v === c.host) ? c.host : 'custom';
    const env = data.env_overrides.length ? `<div class="nv-dim nv-pu-env">Set by environment: ${data.env_overrides.map((x) => `<code>${esc(x)}</code>`).join(' ')}</div>` : '';
    el.innerHTML = `
      <div class="panel-head"><span class="panel-title">Device uploads</span>${badge()}</div>
      <div class="nv-pad nv-pu">
        <p class="nv-dim">Firewalls and sensors send their logs to Night Desk on a separate upload port. Night Desk never logs in to them. Each device gets its own token, and the port accepts uploads and nothing else: the rest of Night Desk stays private to this machine. Night Desk learns how often each device checks in and raises an alert in Network › Alerts when one goes quiet.</p>
        <div class="nv-pu-cfg">
          <label class="src-toggle"><input type="checkbox" data-pa="enabled" ${c.enabled ? 'checked' : ''}><span class="src-sw"></span>Accept uploads</label>
          <label class="nv-pu-f nv-pu-wide"><span class="label">Who can send</span><select class="src-input" data-pf="hostpick" ${envHost ? 'disabled title="Set by OSINTHUB_INGEST_HOST"' : ''}>
            ${hostOpts.map(([v, l]) => `<option value="${esc(v)}" ${v === pick ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label>
          <label class="nv-pu-f" ${pick === 'custom' ? '' : 'hidden'}><span class="label">Address</span><input class="src-input mono" data-pf="host" value="${esc(c.host === 'auto' ? '' : c.host)}" placeholder="one of this machine’s addresses"></label>
          <label class="nv-pu-f nv-pu-port"><span class="label">Port</span><input class="src-input mono" data-pf="port" value="${esc(c.port)}" inputmode="numeric"></label>
          <label class="nv-pu-f nv-pu-port"><span class="label">Max MB</span><input class="src-input mono" data-pf="max_mb" value="${esc(c.max_mb)}" inputmode="numeric"></label>
          <label class="src-toggle" title="Encrypt uploads with this machine's own certificate. Devices check it by its key pin."><input type="checkbox" data-pa="tls" ${c.tls ? 'checked' : ''}><span class="src-sw"></span>TLS</label>
          <button class="src-btn" data-pa="savecfg" disabled>Apply</button>
        </div>
        ${env}
        ${bindHtml(data)}
        ${st.error ? `<div class="nv-warnbox nv-bad">${esc(st.error)}</div>` : ''}
        ${!c.tls ? '<div class="nv-warnbox">TLS is off: tokens and logs cross your network unencrypted. Only use this on a cable between two machines you trust.</div>' : ''}
        ${c.enabled && st.running ? `
        <div class="nv-pu-grid">
          <div><span class="label">Upload address</span>${st.urls.length ? st.urls.map((u, i) => `<div class="nv-pathbox"><code class="nv-path">${esc(u)}/ingest</code>${copyBtn(`${u}/ingest`)}</div>`).join('') : '<div class="nv-dim">No network address found.</div>'}</div>
          ${tls && !tls.error ? `<div><span class="label">Certificate key pin</span><div class="nv-pathbox"><code class="nv-path">${esc(tls.pin)}</code>${copyBtn(tls.pin)}</div>
            <div class="nv-dim nv-pu-small">${tls.source === 'provided' ? 'Your certificate (OSINTHUB_INGEST_CERT).' : 'Self-signed by Night Desk'} · expires ${esc(T.date(tls.not_after))} · <a href="api/netlog/ingest/cert" download>download certificate</a>${tls.source === 'self-signed' ? ' · <button class="nv-link" data-pa="regen">make a new one</button>' : ''}</div></div>` : tls?.error ? `<div class="nv-warnbox nv-bad">${esc(tls.error)}</div>` : ''}
        </div>
        <div class="nv-dim nv-pu-small">macOS may ask whether Python may accept incoming connections: allow it, or devices will time out.</div>` : ''}
        <div class="nv-pu-sh"><span class="label">Devices</span><button class="src-btn" data-pa="add">+ Add device</button></div>
        ${adding ? addForm() : ''}
        ${reveal ? setup(reveal) : ''}
        <div class="nv-pu-live">${senders()}${uploads()}</div>
      </div>`;
    if (adding) $('[data-pf="name"]')?.focus();
  }

  function addForm() {
    return `<div class="nv-pu-add">
      <label class="nv-pu-f"><span class="label">Name</span><input class="src-input" data-pf="name" placeholder="Garage firewall" maxlength="60"></label>
      <label class="nv-pu-f"><span class="label">Type</span><select class="src-input" data-pf="kind">${Object.entries(KINDS).map(([k, v]) => `<option value="${k}">${esc(v.label)}</option>`).join('')}</select></label>
      <label class="nv-pu-f nv-pu-wide"><span class="label">Only from (optional)</span><input class="src-input mono" data-pf="allow" placeholder="the device's address, e.g. 192.0.2.1"></label>
      <div class="nv-row"><span class="nv-dim">The token is shown once, right after you create it.</span><button class="src-btn ghost" data-pa="cancel">Cancel</button><button class="src-btn primary" data-pa="create">Create token</button></div>
    </div>`;
  }

  const setup = (r) => setupHtml(data, r, urlPick);

  function senders() {
    const ss = data.senders;
    if (!ss.length) return emptyState({ why: 'No devices yet. Add one to get its token and setup commands.', size: 'inline' });
    return `<table class="nv-ft nv-pu-t"><thead><tr><th>Device</th><th>Last check-in</th><th>Cadence</th><th class="r">Files</th><th class="r">New rows</th><th>Status</th><th></th></tr></thead><tbody>
      ${ss.map((s) => `<tr class="${s.last_status === 'error' || s.health?.state === 'silent' ? 'bad' : ''}">
        <td><b>${esc(s.name)}</b> <span class="nv-dim mono">${esc((KINDS[s.kind] || KINDS.custom).label)} · …${esc(s.token_hint)}</span>${s.allow_cidrs?.length ? `<div class="nv-dim mono nv-pu-small">only from ${esc(s.allow_cidrs.join(', '))}</div>` : ''}</td>
        <td class="mono nv-dim" title="${esc(s.last_ip || '')}">${s.last_seen ? `${ago(s.last_seen)}${s.last_ip ? ` · ${esc(s.last_ip)}` : ''}` : 'never'}${healthLine(s)}</td>
        <td class="mono nv-dim">${cadenceCell(s)}</td>
        <td class="r mono">${fmt(s.uploads || 0)}</td><td class="r mono">${fmt(s.rows || 0)}</td>
        <td class="mono">${s.paused ? '<span class="nv-warn">paused</span>' : s.last_status === 'error' ? `<span class="nv-bad" title="${esc(s.last_error || '')}">${esc((s.last_error || 'error').replace(/^\w+Error: /, '').slice(0, 48))}</span>` : s.last_status ? '<span class="nv-okc">ok</span>' : '<span class="nv-dim">waiting</span>'}</td>
        <td class="r nv-pu-acts"><button class="nv-link" data-sp="${esc(s.id)}">${s.paused ? 'resume' : 'pause'}</button><button class="nv-link" data-sr="${esc(s.id)}">rotate</button><button class="nv-link nv-bad" data-sd="${esc(s.id)}">remove</button></td></tr>`).join('')}
    </tbody></table>`;
  }

  // Silence alerts (ingest.py): the learned cadence and when an alert would open.
  function healthLine(s) {
    const h = s.health || {};
    if (h.state === 'silent') return `<div class="nv-pu-health silent">silent for ${dur(h.silent_s * 1000)} · alert open</div>`;
    if (h.state === 'late') return `<div class="nv-pu-health late">late · expected ${ago(new Date(h.due_at * 1000))}</div>`;
    return '';
  }
  function cadenceCell(s) {
    const h = s.health || {};
    const cad = h.cadence_s ? `every ${dur(h.cadence_s * 1000)}` : h.state === 'waiting' ? '—' : `learning (${h.cadence_n || 0}/3 runs)`;
    const al = s.alert_after_min === 0 ? 'alerts off' : h.threshold_s ? `alert after ${dur(h.threshold_s * 1000)}${h.threshold_from === 'set' ? ' (set)' : ''}` : 'alerts once learned';
    return `${cad}<div class="nv-pu-small"><button class="nv-link" data-sa="${esc(s.id)}" title="When to alert if this device stops sending">${al}</button></div>`;
  }

  function uploads() {
    const us = data.uploads.slice(0, 12), st = data.status;
    const q = st.pending ? ` · ${st.pending} waiting to import` : '';
    const f = st.failed ? ` · <span class="nv-bad">${st.failed} rejected</span> <button class="nv-link" data-pa="retry">retry</button>` : '';
    if (!us.length && !q && !f) return '';
    return `<div class="nv-pu-sh"><span class="label">Recent uploads</span><span class="nv-dim mono nv-pu-small">since Night Desk started${q}${f}</span></div>
      <div class="nv-pu-ups">${us.map((u) => `<div class="nv-pu-up ${esc(u.status)}"><span class="mono nv-dim">${ago(u.received_at)}</span><b>${esc(u.sender_name)}</b><span class="mono nv-fn" title="${esc(u.name)}">${esc(u.name)}</span><span class="mono nv-dim">${bytes(u.bytes)}</span>
        <span class="mono">${u.status === 'queued' ? 'importing…' : u.status === 'error' ? `<span class="nv-bad" title="${esc(u.error || '')}">${esc((u.error || '').replace(/^\w+Error: /, '').slice(0, 40))}</span>` : u.duplicate ? '<span class="nv-dim">already had it</span>' : `<span class="nv-okc">+${fmt(u.inserted)} rows</span>${u.matches ? ` <span class="tag red">${u.matches} matches</span>` : ''}`}</span></div>`).join('')}</div>`;
  }

  // ---------------------------------------------------------------- actions
  const cfgInputs = () => [...el.querySelectorAll('[data-pf="host"],[data-pf="port"],[data-pf="max_mb"]')];
  // the host to save: the picked choice, or the typed address for "A specific address…"
  function cfgValues() {
    const v = Object.fromEntries(cfgInputs().map((i) => [i.dataset.pf, i.value.trim()]));
    const hp = $('[data-pf="hostpick"]');
    if (!hp || hp.disabled) delete v.host;
    else if (hp.value !== 'custom') v.host = hp.value;
    return v;
  }
  el.addEventListener('input', (e) => {
    if (cfgInputs().includes(e.target)) $('[data-pa="savecfg"]').disabled = false;
  });
  el.addEventListener('change', async (e) => {
    const a = e.target.dataset.pa;
    if (a === 'enabled' || a === 'tls') {
      try { data = await api.put('/api/netlog/ingest', { [a]: e.target.checked }); paint(); onChange?.(data); toast(a === 'enabled' ? (e.target.checked ? (data.status.running ? 'Accepting uploads' : 'Could not start the upload port') : 'Uploads turned off') : 'Saved'); }
      catch (err) { toast(err.message, true); load(); }
    }
    if (e.target.dataset.pf === 'urlpick') { urlPick = +e.target.value; paint(); }
    if (e.target.dataset.pf === 'hostpick') {
      const custom = e.target.value === 'custom', f = $('[data-pf="host"]');
      f.closest('label').hidden = !custom;
      if (custom) f.focus();
      $('[data-pa="savecfg"]').disabled = false;
    }
  });
  el.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.dataset.pf === 'name') { e.preventDefault(); el.querySelector('[data-pa="create"]').click(); }
    if (e.key === 'Enter' && cfgInputs().includes(e.target)) { e.preventDefault(); el.querySelector('[data-pa="savecfg"]').click(); }
  });
  el.addEventListener('click', async (e) => {
    const cp = e.target.closest('[data-copy]');
    if (cp) { e.preventDefault(); try { await navigator.clipboard.writeText(cp.dataset.copy); toast('Copied'); } catch { toast('Copy failed: select the text instead', true); } return; }
    const b = e.target.closest('[data-pa],[data-sp],[data-sr],[data-sd],[data-sa]');
    if (!b) return;
    const a = b.dataset.pa;
    try {
      if (a === 'savecfg') {
        data = await api.put('/api/netlog/ingest', cfgValues()); paint(); toast(data.status.error ? data.status.error : 'Saved');
        onChange?.(data);
      } else if (a === 'homeonly') {
        data = await api.put('/api/netlog/ingest', { host: 'auto' }); paint(); toast(data.status.error ? data.status.error : 'Uploads now reach your home network only');
        onChange?.(data);
      } else if (a === 'add') { adding = true; reveal = null; paint(); }
      else if (a === 'cancel') { adding = false; paint(); }
      else if (a === 'create') {
        const name = $('[data-pf="name"]').value.trim();
        if (!name) { toast('Give the device a name', true); return; }
        const r = await api.post('/api/netlog/ingest/senders', { name, kind: $('[data-pf="kind"]').value, allow_cidrs: $('[data-pf="allow"]').value });
        adding = false; reveal = r; await load();
      } else if (a === 'done') {
        if (!confirm('Close the setup? The token will not be shown again.')) return;
        reveal = null; paint();
      } else if (a === 'regen') {
        if (!confirm('Make a new certificate? Every device must be given the new pin (HLTA_PIN) before its next upload.')) return;
        data = await api.post('/api/netlog/ingest/cert/regenerate'); paint(); toast('New certificate. Update HLTA_PIN on your devices.');
      } else if (a === 'retry') {
        const r = await api.post('/api/netlog/ingest/retry-failed'); toast(`Retrying ${r.requeued} upload${r.requeued === 1 ? '' : 's'}`); setTimeout(load, 1500);
      } else if (b.dataset.sp) {
        const s = data.senders.find((x) => x.id === b.dataset.sp);
        await api.patch(`/api/netlog/ingest/senders/${s.id}`, { paused: !s.paused }); toast(s.paused ? `${s.name} resumed` : `${s.name} paused: its uploads are refused`); load();
      } else if (b.dataset.sa) {
        const s = data.senders.find((x) => x.id === b.dataset.sa);
        const cur = s.alert_after_min == null ? '' : String(s.alert_after_min);
        const v = prompt(`Alert when ${s.name} has not checked in for how many minutes?\n\nLeave empty to learn it from the device's usual cadence (recommended). 0 turns these alerts off.`, cur);
        if (v === null) return;
        await api.patch(`/api/netlog/ingest/senders/${s.id}`, { alert_after_min: v.trim() === '' ? null : v.trim() });
        toast(v.trim() === '' ? 'Learning the cadence automatically' : v.trim() === '0' ? `Silence alerts off for ${s.name}` : `Alert after ${v.trim()} min of silence`);
        load();
      } else if (b.dataset.sr) {
        const s = data.senders.find((x) => x.id === b.dataset.sr);
        if (!confirm(`Rotate the token for ${s.name}? The old token stops working now; put the new one in /usr/local/etc/hlta-push.token on the device.`)) return;
        reveal = await api.post(`/api/netlog/ingest/senders/${s.id}/rotate`); await load();
      } else if (b.dataset.sd) {
        const s = data.senders.find((x) => x.id === b.dataset.sd);
        if (!confirm(`Remove ${s.name}? Its token stops working now. Logs it already sent stay.`)) return;
        await api.del(`/api/netlog/ingest/senders/${s.id}`); if (reveal?.sender.id === s.id) reveal = null; toast(`${s.name} removed`); load();
      }
    } catch (err) { toast(err.message, true); }
  });

  return {
    reload: () => load(),
    show() { visible = true; load(); clearInterval(timer); timer = setInterval(() => { if (visible) load(!adding && !reveal && !el.contains(document.activeElement)); }, 5000); },
    hide() { visible = false; clearInterval(timer); },
  };
}

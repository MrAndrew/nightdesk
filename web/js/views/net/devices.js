// Network → Devices: list and detail. Names, types, owners and notes are the user's (PATCH /api/netlog/devices/{id});
// "Merge into…" joins two records of one machine (POST /devices/merge, undo /devices/unmerge). okf/data/netlog.md#devices
import { S, SEVTAG, CONF, DEV_TYPES, onChange, emit, loadDevices, v, bytes, ts, tsShort, esc, fmt, compact, barList, ruleLabel,
  typeIcon, typeLabel, toast, Z, tierChip, escCloses } from './common.js';
import { srcName, serverWhy } from './alert-text.js';
import * as T from '../../core/time.js';
import { withRange } from '../../core/range.js';
import { ago, chartTheme, debounce } from '../../core/util.js';
import { PAL, SEV as SEVCOL } from '../../core/util.js';   // the shared palette and the one severity map
import { emptyState, errorState, loadingState, stateAct } from '../../core/view.js';
import { deviceSplit } from '../../core/alerts-badge.js';
import { need } from '../../core/libs.js';
import { isPhone, copyText } from './m.js';
import * as MD from './m-devices.js';
import { actionSheet } from '../../core/sheet.js';
import { setPhoneTitle, setActionBar, afterRender, entryState, setEntryState, pushPage } from '../../core/page.js';

// Device stat tiles: a value wraps only between its parts ("21 Nov" / "02:28", "780 KB /" / "32 MB"), never inside a
// date, a time or a size, so a narrow detail pane (1024 px) shows it in full instead of cutting or splitting it.
const nb = (x) => `<span class="nv-nb">${esc(x)}</span>`;
const tileTime = (t) => (t ? `${nb(T.date(t))} ${nb(T.time(t))}` : '—');

const SORTS = [['alerts', 'Alerts'], ['bytes', 'Traffic'], ['last_seen', 'Last seen'], ['rows', 'Rows']];
const HOW = { dhcp: 'DHCP lease', l2: 'hardware address seen in the connection log', eui64: 'IPv6 address built from its hardware address', behaviour: 'what it looked up (names) matched', merged: 'merged by you' };
const SRC = { you: 'Named by you', device: 'Name the device gave itself', fallback: 'No readable name in the logs' };

// One line under a device's name: owner, then what kind of thing it is, then the identity it rests on.
function subLine(d) {
  const bits = [];
  if (d.owner) bits.push(d.owner);
  if (d.type) bits.push(typeLabel(d));
  if (d.name_source === 'you' && d.naming?.name) bits.push(`seen as ${d.naming.name}`);
  bits.push(d.mac || (d.identity === 'ip' ? 'address only, no MAC' : ''));
  return bits.filter(Boolean).join(' · ');
}

function typeOptions(cur) {
  return `<option value="">Not set</option>${Object.entries(DEV_TYPES).map(([k, [l]]) => `<option value="${k}" ${cur === k ? 'selected' : ''}>${esc(l)}</option>`).join('')}`;
}

// The edit form: inline in the list (compact) or in the device page (with the note and icon picker).
function editForm(d, full = false) {
  const lab = d.label || {};
  const type = lab.type || '';
  return `<form class="devices-form ${full ? 'devices-form-full' : ''}" data-edit="${esc(d.id)}" autocomplete="off">
    <label><span class="label">Name</span><input name="name" maxlength="60" value="${esc(lab.name || '')}" placeholder="${esc(d.naming?.name || 'e.g. Kids’ iPad')}"></label>
    ${full ? `<div class="devices-types" role="radiogroup" aria-label="Type">${Object.entries(DEV_TYPES).map(([k, [l]]) => `
      <button type="button" role="radio" aria-checked="${type === k}" data-type="${k}" class="devices-tbtn ${type === k ? 'on' : ''}" title="${esc(l)}">${typeIcon(k)}<span>${esc(l)}</span></button>`).join('')}
      <input type="hidden" name="type" value="${esc(type)}"></div>`
    : `<label><span class="label">Type</span><select name="type">${typeOptions(type)}</select></label>`}
    <label><span class="label">Owner or room <em>optional</em></span><input name="owner" maxlength="60" value="${esc(lab.owner || '')}" placeholder="e.g. Sam, or living room"></label>
    ${full ? `<label class="devices-note"><span class="label">Note <em>optional</em></span><textarea name="note" maxlength="280" rows="2">${esc(lab.note || '')}</textarea></label>` : ''}
    <div class="devices-form-act"><button class="src-btn primary" type="submit">Save</button><button class="src-btn" type="button" data-act="cancel">Cancel</button>
      ${d.label ? '<button class="src-btn devices-clear" type="button" data-act="clear" title="Go back to the name found in the logs">Clear my labels</button>' : ''}</div>
  </form>`;
}

export function mount(el, ctx) {
  const { api } = ctx;
  const st = { only: 'all', shown: MD.PAGE, open: new Map(), sort: 'alerts', q: '', rows: [], sel: null, visible: false, stale: true, editing: null, detail: null, mode: null, focus: false, auto: false, routed: false };
  let chart = null;
  el.innerHTML = `
    <div class="nv-dv">
      <div class="nv-dv-list">
        <div class="nv-bar">
          <div class="nv-seg" data-k="sort"><span class="nv-seg-l mono">sort</span>${SORTS.map(([k, l]) => `<button data-v="${k}">${l}</button>`).join('')}</div>
          <label class="nv-in"><svg class="i"><use href="#i-search"/></svg><input placeholder="Name, owner, IP or MAC…" aria-label="Find a device"></label>
          <span class="nv-total mono"></span>
        </div>
        <div class="nv-dl"></div>
      </div>
      <aside class="nv-dv-side"><div class="nv-dd"></div></aside>
    </div>`;
  const $ = (s) => el.querySelector(s);
  const side = $('.nv-dv-side');
  // a closed detail is inert: out of the Tab order and the accessibility tree, not just 0 px wide (B2-06)
  const sideOpen = (on) => { el.classList.toggle('has-detail', on); side.inert = !on; };
  sideOpen(false);

  async function load() {
    st.stale = false;
    el.querySelectorAll('[data-k="sort"] button').forEach((b) => b.classList.toggle('on', b.dataset.v === st.sort));
    try {
      const [rows, inc] = await Promise.all([api.get('/api/netlog/devices', { sort: st.sort, q: st.q || undefined, limit: 1000 }),
        // a phone row's "1 alert" tag: open (new) high and medium incidents per device, demo ones included
        isPhone() ? api.get('/api/netlog/incidents', { status: 'new', severity: 'high,medium', limit: 1000 }).catch(() => []) : null]);
      st.rows = rows;
      if (inc) {
        st.open = new Map();
        for (const a of inc) { if (!a.device) continue; const o = st.open.get(a.device) || { n: 0, real: false }; o.n++; if (!a.demo) o.real = true; st.open.set(a.device, o); }
      }
      if (!st.q) loadDevices();
      // logs still arriving can leave the Network header's count a step behind this list: re-read it, so the header,
      // the Devices tab and this list agree
      if (!st.q && S.summary && st.rows.length !== S.summary.devices) ctx.refreshSummary?.();
      render();
      if (!st.q) checkGone();
    } catch (e) { $('.nv-dl').innerHTML = errorState({ retry: load, title: "Couldn't load your devices", why: serverWhy(e), err: e.message, size: 'sm' }); }
  }

  function row(d, maxB) {
    const c = CONF[d.confidence] || ['', ''];
    const edit = st.editing === d.id;
    // The row is not a role=button (it holds the rename button): its name is the one control that opens it, and a tap
    // anywhere else on the row (addresses included: plain text, not an IP chip) opens it too (S2-15)
    return `<div class="nv-tr nv-drow ${st.sel === d.id ? 'sel' : ''}" data-id="${esc(d.id)}"${st.sel === d.id ? ' aria-current="true"' : ''}>
        <span class="nv-bell" style="background:${d.max_severity && d.alerts ? SEVCOL[d.max_severity] : 'var(--line-2)'}"></span>
        <span class="nv-dn devices-dn"><span class="devices-ic" title="${esc(typeLabel(d))}">${typeIcon(d.type)}</span>
          <button type="button" class="devices-nm fnet-open" data-open title="Open ${esc(d.name)}"><b class="${d.name_source === 'fallback' ? 'devices-unnamed' : ''}" data-nochips>${esc(d.name)}</b><em class="mono">${esc(subLine(d))}</em></button>
          <button class="icon-btn devices-pen" data-act="edit" title="Rename or set type" aria-label="Rename ${esc(d.name)}"><svg viewBox="0 0 16 16" class="devices-ico" aria-hidden="true"><path d="M10.5 2.5l3 3L6 13H3v-3z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/></svg></button></span>
        <span class="mono nv-dim nv-ips" data-nochips>${esc((d.ips || []).slice(0, 2).join(', '))}${d.ips?.length > 2 ? ` +${d.ips.length - 2}` : ''}</span>
        <span><span class="tag ${c[0]}" title="${esc(c[1])}">${esc(d.confidence)}</span></span>
        <span class="mono nv-dim" title="first ${ts(d.first_seen)} · last ${ts(d.last_seen)} ${Z()}">${ago(d.last_seen)}</span>
        <span class="r mono nv-trf"><i style="width:${(100 * (d.bytes_in + d.bytes_out) / maxB).toFixed(1)}%"></i>${bytes(d.bytes_in + d.bytes_out)}</span>
        <span class="r mono">${d.alerts_high_medium ? `<span class="tag ${SEVTAG[d.max_severity]}" title="Need you (high and medium)${d.alerts > d.alerts_high_medium ? `; ${d.alerts - d.alerts_high_medium} low not counted` : ''}">${d.alerts_high_medium}</span>` : d.alerts ? `<span class="nv-dim" title="Low only: not counted as needing you">${d.alerts} low</span>` : '<span class="nv-dim">—</span>'}</span>
      </div>${edit ? `<div class="devices-inline">${editForm(d)}</div>` : ''}`;
  }

  function render() {
    if (isPhone()) { renderPhone(); return; }
    el.querySelector('.nv-m-dvhead')?.remove();
    // Low-evidence fragments (IPv6 privacy addresses with nothing to name them) fold away, unless they have alerts.
    const main = st.rows.filter((d) => !d.fragment || d.alerts);
    const frag = st.rows.filter((d) => d.fragment && !d.alerts);
    // the same total as the Network header and the Devices tab (core/alerts-badge.js deviceSplit), then its split
    const sp = deviceSplit(st.rows);
    $('.nv-total').textContent = st.q ? `${fmt(st.rows.length)} match${st.rows.length === 1 ? '' : 'es'}`
      : `${fmt(sp.total)} device${sp.total === 1 ? '' : 's'}${sp.unid ? `: ${fmt(sp.known)} known · ${fmt(sp.unid)} unidentified` : ''}`;
    if (!st.rows.length) { $('.nv-dl').innerHTML = st.q ? emptyState({ title: 'No device matches', why: 'Try part of a name, an address or a MAC.' })
      : emptyState({ title: 'No devices yet', why: 'Devices appear after the first import, identified from DHCP, layer-2 addresses and IPv6 behaviour.', act: stateAct('Connect logs', { href: '#network/import' }) }); return; }
    const maxB = Math.max(...st.rows.map((d) => d.bytes_in + d.bytes_out), 1);
    const open = $('.devices-unid')?.open || (st.sel && frag.some((d) => d.id === st.sel)) || !!st.q;
    $('.nv-dl').innerHTML = `<div class="nv-tbl nv-dt">
      <div class="nv-th"><span></span><span>Device</span><span>Addresses</span><span>Identity</span><span>Seen</span><span class="r">Traffic</span><span class="r">Alerts</span></div>
      ${main.map((d) => row(d, maxB)).join('')}</div>
      ${frag.length ? `<details class="devices-unid" ${open ? 'open' : ''}><summary><b>Unidentified (${fmt(frag.length)})</b>
        <span>Addresses with no hardware address or name in the logs: short-lived IPv6 addresses (usually a phone or laptop that rotates its address for privacy) and addresses that never sent or received any data. Open one and use “Merge into…” when you know which device it is.</span></summary>
        <div class="nv-tbl nv-dt">${frag.map((d) => row(d, maxB)).join('')}</div></details>` : ''}`;
    wireForms($('.nv-dl'));
    el.querySelector('.devices-inline input[name="name"]')?.focus();
  }

  // Save / cancel / clear on any edit form (list or detail).
  function wireForms(root) {
    root.querySelectorAll('form[data-edit]').forEach((f) => {
      const id = f.dataset.edit;
      f.querySelectorAll('[data-type]').forEach((b) => (b.onclick = () => {
        const on = !b.classList.contains('on');
        f.querySelectorAll('[data-type]').forEach((x) => { x.classList.remove('on'); x.setAttribute('aria-checked', 'false'); });
        if (on) { b.classList.add('on'); b.setAttribute('aria-checked', 'true'); }
        f.elements.type.value = on ? b.dataset.type : '';
      }));
      f.onsubmit = (e) => {
        e.preventDefault();
        const body = { name: f.elements.name.value, type: f.elements.type.value || null, owner: f.elements.owner.value };
        if (f.elements.note) body.note = f.elements.note.value;
        save(id, body);
      };
      f.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.stopPropagation(); cancel(); } });
      f.querySelector('[data-act="cancel"]').onclick = cancel;
      f.querySelector('[data-act="clear"]')?.addEventListener('click', () => save(id, { name: null, type: null, owner: null, note: null }));
    });
  }
  function cancel() {
    if (st.editing) { st.editing = null; render(); }
    if (st.mode) { st.mode = null; if (st.detail) renderDetail(st.detail); }
  }

  async function save(id, body) {
    try {
      const d = await api.patch(`/api/netlog/devices/${encodeURIComponent(id)}`, body);
      st.editing = null; st.mode = null;
      const i = st.rows.findIndex((r) => r.id === id);
      if (i >= 0) st.rows[i] = { ...st.rows[i], ...pick(d) };
      if (S.devices.has(id)) S.devices.set(id, { ...S.devices.get(id), ...pick(d) });
      render();
      if (st.sel === id) renderDetail(d);
      toast(`Saved · ${d.name}`);
      emit('devices');
      return true;
    } catch (e) { toast(e.message, true); return false; }
  }
  const pick = (d) => ({ name: d.name, name_source: d.name_source, type: d.type, type_source: d.type_source, owner: d.owner, note: d.note, label: d.label, fragment: d.fragment });

  // ------------------------------------------------------------ the route: #network/devices/<id> (like an alert's)
  // Opening a device adds a history entry (Back closes it, Forward reopens it); moving from one device to the next
  // replaces it. The ?range= the Network header keeps is carried along (core/range.js).
  const hashDev = () => { const t = location.hash.slice(1).split('?')[0].split('/'); return t[0] === 'network' && t[1] === 'devices' && t[2] ? decodeURIComponent(t.slice(2).join('/')) : null; };
  function setHash(id, mode = 'push') {
    if (!document.body.classList.contains('nv-active')) return;
    const q = location.hash.includes('?') ? location.hash.slice(location.hash.indexOf('?')) : '';
    const h = withRange((id ? `#network/devices/${encodeURIComponent(id)}` : '#network/devices') + q, S.range);
    if (location.hash === h) return;
    // a push from the list marks its entry (history.state.ndFromList): closing goes back to that list entry, so Back
    // never reopens a closed device; a device from a link or a reload has its entry replaced by the list instead
    if (mode === 'push' && !hashDev() && isPhone()) { pushPage(h); return; }   // a phone: a page of its own (core/page.js)
    if (mode === 'push' && !hashDev()) history.pushState({ ndFromList: 'devices', from: location.hash }, '', h);
    else history.replaceState(id ? history.state : null, '', h);
  }
  const markSel = (id) => el.querySelectorAll('.nv-drow').forEach((r) => { const on = r.dataset.id === id; r.classList.toggle('sel', on); if (on) r.setAttribute('aria-current', 'true'); else r.removeAttribute('aria-current'); });
  // Close the detail. nav: drop the id from the URL (a Back already did); refocus: back to the device's row (Esc, Close).
  function close(nav = true, refocus = false) {
    const was = st.sel;
    st.sel = null; st.mode = null; st.detail = null; st.focus = false;
    chart?.dispose(); chart = null;
    sideOpen(false);
    markSel(null);
    // back only onto the list as it is now (same ?range): otherwise replace this entry with the current list URL
    if (nav && hashDev()) {
      const q = location.hash.includes('?') ? location.hash.slice(location.hash.indexOf('?')) : '';
      const want = withRange('#network/devices' + q, S.range);
      if (history.state?.ndFromList === 'devices' && history.state.from === want) history.back();
      else history.replaceState(null, '', want);
    }
    if (isPhone()) { if (refocus) el.querySelector(was ? `.nv-m-drow[data-id="${CSS.escape(was)}"] .nv-m-dmain` : '.nv-m-dmain')?.focus({ preventScroll: true }); afterRender('network'); return; }
    if (refocus) (el.querySelector(was ? `.nv-drow[data-id="${CSS.escape(was)}"] [data-open]` : null) || el.querySelector('.nv-drow [data-open]'))?.focus();
  }
  // Opened by click, Enter or a link: focus goes to the device's name, which a screen reader reads out.
  function focusDetail() {
    if (!st.focus) return;
    st.focus = false;
    (el.querySelector('.nv-dd h2') || el.querySelector('.nv-dd [data-act="close"]'))?.focus({ preventScroll: true });
  }

  async function select(id, nav = false, focus = false) {
    st.sel = id; st.mode = null; st.focus = focus;
    if (nav) setHash(id, nav);
    st.routed = hashDev() === id;   // the wide-screen preview is not in the URL, so a Back does not close it
    markSel(id);
    sideOpen(true);
    const box = $('.nv-dd');
    box.innerHTML = loadingState('Loading device…', { size: 'sm' });
    try {
      const d = await api.get(`/api/netlog/devices/${encodeURIComponent(id)}`);
      if (st.sel !== id) return;
      if (d.id !== id) { st.sel = d.id; markSel(d.id); if (hashDev() === id) setHash(d.id, 'replace'); }
      renderDetail(d);
      focusDetail();
    } catch (e) {
      if (st.sel !== id) return;
      st.detail = null;
      // a dead link (merged away, its logs or the demo removed) can never load: no "Try again" for it (B2-11)
      const gone = e.status === 404 || /not found|no such/i.test(e.message);
      box.innerHTML = `<div class="nv-dh"><button class="icon-btn nv-back" data-act="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button></div>${gone ? goneHtml()
        : errorState({ retry: () => select(id), title: "Couldn't load this device", why: serverWhy(e), err: e.message, size: 'sm' })}`;
      box.querySelector('[data-act="close"]').onclick = () => close(true, true);
      focusDetail();
    }
  }

  const goneHtml = () => emptyState({ title: 'This device is no longer in your logs', why: 'Its logs or the demo data were removed, or it was merged into another device.', size: 'sm' });
  // The open device may have gone since it was opened (the demo removed from another tab): when the list reloads
  // without it, ask the server; a 404 turns the detail into "no longer in your logs" (B2-05)
  function checkGone() {
    const d = st.detail; if (!d || st.rows.some((r) => r.id === d.id)) return;
    // the list just read is every device (no search, up to 1000): not in it means gone; past 1000, ask the server
    (st.rows.length < 1000 ? Promise.reject({ status: 404 }) : api.get(`/api/netlog/devices/${encodeURIComponent(d.id)}`)).catch((e) => {
      if (e.status !== 404 || st.detail !== d) return;
      st.detail = null; st.mode = null; chart?.dispose(); chart = null;
      const box = $('.nv-dd');
      box.innerHTML = `<div class="nv-dh"><button class="icon-btn nv-back" data-act="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button></div>${goneHtml()}`;
      box.querySelector('[data-act="close"]').onclick = () => close(true, true);
    });
  }

  function timelineList(d) {
    const evs = d.events || [];
    if (!evs.length) return '<div class="nv-calm">Nothing recorded yet.</div>';
    const shown = evs.slice(0, 30);
    return `<ol class="devices-tl">${shown.map((e) => `
      <li class="devices-tl-${esc(e.kind)}" ${e.alert ? `data-alert="${esc(e.alert)}" tabindex="0"` : ''}>
        <span class="devices-tl-dot" style="${e.kind === 'alert' ? `background:${SEVCOL[e.severity]}` : ''}"></span>
        <span class="devices-tl-t mono" title="${ts(e.t)} ${Z()}">${tsShort(e.t)}</span>
        <span class="devices-tl-x">${e.kind === 'alert' ? `<b>${esc(e.severity)}</b> ${esc(String(e.text || '').replace(/\bDEMO Night Desk\s+/g, ''))} <span class="nv-dim">${esc(ruleLabel(e.rule))} · ${esc(e.status)}</span>` : esc(e.text)}</span>
      </li>`).join('')}</ol>${evs.length > shown.length ? `<div class="nv-dim mono">${fmt(evs.length - shown.length)} older events not shown</div>` : ''}`;
  }

  function namesSection(d) {
    const nm = d.naming || {};
    const readable = nm.names || [];
    const junk = nm.junk || [];
    return `<section class="nv-sec devices-names"><div class="label">Names and evidence</div>
      <p><b>${esc(SRC[d.name_source] || '')}</b>${d.name_source === 'device' && nm.why === 'shared' ? ' (other devices use it too, so a short id is added)' : ''}${d.name_source === 'fallback' ? `: shown as “Unnamed device”${nm.hint ? ` with a hint (${esc(nm.hint)})` : ''} and the end of its ${d.identity === 'mac' ? 'hardware address' : 'address'}.` : '.'}</p>
      ${d.type ? `<p class="nv-dim">Type: ${esc(typeLabel(d))}${d.type_source === 'guess' ? ', from its names and the services it announces' : ''}.</p>` : ''}
      ${readable.length ? `<div class="nv-chips">${readable.map((h) => `<span class="tag">${esc(h)}</span>`).join('')}</div>` : ''}
      ${junk.length || (nm.services || []).length ? `<details class="devices-raw"><summary>Raw names found in the logs (${fmt((d.hostnames || []).length)})</summary>
        <p class="nv-dim">Service announcements, random ids and reverse-DNS names say little about which device this is, so they are not used as its name.</p>
        <div class="devices-rawlist mono">${(d.hostnames || []).map((h) => `<div>${v('q', h)}</div>`).join('')}</div>
        ${(nm.services || []).length ? `<p class="nv-dim">Services it announces: <span class="mono">${nm.services.map(esc).join(', ')}</span></p>` : ''}</details>` : ''}
    </section>`;
  }

  function mergeBox(d) {
    const sim = (d.similar || []).filter((s) => s.id !== d.id);
    return `<section class="nv-sec devices-merge"><div class="label">Merge into…</div>
      <p>If this record and another are the same machine (for example a phone's private IPv6 address and its usual address), merge them. Its addresses, traffic and alerts are then counted under the other device. You can undo it.</p>
      ${sim.length ? `<div class="devices-sim"><span class="nv-dim">Same name seen on:</span>${sim.map((s) => `<button class="chip" data-merge="${esc(s.id)}">${esc(s.name)}</button>`).join('')}</div>` : ''}
      <label class="nv-in devices-msearch"><svg class="i"><use href="#i-search"/></svg><input placeholder="Find the device to merge into…" aria-label="Find the device to merge into"></label>
      <div class="devices-mlist"></div>
      <div class="devices-mconfirm"></div>
      <div class="devices-form-act"><button class="src-btn" data-act="mcancel">Cancel</button></div>
    </section>`;
  }

  function renderDetail(d) {
    st.detail = d;
    chart?.dispose(); chart = null;
    if (isPhone()) { renderPhoneDetail(d); return; }
    const c = CONF[d.confidence] || ['', ''];
    const evIps = d.evidence?.ips || [];
    const open = (d.alerts || []).filter((a) => a.status !== 'dismissed');
    const mf = d.merged_from || [];
    $('.nv-dd').innerHTML = `
      <div class="nv-dh">
        <button class="icon-btn nv-back" data-act="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button>
        <div class="nv-dh-tags"><span class="tag ${c[0]}" title="${esc(c[1])}">${esc(d.confidence)}</span><span class="tag">${esc(d.identity === 'mac' ? 'identified by MAC' : 'identified by IP')}</span></div>
        <h2 class="devices-h2" tabindex="-1"><span class="devices-ic devices-ic-lg" title="${esc(typeLabel(d))}">${typeIcon(d.type)}</span><span class="${d.name_source === 'fallback' ? 'devices-unnamed' : ''}" data-nochips>${esc(d.name)}</span></h2>
        <div class="devices-who">${esc([d.owner, d.type ? typeLabel(d) : ''].filter(Boolean).join(' · ') || 'No owner or type set')}</div>
        ${d.note ? `<p class="devices-notep">${esc(d.note)}</p>` : ''}
        <div class="mono nv-dim">${esc(d.id)}</div>
        ${d.merged_into ? `<div class="nv-warnbox devices-mi">You opened ${esc(d.asked)}, which you merged into this device.</div>` : ''}
        <div class="nv-dh-act"><button class="src-btn primary" data-act="rename">Rename or set type</button><button class="src-btn" data-act="hunt">Search this device's logs</button>${open.length ? `<button class="src-btn" data-act="alerts">${open.length} alert${open.length === 1 ? '' : 's'}</button>` : ''}<button class="src-btn" data-act="merge">Merge into…</button></div>
      </div>
      ${st.mode === 'edit' ? `<section class="nv-sec">${editForm(d, true)}</section>` : ''}
      ${st.mode === 'merge' ? mergeBox(d) : ''}
      ${mf.length ? `<section class="nv-sec devices-inc"><div class="label">Includes</div>${mf.map((m) => `<div class="devices-inc-r"><span><b>${esc(d.merged_from_names?.[m] || m.replace(/^(mac|ip):/, ''))}</b> <span class="nv-dim mono">${esc(m)}</span> <span class="nv-dim">· merged by you</span></span><button class="chip" data-unmerge="${esc(m)}">Undo merge</button></div>`).join('')}</section>` : ''}
      <div class="nv-dk">
        <div><span class="label">First seen</span><b class="mono" title="${esc(T.full(d.first_seen))}">${tileTime(d.first_seen)}</b></div>
        <div><span class="label">Last seen</span><b class="mono" title="${esc(T.full(d.last_seen))}">${tileTime(d.last_seen)}</b><em>${ago(d.last_seen)}</em></div>
        <div><span class="label">Connections</span><b class="mono">${fmt(d.conns)}</b><em>${fmt(d.rows)} rows</em></div>
        <div><span class="label">Sent / received</span><b class="mono">${nb(bytes(d.bytes_out))} / ${nb(bytes(d.bytes_in))}</b></div>
      </div>
      <section class="nv-sec"><div class="label">Timeline</div><div class="nv-chart nv-dchart" role="img" aria-label="Connections per hour, with alerts marked"></div>${timelineList(d)}</section>
      ${namesSection(d)}
      <section class="nv-sec"><div class="label">Identity evidence</div>
        <p class="nv-dim">${esc(c[1])}</p>
        <div class="devices-scroll"><table class="nv-ivt mono"><thead><tr><th>IP</th><th>How</th><th>Seen</th><th class="r">Rows</th></tr></thead><tbody>
        ${(evIps.length ? evIps : (d.ip_history || []).map((h) => ({ ip: h.ip, how: h.how }))).map((x) => `<tr><td>${v('ip', x.ip)}</td><td>${esc(HOW[x.how] || x.how || '')}${x.basis ? ` <span class="nv-dim">${esc(typeof x.basis === 'string' ? x.basis : JSON.stringify(x.basis))}</span>` : ''}</td><td>${x.first_ts ? `${tsShort(x.first_ts)} → ${tsShort(x.last_ts)}` : ''}</td><td class="r">${x.rows != null ? fmt(x.rows) : ''}</td></tr>`).join('')}
        </tbody></table></div>
        ${(d.ip_history || []).some((h) => !h.from_ts.startsWith('1970')) ? `<div class="nv-dim mono" style="margin-top:6px">Address changes: ${d.ip_history.filter((h) => !h.from_ts.startsWith('1970')).map((h) => `${esc(h.ip)} from ${tsShort(h.from_ts)}`).join(' · ')}</div>` : ''}
      </section>
      <section class="nv-sec"><div class="label">Alerts</div>
        ${(d.alerts || []).length ? `<div class="nv-att">${d.alerts.slice(0, 20).map((a) => `<div class="nv-att-r" data-alert="${esc(a.id)}"><span class="nv-bell" style="background:${SEVCOL[a.severity]}"></span><div class="nv-att-m"><div class="nv-att-t">${v('ip', a.indicator)} <span class="nv-dim">${esc(ruleLabel(a.rule))}</span></div><div class="nv-att-s mono">${esc(srcName(a.source))} ${tierChip(a.source)} · ${fmt(a.count)} row${a.count === 1 ? '' : 's'} · ${esc({ ack: 'acknowledged' }[a.status] || a.status)}</div></div><span class="nv-att-w mono">${tsShort(a.last_ts)}</span></div>`).join('')}</div>` : '<div class="nv-calm">No alerts for this device.</div>'}
      </section>
      <div class="nv-g2">
        <section class="nv-sec"><div class="label">Top destinations</div>${barList(d.top_dests, { key: 'ip', val: 'bytes', fmtv: bytes, field: 'ip', color: PAL.teal, sub: (r) => `${fmt(r.conns)} conns` })}</section>
        <section class="nv-sec"><div class="label">Names looked up</div>${barList(d.top_names, { key: 'name', val: 'n', field: 'q', color: PAL.olive })}</section>
      </div>`;
    const box = $('.nv-dd');
    box.querySelector('[data-act="close"]').onclick = () => close(true, true);
    box.querySelector('[data-act="hunt"]').onclick = () => { S.filters = [{ f: 'device', v: d.id }]; S.groupby = ['resp_h']; emit('filters'); ctx.goto('hunt'); };
    box.querySelector('[data-act="rename"]').onclick = () => { st.mode = st.mode === 'edit' ? null : 'edit'; renderDetail(d); box.querySelector('form input[name="name"]')?.focus(); };
    box.querySelector('[data-act="merge"]').onclick = () => { st.mode = st.mode === 'merge' ? null : 'merge'; renderDetail(d); box.querySelector('.devices-msearch input')?.focus(); };
    box.querySelector('[data-act="alerts"]')?.addEventListener('click', () => ctx.goto('alerts', { alert: open[0].id }));
    box.querySelectorAll('[data-alert]').forEach((r) => {
      const go = (e) => { if (!e.target.closest('.nv-v')) ctx.goto('alerts', { alert: r.dataset.alert }); };
      r.onclick = go;
      r.onkeydown = (e) => { if (e.key === 'Enter') go(e); };
    });
    box.querySelectorAll('[data-unmerge]').forEach((b) => (b.onclick = () => unmerge(b.dataset.unmerge, d.id)));
    wireForms(box);
    if (st.mode === 'merge') wireMerge(box, d);
    drawChart(box.querySelector('.nv-dchart'), d);
  }

  // the device's activity: connections per hour, alerts marked (echarts on demand, core/libs.js)
  function drawChart(node, d) {
    requestAnimationFrame(async () => {
      if (!node.offsetWidth) return;
      await need('echarts');
      if (st.detail !== d || !node.isConnected) return;
      chart?.dispose();
      chart = echarts.init(node);
      chart.setOption({
        animation: false, useUTC: T.isUTC(), // ticks in the app's one clock (Settings › Display), like the tooltip
        textStyle: chartTheme.textStyle, grid: { left: 36, right: 26, top: 8, bottom: 20 },   // right: room for the last date label (D2-06)
        tooltip: { trigger: 'axis', backgroundColor: '#14171c', borderColor: '#262b33', textStyle: { color: '#d7dbe0', fontSize: 11 },
          formatter: (ps) => `<div style="font-family:JetBrains Mono,monospace;font-size:11px"><b>${ts(ps[0].axisValue, false)} ${Z()}</b><br>${ps.map((p) => `${p.marker}${p.seriesName === 'alert' ? 'alert' : `${p.seriesName} <b style="float:right;margin-left:14px">${fmt(p.value[1])}</b>`}`).join('<br>')}</div>` },
        // about one label per 80 px, so narrow screens get fewer dates instead of "Nov 10Nov 11" run together
        xAxis: { type: 'time', splitNumber: Math.max(2, Math.floor(node.offsetWidth / 80)), axisLine: { lineStyle: { color: chartTheme.axisLine } }, splitLine: { show: false },
          // dates ('Nov 4'), not ECharts' bare day number, as on the Network overview
          axisLabel: { color: '#9aa1ab', fontSize: 10, hideOverlap: true, formatter: { year: '{yyyy}', month: '{MMM}', day: '{MMM} {d}', hour: '{HH}:{mm}', minute: '{HH}:{mm}' } } },
        yAxis: { type: 'value', splitNumber: 2, axisLabel: { color: '#9aa1ab', fontSize: 10, formatter: (x) => compact(x) }, splitLine: { lineStyle: { color: chartTheme.split } } },
        series: [{ type: 'bar', name: 'conns', data: (d.timeline || []).map((r) => [Date.parse(r.t), r.conns]), itemStyle: { color: PAL.amber }, barMaxWidth: 6, barMinWidth: 1 },
          ...(d.alerts || []).length ? [{ type: 'scatter', name: 'alert', symbolSize: 7, data: d.alerts.map((a) => ({ value: [Date.parse(a.ts), 0], itemStyle: { color: SEVCOL[a.severity] } })) }] : []],
      });
    });
  }

  function wireMerge(box, d) {
    const list = box.querySelector('.devices-mlist');
    const confirmBox = box.querySelector('.devices-mconfirm');
    const input = box.querySelector('.devices-msearch input');
    const all = () => [...S.devices.values()].filter((x) => x.id !== d.id);
    const paint = () => {
      const q = input.value.trim().toLowerCase();
      const rows = all().filter((x) => !q || [x.name, x.owner, x.id, ...(x.ips || [])].some((s) => String(s || '').toLowerCase().includes(q)))
        .sort((a, b) => (a.fragment - b.fragment) || (a.identity !== 'mac') - (b.identity !== 'mac') || (a.name_source === 'fallback') - (b.name_source === 'fallback') || String(a.name).localeCompare(String(b.name)))
        .slice(0, 8);
      list.innerHTML = rows.length ? rows.map((x) => `<button class="devices-mopt" data-merge="${esc(x.id)}">${typeIcon(x.type)}<span><b>${esc(x.name)}</b><em class="mono">${esc((x.ips || []).slice(0, 2).join(', '))}</em></span></button>`).join('') : '<div class="nv-dim">No other device matches.</div>';
      list.querySelectorAll('[data-merge]').forEach((b) => (b.onclick = () => ask(b.dataset.merge)));
    };
    const ask = (dst) => {
      const target = S.devices.get(dst);
      confirmBox.innerHTML = `<div class="nv-warnbox">Merge <b data-nochips>${esc(d.name)}</b> into <b data-nochips>${esc(target?.name || dst)}</b>? Its ${fmt((d.ips || []).length)} address${(d.ips || []).length === 1 ? '' : 'es'}, traffic and alerts will count under ${esc(target?.name || dst)}. You can undo this from that device.</div>
        <div class="devices-form-act"><button class="src-btn primary" data-act="mgo">Merge</button></div>`;
      confirmBox.querySelector('[data-act="mgo"]').onclick = () => doMerge(d.id, dst);
    };
    box.querySelectorAll('.devices-sim [data-merge]').forEach((b) => (b.onclick = () => ask(b.dataset.merge)));
    box.querySelector('[data-act="mcancel"]').onclick = cancel;
    input.addEventListener('input', debounce(paint, 120));
    input.addEventListener('keydown', (e) => { if (e.key === 'Escape') cancel(); });
    paint();
  }

  async function doMerge(src, dst) {
    const box = $('.nv-dd');
    box.querySelector('.devices-mconfirm').innerHTML = loadingState('Merging and re-checking its alerts…', { size: 'sm' });
    try {
      await api.post('/api/netlog/devices/merge', { src, dst });
      toast('Merged. Undo is on the device it went into.');
      st.mode = null;
      await loadDevices();
      emit('data');
      await load();
      select(dst, 'replace');
    } catch (e) { toast(e.message, true); box.querySelector('.devices-mconfirm').innerHTML = ''; }
  }

  async function unmerge(src, cur) {
    try {
      await api.post('/api/netlog/devices/unmerge', { src });
      toast('Merge undone');
      await loadDevices();
      emit('data');
      await load();
      select(cur, 'replace');
    } catch (e) { toast(e.message, true); }
  }

  // ------------------------------------------------------------ the phone (design §4.2; markup in m-devices.js)
  const devsHash = () => withRange('#network/devices', S.range);
  function phoneHead() {
    const list = $('.nv-dv-list');
    let h = list.querySelector(':scope > .nv-m-dvhead');
    const counts = { all: st.rows.length, unnamed: st.rows.filter((d) => d.name_source === 'fallback').length };
    const html = MD.headHtml(st, counts);
    if (!h) {
      h = document.createElement('div');
      h.className = 'nv-m-dvhead';
      h.innerHTML = html;
      list.prepend(h);
      h.querySelector('input').addEventListener('input', debounce((e) => { st.q = e.target.value.trim(); st.shown = MD.PAGE; load(); }, 250));
      h.addEventListener('click', async (e) => {
        const only = e.target.closest('[data-monly]');
        if (only) { st.only = only.dataset.monly; st.shown = MD.PAGE; render(); return; }
        if (e.target.closest('[data-msort]')) {
          const it = await actionSheet({ id: 'nv-dsort', title: 'Sort devices', items: [['alerts', 'Alerts first'], ['bytes', 'Most traffic'], ['last_seen', 'Last seen'], ['rows', 'Most rows']].map(([v0, l]) => ({ label: l, value: v0, current: v0 === st.sort })) });
          if (it && it.value !== st.sort) { st.sort = it.value; load(); }
        }
      });
    } else {
      const t = document.createElement('template');
      t.innerHTML = html;
      h.querySelector('.nv-m-chips').replaceWith(t.content.querySelector('.nv-m-chips'));
    }
  }
  function renderPhone() {
    phoneHead();
    const box = $('.nv-dl');
    if (!st.rows.length) {
      box.innerHTML = st.q ? emptyState({ title: 'No device matches', why: 'Try part of a name, an address or a MAC.' })
        : emptyState({ title: 'No devices yet', why: 'Devices appear after the first import of your logs.', act: stateAct('Connect logs', { href: '#network/import' }) });
      afterRender('network');
      return;
    }
    // named and MAC-identified devices first, the short-lived unidentified addresses after them
    const all = st.rows.filter((d) => st.only !== 'unnamed' || d.name_source === 'fallback');
    const rows = [...all.filter((d) => !d.fragment || d.alerts), ...all.filter((d) => d.fragment && !d.alerts)];
    const shown = rows.slice(0, st.shown);
    box.innerHTML = `<div class="nv-m-dlist">${shown.map((d) => MD.rowHtml(d, st.open)).join('')}</div>
      ${rows.length > shown.length ? `<button type="button" class="m-btn nv-m-showmore" data-more>Show more <span class="nv-m-dim">(${fmt(rows.length - shown.length)} more)</span></button>` : ''}`;
    afterRender('network');
  }
  function phoneClick(e) {
    if (e.target.closest('[data-more]')) {
      st.shown += MD.PAGE;
      setEntryState({ nvShown: st.shown });   // Back to this list shows as many rows again (core/page.js)
      renderPhone();
      return;
    }
    const more = e.target.closest('.nv-m-more');
    if (more) {
      const d = st.rows.find((x) => x.id === more.closest('[data-id]').dataset.id);
      if (d) rowMenu(d);
    }
  }
  function rowMenu(d) {
    actionSheet({ id: 'nv-drow', title: d.name, items: [
      { label: 'Search its logs', run: () => huntDevice(d) },
      { label: 'Rename…', run: () => MD.renameSheet(d, (body) => savePhone(d.id, body)) },
      { label: 'Copy address', run: () => copyText((d.ips || [])[0] || d.mac || d.id) },
    ] });
  }
  const huntDevice = (d) => { S.filters = [{ f: 'device', v: d.id }]; S.groupby = ['resp_h']; emit('filters'); ctx.goto('hunt'); };
  const savePhone = (id, body) => save(id, body);
  function renderPhoneDetail(d) {
    const box = $('.nv-dd');
    box.innerHTML = MD.detailHtml(d, { mode: st.mode });
    setPhoneTitle(d.name, { back: { label: 'Devices', href: devsHash() } });
    const btn = (label, fn, aria) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'm-btn'; b.textContent = label; if (aria) b.setAttribute('aria-label', aria); b.onclick = fn; return b; };
    const dots = btn('', () => actionSheet({ id: 'nv-ddots', title: d.name, items: [
      { label: 'Merge into…', run: () => { st.mode = 'merge'; renderDetail(d); box.querySelector('.devices-merge')?.scrollIntoView({ block: 'start' }); } },
      { label: 'Copy summary', run: () => copyText([d.name, (d.ips || []).join(', '), d.mac, `first seen ${ts(d.first_seen, false)}`, `last seen ${ts(d.last_seen, false)}`, `${fmt(d.conns)} connections`].filter(Boolean).join('\n'), 'Summary copied') },
      { label: 'Copy address', run: () => copyText((d.ips || [])[0] || d.mac || d.id) },
    ] }), 'More actions');
    dots.className = 'm-btn m-btn-sq nv-m-dots';
    dots.innerHTML = '<svg class="i" viewBox="0 0 20 20" aria-hidden="true"><circle cx="4" cy="10" r="1.7" fill="currentColor"/><circle cx="10" cy="10" r="1.7" fill="currentColor"/><circle cx="16" cy="10" r="1.7" fill="currentColor"/></svg>';
    dots.setAttribute('aria-haspopup', 'menu');
    setActionBar([btn('Search its logs', () => huntDevice(d)), btn('Rename…', () => MD.renameSheet(d, (body) => savePhone(d.id, body))), dots]);
    const slot = box.querySelector('.nv-m-mergeslot');
    if (slot) { slot.outerHTML = mergeBox(d); wireMerge(box, d); }
    box.querySelector('.nv-m-namesb').innerHTML = namesSection(d);
    box.querySelector('[data-act="alerts"]')?.addEventListener('click', () => pushPage('#network/alerts'));
    box.querySelector('[data-act="dests"]')?.addEventListener('click', () => huntDevice(d));
    drawChart(box.querySelector('.nv-dchart'), d);
    afterRender('network');
  }

  el.querySelectorAll('[data-k="sort"] button').forEach((b) => (b.onclick = () => { st.sort = b.dataset.v; load(); }));
  $('.nv-bar input').addEventListener('input', debounce((e) => { st.q = e.target.value.trim(); load(); }, 250));
  $('.nv-dl').addEventListener('click', (e) => {
    if (isPhone()) { phoneClick(e); return; }
    const r = e.target.closest('[data-id]');
    if (!r || e.target.closest('.nv-v, form, .devices-inline')) return;
    if (e.target.closest('[data-act="edit"]')) { e.stopPropagation(); st.editing = st.editing === r.dataset.id ? null : r.dataset.id; render(); return; }
    select(r.dataset.id, 'push', true);
  });
  // Keyboard: each row's name is a button (Tab stop); Enter or Space on it opens the device through the click above
  // Back (or any move) to #network/devices with no id closes a routed device; the unrouted preview stays.
  // network.js's own listener has run show() by now (it was registered first).
  window.addEventListener('hashchange', () => {
    const t = location.hash.slice(1).split('?')[0].split('/');
    // focus goes back to the row, not left on the hidden heading (B2-06)
    if (st.visible && t[0] === 'network' && t[1] === 'devices' && !t[2] && st.sel && st.routed) { const a = document.activeElement; close(false, !a || a === document.body || side.contains(a)); }
  });
  // Esc closes the device and puts focus back on its row (common.js escCloses; an edit form's own Esc wins)
  escCloses(() => st.visible && el.classList.contains('has-detail'), () => close(true, true));
  const ro = new ResizeObserver(debounce(() => chart?.resize(), 80));
  ro.observe(el);
  onChange((w) => { if (w === 'data' || w === 'alerts') { st.stale = true; if (st.visible) load(); } });

  return {
    // opts.device: from a link or Back/Forward (the URL already names it), or from another tab (the URL gets it).
    // The wide-screen first-device preview opens once, so it never comes back after a Back closed a device.
    async show(opts = {}) {
      st.visible = true;
      if (isPhone()) { const n = entryState().nvShown; if (n && n !== st.shown && !hashDev()) { st.shown = n; if (!st.stale) render(); } }
      if (st.stale) await load();
      if (isPhone() && !hashDev() && st.sel) close(false);
      const want = opts.device || hashDev();
      if (want) {
        if (st.sel !== want || !st.detail) select(want, hashDev() === want ? false : 'replace', true);
        else if (opts.device) { st.focus = true; focusDetail(); }
        return;
      }
      if (!st.sel && !st.auto && window.innerWidth > 900 && st.rows.length) { st.auto = true; select(st.rows.find((d) => !d.fragment)?.id || st.rows[0].id); }
    },
    hide() { st.visible = false; },
  };
}

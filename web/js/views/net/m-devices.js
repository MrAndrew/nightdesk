// Network › Devices on a phone (lane m-net; design §4.2 "Devices", "Device detail"). Markup and sheets of the phone
// layout; devices.js keeps the data, the route and saving, and calls these behind isPhone().
import { DEV_TYPES, typeIcon, bytes, esc, fmt, ruleLabel, ts, tsShort, Z } from './common.js';
import { openSheet } from '../../core/sheet.js';
import { ago } from '../../core/util.js';
import { SEV as SEVCOL } from '../../core/util.js';
import { DOTS, CARET, SEV_WORD, shortId } from './m.js';

export const PAGE = 60;
const SHORT_TYPE = { laptop: 'Laptop', phone: 'Phone', tv: 'TV', iot: 'Smart home', server: 'Server', console: 'Console', network: 'Network', other: 'Other' };
export const typeWord = (d) => SHORT_TYPE[d.type] || 'Unknown';
const short = (t) => String(ago(t)).replace(/ ago$/, '');
const SR = { high: 0, medium: 1, low: 2, info: 3 };

export function headHtml(st, counts) {
  const sortWord = { alerts: 'Alerts first', bytes: 'Most traffic', last_seen: 'Last seen', rows: 'Most rows' }[st.sort] || 'Sort';
  return `<label class="nv-m-dsearch"><svg class="i" aria-hidden="true"><use href="#i-search"/></svg><input type="search" value="${esc(st.q)}" placeholder="Name, address or MAC" aria-label="Find a device" autocomplete="off"></label>
    <div class="nv-m-chips" role="toolbar" aria-label="Sort and filter devices">
      <button type="button" class="m-chip on" data-msort aria-haspopup="menu">${esc(sortWord)}${CARET}</button>
      <button type="button" class="m-chip ${st.only !== 'unnamed' ? 'on' : ''}" data-monly="all" aria-pressed="${st.only !== 'unnamed'}">All <b class="nv-m-cn">${fmt(counts.all)}</b></button>
      <button type="button" class="m-chip ${st.only === 'unnamed' ? 'on' : ''}" data-monly="unnamed" aria-pressed="${st.only === 'unnamed'}">Unnamed <b class="nv-m-cn">${fmt(counts.unnamed)}</b></button>
    </div>`;
}

// The row's id: a long IPv6 address keeps its last two groups ("…7a2f:19c0", the part that tells devices apart;
// the full address is its title); the line ellipsises the id, never the age after it
const rowId = (d) => { const id = shortId(d); const g = id.split(':'); return g.length > 4 && id.length > 14 ? `…${g.slice(-2).join(':')}` : id; };

// A row: the type tile, the full name (it wraps, never cut), one mono line that does not wrap, the traffic, a ⋯.
export function rowHtml(d, open) {
  const n = open.get(d.id);
  const tag = n ? `<span class="nv-m-tag${n.real ? '' : ' demo'}">${fmt(n.n)} alert${n.n === 1 ? '' : 's'}</span>` : '';
  return `<div class="nv-m-drow" data-id="${esc(d.id)}">
    <a class="nv-m-dmain" href="#network/devices/${encodeURIComponent(d.id)}">
      <span class="nv-m-tile">${typeIcon(d.type)}</span>
      <span class="nv-m-dtext"><span class="nv-m-dname"><b class="${d.name_source === 'fallback' ? 'devices-unnamed' : ''}" data-nochips>${esc(d.name)}</b>${tag}</span>
        <span class="nv-m-dline" data-nochips><span>${esc(typeWord(d))} ·&nbsp;</span><span class="nv-m-did" title="${esc(shortId(d))}">${esc(rowId(d))}</span><span>&nbsp;· ${esc(short(d.last_seen))}</span></span></span>
      <span class="nv-m-dbytes">${bytes((d.bytes_in || 0) + (d.bytes_out || 0))}</span>
    </a>
    <button type="button" class="m-more nv-m-more" aria-haspopup="menu" aria-label="Actions for ${esc(d.name)}">${DOTS}</button>
  </div>`;
}

// The device page: head, alerts on it, live state, top destinations above the fold; activity, timeline and names below.
export function detailHtml(d, { mode }) {
  const guess = d.type_source === 'guess';
  const typeLine = d.type ? `${DEV_TYPES[d.type]?.[0] || d.type}${guess ? ' (guessed from its traffic)' : ''}` : 'Type not set';
  const ip = (d.ips || [])[0] || '';
  const sid = shortId(d);
  const idLine = [ip, sid !== ip ? sid : '', d.identity === 'mac' ? 'identified by MAC' : 'identified by its address'].filter(Boolean).join(' · ');
  const open = (d.alerts || []).filter((a) => a.status === 'new').sort((a, b) => SR[a.severity] - SR[b.severity] || (b.last_ts > a.last_ts ? 1 : -1));
  const dests = (d.top_dests || []).slice(0, 5);
  return `
    <div class="nv-m-dhead">
      <span class="nv-m-tile nv-m-tile-lg">${typeIcon(d.type)}</span>
      <div class="nv-m-dhead-t">
        <h2 class="nv-m-dh2" tabindex="-1"><span class="${d.name_source === 'fallback' ? 'devices-unnamed' : ''}" data-nochips>${esc(d.name)}</span></h2>
        <div class="nv-m-dtype">${esc([d.owner, typeLine].filter(Boolean).join(' · '))}</div>
        <div class="nv-m-did" data-nochips>${esc(idLine)}</div>
      </div>
    </div>
    ${d.merged_into ? `<div class="nv-warnbox devices-mi">You opened ${esc(d.asked)}, which you merged into this device.</div>` : ''}
    ${mode === 'merge' ? '<div class="nv-m-mergeslot"></div>' : ''}
    <section class="nv-m-sec">
      <h3 class="nv-m-sh"><span>Alerts on this device</span><span class="nv-m-sh-r">${open.length ? `${fmt(open.length)} open` : ''}</span></h3>
      ${open.length ? `<div class="nv-m-dalerts">${open.slice(0, 3).map((a) => `<a class="nv-m-dalert nv-m-s-${esc(a.severity)}" href="#network/alerts/${encodeURIComponent(a.id)}">
          <span class="nv-m-l2">${esc(ruleLabel(a.rule))}</span>
          <span class="nv-m-l3"><span class="nv-m-sev">${esc((SEV_WORD[a.severity] || a.severity).toUpperCase())}</span><span class="nv-m-val" data-nochips>${esc(a.indicator)}</span><span class="nv-m-dim">· ${esc(short(a.last_ts))}</span></span></a>`).join('')}</div>
        ${open.length > 3 ? `<button type="button" class="nv-m-all" data-act="alerts">All ${fmt(open.length)} ›</button>` : ''}` : '<p class="nv-m-none">No open alerts on this device</p>'}
    </section>
    <section class="nv-m-live" aria-label="Live state">
      <div><span class="nv-m-k">Last seen</span><b>${esc(ago(d.last_seen))}</b></div>
      <div><span class="nv-m-k">Traffic</span><b>↓ ${bytes(d.bytes_in)} ↑ ${bytes(d.bytes_out)}</b></div>
      <p class="nv-m-livs">first seen ${esc(ts(d.first_seen, false))} ${Z()} · ${fmt(d.conns)} connections</p>
    </section>
    <section class="nv-m-sec">
      <h3 class="nv-m-sh"><span>Top destinations</span>${dests.length ? '<button type="button" class="nv-m-all" data-act="dests">All ›</button>' : ''}</h3>
      ${dests.length ? `<ol class="nv-m-dests">${dests.map((r, i) => `<li><span class="nv-m-dn">${i + 1}</span><span class="nv-m-dv" data-nochips>${esc(r.name || r.ip)}</span><span class="nv-m-db">${bytes(r.bytes)}</span></li>`).join('')}</ol>`
        : '<p class="nv-m-none">No outside destinations in its logs</p>'}
    </section>
    <section class="nv-m-sec"><h3 class="nv-m-sh"><span>Activity</span></h3><div class="nv-chart nv-dchart nv-m-dchart" role="img" aria-label="Connections per hour, with alerts marked"></div></section>
    <details class="nv-m-det"><summary>Timeline</summary>${timeline(d)}</details>
    <details class="nv-m-det nv-m-names"><summary>Names and evidence</summary><div class="nv-m-namesb"></div></details>`;
}

function timeline(d) {
  const evs = (d.events || []).slice(0, 30);
  if (!evs.length) return '<p class="nv-m-none">Nothing recorded yet.</p>';
  return `<ol class="nv-m-tl">${evs.map((e) => `<li><span class="nv-m-tlt">${esc(tsShort(e.t))}</span>
    <span class="nv-m-tlx">${e.kind === 'alert' ? `<i style="background:${SEVCOL[e.severity]}"></i><b>${esc(e.severity)}</b> ` : ''}${esc(String(e.text || '').replace(/\bDEMO Night Desk\s+/g, ''))}</span></li>`).join('')}</ol>`;
}

// Rename: a name field, a 44 px type grid and the owner, with Save pinned above the keyboard.
export function renameSheet(d, save) {
  const lab = d.label || {};
  let type = lab.type || '';
  const body = document.createElement('form');
  body.className = 'nv-m-rename';
  body.autocomplete = 'off';
  body.innerHTML = `<label class="nv-m-fl"><span>Name</span><input name="name" maxlength="60" value="${esc(lab.name || '')}" placeholder="${esc(d.naming?.name || d.name || 'e.g. Kids’ iPad')}" autofocus></label>
    <div class="nv-m-fl"><span id="nv-m-tlab">Type</span><div class="nv-m-types" role="radiogroup" aria-labelledby="nv-m-tlab">${Object.entries(DEV_TYPES).map(([k, [l]]) => `<button type="button" role="radio" aria-checked="${type === k}" data-type="${k}">${typeIcon(k)}<span>${esc(SHORT_TYPE[k] || l)}</span></button>`).join('')}</div></div>
    <label class="nv-m-fl"><span>Owner or room (optional)</span><input name="owner" maxlength="60" value="${esc(lab.owner || '')}" placeholder="e.g. Sam, or living room"></label>`;
  body.addEventListener('click', (e) => {
    const b = e.target.closest('[data-type]'); if (!b) return;
    type = type === b.dataset.type ? '' : b.dataset.type;
    body.querySelectorAll('[data-type]').forEach((x) => x.setAttribute('aria-checked', String(x.dataset.type === type)));
  });
  const cancel = document.createElement('button');
  cancel.type = 'button'; cancel.className = 'm-btn'; cancel.textContent = 'Cancel';
  const ok = document.createElement('button');
  ok.type = 'button'; ok.className = 'm-btn m-btn-primary'; ok.textContent = 'Save';
  const h = openSheet({ id: 'nv-rename', title: `Rename ${d.name}`, body, footer: [cancel, ok] });
  cancel.addEventListener('click', () => h.close('close'));
  const go = async () => {
    ok.disabled = true;
    const ok2 = await save({ name: body.elements.name.value, type: type || null, owner: body.elements.owner.value });
    if (ok2) h.close('close'); else ok.disabled = false;
  };
  ok.addEventListener('click', go);
  body.addEventListener('submit', (e) => { e.preventDefault(); go(); });
  return h;
}

// Campaign "metro map" (#entities/metro?lab=1, hidden from navigation since v1.1): campaigns or actors as coloured lines over time; the malware,
// tools, CVEs and infrastructure they share are interchange stations joining the lines. Each line stops at a
// shared item at its own time, so the transfer shows the item moving between operations.
// Data: GET /api/entities/timeline. Pure SVG, no library.
import { api, esc, tmeta, tcolor, icon, shown, nameOf, typeOf, LS, specificity, fmtDate } from './common.js';
import { openEntity } from '../../core/entity-panel.js';
import { emptyState } from '../../core/view.js';
import * as T from '../../core/time.js';
import { SERIES } from '../../core/util.js';

// Campaign lines: the app's muted series palette (core/util.js SERIES), amber first; no red, no v1 green.
const PALETTE = SERIES;
const STATION_SETS = {
  arsenal: ['Malware & tools', 'malware,tool'], cve: ['CVEs', 'cve'], infra: ['Infrastructure', 'ip,domain,url,hash'], technique: ['Techniques', 'technique'],
};
const ROW = 50, DX = 20, SLOT_PAD = 26, TOP = 74, PRIV_CAP = 5;

let M = null;

export async function showMetro(pane, ctx) {
  if (!M) M = init(pane, ctx);
  M.ctx = ctx;
  if (!M.data) load();
}

function init(pane, ctx) {
  const saved = LS.get('nd.entities.metro', {});
  const S = { pane, ctx, lanes: saved.lanes || 'campaign,actor', n: saved.n || 12, sets: new Set(saved.sets || ['arsenal', 'cve', 'infra']), data: null, sharedOnly: saved.sharedOnly ?? false, hideCommodity: saved.hideCommodity ?? false };
  pane.innerHTML = `<div class="mt">
    <div class="mt-bar">
      <div><h2 class="en-h1">Campaign map</h2><div class="en-sub mono mt-sub"></div></div>
      <div class="mt-ctl">
        <div class="gr-seg" data-k="lanes"><button data-v="campaign">Campaigns</button><button data-v="actor">Actors</button><button data-v="campaign,actor">Both</button></div>
        <div class="gr-seg" data-k="n"><button data-v="8">8</button><button data-v="12">12</button><button data-v="20">20</button></div>
        <div class="mt-sets">${Object.entries(STATION_SETS).map(([k, [l]]) => `<button data-set="${k}">${esc(l)}</button>`).join('')}</div>
        <label class="mt-chk"><input type="checkbox" class="mt-so"> shared only</label>
        <label class="mt-chk" title="Commodity tools (Mimikatz, PsExec, Cobalt Strike…) are used by many unrelated groups"><input type="checkbox" class="mt-hc"> hide commodity tools</label>
      </div>
    </div>
    <div class="mt-wrap"><div class="mt-lanes"></div><div class="mt-scroll"><svg class="mt-svg"></svg></div><div class="mt-tip" hidden></div></div>
    <div class="mt-foot">
      <div class="mt-leg"><span><svg width="34" height="10"><line x1="2" x2="32" y1="5" y2="5" stroke="#e4a84c" stroke-width="6" stroke-linecap="round"/></svg>a line: one ${'campaign'}'s active period</span>
        <span><svg width="16" height="16"><circle cx="8" cy="8" r="5.5" fill="#e9e3d4" stroke="#0a0d12" stroke-width="2"/></svg>interchange: an item shared with another line</span>
        <span><svg width="16" height="16"><circle cx="8" cy="8" r="4" fill="#59606b" stroke="#08090b" stroke-width="1.5"/></svg>commodity tool: weak evidence of a link</span>
        <span><svg width="12" height="14"><line x1="6" x2="6" y1="2" y2="12" stroke="#b7b1a2" stroke-width="2.5"/></svg>stop seen on one line only</span>
        <span><svg width="30" height="14"><path d="M2 12 C 12 12, 18 2, 28 2" stroke="rgba(230,234,240,.45)" stroke-width="3" fill="none"/></svg>transfer between lines</span></div>
      <div class="mt-x"></div>
    </div>
  </div>`;
  const $ = (s) => pane.querySelector(s);
  S.$ = $;
  const sync = () => {
    pane.querySelectorAll('[data-k="lanes"] button').forEach((b) => b.classList.toggle('on', b.dataset.v === S.lanes));
    pane.querySelectorAll('[data-k="n"] button').forEach((b) => b.classList.toggle('on', +b.dataset.v === S.n));
    pane.querySelectorAll('[data-set]').forEach((b) => b.classList.toggle('on', S.sets.has(b.dataset.set)));
    $('.mt-so').checked = S.sharedOnly;
    $('.mt-hc').checked = S.hideCommodity;
    LS.set('nd.entities.metro', { lanes: S.lanes, n: S.n, sets: [...S.sets], sharedOnly: S.sharedOnly, hideCommodity: S.hideCommodity });
  };
  $('.mt-ctl').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    const k = b.parentElement.dataset.k;
    if (k === 'lanes') S.lanes = b.dataset.v;
    else if (k === 'n') S.n = +b.dataset.v;
    else if (b.dataset.set) { const s = b.dataset.set; S.sets.has(s) ? S.sets.delete(s) : S.sets.add(s); if (!S.sets.size) S.sets.add('arsenal'); }
    sync(); load();
  });
  $('.mt-so').onchange = (e) => { S.sharedOnly = e.target.checked; sync(); draw(); };
  $('.mt-hc').onchange = (e) => { S.hideCommodity = e.target.checked; sync(); draw(); };
  sync();
  return S;
}

async function load() {
  const S = M;
  S.$('.mt-sub').textContent = 'Loading…';
  const st = [...S.sets].map((k) => STATION_SETS[k][1]).join(',');
  try { S.data = await api.get('/api/entities/timeline', { type: S.lanes, limit: S.n, station_types: st }); }
  catch (e) { S.$('.mt-sub').textContent = `Could not load: ${e.message}`; return; }
  draw();
}

function orderLanes(lanes, shared) {
  // greedy: start with the lane sharing most, then repeatedly take the lane sharing most with the last placed
  const sh = new Map(lanes.map((l) => [l.id, new Set(l.stations.filter((s) => s.shared).map((s) => s.id))]));
  const overlap = (a, b) => [...sh.get(a)].filter((x) => sh.get(b).has(x)).length;
  const left = [...lanes].sort((a, b) => sh.get(b.id).size - sh.get(a.id).size);
  const out = [left.shift()];
  while (left.length) {
    const last = out[out.length - 1];
    left.sort((a, b) => overlap(b.id, last.id) - overlap(a.id, last.id) || sh.get(b.id).size - sh.get(a.id).size);
    out.push(left.shift());
  }
  void shared;
  return out.filter(Boolean);
}

function draw() {
  const S = M;
  const { pane } = S;
  const data = S.data;
  const svg = S.$('.mt-svg');
  if (!data?.lanes?.length) { S.$('.mt-sub').textContent = 'No campaigns or actors with dated stations yet.'; svg.innerHTML = ''; S.$('.mt-lanes').innerHTML = ''; return; }
  const weak = (id) => specificity({ ...(data.shared.find((x) => x.id === id) || { id }), total: data.lanes.length }) < 0.5;
  data.shared.sort((a, b) => (weak(a.id) - weak(b.id)) || b.lanes.length - a.lanes.length);
  const sharedOrder = new Map(data.shared.map((s, i) => [s.id, i]));
  const lanes = orderLanes(data.lanes, data.shared);
  lanes.forEach((l, i) => { l.color = PALETTE[i % PALETTE.length]; l.y = TOP + i * ROW + ROW / 2; });
  const slotOf = (ts) => (ts ? String(ts).slice(0, 7) : 'undated');
  // stops per (slot, lane)
  const slots = new Map();
  for (const l of lanes) {
    for (const s of l.stations) {
      if (S.sharedOnly && !s.shared) continue;
      if (S.hideCommodity && weak(s.id)) continue;
      const k = slotOf(s.ts);
      if (!slots.has(k)) slots.set(k, new Map());
      const m = slots.get(k);
      (m.get(l.id) || m.set(l.id, []).get(l.id)).push(s);
    }
  }
  const keys = [...slots.keys()].sort((a, b) => (a === 'undated') - (b === 'undated') || a.localeCompare(b));
  // within a slot: shared stations get common sub-columns (aligned across lanes), then each lane's private stops
  let x = 18;
  const pos = new Map(); // `${lane}|${station}` -> {x, y}
  const slotX = [];
  const privMore = [];
  for (const k of keys) {
    const m = slots.get(k);
    const sharedIds = [...new Set([...m.values()].flat().filter((s) => s.shared).map((s) => s.id))].sort((a, b) => sharedOrder.get(a) - sharedOrder.get(b));
    const sx = x;
    const maxPriv = Math.min(PRIV_CAP, Math.max(0, ...[...m.values()].map((list) => list.filter((s) => !s.shared).length)));
    for (const l of lanes) {
      const list = m.get(l.id) || [];
      for (const s of list) if (s.shared) pos.set(`${l.id}|${s.id}`, { x: sx + sharedIds.indexOf(s.id) * DX, y: l.y, s, l });
      const priv = list.filter((s) => !s.shared);
      priv.slice(0, PRIV_CAP).forEach((s, i) => pos.set(`${l.id}|${s.id}`, { x: sx + (sharedIds.length + i) * (DX * 0.6), y: l.y, s, l, priv: true }));
      if (priv.length > PRIV_CAP) privMore.push({ x: sx + (sharedIds.length + PRIV_CAP) * (DX * 0.6), y: l.y, n: priv.length - PRIV_CAP, l, k });
    }
    const w = Math.max(DX, sharedIds.length * DX + maxPriv * DX * 0.6 + (privMore.some((p) => p.k === k) ? 22 : 0));
    slotX.push({ k, x: sx, w });
    x = sx + w + SLOT_PAD;
  }
  const W = Math.max(x + 30, S.$('.mt-scroll').clientWidth);
  const H = TOP + lanes.length * ROW + 16;
  // lane spans
  const span = new Map();
  for (const p of pos.values()) {
    const sp = span.get(p.l.id) || { a: Infinity, b: -Infinity };
    sp.a = Math.min(sp.a, p.x); sp.b = Math.max(sp.b, p.x);
    span.set(p.l.id, sp);
  }
  for (const p of privMore) { const sp = span.get(p.l.id); if (sp) sp.b = Math.max(sp.b, p.x + 12); }
  let g = '';
  // time axis: slot labels with breaks between non-consecutive months
  const prevMonth = (k) => { const [y, m] = k.split('-').map(Number); return m === 1 ? `${y - 1}-12` : `${y}-${String(m - 1).padStart(2, '0')}`; };
  slotX.forEach((s, i) => {
    const lab = s.k === 'undated' ? 'undated' : T.monthYear(s.k);
    g += `<line x1="${s.x - 6}" x2="${s.x - 6}" y1="${TOP - 26}" y2="${H - 8}" class="mt-grid"/>`;
    g += `<text x="${s.x - 4}" y="${TOP - 32}" class="mt-tick">${esc(lab)}</text>`;
    if (i && s.k !== 'undated' && slotX[i - 1].k !== prevMonth(s.k)) g += `<text x="${s.x - SLOT_PAD / 2 - 9}" y="${TOP - 18}" class="mt-brk">⫽</text>`;
  });
  // lines
  for (const l of lanes) {
    const sp = span.get(l.id);
    if (!sp) continue;
    g += `<line class="mt-line" data-lane="${esc(l.id)}" x1="${sp.a - 10}" x2="${sp.b + 10}" y1="${l.y}" y2="${l.y}" stroke="${l.color}"/>`;
  }
  // transfers: connect each shared station's stops across lanes (sorted by y)
  const byStation = new Map();
  for (const p of pos.values()) if (!p.priv) (byStation.get(p.s.id) || byStation.set(p.s.id, []).get(p.s.id)).push(p);
  let tr = '', stops = '', labels = '';
  for (const [sid, ps] of byStation) {
    ps.sort((a, b) => a.y - b.y);
    const lanesAttr = ps.map((p) => p.l.id).join(' ');
    for (let i = 1; i < ps.length; i++) {
      const a = ps[i - 1], b = ps[i];
      const d = a.x === b.x ? `M${a.x} ${a.y} L${b.x} ${b.y}` : `M${a.x} ${a.y} C ${a.x} ${(a.y + b.y) / 2}, ${b.x} ${(a.y + b.y) / 2}, ${b.x} ${b.y}`;
      tr += `<path class="mt-tr${weak(sid) ? ' cm' : ''}" data-st="${esc(sid)}" data-lanes="${esc(lanesAttr)}" d="${d}"/>`;
    }
    const top = ps[0];
    const nm = shown(top.s.name || nameOf(sid), top.s.type);
    const wk = weak(sid);
    labels += `<text class="mt-sl${wk ? ' cm' : ''}" data-st="${esc(sid)}" x="${top.x + 2}" y="${top.y - 11}" transform="rotate(-32 ${top.x + 2} ${top.y - 11})" fill="${wk ? '#8a8578' : tcolor(top.s.type)}">${esc(nm.length > 22 ? nm.slice(0, 21) + '…' : nm)}</text>`;
    for (const p of ps) stops += `<circle class="mt-ic${wk ? ' cm' : ''}" data-st="${esc(sid)}" data-lane="${esc(p.l.id)}" cx="${p.x}" cy="${p.y}" r="${wk ? 4.2 : 7}" stroke="${p.l.color}"/>`;
  }
  for (const p of pos.values()) if (p.priv) stops += `<line class="mt-pv" data-st="${esc(p.s.id)}" data-lane="${esc(p.l.id)}" x1="${p.x}" x2="${p.x}" y1="${p.y - 8}" y2="${p.y + 8}" stroke="${p.l.color}"/>`;
  for (const p of privMore) stops += `<text class="mt-more" x="${p.x}" y="${p.y + 4}" data-lane="${esc(p.l.id)}">+${p.n}</text>`;
  svg.setAttribute('width', W); svg.setAttribute('height', H); svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.innerHTML = g + tr + stops + labels;
  // lane labels (sticky column)
  const L = S.$('.mt-lanes');
  L.style.height = `${H}px`;
  L.innerHTML = `<div class="mt-lh" style="height:${TOP - 8}px"><span class="label">${S.lanes === 'actor' ? 'Actors' : S.lanes === 'campaign' ? 'Campaigns' : 'Lines'}</span></div>` + lanes.map((l) => {
    const n = l.stations.length, ns = l.stations.filter((s) => s.shared && !weak(s.id)).length, nw = l.stations.filter((s) => s.shared && weak(s.id)).length;
    return `<a class="mt-ln" href="#entities/${encodeURIComponent(l.id)}" data-entity="${esc(l.id)}" data-lane="${esc(l.id)}" style="top:${l.y - ROW / 2}px;height:${ROW}px;--c:${l.color}">
      <i></i><span class="mt-lnn">${esc(l.name)}</span><span class="mt-lns mono">${l.type === 'actor' ? 'actor · ' : ''}${esc((l.start || '').slice(0, 7) || '?')}${l.end && l.end.slice(0, 7) !== (l.start || '').slice(0, 7) ? ` → ${esc(l.end.slice(0, 7))}` : ''} · ${ns} distinctive${nw ? ` + ${nw} commodity` : ''} shared</span></a>`;
  }).join('');
  const nShared = data.shared.length, nWeak = data.shared.filter((s) => weak(s.id)).length;
  S.$('.mt-sub').textContent = `${lanes.length} lines · ${nShared - nWeak} distinctive and ${nWeak} commodity interchange${nShared === 1 ? '' : 's'} · ${keys.length} months with activity · hover a station to trace it, click to open`;
  // interchange table (also the phone-friendly reading)
  const note = nShared && nShared === nWeak ? `<div class="mt-note">Every item these lines share is a commodity tool used by many unrelated groups, so none of the joins is good evidence of a link. Try <b>Actors</b>, <b>Both</b> or more lines.</div>` : '';
  S.$('.mt-x').innerHTML = note + (nShared ? `<div class="enp-ch"><h3>Interchanges</h3><span class="mono en-dim">items shared by two or more lines</span></div>
    <div class="mt-xt">${data.shared.slice(0, 40).map((s) => `<div class="mt-xr${weak(s.id) ? ' cm' : ''}" data-st="${esc(s.id)}"><a class="en-chip" href="#entities/${encodeURIComponent(s.id)}" data-entity="${esc(s.id)}" style="--c:${tcolor(s.type)}">${icon(s.type)}<span>${esc(shown(s.name, s.type))}</span></a>
      <span class="mono en-dim">${weak(s.id) ? 'commodity ' : ''}${esc(tmeta(s.type)[0].toLowerCase())}</span><span class="mt-xl">${s.lanes.map((lid) => { const l = lanes.find((x) => x.id === lid); return l ? `<span class="mt-xd" style="--c:${l.color}" title="${esc(l.name)}">${esc(l.name)}</span>` : ''; }).join('')}</span></div>`).join('')}</div>`
    : emptyState({ why: 'These lines share nothing with the selected station types. Try adding techniques or showing more lines.', size: 'inline' }));
  wire(S, lanes);
}

function wire(S, lanes) {
  const { pane } = S;
  const svg = S.$('.mt-svg'), tip = S.$('.mt-tip'), wrap = S.$('.mt-wrap');
  const laneBy = new Map(lanes.map((l) => [l.id, l]));
  const station = new Map();
  for (const l of lanes) for (const s of l.stations) { const e = station.get(s.id) || { ...s, lanes: [] }; e.lanes.push({ l, ts: s.ts, how: s.how }); station.set(s.id, e); }
  const clear = () => { pane.querySelector('.mt').classList.remove('focus'); pane.querySelectorAll('.on-f').forEach((x) => x.classList.remove('on-f')); tip.hidden = true; };
  const focusLanes = (ids, sid) => {
    pane.querySelector('.mt').classList.add('focus');
    pane.querySelectorAll('.on-f').forEach((x) => x.classList.remove('on-f'));
    for (const id of ids) pane.querySelectorAll(`[data-lane="${CSS.escape(id)}"]`).forEach((x) => x.classList.add('on-f'));
    if (sid) pane.querySelectorAll(`[data-st="${CSS.escape(sid)}"]`).forEach((x) => x.classList.add('on-f'));
  };
  svg.onmouseover = (e) => {
    const t = e.target.closest('[data-st], [data-lane]');
    if (!t) return clear();
    const sid = t.dataset.st;
    if (sid) {
      const st = station.get(sid);
      if (!st) return;
      focusLanes(st.lanes.map((x) => x.l.id), sid);
      const r = wrap.getBoundingClientRect(), b = t.getBoundingClientRect();
      tip.innerHTML = `<div class="mt-tt" style="color:${tcolor(st.type)}">${icon(st.type)}${esc(tmeta(st.type)[0])}</div><b>${esc(shown(st.name || nameOf(sid), st.type))}</b>
        <ul>${st.lanes.map((x) => `<li><i style="background:${x.l.color}"></i>${esc(x.l.name)}<span class="mono">${x.ts ? fmtDate(x.ts) : 'undated'} · ${x.how === 'claim' ? 'claimed' : 'co-mentioned'}</span></li>`).join('')}</ul><div class="mono en-dim">click to open</div>`;
      tip.hidden = false;
      // park the card in the corner away from the station so it never covers the traced lines' stops
      const sx = b.left - r.left, sy = b.top - r.top, lanesW = S.$('.mt-lanes').offsetWidth;
      tip.style.left = sx > lanesW + (r.width - lanesW) / 2 ? `${lanesW + 12}px` : `${Math.max(8, r.width - 272)}px`;
      tip.style.top = sy > r.height / 2 ? '12px' : `${Math.max(12, r.height - tip.offsetHeight - 12)}px`;
    } else focusLanes([t.dataset.lane]);
  };
  svg.onmouseleave = clear;
  svg.onclick = (e) => {
    const t = e.target.closest('[data-st]');
    if (t) openEntity(t.dataset.st);
    else { const l = e.target.closest('[data-lane]'); if (l) S.ctx.go({ tab: 'page', id: l.dataset.lane }); }
  };
  S.$('.mt-lanes').onmouseover = (e) => { const a = e.target.closest('[data-lane]'); if (a) focusLanes([a.dataset.lane]); };
  S.$('.mt-lanes').onmouseleave = clear;
  S.$('.mt-x').onmouseover = (e) => { const r = e.target.closest('.mt-xr'); if (r) { const st = station.get(r.dataset.st); if (st) focusLanes(st.lanes.map((x) => x.l.id), r.dataset.st); } };
  S.$('.mt-x').onmouseleave = clear;
  void laneBy; void typeOf;
}

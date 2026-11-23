// Network › Alerts on a phone (lane m-net; design §4.2 "Alerts", "Alert detail", "Mark as expected"). The markup and
// sheets of the phone layout; alerts.js keeps the data, the routes and triage, and calls these behind isPhone().
import { S, SEV, esc, fmt } from './common.js';
import { headline, rowValue, kindOf, dname, indicatorNoun, sigName, kindWord as kindWordOf } from './alert-text.js';
import { openSheet } from '../../core/sheet.js';
import { ago } from '../../core/util.js';
import { DOTS, CARET, FILTER, SEV_WORD, rangeChip, shortId } from './m.js';

const STATUS_WORD = { new: 'New', ack: 'Acknowledged', dismissed: 'Dismissed', expected: 'Expected', '': 'All' };
export const STATUS_ORDER = ['new', 'ack', 'dismissed', 'expected', ''];
const GROUP_WORD = { none: 'Flat list', device: 'By device', indicator: 'By address', rule: 'By kind' };
const plural = (n, w) => `${fmt(n)} ${w}${n === 1 ? '' : 's'}`;

// ---------------------------------------------------------------- the list
// The header: a serif summary ("2 need you · 3 low") with Select, then one chip row that fits at 360 px.
export function headHtml(st) {
  // no count (the read failed, or has not answered yet): no all-clear, just the title
  const c = st.count || {};
  const low = (c.low || 0) + (c.info || 0);
  const need = c.needs_you || 0;
  const big = !st.count ? 'Alerts' : need ? `${fmt(need)} need${need === 1 ? 's' : ''} you` : c.demo ? 'No real alerts' : 'Nothing needs you';
  const small = !st.count ? '' : [c.demo ? `${fmt(c.demo)} demo` : '', low ? `${fmt(low)} low` : ''].filter(Boolean).join(' · ');
  const stN = st.stateCounts?.[st.status];
  const sevs = st.sevs.size === SEV.length ? 'Severity' : st.sevs.size === 1 ? SEV_WORD[[...st.sevs][0]] : `${st.sevs.size} severities`;
  const nf = (st.q ? 1 : 0) + (st.group !== 'none' ? 1 : 0);
  return `<div class="nv-m-sumrow"><h2 class="nv-m-sum">${esc(big)}${small ? ` <span class="nv-m-sum-s">· ${esc(small)}</span>` : ''}</h2>
      <button type="button" class="nv-m-select" data-mselect aria-pressed="${st.selecting ? 'true' : 'false'}">${st.selecting ? 'Done' : 'Select'}</button></div>
    <div class="nv-m-chips" role="toolbar" aria-label="Filter alerts">
      <button type="button" class="m-chip on" data-mstatus aria-haspopup="menu">${esc(STATUS_WORD[st.status])}${st.status && stN != null ? ` <b class="nv-m-cn">${fmt(stN)}</b>` : ''}${CARET}</button>
      <button type="button" class="m-chip ${st.sevs.size < SEV.length ? 'on' : ''}" data-msev aria-haspopup="menu">${esc(sevs)}${CARET}</button>
      ${rangeChip()}
      <button type="button" class="m-chip nv-m-fbtn" data-mfilter aria-label="More filters${nf ? ` (${nf} on)` : ''}">${FILTER}${nf ? `<b class="nv-m-fn">${nf}</b>` : ''}</button>
    </div>`;
}

// One row: a stripe, the device and the time, what happened (2 lines at most), the severity word and the address in
// mono, and a 44 px ⋯. The row is one link; the ⋯ is its only other control (a checkbox only in Select mode).
export function rowHtml(a, { selecting = false, checked = false } = {}) {
  const h = headline(a);
  const sev = a.severity;
  const href = `#network/alerts/${encodeURIComponent(a.id)}`;
  const dev = a.device ? dname(a.device, a) : h.lead;
  const unread = a.state === 'new' || a.status === 'new';
  const contacts = a.count > 1 ? `${fmt(a.count)} contacts` : '';
  const state = a.state && a.state !== 'new' ? `<span class="nv-m-st">${esc(STATUS_WORD[a.state] || a.state)}</span>` : '';
  const label = `${SEV_WORD[sev] || sev}: ${dev}, ${h.what} ${rowValue(a)}${a.demo ? ' (demo)' : ''}`;
  return `<div class="nv-m-aw" data-mid="${esc(a.id)}"><div class="nv-m-arow nv-m-s-${esc(sev)}${checked ? ' on' : ''}" data-id="${esc(a.id)}" data-sev="${esc(sev)}">
      ${selecting ? `<label class="nv-m-ck"><input type="checkbox" ${checked ? 'checked' : ''} aria-label="Select: ${esc(label)}"></label>` : ''}
      <a class="nv-m-amain" href="${href}" aria-label="${esc(label)}">
        <span class="nv-m-l1"><b data-nochips>${esc(dev)}</b><span class="nv-m-when">${esc(String(ago(a.last_ts)).replace(/ ago$/, ''))}${unread ? '<i class="nv-m-dot" title="New"></i>' : ''}</span></span>
        <span class="nv-m-l2">${esc(h.what)}</span>
        <span class="nv-m-l3"><span class="nv-m-sev">${esc((SEV_WORD[sev] || sev).toUpperCase())}</span><span class="nv-m-val" data-nochips>${esc(rowValue(a))}</span>${contacts ? `<span class="nv-m-dim">· ${contacts}</span>` : ''}${a.demo ? '<span class="nv-m-demo">DEMO</span>' : ''}${state}</span>
      </a>
      ${selecting ? '' : `<button type="button" class="m-more nv-m-more" aria-haspopup="menu" aria-label="Actions for this alert">${DOTS}</button>`}
    </div></div>`;
}

export function groupHtml(g, open, group) {
  const label = group === 'device' ? (g.key ? dname(g.key, g.rows[0]) : 'From outside') : group === 'indicator' ? g.key : g.key;
  return `<button type="button" class="nv-m-grp nv-m-s-${esc(g.sev)}" data-g="${esc(g.key)}" aria-expanded="${open}">
    <span class="nv-m-grp-t"${group === 'indicator' ? ' data-nochips' : ''}>${esc(label)}</span><span class="nv-m-grp-n">${plural(g.rows.length, 'alert')} · ${esc(SEV_WORD[g.sev])}</span></button>`;
}

export function skeletonRows(n = 5) {
  return `<div class="nv-m-skel" aria-busy="true" aria-label="Loading alerts">${'<span class="m-skel m-skel-row"></span>'.repeat(n)}</div>`;
}

// The Filter sheet (full screen): status, severity, group by and the text filter, with a pinned "Show N alerts".
// count(draft) -> Promise<number> answers for the draft. Closing it any other way applies nothing.
export function openFilterSheet(st, { count, apply }) {
  const draft = { status: st.status, sevs: new Set(st.sevs), group: st.group, q: st.q };
  const body = document.createElement('div');
  body.className = 'nv-m-filter';
  const seg = (k, opts, on) => `<div class="nv-m-fseg" role="group" data-fk="${k}">${opts.map(([v, l]) => `<button type="button" class="m-chip" data-fv="${esc(v)}" aria-pressed="${on(v)}">${esc(l)}</button>`).join('')}</div>`;
  const paint = () => {
    body.innerHTML = `
      <h3 class="nv-m-fh">Status</h3>${seg('status', STATUS_ORDER.map((s) => [s, STATUS_WORD[s]]), (v) => v === draft.status)}
      <h3 class="nv-m-fh">Severity</h3>${seg('sev', SEV.map((s) => [s, SEV_WORD[s]]), (v) => draft.sevs.has(v))}
      <h3 class="nv-m-fh">Show as</h3>${seg('group', Object.entries(GROUP_WORD), (v) => v === draft.group)}
      <h3 class="nv-m-fh"><label for="nv-m-fq">Contains</label></h3>
      <input id="nv-m-fq" class="nv-m-fq" type="search" value="${esc(draft.q)}" placeholder="Device, address, malware or list" autocomplete="off">
      <p class="nv-m-flink"><a href="#network/alerts/rules">Expected traffic rules ›</a></p>`;
    body.querySelector('.nv-m-fq').addEventListener('input', (e) => { draft.q = e.target.value.trim(); recount(); });
  };
  const show = document.createElement('button');
  show.type = 'button';
  show.className = 'm-btn m-btn-primary';
  show.textContent = 'Show alerts';
  let seq = 0, t = null;
  const recount = () => {
    clearTimeout(t);
    t = setTimeout(async () => {
      const my = ++seq;
      try { const n = await count(draft); if (my === seq) show.textContent = `Show ${plural(n, 'alert')}`; } catch { if (my === seq) show.textContent = 'Show alerts'; }
    }, 200);
  };
  body.addEventListener('click', (e) => {
    const b = e.target.closest('[data-fv]'); if (!b) return;
    const k = b.parentElement.dataset.fk, v = b.dataset.fv;
    if (k === 'status') draft.status = v;
    if (k === 'group') draft.group = v;
    if (k === 'sev') { if (draft.sevs.has(v)) draft.sevs.delete(v); else draft.sevs.add(v); if (!draft.sevs.size) draft.sevs = new Set(SEV); }
    b.parentElement.querySelectorAll('[data-fv]').forEach((x) => x.setAttribute('aria-pressed', k === 'sev' ? String(draft.sevs.has(x.dataset.fv)) : String(x.dataset.fv === (k === 'status' ? draft.status : draft.group))));
    recount();
  });
  paint();
  const h = openSheet({ id: 'nv-filter', title: 'Filter alerts', size: 'full', body, footer: [show] });
  show.addEventListener('click', () => { apply(draft); h.close('close'); });
  recount();
  return h;
}

// ---------------------------------------------------------------- the detail
export function devChip(d) {
  if (!d.device) return '';
  const dv = S.devices.get(d.device) || {};
  const sid = shortId(dv.id ? dv : { id: d.device, mac: d.evidence?.device?.mac, ips: d.evidence?.device?.home_ips });
  const name = dname(d.device, d);
  return `<a class="nv-m-devchip" href="#network/devices/${encodeURIComponent(d.device)}" data-nochips><span>${esc(name)}${sid && sid !== name ? ` · ${esc(sid)}` : ''}</span><span aria-hidden="true">›</span></a>`;
}

// "Mark as expected" (#network/alerts/<id>/expected, a routed sheet). The narrowest scope is chosen; scopes that
// cover every device sit behind "More scopes" (and, on a high alert, a second disclosure); 30 days by default.
export function expectSheet(d, { save, route }) {
  const k = kindOf(d), noun = indicatorNoun(d), dev = d.device ? dname(d.device, d) : null;
  const sig = noun === 'signature' ? sigName(d) : null;
  // a signature by its name; one with no name is "this intrusion signature", never its raw "sid:…" id
  const what = sig ? `“${sig}”` : noun === 'signature' ? 'this intrusion signature' : d.indicator;
  const kindWord = kindWordOf(k.kindLabel);   // "intrusion" for "Intrusion alert": "every intrusion alert", not "alert alert"
  const high = d.severity === 'high';
  const talk = noun === 'signature' ? 'setting off this signature' : noun === 'vulnerability' ? 'reporting this vulnerability' : noun === 'domain' ? 'looking up this name' : 'talking to this address';
  const near = [
    dev ? { v: 'device_indicator', t: `Only ${dev} ${talk}`, s: `${dev} → ${what}`, mono: true } : null,
    dev ? { v: 'device_kind', t: `Every ${kindWord} alert from ${dev}`, s: k.fam === 'ids' ? 'Covers its other signatures too' : 'Covers new addresses of the same kind' } : null,
  ].filter(Boolean);
  const wide = [{ v: 'indicator', t: `Any device ${talk}`, s: `${noun === 'signature' && !sig ? 'This intrusion signature' : what}, whichever device it is` }];
  const st = { scope: (near[0] || wide[0]).v, days: 30, more: !near.length, sure: !near.length || !high };
  const body = document.createElement('div');
  body.className = 'nv-m-exp';
  const opt = (o) => `<label class="nv-m-opt"><input type="radio" name="nv-m-scope" value="${o.v}" ${st.scope === o.v ? 'checked' : ''}><span><span class="nv-m-opt-t">${esc(o.t)}</span><span class="nv-m-opt-s${o.mono ? ' mono' : ''}" data-nochips>${esc(o.s)}</span></span></label>`;
  const caution = () => {
    const until = st.days ? `for ${st.days} days` : 'until you remove the rule';
    // what the chosen scope hides: every alert of the kind only for the kind scope, else this signature or address
    if (st.scope === 'device_kind') return `This hides future ${kindWord} alerts from ${dev} ${until}.`;
    const about = noun === 'signature' ? (sig ? `the signature ${what}` : 'this intrusion signature') : `${what}`;
    return `This hides future alerts about ${about} from ${st.scope === 'indicator' ? 'any of your devices' : dev} ${until}.`;
  };
  const paint = () => {
    body.innerHTML = `<p class="nv-m-exp-i">Matching traffic stops raising alerts until the rule ends. The alerts stay listed under Expected.</p>
      <fieldset class="nv-m-scopes"><legend class="nv-m-vh">Which traffic</legend>${near.map(opt).join('')}
      ${st.more && st.sure ? wide.map(opt).join('') : ''}</fieldset>
      ${!st.more ? '<button type="button" class="nv-m-disc" data-more aria-expanded="false">More scopes (cover every device)</button>'
        : !st.sure ? `<div class="nv-m-wide"><p>A scope for every device would also hide this ${esc(kindWord)} alert on devices that are not ${esc(dev)}.</p>
          <button type="button" class="nv-m-disc" data-sure aria-expanded="false">Show scopes that cover every device</button></div>` : ''}
      <h3 class="nv-m-fh">For how long</h3>
      <div class="nv-m-fseg" role="group" aria-label="For how long">${[[7, '7 days'], [30, '30 days'], [0, 'Always']].map(([v, l]) => `<button type="button" class="m-chip" data-days="${v}" aria-pressed="${st.days === v}">${l}</button>`).join('')}</div>
      ${st.days ? '' : '<p class="nv-m-exp-n">You can remove it in Expected traffic.</p>'}
      ${high ? `<p class="nv-m-caution" role="note">${esc(caution())}</p>` : ''}`;
  };
  body.addEventListener('change', (e) => { if (e.target.name === 'nv-m-scope') { st.scope = e.target.value; if (high) body.querySelector('.nv-m-caution').textContent = caution(); } });
  body.addEventListener('click', (e) => {
    const b = e.target.closest('[data-more], [data-sure], [data-days]'); if (!b) return;
    if (b.dataset.more != null) st.more = true;
    if (b.dataset.sure != null) st.sure = true;
    if (b.dataset.days != null) st.days = +b.dataset.days;
    paint();
    (b.dataset.days != null ? body.querySelector(`[data-days="${st.days}"]`) : body.querySelector('[data-sure]') || body.querySelector('input[value="indicator"]'))?.focus({ preventScroll: true });
  });
  paint();
  const cancel = document.createElement('button');
  cancel.type = 'button'; cancel.className = 'm-btn'; cancel.textContent = 'Cancel';
  const ok = document.createElement('button');
  ok.type = 'button'; ok.className = 'm-btn m-btn-primary'; ok.textContent = 'Save rule';
  const h = openSheet({ id: 'nv-expect', title: 'Mark as expected', body, footer: [cancel, ok], route });
  cancel.addEventListener('click', () => h.close('close'));
  ok.addEventListener('click', async () => {
    ok.disabled = true; h.setBusy(true);
    try { await save({ scope: st.scope, days: st.days }); h.close('close'); }
    catch { ok.disabled = false; h.setBusy(false); }
  });
  return h;
}

// Network → Alerts: incidents (alerts of one device + indicator + kind joined across days), a flat list by default,
// each with a plain headline, what to do, why this severity, and the evidence chain under it. "This is expected"
// rules hide repeating harmless traffic. Contract: okf/data/netlog.md#incidents-and-expected-traffic
import { S, SEV, SEVTAG, CONF, onChange, timeParams, v, devLink, tierOf, bytes, ts, tsShort, dur, durWords,
  esc, fmt, toast, jsonHtml, toExplorer, emit, CATS, Z, day, escCloses, hsCue } from './common.js';
import { ago, shortcutBlocked, safeUrl } from '../../core/util.js';
import { SEV as SEVCOL } from '../../core/util.js';   // the one severity map
import { withRange } from '../../core/range.js';
import * as T from '../../core/time.js';
import { questionsHtml, runQuestions, huntPivot, indicatorProfile } from './questions.js';
import { mountNotes } from '../../core/notes.js';
import { incidentSummary } from '../../core/summary.js';
import { headline, whySeverity, whatToDo, whatHappened, kindOf, dname, homeNames, srcName, scopeText, remoteOf, sinkLine, rowValue, anyKind, indicatorNoun, serverWhy, sigName, sigQuoted, spanText } from './alert-text.js';
import { emptyState, errorState, loadingState, stateAct } from '../../core/view.js';
import { demoOnly, noRealText } from '../../core/alerts-badge.js';
import { openSummary } from '../../core/summary.js';
import { isPhone, DOTS, openRangeSheet, copyText } from './m.js';
import * as M from './m-alerts.js';
import { swipeRow } from '../../core/swipe.js';
import { undoToast } from '../../core/undo.js';
import { actionSheet } from '../../core/sheet.js';
import { openNoteSheet } from '../../core/note-sheet.js';
import { pushPage, back as pageBack, setPhoneTitle, setActionBar, afterRender } from '../../core/page.js';
import { LS } from '../../core/prefs.js';
const STATUS = [['new', 'New'], ['ack', 'Acknowledged'], ['dismissed', 'Dismissed'], ['expected', 'Expected'], ['', 'All']];
const GROUPS = [['none', 'Flat'], ['device', 'Device'], ['indicator', 'Indicator'], ['rule', 'Rule']];
const GKEY = 'nd.network.alerts.group';
const bell = (s) => `<span class="nv-bell" style="background:${SEVCOL[s] || '#6b727d'}" title="${esc(s)}"></span>`;
const ST_WORD = { new: 'new', ack: 'acknowledged', dismissed: 'dismissed', expected: 'expected' };
const stTag = (s) => `<span class="nv-st ${s}">${ST_WORD[s] || s}</span>`;
const demoChip = '<span class="al-chip al-demo" title="Demo data: made up to show how alerts work. Not counted in “needs you”. Remove it in Network › Connect logs.">DEMO</span>';
const laterChip = (a) => `<span class="al-chip al-later" title="${esc(laterLine(a))}">Found later</span>`;
const laterLine = (a) => { const f = a.evidence?.found_later; return f ? `A list added this address on ${ts(f.listed_at, false)} ${Z()}, after these logs were imported (${ts(f.imported_at, false)} ${Z()}). Night Desk re-checked your older logs and found the contact.` : ''; };
const groupKey = (a, g) => (g === 'device' ? (a.device || '') : g === 'indicator' ? (a.indicator || '') : g === 'rule' ? kindOf(a).kindLabel : '');
const SR = { high: 0, medium: 1, low: 2, info: 3 };
const pl = (n, w) => `${fmt(n)} ${w}${n === 1 ? '' : /(s|sh|ch|x)$/.test(w) ? 'es' : 's'}`;
// "Why high: …": the sentence without its leading severity word
const whyText = (d) => { const t = whySeverity(d).replace(/^(High|Medium|Low|Info)[:,]\s*/, ''); return t.charAt(0).toUpperCase() + t.slice(1); };
const stepHtml = (s0) => s0.others ? '<li data-others hidden></li>' : `<li>${s0.t}${s0.copy ? ` <button class="chip al-copy" data-copy="${esc(s0.copy)}" title="Copy the address for a router block rule">Copy</button>` : ''}${s0.link && safeUrl(s0.link) ? ` <a href="${esc(safeUrl(s0.link))}" target="_blank" rel="noopener">Read about it ›</a>` : ''}</li>`;

export function mount(el, ctx) {
  const { api } = ctx;
  const st = {
    group: LS.get(GKEY, 'none'), status: 'new', sevs: new Set(SEV), q: '',
    rows: [], open: new Set(), sel: null, detail: null, visible: false, stale: true, checked: new Set(),
    byId: new Map(), count: null, summ: null, seq: 0, side: null, rules: null,
  };
  el.innerHTML = `
    <div class="nv-al">
      <div class="nv-al-main">
        <div class="al-head"><span class="al-need"></span><button class="chip" data-act="rules" title="Traffic you marked as expected: list, edit or delete the rules">Expected traffic</button></div>
        <div class="nv-bar">
          <div class="nv-seg" data-k="group" title="Show as a flat list or grouped"><span class="nv-seg-l mono">view</span>${GROUPS.map(([k, l]) => `<button data-v="${k}">${l}</button>`).join('')}</div>
          <div class="nv-seg" data-k="status">${STATUS.map(([k, l]) => `<button data-v="${k}">${l}<span class="n"></span></button>`).join('')}</div>
          <div class="nv-sevc">${SEV.map((s) => `<button class="chip" data-sev="${s}"><i class="sw" style="background:${SEVCOL[s]}"></i>${s}<span class="n"></span></button>`).join('')}</div>
          <label class="nv-in"><svg class="i"><use href="#i-search"/></svg><input placeholder="Filter: device, address, malware, list…" data-k="q" aria-label="Filter alerts"></label>
          <span class="nv-total mono"></span>
        </div>
        <div class="nv-bulk" hidden><span class="mono"></span><button class="chip" data-bulk="ack">Acknowledge</button><button class="chip" data-bulk="dismissed">Dismiss</button><button class="chip" data-bulk="new">Reopen</button><button class="chip" data-bulk="clear">Clear</button></div>
        <div class="nv-al-list"></div>
      </div>
      <aside class="nv-al-side"><div class="nv-al-detail"></div></aside>
    </div>`;
  const $ = (s) => el.querySelector(s);
  const list = $('.nv-al-list');
  const det = $('.nv-al-detail');
  const side = $('.nv-al-side');
  // A closed detail is out of the Tab order and the accessibility tree (inert), not just squeezed to 0 px (B2-06)
  const sideOpen = (on) => { el.classList.toggle('has-detail', on); side.inert = !on; };
  sideOpen(false);

  function paintBar() {
    el.querySelectorAll('.nv-seg[data-k="group"] button').forEach((b) => b.classList.toggle('on', b.dataset.v === st.group));
    el.querySelectorAll('.nv-seg[data-k="status"] button').forEach((b) => b.classList.toggle('on', b.dataset.v === st.status));
    el.querySelectorAll('.nv-sevc [data-sev]').forEach((b) => b.classList.toggle('on', st.sevs.has(b.dataset.sev)));
  }

  function params(skip) {
    const p = { ...timeParams() };
    if (st.q) p.q = st.q;
    if (skip !== 'status' && st.status) p.status = st.status;
    if (skip !== 'severity' && st.sevs.size < SEV.length) p.severity = [...st.sevs].join(',');
    return p;
  }

  // The one count (okf/data/netlog.md#the-needs-you-count): the badge and the Network header show the same number.
  function paintNeed() {
    const c = st.count; if (!c) return;
    const extra = [c.low + c.info ? `${fmt(c.low + c.info)} low or info` : '', c.demo ? `${fmt(c.demo)} demo` : '', c.expected ? `${fmt(c.expected)} expected` : ''].filter(Boolean);
    const demo = demoOnly(c);   // only demo alerts open: never "Nothing needs you" above demo rows
    if (demo) extra.splice(extra.indexOf(`${fmt(c.demo)} demo`), 1);   // the headline already counts them
    const inR = st.inR || '';
    $('.al-need').innerHTML = `${c.needs_you ? `<b class="al-need-n hot">${fmt(c.needs_you)} need${c.needs_you === 1 ? 's' : ''} you${inR}</b>` : demo ? `<b class="al-need-n finisha-demo-t">${esc(noRealText(c))}${inR}</b>` : `<b class="al-need-n">Nothing needs you${inR}</b>`}<span class="al-sub">${c.needs_you ? 'untriaged high and medium' : demo ? 'the open alerts below are made-up demo data' : 'no untriaged high or medium alerts'}${extra.length ? ` · ${extra.join(' · ')} not counted` : ''}</span>`;
  }

  async function load() {
    st.stale = false;
    const my = ++st.seq;
    if (!list.children.length || list.querySelector('.vs')) list.innerHTML = isPhone() ? M.skeletonRows() : loadingState('Loading alerts…', { size: 'sm' });
    try {
      const ranged = !!(S.range.h || S.range.from != null);
      const [count, bySt, bySev, rows, rcount] = await Promise.all([
        api.get('/api/netlog/alerts/count'),
        api.get('/api/netlog/incidents/summary', params('status')),
        api.get('/api/netlog/incidents/summary', params('severity')),
        api.get('/api/netlog/incidents', { ...params(), limit: 1000 }),
        // the need line counts the selected range, like the chips beside it and the Network header (all time on All)
        ranged ? api.get('/api/netlog/alerts/count', timeParams()) : null,
      ]);
      if (my !== st.seq) return;
      st.count = rcount || count; st.inR = ranged ? ' in this range' : ''; st.rows = rows;
      st.everything = count.incidents;
      rows.forEach((a) => { st.byId.set(a.id, a); a.alerts?.forEach((x) => st.byId.set(x, a)); });
      const cs = { ...bySt.state, '': bySt.total };
      st.stateCounts = cs;
      el.querySelectorAll('.nv-seg[data-k="status"] button').forEach((b) => (b.querySelector('.n').textContent = fmt(cs[b.dataset.v] || 0)));
      el.querySelectorAll('.nv-sevc [data-sev]').forEach((b) => (b.querySelector('.n').textContent = fmt(bySev.severity[b.dataset.sev] || 0)));
      st.demoIn = bySev.demo_new > 0;   // the severity chips count demo in: the total line says so (Overview counts it apart)
      paintNeed();
      render();
      checkGone();
    } catch (e) {
      if (my !== st.seq) return;
      list.innerHTML = errorState({ retry: load, title: isPhone() ? "Couldn't load alerts" : "Couldn't load the alerts", why: serverWhy(e), err: e.message, size: 'sm' });
      // the count is unknown now: the phone header shows no all-clear (m-alerts.js headHtml)
      if (isPhone()) { st.count = null; phoneHead(); afterRender('network'); }
    }
  }

  // The open alert may have gone since it was opened (the demo removed from another tab, its logs deleted): when the
  // list reloads and it is not in it, ask the server; a 404 turns the detail into "This alert no longer exists" (B2-05)
  function checkGone() {
    const d = st.detail; if (!d || st.side !== 'alert') return;
    const iid = d.incident?.id || d.id;
    if (st.rows.some((a) => a.id === iid)) return;
    // by its indicator over all time and every status (a list read, so a removed alert is no 404 in the console)
    const ids = new Set([iid, d.id, ...(d.incident?.alerts || [])]);
    api.get('/api/netlog/incidents', { indicator: d.indicator, limit: 1000 }).then((rows) => {
      if (st.detail === d && !rows.some((a) => ids.has(a.id) || (a.alerts || []).some((x) => ids.has(x)))) renderGone();
    }).catch(() => {});
  }
  function goneHtml() {
    return `<div class="nv-dh"><button class="icon-btn nv-back" data-act="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button>${emptyState({ title: 'This alert no longer exists', why: 'Its logs or the demo data were removed, so there is nothing left to acknowledge or dismiss.', size: 'sm' })}</div>`;
  }
  function renderGone() {
    st.detail = null; st.form = null;
    if (isPhone()) { phoneGone({ status: 404 }); return; }
    det.innerHTML = goneHtml();
    det.querySelector('[data-act="close"]').onclick = () => closeSide(true, true);
  }

  function render() {
    paintBar();
    phoneHead();
    const n = st.rows.length;
    $('.nv-total').innerHTML = `showing ${pl(n, 'incident')}${st.status ? ` · ${esc(STATUS.find((x) => x[0] === st.status)[1].toLowerCase())}` : ''}${st.demoIn ? ' · <span class="fnet-cap" title="The counts on these chips include made-up demo alerts; Network › Overview counts them apart">demo included</span>' : ''}`;
    if (!st.everything) {
      list.innerHTML = S.summary?.rows ? emptyState({ title: 'No alerts', why: 'Nothing in your logs matched a threat list while it was listed.' })
        : emptyState({ title: 'No alerts yet', why: 'Connect your Zeek, Suricata or DNS logs, or load the demo, to start matching.', act: stateAct('Connect logs', { href: '#network/import' }) });
      return;
    }
    if (!n) {
      const what = st.status === 'expected' ? 'Nothing is marked as expected in this range.' : `No ${st.status ? ST_WORD[st.status] + ' ' : ''}alerts at the selected severities in this time range.`;
      list.innerHTML = emptyState({ title: 'Nothing here', why: what });
      if (isPhone()) afterRender('network');
      return;
    }
    if (isPhone()) { renderPhone(); return; }
    if (st.group === 'none') {
      list.innerHTML = `<div class="nv-tbl nv-at">${head(false)}${st.rows.map((a) => incRow(a)).join('')}</div>`;
    } else {
      const groups = new Map();
      for (const a of st.rows) { const k = groupKey(a, st.group); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(a); }
      const gs = [...groups.entries()].map(([k, xs]) => ({ key: k, rows: xs, sev: xs.reduce((m, x) => (SR[x.severity] < SR[m] ? x.severity : m), 'info'), last: xs.reduce((m, x) => (x.last_ts > m ? x.last_ts : m), '') }))
        .sort((a, b) => SR[a.sev] - SR[b.sev] || b.rows.length - a.rows.length || (b.last > a.last ? 1 : -1));
      list.innerHTML = `<div class="nv-tbl nv-at">${head(true)}${gs.map((g) => groupRow(g) + (st.open.has(g.key) ? `<div class="nv-gk">${g.rows.map((a) => incRow(a)).join('')}</div>` : '')).join('')}</div>`;
    }
    if (st.sel) list.querySelector(`[data-id="${CSS.escape(st.sel)}"]`)?.classList.add('sel');
  }

  function head(grouped) {
    return `<div class="nv-th"><span></span><span></span><span class="r">${grouped ? 'Alerts' : 'Contacts'}</span><span>${grouped ? GROUPS.find((g) => g[0] === st.group)[1] : 'What happened'}</span><span>Severity</span><span>${grouped ? 'Covers' : 'Span'}</span><span>Last seen</span><span></span></div>`;
  }
  function groupLabel(g) {
    if (st.group === 'device') return g.key ? `<b data-nochips>${esc(dname(g.key, g.rows[0]))}</b>` : '<b>From outside</b> <span class="nv-dim">(inbound, several devices)</span>';
    if (st.group === 'indicator') return `<span class="mono">${esc(g.key)}</span> <span class="nv-dim">${esc(kindOf(g.rows[0]).kindLabel)}</span>`;
    return `<b>${esc(g.key)}</b>`;
  }
  function groupRow(g) {
    const devs = new Set(g.rows.map((a) => a.device).filter(Boolean)).size, inds = new Set(g.rows.map((a) => a.indicator)).size;
    const scope = st.group === 'device' ? pl(inds, 'address') : st.group === 'indicator' ? pl(devs, 'device') : `${pl(devs, 'device')} · ${pl(inds, 'address')}`;
    const ids = g.rows.map((a) => a.id).join(',');
    // rows are not role=button (they hold the triage buttons): the label is the button that folds the group (S2-15)
    return `<div class="nv-tr nv-grp ${st.open.has(g.key) ? 'open' : ''}" data-g="${esc(g.key)}">
      <span class="nv-chev">›</span>${bell(g.sev)}
      <span class="r mono nv-cnt">${fmt(g.rows.length)}</span>
      <button type="button" class="nv-gl fnet-open" aria-expanded="${st.open.has(g.key)}" title="${esc(`${g.sev}: ${pl(g.rows.length, 'alert')}, ${scope}`)}">${groupLabel(g)}</button>
      <span><span class="tag ${SEVTAG[g.sev]}">${g.sev}</span></span>
      <span class="mono nv-dim nv-scope">${scope}</span>
      <span class="mono nv-dim" title="${ts(g.last)} ${Z()}">${ago(g.last)}</span>
      <span class="nv-acts"><button class="icon-btn" data-gact="ack" data-ids="${esc(ids)}" title="Acknowledge all ${g.rows.length}" aria-label="Acknowledge all">✓</button><button class="icon-btn" data-gact="dismissed" data-ids="${esc(ids)}" title="Dismiss all ${g.rows.length}" aria-label="Dismiss all">✕</button></span>
    </div>`;
  }
  function incRow(a) {
    const h = headline(a), k = kindOf(a);
    const chips = [a.demo ? demoChip : '', a.evidence?.found_later ? laterChip(a) : '', a.state !== 'new' ? stTag(a.state) : ''].join('');
    const span = spanText(a);
    // not role=button (it holds a checkbox and triage buttons): the headline is the button that opens it
    return `<div class="nv-tr nv-arow" data-id="${esc(a.id)}" title="${esc(k.kindLabel)}${a.evidence?.indicator?.meta?.malware ? ' · ' + esc(a.evidence.indicator.meta.malware) : ''}">
      <label class="nv-ck" title="Select"><input type="checkbox" aria-label="Select" ${st.checked.has(a.id) ? 'checked' : ''}></label>${bell(a.severity)}
      <span class="r mono">${fmt(a.count)}</span>
      <button type="button" class="nv-gl al-line fnet-open" aria-label="${esc(`${a.severity}: ${h.lead} ${h.what} ${rowValue(a)}${a.demo ? ' (demo)' : ''}`)}"><b>${esc(h.lead)}</b> <span class="al-what">${esc(h.what)}</span><span class="al-ind mono">${esc(rowValue(a))}${(a.sources || []).length > 1 ? ` · ${a.sources.length} lists` : ''}</span>${chips}</button>
      <span><span class="tag ${SEVTAG[a.severity]}">${a.severity}</span></span>
      <span class="mono nv-dim" title="${ts(a.ts)} → ${ts(a.last_ts)} ${Z()}">${span}</span>
      <span class="mono nv-dim" title="${ts(a.last_ts)} ${Z()}">${ago(a.last_ts)}</span>
      <span class="nv-acts">${a.status !== 'ack' ? '<button class="icon-btn" data-aact="ack" title="Acknowledge (a): I have seen this" aria-label="Acknowledge">✓</button>' : ''}${a.status !== 'dismissed' ? '<button class="icon-btn" data-aact="dismissed" title="Dismiss (d): a false alarm" aria-label="Dismiss">✕</button>' : '<button class="icon-btn" data-aact="new" title="Reopen" aria-label="Reopen">↺</button>'}</span>
    </div>`;
  }

  async function setStatus(ids, status, { quiet = false } = {}) {
    if (!ids.length) return false;
    try {
      const r = await api.post('/api/netlog/incidents/status', { ids, status });
      // none of them exists any more (the demo or its logs were removed meanwhile): never a "done" toast (B2-05)
      if (r.updated === 0) {
        toast(ids.length === 1 ? 'This alert no longer exists: nothing was changed' : 'These alerts no longer exist: nothing was changed', true);
        if (st.detail && ids.some((i) => i === st.sel || (st.detail.incident?.alerts || [st.detail.id]).includes(i))) renderGone();
        st.checked.clear(); paintBulk(); load(); return false;
      }
      if (st.detail && ids.some((i) => (st.detail.incident?.alerts || [st.detail.id]).includes(i) || i === st.sel)) { st.detail.incident = { ...(st.detail.incident || {}), status, state: st.detail.incident?.suppressed ? 'expected' : status }; st.detail.status = status; renderDetail(); }
      // one row in the list is one alert to the owner (the days it spans are its storage, not news): "Alert acknowledged"
      if (!quiet) toast(`${ids.length === 1 ? 'Alert' : `${fmt(ids.length)} alerts`} ${status === 'ack' ? 'acknowledged' : status === 'dismissed' ? 'dismissed' : 'reopened'}`);
      st.checked.clear(); paintBulk();
      ctx.refreshSummary();
      load();
      emit('alerts');
      return true;
    } catch (e) { toast(e.message, true); return false; }
  }
  function paintBulk() {
    $('.nv-bulk').hidden = !st.checked.size;
    $('.nv-bulk .mono').textContent = `${pl(st.checked.size, 'alert')} selected`;
  }

  // ------------------------------------------------------------ deep links: #network/alerts/<id> and #network/alerts/rules
  // the ?range= the Network header adds is not part of the id, and a new entry keeps it (core/range.js)
  // #network/alerts/<id>/expected is "Mark as expected" over that alert (a routed sheet on a phone, the form at desktop)
  const hashParts = () => {
    const t = location.hash.slice(1).split('?')[0].split('/');
    if (t[0] !== 'network' || t[1] !== 'alerts') return null;
    const rest = t.slice(2), sub = rest.length > 1 && rest[rest.length - 1] === 'expected' ? 'expected' : null;
    return { id: decodeURIComponent((sub ? rest.slice(0, -1) : rest).join('/')), sub };
  };
  const hashArg = () => { const p = hashParts(); return p ? p.id : null; };
  // push: true adds an entry when the list is in the URL (moving from one alert to the next replaces it), and
  // marks that entry (history.state.ndFromList): closing that detail then goes BACK to the list entry under it, so Back never reopens
  // what was closed and triaging ten alerts leaves no trail of entries. A detail from a link or a reload has no list
  // entry under it: closing replaces its entry with the list.
  function setHash(arg, push) {
    const h = withRange(arg ? `#network/alerts/${encodeURIComponent(arg)}` : '#network/alerts', S.range);
    if (location.hash === h) return;
    if (push && !hashArg() && isPhone()) { pushPage(h); return; }   // a phone: a page of its own (core/page.js)
    if (push && !hashArg()) history.pushState({ ndFromList: 'alerts', from: location.hash }, '', h);
    else history.replaceState(arg ? history.state : null, '', h);   // alert to alert keeps the mark
  }
  function closeHash() {
    // back only when the list entry under it is the list as it is now: if the range changed while the detail was
    // open, going back would bring the old range back, so the detail's entry becomes the list with the current range
    const want = withRange('#network/alerts', S.range);
    if (history.state?.ndFromList === 'alerts' && history.state.from === want) history.back();
    else history.replaceState(null, '', want);
  }
  function closeSide(nav = true, refocus = false) {
    const was = st.sel;
    st.sel = null; st.detail = null; st.side = null; st.focus = false;
    sideOpen(false);
    list.querySelectorAll('.sel').forEach((r) => { r.classList.remove('sel'); r.removeAttribute('aria-current'); });
    if (isPhone()) {
      // a phone: the list is the page again (Back, or ‹ Alerts); its scroll comes back from core/page.js
      if (nav && hashArg()) pageBack(withRange('#network/alerts', S.range));
      if (refocus) list.querySelector(was ? `.nv-m-arow[data-id="${CSS.escape(was)}"] .nv-m-amain` : '.nv-m-amain')?.focus({ preventScroll: true });
      afterRender('network');
      return;
    }
    if (nav && hashArg()) closeHash();
    // back to the row the detail was opened from (Esc, Close), so a keyboard user keeps their place in the list
    if (refocus) (list.querySelector(was ? `.nv-arow[data-id="${CSS.escape(was)}"] .fnet-open` : null) || list.querySelector('.nv-arow .fnet-open, .nv-grp .fnet-open'))?.focus({ preventScroll: false });
  }
  // Opening a detail by click, Enter or a link moves focus to its heading, which names the alert for a screen reader.
  // The wide-screen auto-open and j/k do not: they must not pull focus out of the list.
  function focusDetail() {
    if (!st.focus) return;
    st.focus = false;
    const h = det.querySelector('h2') || det.querySelector('[data-act="close"]');
    if (!h) return;
    if (h.tagName === 'H2' && !h.hasAttribute('tabindex')) h.setAttribute('tabindex', '-1');
    h.focus({ preventScroll: true });
  }
  window.addEventListener('hashchange', () => {
    if (!st.visible) return;
    const arg = hashArg();
    if (arg === 'rules') { if (st.side !== 'rules') openRules(false); }
    else if (arg) { if (arg !== st.sel && !(st.detail?.incident?.alerts || []).includes(arg)) select(arg, false); else { phoneChrome(); maybeExpect(); } }
    // Back closed it: focus returns to the row it was opened from, not left on the hidden heading (B2-06)
    else if (el.classList.contains('has-detail')) { const a = document.activeElement; closeSide(false, !a || a === document.body || side.contains(a)); }
  });

  // ------------------------------------------------------------ detail
  async function select(id, nav = true, focus = false) {
    st.sel = id; st.side = 'alert'; st.focus = focus;
    list.querySelectorAll('.nv-arow').forEach((r) => { const on = r.dataset.id === id; r.classList.toggle('sel', on); if (on) r.setAttribute('aria-current', 'true'); else r.removeAttribute('aria-current'); });
    sideOpen(true);
    det.innerHTML = loadingState('Loading evidence…', { size: 'sm' });
    try {
      let d = await api.get(`/api/netlog/alerts/${encodeURIComponent(id)}`);
      if (st.sel !== id) return;
      // show the incident's lead (its worst alert), so the kind, list and "why" describe the same alert
      if (d.incident?.lead && d.incident.lead !== d.id) { d = await api.get(`/api/netlog/alerts/${encodeURIComponent(d.incident.lead)}`); if (st.sel !== id) return; }
      // the incident's own row (its first alert) is the one the list and the link use
      const iid = d.incident?.id || id;
      st.sel = iid;
      list.querySelectorAll('.nv-arow').forEach((r) => r.classList.toggle('sel', r.dataset.id === iid));
      st.detail = d;
      st.dtab = st.dtab || 'questions';
      st.lookup = null; st.form = null;
      if (nav) setHash(iid, true);
      renderDetail();
      focusDetail();
      maybeExpect();
    } catch (e) {
      if (st.sel !== id) return;
      st.detail = null;
      if (isPhone()) { phoneGone(e); return; }
      det.innerHTML = e.status === 404 || /not found|no such/i.test(e.message) ? goneHtml()
        : `<div class="nv-dh"><button class="icon-btn nv-back" data-act="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button>${errorState({ retry: () => select(id, false), title: "Couldn't open this alert", why: serverWhy(e), err: e.message, size: 'sm' })}</div>`;
      det.querySelector('[data-act="close"]').onclick = () => closeSide(true, true); focusDetail();
    }
  }

  // SVG: listing interval(s) against contact times.
  function timeline(d) {
    const ivs = (d.intervals || []).map((i) => ({ s: Date.parse(i.start), e: i.end ? Date.parse(i.end) : null }));
    const contacts = (d.rows || []).map((r) => Date.parse(r.ts)).filter((x) => !isNaN(x));
    if (!contacts.length) contacts.push(Date.parse(d.ts));
    const now = Date.now();
    let lo = Math.min(...contacts, ...ivs.map((i) => i.s)), hi = Math.max(...contacts, ...ivs.map((i) => Math.min(i.e ?? now, now)));
    if (hi - lo < 3600e3) { const c = (hi + lo) / 2; lo = c - 1800e3; hi = c + 1800e3; }
    const pad = (hi - lo) * 0.06; lo -= pad; hi = Math.min(hi + pad, Math.max(now, Math.max(...contacts)));
    const W = Math.round(Math.max(300, Math.min(760, (det.clientWidth || 560) - 54))), L = 10, R = 10, X = (t) => L + ((Math.min(t, hi) - lo) / (hi - lo)) * (W - L - R);
    const col = SEVCOL[d.severity] || '#6b727d';
    const inIv = (t) => ivs.some((i) => t >= i.s && (i.e == null || t < i.e));
    const ticks = [];
    const NT = W < 460 ? 2 : 4;
    // whole labels: "10 Nov 23:32" on spans of a few days, the date alone on longer ones (never a cut "23:3")
    const tick = (t) => (hi - lo > 3 * 86400e3 ? T.date(t) : T.stamp(t));
    for (let k = 0; k <= NT; k++) { const t = lo + ((hi - lo) * k) / NT; ticks.push(`<text x="${X(t)}" y="98" text-anchor="${k === 0 ? 'start' : k === NT ? 'end' : 'middle'}">${k === NT && hi >= now - 60e3 ? 'now' : tick(t)}</text><line x1="${X(t)}" x2="${X(t)}" y1="84" y2="88"/>`); }
    const first = Math.min(...contacts);
    const firstIv = ivs.filter((i) => i.s <= first).sort((a, b) => b.s - a.s)[0] || ivs[0];
    const fx = firstIv ? X(firstIv.s) : 0;
    const right = fx > W * 0.6;
    return `<svg class="nv-ivsvg" viewBox="0 0 ${W} 104" role="img" aria-label="When it was listed, against when your devices made contact">
      <text class="lab" x="${L}" y="9">LISTED BY ${esc(srcName(d.source).toUpperCase())}</text>
      <line class="trk" x1="${L}" x2="${W - R}" y1="23" y2="23"/>
      ${ivs.map((i) => `<rect x="${X(i.s)}" y="16" width="${Math.max(2, X(i.e ?? hi) - X(i.s))}" height="14" rx="2" fill="${col}" fill-opacity=".22" stroke="${col}" stroke-opacity=".7"/>${i.e == null ? `<text class="open" x="${W - R - 4}" y="26.5" text-anchor="end" fill="${col}">still listed ▸</text>` : ''}`).join('')}
      ${firstIv ? `<line x1="${fx}" x2="${fx}" y1="14" y2="76" class="mark" stroke="${col}"/><text class="lab2" x="${right ? fx - 4 : fx + 4}" y="44" text-anchor="${right ? 'end' : 'start'}" fill="${col}">listed ${tsShort(firstIv.s)}</text>` : ''}
      <text class="lab" x="${W - R}" y="56" text-anchor="end">CONTACTS (${contacts.length})</text>
      <line class="trk" x1="${L}" x2="${W - R}" y1="68" y2="68"/>
      ${contacts.map((t) => `<line x1="${X(t)}" x2="${X(t)}" y1="61" y2="75" stroke="${inIv(t) ? col : '#8b93a1'}" stroke-width="2"/>`).join('')}
      <g class="ax"><line x1="${L}" x2="${W - R}" y1="84" y2="84"/>${ticks.join('')}</g>
    </svg>
    <div class="nv-ivleg mono"><span><i style="background:${col}"></i>while listed</span><span><i style="background:#8b93a1"></i>not listed</span>${firstIv && first >= firstIv.s ? `<span>first contact <b>${durWords(first - firstIv.s)}</b> after listing</span>` : firstIv ? `<span>first contact <b>${durWords(firstIv.s - first)}</b> before listing</span>` : ''}</div>`;
  }

  function connRows(rows) {
    if (!rows?.length) return emptyState({ why: 'No log rows.', size: 'inline' });
    return `<div class="nv-crows">${rows.map((r, i) => {
      const detail = r.query ? `${v('q', r.query)}${r.answers?.length ? ` → ${r.answers.slice(0, 3).map((x) => v('ip', x)).join(', ')}` : ''}` : r.server_name ? `name ${v('q', r.server_name)}` : r.host ? `${v('q', r.host)}${esc(r.uri || '')}` : '';
      const icmp = /icmp/i.test(r.proto || '');
      return `<div class="nv-crow" data-i="${i}">
        <div class="nv-crow-h">
          <span class="nv-chev">›</span>
          <span class="mono nv-dim">${tsShort(r.ts)}</span>
          <span class="tag">${esc(r.log_type)}</span>
          <span class="mono">${v('ip', r.orig_h)}${icmp ? '' : `<span class="nv-dim">:${esc(r.orig_p ?? '')}</span>`} → ${v('ip', r.resp_h)}${icmp ? ' <span class="nv-dim">ICMP</span>' : `<span class="nv-dim">:</span>${v('port', r.resp_p)}`}</span>
          <span class="mono nv-dim">${esc([icmp ? '' : r.proto, r.service, r.conn_state].filter(Boolean).join(' · '))}${r.orig_bytes != null ? ` · ↑${bytes(r.orig_bytes)} ↓${bytes(r.resp_bytes)}` : ''}</span>
          ${detail ? `<span class="mono nv-crow-d">${detail}</span>` : ''}
          ${r.raw?.sinkhole ? `<span class="tag ${r.raw.blocked ? 'green' : 'amber'}" title="${esc(r.raw.reason || '')}">${r.raw.blocked ? 'blocked' : 'allowed'} by ${r.raw.sinkhole === 'adguard' ? 'AdGuard Home' : 'Pi-hole'}</span>` : ''}
        </div>
        <div class="nv-crow-raw" hidden></div>
      </div>`;
    }).join('')}</div>`;
  }

  function lookValue(d) {
    const k = kindOf(d);
    if (k.fam === 'ids') return remoteOf(d);
    return d.indicator;
  }
  function setDtab(t, value) {
    if (isPhone() && det.querySelector('.nv-m-acc')) { openAcc(t, value); return; }
    st.dtab = t;
    det.querySelectorAll('[data-dtab]').forEach((b) => { b.classList.toggle('on', b.dataset.dtab === t); b.setAttribute('aria-selected', b.dataset.dtab === t); });
    det.querySelectorAll('[data-dpane]').forEach((p) => (p.hidden = p.dataset.dpane !== t));
    hsCue(det.querySelector(`[data-dpane="${t}"]`));   // a hidden pane measured nothing: repaint its sideways cues
    if (t === 'indicator') loadIndicator(value);
  }
  function loadIndicator(value) {
    {
      const val = value || st.lookup || lookValue(st.detail);
      const pane = det.querySelector('[data-dpane="indicator"]');
      if (!val) { pane.innerHTML = emptyState({ why: 'No outside address to look up.', size: 'inline' }); return; }
      if (pane.dataset.v !== val) {
        pane.dataset.v = val;
        const d0 = kindOf(st.detail).fam === 'ids' ? { ...st.detail, indicator: val, evidence: { ...st.detail.evidence, indicator: { kind: 'ip' } } } : st.detail;
        indicatorProfile(pane, val, d0, { ...ctx, toExplorer }, (id) => select(id)).then(() => {
          pane.querySelector('[data-crumb]')?.addEventListener('click', () => { st.lookup = null; setDtab('indicator', lookValue(st.detail)); });
        });
      }
    }
  }
  // An IP looked up from inside the alert opens in the Indicator tab, not a second drawer.
  S.feedHandler = (ip) => {
    if (!st.visible || !st.detail || !el.classList.contains('has-detail')) return false;
    st.lookup = ip === st.detail.indicator ? null : ip;
    setDtab('indicator', ip);
    det.querySelector('.nv-dtabs')?.scrollIntoView({ block: 'start', behavior: 'smooth' });
    return true;
  };

  // A device that stopped checking in (osinthub/netlog/ingest.py): no rows or indicators, so its own layout.
  function silenceDetail(d) {
    const e = d.evidence || {}, snd = e.sender || {}, now = d.sender_now, h = now?.health || {};
    const open = e.state !== 'resolved';
    const last = e.last_checkin ? new Date(e.last_checkin * 1000) : null;
    const cad = e.cadence_s ? `every ${dur(e.cadence_s * 1000)}` : 'on no regular schedule yet';
    const thr = e.threshold_s ? `${dur(e.threshold_s * 1000)} of silence (${e.threshold_from === 'set' ? 'set by you' : `learned from ${e.cadence_n} gaps between check-ins`})` : 'a while';
    const stillNow = open && now ? (h.state === 'silent' ? `still silent, last heard ${ago(new Date(h.last_checkin * 1000))}` : `checking in again (${esc(h.state)})`) : '';
    const end = Date.parse(d.last_ts), start = end - 24 * 3600e3;
    const ticks = (e.checkins || []).map((t) => t * 1000).filter((t) => t >= start && t <= end);
    const pct = (t) => Math.min(100, Math.max(0, (t - start) / (end - start) * 100)).toFixed(2);
    const strip = `<div class="label">Check-ins, last 24 hours</div>
      <div class="nv-sil-strip" title="Each tick is one check-in (a run of hlta-push.sh or an upload)">
        ${last ? `<span class="nv-sil-gap" style="left:${pct(+last)}%;right:${open ? 0 : (100 - pct(end)).toFixed(2)}%"></span>` : ''}
        ${ticks.map((t) => `<i style="left:${pct(t)}%"></i>`).join('')}</div>
      <div class="nv-sil-ax mono nv-dim"><span>${ts(new Date(start), false)}</span><span>${ts(d.last_ts, false)} ${Z()}</span></div>`;
    return `
      <div class="nv-dh">
        <button class="icon-btn nv-back" data-act="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button>
        <div class="nv-dh-tags"><span class="tag ${SEVTAG[d.severity]}">${d.severity}</span><span class="tag">Sensor silent</span>${open ? '' : '<span class="tag green">resumed</span>'}${stTag(d.status)}</div>
        <h2 class="al-h" tabindex="-1">${esc(snd.name || d.indicator)} <span class="nv-dim">${open ? 'stopped sending logs' : 'was silent, then resumed'}</span></h2>
        <p class="al-sev"><b>Why ${esc(d.severity)}:</b> ${esc(whyText(d))}</p>
        <div class="nv-dh-act">
          ${d.status !== 'ack' ? '<button class="src-btn primary" data-st="ack">✓ Acknowledge</button>' : ''}
          ${d.status !== 'dismissed' ? '<button class="src-btn" data-st="dismissed">Dismiss</button>' : ''}
          ${d.status !== 'new' ? '<button class="src-btn" data-st="new">Reopen</button>' : ''}
          <button class="src-btn ghost" data-act="uploads">Sensor settings</button>
        </div>
      </div>
      ${(() => { const st0 = whatToDo(d); return st0.length ? `<div class="al-box al-todo"><div class="label">What to do</div><ol>${st0.map(stepHtml).join('')}</ol></div>` : ''; })()}
      <div class="nv-why"><div class="label">What happened</div>
        <p>${esc(snd.name)} usually checks in <b>${esc(cad)}</b>. Its last check-in was at <b>${last ? ts(last) : 'never'}</b> ${Z()}${open ? `, and nothing has arrived for <b>${dur((e.gap_s || 0) * 1000)}</b>` : `; it came back after <b>${dur((e.gap_s || 0) * 1000)}</b>`}. The alert opens after ${esc(thr)}.</p>
        ${open ? `<p class="nv-why-s">While it is silent, nothing it logs reaches Night Desk: a blind spot, not proof of an attack.${stillNow ? ` <b>Now:</b> ${stillNow}.` : ''}</p>`
          : '<p class="nv-why-s">Logs from the gap can still arrive: the sensor sends finished files and missed lines on its next successful run.</p>'}
      </div>
      <div class="nv-ivbox nv-sil">${strip}</div>
      <div class="nv-pad nv-sil">
        <dl class="nv-kv">
          <dt>device</dt><dd>${esc(snd.name)} <span class="nv-dim">${esc(snd.kind || '')}</span></dd>
          <dt>last address</dt><dd>${esc(snd.last_ip || '—')}</dd>
          <dt>last import</dt><dd>${e.last_import ? `${ts(e.last_import)} ${Z()}` : '—'}</dd>
          <dt>silent</dt><dd>${ts(d.ts)} ${Z()} → ${open ? 'now' : `${ts(d.last_ts)} ${Z()}`}</dd>
          <dt>missed runs</dt><dd>about ${fmt(d.count)}</dd>
        </dl>
        ${open ? `<details class="al-tech"><summary class="mono">Commands to run on the sensor</summary>
        <ol class="nv-sil-todo">
          <li><code>/usr/local/bin/hlta-push.sh --check</code> says what is wrong with the address, pin or upload key.</li>
          <li><code>crontab -l</code> shows whether the upload schedule is still there (firewall upgrades can remove it).</li>
        </ol></details>` : ''}
      </div>
      ${techDetails(d)}`;
  }

  function techDetails(d) {
    const e = d.evidence || {}, inc = d.incident || {};
    return `<details class="al-tech"><summary class="mono">Technical details</summary><dl class="nv-kv mono">
      <dt>rule</dt><dd>${esc(d.rule)}${e.rule?.rules?.length > 1 ? ` <span class="nv-dim">(${esc(e.rule.rules.join(', '))})</span>` : ''}</dd>
      <dt>kind</dt><dd>${esc(inc.kind || kindOf(d).key)}</dd>
      <dt>list</dt><dd>${esc(d.source)}${e.source_tier ? ` · tier ${esc(e.source_tier)}` : ''}${(e.sources || []).length > 1 ? ` · ${esc(e.sources.join(', '))}` : ''}</dd>
      <dt>incident</dt><dd>${esc(inc.id || d.id)} · ${pl(inc.n_alerts || 1, 'daily alert')}: ${(inc.alerts || [d.id]).map(esc).join(', ')}</dd>
      ${e.uid_count != null ? `<dt>rows</dt><dd>${fmt(d.rows_total ?? e.rows)} matched rows · ${fmt(e.uid_count)} uids · ${esc((e.log_types || []).join(', '))}</dd>` : ''}
      <dt>created</dt><dd>${ago(d.created_at)} · updated ${ago(d.updated_at)}</dd>
    </dl></details>`;
  }

  function reportsBox(d) {
    const rs = d.reports || [];
    const m = d.evidence?.indicator?.meta || {};
    if (!rs.length && !(m.sources || []).length) return '';
    const link = (r) => r.type === 'article' ? (r.story_id ? `#news/story/${encodeURIComponent(r.story_id)}` : `#news/article/${encodeURIComponent(r.id)}`) : null;
    const items = rs.slice(0, 6).map((r) => {
      const href = link(r);
      const title = esc(r.story_title || r.title || 'Untitled report');
      return `<li><div>${href ? `<a href="${href}" class="al-story">${title}</a>` : safeUrl(r.url) ? `<a href="${esc(safeUrl(r.url))}" target="_blank" rel="noopener" class="al-story">${title}</a>` : `<b>${title}</b>`}
        <span class="nv-dim"> · ${esc(r.source || '')}${r.published ? ` · ${day(r.published)}` : ''}</span></div>
        ${r.quote ? `<blockquote class="al-quote">${esc(r.quote)}</blockquote>` : ''}</li>`;
    }).join('');
    const pubs = (m.sources || []).join(', ');
    return `<div class="al-box al-reports"><div class="label">Named in the news</div>
      ${items ? `<ul class="al-rlist">${items}</ul>` : ''}
      <p class="al-small">${pubs ? `Reported by ${esc(pubs)}` : ''}${m.independent_sources ? ` · ${pl(m.independent_sources, 'independent publisher')}` : ''}${m.last_report ? ` · last report ${day(m.last_report)}` : ''}${!items ? '. The story is not in your News archive.' : ''}</p></div>`;
  }

  function expectedBox(d) {
    const inc = d.incident || {};
    if (!inc.suppressed || !inc.rule) return '';
    const r = inc.rule;
    return `<div class="al-box al-expected"><div class="label">Marked as expected</div>
      <p>Hidden by your rule: ${scopeText(r)}${r.expires_at ? `, until ${ts(r.expires_at, false)} ${Z()}` : ''}.${r.note ? ` <i>“${esc(r.note)}”</i>` : ''}</p>
      <div class="nv-dh-act"><button class="src-btn" data-act="rule-edit" data-rid="${esc(r.id)}">Edit rule</button><button class="src-btn" data-act="rule-del" data-rid="${esc(r.id)}">Stop treating as expected</button></div>
      <p class="al-small"><a href="#network/alerts/rules" class="al-story">See all expected-traffic rules ›</a></p></div>`;
  }

  function expectForm(d) {
    const k = kindOf(d), dev = d.device, noun = indicatorNoun(d);
    // the indicator as a person reads it: a signature by its name (its id in the tooltip), anything else as itself
    const sigN = noun === 'signature' ? sigName(d) : null;
    const what = sigN ? `<span class="netdetail-sig" title="${esc(d.indicator)}">“${esc(sigN)}”</span>`
      : noun === 'signature' ? `<span title="${esc(d.indicator)}">this intrusion signature</span>` : `<span class="mono">${esc(d.indicator)}</span>`;
    const anyDev = noun === 'signature' ? 'whichever device sets it off' : noun === 'vulnerability' ? 'on whichever device reports it' : 'whichever device reaches it';
    const opts = [
      dev ? ['device_indicator', `${esc(dname(dev, d))} + ${what}`, `Only this device and this ${noun}.`] : null,
      ['indicator', `Any device + ${what}`, `This ${noun}, ${anyDev}.`],
      dev ? ['device_kind', `${esc(dname(dev, d))} + ${esc(anyKind(k.kindLabel))}`, k.fam === 'ids' ? 'Every intrusion alert from this device.' : 'Every alert of this kind from this device.'] : null,
    ].filter(Boolean);
    const high = d.severity === 'high';
    return `<form class="al-box al-form" data-form="expect"><div class="label">This is expected</div>
      <p class="al-small">Hide this and future matching alerts. They stay viewable under <b>Expected</b>, and deleting the rule brings them back.</p>
      <fieldset><legend class="al-small">Applies to</legend>${opts.map(([v0, l, s], i) => `<label class="al-opt"><input type="radio" name="scope" value="${v0}" ${i === 0 ? 'checked' : ''}><span>${l}<small>${s}</small></span></label>`).join('')}</fieldset>
      <label class="al-fl">Note (optional)<input name="note" maxlength="500" placeholder="e.g. the kids' game launcher"></label>
      <label class="al-fl">For<select name="exp"><option value="">Always</option><option value="7">7 days</option><option value="30" ${high ? 'selected' : ''}>30 days</option><option value="90">90 days</option></select></label>
      ${high ? '<p class="al-warn">This is a high-severity alert. Hiding it for good means a real infection on this device would go unnoticed: prefer an expiry.</p>' : ''}
      <div class="nv-dh-act"><button class="src-btn primary" type="submit">Save rule</button><button class="src-btn" type="button" data-act="form-cancel">Cancel</button></div></form>`;
  }

  // The "other devices" step only when the logs show other devices reached the same value (else it is left out).
  function fillOthers(d, inc, k) {
    const li = det.querySelector('[data-others]'); if (!li) return;
    const obs = (d.evidence?.indicator?.observed || [])[0];
    const val = d.evidence?.indicator?.kind === 'cidr' && obs ? obs : d.indicator;
    const f = d.evidence?.indicator?.kind === 'domain' ? 'query' : 'ip';
    api.get('/api/netlog/aggregate', { group: 'device', query: `${f}:${val}`, limit: 20 }).then((r) => {
      const others = (r.groups || []).filter((g) => g.key && g.key !== d.device);
      if (!others.length || st.detail !== d) return;
      li.innerHTML = `Also check ${others.map((g) => devLink(g.key)).join(', ')}: ${others.length === 1 ? 'it' : 'they'} reached the same address too. Do the same steps there.`;
      li.hidden = false;
    }).catch(() => {});
  }

  // A device seen for the first time (osinthub/netlog/newdev.py): no log rows or indicator, just the device.
  // "Still happening?": the last contact against how far the logs of the source that saw it reach (server:
  // netlog/api.py still_happening), so silence after an alert never reads as "fixed".
  function stillLine(d) {
    const s = d.still;
    // only where it matters: on a low or info alert (the panel says "nothing to do now") an amber
    // "likely ongoing" is alarm copy (D2-04)
    if (!s || !s.text || !['high', 'medium'].includes(d.severity)) return '';
    const cover = s.covered_to ? `${s.source_label || 'Its logs'} cover up to ${ts(s.covered_to, false)} ${Z()}${s.last_contact ? `; last contact ${ts(s.last_contact, false)} ${Z()}` : ''}.` : '';
    return `<p class="finisha-still finisha-still-${esc(s.state)}" title="${esc(cover)}"><b>Still happening?</b> ${esc(s.text)}.${cover ? `<small class="mono">${esc(cover)}</small>` : ''}</p>`;
  }

  function newDeviceDetail(d) {
    const e = d.evidence || {}, dv = e.device || {}, inc = d.incident || {};
    const state = inc.state || d.status;
    const kv = [
      dv.mac ? ['MAC', `<span class="mono">${esc(dv.mac)}</span>${dv.private_mac ? ' <span class="nv-dim">(private, randomised)</span>' : ''}`] : null,
      (dv.home_ips || []).length ? ['Addresses', dv.home_ips.slice(0, 6).map((x) => v('ip', x)).join(', ')] : null,
      dv.vendor ? ['Maker', esc(dv.vendor)] : null,
      (dv.hostnames || []).length ? ['Names it gave', esc(dv.hostnames.slice(0, 5).join(', '))] : null,
      ['First seen', `${ts(e.first_seen || d.ts)} ${Z()}`],
      (e.top_names || []).length ? ['First names it looked up', esc(e.top_names.slice(0, 5).map((x) => x.name).join(', '))] : null,
      (e.top_dests || []).length ? ['Talked to', e.top_dests.slice(0, 5).map((x) => v('ip', x.ip)).join(', ')] : null,
    ].filter(Boolean);
    return `
      <div class="nv-dh">
        <button class="icon-btn nv-back" data-act="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button>
        <div class="nv-dh-tags"><span class="tag ${SEVTAG[d.severity]}">${d.severity}</span><span class="tag">New device</span>${stTag(state)}</div>
        <h2 class="al-h" tabindex="-1">${esc(headline(d).text)}</h2>
        ${stillLine(d)}
        ${e.merged_into ? `<div class="al-note">You merged it into ${devLink(e.merged_into)}: it was a device you already had.</div>` : ''}
        <div class="nv-dh-act">
          ${d.status !== 'ack' ? '<button class="src-btn primary" data-st="ack" title="I know this device (a)">✓ I know this device</button>' : ''}
          ${d.status !== 'dismissed' ? '<button class="src-btn" data-st="dismissed">Dismiss</button>' : ''}
          ${d.status !== 'new' ? '<button class="src-btn" data-st="new">Reopen</button>' : ''}
          <button class="src-btn ghost" data-act="device">Name it in Devices</button>
        </div>
        <p class="al-sev"><b>Why ${esc(d.severity)}:</b> ${esc(whyText(d))}</p>
      </div>
      ${expectedBox(d)}
      ${(() => { const s0 = whatToDo(d); return s0.length ? `<div class="al-box al-todo"><div class="label">What to do</div><ol>${s0.map(stepHtml).join('')}</ol></div>` : ''; })()}
      <div class="nv-why"><div class="label">What happened</div>${whatHappened(d, inc)}</div>
      <div class="al-box"><div class="label">What Night Desk knows about it</div><dl class="nv-kv">${kv.map(([k0, x]) => `<dt>${k0}</dt><dd>${x}</dd>`).join('')}</dl></div>
      <p class="al-small netx-ndfoot">New-device alerts can be turned off in Network › Connect logs › Home network.</p>`;
  }

  function renderDetail() {
    const d = st.detail; if (!d) return;
    if (d.rule === 'new_device') {
      det.innerHTML = newDeviceDetail(d);
      det.querySelectorAll('[data-st]').forEach((b) => (b.onclick = () => setStatus([d.incident?.id || d.id], b.dataset.st)));
      det.querySelector('[data-act="close"]').onclick = () => closeSide(true, true);
      det.querySelector('[data-act="device"]').onclick = () => ctx.goto('devices', { device: d.evidence?.merged_into || d.device });
      det.querySelectorAll('[data-act="rule-del"]').forEach((b) => (b.onclick = () => deleteRule(b.dataset.rid)));
      det.querySelectorAll('[data-act="rule-edit"]').forEach((b) => (b.onclick = () => openRules(true, b.dataset.rid)));
      phoneDetail(d, d.incident || { id: d.id, status: d.status });
      return;
    }
    if (d.rule === 'sensor_silent') {
      det.innerHTML = silenceDetail(d);
      det.querySelectorAll('[data-st]').forEach((b) => (b.onclick = () => setStatus([d.id], b.dataset.st)));
      det.querySelector('[data-act="close"]').onclick = () => closeSide(true, true);
      det.querySelector('[data-act="uploads"]').onclick = () => ctx.goto('import', { advanced: true });
      phoneDetail(d, d.incident || { id: d.id, status: d.status });
      return;
    }
    const e = d.evidence || {}, ind = e.indicator || {}, m = ind.meta || {}, dev = e.device || {};
    const inc = d.incident || { id: d.id, ts: d.ts, last_ts: d.last_ts, days: 1, n_alerts: 1, count: d.count, state: d.status, status: d.status };
    const k = kindOf({ ...d, kind: inc.kind });
    const h = headline({ ...d, kind: inc.kind });
    const src = S.sources.get(d.source) || {};
    const [tier, tierL, tierD] = tierOf(d.source, d.evidence);
    const conf = CONF[dev.confidence] || ['', ''];
    const related = (d.related || []).filter((r) => !(d.rows || []).some((x) => x.uid === r.uid && x.log_type === r.log_type && x.ts === r.ts));
    const steps = whatToDo({ ...d, kind: inc.kind, incident: inc });
    const listed = !['ids', 'kev', 'sensor'].includes(k.fam) && k.cat !== 'own';   // your own lists have no listing period to draw
    const homes = homeNames(d);
    const span = inc.days > 1 ? ` over ${inc.days} days` : '';
    const qs = questionsHtml({ ...d, incident: inc });
    det.innerHTML = `
      <div class="nv-dh">
        <button class="icon-btn nv-back" data-act="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button>
        <div class="nv-dh-tags"><span class="tag ${SEVTAG[d.severity]}">${d.severity}</span><span class="tag">${esc(k.kindLabel)}</span>${stTag(inc.state || d.status)}${inc.demo || d.demo ? demoChip : ''}${e.found_later ? laterChip(d) : ''}</div>
        <h2 class="al-h" tabindex="-1">${esc(h.text)}</h2>
        <div class="al-meta mono">${homes.length > 1 ? `${esc(homes.join(', '))} · ` : ''}${inc.ts === inc.last_ts ? `at ${ts(inc.ts, false)}` : `${ts(inc.ts, false)} → ${ts(inc.last_ts, false)}`} ${Z()} · ${pl(inc.count || d.count, 'contact')}${span}</div>
        ${stillLine(d)}
        ${inc.reopened && inc.triaged ? `<div class="al-note">New contacts after you ${inc.triaged.status === 'ack' ? 'acknowledged' : 'dismissed'} it ${ago(inc.triaged.at)}: it is still happening.</div>` : ''}
        <div class="nv-dh-act">
          ${inc.status !== 'ack' ? '<button class="src-btn primary" data-st="ack" title="I have seen this and am dealing with it (a)">✓ Acknowledge</button>' : ''}
          ${inc.status !== 'dismissed' ? '<button class="src-btn" data-st="dismissed" title="A false alarm, this time (d)">Dismiss</button>' : ''}
          ${inc.status !== 'new' ? '<button class="src-btn" data-st="new">Reopen</button>' : ''}
          ${!inc.suppressed ? '<button class="src-btn" data-act="expect" title="Stop alerting on this and future matching traffic">This is expected…</button>' : ''}
          <button class="src-btn ghost" data-act="hunt" title="Search every log row with this ${k.fam === 'ids' ? 'outside address' : 'indicator'}${d.device ? ' and device' : ''}">Search logs</button>
        </div>
        <p class="al-sev"><b>Why ${esc(d.severity)}:</b> ${esc(whyText({ ...d, incident: inc }))}</p>
        ${(inc.sources || []).length > 1 ? `<p class="al-small">Named by ${inc.sources.length} lists: ${esc(inc.sources.map(srcName).join(', '))} (one incident).</p>` : ''}
      </div>
      <div class="al-formslot">${st.form === 'expect' ? expectForm(d) : ''}</div>
      ${expectedBox(d)}
      ${e.found_later ? `<div class="al-box al-laterbox"><div class="label">Found later</div><p>${esc(laterLine(d))}</p></div>` : ''}
      ${sinkLine(d) ? `<div class="al-box al-sink"><div class="label">Your DNS filter</div><p>${esc(sinkLine(d))}</p></div>` : ''}
      ${steps.length ? `<div class="al-box al-todo"><div class="label">What to do</div><ol>${steps.map(stepHtml).join('')}</ol></div>` : ''}
      ${reportsBox(d)}
      <div class="nv-why"><div class="label">What happened</div>${whatHappened(d, inc)}${e.capped_note || /_spanning$|_ambiguous$/.test(d.rule) ? '' : ''}</div>
      ${listed ? `<div class="nv-ivbox">${timeline(d)}</div>` : ''}
      <nav class="nv-dtabs" role="tablist">
        <button data-dtab="questions" role="tab">Questions <span class="nv-tn">${qs.n}</span></button>
        <button data-dtab="evidence" role="tab">Evidence chain</button>
        <button data-dtab="indicator" role="tab">${k.fam === 'ids' ? 'Outside address' : k.fam === 'kev' ? 'Vulnerability' : 'Indicator'}</button>
      </nav>
      <div class="nv-dpane" data-dpane="questions">${qs.html}</div>
      <div class="nv-dpane" data-dpane="indicator"></div>
      <div class="nv-dpane" data-dpane="evidence">
      <ol class="nv-chain">
        <li class="nv-ch">
          <div class="nv-ch-h"><span class="nv-ch-n">1</span><span class="label">${homes.length > 1 ? 'Devices' : 'Device'}</span></div>
          <div class="nv-ch-b">
            <div class="nv-ch-t">${d.device ? devLink(d.device) : (dev.devices || []).length ? dev.devices.map(devLink).join(', ') : '<span class="nv-dim">No single home device</span>'} ${dev.confidence ? `<span class="tag ${conf[0]}" title="${esc(conf[1])}">${esc(dev.confidence)}</span>` : ''}</div>
            <dl class="nv-kv">
              ${dev.mac ? `<dt>MAC</dt><dd class="mono">${esc(dev.mac)}</dd>` : ''}
              ${dev.home_ips?.length ? `<dt>Home addresses</dt><dd>${dev.home_ips.map((x) => v('ip', x)).join(', ')}</dd>` : ''}
              ${dev.hostnames?.length ? `<dt>Names</dt><dd>${dev.hostnames.map(esc).join(', ')}</dd>` : ''}
              ${dev.confidence ? `<dt>Identity</dt><dd>${esc(conf[1])}</dd>` : ''}
              ${d.device && dev.devices?.length > 1 ? `<dt>Also</dt><dd>${dev.devices.filter((x) => x !== d.device).map(devLink).join(', ')}</dd>` : ''}
            </dl>
          </div>
        </li>
        <li class="nv-ch">
          <div class="nv-ch-h"><span class="nv-ch-n">2</span><span class="label">${k.fam === 'ids' ? 'Intrusion alert and traffic' : k.fam === 'kev' ? 'Log entries' : e.rule?.direction === 'dns' ? 'Lookups and connections' : 'Connections'}</span><span class="nv-dim mono">${pl(d.rows_total ?? e.rows, 'row')}</span></div>
          <div class="nv-ch-b">
            ${connRows(d.rows)}
            ${related.length ? `<details class="nv-rel"><summary class="mono">${fmt(related.length)} more rows from the same connections (DNS, TLS, HTTP…)</summary>${connRows(related)}</details>` : ''}
          </div>
        </li>
        <li class="nv-ch">
          <div class="nv-ch-h"><span class="nv-ch-n">3</span><span class="label">${k.fam === 'ids' ? 'Signature' : k.fam === 'kev' ? 'Vulnerability' : 'Indicator'}</span></div>
          <div class="nv-ch-b">
            <div class="nv-ch-t">${k.fam === 'ids' ? `<span title="${esc([(ind.observed || [])[0], d.indicator].filter(Boolean).join(' · '))}">${esc(sigQuoted(d))}</span>` : v(ind.kind === 'domain' ? 'q' : 'ip', d.indicator)} <span class="tag">${esc(k.kindLabel)}</span></div>
            ${ind.observed?.length && ind.observed.join() !== d.indicator && k.fam !== 'ids' ? `<div class="nv-dim mono">seen as ${ind.observed.map((x) => v('ip', x)).join(', ')}</div>` : ''}
            <dl class="nv-kv">${m.malware ? `<dt>Malware</dt><dd>${esc(m.malware)}</dd>` : ''}${e.interval?.start ? `<dt>On our copy of the list</dt><dd>since ${ts(e.interval.start)} ${Z()}</dd>` : ''}${m.first_seen ? `<dt>Provider first saw it</dt><dd>${esc(T.stamp(m.first_seen))}</dd>` : ''}</dl>
            <div class="nv-links"><button class="chip" data-dtab-go="indicator">${k.fam === 'ids' ? 'Outside address' : k.fam === 'kev' ? 'Vulnerability' : 'Indicator'} tab ›</button></div>
          </div>
        </li>
        ${d.source !== 'suricata' ? `<li class="nv-ch">
          <div class="nv-ch-h"><span class="nv-ch-n">4</span><span class="label">Source list</span></div>
          <div class="nv-ch-b">
            <div class="nv-ch-t"><b>${esc(srcName(d.source))}</b> <span class="nv-tier t${tier}" title="${esc(tierD)}">${esc(tierL)}</span></div>
            <div class="nv-dim">${esc(src.description || '')}</div>
            <dl class="nv-kv">
              ${src.provider ? `<dt>Provider</dt><dd>${esc(src.provider)}${safeUrl(src.homepage) ? ` · <a href="${esc(safeUrl(src.homepage))}" target="_blank" rel="noopener">${esc(src.homepage.replace(/^https?:\/\//, '').replace(/\/$/, ''))}</a>` : ''}</dd>` : ''}
              ${src.license ? `<dt>License</dt><dd>${esc(src.license)}</dd>` : ''}
              <dt>Trust</dt><dd>${esc(tierD)}</dd>
              ${src.last_ok ? `<dt>Last fetch</dt><dd>${ts(src.last_ok)} ${Z()} · ${ago(src.last_ok)}</dd>` : ''}
            </dl>
            <table class="nv-ivt mono"><thead><tr><th>Listed from</th><th>Until</th><th>Length</th></tr></thead><tbody>
              ${(d.intervals || []).map((i) => `<tr><td data-l="Listed from">${ts(i.start)}</td><td data-l="Until">${i.end ? ts(i.end) : '<b class="nv-hot">still listed</b>'}</td><td data-l="Length">${dur((i.end ? Date.parse(i.end) : Date.now()) - Date.parse(i.start))}</td></tr>`).join('') || '<tr><td colspan="3" class="nv-dim">No listing recorded</td></tr>'}
            </tbody></table>
            ${(e.listing || []).length ? `<div class="nv-prov">${e.listing.slice(0, 3).map((l) => `
              <details class="nv-rel"><summary class="mono">The list's own record${l.end_path ? ' (and its removal)' : ''}</summary>
              <div class="nv-dim mono al-path">file ${esc((l.start_path || '').split('/raw/').pop() || '?')}${l.start_record?.line != null ? ` line ${fmt(l.start_record.line)}` : ''} · key ${esc(l.key || '')}${l.end_path ? ` · removed in ${esc(l.end_path.split('/raw/').pop())}` : ''}</div>
              ${l.start_record?.data ? jsonHtml(l.start_record.data, false) : ''}</details>`).join('')}</div>` : ''}
            ${(e.also_listed || []).length ? `<div class="nv-also"><div class="label">Also on · one alert, corroborated</div>
              <table class="nv-ivt mono"><thead><tr><th>List</th><th>Indicator</th><th>What</th><th>Listing</th></tr></thead><tbody>
              ${e.also_listed.map((x) => `<tr><td>${esc(x.source_name || srcName(x.source))}</td>
                <td>${esc((x.values || [{ value: x.value }]).map((y) => y.value).join(', '))}${x.malware ? ` · ${esc(x.malware)}` : ''}</td><td>${esc(CATS[x.category] || x.category)} · ${esc(x.severity || '')}</td>
                <td>${x.in_listing ? `${ts(x.start)} → ${x.end ? ts(x.end) : '<b class="nv-hot">still listed</b>'}` : '<span class="nv-dim">outside listing</span>'}</td></tr>`).join('')}
              </tbody></table></div>` : ''}
          </div>
        </li>` : ''}
      </ol>
      </div>
      ${techDetails(d)}`;
    if (!isPhone()) mountNotes(det, { kind: 'incident', item: inc.id || d.id, title: h.text, before: '.nv-dtabs', actions: '.nv-dh-act', summary: () => incidentSummary(d, inc) });

    det.querySelectorAll('[data-st]').forEach((b) => (b.onclick = () => setStatus([inc.id], b.dataset.st)));
    det.querySelector('[data-act="close"]').onclick = () => closeSide(true, true);
    det.querySelector('[data-act="hunt"]').onclick = () => huntFor(d);
    det.querySelector('[data-act="expect"]')?.addEventListener('click', () => { st.form = 'expect'; renderDetail(); det.querySelector('[data-form]')?.scrollIntoView({ block: 'nearest' }); });
    det.querySelectorAll('[data-copy]').forEach((b) => (b.onclick = async () => { try { await navigator.clipboard.writeText(b.dataset.copy); toast('Copied'); } catch { toast(b.dataset.copy); } }));
    det.querySelectorAll('[data-act="rule-del"]').forEach((b) => (b.onclick = () => deleteRule(b.dataset.rid)));
    det.querySelectorAll('[data-act="rule-edit"]').forEach((b) => (b.onclick = () => openRules(true, b.dataset.rid)));
    const form = det.querySelector('[data-form="expect"]');
    if (form) {
      form.querySelector('[data-act="form-cancel"]').onclick = () => { st.form = null; leaveExpected(); renderDetail(); };
      form.onsubmit = async (ev) => {
        ev.preventDefault();
        const fd = new FormData(form);
        try {
          await api.post('/api/netlog/rules', { from_alert: d.id, scope: fd.get('scope'), note: fd.get('note') || null, ...(fd.get('exp') ? { expires_days: +fd.get('exp') } : {}) });
          toast('Marked as expected. Matching alerts are now under Expected.');
          st.form = null;
          leaveExpected();
          ctx.refreshSummary(); emit('alerts');
          await load();
          select(inc.id, false);
        } catch (err) { toast(err.message, true); }
      };
    }
    hsCue(det.querySelector('[data-dpane="evidence"]'), 'Listing table');
    fillOthers(d, inc, k);
    const pivots = runQuestions(det, { ...d, incident: inc }, ctx);
    det.querySelectorAll('[data-hunt]').forEach((b) => (b.onclick = () => huntPivot(ctx, pivots[b.dataset.hunt])));
    det.querySelectorAll('[data-dtab], [data-dtab-go]').forEach((b) => (b.onclick = () => setDtab(b.dataset.dtab || b.dataset.dtabGo)));
    setDtab(st.dtab);
    det.querySelectorAll('.nv-crow-h').forEach((h0) => (h0.onclick = (ev) => {
      if (ev.target.closest('.nv-v')) return;
      const row = h0.parentElement, raw = row.querySelector('.nv-crow-raw');
      const inRel = !!row.closest('.nv-rel');
      const src0 = inRel ? related : d.rows;
      const r = src0[+row.dataset.i];
      row.classList.toggle('open');
      raw.hidden = !raw.hidden;
      if (!raw.hidden && !raw.innerHTML) {
        if (r.raw) raw.innerHTML = jsonHtml(r.raw);
        else {
          const loadRaw = () => api.get('/api/netlog/connections', { uid: r.uid, log_type: r.log_type, raw: true, limit: 5 }).then((x) => { const m0 = x.rows.find((y) => y.ts === r.ts) || x.rows[0]; raw.innerHTML = m0?.raw ? jsonHtml(m0.raw) : emptyState({ why: 'No raw JSON was kept for this row.', size: 'inline' }); }).catch((e) => { raw.innerHTML = errorState({ title: "Couldn't load the raw record", why: serverWhy(e), err: e.message, retry: loadRaw, size: 'inline' }); });
          loadRaw();
        }
      }
    }));
    phoneDetail(d, inc);
  }

  // ------------------------------------------------------------ expected-traffic rules (one place; Settings links here)
  async function openRules(nav = true, editId = null, focus = nav) {
    if (nav && isPhone()) { pushPage('#network/alerts/rules'); return; }
    st.side = 'rules'; st.sel = null; st.detail = null; st.focus = focus;
    list.querySelectorAll('.sel').forEach((r) => r.classList.remove('sel'));
    sideOpen(true);
    if (nav) setHash('rules', true);
    det.innerHTML = loadingState('Loading rules…', { size: 'sm' });
    try { st.rules = await api.get('/api/netlog/rules'); } catch (e) { det.innerHTML = errorState({ retry: () => openRules(false, editId), title: "Couldn't load the rules", why: serverWhy(e), err: e.message, size: 'sm' }); return; }
    if (st.side !== 'rules') return;
    const rs = st.rules;
    det.innerHTML = `
      <div class="nv-dh">
        <button class="icon-btn nv-back" data-act="close" title="Close" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button>
        <div class="nv-dh-tags"><span class="tag">${pl(rs.length, 'rule')}</span></div>
        <h2 class="al-h" tabindex="-1">Expected traffic</h2>
        <p class="al-small">Traffic you told Night Desk is fine. Matching alerts, today's and future ones, are hidden from “needs you” and listed under <b>Expected</b>. Delete a rule to bring its alerts back. To add one, open an alert and choose <b>This is expected…</b></p>
      </div>
      ${rs.length ? `<ul class="al-rules">${rs.map((r) => `<li data-rid="${esc(r.id)}" class="${r.active ? '' : 'off'}">
        <div class="al-rule-t">${scopeText(r)}</div>
        ${r.note ? `<div class="al-rule-n">“${esc(r.note)}”</div>` : ''}
        <div class="al-rule-s mono">${r.active ? (r.expires_at ? `until ${ts(r.expires_at, false)} ${Z()}` : 'always') : `expired ${ts(r.expires_at, false)} ${Z()}`} · hides ${pl(r.hits?.incidents || 0, 'incident')}${r.hits?.week ? ` (${pl(r.hits.week, 'alert')} this week)` : ''}${r.hits?.last ? ` · last ${ago(r.hits.last)}` : ''}</div>
        <div class="nv-dh-act"><button class="chip" data-redit="${esc(r.id)}">Edit</button><button class="chip" data-rdel="${esc(r.id)}">Delete</button>${r.from_alert ? `<button class="chip" data-rfrom="${esc(r.from_alert)}">Show alert</button>` : ''}</div>
        <form class="al-redit" hidden><label class="al-fl">Note<input name="note" maxlength="500" value="${esc(r.note || '')}"></label>
          <label class="al-fl">For<select name="exp"><option value="keep">Keep (${r.expires_at ? 'until ' + esc(ts(r.expires_at, false)) : 'always'})</option><option value="">Always</option><option value="7">7 more days</option><option value="30">30 more days</option><option value="90">90 more days</option></select></label>
          <div class="nv-dh-act"><button class="src-btn primary" type="submit">Save</button><button class="src-btn" type="button" data-rcancel>Cancel</button></div></form>
      </li>`).join('')}</ul>` : '<div class="nv-calm al-pad">No rules yet. When a device does something harmless over and over (a game server on a blocklist, Tor on purpose), open its alert and choose “This is expected…”.</div>'}`;
    det.querySelector('[data-act="close"]').onclick = () => closeSide(true, true);
    if (isPhone()) { setPhoneTitle('Expected traffic', { back: { label: 'Alerts', href: withRange('#network/alerts', S.range) } }); setActionBar(null); afterRender('network'); }
    det.querySelectorAll('[data-rdel]').forEach((b) => (b.onclick = () => {
      if (b.dataset.armed) { deleteRule(b.dataset.rdel); return; }
      b.dataset.armed = '1'; b.textContent = 'Delete: its alerts come back'; b.classList.add('al-armed');
      setTimeout(() => { if (b.isConnected) { delete b.dataset.armed; b.textContent = 'Delete'; b.classList.remove('al-armed'); } }, 4000);
    }));
    det.querySelectorAll('[data-rfrom]').forEach((b) => (b.onclick = () => (isPhone() ? pushPage(`#network/alerts/${encodeURIComponent(b.dataset.rfrom)}`) : select(b.dataset.rfrom, true, true))));
    det.querySelectorAll('[data-redit]').forEach((b) => (b.onclick = () => { const f = b.closest('li').querySelector('form'); f.hidden = !f.hidden; f.querySelector('input')?.focus(); }));
    det.querySelectorAll('.al-redit').forEach((f) => {
      f.querySelector('[data-rcancel]').onclick = () => (f.hidden = true);
      f.onsubmit = async (ev) => {
        ev.preventDefault();
        const fd = new FormData(f), rid = f.closest('li').dataset.rid;
        const body = { note: fd.get('note') };
        if (fd.get('exp') !== 'keep') body.expires_days = fd.get('exp') ? +fd.get('exp') : null;
        try { await api.put(`/api/netlog/rules/${encodeURIComponent(rid)}`, body); toast('Rule saved'); ctx.refreshSummary(); emit('alerts'); load(); openRules(false); } catch (err) { toast(err.message, true); }
      };
    });
    focusDetail();
    if (editId) { const li = det.querySelector(`li[data-rid="${CSS.escape(editId)}"]`); li?.querySelector('form')?.removeAttribute('hidden'); li?.scrollIntoView({ block: 'nearest' }); }
  }
  async function deleteRule(rid) {
    try {
      await api.del(`/api/netlog/rules/${encodeURIComponent(rid)}`);
      toast('Rule deleted. Its alerts are back.');
      ctx.refreshSummary(); emit('alerts');
      await load();
      if (st.side === 'rules') openRules(false); else if (st.detail) select(st.detail.incident?.id || st.detail.id, false);
    } catch (e) { toast(e.message, true); }
  }

  // ------------------------------------------------------------ the phone (design §4.2; markup in m-alerts.js)
  // A phone gets its own list (rows of one link plus ⋯, swipes, Select mode, the chip row and the Filter sheet) and
  // shows a detail as a page of its own, with the actions in the bottom action bar (core/page.js).
  const cap = (x) => String(x || '').charAt(0).toUpperCase() + String(x || '').slice(1);
  const alertsHash = () => withRange('#network/alerts', S.range);
  const expectable = (a) => !['new_device', 'sensor_silent'].includes(a.rule) && a.state !== 'expected' && !a.incident?.suppressed;
  const rowById = (id) => st.rows.find((r) => r.id === id);
  let swipeOffs = [];
  function phoneHead() {
    const main = $('.nv-al-main');
    let h = main.querySelector(':scope > .nv-m-alhead');
    if (!isPhone()) { h?.remove(); swipeOffs.forEach((f) => f()); swipeOffs = []; return; }
    if (!h) {
      h = document.createElement('div');
      h.className = 'nv-m-alhead';
      main.prepend(h);
      h.addEventListener('click', (e) => {
        if (e.target.closest('[data-mselect]')) setSelecting(!st.selecting);
        else if (e.target.closest('[data-mstatus]')) statusMenu();
        else if (e.target.closest('[data-msev]')) sevMenu();
        else if (e.target.closest('[data-mrange]')) openRangeSheet();
        else if (e.target.closest('[data-mfilter]')) filterSheet();
      });
    }
    h.innerHTML = M.headHtml(st);
  }
  function groupsOf() {
    const groups = new Map();
    for (const a of st.rows) { const k = groupKey(a, st.group); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(a); }
    return [...groups.entries()].map(([k, xs]) => ({ key: k, rows: xs, sev: xs.reduce((m, x) => (SR[x.severity] < SR[m] ? x.severity : m), 'info'), last: xs.reduce((m, x) => (x.last_ts > m ? x.last_ts : m), '') }))
      .sort((a, b) => SR[a.sev] - SR[b.sev] || b.rows.length - a.rows.length || (b.last > a.last ? 1 : -1));
  }
  function renderPhone() {
    swipeOffs.forEach((f) => f()); swipeOffs = [];
    const one = (a) => M.rowHtml(a, { selecting: st.selecting, checked: st.checked.has(a.id) });
    list.innerHTML = `<div class="nv-m-alist">${st.group === 'none' ? st.rows.map(one).join('')
      : groupsOf().map((g) => M.groupHtml(g, st.open.has(g.key), st.group) + (st.open.has(g.key) ? g.rows.map(one).join('') : '')).join('')}</div>`;
    if (!st.selecting) {
      list.querySelectorAll('.nv-m-arow').forEach((r) => {
        const a = rowById(r.dataset.id); if (!a) return;
        swipeOffs.push(swipeRow(r, {
          right: () => triage([a.id], 'ack'),
          left: () => triage([a.id], 'dismissed'),
          // a high alert is never dismissed by a flick: its left swipe opens the ⋯ sheet and changes nothing
          guard: (dir) => (dir === 'left' && a.severity === 'high' ? 'menu' : dir === 'right' ? a.status !== 'ack' : a.status !== 'dismissed'),
          menu: () => rowMenu(a),
        }));
      });
    }
    afterRender('network');
  }
  function phoneClick(e) {
    const more = e.target.closest('.nv-m-more');
    if (more) { const a = rowById(more.closest('[data-id]')?.dataset.id); if (a) rowMenu(a); return true; }
    const g = e.target.closest('.nv-m-grp');
    if (g) {
      const k = g.dataset.g;
      if (st.open.has(k)) st.open.delete(k); else st.open.add(k);
      renderPhone();
      list.querySelector(`.nv-m-grp[data-g="${CSS.escape(k)}"]`)?.focus({ preventScroll: true });
      return true;
    }
    const row = e.target.closest('.nv-m-arow');
    if (row && st.selecting) {
      const cb = row.querySelector('input');
      const direct = e.target === cb;
      if (!direct) e.preventDefault();
      const on = direct ? cb.checked : !st.checked.has(row.dataset.id);
      if (on) st.checked.add(row.dataset.id); else st.checked.delete(row.dataset.id);
      if (cb) cb.checked = on;
      row.classList.toggle('on', on);
      selectBar();
      return true;
    }
    return !!row;   // a row's own link opens its page (#network/alerts/<id>)
  }
  function setSelecting(on) {
    st.selecting = on;
    if (!on) st.checked.clear();
    if (st.visible || !on) render();
    selectBar();
  }
  const mkBtn = (label, cls, fn, { aria, html, disabled } = {}) => {
    const b = document.createElement('button');
    b.type = 'button'; b.className = `m-btn ${cls || ''}`.trim();
    if (html) b.innerHTML = html; else b.textContent = label;
    if (aria) b.setAttribute('aria-label', aria);
    if (disabled) b.disabled = true;
    b.addEventListener('click', fn);
    return b;
  };
  function selectBar() {
    if (!isPhone()) return;
    if (!st.selecting) { if (!el.classList.contains('has-detail')) setActionBar(null); return; }
    const ids = () => [...st.checked], n = st.checked.size;
    setActionBar([
      mkBtn(n ? `Acknowledge ${fmt(n)}` : 'Acknowledge', 'm-btn-primary', () => triage(ids(), 'ack'), { disabled: !n }),
      mkBtn('Dismiss', '', () => triage(ids(), 'dismissed'), { disabled: !n }),
      mkBtn('Done', '', () => setSelecting(false)),
    ]);
  }
  // triage on a phone: one call, then an Undo toast that puts each alert back to the status it had
  const statusOf = (id) => rowById(id)?.status || ((st.detail?.incident?.id || st.detail?.id) === id ? (st.detail.incident?.status || st.detail.status) : null) || 'new';
  async function triage(ids, status) {
    if (!ids.length) return;
    const prev = new Map(ids.map((id) => [id, statusOf(id)]));
    if (!(await setStatus(ids, status, { quiet: true }))) return;
    if (st.selecting) setSelecting(false);
    const word = status === 'ack' ? 'acknowledged' : status === 'dismissed' ? 'dismissed' : 'reopened';
    undoToast(`${ids.length === 1 ? 'Alert' : `${fmt(ids.length)} alerts`} ${word}`, async () => {
      const by = new Map();
      for (const [id, s0] of prev) { if (!by.has(s0)) by.set(s0, []); by.get(s0).push(id); }
      for (const [s0, xs] of by) if (!(await setStatus(xs, s0, { quiet: true }))) throw new Error('the server did not take it');
    });
  }
  async function statusMenu() {
    const cs = st.stateCounts || {};
    const it = await actionSheet({ id: 'nv-status', title: 'Show', items: M.STATUS_ORDER.map((v0) => ({ label: STATUS.find((x) => x[0] === v0)[1], hint: cs[v0] != null ? fmt(cs[v0]) : '', value: v0, current: v0 === st.status })) });
    if (it && it.value !== st.status) { st.status = it.value; load(); }
  }
  async function sevMenu() {
    const all = st.sevs.size === SEV.length;
    const it = await actionSheet({ id: 'nv-sev', title: 'Severity', items: [{ label: 'Every severity', value: null, current: all }, ...SEV.map((x) => ({ label: cap(x), value: x, current: !all && st.sevs.size === 1 && st.sevs.has(x) }))] });
    if (!it) return;
    st.sevs = it.value ? new Set([it.value]) : new Set(SEV);
    load();
  }
  function filterSheet() {
    M.openFilterSheet(st, {
      count: async (dr) => {
        const p = { ...timeParams() };
        if (dr.q) p.q = dr.q;
        if (dr.sevs.size < SEV.length) p.severity = [...dr.sevs].join(',');
        const r = await api.get('/api/netlog/incidents/summary', p);
        return dr.status ? (r.state?.[dr.status] || 0) : (r.total || 0);
      },
      apply: (dr) => {
        st.status = dr.status; st.sevs = dr.sevs; st.q = dr.q;
        $('[data-k="q"]').value = st.q;
        if (dr.group !== st.group) { st.group = dr.group; LS.set(GKEY, st.group); st.open.clear(); }
        load();
      },
    });
  }
  function rowMenu(a) {
    const id = a.id, enc = encodeURIComponent(id);
    const items = [];
    if (a.status !== 'ack') items.push({ label: 'Acknowledge', hint: 'I’ve seen it; keep it in the list', run: () => triage([id], 'ack') });
    if (a.status !== 'dismissed') items.push({ label: 'Dismiss', hint: 'Not a problem; hide it', run: () => triage([id], 'dismissed') });
    if (a.status !== 'new') items.push({ label: 'Reopen', run: () => triage([id], 'new') });
    if (expectable(a)) items.push({ label: 'This is expected…', href: `#network/alerts/${enc}/expected` });
    items.push({ label: 'Copy summary', run: () => summaryOf(id) });
    items.push({ label: 'Expected traffic rules', href: '#network/alerts/rules' });
    actionSheet({ id: 'nv-row', title: headline(a).text, items });
  }
  const notesOf = (id) => () => api.get('/api/notes', { kind: 'incident', item: id }).then((r) => r.notes || []);
  function summaryOf(id) {
    openSummary(async () => {
      let d = await api.get(`/api/netlog/alerts/${encodeURIComponent(id)}`);
      if (d.incident?.lead && d.incident.lead !== d.id) d = await api.get(`/api/netlog/alerts/${encodeURIComponent(d.incident.lead)}`);
      return incidentSummary(d, d.incident || {});
    }, notesOf(id));
  }
  function huntFor(d) {
    const ind = d.evidence?.indicator || {}, k = kindOf({ ...d, kind: d.incident?.kind });
    const val = lookValue(d);
    S.filters = [...(val ? [{ f: ind.kind === 'domain' ? 'q' : k.fam === 'kev' ? 'q' : 'ip', v: val }] : []), ...(d.device ? [{ f: 'device', v: d.device }] : [])];
    S.groupby = ['log_type']; emit('filters'); ctx.goto('hunt');
  }

  // the detail as a page: title and ‹ Alerts in the top bar, the actions in the bottom bar, accordions in between
  function phoneDetail(d, inc) {
    if (!isPhone()) return;
    phoneChrome();
    const h2 = det.querySelector('.al-h');
    if (h2 && d.rule !== 'sensor_silent') h2.insertAdjacentHTML('afterend', M.devChip(d));
    // Questions: each one a closed accordion; its answer (and its log search) shows when opened
    det.querySelectorAll('.nv-q').forEach((q, i) => {
      const hd = q.querySelector(':scope > .nv-q-h'); if (!hd) return;
      const tEl = hd.querySelector('.nv-q-t').cloneNode(true);
      const sub = tEl.querySelector('.nv-q-s')?.textContent || '';
      tEl.querySelector('.nv-q-s')?.remove();
      const b = document.createElement('button');
      b.type = 'button'; b.className = 'nv-m-qbtn'; b.setAttribute('aria-expanded', 'false');
      const bid = `nv-m-q${i}`;
      b.setAttribute('aria-controls', bid);
      b.innerHTML = `<span class="nv-q-n">${esc(hd.querySelector('.nv-q-n')?.textContent || '')}</span><span class="nv-m-qt">${esc(tEl.textContent.trim())}${sub ? `<span class="nv-m-qs">${esc(sub)}</span>` : ''}</span>`;
      const box = document.createElement('div');
      box.className = 'nv-m-qbody'; box.id = bid; box.hidden = true;
      const go = hd.querySelector('.nv-q-go');
      hd.replaceWith(b);
      const ans = q.querySelector('.nv-q-a');
      ans.before(box); box.append(ans);
      if (go) { go.textContent = 'Search these logs ›'; box.append(go); }
      b.onclick = () => { const open = box.hidden; box.hidden = !open; b.setAttribute('aria-expanded', String(open)); };
    });
    // Evidence and the indicator: closed accordions (the desktop's tabs)
    const nav = det.querySelector('.nv-dtabs');
    if (nav) {
      const qp = det.querySelector('[data-dpane="questions"]'); if (qp) qp.hidden = false;
      for (const t0 of ['evidence', 'indicator']) {
        const pane = det.querySelector(`[data-dpane="${t0}"]`); if (!pane) continue;
        const b = document.createElement('button');
        b.type = 'button'; b.className = 'nv-m-acc'; b.dataset.macc = t0; b.setAttribute('aria-expanded', 'false');
        b.textContent = nav.querySelector(`[data-dtab="${t0}"]`)?.textContent.trim() || t0;
        pane.before(b); pane.hidden = true;
        b.onclick = () => openAcc(t0, null, true);
      }
    }
    phoneNotes(d, inc);
    afterRender('network');
  }
  // the top bar's title and ‹ Alerts, and the action bar (core/page.js clears both on every page change, so a Back
  // from the routed "Mark as expected" sheet to this alert puts them back)
  function phoneChrome() {
    if (!isPhone() || !st.detail || !el.classList.contains('has-detail')) return;
    const d = st.detail, inc = d.incident || { id: d.id, status: d.status };
    const k = kindOf({ ...d, kind: inc.kind });
    const t = d.rule === 'new_device' ? 'New device' : d.rule === 'sensor_silent' ? 'Sensor silent' : (k.kindLabel || 'Alert');
    setPhoneTitle(cap(t), { back: { label: 'Alerts', href: alertsHash() } });
    detailBar(d, inc);
  }
  function openAcc(t, value, toggle = false) {
    const b = det.querySelector(`.nv-m-acc[data-macc="${t}"]`), pane = det.querySelector(`[data-dpane="${t}"]`);
    if (!b || !pane) return;
    const open = toggle ? pane.hidden : true;
    pane.hidden = !open; b.setAttribute('aria-expanded', String(open));
    if (open && t === 'indicator') loadIndicator(value);
    if (open && !toggle) b.scrollIntoView({ block: 'start' });
  }
  function detailBar(d, inc) {
    if (!isPhone() || st.detail !== d) return;
    const id = inc.id || d.id, status = inc.status || d.status;
    const nodes = [];
    if (status === 'new') nodes.push(mkBtn(d.rule === 'new_device' ? 'I know it' : 'Acknowledge', 'm-btn-primary', () => triage([id], 'ack')), mkBtn('Dismiss', '', () => triage([id], 'dismissed')));
    else {
      const s0 = document.createElement('span');
      s0.className = 'nv-m-state'; s0.textContent = ST_WORD[status] ? cap(ST_WORD[status]) : status;
      nodes.push(s0, mkBtn('Reopen', '', () => triage([id], 'new')));
    }
    if (expectable({ ...d, state: inc.state, incident: inc })) nodes.push(mkBtn('Expected…', '', () => pushPage(`#network/alerts/${encodeURIComponent(id)}/expected`), { aria: 'This is expected…' }));
    const dots = mkBtn('', 'm-btn-sq nv-m-dots', () => detailMenu(d, inc), { aria: 'More actions', html: DOTS });
    dots.setAttribute('aria-haspopup', 'menu');
    nodes.push(dots);
    setActionBar(nodes);
  }
  function detailMenu(d, inc) {
    const id = inc.id || d.id;
    const items = [
      { label: 'Copy summary', run: () => openSummary(() => incidentSummary(d, inc), notesOf(id)) },
      { label: 'Copy link', run: () => copyText(`${location.origin}${location.pathname}#network/alerts/${encodeURIComponent(id)}`, 'Link copied') },
    ];
    if (d.rule === 'new_device') items.push({ label: 'Name it in Devices', href: `#network/devices/${encodeURIComponent(d.evidence?.merged_into || d.device)}` });
    else if (d.rule === 'sensor_silent') items.push({ label: 'Sensor settings', run: () => ctx.goto('import', { advanced: true }) });
    else items.push({ label: 'Search these logs', run: () => huntFor(d) });
    items.push({ label: 'Expected traffic rules', href: '#network/alerts/rules' });
    actionSheet({ id: 'nv-detail', title: 'This alert', items });
  }
  function phoneGone(e) {
    const gone = e.status === 404 || /not found|no such/i.test(e.message || '');
    det.innerHTML = gone ? emptyState({ title: 'This alert isn’t in your logs any more', why: 'Its logs or the demo data were removed, so there is nothing left to acknowledge or dismiss.', act: '<button type="button" class="vs-btn primary" data-mback>Back to alerts</button>', size: 'sm' })
      : errorState({ retry: () => select(st.sel, false), title: 'Couldn’t open this alert', why: serverWhy(e), err: e.message, size: 'sm' });
    det.querySelector('[data-mback]')?.addEventListener('click', () => pageBack(alertsHash()));
    setPhoneTitle('Alert', { back: { label: 'Alerts', href: alertsHash() } });
    setActionBar(null);
  }
  // Notes: the list, and "Add a note" opens the composer sheet (core/note-sheet.js)
  function phoneNotes(d, inc) {
    const id = inc.id || d.id, title = headline({ ...d, kind: inc.kind }).text;
    const sec = document.createElement('section');
    sec.className = 'nv-m-notes';
    det.querySelector(':scope > .al-tech') ? det.querySelector(':scope > .al-tech').before(sec) : det.append(sec);
    let notes = [];
    const paint = (err) => {
      sec.innerHTML = `<h3 class="label">Notes</h3>${err ? '<p class="nv-dim">Couldn’t load your notes.</p>' : notes.length ? `<ul class="nv-m-nlist">${notes.map((n) => `<li><button type="button" class="nv-m-note" data-nid="${esc(n.id)}"><span class="nv-m-note-b">${esc(n.body)}</span><span class="nv-m-note-t">${esc(ago(n.updated_at || n.created_at))}</span></button></li>`).join('')}</ul>` : ''}
        <button type="button" class="m-btn nv-m-addnote">Add a note</button>`;
    };
    st.notesReload = async () => {
      try { notes = await notesOf(id)(); if (st.detail === d) paint(); } catch { if (st.detail === d) paint(true); }
    };
    st.notesFor = id;
    sec.addEventListener('click', (e) => {
      const nb = e.target.closest('[data-nid]');
      if (nb) openNoteSheet({ kind: 'incident', id, title, note: notes.find((n) => String(n.id) === nb.dataset.nid) });
      else if (e.target.closest('.nv-m-addnote')) openNoteSheet({ kind: 'incident', id, title });
    });
    paint();
    st.notesReload();
  }
  window.addEventListener('nd:notes-changed', (e) => { if (isPhone() && st.detail && e.detail?.kind === 'incident' && String(e.detail.item) === String(st.notesFor)) st.notesReload?.(); });

  // #network/alerts/<id>/expected: "Mark as expected" over the alert. A phone: the routed sheet (its Close, Cancel and
  // Save go back to the alert). A desktop: today's form in the alert's panel.
  function maybeExpect() {
    const p = hashParts();
    if (!p || p.sub !== 'expected' || !st.detail) return;
    const d = st.detail, inc = d.incident || {};
    if (!expectable({ ...d, state: inc.state, incident: inc })) { leaveExpected(); return; }
    if (isPhone()) {
      if (st.xsheet) return;
      st.xsheet = M.expectSheet(d, { route: location.hash, save: (o) => saveRule(d, o) });
      st.xsheet.closed.then(() => { st.xsheet = null; });
    } else if (st.form !== 'expect') { st.form = 'expect'; renderDetail(); det.querySelector('[data-form]')?.scrollIntoView({ block: 'nearest' }); }
  }
  function leaveExpected() {
    const p = hashParts();
    if (p?.sub !== 'expected') return;
    const h = withRange(`#network/alerts/${encodeURIComponent(p.id)}`, S.range);
    if (isPhone()) pageBack(h); else history.replaceState(history.state, '', h);
  }
  async function saveRule(d, { scope, days }) {
    const after = async () => { ctx.refreshSummary(); emit('alerts'); await load(); if (st.detail) select(st.detail.incident?.id || st.detail.id, false); };
    try {
      const r = await api.post('/api/netlog/rules', { from_alert: d.id, scope, ...(days ? { expires_days: days } : {}) });
      after();
      undoToast('Rule saved', async () => { await api.del(`/api/netlog/rules/${encodeURIComponent(r.id)}`); await after(); });
    } catch (err) { toast(err.message, true); throw err; }
  }

  // ------------------------------------------------------------ events
  $('[data-act="rules"]').onclick = () => openRules();
  el.querySelectorAll('.nv-seg[data-k] button').forEach((b) => (b.onclick = () => {
    const k = b.parentElement.dataset.k;
    st[k] = b.dataset.v;
    if (k === 'group') { LS.set(GKEY, st.group); st.open.clear(); render(); return; }
    load();
  }));
  el.querySelectorAll('.nv-sevc [data-sev]').forEach((b) => (b.onclick = (e) => {
    const s = b.dataset.sev;
    if (e.shiftKey || e.metaKey) { st.sevs = new Set([s]); }
    else if (st.sevs.has(s)) { st.sevs.delete(s); if (!st.sevs.size) st.sevs = new Set(SEV); } else st.sevs.add(s);
    load();
  }));
  let qt;
  $('[data-k="q"]').addEventListener('input', (e) => { clearTimeout(qt); qt = setTimeout(() => { st.q = e.target.value.trim(); load(); }, 300); });
  list.addEventListener('click', (e) => {
    if (isPhone() && phoneClick(e)) return;
    if (e.target.closest('.nv-v')) return;
    const ck = e.target.closest('.nv-ck');
    if (ck) {
      const id = ck.closest('[data-id]').dataset.id;
      if (e.target.tagName === 'INPUT') { e.target.checked ? st.checked.add(id) : st.checked.delete(id); paintBulk(); }
      return;
    }
    const gact = e.target.closest('[data-gact]');
    if (gact) { setStatus(gact.dataset.ids.split(',').filter(Boolean), gact.dataset.gact); return; }
    const aact = e.target.closest('[data-aact]');
    if (aact) { setStatus([aact.closest('[data-id]').dataset.id], aact.dataset.aact); return; }
    const g = e.target.closest('[data-g]');
    if (g) { const k = g.dataset.g, kb = e.detail === 0; st.open.has(k) ? st.open.delete(k) : st.open.add(k); render(); if (kb) list.querySelector(`[data-g="${CSS.escape(k)}"] .fnet-open`)?.focus(); return; }
    const a = e.target.closest('[data-id]');
    if (a) select(a.dataset.id, true, true);
  });
  // Keyboard: each row's headline (or group label) is a button: Enter or Space opens it, or folds the group, via the click above
  $('.nv-bulk').addEventListener('click', (e) => {
    const b = e.target.closest('[data-bulk]'); if (!b) return;
    if (b.dataset.bulk === 'clear') { st.checked.clear(); paintBulk(); render(); return; }
    setStatus([...st.checked], b.dataset.bulk);
  });
  // Esc closes the open detail (alert or rules) and puts focus back on its row (common.js escCloses)
  escCloses(() => st.visible && el.classList.contains('has-detail'), () => closeSide(true, true));
  document.addEventListener('keydown', (e) => {
    // triage keys act only when the alert list is the surface in front: not behind the entity panel, tour or drawer
    if (!st.visible || !st.detail || shortcutBlocked(e)) return;
    const iid = st.detail.incident?.id || st.detail.id;
    if (e.key === 'a') setStatus([iid], 'ack');
    if (e.key === 'd') setStatus([iid], 'dismissed');
    if (e.key === 'j' || e.key === 'k') {
      const rows = [...list.querySelectorAll('.nv-arow')];
      const i = rows.findIndex((r) => r.dataset.id === st.sel);
      const n = rows[i + (e.key === 'j' ? 1 : -1)];
      if (n) { select(n.dataset.id); n.scrollIntoView({ block: 'nearest' }); }
    }
  });

  onChange((w) => { if (w === 'range' || w === 'data') { st.stale = true; if (st.visible) load(); } });

  return {
    async show(opts = {}) {
      st.visible = true;
      if (opts.severity) { st.sevs = new Set([opts.severity]); st.status = 'new'; st.stale = true; }
      if (isPhone() && opts.alert && hashArg() !== opts.alert) { pushPage(`#network/alerts/${encodeURIComponent(opts.alert)}`); return; }
      if (isPhone() && !hashArg() && el.classList.contains('has-detail')) closeSide(false);
      const want = opts.alert || hashArg();
      if (want === 'rules') { if (st.stale) await load(); if (st.side !== 'rules') openRules(false); return; }
      if (want) {
        let a = st.byId.get(want);
        if (!a) { try { a = await api.get(`/api/netlog/alerts/${encodeURIComponent(want)}`); } catch {} }
        const state = a?.incident?.state || a?.state || a?.status;
        if (a && st.status && state !== st.status) { st.status = ''; st.stale = true; }
        if (a && !st.sevs.has(a.incident?.severity || a.severity)) { st.sevs = new Set(SEV); st.stale = true; }
        if (st.stale) await load();
        const iid = a?.incident?.id || a?.id || want;
        if (st.group !== 'none') { const r = st.rows.find((x) => x.id === iid); if (r) { st.open.add(groupKey(r, st.group)); render(); } }
        if (st.sel !== iid || !st.detail) select(want, !!opts.alert, true);
        else { st.focus = true; focusDetail(); }
        requestAnimationFrame(() => list.querySelector(`[data-id="${CSS.escape(iid)}"]`)?.scrollIntoView({ block: 'center' }));
        return;
      }
      if (st.stale) {
        await load();
        // open the first incident so the evidence is visible straight away (wide screens only)
        if (!st.sel && window.innerWidth > 900 && st.rows.length) {
          const first = st.rows[0];
          if (st.group !== 'none') { st.open.add(groupKey(first, st.group)); render(); }
          select(first.id, false);
        }
      }
    },
    hide() { st.visible = false; if (st.selecting) setSelecting(false); },
  };
}

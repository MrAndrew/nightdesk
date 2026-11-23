// Network view: imported Zeek logs matched against threat lists, as they were at the time.
// Sub-tabs: Overview, Alerts, Hunt, Devices, Connect logs (id import). Contract: okf/architecture/web-client.md
import { registerView } from '../core/panels.js';
import { LS } from '../core/prefs.js';
import { LABELS, openDetails, openFull, entityHref } from '../core/open.js';
import { S, onChange, emit, setRange, rangeText, timeParams, loadDevices, loadSources, lookupIp, toExplorer, isIp, esc, fmt, toast, devName } from './net/common.js';
import { demoOnly } from '../core/alerts-badge.js';
import { sqlConsoleOn } from '../core/api.js';
import * as overview from './net/overview.js';
import * as alerts from './net/alerts.js';
import * as hunt from './net/hunt.js';
import * as devices from './net/devices.js';
import * as importer from './net/import.js';
import { hashRange, withRange, isCustom } from '../core/range.js';
import { viewHeader, headerRange } from '../core/view.js';
import * as T from '../core/time.js';
import { isPhone, onPhoneChange } from './net/m.js';
import { actionSheet } from '../core/sheet.js';
import { pushPage } from '../core/page.js';

const TABS = [
  ['overview', 'Overview', overview], ['alerts', 'Alerts', alerts], ['hunt', 'Search logs', hunt],
  ['devices', 'Devices', devices], ['import', 'Connect logs', importer],
];
// the phone's sub-nav words (design §4.2: "Alerts · Devices · Overview · Logs"; the order is CSS, m:net)
const PHONE_LABEL = { hunt: 'Logs' };
const GROUPABLE = { ip: 'resp_h', port: 'resp_p', log_type: 'log_type', proto: 'proto', service: 'service', conn_state: 'conn_state', device: 'device',
  query: 'query', server_name: 'server_name', host: 'host' };
const HUNTABLE = (f) => ['device', 'ip', 'port', 'log_type', 'proto', 'service', 'uid', 'q', 'conn_state', 'query', 'server_name', 'host'].includes(f) || f.startsWith('raw.');


let inst = null;
registerView({
  id: 'network',
  mount(el, ctx) {
    const { api, openEvent, live } = ctx;
    el.innerHTML = `
      <div class="nv-wrap">
        ${viewHeader({
          title: 'Network', cls: 'nv-head', purpose: 'Your own logs, checked against threat lists', status: '<span class="nv-sub"></span>',
          tabs: TABS.map(([id, label]) => `<button data-tab="${id}" role="tab"><span class="nv-tlab">${label}</span><span class="nv-tn" data-tn="${id}"></span></button>`).join(''),
          tabsCls: 'nv-tabs', tabsLabel: 'Network sections', range: { cls: 'nv-range', lead: '<span class="nv-rt vh-rt"></span>' },
        })}
        <div class="nv-panes">${TABS.map(([id]) => `<div class="nv-pane" data-pane="${id}"></div>`).join('')}</div>
        <div class="nv-pop" hidden></div>
      </div>`;
    const $ = (s) => el.querySelector(s);
    const mounted = new Map();
    let tab = null;

    const sub = {
      api, openEvent, live,
      goto(t, opts) {
        // a phone: an alert or a device is a page of its own, opened through core/page.js so the shell sees it
        // (title, ‹ Back, no tab bar), the same as a tapped row or a deep link
        if (isPhone() && (opts?.device || opts?.alert)) {
          pushPage(withRange(opts.device ? `#network/devices/${encodeURIComponent(opts.device)}` : `#network/alerts/${encodeURIComponent(opts.alert)}`, S.range));
          return;
        }
        setTab(t, opts);
      },
      addFilter(f, val, replace = false, neg = false) {
        if (replace) S.filters = [];
        S.filters = S.filters.filter((x) => !(x.f === f && x.v === String(val)));
        S.filters.push({ f, v: String(val), neg });
        emit('filters');
        setTab('hunt');
      },
      setCount(id, n, hot, title = '') { const b = el.querySelector(`[data-tn="${id}"]`); b.textContent = n ? fmt(n) : ''; b.classList.toggle('hot', !!hot); if (title && n) b.title = title; else b.removeAttribute('title'); },
      refreshSummary,
    };

    // The URL follows the sub-tab (#network/<tab>), so reload, Back and shared links return to it. nav: 'push' for a
    // user's tab change (a new history entry, or a rewrite of a bare '#network'), 'none' when the URL already says it.
    function setTab(t, opts, nav = 'push') {
      if (!TABS.some(([id]) => id === t)) t = 'overview';
      tab = t;
      LS.set('nd.network.tab', t);
      syncHash(nav);
      el.querySelectorAll('.nv-tabs button').forEach((b) => b.classList.toggle('on', b.dataset.tab === t));
      el.querySelectorAll('.nv-pane').forEach((p) => p.classList.toggle('on', p.dataset.pane === t));
      range.hide(t === 'devices' || t === 'import'); // the range does nothing there: hidden, not dimmed
      for (const [id, m] of mounted) if (id !== t) m.hide?.();
      const mod = TABS.find(([id]) => id === t)[2];
      if (!mounted.has(t)) mounted.set(t, mod.mount(el.querySelector(`.nv-pane[data-pane="${t}"]`), sub) || {});
      mounted.get(t).show?.(opts);
      // a phone's sub-nav always fits; scrolling it into view would move the page (and lose a restored scroll)
      if (!isPhone()) $('.nv-tabs button.on')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      syncRangeHash();
    }

    function syncHash(nav = 'replace') {
      if (nav === 'none' || !tab || !document.body.classList.contains('nv-active')) return;
      const cur = hashTab();
      if (cur === tab) return;
      history[nav === 'push' && cur ? 'pushState' : 'replaceState'](null, '', withRange(`#network/${tab}`, S.range));
    }
    // The URL carries the range too (#network/hunt?range=7d, or a brushed <from>~<to>): replaced in place.
    // Only the range parameter changes: the path (#network/alerts/<id>, #network/devices/<id>) is never touched.
    function syncRangeHash() {
      if (!tab || !document.body.classList.contains('nv-active') || !hashTab()) return;
      const want = withRange(location.hash, S.range);
      if (location.hash !== want) history.replaceState(history.state, '', want);
    }
    // A link or Back/Forward to an entry with ?range= sets it; an entry without one keeps the current range.
    function rangeFromHash() {
      const r = hashRange(location.hash);
      if (!r) return;
      const same = isCustom(r) ? r.from === S.range.from && r.to === S.range.to : S.range.from == null && r.h === S.range.h;
      if (!same) setRange(r);
    }

    function paintRange() {
      range.set(S.range);
      $('.nv-rt').textContent = isCustom(S.range) ? '' : rangeText(); // a brushed window is in the control itself
      syncRangeHash();
    }

    // The header line and the tab counts. Counts follow okf/data/netlog.md#the-needs-you-count: the header names what
    // each number is ("need you", "demo", "new"); the Alerts tab shows the new (untriaged) count in the current range,
    // the same number as the list's "New" chip; the Devices tab shows every device, as the header and Overview do.
    // A failed load is an error (S.summaryErr), never "no logs": Overview shows Try again, and the load retries by
    // itself (every 8 s while the view is open, on the live connection coming back, and when the view is shown).
    let retryT = null, own = false;
    const tell = (what) => { own = true; try { emit(what); } finally { own = false; } };   // our own news: no re-read
    // Late answers never paint: each read carries a sequence number and the range it was asked for, and an answer
    // for an older read or another range is dropped (B2-04: a slow 24H answer arriving after ALL was clicked).
    let sumSeq = 0, incSeq = 0, incFor = null;   // incFor: {k: range key, inc}: the "new" counts of that range
    // the range's counts: the list's "new" (incidents/summary) and, on a range other than All, the needs-you and demo
    // counts of that range (alerts/count with the range, the same call Overview's card makes), so header and card agree
    const rangedCounts = async () => {
      const tp = timeParams(), ranged = !!(S.range.h || S.range.from != null);
      const [inc, cnt] = await Promise.all([api.get('/api/netlog/incidents/summary', tp).catch(() => null),
        ranged ? api.get('/api/netlog/alerts/count', tp).catch(() => null) : null]);
      return inc ? { ...inc, cnt } : null;
    };
    const rkey = () => JSON.stringify([S.range.h ?? 0, S.range.from ?? null, S.range.to ?? null]);
    async function refreshSummary() {
      const failedBefore = !!S.summaryErr;
      clearTimeout(retryT);
      const my = ++sumSeq, myInc = ++incSeq, k = rkey();
      try {
        const [s, inc] = await Promise.all([api.get('/api/netlog/summary'), rangedCounts()]);
        if (my !== sumSeq) return;
        S.summary = s;
        S.summaryErr = null; S.summaryErrStatus = null;
        if (myInc === incSeq && k === rkey()) incFor = { k, inc };
        paintHeader();
        paintRange();
        if (failedBefore) { await loadDevices(); tell('devices'); tell('data'); }
      } catch (e) {
        if (my !== sumSeq) return;
        S.summaryErr = e.message || 'no answer';
        S.summaryErrStatus = e.status || null;   // the server answered with an error (500), or did not answer at all
        if (!S.summary) {
          $('.nv-sub').innerHTML = `<span class="counts-err">${e.status ? 'Night Desk couldn\u2019t read the network logs (the server answered with an error)' : 'Couldn\u2019t reach the Night Desk server'} · trying again</span>`;
          sub.setCount('alerts', 0); sub.setCount('devices', 0);
        }
        if (!failedBefore || !S.summary) tell('data');   // Overview redraws its error (a Try again may be showing a loader)
        retryT = setTimeout(() => { if (document.body.classList.contains('nv-active') && !document.hidden) refreshSummary(); }, 8000);
      }
    }
    // Groups of words that must stay together on one line (no "· 27 / new" orphan): each count is one nowrap span,
    // and the "·" before it belongs to it, so a wrapped line never ends on a dangling separator.
    const grp = (html, title = '') => `<span class="fnet-nb"${title ? ` title="${title}"` : ''}>${html}</span>`;
    function paintHeader() {
      const s = S.summary; if (!s) return;
      const all = !isCustomRange() && !S.range.h;
      const inc = incFor && incFor.k === rkey() ? incFor.inc : null;   // the "new" counts of THIS range, or none yet
      // on a range, every number on the line is that range's (alerts/count with the range); on All, all time
      const rc = !all ? inc?.cnt : null;
      const need = rc ? rc.needs_you : s.needs_you ?? ((s.alerts.high || 0) + (s.alerts.medium || 0));
      const demoN = rc ? rc.demo : !all && inc?.demo_new != null ? inc.demo_new : (s.alerts_other?.demo || 0);
      const fresh = inc?.state?.new;   // the list's "New" count in this range
      const inR = all ? '' : ' in this range';
      const nw = fresh != null ? ` ${grp(`· ${fmt(fresh)} new${inR}`, 'Untriaged alerts of any severity, demo included: the “New” count in Network › Alerts')}` : '';
      // only demo alerts open: say so instead of "no … open" over a list of demo rows (core/alerts-badge.js demoOnly)
      const al = need ? grp(`· <b class="nv-hot">${fmt(need)} high/medium alert${need === 1 ? '' : 's'} need${need === 1 ? 's' : ''} you${inR}</b>`)
        : demoOnly({ needs_you: need, demo: demoN }) ? grp(`· <span class="finisha-demo-t">No real alerts · ${fmt(demoN)} demo${inR}</span>`) : grp(`· nothing needs you${inR}`);
      // the alert phrase and its "new" count wrap as one unit: never "· 25 new" alone on a line
      $('.nv-sub').innerHTML = s.rows ? `${grp(`${fmt(s.rows)} log rows`)} ${grp(`· ${fmt(s.devices)} devices`)} ${grp(`· ${fmt(s.files)} files`)} <span class="fnet-nbo">${al}${nw}</span>` : 'No logs imported yet';
      // a phone's sub-nav carries the needs-you number (the Network tab badge's), a desktop the "new" count
      if (isPhone()) sub.setCount('alerts', need, need > 0, need ? `${fmt(need)} need${need === 1 ? 's' : ''} you${inR}` : '');
      else sub.setCount('alerts', fresh ?? 0, need > 0, fresh != null ? `${fmt(fresh)} new (untriaged) alert${fresh === 1 ? '' : 's'}${inR}, demo included; ${fmt(need)} need${need === 1 ? 's' : ''} you` : '');
      sub.setCount('devices', s.devices, false, `${fmt(s.devices)} devices in all, unidentified addresses included`);
    }
    const isCustomRange = () => S.range.from != null;
    // the new count follows the range; the rest of the header does not
    async function refreshTabCount() {
      if (!S.summary) return;
      const my = ++incSeq, k = rkey();
      paintHeader();   // the old range's numbers come off at once (no stale "3 new" under ALL)
      try {
        const inc = await rangedCounts();
        if (my !== incSeq || k !== rkey()) return;
        incFor = { k, inc };
        paintHeader();
      } catch {}
    }

    // ---------------------------------------------------------------- pivot menu on any value
    const pop = $('.nv-pop');
    function closePop() { pop.hidden = true; }
    function openPop(target) {
      const f = target.dataset.nf, val = target.dataset.nv;
      const items = [];
      if (f === 'device') items.push(['device', `Open device · ${devName(val)}`]);
      if (f === 'alert') items.push(['alert', 'Open alert']);
      if (HUNTABLE(f)) {
        const short = esc(val.length > 36 ? val.slice(0, 36) + '…' : val);
        items.push(['filter', `Search logs: <b>${esc(f === 'q' ? 'text' : f)}</b> = ${short}`]);
        items.push(['exclude', `Search logs: leave out <b>${esc(f === 'q' ? 'text' : f)}</b> ${short}`]);
        if (tab === 'hunt' && S.filters.length) items.push(['only', 'Search logs with only this filter']);
      }
      if (GROUPABLE[f]) items.push(['group', `Group the log search by ${GROUPABLE[f]}`]);
      const sql = sqlConsoleOn();   // the SQL console pivots exist only while it is on (OSINTHUB_SQL_CONSOLE=1)
      if (f === 'ip' && isIp(val)) { items.push(['event', 'Look up on the threat lists (event drawer)']); if (sql) items.push(['explorer', 'Find in the SQL console']); items.push(['ind', 'Show listing history']); }
      if (sql && f === 'country') items.push(['country', `Explorer: events in ${esc(val)}`]);
      if (sql && f === 'asn') items.push(['asn', `Explorer: events for ${esc(val)}`]);
      if (sql && ['q', 'domain', 'query', 'server_name', 'host'].includes(f)) items.push(['explorer', 'Find in the SQL console']);
      if (target.dataset.entity) items.push(['entity', LABELS.details], ['page', LABELS.full]); // data-entity is added by core/chips.js
      items.push(['copy', 'Copy value']);
      pop.dataset.f = f; pop.dataset.v = val; pop.dataset.e = target.dataset.entity || '';
      if (isPhone()) {   // a phone: the same choices as a ⋯ sheet, in words
        const plain = (h) => new DOMParser().parseFromString(h, 'text/html').body.textContent;
        actionSheet({ id: 'nv-pivot', title: val.length > 40 ? `${val.slice(0, 40)}…` : val, items: items.map(([a, l]) => ({ label: plain(l), run: () => pivot(a, f, val, pop.dataset.e) })) });
        return;
      }
      pop.innerHTML = `<div class="nv-pop-h mono">${esc(f)}</div>${items.map(([a, l]) => `<button class="mi" data-pa="${a}">${l}</button>`).join('')}`;
      pop.hidden = false;
      const r = target.getBoundingClientRect(), W = window.innerWidth, H = window.innerHeight;
      const pw = pop.offsetWidth, ph = pop.offsetHeight;
      pop.style.left = `${Math.max(8, Math.min(r.left, W - pw - 8))}px`;
      pop.style.top = `${r.bottom + 4 + ph > H ? Math.max(8, r.top - ph - 4) : r.bottom + 4}px`;
    }
    el.addEventListener('click', (e) => {
      const t = e.target.closest('.nv-v');
      if (t && el.contains(t)) { e.stopPropagation(); e.preventDefault(); openPop(t); return; }
      if (!e.target.closest('.nv-pop')) closePop();
    });
    el.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.classList?.contains('nv-v')) openPop(e.target); if (e.key === 'Escape') closePop(); });
    el.querySelector('.nv-panes').addEventListener('scroll', closePop, true);
    pop.addEventListener('click', (e) => {
      const b = e.target.closest('[data-pa]'); if (!b) return;
      closePop();
      pivot(b.dataset.pa, pop.dataset.f, pop.dataset.v, pop.dataset.e, e);
    });
    async function pivot(pa, f, val, ent, e) {
      switch (pa) {
        case 'device': setTab('devices', { device: val }); break;
        case 'alert': setTab('alerts', { alert: val }); break;
        case 'filter': sub.addFilter(f, val); break;
        case 'exclude': sub.addFilter(f, val, false, true); break;
        case 'only': sub.addFilter(f, val, true); break;
        case 'group': S.groupby = [GROUPABLE[f]]; emit('filters'); setTab('hunt'); break;
        case 'event': lookupIp(val, openEvent); break;
        case 'explorer': toExplorer({ q: val }); break;
        case 'country': toExplorer({ country: val }); break;
        case 'asn': toExplorer({ q: val }); break;
        case 'ind': {
          try {
            const rows = await api.get('/api/netlog/indicators', { value: val, limit: 20 });
            toast(rows.length ? `${val}: ${rows.map((r) => `${r.source} since ${T.stamp(r.start)}${r.end ? ` until ${T.stamp(r.end)}` : ' (listed)'}`).join(' · ')}` : `${val} has never been on a collected threat list`);
          } catch (err) { toast(err.message, true); }
          break;
        }
        case 'entity': openDetails(ent, e); break;
        case 'page': openFull(entityHref(ent), e); break;
        case 'copy': try { await navigator.clipboard.writeText(val); toast('Copied'); } catch { toast(val); } break;
      }
    }
    document.addEventListener('click', (e) => { if (!el.contains(e.target)) closePop(); });

    // ---------------------------------------------------------------- wiring
    el.querySelectorAll('.nv-tabs button').forEach((b) => (b.onclick = () => setTab(b.dataset.tab)));
    const relabel = () => el.querySelectorAll('.nv-tabs button').forEach((b) => {
      const t = TABS.find(([id]) => id === b.dataset.tab);
      b.querySelector(".nv-tlab").textContent = (isPhone() && PHONE_LABEL[t[0]]) || t[1];
    });
    relabel();
    // a phone turned into a tablet or back (rotation, split screen): every pane draws its other layout
    onPhoneChange(() => { relabel(); paintHeader(); emit('data'); });
    onChange((what) => { if (what === 'range') { paintRange(); refreshTabCount(); } if (what === 'data' && !own) refreshSummary(); });

    let pending = null;
    live.on('netlog_alerts', () => { clearTimeout(pending); pending = setTimeout(() => { refreshSummary(); emit('data'); }, 1500); });
    // the server came back (a restart): read again, so an outage never leaves the view on its error
    live.on('status', (ok) => { if (ok && S.summaryErr) refreshSummary(); });

    // Network remembers its own range (nd.network.range); a link's ?range= wins.
    const range = headerRange(el, { value: { h: LS.get('nd.network.range', 0) }, label: 'Network time range', onChange: (v) => setRange(v) });
    S.range = (/^#network\b/.test(location.hash) && hashRange(location.hash)) || range.get();
    onChange((w) => { if (w === 'range' && S.range.from == null) LS.set('nd.network.range', S.range.h); });
    paintRange();

    api.get('/api/paths').then((l) => (S.lake = { path: l.lake, where: l.inbox_where || null })).catch(() => {});
    Promise.allSettled([refreshSummary(), loadDevices(), loadSources()])
      .then(() => setTab(hashTab() || (badSub() ? 'overview' : LS.get('nd.network.tab', 'overview')), hashOpts(), 'replace'));

    // Deep link #network/<tab> (the shell's alerts badge uses #network/alerts).
    const hashTab = () => { const t = location.hash.slice(1).split('?')[0].split('/'); return t[0] === 'network' && TABS.some(([id]) => id === t[1]) ? t[1] : null; };
    // #network/<not a tab> (a mistyped or old link): Overview, and the URL says so, never the last-used tab (B2-09)
    const badSub = () => { const t = location.hash.slice(1).split('?')[0].split('/'); return t[0] === 'network' && !!t[1] && !TABS.some(([id]) => id === t[1]); };
    // #network/devices/<id> opens that device (global search links to it)
    const hashOpts = () => { const t = location.hash.slice(1).split('?')[0].split('/'); return t[1] === 'devices' && t[2] ? { device: decodeURIComponent(t.slice(2).join('/')) } : undefined; };
    window.addEventListener('hashchange', () => {
      const t = hashTab();
      if (t && tab) { rangeFromHash(); setTab(t, hashOpts(), 'none'); syncRangeHash(); }
      else if (tab && badSub()) { rangeFromHash(); setTab('overview', undefined, 'replace'); }   // a bad link keeps its ?range=
    });
    inst = {
      show() {
        if (S.summaryErr) refreshSummary();
        const t = hashTab();
        if (t) rangeFromHash();
        if (tab && !t && badSub()) { rangeFromHash(); setTab('overview', undefined, 'replace'); }
        else if (t && tab && (t !== tab || hashOpts())) setTab(t, hashOpts(), 'none'); else if (tab) mounted.get(tab)?.show?.();
        setTimeout(() => { syncHash('replace'); syncRangeHash(); }, 0); // the shell writes a bare '#network' after show(); add the sub-tab and range back
      },
      hide() { closePop(); for (const m of mounted.values()) m.hide?.(); },
    };
  },
  show() { document.body.classList.add('nv-active'); inst?.show(); },
  hide() { document.body.classList.remove('nv-active'); inst?.hide(); },
});

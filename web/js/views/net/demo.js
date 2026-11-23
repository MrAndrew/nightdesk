// Network → Import → Demo data: load a day of invented home-network logs with contacts planted against the
// indicators listed right now, check each scenario against the alert it produced, and remove it all again.
// Backend: osinthub/netlog/demo.py. Reference: okf/data/netlog.md#demo-data
import { isPhone } from '../../core/mobile.js';
import { confirmSheet } from '../../core/sheet.js';
import { emit, esc, fmt, toast, loadDevices, SEVTAG, ts, Z } from './common.js';
import { errorState, stateAct } from '../../core/view.js';

// Scenarios left out, grouped by cause: one line per cause with its fix (naming the lists when several share
// it), and the scenario names under it.
const GROUP_REASON = {
  offline: 'These lists have never been downloaded, and fetching is off (offline mode):',
  first: 'These lists have not finished their first download yet:',
  off: 'These lists are turned off:',
  empty: 'These lists have no usable entries right now:',
  key: 'These lists need an API key:',
};
export function skippedHtml(st) {
  const sk = st.skipped || [];
  if (!sk.length) return '';
  const groups = new Map();
  for (const s of sk) {
    const k = s.cause || `${s.reason}\u0000${s.fix}`;
    if (!groups.has(k)) groups.set(k, { ...s, titles: [], lists: [] });
    const g = groups.get(k);
    g.titles.push(s.title);
    if (s.list && !g.lists.includes(s.list)) g.lists.push(s.list);
  }
  const reason = (g) => (g.lists.length > 1 && GROUP_REASON[g.cause] ? `${GROUP_REASON[g.cause]} ${g.lists.join(', ')}.` : g.reason);
  return `<div class="states-demo-skip"><div class="states-demo-skh">${sk.length} scenario${sk.length === 1 ? ' was' : 's were'} left out (never faked):</div>
    <ul>${[...groups.values()].map((g) => `<li><b>${esc(reason(g))}</b> <span${g.tech ? ` title="${esc(g.tech)}"` : ''}>${esc(g.fix)}</span>${g.action === 'sources' || g.action === 'key' ? ' <a class="nv-link" href="#sources">Open Sources</a>' : g.action === 'news' ? ' <a class="nv-link" href="#news">Open News</a>' : ''}
      <small>${g.titles.map(esc).join(' · ')}</small></li>`).join('')}</ul></div>`;
}

// What removing the demo does to things you made, exactly as the server will do it (demo.py removal_plan, the same
// function DELETE /demo runs): what goes, what is un-merged and which rules stay because they also match your data.
export function yoursHtml(p) {
  if (!p) return '';
  const li = (xs, why) => xs.map((x) => `<li>${esc(x.text)}${why && x.why ? ` <small>(${esc(x.why)})</small>` : ''}</li>`).join('');
  const rm = p.remove || {};
  const blocks = [
    [rm.labels, 'Names you gave demo devices, removed'],
    [rm.merges, 'Merges of demo devices, undone'],
    [rm.rules, '“This is expected” rules that only match the demo, removed'],
    [p.unmerge, 'Your devices that were merged into a demo device, un-merged'],
    [p.keep?.rules, '“This is expected” rules kept, because they also match your own data', true],
  ].filter(([xs]) => xs?.length);
  return blocks.length ? `<div class="finisha-plan">${blocks.map(([xs, h, why]) => `<div class="finisha-plan-h">${esc(h)}:</div><ul>${li(xs, why)}</ul>`).join('')}</div>` : '';
}

// A one-line note over the Network tabs while the demo just loaded is on screen, so it never passes for real data.
function demoNote(ctx, on) {
  const panes = document.querySelector('#view-network .nv-panes');
  if (!panes) return;
  panes.querySelector('.states-demo-note')?.remove();
  panes.classList.toggle('states-has-note', !!on);
  if (!on) return;
  const n = document.createElement('div');
  n.className = 'states-demo-note';
  n.setAttribute('role', 'status');
  n.innerHTML = `<span><b>This is demo data</b> — remove it in Network › Connect logs.</span><button class="nv-link" data-dn="go">Go to Connect logs</button><button class="icon-btn" data-dn="x" title="Hide this note" aria-label="Hide the demo note"><svg class="i"><use href="#i-x"/></svg></button>`;
  n.addEventListener('click', (e) => {
    const a = e.target.closest('[data-dn]')?.dataset.dn;
    if (a === 'go') ctx.goto('import');
    if (a) demoNote(ctx, false);
  });
  panes.prepend(n);
}
// The note is pointless on Import itself (the Remove button is right there): hidden there by CSS, back on other tabs.

// The result tag: green when every scenario was planted and passed, plain when every planted one passed but some
// could not be planted (nothing failed: red is for a check that failed), red only when a planted check failed.
export const badgeCls = (st, possible) => (st.passed < st.total ? 'bad' : st.total === possible ? 'ok' : '');
// One short line on why the rest were not planted; the list with each fix is further down (skippedHtml).
const LEFT_WHY = { offline: 'a threat list that has not been downloaded', first: 'a threat list that has not been downloaded',
  off: 'a threat list that is turned off', empty: 'a threat list with no usable entries right now', key: 'a threat list that needs an API key',
  news: 'a news story naming an indicator', retro: 'a threat-list entry with the right dates', history: 'a threat-list entry with the right dates' };
export function leftOutLine(st, possible) {
  const n = possible - (st.total || 0);
  if (n <= 0) return '';
  const why = [...new Set((st.skipped || []).map((s) => LEFT_WHY[s.cause]).filter(Boolean))];
  return `<p class="netdetail-demo-left">The other ${n} ${n === 1 ? 'was' : 'were'} left out, not faked: ${why.length ? `${n === 1 ? 'it needs' : 'they need'} ${why.join(', or ')}` : 'what they need is not in this install yet'}. Details below.</p>`;
}

export function mount(el, ctx) {
  const { api } = ctx;
  let st = null, busy = '', confirm = false;

  async function load() {
    try { st = await api.get('/api/netlog/demo'); } catch (e) { st = { error: e.message }; }
    paint();
  }

  function paint() {
    const loaded = st?.loaded;
    const possible = st?.possible || st?.total || 0;
    const badge = busy ? `<span class="panel-badge">${esc(busy)}</span>`
      : loaded ? `<span class="panel-badge ${badgeCls(st, possible)}" title="${st.passed} of ${st.total} planted scenarios raised the right alert; ${possible - st.total} could not be planted">${st.total} of ${possible} planted · ${st.passed} pass</span>` : '';
    let body;
    if (st?.error) body = errorState({ act: stateAct('Load the demo again', { data: { demo: 'load' } }), title: 'The demo did not finish', why: 'Nothing of yours was touched. Try loading it again.', err: st.error, size: 'sm' });
    else if (busy === 'loading') body = `<p class="nv-dim">Building a day of traffic for seven invented devices, planting contacts with indicators listed in your lake right now, then importing and matching it…</p>`;
    else if (busy === 'removing') body = `<p class="nv-dim">Removing the demo rows, devices, alerts and files…</p>`;
    else if (!loaded) {
      body = `
        <p class="nv-dim">Try matching without a sensor. Night Desk makes up a day of logs for a small home network (laptop, phone, TV, thermostat, doorbell, NAS, gaming PC) and plants contacts with real indicators from your lists: a Feodo botnet controller, a Spamhaus DROP range, a Tor exit, an IOC from a news story, a known-exploited CVE and more. Then it checks that each one raised the alert it should.</p>
        <p class="nv-dim">The demo uses its own addresses (<code>10.86.24.0/24</code>, <code>fd4e:6400:d35c::/48</code>) and is clearly named, so it never mixes with your own devices. One click removes it all.</p>
        <div class="nv-row"><a class="nv-link" href="api/netlog/demo/bundle" download>Download as a file</a><span class="nv-dim"></span><button class="src-btn primary" data-demo="load">Load demo</button></div>`;
    } else {
      const fp = st.false_positives || [];
      body = `
        <p class="states-demo-head">${st.total < possible / 3 ? `Only <b>${st.total} of ${possible}</b> scenarios could be planted: most need threat lists this install has not downloaded yet.`
          : `Planted <b>${st.total} of ${possible}</b> scenarios; ${st.passed === st.total && st.total ? `all ${st.total} raised` : `<b>${st.passed}</b> raised`} the alert they should.`}</p>
        ${st.total < possible / 3 ? "" : leftOutLine(st, possible)}
        <p class="nv-dim">Loaded ${esc(ts(st.loaded_at, false))} ${Z()}: ${fmt(st.rows || 0)} rows, ${st.devices?.found ?? 0} of ${st.devices?.expected ?? 0} devices recognised, ${fp.length ? `<b class="nv-bad">${fp.length} unexpected high or medium alert${fp.length === 1 ? '' : 's'}</b> on ordinary traffic` : 'no false alarms on ordinary traffic'}. Click a check to open its alert.</p>
        <ul class="nv-demo-l">${(st.scenarios || []).map((s) => `
          <li class="${s.ok ? 'ok' : 'bad'}" ${s.alert ? `data-alert="${esc(s.alert.id)}" tabindex="0" role="button"` : ''} title="${esc(s.story)}">
            <span class="nv-demo-i" aria-label="${s.ok ? 'pass' : 'fail'}">${s.ok ? '✓' : '✕'}</span>
            <span class="nv-demo-t"><b>${esc(s.title)}</b><small>${esc(s.feature || '')}${s.ok ? '' : ` · ${esc(s.why)}`}</small></span>
            <span class="tag ${SEVTAG[s.alert?.severity || s.expect.severity] || ''}">${esc(s.alert?.severity || s.expect.severity)}</span>
          </li>`).join('')}</ul>
        ${skippedHtml(st)}
        ${confirm
          ? `<div class="nv-warnbox">Remove the demo? Its ${fmt(st.rows || 0)} rows, devices and alerts are deleted, and its home prefixes are taken out of your settings. Night Desk also forgets the demo devices, so they never count as known devices. Your own logs, devices and rules for them are not touched.${yoursHtml(st.your_changes)}</div>
             <div class="nv-row"><span class="nv-dim"></span><button class="src-btn" data-demo="cancel">Cancel</button><button class="src-btn primary" data-demo="remove">Remove demo</button></div>`
          : `<div class="nv-row"><button class="src-btn" data-demo="recheck">Check again</button><span class="nv-dim"></span><button class="src-btn" data-demo="ask">Remove demo</button></div>`}`;
    }
    el.innerHTML = `<div class="panel-head"><span class="panel-title">Demo data</span>${badge}</div><div class="nv-cb nv-pad">${body}</div>`;
  }

  async function changed() { await loadDevices(); ctx.refreshSummary(); emit('data'); }

  el.addEventListener('click', async (e) => {
    const li = e.target.closest('[data-alert]');
    if (li) { ctx.goto('alerts', { alert: li.dataset.alert }); return; }
    let a = e.target.closest('[data-demo]')?.dataset.demo;
    if (!a) return;
    // a phone asks in a confirm sheet (core/sheet.js); a desktop in the card
    if (a === 'ask' && isPhone()) {
      if (!(await confirmSheet({ title: 'Remove the demo?', text: 'Its rows, devices and alerts are deleted, and its home prefixes are taken out of your settings. Your own logs, devices and rules are not touched.', confirm: 'Remove demo', danger: true }))) return;
      a = 'remove';
    }
    if (a === 'ask') { confirm = true; paint(); return; }
    if (a === 'cancel') { confirm = false; paint(); return; }
    if (a === 'recheck') { await load(); return; }
    if (a === 'load') await start();
    if (a === 'remove') {
      busy = 'removing'; confirm = false; paint();
      try {
        const r = await api.del('/api/netlog/demo');
        const mine = (r.removed_labels || 0) + (r.removed_merges || 0) + (r.removed_rules || 0);
        toast(`Demo removed: ${fmt(r.removed_rows)} rows and ${fmt(r.removed_alerts)} alerts${mine ? ', and the names and rules made only for it' : ''}${r.unmerged ? `; ${fmt(r.unmerged)} of your devices un-merged` : ''}${r.kept_rules ? `; ${fmt(r.kept_rules)} rule${r.kept_rules === 1 ? '' : 's'} kept` : ''}`);
        demoNote(ctx, false);
        await changed();
      } catch (err) { toast(err.message, true); }
      busy = ''; await load();
    }
  });
  el.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target.closest('[data-alert]')) { e.preventDefault(); e.target.click(); } });

  async function start() {
    busy = 'loading'; paint();
    try {
      st = await api.post('/api/netlog/demo');
      const possible = st.possible || st.total;
      toast(`Demo loaded: ${st.total} of ${possible} scenarios planted, ${st.passed} pass${st.total < possible ? ' (see Connect logs for what was left out)' : ''}`, st.passed !== st.total);
      await changed();
    } catch (err) { toast(err.message, true); await load(); busy = ''; paint(); return; }
    busy = ''; paint();
    // land on the payoff: the most important demo alert, with a note that it is demo data
    if (st?.top_alert) {
      ctx.goto('alerts', { alert: st.top_alert });
      history.replaceState(null, '', `#network/alerts/${encodeURIComponent(st.top_alert)}`);
      demoNote(ctx, true);
    }
  }

  return {
    show(opts) { if (opts?.demo === 'load' && !busy) start(); else load(); },
  };
}

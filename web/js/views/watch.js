// Watch: the front page. One deterministic "since you were last here" briefing (GET /api/watch) in a fixed order:
// Your network, Touches you, Newly exploited, News you follow, Big stories, Feed health (only when something is
// wrong). "Caught up" moves the app's one last-seen marker (PUT /api/marker), which News and the KEV list share.
// On a new lake a setup checklist (GET /api/setup/status) sits on top. Contract: okf/architecture/watch.md
import { registerView } from '../core/panels.js';
import { esc, ago, toast, epssTag, epssText, debounce, reducedMotion } from '../core/util.js';
import * as T from '../core/time.js';
import * as stack from '../core/stack.js';
import { entityHref, newTab } from '../core/open.js';
import { viewHeader, emptyState, errorState, loadingState } from '../core/view.js';
import { isPhone, onPhoneChange } from '../core/mobile.js';
import { actionSheet, confirmSheet } from '../core/sheet.js';
import { undoToast } from '../core/undo.js';
import { afterRender } from '../core/page.js';

// Times come from the app's one clock (core/time.js, Settings › Display): "21:40" today, "Mon 21:40" this week,
// "3 Nov 21:40" before that.
const when = (t) => (t ? T.when(t) : '');
const longDate = () => T.longDate();
const since = (t) => { const s = (Date.now() - new Date(t).getTime()) / 1e3; return s < 60 ? 'just now' : `${ago(t).replace(' ago', '')} ago`; };
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const SEV = { high: 'red', medium: 'amber', low: '', info: '' };
// whole units, rounded down, as Network's "Are my logs current?" card words an age (net/overview.js span)
const spanWords = (sec) => {
  if (sec == null) return '—';
  const m = Math.floor(sec / 60), h = Math.floor(sec / 3600), d = Math.floor(sec / 86400);
  if (sec < 5400) return plural(Math.max(1, m), 'minute');
  if (sec < 172800) return plural(h, 'hour');
  return plural(d, 'day');
};

let headlineOf = null; // the Network view's own plain headline for an alert (net/alert-text.js), when available
import('./net/alert-text.js').then((m) => { if (typeof m.headline === 'function') headlineOf = m.headline; }).catch(() => {});

registerView({
  id: 'watch',
  mount(el, ctx) {
    const { api, live, openEvent } = ctx;
    const S = { quick: null, data: null, setup: null, showSetup: false, busy: false, visible: true, dirty: false, err: null, demo: null };
    el.innerHTML = `${viewHeader({ title: 'Watch', cls: 'watch-mast', purpose: esc(longDate()), actions: '<span class="watch-mast-links"></span>' })}
      <div class="watch" aria-live="polite">${loadingState('Reading what changed…')}</div>`;
    const root = el.querySelector('.watch');

    // A failed load retries by itself: every 10 s while Watch is open, when the live connection comes back, and when
    // Watch is shown again, so a server restart never leaves "Couldn't read the briefing" up.
    let retryT = null;
    async function load() {
      clearTimeout(retryT);
      try {
        // the alert counts (okf/data/netlog.md#the-needs-you-count) and the per-source freshness verdicts are the
        // ones Network shows, read from the same endpoints so the two pages cannot disagree
        const [d, s, c, f] = await Promise.all([api.get('/api/watch'), api.get('/api/setup/status').catch(() => null),
          api.get('/api/netlog/alerts/count').catch(() => null), api.get('/api/netlog/freshness').catch(() => null)]);
        S.data = d; S.setup = s; S.count = c; S.fresh = f; S.err = null;
      } catch (e) {
        S.err = e.message || 'unknown error';
        retryT = setTimeout(() => { if (S.visible && !document.hidden) load(); }, 10000);
      }
      S.dirty = false;
      render();
    }
    const reload = debounce(() => { if (!S.visible) S.dirty = true; else if (isPhone()) M.load(); else load(); }, 600);

    // ------------------------------------------------------------ pieces
    const fill = (txt) => esc(txt).replace('{since}', `<b>${esc(when(S.data.window.since))}</b>`);
    const headline = (i) => {
      if (headlineOf && i.evidence) { try { return headlineOf({ ...i, evidence: i.evidence }).text; } catch {} }
      return i.title || `${i.device_name || i.device || 'A home device'}: ${i.indicator || 'alert'}`;
    };
    const demoTag = '<span class="tag watch-demo" title="Made-up demo data, not your network">DEMO</span>';

    function netRow(i) {
      return `<a class="watch-row" href="${esc(i.href)}">
        <span class="watch-sev ${i.demo ? '' : SEV[i.severity] || ''}">${esc(i.severity || '')}</span>
        <span class="watch-main"><span class="watch-t">${esc(headline(i))}</span>
          <span class="watch-m">${i.demo ? demoTag : ''}${esc(i.device_name || i.device || '')}${i.reopened ? ' · <span class="watch-acc">back again</span>' : ''}${i.still_open ? ' · <span class="watch-acc">still open</span>' : ''} · ${esc(ago(i.last_ts || i.ts))}</span></span>
        <span class="watch-go" aria-hidden="true">›</span></a>`;
    }
    function kevRow(i, extra = '') {
      return `<a class="watch-row" href="${esc(entityHref(`cve:${String(i.cve || '').toLowerCase()}`))}" data-ev="${esc(i.id)}" title="Details: ${esc(i.cve)} (Cmd- or Ctrl-click: open full page)">
        <span class="watch-cve mono">${esc(i.cve)}</span>
        <span class="watch-main"><span class="watch-t">${esc([i.vendor, i.product].filter(Boolean).join(' '))}${i.name ? ` <span class="watch-dim">· ${esc(i.name)}</span>` : ''}</span>
          <span class="watch-m">${extra}${i.ransomware ? '<span class="tag red">ransomware</span>' : ''}${i.epss != null ? epssTag(i.epss, i.epss_percentile) : ''}<span>added ${esc(i.added ? T.date(i.added) : '—')}</span>${i.due ? `<span>fix by ${esc(T.date(i.due))}</span>` : ''}</span></span>
        <span class="watch-go" aria-hidden="true">›</span></a>`;
    }
    function storyRow(i, meta) {
      return `<a class="watch-row" href="${esc(i.href)}">
        <span class="watch-main"><span class="watch-t watch-serif">${esc(i.title || 'Untitled story')}</span>
          <span class="watch-m">${meta}</span></span>
        <span class="watch-go" aria-hidden="true">›</span></a>`;
    }
    const outlets = (n) => (n ? plural(n, 'outlet') : '');
    // "You follow SonicWall": what in your followed list (My stack) this item matched
    const followTag = (i) => `<span class="tag stack-tag" title="Matches what you follow">You follow ${esc((i.matched || []).map((m) => stack.matchName(m, i.matched_names)).join(', '))}</span>`;
    function followAlertRow(i, why) {
      return `<a class="watch-row" href="${esc(i.href)}">
        <span class="watch-sev ${i.demo ? '' : SEV[i.severity] || ''}">${esc(i.severity || '')}</span>
        <span class="watch-main"><span class="watch-t">${esc(headline(i))}</span>
          <span class="watch-m">${why}${i.demo ? demoTag : ''}${i.malware ? `<span>${esc(i.malware)}</span>` : ''}<span>${esc(i.device_name || i.device || '')}</span><span>${esc(ago(i.last_ts || i.ts))}</span></span></span>
        <span class="watch-go" aria-hidden="true">›</span></a>`;
    }
    function epssRow(i, why) {
      // a CVE: click = Details, Cmd/Ctrl/middle-click = its full page (core/open.js)
      return `<a class="watch-row" href="${esc(entityHref(`cve:${String(i.cve || '').toLowerCase()}`))}" data-entity="cve:${esc(String(i.cve || '').toLowerCase())}" data-nocard>
        <span class="watch-cve mono">${esc(i.cve)}</span>
        <span class="watch-main"><span class="watch-t">Exploit likelihood jumped from ${esc(epssText(i.prev_epss))} to ${esc(epssText(i.epss))}</span>
          <span class="watch-m">${why}${epssTag(i.epss, i.epss_percentile, i.prev_epss, i.since)}<span>${esc(ago(i.since))}</span></span></span>
        <span class="watch-go" aria-hidden="true">›</span></a>`;
    }
    function victimRow(i, why) {
      return `<button class="watch-row" data-ev="${esc(i.id)}" title="Open the ransomware post">
        <span class="watch-main"><span class="watch-t">${esc(i.group)} claims <b>${esc(i.victim)}</b></span>
          <span class="watch-m">${why}<span>ransomware leak site</span><span>${esc(ago(i.ts))}</span></span></span>
        <span class="watch-go" aria-hidden="true">›</span></button>`;
    }

    // Just loaded the demo from here: the same report as Network › Connect logs (what was planted, what was left out
    // and how to get it), with a link to the top demo alert, which is also highlighted in the list below.
    function demoResult() {
      const r = S.demo;
      if (!r) return '';
      const possible = r.possible || r.total || 0;
      const top = r.top_alert ? `<a class="src-btn primary finisha-demo-go" href="#network/alerts/${encodeURIComponent(r.top_alert)}?range=all">Open the top demo alert</a>` : '';
      return `<div class="finisha-demo-res" id="finisha-demo-res" role="status">
        <div class="finisha-demo-rh"><p><b>Demo loaded.</b> Planted ${esc(r.total)} of ${esc(possible)} scenarios; ${esc(r.passed)} raised the alert they should.</p>
          <button class="icon-btn" data-act="demo-hide" title="Hide this report" aria-label="Hide the demo report"><svg class="i"><use href="#i-x"/></svg></button></div>
        ${S.demoSkip || ''}
        <div class="finisha-demo-ra">${top}<a class="watch-btnlink" href="#network/import">See every check in Connect logs</a></div></div>`;
    }

    // "Are my logs current?" in one line, with Network's per-source verdict (GET /api/netlog/freshness): the newest
    // time overall, then each source Network calls stale with its own age. A source Network calls current is never
    // named next to the word "stale". Falls back to the briefing's summary when freshness could not be read.
    function freshLine(lg) {
      const f = S.fresh;
      const stale = f ? (f.sources || []).filter((x) => x.stale) : null;
      const newest = f?.newest || lg.newest;
      const tail = stale ? stale.map((x) => ` <span class="counts-stale">${esc(x.label)}: stale, nothing newer for ${esc(spanWords(x.age_s))}.</span>`).join('')
        : lg.stale ? ` <span class="counts-stale">Stale: nothing newer from ${esc((lg.stale_sources || []).join(', ') || 'your sensors')}.</span>` : '';
      return `<p class="watch-note">Your logs cover up to <b>${esc(when(newest))}</b> (${esc(ago(newest))}).${tail}</p>`;
    }

    function sectionBody(s) {
      switch (s.id) {
        case 'network': {
          const lg = s.logs;
          const logLine = !lg ? '' : lg.has_logs ? freshLine(lg)
            : lg.demo_loaded ? '<p class="watch-note">Only demo logs are loaded. <a href="#network/import">Connect your own</a>.</p>'
              : '<p class="watch-note">No network logs yet. <a href="#network/import">Connect your logs</a> or load the demo from the checklist.</p>';
          const so = s.still_open || [], soN = s.still_open_count || 0;
          const still = soN ? `<p class="watch-note watch-still">Still open: ${plural(soN, 'older alert')} ${soN === 1 ? 'is' : 'are'} not new but still need${soN === 1 ? 's' : ''} you.${soN > so.length ? ` <a href="#network/alerts">See all ${esc(soN)}</a>.` : ''}</p>
            <div class="watch-list">${so.map(netRow).join('')}</div>` : '';
          // removing asks first and shows exactly what goes and what stays (the server's removal plan)
          const ask = S.removeAsk ? `<div class="nv-warnbox finisha-watch-ask" role="alert">Remove the demo? Its rows, devices and alerts are deleted. Your own logs, devices and rules for them are not touched.${S.removeAsk}
            <div class="finisha-demo-ra"><button class="watch-btnlink" data-act="demo-cancel">Cancel</button><button class="src-btn primary" data-api="/api/netlog/demo" data-method="DELETE" data-item="demo-remove">Remove demo</button></div></div>` : '';
          const demo = s.demo || lg?.demo_loaded ? `<p class="watch-note">${s.demo ? 'No real alerts: these come from the demo data. ' : ''}${S.removeAsk ? '' : '<button class="watch-btnlink" data-act="demo-ask">Remove demo data…</button>'}</p>${ask}` : '';
          return logLine + (lg?.demo_loaded ? demoResult() : '') + demo + (s.items.length ? `<div class="watch-list">${s.items.map(netRow).join('')}</div>` : '') + still;
        }
        case 'touches': {
          // demo sightings collapse to one line: made-up data should not crowd real matches
          const dm = s.items.filter((i) => i.why === 'network' && i.demo);
          const dl = dm.length ? `<p class="watch-note">${demoTag} ${plural(dm.length, 'demo sighting')} (${esc(dm.map((i) => i.cve || i.indicator || i.title).slice(0, 3).join(', '))}) seen in the demo logs. <a href="#network/alerts">Open the demo alerts</a>.</p>` : '';
          const row = (i) => {
            const why = i.why === 'network'
              ? `<span class="tag red" title="Seen in your network logs">seen on your network${i.devices ? ` · ${plural(i.devices, 'device')}` : ''}</span>${i.demo ? demoTag : ''}`
              : followTag(i);
            if (i.type === 'kev') return kevRow(i, i.recent_follow ? `${why}<span title="Shown once because you just started following it">recent, before you followed</span>` : why);
            if (i.type === 'alert') return followAlertRow(i, i.recent_follow ? `${why}<span title="Shown because you just started following it">open, before you followed</span>` : why);
            if (i.type === 'epss') return epssRow(i, why);
            if (i.type === 'victim') return victimRow(i, why);
            return storyRow(i, `${why}<span>names ${esc(i.indicator || '')}</span><span>${esc(outlets(i.source_count))}</span>`);
          };
          const so = s.still_open || [], soN = s.still_open_count || 0;
          const still = soN ? `<p class="watch-note watch-still">Still open about what you follow: ${plural(soN, 'alert')} not new but not dealt with yet.</p>
            <div class="watch-list">${so.map(row).join('')}</div>` : '';
          return dl + `<div class="watch-list">${s.items.filter((i) => !(i.why === 'network' && i.demo)).map(row).join('')}</div>` + still;
        }
        case 'kev':
          return `<div class="watch-list">${s.items.map((i) => kevRow(i)).join('')}</div>`;
        case 'follow':
          return `<div class="watch-list">${s.items.map((i) => storyRow(i,
            `${i.is_new ? '<span class="tag green">new</span>' : i.new_articles ? `<span class="tag green">+${esc(i.new_articles)} new</span>` : ''}${followTag({ ...i, matched: (i.matched || []).slice(0, 3) })}<span>${esc(outlets(i.source_count))}</span><span>${esc(ago(i.last_seen))}</span>`)).join('')}</div>`;
        case 'stories':
          return `<div class="watch-list">${s.items.map((i) => storyRow(i,
            `${i.is_new ? '<span class="tag green">new</span>' : ''}<span>${esc(outlets(i.source_count))}</span><span>${esc(plural(i.article_count || 0, 'article'))}</span><span>${esc(ago(i.last_seen))}</span>`)).join('')}</div>`;
        case 'health':
          return `<div class="watch-list">${s.items.map((i) => `<a class="watch-row" href="${esc(i.href || '#sources')}">
            <span class="watch-main"><span class="watch-t">${esc(i.name)} <span class="watch-dim">· ${esc({ failing: 'failing', stale: 'stale', off: 'off', offline: 'not fetching' }[i.problem] || i.problem)}</span></span>
            <span class="watch-m"><span>${esc(i.text || '')}</span>${i.since ? `<span>last good ${esc(ago(i.since))}</span>` : ''}</span></span>
            <span class="watch-go" aria-hidden="true">›</span></a>`).join('')}</div>`;
        default: return '';
      }
    }

    // Your network's number says what it counts, next to the total the Alerts tab shows (okf/data/netlog.md#the-needs-you-count)
    function netQual(s) {
      const c = S.count;
      const w = S.data?.window || {};
      const what = `high/medium${s.demo ? ' demo' : ''} ${w.first_visit && !S.data?.viewing_previous ? 'in the last 24 hours' : `new since ${esc(when(w.since))}`}`;
      const all = c && c.open != null ? ` · <a class="counts-all" href="#network/alerts" title="Untriaged alerts of any severity, demo included: the “New” count in Network › Alerts">${esc(c.open)} new in all</a>` : '';
      return `<span class="watch-dim counts-q">${what}${all}</span>`;
    }

    function section(s, quiet) {
      const more = s.count > s.items.length ? ` · showing ${s.items.length}` : '';
      const ofN = s.count > s.items.length ? `<span class="watch-dim watch-of">${esc(s.items.length)} of ${esc(s.count)}</span>` : '';
      const flag = s.id === 'network' && s.items.some((i) => i.severity === 'high' && !i.demo);
      const head = `<header class="watch-sh"><h2 class="watch-h2">${esc(s.title)}</h2>
        <span class="watch-count${s.count ? (flag ? ' red' : s.demo ? '' : ' on') : ''}" title="${esc(`${s.count} new${s.demo ? ' demo alerts' : ''}${more}`)}">${esc(s.count)}</span>${s.demo && s.count ? demoTag : ''}${s.id === 'network' ? netQual(s) : ''}${ofN}
        ${s.link ? `<a class="watch-link" href="${esc(s.link.href)}">${esc(s.link.label)} ›</a>` : ''}</header>`;
      // a section with still-open rows (Touches you: alerts about what you follow) is never hidden or called empty
      const empty = !s.items.length && s.id !== 'network' && !s.still_open_count;
      const noLogs = s.id === 'network' && s.logs && !s.logs.has_logs && !s.logs.demo_loaded; // the logs line says it
      if (quiet && empty) return '';
      return `<section class="watch-sec" data-sec="${esc(s.id)}">${head}
        ${s.items.length || s.id === 'network' || s.still_open_count ? sectionBody(s) : ''}
        ${!s.items.length && !s.still_open_count && s.empty && !noLogs ? emptyState({ why: fill(s.empty), size: 'inline' }) : ''}</section>`;
    }

    function checklist() {
      const st = S.setup;
      if (!st) return '';
      const item = (i) => {
        const a = i.action || {};
        const btn = a.api ? `<button class="src-btn watch-act" data-api="${esc(a.api)}" data-method="${esc(a.method || 'POST')}" data-item="${esc(i.id)}">${esc(a.label)}</button>`
          : a.href ? `<a class="src-btn watch-act" href="${esc(a.href)}">${esc(a.label)}</a>` : '';
        // "What do you run?": common home-lab gear (with its exploited-bug count), then KEV's busiest vendors. The
        // chips stay after a click (shown as followed) so several can be picked in a row.
        if (i.id === 'watchlist' && !i.done && !S.quick && ((i.quick || []).length || (i.suggest || []).length)) {
          const q = (i.quick || []).slice(0, 8);
          S.quick = [...q, ...(i.suggest || []).filter((v) => !q.some((x) => x.label.toLowerCase() === v.toLowerCase())).slice(0, 4)
            .map((v) => ({ vendor: v, product: '', label: v, kev: null }))];
        }
        const sugg = i.id === 'watchlist' && S.quick?.length ? `<div class="watch-sugg-w"><div class="watch-sugg-l">What do you run?</div>
          <div class="watch-sugg" role="group" aria-label="What do you run? One click follows it">${S.quick.map((q) => stack.followButton({ vendor: q.vendor, product: q.product },
            { name: q.label, cls: 'chip watch-follow', chip: q.kev ? `${q.kev} exploited` : '' })).join('')}</div>
          <div class="watch-dim watch-sugg-n">The number is how many of its bugs CISA lists as exploited.</div></div>` : '';
        return `<li class="watch-ck${i.done ? ' done' : ''}${i.optional ? ' opt' : ''}">
          <span class="watch-ck-m" aria-hidden="true">${i.done ? '✓' : '○'}</span>
          <div class="watch-ck-b"><div class="watch-ck-t">${esc(i.title)}${i.optional ? ' <span class="watch-dim">· optional</span>' : ''}<span class="sr-only">${i.done ? ' (done)' : ' (not done)'}</span></div>
            <div class="watch-ck-d"${i.tech ? ` title="${esc(i.tech)}"` : ''}>${esc(i.detail || '')}</div>${sugg}</div>
          ${i.done && !a.api ? '' : btn}</li>`;
      };
      return `<section class="watch-setup" aria-label="Setup checklist">
        <header class="watch-sh"><h2 class="watch-h2">Get set up</h2><span class="watch-dim">${esc(st.done)} of ${esc(st.required)} done</span>
          <button class="watch-link watch-btnlink" data-act="hide-setup">Hide checklist</button></header>
        <ol class="watch-cks">${st.items.map(item).join('')}</ol></section>`;
    }

    function render() {
      if (S.err && !S.data) {
        root.innerHTML = errorState({ retry: load, title: "Couldn't read the briefing", why: 'The Night Desk server did not answer. Everything is still stored; Watch tries again by itself every few seconds.', err: S.err });
        return;
      }
      const d = S.data;
      if (!d) return;
      const w = d.window, m = d.marker;
      const secs = d.sections || [];
      const st = S.setup;
      const setupOn = st && (S.showSetup || (st.first_run && !st.dismissed));
      const nothingNew = !w.first_visit && d.total === 0 && !d.viewing_previous;
      const followOpen = secs.find((s) => s.id === 'touches')?.still_open_count || 0;
      const caught = nothingNew && !d.needs_you && !followOpen;   // never an all-clear while something still needs you
      const sinceLine = d.viewing_previous ? `Showing again since <b>${esc(when(w.since))}</b>`
        : w.first_visit ? 'First visit: the last 24 hours'
          : `Since <b>${esc(when(w.since))}</b> · ${esc(since(w.since))}`;
      const capNote = w.capped ? `<span class="watch-dim"> · your last visit was ${esc(when(w.asked))}; Watch looks back at most ${esc(w.cap_days)} days</span>` : '';
      const prevLink = m.previous && !caught ? `<button class="vh-link" data-act="${d.viewing_previous ? 'current' : 'previous'}">${d.viewing_previous ? 'Back to since your last visit' : `Show since ${esc(when(m.previous))} again`}</button>` : '';
      const setupLink = st && !setupOn ? '<button class="vh-link" data-act="show-setup">Setup checklist</button>' : '';
      // the view header (core/view.js): the date and the window on the left, Caught up and the window links on the right
      el.querySelector('.watch-mast .vh-purpose').innerHTML = `${esc(longDate())} · <span class="watch-since">${sinceLine}${capNote}</span>`;
      el.querySelector('.watch-mast-links').innerHTML = prevLink + setupLink
        // a first visit always offers it, so Watch can leave "First visit" mode even when nothing is new
        + (caught || (setupOn && d.total === 0 && !w.first_visit) ? '' : `<button class="vh-btn primary watch-caught" data-act="caught" ${S.busy ? 'disabled' : ''} title="Mark everything here as seen. News and the KEV list count new from now too.">Caught up</button>`);
      const calm = caught ? `<section class="watch-calm"><h2 class="watch-calm-t">You're caught up.</h2>
        <p>Marked ${m.set_at || m.last_seen ? `at <b>${esc(when(m.last_seen))}</b>` : ''}. New alerts, exploited bugs and stories will show here as they arrive.</p>
        ${m.previous ? `<button class="watch-btnlink" data-act="previous">Show since ${esc(when(m.previous))} again</button>` : ''}</section>` : '';
      const stillNote = nothingNew && (d.needs_you || followOpen) ? `<section class="watch-calm watch-calm-open"><h2 class="watch-calm-t">Nothing new since ${esc(when(w.since))}.</h2>
        <p>But ${d.needs_you ? `${plural(d.needs_you, 'alert')} on your network still need${d.needs_you === 1 ? 's' : ''} you` : `${plural(followOpen, 'open alert')} about what you follow still ${followOpen === 1 ? 'needs' : 'need'} you`}. <a href="#network/alerts">Open them</a>.</p></section>` : '';
      const quiet = !!setupOn || nothingNew;
      const body = secs.map((s) => section(s, quiet)).join('');
      const hidden = quiet ? secs.filter((s) => !s.items.length && s.id !== 'network' && !s.still_open_count).map((s) => s.title) : [];
      const rest = hidden.length ? `<p class="watch-rest">${nothingNew ? 'Nothing new in' : 'Nothing yet in'} ${esc(hidden.join(', '))}${nothingNew ? '.' : ': they fill in as data arrives.'}</p>` : '';
      root.innerHTML = (setupOn ? checklist() : '') + calm + stillNote + body + rest;
      markDemo();
    }

    // ------------------------------------------------------------ actions
    async function caughtUp() {
      S.busy = true; render();
      try { await api.put('/api/marker', {}); await load(); toast('Caught up. New things will show here as they arrive.'); }
      catch (e) { toast(e.message, true); }
      S.busy = false; render();
    }
    async function viewSince(which) {
      try {
        S.data = await api.get('/api/watch', which === 'previous' ? { since: 'previous' } : {});
        render();
        root.closest('.view')?.scrollTo?.({ top: 0 });
      } catch (e) { toast(e.message, true); }
    }
    async function runApi(b) {
      b.disabled = true;
      const label = b.textContent;
      b.textContent = 'Working…';
      try {
        const meth = (b.dataset.method || 'POST').toUpperCase();
        const r = meth === 'DELETE' ? await api.del(b.dataset.api) : await api[meth === 'PUT' ? 'put' : 'post'](b.dataset.api, {});
        const item = b.dataset.item;
        if (item === 'demo' && r && r.scenarios) {
          S.demo = r;
          try { S.demoSkip = (await import('./net/demo.js')).skippedHtml(r); } catch { S.demoSkip = ''; }
        }
        if (item === 'demo-remove') { S.demo = null; S.demoSkip = ''; S.removeAsk = ''; }
        toast(item === 'demo' ? 'Demo data loaded: its alerts are marked DEMO.' : item === 'demo-remove' ? removedText(r) : 'Done');
        await load();
        if (item === 'demo') showDemo();
      } catch (e) { b.disabled = false; b.textContent = label; toast(e.message, true); }
    }
    const removedText = (r) => {
      const mine = [r?.removed_labels && `${r.removed_labels} device name${r.removed_labels === 1 ? '' : 's'}`,
        r?.removed_merges && `${r.removed_merges} merge${r.removed_merges === 1 ? '' : 's'}`,
        r?.removed_rules && `${r.removed_rules} expected-traffic rule${r.removed_rules === 1 ? '' : 's'}`].filter(Boolean);
      return `Demo data removed${mine.length ? `, with the ${mine.join(', ')} made only for it` : ''}${r?.unmerged ? `; ${r.unmerged} of your devices un-merged` : ''}${r?.kept_rules ? `; ${r.kept_rules} rule${r.kept_rules === 1 ? '' : 's'} kept because ${r.kept_rules === 1 ? 'it matches' : 'they match'} your own data` : ''}.`;
    };
    // while the demo report shows, the top demo alert in Your network is marked (kept across live re-renders)
    function markDemo() {
      const sec = S.demo && root.querySelector('[data-sec="network"]');
      if (!sec) return;
      const id = S.demo.top_alert;
      const rows = [...sec.querySelectorAll('.watch-list .watch-row')];
      const row = rows.find((x) => id && x.getAttribute('href') === `#network/alerts/${id}`) || rows[0];
      if (row) { row.classList.add('finisha-hl'); }
    }
    // after a load from here: bring Your network into view with the report on top and the top demo alert marked
    function showDemo() {
      const t = root.querySelector('[data-sec="network"] .finisha-hl') || root.querySelector('[data-sec="network"]');
      if (t) t.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
    }
    async function askRemove() {
      try {
        const [st, m] = await Promise.all([api.get('/api/netlog/demo'), import('./net/demo.js')]);
        S.removeAsk = m.yoursHtml(st.your_changes) || ' ';
      } catch (e) { toast(e.message, true); return; }
      render();
    }
    async function setDismissed(flag) {
      S.showSetup = !flag;
      try { await api.put('/api/setup/dismiss', { dismissed: flag }); if (S.setup) S.setup.dismissed = flag; } catch {}
      render();
    }

    el.addEventListener('click', (e) => {   // the header's actions too
      const ev = e.target.closest('[data-ev]');
      if (ev) { if (!newTab(e)) { e.preventDefault(); openEvent(ev.dataset.ev); } return; }
      const a = e.target.closest('[data-api]');
      if (a) { runApi(a); return; }
      const act = e.target.closest('[data-act]')?.dataset.act;
      if (act === 'caught') caughtUp();
      else if (act === 'previous') viewSince('previous');
      else if (act === 'current') load();
      else if (act === 'hide-setup') setDismissed(true);
      else if (act === 'show-setup') setDismissed(false);
      else if (act === 'retry') load();
      else if (act === 'demo-hide') { S.demo = null; render(); }
      else if (act === 'demo-cancel') { S.removeAsk = ''; render(); }
      else if (act === 'demo-ask') askRemove();
    });

    // live: new needs-you incidents and new KEV entries; the marker moved elsewhere (News "Mark all as read")
    live.on('netlog_alerts', reload);
    live.on('events', (m) => { if (m?.source === 'cisa_kev') reload(); });
    live.on('marker', reload);
    live.on('status', (ok) => { if (ok && isPhone()) { if (M.cardErr || M.feedErr) M.load(); } else if (ok && S.err) load(); });   // the server is back after an outage
    window.addEventListener('nd:stack', reload);   // followed or unfollowed something (here or in any view)
    // a minute-level refresh keeps "3 h ago" and the log age honest while the page stays open
    setInterval(() => { if (S.visible && !document.hidden) (isPhone() ? M.load : load)(); }, 5 * 60e3);

    // ------------------------------------------------------------ the phone Watch (design.md §4.1)
    const M = phoneWatch(el, { api, openEvent, headline: (i) => headline(i), removedText, after: () => afterRender('watch') });
    const layout = (phone) => {
      M.root.hidden = !phone;
      root.hidden = phone;
      if (phone) M.load(); else if (!S.data && !S.err) load();
    };
    onPhoneChange((phone) => layout(phone));
    layout(isPhone());
    inst = {
      show() { S.visible = true; if (isPhone()) M.load(); else if (S.dirty || S.data || S.err) load(); },
      hide() { S.visible = false; },
    };
  },
  show() { inst?.show(); },
  hide() { inst?.hide(); },
});
let inst = null;

// ------------------------------------------------------------------------------------------------ phone
// On a phone Watch is one answer card, then three short cards and the end of the feed (design.md §4.1). Card 1 is
// built from the network endpoints alone (the alert count, log freshness and the top alerts), so it shows first and
// on its own; the other cards come from /api/watch and fail separately with Try again.
const SEVW = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const spanAgo = (sec) => {
  const d = Math.floor(sec / 86400), h = Math.floor(sec / 3600), m = Math.floor(sec / 60);
  return d >= 1 ? plural(d, 'day') : h >= 1 ? plural(h, 'hour') : plural(Math.max(1, m), 'minute');
};
function phoneWatch(el, { api, openEvent, headline, removedText, after }) {
  const M = { card: null, cardErr: null, feed: null, feedErr: null, busy: false };
  const root = document.createElement('div');
  root.className = 'watch-m-root';
  root.hidden = true;
  el.append(root);
  M.root = root;
  root.innerHTML = `<section class="watch-m-answer watch-m-wait" aria-label="Your network" aria-busy="true"><span class="m-skel watch-m-sk1"></span><span class="m-skel watch-m-sk2"></span><span class="m-skel watch-m-sk3"></span></section>
    <div class="watch-m-feed" aria-live="polite"><span class="m-skel m-skel-row"></span><span class="m-skel m-skel-row"></span></div>`;
  const cardEl = () => root.querySelector('.watch-m-answer');
  const feedEl = () => root.querySelector('.watch-m-feed');
  const more = '<button type="button" class="watch-m-more" data-m="menu" aria-haspopup="menu" aria-label="More actions for this card"><svg class="i" aria-hidden="true" viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.7" fill="currentColor"/><circle cx="12" cy="12" r="1.7" fill="currentColor"/><circle cx="19" cy="12" r="1.7" fill="currentColor"/></svg></button>';

  async function loadCard() {
    try {
      const [c, f, top] = await Promise.all([api.get('/api/netlog/alerts/count'), api.get('/api/netlog/freshness'),
        api.get('/api/netlog/incidents', { needs_you: true, limit: 3 }).catch(() => [])]);
      M.card = { c, f, top: Array.isArray(top) ? top : top?.items || [] };
      M.cardErr = null;
    } catch (e) { M.cardErr = e.message || 'unknown error'; }
    drawCard();
  }
  async function loadFeed() {
    try { M.feed = await api.get('/api/watch'); M.feedErr = null; } catch (e) { M.feedErr = e.message || 'unknown error'; }
    drawFeed();
  }
  M.load = () => Promise.all([loadCard(), loadFeed()]).then(() => after?.());

  function alertRow(i) {
    const sev = i.severity || 'info';
    let what = headline(i);
    if (headlineOf && i.evidence) { try { const h = headlineOf(i); what = h.what ? h.what.charAt(0).toUpperCase() + h.what.slice(1) : h.text; } catch {} }
    return `<a class="watch-m-arow" href="#network/alerts/${encodeURIComponent(i.id)}">
      <span class="watch-m-stripe sev-${esc(sev)}" aria-hidden="true"></span>
      <span class="watch-m-amain"><span class="watch-m-dev">${esc(i.device_name || i.device || 'A home device')}</span><span class="watch-m-what">${esc(what)}</span></span>
      <span class="watch-m-aend"><span class="watch-m-sev sev-${esc(sev)}">${esc(SEVW[sev] || sev)}</span><span class="watch-m-age">${esc(ago(i.last_ts || i.ts).replace(' ago', ''))}</span></span></a>`;
  }
  function drawCard() {
    const box = cardEl();
    if (M.cardErr && !M.card) {
      box.className = 'watch-m-answer watch-m-err';
      box.removeAttribute('aria-busy');
      box.innerHTML = `<p class="watch-m-eye">Your network</p><h2 class="watch-m-h">Couldn't load your network</h2>
        <p class="watch-m-p">Night Desk did not answer. It tries again by itself.</p>
        <div class="watch-m-acts"><button type="button" class="m-btn" data-m="retry-card">Try again</button></div>
        <details class="watch-m-det"><summary>Details</summary><p class="mono">${esc(M.cardErr)}</p></details>`;
      return;
    }
    const { c, f, top } = M.card;
    const srcs = f?.sources || [];
    const newest = f?.newest || null;
    const thr = (f?.stale_hours || 24) * 3600;
    const hasLogs = !!newest;
    const stale = hasLogs && (f.age_s ?? 0) > thr;
    const needs = c?.needs_you || 0;
    const open = (c?.high || 0) + (c?.medium || 0) + (c?.low || 0) + (c?.info || 0);   // own alerts, any severity
    const demoN = c?.demo || 0;
    const anyHigh = (c?.high || 0) > 0;
    let state, body, tail = '';
    const current = hasLogs ? `<p class="watch-m-fresh"><span class="watch-m-dot" aria-hidden="true"></span>Logs current · newest ${esc(ago(newest))}</p>` : '';
    if (!hasLogs) {
      state = 'empty';
      body = `<h2 class="watch-m-h">${f?.demo?.loaded ? 'No logs of your own yet' : 'No network logs yet'}</h2>
        <p class="watch-m-p">Night Desk checks your home network's logs against threat lists. Connect logs on a computer${f?.demo?.loaded ? '; the demo alerts show what it finds.' : ', or try it now with made-up demo data.'}</p>
        <div class="watch-m-acts">${f?.demo?.loaded ? '<a class="m-btn m-btn-primary" href="#network/alerts">Open the demo alerts</a>' : '<button type="button" class="m-btn m-btn-primary" data-m="demo">Try the demo</button>'}<a class="m-btn" href="#network/import">Connect logs</a></div>`;
    } else if (stale) {
      state = 'stale';
      const at = T.when(newest);
      const per = srcs.map((x) => `${esc(x.label)}: ${x.stale ? `stale ${esc(spanAgo(x.age_s || 0))}` : 'current'}`).join(' · ');
      const still = open ? `<a class="watch-m-still" href="#network/alerts"><span class="watch-m-stripe sev-${anyHigh ? 'high' : needs ? 'medium' : 'low'}" aria-hidden="true"></span>
          <span>${needs ? `${plural(needs, 'alert')} that need${needs === 1 ? 's' : ''} you, still open from before ${esc(at)}` : `${plural(open, 'low-priority alert')} still open from before ${esc(at)}`}</span><span class="watch-m-go" aria-hidden="true">›</span></a>` : '';
      body = `<h2 class="watch-m-h">Your logs stopped ${esc(spanAgo(f.age_s || 0))} ago</h2>
        <p class="watch-m-p">Nothing after <b>${esc(at)}</b> has been checked, so Night Desk can't tell you whether anything is wrong right now.</p>
        ${per ? `<p class="watch-m-mono">${per}</p>` : ''}
        <div class="watch-m-acts"><a class="m-btn m-btn-primary watch-m-wide" href="#network/import">Check your log sources</a></div>`;
      tail = still;
    } else if (needs) {
      state = anyHigh ? 'high' : 'alerts';
      body = `<h2 class="watch-m-h">${esc(plural(needs, 'alert'))} need${needs === 1 ? 's' : ''} you</h2>${current}
        <div class="watch-m-arows">${top.slice(0, 3).map(alertRow).join('')}</div>
        <div class="watch-m-acts"><a class="m-btn m-btn-primary" href="#network/alerts">Open alerts</a><a class="m-btn" href="#network/devices">Devices</a></div>`;
    } else {
      state = 'calm';
      body = `<h2 class="watch-m-h">Nothing needs you</h2>${current}`;
    }
    const demo = demoN ? `<p class="watch-m-demo mono">${esc(plural(demoN, 'demo alert'))} (made-up) not counted</p>` : '';
    box.className = `watch-m-answer is-${state}`;
    box.removeAttribute('aria-busy');
    box.innerHTML = `<div class="watch-m-top"><p class="watch-m-eye">Your network</p>${more}</div>${body}${demo}${tail}`;
  }

  // the cards after the answer: 3 rows each, then "All N ›"
  const rowLink = (href, t, meta, attrs = '') => `<a class="watch-m-row" href="${esc(href)}"${attrs}><span class="watch-m-rt">${t}</span><span class="watch-m-rm">${meta}</span></a>`;
  function itemRow(i) {
    const cve = String(i.cve || '').toLowerCase();
    if (i.type === 'kev' || (!i.type && i.cve)) return rowLink(entityHref(`cve:${cve}`), esc([i.vendor, i.product].filter(Boolean).join(' ') + (i.name ? ` · ${i.name}` : '') || i.cve), `${esc(i.cve)} · added ${esc(i.added ? ago(i.added) : '—')}`);
    if (i.type === 'epss') return rowLink(entityHref(`cve:${cve}`), `Exploit likelihood of ${esc(i.cve)} jumped`, `${esc(epssText(i.prev_epss))} → ${esc(epssText(i.epss))} · ${esc(ago(i.since))}`);
    if (i.type === 'alert') return rowLink(i.href, esc(headline(i)), `${esc(i.severity || '')} · ${esc(i.device_name || i.device || '')} · ${esc(ago(i.last_ts || i.ts))}`);
    if (i.type === 'victim') return `<button type="button" class="watch-m-row" data-ev="${esc(i.id)}"><span class="watch-m-rt">${esc(i.group)} claims ${esc(i.victim)}</span><span class="watch-m-rm">ransomware leak site · ${esc(ago(i.ts))}</span></button>`;
    const n = i.source_count || 0;
    return rowLink(i.href || '#news', esc(i.title || 'Untitled story'), `${n ? `${esc(plural(n, 'outlet'))} · ` : ''}${i.new_articles ? `+${esc(i.new_articles)} new · ` : ''}${esc(ago(i.last_seen || i.ts))}`);
  }
  function card(s, title, emptyHtml) {
    if (!s) return '';
    const items = [...(s.items || []), ...(s.still_open || [])].filter((i) => !(i.demo && s.id === 'touches'));
    const n = Math.max(s.count || 0, items.length);
    const all = n > 3 && s.link ? `<a class="watch-m-all" href="${esc(s.link.href)}">All ${esc(n)} ›</a>` : '';
    return `<section class="watch-m-card" data-sec="${esc(s.id)}"><header class="watch-m-ch"><h2 class="watch-m-ct">${esc(title)}</h2>${all}</header>
      ${items.length ? items.slice(0, 3).map(itemRow).join('') : `<p class="watch-m-none">${emptyHtml}</p>`}</section>`;
  }
  function drawFeed() {
    const box = feedEl();
    if (M.feedErr && !M.feed) {
      box.innerHTML = `<section class="watch-m-card watch-m-err"><h2 class="watch-m-ct">Couldn't load the rest of the briefing</h2>
        <p class="watch-m-none">Your network above is up to date. The news and exploited-bug cards did not load.</p>
        <div class="watch-m-acts"><button type="button" class="m-btn" data-m="retry-feed">Try again</button></div>
        <details class="watch-m-det"><summary>Details</summary><p class="mono">${esc(M.feedErr)}</p></details></section>`;
      return;
    }
    const secs = M.feed.sections || [];
    const by = (id) => secs.find((x) => x.id === id);
    const since = M.feed.window?.since;
    const nothing = (what) => `Nothing new ${what} since ${esc(T.when(since))}.`;
    const fol = by('follow');
    const followEmpty = fol && fol.following === false
      ? 'You don\'t follow anything yet. <a class="watch-m-in" href="#settings/follow">Settings › What you follow</a>'
      : nothing('about what you follow');
    box.innerHTML = card(by('touches'), 'Touches you', nothing('touches your network or what you follow'))
      + card(by('kev'), 'Newly exploited', nothing('on the exploited list'))
      + card(fol || { id: 'follow', items: [], count: 0 }, 'Following', followEmpty)
      + `<section class="watch-m-end"><p class="watch-m-endt">You're caught up to here</p>
        <button type="button" class="m-btn watch-m-seen" data-m="seen" ${M.busy ? 'disabled' : ''}>Mark all as seen</button></section>`;
  }

  async function markSeen() {
    if (M.busy) return;
    M.busy = true;
    root.querySelectorAll('[data-m="seen"]').forEach((b) => { b.disabled = true; });
    try {
      const r = await api.put('/api/marker', {});
      const prior = r?.undo || null;
      undoToast('Marked all as seen.', prior ? async () => { await api.put('/api/marker', { restore: prior }); await M.load(); } : null);
      await M.load();
    } catch (e) { toast(e.message, true); }
    M.busy = false;
    root.querySelectorAll('[data-m="seen"]').forEach((b) => { b.disabled = false; });
  }
  async function removeDemo() {
    const ok = await confirmSheet({ title: 'Remove the demo?', text: 'Its rows, devices and alerts are deleted. Your own logs, devices and rules for them are not touched.', confirm: 'Remove demo', danger: true });
    if (!ok) return;
    try { const r = await api.del('/api/netlog/demo'); toast(removedText(r)); } catch (e) { toast(e.message, true); }
    M.load();
  }
  async function loadDemo(b) {
    b.disabled = true; b.textContent = 'Loading the demo…';
    try { await api.post('/api/netlog/demo', {}); toast('Demo data loaded: its alerts are marked DEMO.'); } catch (e) { toast(e.message, true); }
    M.load();
  }
  root.addEventListener('click', (e) => {
    const ev = e.target.closest('[data-ev]');
    if (ev) { e.preventDefault(); openEvent(ev.dataset.ev); return; }
    const b = e.target.closest('[data-m]');
    if (!b) return;
    const m = b.dataset.m;
    if (m === 'seen') markSeen();
    else if (m === 'retry-card') loadCard();
    else if (m === 'retry-feed') loadFeed();
    else if (m === 'demo') loadDemo(b);
    else if (m === 'menu') {
      const demo = (M.card?.c?.demo_loaded) || M.card?.f?.demo?.loaded;
      b.setAttribute('aria-expanded', 'true');
      actionSheet({ id: 'watch-card', title: 'Your network', items: [
        { label: 'Mark all as seen', hint: 'Caught up', run: markSeen },
        ...(demo ? [{ label: 'Remove demo data…', danger: true, run: removeDemo }] : []),
      ] }).finally(() => b.setAttribute('aria-expanded', 'false'));
    }
  });
  return M;
}

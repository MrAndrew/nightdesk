// "Is everything working?": a live check built from what the app already reports. Each line is
//   { id, state: 'ok' | 'warn' | 'off', title, detail, fix?: action (help/actions.js) }
// ok = green (working), warn = amber (needs a look), off = grey (off, optional or not set up: not a fault).
// Inputs: live.status() (the live connection), /api/health (offline mode), /api/setup/status (the Watch checklist),
// /api/sources (feed health), /api/netlog/freshness and /api/netlog/status (network logs and list matching),
// /api/settings/about (the AI helper). A failing endpoint makes its line grey "could not check", never green.
// Contract: okf/architecture/help.md#is-everything-working
import { api } from '../core/api.js';
import { live } from '../core/live.js';
import * as T from '../core/time.js';

const safe = (p) => p.then((v) => v, () => null);
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
function age(s) {
  if (s == null) return '';
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))} min`;
  if (s < 172800) return `${Math.floor(s / 3600)} h`;
  return `${Math.floor(s / 86400)} days`;
}
const when = (t) => T.when(t);   // the app's one clock (core/time.js)

export async function checks() {
  const [health, setup, srcs, fresh, nstat, about] = await Promise.all([
    safe(api.get('/api/health')), safe(api.get('/api/setup/status')), safe(api.sources()),
    safe(api.get('/api/netlog/freshness')), safe(api.get('/api/netlog/status')), safe(api.get('/api/settings/about')),
  ]);
  const offline = !!health?.offline;
  const item = (id) => setup?.items?.find((i) => i.id === id);
  const out = [];

  // 1. the server and the live connection
  const ls = live.status();
  if (!health) out.push({ id: 'server', state: 'warn', title: 'Night Desk server', detail: 'The server did not answer. Is it still running? Reload once it is back.', fix: { fn: 'reload', label: 'Reload' } });
  else if (ls.state === 'offline' && !offline) out.push({ id: 'server', state: 'warn', title: 'Live connection', detail: 'Lost the live connection to the server; retrying by itself. Pages still load, but nothing updates live meanwhile.', fix: { fn: 'reload', label: 'Reload' } });
  else out.push({ id: 'server', state: 'ok', title: 'Live connection', detail: ls.state === 'idle' ? `Connected. ${ls.title.replace(/^Connected, but /, 'No new data for ')}`.replace(/\.$/, '') + '.' : 'Connected to the Night Desk server; updates arrive live.' });

  // 2. offline mode
  out.push(offline
    ? { id: 'offline', state: 'off', title: 'Offline mode is on', detail: 'Nothing is fetched from the internet. Your logs still import and match against the lists already here; sources do not update.', tech: 'Offline mode is the OSINTHUB_OFFLINE=1 setting in the command or file that starts Night Desk.', fix: { help: 'guides/offline', label: 'About offline mode' } }
    : { id: 'offline', state: 'ok', title: 'Online', detail: 'Sources are fetched on their schedules. Nothing else leaves this machine.' });

  // 3. feeds
  const list = Array.isArray(srcs) ? srcs : srcs?.sources || null;
  const feeds = item('feeds');
  if (!list) out.push({ id: 'feeds', state: 'off', title: 'Sources', detail: 'Could not read the list of sources.', fix: { go: '#settings/sources', label: 'Open Sources' } });
  else {
    const on = list.filter((s) => s.enabled && !s.unavailable);
    const bad = on.filter((s) => ['error', 'reconnecting'].includes(s.status));
    const fixHref = feeds?.action?.href?.replace(/^#sources$/, '#settings/sources') || '#settings/sources';
    const fix = { go: fixHref, label: feeds?.action?.label || 'Open Sources' };
    if (!on.length) out.push({ id: 'feeds', state: 'off', title: 'Every source is off', detail: 'Night Desk is not collecting anything. Turn on the sources you want in Settings › Sources.', fix });
    else if (offline) out.push({ id: 'feeds', state: 'off', title: `${plural(on.length, 'source')} on, paused by offline mode`, detail: feeds?.detail || 'They will update again when offline mode is off.', tech: feeds?.tech, fix });
    else if (bad.length) out.push({ id: 'feeds', state: 'warn', title: `${plural(bad.length, 'source')} with a problem`, detail: `${bad.slice(0, 4).map((s) => s.name).join(', ')}${bad.length > 4 ? ` and ${bad.length - 4} more` : ''} reported an error. The others are fine; Sources shows each one's last message.`, fix });
    else if (feeds && !feeds.done) out.push({ id: 'feeds', state: 'warn', title: 'Sources starting', detail: feeds.detail, fix });
    else out.push({ id: 'feeds', state: 'ok', title: `${plural(on.length, 'source')} on, none failing`, detail: feeds?.detail || 'Every source that is on reports no problem.', fix: feeds?.action?.href?.endsWith('/choose') ? fix : null });
  }

  // 4. network logs and their freshness
  const logs = item('logs');
  if (!fresh && !logs) out.push({ id: 'logs', state: 'off', title: 'Network logs', detail: 'The network part is not installed in this build.' });
  else if (!setup?.has_logs) {
    out.push({ id: 'logs', state: 'off', title: 'No network logs connected yet', detail: setup?.demo ? 'Only the demo network is loaded. Connect your firewall, sensor or Pi-hole to watch your real network.' : 'Night Desk is not watching your network yet. Connect a firewall, sensor or Pi-hole, or import files.', fix: { help: 'guides/connect', label: 'Connect logs' } });
  } else {
    const stale = (fresh?.sources || []).filter((s) => s.stale);
    const waiting = (fresh?.sources || []).filter((s) => s.waiting);
    if (stale.length) out.push({ id: 'logs', state: 'warn', title: 'Network logs have gone quiet', detail: `${stale.map((s) => `${s.label}: nothing newer for ${age(s.age_s)}`).join('; ')} (the limit is ${age(stale[0].threshold_s)}). Night Desk cannot see what is happening now. Check the device or sensor is still sending.`, fix: { go: '#network/import', label: 'Open Connect logs' } });
    else out.push({ id: 'logs', state: 'ok', title: 'Network logs are current', detail: fresh?.newest ? `Logs cover up to ${when(fresh.newest)} (${T.ago(fresh.newest)}).` : (logs?.detail || 'Logs are coming in.') });
    if (waiting.length) out.push({ id: 'senders', state: 'warn', title: `${plural(waiting.length, 'device')} not sending yet`, detail: `${waiting.map((s) => s.label).join(', ')} has a token but has not delivered logs. Run its commands on the device, or check it can reach the upload port.`, fix: { go: '#network/import', label: 'Open Connect logs' } });
  }
  const demo = item('demo');
  if (setup?.demo) out.push({ id: 'demo', state: 'ok', title: 'Demo data is loaded', detail: 'Its alerts are marked DEMO and never count as needing you. Remove it from Connect logs when you are done.', fix: { go: '#network/import', label: 'Manage the demo' } });
  else if (demo && !setup?.has_logs) out.push({ id: 'demo', state: 'off', title: 'Demo data not loaded', detail: demo.detail, fix: { api: '/api/netlog/demo', method: 'POST', label: 'Load demo data', done: 'Demo data loaded' } });

  // 5. matching against the threat lists
  if (nstat) {
    const errs = nstat.errors || [];
    if (errs.length) out.push({ id: 'matching', state: 'warn', title: 'Some threat lists could not be loaded for matching', detail: `${plural(errs.length, 'error')}: ${String(errs[0]?.message || errs[0]?.error || errs[0]).slice(0, 160)}. Alerts from the other lists still work.`, fix: { go: '#settings/sources', label: 'Open Sources' } });
    else {
      const lists = (nstat.sources || []).filter((x) => (x.active || 0) > 0);
      const active = lists.reduce((n, x) => n + (x.active || 0), 0) + (nstat.reported?.active || 0);
      if (!active) out.push({ id: 'matching', state: offline ? 'off' : 'warn', title: 'No threat lists loaded yet', detail: offline
        ? 'There is nothing to check your logs against, and offline mode stops the lists from being fetched. Logs still import; alerts start once lists are in.'
        : 'There is nothing to check your logs against yet, so no alert can be raised. Turn on threat lists in Settings › Sources; they fill on their first run.', fix: { go: '#settings/sources', label: 'Open Sources' } });
      else out.push({ id: 'matching', state: 'ok', title: 'Matching against threat lists', detail: `${active.toLocaleString()} active entries from ${new Set(lists.map((x) => x.source)).size} list${new Set(lists.map((x) => x.source)).size === 1 ? '' : 's'}${nstat.last_refresh ? `, last refreshed ${when(nstat.last_refresh)}` : ''}. New list entries re-check your recent logs by themselves.` });
    }
  }

  // 6. the setup to-dos the checklist tracks
  const watch = item('watchlist');
  if (watch) out.push(watch.done ? { id: 'watchlist', state: 'ok', title: 'You follow what you run', detail: watch.detail }
    : { id: 'watchlist', state: 'warn', title: 'Not following anything yet', detail: watch.detail, fix: { fn: 'follow', label: 'Follow a vendor' } });
  const ab = item('abusech');
  if (ab) out.push(ab.done ? { id: 'abusech', state: 'ok', title: 'abuse.ch key set', detail: ab.detail }
    : { id: 'abusech', state: 'off', title: 'abuse.ch key not set (optional)', detail: ab.detail, tech: ab.tech, fix: { help: 'glossary/abusech', label: 'What it unlocks' } });

  // 7. the local AI helper
  const ai = about?.ai;
  if (!about) out.push({ id: 'ai', state: 'off', title: 'Local AI helper', detail: 'Could not check.' });
  else if (!ai) out.push({ id: 'ai', state: 'off', title: 'Local AI helper (optional)', detail: 'Not part of this build. Keyword search is used, and everything else works.' });
  else if (ai.up) out.push({ id: 'ai', state: 'ok', title: 'Local AI helper running', detail: 'Search by meaning and story summaries are on, on this machine.' });
  else if (ai.configured) out.push({ id: 'ai', state: 'warn', title: 'Local AI helper not answering', detail: 'It is turned on (Settings › AI, or AI_HELPER) but did not answer. Keyword search is used meanwhile.', fix: { go: '#settings/ai', label: 'Open Local AI' } });
  else out.push({ id: 'ai', state: 'off', title: 'Local AI helper not running (optional)', detail: 'Search by meaning and story summaries need it; everything else works without it, using keyword search.', fix: { go: '#settings/ai', label: 'Set up AI' } });

  return { lines: out, at: new Date(), offline };
}

export function summary(lines) {
  const warn = lines.filter((l) => l.state === 'warn').length;
  return warn ? { state: 'warn', text: `${plural(warn, 'thing')} need${warn === 1 ? 's' : ''} a look` } : { state: 'ok', text: 'Everything is working' };
}

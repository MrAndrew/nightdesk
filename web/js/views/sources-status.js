// Sources view, "Local pipeline" section: the AI helper (models, up or down, queue), the vector index (backend,
// counts per collection), the article fetch queue (blocked counts per outlet), the entity pipeline and
// network-log matching. Reads /api/ai/status, /api/news/sources, /api/entities/status and /api/netlog/status;
// a card whose package is missing says so. Contract: okf/architecture/web-client.md#sources-view
import { esc, ago, fmt, compact } from '../core/util.js';

const COLLS = [['cves', 'CVEs'], ['articles', 'Article chunks'], ['entities', 'Entities'], ['events', 'Events']];
const dot = (cls, label) => `<span class="ps-dot ${cls}"></span><span class="ps-st ${cls}">${esc(label)}</span>`;
const kv = (rows) => `<dl class="ps-kv">${rows.filter(Boolean).map(([k, v, cls = '']) => `<dt>${esc(k)}</dt><dd class="mono ${cls}">${v}</dd>`).join('')}</dl>`;
const unix = (t) => (t ? new Date(t * 1000).toISOString() : null);
const unavailable = (what, e) => `<div class="ps-na">${esc(what)} is not available${e ? ` (${esc(e)})` : ''}.</div>`;

function card(id, title, sub, state, body) {
  return `<article class="ps-card" data-ps="${id}"><header class="ps-h"><div><div class="ps-t">${esc(title)}</div><div class="ps-sub">${esc(sub)}</div></div><div class="ps-state">${state}</div></header>${body}</article>`;
}

// The AI helper is optional. Red only when it was expected (AI_HELPER set) or answered during this server run and
// has stopped; otherwise grey "Not running — optional". The raw connection error only ever sits under Details.
function aiCard(ai, err) {
  if (!ai) return card('ai', 'Local AI helper', 'Optional: smarter search and summaries on this machine', dot('off', 'unknown'), unavailable('AI status', err));
  const h = ai.helper || {}, hh = h.health || {};
  const up = !h.down && hh.ok;
  const m = hh.models || {};
  const pending = Object.values(ai.index || {}).reduce((a, x) => a + (x.pending || 0), 0);
  const embedded = Object.values(ai.index || {}).reduce((a, x) => a + (x.documents || 0), 0);
  const details = kv([
    ['Looks for it at', esc(h.url || '—')],
    h.last_error && ['Last answer', esc(h.last_error)],
    ['Waiting to embed', `${fmt(pending)} items (kept until it runs)`],
  ]);
  if (!up && !h.configured && !h.ever_up) {
    return card('ai', 'Local AI helper', 'Optional: smarter search and summaries on this machine', dot('off', 'Not running — optional'), `
      <p class="states-ai-what">Adds search by meaning (not just keywords), story summaries and better entity extraction. Without it everything works with keyword search and rule-based extraction.</p>
      ${embedded ? '<p class="states-ai-what">It has run on this machine before: until it is started again, search falls back to keywords and new items wait in the queue.</p>' : ''}
      <p class="states-ai-how">Turn it on in <a href="#settings/ai">Settings › AI</a> (Apple silicon): you choose which models to download, and Night Desk starts it. This card turns green within a minute.</p>
      <details class="ps-det"><summary>Details</summary>${details}</details>`);
  }
  if (!up) {
    return card('ai', 'Local AI helper', 'Embeddings and chat on this machine', dot('err', 'Not responding'), `
      <p class="states-ai-what">${h.ever_up ? 'It was working earlier in this session but has stopped answering.' : 'It is turned on (Settings › AI, or AI_HELPER) but is not answering.'} Search falls back to keywords and new items wait in the queue until it is back.</p>
      <p class="states-ai-how">Start it once (it is shared, never run a second copy): <code>uv run python -m osinthub.ai.server</code></p>
      <details class="ps-det"><summary>Details</summary>${kv([
        ['Endpoint', esc(h.url || '—')],
        h.last_error && ['Last error', esc(h.last_error)],
        h.retry_in_s > 0 && ['Retry in', `${Math.round(h.retry_in_s)} s`],
        ['Embedding queue', `${fmt(pending)} pending`],
      ])}</details>`);
  }
  const model = (x, kind) => (x ? `<span class="ps-model"><b>${esc(kind)}</b><span title="${esc(x.id || '')}">${esc(x.id || '—')}</span>${x.loaded ? '<i class="ok">loaded</i>' : `<i class="err">${esc(x.error || 'not loaded')}</i>`}${x.dim ? `<i>${x.dim}-d</i>` : ''}</span>` : '');
  return card('ai', 'Local AI helper', 'Embeddings and chat on this machine', dot('ok', 'Up'), `
    <div class="ps-models">${model(m.chat, 'Chat')}${model(m.embed, 'Embed')}</div>
    ${kv([
      ['Endpoint', esc(h.url || '—')],
      ['Uptime', hh.uptime_s ? `${(hh.uptime_s / 3600).toFixed(1)} h` : '—'],
      ['Embedding queue', `${fmt(pending)} pending`, pending ? 'warn' : ''],
      ['Mode', ai.offline ? 'offline (no outbound fetches)' : 'online'],
    ])}`);
}

function vecCard(ai, err) {
  const v = ai?.vectors;
  if (!v || v.error) return card('vec', 'Search index', 'Search by meaning', dot('err', 'Error'), unavailable('The vector index', v?.error || err));
  const counts = v.counts || {};
  const max = Math.max(1, ...Object.values(counts));
  const idx = ai.index || {};
  return card('vec', 'Search index', 'Search by meaning, kept on this machine', dot('ok', v.backend || '—'), `
    <div class="ps-bars">${COLLS.map(([k, l]) => `<div class="ps-bar"><span class="ps-bl">${l}</span><span class="ps-bt"><i style="width:${(100 * (counts[k] || 0) / max).toFixed(1)}%"></i></span><b class="mono">${fmt(counts[k] ?? 0)}</b></div>`).join('')}</div>
    ${kv(Object.entries(idx).map(([k, x]) => [`${k} index`, `${fmt(x.documents)} docs · ${x.pending ? `<span class="warn">${fmt(x.pending)} pending</span>` : 'up to date'} · pass ${esc(ago(unix(x.last_pass)))}`]))}`);
}

function fetchCard(ns, err) {
  if (!ns) return card('fetch', 'Article fetch queue', 'Full-text fetching for news items', dot('off', 'unknown'), unavailable('News status', err));
  const q = ns.queue || {}, f = ns.fetcher || {};
  const outlets = ns.outlets || [];
  const blocked = outlets.reduce((a, o) => a + (o.blocked || 0), 0), failed = outlets.reduce((a, o) => a + (o.failed || 0), 0);
  const bad = outlets.filter((o) => o.blocked || o.failed).sort((a, b) => (b.blocked + b.failed) - (a.blocked + a.failed));
  const state = ns.offline ? dot('warn', 'Paused (offline)') : f.running ? dot('run', 'Fetching') : dot('ok', 'Idle');
  return card('fetch', 'Article fetch queue', 'Full-text fetching for news items', state, `
    <div class="ps-tiles">
      <div><b>${fmt(q.due)}</b><span>due</span></div>
      <div><b>${fmt(q.waiting_retry)}</b><span>retrying</span></div>
      <div class="${blocked ? 'err' : ''}"><b>${fmt(blocked)}</b><span>blocked</span></div>
      <div class="${failed ? 'warn' : ''}"><b>${fmt(failed)}</b><span>failed</span></div>
    </div>
    ${kv([
      ['Embedding', `${fmt(q.embedded)} embedded · ${q.embed_pending ? `<span class="warn">${fmt(q.embed_pending)} pending</span>` : 'none pending'}`],
      ['Clustering', `${fmt(ns.stories?.total)} stories · ${fmt(q.unclustered)} unclustered`],
      ['Last pass', f.last_pass ? `${esc(ago(f.last_pass))} · ${fmt(f.fetched)} fetched` : 'none since start'],
    ])}
    ${bad.length ? `<table class="ps-tbl"><thead><tr><th>Outlet</th><th class="r">Blocked</th><th class="r">Failed</th><th>Why</th></tr></thead><tbody>${bad.slice(0, 6).map((o) => {
      const why = (ns.reasons || []).find((r) => r.source === o.source);
      return `<tr><td>${esc(o.source)}</td><td class="r ${o.blocked ? 'err' : ''}">${fmt(o.blocked)}</td><td class="r ${o.failed ? 'warn' : ''}">${fmt(o.failed)}</td><td class="ps-why" title="${esc(why?.reason || '')}">${esc(why?.reason || '—')}</td></tr>`;
    }).join('')}</tbody></table>` : '<div class="ps-note">No outlet is blocking or failing.</div>'}
    ${(ns.skipped_feeds || []).length ? `<details class="ps-det"><summary>${ns.skipped_feeds.length} sources skipped on purpose</summary><ul>${ns.skipped_feeds.map((s) => `<li><b>${esc(s.name)}</b> ${esc(s.reason)}</li>`).join('')}</ul></details>` : ''}`);
}

function entCard(es, err) {
  if (!es) return card('ent', 'Entity pipeline', 'Extraction, linking and claim scoring', dot('off', 'unknown'), unavailable('The entities layer', err));
  const t = es.task || {}, lp = t.last_pass || {};
  const refs = Object.entries(t.reference?.files || {});
  const missing = refs.filter(([, v]) => /missing/.test(String(v)));
  const co = es.claims_by_origin || {};
  return card('ent', 'Entity pipeline', 'Extraction, linking and claim scoring', lp.at ? dot(lp.dirty ? 'run' : 'ok', lp.dirty ? 'Working' : 'Up to date') : dot('warn', 'No pass yet'), `
    <div class="ps-tiles">
      <div><b>${compact(es.entities)}</b><span>entities</span></div>
      <div><b>${compact(es.mentions)}</b><span>mentions</span></div>
      <div><b>${compact(es.claims)}</b><span>claims</span></div>
      <div><b>${compact(es.events_linked)}</b><span>linked</span></div>
    </div>
    ${kv([
      ['Claims by origin', Object.entries(co).map(([k, n]) => `${esc(k)} ${fmt(n)}`).join(' · ') || '—'],
      ['Last pass', lp.at ? `${esc(ago(lp.at))} · ${fmt(lp.claims_scored)} claims scored · ${lp.seconds ?? '—'} s${lp.dirty ? ` · <span class="warn">${fmt(lp.dirty)} dirty</span>` : ''}` : '—'],
      ['Reference sets', refs.length ? (missing.length ? `<span class="warn">${missing.length} of ${refs.length} missing</span> (${esc(missing.map(([k]) => k).join(', '))})` : `${refs.length} loaded`) : '—'],
    ])}
    ${missing.length ? '<div class="ps-note">Reference sets (ATT&amp;CK, MISP galaxies, public suffixes) download when online; until then aliases and technique names come from what is already in the lake.</div>' : ''}`);
}

function netCard(nl, err) {
  if (!nl) return card('net', 'Network log matching', 'Threat-list intervals for Zeek imports', dot('off', 'not installed'), unavailable('Network log matching', err));
  const src = nl.sources || [];
  const total = src.reduce((a, s) => a + (s.active || 0), 0);
  const errs = nl.errors || [];
  return card('net', 'Network log matching', 'Threat-list intervals for Zeek imports', errs.length ? dot('err', `${errs.length} error${errs.length > 1 ? 's' : ''}`) : dot('ok', 'Current'), `
    ${kv([
      ['Intervals rebuilt', esc(ago(nl.last_refresh))],
      ['Active indicators', `${fmt(total)} across ${new Set(src.map((s) => s.source)).size} lists`],
      nl.reported && ['From reporting', `${fmt(nl.reported.indicators)} kept · ${fmt(nl.reported.active)} active · ${fmt(nl.reported.counts?.allowlisted_domain || 0)} allowlisted`],
      ...errs.slice(0, 3).map((e) => ['Error', esc(typeof e === 'string' ? e : JSON.stringify(e)), 'err']),
    ])}
    <a class="src-btn" href="#network/import">Import logs ›</a>`);
}

export function mountPipelineStatus(host, api) {
  host.innerHTML = `<div class="src-group-head"><span class="src-gname">Behind the scenes</span><span class="src-gdesc">The parts that run on this machine: the optional AI helper, the search index, article fetching, Intel and log matching. They keep working offline.</span><button class="src-btn ghost ps-refresh" title="Refresh now"><svg class="i"><use href="#i-clock"/></svg><span class="ps-at mono"></span></button></div>
    <details class="finishb-pipe"><summary>Technical details: how each part is doing</summary>
    <div class="ps-grid">${['ai', 'vec', 'fetch', 'ent', 'net'].map((k) => `<article class="ps-card ps-skel" data-ps="${k}"></article>`).join('')}</div></details>`;
  const grid = host.querySelector('.ps-grid');
  let at = null, busy = false;
  async function load() {
    if (busy) return; busy = true;
    const [ai, ns, es, nl] = await Promise.allSettled([api.get('/api/ai/status'), api.get('/api/news/sources'), api.get('/api/entities/status'), api.get('/api/netlog/status')]);
    const v = (r) => (r.status === 'fulfilled' ? r.value : null), e = (r) => r.reason?.message;
    grid.innerHTML = aiCard(v(ai), e(ai)) + vecCard(v(ai), e(ai)) + fetchCard(v(ns), e(ns)) + entCard(v(es), e(es)) + netCard(v(nl), e(nl));
    // "updated …" only when something answered: a failed check never claims fresh data
    const any = [ai, ns, es, nl].some((r) => r.status === 'fulfilled');
    if (any) at = new Date().toISOString();
    failed = !any; busy = false; stamp();
  }
  let failed = false;
  const stamp = () => { host.querySelector('.ps-at').textContent = failed ? 'could not check' : at ? `updated ${ago(at)}` : ''; };
  host.querySelector('.ps-refresh').onclick = load;
  load();
  const t = setInterval(() => { if (host.offsetParent) load(); else stamp(); }, 20000);
  return { refresh: load, destroy() { clearInterval(t); } };
}

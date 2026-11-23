// Network → Alerts: guided questions (answered inline from the netlog API, each with a Hunt pivot)
// and the indicator profile (provider details, lists and tiers, feed records, other alerts/devices, entity claims).
import { S, SEVC, emit, setRange, v, devLink, ruleLabel, tierChip, bytes, ts, tsShort, esc, fmt, toast, Z, hsCue } from './common.js';
import * as T from '../../core/time.js';
import { flag, accentColor } from '../../core/util.js';
import { kindOf, remoteOf, dname, homeNames, srcName } from './alert-text.js';
import { errorState, loadingState } from '../../core/view.js';

const H = 3600e3, D = 86400e3;
const iso = (t) => new Date(t).toISOString();

// The question context: the incident's first contact (so an earlier day of the same beacon is never "history"),
// the value to ask about (the outside address for an IDS alert, the name actually looked up for a domain), and the kind.
export function alertCtx(d) {
  const e = d.evidence || {};
  const k = kindOf(d.incident?.kind ? { ...d, kind: d.incident.kind } : d);
  let kind = e.indicator?.kind;
  let ind = d.indicator;
  if (k.fam === 'ids') { ind = remoteOf(d); kind = 'ip'; }
  else if (kind === 'domain') ind = (e.indicator?.observed || [])[0] || d.indicator;
  const indF = kind === 'domain' ? 'query' : kind === 'cve' ? 'text' : 'ip';
  const t0 = Date.parse(d.incident?.ts || e.first_ts || d.ts), t1 = Date.parse(d.incident?.last_ts || e.last_ts || d.last_ts || d.ts);
  const homes = e.device?.home_ips || [];
  const port = (d.rows || []).find((r) => homes.includes(r.resp_h))?.resp_p ?? (e.sample || [])[0]?.resp_p;
  return { e, dev: d.device, ind, indF, t0, t1, kind, k, homes, port };
}

// One question card: title, an answer filled in later, and a Hunt pivot.
const qcard = (id, n, title, sub) => `
  <section class="nv-q" data-q="${id}">
    <div class="nv-q-h"><span class="nv-q-n">Q${n}</span><div class="nv-q-t">${title}${sub ? `<div class="nv-q-s mono">${sub}</div>` : ''}</div>
      <button class="chip nv-q-go" data-hunt="${id}" title="Open this question as a log search">Search ›</button></div>
    <div class="nv-q-a"><div class="nv-sk" style="width:70%"></div><div class="nv-sk" style="width:45%;margin-top:8px"></div></div>
  </section>`;

// The questions that fit the kind and direction; ones that cannot apply are left out.
function questionSet(d) {
  const c = alertCtx(d);
  const who = c.dev ? `<b data-nochips>${esc(dname(c.dev))}</b>` : 'a home device';
  const ind = `<b class="mono">${esc(c.ind || '')}</b>`;
  const qs = [];
  const add = (id, title, sub) => qs.push([id, title, sub]);
  if (c.k.fam === 'kev') {
    add('notice', 'What did the log entry say?', 'the notice or software rows that named it');
    add('others', `Do other devices mention ${ind}?`, 'all imported logs');
    return qs;
  }
  if (c.k.fam === 'in') {
    add('others', `Which of your devices did ${ind} try?`, 'all imported logs');
    add('answered', `Did ${homeNames(d).length > 1 ? 'they' : who} answer?`, 'connection outcomes from this address');
    if (c.homes.length && c.port != null) add('exposed', `Is port ${esc(c.port)} reachable from the internet?`, 'outside addresses that got an answer on that port');
    add('talkback', `Did any home device connect back to ${ind}?`, 'from the first contact on');
    if (c.k.accepted) add('volume', `How much data moved?`, 'compared with this device\'s other connections');
    return qs;
  }
  if (!c.ind) { add('around', `What else did ${who} talk to around that time?`, `±10 min around ${ts(c.t0)} ${Z()}`); return qs; }
  if (c.dev) add('before', `Has ${who} contacted ${ind} before?`, '30 days before this incident began');
  if (c.dev) add('around', `What else did ${who} talk to around that time?`, `±10 min around ${ts(c.t0)} ${Z()}`);
  add('others', `Which other devices contacted ${ind}?`, 'all imported logs');
  add('proto', 'What do the protocol details say?', 'web requests, secure-connection names and DNS lookups');
  if (c.dev && c.k.fam !== 'ids') add('volume', `Are the bytes and duration unusual for ${who}?`, `compared with all of this device's connections`);
  return qs;
}

export function questionsHtml(d) {
  const qs = questionSet(d);
  return { n: qs.length, html: `<div class="nv-qs">${qs.map(([id, t, s0], i) => qcard(id, i + 1, t, s0)).join('')}</div>` };
}

function spark(days, mark) {
  const W = 300, Hh = 34, n = days.length, max = Math.max(1, ...days.map((x) => x.n));
  const bw = W / n;
  return `<svg class="nv-spark" viewBox="0 0 ${W} ${Hh}" preserveAspectRatio="none" role="img" aria-label="Daily contacts">
    ${days.map((x, i) => `<rect x="${i * bw + 0.5}" y="${Hh - (x.n ? Math.max(2, (x.n / max) * Hh) : 1)}" width="${Math.max(1, bw - 1.5)}" height="${x.n ? Math.max(2, (x.n / max) * Hh) : 1}" fill="${i === mark ? SEVC.high : x.n ? accentColor() : '#262b33'}"><title>${T.date(x.day)}: ${x.n}</title></rect>`).join('')}
  </svg><div class="nv-spark-l mono"><span>${T.date(days[0]?.day)}</span><span>daily rows to the indicator, 30 days</span><span>${T.date(days[n - 1]?.day)} (incident start)</span></div>`;
}

const mini = (cols, rows) => `<table class="nv-qt"><thead><tr>${cols.map((c) => `<th class="${c.r ? 'r' : ''}">${c.h}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${cols.map((c) => `<td class="${c.r ? 'r ' : ''}mono" data-l="${String(c.h).replace(/<[^>]*>/g, '').replace(/"/g, '&quot;')}">${c.f(r)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
const pct = (x) => `${Math.round(x * 100)}%`;
const ACC = 'SF,S1,S2,S3,RSTO,RSTR';

// Fill every question; returns the Hunt pivots by question id.
export function runQuestions(root, d, ctx) {
  const { api } = ctx;
  const c = alertCtx(d);
  const devQ = c.dev ? `device:${c.dev}` : '';
  const indQ = c.ind ? `${c.indF}:${c.ind}` : '';
  const has = (id) => !!root.querySelector(`[data-q="${id}"]`);
  const set = (id, html) => { const a = root.querySelector(`[data-q="${id}"] .nv-q-a`); if (a) { a.innerHTML = html; hsCue(a, 'Answer table'); } };
  const fail = (id) => (e) => set(id, errorState({ retry: () => location.reload(), retryLabel: 'Reload the page', title: "Couldn't answer this one", why: 'The logs could not be searched just now; the other answers still stand.', err: e.message, size: 'inline' }));
  const agg = (p) => api.get('/api/netlog/aggregate', p);
  const homeQ = c.homes.length ? `resp_h:${c.homes.join(',')}` : '';
  const pivots = {
    before: { filters: [...(c.dev ? [{ f: 'device', v: c.dev }] : []), { f: c.indF, v: c.ind }], groupby: ['day', 'log_type'], range: { from: c.t0 - 30 * D, to: c.t1 + H } },
    around: { filters: c.dev ? [{ f: 'device', v: c.dev }] : [{ f: c.indF, v: c.ind }], groupby: ['resp_h', 'resp_p'], range: { from: c.t0 - 10 * 60e3, to: c.t0 + 10 * 60e3 } },
    others: { filters: [{ f: c.indF, v: c.ind }], groupby: ['device', 'log_type'], range: { h: 0 } },
    proto: { filters: [...(c.dev ? [{ f: 'device', v: c.dev }] : []), { f: c.indF, v: c.ind }, { f: 'log_type', v: 'conn', neg: true }], groupby: ['log_type'], range: { h: 0 } },
    volume: { filters: [...(c.dev ? [{ f: 'device', v: c.dev }] : []), { f: 'log_type', v: 'conn' }], groupby: ['resp_h'], range: { h: 0 } },
    notice: { filters: [{ f: 'q', v: c.ind }], groupby: ['log_type'], range: { h: 0 } },
    answered: { filters: [{ f: 'orig_h', v: c.ind }], groupby: ['conn_state'], range: { h: 0 } },
    exposed: { filters: [{ f: 'resp_h', v: c.homes.join(',') }, { f: 'resp_p', v: String(c.port) }, { f: 'conn_state', v: ACC }], groupby: ['orig_h'], range: { h: 0 } },
    talkback: { filters: [{ f: 'resp_h', v: c.ind }], groupby: ['device'], range: { from: c.t0, to: Date.now() } },
  };

  // Q: baseline before the incident began (so the incident's own later days are never cited as history).
  // asked per hour and folded into days of the app's one clock (core/time.js), so the bars match the dates shown
  if (has('before')) agg({ group: 'hour', query: `${devQ} ${indQ}`, since: iso(c.t0 - 30 * D), until: iso(c.t0), limit: 800 }).then((r) => {
    const byDay = new Map(), dayLast = new Map();
    for (const g of r.groups) {
      const k = T.dayKey(g.key);
      byDay.set(k, (byDay.get(k) || 0) + g.count);
      const l = g.last || g.key;
      if (!dayLast.has(k) || String(l) > String(dayLast.get(k))) dayLast.set(k, l);
    }
    const alertDay = T.dayKey(c.t0);
    const days = [];
    for (let t = c.t0 - 29 * D; t < c.t0 + D / 2; t += D) { const k = T.dayKey(t); days.push({ day: k, n: k === alertDay ? (byDay.get(k) || 0) + (d.incident?.count || d.count || 0) : byDay.get(k) || 0 }); }
    const prior = [...byDay].map(([key, count]) => ({ key, count, last: dayLast.get(key) }));
    const n30 = r.total;
    const n7 = prior.filter((g) => Date.parse(g.last || g.key) >= c.t0 - 7 * D).reduce((s0, g) => s0 + g.count, 0);
    const lastPrior = prior.map((g) => g.last).sort().pop();
    const verdict = n30 ? `<span class="nv-ans warn">Yes</span> ${fmt(n30)} rows on ${prior.length} day${prior.length === 1 ? '' : 's'} in the 30 days before this incident began (last ${tsShort(lastPrior)})${Date.parse(lastPrior) < Date.parse(c.e.interval?.start || 0) ? ', before it was listed, so those did not alert' : ''}. A habit, not a one-off.`
      : `<span class="nv-ans bad">No</span> Nothing in the 30 days before ${tsShort(c.t0)}: this incident is the <b>first</b> time this device reached ${esc(c.ind)}.`;
    set('before', `<div class="nv-q-r">${verdict}</div>
      <div class="nv-q-kpis"><div><span class="label">7 days before</span><b class="mono">${fmt(n7)}</b></div><div><span class="label">30 days before</span><b class="mono">${fmt(n30)}</b></div><div><span class="label">This incident</span><b class="mono">${fmt(d.incident?.count ?? d.count)}</b></div></div>
      ${spark(days, days.length - 1)}`);
  }).catch(fail('before'));

  // Q: what else around the first contact.
  const win = { since: iso(c.t0 - 10 * 60e3), until: iso(c.t0 + 10 * 60e3) };
  if (has('around')) {
    if (!c.dev) set('around', '<div class="nv-q-r">No single home device to follow. Search the logs for everything around that time.</div>');
    else Promise.all([
      agg({ group: 'resp_h', query: `${devQ} log_type:conn`, ...win, limit: 8 }),
      agg({ group: 'query', query: `${devQ} log_type:dns`, ...win, limit: 6 }),
    ]).then(([dst, dns]) => {
      if (!dst.groups.length && !dns.groups.length) { set('around', '<div class="nv-q-r">No other traffic from this device in that window.</div>'); return; }
      set('around', `<div class="nv-q-r">${fmt(dst.total)} connections to ${fmt(dst.groups.length)}${dst.groups.length === 8 ? '+' : ''} destinations and ${fmt(dns.total)} DNS lookups in the 20 minutes around the first contact.</div>
        <div class="nv-q-2">
          ${mini([{ h: 'Destination', f: (g) => `${v('ip', g.key)}${g.key === c.ind ? ' <span class="tag red">this one</span>' : ''}` }, { h: 'Conns', r: 1, f: (g) => fmt(g.count) }, { h: 'Bytes', r: 1, f: (g) => bytes(g.bytes) }], dst.groups)}
          ${dns.groups.length ? mini([{ h: 'Names looked up', f: (g) => v('query', g.key) }, { h: 'n', r: 1, f: (g) => fmt(g.count) }], dns.groups) : ''}
        </div>`);
    }).catch(fail('around'));
  }

  // Q: other devices (outbound: who else reached it; inbound: which devices it tried, calmly).
  if (has('others')) agg({ group: 'device', query: indQ, limit: 20 }).then((r) => {
    const homesG = r.groups.filter((g) => g.key);
    const others = homesG.filter((g) => g.key !== c.dev);
    let verdict;
    if (c.k.fam === 'in') verdict = homesG.length > 1 ? `<span class="nv-ans warn">${homesG.length} devices</span> It tried ${homesG.length} of your devices. That is normal for a scanner; what matters is whether any answered (next question).`
      : `<span class="nv-ans">One device</span> It only reached ${homesG[0] ? esc(dname(homesG[0].key)) : 'one address'}.`;
    else if (c.k.fam === 'kev') verdict = others.length ? `<span class="nv-ans warn">${others.length} more</span> Other devices' logs mention it too: check their software as well.` : '<span class="nv-ans">Only this one</span> No other device\'s logs mention it.';
    else verdict = !others.length ? `<span class="nv-ans">Only this one</span> No other device in your logs reached ${esc(c.ind)}.`
      : `<span class="nv-ans bad">${others.length} more</span> ${others.length === 1 ? 'Another device' : 'Other devices'} also reached it: open ${others.length === 1 ? 'it' : 'them'} below and check ${others.length === 1 ? 'it' : 'them'} too.`;
    set('others', `<div class="nv-q-r">${verdict}</div>${r.groups.length ? mini([
      { h: 'Device', f: (g) => (g.key ? devLink(g.key) : '<span class="nv-dim">outside address</span>') + (g.key === c.dev ? ' <span class="tag">this alert</span>' : '') },
      { h: 'Rows', r: 1, f: (g) => fmt(g.count) }, { h: 'First', f: (g) => tsShort(g.first) }, { h: 'Last', f: (g) => tsShort(g.last) }], r.groups) : ''}`);
  }).catch(fail('others'));

  // Q (inbound): did the device answer?
  if (has('answered')) agg({ group: 'conn_state', query: `orig_h:${c.ind} ${homeQ}`, limit: 12 }).then((r) => {
    const acc = r.groups.filter((g) => ACC.split(',').includes(g.key));
    const n = acc.reduce((s0, g) => s0 + g.count, 0);
    const verdict = n ? `<span class="nv-ans bad">Yes</span> ${fmt(n)} of ${fmt(r.total)} connections were answered and completed.`
      : `<span class="nv-ans">No</span> None of its ${fmt(r.total)} connections got a real answer (refused, reset, unanswered or unclear).`;
    const words = { SF: 'completed', S0: 'no reply', REJ: 'refused', RSTO: 'completed, then reset', RSTR: 'answered, then reset', S1: 'still open', OTH: 'unclear', SH: 'half-open', RSTOS0: 'reset before answer' };
    set('answered', `<div class="nv-q-r">${verdict}</div>${mini([{ h: 'Outcome', f: (g) => `${esc(words[g.key] || g.key || '—')} <span class="nv-dim">${esc(g.key || '')}</span>` }, { h: 'Conns', r: 1, f: (g) => fmt(g.count) }, { h: 'Bytes', r: 1, f: (g) => bytes(g.bytes) }], r.groups)}`);
  }).catch(fail('answered'));

  // Q (inbound): is the port open to the internet?
  if (has('exposed')) agg({ group: 'orig_h', query: `${homeQ} resp_p:${c.port} conn_state:${ACC}`, limit: 15 }).then((r) => {
    const home = new Set([...S.devices.values()].flatMap((x) => x.ips || []));
    const out = r.groups.filter((g) => g.key && !home.has(g.key));
    const verdict = out.length ? `<span class="nv-ans bad">Yes</span> ${fmt(out.length)}${out.length === 15 ? '+' : ''} outside address${out.length === 1 ? '' : 'es'} got an answer on port ${esc(c.port)}. It is reachable from the internet: check port forwarding and UPnP on your router.`
      : `<span class="nv-ans">No sign of it</span> No outside address got an answer on port ${esc(c.port)} in your logs.`;
    set('exposed', `<div class="nv-q-r">${verdict}</div>${out.length ? mini([{ h: 'Outside address', f: (g) => v('ip', g.key) }, { h: 'Conns', r: 1, f: (g) => fmt(g.count) }, { h: 'Last', f: (g) => tsShort(g.last) }], out.slice(0, 8)) : ''}`);
  }).catch(fail('exposed'));

  // Q (inbound): did anything at home connect back to it?
  if (has('talkback')) agg({ group: 'device', query: `resp_h:${c.ind}`, since: iso(c.t0), limit: 10 }).then((r) => {
    const back = r.groups.filter((g) => g.key);
    set('talkback', `<div class="nv-q-r">${back.length ? `<span class="nv-ans bad">Yes</span> ${back.map((g) => devLink(g.key)).join(', ')} connected to it afterwards: treat that device as possibly compromised.`
      : '<span class="nv-ans">No</span> No home device connected to it afterwards.'}</div>`);
  }).catch(fail('talkback'));

  // Q (KEV): the log entry that named the CVE.
  if (has('notice')) api.get('/api/netlog/connections', { query: `text:${c.ind}`, raw: true, limit: 20 }).then((r) => {
    const rows = r.rows.map((x) => ({ t: x.ts, type: x.log_type, msg: x.raw?.msg || x.raw?.note || x.raw?.name || x.raw?.unparsed_version || '' }));
    set('notice', rows.length ? `<div class="nv-q-r">${fmt(r.total)} log entr${r.total === 1 ? 'y' : 'ies'} name it.</div>${mini([{ h: 'When', f: (x) => tsShort(x.t) }, { h: 'Log', f: (x) => esc(x.type) }, { h: 'Says', f: (x) => esc(x.msg) }], rows.slice(0, 8))}`
      : '<div class="nv-q-r">The entries are no longer in your logs.</div>');
  }).catch(fail('notice'));

  // Q: protocol details from the raw Zeek rows.
  if (has('proto')) api.get('/api/netlog/connections', { query: `${devQ} ${indQ} -log_type:conn`.trim(), raw: true, limit: 200 }).then((r) => {
    const tally = (rows, fn) => { const m = new Map(); rows.forEach((x) => { const k = fn(x); if (k) m.set(k, (m.get(k) || 0) + 1); }); return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6); };
    const by = (t) => r.rows.filter((x) => x.log_type === t);
    const http = tally(by('http'), (x) => x.raw && [x.raw.method, (x.raw.host || '') + (x.raw.uri || ''), x.raw.user_agent, x.raw.status_code].filter((y) => y != null).join('\u0000'));
    const ssl = tally(by('ssl'), (x) => x.raw && [x.raw.server_name || '(no name)', x.raw.version, x.raw.ja3 || x.raw.ja4, x.raw.validation_status].map((y) => y ?? '').join('\u0000'));
    const dns = tally(by('dns'), (x) => x.raw && [x.raw.query, x.raw.qtype_name, (x.raw.answers || []).slice(0, 3).join(' ')].map((y) => y ?? '').join('\u0000'));
    const parts = [];
    if (http.length) parts.push(`<div class="label">Web requests</div>${mini([{ h: 'Method', f: ([k]) => esc(k.split('\u0000')[0]) }, { h: 'Host + path', f: ([k]) => esc(k.split('\u0000')[1]) }, { h: 'User agent', f: ([k]) => v('raw.user_agent', k.split('\u0000')[2] || '') }, { h: 'n', r: 1, f: ([, n]) => fmt(n) }], http)}`);
    if (ssl.length) parts.push(`<div class="label">Secure connections (TLS)</div>${mini([{ h: 'Server name', f: ([k]) => v('server_name', k.split('\u0000')[0]) }, { h: 'Version', f: ([k]) => esc(k.split('\u0000')[1]) }, { h: 'JA3', f: ([k]) => (k.split('\u0000')[2] ? v('raw.ja3', k.split('\u0000')[2], k.split('\u0000')[2].slice(0, 12) + '…') : '<span class="nv-null">not logged</span>') }, { h: 'n', r: 1, f: ([, n]) => fmt(n) }], ssl)}`);
    if (dns.length) parts.push(`<div class="label">DNS</div>${mini([{ h: 'Query', f: ([k]) => v('query', k.split('\u0000')[0]) }, { h: 'Type', f: ([k]) => esc(k.split('\u0000')[1]) }, { h: 'Answers', f: ([k]) => esc(k.split('\u0000')[2]) }, { h: 'n', r: 1, f: ([, n]) => fmt(n) }], dns)}`);
    const sniNote = ssl.some(([k]) => k.startsWith('(no name)')) ? ' A secure connection to a bare address with no server name is typical of malware.' : '';
    set('proto', parts.length ? `<div class="nv-q-r">${fmt(r.total)} detailed row${r.total === 1 ? '' : 's'} (${[http.length && 'web', ssl.length && 'TLS', dns.length && 'DNS'].filter(Boolean).join(', ')}).${sniNote}</div>${parts.join('')}`
      : '<div class="nv-q-r">Only connection records: no web, TLS or DNS entries mention it, so what was sent is unknown (encrypted or not logged).</div>');
  }).catch(fail('proto'));

  // Q: bytes and duration against the device's normal.
  const conns = (d.rows || []).filter((x) => x.log_type === 'conn');
  if (has('volume')) {
    if (!c.dev || !conns.length) set('volume', `<div class="nv-q-r">${!conns.length ? 'No connection records in this alert to measure.' : 'No single home device to compare with.'}</div>`);
    else {
      const up = Math.max(...conns.map((x) => x.orig_bytes || 0)), down = Math.max(...conns.map((x) => x.resp_bytes || 0));
      const durMax = Math.max(...conns.map((x) => x.duration || 0));
      const base = `${devQ} log_type:conn`;
      Promise.all([
        agg({ group: 'log_type', query: base, metric: 'bytes_out' }), agg({ group: 'log_type', query: base, metric: 'duration' }),
        agg({ group: 'log_type', query: base, metric: 'bytes_in' }),
        agg({ group: 'log_type', query: `${base} orig_bytes:>${up}` }), agg({ group: 'log_type', query: `${base} resp_bytes:>${down}` }),
        agg({ group: 'log_type', query: `${base} duration:>${durMax}` }),
      ]).then(([bo, du, bi, aUp, aDn, aDu]) => {
        const g = (r, k) => r.groups[0]?.[k] ?? 0;
        const n = g(bo, 'count') || 1;
        const rank = (above) => 1 - (g(above, 'count') / n);
        const row = (label, val, avg, r0, f) => `<tr><td>${label}</td><td class="r mono"><b>${f(val)}</b></td><td class="r mono">${f(avg)}</td><td class="nv-pbar">${n === 1 ? '<span class="nv-dim">its only connection</span>' : `<i style="width:${pct(r0)}"></i><span class="mono">p${Math.round(r0 * 100)}</span>`}</td></tr>`;
        // "more than 100% of" reads wrong: the top one is "the largest of", and a lone connection is "its only connection"
        const beyond = (r0, more, top) => (Math.round(r0 * 100) >= 100 ? `${top} of this device's ${fmt(n)} connections` : `${more} ${pct(r0)} of this device's ${fmt(n)} connections`);
        const ranks = [rank(aUp), rank(aDn), rank(aDu)];
        const hi = Math.max(...ranks);
        // "large" needs a real outlier: a big absolute size or length, well above the device's average, among
        // enough connections to compare with (a tie at the top of four identical ones is not an outlier)
        const avgUp = g(bo, 'bytes_out') / n, avgDn = g(bi, 'bytes_in') / n, avgDu = g(du, 'duration') / n;
        const big = up + down >= 1e6 || durMax >= 600;
        const outlier = n >= 20 && (up > 3 * avgUp || down > 3 * avgDn || durMax > 3 * avgDu);
        const verdict = n === 1 ? `<span class="nv-ans">Too few to compare</span> This is its only connection in your logs; it moved ${bytes(up + down)}${durMax ? ` over ${Math.round(durMax)}s` : ''}.`
          : n < 20 ? `<span class="nv-ans">Too few to compare</span> This device has only ${fmt(n)} connections in your logs; the largest here moved ${bytes(up + down)}${durMax ? ` over ${Math.round(durMax)}s` : ''}.`
          : hi >= 0.95 && up + down >= 1e6 && outlier ? `<span class="nv-ans bad">Large</span> ${beyond(Math.max(ranks[0], ranks[1]), 'More data than', 'The most data')} (${bytes(up + down)}): possible data transfer.`
          : hi >= 0.95 && big && outlier ? `<span class="nv-ans warn">Long</span> ${beyond(ranks[2], 'Lasted longer than', 'The longest')} (${Math.round(durMax / 60)} min) but moved little data (${bytes(up + down)}): a long-lived session, not a bulk transfer.`
          : hi >= 0.75 && outlier ? `<span class="nv-ans warn">Above typical</span> In the top quarter of this device's ${fmt(n)} connections.`
            : conns.length > 1 ? `<span class="nv-ans warn">Small and repeated</span> ${fmt(conns.length)} small, short connections: typical of beaconing or regular check-ins, not bulk transfer.`
              : '<span class="nv-ans">Small</span> One short connection with little data: not a bulk transfer.';
        set('volume', `<div class="nv-q-r">${verdict}</div>
          <table class="nv-qt"><thead><tr><th>Largest in alert</th><th class="r">Value</th><th class="r">Device average</th><th>Percentile among device conns</th></tr></thead><tbody>
          ${row('Sent ↑', up, g(bo, 'bytes_out') / n, ranks[0], bytes)}
          ${row('Received ↓', down, g(bi, 'bytes_in') / n, ranks[1], bytes)}
          ${row('Duration', durMax, g(du, 'duration') / n, ranks[2], (x) => (x ? `${x < 10 ? x.toFixed(2) : Math.round(x)}s` : '0s'))}
          </tbody></table>`);
      }).catch(fail('volume'));
    }
  }
  return pivots;
}

export function huntPivot(ctx, p) {
  S.filters = p.filters.map((x) => ({ ...x }));
  S.groupby = [...p.groupby];
  setRange(p.range);
  emit('filters');
  ctx.goto('hunt');
}

// ---------------------------------------------------------------- indicator profile
export async function indicatorProfile(root, value, d, ctx, onSelectAlert) {
  const { api } = ctx;
  const own = value === d.indicator;
  const e = d.evidence || {}, m = own ? e.indicator?.meta || {} : {};
  const rec = own ? (e.listing || [])[0]?.start_record?.data || {} : {};
  const iv = own ? e.interval || {} : {};
  root.innerHTML = loadingState('Loading indicator…', { size: 'sm' });
  const isIpv = /^[\d.]+$|:/.test(value);
  const [lists, evts, alerts, devs, ent] = await Promise.all([
    api.get('/api/netlog/indicators', { value, limit: 50 }).catch(() => []),
    isIpv ? api.events({ q: value, limit: 6 }).catch(() => []) : Promise.resolve([]),
    api.get('/api/netlog/alerts', { indicator: value, limit: 50 }).catch(() => []),
    api.get('/api/netlog/aggregate', { group: 'device', query: `${isIpv ? 'ip' : 'query'}:${value}`, limit: 20 }).catch(() => null),
    // look the entity up first, so an address no report names is not a 404 in the console
    api.get('/api/entities/lookup', { values: value }).then((r) => {
      const hit = r?.results?.[0]?.entity;
      return hit ? api.get(`/api/entities/${encodeURIComponent(hit.id)}`) : null;
    }).catch(() => null),
  ]);
  const ev0 = evts[0] || {};
  const country = m.country || ev0.country, asn = ev0.asn || (rec.as_number ? `AS${rec.as_number}` : null);
  const firstListed = lists.length ? lists.map((l) => l.start).sort()[0] : iv.start;
  const kv = [
    ['Malware family', m.malware || rec.malware], ['Controller port', m.port ?? rec.port], ['Provider status', m.status || rec.status],
    ['Hostname', rec.hostname], ['Network', [asn && v('asn', asn), esc(m.as_name || rec.as_name || '')].filter(Boolean).join(' ')],
    ['Location', country ? `${flag(country)} ${v('country', country)}${ev0.city ? ' · ' + esc(ev0.city) : ''}` : null],
  ].filter(([, x]) => x != null && x !== '');
  const dates = [
    ['On our copy of the list since', firstListed ? `<b>${ts(firstListed)}</b> ${Z()} <span class="nv-dim">— when Night Desk first saw it listed; alerts are timed against this</span>` : null],
    ['Provider first seen', m.first_seen || rec.first_seen ? `${esc(m.first_seen || rec.first_seen)} <span class="nv-dim">— the list's own claim, before Night Desk collected it</span>` : null],
    ['Provider last online', m.last_online || rec.last_online ? `${esc(m.last_online || rec.last_online)} <span class="nv-dim">— last time the provider saw it answer</span>` : null],
  ].filter(([, x]) => x);
  // sourced claims only; computed links are hypotheses (trust lane), counted and labelled apart
  const claims = ent ? [...(ent.claims?.observed || []), ...(ent.claims?.reported || [])] : [];
  const hyps = ent ? (ent.claims?.inferred || []).length : 0;
  const ORIGIN = { observed: 'observed', reported: 'reported' };
  root.innerHTML = `
    ${!own ? `<button class="nv-crumb mono" data-crumb>← Back to ${esc(d.indicator)}</button>` : ''}
    <div class="nv-ip-h"><span class="nv-ip-v mono">${esc(value)}</span>${own ? `<span class="tag">${esc(e.indicator?.kind || '')}</span><span class="tag red">${esc(e.indicator?.category || '')}</span>` : ''}${m.malware ? `<span class="tag violet">${esc(m.malware)}</span>` : ''}</div>
    ${kv.length ? `<dl class="nv-kv">${kv.map(([k, x]) => `<dt>${k}</dt><dd>${typeof x === 'string' && /<span|<b[ >]/.test(x) ? x : esc(x)}</dd>`).join('')}</dl>` : ''}
    ${dates.length ? `<div class="nv-dates">${dates.map(([k, x]) => `<div><span class="label">${k}</span><div>${x}</div></div>`).join('')}</div>` : ''}
    <section class="nv-ips"><div class="label">On threat lists (${lists.length})</div>
      ${lists.length ? mini([{ h: 'List', f: (l) => `${esc(S.sources.get(l.source)?.name || l.source)} ${tierChip(l.source)}` }, { h: 'Category', f: (l) => esc(l.category || '') },
        { h: 'Since', f: (l) => tsShort(l.start) }, { h: 'Until', f: (l) => (l.end ? tsShort(l.end) : '<b class="nv-hot">listed</b>') }], lists)
        : '<div class="nv-dim">Not on any collected list.</div>'}
    </section>
    <section class="nv-ips"><div class="label">Alerts on this indicator (${alerts.length})</div>
      ${alerts.length ? `<div class="nv-att">${alerts.slice(0, 12).map((a) => `<div class="nv-att-r" data-oalert="${esc(a.id)}"><span class="nv-bell" style="background:${SEVC[a.severity]}"></span><div class="nv-att-m"><div class="nv-att-t">${devLink(a.device)} <span class="nv-dim">${esc(ruleLabel(a.rule))}</span>${a.id === d.id ? ' <span class="tag">this alert</span>' : ''}</div><div class="nv-att-s mono">${esc(srcName(a.source))} ${tierChip(a.source)} · ${fmt(a.count)} rows · ${esc({ ack: 'acknowledged' }[a.status] || a.status)}</div></div><span class="nv-att-w mono">${tsShort(a.last_ts)}</span></div>`).join('')}</div>` : '<div class="nv-dim">None.</div>'}
    </section>
    <section class="nv-ips"><div class="label">Devices that contacted it</div>
      ${devs?.groups?.length ? `<div class="nv-chips">${devs.groups.map((g) => `${g.key ? devLink(g.key) : '<span class="nv-dim">non-home</span>'} <span class="nv-dim mono">${fmt(g.count)}</span>`).join('<span class="nv-sep">·</span>')}</div>` : '<div class="nv-dim">No device in your logs.</div>'}
    </section>
    ${ent ? `<section class="nv-ips"><div class="label">Knowledge graph · ${fmt(claims.length)} claim${claims.length === 1 ? '' : 's'}${ent.conflicting_attribution ? ' · <span class="nv-hot">conflicting attribution</span>' : ''}</div>
      ${claims.length ? `<div class="nv-claims">${claims.slice(0, 8).map((cl) => `<div class="nv-claim"><span class="mono">${esc(cl.predicate)}</span> <b>${esc(cl.other_name || cl.obj)}</b> <span class="tag">${esc(ORIGIN[cl.origin] || 'hypothesis')}</span> <span class="nv-dim mono">${esc(cl.band || '')} · ${(cl.sources || []).map((s0) => `${esc(s0)} ${tierChip(s0)}`).join(' ')}</span></div>`).join('')}</div>` : '<div class="nv-dim">No claims yet.</div>'}${hyps ? `<div class="nv-dim">${fmt(hyps)} hypothes${hyps === 1 ? 'is' : 'es'} (computed links, not reported by a source) not shown.</div>` : ''}
      ${ent.related?.length ? `<div class="nv-chips" style="margin-top:6px">${ent.related.slice(0, 10).map((r) => `<span class="tag">${esc(r.type)} · ${esc(r.name)}</span>`).join('')}</div>` : ''}
    </section>` : ''}
    ${evts.length ? `<section class="nv-ips"><div class="label">Source records (${evts.length})</div>
      ${evts.map((x) => `<div class="nv-feed"><div>${esc(x.title)}</div><div class="nv-dim mono">${esc(S.sources.get(x.source)?.name || x.source)} ${tierChip(x.source)} · provider time ${ts(x.ts, false)} ${Z()} · stored ${ts(x.stored_at || x.ingested_at, false)}</div>${x.summary ? `<div class="nv-dim">${esc(x.summary)}</div>` : ''}</div>`).join('')}
    </section>` : ''}
    <div class="nv-links"><button class="chip needs-sql" data-xexp>Find in the SQL console</button><button class="chip" data-xcopy>Copy</button></div>`;
  root.querySelector('[data-xexp]').onclick = () => ctx.toExplorer({ q: value });
  root.querySelector('[data-xcopy]').onclick = async () => { try { await navigator.clipboard.writeText(value); toast('Copied'); } catch { toast(value); } };
  root.querySelectorAll('[data-oalert]').forEach((r) => (r.onclick = (ev) => { if (!ev.target.closest('.nv-v')) onSelectAlert(r.dataset.oalert); }));
}

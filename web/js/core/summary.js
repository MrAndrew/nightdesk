// "Copy summary": a clean Markdown hand-off of an incident, an entity or a news story (title, what and why, key
// facts, evidence with times, sources with links, the user's notes), for a forum post, an ISP or abuse report or
// an issue. "Redact my network" (on by default) asks the server (POST /api/notes/redact) to replace home
// addresses, MACs and device names with placeholders. The text is copied to the clipboard and also shown,
// selectable, in case the browser refuses. Contract: okf/architecture/notes.md
import { api } from './api.js';
import { toast, safeUrl } from './util.js';
import { ttpName } from './ttp.js';

const pad = (n) => String(n).padStart(2, '0');
export function utc(t) {
  if (!t) return '';
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) return String(t);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}
const day = (t) => utc(t).slice(0, 10);
// App-made HTML (already escaped) to plain text
export function plain(html) {
  const div = document.createElement('div');
  div.innerHTML = String(html ?? '');
  return div.textContent.replace(/\s+/g, ' ').trim();
}
// Markdown-safe single line: no stray line breaks; brackets kept (they read fine as text)
const line = (s) => String(s ?? '').replace(/\s+/g, ' ').trim();
const mdLink = (name, url) => { const u = safeUrl(url); return u ? `[${line(name).replace(/[[\]]/g, '')}](${u.replace(/[()\s]/g, (c) => ({ '(': '%28', ')': '%29' }[c] || '%20'))})` : line(name); };

/**
 * Markdown from a summary object:
 * { kind, title, what, why, facts: [[label, value]], evidence: [{t, text}], sources: [{name, url, t}], steps: [] }
 * and the item's notes ([{body, created_at, updated_at}]).
 */
export function toMarkdown(s, notes = []) {
  const out = [`# ${line(s.title) || 'Untitled'}`, '', `_${line(s.kindLabel || s.kind || 'Item')} · summary from Night Desk, ${utc(new Date())}_`, ''];
  if (s.what) out.push(`## ${s.whatHead || 'What happened'}`, '', String(s.what).trim(), '');
  if (s.why) out.push(`**Why it matters:** ${line(s.why)}`, '');
  const facts = (s.facts || []).filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && !v.length));
  if (facts.length) out.push('## Key facts', '', ...facts.map(([k, v]) => `- **${line(k)}:** ${line(Array.isArray(v) ? v.join(', ') : v)}`), '');
  if ((s.steps || []).length) out.push('## What to do', '', ...s.steps.map((x, i) => `${i + 1}. ${line(x)}`), '');
  if ((s.evidence || []).length) {
    out.push(`## ${s.evidenceHead || 'Evidence'}`, '', ...s.evidence.map((e) => `- ${e.t ? `\`${utc(e.t)}\` ` : ''}${line(e.text)}`));
    if (s.evidenceMore) out.push(`- …and ${s.evidenceMore} more`);
    out.push('');
  }
  if ((s.sources || []).length) out.push('## Sources', '', ...s.sources.map((x) => `- ${mdLink(x.name || x.url || 'source', x.url)}${x.t ? ` (${day(x.t)})` : ''}${x.note ? `: ${line(x.note)}` : ''}`), '');
  if (notes.length) {
    out.push('## My notes', '');
    for (const n of notes) {
      const body = String(n.body || '').trim().split('\n');
      out.push(`- _${utc(n.created_at)}${n.updated_at && n.updated_at !== n.created_at ? `, edited ${utc(n.updated_at)}` : ''}_`);
      out.push(...body.map((l) => (l.trim() ? `  ${l}` : '')));
    }
    out.push('');
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim() + '\n';
}

// ------------------------------------------------------------------ structural redaction
// A value the builder knows is home-side is wrapped in a marker (kind: name | mac | ip, or ipq = "an address: the
// server redacts it when it is in the home network"). The server (POST /api/notes/redact) turns every marker into a
// placeholder before its text passes run, so known home values never depend on pattern matching. Unredacted copies
// just drop the markers. Contract: okf/architecture/notes.md
const MO = '\ue010', MS = '\ue012', MC = '\ue011';
const MARKED = /\ue010[a-z]+\ue012([^\ue010\ue011\ue012]*)\ue011/g;
export const mk = (kind, v) => (v == null || v === '' ? (v ?? '') : `${MO}${kind}${MS}${String(v).replace(/[\ue010-\ue012]/g, '')}${MC}`);
export const unmark = (s) => String(s ?? '').replace(MARKED, '$1').replace(/[\ue010-\ue012]/g, '');
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Wrap every known home value found in free text (outside existing markers), longest first; names whole-word,
// any case. Returns a function over strings.
function marker(vals) {
  const all = [...vals.name].filter(Boolean).map((v) => [v, 'name'])
    .concat([...vals.ip].filter(Boolean).map((v) => [v, 'ip']), [...vals.mac].filter(Boolean).map((v) => [v, 'mac']))
    .sort((a, b) => b[0].length - a[0].length);
  if (!all.length) return (s) => s;
  const kind = new Map(all.map(([v, k]) => [v.toLowerCase(), k]));
  const rx = new RegExp(`(?<![\\w:.])(?:${all.map(([v]) => reEsc(v)).join('|')})(?![\\w])`, 'giu');
  return (s) => String(s).split(/(\ue010[^\ue011]*\ue011)/).map((part, i) => (i % 2 ? part : part.replace(rx, (m) => mk(kind.get(m.toLowerCase()) || 'name', m)))).join('');
}
// Every string in a summary object (not urls or times) through f
function deepMap(o, f) {
  if (typeof o === 'string') return f(o);
  if (Array.isArray(o)) return o.map((x) => deepMap(x, f));
  if (o && typeof o === 'object') return Object.fromEntries(Object.entries(o).map(([k, v]) => [k, k === 'url' || k === 't' ? v : deepMap(v, f)]));
  return o;
}
// An address in an evidence row: the server decides whether it is home; v6 with a port gets brackets
const addr = (ip, port) => (ip ? (port != null && String(ip).includes(':') ? `[${mk('ipq', ip)}]:${port}` : `${mk('ipq', ip)}${port != null ? `:${port}` : ''}`) : '?');

// ------------------------------------------------------------------ the three summaries
const tsOf = (r) => r.ts || r.published || r.first_seen;

/** An incident (Network → Alerts detail): `d` the alert detail, `inc` its incident. */
export async function incidentSummary(d, inc = {}) {
  const T = await import('../views/net/alert-text.js');
  const C = await import('../views/net/common.js').catch(() => null);
  const a = { ...d, kind: inc.kind || d.kind, incident: inc };
  const e = d.evidence || {}, ind = e.indicator || {}, m = ind.meta || {};
  const k = T.kindOf(a);
  const rows = d.rows || [];
  const steps = T.whatToDo(a).filter((x) => !x.others).map((x) => plain(x.t));
  const homes = T.homeNames(a);
  // every value known to be home-side: device names, labels, owners, announced names, addresses, MACs
  const dv = e.device || {};
  const vals = { name: new Set(homes), ip: new Set(dv.home_ips || []), mac: new Set(dv.mac ? [dv.mac] : []) };
  for (const h of dv.hostnames || []) { vals.name.add(h); vals.name.add(String(h).split('.')[0]); }
  for (const id of new Set([...(dv.devices || []), ...(d.device ? [d.device] : [])])) {
    const x = C?.S?.devices?.get(id) || {};
    const lab = typeof x.label === 'object' && x.label ? x.label : {};
    [x.name, typeof x.label === 'string' ? x.label : lab.name, x.owner, lab.owner, ...(x.hostnames || [])].forEach((v) => v && vals.name.add(String(v)));
    (x.ips || []).forEach((v) => vals.ip.add(v));
    if (x.mac) vals.mac.add(x.mac);
    const m = /^(mac|ip):(.+)$/.exec(id);
    if (m) vals[m[1] === 'mac' ? 'mac' : 'ip'].add(m[2]);
  }
  for (const v of [...vals.name]) if (!v || String(v).trim().length < 1 || /^(a home device|the device)$/i.test(v)) vals.name.delete(v);
  const sources = [];
  for (const r of (d.reports || []).slice(0, 8)) {
    const link = r.type === 'article' ? (r.story_id ? `#news/story/${encodeURIComponent(r.story_id)}` : `#news/article/${encodeURIComponent(r.id)}`) : null;
    sources.push({ name: `${r.story_title || r.title || 'Report'}${r.source ? ` (${r.source})` : ''}`, url: r.url || (link ? `${location.origin}${location.pathname}${link}` : ''), t: r.published });
  }
  const iv = (d.intervals || []).map((i) => `${day(i.start)} → ${i.end ? day(i.end) : 'still listed'}`);
  const src = C?.S?.sources?.get(d.source) || {};
  if (d.source && d.source !== 'suricata') sources.unshift({ name: `${T.srcName(d.source)}${iv.length ? `, listed ${iv.join('; ')}` : ''}`, url: src.homepage || '' });
  return deepMap({
    kind: 'incident', kindLabel: `Network incident · ${d.severity || ''} · ${k.kindLabel}`,
    title: T.headline(a).text,
    what: plain(T.whatHappened(d, inc)),
    why: T.whySeverity(a),
    facts: [
      ['Device', homes.map((x) => mk('name', x)).join(', ')],
      [k.fam === 'ids' ? 'Signature' : k.fam === 'kev' ? 'Vulnerability' : 'Indicator', ind.observed?.length && ind.observed.join() !== d.indicator && k.fam !== 'ids' ? `${d.indicator} (seen as ${ind.observed.join(', ')})` : d.indicator],
      ['Malware', m.malware],
      ['First contact', utc(inc.ts || d.ts)], ['Last contact', utc(inc.last_ts || d.last_ts)],
      ['Contacts', inc.count ?? d.count], ['Days', inc.days > 1 ? inc.days : ''],
      ['Status', { new: 'new', ack: 'acknowledged', dismissed: 'dismissed', expected: 'expected' }[inc.state || d.status] || inc.state || d.status],
      ['Lists', (inc.sources || []).length > 1 ? inc.sources.map(T.srcName) : ''],
    ],
    steps,
    evidenceHead: 'Evidence (log rows)',
    evidence: rows.slice(0, 15).map((r) => ({ t: r.ts, text: `${r.log_type || 'row'}: ${addr(r.orig_h, r.orig_p)} → ${addr(r.resp_h, r.resp_p)}${r.query ? ` query ${r.query}` : r.server_name ? ` name ${r.server_name}` : r.host ? ` host ${r.host}` : ''}${r.conn_state ? ` (${r.conn_state})` : ''}` })),
    evidenceMore: Math.max(0, (d.rows_total ?? rows.length) - Math.min(15, rows.length)),
    sources,
  }, marker(vals));
}

const PRED = { uses: 'uses', targets: 'targets', 'attributed-to': 'is attributed to', 'communicates-with': 'communicates with', 'linked-to': 'is linked to',
  exploits: 'exploits', 'variant-of': 'is a variant of', drops: 'drops', 'part-of': 'is part of', delivers: 'delivers', affects: 'affects', 'made-by': 'is made by' };
const TYPE = { cve: 'Vulnerability (CVE)', actor: 'Threat actor', malware: 'Malware', tool: 'Tool', campaign: 'Campaign', vendor: 'Vendor', product: 'Product',
  org: 'Organisation', technique: 'ATT&CK technique', ip: 'IP address', domain: 'Domain', url: 'URL', hash: 'File hash', country: 'Country', sector: 'Sector', asn: 'ASN', prefix: 'Prefix' };

/** An entity (drawer or full profile): `d` the GET /api/entities/<id> response. */
export function entitySummary(d) {
  const name = d.name || String(d.id).split(':').slice(1).join(':');
  const claims = [...(d.claims?.reported || []), ...(d.claims?.observed || []), ...(d.claims?.user || [])]
    .filter((c) => c.predicate !== 'announced-by' && c.predicate !== 'in-prefix')
    .sort((a, b) => (b.evidence_count || b.evidence?.length || 0) - (a.evidence_count || a.evidence?.length || 0) || (b.confidence || 0) - (a.confidence || 0))
    .slice(0, 10);
  const evidence = claims.map((c) => {
    const other = c.other_name || String(c.other || '').split(':').slice(1).join(':');
    const ev = (c.evidence || [])[0] || {};
    const q = ev.quote ? ` “${line(ev.quote).slice(0, 220)}”` : '';
    return { t: ev.ts || c.last_seen, text: `${c.direction === 'in' ? `${other} ${PRED[c.predicate] || c.predicate} ${name}` : `${name} ${PRED[c.predicate] || c.predicate} ${other}`}${ev.source ? ` (${ev.source})` : ''}.${q}` };
  });
  const sources = [];
  const seen = new Set();
  for (const r of d.refs || []) {
    const href = r.ref_type === 'article' ? `${location.origin}${location.pathname}#news/article/${encodeURIComponent(r.ref_id)}` : r.url;
    const key = r.url || r.ref_id;
    if (seen.has(key)) continue; seen.add(key);
    sources.push({ name: `${r.title || r.ref_id}${r.source ? ` (${r.source})` : ''}`, url: r.url || href, t: r.ts });
    if (sources.length >= 10) break;
  }
  const desc = d.attrs?.description || d.description || '';
  return {
    kind: 'entity', kindLabel: TYPE[d.type] || d.type || 'Entity', whatHead: 'What it is',
    title: name,
    what: desc ? line(desc).slice(0, 900) : '',
    why: d.listed_by?.length ? `On ${d.listed_by.length} threat list${d.listed_by.length === 1 ? '' : 's'}: ${d.listed_by.map((l) => l.name || l.source).join(', ')}.` : '',
    facts: [
      ['Type', TYPE[d.type] || d.type], ['Also known as', (d.aliases || []).filter((a) => a.toLowerCase() !== String(name).toLowerCase()).slice(0, 10)],
      ['Country', d.attrs?.country], ['Mentions', d.mentions?.refs ?? ''], ['Sources', (d.sources || []).length || ''],
      ['First seen in your data', day(d.first_seen)], ['Last seen', day(d.last_seen)],
      ['Threat lists', (d.listed_by || []).map((l) => `${l.name || l.source}${l.active ? ' (listed now)' : ''}`)],
      ['Conflicting attribution', d.conflicting_attribution ? 'yes, sources disagree' : ''],
    ],
    evidenceHead: 'Reported claims',
    evidence,
    sources,
  };
}

/** A news story: the story `s` with its articles, and what the reader extracted from it (`ttps`: core/ttp.js ttpList). */
export function storySummary({ s, arts = [], inds = [], named = [], cves = [], ttps = [] }) {
  const nm = (e) => e.name || String(e.id || '').split(':').slice(1).join(':');
  const actors = named.filter((e) => /^(actor|malware|tool|campaign)$/.test(e.type || String(e.id).split(':')[0])).map(nm);
  const iocs = inds.filter((i) => !['cve', 'technique'].includes(i.type)).map((i) => i.name || i.value).filter(Boolean);
  return {
    kind: 'story', kindLabel: 'News story', whatHead: 'Summary',
    title: s.title,
    what: s.summary ? line(String(s.summary).replace(/\[\d+\]/g, '')) : '',
    facts: [
      ['First reported', utc(s.first_seen)], ['Last update', utc(s.last_seen)],
      ['Outlets', s.source_count], ['Actors and malware', actors.slice(0, 12)],
      ['CVEs', cves.map((c) => c.name || c.value || String(c.id || '').split(':').slice(1).join(':')).filter(Boolean).slice(0, 12)],
      ['Indicators', iocs.length ? `${iocs.slice(0, 12).join(', ')}${iocs.length > 12 ? ` and ${iocs.length - 12} more` : ''}` : ''],
      // techniques read from the articles (core/ttp.js labels): never stated more firmly than the story page does
      ...[['named', 'ATT&CK techniques named in the articles'], ['likely', 'ATT&CK techniques, likely (found automatically; can be wrong)'],
        ['possible', 'ATT&CK techniques, possible (a guess by the local AI; often wrong)']]
        .map(([k, label]) => [label, ttps.filter((t) => t?.kind === k).map((t) => `${t.id}${ttpName(t.id, t.name) ? ` ${ttpName(t.id, t.name)}` : ''}`).slice(0, 12)]),
    ],
    evidenceHead: 'Timeline of coverage',
    evidence: arts.slice(0, 20).map((a) => ({ t: tsOf(a) || a.fetched_at, text: `${a.source || ''}: ${a.title || ''}${a.dup_of ? ' (syndicated copy)' : ''}` })),
    evidenceMore: Math.max(0, arts.length - 20),
    sources: arts.filter((a) => safeUrl(a.url)).slice(0, 20).map((a) => ({ name: `${a.source}: ${a.title}`, url: a.url, t: tsOf(a) })),
  };
}

// ------------------------------------------------------------------ dialog
let dlg = null;
function ensureDialog() {
  if (dlg) return dlg;
  dlg = document.createElement('div');
  dlg.className = 'notes-dlg';
  dlg.hidden = true;
  dlg.innerHTML = `<div class="notes-dlg-box" role="dialog" aria-modal="true" aria-labelledby="notes-dlg-h">
      <div class="notes-dlg-head"><h3 id="notes-dlg-h">Copy summary</h3><button class="icon-btn" data-x="close" title="Close (Esc)" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button></div>
      <p class="notes-dlg-sub">Markdown, ready to paste into a forum post, an abuse report or an issue.</p>
      <label class="notes-dlg-opt"><input type="checkbox" data-x="redact" checked> <span><b>Redact my network</b><small>Replaces your home addresses, MAC addresses and device names with placeholders like [home IP 1]. Outside addresses stay.</small></span></label>
      <div class="notes-dlg-st mono" aria-live="polite"></div>
      <textarea class="notes-dlg-ta mono" readonly spellcheck="false" aria-label="Summary in Markdown"></textarea>
      <div class="notes-dlg-act"><button class="src-btn primary" data-x="copy">Copy</button><button class="src-btn" data-x="close">Close</button></div>
    </div>`;
  document.body.append(dlg);
  dlg.addEventListener('click', (e) => { if (e.target === dlg || e.target.closest('[data-x="close"]')) closeDialog(); });
  dlg.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { e.stopPropagation(); e.preventDefault(); closeDialog(); }
    if (e.key === 'Tab') {   // keep focus inside the dialog
      const f = [...dlg.querySelectorAll('button, input, textarea')].filter((x) => !x.disabled && x.offsetParent);
      if (!f.length) return;
      if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
    }
  });
  return dlg;
}
let opener = null;
function closeDialog() {
  if (!dlg || dlg.hidden) return;
  dlg.hidden = true;
  if (opener?.isConnected) opener.focus({ preventScroll: true });
  opener = null;
}

async function writeClipboard(text, ta) {
  try { await navigator.clipboard.writeText(text); return true; } catch {}
  try { ta.focus(); ta.select(); if (document.execCommand('copy')) return true; } catch {}
  return false;
}

/**
 * Open the Copy summary dialog. `build` returns (or resolves to) a summary object; `notes` returns the notes.
 * The Markdown is built once; redaction runs on the server each time the box is ticked.
 */
export async function openSummary(build, notes = async () => []) {
  const box = ensureDialog();
  opener = document.activeElement;
  const ta = box.querySelector('textarea'), st = box.querySelector('.notes-dlg-st'), cb = box.querySelector('[data-x="redact"]'), btn = box.querySelector('[data-x="copy"]');
  ta.value = ''; st.textContent = 'Building the summary…'; btn.disabled = true;
  box.hidden = false;
  box.querySelector('[data-x="close"]').focus();
  let md = '';   // with markers around known home values (core/summary.js#structural redaction)
  try { md = toMarkdown(await build(), await notes().catch(() => [])); } catch (e) { st.textContent = `Could not build the summary: ${e.message}`; return; }
  const raw = unmark(md);
  let seq = 0;
  const paint = async () => {
    const my = ++seq;
    btn.disabled = true;
    if (!cb.checked) { ta.value = raw; st.textContent = 'Not redacted: your own addresses and device names are included.'; btn.disabled = false; return; }
    st.textContent = 'Redacting…';
    try {
      const r = await api.post('/api/notes/redact', { text: md });
      if (my !== seq) return;
      // fail closed: anything the server left marked is dropped, never shown raw
      ta.value = String(r.text).replace(MARKED, '[redacted]').replace(/[\ue000-\uf8ff]/g, '');
      const n = r.replaced || {};
      const parts = [n.ips && `${n.ips} home address${n.ips === 1 ? '' : 'es'}`, n.macs && `${n.macs} MAC${n.macs === 1 ? '' : 's'}`, n.names && `${n.names} device name${n.names === 1 ? '' : 's'}`].filter(Boolean);
      st.textContent = parts.length ? `Redacted ${parts.join(', ')}.` : 'Nothing from your network to redact.';
      btn.disabled = false;
    } catch (e) {
      if (my !== seq) return;
      ta.value = '';
      st.textContent = `Could not redact (${e.message}). Untick “Redact my network” to copy it as is.`;
    }
  };
  cb.onchange = paint;
  btn.onclick = async () => {
    const ok = await writeClipboard(ta.value, ta);
    if (ok) { toast('Summary copied'); st.textContent = 'Copied to the clipboard.'; }
    else { ta.focus(); ta.select(); st.textContent = 'The browser blocked the clipboard: the text is selected, press Ctrl+C (⌘C on a Mac).'; }
  };
  await paint();
}


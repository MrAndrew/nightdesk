// Story detail and article reader for the News view.
// Story and article intel (claims with quotes, indicators with first/last seen) come from /api/news/intel.
import {
  api, esc, ago, emeta, entType, entName, isIoc, chip, tierBadge, tierLabel, fmtDate, decode, copy, download, toCsv,
  highlight, eicon, defang, iocSummary, dedupeByName, chipList,
} from './common.js';
import { safeUrl, epssTag } from '../../core/util.js';
import * as T from '../../core/time.js';
import { seenSlot, fillSeen } from '../../core/chips.js';
import { mountNotes } from '../../core/notes.js';
import { storySummary, openSummary } from '../../core/summary.js';
import { pushPage } from '../../core/page.js';
import { actionSheet } from '../../core/sheet.js';
import { openNoteSheet } from '../../core/note-sheet.js';
import { followButton, matchName } from '../../core/stack.js';
import { errorState, stateAct } from '../../core/view.js';
import { TTP_KINDS, TTP_ORDER, TTP_CAVEAT, TTP_HOW, ttpList, ttpLinkKind, ttpQuote, ttpTag, ttpExportable, ttpAttrs, ttpName, mitreUrl, navigatorLayer, stixAttackPattern, wireTtpTips } from '../../core/ttp.js';

const ICON_COPY = '<svg class="i" viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>';
const ICON_EXT = '<svg class="i"><use href="#i-ext"/></svg>';
const ICON_DL = '<svg class="i" viewBox="0 0 24 24"><path d="M12 4v11m-5-5 5 5 5-5M5 20h14" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>';
const PRED = {
  uses: 'uses', targets: 'targets', 'attributed-to': 'attributed to', 'communicates-with': 'communicates with', 'linked-to': 'linked to',
  exploits: 'exploits', 'variant-of': 'variant of', drops: 'drops', 'part-of': 'part of', delivers: 'delivers', affects: 'affects', 'made-by': 'made by',
};
const PRED_IN = { uses: 'used by', targets: 'targeted by', 'attributed-to': 'attribution of', drops: 'dropped by', delivers: 'delivered by', exploits: 'exploited by', 'part-of': 'includes', 'variant-of': 'has variant', 'communicates-with': 'contacted by', 'linked-to': 'linked to' };

const loading = (el) => { el.innerHTML = `<div class="nw-skel pane">${'<div></div>'.repeat(5)}</div>`; };
const err = (el, e, retry) => { el.innerHTML = errorState({ retry, act: stateAct('Back to the list', { data: { act: 'close-pane' } }), title: "Couldn't open this", why: 'It may have been removed from the lake, or the server did not answer. Go back and try again.', err: String(e.message || e) }); };
const roleLabel = (r) => (r === 'research' ? 'Research' : r === 'newsroom' ? 'Newsroom' : r || '');
// The role becomes a class name: only the two known roles pass (anything else, even from a tampered row, gets none).
const roleCls = (r) => (r === 'research' || r === 'newsroom' ? r : '');
const shortDate = (t) => (t ? T.date(t) : '—');
const slug = (t) => t.slice(0, 50).replace(/\W+/g, '-').replace(/^-|-$/g, '').toLowerCase();

// ------------------------------------------------------------------ indicators: suspicion, exports
// A dotted quad right after "version(s)/release/build ... and" is far more likely a version number than an IP.
function suspect(ind, texts) {
  if (ind.type !== 'ip' || !/^\d+\.\d+\.\d+\.\d+$/.test(ind.name)) return null;
  for (const t of texts) {
    let i = (t || '').indexOf(ind.name);
    while (i >= 0) {
      const before = t.slice(Math.max(0, i - 48), i);
      if (/\b(versions?|release[sd]?|build|patch(ed)?|update[sd]?|upgrade|fixed in|v)\b[^.]{0,40}$/i.test(before)) return 'Looks like a software version number in the text, not an address';
      i = t.indexOf(ind.name, i + 1);
    }
  }
  return null;
}
const hashKind = (h) => ({ 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' }[h.length] || 'SHA-256');
function stixPattern(i) {
  const v = i.name.replace(/'/g, "\\'");
  if (i.type === 'ip') return `[${v.includes(':') ? 'ipv6' : 'ipv4'}-addr:value = '${v}']`;
  if (i.type === 'domain') return `[domain-name:value = '${v}']`;
  if (i.type === 'url') return `[url:value = '${v}']`;
  if (i.type === 'hash') return `[file:hashes.'${hashKind(v)}' = '${v}']`;
  return null;
}
const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx'.replace(/x/g, () => ((Math.random() * 16) | 0).toString(16)));
function stixBundle(title, url, inds, ttps, named, published) {
  const now = new Date().toISOString();
  const idt = { type: 'identity', spec_version: '2.1', id: `identity--${uuid()}`, created: now, modified: now, name: 'Night Desk (local)', identity_class: 'system' };
  const objs = [idt];
  for (const i of inds) {
    if (i.type === 'cve') { objs.push({ type: 'vulnerability', spec_version: '2.1', id: `vulnerability--${uuid()}`, created: now, modified: now, name: i.name, external_references: [{ source_name: 'cve', external_id: i.name }] }); continue; }
    const p = stixPattern(i);
    if (!p) continue;
    objs.push({ type: 'indicator', spec_version: '2.1', id: `indicator--${uuid()}`, created: now, modified: now, created_by_ref: idt.id, name: i.name,
      pattern: p, pattern_type: 'stix', valid_from: i.first_seen || now, indicator_types: ['malicious-activity'], confidence: Math.round((i.confidence ?? 0.5) * 100) });
  }
  for (const t of ttpExportable(ttps)) objs.push(stixAttackPattern(t, `attack-pattern--${uuid()}`, now));
  for (const e of named) {
    const t = entType(e);
    const st = t === 'actor' ? 'threat-actor' : t === 'malware' ? 'malware' : t === 'tool' ? 'tool' : t === 'campaign' ? 'campaign' : null;
    if (!st) continue;
    objs.push({ type: st, spec_version: '2.1', id: `${st}--${uuid()}`, created: now, modified: now, name: entName(e), ...(st === 'malware' ? { is_family: true } : {}) });
  }
  objs.push({ type: 'report', spec_version: '2.1', id: `report--${uuid()}`, created: now, modified: now, created_by_ref: idt.id, name: title, published: published || now,
    report_types: ['threat-report'], object_refs: objs.slice(1).map((o) => o.id), external_references: url ? [{ source_name: 'source', url }] : [] });
  return JSON.stringify({ type: 'bundle', id: `bundle--${uuid()}`, objects: objs }, null, 2);
}
function mispEvent(title, url, inds, ttps, published) {
  const misp = { ip: ['ip-dst', 'Network activity'], domain: ['domain', 'Network activity'], url: ['url', 'Network activity'], cve: ['vulnerability', 'External analysis'] };
  const attrs = inds.map((i) => {
    const [type, category] = i.type === 'hash' ? [hashKind(i.name).toLowerCase().replace('-', ''), 'Payload delivery'] : misp[i.type] || ['text', 'Other'];
    return { type, category, value: i.name, to_ids: i.type !== 'cve' && !i.suspect, comment: i.suspect ? `suspect: ${i.suspect}` : `seen in ${i.articles || 1} article(s)` };
  });
  if (url) attrs.push({ type: 'link', category: 'External analysis', value: url, to_ids: false });
  return JSON.stringify({ Event: { info: title, date: (published || new Date().toISOString()).slice(0, 10), threat_level_id: '2', analysis: '2', distribution: '0',
    Attribute: attrs, Tag: ttpExportable(ttps).map((t) => ({ name: `mitre-attack:${t.id}` })) } }, null, 2);
}

// Threat lists that also hold an indicator (Feodo, ThreatFox, URLhaus, SSLBL, ...): independent corroboration.
function listedChip(ls) {
  if (!ls?.length) return '';
  const active = ls.filter((l) => l.active);
  const tip = ls.map((l) => `${l.name || l.source}${l.malware ? ` (${l.malware})` : ''}: ${l.active ? 'listed now' : 'listed before'}${l.value ? ` as ${l.value}` : ''}`).join('\n');
  return `<span class="nw-listed${active.length ? ' on' : ''}" title="${esc(tip)}">${active.length ? 'listed' : 'was listed'} · ${esc([...new Set(ls.map((l) => l.source))].join(', '))}</span>`;
}

// The IoC table with exports, used by story and article.
function iocBlock(inds, { title, url, ttps, named, published, story }) {
  const iocs = inds.filter((i) => i.type !== 'cve' && i.type !== 'technique');
  if (!iocs.length) return '';
  const nSus = iocs.filter((i) => i.suspect).length;
  const rows = iocs.map((i) => `
    <tr class="${i.suspect ? 'sus' : ''}">
      <td class="mono nw-iv"><button class="nw-iocv" data-eid="${esc(i.id)}" title="${esc(i.name)}">${esc(defang(i.name, i.type))}</button>${i.suspect ? `<span class="nw-sus" title="${esc(i.suspect)}">version?</span>` : ''}${listedChip(i.listed)}${['ip', 'domain', 'hash', 'prefix', 'url'].includes(i.type) ? seenSlot(i.name, { compact: true }) : ''}</td>
      <td><span class="tag">${esc(i.type === 'hash' ? hashKind(i.name) : emeta(i.type).label)}</span></td>
      ${story ? `<td class="r mono">${i.articles}</td>` : ''}
      <td class="r mono" title="${esc((i.rels || []).map((r) => `${r.direction === 'in' ? '← ' : ''}${r.predicate} ${r.name}`).join('\n') || 'claims linking this indicator')}">${i.relationships || '—'}${i.rels?.length ? `<span class="nw-relh">${esc((i.rels[0].direction === 'in' ? (PRED_IN[i.rels[0].predicate] || i.rels[0].predicate) : (PRED[i.rels[0].predicate] || i.rels[0].predicate)) + ' ' + i.rels[0].name)}</span>` : ''}</td>
      <td class="mono nw-d">${esc(shortDate(i.first_seen))}</td>
      <td class="mono nw-d">${esc(shortDate(i.last_seen))}</td>
      <td class="r"><button class="icon-btn" data-copy="${esc(i.name)}" title="Copy (re-fanged)">${ICON_COPY}</button></td>
    </tr>`).join('');
  const many = iocs.length > 12;
  return `
    <div class="nw-x nw-xioc">
      <div class="nw-xh"><span class="nw-xb">AI</span><b data-term="ioc">${iocs.length} IoC${iocs.length === 1 ? '' : 's'}</b><span class="nw-xs">(${esc(iocSummary(iocs))})${nSus ? ` · ${nSus} flagged` : ''}</span></div>
      <div class="nw-xa">
        <button class="src-btn primary" data-x="stix">${ICON_DL}Export STIX 2.1</button>
        <button class="src-btn" data-x="misp">${ICON_DL}MISP</button>
        <button class="src-btn" data-x="csv">${ICON_DL}CSV</button>
        <button class="src-btn" data-x="copy-iocs">${ICON_COPY}Copy all</button>
      </div>
      <div class="nw-tbl ${many ? 'clip' : ''}"><table class="nw-ioct"><thead><tr><th>IoC</th><th>Type</th>${story ? '<th class="r">Articles</th>' : ''}<th class="r"><span data-term="claim">Relationships</span></th><th>First mention</th><th>Last mention</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      ${many ? `<button class="nw-morebtn" data-x="all-iocs">Show all ${iocs.length}</button>` : ''}
    </div>`;
}

// ATT&CK techniques read from the text, under the three plain labels of core/ttp.js (named, likely, possible). Each
// chip links to MITRE and copies its id; hovering or focusing it, or its quote button, shows the sentence it came from.
const ICON_QUOTE = '<svg class="i" viewBox="0 0 24 24"><path d="M5 17c0-4 1.5-7 5-9M14 17c0-4 1.5-7 5-9" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
const ttpChip = (t) => {
  const nm = ttpName(t.id, t.name);
  return `<span class="nw-chip e-ttp nw-ttp k-${esc(t.kind)}" ${ttpAttrs(t)}>${eicon('technique')}<a href="${esc(mitreUrl(t.id))}" target="_blank" rel="noopener">${esc(t.id)}${nm ? ` <i>${esc(nm)}</i>` : ''}</a><button class="nw-ttp-ev" data-ttp-ev aria-expanded="false" aria-label="Where ${esc(t.id)} came from" title="Where it came from">${ICON_QUOTE}</button><button data-copy="${esc(t.id)}" title="Copy">${ICON_COPY}</button></span>`;
};
const ttpCount = (list) => TTP_ORDER.map((k) => [k, list.filter((t) => t.kind === k).length]).filter(([, n]) => n).map(([k, n]) => `${n} ${TTP_KINDS[k].short}`).join(' · ');
function ttpGroups(list, chip, box = 'nw-chips') {
  return TTP_ORDER.map((k) => {
    const items = list.filter((t) => t.kind === k);
    return items.length ? `<div class="nw-ttpg k-${k}"><div class="nw-ttpg-h"><span class="nw-ttpk k-${k}">${esc(TTP_KINDS[k].label)}</span><span class="nw-ttpg-s">${esc(TTP_KINDS[k].sub)}</span></div>
      <div class="${box}">${items.map(chip).join('')}</div></div>` : '';
  }).join('');
}
function ttpBlock(list, many = false) {
  if (!list.length) return '';
  const nx = ttpExportable(list).length;
  return `
    <div class="nw-x nw-ttpx">
      <div class="nw-xh"><span class="nw-xb">AI</span><b>Techniques read from ${many ? 'these articles' : 'this article'}</b><span class="nw-xs" data-term="attack-technique">MITRE ATT&amp;CK · ${esc(ttpCount(list))}</span></div>
      <p class="nw-ttp-cav">${esc(TTP_CAVEAT)} ${esc(TTP_HOW)}</p>
      ${nx ? `<div class="nw-xa"><a class="src-btn primary" href="https://mitre-attack.github.io/attack-navigator/" target="_blank" rel="noopener" data-x="nav">Open in ATT&amp;CK Navigator ${ICON_EXT}</a><button class="src-btn" data-x="layer">${ICON_DL}Download layer</button><button class="src-btn" data-x="copy-ttps">${ICON_COPY}Copy</button><span class="nw-ttp-xn">Exports hold the ${list.some((t) => t.kind === 'possible') ? 'named and likely ones, not the possible ones' : 'named and likely ones'}.</span></div>` : '<div class="nw-hint">Only possible techniques here, so there is nothing to export.</div>'}
      ${ttpGroups(list, ttpChip)}
    </div>`;
}

function cveBlock(cves, enrich = []) {
  if (!cves.length) return '';
  const en = Object.fromEntries((enrich || []).map((c) => [String(c.id).toUpperCase(), c]));
  return `<div class="nw-x"><div class="nw-xh"><span class="nw-xb">AI</span><b>${cves.length} vulnerabilit${cves.length === 1 ? 'y' : 'ies'}</b>
      <div class="nw-xa inl"><button class="src-btn" data-x="copy-cves">${ICON_COPY}Copy</button></div></div>
    <div class="nw-cves">${cves.map((c) => {
      const e = en[String(c.name).toUpperCase()] || {};
      return `<div class="nw-cverow"><button class="nw-chip e-cve" data-eid="${esc(c.id)}">${eicon('cve')}<span class="nw-cn">${esc(c.name)}</span></button>
        ${e.kev ? `<span class="tag red" title="CISA KEV${e.kev_added ? `, added ${esc(T.date(e.kev_added))}` : ''}">KEV</span>` : ''}${e.ransomware ? '<span class="tag red">ransomware</span>' : ''}
        ${e.cvss != null ? `<span class="tag ${e.cvss >= 9 ? 'red' : e.cvss >= 7 ? 'orange' : 'amber'}" title="${esc(e.cvss_status === 'ok' ? 'CVSS from NVD' : e.cvss_status || '')}">CVSS ${esc(e.cvss)}</span>` : ''}
        ${e.epss != null ? epssTag(e.epss, e.epss_percentile, e.epss_prev, e.epss_since) : e.epss_status === 'not scored' ? '<span class="tag" title="FIRST EPSS has no score for this id (often too new or reserved)">EPSS n/a</span>' : ''}
        ${(e.advisories || []).slice(0, 2).map((a) => (safeUrl(a.url) ? `<a class="tag amber" href="${esc(safeUrl(a.url))}" target="_blank" rel="noopener" title="CISA ${esc(a.kind || 'advisory')}: ${esc(a.title || '')}">${esc(a.id)}</a>` : `<span class="tag amber">${esc(a.id)}</span>`)).join('')}
        ${seenSlot(c.name, { compact: true })}<span class="nw-cves-s">${esc(e.summary ? (e.summary.length > 120 ? e.summary.slice(0, 118) + '…' : e.summary) : '')}</span></div>`;
    }).join('')}</div></div>`;
}

function wireExports(el, ctx) {
  fillSeen(el);   // "Seen on your network" chips in the IoC and CVE lists (left empty when never seen)
  wireTtpTips();  // the sentence behind each technique chip
  const { title, url, inds, ttps, named, published } = ctx;
  const iocs = inds.filter((i) => i.type !== 'cve' && i.type !== 'technique');
  const cves = inds.filter((i) => i.type === 'cve');
  el.querySelectorAll('[data-copy]').forEach((b) => (b.onclick = (e) => { e.stopPropagation(); copy(b.dataset.copy, `Copied ${b.dataset.copy.slice(0, 40)}`); }));
  const on = (k, fn) => el.querySelectorAll(`[data-x="${k}"]`).forEach((b) => (b.onclick = fn));
  on('copy-iocs', () => copy(iocs.map((i) => i.name).join('\n'), `Copied ${iocs.length} IoCs`));
  on('csv', () => download(`${slug(title)}-iocs.csv`, toCsv([['type', 'value', 'first_seen', 'last_seen', 'articles', 'relationships', 'flag'], ...iocs.map((i) => [i.type === 'hash' ? hashKind(i.name) : i.type, i.name, i.first_seen || '', i.last_seen || '', i.articles || 1, i.relationships || 0, i.suspect || ''])])));
  on('stix', () => download(`${slug(title)}.stix.json`, stixBundle(title, url, [...iocs.filter((i) => !i.suspect), ...cves], ttps, named, published), 'application/json'));
  on('misp', () => download(`${slug(title)}.misp.json`, mispEvent(title, url, [...iocs, ...cves], ttps, published), 'application/json'));
  const tx = ttpExportable(ttps || []);
  on('copy-ttps', () => copy(tx.map((t) => t.id).join('\n'), `Copied ${tx.length} techniques`));
  on('layer', () => download(`${slug(title)}-layer.json`, navigatorLayer(title, ttps), 'application/json'));
  on('nav', () => download(`${slug(title)}-layer.json`, navigatorLayer(title, ttps), 'application/json'));
  on('copy-cves', () => copy(cves.map((i) => i.name).join('\n'), `Copied ${cves.length} CVEs`));
  on('all-iocs', (e) => { e.currentTarget.previousElementSibling.classList.remove('clip'); e.currentTarget.remove(); });
}

// Merge indicator rows from /intel with entity chips (fallback when /intel is unavailable).
function indicators(intel, ents, storyIocs) {
  if (storyIocs?.length) {
    return storyIocs.map((i) => ({ id: i.id, type: i.type, name: i.value, first_seen: i.global_first_seen || i.first_seen, last_seen: i.global_last_seen || i.last_seen,
      articles: i.articles, relationships: (i.relationships || []).length, rels: i.relationships || [], sources: i.sources || [],
      listed: i.listed_by || [] }));
  }
  const rows = (intel?.indicators || []).filter((i) => i.type !== 'technique').map((i) => ({ ...i, name: i.name || i.id.split(':').slice(1).join(':') }));
  if (rows.length) return rows;
  return ents.filter((e) => isIoc(entType(e)) || entType(e) === 'cve').map((e) => ({ id: e.id, type: entType(e), name: entName(e), articles: e.articles || 1, confidence: e.confidence }));
}

// The label of a stored link to a technique, in this story's words (core/ttp.js): the technique block's label when the
// story lists it, else the claim's own; nothing for a link MITRE's catalogue states. `ttps`: ttpList().
function linkTag(c, ttps) {
  const tech = typeOf(c.obj) === 'technique' ? c.obj : typeOf(c.subj) === 'technique' ? c.subj : null;
  if (!tech) return '';
  const tid = tech.split(':').slice(1).join(':').toUpperCase();
  const own = ttpLinkKind(c, tid);
  if (!own || own === 'confirmed') return '';
  const t = (ttps || []).find((x) => x.id === tid);
  const q = ttpQuote(c);
  return ttpTag({ id: tid, kind: t?.kind || own, name: t?.name || (tech === c.obj ? c.obj_name : c.subj_name), quote: t?.quote || q?.quote, source: t?.source || q?.source });
}
const typeOf = (id) => String(id || '').split(':')[0];

// Claims → per-entity relationship lines.
function relationships(claims, ttps = []) {
  const by = new Map();
  const add = (id, line) => { if (!by.has(id)) by.set(id, []); by.get(id).push(line); };
  for (const c of claims || []) {
    const q = c.evidence?.[0];
    const tag = linkTag(c, ttps);
    add(c.subj, { text: PRED[c.predicate] || c.predicate, other: { id: c.obj, name: c.obj_name || c.obj.split(':').slice(1).join(':'), type: c.obj_type || c.obj.split(':')[0] }, conf: c.confidence, quote: q?.quote, src: q?.source, ref: q?.ref_id, tag });
    add(c.obj, { text: PRED_IN[c.predicate] || `← ${c.predicate}`, other: { id: c.subj, name: c.subj_name || c.subj.split(':').slice(1).join(':'), type: c.subj_type || c.subj.split(':')[0] }, conf: c.confidence, quote: q?.quote, src: q?.source, ref: q?.ref_id, tag });
  }
  return by;
}
const band = (c) => (c == null ? '' : c >= 0.6 ? 'high' : c >= 0.35 ? 'mod' : 'low');
const confCell = (c) => (c == null ? '<span class="nw-conf">—</span>' : `<span class="nw-conf ${band(c)}" title="confidence ${c}"><i style="width:${Math.round(c * 100)}%"></i></span><span class="nw-confv mono">${Math.round(c * 100)}</span>`);

function actorTable(list, rels, cite) {
  if (!list.length) return '<div class="nw-hint">No actors or malware named.</div>';
  return `<table class="nw-at"><thead><tr><th>Name</th><th>Relationship</th><th class="r">Confidence</th></tr></thead><tbody>
    ${list.map((e) => {
      const rs = (rels.get(e.id) || []).slice(0, 3);
      const conf = Math.max(e.confidence ?? 0, ...rs.map((r) => r.conf ?? 0)) || null;
      return `<tr><td>${chip(e)}<div class="nw-atn mono">${e.articles ? `${e.articles} article${e.articles === 1 ? '' : 's'}` : ''}${e.method ? ` · ${esc(e.method === 'llm' ? 'LLM' : e.method)}` : ''}</div></td>
        <td>${rs.length ? rs.map((r) => `<div class="nw-rel"><span>${esc(r.text)}</span> <button class="nw-relo" data-eid="${esc(r.other.id)}">${esc(r.other.name)}</button>${r.tag || ''}${r.ref ? cite(r.ref) : ''}</div>`).join('') : '<span class="nw-hint">mentioned</span>'}</td>
        <td class="r">${confCell(conf)}</td></tr>`;
    }).join('')}</tbody></table>`;
}

// Cite summary sentences to the articles whose text overlaps them most.
const STOP = new Set('that this with from have were their they which been about into after over also said says will more than other these those when what while where under including according company companies attack attacks'.split(' '));
const toks = (s) => new Set((s.toLowerCase().match(/[a-z0-9][a-z0-9.-]{3,}/g) || []).filter((w) => !STOP.has(w)));
function citeSummary(summary, arts, byId, fallback) {
  const sents = summary.split(/(?<=[.!?])\s+(?=[A-Z0-9“"])/);
  const at = arts.map((a) => ({ n: a._n, t: toks(`${a.title} ${a.dek || ''} ${byId[a.id]?.text || ''}`) }));
  return sents.map((s) => {
    const st = toks(s);
    if (!st.size) return esc(s);
    const sc = at.map((a) => ({ n: a.n, v: [...st].filter((w) => a.t.has(w)).length / st.size })).filter((x) => x.v >= 0.45).sort((a, b) => b.v - a.v).slice(0, 3);
    const ns = sc.length ? sc.map((x) => x.n).sort((a, b) => a - b) : fallback ? [fallback] : [];
    return `${esc(s)}${ns.map((n) => `<button class="nw-cite" data-cite="${n}" title="Article ${n}">${n}</button>`).join('')}`;
  }).join(' ');
}

// ------------------------------------------------------------------ story
export async function renderStory(el, id, ctx) {
  loading(el);
  let s, intel;
  try {
    [s, intel] = await Promise.all([api.get(`/api/news/stories/${encodeURIComponent(id)}`), api.get('/api/news/intel', { story: id }).catch(() => null)]);
  } catch (e) { return err(el, e, () => renderStory(el, id, ctx)); }
  if (ctx.S.pane !== 'story' || ctx.S.paneArg !== id) return;
  s.title = decode(s.title); s.summary = decode(s.summary);
  const arts = s.articles || [];
  arts.forEach((a, i) => { a._n = i + 1; });
  const lead = arts.find((a) => a.id === s.lead_article) || arts[0];
  const readable = arts.filter((a) => a.status === 'ok').slice(0, 10);
  const details = await Promise.all(readable.map((a) => api.get(`/api/news/articles/${a.id}`, { similar: a.id === lead?.id ? 16 : 0 }).catch(() => null)));
  if (ctx.S.pane !== 'story' || ctx.S.paneArg !== id) return;
  const byId = Object.fromEntries(details.filter(Boolean).map((d) => [d.id, d]));
  const texts = details.map((d) => d?.text || '');

  const ents = (s.entities || []).map((e) => ({ ...e, articles: e.articles ?? 1 }));
  ents.forEach((e) => ctx.known.set(e.id, e));
  const named = dedupeByName(ents.filter((e) => !isIoc(entType(e)) && !['cve', 'technique'].includes(entType(e))));
  const inds = indicators(intel, ents, s.iocs).map((i) => ({ ...i, suspect: suspect(i, texts) }));
  const cves = inds.filter((i) => i.type === 'cve').map((i) => ({ ...i, id: i.id }));
  const ttps = ttpList(intel, ents, texts);
  const nTtp = ttpExportable(ttps).length;
  const rels = relationships(intel?.claims, ttps);
  const actors = named.filter((e) => ['actor', 'malware', 'tool', 'campaign'].includes(entType(e)))
    .sort((a, b) => (rels.get(b.id)?.length || 0) - (rels.get(a.id)?.length || 0) || b.articles - a.articles);
  const others = named.filter((e) => !actors.includes(e));
  // victims & targets: 'targets' claims, else org/sector/country entities named most
  const targets = [];
  const seenT = new Set();
  for (const c of intel?.claims || []) {
    if (c.predicate !== 'targets' || seenT.has(c.obj)) continue;
    seenT.add(c.obj);
    targets.push({ id: c.obj, name: c.obj_name || c.obj.split(':').slice(1).join(':'), type: c.obj_type || c.obj.split(':')[0], by: c.subj_name || c.subj.split(':').slice(1).join(':'), quote: c.evidence?.[0]?.quote, ref: c.evidence?.[0]?.ref_id });
  }
  const sectors = ents.filter((e) => entType(e) === 'sector').slice(0, 6);
  const geos = ents.filter((e) => entType(e) === 'country').slice(0, 8);
  const nAct = named.filter((e) => entType(e) === 'actor').length, nMal = named.filter((e) => ['malware', 'tool'].includes(entType(e))).length;
  const iocN = inds.filter((i) => i.type !== 'cve' && i.type !== 'technique').length;
  const matched = ctx.watchMatch(id);
  const mNames = ctx.watchNames?.(id) || {};
  // Follow buttons for what the story is about: vendors and products first, then groups and malware
  const followable = ['vendor', 'product', 'actor', 'malware', 'tool'];
  const fcands = dedupeByName(ents.filter((e) => followable.includes(entType(e))))
    .sort((a, b) => followable.indexOf(entType(a)) - followable.indexOf(entType(b)) || (b.articles || 0) - (a.articles || 0)).slice(0, 3);
  const artN = Object.fromEntries(arts.map((a) => [a.id, a._n]));
  const cite = (ref) => (artN[ref] ? `<button class="nw-cite" data-cite="${artN[ref]}" title="Article ${artN[ref]}">${artN[ref]}</button>` : '');
  const t0 = new Date(s.first_seen).getTime(), span = Math.max(1, new Date(s.last_seen).getTime() - t0);
  ctx.setCrumb(`STORY <span class="nw-crumb-t">${esc(s.title)}</span>`);

  const timeline = arts.map((a) => `
    <li class="nw-tl ${a.dup_of ? 'dup' : ''}" id="nw-ref-${a._n}">
      <span class="nw-tln mono">${a._n}</span>
      <div class="nw-tlm mono">${esc(fmtDate(a.published || a.fetched_at))}${a._n === 1 ? '<span class="nw-first">first report</span>' : ''}</div>
      <div class="nw-tlo"><b>${esc(a.source)}</b>${tierBadge(a.tier, roleLabel(a.role))}${a.role ? `<span class="nw-rolet ${roleCls(a.role)}">${esc(roleLabel(a.role))}</span>` : ''}${a.author && a.author !== a.source ? `<span class="nw-auth">${esc(a.author)}</span>` : ''}</div>
      <button class="nw-tlt" data-open="${esc(a.id)}">${esc(decode(a.title))}</button>
      <div class="nw-tlf mono">
        ${a.dup_of ? '<span class="nw-syn" title="Same text as an earlier article; counted once">syndicated copy</span>' : ''}
        ${a.status !== 'ok' ? `<span class="nw-warn" title="${esc(a.reason || '')}">${esc(a.status)}</span>` : ''}
        ${(a.entities || []).length ? `<span>${a.entities.length} entities</span>` : ''}
        ${safeUrl(a.url) ? `<a href="${esc(safeUrl(a.url))}" target="_blank" rel="noopener">original ${ICON_EXT}</a>` : a.url ? `<span title="Not a web link: ${esc(a.url)}">original not linkable</span>` : ''}
      </div>
    </li>`).join('');

  el.innerHTML = `
    <article class="nw-st">
      <div class="nw-st-top mono"><span class="nw-live"></span>Reported ${esc(ago(s.first_seen))}<span class="nw-sl">/</span>Updated ${esc(ago(s.last_seen))}<span class="nw-sl">/</span>${esc(fmtDate(s.first_seen))}</div>
      <h2 class="nw-st-h">${esc(s.title)}</h2>
      <div class="nw-st-kpis">
        <span><b>${s.source_count}</b> ${s.source_count === 1 ? 'source' : 'sources'} ${Object.entries(s.tier_counts || {}).map(([t]) => tierBadge(t)).join('')}</span>
        ${nAct ? `<a href="#nw-actors" class="e-act">${eicon('actor')}<b>${nAct}</b> threat actor${nAct === 1 ? '' : 's'}</a>` : ''}
        ${nMal ? `<a href="#nw-actors" class="e-mal">${eicon('malware')}<b>${nMal}</b> malware</a>` : ''}
        ${cves.length ? `<a href="#nw-iocs" class="e-cve">${eicon('cve')}<b>${cves.length}</b> CVE${cves.length === 1 ? '' : 's'}</a>` : ''}
        ${iocN ? `<a href="#nw-iocs" class="e-ioc">${eicon('ioc')}<b>${iocN}</b> IoC${iocN === 1 ? '' : 's'}</a>` : ''}
        ${ttps.length ? `<a href="#nw-ttps" class="e-ttp" title="${esc(ttpCount(ttps))}">${eicon('technique')}<b>${ttps.length}</b> technique${ttps.length === 1 ? '' : 's'}</a>` : ''}
        ${sectors.length ? `<span class="nw-tg">Sector: ${sectors.slice(0, 3).map((e) => `<button class="nw-relo" data-eid="${esc(e.id)}">${esc(entName(e))}</button>`).join(', ')}</span>` : ''}
      </div>
      ${matched.length ? `<div class="nw-why stack-why">${eyeIcon()}<span>You follow ${matched.map((m) => `<b>${esc(matchName(m, mNames))}</b>`).join(', ')}</span></div>` : ''}
      ${fcands.length ? `<div class="stack-follow-row"><span class="stack-follow-l">Follow what this is about</span>${fcands.map((e) => followButton({ entity: e.id }, { name: entName(e), cls: 'stack-fb-sm' })).join('')}</div>` : ''}
      <div class="nw-st-act">
        ${lead ? `<button class="src-btn primary" data-open="${esc(lead.id)}">Read lead article</button>` : ''}
        ${lead && safeUrl(lead.url) ? `<a class="src-btn" href="${esc(safeUrl(lead.url))}" target="_blank" rel="noopener">Original ${ICON_EXT}</a>` : ''}
        ${inds.length || nTtp ? `<button class="src-btn" data-x="stix">${ICON_DL}STIX 2.1</button><button class="src-btn" data-x="misp">${ICON_DL}MISP</button>` : ''}
        <button class="src-btn" data-x="link">${ICON_COPY}Copy link</button>
      </div>

      <div class="nw-st-grid">
        <div class="nw-st-main">
          <section class="nw-sec first">
            <div class="nw-sech"><h3>Summary</h3><span class="nw-src-l mono">${s.summary_by === 'llm' ? `<span class="nw-ai">AI</span>local LLM over ${s.summary_n || s.article_count} articles · citations by text match` : 'lead article’s summary'}</span><button class="src-btn ghost sm" data-x="copy-sum">${ICON_COPY}Copy</button></div>
            <p class="nw-sum">${citeSummary(s.summary || 'No summary yet.', arts, byId, lead?._n)}</p>
          </section>
          <section class="nw-sec">
            <div class="nw-sech"><h3>Timeline of coverage</h3><span class="nw-src-l mono">${arts.length} article${arts.length === 1 ? '' : 's'} · ${s.source_count} outlet${s.source_count === 1 ? '' : 's'}${s.syndicated ? ` · ${s.syndicated} syndicated` : ''}</span></div>
            ${arts.length > 1 ? `<div class="nw-span">${arts.map((a) => `<i class="t-${esc(a.tier || '')}" style="left:${((new Date(a.published || a.fetched_at).getTime() - t0) / span) * 100}%" title="${esc(a.source)} · ${esc(fmtDate(a.published))}"></i>`).join('')}
              <span class="l mono">${esc(fmtDate(s.first_seen))}</span><span class="r mono">${esc(fmtDate(s.last_seen))}</span></div>` : ''}
            <ol class="nw-tls">${timeline}</ol>
          </section>
        </div>
        <aside class="nw-st-side">
          <section class="nw-sec first">
            <div class="nw-sech"><h3>Victims &amp; targets</h3></div>
            ${targets.length ? `<div class="nw-vics">${targets.slice(0, 6).map((v) => `<div class="nw-vic"><button class="nw-vicn" data-eid="${esc(v.id)}">${esc(v.name)}</button><span class="nw-vict">${esc(emeta(v.type).label)} · targeted by ${esc(v.by)}${v.ref ? cite(v.ref) : ''}</span>${v.quote ? `<q>${esc(v.quote.length > 140 ? v.quote.slice(0, 138) + '…' : v.quote)}</q>` : ''}</div>`).join('')}</div>` : ''}
            ${sectors.length || geos.length ? `<div class="nw-vtags">${sectors.map((e) => chip(e, { count: true })).join('')}${geos.map((e) => chip(e, { count: true })).join('')}</div>` : ''}
            ${!targets.length && !sectors.length && !geos.length ? '<div class="nw-hint">No victim or sector extracted.</div>' : ''}
          </section>
        </aside>
      </div>

      <section class="nw-sec" id="nw-actors">
        <div class="nw-sech"><h3>Associated actors &amp; malware</h3><span class="nw-src-l mono">${actors.length}</span></div>
        ${(() => {
          const withRel = actors.filter((e) => rels.get(e.id)?.length);
          const head = [...withRel, ...actors.filter((e) => !withRel.includes(e)).slice(0, Math.max(0, 5 - withRel.length))];
          const rest = actors.filter((e) => !head.includes(e));
          return actorTable(head, rels, cite) + (rest.length ? `<div class="nw-also"><span class="label">Also named</span><div class="nw-chips">${chipList(rest, 14)}</div></div>` : '');
        })()}
      </section>

      <section class="nw-sec nw-iocs" id="nw-iocs">
        <div class="nw-sech"><h3>Indicators of compromise</h3><span class="nw-src-l mono">addresses, domains, URLs, file hashes and CVEs · merged across the story · first and last mention across all data</span></div>
        <div class="nw-xwrap">
          ${iocBlock(inds, { title: s.title, url: lead?.url, ttps, named, published: s.first_seen, story: true })}
          ${cveBlock(cves, s.cves)}
          ${!inds.some((i) => i.type !== 'technique') ? '<div class="nw-hint pad">No addresses, domains, URLs, file hashes or CVEs in this story’s articles.</div>' : ''}
        </div>
      </section>

      ${ttps.length ? `<section class="nw-sec nw-ttps" id="nw-ttps">
        <div class="nw-sech"><h3>ATT&amp;CK techniques</h3><span class="nw-src-l mono">how the attackers worked, as MITRE ATT&amp;CK ids · behaviour, not indicators</span></div>
        <div class="nw-xwrap">${ttpBlock(ttps, readable.length > 1)}</div>
      </section>` : ''}

      ${others.length ? `<section class="nw-sec"><div class="nw-sech"><h3>Also mentioned</h3><span class="nw-src-l mono">${others.length} organisations, vendors and products</span></div>
        <div class="nw-chips">${chipList(others, 16, { count: true })}</div></section>` : ''}

      <section class="nw-sec nw-simsec">
        <div class="nw-sech"><h3>Similar stories</h3><span class="nw-src-l mono nw-simm"></span></div>
        <div class="nw-sim"></div>
      </section>
    </article>`;

  el.querySelectorAll('[data-open]').forEach((b) => (b.onclick = () => ctx.openArticle(b.dataset.open, { story: id })));
  el.querySelectorAll('.nw-st-kpis a[href^="#nw-"]').forEach((a) => (a.onclick = (e) => { e.preventDefault(); el.querySelector(a.getAttribute('href'))?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }));
  el.addEventListener('click', (e) => {
    const c = e.target.closest('[data-cite]');
    if (!c) return;
    const li = el.querySelector(`#nw-ref-${c.dataset.cite}`);
    if (li) { li.scrollIntoView({ behavior: 'smooth', block: 'center' }); li.classList.remove('flash'); void li.offsetWidth; li.classList.add('flash'); }
  });
  el.querySelector('[data-x="link"]').onclick = () => copy(`${location.origin}${location.pathname}#news/story/${encodeURIComponent(id)}`, 'Link copied');
  el.querySelector('[data-x="copy-sum"]').onclick = () => copy(s.summary || '', 'Summary copied');
  wireExports(el, { title: s.title, url: lead?.url, inds, ttps, named, published: s.first_seen });
  mountNotes(el.querySelector('.nw-st-main'), { kind: 'story', item: id, title: s.title, cls: 'nw-sec', at: '.nw-sec.first', actions: el.querySelector('.nw-st-act'), summary: () => storySummary({ s, arts, inds, named, cves, ttps }) });

  const ld = byId[lead?.id];
  const sims = [];
  const seen = new Set([id]);
  for (const r of ld?.similar?.results || []) {
    const sid = r.story_id || `a:${r.id}`;
    if (seen.has(sid)) continue;
    seen.add(sid); sims.push(r);
    if (sims.length >= 6) break;
  }
  el.querySelector('.nw-simm').textContent = ld?.similar ? (ld.similar.method === 'vector' ? 'by meaning (local embeddings)' : 'by keywords (AI helper offline)') : '';
  el.querySelector('.nw-sim').innerHTML = sims.length ? sims.map((r) => {
    const sm = ctx.storyMeta(r.story_id);
    return `<button class="nw-simr" data-sid="${esc(r.story_id || '')}" data-aid="${esc(r.id)}">
      <span class="nw-simt">${esc(decode(sm?.title || r.title))}</span>
      <span class="nw-simm2 mono">${esc(r.source)} ${tierBadge(r.tier)} · ${esc(ago(r.published))}${sm && sm.source_count > 1 ? ` · ${sm.source_count} sources` : ''}${r.score != null ? `<span class="nw-simsc" title="similarity">${Math.round(r.score * 100)}%</span>` : ''}</span>
    </button>`;
  }).join('') : '<div class="nw-hint">No similar stories.</div>';
  el.querySelectorAll('.nw-simr').forEach((b) => (b.onclick = () => (b.dataset.sid ? ctx.openStory(b.dataset.sid) : ctx.openArticle(b.dataset.aid, { similarTo: s.title }))));
}

function eyeIcon() {
  return '<svg class="i" viewBox="0 0 24 24"><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.6" fill="currentColor"/></svg>';
}
function infoIcon() {
  return '<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M12 11v5.5M12 7.6v.4" stroke="currentColor" stroke-width="1.8"/></svg>';
}

// ------------------------------------------------------------------ article reader
// (Article notes live on the server now: core/notes.js, which also moved the old browser-only notes.)

export async function renderArticle(el, id, ctx, why) {
  loading(el);
  let a, intel;
  try {
    [a, intel] = await Promise.all([api.get(`/api/news/articles/${encodeURIComponent(id)}`, { similar: 8 }), api.get('/api/news/intel', { article: id }).catch(() => null)]);
  } catch (e) { return err(el, e, () => renderArticle(el, id, ctx, why)); }
  if (ctx.S.pane !== 'article' || ctx.S.paneArg !== id) return;
  why = why || {};
  const title = decode(a.title);
  const ents = a.entities || [];
  ents.forEach((e) => ctx.known.set(e.id, e));
  const named = dedupeByName(ents.filter((e) => !isIoc(entType(e)) && !['cve', 'technique', 'country', 'sector'].includes(entType(e))));
  const inds = indicators(intel, ents).map((i) => ({ ...i, suspect: suspect(i, [a.text || '']) }));
  const cves = inds.filter((i) => i.type === 'cve');
  const ttps = ttpList(intel, ents, [a.text || '']);
  const actors = named.filter((e) => entType(e) === 'actor'), mal = named.filter((e) => ['malware', 'tool'].includes(entType(e))), camp = named.filter((e) => entType(e) === 'campaign');
  const rest = named.filter((e) => !actors.includes(e) && !mal.includes(e) && !camp.includes(e));
  const sm = ctx.storyMeta(a.story_id);
  const matched = ctx.watchMatch(a.story_id);
  const claims = (intel?.claims || []).filter((c) => c.evidence?.length).slice(0, 8);
  ctx.setCrumb(`ARTICLE <b>${esc(a.source)}</b> ${tierBadge(a.tier)} <span class="nw-crumb-t">${esc(shortDate(a.published))} · ${esc(title)}</span>`);

  const reasons = [];
  if (why.search) reasons.push(`matched your search <b>“${esc(why.search)}”</b>${why.chunk !== '' && why.chunk != null && Number.isInteger(+why.chunk) && +why.chunk >= 0 ? ` (best passage ${+why.chunk + 1})` : ''}`);
  if (why.entity) reasons.push(`mentions <b>${esc(why.entity.split(':').slice(1).join(':'))}</b>`);
  if (why.similarTo) reasons.push(`similar to <b>${esc(why.similarTo)}</b>`);
  if (matched.length) reasons.push(`you follow ${matched.map((m) => `<b>${esc(matchName(m, ctx.watchNames?.(a.story_id) || {}))}</b>`).join(', ')}`);
  reasons.push(`from <b>${esc(a.source)}</b> (${esc(roleLabel(a.role).toLowerCase() || 'news')}, trust: ${esc(tierLabel(a.tier).toLowerCase())})${a.fetched_at ? `, fetched ${esc(ago(a.fetched_at))}` : ''}`);
  if (sm && sm.source_count > 1) reasons.push(`${sm.source_count} outlets cover this story`);

  const body = a.status === 'ok' && a.text
    ? highlight(a.text, ents, { q: why.search })
    : `<div class="nw-nofull">${infoIcon()}<div><b>Full text not stored</b><span>${esc(a.status)}${a.reason ? ` · ${esc(a.reason)}` : ''}. Night Desk never works around paywalls or bot checks; the outlet's own summary is shown instead.</span></div></div>${a.dek ? `<p>${esc(decode(a.dek))}</p>` : ''}`;
  const nameLine = [actors.length && `${actors.length} threat actor${actors.length === 1 ? '' : 's'}`, mal.length && `${mal.length} malware famil${mal.length === 1 ? 'y' : 'ies'}`, camp.length && `${camp.length} campaign${camp.length === 1 ? '' : 's'}`].filter(Boolean).join(' · ');
  const hasX = inds.length || ttps.length || named.length;

  el.innerHTML = `
    <article class="nw-art">
      <header class="nw-art-id">
        <div class="nw-art-src">
          <b>${esc(a.source)}</b>${tierBadge(a.tier, roleLabel(a.role))}${a.role ? `<span class="nw-rolet ${roleCls(a.role)}">${esc(roleLabel(a.role))}</span>` : ''}
          <span class="nw-dotsep"></span><span class="mono">${esc(fmtDate(a.published))}</span>
          ${a.author && a.author !== a.source ? `<span class="nw-dotsep"></span><span>by ${esc(a.author)}</span>` : ''}
          <span class="nw-dotsep"></span><span class="mono">${a.text ? `${Math.max(1, Math.round(a.text.split(/\s+/).length / 230))} min read` : 'summary only'}</span>
        </div>
        <h2 class="nw-art-h">${esc(title)}</h2>
        <div class="nw-st-act">
          ${safeUrl(a.url) ? `<a class="src-btn primary" href="${esc(safeUrl(a.url))}" target="_blank" rel="noopener">Read original ${ICON_EXT}</a>` : a.url ? `<span class="nw-src-l mono" title="Not a web link, shown as text">Source URL: ${esc(a.url)}</span>` : ''}
          ${sm && sm.source_count > 1 && ctx.S.paneArg !== a.story_id ? `<button class="src-btn" data-story="${esc(a.story_id)}">Story · ${sm.source_count} sources ›</button>` : ''}
          <button class="src-btn" data-x="link">${ICON_COPY}Copy link</button>
        </div>
      </header>

      <section class="nw-extp">
        <div class="nw-extp-h"><h3>Extracted</h3><span class="nw-src-l mono">${hasX ? 'regex for indicators, local LLM for names · click any item for details' : ''}</span></div>
        ${nameLine ? `<div class="nw-x"><div class="nw-xh"><span class="nw-xb">AI</span><b>${esc(nameLine)}</b></div><div class="nw-chips">${chipList([...actors, ...mal, ...camp], 10)}</div></div>` : ''}
        ${iocBlock(inds, { title, url: a.url, ttps, named, published: a.published, story: false })}
        ${ttpBlock(ttps)}
        ${cveBlock(cves, a.cves)}
        ${claims.length ? `<div class="nw-x"><div class="nw-xh"><span class="nw-xb">AI</span><b>${claims.length} reported relationship${claims.length === 1 ? '' : 's'}</b><span class="nw-xs">with the sentence each came from</span></div>
          <ul class="nw-claims">${claims.map((c) => `<li><div><button class="nw-relo" data-eid="${esc(c.subj)}">${esc(c.subj_name || c.subj.split(':').slice(1).join(':'))}</button> <span>${esc(PRED[c.predicate] || c.predicate)}</span> <button class="nw-relo" data-eid="${esc(c.obj)}">${esc(c.obj_name || c.obj.split(':').slice(1).join(':'))}</button>${linkTag(c, ttps)}${confCell(c.confidence)}</div><q>${esc(c.evidence[0].quote || '')}</q></li>`).join('')}</ul></div>` : ''}
        ${!hasX ? '<div class="nw-hint pad">This article names no indicators, techniques, actors or malware.</div>' : ''}
        ${rest.length ? `<div class="nw-x minor"><div class="nw-xh"><b>Also mentioned</b></div><div class="nw-chips">${chipList(rest, 10)}</div></div>` : ''}
      </section>

      <div class="nw-why">${infoIcon()}<span><em>Why this is here:</em> ${reasons.join(' · ')}</span></div>
      <div class="nw-body">${body}</div>
      ${a.original ? `<div class="nw-hint pad">Syndicated copy of <button class="nw-link" data-open="${esc(a.original.id)}">${esc(decode(a.original.title))}</button> (${esc(a.original.source)})</div>` : ''}
      ${a.copies?.length ? `<div class="nw-hint pad">Republished by ${a.copies.map((c) => `<button class="nw-link" data-open="${esc(c.id)}">${esc(c.source)}</button>`).join(', ')}</div>` : ''}
      ${safeUrl(a.url) ? `<div class="nw-art-end"><a class="src-btn" href="${esc(safeUrl(a.url))}" target="_blank" rel="noopener">Continue on ${esc(a.source)} ${ICON_EXT}</a></div>` : ''}

      ${a.similar?.results?.length ? `<section class="nw-sec">
        <div class="nw-sech"><h3>Similar articles</h3><span class="nw-src-l mono">${a.similar.method === 'vector' ? 'by meaning (local embeddings)' : 'by keywords'}</span></div>
        <div class="nw-sim">${a.similar.results.slice(0, 6).map((r) => `<button class="nw-simr" data-open="${esc(r.id)}">
          <span class="nw-simt">${esc(decode(r.title))}</span>
          <span class="nw-simm2 mono">${esc(r.source)} ${tierBadge(r.tier)} · ${esc(ago(r.published))}${r.story_id === a.story_id ? ' · same story' : ''}${r.score != null ? `<span class="nw-simsc">${Math.round(r.score * 100)}%</span>` : ''}</span></button>`).join('')}</div>
      </section>` : ''}
    </article>`;

  el.querySelectorAll('[data-open]').forEach((b) => (b.onclick = () => ctx.openArticle(b.dataset.open, { similarTo: title })));
  el.querySelector('[data-story]')?.addEventListener('click', (e) => ctx.openStory(e.currentTarget.dataset.story));
  el.querySelector('[data-x="link"]').onclick = () => copy(`${location.origin}${location.pathname}#news/article/${encodeURIComponent(id)}`, 'Link copied');
  mountNotes(el.querySelector('.nw-art'), { kind: 'article', item: id, title, cls: 'nw-notes', before: '.nw-why' });
  wireExports(el, { title, url: a.url, inds, ttps, named, published: a.published });
  if (why.search) setTimeout(() => el.querySelector('.nw-body mark.nw-q')?.scrollIntoView({ block: 'center' }), 60);
}

// ------------------------------------------------------------------ phone pages (design.md §4.3, mock-story.png)
// A story and an article are pushed pages on a phone (views/news/phone.js): one column, the action bar at the bottom
// (core/page.js setActionBar), every section below the summary collapsed. o: { alive() (false once the page was left),
// setBack({ label, href }) (the top bar's ‹ Parent), setBar(nodes) (the action bar; phone.js keeps it
// and puts it back when the page is shown again), after() (the page has its content: restore the scroll) }.
const MI = {
  note: '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3.5h8.5L19 8v12.5H6z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M14 3.5V8h4.5M9 12h7M9 15.5h7" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>',
  share: '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 15V4M8 8l4-4 4 4M6 11v8.5h12V11" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  dots: '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><circle cx="5" cy="12" r="1.7" fill="currentColor"/><circle cx="12" cy="12" r="1.7" fill="currentColor"/><circle cx="19" cy="12" r="1.7" fill="currentColor"/></svg>',
};
function mBtn(label, { primary = false, icon = '', square = false, href = '', onClick } = {}) {
  const b = document.createElement(href ? 'a' : 'button');
  if (href) { b.href = href; b.target = '_blank'; b.rel = 'noopener'; } else b.type = 'button';
  b.className = `m-btn${primary ? ' m-btn-primary' : ''}${square ? ' m-btn-sq' : ''}`;
  if (square) { b.innerHTML = icon; b.setAttribute('aria-label', label); b.title = label; } else { b.innerHTML = `${icon}<span>${esc(label)}</span>`; }
  if (onClick) b.addEventListener('click', onClick);
  return b;
}
const moreBtn = (items) => { const b = mBtn('More actions', { square: true, icon: MI.dots, onClick: () => actionSheet({ id: 'news-more', title: '', label: 'More actions', items: items() }) }); b.setAttribute('aria-haspopup', 'menu'); return b; };
async function share(title, url) {
  if (navigator.share) { try { await navigator.share({ title, url }); return; } catch (e) { if (e?.name === 'AbortError') return; } }
  copy(url, 'Link copied');
}
const linkTo = (kind, id) => `${location.origin}${location.pathname}#news/${kind}/${encodeURIComponent(id)}`;
const plainText = (html) => { const d = document.createElement('div'); d.innerHTML = html || ''; return d.textContent.replace(/\s+/g, ' ').trim(); };
const mErr = (el, e, retry) => { el.innerHTML = errorState({ retry, title: "Couldn't open this", why: 'It may have been removed from the lake, or the server did not answer.', err: String(e?.message || e) }); };
const mSkel = (n = 4) => `<div class="nw-m-pskel" aria-hidden="true">${'<div class="m-skel"></div>'.repeat(n)}</div>`;
const acc = (key, t1, t2, inner) => `<div class="m-acc nw-m-acc" data-acc="${key}">
  <button type="button" class="m-acc-q" aria-expanded="false" aria-controls="nw-m-acc-${key}"><span class="nw-m-accl"><span class="nw-m-acct">${t1}</span>${t2 ? `<span class="nw-m-acc2">${t2}</span>` : ''}</span></button>
  <div class="m-acc-a" id="nw-m-acc-${key}" hidden>${inner}</div></div>`;
// (wired on the page's own article element: the page container is reused, so a listener on it would add up)
// The Notes row: "No notes yet" opens the composer; with notes it opens to the list (a tap on a note edits it).
function notesRow(el, kind, id, title, o) {
  const box = el.querySelector('.nw-m-notes');
  if (!box) return;
  let notes = [];
  const paint = () => {
    box.innerHTML = notes.length
      ? acc('notes', 'Notes', plural(notes.length, 'note'), `<div class="nw-m-nlist">${notes.map((n) => `<button type="button" class="nw-m-note" data-note="${esc(n.id)}"><span class="nw-m-nmeta">${esc(ago(n.created_at))}</span><span class="nw-m-nbody">${esc(plainText(n.html || n.body).slice(0, 400))}</span></button>`).join('')}
          <button type="button" class="m-btn nw-m-nadd" data-note-add>Add a note</button></div>`)
      : `<button type="button" class="nw-m-nrow" data-note-add><span class="nw-m-accl"><span class="nw-m-acct">Notes</span><span class="nw-m-acc2">No notes yet</span></span></button>`;
  };
  const load = () => api.get('/api/notes', { kind, item: id }).then((r) => { notes = r.notes || []; if (o.alive()) paint(); }).catch(() => {});
  paint(); load();
  box.addEventListener('click', (e) => {
    const n = e.target.closest('[data-note]');
    if (n) { const note = notes.find((x) => String(x.id) === n.dataset.note); if (note) openNoteSheet({ kind, id, title, note }); return; }
    if (e.target.closest('[data-note-add]')) openNoteSheet({ kind, id, title });
  });
  const onCh = (ev) => { if (!el.isConnected || !o.alive()) { window.removeEventListener('nd:notes-changed', onCh); return; } if (ev.detail?.kind === kind && String(ev.detail?.item) === String(id)) load(); };
  window.addEventListener('nd:notes-changed', onCh);
  return () => notes;
}
function wireAcc(el, onOpen = {}) {
  el.addEventListener('click', (e) => {
    const q = e.target.closest('.m-acc-q');
    if (!q || !el.contains(q)) return;
    const a = q.parentElement.querySelector(':scope > .m-acc-a');
    const open = q.getAttribute('aria-expanded') !== 'true';
    q.setAttribute('aria-expanded', open);
    a.hidden = !open;
    if (open) onOpen[q.parentElement.dataset.acc]?.(a);
  });
}
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
// A phone technique chip is one button: a tap shows the sentence it came from, with the MITRE link in that card.
const ttpChipPhone = (t) => { const nm = ttpName(t.id, t.name); return `<button type="button" class="nw-m-ent e-ttp nw-m-ttp k-${esc(t.kind)}" ${ttpAttrs(t)} data-ttp-ev aria-expanded="false">${eicon('technique')}<span><b class="mono">${esc(t.id)}</b>${nm ? ` ${esc(nm)}` : ''}</span></button>`; };
const mChip = (e) => `<button type="button" class="nw-m-ent ${emeta(entType(e)).cls}" data-eid="${esc(e.id)}">${eicon(entType(e))}<span>${esc(isIoc(entType(e)) ? defang(entName(e), entType(e)) : entName(e))}</span></button>`;

export async function renderStoryPhone(el, id, ctx, o) {
  const meta = ctx.storyMeta(id);
  const head = (s) => `
    <div class="nw-m-st-top"><i class="nw-m-live" aria-hidden="true"></i>Reported ${esc(ago(s.first_seen))}${s.last_seen && s.last_seen !== s.first_seen ? ` · updated ${esc(ago(s.last_seen))}` : ''}</div>
    <h1 class="nw-m-st-h">${esc(s.title)}</h1>`;
  const sumHtml = (t) => String(t || 'No summary yet.').split(/\n{2,}/).map((p) => `<p>${esc(p.trim())}</p>`).join('');
  el.innerHTML = meta ? `<article class="nw-m-st">${head(meta)}<div class="nw-m-st-meta">&nbsp;</div><div class="nw-m-st-sum">${sumHtml(meta.summary)}</div>${mSkel(3)}</article>` : `<article class="nw-m-st">${mSkel(6)}</article>`;
  o.setBar(null);
  let s, intel;
  try {
    [s, intel] = await Promise.all([api.get(`/api/news/stories/${encodeURIComponent(id)}`), api.get('/api/news/intel', { story: id }).catch(() => null)]);
  } catch (e) { if (o.alive()) mErr(el, e, () => renderStoryPhone(el, id, ctx, o)); return; }
  if (!o.alive()) return;
  s.title = decode(s.title); s.summary = decode(s.summary);
  const arts = s.articles || [];
  const lead = arts.find((a) => a.id === s.lead_article) || arts[0];
  const ents = (s.entities || []).map((e) => ({ ...e, articles: e.articles ?? 1 }));
  ents.forEach((e) => ctx.known.set(e.id, e));
  const named = dedupeByName(ents.filter((e) => !isIoc(entType(e)) && !['cve', 'technique', 'country', 'sector'].includes(entType(e))));
  const cvesE = ents.filter((e) => entType(e) === 'cve');
  const inds = indicators(intel, ents, s.iocs);
  const iocs = inds.filter((i) => i.type !== 'cve' && i.type !== 'technique');
  const ttps = ttpList(intel, ents);
  const sectors = ents.filter((e) => entType(e) === 'sector').slice(0, 3).map(entName);
  const tiers = Object.keys(s.tier_counts || {}).map((t) => String(t).toUpperCase()).sort();
  const outlets = [...new Set(arts.map((a) => a.source))];
  const metaLine = [plural(s.source_count || outlets.length || 1, 'source'), tiers.length ? tierLabel(tiers[0]).toLowerCase() : '', sectors.join(', ')].filter(Boolean).join(' · ');
  let touches = dedupeByName([...named.sort((a, b) => (b.articles || 0) - (a.articles || 0)), ...cvesE]).slice(0, 10);
  // a story that names only places and sectors still gets its chips
  if (!touches.length) touches = dedupeByName(ents.filter((e) => ['country', 'sector'].includes(entType(e)))).slice(0, 8);
  const matched = ctx.watchMatch(id);
  const mNames = ctx.watchNames?.(id) || {};
  const sources = arts.map((a) => `<button type="button" class="nw-m-arow" data-open="${esc(a.id)}">
      <span class="nw-m-arow-s">${esc(a.source)} · ${esc(tierLabel(a.tier).toLowerCase())} · ${esc(ago(a.published || a.fetched_at))}${a.dup_of ? ' · syndicated copy' : ''}</span>
      <span class="nw-m-arow-t">${esc(decode(a.title))}</span></button>`).join('');

  el.innerHTML = `<article class="nw-m-st">
    ${head(s)}
    <div class="nw-m-st-meta">${esc(metaLine)}</div>
    <div class="nw-m-st-sum">${sumHtml(s.summary)}</div>
    ${matched.length ? `<p class="nw-m-why">You follow ${matched.map((m) => `<b>${esc(matchName(m, mNames))}</b>`).join(', ')}</p>` : ''}
    ${touches.length ? `<section class="nw-m-sec"><h2 class="nw-m-k">What it touches</h2><div class="nw-m-ents">${touches.map(mChip).join('')}</div></section>` : ''}
    <div class="nw-m-accs">
      ${acc('sources', plural(arts.length, 'article') === plural(outlets.length, 'article') ? plural(outlets.length, 'source') : `${plural(outlets.length, 'source')}, ${plural(arts.length, 'article')}`, esc(outlets.slice(0, 3).join(' · ') + (outlets.length > 3 ? ` +${outlets.length - 3}` : '')), `<div class="nw-m-alist">${sources}</div>`)}
      ${iocs.length ? acc('iocs', 'Indicators', esc(iocSummary(iocs)), `<p class="nw-m-hint">Addresses, domains and file hashes the articles name as signs of an attack. Tap one to see what Night Desk knows about it.</p>
        <div class="nw-m-ents">${iocs.slice(0, 40).map((i) => mChip({ id: i.id, type: i.type, name: i.name })).join('')}</div>
        <button type="button" class="m-btn nw-m-copyall" data-copy-iocs>Copy all ${iocs.length}</button>`) : ''}
      ${ttps.length ? acc('ttps', 'Techniques', esc(ttpCount(ttps)), `<p class="nw-m-hint">How the attackers worked, as MITRE ATT&amp;CK techniques read from the articles. ${esc(TTP_CAVEAT)} Tap a technique to see it.</p>
        ${ttpGroups(ttps, ttpChipPhone, 'nw-m-ents')}`) : ''}
      ${acc('similar', 'Similar stories', '', mSkel(2))}
      <div class="nw-m-notes"></div>
    </div>
  </article>`;
  wireTtpTips();
  el.querySelectorAll('[data-open]').forEach((b) => b.addEventListener('click', () => pushPage(`#news/article/${encodeURIComponent(b.dataset.open)}`)));
  el.querySelector('[data-copy-iocs]')?.addEventListener('click', () => copy(iocs.map((i) => i.name).join('\n'), `Copied ${iocs.length} indicators`));
  wireAcc(el.querySelector('.nw-m-st'), {
    similar: async (box) => {
      if (box.dataset.done) return;
      box.dataset.done = '1';
      let rows = [];
      try {
        const d = lead ? await api.get(`/api/news/articles/${encodeURIComponent(lead.id)}`, { similar: 16 }) : null;
        const seen = new Set([id]);
        for (const r of d?.similar?.results || []) { const sid = r.story_id || `a:${r.id}`; if (seen.has(sid)) continue; seen.add(sid); rows.push(r); if (rows.length >= 6) break; }
      } catch { rows = null; }
      if (!o.alive()) return;
      box.innerHTML = rows == null ? '<p class="nw-m-hint">Couldn\'t load similar stories.</p>' : rows.length ? `<div class="nw-m-alist">${rows.map((r) => `<button type="button" class="nw-m-arow" data-sim="${esc(r.story_id ? `story/${r.story_id}` : `article/${r.id}`)}">
          <span class="nw-m-arow-s">${esc(r.source)} · ${esc(ago(r.published))}</span><span class="nw-m-arow-t">${esc(decode(ctx.storyMeta(r.story_id)?.title || r.title))}</span></button>`).join('')}</div>` : '<p class="nw-m-hint">No similar stories.</p>';
      box.querySelectorAll('[data-sim]').forEach((b) => b.addEventListener('click', () => { const [k, ...v] = b.dataset.sim.split('/'); pushPage(`#news/${k}/${encodeURIComponent(v.join('/'))}`); }));
    },
  });
  const notesOf = notesRow(el, 'story', id, s.title, o);
  const summary = () => storySummary({ s, arts, inds, named, cves: inds.filter((i) => i.type === 'cve'), ttps });
  o.setBar([
    lead ? mBtn('Read lead article', { primary: true, onClick: () => pushPage(`#news/article/${encodeURIComponent(lead.id)}`) }) : null,
    mBtn('Add note', { square: true, icon: MI.note, onClick: () => openNoteSheet({ kind: 'story', id, title: s.title }) }),
    mBtn('Share', { square: true, icon: MI.share, onClick: () => share(s.title, linkTo('story', id)) }),
    moreBtn(() => [
      { label: 'Copy link', run: () => copy(linkTo('story', id), 'Link copied') },
      { label: 'Copy summary', hint: 'Markdown', run: () => openSummary(summary, async () => notesOf?.() || []) },
      ...(lead && safeUrl(lead.url) ? [{ label: `Open ${lead.source}`, hint: 'original site', run: () => window.open(safeUrl(lead.url), '_blank', 'noopener') }] : []),
    ]),
  ]);
  o.after?.();
}

export async function renderArticlePhone(el, id, ctx, o) {
  el.innerHTML = `<article class="nw-m-art">${mSkel(6)}</article>`;
  o.setBar(null);
  let a;
  try { a = await api.get(`/api/news/articles/${encodeURIComponent(id)}`); } catch (e) { if (o.alive()) mErr(el, e, () => renderArticlePhone(el, id, ctx, o)); return; }
  if (!o.alive()) return;
  const title = decode(a.title);
  const ents = a.entities || [];
  ents.forEach((e) => ctx.known.set(e.id, e));
  const sm = ctx.storyMeta(a.story_id);
  if (a.story_id) o.setBack?.({ label: 'Story', href: `#news/story/${encodeURIComponent(a.story_id)}` });
  const named = dedupeByName(ents.filter((e) => !isIoc(entType(e)) && !['technique', 'country', 'sector'].includes(entType(e))));
  const mins = a.text ? Math.max(1, Math.round(a.text.split(/\s+/).length / 230)) : 0;
  const by = [a.author && a.author !== a.source ? `by ${a.author}` : '', fmtDate(a.published), mins ? `${mins} min read` : 'summary only', `${tierLabel(a.tier)} source`].filter(Boolean).join(' · ');
  const body = a.status === 'ok' && a.text
    ? highlight(a.text, ents)
    : `<p class="nw-m-nofull"><b>Full text not stored.</b> ${esc(a.status || '')}${a.reason ? ` · ${esc(a.reason)}` : ''}. Night Desk never works around paywalls or bot checks; the outlet's own summary is shown instead.</p>${a.dek ? `<p>${esc(decode(a.dek))}</p>` : ''}`;
  el.innerHTML = `<article class="nw-m-art">
    <div class="nw-m-art-src">${esc(a.source)}</div>
    <h1 class="nw-m-art-h">${esc(title)}</h1>
    <div class="nw-m-art-by">${esc(by)}</div>
    <div class="nw-m-body">${body}</div>
    ${a.original ? `<p class="nw-m-hint">A copy of an article first published by ${esc(a.original.source)}.</p>` : ''}
    <div class="nw-m-accs">
      ${named.length ? acc('names', 'What it names', esc(plural(named.length, 'name')), `<div class="nw-m-ents">${named.slice(0, 16).map(mChip).join('')}</div>`) : ''}
      ${sm && sm.source_count > 1 ? `<button type="button" class="nw-m-nrow" data-story><span class="nw-m-accl"><span class="nw-m-acct">The whole story</span><span class="nw-m-acc2">${esc(plural(sm.source_count, 'source'))} cover it</span></span></button>` : ''}
      <div class="nw-m-notes"></div>
    </div>
  </article>`;
  el.querySelector('[data-story]')?.addEventListener('click', () => pushPage(`#news/story/${encodeURIComponent(a.story_id)}`));
  wireAcc(el.querySelector('.nw-m-art'));
  notesRow(el, 'article', id, title, o);
  const url = safeUrl(a.url);
  o.setBar([
    url ? mBtn('Open original', { primary: true, href: url }) : mBtn('Copy link', { primary: true, onClick: () => copy(linkTo('article', id), 'Link copied') }),
    mBtn('Add note', { square: true, icon: MI.note, onClick: () => openNoteSheet({ kind: 'article', id, title }) }),
    moreBtn(() => [
      ...(url ? [{ label: 'Copy link', run: () => copy(linkTo('article', id), 'Link copied') }] : []),
      ...(url ? [{ label: 'Share', run: () => share(title, url) }] : []),
      ...(a.story_id ? [{ label: 'Open the story', run: () => pushPage(`#news/story/${encodeURIComponent(a.story_id)}`) }] : []),
    ]),
  ]);
  o.after?.();
}

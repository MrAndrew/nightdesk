// Global search and the ⌘K palette: one box in the top bar, one result model.
//   /      opens it for search: network incidents, devices, stories, articles, entities, CVEs, sources and settings,
//          notes and feed items from GET /api/search (grouped, each group capped with "See all"), then matching
//          app commands (core/commands.js registry) at the bottom.
//   ⌘K     opens the same box with the commands at the top (all of them before you type), then the same groups.
// Every row says why it matched (the field, with the matched words marked). ↑/↓ move across groups, Enter opens,
// Esc closes. Searching navigates; it never filters a view (on Ops an explicit "Filter panels" row offers that).
// The KEYWORD / SEMANTIC badge comes from the response's mode (keyword when the local AI helper is down).
// The route #search?q= (v1.2 mobile, design.md §4.11): on a phone it is a full-screen page (searchRoute(): one
// history entry; typing replaces ?q=; opening a result replaces the search entry with the result, so Back returns to
// where you were before searching; Cancel = Back). On desktop the same route opens today's dropdown with q in it.
// Contract: okf/architecture/web-client.md#global-search
import { api } from './api.js';
import { isPhone } from './mobile.js';
import { pushPage, replaceTo, back } from './page.js';
import { esc, ago, epssText, epssTitle, kindMeta } from './util.js';
import { openDetails, openFull, entityHref, newTab } from './open.js';
import { commands } from './commands.js';

const PER_GROUP = 5;
const CMD_CAP = { search: 3, cmd: 6 };
const KIND = { incident: 'Incident', device: 'Device', story: 'Story', article: 'Article', cve: 'CVE', source: 'Source',
  setting: 'Setting', note: 'Note', event: 'Source item', command: 'Command' };
const ETYPE = { actor: 'Actor', malware: 'Malware', tool: 'Tool', campaign: 'Campaign', cve: 'CVE', ip: 'IP', domain: 'Domain', url: 'URL',
  hash: 'Hash', asn: 'ASN', prefix: 'Prefix', vendor: 'Vendor', product: 'Product', org: 'Org', country: 'Country', sector: 'Sector', technique: 'Technique' };
const STATE = { new: 'Needs a look', ack: 'Seen', dismissed: 'Dismissed', expected: 'Expected' };
const LS_KEY = 'nd.search.recent';
const recent = {
  get() { try { return JSON.parse(localStorage.getItem(LS_KEY)) || []; } catch { return []; } },
  add(q) { try { localStorage.setItem(LS_KEY, JSON.stringify([q, ...recent.get().filter((x) => x !== q)].slice(0, 6))); } catch {} },
};

// Terms are matched in the raw text and each piece is escaped on its own, so a term can never land inside an
// entity of the escaped HTML ('amp' in '&amp;').
function mark(text, q) {
  const s = String(text ?? '');
  const terms = [...new Set(String(q).toLowerCase().split(/[^a-z0-9.:@-]+/).flatMap((t) => [t, ...t.split('-')]).filter((t) => t.length > 1))]
    .sort((a, b) => b.length - a.length);
  if (!terms.length) return esc(s);
  const re = new RegExp(`(${terms.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'gi');
  return s.split(re).map((part, i) => (i % 2 ? `<mark>${esc(part)}</mark>` : esc(part))).join('');
}

// App commands from the ⌘K registry, scored like the palette scores them.
function cmdScore(c, q) {
  if (!q) return 1;
  const hay = `${c.label} ${c.group} ${c.keywords}`.toLowerCase();
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.every((w) => hay.includes(w))) return 0;
  const l = c.label.toLowerCase(), ql = q.trim().toLowerCase();
  // the exact title first, then a label that holds the whole query, then by first word
  if (l === ql) return 6;
  if (l.startsWith(ql)) return 5;
  if (l.includes(ql)) return 4;
  return l.startsWith(words[0]) ? 3 : l.includes(words[0]) ? 2 : 1;
}
function matchCommands(q) {
  return commands().filter((c) => { try { return !c.when || c.when(); } catch { return false; } })
    .map((c) => [c, cmdScore(c, q)]).filter(([, s]) => s > 0)
    .sort((a, b) => b[1] - a[1] || a[0].order - b[0].order || a[0].label.localeCompare(b[0].label))
    .map(([c]) => ({ type: 'command', id: c.id, title: c.label, cmd: c, group: c.group,
      // matched on its label: the marked label says why; matched on other words: show them
      why: q && !q.toLowerCase().split(/\s+/).every((w) => c.label.toLowerCase().includes(w)) ? { field: 'Also called', text: `${c.group} ${c.keywords}`.trim() } : null }));
}

// Incident headlines read exactly as in Network › Alerts (views/net/alert-text.js), loaded on first need.
let alertText = null, alertTextP = null;
const loadAlertText = () => (alertTextP ||= import('../views/net/alert-text.js').then((m) => (alertText = m)).catch(() => null));

// After navigating, bring a heading or card inside the newly shown view into sight and mark it briefly.
function reveal(find, tries = 30) {
  const el = find();
  if (el) {
    el.scrollIntoView({ block: 'start', behavior: 'auto' });
    el.classList.add('search-flash');
    setTimeout(() => el.classList.remove('search-flash'), 1800);
    return;
  }
  if (tries > 0) setTimeout(() => reveal(find, tries - 1), 100);
}

// The full page of a result, when it has one (entities and CVEs through core/open.js's entityHref).
function pageOf(r) {
  if (!r) return null;
  if (r.type === 'entity') return entityHref(r.id);
  if (r.type === 'cve') return entityHref(`cve:${String(r.id).toLowerCase()}`);
  if (r.type === 'event' || r.type === 'command') return null;
  return r.href || null;
}

let closeFn = () => {};
// Close the dropdown (and the expanded phone search box): called on every view change.
export function closeSearch() { closeFn(); }
let openCmdFn = () => {};
let routeFn = () => {};
// The shell calls this when the URL is #search[?q=…] (a tap on search, a link, a reload, Back/Forward).
export function searchRoute() { routeFn(); }
const isSearchHash = (h = location.hash) => /^#\/?search(?:[/?]|$)/i.test(h);
const qOfHash = (h = location.hash) => { const m = String(h).match(/[?&]q=([^&]*)/); try { return m ? decodeURIComponent(m[1].replace(/\+/g, ' ')) : ''; } catch { return m ? m[1] : ''; } };
// Open the box in command mode (⌘K): commands first, then search results.
export function openCommandSearch(prefill = '') { openCmdFn(prefill); }

// On Ops, the dropdown also offers filtering the deck's panels by the typed text: an explicit action, never a
// side effect of typing (store.opsQ; shell.js shows it in the sub-bar and clears it when leaving Ops).
const onOps = () => document.querySelector('.views button.active')?.dataset.view === 'ops';

export function setupSearch({ openEvent, store }) {
  const root = document.getElementById('gs');
  const input = document.getElementById('global-search');
  const drop = document.getElementById('gs-list');
  const box = root.querySelector('.gs-box');
  const badge = root.querySelector('.gs-mode');
  const placeholder = input.getAttribute('placeholder') || 'Search everything…';
  const live = document.createElement('div');
  live.className = 'sr-only'; live.setAttribute('aria-live', 'polite'); root.append(live);

  // mode: 'search' (/) or 'cmd' (⌘K). data: the server's answer for dataQ. expanded: a group shown in full.
  let mode = 'search', data = null, dataQ = null, inflight = null, seq = 0;
  let expanded = null; // { id, label, total, items, q }
  let rows = [], active = -1;
  let shownQ = null; // the query whose results the dropdown lists (Enter must never open another query's hit)
  // the phone search page (#search): on while the route shows; lastPage is the page to return to
  let pageMode = false;
  let lastPage = isSearchHash() ? null : location.hash;
  let cancelBtn = null;
  // Where focus was before the box took it: Esc gives it back there (when it is still on screen).
  let returnTo = null;
  const restoreFocus = () => {
    const t = returnTo; returnTo = null;
    if (t && t !== document.body && t.isConnected && !root.contains(t) && !t.closest('[inert]') && t.getClientRects().length) t.focus({ preventScroll: true });
  };
  // The list is a popup of the input (aria-activedescendant moves through it), never a Tab stop of its own.
  drop.tabIndex = -1;

  // Only while the box has focus: results that arrive after Tab (or a click) took focus elsewhere must not pop the
  // list (or the empty-box hint) back open over the page, e.g. over the Ops deck button.
  const open = () => { if (!root.contains(document.activeElement)) return; drop.hidden = false; box.setAttribute('aria-expanded', 'true'); };
  const close = () => {
    drop.hidden = true; box.setAttribute('aria-expanded', 'false'); active = -1; expanded = null;
    input.removeAttribute('aria-activedescendant');
    if (mode === 'cmd') { mode = 'search'; input.setAttribute('placeholder', placeholder); root.classList.remove('search-cmd'); }
  };
  const collapse = () => {
    if (pageMode) return;
    close(); root.classList.remove('expanded');
    if (isSearchHash()) history.replaceState(history.state, '', homeHash());
  };
  closeFn = () => { if (pageMode) leavePage(); if (!drop.hidden || root.classList.contains('expanded')) { collapse(); if (document.activeElement === input) input.blur(); } };

  // ------------------------------------------------------------ rows
  function meta(r) {
    const m = [];
    if (r.type === 'incident') {
      m.push(`<b class="search-sev search-sev-${esc(r.severity)}">${esc(r.severity)}</b>`);
      m.push(esc(STATE[r.state] || r.state));
      if (r.demo) m.push('<span class="search-demo">demo</span>');
      if (r.last_ts) m.push(esc(ago(r.last_ts)));
    } else if (r.type === 'device') {
      if (r.last_seen) m.push(`seen ${esc(ago(r.last_seen))}`);
    } else if (r.type === 'cve') {
      if (r.kev) m.push('<b class="gs-kev">KEV</b>');
      if (r.cvss != null) m.push(`CVSS ${esc(r.cvss)}`);
      if (r.epss != null) m.push(`<span title="${esc(epssTitle(r.epss, r.epss_percentile))}">EPSS ${esc(epssText(r.epss))}</span>`);
    } else if (r.type === 'article' || r.type === 'event') {
      if (r.source) m.push(esc(r.source));
      if (r.ts) m.push(esc(ago(r.ts)));
    } else if (r.type === 'story' || r.type === 'note') {
      if (r.ts) m.push(esc(ago(r.ts)));
    }
    return m.join(' · ');
  }
  function kindLabel(r) {
    if (r.type === 'entity') { const t = r.entity_type || String(r.id).split(':')[0]; return ETYPE[t] || t; }
    if (r.type === 'event') return r.kind ? kindMeta(r.kind).label : KIND.event;
    if (r.type === 'command') return r.group || KIND.command;
    return KIND[r.type] || r.type;
  }
  function titleOf(r) {
    if (r.type === 'incident' && alertText && alertText.headline) {
      try { return alertText.headline(r).text; } catch { /* fall back to the stored title */ }
    }
    // a note on an incident reads with the incident's title as it is now (a renamed device shows its new name)
    if (r.type === 'note' && r.incident && alertText && alertText.headline) {
      try { return alertText.headline(r.incident).text; } catch { /* the server's current title */ }
    }
    return r.title || r.id;
  }
  function itemHtml(r, i, q0) {
    const t = titleOf(r);
    const q = r.fuzzy && r.why?.near ? r.why.near : q0;   // a close match marks the spelling it was found by
    // the field that matched, with its words marked; when that field is the title itself, the marked title already
    // shows the words, so the line names the field and adds the row's details instead of repeating it
    const same = r.why && String(r.why.text).trim().toLowerCase() === String(t).trim().toLowerCase();
    const why = r.why && r.why.text ? `<div class="gs-s search-why"><b>${esc(r.why.field)}</b> ${same ? esc(r.sub || '') : mark(String(r.why.text).length > 180 ? String(r.why.text).slice(0, 178) + '…' : r.why.text, q)}</div>`
      : r.sub ? `<div class="gs-s">${esc(r.sub)}</div>` : '';
    const idTag = r.type === 'cve' ? `<span class="mono gs-id">${esc(r.id)}</span> ` : '';
    // a row with a page of its own is a real link, so Cmd/Ctrl/Shift-click and middle-click open it in a new tab
    const href = pageOf(r);
    const tag = href ? 'a' : 'div';
    return `<${tag} class="gs-item search-${esc(r.type)}" role="option" id="gs-o${i}" data-i="${i}" aria-selected="false"${href ? ` href="${esc(href)}"` : ''}>
      <span class="gs-k mono">${esc(kindLabel(r))}</span>
      <div class="gs-main"><div class="gs-t">${idTag}${mark(t, q)}</div>${why}</div>
      <span class="gs-m mono">${meta(r)}</span>
    </${tag}>`;
  }
  const actionHtml = (i, cls, k, t, s = '') => `<div class="gs-item gs-act ${cls}" role="option" id="gs-o${i}" data-i="${i}" aria-selected="false">
      <span class="gs-k mono">${k}</span><div class="gs-main"><div class="gs-t">${t}</div>${s ? `<div class="gs-s">${s}</div>` : ''}</div></div>`;

  function groupHtml(label, count, items, q, more) {
    let html = `<div class="gs-g" role="group" aria-label="${esc(label)}"><div class="gs-gh mono">${esc(label)}<span>${count}</span></div>`;
    for (const it of items) { html += itemHtml(it, rows.length, q); rows.push({ kind: 'item', item: it }); }
    if (more) { html += actionHtml(rows.length, 'search-more', '›', `See all ${esc(more.total)} ${esc(more.label.toLowerCase())}`); rows.push({ kind: 'more', group: more }); }
    return html + '</div>';
  }

  // ------------------------------------------------------------ painting
  function paintBadge(res) {
    const any = res && res.groups && res.groups.length;
    const semantic = res?.mode && res.mode !== 'keyword';
    badge.hidden = !any;
    badge.textContent = semantic ? 'SEMANTIC' : 'KEYWORD';
    badge.className = `gs-mode mono ${semantic ? 'sem' : 'kw'}`;
    badge.title = semantic ? 'Ranked by meaning (local embeddings) and keywords' : 'Keyword ranking: the optional local AI helper is not running';
  }
  const foot = (semantic) => `<div class="gs-foot mono"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span><span class="gs-foot-m">${mode === 'cmd' ? '<kbd>⌘K</kbd> close' : '<kbd>⌘K</kbd> commands first'} · ${semantic ? 'meaning + keywords' : 'keywords only'}</span></div>`;

  function paint(q) {
    rows = []; active = -1;
    let html = '';
    const cmds = matchCommands(q);
    const cmdGroup = (cap) => (cmds.length ? groupHtml('Commands', cmds.length > cap ? `${cap} of ${cmds.length}` : cmds.length, cmds.slice(0, cap), q,
      cmds.length > cap ? { id: 'command', label: 'Commands', total: cmds.length } : null) : '');
    if (expanded) {
      html += actionHtml(rows.length, 'search-back', '‹', 'All results'); rows.push({ kind: 'back' });
      const items = expanded.id === 'command' ? cmds : expanded.items;
      html += groupHtml(`All ${expanded.label}`, items.length < expanded.total ? `${items.length} of ${expanded.total}` : items.length, items, q, null);
      shownQ = q;
    } else if (q.length < 2) {
      // idle: ⌘K lists every command; / shows recent searches
      if (mode === 'cmd') { html += cmdGroup(99); shownQ = q; }
      else {
        const rec = recent.get();
        html += `<div class="gs-state"><b>Search everything</b><span>Network incidents, devices, news, entities, CVEs, sources and settings, notes and commands. <span class="search-hint-keys">Press <kbd class="mono">⌘K</kbd> for commands first.</span><span class="search-hint-touch">Tap to search, then tap a result to open it.</span></span></div>`;
        if (rec.length) {
          html += '<div class="gs-g" role="group" aria-label="Recent searches"><div class="gs-gh mono">Recent</div>';
          for (const r of rec) { html += actionHtml(rows.length, 'gs-rec', '↺', esc(r)); rows.push({ kind: 'recent', q: r }); }
          html += '</div>';
        }
        shownQ = null;
      }
    } else {
      const res = dataQ === q ? data : null;
      if (mode === 'cmd') html += cmdGroup(CMD_CAP.cmd);
      if (!res) html += `<div class="gs-state"><div class="gs-load" aria-label="Searching"><i></i><i></i><i></i></div></div>`;
      else {
        const short = (x) => (x.length > 60 ? `${x.slice(0, 58)}…` : x);
        if (res.corrected) {
          const anyExact = res.groups.some((g) => g.items.some((i) => !i.fuzzy));
          html += `<div class="gs-state search-near"><span>${anyExact ? `Close matches for “<b>${esc(res.corrected)}</b>” follow the exact ones.`
            : `No exact matches for “${esc(short(q))}”. Showing close matches for “<b>${esc(res.corrected)}</b>”.`}</span></div>`;
        }
        for (const g of res.groups) {
          if (!g.items.length) continue;
          html += groupHtml(g.label, g.more ? `${g.items.length} of ${g.total}` : g.items.length, g.items, q, g.more ? g : null);
        }
        if (mode === 'search') html += cmdGroup(CMD_CAP.search);
        if (res.warming) html += `<div class="gs-state search-warming"><span>Still getting ready after the start: ${esc(res.groups.filter((g) => g.warming).map((g) => g.label).join(', '))}. They appear here in a few seconds.</span></div>`;
        if (!rows.length && !res.warming) html += `<div class="gs-state"><b>No matches for “${esc(short(q))}”</b><span>Try other words, part of a name, or an address. Search covers network incidents, devices, news, entities, CVEs, sources and settings, notes and commands.</span></div>`;
        else if (res.groups.some((g) => g.error)) html += `<div class="gs-state"><span>Some kinds of result could not be searched just now: ${esc(res.groups.filter((g) => g.error).map((g) => g.label).join(', '))}.</span></div>`;
        shownQ = q;
      }
      if (onOps() && q) { html += actionHtml(rows.length, 'states-gs-filter', 'Filter', `Filter panels by “${esc(q)}”`, 'Show only matching rows in the Ops panels, until you clear it or leave Ops.'); rows.push({ kind: 'filter' }); }
      if (res) {
        const n = rows.filter((r) => r.kind === 'item').length;
        live.textContent = n ? `${n} results shown` : `No matches for ${q}`;
      }
    }
    html += foot(data?.mode && data.mode !== 'keyword');
    if (pageMode && q.length >= 2 && dataQ === q && data) {
      const n = (data.groups || []).reduce((a, g) => a + (g.total ?? g.items.length), 0);
      html = `<p class="gs-sum mono">${n} result${n === 1 ? '' : 's'} · ${data.mode && data.mode !== 'keyword' ? 'meaning + keywords' : 'keyword match (offline)'}</p>${html}`;
    }
    drop.innerHTML = html;
    paintBadge(q.length >= 2 && dataQ === q ? data : null);
    open();
  }

  // ------------------------------------------------------------ fetching
  function run(q) {
    if (q === dataQ && data) { paint(q); return Promise.resolve(); }
    if (inflight && inflight.q === q) return inflight.p; // already searching this query: wait for that answer
    const my = ++seq;
    data = null; dataQ = null; expanded = null;
    paint(q);
    const p = (async () => {
      try {
        const [res] = await Promise.all([api.get('/api/search', { q, per: PER_GROUP }), loadAlertText()]);
        if (my !== seq) return;
        data = res; dataQ = q;
        paint(q);
        if (res.warming) setTimeout(() => refresh(q, my, 1), 2000);
      } catch (e) {
        if (my !== seq) return;
        rows = []; shownQ = null;
        badge.hidden = true;
        drop.innerHTML = `<div class="gs-state err"><b>Search failed</b><span>${esc(e.message)}</span></div>`;
        open();
      } finally {
        if (inflight?.p === p) inflight = null;
      }
    })();
    inflight = { q, p };
    return p;
  }
  // Groups still warming up after a start: ask again quietly until they answer (the shown rows stay put).
  async function refresh(q, my, n) {
    if (my !== seq || dataQ !== q || drop.hidden || expanded) return;
    try {
      const res = await api.get('/api/search', { q, per: PER_GROUP });
      if (my !== seq || dataQ !== q || drop.hidden || expanded) return;
      const was = active;
      data = res;
      paint(q);
      if (was >= 0) setActive(was);
      if (res.warming && n < 15) setTimeout(() => refresh(q, my, n + 1), 2000);
    } catch { /* the rows shown stay */ }
  }
  let soonT = null;
  const runSoon = (q) => { clearTimeout(soonT); soonT = setTimeout(() => run(q), 180); };

  async function expand(g) {
    const q = input.value.trim();
    if (g.id === 'command') { expanded = { id: 'command', label: 'Commands', total: g.total, items: [] }; paint(q); setActive(1); return; }
    const my = ++seq;
    try {
      const res = await api.get('/api/search', { q, per: 50, groups: g.id });
      if (my !== seq || input.value.trim() !== q) return;
      const full = res.groups.find((x) => x.id === g.id) || { ...g };
      expanded = { id: g.id, label: g.label, total: full.total, items: full.items };
      paint(q);
      setActive(1);
    } catch (e) { live.textContent = `Could not load all ${g.label}: ${e.message}`; }
  }

  function setActive(i) {
    const els = drop.querySelectorAll('.gs-item');
    if (!els.length) return;
    active = (i + els.length) % els.length;
    els.forEach((el, j) => { el.classList.toggle('on', j === active); el.setAttribute('aria-selected', j === active ? 'true' : 'false'); });
    els[active].scrollIntoView({ block: 'nearest' });
    input.setAttribute('aria-activedescendant', els[active].id || '');
  }

  // ------------------------------------------------------------ opening a result
  // core/open.js: a click opens Details (the side panel) where there is one, else the page; Cmd/Ctrl/Shift or the
  // middle button opens the page in a new tab
  function openItem(r, ev) {
    if (newTab(ev) && pageOf(r)) { openFull(pageOf(r), ev); return; }
    switch (r.type) {
      case 'command': try { r.cmd.run(); } catch (e) { console.error(e); } break;
      case 'entity': openDetails(r.id, ev); break;
      case 'cve': openDetails(`cve:${String(r.id).toLowerCase()}`, ev); break;
      case 'event': openEvent(r.id); break;
      case 'setting':
        location.hash = r.href;
        if (r.anchor) reveal(() => [...document.querySelectorAll('.set-sec:not([hidden]) .set-h3')].find((h) => h.textContent.trim().toLowerCase().startsWith(r.anchor.toLowerCase())));
        break;
      case 'source':
        location.hash = r.href;
        reveal(() => document.querySelector(`.set-sec:not([hidden]) .src-card[data-id="${CSS.escape(r.target || r.id)}"]`));
        break;
      default: if (r.href) openFull(r.href, ev);
    }
  }

  function choose(el, ev) {
    if (!el) return;
    const row = rows[+el.dataset.i];
    if (!row) return;
    if (row.kind === 'recent') { input.value = row.q; root.classList.add('has-q'); run(row.q); input.focus(); return; }
    if (row.kind === 'more') { expand(row.group); return; }
    if (row.kind === 'back') { expanded = null; paint(input.value.trim()); setActive(0); return; }
    if (row.kind === 'filter') {
      const q = input.value.trim();
      if (q) { recent.add(q); store.set({ opsQ: q }); }
      collapse(); input.blur();
      return;
    }
    const r = row.item;
    if (shownQ && r.type !== 'command') recent.add(shownQ); // the query that produced the opened hit, not whatever is typed now
    if (pageMode) { openFromPage(r); return; }
    collapse(); input.blur();
    openItem(r, ev);
  }

  // ------------------------------------------------------------ events
  input.addEventListener('input', () => {
    const q = input.value.trim();
    root.classList.toggle('has-q', !!q);
    if (pageMode) syncQ(q);
    expanded = null;
    if (q.length < 2) { clearTimeout(soonT); seq++; inflight = null; paint(q); if (mode === 'cmd' && rows.length) setActive(0); return; }
    if (mode === 'cmd') { paint(q); if (rows.length) setActive(0); }   // commands answer at once; results follow
    runSoon(q);
  });
  input.addEventListener('focus', (e) => {
    if (!e.relatedTarget || !root.contains(e.relatedTarget)) returnTo = e.relatedTarget || null;
    root.classList.add('focus');
    input.select();   // typing replaces the last query; arrows or End keep it
    const q = input.value.trim();
    if (q.length >= 2) run(q); else paint(q);
  });
  input.addEventListener('blur', () => root.classList.remove('focus'));
  root.addEventListener('focusout', (e) => {
    const to = e.relatedTarget;
    if (to && !root.contains(to) && !drop.hidden) collapse();
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); if (drop.hidden) open(); setActive(active + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(active - 1); }
    else if (e.key === 'Home' && !drop.hidden && active >= 0) { e.preventDefault(); setActive(0); }
    else if (e.key === 'End' && !drop.hidden && active >= 0) { e.preventDefault(); setActive(-1); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const q = input.value.trim();
      const els = drop.querySelectorAll('.gs-item');
      if (active >= 0 && els[active]) { choose(els[active], e); return; }
      if (q.length >= 2 && shownQ !== q) {
        // typed faster than the debounce: search this query now and open its top hit, never the previous query's
        clearTimeout(soonT);
        const mods = { shiftKey: e.shiftKey, metaKey: e.metaKey, ctrlKey: e.ctrlKey };
        run(q).then(() => { if (shownQ === q && input.value.trim() === q && document.activeElement === input) choose(firstHit(), mods); });
        return;
      }
      choose(firstHit(), e);   // Enter with nothing highlighted opens the top hit, never "Filter panels" or "See all"
    } else if (e.key === 'Escape') {
      e.preventDefault(); e.stopPropagation();
      if (pageMode) { cancel(); return; }
      if (!drop.hidden) { close(); input.blur(); collapse(); } else { input.blur(); collapse(); }
      restoreFocus();
    } else if (e.key === 'Tab' && !drop.hidden && !pageMode) {
      // Tab leaves the box: the list closes rather than staying open over the page while focus walks the top bar.
      // (↑/↓ move through the results; Tab moves on, as in any combobox.)
      collapse();
      returnTo = null;
    }
  });
  const firstHit = () => { const i = rows.findIndex((r) => r.kind === 'item' || r.kind === 'recent'); return i >= 0 ? drop.querySelector(`#gs-o${i}`) : null; };
  drop.addEventListener('mousemove', (e) => {
    const el = e.target.closest('.gs-item');
    if (el) { const i = [...drop.querySelectorAll('.gs-item')].indexOf(el); if (i !== active) setActive(i); }
  });
  drop.addEventListener('mousedown', (e) => e.preventDefault());   // keep focus in the input
  drop.addEventListener('click', (e) => {
    const el = e.target.closest('.gs-item');
    if (!el) return;
    // a modified click on a real link: the browser opens it in a new tab; just close the dropdown
    if (el.tagName === 'A' && newTab(e)) { collapse(); input.blur(); return; }
    e.preventDefault();
    choose(el, e);
  });
  // middle click fires auxclick: real links open natively, other rows are opened here (entities in a new tab)
  drop.addEventListener('auxclick', (e) => {
    const el = e.target.closest('.gs-item');
    if (e.button !== 1 || !el) return;
    if (el.tagName === 'A') { collapse(); return; }
    e.preventDefault(); choose(el, e);
  });
  document.addEventListener('pointerdown', (e) => { if (!root.contains(e.target)) collapse(); });
  root.querySelector('.gs-open').addEventListener('click', () => {
    if (isPhone()) { if (!isSearchHash()) pushPage('#search'); else input.focus(); return; }
    root.classList.add('expanded'); input.focus();
  });
  root.querySelector('.gs-x').addEventListener('click', () => {
    if (pageMode) { input.value = ''; root.classList.remove('has-q'); expanded = null; seq++; inflight = null; syncQ(''); paint(''); input.focus(); return; }
    input.blur(); collapse();
  });

  // ------------------------------------------------------------ #search: the phone page, or the desktop dropdown
  function syncQ(q) {
    clearTimeout(syncQ.t);
    syncQ.t = setTimeout(() => {
      if (!pageMode || !isSearchHash()) return;
      const want = q ? `#search?q=${encodeURIComponent(q)}` : '#search';
      if (location.hash !== want) history.replaceState(history.state, '', want);
    }, 250);
  }
  const homeHash = () => (lastPage && !isSearchHash(lastPage) ? lastPage : `#${document.body.dataset.view || 'watch'}`);
  function enterPage(q) {
    if (!pageMode) {
      pageMode = true;
      document.body.classList.add('m-search');
      root.classList.add('expanded', 'gs-page');
      drop.classList.add('gs-page-list');
      document.querySelector('.topbar')?.after(drop);   // the results flow in the page under the sticky search row
      if (!cancelBtn) {
        cancelBtn = Object.assign(document.createElement('button'), { type: 'button', className: 'gs-cancel', textContent: 'Cancel' });
        cancelBtn.addEventListener('click', () => cancel());
      }
      root.append(cancelBtn);
      root.querySelector('.gs-x')?.setAttribute('aria-label', 'Clear the search');
    }
    if (input.value.trim() !== q) input.value = q;
    root.classList.toggle('has-q', !!q);
    expanded = null;
    if (document.activeElement !== input) input.focus({ preventScroll: true });
    else if (q.length >= 2) run(q); else paint(q);
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
  }
  function leavePage() {
    if (!pageMode) return;
    pageMode = false;
    clearTimeout(syncQ.t);
    document.body.classList.remove('m-search');
    root.classList.remove('gs-page', 'has-q', 'expanded');
    drop.classList.remove('gs-page-list');
    box.after(drop);
    cancelBtn?.remove();
    root.querySelector('.gs-x')?.setAttribute('aria-label', 'Close search');
    close();
    if (document.activeElement === input) input.blur();
  }
  // Cancel: back to the page under the search (one Back, never out of the app)
  function cancel() { back(homeHash()); }
  // A result replaces the search entry: Back from it returns to the page before the search.
  function openFromPage(r) {
    const target = r.type === 'setting' || r.type === 'source' ? r.href : pageOf(r);
    const after = () => {
      if (r.type === 'command') { try { r.cmd.run(); } catch (e) { console.error(e); } }
      else if (r.type === 'event') openEvent(r.id);
      else if (r.type === 'setting' && r.anchor) reveal(() => [...document.querySelectorAll('.set-sec:not([hidden]) .set-h3')].find((h) => h.textContent.trim().toLowerCase().startsWith(r.anchor.toLowerCase())));
      else if (r.type === 'source') reveal(() => document.querySelector(`.set-sec:not([hidden]) .src-card[data-id="${CSS.escape(r.target || r.id)}"]`));
    };
    input.blur();
    if (target) { replaceTo(target); setTimeout(after, 60); return; }
    // no page of its own (a source item, a command): back to the page under the search, then do it there
    back(homeHash());
    setTimeout(after, 120);
  }
  routeFn = () => {
    const q = qOfHash();
    if (isPhone()) { enterPage(q); return; }
    // desktop: today's dropdown, with the query in it; the address goes back to the page underneath once it closes
    root.classList.add('expanded');
    input.value = q;
    root.classList.toggle('has-q', !!q);
    input.focus();
    if (q.length >= 2) run(q); else paint(q);
  };
  window.addEventListener('hashchange', () => {
    if (isSearchHash()) return;
    lastPage = location.hash;
    if (pageMode) leavePage();
  });

  // ⌘K / Ctrl+K: the same box, commands first. Captured before the palette's own listener (core/commands.js), so
  // there is one result model; the palette's registry still supplies the commands.
  openCmdFn = (prefill = '') => {
    if (document.activeElement && document.activeElement !== input && !root.contains(document.activeElement)) returnTo = document.activeElement;
    mode = 'cmd'; expanded = null;
    root.classList.add('expanded', 'search-cmd');
    input.setAttribute('placeholder', 'Type a command or search…');
    input.value = prefill;   // like the palette it replaces, ⌘K starts empty: every command, then type to narrow
    root.classList.toggle('has-q', !!input.value.trim());
    if (document.activeElement !== input) input.focus(); // focus paints, in command mode
    const q = input.value.trim();
    if (q.length >= 2) run(q); else paint(q);
    if (rows.length) setActive(0);
  };
  window.addEventListener('keydown', (e) => {
    if (!((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'k')) return;
    if (document.querySelector('.tour-root') || document.body.classList.contains('shell-kiosk')) return;
    e.preventDefault(); e.stopImmediatePropagation();
    // a phone sheet is open: the page under it (the search box too) is inert, so nothing opens behind the sheet
    if (document.querySelector('.m-sheet-root')) return;
    if (mode === 'cmd' && !drop.hidden) { collapse(); input.blur(); restoreFocus(); return; }
    openCmdFn();
  }, true);
}

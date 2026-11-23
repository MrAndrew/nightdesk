// Notes on anything: incidents, entities, news stories and articles, kept on the Night Desk server
// (GET/POST/PUT/DELETE /api/notes). One shared component, mounted with one line where an item is shown:
//   mountNotes(container, { kind, item, title, at, cls, actions, summary })
// It also puts a note-count badge on list rows (incidents, stories, articles, entities), owns the #notes view
// (every note, searchable) and moves the old browser-only article notes to the server once.
// Contract: okf/architecture/notes.md
import { api } from './api.js';
import * as T from './time.js';
import { esc, ago, toast, debounce, isTyping } from './util.js';
import { registerView } from './panels.js';
import { registerCommand } from './commands.js';
import { openSummary } from './summary.js';
import { viewHeader, emptyState, errorState, loadingState, stateAct } from './view.js';
import { isPhone, onPhoneChange } from './mobile.js';

export const KIND_LABEL = { incident: 'Network incident', entity: 'Entity', story: 'News story', article: 'Article' };
const KIND_SHORT = { incident: 'Incidents', entity: 'Entities', story: 'Stories', article: 'Articles' };
const ICON = '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3.5h8.5L19 8v12.5H6z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M14 3.5V8h4.5M9 12h7M9 15.5h7" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>';
const LEGACY = 'nd.news.notes';   // the v1.0 article notes, "saved in this browser"
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const when = (t) => T.full(t);

// ------------------------------------------------------------------ counts and change events
let counts = null;
let countsP = null;
const subs = new Set();
export function onNotesChange(fn) { subs.add(fn); return () => subs.delete(fn); }
function changed(kind, item) { counts = null; loadCounts(); subs.forEach((fn) => { try { fn(kind, item); } catch (e) { console.error(e); } }); }
export function loadCounts() {
  if (counts) return Promise.resolve(counts);
  return (countsP ||= api.get('/api/notes/counts').then((c) => { counts = c; countsP = null; scheduleBadges(); return c; })
    .catch(() => { countsP = null; return null; }));
}
export const noteCount = (kind, item) => counts?.[kind]?.[item] || 0;

// ------------------------------------------------------------------ badges on list rows
// Rows other views render; the badge goes into the given slot (the row itself when there is none).
const ROWS = [
  { sel: '.nv-arow[data-id]', kind: 'incident', key: (r) => r.dataset.id, slot: '.al-line' },
  { sel: '.nw-card[data-sid]', kind: 'story', key: (r) => r.dataset.sid, slot: '.nw-cmeta' },
  { sel: '.nw-drow[data-sid]', kind: 'story', key: (r) => r.dataset.sid, slot: '.nw-dmeta' },
  { sel: '.nw-res[data-aid]', kind: 'article', key: (r) => r.dataset.aid, slot: '.nw-cmeta' },
  { sel: 'a.en-row[data-entity]', kind: 'entity', key: (r) => r.dataset.entity, slot: '.en-nmt > b', after: true },
];
function paintBadges() {
  if (!counts) return;
  for (const R of ROWS) {
    for (const row of document.querySelectorAll(R.sel)) {
      const n = noteCount(R.kind, R.key(row));
      let b = row.querySelector(':scope .notes-badge');
      if (!n) { b?.remove(); continue; }
      const label = plural(n, 'note');
      if (b) { if (b.dataset.n !== String(n)) { b.dataset.n = n; b.lastChild.textContent = n; b.title = label; b.setAttribute('aria-label', label); } continue; }
      b = document.createElement('span');
      b.className = 'notes-badge';
      b.dataset.n = n; b.title = label; b.setAttribute('aria-label', label); b.setAttribute('role', 'img');
      b.innerHTML = `${ICON}<span>${n}</span>`;
      const slot = (R.slot && row.querySelector(R.slot)) || row;
      if (R.after && slot !== row) slot.after(b); else slot.append(b);
    }
  }
}
let badgeQueued = false;
function scheduleBadges() {
  if (badgeQueued) return;
  badgeQueued = true;
  requestAnimationFrame(() => { badgeQueued = false; paintBadges(); });
}
function watchLists() {
  const main = document.getElementById('views') || document.body;
  new MutationObserver((recs) => {
    // ignore our own badge insertions
    if (recs.every((r) => [...r.addedNodes, ...r.removedNodes].every((n) => n.nodeType !== 1 || n.classList?.contains('notes-badge')))) return;
    scheduleBadges();
  }).observe(main, { childList: true, subtree: true });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { counts = null; loadCounts(); } });
  loadCounts();
}

// ------------------------------------------------------------------ the shared component
/**
 * Mount the notes block for one item inside `host`.
 *   kind: 'incident' | 'entity' | 'story' | 'article';  item: its id;  title: its title (shown in the Notes list)
 *   before: a selector inside host to insert before;  at: 'prepend' | a selector to insert after | (default) append
 *   cls: extra classes for the block (e.g. the host's card class)
 *   actions: a button row (an element, or a selector inside host) that gets the "Copy summary" button; without
 *            one the button sits in the notes header
 *   summary: () => summary object (core/summary.js), or a Promise of one; omitted: no Copy summary
 */
export function mountNotes(host, o = {}) {
  if (!host || !o.kind || !o.item) return null;
  host.querySelectorAll(':scope .notes-blk').forEach((x) => x.remove());
  const sec = document.createElement('section');
  sec.className = `notes-blk ${o.cls || ''}`.trim();
  sec.dataset.kind = o.kind; sec.dataset.item = o.item;
  const before = o.before ? host.querySelector(o.before) : null;
  const ref = typeof o.at === 'string' && o.at !== 'prepend' ? host.querySelector(o.at) : null;
  if (before) before.before(sec); else if (ref) ref.after(sec); else if (o.at === 'prepend') host.prepend(sec); else host.append(sec);
  const S = { notes: null, editing: null, confirm: null, err: null };
  const fetchNotes = () => api.get('/api/notes', { kind: o.kind, item: o.item }).then((r) => r.notes);

  if (o.summary) {
    const row = typeof o.actions === 'string' ? host.querySelector(o.actions) : o.actions || null;
    const btn = document.createElement('button');
    btn.className = 'src-btn notes-sumbtn';
    btn.type = 'button';
    btn.title = 'Copy this as Markdown for a forum post, report or issue (your network redacted by default)';
    btn.innerHTML = `${ICON}Copy summary`;
    btn.onclick = () => openSummary(o.summary, () => (S.notes ? Promise.resolve(S.notes) : fetchNotes()));
    if (row) { row.querySelector(':scope > .notes-sumbtn')?.remove(); row.append(btn); }
    else sec.dataset.sum = '1';
    S.sumBtn = row ? null : btn;
  }

  async function load() {
    try { S.notes = await fetchNotes(); S.err = null; } catch (e) { S.err = e.message; }
    if (sec.isConnected) render();
  }
  function item(n) {
    if (S.editing === n.id) {
      return `<li class="notes-it editing" data-id="${esc(n.id)}"><textarea class="notes-ta" rows="4" aria-label="Edit note" maxlength="10000">${esc(n.body)}</textarea>
        <div class="notes-row"><button class="src-btn primary sm" data-a="save">Save</button><button class="src-btn sm" data-a="cancel">Cancel</button><span class="notes-hint">Ctrl+Enter saves · Esc cancels</span></div></li>`;
    }
    const edited = n.updated_at && n.updated_at !== n.created_at;
    return `<li class="notes-it" data-id="${esc(n.id)}">
      <div class="notes-meta mono"><span title="${esc(when(n.created_at))}">${esc(ago(n.created_at))}</span>${edited ? ` · <span title="${esc(when(n.updated_at))}">edited ${esc(ago(n.updated_at))}</span>` : ''}
        <span class="notes-acts">${S.confirm === n.id
          ? '<span class="notes-q">Delete this note?</span><button class="src-btn sm danger" data-a="del-yes">Delete</button><button class="src-btn sm" data-a="del-no">Keep</button>'
          : '<button class="notes-lnk" data-a="edit">Edit</button><button class="notes-lnk" data-a="del">Delete</button>'}</span></div>
      <div class="notes-body">${n.html}</div></li>`;
  }
  function render() {
    const ns = S.notes || [];
    const draft = sec.querySelector('.notes-add textarea')?.value || '';
    sec.innerHTML = `
      <div class="notes-head"><h3>Notes</h3>${ns.length ? `<span class="notes-n mono">${ns.length}</span>` : ''}<span class="notes-sp"></span>
        <a class="notes-all" href="#notes">All notes ›</a></div>
      ${S.err ? errorState({ retry: load, title: "Couldn't read the notes here", why: 'The Night Desk server did not answer.', err: S.err, size: 'inline' }) : ''}
      ${ns.length ? `<ol class="notes-list">${ns.map(item).join('')}</ol>` : S.notes ? emptyState({ why: 'No notes yet. Write down what you checked, what you decided, or what to look at next.', size: 'inline' }) : ''}
      <form class="notes-add">
        <textarea class="notes-ta" rows="2" maxlength="10000" placeholder="Add a note…" aria-label="Add a note">${esc(draft)}</textarea>
        <div class="notes-row"><button class="src-btn primary sm" type="submit">Add note</button>
          <span class="notes-hint">Saved on your Night Desk server · **bold**, *italic*, - lists, [link](https://…)</span></div>
      </form>`;
    if (S.sumBtn) sec.querySelector('.notes-head .notes-sp').after(S.sumBtn);
    const ed = sec.querySelector('.notes-it.editing textarea');
    if (ed) { ed.focus(); ed.setSelectionRange(ed.value.length, ed.value.length); }
  }
  async function add(ta) {
    const body = ta.value.trim();
    if (!body) { ta.focus(); return; }
    const btn = sec.querySelector('.notes-add [type="submit"]');
    btn.disabled = true;
    try {
      await api.post('/api/notes', { kind: o.kind, item: o.item, body, title: o.title || '' });
      ta.value = '';
      await load();
      changed(o.kind, o.item);
      sec.querySelector('.notes-add textarea')?.focus();
    } catch (e) { toast(`Could not save the note: ${e.message}`, true); btn.disabled = false; }
  }
  async function save(id) {
    const ta = sec.querySelector(`.notes-it[data-id="${CSS.escape(id)}"] textarea`);
    const body = ta?.value.trim();
    if (!body) { toast('A note cannot be empty. Use Delete to remove it.', true); return; }
    try { await api.put(`/api/notes/${encodeURIComponent(id)}`, { body }); S.editing = null; await load(); changed(o.kind, o.item); }
    catch (e) { toast(`Could not save the note: ${e.message}`, true); }
  }
  async function del(id) {
    try { await api.del(`/api/notes/${encodeURIComponent(id)}`); S.confirm = null; await load(); changed(o.kind, o.item); toast('Note deleted'); }
    catch (e) { toast(`Could not delete the note: ${e.message}`, true); }
  }
  sec.addEventListener('submit', (e) => { e.preventDefault(); add(sec.querySelector('.notes-add textarea')); });
  sec.addEventListener('click', (e) => {
    const b = e.target.closest('[data-a]'); if (!b) return;
    const id = b.closest('.notes-it')?.dataset.id;
    const a = b.dataset.a;
    if (a === 'edit') { S.editing = id; S.confirm = null; render(); }
    else if (a === 'cancel') { S.editing = null; render(); }
    else if (a === 'save') save(id);
    else if (a === 'del') { S.confirm = id; render(); sec.querySelector('[data-a="del-no"]')?.focus(); }
    else if (a === 'del-no') { S.confirm = null; render(); }
    else if (a === 'del-yes') del(id);
  });
  sec.addEventListener('keydown', (e) => {
    e.stopPropagation();   // typing here never reaches the view's single-key shortcuts
    const ta = e.target.closest('textarea'); if (!ta) return;
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); if (ta.closest('.notes-add')) add(ta); else save(ta.closest('.notes-it').dataset.id); }
    if (e.key === 'Escape' && ta.closest('.editing')) { e.preventDefault(); S.editing = null; render(); }
  });
  render();
  load();
  return sec;
}

// ------------------------------------------------------------------ one-time move of the browser notes
export async function migrateLegacy() {
  let raw;
  try { raw = localStorage.getItem(LEGACY); } catch { return null; }
  if (raw == null) return null;
  let map = {};
  try { map = JSON.parse(raw) || {}; } catch { map = {}; }
  const notes = Object.entries(map).filter(([k, v]) => k && typeof v === 'string' && v.trim()).map(([item, body]) => ({ kind: 'article', item, body }));
  if (!notes.length) { try { localStorage.removeItem(LEGACY); } catch {} return { imported: 0, skipped: 0 }; }
  try {
    const r = await api.post('/api/notes/import', { notes });
    try { localStorage.removeItem(LEGACY); } catch {}
    if (r.imported) { changed('article'); toast(`Moved ${plural(r.imported, 'article note')} from this browser to your Night Desk server`); }
    return r;
  } catch (e) { console.warn('notes: browser notes not moved yet:', e.message); return null; }   // kept; tried again next load
}

// ------------------------------------------------------------------ the Notes view (#notes)
/** Open the list of all notes (also the ⌘K command NOTES_COMMAND, registered below). */
export function openNotes(q = '') { location.hash = q ? `#notes/${encodeURIComponent(q)}` : '#notes'; }
export const NOTES_COMMAND = { id: 'notes', label: 'All notes', keywords: 'notes find search annotations comments my', run: () => openNotes() };

// An incident note's title is its incident as it reads now (the server sends `incident`), in the Network view's own
// headline wording when that module is loaded; the stored title only for an incident that is gone.
let alertText = null, alertTextP = null;
const loadAlertText = () => (alertTextP ||= import('../views/net/alert-text.js').then((m) => (alertText = m)).catch(() => null));
function itemTitle(n) {
  if (n.incident && alertText?.headline) { try { return alertText.headline(n.incident).text; } catch { /* below */ } }
  return n.title || n.item;
}

function mountView(el) {
  const V = { q: '', kind: '', data: null, err: null, seq: 0 };
  el.innerHTML = `${viewHeader({ title: 'Notes', cls: 'notes-vh', purpose: 'Everything you wrote on incidents, entities, stories and articles, newest first. Kept on your Night Desk server' })}
    <div class="notes-view">
      <div class="notes-bar">
        <label class="notes-search"><svg class="i"><use href="#i-search"/></svg><input type="search" placeholder="Find in notes and titles…" aria-label="Find in notes"></label>
        <div class="notes-kinds" role="group" aria-label="Show"></div>
      </div>
      <div class="notes-res" aria-live="polite"></div></div>`;
  const $ = (s) => el.querySelector(s);
  const input = $('.notes-search input');
  async function load() {
    const my = ++V.seq;
    try { [V.data] = await Promise.all([api.get('/api/notes', { q: V.q, kind: V.kind, limit: 500 }), loadAlertText()]); V.err = null; } catch (e) { V.err = e.message; }
    if (my === V.seq) paint();
  }
  function paint() {
    const k = V.data?.kinds || {};
    const all = Object.values(k).reduce((a, b) => a + b, 0);
    $('.notes-kinds').innerHTML = [['', 'All', all], ...Object.keys(KIND_SHORT).map((x) => [x, KIND_SHORT[x], k[x] || 0])]
      .map(([v, l, n]) => `<button class="chip ${V.kind === v ? 'on' : ''}" data-k="${v}" aria-pressed="${V.kind === v}">${l}<span class="n">${n}</span></button>`).join('');
    const box = $('.notes-res');
    if (V.err) { box.innerHTML = errorState({ retry: load, title: "Couldn't read your notes", why: 'The Night Desk server did not answer. Your notes are safe there; try again in a moment.', err: V.err }); return; }
    if (!V.data) { box.innerHTML = loadingState('Reading notes…'); return; }
    const ns = V.data.notes;
    if (!ns.length) {
      box.innerHTML = all ? emptyState({ title: 'No notes match', why: `Nothing ${V.kind ? `in ${esc(KIND_SHORT[V.kind].toLowerCase())} ` : ''}contains “${esc(V.q)}”. Try fewer words, or show all kinds.` })
        : emptyState({ title: 'No notes yet', why: 'Open an alert in Network, an entity, or a news story or article, and write a note under <em>Notes</em>. It shows up here, and as a small note badge in the lists.', act: stateAct('Open Network alerts', { href: '#network/alerts' }) });
      return;
    }
    // grouped by item, in the order of each item's latest change
    const phone = isPhone();
    const groups = new Map();
    for (const n of ns) { const key = `${n.kind}\u0000${n.item}`; if (!groups.has(key)) groups.set(key, []); groups.get(key).push(n); }
    box.innerHTML = `<p class="notes-tot mono">${plural(V.data.total, 'note')}${V.data.total > ns.length ? `, showing the latest ${ns.length}` : ''} on ${plural(groups.size, 'item')}</p>
      <ul class="notes-groups">${[...groups.values()].map((g) => `<li class="notes-g">
        <a class="notes-gt" href="${esc(g[0].href)}"><span class="notes-kind">${esc(KIND_LABEL[g[0].kind] || g[0].kind)}</span><b>${esc(itemTitle(g[0]))}</b></a>
        <ol class="notes-list">${g.map((n) => (phone
          // a phone: each note is one button that opens the note sheet (edit, delete); the text is shown plain
          ? `<li class="notes-it notes-m-li"><button type="button" class="notes-m-it" data-nid="${esc(n.id)}" aria-label="Edit note: ${esc(String(n.body || '').slice(0, 80))}"><span class="notes-meta mono">${esc(ago(n.created_at))}${n.updated_at !== n.created_at ? ` · edited ${esc(ago(n.updated_at))}` : ''}</span><span class="notes-m-body">${esc(n.body || '')}</span></button></li>`
          : `<li class="notes-it"><div class="notes-meta mono"><span title="${esc(when(n.created_at))}">${esc(ago(n.created_at))}</span>${n.updated_at !== n.created_at ? ` · edited ${esc(ago(n.updated_at))}` : ''}</div><div class="notes-body">${n.html}</div></li>`)).join('')}</ol>
      </li>`).join('')}</ul>`;
  }
  const reload = debounce(() => { V.q = input.value.trim(); load(); }, 250);
  input.addEventListener('input', reload);
  $('.notes-kinds').addEventListener('click', (e) => { const b = e.target.closest('[data-k]'); if (!b) return; V.kind = b.dataset.k; paint(); load(); });
  onNotesChange(() => { if (el.closest('.view')?.classList.contains('active')) load(); else V.data = null; });
  // a phone: tapping a note opens the note sheet (core/note-sheet.js), which saves through the same API
  $('.notes-res').addEventListener('click', (e) => {
    const b = e.target.closest('[data-nid]');
    const n = b && V.data?.notes.find((x) => x.id === b.dataset.nid);
    if (!n) return;
    import('./note-sheet.js').then((m) => m.openNoteSheet({ kind: n.kind, id: n.item, title: itemTitle(n), note: { id: n.id, body: n.body } }))
      .catch((err) => toast(`Could not open the note: ${err.message}`, true));
  });
  onPhoneChange(() => { if (V.data) paint(); });
  return {
    show() {
      const arg = decodeURIComponent(location.hash.slice(1).split('/').slice(1).join('/') || '');
      if (arg && arg !== V.q) { V.q = arg; input.value = arg; }
      load();
      if (!isTyping()) setTimeout(() => { if (matchMedia('(min-width: 761px)').matches) input.focus({ preventScroll: true }); }, 30);
    },
  };
}

let viewApi = null;
registerView({
  id: 'notes',
  mount(el) { viewApi = mountView(el); },
  show() { viewApi?.show(); },
});
registerCommand({ ...NOTES_COMMAND, group: 'Pages', order: 30 });
// the phone's note sheet (core/note-sheet.js) saves on its own: the badges, blocks and the Notes view follow it
window.addEventListener('nd:notes-changed', (e) => changed(e.detail?.kind, e.detail?.item));
watchLists();
migrateLegacy();

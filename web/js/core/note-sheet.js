// The note composer sheet (v1.2 mobile, Phase 0 contract: design.md §4.2 / §4.10, build-plan.md "Phase 0").
//   openNoteSheet({ kind, id, title, note }) -> Promise<{ action: 'saved' | 'deleted', note } | null>
//     kind: 'incident' | 'entity' | 'story' | 'article';  id: the item's id;  title: the item's title (the Notes list
//     shows it);  note: an existing note { id, body } to edit (omit to add a new one).
//     A sheet with the textarea autofocused (16 px, so iOS does not zoom), Save pinned above the keyboard, and,
//     when editing, Delete through confirmSheet. It uses today's notes API (POST /api/notes, PUT/DELETE
//     /api/notes/<id>) through core/api.js. After a change it dispatches `nd:notes-changed` on window
//     (detail: { kind, item }) so the page showing the item can reload its notes block; resolves null on Cancel.
import { api } from './api.js';
import { openSheet, confirmSheet } from './sheet.js';
import { undoToast } from './undo.js';

const KIND_WORD = { incident: 'alert', entity: 'entity', story: 'story', article: 'article' };

export function openNoteSheet({ kind, id, title = '', note = null } = {}) {
  return new Promise((resolve) => {
    let result = null;
    const wrap = document.createElement('div');
    wrap.className = 'm-note';
    const lab = document.createElement('label');
    lab.className = 'm-note-l';
    lab.htmlFor = `m-note-ta-${Date.now()}`;
    lab.textContent = title ? `Note on ${title}` : `Note on this ${KIND_WORD[kind] || 'item'}`;
    const ta = document.createElement('textarea');
    ta.id = lab.htmlFor;
    ta.className = 'm-note-ta';
    ta.rows = 6;
    ta.maxLength = 10000;
    ta.placeholder = 'What you checked, what you decided, what to look at next…';
    ta.autofocus = true;
    ta.value = note?.body || '';
    const hint = document.createElement('p');
    hint.className = 'm-note-hint';
    hint.textContent = 'Saved on your Night Desk server. **bold**, *italic*, - lists work.';
    const err = document.createElement('p');
    err.className = 'm-note-err';
    err.setAttribute('role', 'alert');
    err.hidden = true;
    wrap.append(lab, ta, hint, err);

    const btn = (label, cls) => { const b = document.createElement('button'); b.type = 'button'; b.className = `m-btn ${cls || ''}`.trim(); b.textContent = label; return b; };
    const del = note ? btn('Delete', 'm-btn-ghost m-btn-danger-text') : null;
    const cancel = btn('Cancel');
    const save = btn(note ? 'Save' : 'Add note', 'm-btn-primary');
    const sh = openSheet({ id: 'note', title: note ? 'Edit note' : 'Add a note', body: wrap, footer: [del, cancel, save].filter(Boolean),
      onClose: () => resolve(result) });
    const fail = (e) => { err.textContent = `Couldn't save the note: ${e.message}`; err.hidden = false; save.disabled = false; sh.setBusy(false); };
    const changed = () => window.dispatchEvent(new CustomEvent('nd:notes-changed', { detail: { kind, item: id } }));

    cancel.addEventListener('click', () => sh.close('close'));
    save.addEventListener('click', async () => {
      const body = ta.value.trim();
      if (!body) { err.textContent = note ? 'A note cannot be empty. Use Delete to remove it.' : 'Write something first.'; err.hidden = false; ta.focus(); return; }
      save.disabled = true; sh.setBusy(true); err.hidden = true;
      try {
        const r = note ? await api.put(`/api/notes/${encodeURIComponent(note.id)}`, { body })
          : await api.post('/api/notes', { kind, item: id, body, title });
        result = { action: 'saved', note: r?.note || r || null };
        changed();
        sh.close('close');
      } catch (e) { fail(e); }
    });
    del?.addEventListener('click', async () => {
      const ok = await confirmSheet({ title: 'Delete this note?', text: 'It is removed from your Night Desk server.', confirm: 'Delete', danger: true });
      if (!ok) return;
      try {
        await api.del(`/api/notes/${encodeURIComponent(note.id)}`);
        result = { action: 'deleted', note };
        changed();
        await sh.close('close');
        undoToast('Note deleted', async () => {
          await api.post('/api/notes', { kind, item: id, body: note.body, title });
          changed();
        });
      } catch (e) { fail(e); }
    });
    ta.addEventListener('keydown', (e) => {
      e.stopPropagation(); // typing here never reaches a view's single-key shortcuts
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); save.click(); }
    });
  });
}

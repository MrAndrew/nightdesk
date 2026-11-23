// Identity and disagreement (v1.1 intelx): "Same as…" (merge two entities), "Wrong type…" (retype), likely
// duplicates with one-click merge or "Not the same", one "Disagree…" action with a reason on claim rows, and the
// Review queue (#entities/review). Data: /api/entities/{merge,retype,not-same,duplicates,review,overrides}.
// Contract: okf/data/entities.md#overrides and #disagree
import { api, esc, toast, tmeta, tcolor, icon, chip, shown, typeOf, bandPill, fmtDate, predText } from './common.js';
import { entityHref } from '../../core/open.js';
import { emptyState, errorState, loadingState } from '../../core/view.js';
import { isPhone } from '../../core/mobile.js';

export const NAMED = ['actor', 'campaign', 'malware', 'tool', 'org', 'vendor', 'product', 'sector', 'country'];
const RETYPE_TO = ['actor', 'malware', 'tool', 'campaign', 'org', 'vendor', 'product'];
export const REASONS = [
  ['wrong-link', 'Wrong link', 'These two are not connected like this.'],
  ['wrong-type', 'Wrong type', 'One of them is the wrong kind of thing (a group listed as malware, say).'],
  ['outdated', 'Outdated', 'It was true once, but not any more.'],
  ['other', 'Something else', 'Say why in the note.'],
];
export const reasonLabel = (r) => (REASONS.find((x) => x[0] === r) || [, ''])[1];
const tname = (t) => tmeta(t)[0];
const lower = (t) => tname(t).toLowerCase();
const n = (x, w) => `${x} ${w}${x === 1 ? '' : 's'}`;

// ------------------------------------------------------------------------------------------------ toasts with Undo
function undoToast(msg, oid, after) {
  const box = document.getElementById('toasts');
  if (!box) return toast(msg);
  const el = document.createElement('div');
  el.className = 'toast ix-toast';
  el.innerHTML = `<span>${esc(msg)}</span>${oid ? '<button class="ix-tundo">Undo</button>' : ''}`;
  box.append(el);
  const t = setTimeout(() => el.remove(), 9000);
  el.querySelector('.ix-tundo')?.addEventListener('click', async () => {
    clearTimeout(t); el.remove();
    try { if (await undo(oid)) after?.(true); } catch (e) { toast(`Undo failed: ${e.message}`, true); }
  });
}
// Undo a merge, retype or "not the same". Changes made since a merge go back with the merged entity; the few that
// can't be split (on a link both entities had) are listed first, and Undo waits for a yes. Resolves null if cancelled.
async function undo(oid, anchor) {
  const pv = await api.get(`/api/entities/overrides/${encodeURIComponent(oid)}/undo-preview`).catch(() => null);
  if (pv?.stays?.length) {
    const ok = await new Promise((res) => {
      if (!anchor?.isConnected) { res(window.confirm(`${pv.stays.length} later change${pv.stays.length === 1 ? '' : 's'} can't be split and will stay on ${pv.dst_name}:\n\n${pv.stays.join('\n')}\n\nUndo anyway?`)); return; }
      const el = openPop(anchor, `Split ${pv.src_name} out again?`, `
        <p class="ix-line">${pv.moved_back ? `${n(pv.moved_back, 'change')} made since the merge go${pv.moved_back === 1 ? 'es' : ''} back to ${esc(pv.src_name)}. ` : ''}These stay on <b>${esc(pv.dst_name)}</b>, because both entities had the link:</p>
        <ul class="ix-stays">${pv.stays.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>
        <div class="ix-btns"><button class="src-btn ix-cancel">Cancel</button><button class="src-btn ix-go">Undo anyway</button></div>`);
      let done = false;
      const fin = (v) => { if (!done) { done = true; closePop(); res(v); } };
      el.querySelector('.ix-cancel').onclick = () => fin(false);
      el.querySelector('.ix-go').onclick = () => fin(true);
      new MutationObserver((_, mo) => { if (!el.isConnected) { mo.disconnect(); fin(false); } }).observe(document.body, { childList: true });
    });
    if (!ok) return null;
  }
  const r = await api.post(`/api/entities/overrides/${encodeURIComponent(oid)}/undo`, {});
  toast(r.action === 'distinct' ? 'Undone. The pair is suggested again.'
    : r.moved_back ? `Undone. Both entities are back, with ${n(r.moved_back, 'later change')} returned to ${pv?.src_name || 'the one you split out'}.`
      : 'Undone. Both entities are back as they were.');
  return r;
}
// "Merged. AgendaCrypt is now part of Qilin." — or, when both have one name, say which entry went where.
function mergedMsg(r) {
  if (String(r.src_name).toLowerCase() === String(r.dst_name).toLowerCase() && r.src_type && r.dst_type) {
    return `Merged the ${lower(r.src_type)} entry into the ${lower(r.dst_type)} ${r.dst_name}.`;
  }
  return `Merged. ${r.src_name} is now part of ${r.dst_name}.`;
}

// ------------------------------------------------------------------------------------------------ popover
// One small dialog at a time, anchored under the button that opened it (a bottom sheet on a phone).
let POP = null;
export function closePop() {
  if (!POP) return;
  const { el, from, onKey, onDown } = POP;
  POP = null;
  document.removeEventListener('keydown', onKey, true);
  document.removeEventListener('pointerdown', onDown, true);
  el.remove();
  from?.focus?.();
}
function openPop(from, title, body) {
  closePop();
  const el = document.createElement('div');
  el.className = 'ix-pop';
  el.setAttribute('role', 'dialog');
  el.setAttribute('aria-label', title);
  el.innerHTML = `<div class="ix-poph"><h4>${esc(title)}</h4><button class="icon-btn ix-x" aria-label="Close"><svg class="i"><use href="#i-x"/></svg></button></div><div class="ix-popb">${body}</div>`;
  document.body.append(el);
  const r = from.getBoundingClientRect();
  if (window.innerWidth > 640) {
    const w = Math.min(380, window.innerWidth - 32);
    el.style.width = `${w}px`;
    el.style.left = `${Math.max(16, Math.min(window.innerWidth - w - 16, r.right - w))}px`;
    // under the button, or above it when there is no room; re-placed when its content grows (a hint appears)
    const place = () => {
      const below = r.bottom + 6;
      const h = el.offsetHeight;
      const top = below + h > window.innerHeight - 16 ? r.top - h - 6 : below;
      el.style.top = `${Math.max(16, Math.min(top, window.innerHeight - h - 16))}px`;
    };
    place();
    new ResizeObserver(() => { if (el.isConnected) place(); }).observe(el);
  } else el.classList.add('sheet');
  const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); closePop(); } };
  const onDown = (e) => { if (!el.contains(e.target) && !from.contains(e.target)) closePop(); };
  document.addEventListener('keydown', onKey, true);
  document.addEventListener('pointerdown', onDown, true);
  el.querySelector('.ix-x').onclick = closePop;
  POP = { el, from, onKey, onDown };
  (el.querySelector('input:not([type=radio]), input[type=radio]:checked, input[type=radio], textarea, button.ix-go') || el).focus();
  return el;
}

// ------------------------------------------------------------------------------------------------ disagree
// The one action on a claim row a person can judge (reported claims and hypotheses). A disagreement is a reject
// with a reason: the link leaves the page, Related, the graph and the counts, and waits under "You disagreed".
export function disagreeCell(c) {
  if (c.verdict === 'confirm') return `<span class="cl-vote"><span class="cl-voted confirm">✓ You agreed</span><button class="cl-undo" data-act="clear" data-cid="${esc(c.id)}" title="Withdraw it">Undo</button></span>`;
  if (c.verdict === 'reject') return `<span class="cl-vote"><span class="cl-voted reject">You disagreed${c.verdict_reason ? ` · ${esc(reasonLabel(c.verdict_reason).toLowerCase())}` : ''}</span><button class="cl-undo" data-act="clear" data-cid="${esc(c.id)}" title="Withdraw it: the link comes back">Undo</button></span>`;
  if (c.authoritative || !(c.origin === 'inferred' || c.origin === 'reported')) return '';
  return `<span class="cl-vote"><button class="ix-dis" data-act="disagree" data-cid="${esc(c.id)}" title="Say this claim is wrong, and why">Disagree…</button></span>`;
}

// claim: {id, subj/obj names}; send(body) posts the verdict and redraws.
export function disagreePop(from, claim, send) {
  const ends = [[claim.subj, claim.subj_name], [claim.obj, claim.obj_name]].filter(([id]) => id && NAMED.includes(typeOf(id)));
  const el = openPop(from, 'Disagree with this claim', `
    <p class="ix-line">${esc(claim.subj_name)} <b>${esc(predText(claim.predicate, 'out'))}</b> ${esc(claim.obj_name)}</p>
    <fieldset class="ix-reasons"><legend class="label">What is wrong?</legend>
      ${REASONS.map(([k, l, h], i) => `<label class="ix-r"><input type="radio" name="ixr" value="${k}"${i === 0 ? ' checked' : ''}><span><b>${esc(l)}</b><small>${esc(h)}</small></span></label>`).join('')}
    </fieldset>
    <div class="ix-wt" hidden>${ends.length ? `To fix the type itself, open the full page of ${ends.map(([id, nm]) => `<a href="${esc(entityHref(id))}" data-open-full>${esc(nm)}</a>`).join(' or ')} and use <b>Wrong type…</b> there.` : ''}</div>
    <label class="ix-note"><span class="label">Note <small class="ix-opt">(optional)</small></span><textarea rows="2" maxlength="1000" placeholder="What you know, for later"></textarea></label>
    <p class="ix-foot">The link is hidden from this page, Related and the graph. You can undo it.</p>
    <div class="ix-btns"><button class="src-btn ix-cancel">Cancel</button><button class="src-btn ix-go">Disagree</button></div>`);
  const pick = () => el.querySelector('input[name=ixr]:checked').value;
  const sync = () => {
    el.querySelector('.ix-wt').hidden = pick() !== 'wrong-type' || !ends.length;
    el.querySelector('.ix-opt').textContent = pick() === 'other' ? '(say why)' : '(optional)';
  };
  el.querySelectorAll('input[name=ixr]').forEach((r) => r.addEventListener('change', sync));
  el.querySelector('.ix-cancel').onclick = closePop;
  el.querySelector('.ix-go').onclick = async (e) => {
    const note = el.querySelector('textarea').value.trim();
    if (pick() === 'other' && !note) { el.querySelector('textarea').focus(); el.querySelector('.ix-opt').textContent = '(say why: needed for “Something else”)'; return; }
    e.target.disabled = true;
    try { await send({ verdict: 'reject', reason: pick(), note }); closePop(); } catch (err) { e.target.disabled = false; if (!err.toasted) toast(`Could not save: ${err.message}`, true); }
  };
  el.querySelector('input[name=ixr]:checked').focus();
}

// ------------------------------------------------------------------------------------------------ entity page
// Header buttons for named things.
export function identityActs(d) {
  if (!NAMED.includes(d.type)) return '';
  return `<button class="src-btn" data-act="ix-same" title="This is the same thing as another entity: merge them">Same as…</button>
    <button class="src-btn" data-act="ix-type" title="This is listed as the wrong kind of thing">Wrong type…</button>`;
}

// The identity strip under the name: where an old link came from, what was merged here (Undo), likely duplicates.
export function identityHtml(d) {
  const out = [];
  const rf = d.redirected_from;
  if (rf) out.push(`<div class="ix-note-b">You merged <b>${esc(rf.name)}</b> into ${esc(d.name)}${rf.action === 'retype' ? ` when you changed its type to ${esc(lower(d.type))}` : ''}, so its link opens here.</div>`);
  const mh = (d.merged_here || []).filter((o) => o.action !== 'distinct');
  if (mh.length) {
    out.push(`<div class="ix-merged"><span class="label">Merged here</span>${mh.map((o) => `<span class="ix-mh"><span class="en-tbadge" style="--c:${tcolor(typeOf(o.src))}">${icon(typeOf(o.src))}${esc(tname(typeOf(o.src)))}</span>${esc(o.src_name)}<button class="cl-undo" data-act="ix-undo" data-oid="${esc(o.id)}" title="Split ${esc(o.src_name)} out again">Undo</button></span>`).join('')}</div>`);
  }
  const dup = d.possible_duplicates || [];
  if (dup.length) {
    out.push(`<div class="ix-dup" role="note"><span class="ix-dup-h">Possibly the same as</span>${dup.slice(0, 3).map((s) => {
      const o = s.a.id === d.id ? s.b : s.a;
      return `<span class="ix-dup-i">${chip(o.id, { type: o.type, name: o.name })}<small>${esc(s.reasons[0])}</small>
        <button class="src-btn sm" data-act="ix-same" data-with="${esc(o.id)}">Same thing…</button><button class="src-btn sm ghost" data-act="ix-notsame" data-a="${esc(d.id)}" data-b="${esc(o.id)}">Not the same</button></span>`;
    }).join('')}</div>`);
  }
  return out.length ? `<div class="ix-id">${out.join('')}</div>` : '';
}

// Page actions; returns true when it handled the click. reload() redraws the page from fresh data; go(id) opens one.
export function identityAct(act, btn, d, { reload, open }) {
  if (act === 'ix-undo') { btn.disabled = true; undo(btn.dataset.oid, btn).then((r) => { if (r) reload(); else btn.disabled = false; }).catch((e) => { btn.disabled = false; toast(`Undo failed: ${e.message}`, true); }); return true; }
  if (act === 'ix-notsame') { notSame(btn.dataset.a, btn.dataset.b, btn).then((ok) => ok && reload()); return true; }
  if (act === 'ix-same') { samePop(btn, d, btn.dataset.with || null, { reload, open }); return true; }
  if (act === 'ix-type') { typePop(btn, d, { reload, open }); return true; }
  return false;
}

async function notSame(a, b, btn) {
  if (btn) btn.disabled = true;
  try {
    const r = await api.post('/api/entities/not-same', { a, b });
    undoToast('Noted: not the same. The hub stops suggesting this pair.', r.id);
    return true;
  } catch (e) { if (btn) btn.disabled = false; toast(`Could not save: ${e.message}`, true); return false; }
}

// "Same as…": pick the other entity (suggestions first, or search), then which one to keep.
function samePop(from, d, withId, ctx) {
  const sug = (d.possible_duplicates || []).map((s) => (s.a.id === d.id ? s.b : s.a));
  const el = openPop(from, `${d.name} is the same as…`, `
    <div class="ix-step1">
      ${sug.length ? `<div class="label">Suggested</div><div class="ix-cands ix-sug">${sug.map((o) => cand(o)).join('')}</div>` : ''}
      <label class="ix-find"><span class="label">Find another</span><input type="search" placeholder="Name or alias" spellcheck="false" autocomplete="off"></label>
      <div class="ix-cands ix-res"></div>
    </div>
    <div class="ix-step2" hidden></div>`);
  const res = el.querySelector('.ix-res');
  let seq = 0, timer;
  el.querySelector('.ix-find input').addEventListener('input', (e) => {
    clearTimeout(timer);
    const q = e.target.value.trim();
    timer = setTimeout(async () => {
      const my = ++seq;
      if (q.length < 2) { res.innerHTML = ''; return; }
      const r = await api.get('/api/entities', { q, type: NAMED.join(','), limit: 8 }).catch(() => null);
      if (my !== seq || !r) return;
      const items = r.items.filter((x) => x.id !== d.id);
      res.innerHTML = items.length ? items.map(cand).join('') : emptyState({ why: `No named entity matches “${esc(q)}”.`, size: 'inline' });
    }, 220);
  });
  el.addEventListener('click', (e) => {
    const c = e.target.closest('[data-pick]');
    if (c) step2(el, d, { id: c.dataset.pick, name: c.dataset.name, type: c.dataset.type, weight: +c.dataset.w || 0 }, ctx);
  });
  if (withId) {
    const o = sug.find((x) => x.id === withId);
    if (o) step2(el, d, { id: o.id, name: o.name, type: o.type, weight: (o.mentions || 0) + (o.claims || 0) }, ctx);
  }
}
const cand = (o) => `<button class="ix-cand" data-pick="${esc(o.id)}" data-name="${esc(o.name)}" data-type="${esc(o.type)}" data-w="${(o.mentions || 0) + (o.claims || 0)}">
  <span class="en-tbadge" style="--c:${tcolor(o.type)}">${icon(o.type)}${esc(tname(o.type))}</span><b>${esc(shown(o.name, o.type))}</b><small class="mono">${n(o.mentions || 0, 'mention')}</small></button>`;

function step2(el, d, o, { reload, open }) {
  const s1 = el.querySelector('.ix-step1'), s2 = el.querySelector('.ix-step2');
  const mine = (d.mentions?.refs || 0) + Object.values(d.claim_counts || {}).reduce((a, b) => a + b, 0);
  const keepOther = o.weight > mine;
  s1.hidden = true; s2.hidden = false;
  const opt = (id, name, type, on) => `<label class="ix-r"><input type="radio" name="ixk" value="${esc(id)}"${on ? ' checked' : ''}><span><b>${esc(name)}</b><small>as a ${esc(lower(type))}</small></span></label>`;
  s2.innerHTML = `<p class="ix-line">${esc(d.name)} <span class="en-dim">(${esc(lower(d.type))})</span> and ${esc(o.name)} <span class="en-dim">(${esc(lower(o.type))})</span> become one entity: names, mentions and claims together.</p>
    <fieldset class="ix-reasons"><legend class="label">Keep it as</legend>${opt(d.id, d.name, d.type, !keepOther)}${opt(o.id, o.name, o.type, keepOther)}</fieldset>
    <label class="ix-note"><span class="label">Note <small>(optional)</small></span><textarea rows="2" maxlength="1000" placeholder="Why they are the same"></textarea></label>
    <p class="ix-foot">The other name becomes an alias, and new reports under either name land here. You can undo it.</p>
    <div class="ix-btns"><button class="src-btn ix-back">Back</button><button class="src-btn ix-go">Merge</button></div>`;
  s2.querySelector('.ix-back').onclick = () => { s2.hidden = true; s1.hidden = false; };
  s2.querySelector('.ix-go').focus();
  s2.querySelector('.ix-go').onclick = async (e) => {
    const dst = s2.querySelector('input[name=ixk]:checked').value;
    const src = dst === d.id ? o.id : d.id;
    e.target.disabled = true;
    try {
      const r = await api.post('/api/entities/merge', { src, dst, note: s2.querySelector('textarea').value.trim() });
      closePop();
      undoToast(mergedMsg(r), r.id, () => (dst === d.id ? reload() : open(src)));
      if (dst === d.id) reload(); else open(dst);
    } catch (err) { e.target.disabled = false; toast(`Merge failed: ${err.message}`, true); }
  };
}

// "Wrong type…": pick the right type; a same-name entity of that type, if there is one, is merged into.
function typePop(from, d, { reload, open }) {
  const el = openPop(from, 'Wrong type', `
    <p class="ix-line">${esc(d.name)} is listed as a <b>${esc(lower(d.type))}</b>. What is it?</p>
    <fieldset class="ix-reasons ix-types">${RETYPE_TO.filter((t) => t !== d.type).map((t, i) => `<label class="ix-r"><input type="radio" name="ixt" value="${t}"${i === 0 ? ' checked' : ''}><span class="ix-tl" style="--c:${tcolor(t)}">${icon(t)}<b>${esc(tname(t))}</b></span></label>`).join('')}</fieldset>
    <label class="ix-note"><span class="label">Note <small>(optional)</small></span><textarea rows="2" maxlength="1000"></textarea></label>
    <p class="ix-foot">If a ${'same-name'} entity of that type exists, the two become one. New reports that use the old type land on the new one. You can undo it.</p>
    <div class="ix-btns"><button class="src-btn ix-cancel">Cancel</button><button class="src-btn ix-go">Change type</button></div>`);
  el.querySelector('.ix-cancel').onclick = closePop;
  el.querySelector('.ix-go').onclick = async (e) => {
    const type = el.querySelector('input[name=ixt]:checked').value;
    e.target.disabled = true;
    try {
      const r = await api.post('/api/entities/retype', { id: d.id, type, note: el.querySelector('textarea').value.trim() });
      closePop();
      undoToast(r.dst_created ? `${r.src_name} is now a ${lower(type)}.` : `${r.src_name} is now a ${lower(type)}, joined with the existing ${r.dst_name}.`, r.id, () => open(d.id));
      open(r.dst);
    } catch (err) { e.target.disabled = false; toast(`Could not change the type: ${err.message}`, true); }
  };
  void reload;
}

// ------------------------------------------------------------------------------------------------ review queue
// No count on the tab: the queue is a place to work through, not one more number that needs you.
export async function showReview(pane, { onCount } = {}) {
  if (!pane.dataset.ix) {
    pane.dataset.ix = '1';
    pane.addEventListener('click', (e) => reviewClick(pane, e, onCount));
  }
  if (!pane.innerHTML) pane.innerHTML = `<div class="ix-rv">${loadingState('Loading the review queue…')}</div>`;
  let r;
  try { r = await api.get('/api/entities/review', { limit: 60 }); }
  catch (e) { pane.innerHTML = errorState({ retry: () => showReview(pane, { onCount }), title: "Couldn't load the review queue", why: 'The Intel data did not answer. Try again in a moment.', err: e.message }); return; }
  pane._rv = r;
  onCount?.(r.counts.duplicates + r.counts.contested);
  const c = r.counts;
  const disRow = (x) => `<div class="ix-dr" data-cid="${esc(x.id)}">
      <span class="ix-dl">${chip(x.subj, { name: x.subj_name })}<span class="ix-p">${esc(predText(x.predicate, 'out'))}</span>${chip(x.obj, { name: x.obj_name })}</span>
      <span class="ix-dm"><span class="cl-voted reject">${esc(x.reason ? reasonLabel(x.reason) : 'Disagreed')}</span>${x.note ? `<q>${esc(x.note)}</q>` : ''}<span class="mono en-dim">${fmtDate(x.ts)}</span>
      <button class="cl-undo" data-rv="clear" data-cid="${esc(x.id)}" title="Withdraw it: the link comes back">Undo</button></span></div>`;
  const chRow = (o) => {
    const what = o.action === 'merge' ? `<b>${esc(o.src_name)}</b> merged into ${chip(o.dst, { name: o.dst_name })}`
      : o.action === 'retype' ? `<b>${esc(o.src_name)}</b> changed from ${esc(lower(typeOf(o.src)))} to ${chip(o.dst, { name: o.dst_name })}`
        : `${chip(o.src, { name: o.src_name })} and ${chip(o.dst, { name: o.dst_name })} are not the same`;
    return `<div class="ix-dr"><span class="ix-dl">${what}</span><span class="ix-dm">${o.note ? `<q>${esc(o.note)}</q>` : ''}<span class="mono en-dim">${fmtDate(o.ts)}</span>
      <button class="cl-undo" data-rv="undo" data-oid="${esc(o.id)}">Undo</button></span></div>`;
  };
  // a phone reads the queue only: the decisions (merge, split, pick a side, undo) wait for a computer (design.md §4.4)
  const phone = isPhone();
  pane.innerHTML = `<div class="ix-rv${phone ? ' ix-rv-m' : ''}">
    <header class="ix-rvh"><h2 class="en-h1">Review</h2>
      <p>Things worth a second look: entities that are probably the same thing, and attributions where sources disagree. Nothing changes until you choose, and every choice can be undone.</p></header>
    ${phone ? `<div class="ix-m-banner" role="note"><p><b>Decide these on a computer.</b> Here you can read the queue; merging, splitting and picking a side need a bigger screen.</p>
      <button type="button" class="m-btn ix-m-copy">Copy link</button></div>` : ''}
    <section class="enp-card ix-sec" id="ix-dups"><div class="enp-ch"><h3>Possibly the same thing</h3><span class="mono en-dim">${n(c.duplicates, 'pair')}</span></div>
      ${r.duplicates.length ? `<div class="ix-pairs">${r.duplicates.map(pairCard).join('')}</div>${c.duplicates > r.duplicates.length ? `<p class="en-dim ix-more">Showing ${r.duplicates.length} of ${c.duplicates}, most mentioned first. Settle these and the next ones move up.</p>` : ''}`
        : emptyState({ why: 'No likely duplicates. The hub looks for one name under two types, and for one entity listing another’s name.', size: 'inline' })}</section>
    <section class="enp-card ix-sec" id="ix-cont"><div class="enp-ch"><h3>Sources disagree</h3><span class="mono en-dim">${n(c.contested, 'attribution')}</span></div>
      ${r.contested.length ? r.contested.map(contestCard).join('') : emptyState({ why: 'No contested attributions left. When two sources name different actors for the same thing, it shows up here until you pick one.', size: 'inline' })}</section>
    <section class="enp-card ix-sec" id="ix-dis"><div class="enp-ch"><h3>You disagreed</h3><span class="mono en-dim">${n(c.disagreed, 'claim')} · hidden everywhere until you undo</span></div>
      ${r.disagreed.length ? r.disagreed.map(disRow).join('') : emptyState({ why: 'Nothing yet. Use <b>Disagree…</b> on a claim you think is wrong.', size: 'inline' })}</section>
    ${r.changes.length ? `<section class="enp-card ix-sec" id="ix-ch"><div class="enp-ch"><h3>Your changes</h3><span class="mono en-dim">merges, type changes and “not the same”</span></div>${r.changes.map(chRow).join('')}</section>` : ''}
  </div>`;
  const cp = pane.querySelector('.ix-m-copy');
  if (cp) cp.onclick = () => navigator.clipboard?.writeText(location.href).then(() => toast('Link copied'), () => toast('Copy failed', true));
}

const STRENGTH = {
  possible: 'The names are close but not equal (“Akira” and “Akira Stealer”): often two different things.',
  weak: 'A group lists a malware or tool name as one of its names; reference sets often list a group’s tools this way.',
};
function pairCard(s) {
  const side = (e) => `<div class="ix-side">${chip(e.id, { type: e.type, name: e.name })}<span class="mono en-dim">${n(e.mentions, 'mention')} · ${n(e.claims, 'claim')}</span>
    ${e.aliases?.length ? `<small class="en-dim">aka ${esc(e.aliases.slice(0, 3).join(', '))}</small>` : ''}</div>`;
  return `<div class="ix-pair" data-pair="${esc(s.id)}">
    <div class="ix-sides">${side(s.a)}<span class="ix-eq" aria-hidden="true">≟</span>${side(s.b)}</div>
    <div class="ix-why">${s.strength && s.strength !== 'strong' ? `<b class="ix-str ${esc(s.strength)}" title="${esc(STRENGTH[s.strength] || '')}">${esc(s.strength)} match</b>` : ''}${s.reasons.map((x) => `<span>${esc(x)}</span>`).join('')}</div>
    <div class="ix-btns">
      <button class="src-btn sm ix-keep" data-rv="merge" data-src="${esc(s.b.id)}" data-dst="${esc(s.a.id)}" title="Merge ${esc(s.b.name)} into ${esc(s.a.name)}">Keep as ${esc(s.a.name)} (${esc(lower(s.a.type))})</button>
      <button class="src-btn sm" data-rv="merge" data-src="${esc(s.a.id)}" data-dst="${esc(s.b.id)}" title="Merge ${esc(s.a.name)} into ${esc(s.b.name)}">Keep as ${esc(s.b.name)} (${esc(lower(s.b.type))})</button>
      <button class="src-btn sm ghost" data-rv="notsame" data-a="${esc(s.a.id)}" data-b="${esc(s.b.id)}">Not the same</button>
    </div></div>`;
}

function contestCard(g) {
  return `<div class="ix-ct"><p class="ix-ctq">Who is behind ${chip(g.subj, { name: g.subj_name })}? Sources name ${g.candidates.length} different ${esc(lower(g.type))}s.</p>
    <div class="ix-cands2">${g.candidates.map((c) => `<div class="ix-cc">
      <div class="ix-cct">${chip(c.obj, { name: c.name })}${bandPill(c.confidence, c.band)}</div>
      <div class="mono en-dim ix-ccs">${esc(c.sources.slice(0, 3).join(', '))}${c.authoritative ? ' · reference' : ''}</div>
      ${c.quote ? `<blockquote>“${esc(c.quote.slice(0, 160))}${c.quote.length > 160 ? '…' : ''}”</blockquote>` : ''}
      <div class="ix-btns"><button class="src-btn sm" data-rv="agree" data-cid="${esc(c.id)}" title="You trust this one; the question leaves the queue">This one</button>
        ${c.authoritative ? '' : `<button class="src-btn sm ghost" data-rv="disagree" data-cid="${esc(c.id)}" data-subj="${esc(g.subj)}" data-sname="${esc(g.subj_name)}" data-obj="${esc(c.obj)}" data-oname="${esc(c.name)}">Disagree…</button>`}</div>
    </div>`).join('')}</div></div>`;
}

async function reviewClick(pane, e, onCount) {
  const b = e.target.closest('[data-rv]');
  if (!b) return;
  const act = b.dataset.rv;
  const again = () => showReview(pane, { onCount });
  const fb = (cid, body) => api.post(`/api/entities/claims/${encodeURIComponent(cid)}/feedback`, body);
  try {
    if (act === 'merge') {
      b.closest('.ix-pair')?.querySelectorAll('button').forEach((x) => (x.disabled = true));
      const r = await api.post('/api/entities/merge', { src: b.dataset.src, dst: b.dataset.dst });
      undoToast(mergedMsg(r), r.id, again);
    } else if (act === 'notsame') {
      b.disabled = true;
      if (!(await notSame(b.dataset.a, b.dataset.b))) { b.disabled = false; return; }
    } else if (act === 'undo') { b.disabled = true; if (!(await undo(b.dataset.oid, b))) { b.disabled = false; return; } }
    else if (act === 'clear') { b.disabled = true; await fb(b.dataset.cid, { verdict: 'clear' }); toast('Undone. The link is back.'); }
    else if (act === 'agree') { b.disabled = true; await fb(b.dataset.cid, { verdict: 'confirm' }); toast('Noted. You trust this attribution; it is marked as yours.'); }
    else if (act === 'disagree') {
      const claim = { id: b.dataset.cid, subj: b.dataset.subj, subj_name: b.dataset.sname, predicate: 'attributed-to', obj: b.dataset.obj, obj_name: b.dataset.oname };
      disagreePop(b, claim, async (body) => { await fb(claim.id, body); toast('Noted. The link is hidden; undo it under “You disagreed”.'); again(); });
      return;
    }
  } catch (err) { b.disabled = false; toast(`Could not save: ${err.message}`, true); return; }
  again();
}

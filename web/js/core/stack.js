// My stack, client side: the one followed list (GET /api/stack, osinthub/stack.py) shared by every view.
//   followButton({ entity } | { vendor, product } | { keyword }, { name, cls }) -> HTML for a Follow/Following toggle.
//   Any element rendered from it works anywhere: one document-level click handler toggles it, and every such
//   button on the page repaints when the list changes (window event 'nd:stack', detail = the new list).
//   isFollowed(id) reads an entity id through the user's merges (the server sends each followed id's equivalents),
//   so a chip for the kept id shows Following when the merged id is followed. Contract: okf/architecture/my-stack.md
import { api } from './api.js';
import { esc, toast } from './util.js';

let W = null, loading = null;
let eqIndex = new Map();   // lower-case id -> the followed id it means

function index(w) {
  W = w;
  eqIndex = new Map();
  for (const e of w.entities || []) for (const i of (w.equivalents?.[e] || [e])) eqIndex.set(i.toLowerCase(), e);
}

export async function loadStack(force = false) {
  if (W && !force) return W;
  if (!loading || force) loading = api.get('/api/stack').then((w) => { index(w); return w; }).finally(() => { loading = null; });
  return loading;
}
function changed(w) {
  index(w);
  window.dispatchEvent(new CustomEvent('nd:stack', { detail: w }));
  paintAll();
}

const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
export const stackLabel = (it) => [it.vendor, it.product].filter(Boolean).join(' ');
/** The followed id an entity id means (through merges), or null. */
export function followedEntity(id) { return W && id ? eqIndex.get(String(id).toLowerCase()) || null : null; }
export function isFollowed(id) { return !!followedEntity(id); }
export function followedStack(vendor, product = '') {
  if (!W) return null;
  return (W.stack || []).find((x) => norm(x.vendor) === norm(vendor) && norm(x.product) === norm(product)) || null;
}
export function followedKeyword(k) { return W ? (W.keywords || []).find((x) => x.toLowerCase() === String(k).toLowerCase()) || null : null; }
/** Display name for a `matched` key ("stack:SonicWall", "malware:qakbot", "keyword:foo"). */
export function matchName(key, names = {}) {
  if (names[key]) return names[key];
  if (W?.names?.[key]) return W.names[key];
  return String(key).replace(/^(stack|keyword):/, '').replace(/^[a-z]+:/, '');
}

export async function follow(what) {
  const w = await api.post('/api/stack/follow', what);
  changed(w);
  return w;
}
export async function unfollow(what) {
  const w = await api.post('/api/stack/unfollow', what);
  changed(w);
  return w;
}

function state(b) {
  const d = b.dataset;
  if (d.stackEntity) return isFollowed(d.stackEntity);
  if (d.stackKeyword) return !!followedKeyword(d.stackKeyword);
  return !!followedStack(d.stackVendor, d.stackProduct || '');
}
function chipHtml(on, name, extra) {
  return `${on ? '✓' : '+'} ${esc(name)}${extra ? ` <span class="stack-kev">${esc(extra)}</span>` : ''}`;
}
function paint(b) {
  const on = state(b);
  const name = b.dataset.stackName;
  b.setAttribute('aria-pressed', on ? 'true' : 'false');
  b.classList.toggle('on', on);
  if (b.dataset.stackChip !== undefined) b.innerHTML = chipHtml(on, name, b.dataset.stackChip);
  else b.textContent = on ? `Following ${name}` : `Follow ${name}`;
  b.title = on ? `You follow ${name}. Click to stop following.` : `Follow ${name}: its exploited bugs, news and alerts come first on Watch`;
}
export function paintAll(root = document) { root.querySelectorAll?.('[data-stack-btn]').forEach(paint); }

/** HTML for a Follow/Following toggle. `chip: '3 exploited'` (or '') renders it as a "+ name" chip instead. */
export function followButton(what, { name, cls = 'src-btn', chip = null } = {}) {
  const nm = name || what.keyword || stackLabel(what) || String(what.entity || '').split(':').slice(1).join(':');
  const attrs = what.entity ? `data-stack-entity="${esc(what.entity)}"`
    : what.keyword ? `data-stack-keyword="${esc(what.keyword)}"`
      : `data-stack-vendor="${esc(what.vendor || '')}" data-stack-product="${esc(what.product || '')}"`;
  const on = W ? (what.entity ? isFollowed(what.entity) : what.keyword ? !!followedKeyword(what.keyword) : !!followedStack(what.vendor, what.product || '')) : false;
  const label = chip !== null ? chipHtml(on, nm, chip) : `${on ? 'Following' : 'Follow'} ${esc(nm)}`;
  return `<button type="button" class="${esc(cls)} stack-fb${on ? ' on' : ''}" data-stack-btn ${attrs} data-stack-name="${esc(nm)}"${chip !== null ? ` data-stack-chip="${esc(chip)}"` : ''} aria-pressed="${on}">${label}</button>`;
}

async function toggle(b) {
  const d = b.dataset, on = state(b), name = d.stackName;
  const what = d.stackEntity ? { entity: d.stackEntity } : d.stackKeyword ? { keyword: d.stackKeyword } : { vendor: d.stackVendor, product: d.stackProduct || '' };
  b.disabled = true;
  try {
    if (on) { await unfollow(what); toast(`Stopped following ${name}`); }
    else {
      const r = await follow(what);
      toast(r.kev ? `Following ${name}: ${r.kev} exploited bug${r.kev === 1 ? '' : 's'} match` : `Following ${name}`);
    }
  } catch (e) { toast(e.message, true); }
  b.disabled = false;
  paint(b);
}

document.addEventListener('click', (e) => {
  const b = e.target.closest?.('[data-stack-btn]');
  if (!b) return;
  e.preventDefault();
  e.stopPropagation();   // a button inside a clickable row toggles only
  toggle(b);
}, true);

// buttons rendered before the list arrived get their real state as soon as it does
loadStack().then(() => paintAll()).catch(() => {});

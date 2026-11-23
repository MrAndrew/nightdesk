// One time-range control for every view header (IA-07): the same presets, look, place and keys everywhere.
//
//   const r = mount(el, { value: { h: 24 }, live: true, onChange(v) { ... } });
//   r.set({ from, to });   // show a brushed window as "3 Nov – 5 Nov ×" (no onChange)
//   r.get(); r.hide(true); r.destroy();
//
// A value is { h } (relative hours, 0 = all time) or { from, to } (ms, a custom window from brushing a chart).
// Presets: 24H · 7D · 30D · ALL; views with live data (Ops, Cinema) add 1H and 6H (opts.live).
// Keys: one Tab stop; ←/→ (or ↑/↓) move and select, Home/End jump; Enter or Space on the window chip clears it
// back to the last preset. Each view remembers its own range and writes it into its URL (?range=7d), see the
// helpers below. Contract: okf/architecture/web-client.md#time-ranges
// On a phone (core/mobile.js isPhone()) the presets give way to one chip, "24h ▾", that opens the range sheet (an
// action sheet of the presets, plus "Clear the window" while a brushed window is shown); the value, onChange and
// ?range= are unchanged.
import * as T from './time.js';
import { isPhone, onPhoneChange } from './mobile.js';
import { safeDecode as dec } from './util.js';

export const BASE = [24, 168, 720, 0];
export const LIVE = [1, 6, 24, 168, 720, 0];
const LABEL = { 1: '1H', 6: '6H', 24: '24H', 168: '7D', 720: '30D', 0: 'ALL' };

export const isCustom = (v) => v != null && v.from != null && v.to != null;

// Hours that are not a preset of this control snap to the nearest wider one (e.g. an old saved 6H on Network -> 24H).
export function snap(h, presets = BASE) {
  h = Number(h);
  if (!Number.isFinite(h) || h <= 0) return 0;
  if (presets.includes(h)) return h;
  const wider = presets.filter((p) => p > 0 && p >= h).sort((a, b) => a - b);
  return wider.length ? wider[0] : 0;
}

// ---------------------------------------------------------------- words
// The custom window as the chip shows it, in the app's one clock (core/time.js): "3 Nov – 5 Nov", "3 Nov 14:00–18:00".
export const windowLabel = (from, to) => T.span(from, to);
const longOf = (h) => (!h ? 'All time' : h === 1 ? 'Last hour' : h < 24 ? `Last ${h} hours` : h === 24 ? 'Last 24 hours' : `Last ${h / 24} days`);
// For sentences: "the last 24 hours", "all time", "3 Nov – 5 Nov".
export function phrase(v) {
  if (isCustom(v)) return windowLabel(v.from, v.to);
  return v?.h ? longOf(v.h).replace(/^Last/, 'the last') : 'all time';
}

// ---------------------------------------------------------------- URL (?range=24h | 7d | all | <from>~<to>)
const iso = (t) => new Date(t).toISOString().replace(/\.\d{3}Z$/, 'Z');
export function toParam(v) {
  if (isCustom(v)) return `${iso(v.from)}~${iso(v.to)}`;
  const h = v?.h || 0;
  return !h ? 'all' : h > 24 && h % 24 === 0 ? `${h / 24}d` : `${h}h`;
}
export function fromParam(s, presets = BASE) {
  s = String(s || '').trim().toLowerCase();
  if (!s) return null;
  if (s === 'all') return { h: 0 };
  const m = s.match(/^(\d{1,5})(h|d)$/);
  if (m) return { h: snap(+m[1] * (m[2] === 'd' ? 24 : 1), presets) };
  const [a, b] = s.split('~').map((x) => Date.parse(x.toUpperCase()));
  if (Number.isFinite(a) && Number.isFinite(b) && b > a) return { from: a, to: b };
  return null;
}
const splitHash = (hash) => { const i = hash.indexOf('?'); return i < 0 ? [hash, ''] : [hash.slice(0, i), hash.slice(i + 1)]; };
// The range a hash carries, or null when it has none (then the view keeps what it remembers).
export function hashRange(hash = location.hash, presets = BASE) {
  const p = splitHash(hash)[1].split('&').find((x) => x.startsWith('range='));
  return p ? fromParam(dec(p.slice(6)), presets) : null;
}
// The hash with its range set to v (or removed for null); other parameters (e.g. ?kiosk) are kept.
export function withRange(hash, v) {
  const [path, q] = splitHash(hash);
  const parts = q.split('&').filter((x) => x && !x.startsWith('range='));
  if (v) parts.push(`range=${toParam(v)}`);
  return parts.length ? `${path}?${parts.join('&')}` : path;
}
export const stripRange = (hash) => withRange(hash, null);
// Write v into the current URL when it belongs to this view (test(hash) says so). It replaces the entry and keeps
// its history.state, so Back still lands on the range each entry had and views' own state rides along.
export function syncHash(v, test) {
  const h = location.hash;
  if (!test(h)) return;
  const want = withRange(h, v);
  if (want !== h) history.replaceState(history.state, '', want);
}

// ---------------------------------------------------------------- the control
const X_ICON = '<svg class="i" aria-hidden="true"><use href="#i-x"/></svg>';
export function mount(el, opts = {}) {
  const presets = opts.presets || (opts.live ? LIVE : BASE);
  const name = opts.label || 'Time range';
  let value = opts.value || { h: presets.includes(24) ? 24 : presets[0] };
  if (!isCustom(value)) value = { h: snap(value.h, presets) };
  let lastPreset = isCustom(value) ? (opts.fallback ?? 0) : snap(value.h, presets);
  let kbTimer = 0;

  el.classList.add('ranges');
  el.innerHTML = `
    <button type="button" class="ranges-x" hidden></button>
    <div class="ranges-seg" role="radiogroup" aria-label="${name}">${presets.map((h) =>
      `<button type="button" role="radio" data-h="${h}" title="${longOf(h)}" aria-label="${longOf(h)}">${LABEL[h]}</button>`).join('')}</div>`;
  const chip = el.querySelector('.ranges-x');
  const radios = [...el.querySelectorAll('[role="radio"]')];

  function paint() {
    const custom = isCustom(value);
    radios.forEach((b) => {
      const on = !custom && +b.dataset.h === value.h;
      b.setAttribute('aria-checked', on ? 'true' : 'false');
      b.classList.toggle('active', on);
    });
    // one Tab stop: the checked preset, or the first one while a custom window is shown
    const stop = radios.find((b) => b.getAttribute('aria-checked') === 'true') || radios[0];
    radios.forEach((b) => (b.tabIndex = b === stop ? 0 : -1));
    chip.hidden = !custom;
    if (custom) {
      const lab = windowLabel(value.from, value.to);
      chip.innerHTML = `<span class="mono">${lab}</span>${X_ICON}`;
      chip.title = `${T.stamp(value.from, { year: true })} → ${T.stamp(value.to, { year: true, zone: true })}. Clear to go back to ${LABEL[lastPreset]}.`;
      chip.setAttribute('aria-label', `Time window ${lab} ${T.zoneName(value.from)}. Clear it and go back to ${longOf(lastPreset).toLowerCase()}`);
    }
  }
  function choose(v, { fire = true, delay = 0 } = {}) {
    value = v;
    if (!isCustom(v)) lastPreset = v.h;
    paint();
    paintChip();
    clearTimeout(kbTimer);
    if (!fire || !opts.onChange) return;
    if (delay) kbTimer = setTimeout(() => opts.onChange(value), delay);
    else opts.onChange(value);
  }

  radios.forEach((b) => (b.onclick = () => choose({ h: +b.dataset.h })));
  // ---- the phone chip and the range sheet
  let mchip = null;
  function paintChip() {
    if (!mchip) return;
    const custom = isCustom(value);
    mchip.querySelector('.ranges-m-t').textContent = custom ? windowLabel(value.from, value.to) : (LABEL[value.h] || '').toLowerCase();
    mchip.setAttribute('aria-label', `${name}: ${custom ? windowLabel(value.from, value.to) : longOf(value.h).toLowerCase()}. Change it`);
  }
  async function openRangeSheet() {
    const { actionSheet } = await import('./sheet.js');
    const custom = isCustom(value);
    const items = presets.map((h) => ({ label: longOf(h), value: h, current: !custom && value.h === h }));
    if (custom) items.unshift({ label: `Clear ${windowLabel(value.from, value.to)}`, hint: `back to ${longOf(lastPreset).toLowerCase()}`, value: lastPreset });
    mchip.setAttribute('aria-expanded', 'true');
    const it = await actionSheet({ id: 'range', title: name, items });
    mchip?.setAttribute('aria-expanded', 'false');
    if (it && (custom || it.value !== value.h)) choose({ h: it.value });
  }
  function syncPhone() {
    const phone = isPhone();
    if (phone && !mchip) {
      mchip = document.createElement('button');
      mchip.type = 'button';
      mchip.className = 'ranges-m m-chip';
      mchip.setAttribute('aria-haspopup', 'dialog');
      mchip.setAttribute('aria-expanded', 'false');
      mchip.innerHTML = '<svg class="i" aria-hidden="true"><use href="#i-clock"/></svg><span class="ranges-m-t mono"></span><svg class="i" aria-hidden="true"><use href="#i-caret"/></svg>';
      mchip.onclick = () => openRangeSheet();
      el.append(mchip);
      paintChip();
    } else if (!phone && mchip) { mchip.remove(); mchip = null; }
  }
  const offPhone = onPhoneChange(syncPhone);
  chip.onclick = () => {
    choose({ h: lastPreset });
    radios.find((b) => +b.dataset.h === lastPreset)?.focus();
  };
  el.querySelector('.ranges-seg').addEventListener('keydown', (e) => {
    const i = radios.indexOf(document.activeElement);
    if (i < 0) return;
    const n = radios.length;
    const j = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? (i + 1) % n
      : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? (i - 1 + n) % n
        : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1;
    if (j < 0) return;
    e.preventDefault();
    radios[j].focus();
    // selection follows focus like native radios; the view reloads once the keys stop
    choose({ h: +radios[j].dataset.h }, { delay: 250 });
  });
  paint();
  syncPhone();

  return {
    el,
    presets,
    get: () => value,
    // Show a value without calling onChange (a brush, a link, another control). Hours snap to this control's presets.
    set(v) { if (!v) return; choose(isCustom(v) ? { from: v.from, to: v.to } : { h: snap(v.h, presets) }, { fire: false }); },
    lastPreset: () => lastPreset,
    hide(on) { el.classList.toggle('ranges-off', !!on); el.toggleAttribute('inert', !!on); },
    destroy() { clearTimeout(kbTimer); offPhone(); mchip = null; el.innerHTML = ''; el.classList.remove('ranges', 'ranges-off'); },
  };
}

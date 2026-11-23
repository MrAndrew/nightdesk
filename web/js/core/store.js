// Global filter state shared by every panel: time range + the Ops deck's text filter (opsQ, from the global search).
const listeners = new Set();
// The Ops deck's time range is remembered across reloads (nd.range); every view keeps its own (core/range.js).
const RANGES = [1, 6, 24, 168, 720, 0];
const savedHours = () => { try { const h = JSON.parse(localStorage.getItem('nd.range')); return RANGES.includes(h) ? h : 24; } catch { return 24; } };
const state = { hours: savedHours(), opsQ: '' };

export const store = {
  get: () => ({ ...state }),
  // since_hours param for the API (undefined = all time)
  sinceHours: () => (state.hours > 0 ? state.hours : undefined),
  set(patch) {
    Object.assign(state, patch);
    if ('hours' in patch) { try { localStorage.setItem('nd.range', JSON.stringify(state.hours)); } catch {} }
    listeners.forEach((fn) => fn({ ...state }));
  },
  subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
};

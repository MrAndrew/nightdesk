// Display preferences kept in this browser (Settings › Display). Each reads safely when storage is blocked.

// A small JSON localStorage get/set, shared by the views that remember their own display state.
export const LS = {
  get(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
};

export const LANDINGS = [
  ['watch', 'Watch', 'The briefing: what changed since your last visit. Recommended.'],
  ['network', 'Network', 'Your own network: alerts, log search and devices.'],
  ['news', 'News', 'Security reporting grouped into stories.'],
  ['ops', 'Ops', 'Your dashboard of live panels.'],
  ['cinema', 'Cinema', 'The lean-back globe, for a wall screen.'],
];
const KEY = 'nd.landing';
export function landing() {
  try { const v = JSON.parse(localStorage.getItem(KEY)); return LANDINGS.some(([id]) => id === v) ? v : 'watch'; } catch { return 'watch'; }
}
export function setLanding(v) {
  try { localStorage.setItem(KEY, JSON.stringify(v)); } catch {}
}

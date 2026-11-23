// Settings sections registry. Each section is its own module in web/js/views/settings/<id>.js that calls
//   registerSettingsSection({ id, label, order, description?, mount(el, ctx) -> { show?, hide?, destroy? } | void })
// and is imported once from ./sections.js (one line). The Settings view lists sections by `order` and routes
// #settings/<id>[/<anchor>]; mount runs the first time the section is opened, with ctx = the view context
// ({ api, live, store, util, openEvent }) plus ctx.sub (the part after the id, e.g. 'choose'). show(sub) runs on
// every later visit. Contract: okf/architecture/web-client.md#settings
export const SECTIONS = new Map();

export function registerSettingsSection(def) {
  if (!def || !def.id || typeof def.mount !== 'function') throw new Error('registerSettingsSection needs {id, label, mount}');
  SECTIONS.set(def.id, { order: 50, ...def });
}
export const sections = () => [...SECTIONS.values()].sort((a, b) => a.order - b.order);

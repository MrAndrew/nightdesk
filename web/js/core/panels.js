// Panel and view registries. Contract: okf/architecture/web-client.md
import { isPhone } from './mobile.js';

export const PANELS = new Map();
export const VIEWS = new Map();

export function registerPanel(def) { PANELS.set(def.id, def); }
export function registerView(def) { VIEWS.set(def.id, def); }

// #ops?panel=<id> (v1.2 mobile, design.md §4.5): on a phone it is a pushed page (views/ops-phone.js); on a computer
// it maximises that panel of the current deck (the first one, when the deck has it twice). Closing the panel (its
// Close button or Esc) takes the address back to #ops without a history entry, so a reload does not reopen it.
const panelLink = () => {
  const m = location.hash.match(/^#\/?ops\?(?:[^#]*&)?panel=([^&#]+)/i);
  return m ? decodeURIComponent(m[1]) : null;
};
let tries = 0, timer = 0, watch = null;
function applyPanelLink() {
  clearTimeout(timer);
  const id = panelLink();
  if (!id || isPhone()) { tries = 0; return; }
  const items = [...document.querySelectorAll('#grid .grid-stack-item')];
  const base = (it) => (it.getAttribute('gs-id') || '').replace(/-\d+$/, '');
  const it = items.find((i) => i.gridstackNode?.panel === id) || items.find((i) => i.getAttribute('gs-id') === id || base(i) === id);
  const p = it?.querySelector('.panel');
  if (!p || document.body.dataset.view !== 'ops') {
    if (tries++ < 60) timer = setTimeout(applyPanelLink, 250);   // the deck mounts lazily on the first visit to Ops
    return;
  }
  tries = 0;
  if (!p.classList.contains('maximized')) p.querySelector('[data-act="max"]')?.click();
  if (!watch) {
    watch = new MutationObserver(() => {
      if (!panelLink() || isPhone() || document.querySelector('#grid .panel.maximized')) return;
      history.replaceState(history.state, '', location.hash.replace(/([?&])panel=[^&#]*&?/i, '$1').replace(/[?&]$/, ''));
    });
    watch.observe(document.getElementById('grid'), { subtree: true, attributes: true, attributeFilter: ['class'] });
  }
}
window.addEventListener('hashchange', applyPanelLink);
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', applyPanelLink, { once: true });
else setTimeout(applyPanelLink, 0);

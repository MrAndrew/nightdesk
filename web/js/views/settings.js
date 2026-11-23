// Settings view (#settings/<section>[/<anchor>]): one place for what Night Desk fetches, keeps and shows.
// Sections are separate modules registered through ./settings/registry.js (see that file for the contract) and
// listed in ./settings/sections.js. Opened from the gear menu, the feed-health dot and old #sources links.
// Contract: okf/architecture/web-client.md#settings
import { registerView } from '../core/panels.js';
import { sections, SECTIONS } from './settings/registry.js';
import { registerCommand } from '../core/commands.js';
import { viewHeader, errorState } from '../core/view.js';
import './settings/sections.js';
import { isPhone, onPhoneChange } from '../core/mobile.js';
import { pushPage, setPhoneTitle, afterRender, addParentRule } from '../core/page.js';
import { healthSplit } from './sources.js';

// a phone: Settings › Sources › Routing watch is a page of its own under Sources (design.md §4.8)
addParentRule(/^settings\/sources\/routing$/i, '#settings/sources');

// ⌘K: one command per section
for (const s of sections()) {
  registerCommand({ id: `settings.${s.id}`, label: `Settings: ${s.label}`, group: 'Settings', keywords: s.id === 'sources' ? 'feeds pipeline' : '',
    order: 30 + s.order / 100, run: () => { location.hash = `#settings/${s.id}`; } });
}

const route = () => {
  const [v, id = '', ...rest] = location.hash.replace(/^#\/?/, '').split('/');
  return v === 'settings' ? { id: decodeURIComponent(id), sub: rest.join('/') } : null;
};

let inst = null;

registerView({
  id: 'settings',
  mount(el, ctx) {
    const { esc } = ctx.util;
    const list = sections();
    el.innerHTML = `${viewHeader({ title: 'Settings', cls: 'set-head', purpose: 'What Night Desk fetches, keeps and shows. Settings stay on this machine; only notifications you turn on leave it' })}
      <div class="set-wrap">
      <div class="set-body">
        <nav class="set-nav" aria-label="Settings sections">${list.map((s) => `<a class="set-nav-a" href="#settings/${esc(s.id)}" data-sec="${esc(s.id)}"><span class="set-m-l">${esc(s.label)}</span><span class="set-m-val" hidden></span><span class="set-m-chev" aria-hidden="true" hidden><svg class="i"><use href="#i-caret-r"/></svg></span></a>`).join('')}</nav>
        <div class="set-main">${list.map((s) => `<section class="set-sec" data-sec="${esc(s.id)}" aria-labelledby="set-h-${esc(s.id)}" hidden>
          <header class="set-sec-h"><h2 class="set-h2" id="set-h-${esc(s.id)}" tabindex="-1">${esc(s.label)}</h2>${s.description ? `<p class="set-sec-d">${esc(s.description)}</p>` : ''}</header>
          <div class="set-sec-b"></div></section>`).join('')}</div>
      </div></div>`;
    const mounted = new Map();   // id -> instance
    let cur = null;

    // On a phone (design.md §4.8) #settings is the list of sections (52 px rows with a chevron) and each section is a
    // pushed page, #settings/<id>, with ‹ Settings in the top bar. On a computer the list is the side nav, as before.
    const phoneMode = (id, sub = '') => {
      const phone = isPhone();
      const rw = phone && id === 'sources' && sub === 'routing';   // Routing watch: a page of its own under Sources
      el.classList.toggle('set-m-list', phone && !id);
      el.classList.toggle('set-m-page', phone && !!id);
      el.classList.toggle('set-m-routing', rw);
      if (rw) setPhoneTitle('Routing watch', { back: { label: 'Sources', href: '#settings/sources' } });
      else if (phone && id) setPhoneTitle(SECTIONS.get(id)?.label || 'Settings', { back: { label: 'Settings', href: '#settings' } });
      else if (phone) { setPhoneTitle(null); fillValues(); }
    };
    function select(id, sub = '', { focus = false } = {}) {
      if (!SECTIONS.has(id)) {
        // an unknown section (#settings/nope) opens the first one, and the URL says #settings (no extra history entry)
        if (id && route()) history.replaceState(null, '', '#settings');
        id = isPhone() ? '' : list[0]?.id;
      }
      phoneMode(id, sub);
      if (!id) { if (cur) { try { mounted.get(cur)?.hide?.(); } catch (e) { console.error(e); } } cur = null; el.querySelectorAll('.set-nav-a').forEach((a) => { a.classList.remove('on'); a.removeAttribute('aria-current'); }); afterRender('settings'); return; }
      const def = SECTIONS.get(id);
      if (cur && cur !== id) { try { mounted.get(cur)?.hide?.(); } catch (e) { console.error(e); } }
      el.querySelectorAll('.set-nav-a').forEach((a) => {
        const on = a.dataset.sec === id;
        a.classList.toggle('on', on);
        if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
      });
      el.querySelectorAll('.set-sec').forEach((s) => (s.hidden = s.dataset.sec !== id));
      const sec = el.querySelector(`.set-sec[data-sec="${CSS.escape(id)}"]`);
      try {
        if (!mounted.has(id)) mounted.set(id, def.mount(sec.querySelector('.set-sec-b'), { ...ctx, sub }) || {});
        else mounted.get(id).show?.(sub);
      } catch (err) {
        console.error(err);
        mounted.delete(id);
        sec.querySelector('.set-sec-b').innerHTML = errorState({ retry: () => location.reload(), retryLabel: 'Reload the page', title: 'This section did not open', why: 'Reload the page to try again. Other sections still work.', err: err.message, size: 'sm' });
      }
      const changed = cur !== id;
      cur = id;
      if (changed) el.scrollTop = 0;
      if (focus) sec.querySelector('.set-h2').focus({ preventScroll: true });
      if (!isPhone()) el.querySelector('.set-nav-a.on')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      afterRender('settings');
    }
    // the value beside a row: the sources that need a look (errors, paused or off)
    let filling = false;
    async function fillValues() {
      if (filling) return;
      filling = true;
      try {
        const rows = await ctx.api.sources();
        // the Sources panel's own split (views/sources.js healthSplit), so the row and the panel agree: an error or a
        // reconnecting stream is an error, offline mode or the routing watch's data limit is "paused"; a routing
        // source that waits for a network to watch is neither
        const b = healthSplit(rows);
        const waiting = rows.filter((s) => s.needs === 'watchlist').length;
        const words = [b.error && `${b.error} with errors`, b.paused && `${b.paused} paused`, waiting && `${waiting} waiting`].filter(Boolean);
        const v = el.querySelector('.set-nav-a[data-sec="sources"] .set-m-val');
        if (v) {
          v.textContent = words.length ? words.join(' · ') : `${b.live + b.ok} on`;
          v.title = waiting ? `${waiting} routing source${waiting === 1 ? '' : 's'} waiting for a network to watch` : '';
          v.hidden = false; v.classList.toggle('bad', !!b.error);
        }
      } catch { /* the row still opens the section */ } finally { filling = false; }
    }

    el.querySelector('.set-nav').addEventListener('click', (e) => {
      const a = e.target.closest('.set-nav-a');
      if (!a) return;
      e.preventDefault();
      if (route()?.id === a.dataset.sec) return;
      if (isPhone()) { pushPage(`#settings/${a.dataset.sec}`); return; }   // a page of its own; the hashchange selects it
      history.pushState(null, '', `#settings/${a.dataset.sec}`);
      select(a.dataset.sec, '', { focus: true });
    });
    window.addEventListener('hashchange', () => {
      const r = route();
      if (r && el.classList.contains('active')) select(r.id, r.sub);
    });
    onPhoneChange(() => { if (el.classList.contains('active')) inst.show(); else { el.classList.remove('set-m-list', 'set-m-page', 'set-m-routing'); } });
    inst = { show() { const r = route() || { id: '', sub: '' }; select(r.id, r.sub); } };
    return inst;
  },
  show() { inst?.show(); },
});

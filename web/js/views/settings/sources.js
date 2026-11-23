// Settings › Sources: the first-run "Choose your sources" step (a new lake only, once), then the feed catalog and
// local pipeline (views/sources.js). Feed terms and defaults: GET/POST /api/settings/sources-choice
// (osinthub/feed_terms.py, policy in okf/project/distribution.md, "Feed terms").
import { registerSettingsSection } from './registry.js';
import { confirmSheet } from '../../core/sheet.js';
import { mountSources } from '../sources.js';
import { mountRouting } from './routing.js';
import { safeUrl } from '../../core/util.js';
import { isPhone } from '../../core/mobile.js';
import { pushPage } from '../../core/page.js';

registerSettingsSection({
  id: 'sources',
  label: 'Sources',
  order: 10,
  description: 'The public lists and news Night Desk collects for you, and whether each one is working.',
  mount(el, ctx) {
    const { api, util } = ctx;
    const { esc, toast } = util;
    // a phone shows Routing watch as one row here and as its own page, #settings/sources/routing (m-desk); the row is
    // hidden everywhere else
    el.innerHTML = `<div class="set-choose-slot"></div>
      <a class="set-m-rwrow" href="#settings/sources/routing" hidden><span class="set-m-rwt"><b>Routing watch</b><small>Who announces the networks you rely on</small></span><span class="set-m-val"></span><span class="set-m-chev" aria-hidden="true"><svg class="i"><use href="#i-caret-r"/></svg></span></a>
      <div class="set-routing-slot"></div><div class="set-src"></div>`;
    const rwRow = el.querySelector('.set-m-rwrow');
    rwRow.addEventListener('click', (e) => { if (!isPhone()) return; e.preventDefault(); pushPage('#settings/sources/routing'); });
    const rwCount = async () => {
      if (!isPhone()) return;
      try {
        const n = ((await api.get('/api/routing/watches')).cards || []).length;
        rwRow.querySelector('.set-m-val').textContent = n ? `${n} network${n === 1 ? '' : 's'}` : 'No networks yet';
      } catch { /* the row still opens the page */ }
    };
    rwCount();
    const slot = el.querySelector('.set-choose-slot');
    const routing = mountRouting(el.querySelector('.set-routing-slot'), ctx);   // #settings/sources/routing
    const catalog = mountSources(el.querySelector('.set-src'), ctx);
    let data = null, review = false;

    // A saved answer (a Yes in Routing watch, an earlier Apply, a hand toggle) is shown as it is, so "Use the ticked
    // sources" keeps it; with no saved answer the row starts from the feed policy's default.
    const ticked = (s, off) => (s.saved ? !!s.enabled && !off : s.local_default === 'on' && !s.unavailable);
    const row = (s) => {
      const url = safeUrl(s.terms_url);
      // a Routing watch source waiting only for a network to watch can be chosen now (the answer is saved and it
      // runs once a network is watched); one that needs a key cannot
      const waits = !!s.unavailable && s.needs === 'watchlist';
      const off = !!s.unavailable && !waits;
      return `<label class="set-ch-row${off ? ' off' : ''}">
        <input type="checkbox" value="${esc(s.id)}"${ticked(s, off) ? ` checked data-shown="${esc(s.id)}"` : ''}${off ? ' disabled' : ''}>
        <span class="set-ch-b"><span class="set-ch-n">${esc(s.name)}${s.badge ? ` <span class="tag amber set-ch-badge">${esc(s.badge)}</span>` : ''}${s.unavailable ? ` <span class="tag">${waits ? 'runs once a network is watched' : 'needs a key'}</span>` : ''}</span>
          <span class="set-ch-g">${esc(s.gives)}</span>
          <span class="set-ch-t">${esc(s.terms)}${url ? ` <a href="${esc(url)}" target="_blank" rel="noopener noreferrer">Read the terms</a>` : ''}</span></span></label>`;
    };

    function paint() {
      const show = data && (data.state === 'pending' || review);
      if (!show) {
        slot.innerHTML = data ? '<p class="set-ch-again"><button class="watch-btnlink set-linkbtn" data-ch="review">Review every source’s terms and choose again</button></p>' : '';
        return;
      }
      // the security-news outlets (news_<outlet>) share one row and one toggle; their names are listed under it
      const isOutlet = (s) => s.id.startsWith('news_');
      const outlets = data.sources.filter(isOutlet);
      const solo = data.sources.filter((s) => !isOutlet(s));
      const outletsOn = outlets.length && outlets[0].local_default === 'on';
      const on = solo.filter((s) => s.local_default === 'on');
      const ask = solo.filter((s) => s.local_default !== 'on');
      // the group row shows the outlets as they are: ticked when all are on, unticked when none is, a dash
      // (indeterminate) when only some are; data-shown lists the ones that were on when it was drawn
      const outletTicks = outlets.filter((s) => ticked(s, false)).map((s) => s.id);
      const grpAll = outlets.length > 0 && outletTicks.length === outlets.length;
      const grpSome = outletTicks.length > 0 && !grpAll;
      const group = outlets.length ? `<div class="set-ch-row set-ch-grp">
        <input type="checkbox" id="set-ch-news" value="group:news" data-ids="${esc(outlets.map((s) => s.id).join(','))}"${grpAll ? ' checked' : ''}${outletTicks.length ? ` data-shown="${esc(outletTicks.join(','))}"` : ''}${grpSome ? ' data-mixed="1"' : ''}>
        <span class="set-ch-b"><label class="set-ch-n" for="set-ch-news">News outlets (${outlets.length})</label>
          <span class="set-ch-g">${esc(outlets[0].gives.replace('this outlet', 'each outlet'))}</span>
          <span class="set-ch-t">${esc(outlets[0].terms)}</span>
          <details class="set-ch-more"><summary>Show the ${outlets.length} outlets</summary><span class="set-ch-t">${esc(outlets.map((s) => s.name).join(' · '))}</span></details></span></div>` : '';
      slot.innerHTML = `<section class="set-choose" id="set-choose" aria-labelledby="set-choose-h">
        <h3 class="set-h3" id="set-choose-h" tabindex="-1">${review ? 'Choose your sources' : 'Choose your sources (one-time step)'}</h3>
        <p class="set-p">Night Desk fetches public sources for you, straight from each publisher. Sources with open terms are ticked. The rest are free for personal use only, or their terms are unclear, so they stay off until you tick them. You can change any of this later in the list below.</p>
        <div class="set-ch-g-h">Open terms <span>· on unless you untick them</span></div>
        <div class="set-ch-list">${on.map(row).join('')}${outletsOn ? group : ''}</div>
        <div class="set-ch-g-h">Your call <span>· off until you tick them</span></div>
        <div class="set-ch-list">${ask.map(row).join('')}${outletsOn ? '' : group}</div>
        <div class="set-ch-act">
          <button class="src-btn primary" data-ch="apply">Use the ticked sources</button>
          <button class="src-btn" data-ch="all">Tick every personal-use source…</button>
          <button class="src-btn" data-ch="keep">${review ? 'Cancel' : 'Keep the current settings'}</button>
        </div></section>`;
      slot.querySelectorAll('input[data-mixed]').forEach((i) => { i.indeterminate = true; });
    }

    async function load() {
      try { data = await api.get('/api/settings/sources-choice'); } catch { data = null; }
      if (ctx.sub === 'choose' && data && data.state !== 'pending') review = true;   // a link to the step after it was done
      paint();
      if (ctx.sub === 'choose') { focusChooser(); ctx.sub = ''; }
      if (ctx.sub === 'routing') { routing.focus(); ctx.sub = ''; }
    }
    function focusChooser() {
      const c = slot.querySelector('#set-choose');
      if (!c) return;
      c.scrollIntoView({ block: 'start' });
      c.querySelector('#set-choose-h')?.focus({ preventScroll: true });
    }

    slot.addEventListener('click', async (e) => {
      const b = e.target.closest('[data-ch]');
      if (!b) return;
      const act = b.dataset.ch;
      if (act === 'review') { review = true; paint(); focusChooser(); return; }
      if (act === 'all') {
        const boxes = [...slot.querySelectorAll('input[type=checkbox]:not(:disabled):not(:checked)')];
        if (!boxes.length) { toast('Every available source is already ticked'); return; }
        const names = boxes.map((i) => (i.value === 'group:news' ? slot.querySelector('label[for="set-ch-news"]').textContent : data.sources.find((s) => s.id === i.value)?.name || i.value));
        if (!(await confirmSheet({ title: `Tick these ${names.length} sources?`, text: `Most are for personal, non-commercial use only: ${names.join(', ')}.`, confirm: 'Tick them' }))) return;
        boxes.forEach((i) => { i.checked = true; i.indeterminate = false; });
        return;
      }
      b.disabled = true;
      try {
        if (act === 'keep') {
          if (review) { review = false; paint(); return; }
          await api.post('/api/settings/sources-choice', { keep: true });
          toast('Kept the current sources');
        } else if (act === 'apply') {
          const ids = (i) => (i.dataset.ids ? i.dataset.ids.split(',') : [i.value]);
          const boxes = [...slot.querySelectorAll('input[type=checkbox]')];
          const was = (i) => (i.dataset.shown ? i.dataset.shown.split(',') : []);
          // a row still showing its dash was not touched: it asks for exactly the outlets that were on
          const enable = boxes.flatMap((i) => (i.indeterminate ? was(i) : i.checked ? ids(i) : []));
          // `shown`: what each row showed when the box was drawn. The server changes only rows the user changed here,
          // so a choice made elsewhere since (a Yes in Routing watch) is never undone by a stale box.
          const shown = boxes.flatMap(was);
          const r = await api.post('/api/settings/sources-choice', { enable, shown });
          toast(`Saved: ${enable.length} source${enable.length === 1 ? '' : 's'} on${r.changed?.length ? `, ${r.changed.length} changed` : ''}`);
        }
        review = false;
        await load();
        catalog.reload?.();
        routing.reload?.();
      } catch (err) { toast(err.message, true); b.disabled = false; }
    });

    load();
    return {
      show(sub) {
        ctx.sub = sub;
        if (sub !== 'routing') rwCount();
        if (sub === 'choose') { if (data?.state !== 'pending') review = true; paint(); focusChooser(); }
        else if (sub === 'routing') { routing.reload(); routing.focus(); }
      },
      destroy() { catalog.destroy?.(); routing.destroy?.(); },
    };
  },
});

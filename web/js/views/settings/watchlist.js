// Settings › What you follow (#settings/follow): the one followed list (My stack, osinthub/stack.py, /api/stack).
// Products and vendors you run, groups, malware and other entities, and plain words. A picker suggests vendors and
// products from CISA KEV, CISA advisories, NVD vendors and common home-lab gear; "What do you run?" chips add the
// usual home-lab kit in one click. Everything here edits the same list as the News rail and the Follow buttons.
import { registerSettingsSection } from './registry.js';
import * as stack from '../../core/stack.js';
import { errorState } from '../../core/view.js';

const TYPE_LABEL = { actor: 'Group', malware: 'Malware', tool: 'Tool', campaign: 'Campaign', cve: 'CVE', asn: 'Network (ASN)', domain: 'Domain',
  ip: 'Address', url: 'Link', hash: 'File', vendor: 'Vendor', product: 'Product', org: 'Organisation' };

registerSettingsSection({
  id: 'follow',
  label: 'What you follow',
  order: 15,
  description: 'The products you run and the groups and words you care about. Their exploited bugs, news and network alerts come first on Watch.',
  mount(el, ctx) {
    const { api, util } = ctx;
    const { esc, toast, debounce } = util;
    let W = null, quick = null, sugg = [], sIdx = -1;
    el.innerHTML = `
      <div class="set-card">
        <h3 class="set-h3">What do you run?</h3>
        <p class="set-p">One click follows it, a second click stops. “Exploited” counts its bugs on CISA’s list of vulnerabilities attackers are using.</p>
        <div class="stack-quick" role="group" aria-label="Common home-lab gear"></div>
      </div>
      <div class="set-card">
        <h3 class="set-h3"><label for="stack-in">Follow something else</label></h3>
        <p class="set-p">A vendor or product (“Synology DSM”, “Ubiquiti UniFi”), a group or malware (“QakBot”), a CVE, a network or domain, or any word.</p>
        <div class="stack-add">
          <input id="stack-in" class="src-input" placeholder="Type a product, group or word…" autocomplete="off" spellcheck="false"
            role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="stack-sugg">
          <ul id="stack-sugg" class="stack-sugg" role="listbox" hidden></ul>
        </div>
      </div>
      <div class="set-card">
        <h3 class="set-h3">You follow <span class="set-dim stack-n"></span></h3>
        <div class="stack-lists"><p class="set-dim">Loading…</p></div>
        <p class="set-p set-dim">Where it shows: Watch (“Touches you” and “News you follow”), the exploited-bugs list (“You follow …”), story headers and the News watchlist.</p>
      </div>`;
    const $ = (s) => el.querySelector(s);
    const input = $('#stack-in'), list = $('#stack-sugg');

    function paintQuick() {
      const box = $('.stack-quick');
      if (!quick) { box.innerHTML = '<p class="set-dim">Loading…</p>'; return; }
      box.innerHTML = quick.length
        ? quick.map((q) => stack.followButton({ vendor: q.vendor, product: q.product }, { name: q.label, cls: 'chip stack-chip', chip: q.kev ? `${q.kev} exploited` : '' })).join('')
        : '<p class="set-dim">You follow all the usual kit. Add anything else below.</p>';
    }
    function row(key, name, meta, href) {
      return `<li class="stack-item"><span class="stack-item-n">${href ? `<a href="${esc(href)}">${esc(name)}</a>` : esc(name)}</span>
        ${meta ? `<span class="stack-item-m">${meta}</span>` : ''}
        <button class="icon-btn stack-rm" data-rm="${esc(key)}" aria-label="Stop following ${esc(name)}" title="Stop following"><svg class="i"><use href="#i-x"/></svg></button></li>`;
    }
    function paintLists() {
      const box = $('.stack-lists');
      if (!W) return;
      $('.stack-n').textContent = W.count ? `· ${W.count}` : '';
      if (!W.count) { box.innerHTML = '<p class="set-p">Nothing yet. Pick what you run above, or type a name.</p>'; return; }
      const kc = W.kev_counts || {};
      const grp = (title, items) => (items.length ? `<div class="stack-grp"><div class="label">${esc(title)}</div><ul class="stack-ul">${items.join('')}</ul></div>` : '');
      const prods = (W.stack || []).map((x) => {
        const lb = stack.stackLabel(x), n = kc[`stack:${lb}`] || 0;
        return row(`stack:${lb}`, lb, n ? `${n} exploited bug${n === 1 ? '' : 's'}` : 'no exploited bugs listed', null);
      });
      const ents = (W.entities || []).map((id) => {
        const t = id.split(':')[0], n = kc[id] || 0;
        return row(id, W.names?.[id] || id.split(':').slice(1).join(':'), `${esc(TYPE_LABEL[t] || t)}${n ? ` · ${n} exploited bug${n === 1 ? '' : 's'}` : ''}`, `#entities/${encodeURIComponent(id)}`);
      });
      const words = (W.keywords || []).map((k) => row(`keyword:${k}`, `“${k}”`, 'word', null));
      box.innerHTML = grp('Products and vendors', prods) + grp('Groups, malware and other things', ents) + grp('Words', words);
    }

    async function load() {
      try {
        // the chips are read once per visit, so a followed one stays (marked followed) instead of vanishing
        const [w, q] = await Promise.all([api.get('/api/stack', { counts: true }), quick ? null : api.get('/api/stack/quick', { limit: 14 })]);
        W = w; if (q) quick = q.items || [];
      } catch (e) { $('.stack-lists').innerHTML = errorState({ retry: load, title: "Couldn't read what you follow", why: 'The Night Desk server did not answer.', err: e.message, size: 'sm' }); return; }
      paintQuick(); paintLists();
    }

    function paintSugg() {
      const q = input.value.trim();
      if (!q) { list.hidden = true; input.setAttribute('aria-expanded', 'false'); return; }
      const opts = [...sugg, { kind: 'word', label: q }];
      list.innerHTML = opts.map((o, i) => `<li role="option" id="stack-o${i}" class="stack-opt${i === sIdx ? ' on' : ''}" aria-selected="${i === sIdx}" data-i="${i}">
        ${o.kind === 'stack' ? `<b>${esc(o.label)}</b><small>you run it${o.kev ? ` · ${esc(o.kev)} exploited` : ''}</small>`
          : o.kind === 'entity' ? `<b>${esc(o.label)}</b><small>${esc(TYPE_LABEL[o.type] || o.type)}</small>`
            : `<b>“${esc(o.label)}”</b><small>follow as a word</small>`}</li>`).join('');
      list.hidden = false;
      input.setAttribute('aria-expanded', 'true');
      if (sIdx >= 0) input.setAttribute('aria-activedescendant', `stack-o${sIdx}`); else input.removeAttribute('aria-activedescendant');
    }
    const search = debounce(async () => {
      const q = input.value.trim();
      sIdx = -1;
      if (q.length < 2) { sugg = []; paintSugg(); return; }
      const [s, e] = await Promise.all([api.get('/api/stack/suggest', { q, limit: 6 }).catch(() => ({ items: [] })),
        api.get('/api/entities', { q, limit: 8 }).catch(() => ({ items: [] }))]);
      if (input.value.trim() !== q) return;
      sugg = [...(s.items || []).map((x) => ({ kind: 'stack', label: x.label, vendor: x.vendor, product: x.product, kev: x.kev })),
        ...(e.items || []).filter((x) => ['actor', 'malware', 'tool', 'campaign', 'cve', 'asn', 'domain', 'org'].includes(x.type)).slice(0, 5)
          .map((x) => ({ kind: 'entity', label: x.name, id: x.id, type: x.type }))];
      paintSugg();
    }, 200);

    async function pick(i) {
      const q = input.value.trim();
      // Enter with nothing highlighted: an exact name among the suggestions is that suggestion, not a plain word
      if (i < 0) i = sugg.findIndex((x) => x.label.toLowerCase() === q.toLowerCase());
      const o = i >= 0 && i < sugg.length ? sugg[i] : null;
      if (!o && !q) return;
      try {
        let r;
        if (!o) r = await stack.follow(/^cve-\d{4}-\d+$/i.test(q) ? { entity: `cve:${q.toLowerCase()}` } : { keyword: q });
        else if (o.kind === 'stack') r = await stack.follow({ vendor: o.vendor, product: o.product });
        else r = await stack.follow({ entity: o.id });
        const name = o ? o.label : q;
        toast(!r.added ? `You already follow ${name}` : r.kev ? `Following ${name}: ${r.kev} exploited bug${r.kev === 1 ? '' : 's'} match` : `Following ${name}`);
      } catch (e) { toast(e.message, true); return; }
      input.value = ''; sugg = []; paintSugg();
    }

    input.addEventListener('input', search);
    // phones: bring the field near the top so the suggestions are not under the bottom bar or the keyboard
    input.addEventListener('focus', () => { if (innerWidth < 640) setTimeout(() => input.scrollIntoView({ block: 'start', behavior: 'auto' }), 250); });
    input.addEventListener('keydown', (e) => {
      const n = sugg.length + 1;
      if (e.key === 'ArrowDown') { sIdx = Math.min(n - 1, sIdx + 1); paintSugg(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { sIdx = Math.max(-1, sIdx - 1); paintSugg(); e.preventDefault(); }
      else if (e.key === 'Enter') { e.preventDefault(); pick(sIdx); }
      else if (e.key === 'Escape') { list.hidden = true; input.setAttribute('aria-expanded', 'false'); }
    });
    list.addEventListener('mousedown', (e) => { const o = e.target.closest('[data-i]'); if (o) { e.preventDefault(); pick(+o.dataset.i); } });
    input.addEventListener('blur', () => setTimeout(() => { list.hidden = true; input.setAttribute('aria-expanded', 'false'); }, 150));

    el.addEventListener('click', async (e) => {
      const rm = e.target.closest('[data-rm]');
      if (rm) {
        rm.disabled = true;
        try { await stack.unfollow({ key: rm.dataset.rm }); toast('Stopped following'); }
        catch (err) { rm.disabled = false; toast(err.message, true); }
      }
    });
    // the list changed here or anywhere else (a Follow button, the News rail): repaint
    window.addEventListener('nd:stack', () => { if (el.isConnected) load(); });
    load();
    return { show() { quick = null; load(); } };
  },
});

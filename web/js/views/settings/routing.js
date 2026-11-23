// Settings › Sources › Routing watch (#settings/sources/routing): the networks to watch (presets and typed ASNs or
// prefixes, validated as typed), one card per watch, the two settings (Check every, Daily data limit) and the four
// routing sources (RPKI file, Cloudflare Radar with its token, RIPEstat opt-in, RIS Live under Advanced).
// API: /api/routing (osinthub/routing/api.py). Design: okf/project/routing-watch.md
import { errorState, loadingState } from '../../core/view.js';

const STATE = {
  normal: ['ok', 'Normal'], changed: ['chg', 'Changed'], unchecked: ['bad', 'Couldn’t check'], pending: ['wait', 'Checking…'],
};
const SRC = {
  rpki_roas: { title: 'RPKI signed routes', what: 'Who may announce each watched network, from a public daily file (about 5 MB, downloaded only when it changed). It is checked on this computer, so nobody learns what you watch.', note: 'The publishers (Cloudflare, rpki-client) state no terms.' },
  cf_radar_bgp: { title: 'Cloudflare Radar', what: 'Suspected hijacks and route leaks worldwide. Night Desk lists them all and picks out the ones that involve your networks here, so Cloudflare does not learn what you watch.', note: 'Data from Cloudflare Radar, CC BY-NC 4.0: personal, non-commercial use.' },
  ripestat: { title: 'RIPEstat lookups', what: 'Who announces each watched network, how widely it is seen, its upstream networks and how busy its routes are. Two or three lookups per network per check.', privacy: 'RIPE will see which networks you look up.', note: 'RIPEstat terms: no redistribution or commercial use.' },
  ris_live: { title: 'RIS Live (live updates)', what: 'Live routing updates for your watched networks only, within seconds. Uses about 70 MB a day per watched AS, counted against the daily limit.', privacy: 'RIPE will see which networks you follow.', note: 'RIPE NCC terms.' },
};
const LIMITS = [10, 25, 50, 100, 250, 500, 1000];
const CHECK_WORD = { ok: 'ok', failed: 'couldn’t check', stale: 'not recent', pending: 'checking…' };

function mb(b) {
  if (!b) return '0 MB';
  if (b < 100_000) return `${Math.max(1, Math.round(b / 1000))} KB`;
  return `${(b / 1e6).toFixed(b < 10e6 ? 1 : 0)} MB`;
}

export function mountRouting(el, ctx) {
  const { api, util, live } = ctx;
  const { esc, toast, ago, debounce } = util;
  let D = null, cards = null, loadErr = null, typed = null, vSeq = 0;

  el.innerHTML = `<section class="rw" id="rw" aria-labelledby="rw-h">
      <h3 class="set-h3 rw-h" id="rw-h" tabindex="-1">Routing watch</h3>
      <p class="set-p">See how the internet reaches the networks you rely on: who announces them, whether they are signed, and whether they go missing. Nothing is checked, and nothing is downloaded, until you add a network.</p>
      <div class="rw-body">${loadingState('Loading your routing watch…', { size: 'sm' })}</div>
    </section>`;
  const body = el.querySelector('.rw-body');

  const stateOf = (c) => STATE[c.state] || STATE.unchecked;
  const evTag = (e) => (e.cleared ? '<span class="tag">Cleared</span>' : e.level === 'needs_you' ? '<span class="tag red">Needs you</span>' : '<span class="tag amber">Information</span>');

  function cardHtml(c) {
    const [cls, word] = stateOf(c);
    const evs = (c.events || []).slice(0, 3);
    return `<li class="rw-card rw-${cls}${c.needs_you ? ' rw-flag' : ''}" data-id="${esc(c.id)}">
      <div class="rw-c-top">
        <span class="rw-dot" aria-hidden="true"></span>
        <div class="rw-c-t"><h4 class="rw-c-n">${esc(c.label)}</h4><span class="rw-c-id mono">${esc(c.id)}</span></div>
        <span class="rw-badge">${esc(c.needs_you ? 'Needs you' : word)}</span>
        <button class="icon-btn rw-rm" data-rm="${esc(c.id)}" aria-label="Stop watching ${esc(c.label)}" title="Stop watching"><svg class="i"><use href="#i-x"/></svg></button>
      </div>
      <p class="rw-c-s">${esc(c.sentence)}</p>
      <p class="rw-c-m">${c.last_checked ? `Last checked <span data-ago="${esc(c.last_checked)}">${esc(ago(c.last_checked))}</span>` : 'Not checked yet'}</p>
      ${(c.checks || []).length ? `<p class="rw-c-src">${c.checks.map((k) => `<span class="rw-k-${esc(k.state)}"${k.why ? ` title="${esc(k.why)}"` : ''}>${esc(k.name)}: ${esc(CHECK_WORD[k.state] || k.state)}</span>`).join('<span aria-hidden="true"> · </span>')}</p>` : ''}
      ${evs.length ? `<ul class="rw-evs" aria-label="Recent events for ${esc(c.label)}">${evs.map((e) => `<li class="rw-ev" title="${esc(e.summary || '')}">${evTag(e)}<span class="rw-ev-t">${esc(e.short || e.title)}</span><span class="rw-ev-w mono">${esc(ago(e.opened))}</span></li>`).join('')}</ul>` : ''}
    </li>`;
  }

  function srcHtml(s, wl) {
    const t = SRC[s.id] || { title: s.name, what: '' };
    // a source can be turned on or off before the first network is added (the choice is kept until then);
    // only Radar without its token cannot be turned on
    const needsToken = s.id === 'cf_radar_bgp' && !s.token;
    const disabled = needsToken;
    const why = needsToken ? 'Add your Cloudflare token first' : '';
    const on = s.enabled && !disabled;
    const status = needsToken ? 'Needs your token'
      : !s.enabled ? ((D.ask || []).includes(s.id) ? 'Off until you answer above' : 'Off')
      : !wl.length ? 'On: starts with the first network you watch'
      : s.status === 'paused' ? 'Paused (daily data limit)'
      : s.status === 'offline' ? 'Paused (offline mode)'
      : s.status === 'error' || s.status === 'reconnecting' ? `Problem: ${s.message || 'the last check failed'}`
      : s.status === 'live' ? 'Connected'
      : s.last_ok ? `Last check ${ago(s.last_ok)}` : 'On; first check soon';
    const use = `Used today: ${mb(s.used_today)}${s.id === 'ripestat' && s.requests_today ? ` · ${s.requests_today} lookups` : ''}`;
    const token = s.id === 'cf_radar_bgp' ? (s.token === 'env' ? '<p class="rw-s-n" title="The CLOUDFLARE_RADAR_TOKEN setting">Token set in the environment that starts Night Desk.</p>'
      : s.token ? '<div class="rw-tok"><span class="rw-s-n">Token saved on this computer (never shown again).</span><button class="src-btn" data-tok="remove">Remove token</button></div>'
        : `<form class="rw-tok" data-tokform>
            <label class="rw-lab" for="rw-tok-in">Cloudflare API token</label>
            <input id="rw-tok-in" class="src-input mono" type="password" autocomplete="off" spellcheck="false" placeholder="Paste a token with Radar read access">
            <button class="src-btn" type="submit">Save token</button>
            <p class="rw-s-n">Free: create one at <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener noreferrer">dash.cloudflare.com</a> with the “Account › Radar › Read” permission.</p>
          </form>`) : '';
    return `<div class="rw-src${on ? ' on' : ''}" data-src="${esc(s.id)}">
      <div class="rw-s-top">
        <span class="rw-s-n1">${esc(t.title)}</span>
        <label class="src-toggle" title="${esc(why || (on ? 'Turn off' : 'Turn on'))}">
          <input type="checkbox" data-src-toggle="${esc(s.id)}"${on ? ' checked' : ''}${disabled ? ' disabled' : ''} aria-label="${esc(t.title)}${why ? ` (${why})` : ''}"><span class="src-sw"></span><span class="mono">${on ? 'On' : 'Off'}</span>
        </label>
      </div>
      <p class="rw-s-w">${esc(t.what)}</p>
      ${t.privacy ? `<p class="rw-s-p"><b>${esc(t.privacy)}</b></p>` : ''}
      ${token}
      <p class="rw-s-st"><span>${esc(status)}</span><span class="mono">${esc(use)}</span></p>
      <p class="rw-s-n">${esc(t.note || '')}</p>
    </div>`;
  }

  function paint() {
    if (!D) {
      body.innerHTML = loadErr ? errorState({ retry: load, title: 'Couldn’t load the routing watch', why: 'The Night Desk server did not answer.', err: loadErr, size: 'sm' }) : loadingState('Loading your routing watch…', { size: 'sm' });
      return;
    }
    const wl = D.watchlist || [];
    const used = D.usage?.total || 0, lim = D.usage?.limit_bytes || 1;
    const every = D.settings.every;
    const choices = D.every_choices || [];
    const radio = (c) => `<label class="rw-opt"><input type="radio" name="rw-every" value="${c.value}"${c.value === every ? ' checked' : ''}${wl.length ? '' : ''}><span>${esc(c.label)}</span></label>`;
    const srcs = D.sources || [];
    const limits = [...new Set([...LIMITS, D.settings.limit_mb])].sort((a, b) => a - b);
    const pct = Math.min(100, Math.round((100 * used) / lim));
    const refocus = focusKey(document.activeElement);
    body.innerHTML = `
      ${D.paused ? `<p class="rw-banner" role="status">${esc(D.paused)}</p>` : ''}
      <div class="rw-add-w">
        <h4 class="rw-h4">Add a network <span class="set-dim">· ${wl.length} of ${D.max}</span></h4>
        <div class="rw-presets" role="group" aria-label="Popular services: one tap adds or removes">
          ${(D.presets || []).map((p) => `<button class="chip rw-preset${p.added ? ' on' : ''}" aria-pressed="${p.added ? 'true' : 'false'}" data-preset="${esc(p.value)}" data-label="${esc(p.label)}">${p.added ? '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>' : '<svg class="i" aria-hidden="true"><use href="#i-plus"/></svg>'}${esc(p.label)} <span class="rw-p-id">${esc(p.value)}</span></button>`).join('')}
        </div>
        <form class="rw-add" novalidate>
          <div class="rw-f"><label class="rw-lab" for="rw-in">AS number or network</label>
            <input id="rw-in" class="src-input mono" placeholder="AS13335 or 1.1.1.0/24" autocomplete="off" spellcheck="false" aria-describedby="rw-msg"></div>
          <div class="rw-f"><label class="rw-lab" for="rw-lb">Name (optional)</label>
            <input id="rw-lb" class="src-input" placeholder="e.g. My provider" maxlength="60" autocomplete="off"></div>
          <button class="src-btn primary rw-go" type="submit"${wl.length >= D.max ? ' disabled' : ''}>Watch</button>
        </form>
        <p class="rw-msg" id="rw-msg" aria-live="polite"></p>
      </div>
      ${askHtml()}
      <h4 class="rw-h4">Your networks</h4>
      ${wl.length ? (cards ? `<ul class="rw-cards">${cards.map(cardHtml).join('')}</ul>` : loadingState('Loading…', { size: 'sm' }))
        : '<p class="set-p rw-empty">No networks yet. Tap a popular service above or type an AS number or network. Until then Night Desk makes no routing requests at all.</p>'}
      <div class="rw-set">
        <fieldset class="rw-fs"><legend class="rw-h4">Check every</legend>
          <div class="rw-seg">${choices.filter((c) => !c.advanced || c.value === every).map(radio).join('')}</div>
        </fieldset>
        <div class="rw-fs"><label class="rw-h4" for="rw-limit">Daily data limit</label>
          <div class="rw-lim"><select id="rw-limit" class="src-input">${limits.map((v) => `<option value="${v}"${v === D.settings.limit_mb ? ' selected' : ''}>${v.toLocaleString()} MB</option>`).join('')}</select>
          <span class="rw-meter" role="img" aria-label="Used today: ${esc(mb(used))} of ${esc(mb(lim))}"><i style="width:${pct}%"></i></span>
          <span class="rw-used mono">${esc(mb(used))} of ${esc(mb(lim))} today</span></div>
          <p class="rw-s-n">When the limit is reached, routing checks pause until midnight and say so here.</p>
        </div>
      </div>
      <h4 class="rw-h4">Where the data comes from</h4>
      <div class="rw-srcs">${srcs.filter((s) => s.id !== 'ris_live').map((s) => srcHtml(s, wl)).join('')}</div>
      <details class="rw-adv"${every === 900 || srcs.find((s) => s.id === 'ris_live')?.enabled ? ' open' : ''}><summary>Advanced</summary>
        <div class="rw-srcs">${srcs.filter((s) => s.id === 'ris_live').map((s) => srcHtml(s, wl)).join('')}</div>
        <fieldset class="rw-fs"><legend class="rw-h4">Check more often</legend>
          <div class="rw-seg">${choices.filter((c) => c.advanced).map(radio).join('')}</div>
          <p class="rw-s-n">Every 15 minutes uses about four times the data and RIPEstat lookups of every hour.</p>
        </fieldset>
      </details>`;
    if (typed) { const i = body.querySelector('#rw-in'); i.value = typed.v; body.querySelector('#rw-lb').value = typed.l; showMsg(typed.msg, typed.bad); }
    if (refocus) body.querySelector(refocus)?.focus({ preventScroll: true });
  }

  // Sources with no stated terms are never switched on by themselves: once a network is watched and no choice is
  // saved, ask once (GET /api/routing `ask`); the answer is saved like the toggle below.
  const ASK = { rpki_roas: { q: 'Also check RPKI signing with the public daily file?', why: 'Its provider states no terms. The file (about 5 MB) is downloaded at most once a day and checked on this computer, so nobody learns what you watch.', yes: 'Yes, check RPKI', no: 'No' } };
  function askHtml() {
    const sid = (D.ask || []).find((x) => ASK[x]);
    if (!sid) return '';
    const a = ASK[sid];
    return `<div class="rw-ask" role="group" aria-labelledby="rw-ask-q">
      <p class="rw-ask-q" id="rw-ask-q"><b>${esc(a.q)}</b> ${esc(a.why)}</p>
      <div class="rw-ask-b"><button class="src-btn primary" data-ask="${esc(sid)}" data-on="1">${esc(a.yes)}</button><button class="src-btn" data-ask="${esc(sid)}" data-on="0">${esc(a.no)}</button></div>
    </div>`;
  }
  async function setSource(sid, want) {
    D = await api.put('/api/routing/source', { id: sid, enabled: want });
    await loadCards();
    paint();
  }

  // A repaint (a live source update, a save) keeps keyboard focus on the same control.
  function focusKey(a) {
    if (!a || !body.contains(a)) return null;
    if (a.id) return `#${CSS.escape(a.id)}`;
    for (const k of ['rm', 'preset', 'srcToggle', 'tok']) {
      if (a.dataset[k] != null) return `[data-${k.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}="${CSS.escape(a.dataset[k])}"]`;
    }
    if (a.name) return `[name="${CSS.escape(a.name)}"][value="${CSS.escape(a.value)}"]`;
    if (a.tagName === 'SUMMARY') return '.rw-adv > summary';
    return null;
  }

  function showMsg(text, bad) {
    const m = body.querySelector('#rw-msg'), i = body.querySelector('#rw-in');
    if (!m) return;
    m.textContent = text || '';
    m.classList.toggle('bad', !!bad);
    if (i) { if (bad) i.setAttribute('aria-invalid', 'true'); else i.removeAttribute('aria-invalid'); }
  }

  async function loadCards() {
    try { cards = (await api.get('/api/routing/watches')).cards; } catch { /* keep the last ones */ }
  }
  async function load() {
    try {
      const [d] = await Promise.all([api.get('/api/routing'), loadCards()]);
      D = d; loadErr = null;
    } catch (e) { loadErr = e.message; }
    paint();
  }
  const reload = debounce(load, 600);

  async function saveList(list, okMsg) {
    try {
      D = await api.put('/api/routing/watchlist', { watches: list.map((w) => ({ value: w.id || w.value, label: w.label })) });
      await loadCards();
      paint();
      if (okMsg) toast(okMsg);
      return true;
    } catch (e) { toast(e.message, true); return false; }
  }

  const validate = debounce(async () => {
    const i = body.querySelector('#rw-in');
    const v = i?.value.trim();
    const seq = ++vSeq;
    if (!v) { showMsg(''); return; }
    try {
      const r = await api.get('/api/routing/validate', { value: v });
      if (seq !== vSeq) return;
      if (!r.ok) showMsg(r.error, true);
      else if (r.duplicate) showMsg(`You already watch ${r.id}.`, true);
      else showMsg(`Ready to watch ${r.id}${r.label ? ` (${r.label})` : ''}.`, false);
    } catch { /* the server will say on Watch */ }
  }, 250);

  body.addEventListener('input', (e) => {
    if (e.target.id === 'rw-in') validate();
    if (e.target.id === 'rw-in' || e.target.id === 'rw-lb') typed = null;
  });

  body.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    if (f.matches('[data-tokform]')) {
      const inp = f.querySelector('#rw-tok-in');
      const v = inp.value.trim();
      if (!v) { inp.focus(); return; }
      try {
        D = await api.put('/api/routing/settings', { radar_token: v });
        inp.value = '';
        paint(); toast('Token saved. Radar checks start shortly.');
      } catch (err) { toast(err.message, true); }
      return;
    }
    const i = body.querySelector('#rw-in'), lb = body.querySelector('#rw-lb');
    const v = i.value.trim();
    if (!v) { showMsg('Type an AS number (like AS13335) or a network (like 1.1.1.0/24).', true); i.focus(); return; }
    let r;
    try { r = await api.get('/api/routing/validate', { value: v }); } catch (err) { toast(err.message, true); return; }
    if (!r.ok || r.duplicate) { showMsg(r.ok ? `You already watch ${r.id}.` : r.error, true); i.focus(); return; }
    const label = lb.value.trim() || r.label || '';
    typed = null;
    if (await saveList([...D.watchlist, { id: r.id, label }], `Watching ${label || r.id}`)) body.querySelector('#rw-in')?.focus();
  });

  body.addEventListener('click', async (e) => {
    const p = e.target.closest('[data-preset]');
    if (p) {
      const id = p.dataset.preset, wl = D.watchlist;
      const on = wl.some((w) => w.id === id);
      if (!on && wl.length >= D.max) { toast(`You can watch up to ${D.max} networks. Remove one first.`, true); return; }
      p.disabled = true;
      await saveList(on ? wl.filter((w) => w.id !== id) : [...wl, { id, label: p.dataset.label }], on ? `Stopped watching ${p.dataset.label}` : `Watching ${p.dataset.label}`);
      body.querySelector(`[data-preset="${CSS.escape(id)}"]`)?.focus();
      return;
    }
    const rm = e.target.closest('[data-rm]');
    if (rm) {
      const id = rm.dataset.rm;
      const w = D.watchlist.find((x) => x.id === id);
      const next = rm.closest('.rw-card')?.nextElementSibling?.dataset.id || rm.closest('.rw-card')?.previousElementSibling?.dataset.id;
      rm.disabled = true;
      if (await saveList(D.watchlist.filter((x) => x.id !== id), `Stopped watching ${w?.label || id}`)) {
        (next && body.querySelector(`[data-rm="${CSS.escape(next)}"]`) || body.querySelector('#rw-in'))?.focus();
      } else rm.disabled = false;
      return;
    }
    const ask = e.target.closest('[data-ask]');
    if (ask) {
      const sid = ask.dataset.ask, want = ask.dataset.on === '1';
      body.querySelectorAll('[data-ask]').forEach((b) => { b.disabled = true; });
      try {
        await setSource(sid, want);
        toast(want ? `${SRC[sid]?.title || sid} on` : `${SRC[sid]?.title || sid} stays off. Turn it on below any time.`);
        body.querySelector(`[data-src-toggle="${CSS.escape(sid)}"]`)?.focus();
      } catch (err) { toast(err.message, true); body.querySelectorAll('[data-ask]').forEach((b) => { b.disabled = false; }); }
      return;
    }
    if (e.target.closest('[data-tok="remove"]')) {
      try { D = await api.put('/api/routing/settings', { radar_token: '' }); paint(); toast('Token removed. Radar checks stopped.'); }
      catch (err) { toast(err.message, true); }
    }
  });

  body.addEventListener('change', async (e) => {
    const t = e.target;
    if (t.name === 'rw-every') {
      try { D = await api.put('/api/routing/settings', { every: Number(t.value) }); await loadCards(); paint(); toast(`Checking every ${t.nextElementSibling.textContent}`); }
      catch (err) { toast(err.message, true); load(); }
      return;
    }
    if (t.id === 'rw-limit') {
      try { D = await api.put('/api/routing/settings', { limit_mb: Number(t.value) }); await loadCards(); paint(); toast(`Daily data limit: ${Number(t.value).toLocaleString()} MB`); }
      catch (err) { toast(err.message, true); load(); }
      return;
    }
    const sid = t.dataset.srcToggle;
    if (sid) {
      const want = t.checked;
      try {
        await api.put('/api/routing/source', { id: sid, enabled: want });
        toast(`${SRC[sid]?.title || sid} ${want ? 'on' : 'off'}${want && !D.watchlist?.length ? ': starts with the first network you watch' : ''}`);
      } catch (err) { t.checked = !want; toast(err.message, true); }
      await load();
      body.querySelector(`[data-src-toggle="${CSS.escape(sid)}"]`)?.focus();
    }
  });

  const ROUTING = new Set(Object.keys(SRC));
  live?.on?.('source', (st) => { if (ROUTING.has(st.id) && el.isConnected) reload(); });
  const tick = setInterval(() => {
    if (!el.isConnected) return;
    el.querySelectorAll('[data-ago]').forEach((n) => { n.textContent = ago(n.dataset.ago); });
  }, 30000);
  const poll = setInterval(() => { if (el.isConnected && el.offsetParent && D?.watchlist?.length) { loadCards().then(() => { if (!el.contains(document.activeElement) || document.activeElement === document.body) paint(); }); } }, 60000);

  load();
  return {
    focus() { const h = el.querySelector('#rw-h'); el.querySelector('#rw')?.scrollIntoView({ block: 'start' }); h?.focus({ preventScroll: true }); },
    reload: load,
    destroy() { clearInterval(tick); clearInterval(poll); },
  };
}

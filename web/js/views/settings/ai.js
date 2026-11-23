// Settings › AI: search by meaning (the built-in helper's search model, downloaded only when the user turns it on)
// and chat (story summaries, entity briefs, names picked out of articles) on the built-in helper, Ollama, LM Studio
// or another OpenAI-compatible address. Nothing is downloaded or contacted until the user chooses it here.
// Backend: osinthub/ai/setup.py (downloads, the helper), osinthub/ai/chatconn.py (where chat goes).
// GET /api/ai/setup, POST /api/ai/setup/plan, POST /api/ai/setup, DELETE /api/ai/setup/job, POST /api/ai/setup/off,
// POST /api/ai/chat/discover, /chat/models, /chat/test, /chat, /chat/off.
// Contract: okf/architecture/local-ai.md#turning-ai-on and #chat-connection
import { registerSettingsSection } from './registry.js';

const GB = 1e9;
function size(b) {
  if (b == null) return '—';
  if (b >= GB) return `${(b / GB).toFixed(b >= 10 * GB ? 0 : 1).replace(/\.0$/, '')} GB`;
  return `${Math.max(1, Math.round(b / 1e6))} MB`;
}
const gib = (b) => Math.round(b / 2 ** 30);
const STEP = { starting: 'Getting ready…', libs: 'Installing the AI libraries…', search: 'Downloading the search model…',
  chat: 'Downloading the chat model…', 'starting the helper': 'Starting the AI helper…' };
const VIA_LABEL = { builtin: 'Built-in', ollama: 'Ollama', lmstudio: 'LM Studio', other: 'Another server' };

registerSettingsSection({
  id: 'ai',
  label: 'AI',
  order: 45,
  description: 'Optional. Search by meaning runs on this Mac; chat (story summaries and entity briefs) runs on this Mac, in Ollama or LM Studio, or on another server. Nothing is downloaded or contacted until you choose it here.',
  mount(el, ctx) {
    const { api, util } = ctx;
    const { esc, toast } = util;
    el.innerHTML = `<div class="set-ai-job" aria-live="polite"></div>
      <div class="set-card"><h3 class="set-h3">Search by meaning</h3><div class="set-ai set-ai-search" aria-live="polite"><p class="set-p">…</p></div></div>
      <div class="set-card"><h3 class="set-h3">Chat</h3><div class="set-ai set-ai-chat" aria-live="polite"><p class="set-p">…</p></div></div>`;
    const jobBox = el.querySelector('.set-ai-job'), sBox = el.querySelector('.set-ai-search'), cBox = el.querySelector('.set-ai-chat');
    let st = null, timer = 0, gone = false, sForm = false, cForm = false;

    async function load() {
      clearTimeout(timer);
      try { st = await api.get('/api/ai/setup'); } catch (e) { sBox.innerHTML = `<p class="set-p">${esc(e.message)}</p>`; return; }
      renderJob();
      if (!sForm) renderSearch();
      if (!cForm) renderChat();
      // poll while it downloads, and while a helper this app just started is still loading its models
      const starting = st.enabled && st.helper.ours && !st.helper.up;
      if ((st.job.running || starting) && !gone) timer = setTimeout(load, st.job.running ? 1000 : 3000);
    }

    function renderJob() {
      const j = st.job;
      if (!j.running) {
        jobBox.innerHTML = j.error ? `<p class="set-warn set-ai-err" role="alert">Turning AI on stopped: ${esc(j.error)}</p>` : '';
        return;
      }
      const pct = j.total ? Math.min(100, Math.round((j.done / j.total) * 100)) : null;
      jobBox.innerHTML = `<div class="set-card"><p class="set-p" role="status">${esc(STEP[j.step] || 'Working…')}${pct != null ? ` ${pct}% <span class="mono">(${size(j.done)} of ${size(j.total)})</span>` : ''}</p>
        <div class="set-ai-bar${pct == null ? ' busy' : ''}"><i style="width:${pct ?? 30}%"></i></div>
        <p class="set-p set-move-why">You can leave this page; the download carries on. If it stops, starting again picks up where it left off.</p>
        <div class="set-ai-act"><button class="src-btn set-ai-stop" type="button">Stop</button></div></div>`;
      jobBox.querySelector('.set-ai-stop').addEventListener('click', async () => { await api.del('/api/ai/setup/job').catch(() => {}); load(); });
    }

    function helperLine() {
      const h = st.helper;
      return h.up ? 'The AI helper is running.' : h.ours ? 'The AI helper is starting (loading the models takes up to a minute).'
        : `The AI helper is not running. Its log is <span class="mono">${esc(st.log)}</span>.`;
    }

    // ---------------------------------------------------------------- search by meaning
    function renderSearch() {
      const busy = st.job.running;
      if (st.why_not && !st.enabled) {
        sBox.innerHTML = `<p class="set-p">${esc(st.why_not)}</p>${st.docker ? `<p class="set-p set-move-why">To use it with Docker, start the helper on the Mac from a copy of the source: <span class="mono">uv run python -m osinthub.ai.server</span>. Night Desk finds it at <span class="mono">host.docker.internal:8790</span>.</p>` : ''}
          <p class="set-p">Without it, search matches words instead of meaning. Chat can still use Ollama, LM Studio or another server (below).</p>`;
        return;
      }
      if (st.enabled) {
        sBox.innerHTML = `<p class="set-p"><b>On.</b> ${helperLine()}</p>
          <div class="set-ai-act"><button class="src-btn set-ai-offopen" type="button"${busy ? ' disabled' : ''}>Turn off…</button></div>`;
        sBox.querySelector('.set-ai-offopen').addEventListener('click', openOff);
        return;
      }
      const m = st.models.search;
      sBox.innerHTML = `<p class="set-p">Finds stories, CVEs and events by what they are about, not only by their words. It runs on this Mac with a small model (${m.present ? 'already on this Mac' : `${size(m.size)} download`}, about ${size(m.memory)} of memory).</p>
        <div class="set-ai-act"><button class="src-btn primary set-ai-open" type="button"${busy ? ' disabled' : ''}>Turn on…</button></div>`;
      sBox.querySelector('.set-ai-open').addEventListener('click', openSearch);
    }

    function openSearch() {
      sForm = true;
      const m = st.models.search;
      sBox.innerHTML = `<form class="set-move-form set-ai-form">
          <div class="set-ai-m off"><span class="set-ai-mt"><span><b>${esc(m.label)}</b> · ${m.present ? 'already on this Mac' : `${size(m.size)} download`} · uses about ${size(m.memory)} of memory while it runs</span>
            <span class="src-ret-h">${esc(m.what)}</span><span class="src-ret-h mono">${esc(m.folder)}</span></span></div>
          <p class="set-p set-ai-plan mono" role="status"></p>
          <div class="src-ret-act">
            <button class="src-btn primary set-ai-go" type="submit">Download and turn on</button>
            <button class="src-btn set-ai-close" type="button">Cancel</button>
          </div>
        </form>`;
      const f = sBox.querySelector('form'), out = f.querySelector('.set-ai-plan'), go = f.querySelector('.set-ai-go');
      const models = ['search', ...(st.chat.via === 'builtin' ? ['chat'] : [])];
      planInto(out, go, { models });
      f.querySelector('.set-ai-close').addEventListener('click', () => { sForm = false; renderSearch(); });
      f.addEventListener('submit', async (e) => {
        e.preventDefault();
        go.disabled = true;
        try { await api.post('/api/ai/setup', { models }); } catch (err) { out.textContent = err.message; out.classList.add('set-ai-err'); go.disabled = false; return; }
        sForm = false;
        load();
      });
    }

    async function planInto(out, go, body) {
      out.textContent = 'Checking…';
      const r = await api.post('/api/ai/setup/plan', body).catch((e) => ({ problem: e.message }));
      const parts = [];
      if (r.need) parts.push(`Downloads about ${size(r.need)}${r.libs ? ' (including about 1 GB of AI libraries)' : ''}.`);
      else if (!r.problem) parts.push('Nothing to download: everything is already on this Mac.');
      if (r.free != null) parts.push(`${size(r.free)} free.`);
      out.textContent = [r.problem, ...parts].filter(Boolean).join(' ');
      out.classList.toggle('set-ai-err', !!r.problem);
      go.disabled = !!r.problem;
      go.textContent = r.need ? 'Download and turn on' : 'Turn on';
    }

    function openOff() {
      sForm = true;
      const del = st.deletable || [];
      const builtinChat = st.chat.via === 'builtin';
      sBox.innerHTML = `<form class="set-move-form set-ai-form">
          <p class="set-p">Turning it off stops the AI helper. Search goes back to matching words.${builtinChat ? ' The built-in chat model stops too.' : ''} Models stay on this Mac unless you tick below.</p>
          ${del.length ? `<label class="set-ai-m"><input type="checkbox" name="models"><span class="set-ai-mt"><span>Also delete the models Night Desk downloaded</span> <span class="src-ret-h">${del.map((d) => `${esc(d.repo)} (${size(d.size)})`).join(', ')}. Another app on this Mac that uses them would have to download them again. Models that were already on this Mac are never deleted.</span></span></label>` : ''}
          ${st.libs.where === 'libs' ? `<label class="set-ai-m"><input type="checkbox" name="libs"><span class="set-ai-mt"><span>Also delete the AI libraries</span> <span class="src-ret-h mono">${esc(st.libs.folder)}</span></span></label>` : ''}
          <div class="src-ret-act">
            <button class="src-btn primary" type="submit">Turn off</button>
            <button class="src-btn set-ai-close" type="button">Cancel</button>
          </div>
        </form>`;
      const f = sBox.querySelector('form');
      f.querySelector('.set-ai-close').addEventListener('click', () => { sForm = false; renderSearch(); });
      f.addEventListener('submit', async (e) => {
        e.preventDefault();
        const r = await api.post('/api/ai/setup/off', { delete_models: !!f.models?.checked, delete_libs: !!f.libs?.checked }).catch((err) => { toast(err.message, true); return null; });
        if (r) toast(r.deleted.length ? `Search by meaning is off. Deleted: ${r.deleted.join(', ')}` : 'Search by meaning is off');
        sForm = false; cForm = false;
        load();
      });
    }

    // ---------------------------------------------------------------- chat
    function chatState() {
      const c = st.chat, h = st.helper_chat || {};
      if (!c.via) return '<p class="set-p"><b>Off.</b> Story summaries, entity briefs and the names picked out of articles need a chat model. Use the one built into Night Desk, a model you already have in Ollama or LM Studio, or another server.</p>';
      if (c.via === 'builtin') {
        return `<p class="set-p"><b>Built-in, on this Mac:</b> <span class="mono">${esc(c.model)}</span>. ${st.enabled ? helperLine() : 'Search by meaning is off, so the helper is not running.'}</p>`;
      }
      const where = `${VIA_LABEL[c.via]}: <span class="mono">${esc(c.model)}</span> at <span class="mono">${esc(c.url)}</span>`;
      const health = h.down ? `<span class="set-ai-err">Not answering${h.last_error ? ` (${esc(h.last_error)})` : ''}.</span>`
        : h.ever_up ? 'Answering.' : 'Not used yet since Night Desk started.';
      return `<p class="set-p"><b>${where}</b>. ${health}</p>
        ${c.blocked_offline ? '<p class="set-warn">Offline mode is on, so chat on this server is paused: it is not on this computer or your network.</p>' : ''}
        ${c.is_local === false && !c.blocked_offline ? `<p class="set-warn">This server is outside your network: the text of each new article and the facts behind entity briefs are sent to it. Your network logs and devices never are.</p>` : ''}`;
    }

    function renderChat() {
      const busy = st.job.running;
      cBox.innerHTML = chatState() + `<div class="set-ai-act">
          <button class="src-btn${st.chat.via ? '' : ' primary'} set-ai-copen" type="button"${busy ? ' disabled' : ''}>${st.chat.via ? 'Change…' : 'Set up chat…'}</button>
          ${st.chat.via ? `<button class="src-btn set-ai-coff" type="button"${busy ? ' disabled' : ''}>Turn off</button>` : ''}</div>`;
      cBox.querySelector('.set-ai-copen').addEventListener('click', openChat);
      cBox.querySelector('.set-ai-coff')?.addEventListener('click', async () => {
        await api.post('/api/ai/chat/off', {}).catch((e) => toast(e.message, true));
        toast('Chat is off');
        load();
      });
    }

    function modelOptions(models, current) {
      return models.map((m) => `<option value="${esc(m.id)}"${m.id === current ? ' selected' : ''}>${esc(m.id)}${m.size ? ` (${size(m.size)})` : ''}</option>`).join('');
    }

    async function openChat() {
      cForm = true;
      cBox.innerHTML = '<p class="set-p" role="status">Looking for Ollama, LM Studio and MLX models on this Mac…</p>';
      const d = await api.post('/api/ai/chat/discover', {}).catch((e) => ({ error: e.message }));
      if (d.error) { cBox.innerHTML = `<p class="set-p set-ai-err">${esc(d.error)}</p>`; cForm = false; return; }
      const c = st.chat;
      const pick = c.via || (d.ollama?.running ? 'ollama' : d.lmstudio?.running ? 'lmstudio' : !d.builtin.why_not ? 'builtin' : 'ollama');
      const found = (k) => d[k].running ? `found, ${d[k].models.length} model${d[k].models.length === 1 ? '' : 's'}` : `not running at ${esc(d[k].url)}`;
      const bi = d.builtin;
      const biOpts = bi.models.map((m) => `<option value="${esc(m.repo)}"${m.enough_memory ? '' : ' disabled'}${(c.via === 'builtin' ? m.repo === c.model : m.recommended) ? ' selected' : ''}>${esc(m.repo)} · ${m.present ? `on this Mac, ${size(m.size)}` : `${size(m.size)} download`}${m.recommended ? ' · recommended' : ''}${m.enough_memory ? '' : ` · needs ${gib(m.memory_needed)} GB of memory`}</option>`).join('');
      cBox.innerHTML = `<form class="set-move-form set-ai-form" novalidate>
          <div class="set-radios" role="radiogroup" aria-label="Where chat runs">
            <label class="set-radio"><input type="radio" name="via" value="builtin"${bi.why_not ? ' disabled' : ''}><span><b>Built-in (this Mac)</b><span class="set-dim">${bi.why_not ? esc(bi.why_not) : 'Night Desk runs an MLX model itself, next to search by meaning.'}</span></span></label>
            <label class="set-radio"><input type="radio" name="via" value="ollama"><span><b>Ollama</b><span class="set-dim">${found('ollama')}</span></span></label>
            <label class="set-radio"><input type="radio" name="via" value="lmstudio"><span><b>LM Studio</b><span class="set-dim">${found('lmstudio')}</span></span></label>
            <label class="set-radio"><input type="radio" name="via" value="other"><span><b>Another server</b><span class="set-dim">Any server that speaks the OpenAI chat format: another machine, or a provider with an API key.</span></span></label>
          </div>
          <div class="set-ai-bi">
            <label class="set-ai-f"><span class="label">Model</span><select class="src-input mono" name="repo">${biOpts}</select></label>
            <p class="set-dim">The MLX language models already in your Hugging Face cache, and the recommended one. It also turns on search by meaning if that is off: the helper always runs the search model.</p>
          </div>
          <div class="set-ai-ext">
            <label class="set-ai-f"><span class="label">Address</span><input class="src-input mono" name="url" type="text" inputmode="url" autocomplete="off" spellcheck="false" placeholder="http://192.168.1.10:11434/v1 or https://openrouter.ai/api/v1"></label>
            <label class="set-ai-f"><span class="label">API key (if the server needs one)</span><input class="src-input mono" name="key" type="password" autocomplete="off" spellcheck="false"></label>
            <p class="set-dim set-ai-keynote"></p>
            <label class="set-ai-f"><span class="label">Model</span><span class="set-ai-mrow"><select class="src-input mono" name="model"></select><input class="src-input mono" name="model_text" type="text" autocomplete="off" spellcheck="false" placeholder="model name" hidden><button class="src-btn set-ai-list" type="button">List models</button></span></label>
          </div>
          <p class="set-p set-ai-plan mono" role="status"></p>
          <div class="src-ret-act">
            <button class="src-btn set-ai-test" type="button">Test</button>
            <button class="src-btn primary set-ai-go" type="submit">Save</button>
            <button class="src-btn set-ai-close" type="button">Cancel</button>
          </div>
        </form>`;
      const f = cBox.querySelector('form'), out = f.querySelector('.set-ai-plan'), go = f.querySelector('.set-ai-go');
      const sel = f.model, txt = f.model_text, keyNote = f.querySelector('.set-ai-keynote');
      const via = () => f.querySelector('input[name=via]:checked')?.value;
      const model = () => (txt.hidden ? sel.value : txt.value).trim();
      const ext = () => ({ via: via(), url: f.url.value.trim(), model: model(), ...(f.key.value ? { key: f.key.value } : {}) });
      const say = (t, bad) => { out.textContent = t; out.classList.toggle('set-ai-err', !!bad); };

      function showModels(list, keep) {
        if (list && list.length) {
          sel.innerHTML = modelOptions(list, keep);
          sel.hidden = false; txt.hidden = true;
        } else {
          sel.hidden = true; txt.hidden = false;
          if (keep && !txt.value) txt.value = keep;
        }
      }
      async function listModels(quiet) {
        if (!f.url.value.trim()) { showModels([], ''); return; }
        if (!quiet) say('Asking the server for its models…');
        const r = await api.post('/api/ai/chat/models', ext()).catch((e) => ({ ok: false, error: e.message, models: [] }));
        showModels(r.models, model() || (c.via === via() ? c.model : ''));
        if (!r.ok) say(`${r.error} You can still type a model name.`, true);
        else if (!quiet) say(`${r.models.length} model${r.models.length === 1 ? '' : 's'} found.`);
        else say('');
      }
      function switchTo(v, first) {
        f.querySelector('.set-ai-bi').hidden = v !== 'builtin';
        f.querySelector('.set-ai-ext').hidden = v === 'builtin';
        f.querySelector('.set-ai-test').hidden = v === 'builtin';
        keyNote.textContent = c.has_key && c.via === v ? 'A key is saved for this address. Leave the field empty to keep it.' : '';
        if (v === 'builtin') {
          planInto(out, go, { models: ['search', 'chat'], chat_repo: f.repo.value });
          return;
        }
        go.disabled = false; go.textContent = 'Save';
        const saved = c.via === v && c.url;
        f.url.value = saved ? c.url : (d[v]?.url || (first && c.url) || '');
        if (d[v]?.running && !saved) { showModels(d[v].models, ''); say(''); } else listModels(true);
      }
      f.querySelectorAll('input[name=via]').forEach((r) => r.addEventListener('change', () => switchTo(r.value)));
      f.repo.addEventListener('change', () => planInto(out, go, { models: ['search', 'chat'], chat_repo: f.repo.value }));
      f.querySelector('.set-ai-list').addEventListener('click', () => listModels(false));
      f.url.addEventListener('change', () => listModels(true));
      f.querySelector('.set-ai-test').addEventListener('click', async (e) => {
        const b = e.currentTarget;
        if (!model()) { say('Choose a model first.', true); return; }
        b.disabled = true;
        say('Sending a short test message (a model that is not loaded yet can take a minute)…');
        const r = await api.post('/api/ai/chat/test', ext()).catch((err) => ({ ok: false, error: err.message }));
        b.disabled = false;
        say(r.ok ? `It works: answered “${r.reply}” in ${r.seconds} s.` : r.error, !r.ok);
      });
      f.querySelector('.set-ai-close').addEventListener('click', () => { cForm = false; renderChat(); });
      f.addEventListener('submit', async (e) => {
        e.preventDefault();
        const v = via();
        go.disabled = true;
        try {
          if (v === 'builtin') {
            await api.post('/api/ai/setup', { models: ['search', 'chat'], chat_repo: f.repo.value });
          } else {
            if (!model()) throw new Error('Choose a model.');
            await api.post('/api/ai/chat', ext());
            toast('Chat settings saved');
          }
        } catch (err) { say(err.message, true); go.disabled = false; return; }
        cForm = false;
        load();
      });
      const radio = f.querySelector(`input[name=via][value="${pick}"]`);
      if (radio && !radio.disabled) radio.checked = true; else f.querySelector('input[name=via][value=ollama]').checked = true;
      switchTo(via(), true);
    }

    load();
    return { show() { gone = false; load(); }, hide() { gone = true; clearTimeout(timer); }, destroy() { gone = true; clearTimeout(timer); } };
  },
});

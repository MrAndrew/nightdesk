// Settings › About: version, commit, where the lake is, offline mode, the SQL console (on or off) and the local AI helper (GET /api/settings/about),
// and Copy diagnostics for a GitHub issue (GET /api/settings/diagnostics: plain text with addresses, host names, folders and keys removed).
import { registerSettingsSection } from './registry.js';

registerSettingsSection({
  id: 'about',
  label: 'About',
  order: 90,
  description: 'Night Desk is a local-first security desk: sources, models and your data stay on this machine.',
  mount(el, ctx) {
    const { api, util } = ctx;
    const { esc, toast } = util;
    el.innerHTML = `<div class="set-card"><dl class="set-kv set-about"><dt>Version</dt><dd>…</dd></dl></div>
      <div class="set-card">
        <h3 class="set-h3">Reporting a problem</h3>
        <p class="set-p">Copy diagnostics gives a short summary for a GitHub issue: the version, how Night Desk is installed, the machine, and how the sources and local AI are doing. Addresses, host names, folders and keys are removed. Please read it before you paste it.</p>
        <div class="set-ai-act"><button class="src-btn primary set-diag-copy" type="button">Copy diagnostics</button><button class="src-btn set-diag-show" type="button">Show it</button></div>
        <pre class="mono set-move-cmd set-diag" hidden></pre>
      </div>`;
    const pre = el.querySelector('.set-diag');
    async function diagnostics() {
      const r = await fetch('api/settings/diagnostics', { cache: 'no-store' });
      if (!r.ok) throw new Error(`Could not make the summary (${r.status})`);
      return r.text();
    }
    el.querySelector('.set-diag-show').addEventListener('click', async () => {
      try { pre.textContent = await diagnostics(); pre.hidden = false; } catch (e) { toast(e.message, true); }
    });
    el.querySelector('.set-diag-copy').addEventListener('click', async () => {
      let text;
      try { text = await diagnostics(); } catch (e) { toast(e.message, true); return; }
      pre.textContent = text; pre.hidden = false;
      try { await navigator.clipboard.writeText(text); toast('Diagnostics copied'); }
      catch { toast('Copy failed: select the text below and copy it', true); }
    });
    async function load() {
      try {
        const a = await api.get('/api/settings/about');
        const ai = !a.ai ? 'Not available in this build'
          : a.ai.up ? 'Running: search by meaning and story summaries are on'
            : a.ai.configured ? 'Expected but not answering. Keyword search is used meanwhile.'
              : 'Not running (optional). Keyword search is used instead.';
        el.querySelector('.set-about').innerHTML = `
          <dt>Version</dt><dd class="mono">${esc(a.version)}</dd>
          <dt>Commit</dt><dd class="mono">${a.commit ? esc(a.commit) : 'unknown'}</dd>
          <dt>Data folder</dt><dd class="mono">${esc(a.lake)}</dd>
          <dt>Offline mode</dt><dd title="The OSINTHUB_OFFLINE=1 setting turns it on">${a.offline ? 'On: nothing is fetched' : 'Off: sources are fetched on schedule'}</dd>
          <dt>SQL console</dt><dd>${a.sql_console ? 'On: read-only SQL over the lake in the <a href="#explorer">SQL console</a> (OSINTHUB_SQL_CONSOLE=1)' : 'Off. Start Night Desk with OSINTHUB_SQL_CONSOLE=1 to turn it on.'}</dd>
          <dt>Local AI helper</dt><dd>${esc(ai)} <a href="#settings/ai">AI settings</a></dd>
          <dt>Sources known</dt><dd class="mono">${esc(a.sources)}</dd>`;
      } catch (e) { el.querySelector('.set-about').innerHTML = `<dt>Error</dt><dd>${esc(e.message)}</dd>`; }
    }
    load();
    return { show: load };
  },
});

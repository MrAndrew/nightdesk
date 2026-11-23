// Settings › Display: the page Night Desk opens on, the clock (local time or UTC), and motion (which follows the operating system).
import { registerSettingsSection } from './registry.js';
import { LANDINGS, landing, setLanding } from '../../core/prefs.js';
import * as T from '../../core/time.js';

registerSettingsSection({
  id: 'display',
  label: 'Display',
  order: 40,
  description: 'How Night Desk looks in this browser: the page it opens on, the clock and motion. These choices are saved here, not on the server.',
  mount(el, ctx) {
    const { esc, toast, reducedMotion } = ctx.util;
    let tzName = ''; try { tzName = (Intl.DateTimeFormat().resolvedOptions().timeZone || '').replace(/_/g, ' '); } catch {}
    const mq = window.matchMedia?.('(prefers-reduced-motion: reduce)');
    el.innerHTML = `
      <fieldset class="set-card set-fs">
        <legend class="set-h3">Open Night Desk on</legend>
        <p class="set-p">Used when you open Night Desk without a link to a particular page.</p>
        <div class="set-radios">${LANDINGS.map(([id, label, d]) => `<label class="set-radio"><input type="radio" name="landing" value="${esc(id)}"${id === landing() ? ' checked' : ''}>
          <span><b>${esc(label)}</b><span class="set-dim">${esc(d)}</span></span></label>`).join('')}</div>
        <p class="set-p set-dim">For a wall screen, use <a href="#cinema?kiosk">kiosk mode</a> (add ?kiosk to the Cinema link): Cinema with no menus. Press Esc to leave it.</p>
      </fieldset>
      <fieldset class="set-card set-fs">
        <legend class="set-h3">Show times in</legend>
        <p class="set-p">Every time and date in Night Desk follows this <span data-term="time-zone">time zone</span>, from the top-bar clock to alert timelines. Times are always 24-hour. Copied summaries for other people always say UTC.</p>
        <div class="set-radios">${[['local', 'Local time', `This computer's clock${tzName ? ` (${tzName})` : ''}. Recommended.`],
          ['utc', 'UTC', 'One zone for every machine. Handy when you compare with router or server logs kept in UTC.']].map(([id, label, d]) => `<label class="set-radio"><input type="radio" name="tz" value="${id}"${id === T.zone() ? ' checked' : ''}>
          <span><b>${esc(label)}</b><span class="set-dim">${esc(d)}</span></span></label>`).join('')}</div>
        <p class="set-p set-dim finishb-tz-now"></p>
      </fieldset>
      <div class="set-card">
        <h3 class="set-h3">Motion</h3>
        <p class="set-p set-motion"></p>
      </div>`;
    const paintMotion = () => {
      el.querySelector('.set-motion').textContent = reducedMotion()
        ? 'Your system asks for less motion, so the globes stop spinning, the camera cuts instead of flying and the tour lamp jumps between steps.'
        : 'Night Desk follows your system’s “reduce motion” setting. It is off now, so the globes turn and the camera flies between events.';
    };
    paintMotion();
    mq?.addEventListener?.('change', paintMotion);
    const paintNow = () => { el.querySelector('.finishb-tz-now').textContent = `Right now that reads ${T.stamp(Date.now(), { zone: true })}.`; };
    paintNow();
    el.addEventListener('change', (e) => {
      if (e.target.name === 'tz') {
        // every view formats its times when it renders, so reload once to redraw them all in the new zone
        T.setZone(e.target.value); paintNow();
        setTimeout(() => location.reload(), 150);
        return;
      }
      if (e.target.name !== 'landing') return;
      setLanding(e.target.value);
      toast(`Night Desk will open on ${LANDINGS.find(([id]) => id === e.target.value)[1]}`);
    });
  },
});

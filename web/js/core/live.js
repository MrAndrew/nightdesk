// Server-sent events hub. Topics and payloads: okf/architecture/web-client.md
//
// Also the one live-status primitive every "LIVE" claim uses (top-bar chip, Cinema ticker, Bluesky and BGP
// panels): live.status(sourceId?) -> { state, label, title }, state one of
//   live     data arrived recently
//   idle     connected, but nothing for a while (IDLE_MS)
//   waiting  connected, no data yet since this page opened
//   offline  OSINTHUB_OFFLINE=1, the app's event stream is down, or the source's stream is down
//   off      the source is turned off in Sources (or needs a key)
// live.onStatus(fn) calls fn() whenever any of it may have changed. live.badge(ctx, sourceId, fmt?) keeps a
// panel badge painted with it.
import { api } from './api.js';

const handlers = new Map();
let es = null;
let msgCount = 0;

const IDLE_MS = 90e3;
const T0 = Date.now();
let sseUp = null;          // null until the first open/error
let lastAny = 0;
const lastBy = new Map();  // source id -> ms of its latest message
const srcs = new Map();    // source id -> {status, enabled, name}
let offline = null;        // from /api/health
const statusSubs = new Set();

function emit(topic, data) {
  (handlers.get(topic) || []).forEach((fn) => { try { fn(data); } catch (e) { console.error(e); } });
}
const changed = () => statusSubs.forEach((fn) => { try { fn(); } catch (e) { console.error(e); } });

// which source a message speaks for
function sourceOf(topic, data) {
  if (topic === 'events') return data?.source;
  if (topic === 'social') return 'bluesky_cyber';
  if (topic === 'bgp_pulse') return 'ris_live';
  if (topic === 'metric') {
    const n = String(data?.name || '');
    return n.startsWith('bgp.') ? 'ris_live' : n.startsWith('bluesky.') ? 'bluesky_cyber' : null;
  }
  return null;
}

async function refreshMeta() {
  try { offline = !!(await api.get('/api/health')).offline; } catch {}
  try {
    const list = await api.sources();
    for (const s of Array.isArray(list) ? list : list.sources || []) srcs.set(s.id, { status: s.status, enabled: s.enabled, name: s.name, unavailable: s.unavailable });
  } catch {}
  changed();
}

const mins = (ms) => { const m = Math.round(ms / 60e3); return m < 1 ? 'under a minute' : m === 1 ? '1 minute' : m < 120 ? `${m} minutes` : `${Math.round(m / 60)} hours`; };

function status(id) {
  const now = Date.now();
  if (offline) return { state: 'offline', label: 'Offline', title: 'Offline mode: Night Desk is not fetching anything.' };
  if (sseUp === false) return { state: 'offline', label: 'Offline', title: 'Lost the live connection to the Night Desk server. Retrying.' };
  if (!id) {
    if (lastAny && now - lastAny < IDLE_MS) return { state: 'live', label: 'Live', title: 'Live: data is arriving.' };
    if (!lastAny && now - T0 < IDLE_MS) return { state: 'waiting', label: 'Connecting', title: 'Connected; waiting for the first data.' };
    return { state: 'idle', label: 'Idle', title: `Connected, but no new data for ${mins(now - (lastAny || T0))}.` };
  }
  const s = srcs.get(id);
  const name = s?.name || id;
  if (s && (s.enabled === false || s.unavailable)) return { state: 'off', label: 'Off', title: `${name} is turned off. Turn it on in Sources.` };
  if (s && ['offline', 'reconnecting', 'error', 'disabled'].includes(s.status)) return { state: 'offline', label: 'Offline', title: `${name}: the stream is down${s.status === 'reconnecting' ? ', reconnecting' : ''}.` };
  const last = lastBy.get(id) || 0;
  if (last && now - last < IDLE_MS) return { state: 'live', label: 'Live', title: `${name}: data is arriving.` };
  if (!last && now - T0 < IDLE_MS) return { state: 'waiting', label: 'Connecting', title: `${name}: waiting for the first data.` };
  return { state: 'idle', label: 'Idle', title: `${name}: connected, but nothing for ${mins(now - (last || T0))}.` };
}

export const live = {
  on(topic, fn) {
    if (!handlers.has(topic)) handlers.set(topic, new Set());
    handlers.get(topic).add(fn);
    return () => handlers.get(topic).delete(fn);
  },
  connect() {
    if (es) return;
    es = new EventSource('api/stream');
    es.onopen = () => { sseUp = true; emit('status', true); changed(); };
    es.onerror = () => { sseUp = false; emit('status', false); changed(); };
    es.onmessage = (m) => {
      msgCount++;
      try {
        const { topic, data } = JSON.parse(m.data);
        const now = Date.now();
        const sid = sourceOf(topic, data);
        const wasIdle = (lastAny && now - lastAny >= IDLE_MS) || !lastAny || (sid && !(lastBy.get(sid) && now - lastBy.get(sid) < IDLE_MS));
        if (topic !== 'source') lastAny = now;
        if (sid) lastBy.set(sid, now);
        if (topic === 'source' && data?.id) { srcs.set(data.id, { ...(srcs.get(data.id) || {}), status: data.status, enabled: data.enabled ?? srcs.get(data.id)?.enabled }); changed(); }
        emit(topic, data);
        if (wasIdle && topic !== 'source') changed();
      } catch {}
    };
    refreshMeta();
    setInterval(refreshMeta, 60e3);
    setInterval(changed, 15e3); // live -> idle happens with no message at all
  },
  takeCount() { const n = msgCount; msgCount = 0; return n; },
  status,
  isOffline: () => !!offline,
  source: (id) => srcs.get(id) || null,
  onStatus(fn) { statusSubs.add(fn); return () => statusSubs.delete(fn); },
  // Paint a panel badge from status(sourceId) once; fmt(st) may return the text (default: the label).
  paintBadge(ctx, sourceId, fmt) {
    const st = status(sourceId);
    ctx.setBadge((fmt && fmt(st)) || st.label.toUpperCase(), st.state === 'live');
    const b = ctx.panelEl?.querySelector('.panel-badge');
    if (b) { b.dataset.ls = st.state; b.title = st.title; }
  },
  // Keep a panel badge painted: returns the unsubscribe.
  badge(ctx, sourceId, fmt) {
    live.paintBadge(ctx, sourceId, fmt);
    return live.onStatus(() => live.paintBadge(ctx, sourceId, fmt));
  },
};

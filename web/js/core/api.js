// Thin fetch wrapper around the backend API.
// Paths are resolved relative to the page, so the app works at / or behind a prefix such as /cyberintel/.
const rel = (path) => path.replace(/^\//, '');

// A 401: the server asks for its password (OSINTHUB_PASSWORD) and the browser's sign-in has gone (or was refused).
// One plain banner, once; the request still fails normally so each view shows its own error state.
let signInShown = false;
function signInAgain() {
  if (signInShown || !document.body) return;
  signInShown = true;
  const d = document.createElement('div');
  d.className = 'nd-signin';
  d.setAttribute('role', 'alert');
  d.innerHTML = '<span>Sign in again: reload the page.</span><button type="button" class="nd-signin-btn">Reload</button>';
  d.querySelector('button').addEventListener('click', () => location.reload());
  document.body.append(d);
}

async function req(method, path, body) {
  const opts = { method, headers: {} };
  if (body instanceof FormData) opts.body = body;
  else if (body !== undefined) { opts.body = JSON.stringify(body); opts.headers['Content-Type'] = 'application/json'; }
  const r = await fetch(rel(path), opts);
  if (!r.ok) {
    if (r.status === 401) signInAgain();
    let msg = r.statusText;
    try { msg = (await r.json()).detail || msg; } catch {}
    const err = new Error(msg);
    err.status = r.status; // lets callers tell a real 404 from a transient failure
    throw err;
  }
  return r.json();
}

function qs(params = {}) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) continue;
    p.set(k, Array.isArray(v) ? v.join(',') : v);
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

let healthP = null;
let sqlOn = false;   // from /api/health: the SQL console is on (OSINTHUB_SQL_CONSOLE=1); false until known
// Whether the SQL console is on. Off (the default) hides its entry points; the Explorer page explains how to turn it on.
export const sqlConsoleOn = () => sqlOn;
export const api = {
  get: (path, params) => req('GET', path + qs(params)),
  post: (path, body, params) => req('POST', path + qs(params), body),
  put: (path, body) => req('PUT', path, body),
  patch: (path, body) => req('PATCH', path, body),
  del: (path) => req('DELETE', path),

  sources: () => req('GET', '/api/sources'),
  setSourceEnabled: (id, enabled) => req('POST', `/api/sources/${id}/enable${qs({ enabled })}`),
  runSource: (id) => req('POST', `/api/sources/${id}/run`),
  sourceRuns: (id) => req('GET', `/api/sources/${id}/runs`),

  // params: kinds, sources, categories (arrays), since_hours, q, country, geo, limit, offset, order
  events: (params) => req('GET', '/api/events' + qs(params)),
  event: (id) => req('GET', `/api/events/${encodeURIComponent(id)}`),
  // returns {fields, rows: [[lon,lat,sev,kind,id,title,country,t]]}
  points: (params) => req('GET', '/api/geo/points' + qs(params)),
  cables: () => req('GET', '/api/geo/cables'),
  fetchCables: () => req('POST', '/api/geo/cables/fetch'),   // opt-in: TeleGeography's files, downloaded once
  basemaps: () => req('GET', '/api/geo/basemaps'),            // {carto_key}: online basemaps only with the user's key
  landings: () => req('GET', '/api/geo/landings'),
  countries: () => req('GET', '/api/geo/countries'),

  summary: (params) => req('GET', '/api/stats/summary' + qs(params)),
  timeline: (params) => req('GET', '/api/stats/timeline' + qs(params)),     // [{t, kind, n}]
  byCountry: (params) => req('GET', '/api/stats/countries' + qs(params)),   // [{country, n, sev, kinds:{kind:n}}]
  top: (params) => req('GET', '/api/stats/top' + qs(params)),               // [{key, n}]; field=ip adds feeds, sources, sev, last, country
  metrics: (names, minutes) => req('GET', '/api/metrics' + qs({ names, minutes })), // [{name, ts, value}]
  pulse: () => req('GET', '/api/pulse'),
  // Cached server info. `offline` means no outbound requests at all, browser included (map tiles, avatars).
  // If it cannot be read, the client assumes offline: private by default.
  health: () => (healthP ||= req('GET', '/api/health').then((h) => { sqlOn = h?.sql_console === true; return h; })
    .catch(() => ({ offline: true }))),

  sql: (sql) => req('POST', '/api/sql', { sql }),   // the SQL console only (off unless OSINTHUB_SQL_CONSOLE=1)
  kevIds: () => req('GET', '/api/kev/ids'),          // {ids: [CVE ids in CISA KEV]}
  asnOrgs: (asns) => req('GET', `/api/asn/orgs${qs({ asn: asns })}`),   // {orgs: {AS: name}}, at most 200 per call
  // latest FIRST EPSS for many CVE ids: {score_date, model_version, scores: {CVE: {epss, percentile, prev_epss, since}}}
  // a GET (v1.2) so read-only clients can call it; callers send at most 500 ids per call (feeds.js chunks)
  epss: (ids) => req('GET', `/api/news/epss${qs({ ids })}`),
  upload: (file, label) => { const f = new FormData(); f.append('file', file); f.append('label', label); return req('POST', '/api/upload', f); },
};

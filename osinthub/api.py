"""HTTP API + static web client."""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import decimal
import hashlib
import ipaddress
import logging
import math
import re
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import duckdb
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

from . import analytics, apiutil, bootstrap, bus, config, db, ext, httpguard, lake, scheduler
from .sources import SOURCES
from .sources.base import Source, now
from .sources import upload as upload_src

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("osinthub.api")

# The same refusal as `python -m osinthub`, for any other way of loading the app (uvicorn osinthub.api:app, fastapi
# run): a non-loopback OSINTHUB_HOST without a password, or a password that is too short. A bind given only on the
# uvicorn command line (--host 0.0.0.0) is not visible here; _open_bind_refusal below covers it per request.
if (_problem := config.bind_problem()) is not None:
    raise SystemExit(f"osinthub: {_problem}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.connect()
    bus.bind_loop(asyncio.get_running_loop())
    await bootstrap.ensure_reference_data()
    await scheduler.start_all()
    await ext.start()
    from . import search_all
    search_all.start_warm()   # global search indexes, in a background daemon thread
    yield
    await ext.stop()
    await scheduler.stop_all()


# FastAPI's /docs and /redoc pull unpinned scripts from a CDN into this origin (and break offline mode): developer-only.
_DOCS = config.DEBUG
app = FastAPI(title="Night Desk", lifespan=lifespan, docs_url="/docs" if _DOCS else None,
              redoc_url="/redoc" if _DOCS else None, openapi_url="/openapi.json" if _DOCS else None)
# Compressed responses (v1.2 m-perf, design §6): app.css, the scripts and the JSON shrink 4-8x for a phone on a slow
# link. Added before _guard below, so it sits inside it and sees each response as the route sent it (the 1 KB minimum
# only works on an unchunked body); level 6 keeps the CPU cost low for large JSON. Starlette leaves text/event-stream
# (the live stream, /api/stream) and images/fonts uncompressed, and keeps every other header (Cache-Control: no-cache
# on the web files, ETag for the 304s).
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=6)

# Request-body cap (L2): JSON and form bodies are small; /api/upload gets its file cap plus the envelope (below). Network-log imports get 2 GB per request: the same as the device-upload listener's default limit (max_mb 2048),
# room for a day of a busy home network's uncompressed Zeek logs or weeks of gzipped ones; bigger sets go through the
# watched inbox folder, which has no request at all. okf/data/netlog.md#import
MAX_BODY = 16 << 20
NETLOG_IMPORT_MAX = 2 << 30
# /api/upload: the 64 MB file cap (sources/upload.py MAX_BYTES, lane harden) plus 1 MB for the multipart envelope,
# counted here while the body streams in. The route's own check runs only after Starlette has spooled the whole body
# to a temporary file, so without this entry one request of any size could fill the temp disk first.
UPLOAD_MAX_BODY = (64 << 20) + (1 << 20)
BODY_LIMITS = {"/api/upload": UPLOAD_MAX_BODY, "/api/netlog/import": NETLOG_IMPORT_MAX}
_BODY_MSG = {"/api/upload": "This file is larger than 64 MB, the most one upload takes. Split it, or keep the first "
                            "200,000 rows.",
             "/api/netlog/import": "This import is larger than 2 GB, the most one upload takes. Import the files in "
                                   "smaller batches, or copy them into the watched inbox folder."}


class _BodyTooLarge(HTTPException):
    def __init__(self, path: str = "", limit: int = MAX_BODY):
        super().__init__(413, _BODY_MSG.get(path) or f"request body is larger than the {limit >> 20} MB limit")


class _BodyCap:
    """413 for a request body over its route's limit (BODY_LIMITS, else MAX_BODY): at once when Content-Length says
    so, and while reading when the body streams in without one (chunked). Raised from `receive`, so FastAPI passes the
    HTTPException through its body or multipart parsing and answers 413 before the route runs (an import over the cap
    stores nothing in the lake: the parts so far sit in anonymous temporary files that vanish when closed); anything
    that swallows it gets the 413 here."""

    def __init__(self, app, limit: int = MAX_BODY, limits: dict | None = None):
        self.app, self.limit, self.limits = app, limit, BODY_LIMITS if limits is None else limits

    @staticmethod
    async def _refuse(scope, receive, send, err):
        await JSONResponse({"detail": err.detail}, status_code=413)(scope, receive, send)

    async def __call__(self, scope, receive, send):
        path = scope.get("path") or ""
        limit = self.limits.get(path, self.limit) if scope["type"] == "http" else None
        if limit is None:
            return await self.app(scope, receive, send)
        cl = dict(scope.get("headers") or []).get(b"content-length")
        if cl is not None and (not cl.strip().isdigit() or int(cl) > limit):
            return await self._refuse(scope, receive, send, _BodyTooLarge(path, limit))
        seen, started = 0, False

        async def capped():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body") or b"")
                if seen > limit:
                    raise _BodyTooLarge(path, limit)
            return msg

        async def tracked(msg):
            nonlocal started
            started = started or msg["type"] == "http.response.start"
            await send(msg)

        try:
            await self.app(scope, capped, tracked)
        except _BodyTooLarge as e:
            if started:
                raise
            await self._refuse(scope, receive, send, e)


app.add_middleware(_BodyCap)


# Content-Security-Policy (M5), on every response. Scripts only from this server (plus the hashes of index.html's own
# inline scripts); no plugins, no <base>, no framing, forms post only here. External origins only for the opt-in
# features that need them, and none at all in offline mode (the browser then cannot reach the internet either).
# Every origin with the feature that needs it: okf/architecture/deployment.md#content-security-policy
CSP_ONLINE = {
    "img-src": ["https://cdn.bsky.app"],                       # Bluesky avatars (opt-in, Feeds panel)
    "connect-src": ["https://public.api.bsky.app"],            # Bluesky names and avatars (opt-in)
}
# Only with the user's own CARTO key (CARTO_API_KEY): the online basemaps Dark Matter and Positron.
CSP_CARTO = {"connect-src": ["https://basemaps.cartocdn.com",       # style.json
                             "https://*.basemaps.cartocdn.com"]}    # ... their tiles, sprites and glyphs
_SCRIPT_RE = re.compile(rb"<script(?![^>]*\ssrc=)[^>]*>(.*?)</script>", re.S | re.I)
_inline_hashes: tuple[float, list[str]] = (-1.0, [])


def _script_hashes() -> list[str]:
    """'sha256-...' for each inline <script> in web/index.html, recomputed when the file changes."""
    global _inline_hashes
    page = config.WEB_DIR / "index.html"
    try:
        mtime = page.stat().st_mtime
        if mtime != _inline_hashes[0]:
            _inline_hashes = (mtime, [f"'sha256-{base64.b64encode(hashlib.sha256(m).digest()).decode()}'"
                                      for m in _SCRIPT_RE.findall(page.read_bytes())])
    except OSError:
        pass
    return _inline_hashes[1]


def csp(offline: bool | None = None) -> str:
    """The policy for one response; `offline` defaults to config.OFFLINE."""
    online = not (config.OFFLINE if offline is None else offline)
    carto = config.CARTO_API_KEY is not None
    extra = (lambda k: CSP_ONLINE.get(k, []) + (CSP_CARTO.get(k, []) if carto else [])) if online else (lambda k: [])
    d = {
        "default-src": ["'self'"],
        "script-src": ["'self'", *_script_hashes()],
        # Inline style attributes (the views' markup) and the <style> elements gridstack, cytoscape and globe.gl add.
        "style-src": ["'self'", "'unsafe-inline'"],
        # data: the favicon and SVG icons; blob: map tiles MapLibre decodes into images
        "img-src": ["'self'", "data:", "blob:", *extra("img-src")],
        "connect-src": ["'self'", *extra("connect-src")],
        "worker-src": ["'self'", "blob:"],                     # MapLibre starts its workers from blob: URLs
        "object-src": ["'none'"], "base-uri": ["'none'"], "frame-ancestors": ["'none'"], "form-action": ["'self'"],
    }
    return "; ".join(f"{k} {' '.join(v)}" for k, v in d.items())


# Sign-in throttle: 10 different wrong passwords from one client (IPv6: its /64) in 10 minutes -> 429 for 15 minutes;
# at most 4096 clients tracked (httpguard.Throttle).
AUTH_THROTTLE = httpguard.Throttle(limit=10, window=600, block=900, max_keys=4096)      # per exact address
# IPv6: one device can rotate through its /64, so the /64 has its own, looser count (50 distinct wrong passwords in
# 10 minutes). It is never cleared by a correct password, so an owner's polling tab cannot hide a neighbour's guesses.
AUTH_NET_THROTTLE = httpguard.Throttle(limit=50, window=600, block=900, max_keys=1024)
_UNAUTHORIZED = {"WWW-Authenticate": 'Basic realm="Night Desk"'}


def _auth_refusal(request) -> JSONResponse | None:
    """401/429 when a password is set and this request does not carry it (HTTP Basic, any user name), else None.
    GET /api/health from this machine is exempt (the Docker health check, local monitors)."""
    if not config.AUTH_REQUIRED:
        return None
    ip = request.client.host if request.client else ""
    if request.method == "GET" and request.url.path == "/api/health" and httpguard.is_loopback(ip):
        return None
    addr, net = httpguard.address_key(ip), httpguard.net_key(ip)
    left = max(AUTH_THROTTLE.blocked(addr), AUTH_NET_THROTTLE.blocked(net))
    if left:
        return JSONResponse({"detail": "too many wrong passwords from this address; try again later"},
                            status_code=429, headers={"Retry-After": str(int(left) + 1)})
    header = request.headers.get("authorization")
    given = httpguard.basic_password(header)
    if httpguard.password_ok(given, config.PASSWORD):
        AUTH_THROTTLE.ok(addr)                              # this exact address only; the /64 count stands
        return None
    # A wrong (or garbled) credential, not a first visit. Each distinct one counts once: a tab polling with an old
    # password is one failure, however often it asks.
    if header is not None:
        tag = httpguard.credential_tag(given if given is not None else header)
        if AUTH_THROTTLE.fail(addr, tag):
            log.warning("sign-in: %s blocked for %ds after %d different wrong passwords", addr,
                        AUTH_THROTTLE.block, AUTH_THROTTLE.limit)
        if AUTH_NET_THROTTLE.fail(net, tag):
            log.warning("sign-in: %s blocked for %ds after %d different wrong passwords from that network", net,
                        AUTH_NET_THROTTLE.block, AUTH_NET_THROTTLE.limit)
    return JSONResponse({"detail": "sign-in needed: this Night Desk asks for its password (any user name)"},
                        status_code=401, headers=_UNAUTHORIZED)


_open_bind_logged = False


def _open_bind_refusal(request) -> JSONResponse | None:
    """No password and no trusted proxy, yet this request reached a non-loopback address of this machine: the app was
    started some other way with a public bind (uvicorn --host 0.0.0.0, fastapi run). Refuse it (503) rather than serve
    an open admin API; requests over loopback still work."""
    global _open_bind_logged
    if config.PASSWORD or config.TRUST_PROXY_AUTH:
        return None
    server = request.scope.get("server")
    addr = server[0] if server else ""
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return None                                         # a unix socket or a test client: not a network address
    if httpguard.is_loopback(addr):
        return None
    if not _open_bind_logged:
        _open_bind_logged = True
        log.error("refusing requests to %s: Night Desk is listening beyond this machine without OSINTHUB_PASSWORD", addr)
    return JSONResponse({"detail": "Night Desk is listening beyond this machine without a password, so it answers only "
                                   "on this machine. Set OSINTHUB_PASSWORD, or bind 127.0.0.1."}, status_code=503)


def _refusal(request) -> JSONResponse | None:
    if (refused := _open_bind_refusal(request)) is not None:
        return refused
    # DNS rebinding: a hostile page can point its own name at 127.0.0.1 and then read this API as
    # "same-origin". The browser still sends that name in Host, so only this machine's loopback
    # names and the configured OSINTHUB_ALLOWED_HOSTS are served.
    host = request.headers.get("host", "")
    if config.host_name(host) not in config.ALLOWED_HOSTS:
        return JSONResponse({"detail": f"host {host[:100]!r} is not allowed: Night Desk answers only localhost, "
                                       "127.0.0.1, [::1] and the names in OSINTHUB_ALLOWED_HOSTS (comma-separated). "
                                       "Opening it to other machines also needs OSINTHUB_PASSWORD (or a reverse "
                                       "proxy that asks for a password); see the deployment notes"},
                            status_code=421)
    # Sign-in (OSINTHUB_PASSWORD): after the Host check, before anything else.
    if (refused := _auth_refusal(request)) is not None:
        return refused
    # CSRF: a state-changing request must come from this app's own pages, not a cross-site page replaying the
    # browser's cached basic-auth credential (ours or Caddy's). Runs whether or not a password is set.
    if (why := httpguard.cross_site(request.method, request.headers, request.url.scheme)) is not None:
        return JSONResponse({"detail": why}, status_code=403)
    return None


@app.middleware("http")
async def _guard(request, call_next):
    resp = _refusal(request) or await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    # OSINTHUB_DEBUG's API explorer pages are FastAPI's own (inline and CDN scripts): framing is all they keep.
    docs_page = _DOCS and request.url.path in ("/docs", "/docs/oauth2-redirect", "/redoc")
    resp.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'" if docs_page else csp())
    return resp


_csv = apiutil.csv_list


# A time window longer than this many hours (about 200 years) is the same as no window: all history.
MAX_WINDOW_HOURS = 24 * 365 * 200


def _hours(v: float | None, name: str = "since_hours") -> float | None:
    """A validated time window in hours: None (no window) stays None, NaN / inf / negative is a 400, and
    anything above MAX_WINDOW_HOURS means all history (None)."""
    if v is None:
        return None
    if not math.isfinite(v) or v < 0:
        raise HTTPException(400, f"{name} must be a finite number >= 0")
    return None if v > MAX_WINDOW_HOURS else v


def _us(hours: float) -> int:
    """A window in hours as whole microseconds, for `now() - to_microseconds(?)`: fractions count
    (0.5 is 30 minutes; INTERVAL (0.5) HOUR would truncate to 0) and 0 is an empty window."""
    return int(round(hours * 3_600_000_000))


like = apiutil.like


def _where(kinds=None, sources=None, categories=None, since_hours=None, q=None, country=None, geo=False):
    clauses, params = [], []
    if kinds:
        clauses.append(f"kind IN ({','.join('?' * len(kinds))})"); params += kinds
    if sources:
        clauses.append(f"source IN ({','.join('?' * len(sources))})"); params += sources
    if categories:
        clauses.append(f"category IN ({','.join('?' * len(categories))})"); params += categories
    if since_hours is not None:   # 0 is an empty window, not "all history"
        clauses.append("ts > now() - to_microseconds(?)"); params.append(_us(since_hours))
    if q:
        clauses.append("(title ILIKE ? ESCAPE '\\' OR summary ILIKE ? ESCAPE '\\' OR ip = ? OR lower(asn) = lower(?) OR list_contains(tags, ?))")
        params += [like(q), like(q), q, q, q]
    if country:
        clauses.append("country = ?"); params.append(country.upper())
    if geo:
        clauses.append("lat IS NOT NULL AND lon IS NOT NULL")
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


# Indicator feeds that re-list addresses other lists already carry (ThreatFox and URLhaus repeat Feodo C2s and
# each other; one IP can be several ThreatFox IOCs, one per port or family). okf/sources/current/threatfox.md#map
CORROBORATING_SOURCES = ("threatfox", "urlhaus", "sslbl")
_RELIST = "(" + ", ".join(f"'{s}'" for s in CORROBORATING_SOURCES) + ")"


def _rep_key(first: bool = False) -> str:
    """The sort key that picks the event standing for an address (the largest wins, with arg_max): an original listing
    before a re-listing feed's copy, then the most severe, then the newest, then the id; `_first` before all that."""
    return ("{" + ("'z': _first, " if first else "") +
            f"'a': source NOT IN {_RELIST}, 'b': coalesce(severity, -1), 'c': ts, 'd': id" + "}")


def _one_per_ip(w: str, cols: str = "*", first: str | None = None) -> str:
    """events{w} with each address counted once, for every count the dashboard shows (the map, Threat Origins, Top
    Offenders, the Activity timeline and the kind totals), so they agree for the same window and filters. Of the
    selected events sharing an IP one stands for it (_rep_key: an original listing before a re-listing feed's copy
    (CORROBORATING_SOURCES), then the most severe, then the newest). Events without an IP are all kept. The filters
    in `w` apply first, so a kind filter counts every address that kind lists. /api/events still lists every event.
    `cols`: "*" or plain column names. `first`: an SQL condition whose events are preferred before all that, kept as
    column `_first` (the summary's "in the window", so an address's all-history event is its in-window one whenever
    it has one). One grouped arg_max per address (a DuckDB aggregate, no per-row Python and no window sort)."""
    extra = f", ({first}) AS _first" if first else ""
    row = "f" if cols.strip() == "*" else "{" + ", ".join(f"'{c.strip()}': {c.strip()}" for c in cols.split(",")) + "}"
    return f"""(WITH f AS (SELECT *{extra} FROM events{w})
               SELECT {cols} FROM f WHERE ip IS NULL OR ip = ''
               UNION ALL
               SELECT unnest(arg_max({row}, {_rep_key(bool(first))})) FROM f WHERE ip <> '' GROUP BY ip)"""


def _feed_name(sid: str) -> str:
    s = SOURCES.get(sid)
    return s.name if s else sid


def _feeds_by_ip(ips: list[str], w: str = "", p: list | None = None) -> dict[str, list[dict]]:
    """The distinct feeds that listed each address among the events{w} selection: {ip: [{source, name, last, events}]},
    newest listing first. One grouped DuckDB query over the given addresses; corroboration, not a confidence score
    (some feeds copy each other). Shown in the local UI only: never put into an AI prompt or an export (abuse.ch terms)."""
    ips = [i for i in dict.fromkeys(ips) if i]
    if not ips:
        return {}
    cond = (w + " AND " if w else " WHERE ") + "ip IN (SELECT unnest(?::VARCHAR[]))"
    rows = db.cursor().execute(
        f"SELECT ip, source, max(ts) AS last, count(*) AS n FROM events{cond} GROUP BY ip, source "
        "ORDER BY ip, last DESC, source", (p or []) + [ips]).fetchall()
    out: dict[str, list[dict]] = {}
    for ip, src, last, n in rows:
        out.setdefault(ip, []).append({"source": src, "name": _feed_name(src), "last": last.isoformat() if last else None,
                                       "events": n})
    return out


def _jsonable(rows):
    for r in rows:
        for k, v in list(r.items()):
            if isinstance(v, dt.datetime):
                r[k] = v.isoformat()
    return rows


# ------------------------------------------------------------------ sources
@app.get("/api/sources")
def list_sources():
    states = {r["id"]: r for r in db.query("SELECT * FROM source_state")}
    out = []
    for s in SOURCES.values():
        st = states.get(s.id, {})
        d = s.describe()
        d.update({k: st.get(k) for k in ("status", "message", "last_run", "last_ok", "items_last", "items_total")})
        d["enabled"] = scheduler.is_enabled(s)
        out.append(d)
    return _jsonable(out)


def _src(sid: str) -> Source:
    if sid not in SOURCES:
        raise HTTPException(404, "unknown source")
    return SOURCES[sid]


@app.post("/api/sources/{sid}/enable")
async def enable_source(sid: str, enabled: bool = Query(...)):
    # async: the source's task is created on the app's event loop (a sync endpoint runs in a worker thread,
    # where asyncio.create_task has no running loop). Its database writes run in a worker thread, so a toggle
    # during a netlog import waits for the write lock without stalling other requests.
    s = _src(sid)
    if enabled and (why := s.unavailable()):
        raise HTTPException(409, why)
    await scheduler.set_enabled(s, enabled)
    return {"id": sid, "enabled": enabled}


@app.post("/api/sources/{sid}/run")
async def run_source(sid: str):
    s = _src(sid)
    if s.mode != "batch":
        raise HTTPException(400, "stream sources run continuously")
    if (why := s.unavailable()):   # no key: nothing to run, and the source's state is left as it was
        raise HTTPException(409, why)
    res = await scheduler.run_batch(s)
    if res.get("running"):   # a run of this source is already in progress (scheduled, or an earlier Run now)
        raise HTTPException(409, "already running")
    return res


@app.get("/api/sources/{sid}/runs")
def source_runs(sid: str, limit: int = Query(20, ge=0, le=1000)):
    _src(sid)  # 404 for an unknown source, not an empty list that looks like "never ran"
    return _jsonable(db.query("SELECT * FROM runs WHERE source = ? ORDER BY started DESC LIMIT ?", [sid, limit]))


# ------------------------------------------------------------------ events
@app.get("/api/events")
def events(kinds: str | None = None, sources: str | None = None, categories: str | None = None,
           since_hours: float | None = None, q: str | None = None, country: str | None = None,
           geo: bool = False, limit: int = Query(200, ge=0, le=5000), offset: int = Query(0, ge=0, le=2**63 - 1), order: str = "ts"):
    w, p = _where(_csv(kinds), _csv(sources), _csv(categories), _hours(since_hours), q, country, geo)
    # id breaks ties, so offset pages are disjoint and cover every row (many events share a ts or severity)
    orders = {"ts": "ts DESC, id", "severity": "severity DESC NULLS LAST, ts DESC, id"}
    if order not in orders:   # a typo is reported, not silently replaced by the default
        raise HTTPException(400, f"order must be one of {', '.join(orders)}")
    order_sql = orders[order]
    rows = db.query(f"SELECT * EXCLUDE (raw_path) FROM events{w} ORDER BY {order_sql} LIMIT ? OFFSET ?", p + [limit, offset])
    return _jsonable(rows)


@app.get("/api/events/{eid:path}")
def event(eid: str):
    rows = db.query("SELECT * FROM events WHERE id = ?", [eid])
    if not rows:
        raise HTTPException(404)
    e = rows[0]
    related = []
    if e.get("ip"):
        related = db.query("SELECT id, source, kind, title, ts FROM events WHERE ip = ? AND id <> ? ORDER BY ts DESC LIMIT 20", [e["ip"], eid])
    elif e.get("asn"):
        related = db.query("SELECT id, source, kind, title, ts FROM events WHERE asn = ? AND id <> ? ORDER BY ts DESC LIMIT 20", [e["asn"], eid])
    e["related"] = _jsonable(related)
    # "Listed by N feeds": every feed that listed this address in all the lake holds (corroboration, local UI only)
    e["reported_by"] = _feeds_by_ip([e["ip"]]).get(e["ip"], []) if e.get("ip") else []
    try:   # vulnerability events: their CVEs (CVSS, KEV, EPSS, CISA advisories) and the news stories covering them
        from .sources.vulns import event_vuln_context
        e.update(event_vuln_context(e))
    except Exception as ex:
        log.warning("event %s: vulnerability context failed: %s", eid, ex)
    e["entities"] = _event_entities(e)
    return _jsonable([e])[0]


def _event_entities(e: dict) -> list[dict]:
    """Entities an event links to (its mentions), plus, for indicator feeds (ThreatFox, URLhaus), the malware family
    its indicators' observed claims point at: the event drawer links to them. [] without the entities tables."""
    try:
        ents = db.query("""SELECT DISTINCT e.id, e.type, e.name, m.role FROM mentions m JOIN entities e ON e.id = m.entity_id
                           WHERE m.ref_type = 'event' AND m.ref_id = ? ORDER BY e.type, e.id LIMIT 40""", [e["id"]])
        ids = [x["id"] for x in ents if x["type"] in ("ip", "domain", "url", "hash")]
        if ids and e.get("source") in CORROBORATING_SOURCES:
            have = {x["id"] for x in ents}
            for f in db.query("""SELECT DISTINCT o.id, o.type, o.name, c.predicate FROM claims c JOIN entities o ON o.id = c.obj
                                 WHERE c.subj IN (SELECT unnest(?)) AND c.origin = 'observed' AND list_contains(c.sources, ?)
                                   AND o.type IN ('malware', 'tool') LIMIT 10""", [ids, e["source"]]):
                if f["id"] not in have:
                    ents.append({"id": f["id"], "type": f["type"], "name": f["name"], "role": f["predicate"]})
        return ents
    except Exception:  # noqa: BLE001  (entities package off or tables not created yet)
        return []


# ------------------------------------------------------------------ geo
_GEO_COLS = "lon, lat, severity, kind, id, title, country, ts"   # what /api/geo/points reads of each counted event


@app.get("/api/geo/points")
def geo_points(kinds: str | None = None, sources: str | None = None, since_hours: float | None = None,
               q: str | None = None, limit: int = Query(20000, ge=0, le=100000), spread: bool = False):
    """Newest first. With spread=1 and more points than `limit`, every k-th point in time order instead of the newest
    `limit`, so a long window (Cinema ALL) covers its whole span rather than only its last days."""
    w, p = _where(_csv(kinds), _csv(sources), None, _hours(since_hours), q, None, True)
    cols = ("round(lon, 3), round(lat, 3), round(coalesce(severity, 0.4), 2), kind, id, title, country, "
            "epoch(ts)::BIGINT")
    if spread and limit:
        sql = (f"SELECT {cols} FROM (SELECT *, row_number() OVER (ORDER BY ts DESC, id) - 1 AS _rn, count(*) OVER () AS _n "
               f"FROM {_one_per_ip(w, _GEO_COLS)}) WHERE _rn % greatest(1, ceil(_n / ?)::BIGINT) = 0 ORDER BY ts DESC LIMIT ?")
        rows = db.cursor().execute(sql, p + [limit, limit]).fetchall()
    else:
        rows = db.cursor().execute(f"SELECT {cols} FROM {_one_per_ip(w, _GEO_COLS)} ORDER BY ts DESC LIMIT ?", p + [limit]).fetchall()
    return {"fields": ["lon", "lat", "sev", "kind", "id", "title", "country", "t"], "rows": rows}


def _ref(path: Path):
    # A brand-new offline lake has no reference geometry yet: an empty layer flagged "missing" (not a 404), so the
    # map draws without it and the browser logs no failed request.
    if not path.exists():
        return JSONResponse({"type": "FeatureCollection", "features": [], "missing": True, "file": path.name},
                            headers={"Cache-Control": "no-store"})
    return FileResponse(path, media_type="application/json", headers={"Cache-Control": "max-age=86400"})


@app.get("/api/geo/cables")
def cables():
    return _ref(config.CABLES_GEOJSON)


@app.get("/api/geo/landings")
def landings():
    return _ref(config.LANDINGS_GEOJSON)


@app.post("/api/geo/cables/fetch")
async def fetch_cables():
    """Download TeleGeography's cable and landing-point files once, when the user turns the cable layer on (they are
    never fetched at start: okf/project/pre-alpha-release.md, terms item 3). 409 in offline mode, 502 when the
    download fails; {"downloaded": false} when the files are already here."""
    try:
        got = await bootstrap.fetch_cables()
    except bootstrap.CablesUnavailable as e:
        raise HTTPException(409 if config.OFFLINE else 502, str(e))
    return {"downloaded": got}


@app.get("/api/geo/basemaps")
def basemaps():
    """The online basemaps the map may offer: CARTO's styles only with the user's own key (CARTO_API_KEY), which the
    browser then adds to CARTO's style URL as CARTO asks; none in offline mode."""
    key = None if config.OFFLINE else config.CARTO_API_KEY
    return JSONResponse({"carto_key": key}, headers={"Cache-Control": "no-store"})


@app.get("/api/geo/countries")
def countries():
    return _ref(config.COUNTRIES_GEOJSON)


# ------------------------------------------------------------------ stats
@app.get("/api/stats/summary")
def summary(since_hours: float = 24):
    """Kind totals: `total` over all history and `recent` in the window, each address counted once (_one_per_ip; an
    address several kinds list counts under the kind of the event standing for it). `totals.events` and
    `totals.recent` are stored records (every row), `totals.ips` the distinct addresses."""
    h = _hours(since_hours)
    recent, p = ("TRUE", []) if h is None else ("ts > now() - to_microseconds(?)", [_us(h)])  # None: all history
    # one pass over all history; an address with an event in the window is represented by that event (the same one
    # the window alone picks), so each kind's `recent` is the timeline's for the window and never above its `total`
    by_kind = db.query(
        f"SELECT kind, category, count(*) AS total, count(*) FILTER (WHERE _first) AS recent "
        f"FROM {_one_per_ip('', 'kind, category, _first', first=recent)} GROUP BY ALL ORDER BY total DESC, kind", p)
    tot = db.query(f"SELECT count(*) AS events, count(*) FILTER (WHERE {recent}) AS recent, "
                   "count(DISTINCT nullif(ip, '')) AS ips, count(DISTINCT country) AS countries, "
                   "max(ingested_at) AS last_ingest FROM events", p)[0]
    return _jsonable([{"totals": tot, "kinds": by_kind}])[0]


@app.get("/api/stats/timeline")
def timeline(hours: float = 72, bucket: str = "hour", kinds: str | None = None, categories: str | None = None,
             q: str | None = None):
    """Events per bucket and kind, each address counted once in the selection (_one_per_ip, as on the map): it sits
    in the bucket and kind of the event standing for it. `a`: how many of the `n` are addresses (the rest are events
    without one), so the panel can say which it counts."""
    if bucket not in ("minute", "hour", "day"):
        raise HTTPException(400)
    w, p = _where(_csv(kinds), None, _csv(categories), _hours(hours, "hours"), q)
    rows = db.query(f"SELECT date_trunc('{bucket}', ts) AS t, kind, count(*) AS n, count(*) FILTER (WHERE ip <> '') AS a "
                    f"FROM {_one_per_ip(w, 'ts, kind, ip')} GROUP BY t, kind ORDER BY t, kind", p)
    return _jsonable(rows)


@app.get("/api/stats/countries")
def by_country(since_hours: float | None = None, kinds: str | None = None, categories: str | None = None):
    w, p = _where(_csv(kinds), None, _csv(categories), _hours(since_hours))
    w = (w + " AND " if w else " WHERE ") + "country IS NOT NULL"
    return db.query(
        f"SELECT country, count(*) AS n, round(avg(severity), 3) AS sev, "
        f"histogram(kind) AS kinds FROM {_one_per_ip(w, 'country, severity, kind')} GROUP BY country ORDER BY n DESC", p)


@app.get("/api/stats/top")
def top(field: str = "asn", kinds: str | None = None, since_hours: float | None = None,
        limit: int = Query(15, ge=0, le=10000), sort: str = "n"):
    """[{key, n, a}] ranked by n (each address counted once; `a` of the `n` are addresses, the rest events without
    one). field=ip gives one row per address with its corroboration: `feeds` (distinct feeds that listed it in the
    selection), `sources` ([{source, name, last, events}]), `sev` (the highest severity any of them gives it), `last`
    (its newest listing) and the `country` of the event standing for it; ranked by `sev` then `last`, or with
    sort=feeds by `feeds` first (ip only)."""
    if field not in ("asn", "country", "tags", "source", "kind", "ip"):
        raise HTTPException(400)
    if sort not in ("n", "feeds") or (sort == "feeds" and field != "ip"):
        raise HTTPException(400, "sort must be n, or feeds with field=ip")
    w, p = _where(_csv(kinds), None, None, _hours(since_hours))
    if field != "ip":
        expr = "unnest(tags)" if field == "tags" else field
        return db.query(f"SELECT {expr} AS key, count(*) AS n, count(*) FILTER (WHERE ip <> '') AS a "
                        f"FROM {_one_per_ip(w, f'{field}, ip')} GROUP BY 1 HAVING key IS NOT NULL AND key <> '' "
                        "ORDER BY n DESC, key LIMIT ?", p + [limit])
    # One row per address (n is 1: each address counts once), with the number of distinct feeds in the same selection
    # beside it, all in one grouped query; the feed names are looked up for the returned rows only.
    wi = (w + " AND " if w else " WHERE ") + "ip <> ''"
    order = "feeds DESC, sev DESC NULLS LAST, last DESC, key" if sort == "feeds" else "n DESC, sev DESC NULLS LAST, last DESC, key"
    rows = db.query(
        f"""SELECT key, 1 AS n, 1 AS a, feeds, sev, last, r.country AS country FROM (
                SELECT ip AS key, count(DISTINCT source) AS feeds, max(severity) AS sev, max(ts) AS last,
                       arg_max({{'country': country}}, {_rep_key()}) AS r
                FROM events{wi} GROUP BY ip)
            ORDER BY {order} LIMIT ?""", p + [limit])
    by = _feeds_by_ip([r["key"] for r in rows], w, p)
    for r in rows:
        r["sources"] = by.get(r["key"], [])
    return _jsonable(rows)


@app.get("/api/stats/feeds")
def feeds_for(ips: str, since_hours: float | None = None, kinds: str | None = None, categories: str | None = None):
    """Corroboration for up to 500 addresses: [{ip, feeds, sources: [{source, name, last, events}]}], the distinct
    feeds that listed each address among the selected events (all history without since_hours). Some feeds copy each
    other (ThreatFox and URLhaus repeat Feodo C2s), so N feeds is not always N independent reports."""
    want = _csv(ips) or []
    if len(want) > 500:
        raise HTTPException(400, "at most 500 addresses")
    try:   # one spelling per address, as the feeds store it (2001:DB8::5 is 2001:db8::5)
        want = [str(ipaddress.ip_address(x)) for x in want]
    except ValueError as ex:
        raise HTTPException(400, f"not an IP address: {str(ex)[:120]}")
    w, p = _where(_csv(kinds), None, _csv(categories), _hours(since_hours))
    by = _feeds_by_ip(want, w, p)
    return [{"ip": ip, "feeds": len(by.get(ip, [])), "sources": by.get(ip, [])} for ip in dict.fromkeys(want)]


@app.get("/api/metrics")
def metrics(names: str, minutes: float = 60):
    h = _hours(minutes / 60 if math.isfinite(minutes) else minutes, "minutes")
    window, p = ("", []) if h is None else (" AND ts > now() - to_microseconds(?)", [_us(h)])
    rows = db.query(
        f"SELECT name, ts, value FROM metrics WHERE name IN ({','.join('?' * len(_csv(names)))})"
        f"{window} ORDER BY ts", _csv(names) + p)
    return _jsonable(rows)


@app.get("/api/pulse")
def get_pulse():
    return analytics.pulse()


# ------------------------------------------------------------------ live stream
@app.get("/api/stream")
async def stream():
    q = bus.subscribe()

    async def gen():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"data: {msg}\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            bus.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ------------------------------------------------------------------ batch upload
@app.post("/api/upload")
async def upload(file: UploadFile = File(...), label: str = Form("custom")):
    label = re.sub(r"[^\w\- ]", "", label)[:40] or "custom"
    ts = now()
    dest_dir = config.UPLOAD_DIR / ts.strftime("%Y/%m/%d")
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.\-]", "_", file.filename or "upload.csv")
    dest = dest_dir / f"{ts.strftime('%H%M%S')}-{safe}"
    max_bytes = upload_src.MAX_BYTES  # cap a manual upload so a huge POST can't exhaust disk or parse time
    written = 0
    try:
        with dest.open("wb") as out:
            while chunk := await file.read(1 << 20):
                written += len(chunk)
                if written > max_bytes:
                    raise HTTPException(413, f"upload is larger than the {max_bytes >> 20} MB limit")
                out.write(chunk)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise
    except Exception:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, "could not read the upload")
    try:   # streamed in batches straight to the lake's NDJSON: memory stays flat whatever the row count
        res = await asyncio.to_thread(upload_src.ingest_to_ndjson, dest, label, str(dest), upload_src.events_path_for(dest))
    except upload_src.UploadRefused as e:   # a shape the parser will not guess at: say what is wrong with the file
        raise HTTPException(400, str(e))
    except Exception as e:
        log.warning("upload parse failed for %s: %s", safe, str(e)[:300])
        raise HTTPException(400, "could not parse the uploaded file")
    n = await asyncio.to_thread(upload_src.load_in_parts, res["out"]) if res["out"] else 0
    bus.publish("events", {"source": "upload", "count": n, "latest": []})
    # No absolute path in a write response (it names the home folder): the file's place in the lake only.
    out = {"rows": n, "geolocated": res["geolocated"], "kept": res["kept"], "total": res["total"],
           "file": dest.relative_to(config.LAKE).as_posix()}
    if res["total"] > res["kept"]:
        out["note"] = (f"Kept the first {res['kept']:,} of {res['total']:,} rows: one upload holds at most "
                       f"{upload_src.MAX_ROWS:,} rows. Split the file to add the rest.")
    return out


# ------------------------------------------------------------------ SQL console (read-only)
READ_ONLY = re.compile(r"^\s*(select|with|describe|summarize|pivot|unpivot|pivot_wider|pivot_longer|from|show|table|values)\b", re.I)
FORBIDDEN = re.compile(r"\b(insert|update|delete|drop|create|alter|attach|detach|copy|export|install|load|pragma|set|call|checkpoint|import)\b", re.I)
# Table functions the console may use: compute-only or catalog introspection. Anything that reads a
# file or a URL (read_text, read_csv/json/parquet, read_blob, glob, *_scan, …) is deliberately absent,
# so the console cannot read local files (e.g. the ingest TLS key, /etc/passwd) or reach the network.
# This is enforced by parsing the query with DuckDB's own parser, not by a bypassable text blocklist.
# (sql_auto_complete is not here: it needs DuckDB's autocomplete extension, which is not built in.)
# duckdb_databases and duckdb_settings are not here either: they show the database file, the lake and DuckDB's folders;
# nor is pragma_storage_info, whose per-segment min/max statistics show a table's values (the settings table's too).
SQL_TABLE_FUNCS_OK = {
    "range", "generate_series", "unnest", "repeat", "values",
    "duckdb_tables", "duckdb_columns", "duckdb_views", "duckdb_types", "duckdb_schemas",
    "duckdb_functions", "duckdb_constraints",
    "duckdb_keywords", "duckdb_indexes", "duckdb_dependencies", "duckdb_memory",
    "pragma_table_info", "pragma_version",
    "pragma_database_size", "pragma_metadata_info",
}
# Functions and views that show server settings, file locations or the environment (DuckDB 2.0's duckdb_functions()
# and system views checked one by one): refused wherever they appear in a query, with SQL_SETTINGS_MSG. The table
# functions among them are already outside the allowlist above; naming them here gives the plain message.
SQL_FUNCS_BLOCKED = {
    "current_setting", "getenv", "which_secret", "write_log",
    "duckdb_settings", "duckdb_databases", "duckdb_extensions", "duckdb_secrets", "duckdb_secret_types",
    "duckdb_secret_type_parameters", "duckdb_temporary_files", "duckdb_extension_repositories", "duckdb_logs",
    "duckdb_logs_parsed", "duckdb_log_contexts", "duckdb_external_file_cache", "duckdb_prepared_statements",
    "duckdb_profiling_settings", "duckdb_variables", "duckdb_connection_count", "duckdb_approx_database_count",
    "pragma_platform", "pragma_user_agent", "pragma_database_list",
}
# DuckDB's own catalog views the console may read (they list tables, columns and types, never a path). Every other
# system view is refused, among them duckdb_databases and pragma_database_list (the database file), pg_settings
# (every setting, with DuckDB's folders), duckdb_logs and pg_prepared_statements.
SQL_SYSTEM_VIEWS_OK = {
    ("information_schema", v) for v in (
        "character_sets", "check_constraints", "columns", "constraint_column_usage", "constraint_table_usage",
        "key_column_usage", "referential_constraints", "schemata", "tables", "table_constraints", "views")
} | {
    ("main", v) for v in (
        "duckdb_columns", "duckdb_constraints", "duckdb_indexes", "duckdb_schemas", "duckdb_tables", "duckdb_types",
        "duckdb_views", "sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_temp_schema")
} | {
    ("pg_catalog", v) for v in (
        "pg_am", "pg_attrdef", "pg_attribute", "pg_class", "pg_collation", "pg_constraint", "pg_database", "pg_depend",
        "pg_description", "pg_enum", "pg_index", "pg_indexes", "pg_namespace", "pg_proc", "pg_sequence",
        "pg_sequences", "pg_tables", "pg_tablespace", "pg_type", "pg_views")
}
# The app's own tables the console never reads. settings holds secrets the rest of the app masks (the notification
# webhook address with its token, notify.config; the log-sender token hashes, netlog_ingest) next to plain app state.
# (Audit, v1.2 sqlgate: no other table stores a secret. The Cloudflare Radar token is a file in the db folder, API keys
# come from the environment only, and device upload tokens are sha256 hashes inside settings.)
SQL_PRIVATE_TABLES = {"settings"}
SQL_PRIVATE_MSG = ("The {} table holds the app's own settings, some of them secret (such as the notification address), "
                   "so the SQL console doesn't show it. Settings shows them, with secrets masked.")
SQL_BLOCKED_VIEWS = {"duckdb_databases", "pragma_database_list", "pg_settings", "duckdb_logs", "pg_prepared_statements"}
SQL_SETTINGS_MSG = ("{} shows server settings or file locations, so the SQL console doesn't allow it. "
                    "Query the app's own tables by name.")
SQL_TIMEOUT_S = 8.0
SQL_MAX_LEN = 20_000              # bound the parser/engine work a single query can trigger
# A CTE name is only trusted as a bare identifier: DuckDB never turns a name without a dot or slash into a file read.
SQL_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")
# The special listings SHOW can produce (SHOW TABLES, SHOW DATABASES, SHOW / SHOW ALL TABLES / DESCRIBE alone).
SQL_SHOW_SPECIAL = {'"tables"', '"databases"', "__show_tables_expanded"}
SQL_NOT_OURS = "Reading files or URLs through the SQL console is not allowed; query the app's own tables by name."


def _sql_refs(s: str) -> tuple[set[str], list[tuple[str, str, str]], set[str], set[str]] | None:
    """(table-function names, table references as (catalog, schema, name), CTE names, every function name) in the
    query, via DuckDB's parser; None if it does not parse. A table reference is every BASE_TABLE and every SHOW target;
    a SHOW listing DuckDB does not name in SQL_SHOW_SPECIAL comes back as a reference that matches no table, so it is
    refused. Every function name: scalar, aggregate, window and table functions, lower-cased, in any spelling
    (system.main.f(x), x.f(), "F"(x)), for the SQL_FUNCS_BLOCKED check."""
    import json
    try:
        doc = json.loads(db.cursor().execute("SELECT json_serialize_sql(?)", [s]).fetchone()[0])
    except Exception:
        return None
    if doc.get("error"):
        return None
    funcs: set[str] = set()
    tables: list[tuple[str, str, str]] = []
    ctes: set[str] = set()
    every: set[str] = set()

    def fname(x):
        if isinstance(x, dict):
            if isinstance(x.get("function_name"), str):
                return x["function_name"]
            for v in x.values():
                if (r := fname(v)):
                    return r
        return None

    def name(o):
        return tuple(str(o.get(k) or "") for k in ("catalog_name", "schema_name", "table_name"))

    def walk(o):
        if isinstance(o, dict):
            t = o.get("type")
            if isinstance(o.get("function_name"), str):
                every.add(o["function_name"].lower())
            if t == "TABLE_FUNCTION" and (n := fname(o.get("function", {}))):
                funcs.add(n.lower())
            elif t == "BASE_TABLE":
                tables.append(name(o))
            elif t == "SHOW_REF" and not o.get("query"):   # with a query, its BASE_TABLEs are walked below
                if o.get("show_type") == "SHOW_SPECIAL":
                    if o.get("table_name") not in SQL_SHOW_SPECIAL:
                        tables.append(("", "", "\0" + str(o.get("table_name"))))
                else:                                       # SHOW <name>: DuckDB looks that name up
                    tables.append(name(o))
            if isinstance(o.get("cte_map"), dict):
                for m in o["cte_map"].get("map") or []:
                    if isinstance(m, dict) and isinstance(m.get("key"), str):
                        ctes.add(m["key"].lower())
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(doc)
    return funcs, tables, ctes, every | funcs


def _sql_table_ok(ref: tuple[str, str, str], ctes: set[str], known: set[tuple[str, str, str]]) -> bool:
    """True when a table reference names a CTE of the query (a bare identifier) or an existing table or view of the
    app's own database (`known`: (catalog, schema, name) from duckdb_tables() / duckdb_views(), lower-cased).
    Allowlist, not patterns: a file path or URL in any spelling ('x.csv', "dir/x".csv, globs, s3://...) matches
    no real table, so DuckDB's replacement scan that would read it never gets the chance."""
    c, s, n = (x.lower() for x in ref)
    if not c and not s and n in ctes and SQL_IDENT.match(n):
        return True
    if c:                                     # catalog.schema.name
        return (c, s, n) in known
    if s:                                     # schema.name, or catalog.name (its main schema)
        return any(k[1] == s and k[2] == n for k in known) or (s, "main", n) in known
    return SQL_IDENT.match(n) is not None and any(k[2] == n for k in known)


def _sql_known_tables() -> set[tuple[str, str, str]]:
    """The app's own tables and views, plus DuckDB's catalog views in SQL_SYSTEM_VIEWS_OK (no other system view)."""
    rows = db.cursor().execute(
        "SELECT database_name, schema_name, table_name, internal FROM duckdb_tables() "
        "UNION SELECT database_name, schema_name, view_name, internal FROM duckdb_views()").fetchall()
    return {(str(c).lower(), str(s).lower(), str(n).lower()) for c, s, n, internal in rows
            if (not internal and str(n).lower() not in SQL_PRIVATE_TABLES)
            or (internal and (str(s).lower(), str(n).lower()) in SQL_SYSTEM_VIEWS_OK)}


def _sql_all_names() -> set[str]:
    """Every table and view name in the database, the app's own and DuckDB's internal ones (lower-cased)."""
    rows = db.cursor().execute("SELECT table_name FROM duckdb_tables() UNION SELECT view_name FROM duckdb_views()").fetchall()
    return {str(n).lower() for (n,) in rows}


def _sql_refused_table(ref: tuple[str, str, str]) -> str:
    """The plain refusal for a table reference that _sql_table_ok turned down. A host path never appears in it: only
    a bare identifier (letters, digits, _ and $) is ever repeated back."""
    n = ref[2].lower()
    if n.startswith("\0"):                        # a SHOW listing other than tables and databases
        return "The console's SHOW lists tables and databases only: try SHOW TABLES, or DESCRIBE events."
    if n in SQL_PRIVATE_TABLES:
        return SQL_PRIVATE_MSG.format(n)
    if n in SQL_BLOCKED_VIEWS or n in SQL_FUNCS_BLOCKED:
        return SQL_SETTINGS_MSG.format(n)
    if not ref[0] and not ref[1] and SQL_IDENT.match(ref[2]):
        return f"There is no table or view named {ref[2]}. The Schema list shows the app's own tables."
    return SQL_NOT_OURS


def _sql_code(s: str) -> str:
    """The query with its string literals, comments and quoted identifiers blanked out, via DuckDB's own tokenizer,
    so the keyword and ';' checks see only SQL code ('%update%' or '%;%' in a LIKE is data, not a statement).
    If the tokenizer fails, the raw text is returned: the checks then stay as strict as a plain text scan."""
    try:
        toks = duckdb.tokenize(s)
    except Exception:
        return s
    out = []
    for i, (start, kind) in enumerate(toks):
        end = toks[i + 1][0] if i + 1 < len(toks) else len(s)
        piece = s[start:end]
        if kind in (duckdb.token_type.string_const, duckdb.token_type.comment) or \
                (kind == duckdb.token_type.identifier and piece.lstrip().startswith('"')):
            piece = " "
        out.append(piece)
    return s[:toks[0][0]] + "".join(out) if toks else s


def _sql_stmt_types(s: str) -> list | None:
    """The DuckDB statement type of each statement in the text (SELECT, MULTI, ...), None if it does not parse."""
    try:
        return [st.type for st in db.cursor().extract_statements(s)]
    except Exception:
        return None


SQL_PIVOT_WORD = re.compile(r"\b(pivot|pivot_wider)\b", re.I)    # only picks the error message, never a security check
SQL_ONLY_MSG = "Only single read-only SELECT / WITH / PIVOT / UNPIVOT / DESCRIBE / SUMMARIZE queries are allowed."
SQL_PIVOT_MSG = ("This kind of PIVOT needs its column values listed: PIVOT events ON kind IN ('a', 'b') USING count(*). "
                 "To see the values: SELECT DISTINCT kind FROM events.")


def _sql_check(raw: str) -> str:
    """The console statement to run, after every sandbox check; raises HTTPException(400) otherwise.

    INVARIANT: the string returned is exactly the text whose DuckDB parse was checked by _sql_refs. It is never
    rewritten, and the caller runs only this returned string (wrapped in SELECT * FROM (...) LIMIT 5000, which adds
    no table reference). Every table it names is a CTE of the query or an existing table or view (_sql_table_ok).
    Never check one text and run another: a rewritten copy can parse differently from the original.

    A PIVOT without an IN list (PIVOT events ON kind) is DuckDB's MULTI statement: it runs a hidden query for the
    values first, and json_serialize_sql cannot show what that reads, so it is refused with a hint to list the values.
    PIVOT / UNPIVOT with IN lists, the SQL-standard PIVOT and UNPIVOT parse as one SELECT and take the normal check."""
    s = raw.strip().rstrip(";")
    if len(s) > SQL_MAX_LEN:
        raise HTTPException(400, f"Query is too long (max {SQL_MAX_LEN} characters).")
    code = _sql_code(s)
    if not s or not READ_ONLY.match(s) or ";" in code or FORBIDDEN.search(code):
        raise HTTPException(400, SQL_ONLY_MSG)
    types = _sql_stmt_types(s)
    if types == [duckdb.StatementType.MULTI] and SQL_PIVOT_WORD.search(code):
        raise HTTPException(400, SQL_PIVOT_MSG)
    if types is not None and types != [duckdb.StatementType.SELECT]:
        raise HTTPException(400, SQL_ONLY_MSG)
    refs = _sql_refs(s)
    if refs is None:
        if types == [duckdb.StatementType.SELECT]:   # DuckDB parses it, but the check cannot see inside it
            raise HTTPException(400, "The console can't check this query safely, so it was not run. "
                                     "Try writing it as a plain SELECT.")
        raise HTTPException(400, "Could not parse the query.")
    tfs, tables, ctes, every = refs
    if (blocked := sorted(every & SQL_FUNCS_BLOCKED)):
        raise HTTPException(400, SQL_SETTINGS_MSG.format(blocked[0]))
    if not tfs <= SQL_TABLE_FUNCS_OK:
        bad = ", ".join(sorted(f for f in tfs - SQL_TABLE_FUNCS_OK if SQL_IDENT.match(f))) or "a table function"
        raise HTTPException(400, f"Table functions that read files or URLs are not allowed here ({bad}); the console reads the app's own tables only.")
    if ctes:
        # A WITH name must be a plain word that no table, view or system object uses: DuckDB scopes a CTE to its own
        # query, so "(WITH settings AS ...) q, settings" would pass the check by name and still read the real table.
        taken = _sql_all_names() | SQL_PRIVATE_TABLES | SQL_BLOCKED_VIEWS | SQL_FUNCS_BLOCKED
        for n in sorted(ctes):
            if not SQL_IDENT.match(n) or n in taken:
                raise HTTPException(400, "That WITH name is not allowed: it must be a plain word that is not already the "
                                         "name of a table or view. Rename it (for example to q1).")
    if tables:
        known = _sql_known_tables()
        for r in tables:
            if not _sql_table_ok(r, ctes, known):
                raise HTTPException(400, _sql_refused_table(r))
    return s


SQL_OFF_MSG = "The SQL console is off. Start Night Desk with OSINTHUB_SQL_CONSOLE=1 to turn it on."


@app.post("/api/sql")
async def sql(body: dict):
    if not config.SQL_CONSOLE:              # off unless OSINTHUB_SQL_CONSOLE=1 (or OSINTHUB_DEBUG=1)
        raise HTTPException(403, SQL_OFF_MSG)
    try:
        s = _sql_check(body.get("sql") or "")   # the checked text; run() below executes nothing else
    except HTTPException as e:
        raise HTTPException(e.status_code, _sql_redact(e.detail))

    def run():
        cur = db.cursor()  # thread-local child connection, so the watchdog interrupts only this query
        done = threading.Event()

        def watchdog():
            if not done.wait(SQL_TIMEOUT_S):
                try:
                    cur.interrupt()
                except Exception:
                    pass
        threading.Thread(target=watchdog, daemon=True).start()
        try:
            if s.lower().startswith(("describe", "summarize", "show")):
                res = cur.execute(s)
                return [d[0] for d in res.description], res.fetchmany(5000)
            # newline: a trailing "-- comment" must not swallow the closing parenthesis
            inner = f"SELECT * FROM ({s}\n) LIMIT 5000"
            try:
                types = cur.sql(inner).types   # binds only; nothing runs
            except Exception as e:
                if "Interrupt" in type(e).__name__:   # the time limit hit while DuckDB was planning: stop, don't re-run
                    raise
                types = []
            # DuckDB's client turns ±infinity DATE/TIMESTAMP values into 9999-12-31 / 0001-01-01, which look like
            # real dates (and a real 9999-12-31 exists): one flag column per column that holds such a type, at any
            # depth inside LIST / ARRAY / STRUCT / MAP / UNION values, says which values were infinite.
            masks = [(i, m) for i, t in enumerate(types) if (m := _sql_inf_mask(f"#{i + 1}", t))]
            if not masks:
                res = cur.execute(inner)
                return [d[0] for d in res.description], res.fetchall()
            try:
                res = cur.execute(f"SELECT *, {', '.join(m for _, m in masks)} FROM ({inner})")
            except duckdb.BinderException:   # a type the flags cannot take: the plain result, as before
                res = cur.execute(inner)
                return [d[0] for d in res.description], res.fetchall()
            n = len(types)
            out = []
            for r in res.fetchall():
                row = list(r[:n])
                for j, (i, _) in enumerate(masks):
                    row[i] = _sql_inf_apply(row[i], r[n + j], types[i])
                out.append(row)
            return [d[0] for d in res.description[:n]], out
        finally:
            done.set()

    try:
        cols, rows = await asyncio.to_thread(run)
    except Exception as e:
        if "Interrupt" in type(e).__name__:
            raise HTTPException(400, f"Query exceeded the {int(SQL_TIMEOUT_S)}s time limit.")
        log.warning("sql console query failed: %s", str(e)[:300])
        raise HTTPException(400, "Query failed — check your SQL.")
    red = _sql_redactor()
    return JSONResponse({"columns": [red(str(c)) for c in cols], "rows": [[red(_sql_value(v)) for v in r] for r in rows]},
                        headers={"Cache-Control": "no-store"})


def _sql_path_marks() -> list[tuple[str, str]]:
    """(host path, placeholder) for the folders a console answer must never name. Only the home folder is private:
    the home folder itself becomes "~", and the database folder "<db>", the lake "<lake>" and the app's own folder
    "<app>" are hidden only when they sit inside it (a Mac owner's ~/Projects/nd/lake). Paths outside the home folder
    (/data/db or /app in the Docker image, an external drive) are left as they are: they say nothing about the owner,
    and the same text is ordinary data in logs and articles ("/app/login.php", MongoDB's "/data/db"). Each path is
    taken as given and resolved (/var -> /private/var), with / and \\ separators, longest first. $HOME and the
    account's home folder both count; a one-part home such as /root (the Docker image) is not private."""
    import os
    homes = []
    try:
        homes.append(Path.home())                       # $HOME
    except Exception:
        pass
    try:
        import pwd
        homes.append(Path(pwd.getpwuid(os.getuid()).pw_dir))   # the account's home, even when $HOME says otherwise
    except Exception:          # no passwd entry (or not a Unix system): nothing to hide under that name
        pass

    def spellings(p):
        return {v.rstrip("/\\") for v in (str(p), os.path.realpath(p), os.path.abspath(p))}

    def parts(v):
        return [x for x in re.split(r"[/\\]", v) if x and not x.endswith(":")]

    home_vs = {v for h in homes for v in spellings(h) if len(parts(v)) >= 2}
    if not home_vs:
        return []

    def in_home(v):
        return any(v == h or v.startswith(h + "/") or v.startswith(h + "\\") for h in home_vs)

    out: dict[str, str] = {}
    for p, mark in ((config.DB_PATH.parent, "<db>"), (config.LAKE, "<lake>"), (config.ROOT, "<app>"),
                    *((h, "~") for h in homes)):
        if p is None:
            continue
        for v in spellings(p):
            if not in_home(v):
                continue
            out.setdefault(v, mark)
            out.setdefault(v.replace("/", "\\"), mark)
    return sorted(out.items(), key=lambda kv: -len(kv[0]))


def _sql_redactor():
    """A function that rewrites every host path in a console value (str, or lists / dicts of them, keys included, as
    _sql_value returns them) to its placeholder, also inside longer strings and JSON text. A mark matches only as a
    whole path: not inside a longer name (/data in /database or https://x/data) and not as a URL's host."""
    marks = _sql_path_marks()
    if not marks:
        return lambda v: v
    to = dict(marks)
    rx = re.compile(r"(?<![\w.\-])(?<!:/)(" + "|".join(re.escape(m) for m, _ in marks) + r")(?![\w\-]|\.\w)")   # "<lake>." ends a sentence

    def red(v):
        if isinstance(v, str):
            return rx.sub(lambda m: to[m.group(1)], v) if any(m in v for m in to) else v
        if isinstance(v, list):
            return [red(x) for x in v]
        if isinstance(v, dict):
            return {red(k): red(x) for k, x in v.items()}
        return v
    return red


def _sql_redact(v):
    return _sql_redactor()(v)


# ------------------------------------------------------------------ small lookups the panels used to ask the console
# The Ops panels' own reads, as GETs that work with the SQL console off (it is off by default).
@app.get("/api/kev/ids")
def kev_ids():
    """Every CVE id in CISA's known-exploited list: {ids: [...]} (the CVE feed's "Known exploited" mark)."""
    rows = db.query("SELECT DISTINCT split_part(title, ' ', 1) AS c FROM events WHERE source = 'cisa_kev'")
    return {"ids": sorted(r["c"] for r in rows if r["c"])}


ASN_RE = re.compile(r"^AS[0-9]{1,10}$")


@app.get("/api/asn/orgs")
def asn_orgs(asn: str = Query("", description="comma-separated AS numbers, e.g. AS64496,AS64497 (at most 200)")):
    """The organisation name the events give each AS number: {orgs: {AS: name or ""}} (Top offenders' ASN tab)."""
    want = list(dict.fromkeys(a.strip().upper() for a in asn.split(",") if a.strip()))
    if len(want) > 200 or not all(ASN_RE.match(a) for a in want):
        raise HTTPException(400, "asn must be up to 200 AS numbers such as AS64496, separated by commas")
    if not want:
        return {"orgs": {}}
    rows = db.query("SELECT asn, any_value(list_filter(tags, lambda x: starts_with(x, 'org:'))[1]) AS org FROM events "
                    f"WHERE asn IN ({', '.join('?' for _ in want)}) GROUP BY asn", want)
    got = {r["asn"]: (r["org"] or "")[4:] for r in rows}
    return {"orgs": {a: got.get(a, "") for a in want}}


SQL_INF_TYPES = {"date", "timestamp", "timestamp with time zone", "timestamp_s", "timestamp_ms", "timestamp_ns"}
SQL_KV_MAP_KEYS = {"list", "array", "struct", "tuple", "map"}   # MAP keys DuckDB hands back as {"key": [...], "value": [...]}


def _sql_inf_mask(expr: str, t, depth: int = 0) -> str | None:
    """A SQL expression shaped like `expr` (DuckDB type `t`) whose leaves say which DATE / TIMESTAMP values are
    infinite: true for infinity, false for -infinity, NULL otherwise. A LIST or ARRAY gives a list of masks, a STRUCT,
    TUPLE or UNION a struct with a field f<i> for each child that can hold one (a UNION's only for its active member),
    a MAP a list of {k, v, e} in entry order: the key and value masks and the entry itself, from which the map is
    rebuilt. None when the type holds no date or timestamp at all."""
    tid = t.id
    if tid in SQL_INF_TYPES:
        return f"CASE WHEN isinf({expr}) THEN {expr} > DATE '1970-01-01' END"
    kids = t.children if tid in ("list", "array", "struct", "tuple", "map", "union") else []
    var = f"_nd_inf{depth}"
    if tid in ("list", "array"):
        m = _sql_inf_mask(var, kids[0][1], depth + 1)
        return m and f"list_transform({expr}, lambda {var}: {m})"
    if tid == "map":
        km = _sql_inf_mask(f"{var}.key", kids[0][1], depth + 1)
        vm = _sql_inf_mask(f"{var}.value", kids[1][1], depth + 1)
        if not (km or vm):
            return None
        # each entry rides along: DuckDB's client folds an infinite key and a real 9999-12-31 key into one Python key
        return (f"list_transform(map_entries({expr}), lambda {var}: "
                f"struct_pack(k := {km or 'NULL'}, v := {vm or 'NULL'}, e := {var}))")
    parts = []
    if tid in ("struct", "tuple"):
        for i, (name, ct) in enumerate(kids):
            key = str(i + 1) if tid == "tuple" else "'" + name.replace("'", "''") + "'"
            if m := _sql_inf_mask(f"struct_extract({expr}, {key})", ct, depth):
                parts.append(f"f{i} := {m}")
    elif tid == "union":
        for i, (name, ct) in enumerate(kids[1:]):   # the first child is the tag
            lit = "'" + name.replace("'", "''") + "'"
            if m := _sql_inf_mask(f"union_extract({expr}, {lit})", ct, depth):
                parts.append(f"f{i} := CASE WHEN union_tag({expr}) = {lit} THEN {m} END")
    return f"struct_pack({', '.join(parts)})" if parts else None


def _sql_inf_apply(v, mask, t):
    """`v` (a value DuckDB returned for type `t`) with each infinite date or timestamp that `mask` (from
    _sql_inf_mask) flags replaced by "infinity" / "-infinity". Anything whose shape does not match is left as it is."""
    if v is None or mask is None:
        return v
    tid = t.id
    if tid in SQL_INF_TYPES:
        return "infinity" if mask else "-infinity"
    kids = t.children if tid in ("list", "array", "struct", "tuple", "map", "union") else []
    if tid in ("list", "array") and isinstance(v, (list, tuple)) and isinstance(mask, list) and len(v) == len(mask):
        return [_sql_inf_apply(x, m, kids[0][1]) for x, m in zip(v, mask)]
    if tid == "map" and isinstance(mask, list) and all(isinstance(m, dict) and isinstance(m.get("e"), dict) for m in mask):
        kt, vt = kids[0][1], kids[1][1]   # rebuilt from the entries, so no two keys fold into one
        keys = [_sql_inf_apply(m["e"].get("key"), m["k"], kt) for m in mask]
        vals = [_sql_inf_apply(m["e"].get("value"), m["v"], vt) for m in mask]
        if kt.id in SQL_KV_MAP_KEYS:      # the shape DuckDB's client gives a map with nested keys
            return {"key": keys, "value": vals}
        try:
            return dict(zip(keys, vals))
        except TypeError:
            return v
    if tid == "struct" and isinstance(v, dict) and isinstance(mask, dict) and len(v) == len(kids):
        return {k: _sql_inf_apply(x, mask.get(f"f{i}"), kids[i][1]) for i, (k, x) in enumerate(v.items())}
    if tid == "tuple" and isinstance(v, (list, tuple)) and isinstance(mask, dict) and len(v) == len(kids):
        return [_sql_inf_apply(x, mask.get(f"f{i}"), kids[i][1]) for i, x in enumerate(v)]
    if tid == "union" and isinstance(mask, dict):
        for i, (_, ct) in enumerate(kids[1:]):
            if mask.get(f"f{i}") is not None:   # the active member's mask
                return _sql_inf_apply(v, mask[f"f{i}"], ct)
    return v
JS_SAFE_INT = 2 ** 53 - 1   # Number.MAX_SAFE_INTEGER: larger integers lose digits in JSON.parse


def _sql_value(v):
    """A DuckDB result value as plain JSON: integers as numbers, but as exact decimal strings beyond JavaScript's
    safe range (|n| > 2^53 - 1: BIGINT / HUGEINT / UBIGINT ...), dates and times as ISO strings, DECIMAL as a number
    (a string when a float would lose digits), INTERVAL as text, UUID as text, BLOB as DuckDB's escaped text,
    NaN/Inf as the strings 'NaN' / 'Infinity' / '-Infinity', and LIST / STRUCT / MAP converted element by element."""
    if v is None or isinstance(v, (bool, str)):
        return v
    if isinstance(v, int):
        return v if -JS_SAFE_INT <= v <= JS_SAFE_INT else str(v)
    if isinstance(v, float):
        return v if math.isfinite(v) else ("NaN" if v != v else "Infinity" if v > 0 else "-Infinity")
    if isinstance(v, (dt.datetime, dt.date, dt.time)):
        return v.isoformat()
    if isinstance(v, decimal.Decimal):
        if not v.is_finite():
            return "NaN" if v.is_nan() else "Infinity" if v > 0 else "-Infinity"
        f = float(v)
        return f if decimal.Decimal(repr(f)) == v else str(v)
    if isinstance(v, dt.timedelta):
        return str(v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "".join(chr(b) if 32 <= b < 127 and b != 92 else f"\\x{b:02X}" for b in bytes(v))
    if isinstance(v, dict):
        return {str(k): _sql_value(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_sql_value(x) for x in v]
    return str(v)  # UUID and anything else DuckDB may hand back


# ------------------------------------------------------------------ lake stats (additive; cached 60s)
_LAKE_CACHE: dict = {}


@app.get("/api/lake")
def lake_stats():
    import time
    if _LAKE_CACHE.get("t", 0) > time.time() - 60:
        return {**_LAKE_CACHE["v"], "location": _lake_location()}   # sizes cached a minute; the location never

    def walk(d: Path):
        n = b = 0
        if d.exists():
            for f in d.rglob("*"):
                if f.is_file():
                    n += 1
                    try:
                        b += f.stat().st_size
                    except OSError:
                        pass
        return {"path": str(d), "files": n, "bytes": b}

    parts = {"raw": walk(config.RAW_DIR), "uploads": walk(config.UPLOAD_DIR), "ref": walk(config.REF_DIR),
             "cache": walk(config.LAKE / "cache")}   # working caches (the routing watch's RPKI file)
    db_bytes = sum(f.stat().st_size for f in config.DB_PATH.parent.glob(config.DB_PATH.name + "*") if f.is_file())
    v = {"path": str(config.LAKE), "db_path": str(config.DB_PATH), "db_bytes": db_bytes,
         "files": sum(p["files"] for p in parts.values()), "bytes": sum(p["bytes"] for p in parts.values()) + db_bytes,
         "parts": parts}
    _LAKE_CACHE.update(t=time.time(), v=v)
    return {**v, "location": _lake_location()}


def _lake_location() -> dict:
    """Where the data folder setting comes from and how it can be changed (Settings › Data › Change…):
    "here" (this page moves it and restarts), "next_start" (moved when Night Desk is next started; it was not started
    by its own command, so it cannot restart itself), "fixed" (the start command names the folder) or "docker" (the
    folder is outside the container; Settings shows the command for the host)."""
    import os
    from . import lakeloc
    from .netlog.ingest import in_docker
    if in_docker():
        how = "docker"
    elif config.LAKE_SOURCE == "env" or os.environ.get("OSINTHUB_DB") or os.environ.get("OSINTHUB_VECTORS_DB"):
        how = "fixed"
    else:
        how = "here" if lakeloc.can_restart() else "next_start"
    out = {"change": how, "source": config.LAKE_SOURCE, "pending": lakeloc.pending(), "last_move": lakeloc.last_result()}
    if how == "docker":
        out["host_path"] = os.environ.get("OSINTHUB_LAKE_HOST", "").strip() or None
        out["install_dir"] = os.environ.get("OSINTHUB_INSTALL_DIR", "").strip() or None
    return out


@app.post("/api/lake/move")
async def move_lake(body: dict):
    """Move the data folder: checks the new folder now; the copy runs when Night Desk next starts, before the database
    opens, and this restarts it when it was started by its own command. The old folder is left as it was."""
    from . import lakeloc
    loc = _lake_location()
    if loc["change"] == "docker":
        raise HTTPException(409, "Night Desk runs in Docker here: change the folder from the computer running Docker.")
    if loc["change"] == "fixed":
        raise HTTPException(409, "The data folder is set by the command that starts Night Desk, so it cannot be changed here.")
    need = (await asyncio.to_thread(lakeloc.tree_size, config.LAKE))[1]
    try:
        dst = await asyncio.to_thread(lakeloc.check_target, str(body.get("path") or ""), config.LAKE, need)
    except ValueError as e:
        raise HTTPException(400, str(e))
    lakeloc.request_move(config.LAKE, dst)
    restarting = loc["change"] == "here"
    if restarting:
        lakeloc.schedule_restart()
    return {"to": str(dst), "bytes": need, "restarting": restarting}


@app.delete("/api/lake/move")
def cancel_or_dismiss_lake_move():
    """Forget a move that has not run yet (next_start), and the last move's result once it has been read."""
    from . import lakeloc
    (lakeloc.config_dir() / "lake-move.json").unlink(missing_ok=True)
    lakeloc.clear_result()
    return {"ok": True}


# ------------------------------------------------------------------ settings
@app.get("/api/settings")
def get_settings():
    return {"retention": lake.retention(), "last_purge": lake.last_purge() or None}


@app.put("/api/settings/retention")
async def set_retention(body: dict):
    """Retention is off by default. Each value is a number of days, or null to keep forever."""
    clean = {}
    for k in ("lake_days", "db_days"):
        v = body.get(k)
        if v in (None, "", 0):
            clean[k] = None
            continue
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise HTTPException(400, f"{k} must be a whole number of days or null")
        if not 1 <= v <= 36500:
            raise HTTPException(400, f"{k} must be between 1 and 36500 days")
        clean[k] = v
    await asyncio.to_thread(db.set_setting, lake.RETENTION_KEY, clean)
    purged = await asyncio.to_thread(lake.purge) if any(clean.values()) else None
    _LAKE_CACHE.clear()
    return {"retention": clean, "last_purge": purged}


def _git_commit() -> str | None:
    """The checkout's commit (short), read from .git without running git; NIGHTDESK_COMMIT wins (images have no .git)."""
    import os
    if (env := os.environ.get("NIGHTDESK_COMMIT", "").strip()):
        return env[:12]
    try:
        g = config.ROOT / ".git"
        if g.is_file():   # a worktree: "gitdir: <path>"
            g = Path(g.read_text().split("gitdir:", 1)[1].strip())
        head = (g / "HEAD").read_text().strip()
        if not head.startswith("ref:"):
            return head[:12]
        ref = head[4:].strip()
        common = g
        if (g / "commondir").is_file():
            common = (g / (g / "commondir").read_text().strip()).resolve()
        for base in (g, common):
            if (base / ref).is_file():
                return (base / ref).read_text().strip()[:12]
        packed = common / "packed-refs"
        if packed.is_file():
            for line in packed.read_text().splitlines():
                if line.endswith(" " + ref):
                    return line.split(" ", 1)[0][:12]
    except Exception:
        pass
    return None


def _version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version
        for name in ("nightdesk", "osinthub"):   # "osinthub" before the package was renamed
            try:
                return version(name)
            except PackageNotFoundError:
                continue
    except Exception:
        pass
    try:
        import tomllib
        return tomllib.loads((config.ROOT / "pyproject.toml").read_text())["project"]["version"]
    except Exception:
        return "unknown"


@app.get("/api/settings/about")
def settings_about():
    """Settings › About: version, commit, where the lake is, offline mode and the AI helper (no secrets)."""
    try:
        from .ai import client
        ai = client.status()
        ai = {"configured": bool(ai.get("configured")), "up": bool(ai.get("ever_up")) and not ai.get("down"),
              "down": bool(ai.get("down")), "url": ai.get("url")}
    except Exception:
        ai = None
    return {"version": _version(), "commit": _git_commit(), "lake": str(config.LAKE), "db_path": str(config.DB_PATH),
            "offline": bool(config.OFFLINE), "ai": ai, "sources": len(SOURCES), "sql_console": bool(config.SQL_CONSOLE)}


@app.get("/api/settings/diagnostics", response_class=PlainTextResponse)
def settings_diagnostics():
    """Settings › About › Copy diagnostics: a plain-text summary for a GitHub issue, with addresses, host names,
    folders and keys removed (osinthub/diagnostics.py)."""
    from . import diagnostics
    return PlainTextResponse(diagnostics.report(_version(), _git_commit()), headers={"Cache-Control": "no-store"})


@app.get("/api/settings/sources-choice")
def get_sources_choice():
    """The first-run "Choose your sources" step: whether to offer it, and each feed with what it gives, its terms
    and its default under the local feed policy (okf/project/distribution.md, "Feed terms")."""
    from . import feed_terms
    out = []
    for s in SOURCES.values():
        if s.withheld:   # left out of this release: not offered
            continue
        # `saved`: the user (or a migration) stored an explicit on/off for it; the box then shows that answer
        # instead of the policy default, so applying the box never silently undoes an earlier choice
        d = {"id": s.id, "name": s.name, "category": s.category, "enabled": scheduler.is_enabled(s),
             "saved": scheduler.state(s.id).get("enabled") is not None,
             "unavailable": s.unavailable() or None, "needs": s.describe().get("needs"), **feed_terms.row(s.id)}
        out.append(d)
    order = {"on": 0, "ask": 1}
    out.sort(key=lambda d: (order.get(d["local_default"], 2), d["category"], d["name"]))
    return {"state": feed_terms.state(), "sources": out}


@app.post("/api/settings/sources-choice")
async def post_sources_choice(body: dict):
    """{"enable": [source ids], "shown": [source ids]} turns the enabled ones on and the rest off, then ends the
    step; with `shown` (what the box showed ticked), a row the user left as shown keeps any answer already saved.
    {"keep": true} ends the step and changes nothing. A source that needs a missing key is never turned on."""
    from . import feed_terms
    if body.get("keep"):
        await asyncio.to_thread(feed_terms.mark_done, "kept")
        return {"state": "done", "changed": []}
    want = body.get("enable")
    if not isinstance(want, list) or not all(isinstance(x, str) for x in want):
        raise HTTPException(400, "enable must be a list of source ids")
    unknown = [x for x in want if x not in SOURCES]
    if unknown:
        raise HTTPException(400, f"unknown source: {unknown[0][:60]}")
    # `shown` (optional): the ids the box showed ticked when it was drawn. A row the user did not change there
    # keeps an answer saved for it already, even one saved elsewhere after the box was drawn (a Yes in Routing
    # watch, a hand toggle in Sources); only rows the user changed, and rows with no saved answer, are written.
    shown = body.get("shown")
    if shown is not None and (not isinstance(shown, list) or not all(isinstance(x, str) for x in shown)):
        raise HTTPException(400, "shown must be a list of source ids")
    shown_set, want_set = set(shown or ()), set(want)
    changed = []
    for s in SOURCES.values():
        if shown is not None and (s.id in want_set) == (s.id in shown_set) \
                and scheduler.state(s.id).get("enabled") is not None:
            continue   # untouched in the box and already answered: leave the saved answer alone
        if s.unavailable():
            if feed_terms.waits_for_watch(s):   # needs only a watched network: save the answer, Routing watch starts it
                on, was = s.id in want, scheduler.is_enabled(s)
                await scheduler._aset_state(s.id, enabled=on)
                if on != was:
                    changed.append({"id": s.id, "enabled": on})
            continue   # needs a key: never started, its "needs key" state is left alone
        on = s.id in want
        was = scheduler.is_enabled(s)
        # saved explicitly either way, so a later change of a code default never flips the user's choice
        await scheduler.set_enabled(s, on)
        if on != was:
            changed.append({"id": s.id, "enabled": on})
    await asyncio.to_thread(feed_terms.mark_done, "applied")
    return {"state": "done", "changed": changed}


@app.get("/api/health")
def health():
    # No filesystem paths here (health is what probes and monitors poll); the UI reads them from /api/paths.
    # `build` names this copy of the web client (web_build_id); open tabs compare it to offer "Night Desk was updated".
    # `sql_console`: whether the SQL console is on (OSINTHUB_SQL_CONSOLE=1); the client hides its entry points when off.
    return {"ok": True, "sources": len(SOURCES), "offline": config.OFFLINE, "build": WEB_BUILD,
            "sql_console": bool(config.SQL_CONSOLE)}


@app.get("/api/paths")
def paths():
    """Where the lake lives, for the UI's "drop files here" hints (the watched Zeek inbox). `inbox_where` is the inbox as
    the user can reach it (in Docker the host folder or a docker compose cp command): okf/data/netlog.md#import"""
    out = {"lake": str(config.LAKE), "inbox": str(config.LAKE / "inbox" / "zeek")}
    if "netlog" in ext.EXTENSIONS:   # the netlog extension is optional (OSINTHUB_DISABLE_EXT)
        from .netlog.ingest import inbox_location
        out["inbox_where"] = inbox_location()
    return out


# ------------------------------------------------------------------ search and extensions
@app.get("/api/search/semantic")
def search_semantic(q: str = "", types: str | None = None, k: int = Query(10, ge=1, le=100)):
    from . import search
    return _jsonable(search.semantic(q, _csv(types) or None, k))


@app.get("/api/search")
def search_everything(q: str = "", per: int = Query(5, ge=1, le=50), groups: str | None = None):
    """Global search: grouped results (incidents, devices, stories, articles, entities, CVEs, sources and settings,
    notes, feed items), each item with why it matched. Contract: okf/architecture/web-client.md#global-search"""
    from . import search_all
    return search_all.everything(q, per, _csv(groups) or None)


@app.get("/api/extensions")
def extensions():
    return ext.status()


# Feature packages (osinthub/<pkg>/ext.py) add their routers here, before the static mount.
ext.load_all()
from . import notify  # noqa: E402,F401  registers Settings › Notifications (osinthub/notify.py)
ext.include_routers(app)
from .routing.api import router as _routing_router  # noqa: E402  (Settings › Sources › Routing watch)
app.include_router(_routing_router)


# ------------------------------------------------------------------ static client
def web_build_id(root: Path) -> str:
    """A short id for this copy of the web client: a hash over every file under `root` (relative path, size and
    mtime). It changes whenever any web file changes and survives a plain restart. okf/architecture/web-client.md#updates"""
    h = hashlib.sha256()
    if root.exists():
        for p in sorted(root.rglob("*")):
            if p.is_file():
                st = p.stat()
                h.update(f"{p.relative_to(root).as_posix()}\0{st.st_size}\0{st.st_mtime_ns}\n".encode())
    return h.hexdigest()[:12]


WEB_BUILD = web_build_id(config.WEB_DIR)   # computed once at startup; a restart after an update recomputes it
BUILD_COOKIE = "nd_build"


def build_cookie_name(port: int | None) -> str:
    """`nd_build_<port>` when the browser-facing address has a port, else `nd_build`. Cookies are per host, not per
    port: without the port, two Night Desk servers on one host (8787 and another) would keep overwriting each other's
    cookie and clear each other's cache. web/index.html and web/js/main.js derive the same name from location.port."""
    return f"{BUILD_COOKIE}_{port}" if port else BUILD_COOKIE


_LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _secure_context(req: Request) -> bool:
    """Whether the browser treats this page as a secure context: https (behind a TLS proxy uvicorn takes the scheme
    from its trusted X-Forwarded-Proto) or a loopback host. Only there does it apply Clear-Site-Data and
    COOP/COEP; elsewhere (plain-http LAN) it ignores them and logs a console error for each."""
    host = (req.url.hostname or "").lower()
    return req.url.scheme == "https" or host in _LOOPBACK or host.endswith(".localhost") or host.startswith("127.")


class _WebFiles(StaticFiles):
    """The web client, revalidated on every load (`no-cache`: the browser may keep a copy but must check its ETag
    first, a cheap 304 when unchanged). Without it browsers cache by heuristic, so after an update a page could pair
    the new index.html and scripts with an old app.css (e.g. v1.1's phone bar showing unstyled on desktop).

    Files cached before that header existed can stay "fresh" for hours, so the page document (and only it) also
    carries a one-shot `Clear-Site-Data: "cache"` whenever the browser's build cookie (build_cookie_name) is missing or
    names another build, and sets the cookie to this build. With a matching cookie it sends neither.
    okf/architecture/web-client.md#updates"""

    def __init__(self, *args, build: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.build = build or web_build_id(Path(self.directory))

    @staticmethod
    def _is_page(path: str) -> bool:
        p = path.strip("/")
        return p in ("", ".") or p.endswith(".html")

    async def get_response(self, path, scope):
        stale, cookie, secure = False, BUILD_COOKIE, True
        if self._is_page(path):
            req = Request(scope)
            secure = _secure_context(req)
            cookie = build_cookie_name(req.url.port)   # the port of the Host the browser used (kept by proxies)
            stale = req.cookies.get(cookie) != self.build
            if stale:   # a full 200, never a 304: the clear must arrive with a document the browser actually loads
                scope = {**scope, "headers": [(k, v) for k, v in scope["headers"]
                                              if k not in (b"if-none-match", b"if-modified-since")]}
        resp = await super().get_response(path, scope)
        resp.headers.setdefault("Cache-Control", "no-cache")
        if stale and resp.headers.get("content-type", "").startswith("text/html"):
            # Never stored: if a browser ignores the clear, a cached copy would hand the isolation headers below back
            # on every later 304 and keep the page isolated for good.
            resp.headers["Cache-Control"] = "no-store"
            if secure:   # elsewhere the browser ignores both; index.html's stale-code check is the recovery there
                resp.headers["Clear-Site-Data"] = '"cache"'
                # Clear-Site-Data empties the HTTP cache, but Chrome keeps the scripts of the page being replaced in
                # its renderer's memory cache and hands them to the new page (a reload stayed broken in the lab).
                # Making this one document cross-origin isolated forces a fresh renderer process, so it loads every
                # file anew. The app embeds nothing from other origins; the next load (cookie matches) drops both.
                resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
                resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
            # no Secure flag: the app is served over plain http on 127.0.0.1 and the LAN
            resp.headers.append("Set-Cookie", f"{cookie}={self.build}; Path=/; Max-Age=31536000; SameSite=Strict")
        return resp


if config.WEB_DIR.exists():
    app.mount("/", _WebFiles(directory=config.WEB_DIR, html=True, build=WEB_BUILD), name="web")

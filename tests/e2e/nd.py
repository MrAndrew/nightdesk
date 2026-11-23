"""Read-only Playwright harness for a running Night Desk (default http://127.0.0.1:8787), used by smoke.py and
deeplinks.py and handy for one-off checks. The E2E journeys (test_*.py here) have their own fixtures (conftest.py).

TARGET: set ND_BASE=http://127.0.0.1:<port> to drive a scratch server instead of the live app.
Set ND_ALLOW_WRITES=1 as well to let writes through, which works ONLY when ND_BASE is not :8787.

SAFETY (enforced here, do not work around it):
  * Browser: every request that is not GET/HEAD/OPTIONS is ABORTED, except POST /api/sql.
    Every request to a host other than 127.0.0.1/localhost is ABORTED (no egress).
    Blocked requests are recorded in log['blocked'].
  * API helpers: get() only issues GET. sql() only sends SELECT/WITH/DESCRIBE/SHOW/EXPLAIN/SUMMARIZE.
  * Never open the DuckDB files, never restart the server, never start the AI helper.

Usage (run with:  uv run --quiet --with playwright --with pillow python your_script.py):

    import sys; sys.path.insert(0, "tests/e2e")        # from the repo root
    from nd import session, get, sql, BASE
    import asyncio
    async def main():
        async with session(width=1440, height=900) as (page, log):
            await page.goto(BASE + "/#news", wait_until="networkidle"); await page.wait_for_timeout(2500)
            await page.screenshot(path="evidence/news.png")
            print(log["console_errors"], log["page_errors"], log["http_errors"], log["blocked"])
    asyncio.run(main())
"""
import asyncio, contextlib, json, os, re, urllib.parse, urllib.request
from playwright.async_api import async_playwright

BASE = os.environ.get("ND_BASE", "http://127.0.0.1:8787").rstrip("/")
# Writes may be allowed ONLY against a scratch server (never the user's live app on :8787).
ALLOW_WRITES = os.environ.get("ND_ALLOW_WRITES") == "1" and not BASE.endswith(":8787")
_READ_SQL = re.compile(r"^\s*(select|with|describe|show|explain|summarize|from)\b", re.I)

@contextlib.asynccontextmanager
async def session(width=1440, height=900, tour_done=True, reduced_motion=None, headless=True, extra_init=None):
    log = {"console_errors": [], "console_warnings": [], "page_errors": [], "http_errors": [], "blocked": []}
    async with async_playwright() as p:
        try:   # Google Chrome when installed, else Playwright's own Chromium (playwright install chromium)
            b = await p.chromium.launch(channel=os.environ.get("ND_E2E_CHANNEL", "chrome") or None, headless=headless)
        except Exception:
            b = await p.chromium.launch(headless=headless)
        ctx = await b.new_context(viewport={"width": width, "height": height}, reduced_motion=reduced_motion)
        if tour_done:
            await ctx.add_init_script("try{localStorage.setItem('nd.tour.done','1')}catch(e){}")
        if extra_init:
            await ctx.add_init_script(extra_init)

        async def guard(route, request):
            u = urllib.parse.urlparse(request.url)
            if u.scheme in ("data", "blob"):
                return await route.continue_()
            if u.hostname not in ("127.0.0.1", "localhost"):
                log["blocked"].append(f"EGRESS {request.method} {request.url[:160]}")
                return await route.abort()
            if request.method in ("GET", "HEAD", "OPTIONS"):
                return await route.continue_()
            if ALLOW_WRITES and str(u.port) == BASE.rsplit(":", 1)[-1]:
                return await route.continue_()
            if request.method == "POST" and u.path == "/api/sql":
                body = request.post_data or ""
                try: q = json.loads(body).get("sql") or json.loads(body).get("q") or json.loads(body).get("query") or ""
                except Exception: q = body
                if q and not _READ_SQL.match(q):
                    log["blocked"].append(f"NONREAD-SQL {q[:120]}")
                    return await route.abort()
                return await route.continue_()
            log["blocked"].append(f"WRITE {request.method} {u.path}")
            return await route.abort()
        await ctx.route("**/*", guard)

        page = await ctx.new_page()
        inflight = log["_inflight"] = set()   # requests still open, minus the live SSE stream (see settle())
        page.on("request", lambda r: "/api/stream" not in r.url and r.resource_type != "eventsource" and inflight.add(r))
        page.on("requestfinished", lambda r: inflight.discard(r))
        page.on("requestfailed", lambda r: inflight.discard(r))
        page.on("console", lambda m: (log["console_errors"] if m.type == "error" else log["console_warnings"] if m.type == "warning" else []).append(m.text[:300]))
        page.on("pageerror", lambda e: log["page_errors"].append(str(e)[:400]))
        page.on("response", lambda r: r.status >= 400 and log["http_errors"].append(f"{r.status} {r.request.method} {r.url[:200]}"))
        try:
            yield page, log
        finally:
            await b.close()

async def settle(page, log, quiet=0.3, cap=3.0):
    """Wait until the app has booted and no request has been open for `quiet` seconds (capped at `cap`), then two
    animation frames. Replaces fixed sleeps: most pages settle in well under a second."""
    import time
    await page.wait_for_function("window.ndMain === 1", timeout=15000)
    t0 = last = time.monotonic()
    while time.monotonic() - t0 < cap:
        if log["_inflight"]:
            last = time.monotonic()
        elif time.monotonic() - last >= quiet:
            break
        await asyncio.sleep(0.05)
    await page.evaluate("new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")

def get(path, params=None, timeout=30):
    """GET an API path. Returns (status, parsed_json_or_text)."""
    url = BASE + path + (("?" + urllib.parse.urlencode(params)) if params else "")
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace"); status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace"); status = e.code
    try: return status, json.loads(raw)
    except Exception: return status, raw

def sql(query, timeout=60):
    """Run a READ-ONLY query through the app's /api/sql. Refuses anything but SELECT/WITH/... ."""
    if not _READ_SQL.match(query):
        raise ValueError("nd.sql refuses non-read SQL")
    req = urllib.request.Request(BASE + "/api/sql", data=json.dumps({"sql": query}).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace"); status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace"); status = e.code
    try: return status, json.loads(raw)
    except Exception: return status, raw

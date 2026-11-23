"""HTTP behaviour of the web files and the page (offline, temporary lake, no network, no AI helper):

* an upgrade can never leave a dead app (B2-01, B2-02): the page document carries a one-shot `Clear-Site-Data: "cache"` plus an `nd_build` cookie whenever the browser's cookie
is missing or names another build; nothing else ever carries it; /api/health reports the build so open tabs can offer
"Night Desk was updated · Reload";
* responses are compressed for a slow phone link (web files still revalidated, 304s still work), and the live stream
  (/api/stream) is never compressed, so every event goes out at once.

    uv run --with pytest pytest tests/app/test_http.py -q
"""
from __future__ import annotations

import asyncio
import gzip
import os
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("upgrade", disable="news,entities,netlog,ai", OSINTHUB_ALLOWED_HOSTS="nd.test")
ROOT = Path(__file__).resolve().parents[2]

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import api  # noqa: E402

WEB = ROOT / "web"


@pytest.fixture(scope="module")
def client():
    with TestClient(api.app, base_url="http://localhost") as c:
        yield c


def fresh(client):
    client.cookies.clear()
    return client


def build(client):
    b = client.get("/api/health").json()["build"]
    assert isinstance(b, str) and len(b) == 12 and "/" not in b
    return b


# 1 ---------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("path", ["/", "/index.html"])
def test_first_visit_clears_the_cache_and_sets_the_cookie(client, path):
    b = build(client)
    r = fresh(client).get(path)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert r.headers["clear-site-data"] == '"cache"'
    sc = r.headers["set-cookie"]
    assert sc.startswith(f"nd_build={b};")
    for part in ("Path=/", "Max-Age=31536000", "SameSite=Strict"):
        assert part in sc, part
    assert "secure" not in sc.lower() and "httponly" not in sc.lower()   # plain http; the page reads it
    # never stored: where the clear is ignored (plain-http LAN), a cached copy would bring the isolation headers
    # back on every later 304
    assert r.headers["cache-control"] == "no-store"
    # the one-shot document also opens in a fresh renderer process: Chrome keeps scripts of the page being replaced
    # in that process's memory cache, which Clear-Site-Data does not reach (lab repro of B2-01)
    assert r.headers["cross-origin-opener-policy"] == "same-origin"
    assert r.headers["cross-origin-embedder-policy"] == "require-corp"


# 2 ---------------------------------------------------------------------------------------------------------------
def test_matching_cookie_sends_neither(client):
    b = build(client)
    fresh(client)
    r = client.get("/", headers={"Cookie": f"nd_build={b}"})
    assert r.status_code == 200
    assert "clear-site-data" not in r.headers and "set-cookie" not in r.headers
    assert "cross-origin-embedder-policy" not in r.headers and "cross-origin-opener-policy" not in r.headers
    assert r.headers["cache-control"] == "no-cache" and r.headers.get("etag")
    # and a revalidation with the matching cookie is the usual cheap 304
    r2 = client.get("/", headers={"Cookie": f"nd_build={b}", "If-None-Match": r.headers["etag"]})
    assert r2.status_code == 304 and "clear-site-data" not in r2.headers


def test_other_cookie_sends_both_and_never_a_304(client):
    b = build(client)
    fresh(client)
    etag = client.get("/", headers={"Cookie": f"nd_build={b}"}).headers["etag"]
    r = client.get("/", headers={"Cookie": "nd_build=0123456789ab", "If-None-Match": etag})
    assert r.status_code == 200, "a stale browser must get the document with the clear, not a 304"
    assert r.headers["clear-site-data"] == '"cache"'
    assert r.headers["set-cookie"].startswith(f"nd_build={b};")


def test_cookie_is_named_per_port(client):
    b = build(client)
    fresh(client)
    r = client.get("http://localhost:8787/")
    assert r.headers["set-cookie"].startswith(f"nd_build_8787={b};") and r.headers["cache-control"] == "no-store"
    # another server's cookie on the same host does not count, this port's does
    r = client.get("http://localhost:8787/", headers={"Cookie": f"nd_build={b}; nd_build_9410={b}"})
    assert r.headers["clear-site-data"] == '"cache"'
    r = client.get("http://localhost:8787/", headers={"Cookie": f"nd_build_8787={b}"})
    assert "clear-site-data" not in r.headers and r.headers["cache-control"] == "no-cache" and r.headers.get("etag")
    assert api.build_cookie_name(None) == "nd_build" and api.build_cookie_name(443) == "nd_build_443"


def test_plain_http_lan_gets_no_clear_or_isolation_headers(client):
    """A non-secure origin ignores Clear-Site-Data and COOP/COEP and logs a console error for each: send neither, keep
    the cookie and no-store; https (a TLS proxy) and loopback names get the full set."""
    b = build(client)
    fresh(client)
    r = client.get("http://nd.test:8787/")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert r.headers["set-cookie"].startswith(f"nd_build_8787={b};")
    for h in ("clear-site-data", "cross-origin-opener-policy", "cross-origin-embedder-policy"):
        assert h not in r.headers, h
    r = client.get("http://nd.test:8787/", headers={"Cookie": f"nd_build_8787={b}", "If-None-Match": r.headers["etag"]})
    assert r.status_code == 304 and "cross-origin-embedder-policy" not in r.headers
    fresh(client)
    r = client.get("https://nd.test:8443/")
    assert r.headers["clear-site-data"] == '"cache"' and r.headers["cross-origin-embedder-policy"] == "require-corp"
    for host in ("http://127.0.0.1:8787/", "http://localhost:8787/"):
        fresh(client)
        assert fresh(client).get(host, headers={"Host": host.split("/")[2]}).headers.get("clear-site-data") == '"cache"', host


# 3 ---------------------------------------------------------------------------------------------------------------
def test_nothing_but_the_page_carries_clear_site_data(client):
    vendor = next(p for p in sorted((WEB / "vendor").rglob("*.js")))
    paths = ["/js/main.js", "/js/core/update.js", "/css/app.css", "/" + vendor.relative_to(WEB).as_posix(), "/api/health"]
    for p in paths:
        r = fresh(client).get(p)
        assert r.status_code == 200, p
        assert "clear-site-data" not in r.headers, p
        assert "nd_build" not in r.headers.get("set-cookie", ""), p
        assert "cross-origin-embedder-policy" not in r.headers, p
    for p in ("/js/main.js", "/css/app.css"):
        assert fresh(client).get(p).headers["cache-control"] == "no-cache", p
    # the live stream (an endless response; read its headers straight from the endpoint)
    resp = asyncio.run(api.stream())
    assert resp.media_type == "text/event-stream" and "clear-site-data" not in resp.headers


# 4 ---------------------------------------------------------------------------------------------------------------
def _tmp_web(tmp_path):
    (tmp_path / "js").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><title>t</title>")
    (tmp_path / "js" / "a.js").write_text("export const a = 1;\n")
    return tmp_path


def _app(web):
    a = FastAPI()
    files = api._WebFiles(directory=web, html=True)
    a.mount("/", files, name="web")
    return a, files


def test_touching_a_web_file_changes_the_build(tmp_path):
    web = _tmp_web(tmp_path)
    a1, f1 = _app(web)
    assert f1.build == api.web_build_id(web)
    assert api.web_build_id(web) == f1.build, "stable across restarts with no change"
    st = (web / "js" / "a.js").stat()
    os.utime(web / "js" / "a.js", ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
    a2, f2 = _app(web)
    assert f2.build != f1.build
    # the rebuilt app hands out the new id, and the old cookie triggers the clear
    with TestClient(a2, base_url="http://localhost") as c:
        r = c.get("/", headers={"Cookie": f"nd_build={f1.build}"})
        assert r.headers["clear-site-data"] == '"cache"' and r.headers["set-cookie"].startswith(f"nd_build={f2.build};")
        r = c.get("/", headers={"Cookie": f"nd_build={f2.build}"})
        assert "clear-site-data" not in r.headers
        assert "clear-site-data" not in c.get("/js/a.js").headers
    # adding a file changes it too
    (web / "js" / "b.js").write_text("export const b = 2;\n")
    assert api.web_build_id(web) != f2.build


def test_running_app_build_is_the_web_dir_build():
    assert api.WEB_BUILD == api.web_build_id(api.config.WEB_DIR)


# client contracts ------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------
GZ = {"Accept-Encoding": "gzip"}


@pytest.fixture()
def warm(client):
    client.get("/")   # the first page load of a build is the one-shot no-store clear; it sets the build cookie
    return client


@pytest.mark.parametrize("path", ["/css/app.css", "/js/core/shell.js", "/", "/index.html"])
def test_web_files_are_gzipped_and_still_revalidated(warm, path):
    r = warm.get(path, headers=GZ)
    assert r.status_code == 200
    assert r.headers["content-encoding"] == "gzip", path
    assert "accept-encoding" in r.headers.get("vary", "").lower()
    assert r.headers["cache-control"] == "no-cache", (path, r.headers["cache-control"])
    assert r.headers.get("etag")
    # httpx decodes it: the body is the file itself
    if path.startswith("/css/"):
        assert r.content == (WEB / "css" / "app.css").read_bytes()


def test_gzip_is_much_smaller_and_304_still_works(warm):
    raw = (WEB / "css" / "app.css").read_bytes()
    with warm.stream("GET", "/css/app.css", headers=GZ) as r:
        wire = b"".join(r.iter_raw())
        etag = r.headers["etag"]
    assert len(wire) < len(raw) / 3
    assert gzip.decompress(wire) == raw
    r = warm.get("/css/app.css", headers={**GZ, "If-None-Match": etag})
    assert r.status_code == 304


def test_no_gzip_without_accept_encoding_or_under_1kb(warm):
    r = warm.get("/css/app.css", headers={"Accept-Encoding": "identity"})
    assert r.status_code == 200 and "content-encoding" not in r.headers
    assert r.headers["cache-control"] == "no-cache"
    r = warm.get("/api/health", headers=GZ)   # a small JSON answer
    assert r.status_code == 200 and len(r.content) < 1024 and "content-encoding" not in r.headers


def test_live_stream_is_not_gzipped():
    """/api/stream (text/event-stream, the live updates) goes out uncompressed, so every event is sent at once.
    Driven at the ASGI level: the stream never ends, so the client disconnects after the first chunk."""
    start, chunks = {}, []

    async def run():
        got = asyncio.Event()
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await got.wait()
            return {"type": "http.disconnect"}

        async def send(msg):
            if msg["type"] == "http.response.start":
                start.update({k.decode().lower(): v.decode() for k, v in msg["headers"]}, status=msg["status"])
            elif msg["type"] == "http.response.body" and msg.get("body"):
                chunks.append(msg["body"])
                got.set()

        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
                 "method": "GET", "scheme": "http", "path": "/api/stream", "raw_path": b"/api/stream",
                 "query_string": b"", "root_path": "", "server": ("localhost", 80), "client": ("127.0.0.1", 5000),
                 "headers": [(b"host", b"localhost"), (b"accept-encoding", b"gzip"), (b"accept", b"text/event-stream")]}
        await asyncio.wait_for(api.app(scope, receive, send), timeout=10)

    asyncio.run(run())
    assert start["status"] == 200
    assert start["content-type"].startswith("text/event-stream")
    assert "content-encoding" not in start
    assert start["cache-control"] == "no-cache"
    assert chunks and chunks[0].startswith(b"retry:")   # plain text on the wire

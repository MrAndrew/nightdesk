"""The HTTP guards in front of every route (osinthub/api.py _guard): a foreign Host is 421 (DNS rebinding), and every
state-changing request (POST/PUT/PATCH/DELETE) from another site or origin is 403, on every route the app has, now
and in future (the route walker), changing nothing; the security headers; /api/health names no paths.

    uv run --with pytest pytest tests/security/test_http_guards.py -q
"""
from __future__ import annotations

import os
import re
import unittest

from _lake import make_lake
LAKE = make_lake("http-guards", OSINTHUB_ALLOWED_HOSTS="desk.lan, Hlta.Local:8443", OSINTHUB_SQL_CONSOLE="1")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
import osinthub.api as A  # noqa: E402

db.connect()
C = TestClient(A.app, base_url="http://localhost")   # no `with`: no lifespan, no scheduler; Host must be allowed
WRITES = {"POST", "PUT", "PATCH", "DELETE"}


def post_sql(q, **headers):
    return C.post("/api/sql", json={"sql": q}, headers=headers)


def _routes(routes, prefix=""):
    for r in routes:
        sub = getattr(r, "original_router", None) or getattr(r, "router", None)   # an included router
        if sub is not None and not hasattr(r, "methods"):
            ctx = getattr(r, "include_context", None)
            yield from _routes(sub.routes, prefix + (getattr(ctx, "prefix", "") or getattr(r, "path", "") or ""))
        elif getattr(r, "methods", None):
            yield r.methods, prefix + r.path


def write_routes() -> list[tuple[str, str]]:
    """Every (method, path) of the app that changes state, path parameters filled with a placeholder."""
    return sorted({(m, re.sub(r"\{[^}:]+(?::path)?\}", "x", path))
                   for methods, path in _routes(A.app.routes) for m in methods & WRITES})


def _state() -> list:
    return db.query("SELECT key, value FROM settings ORDER BY key") + db.query("SELECT * FROM source_state ORDER BY id")


@pytest.mark.parametrize("headers", [{"Sec-Fetch-Site": "cross-site"}, {"Origin": "http://evil.example"}],
                         ids=["cross-site", "foreign-origin"])
def test_every_write_route_refuses_another_site(headers):
    routes = write_routes()
    assert len(routes) >= 60, f"the walker found only {len(routes)} write routes: are the routers mounted?"
    before = _state()
    bad = []
    for method, path in routes:
        r = C.request(method, path, json={}, headers=headers)
        if r.status_code != 403 or "refused" not in r.text:
            bad.append(f"{method} {path} -> {r.status_code}")
    assert not bad, "writes from another site must be 403:\n" + "\n".join(bad)
    assert _state() == before                                        # and nothing changed


class CsrfAndHeaders(unittest.TestCase):
    def test_cross_site_state_change_refused(self):
        self.assertEqual(post_sql("SELECT 1", **{"Sec-Fetch-Site": "cross-site"}).status_code, 403)
        self.assertEqual(post_sql("SELECT 1", **{"Sec-Fetch-Site": "same-site"}).status_code, 403)
        # no Sec-Fetch-Site but a foreign Origin
        self.assertEqual(post_sql("SELECT 1", Origin="http://evil.example").status_code, 403)

    def test_same_origin_and_non_browser_allowed(self):
        self.assertEqual(post_sql("SELECT 1", **{"Sec-Fetch-Site": "same-origin"}).status_code, 200)
        self.assertEqual(post_sql("SELECT 1", **{"Sec-Fetch-Site": "none"}).status_code, 200)
        self.assertEqual(post_sql("SELECT 1").status_code, 200)  # curl / API client, no browser headers

    def test_security_headers_present(self):
        h = C.get("/api/health").headers
        self.assertEqual(h.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(h.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors", h.get("Content-Security-Policy", ""))

    def test_cross_origin_referer_or_null_origin_refused(self):
        # a browser that sends only Referer (no Origin), and sandboxed / file pages (Origin: null)
        self.assertEqual(post_sql("SELECT 1", Referer="http://evil.example/page").status_code, 403)
        self.assertEqual(post_sql("SELECT 1", Origin="null").status_code, 403)
        self.assertEqual(C.put("/api/settings/retention", json={}, headers={"Origin": "http://evil.example"}).status_code, 403)
        self.assertEqual(C.post("/api/sources/x/enable", headers={"Origin": "https://localhost.evil.example"}).status_code, 403)

    def test_same_origin_write_allowed(self):
        self.assertEqual(post_sql("SELECT 1", Origin="http://localhost").status_code, 200)
        self.assertEqual(post_sql("SELECT 1", Referer="http://localhost/#sql").status_code, 200)
        # behind the reverse proxy: Caddy forwards the browser's Host, the browser's Origin matches it
        # (the proxy's X-Forwarded-Proto makes the app see https; here the request URL itself is https)
        proxied = lambda origin: C.post("https://desk.lan:8443/api/sql", json={"sql": "SELECT 1"}, headers={"Origin": origin})
        self.assertEqual(proxied("https://desk.lan:8443").status_code, 200)
        self.assertEqual(proxied("https://evil.example").status_code, 403)

    def test_origin_scheme_must_match(self):
        self.assertEqual(post_sql("SELECT 1", Origin="https://localhost").status_code, 403)   # app is http here
        self.assertEqual(C.post("https://desk.lan:8443/api/sql", json={"sql": "SELECT 1"},
                                headers={"Origin": "http://desk.lan:8443"}).status_code, 403)
        self.assertEqual(post_sql("SELECT 1", Referer="https://localhost/x").status_code, 403)
        self.assertEqual(post_sql("SELECT 1", Origin="HTTP://LOCALHOST").status_code, 200)    # case-insensitive

    def test_sec_fetch_site_case_insensitive(self):
        for v in ("Cross-Site", "CROSS-SITE", " same-site "):
            self.assertEqual(post_sql("SELECT 1", **{"Sec-Fetch-Site": v}).status_code, 403, v)


class HealthHasNoPaths(unittest.TestCase):
    def test_health_is_minimal(self):
        h = C.get("/api/health").json()
        # build: the web client id (v1.2 f-upgrade); sql_console: whether the SQL console is on (v1.2 sqlgate)
        self.assertEqual(set(h), {"ok", "sources", "offline", "build", "sql_console"})
        self.assertNotIn(os.environ["OSINTHUB_LAKE"], C.get("/api/health").text)

    def test_paths_endpoint_has_the_lake(self):
        p = C.get("/api/paths").json()
        self.assertEqual(set(p), {"lake", "inbox", "inbox_where"})
        self.assertEqual(p["lake"], os.environ["OSINTHUB_LAKE"])
        self.assertTrue(p["inbox"].endswith("inbox/zeek"))


class HostAllowlist(unittest.TestCase):
    """DNS rebinding: a hostile name pointed at 127.0.0.1 must not be served."""

    def test_foreign_hosts_refused(self):
        for h in ["evil.example", "evil.example:8787", "rebind.attacker.test:8787", "localhost.evil.example",
                  "127.0.0.1.nip.io", "desk.lan.evil.example", "", "0.0.0.0:8787"]:
            for r in (C.get("/api/health", headers={"Host": h}), C.get("/", headers={"Host": h}),
                      post_sql("SELECT 1", Host=h, Origin=f"http://{h}")):
                self.assertEqual(r.status_code, 421, h)
                self.assertIn("OSINTHUB_ALLOWED_HOSTS", r.text)

    def test_loopback_and_configured_hosts_served(self):
        for h in ["localhost", "localhost:8787", "LOCALHOST.", "127.0.0.1", "127.0.0.1:8933", "[::1]:8787",
                  "desk.lan:8443", "Desk.LAN", "hlta.local:8443"]:
            self.assertEqual(C.get("/api/health", headers={"Host": h}).status_code, 200, h)

    def test_host_name_parsing(self):
        from osinthub.config import host_name
        self.assertEqual(host_name("https://Desk.LAN:8443/x"), "desk.lan")
        self.assertEqual(host_name("[::1]:8787"), "::1")
        self.assertEqual(host_name("::1"), "::1")
        self.assertEqual(host_name("127.0.0.1:80"), "127.0.0.1")
        self.assertEqual(host_name("localhost."), "localhost")

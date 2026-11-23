"""v1.2 pre-alpha lane auth: the sign-in for non-loopback binds (OSINTHUB_PASSWORD, HTTP Basic, any user name), the
refusal to start without it, the throttle, CSRF still enforced with a valid password, the password never in a
response or log; the AI helper's Host / Origin / token guard; /docs off; the Content-Security-Policy; the 16 MB
request-body cap. okf/architecture/deployment.md#who-can-reach-it

    uv run --with pytest pytest tests/app/test_v12_auth.py -q
"""
from __future__ import annotations

import base64
import hashlib
import logging
import re
from pathlib import Path

from _lake import make_lake
PASSWORD = " ".join(["lamp", "desk", "quiet", "harbour"])   # a test value only
LAKE = make_lake("auth", disable="news,entities,ai", OSINTHUB_PASSWORD=PASSWORD,
                 OSINTHUB_ALLOWED_HOSTS="desk.example")

import pytest  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import api, config, db, httpguard  # noqa: E402

db.connect()
ROOT = Path(__file__).resolve().parents[2]
NOTE = {"kind": "story", "item": "story:auth-test", "body": "a note"}
LOOP = ("127.0.0.1", 50000)
LAN = ("192.0.2.10", 50000)


def basic(pw: str, user: str = "anyone") -> dict:
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


def client(addr=LAN, **headers) -> TestClient:
    return TestClient(api.app, base_url="http://localhost", client=addr, headers=headers)


@pytest.fixture(autouse=True)
def _fresh_throttle():
    api.AUTH_THROTTLE.reset()
    api.AUTH_NET_THROTTLE.reset()
    yield
    api.AUTH_THROTTLE.reset()
    api.AUTH_NET_THROTTLE.reset()


# ------------------------------------------------------------------ sign-in
def test_password_is_configured_from_the_environment():
    assert config.PASSWORD == PASSWORD and config.AUTH_REQUIRED and not config.TRUST_PROXY_AUTH


@pytest.mark.parametrize("method,path", [("GET", "/"), ("GET", "/index.html"), ("GET", "/api/events"),
                                         ("GET", "/api/stream"), ("GET", "/api/settings/about"),
                                         ("POST", "/api/notes"), ("GET", "/api/health")])
def test_401_without_the_password(method, path):
    r = client().request(method, path, json={"body": "probe"})
    assert r.status_code == 401, (path, r.status_code)
    assert r.headers["www-authenticate"] == 'Basic realm="Night Desk"'
    assert "content-security-policy" in r.headers                  # refusals carry the security headers too


@pytest.mark.parametrize("user", ["", "anyone", "admin", "ünïcode"])
def test_200_with_the_password_and_any_user_name(user):
    c = client(**basic(PASSWORD, user))
    assert c.get("/api/events").status_code == 200
    assert c.get("/").status_code == 200
    r = c.post("/api/notes", json=NOTE)                        # no browser headers: a script, allowed
    assert r.status_code in (200, 201), r.text


@pytest.mark.parametrize("hdr", [basic("wrong"), basic(PASSWORD + " "), basic(PASSWORD.upper()),
                                 {"Authorization": "Basic !!notbase64"}, {"Authorization": "Bearer " + PASSWORD},
                                 {"Authorization": "Basic " + base64.b64encode(PASSWORD.encode()).decode()}],
                         ids=["wrong", "trailing-space", "case", "garbled", "bearer", "no-colon"])
def test_wrong_or_garbled_credentials_are_401(hdr):
    r = client(**hdr).get("/api/events")
    assert r.status_code == 401 and r.headers["www-authenticate"] == 'Basic realm="Night Desk"'


def test_health_is_exempt_only_from_loopback_and_only_for_get():
    assert client(LOOP).get("/api/health").status_code == 200
    assert client(("::1", 1)).get("/api/health").status_code == 200
    assert client(LAN).get("/api/health").status_code == 401          # a LAN client needs the password
    assert client(LOOP).get("/api/events").status_code == 401         # loopback is exempt for health only
    assert client(LOOP).head("/api/health").status_code == 401
    assert client(LAN, **basic(PASSWORD)).get("/api/health").status_code == 200


def test_host_check_still_first():
    r = client(**basic(PASSWORD)).get("/api/events", headers={"Host": "evil.example"})
    assert r.status_code == 421
    assert "OSINTHUB_PASSWORD" in r.json()["detail"]                 # the 421 no longer suggests a bare allowlist
    assert client(**basic(PASSWORD)).get("/api/events", headers={"Host": "desk.example"}).status_code == 200


@pytest.mark.parametrize("headers", [{"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"},
                                     {"Origin": "http://evil.example"}, {"Origin": "null"},
                                     {"Referer": "http://evil.example/x"}, {"Origin": "http://localhost:9"}])
def test_csrf_still_refused_with_a_valid_password(headers):
    before = db.query("SELECT count(*) FROM notes")
    r = client(**basic(PASSWORD)).post("/api/notes", json={"body": "forged"}, headers=headers)
    assert r.status_code == 403 and "refused" in r.text
    assert db.query("SELECT count(*) FROM notes") == before


def test_same_origin_write_with_the_password_passes():
    r = client(**basic(PASSWORD)).post("/api/notes", json=NOTE,
                                       headers={"Origin": "http://localhost", "Sec-Fetch-Site": "same-origin"})
    assert r.status_code in (200, 201)


def test_no_password_means_no_sign_in(monkeypatch):
    monkeypatch.setattr(config, "PASSWORD", None)
    monkeypatch.setattr(config, "AUTH_REQUIRED", False)
    assert client().get("/api/events").status_code == 200
    assert client().post("/api/notes", json={"body": "x"}, headers={"Origin": "http://evil.example"}).status_code == 403


def test_trust_proxy_auth_skips_the_check(monkeypatch):
    monkeypatch.setattr(config, "TRUST_PROXY_AUTH", True)
    monkeypatch.setattr(config, "AUTH_REQUIRED", False)
    assert client().get("/api/events").status_code == 200
    assert client().post("/api/notes", json={"body": "x"}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


# ------------------------------------------------------------------ throttle
def test_ten_different_wrong_passwords_block_the_address_for_fifteen_minutes(caplog):
    other = client(("192.0.2.11", 1))
    for i in range(9):
        assert client(LAN, **basic(f"guess-{i}")).get("/api/events").status_code == 401
    with caplog.at_level(logging.WARNING, logger="osinthub.api"):
        assert client(LAN, **basic("guess-9")).get("/api/events").status_code == 401   # the tenth blocks
    assert "192.0.2.10 blocked" in caplog.text
    for _ in range(3):                                                 # every attempt while blocked: 429
        r = client(LAN, **basic(PASSWORD)).get("/api/events")          # the right password does not bypass it
        assert r.status_code == 429 and 800 < int(r.headers["retry-after"]) <= 901
    assert other.get("/api/events", headers=basic(PASSWORD)).status_code == 200   # other addresses unaffected
    assert api.AUTH_THROTTLE.limit == 10 and api.AUTH_THROTTLE.window == 600 and api.AUTH_THROTTLE.block == 900


def test_a_stale_tab_with_the_old_password_never_locks_the_owner_out():
    """The evaluator's scenario: the password changed, an open tab keeps polling with the old one."""
    stale = client(LAN, **basic("the-old-password"))
    for _ in range(50):
        assert stale.get("/api/events").status_code == 401             # one distinct wrong credential: counts once
    assert client(LAN, **basic(PASSWORD)).get("/api/events").status_code == 200
    for i in range(9):                                                 # a success cleared the failures: 9 new ones
        client(LAN, **basic(f"other-{i}")).get("/api/events")
    assert client(LAN, **basic(PASSWORD)).get("/api/events").status_code == 200


def test_a_correct_password_clears_earlier_failures():
    for i in range(9):
        client(LAN, **basic(f"typo-{i}")).get("/api/events")
    assert client(LAN, **basic(PASSWORD)).get("/api/events").status_code == 200
    for i in range(9):
        assert client(LAN, **basic(f"again-{i}")).get("/api/events").status_code == 401   # not blocked: 9 < 10


def test_ipv6_counts_per_address_and_more_loosely_per_64():
    # evaluator round 2, failure 1: per exact address, plus a looser /64 count against address rotation
    for i in range(10):                                                # ten passwords from ONE address
        client(("2001:db8:1:2::bad", 1), **basic(f"v6-{i}")).get("/api/events")
    assert client(("2001:db8:1:2::bad", 1), **basic(PASSWORD)).get("/api/events").status_code == 429
    assert client(("2001:db8:1:2::a", 1), **basic(PASSWORD)).get("/api/events").status_code == 200   # the owner, same /64
    for i in range(50):                                                # rotating addresses in one /64
        client((f"2001:db8:1:7::{i + 1:x}", 1), **basic(f"rot-{i}")).get("/api/events")
    assert client(("2001:db8:1:7:ffff::1", 1), **basic(PASSWORD)).get("/api/events").status_code == 429
    assert client(("2001:db8:1:8::1", 1), **basic(PASSWORD)).get("/api/events").status_code == 200   # another /64
    assert httpguard.address_key("::ffff:192.0.2.7") == "192.0.2.7"
    assert httpguard.net_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd") == "2001:db8:1:2::/64"
    assert httpguard.net_key("192.0.2.7") is None and httpguard.net_key("::1") is None
    assert httpguard.net_key("fe80::1%en0") == "fe80::/64"


def test_a_correct_poll_from_another_address_does_not_hide_guesses():
    # evaluator round 2: 9 wrong passwords, then the owner's correct poll from another address of the /64, repeated
    attacker, owner = ("2001:db8:0:7::bad", 1), ("2001:db8:0:7::a", 1)
    codes = []
    for cycle in range(5):
        for i in range(9):
            codes.append(client(attacker, **basic(f"g{cycle}-{i}")).get("/api/events").status_code)
        assert client(owner, **basic(PASSWORD)).get("/api/events").status_code == 200
    assert 429 in codes and codes.index(429) <= 10


def test_ten_wrong_passwords_from_a_neighbour_do_not_lock_the_owner_out():
    for i in range(10):
        client(("2001:db8:0:9::bad", 1), **basic(f"n-{i}")).get("/api/events")
    assert client(("2001:db8:0:9::a", 1), **basic(PASSWORD)).get("/api/events").status_code == 200


def test_eviction_never_lifts_a_block():
    th = httpguard.Throttle(limit=3, window=600, block=900, max_keys=64)
    for t in "abc":
        th.fail("192.0.2.66", t)
    assert th.blocked("192.0.2.66") > 0
    for i in range(5000):                                              # far past the cap, all other keys
        th.fail(f"198.51.100.{i % 250}-{i}", "x")
    assert th.blocked("192.0.2.66") > 0 and len(th) <= 64


def test_a_missing_header_is_not_a_failure():
    for _ in range(30):                                               # a browser's first visits before the prompt
        assert client().get("/api/events").status_code == 401
    assert client(**basic(PASSWORD)).get("/api/events").status_code == 200


def test_throttle_window_and_expiry(monkeypatch):
    t = [1000.0]
    monkeypatch.setattr(httpguard.time, "time", lambda: t[0])
    th = httpguard.Throttle(limit=3, window=10, block=20)
    assert not th.fail("192.0.2.1", "a") and not th.fail("192.0.2.1", "b")
    assert not th.fail("192.0.2.1", "a") and not th.fail("192.0.2.1", "b")   # repeats count once
    t[0] += 11                                                        # the first two fall out of the window
    assert not th.fail("192.0.2.1", "c") and not th.fail("192.0.2.1", "d") and th.fail("192.0.2.1", "e")
    assert th.blocked("192.0.2.1") == 20 and th.blocked("192.0.2.2") == 0
    th.ok("192.0.2.1")                                                # a success does not lift a block
    assert th.blocked("192.0.2.1") == 20
    t[0] += 21
    assert th.blocked("192.0.2.1") == 0


def test_throttle_is_bounded_and_flat_under_many_addresses():
    import time as _t
    import tracemalloc
    th = httpguard.Throttle(limit=10, window=600, block=900, max_keys=4096)
    tracemalloc.start()
    per = []
    for chunk in range(5):                    # 50 000 distinct clients (each its own /64 of 2001:db8::/32), 10 000 at a time
        t0 = _t.perf_counter()
        for i in range(10_000):
            n = chunk * 10_000 + i
            th.fail(f"2001:db8:{n >> 16:x}:{n & 0xffff:x}::1", "x")
        per.append((_t.perf_counter() - t0) / 10_000)
        if chunk == 0:
            mem0 = tracemalloc.get_traced_memory()[0]
    mem = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()
    assert len(th) == 4096                                            # the cap holds, the oldest are evicted
    assert max(per[1:]) < 10 * per[0] + 1e-5, per                      # flat: no growth with the number of clients
    assert max(per) < 2e-4, per                                       # and well under 0.2 ms per failure
    assert mem < mem0 * 1.5 + (1 << 20), (mem0, mem)                  # memory bounded after the cap is reached
    for i in range(50_000):                                           # a whole /64 is one entry
        th.fail(f"2001:db8:ffff:9::{i:x}", f"t{i % 9}")
    assert th.blocked("2001:db8:ffff:9::1") == 0 and len(th) == 4096
    for i in range(1000):                                             # IPv4 documentation ranges, one entry each
        th.fail(f"{('192.0.2', '198.51.100', '203.0.113')[i % 3]}.{i % 256}", "y")
    assert len(th) == 4096


# ------------------------------------------------------------------ the password stays secret
def test_password_never_in_a_response_or_the_log(caplog):
    c = client(**basic(PASSWORD))
    digest = hashlib.sha256(PASSWORD.encode()).hexdigest()
    with caplog.at_level(logging.DEBUG):
        for path in ("/api/settings/about", "/api/help/diagnostics", "/api/paths", "/api/health", "/api/settings",
                     "/api/extensions", "/api/lake"):
            r = c.get(path)
            assert r.status_code == 200, path
            assert PASSWORD not in r.text and digest not in r.text, path
        for _ in range(10):
            client(**basic(PASSWORD[:-1])).get("/api/events")
    assert PASSWORD not in caplog.text and PASSWORD[:-1] not in caplog.text


def test_refuse_to_start_on_a_non_loopback_bind_without_a_password():
    for host in ("0.0.0.0", "::", "192.0.2.10", "nightdesk.lan", "[2001:db8::1]"):
        msg = config.bind_problem(host, password="", trust_proxy=False)
        assert msg and "\n" not in msg and "OSINTHUB_PASSWORD" in msg and "127.0.0.1" in msg, host
        assert "reverse proxy" in msg
        assert config.bind_problem(host, password="long enough", trust_proxy=False) is None
        assert "8 characters" in config.bind_problem(host, password="short", trust_proxy=False)
        assert config.bind_problem(host, password="   \t ", trust_proxy=False) == msg   # whitespace only = unset
        assert config.bind_problem(host, password="", trust_proxy=True) is None
    for host in ("127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.2", "LOCALHOST"):
        assert config.bind_problem(host, password="", trust_proxy=False) is None, host


def test_short_password_refused_even_on_loopback():
    assert "8 characters" in config.bind_problem("127.0.0.1", password="1234567", trust_proxy=False)
    assert config.bind_problem("127.0.0.1", password="12345678", trust_proxy=False) is None


def test_importing_the_app_refuses_an_open_bind():
    """uvicorn osinthub.api:app / fastapi run load the app without __main__: the import refuses too."""
    import os
    import subprocess
    import sys
    env = {**os.environ, "OSINTHUB_HOST": "0.0.0.0"}
    env.pop("OSINTHUB_PASSWORD", None)
    r = subprocess.run([sys.executable, "-c", "import osinthub.api"], cwd=ROOT, env=env, capture_output=True,
                       text=True, timeout=120)
    assert r.returncode != 0 and "OSINTHUB_HOST=0.0.0.0" in r.stderr and "OSINTHUB_PASSWORD" in r.stderr


def test_a_request_over_a_public_interface_without_a_password_is_refused(monkeypatch):
    """`uvicorn osinthub.api:app --host 0.0.0.0` (the bind is not in OSINTHUB_HOST): requests that arrive on a
    non-loopback address of this machine get 503; over loopback the app still works."""
    monkeypatch.setattr(config, "PASSWORD", None)
    monkeypatch.setattr(config, "AUTH_REQUIRED", False)
    lan = TestClient(api.app, base_url="http://192.0.2.5:8787", client=LAN)
    r = lan.get("/api/events")
    assert r.status_code == 503 and "OSINTHUB_PASSWORD" in r.text
    assert TestClient(api.app, base_url="http://127.0.0.1:8787").get("/api/events").status_code == 200
    monkeypatch.setattr(config, "TRUST_PROXY_AUTH", True)                # behind the Compose proxy: served
    assert lan.get("/api/events", headers={"Host": "localhost"}).status_code == 200


def test_main_exits_before_uvicorn(monkeypatch):
    import osinthub.__main__ as m
    monkeypatch.setattr(config, "HOST", "0.0.0.0")
    monkeypatch.setattr(config, "PASSWORD", None)
    monkeypatch.setattr(m.uvicorn, "run", lambda *a, **k: pytest.fail("uvicorn must not start"))
    with pytest.raises(SystemExit) as e:
        m.main()
    assert str(e.value).startswith("osinthub: OSINTHUB_HOST=0.0.0.0") and "OSINTHUB_PASSWORD" in str(e.value)


@pytest.mark.parametrize("raw,want", [("Basic " + base64.b64encode(b"u:p:q").decode(), "p:q"),
                                      ("basic " + base64.b64encode(b":pw").decode(), "pw"),
                                      ("Basic " + base64.b64encode(b"nocolon").decode(), None),
                                      ("Basic " + base64.b64encode(b"\xff:\xfe").decode(), None),
                                      ("Digest x", None), ("", None), (None, None)])
def test_basic_parsing(raw, want):
    assert httpguard.basic_password(raw) == want


# ------------------------------------------------------------------ /docs
@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"])
def test_api_explorer_pages_are_off_by_default(path):
    assert not config.DEBUG
    assert client(**basic(PASSWORD)).get(path).status_code == 404


def test_nothing_in_the_client_or_the_suite_uses_the_api_explorer():
    pat = re.compile(r"""openapi\.json|/redoc\b|['"`]/docs\b""")
    files = [*(ROOT / "web").rglob("*.js"), ROOT / "web" / "index.html", *(ROOT / "tests").rglob("*.py")]
    skip = {Path(__file__).resolve(), ROOT / "tests" / "eval" / "offline_check.py"}   # it turns OSINTHUB_DEBUG on
    hits = [str(p) for p in files if p.resolve() not in skip and "vendor" not in p.parts and pat.search(p.read_text())]
    assert not hits


# ------------------------------------------------------------------ Content-Security-Policy
def _policy(h: str) -> dict:
    return {d.split()[0]: d.split()[1:] for d in (x.strip() for x in h.split(";")) if d}


def test_csp_on_every_response():
    c = client(**basic(PASSWORD))
    for path in ("/", "/js/main.js", "/api/health", "/api/events", "/api/nope"):
        pol = _policy(c.get(path).headers["content-security-policy"])
        for k, v in {"default-src": ["'self'"], "object-src": ["'none'"], "base-uri": ["'none'"],
                     "frame-ancestors": ["'none'"], "form-action": ["'self'"]}.items():
            assert pol[k] == v, (path, k)
        assert "'unsafe-inline'" not in pol["script-src"] and "'unsafe-eval'" not in pol["script-src"]
        assert pol["worker-src"] == ["'self'", "blob:"]


def test_csp_hashes_exactly_the_inline_scripts_of_the_page():
    page = (ROOT / "web" / "index.html").read_text()
    inline = re.findall(r"<script(?![^>]*\ssrc=)[^>]*>(.*?)</script>", page, re.S)
    assert len(inline) == 1                                          # the stale-code check; everything else is a file
    want = ["'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'" for s in inline]
    pol = _policy(client(**basic(PASSWORD)).get("/").headers["content-security-policy"])
    assert pol["script-src"] == ["'self'", *want]
    assert not re.search(r"\son[a-z]+\s*=", page.split("<script", 1)[0])   # no inline handlers in the markup


def test_csp_offline_allows_no_external_origin(monkeypatch):
    off = api.csp(offline=True)
    assert "https:" not in off and "http:" not in off and "*" not in off
    on = _policy(api.csp(offline=False))
    assert "https://cdn.bsky.app" in on["img-src"]
    assert "https://public.api.bsky.app" in on["connect-src"]   # online basemaps: only with a CARTO key (test_v12_terms)
    monkeypatch.setattr(config, "OFFLINE", True)
    assert client(**basic(PASSWORD)).get("/").headers["content-security-policy"] == off
    monkeypatch.setattr(config, "OFFLINE", False)
    assert "cdn.bsky.app" in client(**basic(PASSWORD)).get("/").headers["content-security-policy"]


def test_no_inline_event_handlers_in_the_client():
    for p in (ROOT / "web" / "js").rglob("*.js"):
        assert not re.search(r"""\son(error|load|click|mouseover|change|input|submit)\s*=\s*["'\\]""", p.read_text()), p


# ------------------------------------------------------------------ request-body cap
def test_body_over_16_mb_is_413_by_content_length():
    c = client(**basic(PASSWORD))
    r = c.post("/api/notes", content=b"x", headers={"Content-Length": str(api.MAX_BODY + 1),
                                                     "Content-Type": "application/json"})
    assert r.status_code == 413 and "16 MB" in r.text


def test_streamed_body_over_16_mb_is_413():
    def chunks():
        piece = b"[" + b"0," * (1 << 19)
        sent = 0
        while sent <= api.MAX_BODY:
            yield piece
            sent += len(piece)
    before = db.query("SELECT count(*) FROM notes")
    r = client(**basic(PASSWORD)).post("/api/notes/import", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413, r.text[:200]
    assert db.query("SELECT count(*) FROM notes") == before


def test_upload_is_capped_while_it_streams_not_after_spooling():
    # evaluator round 2, failure 2: the route's own check ran only after the whole body was on disk
    assert api.BODY_LIMITS["/api/upload"] == (64 << 20) + (1 << 20)
    try:
        from osinthub.sources import upload as up
        assert api.BODY_LIMITS["/api/upload"] >= getattr(up, "MAX_BYTES", 0)   # never below the file cap itself
    except ImportError:
        pass
    r = client(**basic(PASSWORD)).post("/api/upload", content=b"x", headers={
        "Content-Length": str(api.BODY_LIMITS["/api/upload"] + 1), "Content-Type": "multipart/form-data; boundary=b"})
    assert r.status_code == 413 and "64 MB" in r.text


def test_body_cap_middleware_exempts_the_upload_routes_and_counts_streams():
    app = FastAPI()

    async def size(request: Request):
        return {"n": len(await request.body())}
    for path in ("/api/upload", "/api/netlog/import", "/api/other"):
        app.add_api_route(path, size, methods=["POST"])
    app.add_middleware(api._BodyCap, limit=1000)
    c = TestClient(app)
    assert c.post("/api/other", content=b"x" * 1000).json() == {"n": 1000}
    assert c.post("/api/other", content=b"x" * 1001).status_code == 413
    assert c.post("/api/other", content=iter([b"x" * 600, b"x" * 600])).status_code == 413     # chunked, no length
    assert c.post("/api/other", content=b"", headers={"Content-Length": "bogus"}).status_code == 413
    app2 = FastAPI()
    for path in ("/api/upload", "/api/netlog/import", "/api/other"):
        app2.add_api_route(path, size, methods=["POST"])
    app2.add_middleware(api._BodyCap, limit=1000, limits={"/api/upload": None, "/api/netlog/import": None})
    c2 = TestClient(app2)
    for path in ("/api/upload", "/api/netlog/import"):                 # a None entry: not counted here
        assert c2.post(path, content=b"x" * 5000).json() == {"n": 5000}
        assert c2.post(path, content=iter([b"x" * 3000, b"x" * 3000])).json() == {"n": 6000}


def test_netlog_import_is_capped_at_2_gb():
    assert api.NETLOG_IMPORT_MAX == 2 << 30
    r = client(**basic(PASSWORD)).post("/api/netlog/import", content=b"x", headers={
        "Content-Length": str(api.NETLOG_IMPORT_MAX + 1), "Content-Type": "multipart/form-data; boundary=b"})
    assert r.status_code == 413 and "2 GB" in r.text and "inbox" in r.text


def test_netlog_import_over_the_cap_while_streaming_stores_nothing(monkeypatch):
    monkeypatch.setitem(api.BODY_LIMITS, "/api/netlog/import", 64 << 10)   # the same check, at a test-sized limit
    raw = Path(LAKE) / "raw" / "netlog"
    before = sorted(raw.rglob("*")) if raw.exists() else []
    line = b'{"ts": 1700000000.0, "uid": "C1", "id.orig_h": "192.0.2.1", "id.orig_p": 1, "id.resp_h": "198.51.100.1", "id.resp_p": 443, "proto": "tcp"}\n'
    body = (b"--b\r\nContent-Disposition: form-data; name=\"files\"; filename=\"conn.log\"\r\n"
            b"Content-Type: application/octet-stream\r\n\r\n" + line * 2000 + b"\r\n--b--\r\n")
    chunks = iter([body[i:i + 8192] for i in range(0, len(body), 8192)])  # chunked: no Content-Length
    r = client(**basic(PASSWORD)).post("/api/netlog/import", content=chunks,
                                       headers={"Content-Type": "multipart/form-data; boundary=b"})
    assert r.status_code == 413 and "2 GB" in r.text
    assert (sorted(raw.rglob("*")) if raw.exists() else []) == before          # nothing reached the lake
    small = body[:body.index(b"\r\n\r\n") + 4] + line * 10 + b"\r\n--b--\r\n"
    ok = client(**basic(PASSWORD)).post("/api/netlog/import", content=small,
                                        headers={"Content-Type": "multipart/form-data; boundary=b"})
    assert ok.status_code == 200, ok.text[:200]


# ------------------------------------------------------------------ the AI helper (in-process, no model loaded)
@pytest.fixture()
def helper(monkeypatch):
    from osinthub.ai import server
    monkeypatch.setattr(server, "TOKEN", None)
    return server


def test_helper_host_allowlist(helper):
    c = TestClient(helper.app, base_url="http://127.0.0.1:8790")       # no `with`: no lifespan, no model
    assert c.get("/health").status_code == 200
    for good in ("localhost:8790", "[::1]:8790", "host.docker.internal:8790"):
        assert c.get("/health", headers={"Host": good}).status_code == 200, good
    for bad in ("rebind.evil.example:8790", "127.0.0.1.evil.example", "192.0.2.10:8790"):
        assert c.get("/health", headers={"Host": bad}).status_code == 421, bad
    assert c.post("/v1/embeddings", json={"input": "x"}, headers={"Host": "rebind.evil.example"}).status_code == 421


def test_helper_refuses_cross_site_writes(helper):
    c = TestClient(helper.app, base_url="http://127.0.0.1:8790")
    for h in ({"Origin": "http://evil.example"}, {"Sec-Fetch-Site": "cross-site"}, {"Origin": "null"}):
        r = c.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "x"}]}, headers=h)
        assert r.status_code == 403, h
    # the app's own calls send no browser headers: they reach the handler (503: no model loaded here)
    assert c.post("/v1/embeddings", json={"input": "x"}).status_code == 503


def test_helper_token(helper, monkeypatch):
    monkeypatch.setattr(helper, "TOKEN", "helper-test-token")
    c = TestClient(helper.app, base_url="http://127.0.0.1:8790")
    assert c.get("/health").status_code == 401
    assert c.get("/health", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/health", headers={"Authorization": "Bearer helper-test-token"}).status_code == 200
    assert c.post("/v1/embeddings", json={"input": "x"}).status_code == 401
    assert c.get("/docs").status_code in (401, 404) and c.get("/openapi.json", headers={
        "Authorization": "Bearer helper-test-token"}).status_code == 404


def test_helper_refuses_to_start_beyond_loopback_without_a_token(helper):
    for host in ("0.0.0.0", "::", "192.0.2.10", "ai.example"):
        msg = helper.bind_problem(host, token="")
        assert msg and "AI_TOKEN" in msg and "\n" not in msg, host
        assert helper.bind_problem(host, token="t") is None
    for host in ("127.0.0.1", "localhost", "::1"):
        assert helper.bind_problem(host, token="") is None


def test_app_sends_the_helper_token(monkeypatch):
    from osinthub.ai import client as ai
    monkeypatch.setattr(config, "AI_TOKEN", "helper-test-token")
    monkeypatch.setattr(ai, "_http", None)
    try:
        assert ai._client().headers["authorization"] == "Bearer helper-test-token"
        monkeypatch.setattr(config, "AI_TOKEN", None)
        monkeypatch.setattr(ai, "_http", None)
        assert "authorization" not in ai._client().headers
    finally:
        monkeypatch.setattr(ai, "_http", None)

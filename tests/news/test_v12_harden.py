"""v1.2 harden (M1): robots.txt is fetched hop by hop with the public-address check, and every request
goes to the address that was checked (DNS rebinding). No real network: an httpx MockTransport stands in
for the internet, and the TLS test runs a loopback server with a certificate made here.

    uv run --with pytest pytest tests/news/test_v12_harden.py -q
"""
import asyncio
import datetime as dt
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
    os.environ.pop(k, None)
from _lake import make_lake  # noqa: E402
LAKE = make_lake("harden-news", offline=False)

import httpx  # noqa: E402
import pytest  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.news import fetcher as F  # noqa: E402
from osinthub.news.common import article_id, ensure_schema  # noqa: E402

ensure_schema()
F.DOMAIN_DELAY = 0.0
ARTICLE = ("<html lang=en><head><title>T</title></head><body><article><h1>T</h1><p>"
           + "Real article words here about a thing that happened to a company. " * 40 + "</p></article></body></html>")

# Check-time DNS. The documentation ranges stand in for public addresses: the real guard treats them as
# non-public (they are not globally routable), so the tests let exactly these ranges through.
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
_real_blocked = F._blocked_ip


def _blocked_for_test(ip):
    try:
        if any(ipaddress.ip_address(ip) in n for n in DOC_NETS):
            return False
    except ValueError:
        pass
    return _real_blocked(ip)



DNS = {"pub.example": ["203.0.113.10"], "cdn.example": ["198.51.100.8"], "lan.example": ["10.86.24.7"],
       "mixed.example": ["203.0.113.11", "10.0.0.9"], "rebind.example": ["203.0.113.20"]}


def _is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


class Net:
    """A fake internet. A request whose URL holds a name (not an IP) is "resolved" with CONNECT_DNS, the
    way the HTTP library would resolve it at connect time; that is where a rebinding name turns into
    loopback. Every delivery is recorded as (address connected to, Host header, path)."""
    CONNECT_DNS = {"rebind.example": "127.0.0.1"}

    def __init__(self, routes):
        self.routes, self.log = routes, []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        dest = req.url.host if _is_ip(req.url.host) else self.CONNECT_DNS.get(req.url.host, "0.0.0.0")
        host = req.headers.get("host", "").split(":")[0]
        self.log.append((dest, host, req.url.path, req.extensions.get("sni_hostname")))
        if ipaddress.ip_address(dest).is_loopback:
            return httpx.Response(200, text="User-agent: *\nAllow: /\n# loopback secret",
                                  headers={"content-type": "text/html"})
        fn = self.routes.get((host, req.url.path))
        return fn() if fn else httpx.Response(404)


@pytest.fixture
def net(monkeypatch):
    def use(routes):
        n = Net(routes)
        monkeypatch.setattr(F, "_article_client", httpx.AsyncClient(transport=httpx.MockTransport(n), follow_redirects=False))
        return n
    monkeypatch.setattr(F, "_blocked_ip", _blocked_for_test)
    monkeypatch.setattr(F, "_resolve", lambda h: list(DNS[h]) if h in DNS else (_ for _ in ()).throw(socket.gaierror("no such name")))
    F._robots.clear()
    F._last_hit.clear()
    db.execute("DELETE FROM news_robots")
    return use


def redirect(to):
    return lambda: httpx.Response(302, headers={"location": to})


@pytest.mark.parametrize("target", ["http://127.0.0.1/robots.txt", "http://192.168.1.1/cgi?x=1",
                                    "http://169.254.169.254/latest/meta-data/", "http://[::1]:8790/health",
                                    "http://lan.example/robots.txt", "http://mixed.example/robots.txt",
                                    "file:///etc/passwd"])
def test_robots_redirect_to_internal_is_refused(net, target):
    n = net({("pub.example", "/robots.txt"): redirect(target)})
    status, body = asyncio.run(F._fetch_robots("https://pub.example/robots.txt"))
    assert (status, body) == (599, "")                       # unavailable, same as an unreachable robots.txt
    assert [x[0] for x in n.log] == ["203.0.113.10"]         # only the public hop was requested
    rp, st = asyncio.run(F.robots_for("https://pub.example", "pub.example"))
    assert rp is None and st == 599                          # robots unavailable -> article retried later
    assert db.query("SELECT count(*) AS n FROM news_robots")[0]["n"] == 0   # nothing stored


def test_robots_public_redirects_still_work(net):
    n = net({("pub.example", "/robots.txt"): redirect("https://cdn.example/r/robots.txt"),
             ("cdn.example", "/r/robots.txt"): lambda: httpx.Response(200, text="User-agent: *\nDisallow: /private\n")})
    rp, st = asyncio.run(F.robots_for("https://pub.example", "pub.example"))
    assert st == 200 and rp is not None
    assert not rp.can_fetch(F.config.USER_AGENT, "https://pub.example/private/x")
    assert rp.can_fetch(F.config.USER_AGENT, "https://pub.example/news/x")
    assert [(x[0], x[1], x[3]) for x in n.log] == [("203.0.113.10", "pub.example", "pub.example"),
                                                   ("198.51.100.8", "cdn.example", "cdn.example")]
    assert db.query("SELECT status FROM news_robots WHERE domain = 'pub.example'")[0]["status"] == 200


def test_robots_too_many_redirects_is_unavailable(net):
    net({("pub.example", "/robots.txt"): redirect("/robots.txt")})
    assert asyncio.run(F._fetch_robots("https://pub.example/robots.txt")) == (599, "")


def test_robots_body_is_capped(net):
    net({("pub.example", "/robots.txt"): lambda: httpx.Response(200, text="# x\n" * 400_000)})
    st, body = asyncio.run(F._fetch_robots("https://pub.example/robots.txt"))
    assert st == 200 and len(body) == F.ROBOTS_MAX_BYTES


def _add(url):
    aid = article_id(url)
    day = (dt.datetime.now(dt.UTC) - dt.timedelta(days=1)).strftime("%Y-%m-%dT10:00:00Z")
    db.execute("INSERT OR REPLACE INTO articles (id, url, source, title, status, attempts, published) "
               "VALUES (?, ?, 'mock', 'T', 'queued', 0, ?)", [aid, url, day])
    return db.query("SELECT * FROM articles WHERE id = ?", [aid])[0]


def test_rebinding_name_never_reaches_loopback(net):
    """rebind.example answers public at check time and loopback at connect time: every request goes to the
    checked address, so loopback is never contacted and nothing from it is stored."""
    n = net({("rebind.example", "/robots.txt"): lambda: httpx.Response(200, text="User-agent: *\nAllow: /\n"),
             ("rebind.example", "/a"): lambda: httpx.Response(200, text=ARTICLE, headers={"content-type": "text/html"})})
    row = _add("https://rebind.example/a")
    assert asyncio.run(F.fetch_article(row)) == "ok"
    assert n.log and all(x[0] == "203.0.113.20" for x in n.log), n.log
    assert all(x[1] == "rebind.example" and x[3] == "rebind.example" for x in n.log)
    got = db.query("SELECT text, canonical_url FROM articles WHERE id = ?", [row["id"]])[0]
    assert "loopback secret" not in (got["text"] or "")
    assert got["canonical_url"].startswith("https://rebind.example/")   # the name, not the pinned address


def test_rebinding_between_check_and_connect_is_refused(net, monkeypatch):
    """The name flips to loopback after _allowed checked it: the pinned send resolves again, refuses, and
    sends nothing."""
    n = net({("pub.example", "/robots.txt"): lambda: httpx.Response(200, text="User-agent: *\nAllow: /\n")})
    row = _add("https://pub.example/b")
    calls = {"n": 0}

    def flip(h):
        calls["n"] += 1
        return ["203.0.113.10"] if calls["n"] <= 2 else ["127.0.0.1"]   # _allowed + robots, then loopback
    monkeypatch.setattr(F, "_resolve", flip)
    assert asyncio.run(F.fetch_article(row)) == "blocked"
    assert [x[2] for x in n.log] == ["/robots.txt"]
    assert "not a public address" in db.query("SELECT reason FROM articles WHERE id = ?", [row["id"]])[0]["reason"]


def test_article_public_redirect_works_and_internal_redirect_is_refused(net):
    ok = lambda: httpx.Response(200, text=ARTICLE, headers={"content-type": "text/html"})  # noqa: E731
    robots = lambda: httpx.Response(200, text="User-agent: *\nAllow: /\n")  # noqa: E731
    n = net({("pub.example", "/robots.txt"): robots, ("cdn.example", "/robots.txt"): robots,
             ("pub.example", "/moved"): redirect("https://cdn.example/new"), ("cdn.example", "/new"): ok,
             ("pub.example", "/evil"): redirect("http://169.254.169.254/latest/")})
    assert asyncio.run(F.fetch_article(_add("https://pub.example/moved"))) == "ok"
    r = _add("https://pub.example/evil")
    assert asyncio.run(F.fetch_article(r)) == "blocked"
    assert {x[0] for x in n.log} == {"203.0.113.10", "198.51.100.8"}   # never the metadata address
    assert "public address" in db.query("SELECT reason FROM articles WHERE id = ?", [r["id"]])[0]["reason"]


def test_pinned_request_shape(monkeypatch):
    monkeypatch.setattr(F, "_resolve", lambda h: ["2001:db8::5"])
    monkeypatch.setattr(F, "_blocked_ip", _blocked_for_test)
    req = F.pinned_request(httpx.AsyncClient(), "https://v6.example:8443/p?q=1", {"Accept": "text/plain"})
    assert str(req.url) == "https://[2001:db8::5]:8443/p?q=1"
    assert req.headers["host"] == "v6.example:8443" and req.extensions["sni_hostname"] == "v6.example"
    with pytest.raises(F.NotPublic):
        F.pinned_request(httpx.AsyncClient(), "http://[::1]/")
    with pytest.raises(F.NotPublic):
        F.pinned_request(httpx.AsyncClient(), "ftp://203.0.113.5/")


def test_article_client_does_not_reuse_connections():
    F._article_client = None
    pool = F.article_client()._transport._pool
    assert pool._max_keepalive_connections == 0     # a TLS connection made for one name is never reused for another
    assert pool._ssl_context.check_hostname and pool._ssl_context.verify_mode == ssl.CERT_REQUIRED


# ------------------------------------------------------------------ real sockets, loopback only
def _certs(tmp):
    """A CA and a leaf certificate for news.example, written to tmp; returns (ca.pem, leaf.pem, key.pem)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = dt.datetime.now(dt.UTC)
    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test ca")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
          .not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "news.example")]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("news.example")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    paths = [os.path.join(tmp, n) for n in ("ca.pem", "leaf.pem", "key.pem")]
    for p, data in zip(paths, (ca.public_bytes(serialization.Encoding.PEM), leaf.public_bytes(serialization.Encoding.PEM),
                               leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))):
        with open(p, "wb") as f:
            f.write(data)
    return paths


def test_https_pinned_ip_verifies_certificate_for_the_real_name(monkeypatch):
    """A loopback TLS server with a certificate for news.example. The request goes to 127.0.0.1 (the
    pinned address) with SNI news.example: it verifies. The same server under another name fails
    verification, so pinning the IP never turns certificate checks off. The name is never looked up by
    the HTTP library (socket.getaddrinfo refuses it)."""
    tmp = tempfile.mkdtemp()
    ca, leaf, key = _certs(tmp)
    seen = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_GET(self):
            seen.append(self.headers.get("Host"))
            b = b"User-agent: *\nDisallow: /x\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(leaf, key)
    snis = []
    sctx.sni_callback = lambda sock, name, ctx: snis.append(name)
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    real_gai = socket.getaddrinfo

    def gai(host, *a, **k):
        if str(host).endswith(".example"):
            raise socket.gaierror("the HTTP library must not resolve the name itself")
        return real_gai(host, *a, **k)
    monkeypatch.setattr(socket, "getaddrinfo", gai)
    monkeypatch.setattr(F, "_resolve", lambda h: ["127.0.0.1"])
    monkeypatch.setattr(F, "_blocked_ip", lambda ip: ip != "127.0.0.1")   # the loopback server stands in for a public one
    monkeypatch.setattr(F, "_article_client", httpx.AsyncClient(verify=ssl.create_default_context(cafile=ca),
                                                                follow_redirects=False,
                                                                limits=httpx.Limits(max_keepalive_connections=0)))
    try:
        st, body = asyncio.run(F._fetch_robots(f"https://news.example:{port}/robots.txt"))
        assert st == 200 and "Disallow: /x" in body
        assert seen == [f"news.example:{port}"] and snis == ["news.example"]
        st2, _ = asyncio.run(F._fetch_robots(f"https://wrong.example:{port}/robots.txt"))
        assert st2 == 599                     # certificate is for news.example: verification fails
        assert seen == [f"news.example:{port}"]
    finally:
        srv.shutdown()
        srv.server_close()


# ------------------------------------------------------------------ round 2
def test_article_client_ignores_proxy_environment(monkeypatch):
    """Pinned connections go direct: a proxy tunnel would start TLS with the pinned IP as the server name."""
    for k in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "HTTP_PROXY"):
        monkeypatch.setenv(k, "http://127.0.0.1:9")
    monkeypatch.setattr(F, "_article_client", None)
    cl = F.article_client()
    try:
        assert cl._trust_env is False
        for u in ("https://203.0.113.10/a", "http://203.0.113.10/a"):
            assert cl._transport_for_url(httpx.URL(u)) is cl._transport    # no proxy transport mounted
    finally:
        asyncio.run(cl.aclose())
        F._article_client = None


def test_multicast_and_6to4_anycast_are_not_public():
    for ip in ("224.0.0.1", "239.255.255.250", "ff02::1", "ff0e::1", "::ffff:224.0.0.1", "192.88.99.1"):
        assert F._blocked_ip(ip), ip


def test_each_checked_address_is_tried_in_order_and_only_those(net, monkeypatch):
    DNS["dual.example"] = ["2001:db8::7", "203.0.113.30"]
    tried = []

    def handler(req):
        tried.append(req.url.host)
        if req.url.host == "2001:db8::7":
            raise httpx.ConnectError("no route", request=req)
        return httpx.Response(200, text="User-agent: *\nAllow: /\n")
    monkeypatch.setattr(F, "_article_client", httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    try:
        st, body = asyncio.run(F._fetch_robots("https://dual.example/robots.txt"))
        assert st == 200 and tried == ["2001:db8::7", "203.0.113.30"]
        DNS["dual.example"] = ["2001:db8::7", "127.0.0.1"]          # one answer not public: nothing is tried
        tried.clear()
        assert asyncio.run(F._fetch_robots("https://dual.example/robots.txt")) == (599, "")
        assert tried == []
    finally:
        DNS.pop("dual.example", None)

"""Fetcher politeness against local mock sites (no internet, temporary lake).

    uv run --with pytest pytest tests/news/test_fetcher.py -q

Checks: robots.txt re-checked on every redirect hop (a redirect into a disallowed host is refused
without requesting it), 503 pauses the whole domain, conditional GET on a re-fetch, the 6 h re-fetch,
and zero requests when offline.
"""
import asyncio
import datetime, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
    os.environ.pop(k, None)
from _lake import make_lake  # noqa: E402
LAKE = make_lake("news", offline=False)

LOG = []
BODY = ("<html lang=en><head><title>T</title></head><body><article><h1>T</h1><p>"
        + "Real article words here about a thing that happened to a company. " * 40 + "</p></article></body></html>")


def make(name, robots):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_GET(self):
            LOG.append({"host": name, "path": self.path, "ua": self.headers.get("User-Agent"),
                        "inm": self.headers.get("If-None-Match")})
            hdr = {}
            if self.path == "/robots.txt":
                code, b, hdr = 200, robots.encode(), {"Content-Type": "text/plain"}
            elif self.path.startswith("/down"):
                code, b = 503, b"down"
            elif self.path.startswith("/redir"):
                code, b, hdr = 302, b"", {"Location": f"http://localhost:{P2}/secret"}
            elif self.path.startswith("/to-lan"):
                code, b, hdr = 302, b"", {"Location": "http://10.255.255.1/x"}
            elif self.path.startswith("/hop"):
                code, b, hdr = 301, b"", {"Location": "/ok-moved"}
            elif self.headers.get("If-None-Match") == '"v1"':
                code, b = 304, b""
            else:
                code, b, hdr = 200, BODY.encode(), {"Content-Type": "text/html", "ETag": '"v1"'}
            self.send_response(code)
            for k, v in hdr.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return H


sA = ThreadingHTTPServer(("127.0.0.1", 0), make("A", "User-agent: *\nDisallow: /private\n"))
sB = ThreadingHTTPServer(("127.0.0.1", 0), make("B", "User-agent: *\nDisallow: /\n"))
P1, P2 = sA.server_address[1], sB.server_address[1]
for s in (sA, sB):
    threading.Thread(target=s.serve_forever, daemon=True).start()

from osinthub import config, db  # noqa: E402
from osinthub.news import fetcher  # noqa: E402
from osinthub.news.common import article_id, ensure_schema  # noqa: E402

fetcher.DOMAIN_DELAY = 0.2
ensure_schema()
A = f"http://127.0.0.1:{P1}"

# The fetcher's SSRF guard refuses every non-public host, which includes these loopback mock sites. The
# test lets exactly the fixture's hosts through by wrapping the guard (production code is unchanged);
# every other host, e.g. a redirect into the LAN, still goes through the real check.
FIXTURE_HOSTS = {"127.0.0.1": "127.0.0.1", "localhost": "127.0.0.1"}
_real_public_ips = fetcher.public_ips


def _public_ips_for_test(host):
    return [FIXTURE_HOSTS[host]] if host in FIXTURE_HOSTS else _real_public_ips(host)


# Article dates are relative to today: the re-fetch schedule skips old articles, so fixed dates made this test
# start failing once they were more than a week old.
DAY = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)).strftime("%Y-%m-%d")


def add(url, published=None):
    published = published or f"{DAY}T10:00:00Z"
    aid = article_id(url)
    db.execute("INSERT OR REPLACE INTO articles (id, url, source, title, status, attempts, published) VALUES (?, ?, 'mock', 'T', 'queued', 0, ?)",
               [aid, url, published])
    return aid


def row(aid):
    return db.query("SELECT status, reason, etag, refetch_stage FROM articles WHERE id = ?", [aid])[0]


fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  {detail}" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def test_fetcher_politeness():
    fetcher.public_ips, _offline = _public_ips_for_test, config.OFFLINE
    try:
        _politeness_checks()
    finally:
        fetcher.public_ips = _real_public_ips
        config.OFFLINE = _offline


def _politeness_checks():
    # 0. the guard itself: loopback, LAN and metadata addresses are refused without the test override
    check("SSRF guard refuses loopback and private hosts",
          not any(_real_public_ips(h) for h in ("127.0.0.1", "localhost", "10.0.0.1", "169.254.169.254", "::1")))

    # 1. redirect into a robots-disallowed host; a same-host redirect is followed; a normal article
    ids = {p: add(A + p, f"{DAY}T10:0{i}:00Z") for i, p in enumerate(["/redir1", "/hop1", "/ok1"])}
    asyncio.run(fetcher.fetch_pass())
    check("redirect into disallowed host is blocked", row(ids["/redir1"])["status"] == "blocked", row(ids["/redir1"]))
    check("disallowed redirect target never requested", not any(l["host"] == "B" and l["path"] != "/robots.txt" for l in LOG))
    check("robots.txt of the redirect target was read", any(l["host"] == "B" and l["path"] == "/robots.txt" for l in LOG))
    check("same-host redirect followed", row(ids["/hop1"])["status"] == "ok", row(ids["/hop1"]))
    check("normal article ok with ETag", row(ids["/ok1"])["status"] == "ok" and row(ids["/ok1"])["etag"] == '"v1"', row(ids["/ok1"]))
    check("honest User-Agent only", {l["ua"] for l in LOG} == {config.USER_AGENT})
    check("redirect into a disallowed host is blocked by robots.txt", "robots" in (row(ids["/redir1"])["reason"] or ""),
          row(ids["/redir1"]))
    lan = add(A + "/to-lan1", f"{DAY}T10:05:00Z")
    asyncio.run(fetcher.fetch_pass())
    check("redirect into the LAN is refused by the SSRF guard", row(lan)["status"] == "blocked"
          and "not a public address" in (row(lan)["reason"] or ""), row(lan))

    # 2. a 503 pauses the whole domain for the rest of the pass
    d = [add(A + p, f"{DAY}T11:0{9 - i}:00Z") for i, p in enumerate(["/down1", "/later1", "/later2"])]  # newest first
    n0 = len(LOG)
    asyncio.run(fetcher.fetch_pass())
    hits = [l["path"] for l in LOG[n0:] if l["host"] == "A" and l["path"] != "/robots.txt"]
    check("503 pauses the domain", hits == ["/down1"], hits)
    check("paused rows wait (next_attempt set)", all(db.query("SELECT next_attempt FROM articles WHERE id=?", [x])[0]["next_attempt"] for x in d[1:]))
    fetcher._paused.clear()

    # 3. re-fetch after 6 h sends If-None-Match and records the stage
    db.execute("UPDATE articles SET fetched_at = now() - INTERVAL 7 HOUR, checked_at = NULL WHERE id = ?", [ids["/ok1"]])
    db.execute("UPDATE articles SET status = 'failed' WHERE id IN (?, ?, ?)", d)
    n0 = len(LOG)
    asyncio.run(fetcher.fetch_pass())
    ref = [l for l in LOG[n0:] if l["path"] == "/ok1"]
    check("6 h re-fetch is conditional", ref and ref[0]["inm"] == '"v1"', ref)
    check("re-fetch stage advanced on 304", row(ids["/ok1"])["refetch_stage"] == 1, row(ids["/ok1"]))

    # 4. offline: nothing
    config.OFFLINE = True
    db.execute("UPDATE articles SET status = 'queued', next_attempt = NULL")
    n0 = len(LOG)
    asyncio.run(fetcher.fetch_pass())
    check("offline makes zero requests", len(LOG) == n0)
    print("ALL PASS" if not fails else f"{len(fails)} FAILED")
    assert not fails, f"{len(fails)} failed: {fails}"


if __name__ == "__main__":
    try:
        test_fetcher_politeness()
    except AssertionError:
        sys.exit(1)


# ---------------------------------------------------------------- SSRF: never a non-public target
import unittest  # noqa: E402

from osinthub.news import fetcher as F  # noqa: E402


class SsrfGuard(unittest.TestCase):
    def test_non_global_ips_blocked(self):
        for ip in ["127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "100.64.0.1",
                   "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:169.254.169.254"]:
            self.assertTrue(F._blocked_ip(ip), ip)
        for ip in ["::7f00:1", "64:ff9b::7f00:1", "64:ff9b::a00:1"]:  # IPv4-compatible / NAT64 embedding internal v4
            self.assertTrue(F._blocked_ip(ip), ip)
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]:
            self.assertFalse(F._blocked_ip(ip), ip)

    def test_host_is_public(self):
        for bad in ["127.0.0.1", "localhost", "169.254.169.254", None, ""]:
            self.assertFalse(F._host_is_public(bad), bad)
        self.assertTrue(F._host_is_public("8.8.8.8"))  # IP literal, no DNS

    def test_allowed_refuses_internal_targets_without_network(self):
        import asyncio
        for u in ["http://127.0.0.1:8790/v1/models", "http://169.254.169.254/latest/meta-data/",
                  "http://[::1]/", "http://192.168.1.1/", "http://10.1.2.3/x"]:
            ok, delay, why = asyncio.run(F._allowed(u))
            self.assertIs(ok, False, u)
            self.assertIn("public address", why)

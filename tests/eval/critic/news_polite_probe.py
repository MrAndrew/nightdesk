"""Critic probe of osinthub.news.fetcher politeness against a local mock site (no internet).

    OSINTHUB_LAKE=<empty scratch dir> OSINTHUB_OFFLINE=0 OSINTHUB_NEWS_NO_VECTORS=1 uv run python tests/eval/critic/news_polite_probe.py

Mock hosts: 127.0.0.1:<p1> ("site A") and localhost:<p2> ("site B", robots disallows all).
Checks: UA, robots disallow, per-domain spacing, 429 handling across a domain, cross-domain redirect
robots bypass, conditional GET, and that OFFLINE=1 makes zero requests.
"""
import asyncio, json, os, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []
BODY = "<html lang=en><head><title>T</title></head><body><article><h1>T</h1>" + "<p>" + ("Real article words here about a thing. " * 40) + "</p></article></body></html>"

def make(name, robots):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            LOG.append({"t": time.monotonic(), "host": name, "path": self.path, "ua": self.headers.get("User-Agent"),
                        "inm": self.headers.get("If-None-Match"), "ims": self.headers.get("If-Modified-Since")})
            if self.path == "/robots.txt":
                b = robots.encode(); self.send_response(200); self.send_header("Content-Type", "text/plain")
            elif self.path.startswith("/busy"):
                b = b"slow down"; self.send_response(429); self.send_header("Retry-After", "600")
            elif self.path.startswith("/down"):
                b = b"down"; self.send_response(503)
            elif self.path.startswith("/redir"):
                b = b""; self.send_response(302); self.send_header("Location", f"http://localhost:{P2}/secret")
            else:
                b = BODY.encode(); self.send_response(200); self.send_header("Content-Type", "text/html")
                self.send_header("ETag", '"v1"'); self.send_header("Last-Modified", "Wed, 04 Nov 2026 10:00:00 GMT")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    return H

sA = ThreadingHTTPServer(("127.0.0.1", 0), make("A", "User-agent: *\nDisallow: /private\n"))
sB = ThreadingHTTPServer(("127.0.0.1", 0), make("B", "User-agent: *\nDisallow: /\n"))
P1, P2 = sA.server_address[1], sB.server_address[1]
for s in (sA, sB): threading.Thread(target=s.serve_forever, daemon=True).start()

for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"): os.environ.pop(k, None)
from osinthub import config, db
from osinthub.news import fetcher
from osinthub.news.common import ensure_schema, article_id
fetcher.DOMAIN_DELAY = 1.0   # shrink the 8 s delay so the probe is quick; spacing is checked relative to it
ensure_schema()

def add(url):
    aid = article_id(url)
    db.execute("INSERT OR REPLACE INTO articles (id, url, source, title, status, attempts) VALUES (?, ?, 'mock', 'T', 'queued', 0)", [aid, url])
    return aid

A = f"http://127.0.0.1:{P1}"
ids = {p: add(A + p) for p in ["/busy1", "/busy2", "/busy3", "/down1", "/ok1", "/private/x", "/redir1"]}
r = asyncio.run(fetcher.fetch_pass())
res = {"pass": r, "rows": {p: db.query("SELECT status, reason, attempts, next_attempt FROM articles WHERE id=?", [i])[0] for p, i in ids.items()}}
a_hits = [l for l in LOG if l["host"] == "A" and l["path"] != "/robots.txt"]
gaps = [round(b["t"] - a["t"], 2) for a, b in zip(a_hits, a_hits[1:])]
res["A_requests"] = [l["path"] for l in a_hits]
res["A_gaps_s"] = gaps
res["requests_after_first_429"] = [l["path"] for l in a_hits[a_hits.index(next(l for l in a_hits if l["path"].startswith("/busy"))) + 1:]]
res["B_requests"] = [l["path"] for l in LOG if l["host"] == "B"]
res["uas"] = sorted({l["ua"] for l in LOG})
res["private_requested"] = any(l["path"].startswith("/private") for l in LOG)

# conditional GET: re-queue the fetched ok article and fetch again
db.execute("UPDATE articles SET status='queued', next_attempt=NULL WHERE id=?", [ids["/ok1"]])
n0 = len(LOG); asyncio.run(fetcher.fetch_pass())
res["refetch_headers"] = [(l["path"], l["inm"], l["ims"]) for l in LOG[n0:] if l["path"] == "/ok1"]

# offline: zero requests
config.OFFLINE = True
db.execute("UPDATE articles SET status='queued', next_attempt=NULL")
n0 = len(LOG); asyncio.run(fetcher.fetch_pass())
res["offline_requests"] = len(LOG) - n0
print(json.dumps(res, indent=1, default=str))

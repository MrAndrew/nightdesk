"""Guard journeys: offline mode sends nothing off the machine across a full walk; the server refuses a foreign Host
(DNS rebinding) and cross-origin writes (CSRF), from a script and from a real browser page on another origin."""
from __future__ import annotations

import http.client
import json

import pytest
from journey import open_app
from playwright.sync_api import expect

# Every top-level view and the routes users reach most, in the order a person might wander through them.
WALK = ["#watch", "#network/overview", "#network/alerts", "#network/hunt", "#network/devices", "#network/import",
        "#news", "#news/story/story:e2e-art-1", "#news/article/e2e-art-1", "#entities", "#entities/actor:apt28",
        "#entities/graph", "#ops", "#cinema", "#explorer", "#notes", "#settings/sources", "#settings/follow",
        "#settings/home", "#settings/data", "#settings/notifications", "#settings/about"]
SETTLE_MS = 700   # after a view renders, time for what it loads lazily (maps, charts, tiles) to ask for it


@pytest.mark.parametrize("form", ["desktop", "phone"])
def test_offline_full_walk_makes_no_outbound_requests(demo, ui, form):
    """With OSINTHUB_OFFLINE=1 the whole app, every view and the Help desk, asks nothing of any host but this one
    (the page's request recorder aborts and lists anything else), and Run now fetches nothing."""
    nd = demo
    assert nd.get("/api/health")["offline"] is True
    page = open_app(ui(form), "#watch")
    seen: list[str] = []
    page.on("request", lambda r: seen.append(r.url))
    for route in WALK:
        if form == "phone" and route == "#cinema":
            continue                                                  # a desktop-only view
        page.evaluate("h => { location.hash = h }", route)
        page.wait_for_function("h => location.hash.split('?')[0] === h || location.hash.startsWith(h)", arg=route)
        expect(page.locator(".view.active")).not_to_be_empty()
        page.wait_for_timeout(SETTLE_MS)
    if form == "desktop":
        page.keyboard.press("?")
        expect(page.locator(".help-x")).to_be_visible()
        page.wait_for_timeout(SETTLE_MS)
    run = nd.post("/api/sources/feodo_c2/run")
    assert run.get("skipped") and run.get("error") == "offline mode", run
    assert len(seen) > 50, f"the walk made only {len(seen)} requests; did the views load?"
    assert page.nd_log["egress"] == [], page.nd_log["egress"]
    assert all(u.startswith(("http://127.0.0.1", "http://localhost", "data:", "blob:")) for u in seen), \
        [u for u in seen if not u.startswith(("http://127.0.0.1", "http://localhost", "data:", "blob:"))][:10]
    # the recorder itself works: a request to another host is caught (and aborted), so an empty list means something.
    # It is sent from a blank page in the same browser context: the app's own pages carry its Content-Security-Policy,
    # which (correctly) blocks the fetch before it is sent, so the recorder would never see it from there.
    probe = page.context.new_page()
    probe.goto("about:blank")
    probe.evaluate("fetch('http://198.51.100.1/e2e-recorder-check').catch(() => null)")
    probe.wait_for_timeout(300)
    probe.close()
    assert any("198.51.100.1" in e for e in page.nd_log["egress"]), page.nd_log["egress"]
    page.nd_log["egress"].clear()
    page.nd_log["console_errors"] = [e for e in page.nd_log["console_errors"] if "ERR_FAILED" not in e]


def _raw(nd, method, path, headers, body=None):
    c = http.client.HTTPConnection("127.0.0.1", nd.port, timeout=10)
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    out = r.status, r.read()
    c.close()
    return out


def _evil_page_server():
    """A plain page on a free loopback port (another origin than the app), served from a daemon thread."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<!doctype html><title>other origin</title><p>another origin</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_security_bad_host_and_cross_origin_writes_refused(nd, ui):
    """A request naming another host gets 421 (DNS rebinding); a write from another origin gets 403 (CSRF) and
    changes nothing, whether a script sends it or a real page on another origin does."""
    st, body = _raw(nd, "GET", "/api/health", {"Host": "evil.example"})
    assert st == 421 and b"not allowed" in body
    st, _ = _raw(nd, "GET", "/", {"Host": f"rebind.example:{nd.port}"})
    assert st == 421
    st, _ = _raw(nd, "GET", "/api/health", {"Host": f"127.0.0.1:{nd.port}"})
    assert st == 200
    note = json.dumps({"kind": "story", "item": "story:e2e-art-1", "body": "E2E cross-origin note"})
    base = {"Host": f"127.0.0.1:{nd.port}", "Content-Type": "application/json"}
    for h in ({"Origin": "http://evil.example"}, {"Referer": "http://evil.example/page"},
              {"Sec-Fetch-Site": "cross-site"}, {"Origin": f"http://localhost:{nd.port}"}):
        st, body = _raw(nd, "POST", "/api/notes", {**base, **h}, note)
        assert st == 403, (h, st, body)
    # a real browser page on another origin of this machine (another loopback port) posting into the app. The page
    # comes from a throwaway server the test starts: a page the app serves carries the app's Content-Security-Policy,
    # which would block the POST in the browser before the server could refuse it, and this journey is about the
    # server's refusal. Loopback, because Chrome lets only a page really served from loopback reach loopback.
    evil_srv = _evil_page_server()
    page = ui("desktop")
    page.goto(f"http://127.0.0.1:{evil_srv.server_port}/")
    statuses: list[int] = []
    page.on("response", lambda r: "/api/notes" in r.url and statuses.append(r.status))
    page.evaluate("""([u, body]) => fetch(u, {method: 'POST', mode: 'no-cors', body,
                                              headers: {'Content-Type': 'text/plain'}}).catch(() => null)""",
                  [f"http://127.0.0.1:{nd.port}/api/notes", note])
    nd.wait_for(lambda: statuses, timeout=10, what="the cross-origin POST to be answered")
    evil_srv.shutdown()
    evil_srv.server_close()
    assert statuses == [403], statuses
    notes = nd.get("/api/notes", kind="story", item="story:e2e-art-1")["notes"]
    assert not any(n["body"] == "E2E cross-origin note" for n in notes)
    # the console error the browser logs for the refused request is the point of this journey, not a problem
    page.nd_log["console_errors"] = [e for e in page.nd_log["console_errors"] if "403" not in e]

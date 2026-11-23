"""Notifications (osinthub/notify.py): request shapes per preset, destination checks (with DNS rebinding), the
incident / sensor / digest triggers and their exclusions, delivery (retries, cap, log), offline mode and the API.
Every request goes to a local test HTTP server on 127.0.0.1; nothing leaves the machine.

    uv run --with pytest pytest tests/app/test_notify.py -q
"""
from __future__ import annotations

import datetime as dt
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from _lake import make_lake
LAKE = make_lake("notify", offline=False)

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db, notify  # noqa: E402
from osinthub.netlog import incidents  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
incidents.ensure()
notify.ensure()
try:
    from osinthub.news.common import ensure_schema
    ensure_schema()
except Exception:   # pragma: no cover
    pass

app = FastAPI()
app.include_router(notify.router)
C = TestClient(app)
UTC = dt.UTC
NOW = dt.datetime.now(UTC)
TOKEN = "s3cretTok3n"
DEV, C2, OTHER = "192.0.2.30", "198.51.100.7", "198.51.100.20"


# ---------------------------------------------------------------- the local test server
class Hook:
    def __init__(self):
        self.requests: list[dict] = []
        self.statuses: list[int] = []      # served in order; then 200
        self.delay = 0.0
        hook = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                hook.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                      "body": json.loads(body) if body else None})
                if hook.delay:
                    import time
                    time.sleep(hook.delay)
                code = hook.statuses.pop(0) if hook.statuses else 200
                self.send_response(code)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"


HOOK = Hook()


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for t in ("alerts", "netlog_rules", "notify_seen", "events", "netlog_files"):
        try:
            db.execute(f"DELETE FROM {t}")
        except Exception:
            pass
    for k in (notify.KEY, notify.LOG_KEY, notify.HELD_KEY, notify.DIGEST_KEY):
        db.execute("DELETE FROM settings WHERE key = ?", [k])
    HOOK.requests.clear()
    HOOK.statuses.clear()
    HOOK.delay = 0
    notify._queue.clear()
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(notify, "RETRY_WAITS", ())
    yield


def enable(**kw) -> dict:
    body = {"enabled": True, "preset": "json", "url": HOOK.url("/hook"), "link_base": "http://127.0.0.1:8787", **kw}
    return notify.save(body)


def alert(aid, ts, sev="high", device=DEV, indicator=C2, rule="list_outbound", direction="outbound", category="c2",
          source="feodo_c2", status="new", demo=False, evidence=None, last=None):
    ev = evidence if evidence is not None else {"indicator": {"category": category, "meta": {"malware": "QakBot"}}}
    db.execute("""INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count,
                                      evidence, status, created_at, updated_at, demo)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, now(), now(), ?)""",
               [aid, ts, last or ts, sev, device, indicator, source, rule, direction,
                f"{device} contacted {indicator} (QakBot C2)", json.dumps(ev), status, demo])
    with db._write_lock:
        incidents.regroup(db.cursor())


def sent() -> list[dict]:
    """Run the trigger check and send what it queued."""
    notify.tick()
    notify.drain(sleep=lambda s: None)
    return [r["body"] for r in HOOK.requests]


# ---------------------------------------------------------------- request shapes
MSG = {"trigger": "incident", "title": "High alert: a device contacted a known command-and-control server",
       "severity": "high", "link": "http://127.0.0.1:8787/#network/alerts/nl-1", "message": "Text.", "time": "t"}


def _deliver(preset, path):
    c = {**notify.load(), "preset": preset, "url": HOOK.url(path)}
    r = notify.deliver(c, MSG, waits=())
    assert r["status"] == "sent", r
    return HOOK.requests[-1]


def test_each_preset_sends_its_own_request_shape():
    r = _deliver("ntfy", "/nd-alerts")                  # JSON to the root, with the topic
    assert r["path"] == "/" and r["headers"]["content-type"] == "application/json"
    assert r["body"] == {**r["body"], "topic": "nd-alerts", "title": MSG["title"], "message": "Text.", "priority": 4,
                         "click": MSG["link"], "tags": ["rotating_light"]}
    r = _deliver("gotify", f"/message?token={TOKEN}")    # /message with the token, the link as a click extra
    assert r["path"] == f"/message?token={TOKEN}" and r["body"]["title"] == MSG["title"] and r["body"]["priority"] == 8
    assert r["body"]["extras"]["client::notification"]["click"]["url"] == MSG["link"]
    assert _deliver("gotify", f"/?token={TOKEN}")["path"] == f"/message?token={TOKEN}"   # server root: /message added
    r = _deliver("homeassistant", "/api/webhook/nd-hook")   # flat JSON
    assert r["path"] == "/api/webhook/nd-hook"
    assert r["body"] == {"title": MSG["title"], "message": "Text.", "severity": "high", "link": MSG["link"],
                         "trigger": "incident", "time": "t"}
    b = _deliver("discord", "/api/webhooks/1/tok")["body"]   # an embed, and never a mention
    assert b["username"] == "Night Desk" and b["allowed_mentions"] == {"parse": []}
    assert {k: b["embeds"][0][k] for k in ("title", "url", "description")} == {
        "title": MSG["title"], "url": MSG["link"], "description": "Text."}
    assert _deliver("json", "/hook")["body"] == {"app": "Night Desk", "trigger": "incident", "title": MSG["title"],
                                                 "message": "Text.", "severity": "high", "link": MSG["link"], "time": "t"}


def test_preset_address_shapes_are_checked():
    with pytest.raises(ValueError, match="token"):
        notify.check_url("http://gotify.lan/message", "gotify", False)
    with pytest.raises(ValueError, match="topic"):
        notify.check_url("http://ntfy.lan/", "ntfy", False)
    with pytest.raises(ValueError, match="webhook"):
        notify.check_url("http://ha.lan:8123/api/services", "homeassistant", False)


# ---------------------------------------------------------------- destinations
DESTINATIONS = [  # host -> where it is: this network, the internet, or never (cloud metadata)
    ("127.0.0.1", "local"), ("192.168.1.10", "local"), ("10.1.2.3", "local"), ("ntfy.lan", "local"),
    ("homeassistant.local", "local"), ("nas", "local"), ("fd4e:6400:d35c::5", "local"), ("fe80::1", "local"),
    ("ntfy.example.com", "internet"), ("203.0.113.5", "internet"),
    ("2130706433", "local"), ("0x7f000001", "local"), ("0177.0.0.1", "local"),   # numeric spellings of 127.0.0.1
    ("134744072", "internet"), ("0x08080808", "internet"), ("169.254.169.254", "bad"),
]


def test_destination_kinds_including_numeric_spellings():
    bad = [(h, notify.host_kind(h), k) for h, k in DESTINATIONS if notify.host_kind(h) != k]
    assert not bad, bad


def test_internet_needs_the_opt_in():
    with pytest.raises(ValueError, match="internet"):
        notify.check_url("https://ntfy.example.com/nd", "ntfy", False)
    assert notify.check_url("https://ntfy.example.com/nd", "ntfy", True)["host_kind"] == "internet"
    with pytest.raises(ValueError):
        notify.check_url("http://0.0.0.0/nd", "json", True)
    r = C.put("/api/notify", json={"enabled": True, "preset": "ntfy", "url": "https://ntfy.example.com/nd"})
    assert r.status_code == 400 and "Send to an internet service" in r.json()["detail"]


def test_local_name_rebound_to_the_internet_is_refused(monkeypatch):
    calls = []
    monkeypatch.setattr(notify, "_resolve", lambda h, p: calls.append(h) or ["203.0.113.5"])
    c = {**notify.load(), "preset": "json", "url": f"http://ntfy.lan:{HOOK.port}/hook"}
    r = notify.deliver(c, MSG, waits=())
    assert calls == ["ntfy.lan"] and r["status"] == "blocked" and "internet" in r["detail"]
    assert HOOK.requests == []
    # a mixed answer (one local, one internet address) is refused too
    monkeypatch.setattr(notify, "_resolve", lambda h, p: ["127.0.0.1", "203.0.113.5"])
    assert notify.deliver(c, MSG, waits=())["status"] == "blocked"
    assert HOOK.requests == []


def test_resolved_name_is_pinned_and_keeps_its_host_header(monkeypatch):
    monkeypatch.setattr(notify, "_resolve", lambda h, p: ["127.0.0.1"])
    c = {**notify.load(), "preset": "json", "url": f"http://ntfy.lan:{HOOK.port}/hook"}
    assert notify.deliver(c, MSG, waits=())["status"] == "sent"
    assert HOOK.requests[-1]["headers"]["host"] == f"ntfy.lan:{HOOK.port}"


def test_redirects_are_not_followed():
    HOOK.statuses = [302]
    c = {**notify.load(), "preset": "json", "url": HOOK.url("/hook")}
    r = notify.deliver(c, MSG, waits=())
    assert r["status"] == "failed" and len(HOOK.requests) == 1


# ---------------------------------------------------------------- offline
def test_offline_holds_internet_destinations_without_a_lookup(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", True)
    calls = []
    monkeypatch.setattr(notify, "_resolve", lambda h, p: calls.append(h) or ["203.0.113.5"])
    c = {**notify.load(), "preset": "ntfy", "url": "https://ntfy.example.com/nd", "allow_public": True}
    r = notify.deliver(c, MSG, waits=())
    assert r["status"] == "held" and r["detail"] == "held: offline" and calls == []
    # a local name that resolves to the internet is held too (allowed or not)
    c2 = {**c, "url": "http://ntfy.lan/nd"}
    assert notify.deliver(c2, MSG, waits=())["detail"] == "held: offline"


def test_offline_still_sends_to_local(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", True)
    c = {**notify.load(), "preset": "json", "url": HOOK.url("/hook")}
    assert notify.deliver(c, MSG, waits=())["status"] == "sent"


# ---------------------------------------------------------------- triggers
def test_one_message_per_new_needs_you_incident_and_exclusions():
    enable()
    assert sent() == []                                         # nothing open: nothing sent
    alert("a-real", NOW - dt.timedelta(hours=1))
    alert("a-demo", NOW - dt.timedelta(hours=1), device="10.86.24.5", demo=True)
    alert("a-exp", NOW - dt.timedelta(hours=1), device="192.0.2.31", indicator=OTHER)
    incidents.create_rule({"indicator": OTHER, "note": "the printer's update server"})
    alert("a-ack", NOW - dt.timedelta(hours=1), device="192.0.2.32", indicator="198.51.100.99", status="ack")
    alert("a-med", NOW - dt.timedelta(hours=1), device="192.0.2.33", indicator="198.51.100.98", sev="medium")
    bodies = sent()
    assert len(bodies) == 1
    b = bodies[0]
    assert b["title"] == "High alert: a device contacted a known command-and-control server"
    assert b["link"] == "http://127.0.0.1:8787/#network/alerts/a-real"
    blob = json.dumps(bodies)
    for leak in (DEV, C2, "QakBot", "10.86.24.5"):
        assert leak not in blob
    HOOK.requests.clear()
    assert sent() == []                                         # never twice


def test_medium_minimum_and_severity_rise_renotifies_once():
    enable(min_severity="medium")
    alert("m1", NOW - dt.timedelta(hours=3), sev="medium")
    assert [b["severity"] for b in sent()] == ["medium"]
    HOOK.requests.clear()
    alert("m2", NOW - dt.timedelta(hours=2), sev="high", source="et_compromised")   # same incident, now high
    bodies = sent()
    assert len(bodies) == 1 and bodies[0]["severity"] == "high" and "now high" in bodies[0]["title"]
    HOOK.requests.clear()
    alert("m3", NOW - dt.timedelta(hours=1), sev="medium")
    assert sent() == []


def test_one_incident_across_utc_midnight_is_one_message():
    enable()
    mid = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    alert("d1", mid - dt.timedelta(minutes=30))                 # yesterday 23:30 UTC
    assert len(sent()) == 1
    HOOK.requests.clear()
    alert("d2", mid + dt.timedelta(minutes=30))                 # today 00:30 UTC: a new per-day alert, same incident
    assert db.query("SELECT count(DISTINCT incident) AS n FROM alerts")[0]["n"] == 1
    assert sent() == []


def test_incidents_open_when_turned_on_are_known_not_sent():
    alert("old", NOW - dt.timedelta(hours=5))
    enable()
    assert sent() == []
    alert("new", NOW - dt.timedelta(hours=1), device="192.0.2.40")
    assert len(sent()) == 1


def test_abusech_alerts_get_the_generic_wording():
    enable()
    alert("tf", NOW - dt.timedelta(hours=1), source="threatfox", category="c2")
    b = sent()[0]
    assert b["title"] == "High alert: a device contacted an address on a threat list"


def test_device_names_only_when_opted_in(monkeypatch):
    from osinthub.netlog import api as napi
    monkeypatch.setattr(napi, "_name_alerts", lambda rows: [r.update(device_name="Living room TV") for r in rows])
    enable()
    alert("n1", NOW - dt.timedelta(hours=1))
    assert "Living room TV" not in json.dumps(sent())
    HOOK.requests.clear()
    db.execute("DELETE FROM notify_seen")
    notify.save({"device_names": True})
    db.execute("DELETE FROM notify_seen")
    assert "(Living room TV)" in sent()[0]["title"]


def test_sensor_going_silent_is_sent_once_whatever_the_minimum():
    enable()
    ev = {"kind": "sender_silence", "sender": {"id": "ab12", "name": "Router logs"}, "state": "open"}
    alert("silent:ab12:1", NOW - dt.timedelta(hours=2), sev="medium", device=None, indicator="Router logs",
          rule="sensor_silent", direction=None, source="ingest", evidence=ev)
    bodies = sent()
    assert len(bodies) == 1 and bodies[0]["trigger"] == "sensor"
    assert bodies[0]["title"] == "Medium: a log sender stopped sending logs"
    assert "Router logs" not in json.dumps(bodies)
    HOOK.requests.clear()
    assert sent() == []
    # resolved (low, state resolved): nothing more
    HOOK.requests.clear()
    db.execute("UPDATE alerts SET severity = 'low', evidence = ? WHERE id = 'silent:ab12:1'",
               [json.dumps({**ev, "state": "resolved"})])
    assert sent() == []


def test_sensor_trigger_can_be_turned_off():
    enable(sensor=False)
    ev = {"kind": "sender_silence", "state": "open"}
    alert("silent:x:1", NOW, sev="high", device=None, indicator="Sensor", rule="sensor_silent", direction=None,
          source="ingest", evidence=ev)
    assert sent() == []


def test_disabled_sends_nothing():
    enable()
    notify.save({"enabled": False})
    alert("off", NOW)
    assert sent() == []


# ---------------------------------------------------------------- quiet hours
def test_quiet_hours_hold_then_release_and_fold(monkeypatch):
    enable()
    monkeypatch.setattr(notify, "in_quiet", lambda c, t=None: True)
    for i in range(5):
        alert(f"q{i}", NOW - dt.timedelta(hours=1), device=f"192.0.2.{60 + i}")
    assert sent() == [] and len(notify._held()) == 5
    monkeypatch.setattr(notify, "in_quiet", lambda c, t=None: False)
    bodies = sent()
    assert len(bodies) == 1 and bodies[0]["title"] == "5 alerts came in during quiet hours"
    assert notify._held() == []


def test_in_quiet_across_midnight():
    c = {**notify.load(), "quiet": {"on": True, "start": "22:00", "end": "07:00"}}
    at = lambda h, m=0: dt.datetime.now().astimezone().replace(hour=h, minute=m)   # noqa: E731
    assert notify.in_quiet(c, at(23)) and notify.in_quiet(c, at(6, 59))
    assert not notify.in_quiet(c, at(7)) and not notify.in_quiet(c, at(12))


# ---------------------------------------------------------------- digest
def kev_event(cve, vendor, product, added):
    db.execute("""INSERT INTO events (id, source, kind, category, ts, title, summary, tags, url, stored_at)
                  VALUES (?, 'cisa_kev', 'kev', 'vuln', ?, ?, ?, ?, ?, ?)""",
               [f"cisa_kev:{cve}", added, f"{cve} · {vendor} {product}", f"{vendor} {product} Flaw.",
                [vendor, product], f"https://nvd.nist.gov/vuln/detail/{cve}", added])


LEAKS = ("203.0.113.50", "evil-c2.example", "44d88612fea8a8f36de82e1278abb02f", "CVE-2026-0001", "Acme", "Router",
         DEV, C2, "QakBot", "10.86.24.5", "CVE-2026-0042")


def test_digest_is_counts_under_fixed_names_only(monkeypatch):
    c = enable()
    alert("dg1", NOW - dt.timedelta(hours=2))
    kev_event("CVE-2026-0001", "Acme", "Router", NOW - dt.timedelta(hours=3))
    for sid, title in (("story:x", "Botnet 203.0.113.50 hits routers, evil-c2.example used"),
                       ("story:y", "Sample 44d88612fea8a8f36de82e1278abb02f spreads via CVE-2026-0001")):
        db.execute("""INSERT INTO stories (id, title, first_seen, last_seen, article_count, source_count)
                      VALUES (?, ?, ?, ?, 3, 3)""", [sid, title, NOW - dt.timedelta(hours=4), NOW - dt.timedelta(hours=1)])
    from osinthub.watch import briefing
    real = briefing.touches
    monkeypatch.setattr(briefing, "touches", lambda t, k: {**real(t, k), "count": 1, "items": [   # the briefing's own shape
        {"type": "story", "id": "story:x", "title": "Botnet 203.0.113.50 hits routers, evil-c2.example used",
         "why": "network", "indicator": "203.0.113.50", "devices": 1, "demo": False, "alert": "dg1"}]})
    since = NOW - dt.timedelta(hours=24)
    m1 = notify.digest_message(c, since)
    m2 = notify.digest_message(c, since)
    assert {k: v for k, v in m1.items() if k != "time"} == {k: v for k, v in m2.items() if k != "time"}   # deterministic
    assert m1["title"] == "Night Desk daily summary: 1 needs you, 1 newly exploited"
    assert m1["link"] == "http://127.0.0.1:8787/#watch"
    lines = m1["message"].splitlines()
    assert lines[:4] == ["Alerts that need you: 1 (1 high, 0 medium)", "Newly exploited vulnerabilities: 1",
                         "Touches your network or what you follow: 1", "Big stories: 2"]
    for preset in notify.PRESETS:   # whatever the shape, nothing of an item's text is in the request
        _, _, body = notify.build_request(preset, "http://ntfy.lan/t?token=x" if preset != "discord" else "http://h.lan/api/webhooks/1/t", m1)
        for leak in LEAKS:
            assert leak not in body.decode(), (preset, leak)
    assert briefing.network(since)["needs_you"] == m1["counts"]["needs_you"]


def test_digest_counts_nothing_from_demo_data():
    c = enable()
    # a demo alert naming a KEV CVE, and that CVE in the KEV list: Watch's "touches" item is demo
    alert("demo-kev", NOW - dt.timedelta(hours=2), device="10.86.24.5", indicator="cve-2026-0042", rule="kev_notice",
          direction=None, category="kev", source="cisa_kev", demo=True)
    kev_event("CVE-2026-0042", "Acme", "Cam", NOW - dt.timedelta(days=30))
    from osinthub.watch import briefing
    t = briefing.touches(NOW - dt.timedelta(hours=24), [])
    assert t["items"] and all(i.get("demo") for i in t["items"])          # the briefing does show it (marked demo)
    m = notify.digest_message(c, NOW - dt.timedelta(hours=24))
    assert "Touches your network or what you follow: 0" in m["message"] and "No alerts need you." in m["message"]
    assert m["counts"]["needs_you"] == 0 and m["counts"]["touches"] == 0
    for leak in LEAKS:
        assert leak not in json.dumps(m)


def test_link_hint_warns_about_loopback_links(monkeypatch):
    c = enable(link_base="http://127.0.0.1:8787")
    assert notify.link_hint(c)["loopback"] is True
    assert notify.link_hint({**c, "link_base": "http://localhost:8787"})["loopback"] is True
    assert notify.link_hint({**c, "link_base": "https://desk.lan:8443"})["loopback"] is False
    monkeypatch.setattr(config, "HOST", "0.0.0.0")
    h = notify.link_hint(c)
    assert not h["listening_local_only"] and h["suggestions"][0].endswith(f".local:{config.PORT}")
    monkeypatch.setattr(config, "HOST", "127.0.0.1")
    assert notify.link_hint(c)["listening_local_only"] and notify.link_hint(c)["suggestions"] == []
    d = C.get("/api/notify").json()["config"]
    assert d["link_hint"]["loopback"] is True


def test_test_message_reports_the_link_it_sent():
    enable()
    r = C.post("/api/notify/test", json={"link_base": "https://desk.lan:8443"}).json()
    assert r["link"] == "https://desk.lan:8443/#settings/notifications"
    assert HOOK.requests[-1]["body"]["link"] == r["link"]


def test_digest_goes_once_a_day_at_its_time(monkeypatch):
    c = enable(digest={"on": True, "time": "08:00"})
    loc = dt.datetime.now().astimezone()
    db.set_setting(notify.DIGEST_KEY, (loc - dt.timedelta(days=1)).replace(hour=8, minute=1).isoformat())
    assert notify.digest_due(c, loc.replace(hour=8, minute=30))
    assert not notify.digest_due(c, loc.replace(hour=7, minute=59))
    assert not notify.digest_due(c, loc.replace(hour=20, minute=0))        # more than 6 h late: skipped today
    db.set_setting(notify.DIGEST_KEY, loc.replace(hour=8, minute=1).isoformat())
    assert not notify.digest_due(c, loc.replace(hour=9))                   # already sent today


def test_digest_endpoint_sends_one():
    enable()
    r = C.post("/api/notify/digest").json()
    assert r["result"]["status"] == "sent"
    assert HOOK.requests[-1]["body"]["trigger"] == "digest"


# ---------------------------------------------------------------- delivery
def test_retries_with_backoff_then_succeeds():
    HOOK.statuses = [500, 503]
    waits = []
    c = {**notify.load(), "preset": "json", "url": HOOK.url("/hook")}
    r = notify.deliver(c, MSG, sleep=waits.append, waits=(2, 10))
    assert r["status"] == "sent" and waits == [2, 10] and len(HOOK.requests) == 3


def test_client_error_is_not_retried_and_failure_never_raises():
    HOOK.statuses = [404]
    c = {**notify.load(), "preset": "json", "url": HOOK.url("/hook")}
    r = notify.deliver(c, MSG, sleep=lambda s: None, waits=(2, 10))
    assert r["status"] == "failed" and "404" in r["detail"] and len(HOOK.requests) == 1
    dead = {**c, "url": "http://127.0.0.1:9/hook"}
    r = notify.deliver(dead, MSG, sleep=lambda s: None, waits=(1,))
    assert r["status"] == "failed" and "could not connect" in r["detail"] and "2 tries" in r["detail"]


def test_timeout(monkeypatch):
    monkeypatch.setattr(notify, "TIMEOUT_S", 0.3)
    HOOK.delay = 1.0
    c = {**notify.load(), "preset": "json", "url": HOOK.url("/hook")}
    r = notify.deliver(c, MSG, waits=())
    assert r["status"] == "failed" and r["detail"] == "timed out"


def test_queue_is_capped_and_drops_are_logged():
    for i in range(notify.QUEUE_MAX + 3):
        notify.enqueue({**MSG, "title": f"m{i}"})
    assert notify.queued() == notify.QUEUE_MAX
    assert [e["status"] for e in notify.delivery_log()[:3]] == ["dropped"] * 3


def test_log_keeps_twenty_and_no_secrets():
    enable(preset="gotify", url=HOOK.url(f"/message?token={TOKEN}"))
    for _ in range(notify.LOG_MAX + 4):
        notify.deliver(notify.load(), MSG, waits=())
    lg = notify.delivery_log()
    assert len(lg) == notify.LOG_MAX and set(lg[0]) == {"at", "trigger", "title", "host", "status", "detail"}
    assert TOKEN not in json.dumps(lg)


def test_api_never_echoes_the_url_in_full():
    r = C.put("/api/notify", json={"enabled": True, "preset": "gotify", "url": HOOK.url(f"/message?token={TOKEN}")})
    assert r.status_code == 200
    d = r.json()
    assert TOKEN not in json.dumps(d)
    assert d["config"]["url_set"] and d["config"]["url_masked"] == f"http://127.0.0.1:{HOOK.port}/…"
    # an empty url keeps the saved one
    d = C.put("/api/notify", json={"url": "", "min_severity": "medium"}).json()
    assert d["config"]["url_set"] and notify.load()["url"].endswith(TOKEN)
    t = C.post("/api/notify/test", json={}).json()
    assert t["result"]["status"] == "sent" and TOKEN not in json.dumps(t)
    assert HOOK.requests[-1]["body"]["title"] == "Night Desk test message"


def test_httpx_log_lines_for_our_requests_are_dropped(caplog):
    import logging
    caplog.set_level(logging.INFO, logger="httpx")
    c = {**notify.load(), "preset": "gotify", "url": HOOK.url(f"/message?token={TOKEN}")}
    notify.deliver(c, MSG, waits=())
    assert TOKEN not in caplog.text


def test_enable_needs_an_address_and_times_are_checked():
    with pytest.raises(ValueError, match="address"):
        notify.save({"enabled": True})
    with pytest.raises(ValueError, match="07:30"):
        notify.save({"quiet": {"on": True, "start": "25:00"}})

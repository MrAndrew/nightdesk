"""Settings › Sources over HTTP: About, the first-run "Choose your sources" step (keyed sources never turned on,
"keep" changes nothing, a bad choice is refused), and turning a source on and off starts and stops its task without
ever leaving it "enabled" with no task. Offline, temporary lake, no network, no AI helper.

    uv run --with pytest pytest tests/app/test_sources_api.py -q

Regression (toggles): enable_source was a sync endpoint (run in a worker thread), so asyncio.create_task had no
running loop: a 500 after the enabled flag was already saved. Offline, a started batch task reports status
"offline" (it ran), a stopped one "disabled".
"""
from __future__ import annotations

import datetime as dt
import os
import re
import time

from _lake import make_lake
LAKE = make_lake("shell", disable="news,entities,netlog,ai")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db, feed_terms, scheduler  # noqa: E402
from osinthub.api import app  # noqa: E402
from osinthub.sources import SOURCES  # noqa: E402



@pytest.fixture()
def client():
    with TestClient(app, base_url="http://localhost") as c:   # with: the lifespan runs (toggles need its loop)
        yield c


@pytest.fixture(autouse=True)
def clean():
    db.connect()
    # a brand-new lake each time: no runs, no source state, no choice (the scheduler's own one-time flags are kept)
    db.execute("DELETE FROM runs")
    db.execute("DELETE FROM source_state")
    db.execute("DELETE FROM settings WHERE key = ?", [feed_terms.CHOICE_KEY])
    yield


# ---------------------------------------------------------------- About
def test_about_has_version_lake_offline_and_ai(client):
    a = client.get("/api/settings/about").json()
    assert a["version"] and a["version"] != ""
    assert a["lake"] == os.environ["OSINTHUB_LAKE"]
    assert a["offline"] is True
    assert a["ai"] is None or set(a["ai"]) >= {"configured", "up"}
    assert a["commit"] is None or re.fullmatch(r"[0-9a-f]{7,12}", a["commit"])


# ---------------------------------------------------------------- feed terms and defaults
def test_every_source_has_terms_and_policy_defaults():
    for sid in SOURCES:
        r = feed_terms.row(sid)
        assert r["local_default"] in ("on", "ask")
        assert r["terms"] and "not reviewed" not in r["terms"].lower(), sid
        assert r["gives"], sid
    # docker.md 11.3: on only for verified-permissive or syndication sources
    for sid in ("cisa_kev", "nvd_recent", "feodo_c2", "sslbl", "tor_exits", "security_news", "cisa_advisories"):
        assert feed_terms.row(sid)["local_default"] == "on"
    for sid in ("spamhaus_drop", "dshield_top", "blocklist_de", "cins_army", "et_compromised", "ioda_outages",
                "ris_live", "bluesky_cyber", "ransomware_live"):
        assert feed_terms.row(sid)["local_default"] == "ask", sid
    for sid in ("dshield_top", "ris_live", "ransomware_live"):
        assert feed_terms.row(sid)["badge"] == feed_terms.PERSONAL


def test_new_lake_is_offered_the_step_once(client):
    d = client.get("/api/settings/sources-choice").json()
    assert d["state"] == "pending"
    assert {s["id"] for s in d["sources"]} == {sid for sid, src in SOURCES.items() if not src.withheld}
    on = [s for s in d["sources"] if s["local_default"] == "on"]
    assert on and d["sources"][: len(on)] == on          # open-terms feeds listed first
    assert client.get("/api/settings/sources-choice").json()["state"] == "pending"   # stays until answered


def test_existing_lake_is_not_asked(client):
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=40)
    db.execute("INSERT INTO runs (source, started, finished, ok, items) VALUES ('cisa_kev', ?, ?, true, 1)", [old, old])
    assert client.get("/api/settings/sources-choice").json()["state"] == "not_needed"
    db.execute("DELETE FROM runs")
    assert client.get("/api/settings/sources-choice").json()["state"] == "not_needed"   # decided once


def test_a_hand_toggled_source_means_not_new(client):
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled) VALUES ('cins_army', true)")
    assert feed_terms.state() == "not_needed"


def test_apply_turns_on_exactly_the_ticked_sources(client):
    assert client.get("/api/settings/sources-choice").json()["state"] == "pending"
    want = ["cisa_kev", "tor_exits"]
    r = client.post("/api/settings/sources-choice", json={"enable": want})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "done"
    for s in SOURCES.values():
        if s.unavailable():
            continue
        assert scheduler.is_enabled(s) is (s.id in want), s.id
    # saved explicitly, so a code default can never flip the choice later
    n = db.query("SELECT count(*) AS n FROM source_state WHERE enabled IS NOT NULL")[0]["n"]
    assert n >= len([s for s in SOURCES.values() if not s.unavailable()])
    assert client.get("/api/settings/sources-choice").json()["state"] == "done"
    for s in SOURCES.values():   # leave the lake as it was for the other tests
        if not s.unavailable():
            client.post(f"/api/sources/{s.id}/enable", params={"enabled": str(s.default_enabled).lower()})


def test_keyed_sources_are_never_turned_on(client):
    # (a Routing watch source waiting only for a network to watch is not keyed: its answer is saved, see
    # tests/routing/test_v12_feeds_rpki.py)
    keyed = [s.id for s in SOURCES.values() if s.unavailable() and not feed_terms.waits_for_watch(s)]
    if not keyed:
        pytest.skip("every keyed source has its key in this environment")
    client.post("/api/settings/sources-choice", json={"enable": keyed})
    for sid in keyed:
        assert scheduler.is_enabled(SOURCES[sid]) is False


def test_keep_changes_nothing(client):
    before = {s.id: scheduler.is_enabled(s) for s in SOURCES.values()}
    r = client.post("/api/settings/sources-choice", json={"keep": True})
    assert r.json() == {"state": "done", "changed": []}
    assert {s.id: scheduler.is_enabled(s) for s in SOURCES.values()} == before


@pytest.mark.parametrize("body", [{"enable": "cisa_kev"}, {"enable": [1]}, {"enable": ["nope"]}, {}])
def test_bad_choice_is_refused(client, body):
    assert client.post("/api/settings/sources-choice", json=body).status_code == 400
    assert feed_terms.state() == "pending"


# ---------------------------------------------------------------- turning a source on and off
SID = next(s.id for s in SOURCES.values() if s.mode == "batch" and not s.default_enabled)


def _state(c, sid=SID):
    return next(s for s in c.get("/api/sources").json() if s["id"] == sid)


def _wait(c, status, sid=SID, t=5.0):
    end = time.time() + t
    while time.time() < end:
        if _state(c, sid)["status"] == status:
            return True
        time.sleep(0.05)
    return False


def test_enable_starts_and_disable_stops():
    with TestClient(app, base_url="http://localhost") as c:   # with: the lifespan (and its event loop) runs
        assert _state(c)["enabled"] is False
        for _ in range(2):                                     # enabling twice is harmless
            r = c.post(f"/api/sources/{SID}/enable", params={"enabled": "true"})
            assert r.status_code == 200, r.text
            assert r.json() == {"id": SID, "enabled": True}
            assert SID in scheduler._tasks
            assert _wait(c, "offline")                         # the task ran (offline mode: it reports and ends)
            assert _state(c)["enabled"] is True
        r = c.post(f"/api/sources/{SID}/enable", params={"enabled": "false"})
        assert r.status_code == 200, r.text
        assert SID not in scheduler._tasks
        s = _state(c)
        assert s["enabled"] is False and s["status"] == "disabled"


def test_failed_start_leaves_source_off(monkeypatch):
    with TestClient(app, base_url="http://localhost", raise_server_exceptions=False) as c:
        def boom(src):
            raise RuntimeError("cannot start")
        monkeypatch.setattr(scheduler, "start_source", boom)
        r = c.post(f"/api/sources/{SID}/enable", params={"enabled": "true"})
        assert r.status_code == 500
        s = _state(c)
        assert s["enabled"] is False and s["status"] == "error"
        assert SID not in scheduler._tasks


def test_failed_save_cancels_the_task(monkeypatch):
    with TestClient(app, base_url="http://localhost", raise_server_exceptions=False) as c:
        real = scheduler._set_state

        def flaky(sid, **kw):
            if kw == {"enabled": True}:
                raise OSError("disk full")
            return real(sid, **kw)
        monkeypatch.setattr(scheduler, "_set_state", flaky)
        r = c.post(f"/api/sources/{SID}/enable", params={"enabled": "true"})
        assert r.status_code == 500
        assert SID not in scheduler._tasks                     # the started task was cancelled and dropped
        s = _state(c)
        assert s["enabled"] is False and s["status"] == "error"


def test_toggle_waits_for_the_write_lock_off_the_event_loop():
    """A toggle during a long write (a netlog import or re-hunt holds db._write_lock) waits for the lock in a worker
    thread: other requests keep being served meanwhile (api-audit-r2-004)."""
    import threading

    from osinthub import db
    with TestClient(app, base_url="http://localhost") as c:
        held, release = threading.Event(), threading.Event()

        def hold():
            with db._write_lock:
                held.set()
                release.wait(5)
        threading.Thread(target=hold, daemon=True).start()
        assert held.wait(2)
        res = {}

        def toggle():
            res["r"] = c.post(f"/api/sources/{SID}/enable", params={"enabled": "false"})
        t = threading.Thread(target=toggle)
        t.start()
        try:
            time.sleep(0.3)                          # the toggle is now waiting for the lock
            assert t.is_alive()
            t0 = time.time()
            assert c.get("/api/health").status_code == 200
            assert time.time() - t0 < 0.5            # served meanwhile (was: blocked until the lock was free)
        finally:
            release.set()
            t.join(5)
        assert res["r"].status_code == 200
        s = _state(c)
        assert s["enabled"] is False and s["status"] == "disabled"


def test_unknown_source_is_404():
    with TestClient(app, base_url="http://localhost") as c:
        assert c.post("/api/sources/no-such-source/enable", params={"enabled": "true"}).status_code == 404

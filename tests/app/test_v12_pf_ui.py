"""v1.2 pf-ui: what the server says to the UI about offline mode and the abuse.ch key is plain language; the setting's
name travels only in a `tech` field (the UI's hover title).

    uv run --with pytest pytest tests/app/test_v12_pf_ui.py -q
"""
from __future__ import annotations

from _lake import make_lake
LAKE = make_lake("pfui")   # offline, no abuse.ch key

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.news.common import ensure_schema  # noqa: E402
from osinthub.watch.api import router  # noqa: E402

db.connect()
ensure_schema()
app = FastAPI()
app.include_router(router)
c = TestClient(app)
NAMES = ("OSINTHUB_OFFLINE", "ABUSECH_AUTH_KEY", "CLOUDFLARE_RADAR_TOKEN")
NATIVE = "the environment that starts Night Desk"   # where a key goes on a native run (it never reads .env)
DOCKER = "the .env file in Night Desk's install folder and run the install line again"   # Docker: Compose reads it


def test_setup_checklist_says_it_plainly_and_names_the_setting_on_hover():
    by = {i["id"]: i for i in c.get("/api/setup/status").json()["items"]}
    for i in by.values():
        assert not any(n in i["detail"] for n in NAMES), i
    assert by["feeds"]["detail"].startswith("Offline mode is on") and "OSINTHUB_OFFLINE=1" in by["feeds"]["tech"]
    assert not by["abusech"]["done"] and NATIVE in by["abusech"]["detail"] and "ABUSECH_AUTH_KEY" in by["abusech"]["tech"]
    assert "Night Desk's settings" not in by["abusech"]["detail"]      # round 1 said this; there is no such field


def test_briefing_offline_problem_is_plain():
    from osinthub.watch import briefing
    probs, summ = briefing.health_problems()
    off = [p for p in probs if p["id"] == "offline"]
    assert summ["offline"] and off and not any(n in off[0]["text"] for n in NAMES)


def test_demo_key_reason_is_plain_and_names_the_setting_in_tech():
    from osinthub.netlog import demo
    r = demo._skip_reason("threatfox_c2", "threatfox", 1)
    assert r["cause"] == "key" and not any(n in r["fix"] + r["reason"] for n in NAMES) and NATIVE in r["fix"]
    assert r["tech"] == "The setting is ABUSECH_AUTH_KEY."


def test_abusech_sources_need_a_key_in_plain_words():
    from osinthub.sources import SOURCES
    for sid in ("threatfox", "urlhaus"):
        d = SOURCES[sid].describe()
        assert d["needs_key"] == "ABUSECH_AUTH_KEY"            # the Sources page shows it under Technical details
        assert d["unavailable"] and "ABUSECH_AUTH_KEY" not in d["unavailable"] and "abuse.ch" in d["unavailable"]
        assert NATIVE in d["unavailable"] and ".env" not in d["unavailable"]   # this test runs natively; no hover needed
        assert ".env" not in d["description"]                  # the description is the same on every install
        assert "ABUSECH_AUTH_KEY" not in d["description"]
    radar = SOURCES["cf_radar_bgp"].describe()
    assert radar["needs_key"] == "CLOUDFLARE_RADAR_TOKEN"
    assert "Routing watch" in radar["unavailable"] and "CLOUDFLARE_RADAR_TOKEN" not in radar["unavailable"]
    assert ".env" not in radar["unavailable"]                  # Compose does not pass this token; the in-app field works


def test_key_steps_match_the_install(monkeypatch):
    """Docker Compose reads the install folder's .env when the install line runs; a native run reads only its
    environment, so each install is told the step that works there (round 2 told both to edit .env and restart)."""
    from osinthub.netlog import demo
    from osinthub.sources import SOURCES
    from osinthub.sources.base import key_steps
    monkeypatch.setenv("OSINTHUB_DOCKER", "1")
    assert DOCKER in key_steps() and DOCKER in SOURCES["threatfox"].unavailable()
    assert DOCKER in demo._skip_reason("threatfox_c2", "threatfox", 1)["fix"]
    monkeypatch.setenv("OSINTHUB_DOCKER", "0")
    assert NATIVE in key_steps() and ".env" not in key_steps() and "restart" in key_steps()

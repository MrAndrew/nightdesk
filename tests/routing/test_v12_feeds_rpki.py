"""The RPKI file has no stated terms (`ask` in feed_terms.py), so it is never switched on by itself: a fresh user can
answer for it before any network is watched (first-run box or the Routing watch toggle), and with a network watched
and no answer saved, Routing watch asks (`ask` in GET /api/routing). Radar keeps its token-driven auto-on.
Offline lake, no network; documentation ASNs only.

    uv run --with pytest pytest tests/routing/test_v12_feeds_rpki.py -q
"""
from __future__ import annotations

import os

os.environ.pop("CLOUDFLARE_RADAR_TOKEN", None)
from _lake import make_lake
LAKE = make_lake("feeds-rpki", disable="news,entities,netlog,ai")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db, feed_terms, scheduler  # noqa: E402
from osinthub.api import app  # noqa: E402
from osinthub.routing import api as rapi, watchlist  # noqa: E402
from osinthub.sources import SOURCES  # noqa: E402

C = TestClient(app, base_url="http://localhost")
ORIGIN = {"Origin": "http://localhost"}
RPKI = SOURCES["rpki_roas"]


@pytest.fixture(scope="module", autouse=True)
def _app():
    with C:   # the lifespan: scheduler started (offline), so toggles and sync() have its loop
        yield


@pytest.fixture(autouse=True)
def _fresh():
    watchlist.ALLOW_DOCUMENTATION = True
    rapi.KICK_DELAY_S = 3600
    db.set_setting(watchlist.KEY, [])
    db.execute("DELETE FROM source_state")
    db.execute("DELETE FROM runs")
    db.execute("DELETE FROM settings WHERE key = ?", [feed_terms.CHOICE_KEY])
    watchlist.set_token(None)
    yield


def _box() -> dict:
    return {s["id"]: s for s in C.get("/api/settings/sources-choice").json()["sources"]}


def _watch(*vals) -> dict:
    r = C.put("/api/routing/watchlist", json={"watches": [{"value": v} for v in vals]}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    return r.json()


def _on(d: dict) -> dict:
    return {s["id"]: s["enabled"] for s in d["sources"]}


def _flag():
    return scheduler.state("rpki_roas").get("enabled")


def test_box_offers_rpki_before_any_watch():
    b = _box()["rpki_roas"]
    assert b["local_default"] == "ask" and b["needs"] == "watchlist" and b["enabled"] is False
    assert feed_terms.waits_for_watch(RPKI) is True
    assert feed_terms.waits_for_watch(SOURCES["cf_radar_bgp"]) is False   # needs a key: cannot be chosen yet


def test_box_applied_unticked_then_a_watch_keeps_it_off():
    r = C.post("/api/settings/sources-choice", json={"enable": ["cisa_kev"]}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    assert _flag() is False                          # the answer is saved although nothing is watched yet
    d = _watch("AS64500")
    assert _on(d)["rpki_roas"] is False and d["ask"] == []
    assert not (scheduler._tasks.get("rpki_roas") and not scheduler._tasks["rpki_roas"].done())


def test_box_applied_ticked_then_a_watch_turns_it_on():
    C.post("/api/settings/sources-choice", json={"enable": ["cisa_kev", "rpki_roas"]}, headers=ORIGIN)
    assert _flag() is True and _box()["rpki_roas"]["enabled"] is True
    d = _watch("AS64500")
    assert _on(d)["rpki_roas"] is True and d["ask"] == []


def test_never_answered_then_a_watch_stays_off_and_asks():
    d = _watch("AS64500")
    assert _on(d)["rpki_roas"] is False and _flag() is None
    assert d["ask"] == ["rpki_roas"]
    assert C.get("/api/routing").json()["ask"] == ["rpki_roas"]
    d = C.put("/api/routing/source", json={"id": "rpki_roas", "enabled": False}, headers=ORIGIN).json()
    assert _flag() is False and d["ask"] == [] and _on(d)["rpki_roas"] is False
    assert _watch("AS64500", "AS64501")["ask"] == []    # asked once: the answer stands


def test_answer_yes_turns_it_on():
    _watch("AS64500")
    d = C.put("/api/routing/source", json={"id": "rpki_roas", "enabled": True}, headers=ORIGIN).json()
    assert _flag() is True and _on(d)["rpki_roas"] is True and d["ask"] == []


def test_toggle_before_the_first_watch_is_kept():
    r = C.put("/api/routing/source", json={"id": "rpki_roas", "enabled": True}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["ask"] == [] and _flag() is True
    assert not (scheduler._tasks.get("rpki_roas") and not scheduler._tasks["rpki_roas"].done())   # nothing to check yet
    assert _on(_watch("AS64500"))["rpki_roas"] is True


def test_existing_install_with_rpki_on_stays_on():
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled, status) VALUES ('rpki_roas', true, 'ok')")
    watchlist.save([{"value": "AS64500"}])
    scheduler._apply_default_flips()
    d = C.get("/api/routing").json()
    assert _on(d)["rpki_roas"] is True and d["ask"] == []
    assert _on(_watch("AS64500", "AS64501"))["rpki_roas"] is True


def test_radar_keeps_its_token_driven_auto_on():
    _watch("AS64500")
    r = C.put("/api/routing/settings", json={"radar_token": "testtoken_" + "x" * 30}, headers=ORIGIN)
    assert _on(r.json())["cf_radar_bgp"] is True and r.json()["ask"] == ["rpki_roas"]


def test_bad_source_requests_are_refused():
    assert C.put("/api/routing/source", json={"id": "cisa_kev", "enabled": True}, headers=ORIGIN).status_code == 400
    assert C.put("/api/routing/source", json={"id": "rpki_roas", "enabled": "yes"}, headers=ORIGIN).status_code == 400
    r = C.put("/api/routing/source", json={"id": "cf_radar_bgp", "enabled": True}, headers=ORIGIN)
    assert r.status_code == 409                       # needs the user's token first
    evil = {"Origin": "http://evil.example"}   # the app's CSRF guard covers it like every write
    assert C.put("/api/routing/source", json={"id": "rpki_roas", "enabled": True}, headers=evil).status_code == 403


def _box_ticks() -> list[str]:
    """What web/js/views/settings/sources.js ticks by default: a saved answer as it is, else the policy default."""
    out = []
    for s in _box().values():
        off = bool(s["unavailable"]) and s.get("needs") != "watchlist"
        if (bool(s["enabled"]) and not off) if s["saved"] else (s["local_default"] == "on" and not s["unavailable"]):
            out.append(s["id"])
    return out


def test_a_yes_in_routing_watch_survives_applying_the_box():
    # evaluator round 2, failure 1: Yes first, then "Use the ticked sources" with the box untouched
    _watch("AS64500")
    C.put("/api/routing/source", json={"id": "rpki_roas", "enabled": True}, headers=ORIGIN)
    b = _box()["rpki_roas"]
    assert b["saved"] is True and b["enabled"] is True
    assert "rpki_roas" in _box_ticks()
    C.post("/api/settings/sources-choice", json={"enable": _box_ticks()}, headers=ORIGIN)
    assert _flag() is True


def test_an_upgraded_auto_on_rpki_survives_applying_the_box():
    # a v1.2 lake whose watch auto-switched RPKI on while the box was still pending
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled, status) VALUES ('rpki_roas', true, 'ok')")
    watchlist.save([{"value": "AS64500"}])
    assert "rpki_roas" in _box_ticks()
    C.post("/api/settings/sources-choice", json={"enable": _box_ticks()}, headers=ORIGIN)
    assert _flag() is True


def test_unsaved_ask_sources_start_unticked():
    assert _box()["rpki_roas"]["saved"] is False
    assert "rpki_roas" not in _box_ticks()


def test_a_stale_box_does_not_undo_a_later_yes():
    # final check, failure 1: the box was drawn before the Yes in Routing watch and not reloaded
    stale = _box_ticks()                                   # drawn now: rpki unticked
    assert "rpki_roas" not in stale
    _watch("AS64500")
    C.put("/api/routing/source", json={"id": "rpki_roas", "enabled": True}, headers=ORIGIN)
    r = C.post("/api/settings/sources-choice", json={"enable": stale, "shown": stale}, headers=ORIGIN)
    assert r.status_code == 200 and _flag() is True


def test_a_row_the_user_changes_is_applied_even_over_a_saved_answer():
    C.put("/api/routing/source", json={"id": "rpki_roas", "enabled": True}, headers=ORIGIN)
    shown = _box_ticks()
    assert "rpki_roas" in shown
    enable = [x for x in shown if x != "rpki_roas"]        # the user unticks it in the box
    C.post("/api/settings/sources-choice", json={"enable": enable, "shown": shown}, headers=ORIGIN)
    assert _flag() is False


def test_a_source_switched_off_by_hand_stays_off_when_its_row_is_untouched():
    # final check, failure 2 (also in v1.2): the News outlets row is drawn ticked from the policy, so applying the
    # box turned a hand-switched-off outlet back on. Same rule for every row: untouched and saved means kept.
    # (This lake has no news outlets registered; cisa_kev, also an `on` source drawn ticked, takes the same path.)
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled, status) VALUES ('cisa_kev', false, 'disabled')")
    shown = sorted(set(_box_ticks()) | {"cisa_kev"})       # drawn ticked as the outlets row is
    C.post("/api/settings/sources-choice", json={"enable": shown, "shown": shown}, headers=ORIGIN)
    assert scheduler.state("cisa_kev").get("enabled") is False


def test_shown_must_be_a_list_of_ids():
    r = C.post("/api/settings/sources-choice", json={"enable": [], "shown": "x"}, headers=ORIGIN)
    assert r.status_code == 400

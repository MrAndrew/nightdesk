"""Feed defaults follow their terms (pre-alpha terms review, okf/project/pre-alpha-release.md): a source is on in code
only when feed_terms.py says `on`; the five `ask` sources that used to be on stay on for an existing install that
already answered (or was never offered) the "Choose your sources" step, and start off on a new one; no abuse.ch source
reaches the AI. Offline, temporary lake, no network, no AI helper.

    uv run --with pytest pytest tests/sources/test_v12_feeds.py -q
"""
from __future__ import annotations

import datetime as dt

from _lake import make_lake
LAKE = make_lake("feeds", disable="news,entities,netlog,ai")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import osinthub.news.sources  # noqa: E402,F401  (registers the news outlets: every registered source is checked)
from osinthub import db, feed_terms, scheduler  # noqa: E402
from osinthub.news import brief  # noqa: E402
from osinthub.routing import api as routing_api  # noqa: E402
from osinthub.sources import SOURCES  # noqa: E402

FIVE = ("spamhaus_drop", "dshield_top", "blocklist_de", "et_compromised", "ioda_outages")

# Sources a feature switches on by itself once it can run. They are off in code and `ask` in the box; the feature's
# own page is where the user opts in, and a flag the user saved is never overridden (osinthub/routing/api.py sync()).
AUTO_SWITCHED = {
    "cf_radar_bgp": "Routing watch: on once the user saved their own Cloudflare token and watches a network, unless "
                    "they turned it off (the token is a deliberate act tied to this source)",
}
# rpki_roas is never switched on by itself: Routing watch asks (routing/api.py ASK_FIRST, tests/routing/test_v12_feeds_rpki.py)


# ---------------------------------------------------------------- the code default follows the terms
def test_every_source_on_in_code_has_terms_that_say_on():
    assert len(SOURCES) >= 32
    wrong = [sid for sid, s in SOURCES.items() if s.default_enabled and feed_terms.row(sid)["local_default"] != "on"]
    assert not wrong, f"on in code but `ask` in feed_terms.py: {wrong}"


def test_the_five_ask_sources_are_off_in_code():
    for sid in FIVE:
        assert SOURCES[sid].default_enabled is False, sid
        assert feed_terms.row(sid)["local_default"] == "ask", sid


def test_auto_switched_sources_are_listed_with_a_reason():
    assert set(routing_api.AUTO_ON) <= set(AUTO_SWITCHED), "a new auto-on source: list it here with its reason"
    assert "rpki_roas" not in routing_api.AUTO_ON and "rpki_roas" in routing_api.ASK_FIRST
    for sid in [*AUTO_SWITCHED, *routing_api.ASK_FIRST]:
        assert SOURCES[sid].default_enabled is False, sid
        assert feed_terms.row(sid)["local_default"] == "ask", sid


def test_rpki_has_no_stated_terms_so_it_is_ask():
    r = feed_terms.row("rpki_roas")
    assert r["local_default"] == "ask" and r["licence"] == "No terms stated"


# ---------------------------------------------------------------- abuse.ch stays out of the AI
def test_no_abusech_source_feeds_the_ai():
    ab = {sid for sid, s in SOURCES.items()
          if "abuse.ch" in (s.provider or "").lower() or "abuse.ch" in (s.homepage or "").lower()}
    assert ab >= {"feodo_c2", "sslbl", "threatfox", "urlhaus"}
    assert [sid for sid in ab if SOURCES[sid].ai_ok] == []
    assert ab <= brief.ai_excluded_sources()


# ---------------------------------------------------------------- existing installs
def _fresh():
    db.connect()
    db.execute("DELETE FROM runs")
    db.execute("DELETE FROM source_state")
    db.execute("DELETE FROM settings WHERE key IN (?, ?)", [feed_terms.CHOICE_KEY, "sources.default_flips"])


def _ran_before(days_ago: int = 40, flags: dict | None = None):
    """A lake an older version ran: a run, and a status row for every source (start_all writes one each start)."""
    t = dt.datetime.now(dt.UTC) - dt.timedelta(days=days_ago)
    db.execute("INSERT INTO runs (source, started, finished, ok, items) VALUES ('cisa_kev', ?, ?, true, 1)", [t, t])
    for sid in SOURCES:
        db.execute("INSERT OR REPLACE INTO source_state (id, enabled, status) VALUES (?, ?, 'ok')",
                   [sid, (flags or {}).get(sid)])


def _choice(state: str, how: str | None = None):
    db.set_setting(feed_terms.CHOICE_KEY, {"state": state, **({"how": how} if how else {}), "at": "2026-11-10T00:00:00Z"})


def _on() -> dict:
    return {sid: scheduler.is_enabled(SOURCES[sid]) for sid in FIVE}


def test_new_install_starts_with_the_five_off():
    _fresh()
    scheduler._apply_default_flips()
    assert _on() == dict.fromkeys(FIVE, False)
    assert all(scheduler.state(sid).get("enabled") is None for sid in FIVE)
    # the step is still to come: the tag is spent, so answering it later never pins them on
    _ran_before(days_ago=1)
    _choice("done", "kept")
    scheduler._apply_default_flips()
    assert _on() == dict.fromkeys(FIVE, False)


def test_kept_install_keeps_them_on():
    _fresh()
    _ran_before()
    _choice("done", "kept")   # "Keep" saved no flags: the five ran on the old code default
    scheduler._apply_default_flips()
    assert _on() == dict.fromkeys(FIVE, True)
    assert all(scheduler.state(sid)["enabled"] is True for sid in FIVE)   # saved, so it survives restarts
    assert scheduler.state("cins_army").get("enabled") is None              # other sources untouched


def test_kept_install_keeps_a_hand_choice():
    _fresh()
    _ran_before(flags={"dshield_top": False, "ioda_outages": True})
    _choice("done", "kept")
    scheduler._apply_default_flips()
    assert _on() == {**dict.fromkeys(FIVE, True), "dshield_top": False}


def test_applied_install_is_unchanged():
    _fresh()
    flags = {sid: sid in ("cisa_kev", "spamhaus_drop") for sid in SOURCES}   # "Apply" saves a flag for every source
    _ran_before(flags=flags)
    _choice("done", "applied")
    scheduler._apply_default_flips()
    assert _on() == {sid: sid == "spamhaus_drop" for sid in FIVE}


def test_install_never_asked_keeps_them_on():
    _fresh()
    _ran_before(days_ago=40)   # an older lake: the step was never offered, no choice saved
    scheduler._apply_default_flips()
    assert _on() == dict.fromkeys(FIVE, True)


def test_install_waiting_for_its_answer_is_not_pinned():
    _fresh()
    _ran_before(days_ago=1)
    _choice("pending")
    scheduler._apply_default_flips()
    assert _on() == dict.fromkeys(FIVE, False)   # the box (five unticked) decides; nothing is fetched before it


def test_young_lake_with_no_saved_choice_is_not_pinned():
    _fresh()
    _ran_before(days_ago=1)   # new enough to be offered the step: peek() says pending
    scheduler._apply_default_flips()
    assert _on() == dict.fromkeys(FIVE, False)
    assert db.get_setting(feed_terms.CHOICE_KEY, None) is None   # the start-up check decides nothing for the step


def test_migration_runs_once():
    _fresh()
    _ran_before()
    _choice("done", "kept")
    scheduler._apply_default_flips()
    db.execute("UPDATE source_state SET enabled = NULL WHERE id = 'blocklist_de'")   # as if never set
    scheduler._apply_default_flips()
    assert scheduler.is_enabled(SOURCES["blocklist_de"]) is False


# ---------------------------------------------------------------- a new install over HTTP
@pytest.fixture()
def client():
    from osinthub.api import app
    _fresh()   # before the lifespan: start_all sees a brand-new lake
    with TestClient(app, base_url="http://localhost") as c:   # the lifespan runs start_all
        yield c


def test_fresh_install_offers_the_five_unticked_and_does_not_start_them(client):
    d = client.get("/api/settings/sources-choice").json()
    assert d["state"] == "pending"
    rows = {s["id"]: s for s in d["sources"]}
    for sid in FIVE:
        assert rows[sid]["local_default"] == "ask" and rows[sid]["enabled"] is False, sid
    for sid in FIVE:
        t = scheduler._tasks.get(sid)
        assert t is None or t.done(), sid
        assert scheduler.state(sid)["status"] == "disabled", sid
    assert db.query(f"SELECT count(*) AS n FROM runs WHERE source IN {FIVE}")[0]["n"] == 0

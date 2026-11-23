"""Demo data on an empty lake says plainly what it could not plant and why, and names the alert to land on.

    uv run --with pytest pytest tests/netlog/test_demo_empty_lake.py -q
"""
from __future__ import annotations


from _lake import make_lake
LAKE = make_lake("demo-states")

import pytest  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.netlog import demo  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)


@pytest.fixture(scope="module")
def loaded():
    # CINS Army: turned off by the user. Spamhaus DROP: on, but never downloaded (offline).
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled, status) VALUES ('cins_army', false, 'disabled')")
    # turned on by the user (off in code since the terms review)
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled) VALUES ('spamhaus_drop', true)")
    res = demo.load(seed=7)
    yield res
    if demo.state():
        demo.unload()


def test_empty_lake_plants_only_the_ids_alert(loaded):
    assert [s["id"] for s in loaded["scenarios"]] == ["suricata_alert"]
    assert loaded["total"] == 1 and loaded["possible"] == len(demo.SCENARIOS) == 15


def test_every_left_out_scenario_says_why_and_how_to_fix(loaded):
    sk = {s["id"]: s for s in loaded["skipped"]}
    assert set(sk) == set(demo.SCENARIOS) - {"suricata_alert"}
    for s in sk.values():
        assert s["reason"] and s["fix"] and s["title"]
    assert sk["cins_inbound"]["reason"] == "CINS Army bad actors is off."
    assert "Turn it on in Sources" in sk["cins_inbound"]["fix"] and sk["cins_inbound"]["action"] == "sources"
    assert "offline" in sk["drop_cidr"]["reason"]
    assert sk["reported_ip"]["action"] == "news"
    assert sk["historical"]["action"] == "wait"
    # the retro match needs the botnet controller: it gives that list's reason, not a made-up one
    assert sk["feodo_retro"]["cause"] == sk["feodo_c2"]["cause"] == "offline"
    assert sk["drop_cidr"]["cause"] == "offline" and sk["cins_inbound"]["cause"] == "off"


def test_lands_on_the_planted_alert(loaded):
    s = loaded["scenarios"][0]
    assert loaded["top_alert"] == s["alert"]["id"]


def test_verify_keeps_the_skipped_list(loaded):
    v = demo.verify()
    assert v["skipped"] == loaded["skipped"] and v["top_alert"] == loaded["top_alert"]


def test_key_reason_names_the_abusech_key(monkeypatch):
    from osinthub.sources import SOURCES
    tf = SOURCES["threatfox"]
    r = demo._skip_reason("x", "threatfox", 1)
    if tf.unavailable():
        assert "abuse.ch key" in r["reason"] and r["action"] == "key"

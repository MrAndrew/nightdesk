"""Help desk backend: sources and terms, redacted diagnostics, the local docs (never a file outside the bundle). The
Help content's integrity (glossary, links, documented shortcuts) is a client lint rule: tests/web/test_client_lint.py.

    uv run --with pytest pytest tests/app/test_help.py -q
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("help")
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.help import api as help_api  # noqa: E402
from osinthub.help.api import redact, router  # noqa: E402

db.connect()
try:
    from osinthub.netlog.devices import AGG_SQL
    from osinthub.netlog.schema import SCHEMA_SQL
    db.cursor().execute(SCHEMA_SQL + AGG_SQL)
except Exception:   # pragma: no cover
    pass

app = FastAPI()
app.include_router(router)
c = TestClient(app)

WEB = ROOT / "web" / "js"


# ------------------------------------------------------------------ redaction
@pytest.mark.parametrize("raw", [
    "seen 192.0.2.17 and 198.51.100.0/24", "v6 2001:db8::1 and 2001:db8:0:0:0:0:0:5/64 and fd4e:6400:d35c::12",
    "mac 00:00:5e:00:53:1a or 00-00-5E-00-53-1B", "ABUSECH_AUTH_KEY=abc123secret token: zzz password=hunter2",
    "tok 3f9a1c0e7b2d4a6f8e1c3b5d7f9a2c4e6b8d0f1a3c5e7b9d", "mapped ::ffff:192.0.2.1 here", "Authorization: Bearer abcdef12345",
])
def test_redact_removes_addresses_and_secrets(raw):
    out = redact(raw)
    for bad in ("192.0.2.17", "198.51.100.0", "2001:db8", "fd4e:6400", "00:00:5e", "00-00-5E", "abc123secret",
                "zzz", "hunter2", "3f9a1c0e7b2d", "192.0.2.1", ".0.2.1", "abcdef12345"):
        assert bad not in out, (raw, out)


def test_redact_keeps_times_versions_and_words():
    s = "at 22:03:05 UTC, version 1.2.3, DuckDB 2.0.0, Python 3.14.7, std::vector, 26 of 29 feeds"
    assert redact(s) == s


def test_redact_home_folder_becomes_tilde():
    assert redact(str(Path.home() / "lake")) == "~/lake"


# ------------------------------------------------------------------ sources and terms
def test_sources_lists_every_registry_source_with_terms_and_tier():
    from osinthub.sources import SOURCES
    d = c.get("/api/help/sources").json()
    ids = {s["id"] for s in d["sources"]}
    assert ids == set(SOURCES)
    for s in d["sources"]:
        assert s["gives"] and s["terms"] and s["terms"] != "Terms not reviewed yet.", s["id"]
        assert isinstance(s["enabled"], bool)
    by = {s["id"]: s for s in d["sources"]}
    assert by["cisa_kev"]["tier"] == "A" and by["epss"]["tier"] == "B" and "FIRST" in by["epss"]["terms"]
    assert by["threatfox"]["unavailable"] or by["threatfox"]["needs_key"]
    assert d["reference"] and all(r["licence"] and r["terms"] for r in d["reference"])
    assert d["offline"] is True
    assert "not-for-profit" in by["threatfox"]["terms_more"] and by["cisa_kev"]["terms_more"] is None


def test_sources_does_not_decide_the_first_run_choice():
    db.execute("DELETE FROM settings WHERE key = 'settings.sources_choice'")
    c.get("/api/help/sources")
    assert db.get_setting("settings.sources_choice", None) is None   # opening Help changes nothing


# ------------------------------------------------------------------ diagnostics
def test_diagnostics_has_the_facts_and_nothing_private():
    from osinthub.netlog import util as nutil
    db.set_setting(nutil.SETTINGS_KEY, {**(db.get_setting(nutil.SETTINGS_KEY) or {}),
                                        "home_prefixes": ["192.0.2.0/24", "2001:db8:5:6::/64"]})
    try:
        db.execute("""INSERT INTO devices (id, mac, name) VALUES ('mac:00:00:5e:00:53:1a', '00:00:5e:00:53:1a', 'kitchen-tablet')""")
    except Exception:
        pass
    help_api._SIZE_CACHE.clear()
    r = c.get("/api/help/diagnostics")
    assert r.status_code == 200
    d = r.json()
    assert d["app"]["version"] and d["app"]["offline"] is True
    assert {"lake", "feeds", "network_logs", "ai_helper", "extensions", "system"} <= set(d)
    assert d["network_logs"].get("home_prefixes_set") == 2          # a count, never the prefixes
    text = json.dumps(d)
    for bad in ("192.0.2", "2001:db8", "00:00:5e", "kitchen-tablet", str(Path.home())):
        assert bad not in text, bad
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)


# ------------------------------------------------------------------ local docs
def test_docs_list_and_page():
    d = c.get("/api/help/docs").json()
    assert d["available"] and any(x["path"] == "project/overview.md" for x in d["docs"])
    assert not any(x["path"] == "log.md" for x in d["docs"])
    p = c.get("/api/help/docs/architecture/help.md").json()
    assert p["title"] and "Help desk" in p["markdown"] and not p["markdown"].startswith("---")
    assert not any("Vantage" in x["title"] for x in d["docs"])


@pytest.mark.parametrize("bad", ["../pyproject.toml", "../README.md", "..%2F..%2Fetc%2Fpasswd.md", "project/overview.txt",
                                 "/etc/passwd", "project/../../osinthub/config.md", "nope.md"])
def test_docs_refuse_anything_outside_the_bundle(bad):
    assert c.get(f"/api/help/docs/{bad}").status_code == 404

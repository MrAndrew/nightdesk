"""Settings › About › Copy diagnostics (osinthub/diagnostics.py): useful facts, nothing about the user.

    uv run --with pytest pytest tests/app/test_diagnostics.py -q
"""
from __future__ import annotations

from _lake import make_lake
LAKE = make_lake("diagnostics", ABUSECH_AUTH_KEY="k3y-of-the-user-0123456789")

from pathlib import Path  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db, diagnostics  # noqa: E402
from osinthub.api import app  # noqa: E402

db.connect()
C = TestClient(app, base_url="http://localhost")


def test_scrub_removes_what_identifies_the_user():
    home = str(Path.home())
    text = "\n".join([
        f"open {config.LAKE}/db/hub.duckdb failed",
        f"see {home}/Projects/nd/server.log",
        "device 192.168.1.23 and 10.0.0.0/8, router fe80::1c2b:3cff:fe4d:5e6f, prefix 2001:db8:abcd::/48",
        "MAC a4:83:e7:12:34:56 and 00-1B-63-84-45-E6",
        "nas.lan, printer.local, router.home.arpa, laptop.internal",
        "GET https://threatfox-api.abuse.ch/api/v1/?query=x&auth_key=abcdef",
        "Auth-Key: k3y-of-the-user-0123456789 then token=s3cr3t and Bearer eyJhbGciOiJIUzI1NiJ9abcdefghijklmnopqrstu",
    ])
    out = diagnostics.scrub(text)
    for leak in (str(config.LAKE), home, "192.168.1.23", "10.0.0.0", "fe80::1c2b", "2001:db8:abcd", "a4:83:e7",
                 "00-1B-63", "nas.lan", "printer.local", "router.home.arpa", "laptop.internal", "auth_key=abcdef",
                 "k3y-of-the-user", "s3cr3t", "eyJhbGci"):
        assert leak not in out, (leak, out)
    assert "<db>/hub.duckdb" in out and "~/Projects/nd/server.log" in out   # the database folder is the longer match
    assert "<ip>" in out and "<mac>" in out and "<host>" in out and "<secret>" in out
    assert "https://threatfox-api.abuse.ch/api/v1/?…" in out          # the public host stays, its query goes


def test_scrub_keeps_ordinary_text():
    text = "cisa_kev: HTTP 503 from www.cisa.gov after 3 tries; version 0.1.0; 12:30:45 UTC; Python 3.14.0"
    assert diagnostics.scrub(text) == text


def test_the_machine_name_is_removed(monkeypatch):
    monkeypatch.setattr(diagnostics.socket, "gethostname", lambda: "Alices-MacBook-Pro.local")
    monkeypatch.setattr(diagnostics.platform, "node", lambda: "Alices-MacBook-Pro")
    out = diagnostics.scrub("helper on Alices-MacBook-Pro failed; Alices-MacBook-Pro.local unreachable")
    assert "Alices" not in out


def test_report_has_the_useful_parts_and_no_paths():
    r = C.get("/api/settings/diagnostics")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert r.headers.get("cache-control") == "no-store"
    t = r.text
    for part in ("Night Desk diagnostics", "Version:", "Installed:", "Machine:", "Switches:", "Sources:", "Local AI:",
                 "Extensions:", "Data:"):
        assert part in t, part
    assert str(config.LAKE) not in t and str(Path.home()) not in t
    assert "k3y-of-the-user" not in t

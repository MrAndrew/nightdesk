"""v1.2 harden (L5): write responses carry no absolute path (lake or home folder).

The lake sits under a temporary folder standing in for the home folder, like a default `./lake` started from
~/Projects/nd. Uploads, log imports (single file and bundle), an inbox scan and the demo load are made through
the app, and every write response is scanned for the lake, home and repo paths. GET routes for settings, about
and paths keep their absolute paths (they serve the loopback UI).

    uv run --with pytest pytest tests/netlog/test_v12_harden.py -q
"""
from __future__ import annotations

import atexit
import io
import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path

FAKE_HOME = Path(os.path.realpath(tempfile.mkdtemp(prefix="nd-test-harden-home-")))
atexit.register(shutil.rmtree, FAKE_HOME, ignore_errors=True)
LAKE = FAKE_HOME / "Projects" / "nd" / "lake"
LAKE.mkdir(parents=True)

from _lake import make_lake  # noqa: E402
make_lake("harden-paths", disable="news,entities,ai", HOME=str(FAKE_HOME), OSINTHUB_LAKE=str(LAKE))

from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
import osinthub.api as A  # noqa: E402
from osinthub.netlog import importer  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

assert config.LAKE == LAKE
db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL + importer.LEDGER_SQL)
C = TestClient(A.app, base_url="http://localhost")
H = {"Origin": "http://localhost"}
PATHS = {str(FAKE_HOME), str(LAKE), str(config.ROOT)}
PATHS |= {p.replace("/private/var/", "/var/", 1) for p in PATHS if p.startswith("/private/var/")}


def _conn(n=3, base=1):
    return "".join(json.dumps({"ts": 1763550000.0 + i, "uid": f"C{base}{i}", "id.orig_h": "10.86.24.15", "id.orig_p": 50000 + i,
                               "id.resp_h": f"203.0.113.{base + i}", "id.resp_p": 443, "proto": "tcp", "conn_state": "SF",
                               "orig_bytes": 100, "resp_bytes": 200}) + "\n" for i in range(n)).encode()


def leaks(text: str) -> list[str]:
    return [p for p in PATHS if p in text]


def test_netlog_import_returns_lake_relative_path():
    r = C.post("/api/netlog/import", files=[("files", ("conn.log", io.BytesIO(_conn()), "application/json"))], headers=H)
    assert r.status_code == 200, r.text
    f = r.json()["files"][0]
    assert f.get("inserted") == 3, f
    assert f["path"].startswith("raw/netlog/") and not f["path"].startswith("/")
    assert (config.LAKE / f["path"]).exists()
    assert leaks(r.text) == []


def test_netlog_bundle_import_has_no_absolute_path():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for i, name in enumerate(("conn.1.log", "conn.2.log")):
            data = _conn(2, 50 + 10 * i)
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    r = C.post("/api/netlog/import", files=[("files", ("logs.tar.gz", io.BytesIO(buf.getvalue()), "application/gzip"))], headers=H)
    assert r.status_code == 200, r.text
    members = r.json()["files"][0]["members"]
    assert len(members) == 2 and all(m["path"].startswith("raw/netlog/") for m in members)
    assert leaks(r.text) == []


def test_inbox_scan_has_no_absolute_path():
    inbox = config.LAKE / "inbox" / "zeek"
    inbox.mkdir(parents=True, exist_ok=True)
    p = inbox / "conn.2026-11-19.log"
    p.write_bytes(_conn(2, 90))
    os.utime(p, (1, 1))                            # old enough: not "still being written"
    r = C.post("/api/netlog/inbox/scan", headers=H)
    assert r.status_code == 200, r.text
    assert any(f.get("inserted") for f in r.json()["files"]), r.text
    assert leaks(r.text) == []


def test_upload_and_demo_have_no_absolute_path():
    r = C.post("/api/upload", files={"file": ("iocs.csv", io.BytesIO(b"ip,title\n192.0.2.7,x\n"), "text/csv")},
               data={"label": "mine"}, headers=H)
    assert r.status_code == 200 and r.json()["file"].startswith("uploads/") and leaks(r.text) == []
    r = C.post("/api/netlog/demo", headers=H)
    assert r.status_code == 200, r.text
    assert leaks(r.text) == []


def test_settings_gets_keep_their_absolute_paths():
    about = C.get("/api/settings/about").json()
    assert about["lake"] == str(LAKE)        # loopback UI shows where the data lives
    assert C.get("/api/paths").json()["lake"] == str(LAKE)

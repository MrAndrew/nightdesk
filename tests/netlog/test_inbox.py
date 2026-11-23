"""v1.2 f-inbox: the ingestion folder is a setting, and files are kept after import unless the user turns deleting on.

    uv run --with pytest pytest tests/netlog/test_inbox.py -q
"""
import gzip
import json
import os
import shutil
import tempfile
import time
from pathlib import Path

for k in ("OSINTHUB_INBOX", "OSINTHUB_DOCKER", "OSINTHUB_LAKE_HOST"):
    os.environ.pop(k, None)
from _lake import make_lake  # noqa: E402
LAKE = make_lake("f-inbox", disable="news,entities,ai")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.api import app  # noqa: E402
from osinthub.netlog import importer, ingest, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL + importer.LEDGER_SQL)
C = TestClient(app, base_url="http://localhost")
ORIGIN = {"Origin": "http://localhost"}
SCRATCH = Path(os.path.realpath(tempfile.mkdtemp(prefix="f-inbox-folders-")))
BROKEN = b'{"ts": 1, "looks like json" \n'   # a log by its first byte that does not parse: it fails to import
OLD = time.time() - 600   # settled even for delete on (2 minutes)
_n = 0


def _rec(uid: str, resp: str = "198.51.100.7") -> dict:
    return {"ts": 981173106.5, "uid": uid, "id.orig_h": "192.0.2.13", "id.orig_p": 5000,
            "id.resp_h": resp, "id.resp_p": 443, "proto": "tcp"}


def _drop(folder: Path, name: str, body: bytes | None = None) -> Path:
    """A settled log file (mtime two minutes ago) with a unique row."""
    global _n
    _n += 1
    p = folder / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body if body is not None else json.dumps(_rec(f"Cfinbox{_n}")).encode())
    os.utime(p, (OLD, OLD))
    return p


def _tree(folder: Path) -> dict[str, bytes]:
    return {str(p.relative_to(folder)): (p.read_bytes() if p.is_file() else b"<dir>")
            for p in sorted(folder.rglob("*"))}


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("OSINTHUB_INBOX", raising=False)
    monkeypatch.setenv("OSINTHUB_DOCKER", "0")
    db.set_setting(util.INBOX_KEY, {})
    db.execute("DELETE FROM netlog_inbox_seen")
    importer._stopped.clear()
    shutil.rmtree(util.default_inbox(), ignore_errors=True)
    util.default_inbox().mkdir(parents=True)
    yield


@pytest.fixture
def calls(monkeypatch):
    """Counts inbox imports (each one reads and hashes the whole file)."""
    seen = []
    real = importer.import_inbox_file

    def counting(fh, name):
        seen.append(name)
        return real(fh, name)
    monkeypatch.setattr(importer, "import_inbox_file", counting)
    return seen


def _folder(name: str) -> Path:
    d = SCRATCH / name
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    return d


# ---------------------------------------------------------------- settings
def test_default_folder_and_delete_off():
    s = util.inbox_settings()
    assert s["path"] == str(config.LAKE / "inbox" / "zeek") == s["default_path"]
    assert s["from_env"] is False and s["delete_after_import"] is False
    g = C.get("/api/netlog/inbox").json()
    assert {"path", "default_path", "from_env", "delete_after_import", "waiting", "imported", "failed"} <= set(g)
    assert g["path"] == s["path"] and g["delete_after_import"] is False and g["failed"] == []


def test_existing_lake_settings_without_the_key_keep_files():
    db.set_setting(util.SETTINGS_KEY, {"inbox_poll_seconds": 30})   # a lake saved by v1.2 before this setting
    assert util.inbox_settings()["delete_after_import"] is False


def test_env_overrides_and_is_read_only(monkeypatch):
    d = _folder("env")
    monkeypatch.setenv("OSINTHUB_INBOX", str(d))
    g = C.get("/api/netlog/inbox").json()
    assert g["path"] == str(d) and g["from_env"] is True
    r = C.put("/api/netlog/inbox", json={"path": str(_folder("other"))}, headers=ORIGIN)
    assert r.status_code == 409 and "OSINTHUB_INBOX" in r.json()["detail"]
    assert C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN).status_code == 200
    _drop(d, "conn.log")
    assert [r.get("inserted") for r in importer.scan_inbox()] == [1]
    assert not (d / "conn.log").exists()                       # the toggle still applies to the env folder


# Folders the inbox never takes: saving one is a 400 that saves nothing, checking one says why.
BAD_VALUES = [("", "full path"), ("relative/logs", "full path"), ("/", "top of the disk"), (None, "full path"),
              (7, "full path"), ("/no/such/folder/f-inbox", "no folder")]
HOME_AND_SYSTEM = [("~", "home folder")] + [(p, "system folder") for p in (
    "/Users", "/Volumes", "/etc", "/System/Library", "/private", "/usr", "/Applications", "/Library", "/opt", "/bin")]


def test_refused_folders_say_why_and_save_nothing():
    for bad, words in BAD_VALUES:
        r = C.put("/api/netlog/inbox", json={"path": bad}, headers=ORIGIN)
        assert r.status_code == 400 and words in r.json()["detail"], (bad, r.json())
    for where, words in HOME_AND_SYSTEM:
        r = C.get("/api/netlog/inbox/check", params={"path": where}).json()
        assert r["ok"] is False and (words in r["error"] or "no folder" in r["error"]), (where, r)
        assert C.put("/api/netlog/inbox", json={"path": where}, headers=ORIGIN).status_code == 400, where
    assert C.put("/api/netlog/inbox", json={"delete_after_import": "yes"}, headers=ORIGIN).status_code == 400
    assert util.inbox_settings()["path"] == util.inbox_settings()["default_path"]
    assert util.inbox_settings()["delete_after_import"] is False


def test_validation_refuses_the_lakes_own_folders_and_files():
    (config.RAW_DIR / "netlog").mkdir(parents=True, exist_ok=True)
    for p, words in ((config.RAW_DIR, "own data"), (config.RAW_DIR / "netlog", "own data"), (config.TMP_DIR, "own data"),
                     (config.DB_PATH.parent, "own data"), (config.LAKE, "own data")):
        r = C.put("/api/netlog/inbox", json={"path": str(p)}, headers=ORIGIN)
        assert r.status_code == 400 and words in r.json()["detail"], (p, r.json())
    f = _drop(_folder("afile"), "x.log")
    r = C.put("/api/netlog/inbox", json={"path": str(f)}, headers=ORIGIN)
    assert r.status_code == 400 and "not a folder" in r.json()["detail"]


def test_unreadable_folder_is_refused():
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    d = _folder("locked")
    d.chmod(0)
    try:
        r = C.put("/api/netlog/inbox", json={"path": str(d)}, headers=ORIGIN)
        assert r.status_code == 400 and "not allowed to read" in r.json()["detail"]
    finally:
        d.chmod(0o755)


# ---------------------------------------------------------------- off (the default)
def test_off_keeps_files_byte_identical_and_creates_nothing(calls):
    inbox = util.default_inbox()
    _drop(inbox, "conn.log")
    _drop(inbox, "sensor/2001-02-03/conn.04.log.gz", gzip.compress(json.dumps(_rec("Cfinboxgz")).encode()))
    _drop(inbox, "broken.log", BROKEN)
    before = _tree(inbox)
    res = importer.scan_inbox()
    assert sorted(r.get("inserted", 0) for r in res) == [0, 1, 1] and len(calls) == 3
    assert _tree(inbox) == before                              # same files, same bytes, no failed/, no tidying
    assert db.query("SELECT count(*) AS n FROM netlog WHERE uid = 'Cfinboxgz'")[0]["n"] == 1
    calls.clear()
    assert importer.scan_inbox() == [] and calls == []         # the ledger: nothing is read again
    g = C.get("/api/netlog/inbox").json()
    assert (g["waiting"], g["imported"]) == (0, 2)
    assert [f["path"] for f in g["failed"]] == ["broken.log"] and g["failed"][0]["error"]
    assert "looks like json" not in json.dumps(g)              # names and errors, never contents


def test_waiting_counts_new_files_without_reading_them(calls):
    _drop(util.default_inbox(), "a.log")
    _drop(util.default_inbox(), "b.log")
    g = C.get("/api/netlog/inbox").json()
    assert g["waiting"] == 2 and calls == []


def test_changed_file_is_imported_again():
    p = _drop(util.default_inbox(), "conn.log")
    assert [r.get("inserted") for r in importer.scan_inbox()] == [1]
    p.write_bytes(p.read_bytes() + b"\n" + json.dumps(_rec("Cfinboxmore")).encode())
    os.utime(p, (OLD + 10, OLD + 10))
    res = importer.scan_inbox()
    assert [r.get("inserted") for r in res] == [1]            # only the new row: row dedupe still applies
    assert db.query("SELECT count(*) AS n FROM netlog WHERE uid = 'Cfinboxmore'")[0]["n"] == 1


def test_same_content_touched_is_read_but_inserts_nothing(calls):
    p = _drop(util.default_inbox(), "conn.log")
    importer.scan_inbox()
    os.utime(p, (OLD + 5, OLD + 5))
    res = importer.scan_inbox()
    assert len(calls) == 2 and res[0].get("duplicate") is True and res[0].get("inserted") == 0


def test_failed_file_is_not_retried_until_it_changes(calls):
    p = _drop(util.default_inbox(), "broken.log", BROKEN)
    assert importer.scan_inbox()[0].get("error")
    for _ in range(3):
        assert importer.scan_inbox() == []
    assert calls == ["broken.log"]
    p.write_bytes(json.dumps(_rec("Cfinboxfixed")).encode())   # fixed: a new size and mtime
    os.utime(p, (OLD + 20, OLD + 20))
    res = importer.scan_inbox()
    assert [r.get("inserted") for r in res] == [1] and calls == ["broken.log", "broken.log"]
    assert C.get("/api/netlog/inbox").json()["failed"] == []


def test_ledger_survives_a_restart(calls):
    _drop(util.default_inbox(), "conn.log")
    importer.scan_inbox()
    importer._ledger_ready = False                              # as after a restart: the table is in the lake DB
    calls.clear()
    assert importer.scan_inbox() == [] and calls == []


def test_ledger_prunes_vanished_files():
    a = _drop(util.default_inbox(), "a.log")
    _drop(util.default_inbox(), "b.log")
    importer.scan_inbox()
    n = lambda: db.query("SELECT count(*) AS n FROM netlog_inbox_seen")[0]["n"]  # noqa: E731
    assert n() == 2
    a.unlink()
    importer.scan_inbox()
    assert n() == 1


def test_unsettled_file_waits():
    p = util.default_inbox() / "growing.log"
    p.write_bytes(json.dumps(_rec("Cfinboxnew")).encode())    # mtime now: still being written
    assert importer.scan_inbox() == [] and importer.last_pass["still_writing"] == 1
    g = C.get("/api/netlog/inbox").json()
    assert (g["waiting"], g["writing"]) == (0, 1)


# ---------------------------------------------------------------- a different folder
def test_switch_folder_through_the_api(calls):
    _drop(util.default_inbox(), "same.log")
    importer.scan_inbox()
    d = _folder("switch")
    _drop(d, "same.log")                                       # same relative name: not "seen" in the new folder
    r = C.put("/api/netlog/inbox", json={"path": str(d)}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["path"] == str(d) and r.json()["waiting"] == 1
    calls.clear()
    res = importer.scan_inbox()                                 # next scan, no restart
    assert [r.get("inserted") for r in res] == [1] and calls == ["same.log"]
    assert (d / "same.log").exists() and not (d / "failed").exists()
    assert ingest.inbox_location()["path"] == str(d) + "/"
    assert {r["folder"] for r in db.query("SELECT DISTINCT folder FROM netlog_inbox_seen")} == {str(d), str(util.default_inbox())}
    r = C.put("/api/netlog/inbox", json={"reset": True}, headers=ORIGIN)
    assert r.json()["path"] == str(util.default_inbox()) and util.inbox_settings()["path"] == r.json()["path"]


def test_missing_chosen_folder_is_reported_and_never_created():
    d = _folder("gone")
    assert C.put("/api/netlog/inbox", json={"path": str(d)}, headers=ORIGIN).status_code == 200
    d.rmdir()
    assert importer.scan_inbox() == [] and not d.exists()
    assert C.get("/api/netlog/inbox").json()["problem"]


def test_docker_chosen_folder_is_inside_the_container(monkeypatch):
    d = _folder("docker")
    C.put("/api/netlog/inbox", json={"path": str(d)}, headers=ORIGIN)
    monkeypatch.setenv("OSINTHUB_DOCKER", "1")
    w = ingest.inbox_location()
    assert w["docker"] and w["inside"] == str(d) + "/" and "inside the Night Desk container" in w["note"]


# ---------------------------------------------------------------- on: v1.2 behaviour
def test_on_deletes_imported_moves_failed_and_tidies(calls):
    assert C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN).json()["delete_after_import"]
    inbox = util.default_inbox()
    ok = _drop(inbox, "sensor/2001-02-03/conn.log")
    bad = _drop(inbox, "sensor/2001-02-04/broken.log", BROKEN)
    live = _drop(inbox, "sensor/current/conn.log")
    res = importer.scan_inbox()
    assert sorted(bool(r.get("error")) for r in res) == [False, True]
    assert not ok.exists() and not ok.parent.exists()           # imported, and the emptied folder tidied
    assert not bad.exists() and (inbox / "failed/sensor/2001-02-04/broken.log").read_bytes() == BROKEN
    assert live.exists()                                        # Zeek's live folder is never touched
    g = C.get("/api/netlog/inbox").json()
    assert [f["path"] for f in g["failed"]] == ["failed/sensor/2001-02-04/broken.log"] and g["failed"][0]["error"]
    calls.clear()
    assert importer.scan_inbox() == [] and calls == []


def test_on_never_deletes_a_file_it_could_not_read(monkeypatch):
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    p = _drop(util.default_inbox(), "conn.log")

    def boom(*a, **kw):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(importer, "import_inbox_file", boom)
    res = importer.scan_inbox()
    assert res[0]["error"] and not p.exists()                   # moved to failed/, not deleted
    assert (util.default_inbox() / "failed" / "conn.log").exists()


def test_check_answers_200_with_the_reason():
    r = C.get("/api/netlog/inbox/check", params={"path": "/"})
    assert r.status_code == 200 and r.json()["ok"] is False and "top of the disk" in r.json()["error"]
    d = _folder("check")
    assert C.get("/api/netlog/inbox/check", params={"path": str(d)}).json() == {"ok": True, "path": str(d), "error": None}
    assert util.inbox_settings()["path"] == util.inbox_settings()["default_path"]   # checking saves nothing


def test_turning_delete_on_clears_files_kept_while_it_was_off(calls):
    inbox = util.default_inbox()
    kept = _drop(inbox, "kept.log")
    broken = _drop(inbox, "broken.log", BROKEN)
    importer.scan_inbox()
    assert kept.exists() and broken.exists()
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    calls.clear()
    res = importer.scan_inbox()
    assert sorted(calls) == ["broken.log", "kept.log"]          # read once more: a duplicate, then deleted
    assert any(r.get("duplicate") for r in res)
    assert not kept.exists() and (inbox / "failed" / "broken.log").exists()
    calls.clear()
    assert importer.scan_inbox() == [] and calls == []


def test_on_with_an_undeletable_file_does_not_reread_it(monkeypatch, calls):
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    p = _drop(util.default_inbox(), "conn.log")
    real_unlink = os.unlink

    def no_unlink(path, *a, **kw):
        if path == "conn.log" and "dir_fd" in kw:
            raise PermissionError(13, "Permission denied")
        return real_unlink(path, *a, **kw)
    monkeypatch.setattr(os, "unlink", no_unlink)
    importer.scan_inbox()
    importer.scan_inbox()
    assert p.exists() and calls == ["conn.log"]


# ---------------------------------------------------------------- round 2: the lake can never be emptied through the inbox
def _raw_day() -> Path:
    """A folder of the lake's own raw copies (stand-ins), which nothing in the inbox code may ever touch."""
    d = config.RAW_DIR / "netlog" / "2001" / "02" / "03"
    d.mkdir(parents=True, exist_ok=True)
    for i in range(3):
        _drop(d, f"copy-{i}.log.gz", gzip.compress(json.dumps(_rec(f"Craw{i}")).encode()))
    return d


def _lake_untouched(d: Path, before: dict) -> None:
    assert _tree(d) == before


def test_dotdot_through_a_symlink_saves_and_scans_the_resolved_folder(calls):
    raw = _raw_day()
    before = _tree(raw)
    lake = Path(os.environ["OSINTHUB_LAKE"])
    evil = _folder("evil")
    (evil / "a").mkdir()
    decoy = evil / lake.name / raw.relative_to(lake)
    decoy.mkdir(parents=True)
    link = lake.parent / f"zz-link-{os.getpid()}"
    link.symlink_to(evil / "a")
    try:
        trick = f"{link}/../{lake.name}/{raw.relative_to(lake)}"
        r = C.put("/api/netlog/inbox", json={"path": trick, "delete_after_import": True}, headers=ORIGIN)
        assert r.status_code == 200 and r.json()["path"] == str(decoy)      # what was checked is what is saved
        assert util.ident(config.LAKE) not in util.ancestry(r.json()["path"])
        importer.scan_inbox()
        _lake_untouched(raw, before)
        assert calls == []
    finally:
        link.unlink()


def test_symlink_repointed_into_the_lake_after_saving_is_never_scanned(calls):
    raw = _raw_day()
    before = _tree(raw)
    safe = _folder("safe")
    swing = SCRATCH / "swing"
    if swing.is_symlink():
        swing.unlink()
    swing.symlink_to(safe)
    r = C.put("/api/netlog/inbox", json={"path": str(swing), "delete_after_import": True}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["path"] == str(safe)          # saved resolved: the link no longer matters
    swing.unlink()
    swing.symlink_to(raw)
    importer.scan_inbox()
    _lake_untouched(raw, before)
    # and a saved folder that later becomes a link into the lake is refused at scan time
    db.set_setting(util.INBOX_KEY, {"path": str(swing), "delete_after_import": True})
    assert importer.scan_inbox() == [] and calls == []
    _lake_untouched(raw, before)
    g = C.get("/api/netlog/inbox").json()
    assert "own data" in g["problem"] and g["waiting"] == 0
    assert "own data" in importer.last_pass["stopped"]


def test_env_value_is_checked_like_a_saved_one(monkeypatch, calls):
    raw = _raw_day()
    before = _tree(raw)
    monkeypatch.setenv("OSINTHUB_INBOX", str(raw) + "/")
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    assert importer.scan_inbox() == [] and calls == []
    _lake_untouched(raw, before)
    g = C.get("/api/netlog/inbox").json()
    assert g["from_env"] and "own data" in g["problem"]
    monkeypatch.setenv("OSINTHUB_INBOX", "relative/logs")
    assert "full path" in util.inbox_settings()["problem"]
    d = _folder("envok")
    monkeypatch.setenv("OSINTHUB_INBOX", str(d) + "//")
    s = util.inbox_settings()
    assert s["problem"] is None and s["path"] == str(d)                     # normalised


def test_symlinked_file_into_the_lake_is_skipped_and_never_deleted(calls):
    raw = _raw_day()
    before = _tree(raw)
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    inbox = util.default_inbox()
    (inbox / "link.log.gz").symlink_to(raw / "copy-0.log.gz")
    (inbox / "linkdir").symlink_to(raw)
    importer.scan_inbox()
    assert calls == [] and (inbox / "link.log.gz").is_symlink() and (inbox / "linkdir").is_symlink()
    _lake_untouched(raw, before)
    g = C.get("/api/netlog/inbox").json()
    assert g["links_count"] == 2 and sorted(g["links"]) == ["link.log.gz", "linkdir"]


def test_refuses_every_lake_folder_but_the_default_inbox():
    lake = Path(os.environ["OSINTHUB_LAKE"])
    for sub in ("inbox", "inbox/push", "ref", "uploads", "raw", "db", "tmp", "cache", "certs", ""):
        (lake / sub).mkdir(parents=True, exist_ok=True)
        r = C.get("/api/netlog/inbox/check", params={"path": str(lake / sub)}).json()
        assert r["ok"] is False and "own data" in r["error"], (sub, r)
    (util.default_inbox() / "sensor").mkdir()
    for ok in (util.default_inbox(), util.default_inbox() / "sensor"):
        assert C.get("/api/netlog/inbox/check", params={"path": str(ok)}).json()["ok"], ok
    r = C.get("/api/netlog/inbox/check", params={"path": str(lake.parent)}).json()
    assert r["ok"] is False and "contains" in r["error"]


def test_tilde_is_expanded(monkeypatch):
    d = _folder("home-like")
    monkeypatch.setenv("HOME", str(SCRATCH))
    assert util.check_inbox_dir("~/home-like") == str(d)


def test_files_that_are_not_logs_are_never_copied_moved_or_deleted(calls):
    inbox = util.default_inbox()
    pic = _drop(inbox, "holiday.jpg", b"\xff\xd8\xff\xe0 not a log")
    doc = _drop(inbox, "notes.txt", b"shopping list\n")
    files_before = db.query("SELECT count(*) AS n FROM netlog_files")[0]["n"]
    assert importer.scan_inbox() == [] and calls == [] and importer.last_pass["not_logs"] == 2
    assert db.query("SELECT count(*) AS n FROM netlog_files")[0]["n"] == files_before
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    importer.scan_inbox()
    assert pic.exists() and doc.exists() and not (inbox / "failed").exists() and calls == []
    g = C.get("/api/netlog/inbox").json()
    assert g["not_logs_count"] == 2 and sorted(g["not_logs"]) == ["holiday.jpg", "notes.txt"] and g["failed"] == []


@pytest.mark.parametrize("body,kind", [
    (json.dumps(_rec("Ck")).encode(), "json"), (gzip.compress(json.dumps(_rec("Ck")).encode()), "json"),
    (b"#separator \\x09\n#path\tconn\n", "zeek-tsv"), (b"PK\x03\x04rest", "zip"), (b"\x00binary", None),
])
def test_log_kind(body, kind):
    assert importer.log_kind(_drop(_folder("kinds"), "f", body)) == kind


def test_manual_scan_leaves_files_still_being_written():
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    p = util.default_inbox() / "grow.log"
    p.write_bytes(json.dumps(_rec("Cgrow")).encode())
    r = C.post("/api/netlog/inbox/scan", headers=ORIGIN).json()
    assert r["files"] == [] and r["still_writing"] == 1 and p.exists()


def test_a_file_written_to_while_it_was_read_is_not_deleted(monkeypatch):
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    p = _drop(util.default_inbox(), "grow.log")
    real = importer.import_inbox_file

    def and_append(fh, name):
        res = real(fh, name)
        with open(p, "ab") as out:
            out.write(b"\n" + json.dumps(_rec("Clater")).encode())
        return res
    monkeypatch.setattr(importer, "import_inbox_file", and_append)
    importer.scan_inbox()
    assert p.exists() and importer.last_pass["still_writing"] == 1


def test_permission_fix_is_retried_without_touching(calls):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    p = _drop(util.default_inbox(), "locked.log")
    p.chmod(0)
    try:
        importer.scan_inbox()
        assert C.get("/api/netlog/inbox").json()["failed"][0]["error"].startswith("could not read")
    finally:
        p.chmod(0o644)
    os.utime(p, (OLD, OLD))
    res = importer.scan_inbox()
    assert [r.get("inserted") for r in res] == [1]
    assert C.get("/api/netlog/inbox").json()["failed"] == []


def test_unreadable_subfolder_is_listed():
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    d = util.default_inbox() / "sealed"
    d.mkdir()
    d.chmod(0)
    try:
        g = C.get("/api/netlog/inbox").json()
        assert [f["path"] for f in g["failed"]] == ["sealed/"]
    finally:
        d.chmod(0o755)


def test_switching_back_reads_nothing_again(calls):
    a, b = _folder("swa"), _folder("swb")
    _drop(a, "a.log")
    _drop(b, "b.log")
    for d in (a, b):
        C.put("/api/netlog/inbox", json={"path": str(d)}, headers=ORIGIN)
        importer.scan_inbox()
    calls.clear()
    C.put("/api/netlog/inbox", json={"path": str(a)}, headers=ORIGIN)
    assert importer.scan_inbox() == [] and calls == []


def test_v12_failed_folder_is_neutral_not_red():
    _drop(util.default_inbox(), "failed/2026-11-10/heartbeat.log.gz", b"")
    g = C.get("/api/netlog/inbox").json()
    assert g["earlier_failed"] == 1 and g["failed"] == [] and g["failed_count"] == 0


# ---------------------------------------------------------------- round 3: identity, not names; no window before a delete
import unicodedata  # noqa: E402


def _variants(path: Path) -> list[str]:
    """Other spellings of an existing path that open the same folder on this volume (case, NFD), if any."""
    out = []
    for v in (str(path).upper(), unicodedata.normalize("NFD", str(path)), str(path).swapcase()):
        if v != str(path) and os.path.isdir(v) and os.path.samefile(v, path):
            out.append(v)
    return out


def test_case_and_unicode_spellings_of_the_lake_are_refused_and_scan_nothing(monkeypatch, calls):
    lake = SCRATCH / "lake-\u00e9"                       # NFC é, like a lake folder named by hand
    raw = lake / "raw" / "netlog" / "2001"
    raw.mkdir(parents=True, exist_ok=True)
    _drop(raw, "copy.log")
    monkeypatch.setattr(config, "LAKE", lake)
    spellings = _variants(raw)
    if not spellings:
        pytest.skip("this volume is case- and normalisation-sensitive: no other spelling opens the folder")
    for v in spellings:
        r = C.get("/api/netlog/inbox/check", params={"path": v}).json()
        assert r["ok"] is False and "own data" in r["error"], (v, r)
        db.set_setting(util.INBOX_KEY, {"path": v, "delete_after_import": True})   # as if saved by an older check
        assert importer.scan_inbox() == [] and calls == [] and (raw / "copy.log").exists()
        monkeypatch.setenv("OSINTHUB_INBOX", v)
        g = C.get("/api/netlog/inbox").json()
        assert "OSINTHUB_INBOX" in g["problem"] and "restart" in g["problem"]
        assert importer.scan_inbox() == [] and (raw / "copy.log").exists()
        monkeypatch.delenv("OSINTHUB_INBOX")


def test_case_spellings_of_home_and_users_are_refused():
    for p in (os.path.expanduser("~"), "/Users"):
        if not os.path.isdir(p):
            continue
        for v in _variants(Path(p)) or [p]:
            r = C.get("/api/netlog/inbox/check", params={"path": v}).json()
            assert r["ok"] is False and ("home folder" in r["error"] or "system folder" in r["error"]), (v, r)


def test_folder_swapped_for_a_link_mid_scan_deletes_nothing_in_the_lake(monkeypatch):
    raw = _raw_day()
    _drop(raw, "x.log")
    before = _tree(raw)
    inbox = _folder("swapdir")
    _drop(inbox, "d/x.log")
    C.put("/api/netlog/inbox", json={"path": str(inbox), "delete_after_import": True}, headers=ORIGIN)
    real = importer.import_inbox_file

    def swap(fh, name):
        (inbox / "d").rename(inbox / "d.real")
        (inbox / "d").symlink_to(raw)                   # the name now leads into the lake
        return real(fh, name)
    monkeypatch.setattr(importer, "import_inbox_file", swap)
    importer.scan_inbox()
    _lake_untouched(raw, before)
    assert not (inbox / "d.real" / "x.log").exists()   # the file that was read, in the folder that was opened


def test_file_swapped_mid_scan_is_left_alone(monkeypatch):
    raw = _raw_day()
    before = _tree(raw)
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    inbox = util.default_inbox()
    _drop(inbox, "a.log")
    _drop(inbox, "b.log")
    real = importer.import_inbox_file

    def swap(fh, name):
        res = real(fh, name)
        if name == "a.log":
            (inbox / "a.log").rename(inbox / "a.orig")
            (inbox / "a.log").symlink_to(raw / "copy-0.log.gz")        # now a link into the lake
        else:
            (inbox / "b.log").rename(inbox / "b.orig")
            (inbox / "b.log").write_bytes(b"someone else's file")      # now a different file
        return res
    monkeypatch.setattr(importer, "import_inbox_file", swap)
    importer.scan_inbox()
    _lake_untouched(raw, before)
    assert (inbox / "a.log").is_symlink() and (inbox / "a.orig").exists()
    assert (inbox / "b.log").read_bytes() == b"someone else's file" and (inbox / "b.orig").exists()


def test_delete_on_waits_two_minutes_off_waits_five_seconds():
    p = util.default_inbox() / "recent.log"
    p.write_bytes(json.dumps(_rec("Crecent")).encode())
    t = time.time() - 60
    os.utime(p, (t, t))
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    assert importer.scan_inbox() == [] and importer.last_pass["still_writing"] == 1 and p.exists()
    assert C.get("/api/netlog/inbox").json()["writing"] == 1
    C.put("/api/netlog/inbox", json={"delete_after_import": False}, headers=ORIGIN)
    assert [r.get("inserted") for r in importer.scan_inbox()] == [1] and p.exists()


def test_zeek_current_link_is_not_counted():
    target = _folder("spool")
    (util.default_inbox() / "current").symlink_to(target)
    (util.default_inbox() / "sensor").mkdir()
    (util.default_inbox() / "sensor" / "current").symlink_to(target)
    assert C.get("/api/netlog/inbox").json()["links_count"] == 0


def test_any_json_is_not_a_log_but_log_json_is():
    d = _folder("jsonkinds")
    assert importer.log_kind(_drop(d, "package.json", b'{\n  "name": "x",\n  "version": "1.0.0"\n}\n')) is None
    assert importer.log_kind(_drop(d, "settings.json", b'{"theme": "dark"}\n')) is None
    assert importer.log_kind(_drop(d, "eve.json", b'{"timestamp": "2001-02-03T04:05:06Z", "event_type": "alert"}\n')) == "json"
    assert importer.log_kind(_drop(d, "q.json", b'{"T": "2001-02-03T04:05:06Z", "QH": "example.com", "IP": "192.0.2.1"}\n')) == "json"


def test_xz_and_bzip2_fail_with_a_reason_and_are_not_copied(calls):
    p = _drop(util.default_inbox(), "conn.log.xz", b"\xfd7zXZ\x00rest")
    res = importer.scan_inbox()
    assert calls == [] and "gzip" in res[0]["error"] and p.exists()
    assert C.get("/api/netlog/inbox").json()["failed"][0]["path"] == "conn.log.xz"


# ---------------------------------------------------------------- round 4: a very deep tree never breaks the inbox
def _deep_tree(root: Path, depth: int) -> int:
    """depth nested folders, made through fds, with names long enough that the full path is longer than PATH_MAX (what
    the fd walk guards), and a log at the bottom. Returns the full path length."""
    name = "d" * min(255, os.pathconf(root, "PC_PATH_MAX") // depth + 2)
    fd = os.open(root, os.O_RDONLY)
    try:
        for _ in range(depth):
            os.mkdir(name, dir_fd=fd)
            nxt = os.open(name, os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = nxt
        f = os.open("deep.log", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
        os.write(f, json.dumps(_rec("Cdeep")).encode())
        os.close(f)
    finally:
        os.close(fd)
    return len(str(root)) + depth * (len(name) + 1)


def test_a_too_deep_tree_is_capped_not_a_crash(calls):
    inbox = _folder("deep")
    _drop(inbox, "top/conn.log")
    assert _deep_tree(inbox, importer.MAX_DEPTH + 6) > os.pathconf(inbox, "PC_PATH_MAX")
    C.put("/api/netlog/inbox", json={"path": str(inbox)}, headers=ORIGIN)
    fds_before = len(os.listdir("/dev/fd"))
    res = importer.scan_inbox()
    assert [r.get("inserted") for r in res] == [1] and calls == ["conn.log"]          # the shallow file, not the deep one
    assert len(os.listdir("/dev/fd")) == fds_before                                  # every fd closed
    r = C.get("/api/netlog/inbox")
    assert r.status_code == 200 and r.json()["problem"] is None
    g = r.json()
    assert g["too_deep_count"] == 1 and g["too_deep"][0].count("/") == importer.MAX_DEPTH + 1
    C.put("/api/netlog/inbox", json={"delete_after_import": True}, headers=ORIGIN)
    importer.scan_inbox()                                                            # delete mode walks it too
    assert C.get("/api/netlog/inbox").status_code == 200
    shutil.rmtree(inbox)


def test_a_failing_status_is_a_problem_not_a_500(monkeypatch):
    def boom():
        raise RecursionError("simulated")
    monkeypatch.setattr(importer, "inbox_status", boom)
    r = C.get("/api/netlog/inbox")
    assert r.status_code == 200 and "could not read" in r.json()["problem"]
    assert r.json()["path"] == str(util.default_inbox())                            # the page can still show and reset it
    d = _folder("after-failure")
    assert C.put("/api/netlog/inbox", json={"path": str(d)}, headers=ORIGIN).status_code == 200
    assert util.inbox_settings()["path"] == str(d)

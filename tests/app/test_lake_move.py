"""Moving the data folder (Settings › Data › Change…): where the lake comes from, the checks on a new folder, the move
at start (copy, check, then switch; the old folder untouched; failures start on the old folder), the API in each setup
(here, next start, fixed by the start command, Docker) and the installer's --move-data. osinthub/lakeloc.py

    uv run --with pytest pytest tests/app/test_lake_move.py -q
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path

from _lake import ROOT, make_lake
LAKE = make_lake("lakemove", disable="news,entities,netlog,ai")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import api, config, db, lakeloc  # noqa: E402

db.connect()
C = TestClient(api.app, base_url="http://localhost")
ORIGIN = {"Origin": "http://localhost"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A temporary home and config folder, so nothing touches the real ones."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    (tmp_path / "home").mkdir()
    return tmp_path


def _lake_at(p: Path) -> Path:
    for rel, text in {"db/hub.duckdb": "db", "raw/feodo/2026/11/20/a.jsonl": "x" * 1000, "ref/geo.json": "{}",
                      "uploads/u.csv": "a,b\n", "tmp/open.jsonl": "y"}.items():
        (p / rel).parent.mkdir(parents=True, exist_ok=True)
        (p / rel).write_text(text)
    return p


# ------------------------------------------------------------------ where the lake comes from
def test_env_wins_then_the_chosen_folder_then_the_app_data_folder(home, monkeypatch):
    monkeypatch.delenv("OSINTHUB_LAKE", raising=False)
    assert lakeloc.resolve() == (lakeloc.default_lake(), "default")
    (home / "config" / "nightdesk").mkdir(parents=True)
    (home / "config" / "nightdesk" / "lake-folder").write_text(str(home / "elsewhere") + "\n")
    assert lakeloc.resolve() == (home / "elsewhere", "chosen")
    monkeypatch.setenv("OSINTHUB_LAKE", str(home / "env-lake"))
    assert lakeloc.resolve() == (home / "env-lake", "env")


def test_the_config_folder_is_outside_the_default_lake(home):
    assert lakeloc.default_lake() not in lakeloc.config_dir().parents
    assert lakeloc.config_dir() not in lakeloc.default_lake().parents


# ------------------------------------------------------------------ checking a new folder
@pytest.mark.parametrize("raw,why", [
    ("", "Type the folder"), ("relative/dir", "full path"), ("/", "not a system folder"), ("/usr/local/nd", "system folder"),
])
def test_refuses_unusable_folders(home, raw, why):
    cur = _lake_at(home / "cur")
    with pytest.raises(ValueError, match=why):
        lakeloc.check_target(raw, cur, 1000)


def test_refuses_same_inside_containing_nonempty_file_and_home(home):
    cur = _lake_at(home / "parent" / "cur")
    (home / "full").mkdir(); (home / "full" / "x").write_text("1")
    (home / "afile").write_text("1")
    for raw, why in [(str(cur), "already uses"), (str(cur / "sub"), "inside the current"), (str(home / "parent"), "contain the current"),
                     (str(home / "full"), "not empty"), (str(home / "afile"), "a file"), (str(home / "home"), "home folder")]:
        with pytest.raises(ValueError, match=why):
            lakeloc.check_target(raw, cur, 1000)


def test_refuses_without_enough_free_space(home, monkeypatch):
    cur = _lake_at(home / "cur")
    monkeypatch.setattr(lakeloc.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(10, 5, 5))
    with pytest.raises(ValueError, match="Not enough free space"):
        lakeloc.check_target(str(home / "new"), cur, 1000)


def test_accepts_a_new_or_empty_folder_and_expands_home(home):
    cur = _lake_at(home / "cur")
    assert lakeloc.check_target(str(home / "new" / "Night Desk"), cur, 1000) == home / "new" / "Night Desk"
    (home / "empty").mkdir(); (home / "empty" / ".DS_Store").write_text("")
    assert lakeloc.check_target(str(home / "empty"), cur, 1000) == home / "empty"
    assert lakeloc.check_target("~/nd", cur, 1000) == home / "home" / "nd"


# ------------------------------------------------------------------ the move at start
def test_move_copies_checks_switches_and_leaves_the_old_folder(home, monkeypatch):
    monkeypatch.delenv("OSINTHUB_LAKE", raising=False)
    old = _lake_at(lakeloc.default_lake())
    before = sorted(str(p.relative_to(old)) for p in old.rglob("*"))
    lakeloc.request_move(old, home / "new")
    r = lakeloc.run_pending_move()
    assert r["ok"] and r["files"] == 5 and r["bytes"] == lakeloc.tree_size(old)[1]
    assert lakeloc.resolve() == (home / "new", "chosen")
    assert sorted(str(p.relative_to(home / "new")) for p in (home / "new").rglob("*")) == before
    assert sorted(str(p.relative_to(old)) for p in old.rglob("*")) == before        # untouched
    assert lakeloc.pending() is None and lakeloc.last_result()["ok"]
    assert lakeloc.run_pending_move() is None                                         # done once


def test_a_failed_move_starts_on_the_old_folder(home, monkeypatch):
    monkeypatch.delenv("OSINTHUB_LAKE", raising=False)
    old = _lake_at(lakeloc.default_lake())
    lakeloc.request_move(old, home / "new")
    (home / "new").mkdir(); (home / "new" / "surprise").write_text("1")              # filled after the check
    r = lakeloc.run_pending_move()
    assert not r["ok"] and "no longer empty" in r["error"]
    assert lakeloc.resolve() == (old, "default") and lakeloc.pending() is None


def test_a_move_is_never_run_when_the_start_command_names_the_lake(home, monkeypatch):
    old = _lake_at(home / "cur")
    monkeypatch.setenv("OSINTHUB_LAKE", str(old))
    lakeloc.request_move(old, home / "new")
    r = lakeloc.run_pending_move()
    assert not r["ok"] and "start command" in r["error"] and not (home / "new").exists()


def test_an_incomplete_copy_is_not_used(home, monkeypatch):
    monkeypatch.delenv("OSINTHUB_LAKE", raising=False)
    old = _lake_at(lakeloc.default_lake())
    lakeloc.request_move(old, home / "new")
    real = lakeloc.tree_size
    monkeypatch.setattr(lakeloc, "tree_size", lambda p: real(p) if Path(p) == old else (1, 1))
    r = lakeloc.run_pending_move()
    assert not r["ok"] and "incomplete" in r["error"] and lakeloc.chosen() is None


# ------------------------------------------------------------------ the API in each setup
def _loc():
    return C.get("/api/lake").json()["location"]


def test_fixed_when_the_start_command_names_the_lake():
    assert config.LAKE_SOURCE == "env"          # the test lake comes from OSINTHUB_LAKE
    assert _loc()["change"] == "fixed"
    r = C.post("/api/lake/move", json={"path": "/tmp/x"}, headers=ORIGIN)
    assert r.status_code == 409 and "command that starts" in r.json()["detail"]


def test_docker_shows_the_host_command_instead(monkeypatch):
    from osinthub.netlog import ingest
    monkeypatch.setattr(ingest, "in_docker", lambda: True)
    monkeypatch.setenv("OSINTHUB_INSTALL_DIR", "/home/someone/.nightdesk")
    monkeypatch.setenv("OSINTHUB_LAKE_HOST", "/home/someone/.local/share/nightdesk")
    loc = _loc()
    assert loc["change"] == "docker" and loc["install_dir"] == "/home/someone/.nightdesk"
    assert C.post("/api/lake/move", json={"path": "/tmp/x"}, headers=ORIGIN).status_code == 409


def test_next_start_and_here(home, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "LAKE_SOURCE", "default")
    monkeypatch.delenv("OSINTHUB_DB", raising=False)
    monkeypatch.delenv("OSINTHUB_VECTORS_DB", raising=False)
    monkeypatch.setattr(lakeloc, "SERVER", None)
    assert _loc()["change"] == "next_start"
    bad = C.post("/api/lake/move", json={"path": "relative"}, headers=ORIGIN)
    assert bad.status_code == 400 and "full path" in bad.json()["detail"]
    r = C.post("/api/lake/move", json={"path": str(tmp_path / "moved")}, headers=ORIGIN).json()
    assert r["restarting"] is False and lakeloc.pending()["to"] == str(tmp_path / "moved")
    assert _loc()["pending"]["to"] == str(tmp_path / "moved")
    assert C.delete("/api/lake/move", headers=ORIGIN).status_code == 200 and lakeloc.pending() is None

    class Srv:
        should_exit = False
    srv = Srv()
    monkeypatch.setattr(lakeloc, "SERVER", srv)
    lakeloc.restart_requested.clear()
    assert _loc()["change"] == "here"
    r = C.post("/api/lake/move", json={"path": str(tmp_path / "moved")}, headers=ORIGIN).json()
    assert r["restarting"] is True
    for _ in range(40):
        if srv.should_exit:
            break
        time.sleep(0.05)
    assert srv.should_exit and lakeloc.restart_requested.is_set()
    lakeloc.restart_requested.clear()
    C.delete("/api/lake/move", headers=ORIGIN)


def test_move_needs_a_same_origin_write():
    assert C.post("/api/lake/move", json={"path": "/tmp/x"}, headers={"Origin": "https://evil.example"}).status_code == 403


# ------------------------------------------------------------------ Docker: the installer moves it
def test_installer_moves_the_data_folder_and_compose_passes_the_install_folder():
    text = (ROOT / "deploy" / "install.sh").read_text()
    assert "--move-data) MOVE=" in text and 'setenv LAKE_DIR "$MOVE"' in text
    assert "compose stop app" in text and 'cp -Rp "$old"/. "$MOVE"/' in text
    assert "say \"NIGHTDESK_HOME='$HOME_DIR'\"" in text and "say \"ND_PROJECT='$PROJECT'\"" in text
    assert "OSINTHUB_INSTALL_DIR: ${NIGHTDESK_HOME:-}" in (ROOT / "docker-compose.yml").read_text()

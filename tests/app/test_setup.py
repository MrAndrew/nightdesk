"""Setting up: the default lake (this computer's app-data folder unless OSINTHUB_LAKE says otherwise), Bluesky off for new lakes but kept on
for lakes that already ran it, and Docker passing every source key through (and documenting it in .env.example).

    uv run --with pytest pytest tests/app/test_setup.py -q
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from _lake import ROOT, make_lake
LAKE = make_lake("setup")

from osinthub import db, scheduler  # noqa: E402
from osinthub.sources import SOURCES  # noqa: E402

db.connect()
BSKY = SOURCES["bluesky_cyber"]


def _config_in(cwd: Path, lake: str | None, home: Path | None = None) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("OSINTHUB_") and k not in ("XDG_DATA_HOME",)}
    if lake is not None:
        env["OSINTHUB_LAKE"] = lake
    if home is not None:
        env["HOME"] = env["USERPROFILE"] = env["LOCALAPPDATA"] = str(home)
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.run([sys.executable, "-c", "from osinthub import config; print(config.LAKE); print(config.DB_PATH)"],
                          cwd=cwd, env=env, capture_output=True, text=True, timeout=60)


def _platform_lake(home: Path) -> Path:
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Night Desk"
    if os.name == "nt":
        return home / "Night Desk"
    return home / ".local" / "share" / "nightdesk"


# ---------------------------------------------------------------- default lake
def test_default_lake_is_the_app_data_folder_not_the_working_directory():
    # a temporary home folder stands in for the real one, so the test never creates the owner's data folder
    with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as h:
        cwd, home = Path(d).resolve(), Path(h).resolve()
        r = _config_in(cwd, None, home)
        assert r.returncode == 0, r.stderr
        lake, dbp = r.stdout.splitlines()     # the macOS folder name has a space
        want = _platform_lake(home)
        assert Path(lake).resolve() == want
        assert Path(dbp).resolve() == want / "db" / "hub.duckdb"
        assert (want / "raw").is_dir() and (want / "db").is_dir()
        assert not (cwd / "lake").exists()


def test_lake_env_still_wins():
    with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as other, tempfile.TemporaryDirectory() as h:
        r = _config_in(Path(d), other, Path(h))
        assert r.returncode == 0, r.stderr
        assert Path(r.stdout.splitlines()[0]) == Path(other)
        assert not (Path(d) / "lake").exists() and not any(Path(h).iterdir())


# ---------------------------------------------------------------- Bluesky default
def _reset(sid: str) -> None:
    db.execute("DELETE FROM source_state WHERE id = ?", [sid])
    db.execute("DELETE FROM settings WHERE key = 'sources.default_flips'")


def test_bluesky_off_for_a_new_lake():
    assert BSKY.default_enabled is False
    _reset(BSKY.id)
    scheduler._apply_default_flips()
    assert scheduler.state(BSKY.id).get("enabled") is None
    assert scheduler.is_enabled(BSKY) is False
    scheduler._set_state(BSKY.id, status="disabled")       # what start_all records for it on that first start
    scheduler._apply_default_flips()                       # a later restart must not switch it on
    assert scheduler.is_enabled(BSKY) is False


def test_bluesky_stays_on_for_an_existing_lake():
    _reset(BSKY.id)
    scheduler._set_state(BSKY.id, status="ok", items_total=12)   # ran under the old on-by-default, flag unset
    scheduler._apply_default_flips()
    assert scheduler.state(BSKY.id)["enabled"] is True and scheduler.is_enabled(BSKY)
    scheduler._set_state(BSKY.id, enabled=False)                 # the user turns it off later: kept
    scheduler._apply_default_flips()
    assert scheduler.is_enabled(BSKY) is False


def test_a_withheld_source_never_runs_and_keeps_its_saved_answer(monkeypatch):
    # `withheld` leaves a source out of a release (no source is withheld now; Bluesky is the stand-in)
    assert BSKY.withheld is None
    why = "Left out of this release: example."
    monkeypatch.setattr(type(BSKY), "withheld", why)
    assert BSKY.unavailable() == why and BSKY.describe()["withheld"] == why
    for saved in (None, True):
        _reset(BSKY.id)
        if saved is not None:
            scheduler._set_state(BSKY.id, enabled=saved)
        assert scheduler.is_enabled(BSKY) is False
    assert scheduler.state(BSKY.id)["enabled"] is True                 # the saved answer is kept for when it returns


def test_bluesky_saved_choices_are_kept():
    for saved in (True, False):
        _reset(BSKY.id)
        scheduler._set_state(BSKY.id, enabled=saved, status="ok")
        scheduler._apply_default_flips()
        assert scheduler.state(BSKY.id)["enabled"] is saved


# ---------------------------------------------------------------- Docker passthrough
KEYS = ["ABUSECH_AUTH_KEY", "RANSOMWARELIVE_API_KEY", "RANSOMWARELIVE_API_URL", "RANSOMWARELIVE_API_KEY_HEADER",
        "QDRANT_API_KEY", "CARTO_API_KEY"]


def _app_env() -> str:
    text = (ROOT / "docker-compose.yml").read_text()
    m = re.search(r"\n  app:\n(.*?)\n  \w+:\n", text, re.S)
    assert m
    return m.group(1)


def test_compose_passes_source_keys_to_the_app():
    app = _app_env()
    for k in KEYS:
        assert re.search(rf"^\s+{k}:(\s*\$\{{{k}:-\}})?\s*$", app, re.M), k
    # read by config.py with a non-empty default: must not be passed as an empty string
    for k in ("RANSOMWARELIVE_API_URL", "RANSOMWARELIVE_API_KEY_HEADER"):
        assert re.search(rf"^\s+{k}:\s*$", app, re.M), k


def test_every_key_the_app_reads_is_passed_and_documented():
    src = "\n".join(p.read_text() for p in (ROOT / "osinthub").rglob("*.py"))
    # credentials only (OSINTHUB_INGEST_KEY is a TLS key *file path* for the upload listener, not a credential)
    read = {k for k in re.findall(r'environ(?:\.get)?\(\s*"([A-Z_]*_(?:KEY|TOKEN|SECRET|PASSWORD))"', src)
            if not k.startswith("OSINTHUB_")}
    assert {"ABUSECH_AUTH_KEY", "RANSOMWARELIVE_API_KEY", "QDRANT_API_KEY"} <= read
    app, example = _app_env(), (ROOT / ".env.example").read_text()
    for k in read | set(KEYS):
        assert re.search(rf"^\s+{k}:", app, re.M), f"{k} not passed to the app container"
        assert re.search(rf"^#?\s*{k}=", example, re.M), f"{k} not in .env.example"


def test_env_example_hash_is_not_set_and_command_doubles_dollars():
    example = (ROOT / ".env.example").read_text()
    assert not re.search(r"^HLTA_AUTH_HASH=", example, re.M)    # appended by the by-hand command, once
    cmd = re.search(r"^#\s+(printf 'HLTA_AUTH_HASH=.*>> \.env)$", example, re.M).group(1)
    assert cmd in (ROOT / "okf" / "architecture" / "deployment.md").read_text()   # the by-hand LAN setup

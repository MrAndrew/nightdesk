"""A lake on an unmounted /Volumes drive refuses to start instead of creating an empty lake on the boot disk.

    uv run --with pytest pytest tests/security/test_paths.py -q
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from _lake import make_lake  # noqa: E402
LAKE = make_lake("mount")

from osinthub.config import unmounted_volume  # noqa: E402

GONE = "/Volumes/ND-test-not-mounted-7f3a"


def _import_config(**env) -> subprocess.CompletedProcess:
    e = {k: v for k, v in os.environ.items() if not k.startswith("OSINTHUB_")} | env
    return subprocess.run([sys.executable, "-c", "import osinthub.config"], cwd=ROOT, env=e,
                          capture_output=True, text=True, timeout=60)


def test_unmounted_volume_lake_refuses_and_creates_nothing():
    assert not os.path.exists(GONE)
    r = _import_config(OSINTHUB_LAKE=f"{GONE}/osint-hub")
    assert r.returncode != 0
    assert "not mounted" in r.stderr and GONE in r.stderr
    assert "Traceback" not in r.stderr          # a clear message, not a crash
    assert not os.path.exists(GONE)


def test_symlink_or_lowercase_path_into_unmounted_volume_refuses():
    with tempfile.TemporaryDirectory() as tmp:
        link = Path(tmp) / "lake-link"
        link.symlink_to(f"{GONE}/osint-hub")                    # a link into the missing drive
        for lake in (str(link), str(link / "sub"), GONE.replace("/Volumes/", "/volumes/") + "/osint-hub"):
            r = _import_config(OSINTHUB_LAKE=lake)
            assert r.returncode != 0 and "not mounted" in r.stderr, (lake, r.stderr[-300:])
            assert "Traceback" not in r.stderr
    assert not os.path.exists(GONE)


def test_db_on_unmounted_volume_refuses():
    with tempfile.TemporaryDirectory() as lake:
        r = _import_config(OSINTHUB_LAKE=lake, OSINTHUB_DB=f"{GONE}/hub.duckdb")
        assert r.returncode != 0 and "not mounted" in r.stderr
        assert not (Path(lake) / "raw").exists()   # refused before any folder was made


def test_normal_missing_path_is_still_created():
    with tempfile.TemporaryDirectory() as tmp:
        lake = Path(tmp) / "new" / "lake"
        r = _import_config(OSINTHUB_LAKE=str(lake))
        assert r.returncode == 0, r.stderr
        for d in ("raw", "ref", "uploads", "tmp", "db"):
            assert (lake / d).is_dir()


def test_unmounted_volume_helper():
    with tempfile.TemporaryDirectory() as vols:
        v = Path(vols)
        (v / "Stale").mkdir()                       # a plain folder left where the drive used to mount
        assert unmounted_volume(v / "Stale" / "osint-hub", volumes=v) == v / "Stale"
        assert unmounted_volume(v / "Missing" / "x", volumes=v) == v / "Missing"
        (v / "link").symlink_to(v / "Stale" / "deep")          # a link resolving into the stale volume
        assert unmounted_volume(v / "link", volumes=v) == v / "Stale"
        assert unmounted_volume(v, volumes=v) is None
    assert unmounted_volume(Path("/tmp/somewhere")) is None
    assert unmounted_volume(Path("/Users/x/lake")) is None
    if os.path.exists("/Volumes/Macintosh HD"):        # macOS: a symlink to /, which is mounted
        assert unmounted_volume(Path("/Volumes/Macintosh HD/Users/x/lake")) is None

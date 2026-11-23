"""Where the data lake lives, and moving it (Settings › Data › Change…).

The lake is, in this order: OSINTHUB_LAKE (also set by `nightdesk --lake`); else the folder chosen in Settings (one
line in the file `lake-folder` in the config folder); else this computer's app-data folder (default_lake).

The config folder is outside every lake, so deleting an old data folder never loses the choice: ~/.config/nightdesk
(macOS and Linux; $XDG_CONFIG_HOME/nightdesk when set) or %APPDATA%\\Night Desk (Windows).

A move happens at the next start, before the database opens: Settings writes `lake-move.json` (from, to), the app
restarts itself (osinthub/__main__.py), copies the lake into the new folder, checks that every file arrived with its
size, and only then points `lake-folder` at it. The old folder is left exactly as it was; the result goes to
`lake-move-result.json`, which Settings shows once. If anything fails, the app starts on the old folder.

This module imports nothing else from osinthub at import time (config imports it).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import shutil
import sys
import threading
from pathlib import Path

log = logging.getLogger("osinthub.lakeloc")

# Set by osinthub/__main__.py: the running uvicorn server, so a move can stop it and the process can start again.
SERVER = None
restart_requested = threading.Event()


def default_lake() -> Path:
    """The platform's folder for app data: ~/Library/Application Support/Night Desk (macOS), %LOCALAPPDATA%\\\\Night Desk
    (Windows), $XDG_DATA_HOME/nightdesk or ~/.local/share/nightdesk (Linux and others)."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Night Desk"
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "Night Desk"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "nightdesk"


def config_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "Night Desk"
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "nightdesk"


def _f(name: str) -> Path:
    return config_dir() / name


def chosen() -> Path | None:
    """The folder chosen in Settings, or None."""
    try:
        line = _f("lake-folder").read_text().strip()
    except OSError:
        return None
    return Path(line) if line else None


def resolve() -> tuple[Path, str]:
    """(the lake, where that came from: "env" | "chosen" | "default")."""
    if os.environ.get("OSINTHUB_LAKE"):
        return Path(os.environ["OSINTHUB_LAKE"]), "env"
    if (c := chosen()) is not None:
        return c, "chosen"
    return default_lake(), "default"


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, p)


def _read_json(name: str) -> dict | None:
    try:
        return json.loads(_f(name).read_text())
    except (OSError, ValueError):
        return None


def pending() -> dict | None:
    return _read_json("lake-move.json")


def last_result() -> dict | None:
    return _read_json("lake-move-result.json")


def clear_result() -> None:
    _f("lake-move-result.json").unlink(missing_ok=True)


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


# ------------------------------------------------------------------ checking a new folder
_SYSTEM = ("/System", "/bin", "/sbin", "/etc", "/private/etc", "/dev", "/proc", "/sys", "/usr", "/var/db",
           "/Library", "/Applications", "/boot", "/lib", "/opt/homebrew", "C:\\Windows", "C:\\Program Files")


def _inside(a: Path, b: Path) -> bool:
    """a is b or inside b."""
    return a == b or b in a.parents


def tree_size(root: Path) -> tuple[int, int]:
    """(files, bytes) under root."""
    n = b = 0
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            try:
                b += os.lstat(os.path.join(dirpath, name)).st_size
                n += 1
            except OSError:
                pass
    return n, b


def check_target(raw: str, current: Path, need_bytes: int) -> Path:
    """The new folder as an absolute path, or ValueError with a plain reason the page shows as it is."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Type the folder to move the data to.")
    p = Path(os.path.expanduser(raw))
    if not p.is_absolute():
        raise ValueError("Give the full path of the folder, starting with / (or ~ for your home folder).")
    p = Path(os.path.abspath(p))
    real, cur = Path(os.path.realpath(p)), Path(os.path.realpath(current))
    home = Path(os.path.realpath(Path.home()))
    if real in (Path(real.anchor), home) or any(_inside(real, Path(os.path.realpath(s))) for s in _SYSTEM if Path(s).exists()):
        raise ValueError("Choose a folder of its own, not a system folder, the top of a drive or your home folder itself.")
    if real == cur:
        raise ValueError("That is the folder Night Desk already uses.")
    if _inside(real, cur):
        raise ValueError("The new folder cannot be inside the current data folder.")
    if _inside(cur, real):
        raise ValueError("The new folder cannot contain the current data folder.")
    from .config import unmounted_volume
    if (vol := unmounted_volume(p)) is not None:
        raise ValueError(f"{vol} is not connected. Connect the drive first.")
    if p.exists():
        if not p.is_dir():
            raise ValueError("That is a file, not a folder.")
        if any(x.name not in (".DS_Store",) for x in p.iterdir()):
            raise ValueError("That folder is not empty. Choose a new or empty folder, so nothing in it is mixed up "
                             "with Night Desk's data.")
    base = p
    while not base.exists():
        base = base.parent
    if not os.access(base, os.W_OK):
        raise ValueError(f"Night Desk cannot write in {base}.")
    free = shutil.disk_usage(base).free
    need = int(need_bytes * 1.1) + 200 * 1024 * 1024
    if free < need:
        gb = lambda x: f"{x / 1024 ** 3:.1f} GB"
        raise ValueError(f"Not enough free space there: the data needs about {gb(need)}, and {gb(free)} is free.")
    return p


def request_move(src: Path, dst: Path) -> None:
    _write(_f("lake-move.json"), json.dumps({"from": str(src), "to": str(dst), "at": _now()}))
    clear_result()


# ------------------------------------------------------------------ the move itself (at start, before the database)
def run_pending_move() -> dict | None:
    """Do a move Settings asked for. Returns the result (also saved for Settings), or None when there was none."""
    job = pending()
    if not job:
        return None
    src, dst = Path(job["from"]), Path(job["to"])
    res = {"from": str(src), "to": str(dst), "asked": job.get("at"), "at": _now()}
    try:
        if os.environ.get("OSINTHUB_LAKE"):
            raise RuntimeError("the data folder is set by the start command (OSINTHUB_LAKE or --lake), so it was "
                               "not changed")
        if Path(os.path.realpath(resolve()[0])) != Path(os.path.realpath(src)):
            raise RuntimeError(f"the data folder is no longer {src}")
        if dst.exists() and any(x.name != ".DS_Store" for x in dst.iterdir()):
            raise RuntimeError(f"{dst} is no longer empty")
        files, size = tree_size(src)
        log.warning("moving the data folder: copying %d files (%.1f GB) from %s to %s; the app starts when it is done",
                    files, size / 1024 ** 3, src, dst)
        dst.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
        got = tree_size(dst)
        if got != (files, size):
            raise RuntimeError(f"the copy is incomplete ({got[0]} of {files} files, {got[1]} of {size} bytes)")
        _write(_f("lake-folder"), str(dst) + "\n")
        res.update(ok=True, files=files, bytes=size)
        log.warning("data folder moved to %s; the old folder %s is unchanged", dst, src)
    except Exception as e:
        res.update(ok=False, error=str(e))
        log.error("the data folder was not moved: %s; starting on %s", e, src)
    _f("lake-move.json").unlink(missing_ok=True)
    _write(_f("lake-move-result.json"), json.dumps(res))
    return res


# ------------------------------------------------------------------ restarting
def can_restart() -> bool:
    """True when Night Desk was started by its own command (`nightdesk`, `python -m osinthub`), which can start again."""
    return SERVER is not None


def schedule_restart(delay: float = 0.5) -> None:
    """Stop the server shortly (after the current answer is sent); __main__ then starts the process again."""
    def go():
        restart_requested.set()
        if SERVER is not None:
            SERVER.should_exit = True
    threading.Timer(delay, go).start()

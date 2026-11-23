"""Small shared helpers: bulk loads through scratch files, settings, the netlog lock."""
from __future__ import annotations

import datetime as dt
import json
import logging
import math
import os
import threading
import uuid
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from .. import config, db

log = logging.getLogger("osinthub.netlog")
UTC = dt.UTC
LOCK = threading.RLock()          # serialises import / re-hunt / interval updates
SETTINGS_KEY = "netlog"
DEFAULTS: dict[str, Any] = {
    "home_prefixes": [],          # empty: private ranges plus the suggested /24 and /64
    "grace_seconds": 0,           # a row this long before an interval's start still matches
    "rehunt_days": 30,            # how far back re-hunting goes when threat data changes
    "inbox_poll_seconds": 15,
    "ti_poll_seconds": 60,
    "stale_hours": 24,            # logs with nothing newer than this are called stale (okf/data/netlog.md#freshness)
    "p2p_cap": True,              # lower list hits (except C2) inside P2P swarms to low; see netlog.md
    "suricata": {"suppress": [], "severity": {}},   # signature tuning by signature_id
}
# Allowed range of each numeric setting (inclusive). A PUT outside it is a 400. A stored value outside it (saved
# by an older version) is read back by fit(): above the range is clamped to the top, anything else is the default.
NUMERIC: dict[str, tuple[float, float]] = {
    "grace_seconds": (0, 365 * 86400),
    "rehunt_days": (1, 36500),
    "inbox_poll_seconds": (1, 86400),
    "ti_poll_seconds": (1, 86400),
    "stale_hours": (1, 24 * 365),
}


def number(v: Any, lo: float, hi: float) -> float | None:
    """v as a float within [lo, hi], or None if it is not a finite number (true/false are not numbers) or out of range."""
    if isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError, OverflowError):
        return None
    return f if math.isfinite(f) and lo <= f <= hi else None


def q(path: Path | str) -> str:
    return str(path).replace("'", "''")


def now() -> dt.datetime:
    return dt.datetime.now(UTC)


def unique_prefixes(prefs) -> list[str]:
    """Prefixes normalised (203.0.113.7/24 -> 203.0.113.0/24) and de-duplicated, in order."""
    from .ipnum import net_range
    out: list[str] = []
    for p in prefs or []:
        r = net_range(str(p))
        n = r[2] if r else str(p)
        if n not in out:
            out.append(n)
    return out


def settings() -> dict:
    s = {**DEFAULTS, **(db.get_setting(SETTINGS_KEY) or {})}
    s["home_prefixes"] = unique_prefixes(s.get("home_prefixes"))  # older saves may hold duplicates
    for k in NUMERIC:  # older saves may hold Infinity, NaN, true, 0 or absurd numbers
        s[k] = fit(k, s.get(k))
    return s


def fit(k: str, v: Any) -> float:
    """A numeric setting as used: v when in range, the top of the range when above it, else the default. Older
    builds saved 0 for NaN or negative input; 0 polls or 0 re-hunt days mean the default, as they always did."""
    lo, hi = NUMERIC[k]
    f = number(v, -math.inf, math.inf)
    if f is None or f < lo:
        return float(DEFAULTS[k])
    return min(f, hi)


def save_settings(s: dict) -> None:
    db.set_setting(SETTINGS_KEY, {k: s[k] for k in DEFAULTS if k in s})


# ------------------------------------------------------------------ the watched inbox (okf/data/netlog.md#inbox)
# Kept under its own settings key so saving the inbox never rebuilds devices or re-hunts (PUT /api/netlog/settings does).
INBOX_KEY = "netlog_inbox"
INBOX_ENV = "OSINTHUB_INBOX"


def default_inbox() -> Path:
    return config.LAKE / "inbox" / "zeek"


# Every "inside", "contains" and "is" check below compares filesystem identity, (st_dev, st_ino) of directories, never
# path strings: a case-insensitive or normalisation-insensitive volume (APFS) opens /Users as /USERS and é as e+U+0301.
Ident = tuple[int, int]
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def ident_of(st: os.stat_result) -> Ident:
    return (st.st_dev, st.st_ino)


def ident(path: str | Path) -> Ident | None:
    try:
        return ident_of(os.stat(path))
    except OSError:
        return None


def ancestry_fd(fd: int) -> list[Ident]:
    """The identity of the directory open as fd, then of each real parent up to the root (".." from the fd itself, so
    no name is ever looked up again)."""
    out = [ident_of(os.fstat(fd))]
    cur = os.dup(fd)
    try:
        while True:
            parent = os.open("..", DIR_FLAGS, dir_fd=cur)
            os.close(cur)
            cur = parent
            i = ident_of(os.fstat(cur))
            if i == out[-1]:
                return out
            out.append(i)
    finally:
        os.close(cur)


def ancestry(path: str | Path) -> list[Ident]:
    fd = os.open(path, DIR_FLAGS)
    try:
        return ancestry_fd(fd)
    finally:
        os.close(fd)


def default_inbox_ident() -> Ident | None:
    """<lake>/inbox/zeek, reached from the lake without following any link: the one part of the lake an inbox may be."""
    fds: list[int] = []
    try:
        fds.append(os.open(config.LAKE, DIR_FLAGS))
        for part in ("inbox", "zeek"):
            fds.append(os.open(part, DIR_FLAGS | NOFOLLOW, dir_fd=fds[-1]))
        return ident_of(os.fstat(fds[-1]))
    except OSError:
        return None
    finally:
        for fd in fds:
            os.close(fd)


def protected_idents() -> set[Ident]:
    """Folders a walk of the inbox must never enter: the lake, every folder directly in it (raw, db, tmp, ref, uploads,
    inbox, ...), the device-upload spool and the database folder."""
    out: set[Ident] = set()
    for p in (config.LAKE, config.LAKE / "inbox" / "push", config.DB_PATH.parent):
        i = ident(p)
        if i:
            out.add(i)
    try:
        with os.scandir(config.LAKE) as it:
            for e in it:
                if e.is_dir(follow_symlinks=False):
                    out.add(ident_of(e.stat(follow_symlinks=False)))
    except OSError:
        pass
    return out


# Folders that are never an inbox: the folder itself (a disk, all users, a system folder) or, for the TREE ones, anything in it.
SYSTEM_EXACT = ("/Users", "/Volumes", "/private", "/usr", "/opt", "/Applications", "/Library", "/var", "/tmp",
                "/private/tmp", "/private/var", "/home", "/root", "/mnt", "/media", "/srv")
SYSTEM_TREE = ("/System", "/bin", "/sbin", "/etc", "/private/etc", "/dev", "/proc", "/sys", "/usr/bin", "/usr/sbin",
               "/usr/lib", "/Library/Keychains")


def _refuse(why: str, hint: str = "Pick the folder your log files are copied into.") -> ValueError:
    e = ValueError(f"{why} {hint}".strip())
    e.why = why            # the reason alone, for OSINTHUB_INBOX (whose fix is not in the app)
    return e


def check_inbox_fd(fd: int) -> None:
    """Raise ValueError unless the directory open as fd may be an inbox, by identity: not the root, the home folder, a
    system folder or in one; not in the lake (unless in its default inbox subtree), not containing the lake."""
    anc = ancestry_fd(fd)
    me = anc[0]
    if me == anc[-1]:
        raise _refuse("That is the top of the disk.")
    home = ident(os.path.expanduser("~"))
    if home and me == home:
        raise _refuse("That is your whole home folder.")
    exact = {i for i in map(ident, SYSTEM_EXACT) if i}
    tree = {i for i in map(ident, SYSTEM_TREE) if i}
    if me in exact or tree.intersection(anc):
        raise _refuse("That is a system folder.")
    dflt = default_inbox_ident()
    own = [i for i in (ident(config.LAKE), ident(config.DB_PATH.parent)) if i]
    if not (dflt and dflt in anc) and set(own).intersection(anc):
        raise _refuse("That folder is part of Night Desk's own data (the lake).",
                      "Use the default inbox folder or a folder outside the lake.")
    for p in (config.LAKE, config.DB_PATH.parent):
        try:
            if me in ancestry(p):
                raise _refuse("That folder contains Night Desk's own data (the lake).")
        except OSError:
            pass


def check_inbox_dir(value: Any) -> str:
    """The folder resolved (~ expanded, links followed, `..` applied after links) and checked by identity
    (check_inbox_fd), which is what is saved and scanned; or ValueError with a message a person can act on.
    Reference: okf/data/netlog.md#inbox-folder"""
    if not isinstance(value, str) or not value.strip():
        raise _refuse("Enter the full path of a folder.", "")
    p = os.path.expanduser(value.strip())
    if not os.path.isabs(p):
        raise _refuse("Use the full path of the folder, starting with / (for example /Users/you/zeek-logs).", "")
    real = os.path.realpath(p)
    if not os.path.exists(real):
        raise _refuse("There is no folder at that path.", "Create it first, or check the spelling.")
    if not os.path.isdir(real):
        raise _refuse("That path is a file, not a folder.", "")
    try:
        fd = os.open(real, DIR_FLAGS)
    except OSError:
        raise _refuse("Night Desk is not allowed to read that folder.", "Check its permissions.")
    try:
        check_inbox_fd(fd)
    finally:
        os.close(fd)
    if not os.access(real, os.R_OK | os.X_OK):
        raise _refuse("Night Desk is not allowed to read that folder.", "Check its permissions.")
    return real


def inbox_settings() -> dict:
    """{path, default_path, is_default, from_env, delete_after_import, problem}. The folder in effect is OSINTHUB_INBOX,
    else the saved folder, else <lake>/inbox/zeek, and it is checked (check_inbox_dir) every time it is read, so a value
    that fails (an env value into the lake, a link re-pointed after saving) gives `problem` and is never scanned.
    Deleting after import is off unless the user turned it on."""
    saved = db.get_setting(INBOX_KEY) or {}
    env = os.environ.get(INBOX_ENV, "").strip()
    chosen = env or (saved.get("path") if isinstance(saved.get("path"), str) else "") or ""
    if not chosen:
        chosen = str(default_inbox())
        try:
            default_inbox().mkdir(parents=True, exist_ok=True)   # the default folder is created when missing
        except OSError:
            pass
    try:
        path, problem = check_inbox_dir(chosen), None
    except ValueError as e:
        path = chosen
        problem = (f"OSINTHUB_INBOX is set to a folder Night Desk will not use: {getattr(e, 'why', str(e))} "
                   "Change OSINTHUB_INBOX where Night Desk is started and restart it.") if env else str(e)
    dflt = default_inbox_ident()
    return {"path": path, "default_path": str(default_inbox()), "is_default": bool(dflt) and ident(path) == dflt,
            "from_env": bool(env), "delete_after_import": saved.get("delete_after_import") is True, "problem": problem}


def save_inbox_settings(path: str | None = None, delete_after_import: bool | None = None) -> None:
    saved = dict(db.get_setting(INBOX_KEY) or {})
    if path is not None:
        dflt = default_inbox_ident()
        saved["path"] = None if dflt and ident(path) == dflt else path
    if delete_after_import is not None:
        saved["delete_after_import"] = bool(delete_after_import)
    db.set_setting(INBOX_KEY, saved)


def scratch(name: str, ext: str = "ndjson") -> Path:
    d = config.TMP_DIR / "netlog"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{name}-{os.getpid()}-{uuid.uuid4().hex[:8]}.{ext}"


def write_ndjson(path: Path, rows: Iterable[dict]) -> int:
    n = 0
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, default=str) + "\n")
            n += 1
    return n


def read_src(path: Path, columns: dict[str, str]) -> str:
    cols = ", ".join(f"'{k}': '{v}'" for k, v in columns.items())
    return f"read_json('{q(path)}', format='newline_delimited', columns={{{cols}}})"


def rows_of(cur, sql: str, params: list | tuple = ()) -> list[dict]:
    res = cur.execute(sql, params)
    cols = [d[0] for d in res.description]
    return [dict(zip(cols, r)) for r in res.fetchall()]


def jsonable(v: Any) -> Any:
    if isinstance(v, dt.datetime):
        return v.isoformat()
    if isinstance(v, list):
        return [jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: jsonable(x) for k, x in v.items()}
    return v


def publish_alerts(payload: dict) -> None:
    """Best-effort publish of a netlog alert refresh to the SSE bus; a failure here never breaks the caller."""
    try:
        from .. import bus
        bus.publish("netlog_alerts", payload)
    except Exception:
        log.debug("netlog: alert publish failed", exc_info=True)

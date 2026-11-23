"""Lake file management: record deltas, hourly stream files and optional retention.

Layout and policy: okf/data/architecture.md
"""
from __future__ import annotations

import datetime as dt
import gzip
import json
import shutil
from pathlib import Path
from typing import Any

from . import config, db

UTC = dt.UTC
STREAM_TMP = config.TMP_DIR / "streams"


def _day_dir(source_id: str, ts: dt.datetime) -> Path:
    return config.RAW_DIR / source_id / ts.strftime("%Y/%m/%d")


# ------------------------------------------------------------------ batch record deltas
def write_records(path: Path, puts: list[tuple[str, Any]], dels: list[str]) -> None:
    """One gzipped NDJSON line per new/changed record ({"key", "op": "put", "data"}) or removal ({"key", "op": "del"})."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", compresslevel=6) as fh:
        for k, rec in puts:
            fh.write(json.dumps({"key": k, "op": "put", "data": rec}, default=str) + "\n")
        for k in dels:
            fh.write(json.dumps({"key": k, "op": "del"}) + "\n")


# ------------------------------------------------------------------ hourly stream files
def stream_hour_path(source_id: str, ts: dt.datetime) -> Path:
    """Final location of a stream's events for the hour containing ts."""
    return _day_dir(source_id, ts) / f"{ts.strftime('%H')}.events.ndjson.gz"


def append_stream(source_id: str, rows: list[dict], ts: dt.datetime) -> None:
    """Append rows to the open hour's plain NDJSON in tmp/; it is gzipped when the hour closes."""
    d = STREAM_TMP / source_id
    d.mkdir(parents=True, exist_ok=True)
    with (d / f"{ts.strftime('%Y%m%d%H')}.ndjson").open("a") as fh:
        for r in rows:
            fh.write(json.dumps(r, default=str) + "\n")


def _merge_into(target: Path, lines: list[str]) -> None:
    """Write lines into a gzipped hourly file, merging with what is there and keeping the last row per id."""
    by_id: dict[str, str] = {}
    if target.exists():
        with gzip.open(target, "rt") as fh:
            for line in fh:
                if line.strip():
                    by_id[json.loads(line)["id"]] = line.rstrip("\n")
    for line in lines:
        if line.strip():
            by_id[json.loads(line)["id"]] = line.rstrip("\n")
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + ".part")
    with gzip.open(part, "wt", compresslevel=6) as fh:
        for line in by_id.values():
            fh.write(line + "\n")
    part.replace(target)


def finalize_streams(now: dt.datetime | None = None) -> int:
    """Gzip every closed hour of stream data into the lake. Returns files finalized."""
    now = now or dt.datetime.now(UTC)
    current = now.strftime("%Y%m%d%H")
    n = 0
    if not STREAM_TMP.exists():
        return 0
    for f in sorted(STREAM_TMP.glob("*/*.ndjson")):
        if f.stem >= current:
            continue
        hour = dt.datetime.strptime(f.stem, "%Y%m%d%H").replace(tzinfo=UTC)
        _merge_into(stream_hour_path(f.parent.name, hour), f.read_text().splitlines())
        f.unlink()
        n += 1
    return n


# ------------------------------------------------------------------ retention (off unless the user sets it)
RETENTION_KEY = "retention"
DEFAULT_RETENTION = {"lake_days": None, "db_days": None}
_last_purge: dict = {}


def retention() -> dict:
    return {**DEFAULT_RETENTION, **(db.get_setting(RETENTION_KEY) or {})}


def last_purge() -> dict:
    return dict(_last_purge)


def purge(now: dt.datetime | None = None) -> dict:
    """Apply the user's retention settings. Does nothing while both are unset (the default)."""
    now = now or dt.datetime.now(UTC)
    r = retention()
    out: dict[str, Any] = {"at": now.isoformat(), "lake_days": r["lake_days"], "db_days": r["db_days"],
                           "lake_files": 0, "lake_bytes": 0, "events": 0}
    if r["lake_days"]:
        first_kept = (now - dt.timedelta(days=int(r["lake_days"]))).date()
        for src_dir in (p for p in config.RAW_DIR.iterdir() if p.is_dir()):
            for day in sorted(src_dir.glob("*/*/*")):
                try:
                    d = dt.date(int(day.parent.parent.name), int(day.parent.name), int(day.name))
                except ValueError:
                    continue
                if d >= first_kept:
                    continue
                for f in day.rglob("*"):
                    if f.is_file():
                        out["lake_files"] += 1
                        out["lake_bytes"] += f.stat().st_size
                shutil.rmtree(day)
            for empty in sorted(src_dir.glob("*/*"), reverse=True) + sorted(src_dir.glob("*")):
                if empty.is_dir() and not any(empty.iterdir()):
                    empty.rmdir()
        cutoff = dt.datetime.combine(first_kept, dt.time(), UTC)
        # Records and events last stored before the cutoff are no longer in the lake. Forget their
        # hashes so the next run stores them again, keeping the lake self-contained for its window.
        db.execute("DELETE FROM record_hashes WHERE stored_at < ?", [cutoff])
        db.execute("UPDATE events SET content_hash = NULL WHERE stored_at < ?", [cutoff])
    if r["db_days"]:
        cutoff = now - dt.timedelta(days=int(r["db_days"]))
        out["events"] = db.query("SELECT count(*) AS n FROM events WHERE ingested_at < ?", [cutoff])[0]["n"]
        db.execute("DELETE FROM events WHERE ingested_at < ?", [cutoff])
        db.execute("DELETE FROM runs WHERE started < ?", [cutoff])
        db.execute("DELETE FROM metrics WHERE ts < ?", [cutoff])
        db.execute("CHECKPOINT")
    _last_purge.clear()
    _last_purge.update(out)
    return out

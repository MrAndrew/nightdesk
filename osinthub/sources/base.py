"""Source plugin contract and event model. Pipeline: okf/data/architecture.md"""
from __future__ import annotations

import asyncio
import datetime as dt
import email.utils
import gzip
import hashlib
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

import httpx

from .. import config, geo

UTC = dt.UTC
log = logging.getLogger("osinthub.sources")


def now() -> dt.datetime:
    return dt.datetime.now(UTC)


_TS_WARNED: set[str] = set()


def _epoch(x: float) -> dt.datetime:
    """Seconds, or milliseconds / microseconds when the number is too large to be seconds."""
    for scale in (1, 1e3, 1e6, 1e9):
        if abs(x) / scale < 1e11:  # 1e11 s is year 5138: anything above is a finer unit
            return dt.datetime.fromtimestamp(x / scale, UTC)
    raise ValueError(f"epoch out of range: {x}")


def to_ts(v: Any) -> dt.datetime:
    """Best-effort timestamp parse to aware UTC datetime.

    Missing values become now(), which content_hash() treats as app-stamped. ISO 8601, RFC 822
    (any zone, including GMT), epoch seconds / milliseconds / microseconds (numbers or numeric
    strings) parse to their real time. Anything else also falls back to now() so one odd record
    does not fail a batch, and is logged once per shape."""
    if v is None or v == "":
        return now()
    if isinstance(v, dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    try:
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return _epoch(float(v))
        s = str(v).strip()
        if re.fullmatch(r"\d{9,}(\.\d+)?", s):  # 8 digits and fewer are dates (20261103), not epochs
            return _epoch(float(s))
    except (ValueError, OverflowError, OSError):
        pass
    else:
        s2 = s.replace("Z", "+00:00")
        for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d"):
            try:
                d = dt.datetime.fromisoformat(s2) if fmt is None else dt.datetime.strptime(s2, fmt)
                return d if d.tzinfo else d.replace(tzinfo=UTC)
            except ValueError:
                continue
        try:
            d = email.utils.parsedate_to_datetime(s)
            return d if d.tzinfo else d.replace(tzinfo=UTC)
        except (TypeError, ValueError, IndexError):
            pass
    shape = re.sub(r"\d", "9", str(v))[:40]
    if shape not in _TS_WARNED and len(_TS_WARNED) < 100:
        _TS_WARNED.add(shape)
        log.warning("unparseable timestamp %r: using the collection time", str(v)[:80])
    return now()


class Unchanged(Exception):
    """Raised by fetch() when the provider says nothing changed since the last run (an HTTP 304, or a
    daily file already loaded). The run is recorded as ok with nothing loaded; no full download happens."""


class Paused(Exception):
    """Raised by fetch() when the source must not fetch right now (the routing watch's daily data limit is used
    up). The source shows as paused with the message; no run is recorded and nothing is fetched."""


def make_id(source: str, *parts: Any) -> str:
    h = hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]
    return f"{source}:{h}"


@dataclass
class Event:
    source: str
    kind: str
    key: tuple
    ts: dt.datetime
    title: str
    summary: str | None = None
    category: str | None = None
    severity: float | None = None  # 0..1
    lat: float | None = None
    lon: float | None = None
    country: str | None = None
    city: str | None = None
    ip: str | None = None
    asn: str | None = None
    url: str | None = None
    tags: list[str] = field(default_factory=list)
    value: float | None = None

    def __post_init__(self):
        # one spelling per address, whatever the feed wrote (2001:DB8:0:0::5 is 2001:db8::5), so the same address from
        # two feeds is one address in every lookup; anything that is not a single address is kept as the feed sent it
        if self.ip:
            try:
                self.ip = str(ipaddress.ip_address(self.ip.strip()))
            except ValueError:
                pass

    def geolocate(self) -> Event:
        if self.ip and self.lat is None:
            g = geo.locate_ip(self.ip)
            if g:
                self.lat, self.lon = g["lat"], g["lon"]
                self.country = self.country or g["country"]
                self.city = self.city or g["city"]
        if self.ip and not self.asn:
            a = geo.asn_for_ip(self.ip)
            if a:
                self.asn = a[0]
                if a[1] and f"org:{a[1]}" not in self.tags:
                    self.tags = [*self.tags, f"org:{a[1]}"]
        if self.lat is None and self.country:
            c = geo.countries().get(self.country)
            if c:
                self.lat, self.lon = c["lat"], c["lon"]
        return self

    def to_row(self, raw_path: str | None) -> dict:
        return {
            "id": make_id(self.source, *self.key),
            "source": self.source,
            "kind": self.kind,
            "category": self.category,
            "ts": self.ts.astimezone(UTC).isoformat(),
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "lat": self.lat,
            "lon": self.lon,
            "country": self.country,
            "city": self.city,
            "ip": self.ip,
            "asn": self.asn,
            "url": self.url,
            "tags": self.tags,
            "value": self.value,
            "raw_path": raw_path,
        }



def key_steps() -> str:
    """Where a source key goes on this install, in plain words for primary text (the variable's name belongs in a
    hover title or Technical details). Docker Compose reads the install folder's .env when the install line runs; a
    native run never reads .env, only the environment that starts it."""
    from ..netlog.ingest import in_docker
    if in_docker():
        return "add it to the .env file in Night Desk's install folder and run the install line again"
    return "set it in the environment that starts Night Desk (your shell or service) and restart Night Desk"

class Source:
    """Subclass and register with @register. Batch sources implement fetch()+parse(); streams implement stream()."""

    id: ClassVar[str]
    name: ClassVar[str]
    provider: ClassVar[str]
    homepage: ClassVar[str] = ""
    description: ClassVar[str] = ""
    category: ClassVar[str] = "threat"  # threat | vuln | infra | news | custom
    mode: ClassVar[str] = "batch"  # batch | stream
    interval: ClassVar[int] = 3600  # seconds between batch runs
    default_enabled: ClassVar[bool] = True
    license: ClassVar[str] = ""
    raw_ext: ClassVar[str] = "json"
    # True when each fetch is a sliding window (records age out); False for lists, where a
    # record that disappears was removed by the provider and the removal is stored.
    windowed: ClassVar[bool] = True
    # Env var holding the API key this source needs, if any. With no key the source is never started
    # or fetched, and the Sources page shows unavailable() instead of an error.
    needs_key: ClassVar[str | None] = None
    # False when the provider's terms forbid using the data with AI models: the source's events, records
    # and the claims they create stay out of every LLM prompt and embedding.
    ai_ok: ClassVar[bool] = True
    # Why the source is left out of this release (its terms ask for something not built yet), else None. A withheld
    # source is never started or fetched, is not offered in "Choose your sources", and says why in Sources.
    withheld: ClassVar[str | None] = None

    def unavailable(self) -> str | None:
        """Why the source cannot run at all (left out of this release, or a missing key), else None."""
        return self.withheld

    def paused_now(self) -> str | None:
        """Optional: after a run, why the source is now paused (the routing data limit was reached), else None."""
        return None

    def jitter(self) -> float:
        """Optional: extra seconds added to each wait between scheduled runs (spreads requests out)."""
        return 0.0

    # ---- batch contract -------------------------------------------------
    async def fetch(self, client: httpx.AsyncClient) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def parse(self, raw: bytes) -> list[Event]:  # pragma: no cover
        raise NotImplementedError

    def prepare(self, raw: bytes, collected_at: dt.datetime) -> None:
        """Optional: idempotent side-table writes that must exist before the run's events are linked (CISA
        advisories' CVE rows). Runs after fetch, before parse(). Anything that gates the next fetch belongs in
        commit() instead."""

    def commit(self, raw: bytes, collected_at: dt.datetime) -> None:
        """Optional: update the source's own side tables from a payload. Runs last, only after the lake delta,
        the record hashes and the event load succeeded, so a failed run leaves the tables as they were and a retry
        reloads (EPSS keeps its latest-score table, CISA advisories their CVE rows)."""

    def stored_count(self) -> int | None:
        """Optional: how many items the source holds, when that is not its event count (EPSS keeps scores in its
        own table and makes no events). Shown as the source's total on the Sources page."""
        return None

    def fetch_errors(self, raw: bytes) -> list[str]:
        """Parts of a payload that failed to fetch (one dead feed of several). The run still
        loads the rest, but the source is marked as erroring and the run keeps the text."""
        return []

    def unseen(self, raw: bytes):
        """For a payload with fetch_errors: a predicate on record keys, True for a key that may belong to a part
        that failed. Such a record was not seen (not changed, not removed), so its stored hash is kept; other
        missing keys age out or are removed as usual. The default cannot tell, so it keeps every key."""
        return lambda key: True

    def records(self, raw: bytes) -> list[tuple[str, Any]]:
        """Split a payload into (key, record) pairs so only new or changed records are stored.

        The default treats the whole payload as one record, so it is stored only when it changes.
        """
        return [("payload", raw.decode("utf-8", "replace"))]

    # ---- stream contract ------------------------------------------------
    async def stream(self, sink: StreamSink) -> None:  # pragma: no cover
        raise NotImplementedError

    def describe(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "homepage": self.homepage,
            "description": self.description,
            "category": self.category,
            "mode": self.mode,
            "interval": self.interval,
            "license": self.license,
            "default_enabled": self.default_enabled,
            "needs_key": self.needs_key,
            "unavailable": self.unavailable(),
            "ai_ok": self.ai_ok,
            "withheld": self.withheld,
        }


def raw_path_for(source_id: str, ext: str, ts: dt.datetime | None = None) -> Path:
    ts = ts or now()
    d = config.RAW_DIR / source_id / ts.strftime("%Y/%m/%d")
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{ts.strftime('%H%M%S')}.{ext}"


def write_raw(path: Path, raw: bytes) -> Path:
    """Store a raw payload gzip-compressed (path should end in .gz)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(raw, compresslevel=6, mtime=0))
    return path


def content_hash(ev: Event, collected_at: dt.datetime) -> str:
    """Hash of an event's content, used to store only new or changed events.

    Timestamps at or after collection time were stamped by the app, not the provider,
    so they are left out; otherwise an unchanged list entry would always look new.
    """
    r = ev.to_row(None)
    if ev.ts >= collected_at - dt.timedelta(seconds=1):
        r.pop("ts")
    return hashlib.sha256(json.dumps(r, sort_keys=True, default=str).encode()).hexdigest()[:32]


ROW_KEYS = ("id", "source", "kind", "category", "ts", "title", "summary", "severity", "lat", "lon", "country", "city",
            "ip", "asn", "url", "tags", "value", "raw_path")   # Event.to_row()'s keys


def stored_content_hash(row: dict, collected_at: dt.datetime) -> str:
    """content_hash() of an event as it is stored in DuckDB (a row with every to_row() column), for a row whose text
    was changed in place (sources/text.py fix_encoded_events): the hash parse() gives that event today, so the
    entity linker relinks it once and a later run that parses the same item does not count it as changed."""
    ts = row["ts"]
    ts = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    r = {k: row.get(k) for k in ROW_KEYS}
    r["raw_path"] = None
    r["tags"] = list(r["tags"]) if r["tags"] is not None else []
    r["ts"] = ts.astimezone(UTC).isoformat()
    if ts >= collected_at - dt.timedelta(seconds=1):
        r.pop("ts")
    return hashlib.sha256(json.dumps(r, sort_keys=True, default=str).encode()).hexdigest()[:32]


def record_hash(rec: Any) -> str:
    return hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest()[:32]


class StreamSink:
    """Handed to stream sources. Buffers events and flushes them to lake+DB periodically."""

    def __init__(self, source: Source, on_flush):
        self.source = source
        self._buf: list[Event] = []
        self._on_flush = on_flush

    def emit(self, ev: Event) -> None:
        self._buf.append(ev)

    async def metric(self, name: str, value: float) -> None:
        from .. import bus, db
        await asyncio.to_thread(db.record_metric, name, value)   # the write waits for db._write_lock: off the loop
        bus.publish("metric", {"name": name, "value": value, "ts": now().isoformat()})

    def drain(self) -> list[Event]:
        buf, self._buf = self._buf, []
        return buf

    async def flush(self) -> None:
        evs = self.drain()
        if evs:
            await self._on_flush(self.source, evs)

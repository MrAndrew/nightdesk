"""User-supplied batch files (CSV / JSON / NDJSON / plain IP list) ingested through DuckDB."""
from __future__ import annotations

import gzip
import itertools
import json
import re
import shutil
import tempfile
from pathlib import Path

import duckdb

from .base import Event, now, to_ts

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

ALIASES = {
    "ip": ["ip", "ip_address", "ipaddress", "src_ip", "source_ip", "srcip", "addr", "address", "host"],
    "lat": ["lat", "latitude", "y"],
    "lon": ["lon", "lng", "long", "longitude", "x"],
    "ts": ["ts", "timestamp", "time", "date", "datetime", "first_seen", "created_at", "published"],
    "title": ["title", "name", "description", "indicator", "message", "summary", "domain", "url"],
    "country": ["country", "country_code", "cc", "iso2"],
    "severity": ["severity", "score", "risk", "confidence"],
    "url": ["url", "link", "reference"],
}


def _pick(cols: list[str], field: str) -> str | None:
    low = {c.lower(): c for c in cols}
    for a in ALIASES[field]:
        if a in low:
            return low[a]
    return None


# Limits for one upload (okf/data/size-limits.md#uploads). The parse streams in batches, so memory stays flat
# whatever the row count; the row cap bounds the DuckDB load and the events table growth from one file, and
# the byte cap bounds disk use and parse time. 64 MB holds about 1.4 million rows of a typical IOC CSV
# (ip,title,severity,country is ~47 bytes a row), far above the row cap, and a 1-million-line plain IP list
# (~14 MB), so no real blocklist is turned away by bytes before the row cap tells the user what was kept.
MAX_ROWS = 200_000
MAX_BYTES = 64 << 20
BATCH = 5_000


JSON_SUFFIXES = (".json", ".ndjson", ".jsonl")
JSON_READ = 1 << 20          # characters read from a JSON upload at a time
_WS = " \t\r\n"
_SKIP = re.compile(r"[ \t\r\n,]*")   # what may sit between two array elements
_NOT_JSON = object()


class UploadRefused(ValueError):
    """A file the upload cannot read; the message is for the person who sent it (the 400 answer of /api/upload)."""


ARRAY_NOT_CLOSED = "The JSON array in this file is never closed: the final ] is missing."
ARRAY_NOT_JSON = "This file starts like a JSON array but is not valid JSON."
ARRAY_TRAILER = ("This file has more after the closing ] of its JSON array. Upload one JSON array of rows, or one "
                 "JSON object per line (NDJSON).")
NOT_JSON = "This file is not valid JSON."


def _csv_shut(con, path: Path, spill: Path) -> None:
    """Settings for the upload's CSV connection: bounded memory and threads, spilling into `spill` (its own folder in
    the lake's tmp, which DuckDB may also use), and file access to this one upload only (no other file, no network;
    extensions never download or auto-load: the shared DUCKDB_CONFIG). The settings are then locked."""
    from .. import db
    con.execute("SET memory_limit = '512MB'")   # the scan spills rather than grows (300k rows use ~40 MB)
    con.execute("SET threads = 2")
    con.execute(f"SET temp_directory = '{db._q(spill)}'")   # not ./.tmp in the cwd
    db.restrict(con, paths=(path,), lock=True)


def _csv_rows(path: Path):
    """Yields the column names, then every row tuple, read by DuckDB's CSV sniffer in batches of BATCH (never
    fetchall). The connection closes when the generator is exhausted or closed."""
    p = str(path).replace("'", "''")
    from .. import config
    from ..db import DUCKDB_CONFIG   # no extension downloads
    base = config.TMP_DIR / "duckdb-upload"
    base.mkdir(parents=True, exist_ok=True)
    spill = Path(tempfile.mkdtemp(dir=base))   # one per upload: two uploads at once never share it
    try:
        with duckdb.connect(config=DUCKDB_CONFIG) as con:
            _csv_shut(con, path, spill)
            cur = con.execute(f"SELECT * FROM read_csv_auto('{p}', ignore_errors=true)")
            yield [d[0] for d in cur.description]
            while batch := cur.fetchmany(BATCH):
                yield from batch
    finally:
        shutil.rmtree(spill, ignore_errors=True)


def _array_values(f, buf: str):
    """The elements of a top-level JSON array, streamed: `buf` starts just after the "[". A value that does not fit
    in the buffer yet is retried with twice as much text, so even one huge element costs a few passes, not one per
    chunk. Any syntax error is the array's error (v1.2 refused a broken array too). Returns (buf, pos), pos just
    after the closing "]" (no copy of the buffer)."""
    dec = json.JSONDecoder()
    pos, eof = 0, False

    def more(n):
        nonlocal buf, pos, eof
        chunk = f.read(n)
        eof = not chunk
        buf, pos = buf[pos:] + chunk, 0

    want = JSON_READ
    while True:
        while True:   # white space and the commas between elements
            pos = _SKIP.match(buf, pos).end()
            if pos < len(buf) or eof:
                break
            more(JSON_READ)
        if pos >= len(buf):
            raise UploadRefused(ARRAY_NOT_CLOSED)
        if buf[pos] == "]":
            return buf, pos + 1
        try:
            obj, end = dec.raw_decode(buf, pos)
            if end == len(buf) and not eof:
                raise ValueError("may be cut short")      # a number at the end of the buffer: read on
        except ValueError:
            if eof:
                raise UploadRefused(ARRAY_NOT_JSON) from None
            more(want)
            want *= 2
            continue
        want = JSON_READ
        pos = end
        yield obj
        if pos > JSON_READ:
            buf, pos = buf[pos:], 0


def _array(f, buf: str):
    """The elements of the file's one top-level JSON array (`buf` starts just after its "["). Only white space may
    follow the closing "]": anything else (a second array, an object, stray text) refuses the file rather than being
    dropped or guessed at. The check reads on 1 MB at a time: linear in the file's size."""
    buf, pos = yield from _array_values(f, buf)
    tail = buf[pos:]                       # one copy, at most the buffer
    while tail:
        if tail.lstrip(_WS):
            raise UploadRefused(ARRAY_TRAILER)
        tail = f.read(JSON_READ)


def _json_values(path: Path):
    """The rows of a JSON upload, streamed with the standard library: the elements of the top-level array, or one
    value per line (NDJSON / JSONL), or, when the first line is not a value
    on its own, the whole file as JSON (one object, pretty-printed; the 64 MB upload cap bounds it). In NDJSON a line
    that is not valid JSON is skipped and costs only that line; each line is parsed once."""
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        while (head := f.read(JSON_READ)) and not (stripped := head.lstrip(_WS)):
            pass                                    # more than 1 MB of white space first: read on, 1 MB at a time
        if head and stripped.startswith("["):
            yield from _array(f, stripped[1:])
            return
        f.seek(0)
        lines = iter(f)
        first = next((ln for ln in lines if ln.strip()), None)
        if first is None:
            return                                  # empty or white space only: no rows, as in v1.2
        try:
            obj = json.loads(first)
        except ValueError:
            obj = _NOT_JSON
        if obj is _NOT_JSON:
            f.seek(0)
            dec, text = json.JSONDecoder(), f.read()
            pos = 0
            while True:   # one value, or several pretty-printed values one after another
                while pos < len(text) and text[pos] in _WS:
                    pos += 1
                if pos >= len(text):
                    break
                try:
                    obj, pos = dec.raw_decode(text, pos)
                except ValueError:
                    raise UploadRefused(NOT_JSON) from None   # a syntax error refuses the file, as v1.2 did
                yield obj
            return
        yield obj                                   # line mode: the first line, parsed once
        for line in lines:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            yield obj


def _as_row(v) -> dict:
    """One JSON value as a row: an object as it is, a bare address as {"ip"}, anything else as {"value"}."""
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and IP_RE.match(v.strip()):
        return {"ip": v.strip()}
    return {"value": v}


def _ip_lines(path: Path):
    with path.open("r", errors="ignore") as f:
        for ln in f:
            ip = ln.strip()
            if IP_RE.match(ip):
                yield ip


def _is_ip_list(path: Path) -> bool:
    with path.open("rb") as f:   # only the first 4 KB: never the whole upload for format detection
        text_head = f.read(4096).decode(errors="ignore")
    lines = [ln.strip() for ln in text_head.splitlines() if ln.strip() and not ln.startswith("#")]
    return path.suffix.lower() in (".txt", ".list") or bool(lines and all(IP_RE.match(ln) for ln in lines[:20]))


def _row_event(label: str):
    """A function (i, row dict) -> the row's event; keys are mapped onto the event model by name."""
    sid = "upload"
    maps: dict[tuple, tuple[dict, set]] = {}

    def event(i: int, r: dict) -> Event:
        shape = tuple(r)
        if shape not in maps:
            if len(maps) >= 1000:   # JSON rows of many shapes: keep the cache small
                maps.clear()
            m = {f: _pick(list(shape), f) for f in ALIASES}
            maps[shape] = (m, set(m.values()))
        m, mapped = maps[shape]

        def g(f):
            c = m.get(f)
            return r.get(c) if c else None
        ip = g("ip")
        ip = str(ip) if ip and IP_RE.match(str(ip)) else None
        lat, lon = g("lat"), g("lon")
        try:
            lat = float(lat) if lat is not None else None
            lon = float(lon) if lon is not None else None
        except (TypeError, ValueError):
            lat = lon = None
        sev = g("severity")
        try:
            sev = float(sev)
            sev = sev / 10 if sev > 1 else sev
            sev = sev / 10 if sev > 1 else sev
        except (TypeError, ValueError):
            sev = 0.5
        title = g("title") or ip or f"{label} row {i + 1}"
        extra = {k: v for k, v in r.items() if k not in mapped}
        return Event(
            source=sid, kind="indicator", key=(label, i, str(title)), ts=to_ts(g("ts")),
            title=f"{str(title)[:160]}", summary=json.dumps(extra, default=str)[:500] if extra else None,
            category="custom", severity=sev, lat=lat, lon=lon, ip=ip,
            country=(str(g("country")).upper()[:2] if g("country") else None),
            url=g("url"), tags=[label],
        )
    return event


def _parse(path: Path, label: str):
    """(rows, event): the file's rows as cheap values (an address, a CSV tuple, a JSON value), streamed, and the
    function (i, row) -> its event. Counting rows past the cap only walks `rows`; no event is built for them."""
    if _is_ip_list(path):
        ts = now()

        def ip_event(i, ip):
            return Event(source="upload", kind="indicator", key=(label, ip), ts=ts, title=f"{label}: {ip}",
                         category="custom", severity=0.5, ip=ip, tags=[label])
        return _ip_lines(path), ip_event
    ev = _row_event(label)
    if path.suffix.lower() in JSON_SUFFIXES:
        return _json_values(path), lambda i, v: ev(i, _as_row(v))
    rows = _csv_rows(path)
    cols = next(rows)
    return rows, lambda i, t: ev(i, dict(zip(cols, t)))


def iter_events(path: Path, label: str):
    """Every event in the file, one at a time (memory stays flat). CSV columns are detected with DuckDB's
    sniffer, JSON is read with a streaming decoder; keys are mapped onto the event model by name. A plain IP
    list gives one indicator per address."""
    rows, event = _parse(path, label)
    try:
        for i, r in enumerate(rows):
            yield event(i, r)
    finally:
        rows.close()


def ingest_file(path: Path, label: str, max_rows: int | None = None) -> list[Event]:
    """The first max_rows events of the file as a list (small files and tests; the API streams)."""
    return list(itertools.islice(iter_events(path, label), MAX_ROWS if max_rows is None else max_rows))


def ingest_to_ndjson(path: Path, label: str, raw_path: str | None, out: Path, max_rows: int | None = None) -> dict:
    """Stream the file's events, geolocated, into a gzipped NDJSON at `out`, keeping the first max_rows.
    Returns {"kept", "total", "geolocated", "out"}; out is None when the file had no rows. Rows past the
    cap are only counted (no event built, no geolocation, nothing written) so the user is told how many were left out."""
    max_rows = MAX_ROWS if max_rows is None else max_rows
    kept = geo_n = 0
    over = False
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".part")
    rows, event = _parse(path, label)
    try:
        with gzip.open(tmp, "wt", compresslevel=6) as fh:
            for r in rows:
                if kept >= max_rows:
                    over = True
                    break
                row = event(kept, r).geolocate().to_row(raw_path)
                geo_n += row["lat"] is not None
                fh.write(json.dumps(row, default=str) + "\n")
                kept += 1
        total = kept + (1 + sum(1 for _ in rows) if over else 0)   # past the cap: counted, no event built
        if kept:
            tmp.replace(out)
    finally:
        rows.close()
        tmp.unlink(missing_ok=True)
    return {"kept": kept, "total": total, "geolocated": geo_n, "out": out if kept else None}


def events_path_for(raw: Path) -> Path:
    """Where the events of an uploaded file go: next to it, `<name>.events.ndjson.gz`."""
    base = raw
    while base.suffix in (".gz", ".json", ".txt", ".csv", ".x"):
        base = base.with_suffix("")
    return Path(str(base) + ".events.ndjson.gz")


LOAD_ROWS = 20_000   # events per DuckDB load: one INSERT of 200k rows took ~600 MB of RSS, 20k-row parts ~20 MB each


def load_in_parts(events: Path, rows: int | None = None) -> int:
    """Load an events NDJSON (gzipped) into DuckDB `rows` events at a time, through temporary part files in
    the lake's tmp folder, so the database's working memory stays small. Returns the rows loaded."""
    from .. import config, db
    rows = rows or LOAD_ROWS
    n = 0
    tmp_dir = config.TMP_DIR / "upload-parts"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    part = tmp_dir / f"{events.name}.part.ndjson.gz"
    try:
        with gzip.open(events, "rt") as src:
            while chunk := list(itertools.islice(src, rows)):
                with gzip.open(part, "wt", compresslevel=1) as fh:
                    fh.writelines(chunk)
                n += db.load_events_ndjson(part)
    finally:
        part.unlink(missing_ok=True)
    return n

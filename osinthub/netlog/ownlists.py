"""Your own lists: a CSV or text file of IP addresses, ranges (CIDR) or domains, uploaded under a name, matched
against your logs like every other threat list.

* Each list is a row in netlog_own_lists; its entries are indicator_intervals rows with source `own:<id>`,
  category `own` and trust tier `U` (you). A list says "these are bad" without saying since when, so a contact
  at any time before the list's expiry is inside the listing (matcher.MATCH_SQL), and every log already imported
  is re-checked when a list is added or replaced (retro: such alerts carry "found later"). The listing's start is
  when the value was added, so the evidence says when Night Desk learned it.
* An optional expiry ends the listing: later contacts are "outside listing" (info), like any delisted address.
* Rename, change the note or expiry, replace the contents, delete: alerts follow at once (a delete removes them).
* Alerts read "… on your list '<name>'" (matcher titles and web/js/views/net/alert-text.js).

Docs: okf/data/netlog.md#your-own-lists
"""
from __future__ import annotations

import asyncio
import csv
import datetime as dt
import io
import json
import re
import threading
import uuid

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from .. import db
from . import ipnum, util

router = APIRouter(prefix="/lists", tags=["netlog"])  # mounted under /api/netlog by ext.py

PREFIX = "own:"
CATEGORY = "own"
MAX_BYTES = 20 * 1024 * 1024
MAX_ENTRIES = 200_000
NAME_MAX, NOTE_MAX = 60, 500
MIN_PREFIX = {4: 8, 6: 16}     # a shorter range than this would match much of the internet
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}$")
_SPLIT = re.compile(r"[\s,;|]+")

SCHEMA = """
CREATE TABLE IF NOT EXISTS netlog_own_lists (
    id         VARCHAR PRIMARY KEY,
    name       VARCHAR,
    note       VARCHAR,
    expires_at TIMESTAMPTZ,            -- the listing ends then; NULL: never
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    file_name  VARCHAR,                -- the file the entries came from
    entries    BIGINT,
    kinds      VARCHAR,                -- JSON {ip, cidr, domain: count}
    skipped    VARCHAR                 -- JSON {count, sample: [{line, value, why}]}
);
"""
_ready: set = set()
_lock = threading.Lock()


def ensure() -> None:
    key = id(db.connect())
    if key in _ready:
        return
    with _lock:
        with db._write_lock:
            db.cursor().execute(SCHEMA)
        _ready.add(key)


def is_own(source: str | None) -> bool:
    return bool(source) and str(source).startswith(PREFIX)


# ------------------------------------------------------------------ parsing
def _refang(v: str) -> str:
    v = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\[dot\]|\(dot\)", ".", v, flags=re.I)
    return v.replace("[:]", ":")


def classify(raw: str) -> tuple[str, str] | tuple[None, str]:
    """(kind, canonical value) for one entry, or (None, why it is not usable)."""
    v = _refang(raw.strip().strip("\"'").strip())
    if not v:
        return None, "empty"
    low = v.lower()
    if "://" in low:                                   # a URL: keep its host
        low = low.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0]
        low = low.rsplit("@", 1)[-1]
        if low.startswith("[") and "]" in low:
            low = low[1:low.index("]")]
        elif low.count(":") == 1:
            low = low.split(":", 1)[0]
    elif low.startswith("[") and "]" in low:           # [2001:db8::1]:443
        low = low[1:low.index("]")]
    elif low.count(":") == 1 and "." in low and "/" not in low:   # 198.51.100.7:443 or name:443
        low = low.split(":", 1)[0]
    low = low.rstrip(".")
    if "/" in low:
        r = ipnum.net_range(low)
        if not r:
            return None, "not an address range"
        bits = int(r[2].rsplit("/", 1)[1])
        fam = 6 if ":" in r[2] else 4
        if bits < MIN_PREFIX[fam]:
            return None, f"range too wide (shorter than /{MIN_PREFIX[fam]})"
        full = 128 if fam == 6 else 32
        if bits == full:
            return "ip", ipnum.canonical(r[2].rsplit("/", 1)[0])
        return "cidr", r[2]
    if ipnum.is_ip(low):
        c = ipnum.canonical(low)
        if not c or ipnum.special(c):
            return None, "a loopback, multicast or unspecified address"
        return "ip", c
    if low.startswith("*."):
        low = low[2:]
    if _DOMAIN_RE.match(low) and not re.fullmatch(r"[0-9.]+", low):
        return "domain", low
    return None, "not an address, range or domain"


def parse(text: str) -> dict:
    """Entries from a CSV or plain text list: one value per line, or any column of a CSV. Lines starting with
    # or ; are comments; a header row is skipped. Returns {values: {(kind, value)}, skipped: [...], lines: n}."""
    values: dict[tuple[str, str], int] = {}
    skipped: list[dict] = []
    n_skip = 0
    lines = 0
    head = next((ln for ln in text[:65536].splitlines() if ln.strip() and not ln.lstrip().startswith(("#", ";", "//"))), "")
    is_csv = "," in head
    rows = csv.reader(io.StringIO(text)) if is_csv else ([ln] for ln in text.splitlines())
    for i, row in enumerate(rows, 1):
        cells = [c for c in row if c is not None]
        if not cells or not "".join(cells).strip():
            continue
        first = cells[0].strip()
        if first.startswith(("#", ";", "//")):
            continue
        lines += 1
        if not is_csv:   # "value", "value  # comment", or a hosts-file line "0.0.0.0 name"
            first = first.split("#", 1)[0].strip()
            cells = [c for c in _SPLIT.split(first) if c] or [first]
        got = None
        whys = []
        for c in cells:
            k, val = classify(c)
            if k:
                got = (k, val)
                break
            whys.append(val)
        if got:
            values.setdefault(got, i)
        elif lines == 1 and is_csv:
            continue   # a header row
        else:
            n_skip += 1
            if len(skipped) < 20:
                skipped.append({"line": i, "value": ",".join(cells)[:120], "why": whys[0] if whys else "empty"})
        if len(values) > MAX_ENTRIES:
            raise ValueError(f"a list can hold at most {MAX_ENTRIES:,} entries")
    return {"values": values, "skipped": {"count": n_skip, "sample": skipped}, "lines": lines}


# ------------------------------------------------------------------ storage
def _expiry(v) -> dt.datetime | None:
    if v in (None, "", 0, "0"):
        return None
    try:
        days = float(v)
    except (TypeError, ValueError):
        days = None
    if days is not None:
        if not 0 < days <= 3650:
            raise ValueError("expires_days must be from 1 to 3650")
        return util.now() + dt.timedelta(days=days)
    try:
        t = dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"bad expiry: {v}")
    return t if t.tzinfo else t.replace(tzinfo=util.UTC)


def _name(v, lid: str | None = None) -> str:
    n = " ".join(str(v or "").split())
    if not n:
        raise ValueError("a list needs a name")
    if len(n) > NAME_MAX:
        raise ValueError(f"the name is longer than {NAME_MAX} characters")
    clash = db.query("SELECT id FROM netlog_own_lists WHERE lower(name) = lower(?) AND id IS DISTINCT FROM ?", [n, lid])
    if clash:
        raise ValueError(f"you already have a list called “{n}”")
    return n


def _note(v) -> str | None:
    n = str(v or "").strip()
    if len(n) > NOTE_MAX:
        raise ValueError(f"the note is longer than {NOTE_MAX} characters")
    return n or None


def _write_entries(cur, lid: str, meta: dict, values: dict, expires_at, keep_start: dict) -> None:
    """Replace the list's indicator_intervals rows. keep_start: (kind, value) -> start of a value already listed."""
    src = PREFIX + lid
    cur.execute("DELETE FROM indicator_intervals WHERE source = ?", [src])
    if not values:
        return
    now = util.now()
    rows = []
    for (kind, value) in values:
        lo = hi = None
        if kind in ("ip", "cidr"):
            r = ipnum.net_range(value)
            lo, hi = str(r[0]), str(r[1])
        start = keep_start.get((kind, value)) or now
        rows.append({"source": src, "kind": kind, "value": value, "start": start, "end": expires_at, "key": value,
                     "category": CATEGORY, "lo": lo, "hi": hi,
                     "meta": json.dumps({**meta, "added_at": util.jsonable(start)}, default=str),
                     "start_path": None, "end_path": None})
    p = util.scratch("ownlist")
    util.write_ndjson(p, rows)
    try:
        s = util.read_src(p, {"source": "VARCHAR", "kind": "VARCHAR", "value": "VARCHAR", "start": "TIMESTAMPTZ",
                              "end": "TIMESTAMPTZ", "key": "VARCHAR", "category": "VARCHAR", "lo": "VARCHAR",
                              "hi": "VARCHAR", "meta": "VARCHAR", "start_path": "VARCHAR", "end_path": "VARCHAR"})
        cur.execute(f"""INSERT INTO indicator_intervals SELECT source, kind, value, "start", "end", key, category,
                        lo::UHUGEINT, hi::UHUGEINT, meta, start_path, end_path FROM {s}""")
    finally:
        p.unlink(missing_ok=True)


def _meta(rec: dict) -> dict:
    return {"list_id": rec["id"], "list_name": rec["name"], "note": rec.get("note"), "own": True}


def _rematch(src: str, everything: bool) -> dict:
    """Re-match after a change: every imported row when values may be new, else only rows the list had matched."""
    from . import matcher
    if not db.query("SELECT 1 FROM netlog LIMIT 1"):
        return {"matches": 0, "alerts_touched": 0}
    with util.LOCK:
        old = matcher.match("rk IN (SELECT rk FROM netlog_matches WHERE source = ?)", [src])
        if not everything:
            return old
        return matcher.match("true")


def get(lid: str) -> dict | None:
    ensure()
    rows = db.query("SELECT * FROM netlog_own_lists WHERE id = ?", [lid])
    if not rows:
        return None
    return _present(rows[0])


def _present(r: dict) -> dict:
    r = dict(r)
    r["kinds"] = json.loads(r.get("kinds") or "{}")
    r["skipped"] = json.loads(r.get("skipped") or "{}")
    r["source"] = PREFIX + r["id"]
    r["active"] = r["expires_at"] is None or r["expires_at"] > util.now()
    try:
        from . import incidents
        incidents.ensure()
        h = db.query(f"""SELECT count(*) AS incidents, count(*) FILTER (WHERE state = 'new') AS open, max(last_ts) AS last
                         FROM ({incidents.incidents_sql("WHERE source = ? OR evidence ILIKE ?")})""",
                     [r["source"], f'%"{r["source"]}"%'])[0]
        r["hits"] = util.jsonable(h)
    except Exception:
        r["hits"] = {"incidents": 0, "open": 0, "last": None}
    return util.jsonable(r)


def list_all() -> list[dict]:
    ensure()
    return [_present(r) for r in db.query("SELECT * FROM netlog_own_lists ORDER BY lower(name), id")]


def create(name, text: str, note=None, expires=None, file_name: str | None = None) -> dict:
    ensure()
    parsed = parse(text)
    if not parsed["values"]:
        raise ValueError("no addresses, ranges or domains found in the file"
                         + (f" ({parsed['skipped']['count']} lines were not usable)" if parsed["skipped"]["count"] else ""))
    exp = _expiry(expires)
    if exp is not None and exp <= util.now():
        raise ValueError("the expiry is already past")
    with util.LOCK:
        rec = {"id": uuid.uuid4().hex[:10], "name": _name(name), "note": _note(note), "expires_at": exp}
        kinds = _kinds(parsed["values"])
        with db._write_lock:
            cur = db.cursor()
            with db.tx(cur):
                cur.execute("""INSERT INTO netlog_own_lists VALUES (?, ?, ?, ?, now(), now(), ?, ?, ?, ?)""",
                            [rec["id"], rec["name"], rec["note"], exp, file_name, len(parsed["values"]),
                             json.dumps(kinds), json.dumps(parsed["skipped"])])
                _write_entries(cur, rec["id"], _meta(rec), parsed["values"], exp, {})
        res = _rematch(PREFIX + rec["id"], True)
    out = get(rec["id"])
    out["match"] = res
    _publish()
    return out


def _kinds(values) -> dict:
    out: dict[str, int] = {}
    for k, _ in values:
        out[k] = out.get(k, 0) + 1
    return out


def _starts(src: str) -> dict:
    return {(r["kind"], r["value"]): r["start"] for r in
            db.query('SELECT kind, value, "start" FROM indicator_intervals WHERE source = ?', [src])}


def update(lid: str, body: dict) -> dict:
    """Rename, change the note or the expiry (expires_days, or expires_at; null or 0 clears it)."""
    ensure()
    cur0 = db.query("SELECT * FROM netlog_own_lists WHERE id = ?", [lid])
    if not cur0:
        raise LookupError("no such list")
    rec = dict(cur0[0])
    if "name" in body:
        rec["name"] = _name(body["name"], lid)
    if "note" in body:
        rec["note"] = _note(body["note"])
    if "expires_days" in body:
        rec["expires_at"] = _expiry(body["expires_days"])
    elif "expires_at" in body:
        rec["expires_at"] = _expiry(body["expires_at"])
    src = PREFIX + lid
    with util.LOCK:
        with db._write_lock:
            c = db.cursor()
            with db.tx(c):
                c.execute("UPDATE netlog_own_lists SET name = ?, note = ?, expires_at = ?, updated_at = now() WHERE id = ?",
                          [rec["name"], rec["note"], rec["expires_at"], lid])
                vals = {(r["kind"], r["value"]): 1 for r in util.rows_of(
                    c, "SELECT kind, value FROM indicator_intervals WHERE source = ?", [src])}
                starts = {(r["kind"], r["value"]): r["start"] for r in util.rows_of(
                    c, 'SELECT kind, value, "start" FROM indicator_intervals WHERE source = ?', [src])}
                _write_entries(c, lid, _meta(rec), vals, rec["expires_at"], starts)
        # a later expiry can bring contacts back into the listing: re-check them all; a rename only re-titles
        widened = "expires_days" in body or "expires_at" in body
        res = _rematch(src, widened)
    out = get(lid)
    out["match"] = res
    _publish()
    return out


def replace(lid: str, text: str, file_name: str | None = None) -> dict:
    """New contents for a list: values still on it keep the time they were first added."""
    ensure()
    cur0 = db.query("SELECT * FROM netlog_own_lists WHERE id = ?", [lid])
    if not cur0:
        raise LookupError("no such list")
    rec = dict(cur0[0])
    parsed = parse(text)
    if not parsed["values"]:
        raise ValueError("no addresses, ranges or domains found in the file")
    src = PREFIX + lid
    with util.LOCK:
        starts = _starts(src)
        with db._write_lock:
            c = db.cursor()
            with db.tx(c):
                c.execute("""UPDATE netlog_own_lists SET file_name = ?, entries = ?, kinds = ?, skipped = ?, updated_at = now()
                             WHERE id = ?""", [file_name, len(parsed["values"]), json.dumps(_kinds(parsed["values"])),
                                               json.dumps(parsed["skipped"]), lid])
                _write_entries(c, lid, _meta(rec), parsed["values"], rec["expires_at"], starts)
        res = _rematch(src, True)
    out = get(lid)
    out["match"] = res
    out["added"] = len(set(parsed["values"]) - set(starts))
    out["removed"] = len(set(starts) - set(parsed["values"]))
    _publish()
    return out


def delete(lid: str) -> dict:
    ensure()
    if not db.query("SELECT 1 FROM netlog_own_lists WHERE id = ?", [lid]):
        raise LookupError("no such list")
    src = PREFIX + lid
    with util.LOCK:
        with db._write_lock:
            c = db.cursor()
            with db.tx(c):
                c.execute("DELETE FROM indicator_intervals WHERE source = ?", [src])
                c.execute("DELETE FROM netlog_own_lists WHERE id = ?", [lid])
        res = _rematch(src, False)
    _publish()
    return {"deleted": lid, "match": res}


def names() -> dict[str, str]:
    """{source id: list name} for every own list (alert text, entity pages)."""
    ensure()
    return {PREFIX + r["id"]: r["name"] for r in db.query("SELECT id, name FROM netlog_own_lists")}


def _publish() -> None:
    util.publish_alerts({"own_lists": True})


# ------------------------------------------------------------------ API
async def _text(file: UploadFile | None, text: str | None) -> tuple[str, str | None]:
    if file is not None and file.filename:
        data = await file.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise HTTPException(413, f"the file is larger than {MAX_BYTES // (1024 * 1024)} MB")
        if data[:2] == b"\x1f\x8b":
            import gzip
            try:
                data = gzip.decompress(data)[: MAX_BYTES + 1]
            except OSError:
                raise HTTPException(400, "the file looks gzipped but could not be read")
        return data.decode("utf-8", errors="replace").lstrip("﻿"), file.filename
    if text:
        if len(text) > MAX_BYTES:
            raise HTTPException(413, "the list is too long")
        return text, None
    raise HTTPException(400, "send a file (CSV or text) or the list as text")


@router.get("")
def api_list():
    return list_all()


@router.post("")
async def api_create(name: str = Form(...), note: str | None = Form(None), expires_days: str | None = Form(None),
                     file: UploadFile | None = File(None), text: str | None = Form(None)):
    """Upload a named list: a CSV or text file of IPs, CIDR ranges or domains (or `text`)."""
    body, fname = await _text(file, text)
    try:
        return await asyncio.to_thread(create, name, body, note, expires_days, fname)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/{lid}")
def api_get(lid: str, entries: int = 0):
    r = get(lid)
    if not r:
        raise HTTPException(404, "no such list")
    if entries:
        r["entries_sample"] = util.jsonable(db.query(
            """SELECT kind, value, "start" AS added_at FROM indicator_intervals WHERE source = ? ORDER BY kind, value LIMIT ?""",
            [PREFIX + lid, max(1, min(int(entries), 5000))]))
    return r


@router.patch("/{lid}")
def api_update(lid: str, body: dict):
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be an object")
    try:
        return update(lid, body)
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/{lid}/file")
async def api_replace(lid: str, file: UploadFile | None = File(None), text: str | None = Form(None)):
    """Replace a list's contents with a new file (the name, note and expiry stay)."""
    body, fname = await _text(file, text)
    try:
        return await asyncio.to_thread(replace, lid, body, fname)
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/{lid}")
def api_delete(lid: str):
    try:
        return delete(lid)
    except LookupError as e:
        raise HTTPException(404, str(e))

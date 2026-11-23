"""Runs batch sources on their intervals and keeps stream sources connected."""
from __future__ import annotations

import asyncio
import functools
import logging
import os
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import bus, config, db, lake
from .sources import SOURCES
from .sources.base import (Event, Paused, Source, StreamSink, Unchanged, content_hash, now, raw_path_for, record_hash,
                           write_raw)

log = logging.getLogger("osinthub.scheduler")

_tasks: dict[str, asyncio.Task] = {}
_toggle_locks: dict[str, asyncio.Lock] = {}
_running: set[str] = set()       # batch sources with a run in progress (read and changed only on the event loop)
_inflight: dict[str, set] = {}   # per source: worker-thread steps of its runs that have not finished yet
# Per source, bumped when it is stopped. A run or loop remembers the generation it started in and its state writes
# carry it: a write from an older generation (a stopped source's run whose thread work was still in flight) is
# dropped, so "disabled" stays the last word.
_gens: dict[str, int] = {}
_state_lock = threading.Lock()   # _set_state runs in the writer thread (_aset_state) as well as on the loop at startup
_state_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="source-state")
STREAM_HEALTHY_S = 60  # a stream session this long resets the reconnect backoff
PAUSED_RETRY_S = 600   # a paused batch source (routing data limit) checks again this often


class OfflineGuard(httpx.AsyncBaseTransport):
    """Backstop for offline mode: any request that slips past a config.OFFLINE check fails at
    once instead of waiting on a dead network or proxy."""

    async def handle_async_request(self, request):
        raise httpx.ConnectError(f"offline mode: refusing {request.url.host}", request=request)
_client: httpx.AsyncClient | None = None


def state(source_id: str) -> dict:
    rows = db.query("SELECT * FROM source_state WHERE id = ?", [source_id])
    return rows[0] if rows else {}


def is_enabled(src: Source) -> bool:
    if src.withheld:   # left out of this release: off whatever was saved (the saved answer is kept for later)
        return False
    st = state(src.id)
    return src.default_enabled if st.get("enabled") is None else bool(st["enabled"])


def _set_state(sid: str, gen: int | None = None, **kw) -> None:
    """Merge kw into the source's saved state. gen: the generation of the run or loop writing (see _gens); the
    write is dropped when the source has been stopped since. None (toggles, startup) always writes."""
    cols = ["id", "enabled", "status", "message", "last_run", "last_ok", "items_last", "items_total"]
    with _state_lock:   # read-modify-write: a run's status and a toggle's flag, written at once, both survive
        if gen is not None and gen != _gens.get(sid, 0):
            return
        st = state(sid)
        st.update(kw)
        st["id"] = sid
        db.execute(
            f"INSERT OR REPLACE INTO source_state ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            [st.get(c) for c in cols],
        )
    bus.publish("source", {"id": sid, **{k: st.get(k) for k in cols}})


async def _aset_state(sid: str, **kw) -> None:
    """_set_state from async code. Its write waits for db._write_lock, which a netlog import, rebuild or re-hunt
    holds for seconds; waiting for it on the event loop would stall every request and SSE stream meanwhile. One
    writer thread applies the writes in the order they were sent, so a later status always lands last."""
    await asyncio.get_running_loop().run_in_executor(_state_pool, functools.partial(_set_state, sid, **kw))


async def _off(sid: str, fn, *args, pool=None):
    """fn(*args) in a worker thread (pool None: the default one) for one of the source's runs. The step is tracked
    until its thread finishes, even when the run is cancelled meanwhile (shield: cancelling the awaiting task
    cannot stop the thread), so the run guard is released only once nothing of the run is still writing."""
    fut = asyncio.get_running_loop().run_in_executor(pool, functools.partial(fn, *args))
    pend = _inflight.setdefault(sid, set())
    pend.add(fut)
    fut.add_done_callback(pend.discard)
    return await asyncio.shield(fut)


def _rows(events: list[Event], raw_path: str | None, collected_at) -> list[dict]:
    rows = []
    for e in events:
        r = e.geolocate().to_row(raw_path)
        r["content_hash"] = content_hash(e, collected_at)
        rows.append(r)
    return rows


def _write_scratch(rows: list[dict], name: str):
    import json
    path = config.TMP_DIR / f"{name}-{os.getpid()}.ndjson"
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, default=str) + "\n")
    return path


def _load(src: Source, rows: list[dict], events_out) -> tuple[int, int]:
    scratch = _write_scratch(rows, src.id)
    try:
        return db.load_batch(scratch, events_out)
    finally:
        scratch.unlink(missing_ok=True)


def _announce(src: Source, events: list[Event], n: int, gen: int | None = None) -> None:
    """Blocking (a query and a state write): call it in a worker thread."""
    total = db.query("SELECT count(*) AS n FROM events WHERE source = ?", [src.id])[0]["n"]
    _set_state(src.id, gen=gen, items_total=total)
    latest = sorted(events, key=lambda e: e.ts, reverse=True)[:25]
    bus.publish("events", {"source": src.id, "count": n, "latest": [
        {k: v for k, v in e.to_row(None).items() if k != "raw_path"} for e in latest
    ]})


def _record_delta(src: Source, recs: list, started, unseen=None) -> tuple[list, list, dict]:
    """Compare a fetch's records with the stored set. Returns (puts, dels, new stored set).

    unseen: for a payload part of which failed to fetch (one dead feed of several, see Source.fetch_errors), a
    predicate true for keys that may belong to the failed part (Source.unseen). Those records were not seen, not
    removed: their stored hashes are kept and they are never counted as removed, so when the part comes back its
    unchanged records are not written to the lake again. Other missing keys age out or are removed as usual, so
    the stored set does not grow while a part stays down."""
    old = db.record_hashes(src.id)
    if not recs and old and not src.windowed:
        raise ValueError("provider returned an empty list; keeping the previous one")
    # A provider can list one key more than once (Spamhaus has CIDRs under two SBL ids);
    # such keys are stored as one record holding every copy, in a stable order.
    grouped: dict = {}
    for k, rec in recs:
        grouped.setdefault(k, []).append(rec)
    new: dict = {}
    puts = []
    for k, items in grouped.items():
        rec = items[0] if len(items) == 1 else sorted(items, key=record_hash)
        h = record_hash(rec)
        prev = old.get(k)
        if prev and prev[0] == h:
            new[k] = prev
        else:
            puts.append((k, rec))
            new[k] = (h, started)
    if unseen is not None:
        for k, v in old.items():
            if k not in new and unseen(k):
                new[k] = v
    dels = [] if src.windowed else [k for k in old if k not in new]
    return puts, dels, new


def _run_failed(src: Source, gen: int, started, raw_path, msg: str) -> None:
    _set_state(src.id, gen=gen, status="error", message=msg)
    db.execute("INSERT INTO runs (source, started, finished, ok, items, raw_path, error) VALUES (?, ?, now(), false, 0, ?, ?)",
               [src.id, started, raw_path, msg])


def _run_unchanged(src: Source, gen: int, started, msg: str) -> None:
    _set_state(src.id, gen=gen, status="ok", message=msg, last_ok=now())
    db.execute("""INSERT INTO runs (source, started, finished, ok, items, raw_path, error,
                                    records_changed, records_removed, events_changed)
                  VALUES (?, ?, now(), true, 0, NULL, NULL, 0, 0, 0)""", [src.id, started])


def _run_done(src: Source, gen: int, started, events, n: int, changed: int, raw_path, partial, puts, dels) -> None:
    """The bookkeeping that ends an ok run: totals, status, the runs row and metrics. Blocking: a worker thread."""
    if changed:
        _announce(src, events, n, gen)
    else:
        _set_state(src.id, gen=gen, items_total=db.query("SELECT count(*) AS n FROM events WHERE source = ?", [src.id])[0]["n"])
    own = src.stored_count()
    if own is not None:
        _set_state(src.id, gen=gen, items_total=own)
    _set_state(src.id, gen=gen, status="error" if partial else "ok",
               message=f"{(own if own is not None else n):,} records" + (f" · failed: {partial}" if partial else ""),
               last_ok=now(), items_last=n)
    db.execute("""INSERT INTO runs (source, started, finished, ok, items, raw_path, error,
                                    records_changed, records_removed, events_changed)
                  VALUES (?, ?, now(), true, ?, ?, ?, ?, ?, ?)""",
               [src.id, started, n, raw_path, partial, len(puts), len(dels), changed])
    db.record_metric(f"source.{src.id}.items", n)
    db.record_metric(f"source.{src.id}.changed", changed)


def is_running(src: Source) -> bool:
    return src.id in _running


def _release(sid: str) -> None:
    """Drop the run guard once no thread step of the source's last run is still in flight (a cancelled run's
    lake write, record-hash replace or bookkeeping keeps going after the cancel)."""
    pend = [f for f in _inflight.get(sid, ()) if not f.done()]
    if not pend:
        _running.discard(sid)
        return
    asyncio.gather(*pend, return_exceptions=True).add_done_callback(lambda _: _release(sid))


async def run_batch(src: Source) -> dict:
    """One run of a batch source. A run of a source that is already running (Run now during a scheduled run, or
    a double click, or a stopped run whose thread work is still finishing) is refused, so two runs never read the
    same record hashes and write the same delta twice."""
    if src.id in _running:   # checked and set with no await in between: atomic on the event loop
        return {"ok": False, "skipped": True, "running": True, "error": "already running"}
    _running.add(src.id)
    try:
        return await _run_batch(src, _gens.get(src.id, 0))
    finally:
        _release(src.id)


async def _run_batch(src: Source, gen: int) -> dict:
    # Every database write below runs in a worker thread: a netlog import or re-hunt can hold db._write_lock for
    # seconds, and waiting for it on the event loop would stall every request meanwhile. State writes and the
    # end-of-run bookkeeping go through the one state writer (in order) and carry the run's generation.
    sid = src.id

    async def state_(**kw):
        await _off(sid, functools.partial(_set_state, sid, gen=gen, **kw), pool=_state_pool)

    if config.OFFLINE:
        await state_(status="offline", message="offline mode: not fetching")
        return {"ok": False, "skipped": True, "error": "offline mode"}
    if (why := src.unavailable()):   # e.g. no API key: never fetch, never record a failed run
        await state_(status="needs_key", message=why)
        return {"ok": False, "skipped": True, "error": why}
    started = now()
    await state_(status="running", last_run=started)
    raw_path = None
    try:
        assert _client is not None
        try:
            raw = await src.fetch(_client)
        except Paused as p:
            # Not allowed to fetch right now (the routing watch's daily data limit): no run is recorded.
            await state_(status="paused", message=str(p)[:300])
            return {"ok": False, "skipped": True, "paused": True, "error": str(p)[:300]}
        except Unchanged as u:
            # Nothing new upstream (a 304, or a daily file already loaded): an ok run that loads nothing.
            msg = f"unchanged: {u}"[:300] if str(u) else "unchanged since the last run"
            await _off(sid, _run_unchanged, src, gen, started, msg, pool=_state_pool)
            return {"ok": True, "items": 0, "changed": 0, "records_changed": 0, "records_removed": 0,
                    "raw_path": None, "unchanged": True}
        try:
            await _off(sid, src.prepare, raw, started)
            events = await _off(sid, src.parse, raw)
            recs = await _off(sid, src.records, raw)
        except Exception:
            rp = raw_path_for(sid, f"{src.raw_ext}.gz", started)  # keep the payload for debugging
            await _off(sid, write_raw, rp, raw)
            raw_path = str(rp)
            raise
        # The full window is always fetched (providers backfill late data); only new or
        # changed records go to the lake, plus removals for lists.
        partial = "; ".join(src.fetch_errors(raw))[:300] or None
        unseen = src.unseen(raw) if partial else None
        puts, dels, stored = await _off(sid, _record_delta, src, recs, started, unseen)
        if puts or dels:
            rp = raw_path_for(sid, "records.ndjson.gz", started)
            await _off(sid, lake.write_records, rp, puts, dels)
            raw_path = str(rp)
        await _off(sid, db.replace_record_hashes, sid, stored)
        rows = await _off(sid, _rows, events, raw_path, started)
        events_out = raw_path_for(sid, "events.ndjson.gz", started)
        n, changed = await _off(sid, _load, src, rows, events_out) if rows else (0, 0)
        # Last write of the run: side tables that gate the next fetch (EPSS "already loaded") change only once the
        # lake delta, record hashes and events are in, so a failure above leaves them as they were.
        await _off(sid, src.commit, raw, started)
        if partial:
            log.warning("source %s partly failed: %s", sid, partial)
        await _off(sid, _run_done, src, gen, started, events, n, changed, raw_path, partial, puts, dels, pool=_state_pool)
        res = {"ok": True, "items": n, "changed": changed, "records_changed": len(puts),
               "records_removed": len(dels), "raw_path": raw_path}
        if (why := await _off(sid, src.paused_now)):   # the run used up the routing data limit: say so, not "error"
            await state_(status="paused", message=why[:300])
            res["paused"] = True
        return res
    except Exception as e:
        msg = f"{type(e).__name__}: {e}"[:300]
        log.warning("source %s failed: %s", sid, msg)
        log.debug(traceback.format_exc())
        await _off(sid, _run_failed, src, gen, started, raw_path, msg, pool=_state_pool)
        return {"ok": False, "error": msg}


async def _batch_loop(src: Source) -> None:
    gen = _gens.get(src.id, 0)
    if config.OFFLINE:
        await _aset_state(src.id, gen=gen, status="offline", message="offline mode: not fetching")
        return
    st = await asyncio.to_thread(state, src.id)
    last_ok = st.get("last_ok")
    if last_ok is not None:
        wait = src.interval - (now() - last_ok).total_seconds()
        if wait > 0:
            await _aset_state(src.id, gen=gen, status="idle")
            await asyncio.sleep(wait)
    while True:
        # A Run now in progress, or the tail of a run stopped just before this task started (the source was turned
        # off and on again): wait for it rather than skip a whole interval.
        while src.id in _running:
            await asyncio.sleep(0.25)
        res = await run_batch(src)
        # A paused source (the routing data limit) looks again every PAUSED_RETRY_S: it resumes after midnight or as
        # soon as the limit is raised, without a request while it is still paused (the check is local).
        await asyncio.sleep(min(PAUSED_RETRY_S, src.interval) if res.get("paused") else src.interval + src.jitter())


async def _stream_loop(src: Source) -> None:
    gen = _gens.get(src.id, 0)
    if config.OFFLINE:
        await _aset_state(src.id, gen=gen, status="offline", message="offline mode: not connecting")
        return
    async def flush(s, evs):
        # Loaded into DuckDB right away; kept in the lake as one gzipped file per hour.
        t = now()
        rows = await asyncio.to_thread(_rows, evs, str(lake.stream_hour_path(s.id, t)), t)
        n, _ = await asyncio.to_thread(_load, s, rows, None)
        await asyncio.to_thread(lake.append_stream, s.id, [{k: v for k, v in r.items() if k != "content_hash"} for r in rows], t)
        await asyncio.to_thread(_announce, s, evs, n, gen)
    backoff = 2
    while True:
        sink = StreamSink(src, flush)
        await _aset_state(src.id, gen=gen, status="live", message="connected", last_run=now())
        t0 = asyncio.get_running_loop().time()
        try:
            await src.stream(sink)
            await sink.flush()
            raise ConnectionError("stream closed")
        except asyncio.CancelledError:
            await sink.flush()
            raise
        except Exception as e:
            msg = f"{type(e).__name__}: {e}"[:300]
            await _aset_state(src.id, gen=gen, status="reconnecting", message=msg)
            # A session that stayed up a while was healthy: reconnect fast after a routine drop.
            # Only drops in quick succession back off (2, 4, 8 ... 120 s).
            if asyncio.get_running_loop().time() - t0 >= STREAM_HEALTHY_S:
                backoff = 2
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 120)


def start_source(src: Source) -> None:
    if src.id in _tasks and not _tasks[src.id].done():
        return
    if (why := src.unavailable()):
        raise ValueError(why)
    loop = _stream_loop if src.mode == "stream" else _batch_loop
    _tasks[src.id] = asyncio.create_task(loop(src), name=f"src:{src.id}")


async def set_enabled(src: Source, enabled: bool) -> None:
    """Turn a source on or off, keeping the saved flag and its task consistent. Must run on the event loop.
    On: start the task, then save; if either fails the task is cancelled and the source is saved as off
    (never "enabled" with no task). Off: save, then stop (stopping cannot fail). The saves run in a worker thread
    (they can wait seconds for the database write lock); toggles of one source are serialized so two requests
    cannot interleave between a save and the task change."""
    async with _toggle_locks.setdefault(src.id, asyncio.Lock()):
        if not enabled:
            await _aset_state(src.id, enabled=False)
            await stop_source(src)
            return
        try:
            start_source(src)
            await _aset_state(src.id, enabled=True)
        except BaseException as e:
            t = _tasks.pop(src.id, None)
            if t:
                t.cancel()
            try:
                await _aset_state(src.id, enabled=False, status="error",
                                  message=f"could not start: {type(e).__name__}"[:300])
            except Exception:
                log.exception("saving %s as off after a failed start failed", src.id)
            raise


async def stop_source(src: Source) -> None:
    # A new generation first: every state write of the runs and loops started before is dropped from here on, even
    # one whose thread is already running (the check and the write happen together under _state_lock).
    _gens[src.id] = _gens.get(src.id, 0) + 1
    t = _tasks.pop(src.id, None)
    if t:
        t.cancel()
    await _aset_state(src.id, status="disabled", message="")


async def _checkpoint_loop() -> None:
    # Fold the write-ahead log into the database file so it doesn't grow without bound.
    while True:
        await asyncio.sleep(600)
        try:
            await asyncio.to_thread(db.execute, "CHECKPOINT")
        except Exception as e:
            log.warning("checkpoint failed: %s", e)


# Sources whose default changed from off to on. Earlier versions saved enabled=False for every default-off
# source at startup, which would keep such a source off; each entry clears that saved flag once (a choice the
# user makes in the Sources view afterwards is kept).
DEFAULT_FLIPS = {"cisa_advisories": "2026-11-csaf"}   # re-sourced from CISA's CSAF repository, now on by default


# Sources whose default changed from on to off. A lake that already has state for the source (it ran under the old
# default) gets its unset flag pinned to on once, so an existing setup keeps what it had; a new lake has no state
# yet, so the source starts off there. A choice saved in the Sources view is never changed.
DEFAULT_OFFS = {"bluesky_cyber": "2026-11-off"}   # unvetted social firehose (tier D): opt-in for new lakes

# Sources whose terms say `ask` (feed_terms.py) but were on in code until the 2026-11-19 terms review. As
# DEFAULT_OFFS, except that a lake still waiting for its first-run "Choose your sources" answer is not pinned: there
# the box (which shows them unticked) decides, so nothing is fetched for them before the user agrees. A lake whose
# step was answered with "Keep" (no flags saved) or never offered (an older lake) keeps them on; "Apply" saved a flag
# for every source, which is never changed. A new lake has no state yet, so they start off there.
TERMS_OFFS = {sid: "2026-11-terms" for sid in ("spamhaus_drop", "dshield_top", "blocklist_de", "et_compromised",
                                                "ioda_outages")}


def _apply_default_flips() -> None:
    done = db.get_setting("sources.default_flips", {}) or {}
    changed = False
    choice = None
    if any(done.get(sid) != tag for sid, tag in TERMS_OFFS.items()):
        from . import feed_terms   # read before any flag below is written (a written flag makes a lake "not new")
        try:
            choice = feed_terms.peek()
        except Exception:
            choice = "pending"   # unsure: do not pin (the source stays off until the user turns it on)
    for sid, tag in DEFAULT_FLIPS.items():
        if done.get(sid) == tag:
            continue
        if state(sid).get("enabled") is False:
            _set_state(sid, enabled=None)
            log.info("source %s: default is now on; cleared the flag saved by an older version", sid)
        done[sid] = tag
        changed = True
    for sid, tag in DEFAULT_OFFS.items():
        if done.get(sid) == tag:
            continue
        st = state(sid)
        if st and st.get("enabled") is None:
            _set_state(sid, enabled=True)
            log.info("source %s: default is now off; kept it on for this existing lake", sid)
        done[sid] = tag
        changed = True
    for sid, tag in TERMS_OFFS.items():
        if done.get(sid) == tag:
            continue
        st = state(sid)
        if st and st.get("enabled") is None and choice != "pending":
            _set_state(sid, enabled=True)
            log.info("source %s: off until chosen now (its terms); kept it on for this existing lake", sid)
        done[sid] = tag
        changed = True
    if changed:
        db.set_setting("sources.default_flips", done)


async def start_all() -> None:
    global _client
    _client = httpx.AsyncClient(headers={"User-Agent": config.USER_AGENT}, timeout=45, follow_redirects=True,
                                transport=OfflineGuard() if config.OFFLINE else None)
    _apply_default_flips()
    try:   # EPSS made events in an earlier version; it no longer does (a score is enrichment, not activity)
        from .sources.vulns import purge_epss_events
        await asyncio.to_thread(purge_epss_events)
    except Exception as e:
        log.warning("removing old EPSS events failed: %s", e)
    for src in SOURCES.values():
        if (why := src.unavailable()):
            # a keyed source with no key: never started, whatever was saved; shown plainly on the Sources page
            _set_state(src.id, status="needs_key", message=why)
        elif is_enabled(src):
            start_source(src)
        else:
            # Only the status: the saved flag stays as it was (unset = the source's default), so a source whose
            # default later changes to on is not held off by a flag nobody chose.
            _set_state(src.id, status="disabled")
    _tasks["_checkpoint"] = asyncio.create_task(_checkpoint_loop(), name="checkpoint")
    _tasks["_housekeeping"] = asyncio.create_task(_housekeeping_loop(), name="housekeeping")


async def _housekeeping_loop() -> None:
    # Close finished stream hours every minute; apply user retention (if set) hourly.
    ticks = 0
    while True:
        try:
            await asyncio.to_thread(lake.finalize_streams)
            if ticks % 60 == 0 and any(lake.retention().values()):
                res = await asyncio.to_thread(lake.purge)
                log.info("retention purge: %s", res)
        except Exception as e:
            log.warning("housekeeping failed: %s", e)
        ticks += 1
        await asyncio.sleep(60)


async def stop_all() -> None:
    for t in _tasks.values():
        t.cancel()
    if _client:
        await _client.aclose()

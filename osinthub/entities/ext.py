"""Registers the entities package with osinthub.ext. Docs: okf/data/entities.md"""
from __future__ import annotations

import asyncio
import logging
import time

from .. import db, ext
from . import api, link, procvec, refdata, scoring, searcher, store

log = logging.getLogger("osinthub.entities")

REF_KEY = "entities.reference_mtime"
SCORING_KEY = "entities.scoring_version"
INTERVAL = 60


def _reference_import() -> dict:
    st = refdata.ensure()
    mt = max((refdata.path(k).stat().st_mtime for k in refdata.FILES if refdata.path(k).exists()), default=0)
    done = db.get_setting(REF_KEY)
    out = {"files": st}
    if mt and done != mt:
        refdata.reload()
        out.update(link.link_reference())
        db.set_setting(REF_KEY, mt)
    out["placeholders_removed"] = link.cleanup_placeholders()
    try:   # once per lake: AI output derived from feeds that are now AI-excluded (Feodo, 2026-11-19)
        out["ai_excluded_purge"] = searcher.purge_ai_excluded_once()
    except Exception as e:
        log.warning("AI-excluded purge failed: %s", e)
    if db.get_setting(SCORING_KEY) != scoring.SCORING_VERSION:
        # the confidence scale changed: rescore every observed and reported claim once
        store.execute("UPDATE claims SET confidence = NULL WHERE origin IN ('observed','reported','local')")
        # and recompute inferred links, which carry their own (capped) confidence
        out["inferred"] = scoring.infer_links()
        db.set_setting(SCORING_KEY, scoring.SCORING_VERSION)
        out["rescored"] = True
    return out


def _pass() -> dict:
    t0 = time.time()
    n = 0
    while True:
        k = link.link_pending(5000)
        n += k
        if k < 5000:
            break
    pfx = link.link_ip_prefixes() if n else 0
    sc = scoring.drain_dirty()
    return {"events_linked": n, "in_prefix": pfx, **sc, "seconds": round(time.time() - t0, 1)}


async def link_loop():
    """Backfill, then link new events every minute; score incrementally; embed names."""
    try:
        api.STATUS["reference"] = await asyncio.to_thread(_reference_import)
    except Exception as e:
        api.STATUS["reference"] = {"error": f"{type(e).__name__}: {e}"}
        log.warning("reference import failed: %s", e)
    while True:
        res = await asyncio.to_thread(_pass)
        api.STATUS["last_pass"] = {**res, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        if res["events_linked"]:
            log.info("entities: %s", res)
        if procvec.load() is None:
            try:   # once: embed ATT&CK procedure examples for the technique verifier
                n = await asyncio.to_thread(procvec.build)
                api.STATUS["procedures_indexed"] = n
            except Exception as e:
                log.debug("procedure index skipped: %s", e)
        try:
            nv = await asyncio.to_thread(searcher.embed_pending)
            if nv:
                api.STATUS["embedded"] = api.STATUS.get("embedded", 0) + nv
        except Exception as e:
            log.debug("entity embedding skipped: %s", e)
        await asyncio.sleep(INTERVAL)


def _on_start():
    store.ensure_schema()
    db.execute(searcher.VEC_SCHEMA)


searcher.register()
ext.register("entities", schema_sql=store.SCHEMA + searcher.VEC_SCHEMA, router=api.router, tasks=(link_loop,), on_start=_on_start)

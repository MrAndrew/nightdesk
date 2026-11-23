"""Registers netlog with the extension registry (osinthub/ext.py)."""
from __future__ import annotations

import asyncio
import logging

from .. import ext
from . import util
from .api import router
from .ingest import import_pushes, mgmt, supervise_listener, watch_senders
from .devices import AGG_SQL
from .importer import LEDGER_SQL
from .schema import SCHEMA_SQL
from .seen import router as seen_router

log = logging.getLogger("osinthub.netlog")


async def watch_inbox() -> None:
    """Poll the inbox folder (util.inbox_settings; <lake>/inbox/zeek/ by default) and import settled new or changed
    files. The folder is read on every pass, so a new folder takes effect on the next scan."""
    from . import importer
    while True:
        try:
            res = await asyncio.to_thread(importer.scan_inbox)
            if res:
                log.info("netlog inbox: imported %d file(s)", len(res))
        except Exception as e:
            log.warning("netlog inbox scan failed: %s", e)
        await asyncio.sleep(float(util.settings().get("inbox_poll_seconds") or 15))


async def follow_threat_data() -> None:
    """After each batch run writes record deltas, update indicator_intervals and re-hunt recent logs."""
    from . import intervals, matcher
    while True:
        try:
            changed = await asyncio.to_thread(intervals.refresh)
            if changed:
                res = await asyncio.to_thread(matcher.rehunt)
                log.info("netlog re-hunt after %s: %s", changed, res)
        except Exception as e:
            log.warning("netlog threat refresh failed: %s", e)
        await asyncio.sleep(float(util.settings().get("ti_poll_seconds") or 60))


async def fetch_allowlist() -> None:
    """Download the Tranco top list once when online (it is then used offline)."""
    from . import allowlist
    res = await asyncio.to_thread(allowlist.ensure_tranco)
    if not res.get("ok"):
        log.info("netlog allowlist: %s", res.get("reason"))


router.include_router(mgmt)  # /api/netlog/ingest: push-upload settings and senders (ingest.py)
router.include_router(seen_router)  # /api/netlog/seen: "seen on your network" lookup (seen.py)
from . import newdev, ownlists  # noqa: E402
router.include_router(ownlists.router)  # /api/netlog/lists: your own lists (ownlists.py)
router.include_router(newdev.router)    # /api/netlog/newdev: the new-device rule (newdev.py)
ext.register("netlog", schema_sql=SCHEMA_SQL + AGG_SQL + LEDGER_SQL, router=router,
             tasks=(watch_inbox, follow_threat_data, fetch_allowlist, supervise_listener, import_pushes, watch_senders))

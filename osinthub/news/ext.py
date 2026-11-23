"""Registers the news package with the extension registry (osinthub/ext.py). Docs: okf/data/news.md"""
from __future__ import annotations

import asyncio

from .. import ext
from . import sources  # noqa: F401  (registers the research and news feeds)
from .api import router
from .common import log
from .fetcher import enqueue_from_events, fetch_loop, fix_titles, regrade_tiers
from .pipeline import entity_loop, process_loop, summary_loop
from .schema import SCHEMA
from .search import searcher


def _register_searcher() -> None:
    try:
        from .. import search
        search.register_searcher("article", searcher)
    except Exception as e:
        log.warning("could not register article searcher: %s", e)


async def on_start() -> None:
    _register_searcher()
    await asyncio.to_thread(fix_titles)
    if await asyncio.to_thread(regrade_tiers):
        from . import stories
        await asyncio.to_thread(stories.refresh_all)
    await asyncio.to_thread(enqueue_from_events)   # backfill: queue articles for existing news events


ext.register("news", schema_sql=SCHEMA, router=router, tasks=(fetch_loop, process_loop, entity_loop, summary_loop), on_start=on_start)

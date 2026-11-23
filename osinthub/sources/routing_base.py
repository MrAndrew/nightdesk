"""Shared bits of the routing watch sources (RPKI file, Cloudflare Radar, RIPEstat): none of them runs, or is even
started, until the watchlist has an entry (okf/project/routing-watch.md)."""
from __future__ import annotations

from ..routing import usage, watchlist
from .base import Source


class RoutingSource(Source):
    category = "infra"
    group = "routing"

    def waiting(self) -> str | None:
        return watchlist.waiting()

    def unavailable(self) -> str | None:
        return self.waiting()

    def paused_now(self) -> str | None:
        return usage.why_paused()

    def describe(self) -> dict:
        d = super().describe()
        why = d.get("unavailable")
        d["needs"] = None if not why else ("watchlist" if why == watchlist.WAITING else "key")
        return d

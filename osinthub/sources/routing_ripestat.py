"""RIPEstat lookups for each watched network. Off by default: an explicit opt-in, because RIPE sees which networks
are looked up.

Per watch and check: `routing-status` (origins, more-specifics, visibility, announced space), `bgp-update-activity`
(updates since the last check), `asn-neighbours` for an AS (its upstreams), and `rpki-validation` per origin and
prefix only when the local RPKI file is not loaded. That is 2-3 requests per watch, so 25 watches every 6 hours
are about 300 requests a day (RIPE asks heavier users, over 1,000 a day, to register).

Polite by construction: every request carries `sourceapp=night-desk` (nothing personal), at most CONCURRENCY are in
flight, each waits a short random moment first, 429 and 5xx answers are retried twice with growing pauses, and a
daily cap (DAILY_CAP requests) stops the lookups for the day. Terms: okf/sources/current/ripestat.md.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import random

import httpx

from ..routing import detect, net, usage, watchlist
from . import caps
from .registry import register
from .routing_base import RoutingSource

BASE = os.environ.get("OSINTHUB_RIPESTAT_URL", "https://stat.ripe.net/data")
SOURCEAPP = "night-desk"
CONCURRENCY = 4
DAILY_CAP = 900
MAX_RPKI_LOOKUPS = 5      # per prefix watch and check, when the local RPKI file is not loaded
_sleep = asyncio.sleep    # tests replace it


class CapReached(Exception):
    pass


@register
class RipeStat(RoutingSource):
    id = "ripestat"
    name = "RIPEstat — lookups for the networks you watch"
    provider = "RIPE NCC"
    homepage = "https://stat.ripe.net/"
    description = ("Who announces each watched network, how widely it is seen, its upstream networks and how busy its "
                   "routes are, looked up one network at a time. Off unless you turn it on: RIPE will see which "
                   "networks you look up.")
    default_enabled = False
    license = "RIPEstat terms (no redistribution)"
    _inflight = 0

    @property
    def interval(self) -> int:
        return watchlist.every()

    def jitter(self) -> float:
        return random.uniform(0, 0.05) * self.interval

    def _opted_in(self) -> bool:
        from .. import scheduler
        return scheduler.state(self.id).get("enabled") is True

    async def _call(self, client, sem, endpoint: str, params: dict) -> dict:
        async with sem:
            for attempt in range(3):
                await _sleep(random.uniform(0.05, 0.3))
                # the cap is exact: requests already counted plus those in flight (no await between check and claim)
                if usage.requests(self.id) + self._inflight >= DAILY_CAP:
                    raise CapReached()
                self._inflight += 1
                try:
                    r = await net.get(client, f"{BASE}/{endpoint}/data.json", sid=self.id,
                                      params={**params, "sourceapp": SOURCEAPP}, headers={"Accept": "application/json"})
                finally:
                    self._inflight -= 1
                if r.status_code == 200:
                    try:
                        return (json.loads(r.content) or {}).get("data") or {}
                    except ValueError:
                        raise RuntimeError("RIPEstat sent something that is not JSON") from None
                if r.status_code in (429, 500, 502, 503, 504) and attempt < 2:
                    await _sleep(2 * 2 ** attempt + random.uniform(0, 1))
                    continue
                raise RuntimeError(f"RIPEstat answered HTTP {r.status_code}")
        raise RuntimeError("RIPEstat did not answer")

    async def _one(self, client, sem, w: dict, hours: float, local_rpki: bool) -> dict:
        now = dt.datetime.now(dt.UTC)
        d: dict = {"ok": True, "hours": hours}
        try:
            d["status"] = await self._call(client, sem, "routing-status", {"resource": w["id"]})
            if w["kind"] == "asn":
                d["neighbours"] = await self._call(client, sem, "asn-neighbours", {"resource": w["id"]})
            elif not local_rpki:
                pairs = [(w["id"], o.get("origin")) for o in d["status"].get("origins") or []]
                pairs += [(m.get("prefix"), m.get("origin")) for m in d["status"].get("more_specifics") or []]
                d["rpki"] = {}
                for p, o in [x for x in pairs if x[0] and str(x[1]).isdigit()][:MAX_RPKI_LOOKUPS]:
                    v = await self._call(client, sem, "rpki-validation", {"resource": f"AS{o}", "prefix": p})
                    s = str(v.get("status") or "unknown").lower()
                    d["rpki"][f"{p}|{int(o)}"] = "invalid" if s.startswith("invalid") else ("valid" if s == "valid" else "unknown")
            start = now - dt.timedelta(hours=hours)
            d["updates"] = await self._call(client, sem, "bgp-update-activity", {
                "resource": w["id"], "starttime": start.strftime("%Y-%m-%dT%H:%M"), "endtime": now.strftime("%Y-%m-%dT%H:%M")})
        except net.LimitReached:   # a pause, not a failure (the run ends as "paused")
            return {"ok": False, "paused": True, "why": "today's data limit was reached"}
        except CapReached:
            return {"ok": False, "paused": True, "why": f"Night Desk's daily allowance of {DAILY_CAP} RIPEstat lookups is used up"}
        except net.Offline:
            return {"ok": False, "why": "offline mode"}
        except caps.TooLarge:   # an oversized answer fails the run: nothing partial is stored
            raise
        except Exception as e:
            return {"ok": False, "why": str(e)[:160] if isinstance(e, RuntimeError) else net.short_error(e, "stat.ripe.net")}
        return d

    async def fetch(self, client: httpx.AsyncClient) -> bytes:
        if not self._opted_in():
            raise RuntimeError("RIPEstat lookups are off. Turn them on in Routing watch first.")
        if usage.over():
            raise net.LimitReached(usage.why_paused())
        if (why := self.paused_now()):
            raise net.LimitReached(why)
        wl = watchlist.load()
        sem = asyncio.Semaphore(CONCURRENCY)
        hours = max(self.interval / 3600, 0.25)
        local = "_meta" in detect.roas()
        res = await asyncio.gather(*(self._one(client, sem, w, hours, local) for w in wl))
        return json.dumps({w["id"]: r for w, r in zip(wl, res)}).encode()

    def fetch_errors(self, raw: bytes) -> list[str]:
        d = json.loads(raw)
        bad = [r.get("why") for r in d.values() if not r.get("ok") and not r.get("paused")]
        return [f"{len(bad)} of {len(d)} networks could not be checked ({bad[0]})"] if bad else []

    def paused_now(self) -> str | None:
        if usage.requests(self.id) >= DAILY_CAP:
            return (f"Paused for today: Night Desk's daily allowance of {DAILY_CAP} RIPEstat lookups is used up. "
                    "It starts again after midnight.")
        return super().paused_now()

    def parse(self, raw: bytes):
        detect.ingest_ripestat(json.loads(raw))
        return []

    def records(self, raw: bytes):
        return [(wid, r) for wid, r in json.loads(raw).items() if r.get("ok")]

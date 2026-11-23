"""Cloudflare Radar: recent BGP hijack and route-leak events, matched to the watchlist on this computer.

* Needs the user's own free Cloudflare API token with Radar read access (Routing watch's token field, saved in a
  file only this user can read, or CLOUDFLARE_RADAR_TOKEN). The token travels only in the Authorization header,
  never in a URL, a log line, a run record or an API answer.
* Private by design: the requests name no ASN or prefix. They list every recent event (`dateRange`, `sortBy=TIME`,
  paging) and the match happens here (osinthub/routing/detect.py ingest_radar).
* Radar data is CC BY-NC 4.0 (non-commercial, with attribution): okf/sources/current/cf_radar_bgp.md.
"""
from __future__ import annotations

import asyncio
import json
import os
import random

import httpx

from ..routing import detect, net, watchlist
from .registry import register
from .routing_base import RoutingSource

BASE = os.environ.get("OSINTHUB_RADAR_URL", "https://api.cloudflare.com/client/v4/radar/bgp")
PER_PAGE = 100
MAX_PAGES = 10


class TokenRefused(RuntimeError):
    pass


@register
class RadarBgp(RoutingSource):
    id = "cf_radar_bgp"
    name = "Cloudflare Radar — BGP hijacks and leaks"
    provider = "Cloudflare Radar"
    homepage = "https://radar.cloudflare.com/routing"
    description = ("Suspected hijacks and route leaks Cloudflare Radar detects worldwide. Night Desk lists all recent "
                   "events and picks out the ones that involve your watched networks here, so Cloudflare does not learn "
                   "what you watch. Needs your own free Cloudflare API token.")
    default_enabled = False   # switched on by routing.api.sync() once it can run (osinthub/routing/api.py AUTO_ON)
    license = "CC BY-NC 4.0"
    needs_key = watchlist.TOKEN_ENV

    @property
    def interval(self) -> int:
        return watchlist.every()

    def jitter(self) -> float:
        return random.uniform(0, 0.05) * self.interval

    def unavailable(self) -> str | None:
        if not watchlist.token():
            # the in-app field is the one way that works on every install (Docker Compose does not pass the variable)
            return "Add your free Cloudflare API token (with Radar read access) in Settings › Sources › Routing watch."
        return self.waiting()

    def _range(self) -> str:
        return "1d" if self.interval < 86400 else "2d"

    async def _list(self, client: httpx.AsyncClient, what: str) -> list[dict]:
        tok = watchlist.token()
        hdrs = {"Authorization": f"Bearer {tok}", "Accept": "application/json"}
        out: list[dict] = []
        for page in range(1, MAX_PAGES + 1):
            params = {"dateRange": self._range(), "sortBy": "TIME", "sortOrder": "DESC", "page": page,
                      "per_page": PER_PAGE, "format": "json"}
            try:
                r = await net.get(client, f"{BASE}/{what}/events", sid=self.id, params=params, headers=hdrs)
            except (net.LimitReached, net.Offline):
                raise
            except Exception as e:
                raise RuntimeError(net.short_error(e, "api.cloudflare.com")) from None
            if r.status_code in (401, 403):
                raise TokenRefused(f"Cloudflare refused the token (HTTP {r.status_code}). Check that it is valid and "
                                   "has Radar read access.")
            if r.status_code != 200:
                raise RuntimeError(f"Cloudflare Radar answered HTTP {r.status_code}")
            try:
                d = json.loads(r.content)
            except ValueError:
                raise RuntimeError("Cloudflare Radar sent something that is not JSON") from None
            res = d.get("result") or {}
            evs = res.get("events") or []
            out += [e for e in evs if isinstance(e, dict)]
            info = d.get("result_info") or res.get("result_info") or {}
            total = info.get("total_count")
            if len(evs) < PER_PAGE or (isinstance(total, int) and len(out) >= total):
                break
        return out

    async def fetch(self, client: httpx.AsyncClient) -> bytes:
        try:
            hijacks = await self._list(client, "hijacks")
            leaks = await self._list(client, "leaks")
        except (net.LimitReached, net.Offline):
            raise
        except Exception as e:
            await asyncio.to_thread(detect.note_check, self.id, False, str(e)[:200])
            raise
        return json.dumps({"hijacks": hijacks, "leaks": leaks}).encode()

    def parse(self, raw: bytes):
        d = json.loads(raw)
        self._matched = detect.ingest_radar(d.get("hijacks") or [], d.get("leaks") or [])
        return []

    def records(self, raw: bytes):
        m = getattr(self, "_matched", None)
        if m is None:
            d = json.loads(raw)
            m = detect.ingest_radar(d.get("hijacks") or [], d.get("leaks") or [])
        self._matched = None
        return [(f"{x['watch']}|{x['type']}|{x.get('id')}", x) for x in m]

"""Live stream sources (websockets)."""
from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import os
import re
import ssl
import time

import certifi
import websockets

from .. import bus, config, geo
from .base import UTC, Event, Source, StreamSink, log, make_id, now, to_ts
from .registry import register
from .text import fix_encoded_events, unentity

SSL_CTX = ssl.create_default_context(cafile=certifi.where())


def _prefix_ip(prefix: str) -> str | None:
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None
    return str(net.network_address + 1) if net.num_addresses > 1 else str(net.network_address)


RIS_URL = os.environ.get("OSINTHUB_RISLIVE_URL", "wss://ris-live.ripe.net/v1/ws/?client=night-desk")
FLUSH_S = 1.0   # matched announcements reach the routing rules within this, message or not


def _until_midnight() -> float:
    t = dt.datetime.now()
    return (dt.datetime.combine(t.date() + dt.timedelta(days=1), dt.time()) - t).total_seconds() + 5


@register
class RisLive(Source):
    """RIS Live, following only the routing watchlist (okf/sources/current/ris_live.md). Never connects while the
    watchlist is empty (unavailable(): the source is not even started), subscribes with one `prefix` filter
    (moreSpecific) per watched prefix and one `path: "<ASN>$"` filter per watched AS on one connection, counts the
    bytes it receives against the routing daily data limit and disconnects for the rest of the day when it is
    reached. Unfiltered, the stream was about 13 GB a day (okf/project/routing-watch.md)."""
    id = "ris_live"
    name = "RIPE RIS Live — live updates for watched networks"
    provider = "RIPE NCC"
    homepage = "https://ris-live.ripe.net/"
    description = ("Live BGP updates from RIPE's route collector, for the networks in Routing watch only. Flags an "
                   "unexpected origin or an RPKI-invalid announcement within seconds. Uses about 70 MB a day per "
                   "watched AS, counted against the routing daily data limit. RIPE sees the networks you follow.")
    category = "advanced"
    mode = "stream"
    interval = 0
    license = "RIPE NCC terms"
    collector = "rrc00"
    default_enabled = False   # was on (the global firehose); off since 2026-11-17, and watchlist-only when on

    def unavailable(self) -> str | None:
        from ..routing import watchlist
        return watchlist.waiting()

    def describe(self) -> dict:
        d = super().describe()
        d["needs"] = "watchlist" if d.get("unavailable") else None
        return d

    @staticmethod
    def subscriptions(wl: list[dict], host: str = "rrc00") -> list[dict]:
        subs = []
        for w in wl:
            data = {"type": "UPDATE", "host": host}
            if w["kind"] == "prefix":
                data.update(prefix=w["id"], moreSpecific=True)
            else:
                data.update(path=f"{int(w['id'][2:])}$")
            subs.append({"type": "ris_subscribe", "data": data})
        return subs

    async def _pause(self, why: str) -> None:
        from .. import scheduler
        from ..routing import detect, usage
        await scheduler._aset_state(self.id, status="paused", message=why[:300])
        await asyncio.to_thread(detect.note_check, self.id, False, why)
        end = time.monotonic() + _until_midnight()
        while time.monotonic() < end and usage.over():
            await asyncio.sleep(60)

    async def stream(self, sink: StreamSink) -> None:
        if config.OFFLINE:  # no outbound connections in offline mode
            return
        from ..routing import detect, usage, watchlist
        wl = watchlist.load()
        if not wl:   # never a firehose: nothing to follow, nothing to connect to
            await asyncio.sleep(3600)
            return
        if usage.over():
            await self._pause(usage.why_paused())
            return
        pfx = {w["id"]: ipaddress.ip_network(w["id"]) for w in wl if w["kind"] == "prefix"}
        asns = {int(w["id"][2:]): w["id"] for w in wl if w["kind"] == "asn"}
        kw = {"ssl": SSL_CTX} if RIS_URL.startswith("wss:") else {}
        pending: list[tuple[str, str, int]] = []   # matched (watch, prefix, origin), handed to the rules within FLUSH_S

        async def flush_pending():
            if pending:
                batch = pending[:]
                del pending[:]
                # shielded: a cancel (a watchlist edit restarts the stream) never loses a finding already seen
                await asyncio.shield(asyncio.to_thread(detect.observe_announcements, batch))

        async def background(ws):   # independent of incoming messages: a single announcement on a quiet prefix counts
            from .. import scheduler
            n = 0
            while True:
                if n % max(1, int(600 / FLUSH_S)) == 0:   # a quiet stream is still a working check (every 10 min)
                    await asyncio.to_thread(detect.note_check, self.id, True)
                await asyncio.sleep(FLUSH_S)
                await flush_pending()
                if usage.over():   # another source used up the limit: say so now and disconnect
                    await scheduler._aset_state(self.id, status="paused", message=(usage.why_paused() or "")[:300])
                    await ws.close()
                    return
                n += 1

        async with websockets.connect(RIS_URL, max_size=2**22, ping_interval=20, close_timeout=2, **kw) as ws:
            for sub in self.subscriptions(wl, self.collector):
                await ws.send(json.dumps(sub))
            bg = asyncio.create_task(background(ws))
            try:
                await self._read(ws, sink, pfx, asns, pending)
            finally:
                bg.cancel()
                await flush_pending()
        # The socket is closed here. Only now wait out the day (a cancel skips this: nothing sleeps with it open).
        if usage.over():
            await self._pause(usage.why_paused())

    async def _read(self, ws, sink: StreamSink, pfx: dict, asns: dict, pending: list) -> None:
        from .. import scheduler
        from ..routing import usage
        seen: set[tuple[str, str, int]] = set()
        counts = {"ann": 0, "wd": 0, "msgs": 0}
        tick = time.monotonic()
        last_pulse = 0.0
        async for raw in ws:
            usage.add(self.id, len(raw) + 8, save=False)   # count on the loop; persist off it (throttled)
            await asyncio.to_thread(usage.maybe_save)
            if usage.over():   # say so at once, then disconnect for the rest of the day
                await scheduler._aset_state(self.id, status="paused", message=(usage.why_paused() or "")[:300])
                await ws.close()
                return
            m = json.loads(raw)
            if m.get("type") != "ris_message":
                continue
            d = m.get("data") or {}
            counts["msgs"] += 1
            path = [p for p in d.get("path", []) if isinstance(p, int)]
            origin = path[-1] if path else None
            ts = d.get("timestamp", time.time())
            for ann in d.get("announcements", []):
                for p in ann.get("prefixes", []):
                    counts["ann"] += 1
                    if origin is None:
                        continue
                    try:
                        pn = ipaddress.ip_network(p, strict=False)
                    except ValueError:
                        continue
                    hits = [wid for wid, n in pfx.items() if pn.version == n.version and pn.subnet_of(n)]
                    if origin in asns:
                        hits.append(asns[origin])
                    for wid in hits:
                        k = (wid, str(pn), origin)
                        if k not in seen and len(seen) < 50_000:
                            seen.add(k)
                            pending.append(k)
                    if ts - last_pulse > 0.25:  # sampled live pulse for the map, not stored
                        last_pulse = ts
                        ip = _prefix_ip(p)
                        g = geo.locate_ip(ip) if ip else None
                        if g and g.get("lat") is not None:
                            bus.publish("bgp_pulse", {"lat": g["lat"], "lon": g["lon"], "prefix": p,
                                                      "origin": origin, "kind": "announce", "cc": g["country"]})
            counts["wd"] += len(d.get("withdrawals", []))
            t = time.monotonic()
            if t - tick >= 5:
                el = t - tick
                await sink.metric("bgp.announcements_per_s", counts["ann"] / el)
                await sink.metric("bgp.withdrawals_per_s", counts["wd"] / el)
                await sink.metric("bgp.updates_per_s", counts["msgs"] / el)
                counts = {"ann": 0, "wd": 0, "msgs": 0}
                tick = t
                await sink.flush()


CYBER_TERMS = re.compile(
    r"\b(CVE-\d{4}-\d{4,}|ransomware|zero[- ]?day|0day|data breach|breached|ddos|botnet|malware|phishing|"
    r"exploit(?:ed|ation)?|apt\d+|threat actor|infostealer|backdoor|vulnerability|leak site|hacktivist|"
    r"cyberattack|cyber attack|outage)\b",
    re.I,
)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


@register
class BlueskyCyber(Source):
    id = "bluesky_cyber"
    name = "Bluesky firehose — cyber chatter"
    provider = "Bluesky Jetstream"
    homepage = "https://github.com/bluesky-social/jetstream"
    description = ("Every public Bluesky post, filtered live for cyber keywords (CVE IDs, ransomware, zero-days, "
                   "breaches, DDoS, botnets). Posts are tagged with mentioned CVEs and countries.")
    category = "social"
    mode = "stream"
    interval = 0
    license = "Public posts, Bluesky ToS"
    # Off for new lakes: an unvetted social firehose (tier D). A lake that already ran it keeps it on
    # (scheduler.DEFAULT_OFFS pins the old default once).
    default_enabled = False
    # Deleted posts: Bluesky asks services to have a method for deleting content a user asked to be deleted. Night
    # Desk runs on the user's own machine and the user manages that data (NOTICE, "Your data and the sources you turn
    # on"); the stream records each delete of a post it stored in `deletion_requests` (db.record_deletion_requests)
    # and leaves the post as it is, so nothing is hidden. Deletes made while Night Desk is stopped are not seen.

    def post_event(self, m: dict) -> Event | None:
        """The event for one Jetstream 'create' commit, or None when the post is not English cyber chatter. The text
        is decoded first: posts copied from web pages or made by feed bots can carry HTML entities ('&amp;', '&#39;')
        that Bluesky stores as typed. Keys and the post URL use the DID and rkey as given."""
        c = m.get("commit") or {}
        rec = c.get("record") or {}
        text = unentity(rec.get("text"))
        hits = CYBER_TERMS.findall(text)
        if not hits or len(text) < 40:
            return None
        # need a CVE id or two distinct cyber terms, to drop casual "I got malware lol" chatter
        if not CVE_RE.search(text) and len({h.lower() for h in hits}) < 2:
            return None
        langs = rec.get("langs") or []
        if langs and "en" not in langs:
            return None
        cves = sorted({h.upper() for h in CVE_RE.findall(text)})
        ccs = geo.tag_countries(text)
        did = m.get("did", "")
        rkey = c.get("rkey", "")
        return Event(
            source=self.id, kind="social", key=(did, rkey), ts=to_ts(rec.get("createdAt")),
            title=text[:140], summary=text[:600], category="social",
            severity=0.55 if cves else 0.3, country=ccs[0] if ccs else None,
            url=f"https://bsky.app/profile/{did}/post/{rkey}",
            tags=[h.lower() for h in dict.fromkeys(hits)][:5] + cves + ccs,
        )

    def deletion(self, m: dict) -> tuple[str, dt.datetime]:
        """(event id, when) for one Jetstream 'delete' commit: the id the post has if it was stored (post_event's key),
        and Jetstream's time for the delete, else now."""
        c = m.get("commit") or {}
        us = m.get("time_us")
        when = dt.datetime.fromtimestamp(us / 1e6, UTC) if isinstance(us, int) and us > 0 else now()
        return make_id(self.id, m.get("did", ""), c.get("rkey", "")), when

    async def record_deletions(self, gone: list[tuple[str, dt.datetime]]) -> list:
        """Mark the stored posts among `gone` as requested to be deleted; returns the empty list to collect into."""
        if gone:
            from .. import db
            n = await asyncio.to_thread(db.record_deletion_requests, self.id, gone)
            if n:
                log.info("bluesky: %d stored post(s) deleted by their authors, marked in deletion_requests", n)
        return []

    async def stream(self, sink: StreamSink) -> None:
        if config.OFFLINE:  # no outbound connections in offline mode
            return
        # Posts stored before the text was decoded: a stream never sees a post again, so they are fixed in place on
        # connect (cheap once nothing is left to fix).
        await asyncio.to_thread(fix_encoded_events, self.id, False)
        url = ("wss://jetstream2.us-east.bsky.network/subscribe"
               "?wantedCollections=app.bsky.feed.post")
        seen = 0
        matched = 0
        gone: list[tuple[str, dt.datetime]] = []   # deletes since the last flush (most are posts never stored)
        tick = time.monotonic()
        async with websockets.connect(url, ssl=SSL_CTX, max_size=2**22, ping_interval=20) as ws:
            async for raw in ws:
                m = json.loads(raw)
                if m.get("kind") != "commit":
                    continue
                c = m.get("commit") or {}
                op = c.get("operation")
                if op == "delete":
                    gone.append(self.deletion(m))
                elif op == "create":
                    seen += 1
                    ev = self.post_event(m)
                    if ev is not None:
                        matched += 1
                        sink.emit(ev)
                        bus.publish("social", {"title": ev.title, "url": ev.url, "tags": ev.tags,
                                               "ts": ev.ts.isoformat(), "author": m.get("did", "")})
                else:
                    continue
                t = time.monotonic()
                if t - tick >= 10:
                    await sink.metric("bluesky.posts_per_s", seen / (t - tick))
                    await sink.metric("bluesky.cyber_per_min", matched * 60 / (t - tick))
                    seen = matched = 0
                    tick = t
                    await sink.flush()   # first, so a post deleted within these ten seconds is stored and then marked
                    gone = await self.record_deletions(gone)

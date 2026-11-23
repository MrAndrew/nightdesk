"""RPKI signed routes: the daily bulk file of validated ROAs, checked locally against the watchlist.

* Default URL https://rpki.cloudflare.com/rpki.json (it sends an ETag and Last-Modified, so an unchanged file is a
  304 and costs a few hundred bytes); fallback https://console.rpki-client.org/rpki.json. Both are configurable
  (OSINTHUB_RPKI_URL, OSINTHUB_RPKI_FALLBACK_URL). The publishers state no terms (okf/sources/current/rpki_roas.md).
* The whole file (about 5 MB compressed, about a million entries) is parsed here and only the entries for watched
  ASNs and prefixes that overlap a watched prefix are kept: nobody learns the watchlist and the lake never holds the
  file. The last download is cached in lake/cache/ (rpki-cache.json.gz), so a new watch is filtered from it
  with no download; a download (conditional, so usually a 304) happens only when the daily check is due.
* Counts against the routing daily data limit; a download that would cross it is stopped (the source pauses).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import gzip
import json
import os
import re

import httpx

from .. import config, db
from ..routing import detect, net, watchlist
from .base import Unchanged
from .registry import register
from .routing_base import RoutingSource

URL = os.environ.get("OSINTHUB_RPKI_URL", "https://rpki.cloudflare.com/rpki.json")
FALLBACK_URL = os.environ.get("OSINTHUB_RPKI_FALLBACK_URL", "https://console.rpki-client.org/rpki.json")
META_KEY = "routing.rpki_meta"


def cache_path():
    """The last downloaded file, gzipped, in lake/cache/: a working cache (one file, replaced each download, deleted
    when the watchlist is emptied) so a new watch is filtered from it instead of downloading again. Not part of any
    run's records; counted in Settings › Data and retention."""
    return config.LAKE / "cache" / "rpki-cache.json.gz"


def forget_cache() -> None:
    cache_path().unlink(missing_ok=True)
    meta = db.get_setting(META_KEY, None)
    if meta:
        db.set_setting(META_KEY, {k: v for k, v in meta.items() if k != "downloaded"})


def _read_cache(p) -> bytes:
    return gzip.decompress(p.read_bytes())


def _write_cache(p, raw: bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_bytes(gzip.compress(raw, compresslevel=3, mtime=0))
    os.replace(tmp, p)


def _now_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def _t(s):
    try:
        d = dt.datetime.fromisoformat(str(s))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.UTC)

_OBJ = re.compile(rb"\{[^{}]*\}")
_PFX = re.compile(rb'"prefix"\s*:\s*"([0-9A-Fa-f.:]+)/(\d{1,3})"')
_ASN = re.compile(rb'"asn"\s*:\s*"?(?:AS)?(\d+)"?')
_MAX = re.compile(rb'"max[Ll]ength"\s*:\s*(\d+)')
_TA = re.compile(rb'"ta"\s*:\s*"([^"]{0,40})"')


def _lead(addr: bytes) -> tuple[int, int] | None:
    """(version, first octet or first 16 bits) of an address string, for a cheap pre-filter."""
    try:
        if b":" in addr:
            h = addr.split(b":", 1)[0]
            return (6, int(h, 16)) if h else None
        return 4, int(addr.split(b".", 1)[0])
    except ValueError:
        return None


def filter_roas(raw: bytes, wl: list[dict]) -> list[list]:
    """[prefix, max_length, asn, ta] for each ROA naming a watched ASN or overlapping a watched prefix."""
    import ipaddress
    asns = set(watchlist.asns(wl))
    nets = list(watchlist.prefixes(wl).values())
    leads: set[tuple[int, int]] = set()
    for n in nets:   # every watched prefix is at least a /8 (v4) or /16 (v6) long: one lead value each
        a = n.network_address.packed
        leads.add((4, a[0]) if n.version == 4 else (6, int.from_bytes(a[:2], "big")))
    out = []
    for m in _OBJ.finditer(raw):
        o = m.group(0)
        p = _PFX.search(o)
        a = _ASN.search(o)
        if not p or not a:
            continue
        asn = int(a.group(1))
        plen = int(p.group(2))
        hit = asn in asns
        if not hit and nets:
            ld = _lead(p.group(1))
            short = ld is None or (ld[0] == 4 and plen < 8) or (ld[0] == 6 and plen < 16)
            if short or ld in leads:
                try:
                    rn = ipaddress.ip_network(f"{p.group(1).decode()}/{plen}", strict=False)
                except ValueError:
                    continue
                hit = any(rn.version == n.version and rn.overlaps(n) for n in nets)
        if not hit:
            continue
        mx = _MAX.search(o)
        ta = _TA.search(o)
        out.append([f"{p.group(1).decode()}/{plen}", int(mx.group(1)) if mx else plen, asn,
                    ta.group(1).decode() if ta else ""])
    return out


@register
class RpkiRoas(RoutingSource):
    id = "rpki_roas"
    name = "RPKI signed routes (daily file)"
    provider = "Cloudflare · rpki-client"
    homepage = "https://rpki.cloudflare.com/"
    description = ("Which networks may announce the addresses you watch, from the public daily list of signed route "
                   "origins (RPKI). The whole file is downloaded and checked on this computer, so nobody learns what "
                   "you watch. Runs only once you add a network to Routing watch.")
    interval = 86400
    default_enabled = False   # never on by itself (no stated terms): Routing watch asks once (routing/api.py ASK_FIRST)
    license = "No terms stated"
    windowed = True

    async def fetch(self, client: httpx.AsyncClient) -> bytes:
        wl = watchlist.load()
        fp = watchlist.fingerprint(wl)
        meta = db.get_setting(META_KEY, {}) or {}
        cache = cache_path()
        got = _t(meta.get("downloaded"))
        fresh = bool(got and cache.exists() and dt.datetime.now(dt.UTC) - got < dt.timedelta(seconds=self.interval))
        if fresh:
            if meta.get("fp") == fp:   # checked within the day and the list is the same: nothing to do
                await asyncio.to_thread(detect.note_check, self.id, True)
                raise Unchanged("the signed-route file was checked within the last day")
            # a changed watchlist: filter the copy downloaded today again, no download
            return await self._bundle(meta, fp, await asyncio.to_thread(_read_cache, cache), wl)
        errors = []
        for url in dict.fromkeys([URL, FALLBACK_URL]):
            hdrs = {"Accept": "application/json"}
            if meta.get("url") == url and cache.exists():
                if meta.get("etag"):
                    hdrs["If-None-Match"] = meta["etag"]
                if meta.get("last_modified"):
                    hdrs["If-Modified-Since"] = meta["last_modified"]
            host = httpx.URL(url).host
            try:
                r = await net.get(client, url, sid=self.id, headers=hdrs)
            except (net.LimitReached, net.Offline):
                raise
            except Exception as e:
                errors.append(net.short_error(e, host))
                continue
            if r.status_code == 304:
                meta["downloaded"] = _now_iso()
                await asyncio.to_thread(db.set_setting, META_KEY, meta)
                if meta.get("fp") == fp:
                    await asyncio.to_thread(detect.note_check, self.id, True)
                    raise Unchanged("the signed-route file has not changed since the last download")
                return await self._bundle(meta, fp, await asyncio.to_thread(_read_cache, cache), wl)
            if r.status_code != 200:
                errors.append(f"{host} answered HTTP {r.status_code}")
                continue
            if b'"roas"' not in r.content:
                errors.append(f"{host} sent a file with no signed routes in it")
                continue
            await asyncio.to_thread(_write_cache, cache, r.content)
            m = {"url": url, "etag": r.headers.get("etag"), "last_modified": r.headers.get("last-modified"),
                 "downloaded": _now_iso()}
            return await self._bundle(m, fp, r.content, wl)
        why = "; ".join(errors) or "no download address"
        await asyncio.to_thread(detect.note_check, self.id, False, f"the signed-route file could not be downloaded ({why})")
        raise RuntimeError(f"could not download the RPKI file: {why}")

    async def _bundle(self, meta: dict, fp: str, raw: bytes, wl: list[dict]) -> bytes:
        roas = await asyncio.to_thread(filter_roas, raw, wl)   # about a million entries: off the event loop
        return json.dumps({**{k: meta.get(k) for k in ("url", "etag", "last_modified", "downloaded")},
                           "fp": fp, "roas": roas}).encode()

    def parse(self, raw: bytes):
        detect.ingest_rpki(json.loads(raw)["roas"])
        return []

    def records(self, raw: bytes):
        return [(f"{r[0]}|{r[1]}|AS{r[2]}", r) for r in json.loads(raw)["roas"]]

    def commit(self, raw: bytes, collected_at) -> None:
        d = json.loads(raw)
        db.set_setting(META_KEY, {k: d.get(k) for k in ("url", "fp", "etag", "last_modified", "downloaded")})

    def stored_count(self) -> int | None:
        r = detect.roas()
        return sum(v.get("count", 0) for k, v in r.items() if k != "_meta") if r else None

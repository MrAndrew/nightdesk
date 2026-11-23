"""Byte caps for source downloads (okf/data/size-limits.md).

Every source reads its HTTP responses through `get()` (or `iter_decoded()` for a response it already
streams): the body is read in chunks and decoded here, with gzip and deflate inflated at most 64 KB at a
time, so a response counts by its decoded size and a gzip bomb is stopped at the cap without ever being
inflated whole. Over the cap the download stops with TooLarge (a clear message naming the host and the
cap); the source's run fails and nothing from that response is stored.

Caps are about 4x the largest response each source has been measured to send (tools/okf_sources.py
MEASURED, 2026-11-04, and the source pages), rounded up, with a 1 MB floor: a small list can easily
grow tenfold and 1 MB is harmless. Where a response can grow by design (NVD's 2,000-result page, the
RPKI file) the cap is set from the largest size the provider can send, as noted.
"""
from __future__ import annotations

import contextlib
import zlib
from collections.abc import AsyncIterator, Iterator

import httpx

MB = 1_000_000
FLOOR = 1 * MB
CHUNK = 64 * 1024            # most bytes one inflate step may produce

# source id -> cap in decoded bytes for any single response. Measured size per run in the comment.
CAPS: dict[str, int] = {
    "cisa_kev": 8 * MB,               # 1.8 MB
    "nvd_recent": 32 * MB,            # 3.7 MB average; a full 2,000-result page is ~18 MB (~9 KB a CVE)
    "feodo_c2": FLOOR,                # 2 KB
    "dshield_top": FLOOR,             # 50 KB (500 rows by design)
    "tor_exits": FLOOR,               # 18 KB
    "blocklist_de": 2 * MB,           # 369 KB
    "cins_army": FLOOR,               # 230 KB
    "et_compromised": FLOOR,          # 7 KB
    "spamhaus_drop": 2 * MB,          # 108 KB (DROP has been up to ~400 KB with ASN-DROP merged)
    "ransomware_live": FLOOR,         # 120 KB
    "ioda_outages": 2 * MB,           # 265 KB for both requests
    "security_news": 2 * MB,          # 260 KB for four feeds; per feed well under that
    "cisa_advisories": 2 * MB,        # changes.csv 232 KB (OT, ~4,000 lines); one CSAF document ~20 KB
    "epss": 12 * MB,                  # 2.8 MB gzip file (inflated separately: EPSS_INFLATED_CAP)
    "threatfox": 4 * MB,              # ~1 MB (estimate)
    "urlhaus": 2 * MB,                # ~400 KB (estimate; 1,000 URLs by design)
    "sslbl": 4 * MB,                  # 844 KB
    "rpki_roas": 300 * MB,            # ~5 MB compressed, about a million ROAs (~75 MB decoded, estimate)
    "cf_radar_bgp": 4 * MB,           # one page of events (estimate, no measurement)
    "ripestat": 8 * MB,               # one RIPEstat answer; a large ASN's neighbours are a few hundred KB (estimate)
    # research and news feeds (osinthub/news/sources.py)
    "news_therecord": FLOOR,          # 5 KB
    "news_securityweek": FLOOR,       # 13 KB
    "news_helpnetsecurity": FLOOR,    # 17 KB
    "news_cyberscoop": FLOOR,         # 70 KB
    "news_darkreading": FLOOR,        # 78 KB
    "news_talos": 5 * MB,             # 1.0 MB
    "news_unit42": FLOOR,             # 24 KB
    "news_mstic": 2 * MB,             # 494 KB
    "news_eset": FLOOR,               # 70 KB
    "news_elastic": 34 * MB,          # 8.4 MB (the whole blog in one feed)
    # reference files (osinthub/entities/refdata.py), sizes as downloaded on 2026-11-05
    "ref_attack": 224 * MB,           # enterprise-attack.json 55 MB
    "ref_misp_actor": 6 * MB,         # 1.5 MB
    "ref_misp_malpedia": 16 * MB,     # 3.8 MB
    "ref_misp_tool": 3 * MB,          # 543 KB
    "ref_psl": 2 * MB,                # 339 KB
    "ref_tlds": FLOOR,                # 10 KB
    "ref_tranco": 40 * MB,            # top-1m.csv.zip 9.7 MB (osinthub/netlog/allowlist.py, online installs only)
}
DEFAULT = 8 * MB                      # a source with no entry above (a new one should get its own)
EPSS_INFLATED_CAP = 64 * MB           # the EPSS CSV once un-gzipped: ~10 MB today (~300k CVEs x ~32 bytes)


def cap_for(sid: str) -> int:
    return CAPS.get(sid, DEFAULT)


def _mb(n: int) -> str:
    return f"{n / MB:g} MB" if n >= MB else f"{n // 1000} KB"


class TooLarge(RuntimeError):
    """A response passed its source's byte cap; the download stopped and nothing from it is stored."""


def too_large(host: str, cap: int) -> TooLarge:
    return TooLarge(f"{host} sent more than {_mb(cap)} (this source's size limit); stopped the download "
                    "and stored nothing from it")


class _Inflate:
    """A bounded zlib stream: never yields more than CHUNK bytes per step."""

    def __init__(self, enc: str):
        self.enc = enc
        self.d = zlib.decompressobj(16 + zlib.MAX_WBITS if enc in ("gzip", "x-gzip") else zlib.MAX_WBITS)
        self.first = True

    def feed(self, data: bytes):
        while data:
            try:
                out = self.d.decompress(data, CHUNK)
            except zlib.error:
                if self.enc == "deflate" and self.first:   # some servers send raw deflate (as httpx allows)
                    self.d, self.first = zlib.decompressobj(-zlib.MAX_WBITS), False
                    continue
                raise httpx.DecodingError(f"could not decode the {self.enc} response") from None
            self.first = False
            data = self.d.unconsumed_tail
            if out:
                yield out
            if self.d.eof:
                return

    def flush(self):
        out = self.d.flush()
        if out:
            yield out


def _decoders(r: httpx.Response) -> list[_Inflate]:
    encs = [e.strip().lower() for e in r.headers.get("content-encoding", "").split(",")]
    encs = [e for e in encs if e and e != "identity"]
    bad = [e for e in encs if e not in ("gzip", "x-gzip", "deflate")]
    if bad:   # only gzip and deflate are asked for (ACCEPT_ENCODING)
        raise httpx.DecodingError(f"unsupported content-encoding {bad[0]!r}")
    return [_Inflate(e) for e in reversed(encs)]   # the last one applied is undone first


ACCEPT_ENCODING = "gzip, deflate"


class _Body:
    """Decodes raw body chunks with bounded inflate steps and counts the decoded bytes against the cap."""

    def __init__(self, r: httpx.Response, cap: int, host: str):
        self.decs, self.cap, self.host, self.got = _decoders(r), cap, host, 0

    def _run(self, data: bytes, level: int):
        if level == len(self.decs):
            yield data
            return
        for part in self.decs[level].feed(data):
            yield from self._run(part, level + 1)

    def _tail(self, level: int):
        if level == len(self.decs):
            return
        for part in self.decs[level].flush():
            yield from self._run(part, level + 1)
        yield from self._tail(level + 1)

    def _count(self, out: bytes) -> bytes:
        self.got += len(out)
        if self.got > self.cap:
            raise too_large(self.host, self.cap)
        return out

    def feed(self, raw: bytes):
        for out in self._run(raw, 0):
            yield self._count(out)

    def finish(self):
        for out in self._tail(0):
            yield self._count(out)


def _pre_read(r: httpx.Response) -> bytes | None:
    try:   # a body read already (an in-memory test transport): httpx decoded it; only the count applies
        return r.content
    except httpx.ResponseNotRead:
        return None


def _slices(pre: bytes, cap: int, host: str):
    for i in range(0, len(pre), CHUNK):
        if i + CHUNK > cap and len(pre) > cap:
            raise too_large(host, cap)
        yield pre[i:i + CHUNK]


async def iter_decoded(r: httpx.Response, cap: int, host: str | None = None) -> AsyncIterator[bytes]:
    """The decoded body of a streamed response, chunk by chunk; raises TooLarge once more than `cap`
    decoded bytes have arrived. Each inflate step is bounded, so a gzip bomb (even gzip inside gzip)
    never takes more than a few chunks of memory."""
    host = host or r.request.url.host
    pre = _pre_read(r)
    if pre is not None:
        for part in _slices(pre, cap, host):
            yield part
        return
    body = _Body(r, cap, host)
    async for raw in r.aiter_raw():
        for out in body.feed(raw):
            yield out
    for out in body.finish():
        yield out


def iter_decoded_sync(r: httpx.Response, cap: int, host: str | None = None) -> Iterator[bytes]:
    """iter_decoded() for a synchronous httpx.Client response."""
    host = host or r.request.url.host
    pre = _pre_read(r)
    if pre is not None:
        yield from _slices(pre, cap, host)
        return
    body = _Body(r, cap, host)
    for raw in r.iter_raw():
        yield from body.feed(raw)
    yield from body.finish()


async def read(r: httpx.Response, cap: int, host: str | None = None) -> bytes:
    buf = bytearray()
    async for chunk in iter_decoded(r, cap, host):
        buf += chunk
    return bytes(buf)


# ------------------------------------------------------------------ redirects, followed by hand
# httpx's own redirect handling reads (and fully inflates) every 3xx body before it follows it, so a capped
# request never uses it: each request is sent with follow_redirects=False, a 3xx is closed unread, and the
# next hop is built here, the way httpx would (http/https only, Authorization dropped for another origin,
# POST to GET on 301/302/303). The cap applies to the final body.
MAX_REDIRECTS = 5
_BODY_KW = ("content", "data", "files", "json")


_SAFE_ACROSS = {"accept", "accept-encoding", "accept-language", "user-agent"}
_DEFAULT_PORT = {"http": 80, "https": 443}


def _same_origin(a: httpx.URL, b: httpx.URL) -> bool:
    """httpx's rule: same scheme, host and port, or the plain upgrade http:80 -> https:443 on the same host."""
    pa, pb = a.port or _DEFAULT_PORT.get(a.scheme), b.port or _DEFAULT_PORT.get(b.scheme)
    if a.host != b.host:
        return False
    if a.scheme == b.scheme:
        return pa == pb
    return (a.scheme, pa, b.scheme, pb) == ("http", 80, "https", 443)


def _hop(resp: httpx.Response, method: str, kw: dict, headers: httpx.Headers, hops: int) -> tuple[str, httpx.URL, dict, httpx.Headers]:
    if hops >= MAX_REDIRECTS:
        raise httpx.TooManyRedirects(f"more than {MAX_REDIRECTS} redirects", request=resp.request)
    url = resp.request.url.join(resp.headers["location"])
    if url.scheme not in ("http", "https"):
        raise httpx.UnsupportedProtocol(f"redirect to a {url.scheme or 'relative'} URL refused", request=resp.request)
    old = resp.request.url
    headers = httpx.Headers(headers)
    if not _same_origin(old, url):
        # Another origin, or https -> http: no caller header that could carry a key goes along (Authorization, the
        # ransomware.live X-API-KEY, any other), only these plain ones.
        headers = httpx.Headers({k: v for k, v in headers.items() if k.lower() in _SAFE_ACROSS})
    code = resp.status_code
    if (code == 303 and method != "HEAD") or (code in (301, 302) and method == "POST"):
        method = "GET"
        kw = {k: v for k, v in kw.items() if k not in _BODY_KW}
    kw = {k: v for k, v in kw.items() if k != "params"}     # the Location carries the query from now on
    return method, url, kw, headers


def _split(kw: dict) -> tuple[bool, dict]:
    follow = kw.pop("follow_redirects", True)
    return follow, kw


@contextlib.asynccontextmanager
async def open_final(client: httpx.AsyncClient, method: str, url, *, headers=None, **kw):
    """The final response of a request, streamed and unread, with redirects followed by hand (3xx bodies are
    never read). With follow_redirects=False the 3xx itself is the final response."""
    follow, kw = _split(kw)
    headers = httpx.Headers(headers or {})
    headers["Accept-Encoding"] = ACCEPT_ENCODING
    hops = 0
    while True:
        r = await client.send(client.build_request(method, url, headers=headers, **kw), stream=True, follow_redirects=False)
        if not (follow and r.has_redirect_location):
            break
        await r.aclose()                    # the 3xx body is never read
        method, url, kw, headers = _hop(r, method, kw, headers, hops)
        hops += 1
    try:
        yield r
    finally:
        await r.aclose()


@contextlib.contextmanager
def open_final_sync(client: httpx.Client, method: str, url, *, headers=None, **kw):
    follow, kw = _split(kw)
    headers = httpx.Headers(headers or {})
    headers["Accept-Encoding"] = ACCEPT_ENCODING
    hops = 0
    while True:
        r = client.send(client.build_request(method, url, headers=headers, **kw), stream=True, follow_redirects=False)
        if not (follow and r.has_redirect_location):
            break
        r.close()
        method, url, kw, headers = _hop(r, method, kw, headers, hops)
        hops += 1
    try:
        yield r
    finally:
        r.close()


_DROP = {"content-encoding", "content-length", "transfer-encoding"}


def _complete(r: httpx.Response, body: bytes) -> httpx.Response:
    return httpx.Response(r.status_code, headers=[(k, v) for k, v in r.headers.multi_items() if k.lower() not in _DROP],
                          content=body, request=r.request)


async def get(client: httpx.AsyncClient, url: str, sid: str, *, method: str = "GET", cap: int | None = None,
              **kw) -> httpx.Response:
    """`client.request(method, url, **kw)`, read with the source's cap and redirects followed by hand (at
    most 5; `follow_redirects=False` returns a 3xx as it is, its body unread). Returns a complete response
    (status, headers, .content, .text, .json(), raise_for_status() all work) whose body is already decoded."""
    cap = cap or cap_for(sid)
    async with open_final(client, method, url, **kw) as r:
        body = b"" if r.has_redirect_location else await read(r, cap)
        return _complete(r, body)


def get_sync(client: httpx.Client, url: str, sid: str, *, method: str = "GET", cap: int | None = None,
             **kw) -> httpx.Response:
    """get() for a synchronous httpx.Client."""
    cap = cap or cap_for(sid)
    with open_final_sync(client, method, url, **kw) as r:
        body = b"" if r.has_redirect_location else b"".join(iter_decoded_sync(r, cap))
        return _complete(r, body)


def inflate_capped(data: bytes, cap: int, what: str) -> bytes:
    """gunzip a downloaded .gz file with a limit on the inflated size (a gzip bomb inside the file)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = bytearray()
    while data:
        out += d.decompress(data, CHUNK)
        if len(out) > cap:
            raise TooLarge(f"{what} unpacks to more than {_mb(cap)} (this source's size limit); stored nothing from it")
        data = d.unconsumed_tail
        if d.eof:
            break
    out += d.flush()
    if len(out) > cap:
        raise TooLarge(f"{what} unpacks to more than {_mb(cap)} (this source's size limit); stored nothing from it")
    return bytes(out)

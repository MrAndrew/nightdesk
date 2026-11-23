"""Polite background article fetcher. Rules: okf/data/news.md#fetching

* Honest User-Agent (config.USER_AGENT); never a browser UA.
* robots.txt per domain, cached for a day (memory + news_robots table); Crawl-delay honoured.
* At most one request at a time per domain, at least DOMAIN_DELAY seconds apart.
* Conditional GET (ETag / Last-Modified) when an article is fetched again.
* Retries with exponential backoff on timeouts, 429 and 5xx (Retry-After honoured).
* Bot checks, paywalls, logins and 401/402/403/451 are never worked around: the article is
  marked `blocked` with the reason.
* Nothing is fetched while config.OFFLINE is set; everything already fetched stays searchable.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import gzip
import ipaddress
import socket
import time
from urllib.robotparser import RobotFileParser

import httpx

from .. import config, db
from ..sources import caps
from ..sources.base import to_ts
from . import extract as X
from .common import ENTITIES_RESET, article_id, clean_title, domain_of, ensure_schema, log, norm_url, offline
from .sources import role_for, tier_for, tier_reason, vendor_promo

UTC = dt.UTC
DOMAIN_DELAY = 8.0           # seconds between requests to one domain (raised by Crawl-delay)
MAX_CRAWL_DELAY = 60.0       # a larger Crawl-delay is honoured by fetching that domain rarely
MAX_ATTEMPTS = 5
MAX_BYTES = 6_000_000
ROBOTS_TTL = 86400
PER_DOMAIN_BATCH = 12        # articles per domain per pass, so one slow domain can't hog a pass

_robots: dict[str, tuple[float, RobotFileParser | None, int]] = {}
_last_hit: dict[str, float] = {}
_domain_locks: dict[str, asyncio.Lock] = {}
stats = {"passes": 0, "fetched": 0, "blocked": 0, "failed": 0, "retry": 0, "last_pass": None, "running": False}


def _now() -> dt.datetime:
    return dt.datetime.now(UTC)


# SSRF guard: article URLs come from feed <link> data, so a malicious/compromised feed item (or a
# redirect) must never make the server reach a non-public address — its own loopback services, the
# cloud metadata endpoint (169.254.169.254), a LAN host, etc. We resolve the host and refuse unless
# every resolved address is globally routable. Applied to the seed URL and every redirect hop, before
# even the robots.txt fetch (so it can't be used as an internal port scanner). okf/data/news.md#fetching
_V6_EMBED = tuple(ipaddress.ip_network(n) for n in ("::/96", "64:ff9b::/96", "64:ff9b:1::/48"))
_V4_ANYCAST = ipaddress.ip_network("192.88.99.0/24")   # 6to4 relay anycast (deprecated): is_global, but no web host


def _blocked_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if isinstance(a, ipaddress.IPv6Address):
        if a.ipv4_mapped is not None:
            a = a.ipv4_mapped                       # ::ffff:127.0.0.1 → 127.0.0.1
        elif any(a in n for n in _V6_EMBED):
            return True                             # IPv4-compatible / NAT64: embeds a v4 that may be internal
    if a.is_multicast or (isinstance(a, ipaddress.IPv4Address) and a in _V4_ANYCAST):
        return True                                 # is_global lets some multicast ranges and 6to4 anycast through
    return not a.is_global  # excludes loopback, private, link-local, CGNAT, reserved, docs


def _resolve(host: str) -> list[str]:
    """Every address the name resolves to now (tests replace this)."""
    return list(dict.fromkeys(i[4][0] for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)))


def public_ips(host: str | None) -> list[str]:
    """Every address to try for `host`, in resolver order, or [] when it is not public. A bare IP literal is
    checked directly; a name is resolved once and every answer must be public. The caller connects only to
    these addresses (`_pinned_send`), so a name that re-resolves to loopback at connect time (DNS
    rebinding) never gets a second lookup."""
    if not host:
        return []
    try:
        a = ipaddress.ip_address(host)
        return [] if _blocked_ip(str(a)) else [str(a)]
    except ValueError:
        pass
    try:
        ips = _resolve(host)
    except (OSError, UnicodeError):
        return []
    if not ips or any(_blocked_ip(ip) for ip in ips):
        return []
    return list(dict.fromkeys(ip.split("%", 1)[0] for ip in ips))


def public_ip(host: str | None) -> str | None:
    """The first address of public_ips(), or None."""
    ips = public_ips(host)
    return ips[0] if ips else None


def _host_is_public(host: str | None) -> bool:
    return public_ip(host) is not None


class NotPublic(Exception):
    """The hop's host is not (or no longer) a public address; nothing was sent."""


def _target(url: str) -> tuple[httpx.URL, str]:
    u = httpx.URL(url)
    if u.scheme not in ("http", "https"):
        raise NotPublic("not an http(s) URL")
    return u, u.raw_host.decode("ascii")      # IDNA form; IPv6 without brackets


def _build(cl: httpx.AsyncClient, u: httpx.URL, name: str, ip: str, headers: dict | None) -> httpx.Request:
    hdrs = dict(headers or {})
    hdrs["Host"] = u.netloc.decode("ascii")   # name[:port], no user info
    ext = {"sni_hostname": name} if u.scheme == "https" else {}
    return cl.build_request("GET", u.copy_with(host=ip, username=None, password=None), headers=hdrs, extensions=ext)


def pinned_request(cl: httpx.AsyncClient, url: str, headers: dict | None = None) -> httpx.Request:
    """A GET for `url` sent to the first address checked now (as notify.pinned_target does): the URL carries
    the IP, the Host header keeps the real name and port, and for HTTPS the TLS server name (SNI) is the
    real name, so the certificate is still verified against it. Raises NotPublic."""
    u, name = _target(url)
    ip = public_ip(name)
    if ip is None:
        raise NotPublic("host is not a public address")
    return _build(cl, u, name, ip, headers)


async def _pinned_send(cl: httpx.AsyncClient, url: str, headers: dict | None = None) -> httpx.Response:
    """Send to each checked address in turn (as a dual-stack connect would) until one connects; never to
    an address that was not checked. Raises NotPublic, or the last connect error."""
    u, name = _target(url)
    ips = await asyncio.to_thread(public_ips, name)
    if not ips:
        raise NotPublic("host is not a public address")
    err: Exception | None = None
    for ip in ips:
        try:
            return await cl.send(_build(cl, u, name, ip, headers), stream=True)
        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            err = e
    raise err   # type: ignore[misc]


# ------------------------------------------------------------------ queue
def enqueue_from_events() -> int:
    """Queue an article for every news event with a URL that has none yet (backfill + new)."""
    ensure_schema()
    rows = db.query("""
        SELECT e.id, e.source, e.ts, e.title, e.summary, e.url, e.tags FROM events e
        WHERE e.category = 'news' AND e.url IS NOT NULL AND e.url LIKE 'http%'
          AND NOT EXISTS (SELECT 1 FROM articles a WHERE a.event_id = e.id)""")
    n = 0
    for r in rows:
        label = (r["tags"] or [None])[0]
        aid = article_id(r["url"])
        title = clean_title(r["title"])
        db.execute("""INSERT OR IGNORE INTO articles (id, url, source, title, published, status, source_id, event_id,
                                                      tier, role, dek, attempts, queued_at, tier_reason)
                      VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, 0, now(), ?)""",
                   [aid, r["url"], label, title, r["ts"], r["source"], r["id"], tier_for(label, r["source"], title),
                    role_for(label), r["summary"], tier_reason(label, r["source"], title)])
        n += 1
    return n


def _kev_vendors() -> dict[str, str]:
    """CVE id -> 'Vendor Product' from CISA KEV events ("CVE-2026-0257 · Palo Alto Networks PAN-OS")."""
    out = {}
    for r in db.query("SELECT title FROM events WHERE kind = 'kev'"):
        t = r["title"] or ""
        if " · " in t:
            cve, _, vp = t.partition(" · ")
            out[cve.strip().upper()] = vp.strip()
    return out


def subject_cve_vendors(title: str | None, text: str | None, kev: dict[str, str]) -> set[str]:
    import re as _re
    head = f"{title or ''} {' '.join((text or '').split()[:80])}"
    return {kev[c.upper()] for c in _re.findall(r"CVE-\d{4}-\d{4,7}", head, _re.I) if c.upper() in kev}


def regrade_tiers() -> int:
    """Re-apply the tier rules to every article: outlet tier, raised to A for a vendor's research on a
    problem in its own products (judged on the headline, the lead and the vendors of the CVEs it names)."""
    kev = _kev_vendors()
    n = 0
    for r in db.query("SELECT id, source, source_id, title, text, dek, tier, tier_reason FROM articles"):
        lead = r["text"] or r["dek"]
        vend = subject_cve_vendors(r["title"], lead, kev)
        t = tier_for(r["source"], r["source_id"], r["title"], lead, vend)
        why = tier_reason(r["source"], r["source_id"], r["title"], lead, vend)
        if t != r["tier"] or why != r["tier_reason"]:
            db.execute("UPDATE articles SET tier = ?, tier_reason = ? WHERE id = ?", [t, why, r["id"]])
            n += 1
        promo = vendor_promo(r["source"], r["title"])
        if promo:
            db.execute("UPDATE articles SET sponsored = coalesce(sponsored, ?) WHERE id = ?", [promo, r["id"]])
    return n


def fix_titles() -> int:
    """One-off repair for rows queued before titles were cleaned."""
    n = 0
    for r in db.query("SELECT id, title FROM articles WHERE title LIKE '%&%;%' OR regexp_matches(title, '\\((Mon|Tue|Wed|Thu|Fri|Sat|Sun), ')"):
        t = clean_title(r["title"])
        if t != r["title"]:
            db.execute("UPDATE articles SET title = ? WHERE id = ?", [t, r["id"]])
            n += 1
    if n:
        db.execute("UPDATE stories SET title = a.title FROM articles a WHERE a.id = stories.lead_article AND a.title <> stories.title")
    return n


# ------------------------------------------------------------------ politeness
async def _wait_turn(domain: str, delay: float) -> None:
    last = _last_hit.get(domain)
    if last is not None:
        gap = delay - (time.monotonic() - last)
        if gap > 0:
            await asyncio.sleep(gap)
    _last_hit[domain] = time.monotonic()


def _robots_from_db(domain: str):
    rows = db.query("SELECT status, body, fetched_at FROM news_robots WHERE domain = ?", [domain])
    if not rows:
        return None
    r = rows[0]
    age = (_now() - r["fetched_at"]).total_seconds()
    if age > ROBOTS_TTL:
        return None
    return r["status"], r["body"] or ""


def _parser(status: int, body: str) -> RobotFileParser | None:
    rp = RobotFileParser()
    if status == 200:
        rp.parse(body.splitlines())
    elif 400 <= status < 500:
        rp.parse([])            # RFC 9309: no robots.txt (4xx) means everything is allowed
    else:
        return None             # 5xx / unreachable: assume disallowed and retry later
    return rp


async def _head(resp: httpx.Response, limit: int) -> bytes:
    """At most `limit` decoded bytes of a streamed body (the rest is not read). Inflating is bounded per step
    (sources/caps.py), so a gzip bomb never takes more than a chunk past the limit in memory."""
    buf = bytearray()
    async for chunk in caps.iter_decoded(resp, limit + caps.CHUNK * 4):
        buf += chunk
        if len(buf) >= limit:
            break
    return bytes(buf[:limit])


ROBOTS_MAX_BYTES = 512_000     # Google reads the first 500 KiB of a robots.txt (RFC 9309 asks for at least 500 KiB)


async def _fetch_robots(url: str) -> tuple[int, str]:
    """(status, body) of a robots.txt, fetched like an article: redirects followed by hand (at most
    MAX_REDIRECTS), every hop pinned to an address checked as public right before it is requested.
    A hop to a non-public host, a non-http(s) URL, too many redirects or a network error give 599
    (unavailable: not stored, retried later); a refused hop's body is never read."""
    cl = article_client()
    for _hop in range(MAX_REDIRECTS + 1):
        try:
            resp = await _pinned_send(cl, url, {"Accept": "text/plain"})
        except NotPublic as e:
            log.info("news fetcher: robots.txt hop %s refused (%s)", url.split("?")[0], e)
            return 599, ""
        except (httpx.HTTPError, httpx.InvalidURL, ValueError):
            return 599, ""
        try:
            if resp.is_redirect and resp.headers.get("location"):
                from urllib.parse import urljoin
                url = urljoin(url, resp.headers["location"])
                continue
            if resp.status_code != 200:
                return resp.status_code, ""
            return 200, (await _head(resp, ROBOTS_MAX_BYTES)).decode(resp.encoding or "utf-8", "replace")
        except httpx.HTTPError:
            return 599, ""
        finally:
            await resp.aclose()
    return 599, ""          # too many redirects: unavailable, retried later


async def robots_for(scheme_host: str, domain: str) -> tuple[RobotFileParser | None, int]:
    hit = _robots.get(domain)
    if hit and time.time() - hit[0] < ROBOTS_TTL:
        return hit[1], hit[2]
    cached = await asyncio.to_thread(_robots_from_db, domain)
    if cached is None:
        await _wait_turn(domain, DOMAIN_DELAY)
        status, body = await _fetch_robots(f"{scheme_host}/robots.txt")
        if status < 500:
            await asyncio.to_thread(db.execute, "INSERT OR REPLACE INTO news_robots VALUES (?, ?, ?, now())",
                                    [domain, status, body[:ROBOTS_MAX_BYTES]])
    else:
        status, body = cached
    rp = _parser(status, body)
    _robots[domain] = (time.time() if status < 500 else time.time() - ROBOTS_TTL + 1800, rp, status)
    return rp, status


def _delay_for(rp: RobotFileParser | None) -> float:
    cd = None
    if rp is not None:
        try:
            cd = rp.crawl_delay(config.USER_AGENT)
        except Exception:
            cd = None
    return max(DOMAIN_DELAY, float(cd or 0))


# ------------------------------------------------------------------ one article
def _set(aid: str, **kw) -> None:
    cols = ", ".join(f"{k} = ?" for k in kw)
    db.execute(f"UPDATE articles SET {cols} WHERE id = ?", [*kw.values(), aid])


def _retry(aid: str, attempts: int, reason: str, retry_after: float | None = None) -> str:
    attempts += 1
    if attempts >= MAX_ATTEMPTS:
        _set(aid, status="failed", reason=f"{reason} (gave up after {attempts} attempts)", attempts=attempts, next_attempt=None)
        stats["failed"] += 1
        return "failed"
    wait = retry_after if retry_after else min(6 * 3600, 120 * 2 ** attempts)
    _set(aid, status="queued", reason=f"retrying: {reason}", attempts=attempts,
         next_attempt=_now() + dt.timedelta(seconds=wait))
    stats["retry"] += 1
    return "retry"


def html_path_for(aid: str, when: dt.datetime) -> str:
    return f"raw/articles/{when.strftime('%Y/%m/%d')}/{aid}.html.gz"


def _store(aid: str, row: dict, html: str, resp: httpx.Response, refetch: bool = False, url: str | None = None) -> str:
    """Extract, detect blocks, write raw HTML and the article row. Returns the new status. `url` is the
    final URL by name (the request itself went to the pinned IP, so resp.url carries the address)."""
    url = url or str(resp.url)
    ex = X.extract(html, url)
    text = ex["text"] or ""
    why = X.detect_block(html, len(text))
    when = _now()
    if refetch:
        stage = (row.get("refetch_stage") or 0) + 1
        if why or len(text) < 200 or text == (row.get("text") or ""):
            # A re-fetch never downgrades a stored article; an unchanged one only gets new validators.
            _set(aid, checked_at=when, refetch_stage=stage, etag=resp.headers.get("etag") or row.get("etag"),
                 last_modified=resp.headers.get("last-modified") or row.get("last_modified"))
            return "unchanged"
    rel = html_path_for(aid, when)
    p = config.LAKE / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(gzip.compress(html.encode("utf-8", "replace"), compresslevel=6, mtime=0))
    common = dict(fetched_at=when, html_path=rel, http_status=resp.status_code,
                  etag=resp.headers.get("etag"), last_modified=resp.headers.get("last-modified"),
                  attempts=(row["attempts"] or 0) + 1, next_attempt=None)
    if why:
        _set(aid, status="blocked", reason=why, **common)
        stats["blocked"] += 1
        return "blocked"
    if len(text) < 200:
        _set(aid, status="failed", reason=f"no main text found ({len(text)} chars)", **common)
        stats["failed"] += 1
        return "failed"
    published = row["published"]
    if published is None:
        d = X.jsonld_dates(html) or ex["date"]
        published = to_ts(d) if d else None
    canon = ex["canonical_url"]
    _set(aid, status="ok", reason=None, text=text, title=clean_title(row["title"] or ex["title"]), author=ex["author"],
         lang=ex["lang"] or "en", links=ex["links"], canonical_url=norm_url(canon) if canon else norm_url(url),
         published=published, dek=row["dek"] or ex["description"], chunks=None, embedded_at=None,
         clustered_at=None, minhash=None, **ENTITIES_RESET,
         sponsored=ex.get("sponsored") or vendor_promo(row.get("source"), row["title"] or ex["title"]), checked_at=when,
         refetch_stage=((row.get("refetch_stage") or 0) + 1) if refetch else 0,
         updated_at=when if refetch else None, **common)
    kev = _kev_vendors()
    vend = subject_cve_vendors(row["title"], text, kev)
    label = row.get("source")
    _set(aid, tier=tier_for(label, None, row["title"], text, vend), tier_reason=tier_reason(label, None, row["title"], text, vend))
    stats["fetched"] += 1
    return "updated" if refetch else "ok"


def reextract(limit: int | None = None) -> int:
    """Re-run extraction on stored raw HTML (no network). Used after extraction rules change;
    chunks, embeddings and entities are then redone incrementally."""
    rows = db.query(f"SELECT id, url, source, title, html_path, text FROM articles WHERE status = 'ok' AND html_path IS NOT NULL{' LIMIT ' + str(int(limit)) if limit else ''}")
    n = 0
    for r in rows:
        p = config.LAKE / r["html_path"]
        if not p.exists():
            continue
        ex = X.extract(gzip.decompress(p.read_bytes()).decode("utf-8", "replace"), r["url"])
        if not ex["text"] or len(ex["text"]) < 200:
            continue
        meta = dict(author=ex["author"], lang=ex["lang"] or "en", links=ex["links"],
                    sponsored=ex.get("sponsored") or vendor_promo(r["source"], r["title"]))
        if ex["text"] != r["text"]:
            # New text: chunks, embeddings and entities are redone incrementally.
            _set(r["id"], text=ex["text"], chunks=None, embedded_at=None, minhash=None, **ENTITIES_RESET, **meta)
            n += 1
        else:
            _set(r["id"], **meta)
    return n


MAX_REDIRECTS = 5
_paused: dict[str, float] = {}   # domain -> monotonic time until which it gets no requests (429 / 503)


def pause_domain(domain: str, seconds: float, why: str) -> None:
    until = time.monotonic() + max(1.0, seconds)
    if until > _paused.get(domain, 0):
        _paused[domain] = until
        log.info("news fetcher: pausing %s for %.0f s (%s)", domain, seconds, why)


def paused_for(domain: str) -> float:
    return max(0.0, _paused.get(domain, 0) - time.monotonic())


def _retry_after(resp: httpx.Response) -> float | None:
    ra = (resp.headers.get("retry-after") or "").strip()
    if ra.isdigit():
        return float(ra)
    if ra:
        try:
            from email.utils import parsedate_to_datetime
            return max(0.0, (parsedate_to_datetime(ra) - _now()).total_seconds())
        except Exception:
            return None
    return None


_article_client: httpx.AsyncClient | None = None


def article_client() -> httpx.AsyncClient:
    """For articles and robots.txt. Redirects are followed by hand so robots.txt and the public-address
    check run for every hop. Requests go to a pinned IP (`pinned_request`); no connection is kept alive,
    so a TLS connection made for one name is never reused for another name on the same address. Proxy
    environment variables are ignored (trust_env=False): a proxy tunnel would start TLS with the pinned IP
    as the server name and fail certificate checks, and a proxy would resolve the name again itself."""
    global _article_client
    if _article_client is None or _article_client.is_closed:
        _article_client = httpx.AsyncClient(headers={"User-Agent": config.USER_AGENT,
                                                      "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                                                      "Accept-Encoding": caps.ACCEPT_ENCODING},
                                            timeout=httpx.Timeout(30, connect=10), follow_redirects=False,
                                            limits=httpx.Limits(max_keepalive_connections=0), trust_env=False)
    return _article_client


async def _allowed(url: str) -> tuple[bool | None, float, str]:
    """(allowed, delay, reason). allowed is None when robots.txt could not be read (retry later)."""
    from urllib.parse import urlsplit
    sp = urlsplit(url)
    if sp.scheme not in ("http", "https"):
        return False, 0.0, "not an http(s) URL"
    if not await asyncio.to_thread(_host_is_public, sp.hostname):
        return False, 0.0, "host is not a public address"  # SSRF guard (loopback/private/metadata)
    rp, rstatus = await robots_for(f"{sp.scheme}://{sp.netloc}", domain_of(url))
    if rp is None:
        return None, 0.0, f"robots.txt unavailable on {sp.netloc} (HTTP {rstatus})"
    if not rp.can_fetch(config.USER_AGENT, url):
        return False, 0.0, "disallowed by robots.txt"
    return True, min(_delay_for(rp), MAX_CRAWL_DELAY), ""


def _blocked(aid: str, row: dict, why: str, code: int | None = None) -> str:
    _set(aid, status="blocked", reason=why, http_status=code, attempts=(row.get("attempts") or 0) + 1,
         next_attempt=None, fetched_at=_now())
    stats["blocked"] += 1
    return "blocked"


async def fetch_article(row: dict, refetch: bool = False) -> str:
    """Fetch one article politely. Returns ok | unchanged | blocked | failed | retry | skipped | paused | offline.

    `refetch` re-checks an article already stored (conditional GET); errors then leave it as it was.
    """
    if offline():
        return "offline"
    aid, url = row["id"], row["url"]
    headers = {}
    if row.get("etag"):
        headers["If-None-Match"] = row["etag"]
    if row.get("last_modified"):
        headers["If-Modified-Since"] = row["last_modified"]
    hops = 0
    try:
        while True:
            domain = domain_of(url)
            if paused_for(domain):
                return "paused"
            ok, delay, why = await _allowed(url)
            if ok is None:
                return "retry" if refetch else await asyncio.to_thread(_retry, aid, row["attempts"] or 0, why)
            if not ok:
                if refetch:
                    return "blocked"
                if why == "not an http(s) URL":
                    await asyncio.to_thread(_set, aid, status="skipped", reason=why)
                    return "skipped"
                return await asyncio.to_thread(_blocked, aid, row, why if hops == 0 else f"redirect to {url.split('?')[0]} {why}")
            await _wait_turn(domain, delay)
            # The address is checked again right before connecting (the politeness wait above opened a
            # window for DNS rebinding) and the request goes to exactly that address.
            try:
                resp = await _pinned_send(article_client(), url, headers)
            except NotPublic as e:
                if refetch:
                    return "blocked"
                return await asyncio.to_thread(_blocked, aid, row, str(e) if hops == 0 else f"redirect to {url.split('?')[0]} {e}")
            try:
                if resp.is_redirect and resp.headers.get("location"):
                    hops += 1
                    if hops > MAX_REDIRECTS:
                        return "failed" if refetch else await asyncio.to_thread(_set_failed, aid, "too many redirects", resp.status_code)
                    from urllib.parse import urljoin
                    url = urljoin(url, resp.headers["location"])
                    if domain_of(url) != domain:
                        headers = {}   # validators belong to the first host
                    continue
                status = await _handle(aid, row, resp, url, refetch, domain)
                return status
            finally:
                await resp.aclose()
    except (httpx.TimeoutException, httpx.TransportError) as e:
        if refetch:
            return "retry"
        return await asyncio.to_thread(_retry, aid, row["attempts"] or 0, f"{type(e).__name__}")


def _set_failed(aid: str, why: str, code: int | None = None) -> str:
    _set(aid, status="failed", reason=why, http_status=code, next_attempt=None)
    stats["failed"] += 1
    return "failed"


async def _handle(aid: str, row: dict, resp: httpx.Response, url: str, refetch: bool, domain: str) -> str:
    code = resp.status_code
    if code == 304:
        await asyncio.to_thread(_mark_unchanged, aid, row, refetch)
        return "unchanged"
    waf = resp.headers.get("x-amzn-waf-action") or resp.headers.get("cf-mitigated")
    if waf:
        return "blocked" if refetch else await asyncio.to_thread(_blocked, aid, row, f"bot check ({waf} by WAF)", code)
    if code in (401, 402, 403, 451):
        why = {401: "login required", 402: "paywall (402)", 403: "refuses automated clients (403)",
               451: "unavailable for legal reasons (451)"}[code]
        return "blocked" if refetch else await asyncio.to_thread(_blocked, aid, row, why, code)
    if code in (404, 410):
        return "failed" if refetch else await asyncio.to_thread(_set_failed, aid, f"HTTP {code}", code)
    if code == 429 or code >= 500:
        body = (await _head(resp, 20000)).decode("utf-8", "ignore").lower()
        if code == 429 and "security checkpoint" in body:
            return "blocked" if refetch else await asyncio.to_thread(_blocked, aid, row, "bot check (429 security checkpoint)", code)
        ra = _retry_after(resp)
        # The whole domain waits, not just this article.
        pause_domain(domain, ra if ra else 120 * 2 ** ((row.get("attempts") or 0) + 1), f"HTTP {code}")
        if refetch:
            return "retry"
        return await asyncio.to_thread(_retry, aid, row["attempts"] or 0, f"HTTP {code}", ra)
    if code >= 400:
        return "failed" if refetch else await asyncio.to_thread(_set_failed, aid, f"HTTP {code}", code)
    ctype = resp.headers.get("content-type", "")
    if "html" not in ctype and "xml" not in ctype:
        if refetch:
            return "skipped"
        await asyncio.to_thread(_set, aid, status="skipped", reason=f"not HTML ({ctype.split(';')[0]})", http_status=code, next_attempt=None)
        return "skipped"
    html = (await _head(resp, MAX_BYTES)).decode(resp.encoding or "utf-8", "replace")
    final = url.lower()
    if any(k in final for k in ("/login", "/signin", "/sign-in", "/subscribe", "/paywall")):
        return "blocked" if refetch else await asyncio.to_thread(_blocked, aid, row, f"redirected to {final.split('?')[0]}", code)
    return await asyncio.to_thread(_store, aid, row, html, resp, refetch, url)


def _mark_unchanged(aid: str, row: dict, refetch: bool) -> None:
    stage = (row.get("refetch_stage") or 0) + (1 if refetch else 0)
    _set(aid, status="ok", reason=None, next_attempt=None, checked_at=_now(), refetch_stage=stage)


async def _domain_worker(domain: str, rows: list[dict], refetch: bool = False) -> dict:
    lock = _domain_locks.setdefault(domain, asyncio.Lock())
    out: dict = {}
    async with lock:
        for i, r in enumerate(rows):
            if offline():
                break
            wait = paused_for(domain)
            if wait:
                # 429 / 503 pause the whole domain: the rest of its queue waits too.
                if not refetch:
                    # Robots decisions need no request: settle those now from the cached robots.txt.
                    rest = []
                    for x in rows[i:]:
                        hit = _robots.get(domain_of(x["url"]))
                        if hit and hit[1] is not None and not hit[1].can_fetch(config.USER_AGENT, x["url"]):
                            await asyncio.to_thread(_blocked, x["id"], x, "disallowed by robots.txt")
                            out["blocked"] = out.get("blocked", 0) + 1
                        else:
                            rest.append(x)
                    ids = [x["id"] for x in rest]
                    until = _now() + dt.timedelta(seconds=wait)
                    await asyncio.to_thread(lambda ids=ids, until=until: [db.execute(
                        "UPDATE articles SET next_attempt = greatest(coalesce(next_attempt, ?), ?) WHERE id = ? AND status = 'queued'",
                        [until, until, x]) for x in ids])
                    out["paused"] = out.get("paused", 0) + len(rest)
                else:
                    out["paused"] = out.get("paused", 0) + len(rows) - i
                break
            try:
                s = await fetch_article(r, refetch=refetch)
            except Exception as e:  # never let one article kill the pass
                log.warning("article %s failed: %s", r["url"], e)
                s = "retry" if refetch else await asyncio.to_thread(_retry, r["id"], r["attempts"] or 0, f"{type(e).__name__}: {e}"[:200])
            out[s] = out.get(s, 0) + 1
    return out


def due_articles(limit: int = 400) -> list[dict]:
    return db.query("""SELECT id, url, source, title, published, dek, attempts, etag, last_modified, refetch_stage FROM articles
                       WHERE status = 'queued' AND (next_attempt IS NULL OR next_attempt <= now())
                       ORDER BY published DESC NULLS LAST LIMIT ?""", [limit])


def due_refetch(limit: int = 200) -> list[dict]:
    """Recent articles due a conditional re-fetch: 6 h after the first fetch, then 48 h."""
    return db.query("""SELECT id, url, source, title, published, dek, attempts, etag, last_modified, refetch_stage, text FROM articles
                       WHERE status = 'ok' AND coalesce(refetch_stage, 0) < 2
                         AND coalesce(published, fetched_at) > now() - INTERVAL 7 DAY
                         AND coalesce(checked_at, fetched_at) <= now() - CASE WHEN coalesce(refetch_stage, 0) = 0
                                                                          THEN INTERVAL 6 HOUR ELSE INTERVAL 48 HOUR END
                       ORDER BY published DESC NULLS LAST LIMIT ?""", [limit])


async def fetch_pass(per_domain: int = PER_DOMAIN_BATCH) -> dict:
    """One pass: queue new news events, then fetch due articles (domains in parallel, each serial)."""
    if offline():
        return {"offline": True}
    stats["running"] = True
    try:
        await asyncio.to_thread(enqueue_from_events)
        total: dict = {}
        for refetch, rows in ((False, await asyncio.to_thread(due_articles)), (True, await asyncio.to_thread(due_refetch))):
            by_dom: dict[str, list[dict]] = {}
            for r in rows:
                lst = by_dom.setdefault(domain_of(r["url"]), [])
                if len(lst) < per_domain:
                    lst.append(r)
            results = await asyncio.gather(*(_domain_worker(d, rs, refetch) for d, rs in by_dom.items()))
            for res in results:
                for k, v in res.items():
                    key = f"refetch_{k}" if refetch else k
                    total[key] = total.get(key, 0) + v
        stats["passes"] += 1
        stats["last_pass"] = _now().isoformat()
        return total
    finally:
        stats["running"] = False


async def fetch_loop() -> None:
    while True:
        try:
            if not offline():
                res = await fetch_pass()
                if res:
                    log.info("news fetch pass: %s", res)
            else:
                await asyncio.to_thread(enqueue_from_events)
        except Exception as e:
            log.warning("news fetch pass failed: %s", e)
        await asyncio.sleep(60)

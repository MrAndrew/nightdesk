"""HTTP guards shared by the app (osinthub/api.py `_guard`) and the AI helper (osinthub/ai/server.py).

Imports nothing from osinthub, so the AI helper can use it without loading the app's configuration (which creates
the lake folders) or the app itself. okf/architecture/deployment.md#who-can-reach-it

* host_name / is_loopback: the bare host of a Host header or a bind address, and whether it names this machine only.
* bind_problem: the one-line refusal for a non-loopback bind without a secret (the app's OSINTHUB_PASSWORD, the
  helper's AI_TOKEN), or None.
* cross_site: the CSRF refusal for a state-changing browser request from another site or origin, or None.
* basic_password / password_ok / bearer_ok: HTTP Basic (any user name) and Bearer checks, constant time over hashes.
* Throttle: N distinct wrong credentials per client (IPv6 by /64) in a window -> blocked for a while; bounded.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import threading
import time
from collections import OrderedDict

LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def host_name(v: str) -> str:
    """The bare, lower-case host of a Host header or a host-list entry: no scheme, path, port,
    [brackets] or trailing dot ("https://NightDesk.LAN:8443/" -> "nightdesk.lan", "[::1]:8787" -> "::1")."""
    v = v.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    if v.startswith("["):                      # [IPv6]:port
        v = v[1:].split("]", 1)[0]
    elif v.count(":") == 1:                    # name:port or IPv4:port (a bare IPv6 has several colons)
        v = v.split(":", 1)[0]
    return v.rstrip(".")


def host_list(raw: str) -> set[str]:
    """A comma- or space-separated host list (ports, schemes and brackets ignored) as bare names."""
    return {h for h in (host_name(x) for x in raw.replace(",", " ").split()) if h}


def is_loopback(v: str) -> bool:
    """True when a bind address or client address reaches this machine only: localhost, ::1 or 127.0.0.0/8."""
    h = host_name(v)
    if h in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def bind_problem(host: str, *, secret: bool, secret_var: str, host_var: str, proxy_hint: bool = True) -> str | None:
    """Why binding to `host` must be refused (one line), or None: a non-loopback address (0.0.0.0, ::, a LAN
    address, a host name) puts the service on the network, so it needs `secret_var` set."""
    if is_loopback(host) or secret:
        return None
    alt = ", or bind 127.0.0.1 and put a reverse proxy that asks for a password in front" if proxy_hint else \
        ", or bind 127.0.0.1"
    return (f"{host_var}={host} makes this reachable from other machines, so it needs {secret_var}: set "
            f"{secret_var}{alt}. Nothing was started.")


def _netloc(url: str) -> str:
    """host[:port] of an Origin / Referer URL ("" when it has none, e.g. `Origin: null`)."""
    return url.split("://", 1)[1].split("/", 1)[0].lower() if "://" in url else ""


def cross_site(method: str, headers, scheme: str) -> str | None:
    """The refusal detail for a state-changing request from another site or origin, else None.

    Browsers send Sec-Fetch-Site and Origin (or at least Referer); non-browser clients (curl, scripts, the app's own
    calls to the AI helper) send none of them and pass. Same scheme, host and port: behind a TLS proxy the scheme
    comes from its X-Forwarded-Proto, which uvicorn trusts from FORWARDED_ALLOW_IPS."""
    if method in SAFE_METHODS:
        return None
    site = (headers.get("sec-fetch-site") or "").strip().lower()
    if site in {"cross-site", "same-site"}:
        return "cross-site request refused"
    origin, referer = headers.get("origin"), headers.get("referer")
    src = origin if origin is not None else referer
    host = headers.get("host", "")
    if src is not None and (src.split("://", 1)[0].strip().lower() != scheme or _netloc(src) != host.lower()):
        return "cross-origin request refused"
    return None


def _digest(s: str) -> bytes:
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).digest()


def basic_password(authorization: str | None) -> str | None:
    """The password of an `Authorization: Basic` header (the user name is ignored), or None when absent/malformed."""
    if not authorization or authorization[:6].lower() != "basic ":
        return None
    try:
        raw = base64.b64decode(authorization[6:].strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return raw.split(":", 1)[1] if ":" in raw else None


def password_ok(given: str | None, expected: str) -> bool:
    """Constant-time comparison of the hashes (equal length whatever was sent)."""
    return given is not None and hmac.compare_digest(_digest(given), _digest(expected))


def bearer_ok(authorization: str | None, token: str) -> bool:
    given = authorization[7:].strip() if authorization and authorization[:7].lower() == "bearer " else None
    return password_ok(given, token)


def address_key(ip: str) -> str:
    """The throttle's per-client key: the exact address (an IPv4-mapped IPv6 address as its IPv4 form)."""
    try:
        a = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return ip
    if a.version == 6 and a.ipv4_mapped is not None:
        return str(a.ipv4_mapped)
    return str(a)


def net_key(ip: str) -> str | None:
    """The key for the looser per-network count: an IPv6 client's /64 (one device can use any number of addresses in
    its /64, so the per-address count alone would give it unlimited guesses). None for IPv4 and loopback."""
    try:
        a = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return None
    if a.version != 6 or a.ipv4_mapped is not None or a.is_loopback:
        return None
    return str(ipaddress.ip_network(f"{a}/64", strict=False))


def credential_tag(value: str | None) -> str:
    """A short hash of a credential, so the throttle can tell distinct wrong passwords apart without keeping them."""
    return hashlib.sha256((value or "").encode("utf-8", "surrogatepass")).hexdigest()[:16]


class Throttle:
    """`limit` DISTINCT wrong credentials under one key within `window` seconds block that key for `block` seconds
    (the ingest listener's numbers: 10 in 10 minutes -> 15 minutes). The app keeps two: one per exact address and a
    looser one per IPv6 /64 (`net_key`), see api._auth_refusal.

    * The same wrong credential repeated counts once: an open tab still holding an old password polls with it
      every few seconds and must not lock its owner out.
    * `ok(key)` clears only that key's own failures (a correct password from that exact address); it never lifts a
      block and never touches another key, so a correct poll from one device cannot hide another device's guesses.
    * A blocked key stays blocked for every attempt, the right password included, until the block ends.
    * Bounded and O(1) amortised: keys live in an OrderedDict in last-touched order; expired ones are dropped from the
      old end, and past `max_keys` the oldest key that is NOT blocked is evicted (a block is never lifted by eviction;
      if the oldest 64 are all blocked, the oldest goes, which takes 64 x `limit` guesses to arrange). Memory only."""

    def __init__(self, limit: int = 10, window: float = 600, block: float = 900, max_keys: int = 4096):
        self.limit, self.window, self.block, self.max_keys = limit, window, block, max_keys
        self._keys: OrderedDict[str, dict] = OrderedDict()   # key -> {"t": last touch, "tags": {tag: ts}, "until": ts}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        keep = max(self.window, self.block)
        while self._keys:
            k, e = next(iter(self._keys.items()))
            if now - e["t"] <= keep or e["until"] > now:
                break
            self._keys.popitem(last=False)
        if len(self._keys) > self.max_keys:
            victim = None
            for i, (k, e) in enumerate(self._keys.items()):
                if e["until"] <= now:
                    victim = k
                    break
                if i >= 63:
                    break
            if victim is None:
                victim = next(iter(self._keys))
            del self._keys[victim]

    def blocked(self, key: str | None) -> float:
        """Seconds left on this key's block (0 when it is not blocked)."""
        if key is None:
            return 0.0
        now = time.time()
        with self._lock:
            self._prune(now)
            e = self._keys.get(key)
            left = (e["until"] - now) if e else 0.0
            return left if left > 0 else 0.0

    def fail(self, key: str | None, tag: str = "") -> bool:
        """Record a wrong credential (`tag`: credential_tag of it) under `key`; True when this one blocks it."""
        if key is None:
            return False
        now = time.time()
        with self._lock:
            e = self._keys.pop(key, None) or {"t": now, "tags": {}, "until": 0.0}
            e["t"] = now
            self._keys[key] = e                                 # newest end
            tags = e["tags"]
            for t in [t for t, ts in tags.items() if ts < now - self.window]:
                del tags[t]
            if tag not in tags:
                tags[tag] = now
            hit = len(tags) >= self.limit
            if hit:
                e["until"], e["tags"] = now + self.block, {}
            self._prune(now)
            return hit

    def ok(self, key: str | None) -> None:
        """A correct credential from exactly this key: forget its own failures (an active block is kept)."""
        if key is None:
            return
        with self._lock:
            e = self._keys.get(key)
            if e is not None:
                e["tags"] = {}
                if e["until"] <= time.time():
                    del self._keys[key]

    def __len__(self) -> int:
        return len(self._keys)

    def reset(self) -> None:
        with self._lock:
            self._keys.clear()

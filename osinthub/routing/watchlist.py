"""The routing watchlist: what to watch, the two user settings, and the Cloudflare Radar token.

A watch is an AS number ("AS13335") or a routed prefix ("1.1.1.0/24"), with a label. Its id is that canonical
value. Typed entries are validated here (the UI asks /api/routing/validate as the user types): ASNs 1-4294967295
outside the private, reserved and documentation blocks; prefixes /8-/24 (IPv4) or /16-/48 (IPv6) of globally
routed space. Stored in the settings table (`routing.watchlist`, `routing.settings`). The Radar token is kept in
a file next to the database (never in the settings table, which the SQL console can read), or comes from the
CLOUDFLARE_RADAR_TOKEN environment variable; it is never returned by the API or written to a log.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import re

from .. import config, db

KEY = "routing.watchlist"
SETTINGS_KEY = "routing.settings"
MAX_WATCHES = 25
LABEL_MAX = 60
TOKEN_ENV = "CLOUDFLARE_RADAR_TOKEN"

# Tests only: documentation ASNs and prefixes are refused for real use, but test fixtures must use them.
ALLOW_DOCUMENTATION = False

PRESETS = [
    {"value": "AS13335", "label": "Cloudflare"},
    {"value": "AS15169", "label": "Google"},
    {"value": "AS16509", "label": "Amazon (AWS)"},
    {"value": "AS8075", "label": "Microsoft"},
    {"value": "AS19281", "label": "Quad9"},
    {"value": "1.1.1.0/24", "label": "Cloudflare DNS (1.1.1.1)"},
    {"value": "8.8.8.0/24", "label": "Google DNS (8.8.8.8)"},
    {"value": "9.9.9.0/24", "label": "Quad9 DNS (9.9.9.9)"},
]

EVERY = {900: "15 minutes", 3600: "1 hour", 21600: "6 hours", 86400: "24 hours"}
ADVANCED_EVERY = {900}
DEFAULTS = {"every": 21600, "limit_mb": 50}
LIMIT_MB = (1, 10_000)

DOC_V4 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
DOC_V6 = [ipaddress.ip_network(n) for n in ("2001:db8::/32", "3fff::/20")]

_ASN_RE = re.compile(r"^(?:AS)?\s*(\d{1,10})$", re.I)


class Invalid(ValueError):
    """A typed watch that cannot be watched; the message is a plain sentence for the user."""


def _asn_problem(n: int) -> str | None:
    if n < 1 or n > 4294967295:
        return "AS numbers run from 1 to 4294967295."
    if 64496 <= n <= 64511 or 65536 <= n <= 65551:
        return None if ALLOW_DOCUMENTATION else f"AS{n} is reserved for documentation and examples, so it never appears on the internet."
    if 64512 <= n <= 65534 or 4200000000 <= n <= 4294967294:
        return f"AS{n} is a private AS number (used inside a network), so it never appears on the internet."
    if n in (23456, 65535, 4294967295) or 65552 <= n <= 131071:
        return f"AS{n} is reserved and is not used on the internet."
    return None


def _prefix_problem(net: ipaddress._BaseNetwork, typed: str | None = None) -> str | None:
    v4 = net.version == 4
    lo, hi = (8, 24) if v4 else (16, 48)
    docs = DOC_V4 if v4 else DOC_V6
    if any(net.subnet_of(d) for d in docs):
        if ALLOW_DOCUMENTATION:
            return None
        return f"{net} is reserved for documentation and examples, so it never appears on the internet."
    if net.prefixlen < lo:
        return f"{typed or net} is too large to watch. Pick a network of /{lo} or smaller."
    if net.prefixlen > hi:
        size = 24 if v4 else 48
        cover = net.supernet(new_prefix=size)
        return (f"Routes smaller than a /{size} are not carried on the internet. "
                f"Watch the /{size} that contains it: {cover}.")
    first, last = net.network_address, net.broadcast_address
    if any(getattr(a, f) for a in (first, last) for f in ("is_multicast", "is_reserved", "is_loopback", "is_link_local", "is_unspecified")):
        return f"{net} is a reserved or special-use range that is not routed on the internet."
    if first.is_private or last.is_private:
        if not v4 and (first in ipaddress.ip_network("fc00::/7")):
            return f"{net} is a private range (used inside home and office networks), so it never appears on the internet."
        if v4 and any(net.subnet_of(ipaddress.ip_network(p)) for p in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
            return f"{net} is a private range (used inside home and office networks), so it never appears on the internet."
        return f"{net} is a special-use range that is not routed on the internet."
    if not (first.is_global and last.is_global):
        return f"{net} is a reserved or special-use range that is not routed on the internet."
    return None


def parse(value: str) -> dict:
    """{'id', 'kind', 'value'} for a typed ASN or prefix, else Invalid with a plain message."""
    s = str(value or "").strip()
    if not s:
        raise Invalid("Type an AS number (like AS13335) or a network (like 1.1.1.0/24).")
    if len(s) > 60:
        raise Invalid("That is too long to be an AS number or a network.")
    m = _ASN_RE.match(s.replace(" ", ""))
    if m:
        n = int(m.group(1))
        if (why := _asn_problem(n)):
            raise Invalid(why)
        return {"id": f"AS{n}", "kind": "asn", "value": f"AS{n}"}
    if "/" not in s:
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            raise Invalid("That is not an AS number or a network. Try AS13335 or 1.1.1.0/24.") from None
        size = 24 if ip.version == 4 else 48
        raise Invalid(f"Add the network size. To watch the network around {ip}, use "
                      f"{ipaddress.ip_network(f'{ip}/{size}', strict=False)}.")
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        raise Invalid("That is not a valid network. Write it like 1.1.1.0/24 or 2606:4700::/32.") from None
    if (why := _prefix_problem(net, s)):
        raise Invalid(why)
    return {"id": str(net), "kind": "prefix", "value": str(net)}


def _label(v, fallback: str) -> str:
    s = " ".join(str(v or "").split())[:LABEL_MAX]
    return s or fallback


def preset_label(wid: str) -> str | None:
    return next((p["label"] for p in PRESETS if p["value"] == wid), None)


def clean(items) -> list[dict]:
    """Validate a whole list (the PUT body). Duplicates keep the first; more than MAX_WATCHES is refused."""
    if not isinstance(items, list):
        raise Invalid("The watchlist must be a list.")
    old = {w["id"]: w for w in load()}
    out, seen = [], set()
    for i, it in enumerate(items):
        if isinstance(it, str):
            it = {"value": it}
        if not isinstance(it, dict):
            raise Invalid(f"Entry {i + 1} is not a network.")
        raw = str(it.get("value") or it.get("id") or "").strip()
        try:
            w = parse(raw)
        except Invalid as e:
            if raw not in old:   # a watch saved earlier stays as it is; only new entries are checked
                raise Invalid(f"{raw[:60]}: {e}") from None
            w = {k: old[raw][k] for k in ("id", "kind", "value")}
        if w["id"] in seen:
            continue
        seen.add(w["id"])
        prev = (old.get(w["id"]) or {}).get("label")   # a PUT without a label keeps the one it had
        w["label"] = _label(it.get("label"), (prev if it.get("label") is None else None) or preset_label(w["id"]) or w["id"])
        w["added"] = (old.get(w["id"]) or {}).get("added") or dt.datetime.now(dt.UTC).isoformat()
        out.append(w)
    if len(out) > MAX_WATCHES:
        raise Invalid(f"You can watch up to {MAX_WATCHES} networks. Remove one to add another.")
    return out


def load() -> list[dict]:
    v = db.get_setting(KEY, []) or []
    return [w for w in v if isinstance(w, dict) and w.get("id")]


def save(items) -> list[dict]:
    wl = clean(items)
    db.set_setting(KEY, wl)
    return wl


def fingerprint(wl: list[dict] | None = None) -> str:
    ids = sorted(w["id"] for w in (load() if wl is None else wl))
    return hashlib.sha1(json.dumps(ids).encode()).hexdigest()[:16]


def asns(wl: list[dict]) -> dict[int, str]:
    return {int(w["id"][2:]): w["id"] for w in wl if w["kind"] == "asn"}


def prefixes(wl: list[dict]) -> dict[str, ipaddress._BaseNetwork]:
    return {w["id"]: ipaddress.ip_network(w["id"]) for w in wl if w["kind"] == "prefix"}


WAITING = "Add a network to watch in Settings › Sources › Routing watch first. Nothing is checked until then."


def waiting() -> str | None:
    """Why routing sources cannot run yet (an empty watchlist), else None."""
    return None if load() else WAITING


# ---------------------------------------------------------------- the two settings
def settings() -> dict:
    s = {**DEFAULTS, **(db.get_setting(SETTINGS_KEY, {}) or {})}
    if s["every"] not in EVERY:
        s["every"] = DEFAULTS["every"]
    try:
        s["limit_mb"] = min(max(int(s["limit_mb"]), LIMIT_MB[0]), LIMIT_MB[1])
    except (TypeError, ValueError):
        s["limit_mb"] = DEFAULTS["limit_mb"]
    return {"every": s["every"], "limit_mb": s["limit_mb"]}


def set_settings(every=None, limit_mb=None) -> dict:
    s = settings()
    if every is not None:
        try:
            every = int(every)
        except (TypeError, ValueError):
            raise Invalid("Check every must be 15 minutes, 1 hour, 6 hours or 24 hours.") from None
        if every not in EVERY:
            raise Invalid("Check every must be 15 minutes, 1 hour, 6 hours or 24 hours.")
        s["every"] = every
    if limit_mb is not None:
        try:
            v = int(limit_mb)
        except (TypeError, ValueError):
            raise Invalid("The daily data limit must be a whole number of megabytes.") from None
        if not LIMIT_MB[0] <= v <= LIMIT_MB[1]:
            raise Invalid(f"The daily data limit must be between {LIMIT_MB[0]} and {LIMIT_MB[1]:,} MB.")
        s["limit_mb"] = v
    db.set_setting(SETTINGS_KEY, s)
    return s


def every() -> int:
    return settings()["every"]


# ---------------------------------------------------------------- the Radar token (write-only)
def _token_path():
    return config.DB_PATH.parent / "radar.token"


def token() -> str | None:
    env = (os.environ.get(TOKEN_ENV) or "").strip()
    if env:
        return env
    try:
        t = _token_path().read_text().strip()
    except OSError:
        return None
    return t or None


def token_source() -> str | None:
    if (os.environ.get(TOKEN_ENV) or "").strip():
        return "env"
    return "saved" if token() else None


_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-.]{20,200}$")


def set_token(value: str | None) -> None:
    """Save (or with ''/None remove) the token. Kept in a file only this user can read."""
    p = _token_path()
    v = (value or "").strip()
    if not v:
        p.unlink(missing_ok=True)
        return
    if not _TOKEN_RE.match(v):
        raise Invalid("That does not look like a Cloudflare API token (letters, digits, - and _, 20 or more characters).")
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(v)
    os.replace(tmp, p)

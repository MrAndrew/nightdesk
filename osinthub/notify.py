"""Notifications: an opt-in webhook for a new needs-you incident, a log sender going quiet, and a daily summary.

Off until the owner turns it on in Settings › Notifications. One generic webhook (no SMTP) in one of five shapes:
ntfy, Gotify, Home Assistant, Discord-compatible or plain JSON. Every text is built here from fixed phrases (never
by a language model), and a message carries a title, a severity and a link back to Night Desk: no addresses, no
hardware ids, no log lines, and device names only when the owner ticks "Include device names". Nothing derived from
abuse.ch data (ThreatFox, URLhaus, SSLBL) is put into a message: alerts from those lists get the generic wording.

Destinations: a local address (loopback, private, link-local, Tailscale/CGNAT, IPv6 ULA) or a .lan/.local/.home.arpa/
.internal name by default. Anything else needs "Send to an internet service". The host is resolved again at send
time and every address is checked (a local-looking name that now points at the internet is refused: no DNS-rebinding
bypass), then the request goes to that checked address (Host header and TLS name kept). No redirects, no proxies
from the environment. OSINTHUB_OFFLINE=1 holds anything not local ("held: offline"); local destinations still work.

Triggers (checked after each netlog_alerts bus message and every POLL_S seconds):
* incident: an untriaged, not-expected, non-demo incident at or above the minimum severity (incidents.py). One
  message per incident, whatever its number of alerts or UTC days; again only when its severity rises. Alerts already
  open when notifications are turned on (or the minimum is changed) are taken as known, not sent.
* sensor: a log sender gone quiet (the sensor_silent alert of netlog/ingest.py), when "A log sender goes quiet" is on.
* digest: once a day at the chosen local time, the Watch briefing's sections (osinthub/watch/briefing.py) since the
  last summary: counts and the top items, in safe wording, with a link to Watch.
Quiet hours hold incident and sensor messages; they go out when quiet hours end (more than QUIET_FOLD at once are
folded into one message).

Delivery: a capped queue (QUEUE_MAX), TIMEOUT_S per try, RETRY_WAITS between tries (network errors, 429 and 5xx), a
log of the last LOG_MAX deliveries (time, trigger, title, host, status; never the URL). Matching and ingest never wait
on any of this: the trigger check runs in its own task and a failure there is logged and retried.
Docs: okf/architecture/notifications.md
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import ipaddress
import json
import logging
import re
import socket
import threading
import time
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, HTTPException

from . import bus, config, db, ext

log = logging.getLogger("osinthub.notify")

KEY, LOG_KEY, HELD_KEY, DIGEST_KEY = "notify.config", "notify.log", "notify.held", "notify.digest_last"
SEVS = ("info", "low", "medium", "high")
RANK = {s: i for i, s in enumerate(SEVS)}
POLL_S = 60
TIMEOUT_S = 10
RETRY_WAITS = (2, 10)       # seconds before the 2nd and 3rd try
QUEUE_MAX = 50
LOG_MAX = 20
QUIET_FOLD = 3              # more than this many held messages go out as one
DIGEST_LATE_H = 6           # a summary missed (app not running) is still sent this long after its time
DEFAULTS = {"enabled": False, "url": "", "preset": "ntfy", "min_severity": "high", "sensor": True,
            "quiet": {"on": False, "start": "22:00", "end": "07:00"}, "digest": {"on": False, "time": "08:00"},
            "device_names": False, "allow_public": False, "link_base": ""}

# Request shapes, from each project's public documentation.
PRESETS = {
    "ntfy": {"label": "ntfy", "example": "http://ntfy.lan/night-desk",
             "hint": "The topic address, for example http://ntfy.lan/night-desk. Night Desk publishes JSON to the server root with the topic inside.",
             "docs": "https://docs.ntfy.sh/publish/#publish-as-json"},
    "gotify": {"label": "Gotify", "example": "http://gotify.lan/message?token=YOUR_APP_TOKEN",
               "hint": "The server address with an application token: http://gotify.lan/message?token=…",
               "docs": "https://gotify.net/docs/pushmsg"},
    "homeassistant": {"label": "Home Assistant", "example": "http://homeassistant.local:8123/api/webhook/night-desk-alert",
                      "hint": "A webhook trigger address: http://homeassistant.local:8123/api/webhook/<webhook id>. Use trigger.json.title, .message, .severity and .link in the automation.",
                      "docs": "https://www.home-assistant.io/docs/automation/trigger/#webhook-trigger"},
    "discord": {"label": "Discord-compatible", "example": "https://discord.com/api/webhooks/<id>/<token>",
                "hint": "A Discord webhook address, or a self-hosted service that accepts the same message shape.",
                "docs": "https://discord.com/developers/docs/resources/webhook#execute-webhook"},
    "json": {"label": "Plain JSON", "example": "http://192.168.1.10:8080/hook",
             "hint": "Any address that accepts a JSON POST: {app, trigger, title, message, severity, link, time}.",
             "docs": ""},
}

# ------------------------------------------------------------------ destinations
LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fe80::/10", "fc00::/7")]
METADATA = (ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254"))   # cloud metadata
LOCAL_SUFFIXES = (".lan", ".local", ".home.arpa", ".internal", ".localdomain", ".home")


def ip_kind(addr: str) -> str:
    """'local', 'internet' or 'bad' (unspecified, multicast, reserved: never a destination)."""
    ip = ipaddress.ip_address(addr.split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_unspecified or ip.is_multicast or (ip.version == 4 and ip.is_reserved) or ip in METADATA:
        return "bad"
    return "local" if any(ip in n for n in LOCAL_NETS) else "internet"


def host_kind(host: str) -> str:
    """By name alone (no lookup): 'local' for a local address, localhost, a single-label name or a local suffix."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return "bad"
    try:
        return ip_kind(host)
    except ValueError:
        pass
    if re.fullmatch(r"(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}", host):
        try:   # 2130706433, 0x7f000001, 0177.0.0.1: the resolver reads these as IPv4 addresses
            return ip_kind(socket.inet_ntoa(socket.inet_aton(host)))
        except OSError:
            pass
    if host == "localhost" or "." not in host or host.endswith(LOCAL_SUFFIXES):
        return "local"
    return "internet"


def _resolve(host: str, port: int) -> list[str]:
    """Every address the host resolves to now (tests replace this)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(i[4][0] for i in infos))


def mask(url: str) -> str:
    """The URL without anything that may be a secret: scheme, host and port, then … for the rest."""
    try:
        p = urlsplit(url)
        host = p.hostname or ""
    except ValueError:
        return "…"
    if not host:
        return "…"
    h = f"[{host}]" if ":" in host else host
    port = f":{p.port}" if p.port else ""
    rest = (p.path or "").strip("/") or p.query
    return f"{p.scheme}://{h}{port}/" + ("…" if rest else "")


def check_url(url: str, preset: str, allow_public: bool) -> dict:
    """Validate a destination when it is saved. Raises ValueError with a plain message."""
    url = (url or "").strip()
    try:
        p = urlsplit(url)
        p.port  # noqa: B018  (reading it raises ValueError for a bad port)
    except ValueError:
        raise ValueError("That address is not a valid web address.")
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("The address must start with http:// or https:// and name a host.")
    if preset not in PRESETS:
        raise ValueError(f"Format must be one of: {', '.join(v['label'] for v in PRESETS.values())}.")
    path = p.path.rstrip("/")
    if preset == "ntfy" and not path.rsplit("/", 1)[-1]:
        raise ValueError("Put the topic at the end of the ntfy address, for example http://ntfy.lan/night-desk.")
    if preset == "gotify" and "token" not in parse_qs(p.query):
        raise ValueError("Gotify needs an application token: add ?token=YOUR_APP_TOKEN to the address.")
    if preset == "homeassistant" and "/api/webhook/" not in p.path + "/":
        raise ValueError("A Home Assistant address looks like http://homeassistant.local:8123/api/webhook/<webhook id>.")
    if preset == "discord" and "/webhooks/" not in p.path:
        raise ValueError("A Discord-compatible address contains /webhooks/<id>/<token>.")
    kind = host_kind(p.hostname)
    if kind == "bad":
        raise ValueError("That host can't receive messages.")
    if kind == "internet" and not allow_public:
        raise ValueError(f"{p.hostname} is on the internet. To send there, tick “Send to an internet service” "
                         "first: the alert's title, severity and link would leave this machine.")
    return {"host": p.hostname, "host_kind": kind}


# ------------------------------------------------------------------ config
def load() -> dict:
    v = db.get_setting(KEY, {}) or {}
    c = {**DEFAULTS, **{k: v[k] for k in DEFAULTS if k in v}}
    c["quiet"] = {**DEFAULTS["quiet"], **(v.get("quiet") or {})}
    c["digest"] = {**DEFAULTS["digest"], **(v.get("digest") or {})}
    return c


def public(c: dict | None = None) -> dict:
    """The config as the UI sees it: the URL masked, never in full."""
    c = c or load()
    out = {k: v for k, v in c.items() if k != "url"}
    out["url_set"] = bool(c["url"])
    out["url_masked"] = mask(c["url"]) if c["url"] else ""
    host = urlsplit(c["url"]).hostname if c["url"] else None
    out["host"] = host
    out["host_kind"] = host_kind(host) if host else None
    out["link_base_default"] = link_base(c)   # what links use while link_base is unset
    out["link_hint"] = link_hint(c)
    return out


_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _hhmm(v, name: str) -> str:
    v = str(v or "").strip()
    if not _HHMM.match(v):
        raise ValueError(f"{name} must be a time like 07:30.")
    return v


def save(body: dict) -> dict:
    """Merge the fields given into the saved config. A new URL is checked; an empty one keeps the saved URL;
    clear_url removes it. Turning notifications on, or changing what counts, takes what is open now as known."""
    old = load()
    c = json.loads(json.dumps(old))
    for k in ("enabled", "device_names", "allow_public", "sensor"):
        if k in body:
            c[k] = bool(body[k])
    if "preset" in body:
        if body["preset"] not in PRESETS:
            raise ValueError("Unknown format.")
        c["preset"] = body["preset"]
    if "min_severity" in body:
        if body["min_severity"] not in ("high", "medium"):
            raise ValueError("Minimum severity must be high or medium.")
        c["min_severity"] = body["min_severity"]
    for grp, fields in (("quiet", ("start", "end")), ("digest", ("time",))):
        g = body.get(grp)
        if isinstance(g, dict):
            if "on" in g:
                c[grp]["on"] = bool(g["on"])
            for f in fields:
                if f in g:
                    c[grp][f] = _hhmm(g[f], f"The {'quiet hours' if grp == 'quiet' else 'summary'} {f}")
    if "link_base" in body:
        lb = str(body["link_base"] or "").strip().rstrip("/")
        if lb and not re.match(r"^https?://[^/\s]+(/\S*)?$", lb):
            raise ValueError("Links open at: give a web address such as http://127.0.0.1:8787.")
        c["link_base"] = lb
    if body.get("clear_url"):
        c["url"] = ""
        c["enabled"] = False
    elif str(body.get("url") or "").strip():
        c["url"] = str(body["url"]).strip()
    if c["url"]:
        check_url(c["url"], c["preset"], c["allow_public"])
    elif c["enabled"]:
        raise ValueError("Add the address to send to before turning notifications on.")
    db.set_setting(KEY, c)
    if c["enabled"] and (not old["enabled"] or c["min_severity"] != old["min_severity"] or c["sensor"] != old["sensor"]):
        baseline(c)
    if c["enabled"] and c["digest"]["on"] and not (old["enabled"] and old["digest"]["on"]):
        db.set_setting(DIGEST_KEY, _now().isoformat())   # the first summary covers from now, not from the start of time
    return c


def _is_loopback_url(u: str) -> bool:
    try:
        h = urlsplit(u).hostname or ""
    except ValueError:
        return False
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def lan_address() -> str | None:
    """This computer's address on the local network, if it has one. A UDP socket's connect() only picks the route;
    nothing is sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ip = s.getsockname()[0]
        return ip if ip_kind(ip) == "local" and not ipaddress.ip_address(ip).is_loopback else None
    except OSError:
        return None


def link_hint(c: dict) -> dict:
    """What the form needs to warn about a link a phone cannot open, and a suggestion."""
    lb = link_base(c)
    host = config.host_name(config.HOST)
    local_only = host in ("127.0.0.1", "localhost", "::1")
    sug = None
    if not local_only:
        name = socket.gethostname().split(".")[0]
        ip = lan_address()
        port = config.PORT
        sug = [f"http://{name}.local:{port}"] + ([f"http://{ip}:{port}"] if ip else [])
    return {"loopback": _is_loopback_url(lb), "listening_local_only": local_only, "suggestions": sug or []}


def link_base(c: dict) -> str:
    return (c.get("link_base") or f"http://127.0.0.1:{config.PORT}").rstrip("/")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _local(t: dt.datetime | None = None) -> dt.datetime:
    return (t or _now()).astimezone()


def in_quiet(c: dict, t: dt.datetime | None = None) -> bool:
    q = c["quiet"]
    if not q.get("on"):
        return False
    hm = _local(t).strftime("%H:%M")
    s, e = q["start"], q["end"]
    if s == e:
        return False
    return s <= hm < e if s < e else (hm >= s or hm < e)


# ------------------------------------------------------------------ wording (fixed phrases, never a model)
ABUSECH = {"threatfox", "urlhaus", "sslbl"}
_OUT = {"c2": "a device contacted a known command-and-control server",
        "compromised": "a device contacted a known compromised host",
        "drop": "a device contacted a network run by criminals",
        "tor": "a device connected to the Tor network",
        "attacker": "a device contacted a known attacking address",
        "scanner": "a device contacted a known scanning address",
        "reputation": "a device contacted an address with a bad reputation"}


def phrase(kind: str | None, category: str | None = None, sources=()) -> str:
    kind = kind or ""
    fam = kind.split(":", 1)[-1] if ":" in kind else kind
    generic = bool(set(sources or ()) & ABUSECH)   # abuse.ch-derived: nothing of the listing goes out
    if kind == "ids":
        return "your network sensor flagged a known attack pattern"
    if kind == "kev":
        return "a device runs software with a known exploited vulnerability"
    if kind == "newdev":
        return "a new device joined your network"
    if kind == "sensor":
        return "a log sender stopped sending logs"
    if kind == "historical":
        return "older logs show contact with an address on a threat list"
    if kind == "retro":
        return "a past contact is now on a threat list"
    if fam == "in":
        return "an address on a threat list reached your network"
    if fam == "out":
        cat = None if generic else (category or kind.split(":", 1)[0])
        return _OUT.get(cat, "a device contacted an address on a threat list")
    return "something on your network needs a look"


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:]


def incident_message(r: dict, c: dict, rose: bool = False) -> dict:
    sev = r.get("severity") or "high"
    if r.get("kind") == "sensor":
        name = r.get("indicator") if c["device_names"] else None
        what = f"{name} stopped sending logs" if name else "a log sender stopped sending logs"
        title = f"{_cap(sev)}: {what}" + (" (still quiet)" if rose else "")
        trig = "sensor"
    else:
        what = phrase(r.get("kind"), r.get("category"), r.get("sources") or ())
        dev = r.get("device_name") if c["device_names"] else None
        title = f"{_cap(sev)} alert: {what}" + (f" ({dev})" if dev else "") + (" — now " + sev if rose else "")
        trig = "incident"
    link = f"{link_base(c)}/#network/alerts/{quote(str(r['id']), safe='')}"
    return {"trigger": trig, "title": title[:200], "severity": sev, "link": link,
            "message": f"{_cap(what)}. Severity: {sev}. Open Night Desk to see the details.",
            "time": _now().isoformat(), "ref": r["id"]}


# ------------------------------------------------------------------ request shapes
_NTFY_PRI = {"high": 4, "medium": 3, "low": 2, "info": 2}
_NTFY_TAG = {"high": "rotating_light", "medium": "warning", "low": "information_source", "info": "memo"}
_GOTIFY_PRI = {"high": 8, "medium": 5, "low": 3, "info": 1}
_DISCORD_COLOR = {"high": 0xE5484D, "medium": 0xE8A33D, "low": 0x7A8BA8, "info": 0x7A8BA8}


def build_request(preset: str, url: str, msg: dict) -> tuple[str, dict, bytes]:
    """(url, headers, body) for one message in the preset's shape."""
    p = urlsplit(url)
    sev = msg.get("severity") or "info"
    h = {"Content-Type": "application/json", "User-Agent": "NightDesk-notify/1"}
    if preset == "ntfy":
        # https://docs.ntfy.sh/publish/#publish-as-json : POST to the server root, topic in the body
        path = p.path.rstrip("/")
        topic = path.rsplit("/", 1)[-1]
        url = urlunsplit((p.scheme, p.netloc, path[: len(path) - len(topic)] or "/", p.query, ""))
        body = {"topic": topic, "title": msg["title"], "message": msg["message"], "priority": _NTFY_PRI.get(sev, 3),
                "tags": [_NTFY_TAG.get(sev, "memo")], "click": msg["link"]}
    elif preset == "gotify":
        # https://gotify.net/docs/pushmsg (POST /message?token=) and https://gotify.net/docs/msgextras (click url)
        path = p.path.rstrip("/")
        if not path.endswith("/message"):
            path += "/message"
        url = urlunsplit((p.scheme, p.netloc, path, p.query, ""))
        body = {"title": msg["title"], "message": msg["message"], "priority": _GOTIFY_PRI.get(sev, 5),
                "extras": {"client::display": {"contentType": "text/plain"},
                           "client::notification": {"click": {"url": msg["link"]}}}}
    elif preset == "homeassistant":
        # https://www.home-assistant.io/docs/automation/trigger/#webhook-trigger : the JSON is trigger.json
        body = {"title": msg["title"], "message": msg["message"], "severity": sev, "link": msg["link"],
                "trigger": msg["trigger"], "time": msg["time"]}
    elif preset == "discord":
        # https://discord.com/developers/docs/resources/webhook#execute-webhook (embed limits: title 256, text 4096)
        body = {"username": "Night Desk", "allowed_mentions": {"parse": []},
                "embeds": [{"title": msg["title"][:256], "description": msg["message"][:4096], "url": msg["link"],
                            "color": _DISCORD_COLOR.get(sev, 0x7A8BA8)}]}
    else:
        body = {"app": "Night Desk", "trigger": msg["trigger"], "title": msg["title"], "message": msg["message"],
                "severity": sev, "link": msg["link"], "time": msg["time"]}
    return url, h, json.dumps(body, ensure_ascii=False).encode()


# ------------------------------------------------------------------ sending
class Refused(Exception):
    """Not sent on purpose: status is 'held' or 'blocked'."""

    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class _Retry(Exception):
    pass


_quiet_urls: set[str] = set()


class _HideOurs(logging.Filter):
    """httpx logs every request URL at INFO; ours may carry a token, so those lines are dropped."""

    def filter(self, record):
        return not any(isinstance(a, (str, httpx.URL)) and str(a) in _quiet_urls for a in (record.args or ()))


logging.getLogger("httpx").addFilter(_HideOurs())


def pinned_target(url: str, allow_public: bool) -> tuple[str, str, str]:
    """(url with the checked address, Host header value, TLS name). Raises Refused."""
    p = urlsplit(url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    named = host_kind(host)
    if named == "bad":
        raise Refused("blocked", "that host can't receive messages")
    if config.OFFLINE and named == "internet":
        raise Refused("held", "held: offline")   # not even a DNS lookup for an internet name
    if named == "internet" and not allow_public:
        raise Refused("blocked", "blocked: internet services are not allowed")
    try:
        addrs = _resolve(host, port)
    except (OSError, UnicodeError):
        raise _Retry("could not look up the host")
    if not addrs:
        raise _Retry("could not look up the host")
    kinds = {a: ip_kind(a) for a in addrs}
    if "bad" in kinds.values():
        raise Refused("blocked", "blocked: the host points at an address that can't receive messages")
    if any(k == "internet" for k in kinds.values()):
        if config.OFFLINE:
            raise Refused("held", "held: offline")
        if not allow_public:
            raise Refused("blocked", "blocked: the name now points at an internet address")
    ip = addrs[0]
    ip_host = f"[{ip.split('%', 1)[0]}]" if ":" in ip else ip
    default = (p.scheme == "https" and port == 443) or (p.scheme == "http" and port == 80)
    host_hdr = (f"[{host}]" if ":" in host else host) + ("" if default else f":{port}")
    return urlunsplit((p.scheme, f"{ip_host}:{port}", p.path or "/", p.query, "")), host_hdr, host


def send_once(c: dict, msg: dict, client: httpx.Client | None = None) -> str:
    """One try. Returns a short status ('HTTP 200'). Raises Refused (no retry) or _Retry (try again)."""
    url, headers, body = build_request(c["preset"], c["url"], msg)
    target, host_hdr, sni = pinned_target(url, c["allow_public"])
    p = urlsplit(url)
    headers["Host"] = host_hdr
    if p.username is not None:   # http://user:pass@host/ (ntfy access control)
        cred = f"{p.username}:{p.password or ''}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(cred).decode()
    own = client is None
    client = client or httpx.Client(timeout=TIMEOUT_S, follow_redirects=False, trust_env=False)
    _quiet_urls.add(target)
    try:
        ext_ = {"sni_hostname": sni} if p.scheme == "https" else {}
        r = client.post(target, headers=headers, content=body, extensions=ext_)
    except httpx.TimeoutException:
        raise _Retry("timed out")
    except httpx.HTTPError as e:
        raise _Retry("could not connect" + (" (TLS)" if "SSL" in type(e).__name__ or "ssl" in str(e).lower() else ""))
    finally:
        _quiet_urls.discard(target)
        if own:
            client.close()
    if r.status_code == 429 or r.status_code >= 500:
        raise _Retry(f"the service answered {r.status_code}")
    if r.status_code >= 300:
        raise Refused("failed", f"the service answered {r.status_code}")
    return f"HTTP {r.status_code}"


def deliver(c: dict, msg: dict, sleep=time.sleep, waits=RETRY_WAITS) -> dict:
    """Send with retries and back-off; log the outcome. Never raises."""
    host = urlsplit(c["url"]).hostname if c.get("url") else None
    tries = 0
    status, detail = "failed", "no address set"
    if c.get("url"):
        for i in range(len(waits) + 1):
            tries += 1
            try:
                detail = send_once(c, msg)
                status = "sent"
                break
            except Refused as e:
                status, detail = e.status, e.detail
                break
            except _Retry as e:
                status, detail = "failed", str(e)
            except Exception as e:   # never let a bug here reach the caller
                status, detail = "failed", f"error: {type(e).__name__}"
                log.warning("notify: delivery error %s", type(e).__name__)
                break
            if i < len(waits):
                sleep(waits[i])
        if status == "failed" and tries > 1:
            detail += f" ({tries} tries)"
    entry = {"at": _now().isoformat(), "trigger": msg.get("trigger"), "title": msg.get("title"), "host": host,
             "status": status, "detail": detail}
    record(entry)
    log.info("notify: %s %s to %s: %s", msg.get("trigger"), status, host, detail)
    return entry


# ------------------------------------------------------------------ queue and log
_lock = threading.Lock()
_queue: list[dict] = []
_has_work = threading.Event()


def record(entry: dict) -> None:
    with _lock:
        rows = [entry] + list(db.get_setting(LOG_KEY, []) or [])
        db.set_setting(LOG_KEY, rows[:LOG_MAX])


def delivery_log() -> list[dict]:
    return list(db.get_setting(LOG_KEY, []) or [])[:LOG_MAX]


def enqueue(msg: dict) -> None:
    with _lock:
        if len(_queue) >= QUEUE_MAX:
            old = _queue.pop(0)
            dropped = {"at": _now().isoformat(), "trigger": old.get("trigger"), "title": old.get("title"),
                       "host": None, "status": "dropped", "detail": "dropped: too many messages waiting"}
        else:
            dropped = None
        _queue.append(msg)
        _has_work.set()
    if dropped:
        record(dropped)


def drain(sleep=time.sleep) -> int:
    """Send everything waiting (in order). Returns how many were tried."""
    n = 0
    while True:
        with _lock:
            if not _queue:
                _has_work.clear()
                return n
            msg = _queue.pop(0)
        c = load()
        if not c["enabled"] and msg.get("trigger") != "test":
            continue
        deliver(c, msg, sleep=sleep)
        n += 1


def queued() -> int:
    with _lock:
        return len(_queue)


# ------------------------------------------------------------------ triggers
SCHEMA = """CREATE TABLE IF NOT EXISTS notify_seen (   -- alerts already notified (or taken as known), osinthub/notify.py
    alert_id VARCHAR PRIMARY KEY,
    incident VARCHAR,
    srank    INTEGER,
    notified_at TIMESTAMPTZ
);"""
_ready: set = set()


def ensure() -> None:
    key = id(db.connect())
    if key not in _ready:
        db.execute(SCHEMA)
        _ready.add(key)


def candidates(c: dict) -> list[dict]:
    """Open incidents that may need a message: needs-you incidents at or above the minimum, and quiet senders."""
    try:
        from .netlog import incidents
        incidents.ensure()
    except Exception as e:   # netlog not there (OSINTHUB_DISABLE_EXT, a fresh lake): nothing to notify
        log.debug("notify: no incidents: %s", e)
        return []
    sevs = ["high"] if c["min_severity"] == "high" else ["high", "medium"]
    sev_in = ", ".join(f"'{s}'" for s in sevs)
    sensor = "OR (kind = 'sensor' AND severity IN ('high', 'medium') AND json_extract_string(evidence, '$.state') = 'open')" \
        if c["sensor"] else ""
    where = f"WHERE state = 'new' AND NOT demo AND ((kind <> 'sensor' AND severity IN ({sev_in})) {sensor})"
    rows = db.query(incidents.incidents_sql("", where, incidents.ORDER, "LIMIT 500"))
    for r in rows:
        try:
            ev = json.loads(r.get("evidence") or "{}") if isinstance(r.get("evidence"), str) else (r.get("evidence") or {})
        except ValueError:
            ev = {}
        r["category"] = (ev.get("indicator") or {}).get("category")
        r["evidence"] = {}
    if c["device_names"]:
        try:
            from .netlog.api import _name_alerts
            _name_alerts(rows)
        except Exception:
            pass
    return rows


def _seen(ids: list[str]) -> int | None:
    if not ids:
        return None
    r = db.query(f"SELECT max(srank) AS m FROM notify_seen WHERE alert_id IN ({','.join('?' * len(ids))})", ids)
    return r[0]["m"] if r and r[0]["m"] is not None else None


def _mark(r: dict, rank: int) -> None:
    ids = list(r.get("alerts") or [r["id"]])
    with db._write_lock:
        cur = db.cursor()
        cur.executemany("""INSERT INTO notify_seen VALUES (?, ?, ?, now())
                           ON CONFLICT (alert_id) DO UPDATE SET srank = greatest(notify_seen.srank, excluded.srank),
                                                                incident = excluded.incident""",
                        [[a, r["id"], rank] for a in ids])


def baseline(c: dict) -> int:
    """Take every incident open now as known: none of them is sent (later rises in severity still are)."""
    ensure()
    rows = candidates(c)
    for r in rows:
        _mark(r, RANK.get(r.get("severity"), 0))
    return len(rows)


def check_incidents(c: dict) -> list[dict]:
    """New messages for incidents not notified yet, or whose severity rose. Marks them as notified."""
    ensure()
    out = []
    for r in candidates(c):
        rank = RANK.get(r.get("severity"), 0)
        prev = _seen(list(r.get("alerts") or [r["id"]]))
        if prev is not None and rank <= prev:
            continue
        out.append(incident_message(r, c, rose=prev is not None))
        _mark(r, rank)
    return out


def _held() -> list[dict]:
    return list(db.get_setting(HELD_KEY, []) or [])


def release_held(c: dict) -> list[dict]:
    held = _held()
    if not held:
        return []
    db.set_setting(HELD_KEY, [])
    if len(held) <= QUIET_FOLD:
        return held
    top = max(held, key=lambda m: RANK.get(m.get("severity"), 0))
    n_high = sum(1 for m in held if m.get("severity") == "high")
    return [{"trigger": "quiet", "title": f"{len(held)} alerts came in during quiet hours", "severity": top.get("severity"),
             "link": f"{link_base(c)}/#network/alerts", "time": _now().isoformat(),
             "message": f"{len(held)} alerts came in during quiet hours ({n_high} high). Open Night Desk to see them."}]


def digest_due(c: dict, t: dt.datetime | None = None) -> bool:
    if not c["digest"]["on"]:
        return False
    loc = _local(t)
    hh, mm = map(int, c["digest"]["time"].split(":"))
    target = loc.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if loc < target or loc - target > dt.timedelta(hours=DIGEST_LATE_H):
        return False
    last = db.get_setting(DIGEST_KEY)
    try:
        last_t = dt.datetime.fromisoformat(last) if last else None
    except ValueError:
        last_t = None
    return last_t is None or last_t < target


def tick(t: dt.datetime | None = None) -> dict:
    """One check of every trigger. Queues what is due; returns what it did."""
    c = load()
    if not c["enabled"] or not c["url"]:
        return {"enabled": False}
    msgs = check_incidents(c)
    quiet = in_quiet(c, t)
    held = 0
    if quiet and msgs:
        db.set_setting(HELD_KEY, (_held() + msgs)[-QUEUE_MAX:])
        held, msgs = len(msgs), []
    if not quiet:
        msgs = release_held(c) + msgs
    for m in msgs:
        enqueue(m)
    dig = False
    if digest_due(c, t):
        enqueue(digest_message(c, since=_digest_since()))
        db.set_setting(DIGEST_KEY, _now().isoformat())
        dig = True
    return {"enabled": True, "queued": len(msgs), "held": held, "digest": dig}


def _digest_since() -> dt.datetime:
    last = db.get_setting(DIGEST_KEY)
    try:
        t = dt.datetime.fromisoformat(last) if last else None
    except ValueError:
        t = None
    floor = _now() - dt.timedelta(days=7)
    return max(t, floor) if t else _now() - dt.timedelta(hours=24)


# ------------------------------------------------------------------ the daily summary
def digest_lines(c: dict, since: dt.datetime) -> tuple[list[str], dict]:
    """The Watch briefing's sections since `since`, as counts under fixed section names. Nothing of an item's own
    text goes out (no headline, title, product, CVE, indicator or device name: free text can carry an address, a
    domain or what your network touched), and nothing derived from demo data is counted."""
    from .watch import briefing
    try:
        from .netlog import incidents
        ny = incidents.needs_you()          # open, untriaged, not expected, not demo
    except Exception:
        ny = {}
    k_sec, kev_items = briefing.kev(since)
    t_sec = briefing.touches(since, kev_items)
    shown = t_sec.get("items") or []      # capped at briefing.MAX_ITEMS; only these can be checked for demo
    n_touch = sum(1 for i in shown if not i.get("demo"))
    more = "+" if (t_sec.get("count") or 0) > len(shown) else ""
    fol = briefing.follow(since)
    big = briefing.big_stories(since)
    h, _ = briefing.health()
    n, hi, me = ny.get("needs_you") or 0, ny.get("high") or 0, ny.get("medium") or 0
    counts = {"needs_you": n, "high": hi, "medium": me, "kev": k_sec.get("count") or 0, "touches": n_touch,
              "follow": (fol.get("count") or 0) if fol.get("following") else 0, "stories": big.get("count") or 0,
              "health": (h or {}).get("count") or 0}
    lines = [f"Alerts that need you: {n} ({hi} high, {me} medium)" if n else "No alerts need you.",
             f"Newly exploited vulnerabilities: {counts['kev']}",
             f"Touches your network or what you follow: {counts['touches']}{more}"]
    if fol.get("following"):
        lines.append(f"News about what you follow: {counts['follow']}")
    lines.append(f"Big stories: {counts['stories']}")
    if counts["health"]:
        lines.append(f"Feed problems: {counts['health']}")
    return lines, counts


def digest_message(c: dict, since: dt.datetime | None = None) -> dict:
    since = since or _now() - dt.timedelta(hours=24)
    try:
        lines, counts = digest_lines(c, since)
    except Exception as e:
        log.warning("notify: summary failed: %s", type(e).__name__)
        lines, counts = ["The summary could not be built. Open Night Desk to see what happened."], {}
    n = counts.get("needs_you") or 0
    k = counts.get("kev") or 0
    title = "Night Desk daily summary: " + (f"{n} need{'s' if n == 1 else ''} you" if n else "nothing needs you") + \
        (f", {k} newly exploited" if k else "")
    link = f"{link_base(c)}/#watch"
    return {"trigger": "digest", "title": title, "severity": "high" if n else "info", "link": link,
            "message": "\n".join(lines + ["", f"Since {_local(since).strftime('%a %H:%M')}. Open Watch for the details: {link}"]),
            "time": _now().isoformat(), "counts": counts}


# ------------------------------------------------------------------ background tasks
async def watch_triggers() -> None:
    """Check the triggers after each new-alert message on the bus, and every POLL_S seconds."""
    q = bus.subscribe()
    try:
        while True:
            try:
                await asyncio.wait_for(_next_alert(q), timeout=POLL_S)
                await asyncio.sleep(2)   # let a burst of alert messages settle
            except TimeoutError:
                pass
            try:
                await asyncio.to_thread(tick)
            except Exception as e:   # never fatal: try again on the next round
                log.warning("notify: trigger check failed: %s", e)
    finally:
        bus.unsubscribe(q)


async def _next_alert(q: asyncio.Queue) -> None:
    while True:
        m = await q.get()
        if '"topic": "netlog_alerts"' in m:
            return


async def send_queue() -> None:
    try:
        while True:
            await asyncio.to_thread(_has_work.wait, 30)
            try:
                await asyncio.to_thread(drain)
            except Exception as e:
                log.warning("notify: sending failed: %s", e)
    finally:
        # cancelled at shutdown: wake the worker thread still blocked in _has_work.wait, or the event loop's
        # executor shutdown waits for it (up to 30 s per stop; it made every TestClient lifespan exit hang)
        _has_work.set()


# ------------------------------------------------------------------ HTTP API
router = APIRouter(prefix="/api/notify")


def _state() -> dict:
    with _lock:
        held = len(_held())
    return {"config": public(), "presets": [{"id": k, **v} for k, v in PRESETS.items()], "log": delivery_log(),
            "queued": queued(), "held": held, "offline": config.OFFLINE, "digest_last": db.get_setting(DIGEST_KEY),
            "quiet_now": in_quiet(load())}


@router.get("")
def get_notify():
    return _state()


@router.put("")
def put_notify(body: dict):
    try:
        save(body or {})
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _state()


@router.post("/test")
def test_notify(body: dict | None = None):
    """Send one test message now (to the saved address, or to the one in the form, not saved)."""
    body = body or {}
    c = load()
    for k in ("preset", "allow_public"):
        if k in body:
            c[k] = body[k] if k == "preset" else bool(body[k])
    if str(body.get("url") or "").strip():
        c["url"] = str(body["url"]).strip()
    lb = str(body.get("link_base") or "").strip().rstrip("/")
    if lb and re.match(r"^https?://[^/\s]+(/\S*)?$", lb):
        c["link_base"] = lb
    if not c["url"]:
        raise HTTPException(400, "Add the address to send to first.")
    try:
        check_url(c["url"], c["preset"], c["allow_public"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    msg = {"trigger": "test", "title": "Night Desk test message", "severity": "info",
           "link": f"{link_base(c)}/#settings/notifications", "time": _now().isoformat(),
           "message": "If you can read this, Night Desk can reach you. Alerts will look like this."}
    return {"result": deliver(c, msg, waits=()), "link": msg["link"], **_state()}


@router.post("/digest")
def digest_now():
    """Send the daily summary now (covering the last 24 hours), whatever the time."""
    c = load()
    if not c["url"]:
        raise HTTPException(400, "Add the address to send to first.")
    msg = digest_message(c, _now() - dt.timedelta(hours=24))
    return {"result": deliver(c, msg, waits=()), "link": msg["link"], **_state()}


ext.register("notify", schema_sql=SCHEMA, router=router, tasks=(watch_triggers, send_queue))

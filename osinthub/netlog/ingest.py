"""Push ingest: firewalls and sensors upload their logs to Night Desk; Night Desk never logs in to them.

A second, minimal HTTP(S) listener (default port 8788, off until enabled in Network → Connect logs; home network only by default)
accepts only authenticated uploads. Each sending device gets its own random token, stored as a
sha256 only and revocable on its own. The main UI keeps listening on 127.0.0.1; the ingest
listener can bind to the LAN without exposing anything else.

Uploads are written to <lake>/inbox/push/<sender>/ first and imported by one worker in the main
process (the same importer as drag-and-drop), so an upload survives a restart and a slow import
never holds the device's connection open unless it asks to wait.
Reference: okf/data/netlog.md#push-uploads
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path

from fastapi import APIRouter, Body, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from .. import config, db
from . import util

log = logging.getLogger("osinthub.netlog.ingest")

SETTINGS_KEY = "netlog_ingest"
SENDERS_KEY = "netlog_senders"
# host "auto": this machine's home-network (private) address, followed when it changes; 127.0.0.1 when it has none.
# The safe default: uploads reach the LAN only. 0.0.0.0 (every network, VPNs and public addresses included) is a choice.
DEFAULTS = {"enabled": False, "host": "auto", "port": 8788, "tls": True, "max_mb": 2048}
PUSH_DIR = config.LAKE / "inbox" / "push"
CERT_DIR = config.LAKE / "certs"
SCRIPT = Path(__file__).with_name("hlta-push.sh")
MIN_FREE = 1 << 30                      # refuse uploads when the lake has less than 1 GB free
FAIL_LIMIT, FAIL_WINDOW, BLOCK_FOR = 10, 600, 900   # bad tokens per source address

_lock = threading.RLock()
_senders: list[dict] | None = None
_fails: dict[str, deque] = {}
_blocked: dict[str, float] = {}
UPLOADS: OrderedDict[str, dict] = OrderedDict()   # recent uploads, newest last (memory only)
WAKE = threading.Event()


# ------------------------------------------------------------------ settings and senders
def cfg() -> dict:
    """Saved settings, with OSINTHUB_INGEST_HOST / _PORT overriding (Docker maps the port)."""
    c = {**DEFAULTS, **(db.get_setting(SETTINGS_KEY) or {})}
    if os.environ.get("OSINTHUB_INGEST_HOST"):
        c["host"] = os.environ["OSINTHUB_INGEST_HOST"]
    if os.environ.get("OSINTHUB_INGEST_PORT"):
        c["port"] = int(os.environ["OSINTHUB_INGEST_PORT"])
    if os.environ.get("OSINTHUB_INGEST", "").lower() in ("1", "true", "yes"):
        c["enabled"] = True
    return c


def env_overrides() -> list[str]:
    return [k for k in ("OSINTHUB_INGEST", "OSINTHUB_INGEST_HOST", "OSINTHUB_INGEST_PORT", "OSINTHUB_INGEST_URL",
                        "OSINTHUB_INGEST_CERT", "OSINTHUB_INGEST_KEY") if os.environ.get(k)]


def save_cfg(c: dict) -> None:
    db.set_setting(SETTINGS_KEY, {k: c[k] for k in DEFAULTS if k in c})


def in_docker() -> bool:
    """True inside a container. OSINTHUB_DOCKER=1/0 overrides the /.dockerenv (Docker) or /run/.containerenv (Podman) check."""
    v = os.environ.get("OSINTHUB_DOCKER", "").strip().lower()
    if v:
        return v in ("1", "true", "yes")
    return Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()


def _scope(a: str) -> str:
    """loopback, lan (a private or link-local address), all (0.0.0.0 / ::) or public (anything else)."""
    if a in ("0.0.0.0", "::", ""):
        return "all"
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return "public"
    if ip.is_loopback:
        return "loopback"
    return "lan" if (ip.is_private or ip.is_link_local) else "public"


# Interfaces "auto" never binds: VPN tunnels, container and VM bridges, Apple's peer-to-peer links. Their private
# addresses are not the home network. Reference: okf/data/netlog.md#the-upload-listener
SKIP_IFACES = re.compile(r"^(utun|tun|tap|wg|docker|br-|veth|bridge|vmnet|vboxnet|virbr|tailscale|zt|ppp|ipsec|gif|stf|awdl|llw|anpi|lo)")
_IFACE_CACHE: list = [0.0, {}]


def _iface_addrs() -> dict[str, list[str]]:
    """{interface: [addresses]} from `ip -o addr` (Linux) or `ifconfig` (macOS, BSD); {} when neither is there.
    Local commands only, cached for 30 s (the listener supervisor asks every 5 s)."""
    if time.time() - _IFACE_CACHE[0] < 30:
        return _IFACE_CACHE[1]
    out: dict[str, list[str]] = {}
    try:
        if shutil.which("ip"):
            txt = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=3).stdout
            for line in txt.splitlines():   # "2: eth0    inet 192.0.2.10/24 brd ..."
                m = re.match(r"\d+:\s+(\S+?)(?:@\S+)?\s+inet6?\s+([0-9a-fA-F:.]+)", line)
                if m:
                    out.setdefault(m.group(1), []).append(m.group(2))
        elif shutil.which("ifconfig") or Path("/sbin/ifconfig").exists():
            exe = shutil.which("ifconfig") or "/sbin/ifconfig"
            txt = subprocess.run([exe], capture_output=True, text=True, timeout=3).stdout
            name = None
            for line in txt.splitlines():   # "en0: flags=..." then "\tinet 192.0.2.10 netmask ..."
                m = re.match(r"^(\S+?):\s", line)
                if m:
                    name = m.group(1)
                    continue
                m = re.match(r"^\s+inet6?\s+([0-9a-fA-F:.]+)", line)
                if m and name:
                    out.setdefault(name, []).append(m.group(1))
    except (OSError, subprocess.SubprocessError):
        out = {}
    _IFACE_CACHE[0], _IFACE_CACHE[1] = time.time(), out
    return out


def _route_addresses() -> list[str]:
    """The source address of the default route, IPv4 then IPv6 (no packet is sent)."""
    out: list[str] = []
    for fam, probe in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:  # connecting a UDP socket only picks the outgoing interface
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.connect((probe, 9))
                out.append(s.getsockname()[0].split("%")[0])
        except OSError:
            pass
    return out


def _homeish(a: str) -> bool:
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return False
    return ip.is_private and not (ip.is_loopback or ip.is_link_local or ip.is_unspecified)


def home_addresses() -> list[str]:
    """This machine's home-network addresses, the choices for "home network only": the default route's address first
    (unless it belongs to a VPN or container interface), then other private addresses of physical interfaces, IPv4
    before IPv6. Link-local addresses are left out (binding them needs a scope id)."""
    ifs = _iface_addrs()
    owner = {a.split("%")[0]: n for n, al in ifs.items() for a in al}
    skipped = lambda a: bool(SKIP_IFACES.match(owner.get(a, "")))   # noqa: E731
    pool = _route_addresses()
    if ifs:
        pool += [a.split("%")[0] for n, al in ifs.items() if not SKIP_IFACES.match(n) for a in al]
    else:
        pool += _lan_addresses()
    out: list[str] = []
    for a in pool:
        if _homeish(a) and not skipped(a) and a not in out:
            out.append(a)
    return sorted(out, key=lambda a: (":" in a, out.index(a)))


def bind_host(c: dict | None = None) -> str:
    """The address the listener actually binds: the setting, with "auto" resolved to the first home address."""
    h = str((c or cfg())["host"] or "").strip()
    if h.lower() != "auto":
        return h or "0.0.0.0"
    homes = home_addresses()
    return homes[0] if homes else "127.0.0.1"


def bind_info(c: dict | None = None) -> dict:
    """Who can reach the upload port, in plain words, and a warning when that is wider than this machine or the LAN.
    Reference: okf/data/netlog.md#the-upload-listener"""
    c = c or cfg()
    auto = str(c["host"]).strip().lower() == "auto"
    host = bind_host(c)
    scope = _scope(host)
    docker = in_docker()
    port = int(c["port"])
    warn = None
    if docker and scope == "loopback":
        explain = "Inside Docker, 127.0.0.1 is the container itself: Docker's published port cannot reach it."
        warn = "Devices cannot reach the upload port. Set OSINTHUB_INGEST_HOST back to 0.0.0.0 (the compose default)."
    elif docker:
        explain = ("Inside Docker the upload port listens on all of the container's addresses so Docker can forward to it. "
                   "Who can reach it is set by the port Docker publishes on this computer.")
        if os.environ.get("OSINTHUB_INGEST_URL"):
            explain += " Devices are told to use " + os.environ["OSINTHUB_INGEST_URL"].rstrip("/") + "."
        warn = (f"Unless you changed it, Docker publishes port {port} on every address of this computer, which can include "
                f"VPNs or a public address. To keep it on your home network, set INGEST_PORT to the computer's LAN address and port "
                f"in .env (for example INGEST_PORT=192.0.2.10:{port}) and run docker compose up -d again.")
    elif scope == "loopback":
        explain = ("Only this machine can send. Other devices cannot reach it" +
                   (": no home-network address was found, so it fell back to this machine only." if auto else "."))
    elif scope == "lan":
        explain = (f"Only devices on your home network can reach it, at {host}" +
                   (" (this machine's home address, followed if it changes)." if auto else "."))
    elif scope == "all":
        explain = "Every network this machine is on can reach it: your home network, but also any VPN, hotspot or public address."
        warn = ("This listens beyond your home network. Every upload still needs a device token, but choose "
                "“Home network only” unless a device sends from elsewhere.")
    else:
        explain = f"Devices reach it at {host}."
        warn = (f"{host} is not a home-network address, so devices outside your home may be able to reach the upload port. "
                "Every upload still needs a device token, but choose “Home network only” unless you mean this.")
    return {"host": c["host"], "auto": auto, "bound": host, "scope": scope, "docker": docker, "explain": explain,
            "warn": warn, "choices": home_addresses()}


def inbox_location() -> dict:
    """Where to put log files so the watched inbox imports them, as the user can actually reach it. In Docker the lake is
    /data inside the container: show the host folder from compose (LAKE_DIR, passed as OSINTHUB_LAKE_HOST) or, for the
    default named volume, a docker compose cp command. Reference: okf/data/netlog.md#import"""
    cfg = util.inbox_settings()
    dflt = cfg["is_default"]
    inside = (str(config.LAKE / "inbox" / "zeek") if dflt else cfg["path"]).rstrip("/") + "/"   # the lake as configured
    if not in_docker():
        return {"path": inside, "docker": False, "inside": inside, "copy_cmd": None, "host_lake": None}
    if not dflt:   # a folder the user chose: it is a path inside the container
        return {"path": None, "docker": True, "inside": inside, "host_lake": None,
                "copy_cmd": f"docker compose cp conn.log.gz app:{inside}",
                "note": f"The inbox is {inside} inside the Night Desk container. Mount a folder of this computer there "
                        "(a volume in docker-compose.yml), or copy files in with docker compose cp."}
    host = os.environ.get("OSINTHUB_LAKE_HOST", "").strip().rstrip("/")
    if host:
        path = f"{host}/inbox/zeek/"
        return {"path": path, "docker": True, "inside": inside, "host_lake": host,
                "copy_cmd": f"cp conn.log.gz {path}", "note": None}
    return {"path": None, "docker": True, "inside": inside, "host_lake": None,
            "copy_cmd": f"docker compose cp conn.log.gz app:{inside}",
            "note": "Night Desk keeps its data in a Docker volume, which your computer cannot open as a folder. Copy files in "
                    "with docker compose cp (run it next to docker-compose.yml), or set LAKE_DIR in .env to a folder on this "
                    "computer and that folder's inbox/zeek/ becomes the inbox."}


def _load() -> list[dict]:
    global _senders
    with _lock:
        if _senders is None:
            _senders = list(db.get_setting(SENDERS_KEY) or [])
        return _senders


def _save() -> None:
    with _lock:
        db.set_setting(SENDERS_KEY, _senders or [])


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _public(s: dict) -> dict:
    return {k: v for k, v in s.items() if k != "token_sha256"}


def senders() -> list[dict]:
    since = None
    if LISTENER.running() and LISTENER.started_at:
        since = max(APP_START, dt.datetime.fromisoformat(LISTENER.started_at).timestamp())
    return [{**_public(s), "health": health(s, since=since)} for s in _load()]


def _norm_cidrs(v) -> list[str]:
    if v in (None, ""):
        return []
    if isinstance(v, str):
        v = [x for x in v.replace(",", " ").split() if x]
    if not isinstance(v, list):
        raise ValueError("allow_cidrs must be a list of addresses or prefixes")
    out = []
    for x in v:
        try:
            out.append(str(ipaddress.ip_network(str(x).strip(), strict=False)))
        except ValueError:
            raise ValueError(f"not an address or prefix: {x}")
    return out


def create_sender(name: str, kind: str = "custom", allow_cidrs=None) -> tuple[dict, str]:
    name = " ".join(str(name or "").split())[:60]
    if not name:
        raise ValueError("name is required")
    token = "hlta_" + secrets.token_urlsafe(32)
    s = {"id": secrets.token_hex(4), "name": name, "kind": str(kind or "custom")[:20],
         "allow_cidrs": _norm_cidrs(allow_cidrs), "token_sha256": _hash(token), "token_hint": token[-4:],
         "created_at": util.now().isoformat(), "paused": False, "last_seen": None, "last_ip": None,
         "uploads": 0, "bytes": 0, "rows": 0, "last_status": None, "last_error": None}
    with _lock:
        if any(x["name"].lower() == name.lower() for x in _load()):
            raise ValueError(f"a sender called {name!r} already exists")
        _load().append(s)
        _save()
    return _public(s), token


def _find(sid: str) -> dict:
    for s in _load():
        if s["id"] == sid:
            return s
    raise KeyError(sid)


def update_sender(sid: str, body: dict) -> dict:
    with _lock:
        s = _find(sid)
        if "name" in body:
            n = " ".join(str(body["name"] or "").split())[:60]
            if not n:
                raise ValueError("name is required")
            s["name"] = n
        if "allow_cidrs" in body:
            s["allow_cidrs"] = _norm_cidrs(body["allow_cidrs"])
        if "paused" in body:
            s["paused"] = bool(body["paused"])
        if "alert_after_min" in body:   # None or "" = learn from the device's cadence; 0 = never alert
            v = body["alert_after_min"]
            if v in (None, ""):
                s["alert_after_min"] = None
            else:
                try:
                    v = float(v)
                except (TypeError, ValueError):
                    raise ValueError("alert_after_min must be a number of minutes, empty for automatic, or 0 for off")
                if v < 0 or (0 < v < 2):
                    raise ValueError("alert_after_min must be at least 2 minutes (0 turns alerts off)")
                s["alert_after_min"] = v
        _save()
        return _public(s)


def rotate_sender(sid: str) -> tuple[dict, str]:
    token = "hlta_" + secrets.token_urlsafe(32)
    with _lock:
        s = _find(sid)
        s["token_sha256"], s["token_hint"] = _hash(token), token[-4:]
        s["rotated_at"] = util.now().isoformat()
        _save()
        return _public(s), token


def delete_sender(sid: str) -> None:
    with _lock:
        s = _find(sid)
        _load().remove(s)
        _save()


# ------------------------------------------------------------------ authentication
def _throttled(ip: str) -> bool:
    until = _blocked.get(ip)
    if until and until > time.time():
        return True
    _blocked.pop(ip, None)
    return False


def _failed(ip: str) -> None:
    q = _fails.setdefault(ip, deque())
    now = time.time()
    q.append(now)
    while q and q[0] < now - FAIL_WINDOW:
        q.popleft()
    if len(q) >= FAIL_LIMIT:
        _blocked[ip] = now + BLOCK_FOR
        q.clear()
        log.warning("ingest: %s blocked for %ds after %d bad tokens", ip, BLOCK_FOR, FAIL_LIMIT)


def authenticate(request: Request) -> dict:
    ip = request.client.host if request.client else "?"
    if _throttled(ip):
        raise HTTPException(429, "too many bad tokens from this address; try again later")
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth[:7].lower() == "bearer " else request.headers.get("x-hlta-token", "").strip()
    h = _hash(token) if token else ""
    match = None
    for s in _load():
        if token and hmac.compare_digest(s["token_sha256"], h):
            match = s
    if match is None:
        _failed(ip)
        raise HTTPException(401, "missing or unknown token", headers={"WWW-Authenticate": "Bearer"})
    if match.get("allow_cidrs"):
        try:
            a = ipaddress.ip_address(ip)
            ok = any(a in ipaddress.ip_network(c) for c in match["allow_cidrs"])
        except ValueError:
            ok = False
        if not ok:
            log.warning("ingest: sender %s used from %s, outside its allowed addresses", match["name"], ip)
            raise HTTPException(403, f"this token is not allowed from {ip}")
    if match.get("paused"):
        raise HTTPException(423, "this sender is paused in Night Desk")
    _fails.pop(ip, None)
    return match


# ------------------------------------------------------------------ TLS certificate
def _lan_addresses() -> list[str]:
    out: list[str] = list(dict.fromkeys(_route_addresses()))
    try:
        for r in socket.getaddrinfo(socket.gethostname(), None):
            a = r[4][0].split("%")[0]
            ip = ipaddress.ip_address(a)
            if not (ip.is_loopback or ip.is_link_local) and a not in out:
                out.append(a)
    except (OSError, ValueError):
        pass
    return out


def cert_paths() -> tuple[Path, Path, str]:
    c, k = os.environ.get("OSINTHUB_INGEST_CERT"), os.environ.get("OSINTHUB_INGEST_KEY")
    if c and k:
        return Path(c), Path(k), "provided"
    return CERT_DIR / "ingest.crt", CERT_DIR / "ingest.key", "self-signed"


def ensure_cert(regenerate: bool = False) -> dict:
    """Make a self-signed certificate on first use. Devices pin its public key, so the
    certificate keeps working when this machine's address changes."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    crt, key, source = cert_paths()
    if source == "self-signed" and (regenerate or not (crt.exists() and key.exists())):
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        pk = ec.generate_private_key(ec.SECP256R1())
        host = socket.gethostname()
        sans: list = [x509.DNSName("localhost")]
        for n in {host, host.split(".")[0] + ".local"}:
            try:
                sans.append(x509.DNSName(n))
            except ValueError:
                pass
        for a in ["127.0.0.1", "::1", *_lan_addresses()]:
            sans.append(x509.IPAddress(ipaddress.ip_address(a)))
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"HLTA log ingest ({host.split('.')[0]})")])
        now = dt.datetime.now(dt.UTC)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(pk.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(pk, hashes.SHA256()))
        tmp = key.with_suffix(".key.part")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        tmp.replace(key)
        crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        log.info("ingest: new self-signed certificate %s", crt)
    cert = x509.load_pem_x509_certificate(crt.read_bytes())
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        sans = [str(v.value) for v in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        sans = []
    return {"source": source, "path": str(crt), "sha256": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
            "pin": "sha256//" + base64.b64encode(hashlib.sha256(spki).digest()).decode(),
            "not_after": cert.not_valid_after_utc.isoformat(), "names": sans, "mtime": crt.stat().st_mtime}


# ------------------------------------------------------------------ the listener app
def _remember(uid: str, rec: dict) -> None:
    with _lock:
        UPLOADS[uid] = rec
        UPLOADS.move_to_end(uid)
        while len(UPLOADS) > 300:
            UPLOADS.popitem(last=False)


def _file_name(name: str | None, sender: dict) -> str:
    from .importer import _safe_name
    base = Path(name or "").name or f"{sender['name']}.log"
    return _safe_name(base) + (".gz" if base.endswith(".gz") else "")


async def _spool(request: Request, sender: dict, name: str | None, limit: int) -> tuple[Path, int]:
    d = PUSH_DIR / sender["id"]
    d.mkdir(parents=True, exist_ok=True)
    uid = secrets.token_hex(6)
    final = d / f"{time.time_ns()}-{uid}-{_file_name(name, sender)}"
    part = d / f".{final.name}.part"
    n = 0
    try:
        with part.open("wb") as fh:
            async for chunk in request.stream():
                n += len(chunk)
                if n > limit:
                    raise HTTPException(413, f"upload is larger than the {limit >> 20} MB limit")
                fh.write(chunk)
        if n == 0:
            raise HTTPException(400, "empty upload")
        part.replace(final)
    finally:
        part.unlink(missing_ok=True)
    return final, n


def build_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, title="HLTA log ingest")

    @app.exception_handler(HTTPException)
    async def _err(request: Request, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/hlta-push.sh")
    def push_script():  # the sender script is not secret; devices fetch it during setup
        return PlainTextResponse(SCRIPT.read_text(), media_type="text/x-shellscript")

    @app.get("/ingest/check")
    def check(request: Request):
        s = authenticate(request)
        checkin(s, request.client.host if request.client else None)   # hlta-push.sh calls this every run
        return {"ok": True, "sender": s["name"], "max_mb": cfg()["max_mb"]}

    async def receive(request: Request, name: str | None):
        s = authenticate(request)
        c = cfg()
        limit = int(float(c["max_mb"]) * (1 << 20))
        try:
            declared = int(request.headers.get("content-length") or 0)
        except ValueError:
            declared = 0
        if declared > limit:
            raise HTTPException(413, f"upload is larger than the {c['max_mb']} MB limit")
        PUSH_DIR.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(PUSH_DIR).free < MIN_FREE + declared:
            raise HTTPException(507, "the Night Desk data drive is nearly full")
        ctype = request.headers.get("content-type", "")
        if ctype.startswith("multipart/form-data"):
            raise HTTPException(415, "send the file as the request body (curl --data-binary @file), not as a form")
        name = name or request.query_params.get("name") or request.headers.get("x-hlta-name")
        path, n = await _spool(request, s, name, limit)
        uid = path.name.split("-")[1]
        ip = request.client.host if request.client else None
        checkin(s, ip)
        _remember(uid, {"id": uid, "sender": s["id"], "sender_name": s["name"], "name": path.name.split("-", 2)[2],
                        "bytes": n, "ip": ip, "received_at": util.now().isoformat(), "status": "queued"})
        WAKE.set()
        wait = request.query_params.get("wait", "").lower() in ("1", "true", "yes")
        if wait:
            deadline = time.time() + 900
            while time.time() < deadline and UPLOADS.get(uid, {}).get("status") == "queued":
                await asyncio.sleep(0.5)
            rec = UPLOADS.get(uid, {})
            code = 200 if rec.get("status") == "ok" else 422 if rec.get("status") == "error" else 202
            return JSONResponse(_upload_public(rec), status_code=code)
        return JSONResponse({"upload_id": uid, "status": "queued", "bytes": n}, status_code=202)

    @app.post("/ingest")
    async def post(request: Request):
        return await receive(request, None)

    @app.put("/ingest/{name}")
    async def put(request: Request, name: str):  # curl -T file https://host:8788/ingest/
        return await receive(request, name)

    @app.get("/ingest/uploads/{uid}")
    def upload_status(request: Request, uid: str):
        s = authenticate(request)
        rec = UPLOADS.get(uid)
        if not rec or rec["sender"] != s["id"]:
            raise HTTPException(404, "unknown upload (only recent uploads are kept)")
        return _upload_public(rec)

    return app


def _upload_public(rec: dict) -> dict:
    return {k: rec.get(k) for k in ("id", "name", "bytes", "status", "received_at", "imported_at", "rows", "inserted",
                                    "duplicate", "matches", "error") if k in rec}


# ------------------------------------------------------------------ worker: spool → importer
def process_pending() -> int:
    """Import every spooled upload, oldest first. Runs in the main process (one at a time)."""
    from . import importer
    if not PUSH_DIR.exists():
        return 0
    files = []
    for d in PUSH_DIR.iterdir():
        if d.is_dir() and d.name != "failed":
            files += [f for f in d.iterdir() if f.is_file() and not f.name.startswith(".")]
    files.sort(key=lambda f: f.name)
    done = 0
    for f in files:
        sid = f.parent.name
        try:
            ts_ns, uid, name = f.name.split("-", 2)
        except ValueError:
            ts_ns, uid, name = "0", f.name, f.name
        with _lock:
            s = next((x for x in _load() if x["id"] == sid), None)
        label = s["name"] if s else f"removed sender {sid}"
        try:
            with f.open("rb") as fh:
                res = importer.import_any(fh, name, origin=f"push:{label}")
        except Exception as e:  # never lose the upload: park it with the failures
            res = {"error": f"{type(e).__name__}: {e}"[:500]}
            log.exception("ingest: importing %s failed", f)
        size = f.stat().st_size
        if res.get("error") and not res.get("inserted"):
            bad = PUSH_DIR / "failed" / sid
            bad.mkdir(parents=True, exist_ok=True)
            f.replace(bad / f.name)
        else:
            f.unlink(missing_ok=True)
        m = res.get("match") or {}
        rec = UPLOADS.get(uid) or {"id": uid, "sender": sid, "sender_name": label, "name": name, "bytes": size,
                                   "received_at": dt.datetime.fromtimestamp(int(ts_ns) / 1e9, util.UTC).isoformat()}
        rec.update({"status": "error" if res.get("error") and not res.get("inserted") else "ok",
                    "imported_at": util.now().isoformat(), "rows": res.get("rows", 0), "inserted": res.get("inserted", 0),
                    "duplicate": bool(res.get("duplicate")), "matches": m.get("matches"),
                    "error": res.get("error"), "log_types": res.get("log_types")})
        _remember(uid, rec)
        if s:
            with _lock:
                s["uploads"] = (s.get("uploads") or 0) + 1
                s["bytes"] = (s.get("bytes") or 0) + size
                s["rows"] = (s.get("rows") or 0) + (res.get("inserted") or 0)
                s["last_status"] = rec["status"]
                s["last_error"] = rec["error"]
                s["last_import"] = rec["imported_at"]
                _save()
        done += 1
    return done


def recent_uploads(limit: int = 50) -> list[dict]:
    with _lock:
        rows = list(UPLOADS.values())[-limit:][::-1]
    return [dict(r) for r in rows]


def pending_count() -> int:
    if not PUSH_DIR.exists():
        return 0
    return sum(1 for d in PUSH_DIR.iterdir() if d.is_dir() and d.name != "failed"
               for f in d.iterdir() if f.is_file() and not f.name.startswith("."))



# ------------------------------------------------------------------ check-ins and silence alerts
# Every authenticated request is a check-in: an upload, or the heartbeat hlta-push.sh sends on
# each run even when it has nothing new. A device's usual cadence is learned from its recent
# check-ins; when it misses it by a clear margin a "sensor_silent" alert opens in Network > Alerts,
# and it resolves (kept, lowered to low) when the device checks in again.
BURST_S = 60          # check-ins this close together are one run (several files in one cron run)
KEEP_CHECKINS = 48
MIN_INTERVALS = 3     # a cadence needs this many gaps between runs before alerts are armed
APP_START = time.time()


def checkin(s: dict, ip: str | None) -> None:
    now = time.time()
    with _lock:
        s["last_seen"], s["last_ip"] = util.now().isoformat(), ip
        cs = s.setdefault("checkins", [])
        if cs and now - cs[-1] < BURST_S:
            return  # same run; persisted with the run's first check-in
        cs.append(round(now, 1))
        del cs[:-KEEP_CHECKINS]
        _save()
    WATCH.set()  # resolve an open silence alert promptly


def cadence(s: dict) -> tuple[float | None, int]:
    """Median seconds between check-ins (None while still learning), and how many gaps it rests on."""
    cs = s.get("checkins") or []
    gaps = sorted(b - a for a, b in zip(cs, cs[1:]) if b - a >= BURST_S)
    if len(gaps) < MIN_INTERVALS:
        return None, len(gaps)
    m = len(gaps) // 2
    return (gaps[m] if len(gaps) % 2 else (gaps[m - 1] + gaps[m]) / 2), len(gaps)


def threshold(s: dict) -> tuple[float | None, str]:
    """Seconds of silence that open an alert, and where the number comes from."""
    v = s.get("alert_after_min")
    if v == 0:
        return None, "off"
    if v:
        return float(v) * 60, "set"
    c, _ = cadence(s)
    if c is None:
        return None, "learning"
    # 5-minute cron: 15 min. Hourly: 3 h. Daily: 30 h.
    return c + max(600.0, min(2 * c, 6 * 3600.0)), "auto"


def health(s: dict, now: float | None = None, since: float | None = None) -> dict:
    """since: when Night Desk could last hear the device (start of the app or of the listener)."""
    now = now or time.time()
    c, n = cadence(s)
    th, how = threshold(s)
    cs = s.get("checkins") or []
    last = cs[-1] if cs else None
    if s.get("last_seen"):
        try:
            last = max(last or 0, dt.datetime.fromisoformat(s["last_seen"]).timestamp())
        except ValueError:
            pass
    out = {"cadence_s": c, "cadence_n": n, "threshold_s": th, "threshold_from": how, "last_checkin": last,
           "silent_s": (now - last) if last else None}
    if s.get("paused"):
        out["state"] = "paused"
    elif not last:
        out["state"] = "waiting"
    elif s.get("outage"):
        out["state"] = "silent"
    elif th is None:
        out["state"] = "learning" if how == "learning" else "ok"
    else:
        ref = max(last, since or 0)
        due = last + (c or th)
        out["due_at"] = due
        out["state"] = "silent" if now - ref > th else "late" if c and now > due + max(120, 0.25 * c) else "ok"
    return out


def _fmt_dur(sec: float) -> str:
    sec = int(sec)
    if sec < 90:
        return f"{sec} s"
    if sec < 5400:
        return f"{round(sec / 60)} min"
    if sec < 172800:
        h, m = divmod(round(sec / 60), 60)
        return f"{h} h {m} min" if m and h < 10 else f"{h} h"
    return f"{round(sec / 86400)} days"


def _put_alert(rec: dict) -> None:
    import json
    with db._write_lock:
        db.cursor().execute("""
            INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count,
                                evidence, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, NULL, ?, 'ingest', 'sensor_silent', NULL, ?, ?, ?,
                    coalesce((SELECT status FROM netlog_alert_status WHERE id = ?), 'new'), now(), now())
            ON CONFLICT (id) DO UPDATE SET last_ts = excluded.last_ts, severity = excluded.severity,
                indicator = excluded.indicator, title = excluded.title, count = excluded.count,
                evidence = excluded.evidence, updated_at = now()""",
            [rec["id"], rec["ts"], rec["last_ts"], rec["severity"], rec["indicator"], rec["title"], rec["count"],
             json.dumps(util.jsonable(rec["evidence"]), default=str), rec["id"]])


def evaluate(now: float | None = None, since: float | None = None) -> dict:
    """Open, escalate and resolve silence alerts. Runs every minute and after each check-in.
    Nothing is raised while the listener is off or for the first threshold after Night Desk starts:
    a device cannot reach a listener that is not there."""
    now = now or time.time()
    if since is None:
        if not LISTENER.running():
            return {"skipped": "listener not running"}
        try:
            since = max(APP_START, dt.datetime.fromisoformat(LISTENER.started_at).timestamp())
        except (TypeError, ValueError):
            since = APP_START
    opened, resolved, changed = [], [], False
    with _lock:
        for s in _load():
            h = health(s, now, since)
            o = s.get("outage")
            c, th = h["cadence_s"], h["threshold_s"]
            ev = {"kind": "sender_silence", "sender": {"id": s["id"], "name": s["name"], "kind": s.get("kind"),
                                                       "last_ip": s.get("last_ip")},
                  "cadence_s": c, "cadence_n": h["cadence_n"], "threshold_s": th, "threshold_from": h["threshold_from"],
                  "last_checkin": h["last_checkin"], "last_import": s.get("last_import"),
                  "checkins": (s.get("checkins") or [])[-KEEP_CHECKINS:]}
            usual = f"usually every {_fmt_dur(c)}" if c else f"alert after {_fmt_dur(th)}" if th else ""
            if o and (h["last_checkin"] or 0) > o["since"] + 1:
                gap = h["last_checkin"] - o["since"]
                _put_alert({"id": o["id"], "ts": _iso(o["since"]), "last_ts": _iso(h["last_checkin"]), "severity": "low",
                            "indicator": s["name"], "count": max(1, round(gap / c)) if c else 1,
                            "title": f"{s['name']} stopped sending logs for {_fmt_dur(gap)}, then resumed ({usual})",
                            "evidence": {**ev, "opened_at": o["opened_at"], "resolved_at": h["last_checkin"], "gap_s": gap,
                                         "state": "resolved"}})
                s["outage"] = None
                s["outages"] = (s.get("outages") or 0) + 1
                resolved.append(s["name"])
                changed = True
            elif o:
                gap = now - o["since"]
                sev = "high" if gap > 24 * 3600 else "medium"
                if sev != o.get("severity") or now - o.get("touched", 0) > 600:
                    _put_alert({"id": o["id"], "ts": _iso(o["since"]), "last_ts": _iso(now), "severity": sev,
                                "indicator": s["name"], "count": max(1, round(gap / c)) if c else 1,
                                "title": f"{s['name']} has not sent logs for {_fmt_dur(gap)} ({usual})",
                                "evidence": {**ev, "opened_at": o["opened_at"], "gap_s": gap, "state": "open"}})
                    o["severity"], o["touched"] = sev, now
                    changed = True
            elif h["state"] == "silent" and th is not None and h["last_checkin"]:
                since_ts = h["last_checkin"]
                gap = now - since_ts
                aid = f"silent:{s['id']}:{int(since_ts)}"
                sev = "high" if gap > 24 * 3600 else "medium"
                _put_alert({"id": aid, "ts": _iso(since_ts), "last_ts": _iso(now), "severity": sev, "indicator": s["name"],
                            "count": max(1, round(gap / c)) if c else 1,
                            "title": f"{s['name']} has not sent logs for {_fmt_dur(gap)} ({usual})",
                            "evidence": {**ev, "opened_at": now, "gap_s": gap, "state": "open"}})
                s["outage"] = {"id": aid, "since": since_ts, "opened_at": now, "severity": sev, "touched": now}
                opened.append(s["name"])
                changed = True
        if changed:
            _save()
    if opened or resolved:
        log.warning("ingest: silent %s; resumed %s", opened, resolved)
        util.publish_alerts({"sender_silent": opened, "sender_resumed": resolved})
    return {"opened": opened, "resolved": resolved}


def _iso(t: float) -> str:
    return dt.datetime.fromtimestamp(t, util.UTC).isoformat()


WATCH = threading.Event()

# ------------------------------------------------------------------ listener supervisor
class _Listener:
    def __init__(self):
        self.server = None
        self.thread: threading.Thread | None = None
        self.key = None
        self.error: str | None = None
        self.started_at: str | None = None
        self.failed_key = None
        self.failed_at = 0.0

    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive() and self.server and self.server.started)

    def stop(self) -> None:
        if self.server:
            self.server.should_exit = True
        if self.thread:
            self.thread.join(timeout=10)
        self.server = self.thread = self.key = None
        self.started_at = None

    def reconcile(self) -> dict:
        import uvicorn
        c = cfg()
        tls = None
        if c["enabled"] and c["tls"]:
            try:
                tls = ensure_cert()
            except Exception as e:
                self.error = f"certificate: {type(e).__name__}: {e}"
                return status()
        host = bind_host(c)   # "auto" follows this machine's home address: a new address rebinds
        key = (c["enabled"], host, int(c["port"]), bool(c["tls"]), tls and tls["mtime"])
        if key == self.key and (self.running() or not c["enabled"]):
            return status()
        if self.thread and not self.thread.is_alive():
            self.server = self.thread = self.key = None
        if key != self.key:
            self.stop()
        if not c["enabled"]:
            self.error = None
            return status()
        if key == self.failed_key and time.time() - self.failed_at < 60:
            return status()  # don't hammer a port that just failed; retry each minute
        crt, k, _ = cert_paths()
        conf = uvicorn.Config(build_app(), host=host, port=int(c["port"]), log_level="warning", access_log=False,
                              ssl_certfile=str(crt) if c["tls"] else None, ssl_keyfile=str(k) if c["tls"] else None,
                              limit_concurrency=16, timeout_keep_alive=10, proxy_headers=False, server_header=False)
        server = uvicorn.Server(conf)
        err: list[str] = []

        def run():
            try:
                server.run()
            except BaseException as e:  # uvicorn exits via SystemExit when it cannot bind
                err.append(f"{type(e).__name__}: {e}")
        t = threading.Thread(target=run, name="netlog-ingest", daemon=True)
        t.start()
        for _ in range(100):
            if server.started or not t.is_alive():
                break
            time.sleep(0.05)
        if server.started:
            self.server, self.thread, self.key, self.error = server, t, key, None
            self.started_at = util.now().isoformat()
            self.failed_key = None
            log.info("ingest: listening on %s://%s:%s", "https" if c["tls"] else "http", host, c["port"])
        else:
            server.should_exit = True
            self.failed_key, self.failed_at, self.key = key, time.time(), None
            self.error = (f"could not listen on {host}:{c['port']} (is the port in use or the address "
                          f"not on this machine?)") + (f" [{err[0]}]" if err and "SystemExit" not in err[0] else "")
            log.warning("ingest: %s", self.error)
        return status()


LISTENER = _Listener()


def status() -> dict:
    c = cfg()
    L = LISTENER
    scheme = "https" if c["tls"] else "http"
    h = bind_host(c)
    addrs = _lan_addresses() if h in ("0.0.0.0", "::", "") else [h]
    urls = [f"{scheme}://{'[' + a + ']' if ':' in a else a}:{c['port']}" for a in addrs]
    if os.environ.get("OSINTHUB_INGEST_URL"):  # e.g. in Docker, where this process only sees container addresses
        urls = [os.environ["OSINTHUB_INGEST_URL"].rstrip("/")]
    return {"running": L.running(), "error": L.error, "started_at": L.started_at, "urls": urls,
            "pending": pending_count(), "failed": _count_failed()}


def _count_failed() -> int:
    d = PUSH_DIR / "failed"
    return sum(1 for _ in d.rglob("*") if _.is_file()) if d.exists() else 0


# ------------------------------------------------------------------ management API (main app, local UI)
mgmt = APIRouter(prefix="/ingest")  # mounted under /api/netlog by ext.py


def _overview() -> dict:
    c = cfg()
    tls = None
    if c["tls"]:
        try:
            tls = ensure_cert()
            tls.pop("mtime", None)
        except Exception as e:
            tls = {"error": f"{type(e).__name__}: {e}"}
    return {"config": c, "env_overrides": env_overrides(), "status": status(), "tls": tls, "senders": senders(),
            "uploads": recent_uploads(), "push_dir": str(PUSH_DIR), "bind": bind_info(c), "inbox": inbox_location()}


@mgmt.get("")
def get_ingest():
    return _overview()


@mgmt.put("")
def put_ingest(body: dict = Body(...)):
    c = cfg()
    if "enabled" in body:
        c["enabled"] = bool(body["enabled"])
    if "tls" in body:
        c["tls"] = bool(body["tls"])
    if "host" in body:
        h = str(body["host"] or "").strip() or "auto"
        if h.lower() == "auto":
            h = "auto"
        else:
            try:
                h = str(ipaddress.ip_address(h))
            except ValueError:
                raise HTTPException(400, "host must be auto (home network only) or an IP address on this machine "
                                         "(0.0.0.0 for every network)")
        c["host"] = h
    if "port" in body:
        try:
            p = int(body["port"])
        except (TypeError, ValueError):
            raise HTTPException(400, "port must be a number")
        if not 1024 <= p <= 65535 or p == config.PORT:
            raise HTTPException(400, f"port must be 1024–65535 and not the UI port {config.PORT}")
        c["port"] = p
    if "max_mb" in body:
        try:
            c["max_mb"] = max(1, min(50_000, int(body["max_mb"])))
        except (TypeError, ValueError):
            raise HTTPException(400, "max_mb must be a number")
    save_cfg(c)
    LISTENER.reconcile()
    return _overview()


@mgmt.post("/senders")
def post_sender(body: dict = Body(...)):
    try:
        s, token = create_sender(body.get("name"), body.get("kind") or "custom", body.get("allow_cidrs"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"sender": s, "token": token}


@mgmt.patch("/senders/{sid}")
def patch_sender(sid: str, body: dict = Body(...)):
    try:
        return update_sender(sid, body)
    except KeyError:
        raise HTTPException(404, "no such sender")
    except ValueError as e:
        raise HTTPException(400, str(e))


@mgmt.post("/senders/{sid}/rotate")
def post_rotate(sid: str):
    try:
        s, token = rotate_sender(sid)
    except KeyError:
        raise HTTPException(404, "no such sender")
    return {"sender": s, "token": token}


@mgmt.delete("/senders/{sid}")
def del_sender(sid: str):
    try:
        delete_sender(sid)
    except KeyError:
        raise HTTPException(404, "no such sender")
    return {"ok": True}


@mgmt.get("/cert")
def get_cert():
    info = ensure_cert()
    return Response(Path(info["path"]).read_bytes(), media_type="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="hlta-ingest.crt"'})


@mgmt.post("/cert/regenerate")
def regen_cert():
    if cert_paths()[2] != "self-signed":
        raise HTTPException(400, "the certificate comes from OSINTHUB_INGEST_CERT; replace that file instead")
    ensure_cert(regenerate=True)
    LISTENER.reconcile()
    return _overview()


@mgmt.post("/retry-failed")
def retry_failed():
    d = PUSH_DIR / "failed"
    n = 0
    if d.exists():
        for f in d.rglob("*"):
            if f.is_file():
                dest = PUSH_DIR / f.parent.name / f.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                f.replace(dest)
                n += 1
    WAKE.set()
    return {"requeued": n}


@mgmt.get("/hlta-push.sh")
def get_script():
    return PlainTextResponse(SCRIPT.read_text(), media_type="text/x-shellscript",
                             headers={"Content-Disposition": 'attachment; filename="hlta-push.sh"'})


# ------------------------------------------------------------------ background tasks (registered in ext.py)
async def supervise_listener() -> None:
    try:
        while True:
            await asyncio.to_thread(LISTENER.reconcile)
            await asyncio.sleep(5)
    finally:
        await asyncio.to_thread(LISTENER.stop)


async def watch_senders() -> None:
    """Silence alerts: check every minute, and right after a check-in (to resolve promptly)."""
    while True:
        WATCH.clear()
        try:
            await asyncio.to_thread(evaluate)
        except Exception as e:
            log.warning("ingest: silence check failed: %s", e)
        await asyncio.to_thread(WATCH.wait, 60)


async def import_pushes() -> None:
    while True:
        WAKE.clear()
        n = await asyncio.to_thread(process_pending)
        if n:
            log.info("ingest: imported %d pushed upload(s)", n)
        await asyncio.to_thread(WAKE.wait, 10)

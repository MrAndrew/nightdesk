"""Runtime configuration. Everything can be overridden with OSINTHUB_* env vars."""
from __future__ import annotations

import os
from pathlib import Path

from . import httpguard

PKG = Path(__file__).resolve().parent
ROOT = PKG.parent   # the repo checkout when run from source
# An installed copy (the `nightdesk` wheel) carries the web client and the docs inside the package; a checkout has
# them at the repo root.
RES = PKG if (PKG / "web").is_dir() else ROOT
WEB_DIR = RES / "web"
DOCS_DIR = RES / "okf"


from .lakeloc import default_lake  # noqa: E402, F401  (kept here: config.default_lake)
from . import lakeloc  # noqa: E402

# The data lake: OSINTHUB_LAKE, else the folder chosen in Settings › Data, else the platform's app-data folder
# (osinthub/lakeloc.py). Docker sets /data. LAKE_SOURCE says which: "env", "chosen" or "default".
LAKE, LAKE_SOURCE = lakeloc.resolve()
RAW_DIR = LAKE / "raw"
REF_DIR = LAKE / "ref"
UPLOAD_DIR = LAKE / "uploads"
TMP_DIR = LAKE / "tmp"
DB_PATH = Path(os.environ.get("OSINTHUB_DB", str(LAKE / "db" / "hub.duckdb")))

GEOIP_DB = REF_DIR / "dbip-city-lite.mmdb"
ASN_DB = REF_DIR / "dbip-asn-lite.mmdb"
CABLES_GEOJSON = REF_DIR / "cable-geo.json"
LANDINGS_GEOJSON = REF_DIR / "landing-point-geo.json"
COUNTRIES_GEOJSON = REF_DIR / "countries-110m.geojson"

HOST = os.environ.get("OSINTHUB_HOST", "127.0.0.1")
PORT = int(os.environ.get("OSINTHUB_PORT", "8787"))


# host_name and the other request guards live in httpguard, which the AI helper shares without loading this module.
host_name = httpguard.host_name


# DNS-rebinding defence: the server answers only requests whose Host header names this machine
# (loopback) or a host listed here. Set OSINTHUB_ALLOWED_HOSTS (comma- or space-separated, ports
# ignored) to the name(s) a reverse proxy forwards, e.g. "nightdesk.lan" behind Caddy, which passes the
# browser's Host through unchanged. See okf/architecture/deployment.md.
ALLOWED_HOSTS = set(httpguard.LOOPBACK_NAMES) | httpguard.host_list(os.environ.get("OSINTHUB_ALLOWED_HOSTS", ""))
if host_name(HOST) not in ("", "0.0.0.0", "::"):
    ALLOWED_HOSTS.add(host_name(HOST))         # bound to one specific address: reachable by that name


def _flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


# Sign-in (okf/architecture/deployment.md#who-can-reach-it). Loopback binds need no password. Any other bind
# (0.0.0.0, ::, a LAN address, a host name) refuses to start without OSINTHUB_PASSWORD (bind_problem, checked by
# __main__). When set, every request needs HTTP Basic with this password (any user name), except GET /api/health from
# this machine. Never logged and never in a response.
PASSWORD = os.environ.get("OSINTHUB_PASSWORD") or None
if PASSWORD is not None and not PASSWORD.strip():
    PASSWORD = None                                          # whitespace only: not a password, so unset
MIN_PASSWORD = 8
# Only when a reverse proxy in front already asks for a password (the Docker Compose setup, Caddy's basic_auth): the
# app then skips both the refusal and its own Basic check, so there is one sign-in, not two.
TRUST_PROXY_AUTH = _flag("OSINTHUB_TRUST_PROXY_AUTH")
AUTH_REQUIRED = bool(PASSWORD) and not TRUST_PROXY_AUTH


def bind_problem(host: str | None = None, password: str | None = None, trust_proxy: bool | None = None) -> str | None:
    """The one-line reason the app must not start on this bind address, or None (defaults: the configured values)."""
    host = HOST if host is None else host
    password = PASSWORD if password is None else password
    trust_proxy = TRUST_PROXY_AUTH if trust_proxy is None else trust_proxy
    if password and not password.strip():
        password = ""
    if password and len(password) < MIN_PASSWORD:
        return (f"OSINTHUB_PASSWORD is shorter than {MIN_PASSWORD} characters: use a longer one (a few words make a "
                "good passphrase). Nothing was started.")
    return httpguard.bind_problem(host, secret=bool(password) or trust_proxy, secret_var="OSINTHUB_PASSWORD",
                                  host_var="OSINTHUB_HOST")


# Offline mode: no outbound fetches at all (sources, reference downloads, article fetching).
# The app starts at once and serves the data it already has. Local services (AI helper,
# Qdrant) still work. See okf/architecture/local-ai.md.
OFFLINE = _flag("OSINTHUB_OFFLINE")

# The one general debug switch: turns the SQL console on (below) and serves FastAPI's /docs, /redoc and /openapi.json
# (which load third-party scripts from a CDN, so they are off otherwise); developer-only extras go here too.
DEBUG = _flag("OSINTHUB_DEBUG")
# The SQL console (POST /api/sql, the Explorer page) is a power tool, off unless one of these is set. The app's own
# features never go through it. okf/architecture/api.md#sql-console
SQL_CONSOLE = _flag("OSINTHUB_SQL_CONSOLE") or DEBUG

# Local AI helper (osinthub/ai/server.py), OpenAI-compatible. Docker uses host.docker.internal.
AI_URL = os.environ.get("AI_URL", "http://127.0.0.1:8790").rstrip("/")
# The helper's token (it requires one when it listens beyond loopback); sent as a Bearer header when set.
AI_TOKEN = (os.environ.get("AI_TOKEN") or "").strip() or None
EMBED_DIM = 1024  # Qwen3-Embedding-0.6B

# Vector index: auto (Qdrant if reachable, else DuckDB), qdrant or duckdb.
VECTORS = os.environ.get("OSINTHUB_VECTORS", "auto").strip().lower()
# HLTA's own Qdrant (container hlta-qdrant). 6333/6334 belong to another Qdrant on the host.
QDRANT_URL = os.environ.get("QDRANT_URL", "http://127.0.0.1:6335").rstrip("/")
QDRANT_API_KEY = os.environ.get("QDRANT_API_KEY") or None
# Prefix for Qdrant collection names, so several lakes can share one Qdrant (e.g. "dev_").
QDRANT_PREFIX = os.environ.get("OSINTHUB_QDRANT_PREFIX", "")
VECTORS_DB = Path(os.environ.get("OSINTHUB_VECTORS_DB", str(DB_PATH.parent / "vectors.duckdb")))

USER_AGENT = "osint-hub/0.1 (local research dashboard)"

# ransomware.live. Set RANSOMWARELIVE_API_KEY to your API PRO key (my.ransomware.live) and the source
# switches to the keyed PRO endpoint automatically; with no key it uses the free v2 API (no auth,
# rate-limited 1 req/min). URL and header can still be overridden if the PRO details ever change.
# The user's own CARTO basemaps key (https://carto.com/basemaps): with it the world map offers CARTO's Dark Matter and
# Positron styles; without it there are no online basemaps, only the local one. CARTO's terms need each user's own key.
CARTO_API_KEY = (os.environ.get("CARTO_API_KEY") or "").strip() or None
RANSOMWARELIVE_API_KEY = os.environ.get("RANSOMWARELIVE_API_KEY") or None
RANSOMWARELIVE_API_KEY_HEADER = os.environ.get("RANSOMWARELIVE_API_KEY_HEADER", "X-API-KEY")
# PRO path/shape differ from the free tier: PRO is /victims/recent (from its swagger.json) and wraps
# the list under a "victims" key; the free tier is /v2/recentvictims and returns a bare list.
RANSOMWARELIVE_API_URL = os.environ.get(
    "RANSOMWARELIVE_API_URL",
    "https://api-pro.ransomware.live/victims/recent" if RANSOMWARELIVE_API_KEY
    else "https://api.ransomware.live/v2/recentvictims",
)

# abuse.ch Auth-Key (free, https://auth.abuse.ch/) for ThreatFox and URLhaus. Sent only in the Auth-Key header;
# never logged, stored or put in a URL. Without it both sources stay off. okf/sources/current/threatfox.md
ABUSECH_AUTH_KEY = (os.environ.get("ABUSECH_AUTH_KEY") or "").strip() or None


def unmounted_volume(p: Path, volumes: Path = Path("/Volumes")) -> Path | None:
    """The volume /Volumes/<name> that `p` lives on, when that volume is not mounted (else None).
    A plain folder left at /Volumes/<name> is on the boot disk, so it counts as not mounted."""
    # Resolve symlinks (a link into /Volumes/<gone>) and compare case-insensitively (/volumes/... is the same
    # folder on macOS's default file system).
    pp, rp = Path(os.path.realpath(p)).parts, Path(os.path.realpath(volumes)).parts
    if len(pp) <= len(rp) or [x.casefold() for x in pp[:len(rp)]] != [x.casefold() for x in rp]:
        return None
    vol = Path(volumes) / pp[len(rp)]
    return None if os.path.ismount(os.path.realpath(vol)) else vol   # realpath: "Macintosh HD" -> /


# A lake on an external drive that isn't mounted must not silently become a new, empty lake on the
# boot disk: refuse to start instead (and never create /Volumes/<name> itself).
for p in (LAKE, DB_PATH, VECTORS_DB):
    if (vol := unmounted_volume(p)) is not None:
        raise SystemExit(f"osinthub: {p} is on {vol}, which is not mounted. Connect the drive (or set OSINTHUB_LAKE "
                         f"to another folder) and start again; nothing was created.")

for d in (RAW_DIR, REF_DIR, UPLOAD_DIR, TMP_DIR, DB_PATH.parent):
    d.mkdir(parents=True, exist_ok=True)

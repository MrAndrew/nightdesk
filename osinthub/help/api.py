"""Help desk API. Reference: okf/architecture/help.md#api

* GET /api/help/sources      every feed with what it gives, its terms in plain words, licence, on/off and health,
                              plus the reference datasets Night Desk ships or downloads once (with their licences).
* GET /api/help/diagnostics  facts for About and "Copy diagnostics": version, commit, runtime, lake size, feeds,
                              network-log counts, AI helper, extensions. Redacted: no IP or MAC addresses, no keys or
                              tokens, the home folder as ~, no device names, sender names or home prefixes.
* GET /api/help/docs         the local docs (okf/) with titles; GET /api/help/docs/{path} one page as Markdown.

Read-only, offline: nothing here fetches or writes.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import platform
import re
import sys
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException

from .. import config, db

router = APIRouter(prefix="/api/help", tags=["help"])

STARTED = time.time()

# Reference data: shipped with the app or downloaded once into <lake>/ref (okf/environment.md,
# okf/data/entities.md#reference-data). Licences in plain words.
REFERENCE = [
    {"name": "DB-IP Lite (city and ASN)", "gives": "Which country and network (ASN) an address belongs to, on this machine.",
     "licence": "CC BY 4.0", "terms": "Free to use with the credit \"IP Geolocation by DB-IP\" linked to db-ip.com (in Credits and on the map).", "terms_url": "https://db-ip.com/db/lite.php"},
    {"name": "MITRE ATT&CK (Enterprise)", "gives": "Attack techniques, groups, malware and tools, and how they relate.",
     "licence": "ATT&CK terms of use", "terms": "Free to use and share with MITRE's copyright notice (in Credits).",
     "terms_url": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"},
    {"name": "MISP galaxy clusters", "gives": "Other names (aliases) for threat groups, malware and tools.",
     "licence": "CC0 / BSD-2", "terms": "Free to use. The Malpedia cluster comes from Malpedia, CC BY-NC-SA 3.0: non-commercial, with credit.", "terms_url": "https://github.com/MISP/misp-galaxy"},
    {"name": "Public Suffix List and IANA TLD list", "gives": "Telling real domain names apart from other text.",
     "licence": "MPL 2.0 / public", "terms": "Free to use.", "terms_url": "https://publicsuffix.org/"},
    {"name": "Natural Earth countries", "gives": "The country shapes on the offline map.",
     "licence": "Public domain", "terms": "No restrictions.", "terms_url": "https://www.naturalearthdata.com/about/terms-of-use/"},
    {"name": "TeleGeography Submarine Cable Map", "gives": "Undersea cables and landing points on the map, downloaded only when you turn the layer on.",
     "licence": "CC BY-NC-SA 3.0", "terms": "Personal and non-commercial use, with credit to TeleGeography.",
     "terms_url": "https://www.submarinecablemap.com/"},
]


# ------------------------------------------------------------------ redaction
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_V4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])")
_V6 = re.compile(r"(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4})(?:/\d{1,3})?(?![0-9A-Za-z:.])")
_KV = re.compile(r"(?i)\b([a-z0-9_]*?(?:key|token|secret|password|passwd)s?)\s*([=:])\s*\S+")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}")
_LONG = re.compile(r"(?<![A-Za-z0-9_\-+])(?=[A-Za-z0-9_\-+]*\d)(?=[A-Za-z0-9_\-+]*[A-Za-z])[A-Za-z0-9_\-+]{32,}={0,2}")


def _ip_ok(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False) if "/" in s else ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def redact(text: str) -> str:
    """Remove what must never leave the machine in a pasted diagnostic: secrets (the configured keys, key=value
    pairs, long token-like strings), MAC and IP addresses (v4 and v6, with or without a prefix length) and the home
    folder. Times such as 22:03:05 and versions such as 1.2.3 are left alone (they are not valid addresses)."""
    if not isinstance(text, str) or not text:
        return text
    s = text
    home = str(Path.home())
    if home and home != "/" and home in s:
        s = s.replace(home, "~")
    for k in (config.ABUSECH_AUTH_KEY, getattr(config, "RANSOMWARELIVE_API_KEY", None), getattr(config, "QDRANT_API_KEY", None)):
        if k:
            s = s.replace(k, "[key]")
    s = _BEARER.sub(lambda m: f"{m.group(1)} [redacted]", s)
    s = _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", s)
    s = _MAC.sub("[mac]", s)
    s = _V6.sub(lambda m: "[ip]" if _ip_ok(m.group(0)) else m.group(0), s)
    s = _V4.sub(lambda m: "[ip]" if _ip_ok(m.group(0)) else m.group(0), s)
    s = _LONG.sub("[redacted]", s)
    return s


def _clean(v):
    if isinstance(v, str):
        return redact(v)
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_clean(x) for x in v]
    if isinstance(v, (dt.datetime, dt.date)):
        return v.isoformat()
    return v


# ------------------------------------------------------------------ sources and terms
# abuse.ch Terms of Use (okf/sources/current/threatfox.md#access-and-terms), spelled out for the Sources page.
ABUSECH_IDS = {"threatfox", "urlhaus", "sslbl", "feodo_c2"}
ABUSECH_MORE = ("abuse.ch free tier: not-for-profit use only; no redistribution or derived products; no high-volume "
                "harvesting (at most one fetch every 5 minutes; Night Desk fetches hourly or less); the data may not be "
                "used to train or improve AI models, so Night Desk never gives it to the AI helper.")

TIER_WORDS = {"A": "primary authority", "B": "established research group", "C": "community list: corroborate first",
              "D": "unverified: a signal, not proof"}
_CAT_ROW = re.compile(r"^\|\s*\[[^\]]*\]\(/sources/current/([a-z0-9_]+)\.md\)\s*\|[^|]*\|[^|]*\|\s*([A-D])\s*\|", re.M)


def catalog_tiers() -> dict[str, str]:
    """Trust tier per source id, read from the okf source catalog (okf/sources/catalog.md); {} without it."""
    try:
        return dict(_CAT_ROW.findall((config.DOCS_DIR / "sources" / "catalog.md").read_text()))
    except OSError:
        return {}


@router.get("/sources")
def sources():
    """Every source in the registry with its plain-language terms. Unlike GET /api/settings/sources-choice this
    never decides or saves the first-run state, so opening Help changes nothing."""
    from .. import feed_terms, scheduler
    from ..sources import SOURCES
    try:
        states = {r["id"]: r for r in db.query("SELECT id, status, last_ok, items_total FROM source_state")}
    except Exception:
        states = {}
    tiers = catalog_tiers()
    out = []
    for s in SOURCES.values():
        st = states.get(s.id) or {}
        tier = tiers.get(s.id)
        out.append({"id": s.id, "name": s.name, "provider": s.provider, "homepage": s.homepage,
                    "category": s.category, "mode": s.mode, "enabled": bool(scheduler.is_enabled(s)),
                    "unavailable": s.unavailable() or None, "needs_key": bool(s.needs_key),
                    "status": st.get("status"), "last_ok": st.get("last_ok"), "items_total": st.get("items_total"),
                    "tier": tier, "tier_words": TIER_WORDS.get(tier or ""),
                    **feed_terms.row(s.id), "terms_more": ABUSECH_MORE if s.id in ABUSECH_IDS else None})
    cat = {"vuln": 0, "threat": 1, "infra": 2, "news": 3, "social": 4}
    out.sort(key=lambda d: (cat.get(d["category"], 9), d["id"].startswith("news_"), d["name"].lower()))
    return _clean({"sources": out, "reference": REFERENCE, "offline": bool(config.OFFLINE)})


# ------------------------------------------------------------------ diagnostics
def _size(p: Path) -> tuple[int, int]:
    n = b = 0
    if p.exists():
        for f in p.rglob("*"):
            try:
                if f.is_file():
                    n += 1
                    b += f.stat().st_size
            except OSError:
                pass
    return n, b


_SIZE_CACHE: dict = {}


def _lake() -> dict:
    if _SIZE_CACHE.get("t", 0) > time.time() - 120:
        return _SIZE_CACHE["v"]
    parts = {}
    for name in ("db", "raw", "ref", "uploads", "inbox"):
        n, b = _size(config.LAKE / name)
        parts[name] = {"files": n, "bytes": b}
    db_bytes = sum(f.stat().st_size for f in config.DB_PATH.parent.glob(config.DB_PATH.name + "*") if f.is_file()) \
        if config.DB_PATH.parent.exists() else 0
    v = {"path": str(config.LAKE), "db_bytes": db_bytes, "bytes": sum(p["bytes"] for p in parts.values()),
         "files": sum(p["files"] for p in parts.values()), "parts": parts}
    _SIZE_CACHE.update(t=time.time(), v=v)
    return v


def _one(sql: str, default=None):
    try:
        r = db.query(sql)
        return r[0] if r else default
    except Exception:
        return default


def build_diagnostics() -> dict:
    from .. import ext
    try:
        from ..api import _git_commit, _version
        version, commit = _version(), _git_commit()
    except Exception:
        version, commit = "unknown", None
    try:
        import duckdb
        duck = duckdb.__version__
    except Exception:
        duck = None
    d: dict = {
        "app": {"version": version, "commit": commit, "uptime_s": round(time.time() - STARTED),
                "offline": bool(config.OFFLINE), "in_docker": Path("/.dockerenv").exists()},
        "system": {"python": sys.version.split()[0], "platform": platform.platform(terse=True),
                   "machine": platform.machine(), "duckdb": duck, "vectors": config.VECTORS},
        "lake": _lake(),
    }
    ev = _one("SELECT count(*) AS n, max(ingested_at) AS last FROM events", {}) or {}
    d["data"] = {"events": ev.get("n"), "last_ingested": ev.get("last")}
    try:
        from .. import scheduler
        from ..sources import SOURCES
        st = {r["id"]: r for r in db.query("SELECT id, status FROM source_state")}
        on = [s for s in SOURCES.values() if scheduler.is_enabled(s) and not s.unavailable()]
        d["feeds"] = {"known": len(SOURCES), "on": len(on),
                      "needs_key": sorted(s.id for s in SOURCES.values() if s.unavailable()),
                      "with_errors": sorted(s.id for s in on if (st.get(s.id) or {}).get("status") in ("error", "reconnecting"))}
    except Exception as e:
        d["feeds"] = {"error": type(e).__name__}
    nl = {}
    if "netlog" in ext.EXTENSIONS:
        f = _one("""SELECT count(*) FILTER (WHERE coalesce(origin, '') <> 'demo') AS files,
                           count(*) FILTER (WHERE origin = 'demo') AS demo_files,
                           max(ts_max) FILTER (WHERE coalesce(origin, '') <> 'demo') AS newest FROM netlog_files""", {}) or {}
        nl = {"files": f.get("files"), "demo_loaded": bool(f.get("demo_files")), "newest_record": f.get("newest"),
              "rows": (_one("SELECT count(*) AS n FROM netlog", {}) or {}).get("n"),
              "devices": (_one("SELECT count(*) AS n FROM devices", {}) or {}).get("n")}
        try:
            from ..netlog import util as nutil
            s = nutil.settings()
            nl["home_prefixes_set"] = len(s.get("home_prefixes") or [])   # a count only, never the prefixes
            nl["stale_hours"] = s.get("stale_hours")
        except Exception:
            pass
        try:
            from ..netlog import ingest
            nl["upload_devices"] = len(ingest.senders())                    # a count only, never their names
        except Exception:
            pass
        try:
            from ..netlog.api import alerts_count
            c = alerts_count()
            nl["needs_you"] = c.get("needs_you") if isinstance(c, dict) else None
        except Exception:
            pass
    d["network_logs"] = nl or {"installed": False}
    try:
        from ..ai import client
        a = client.status()
        d["ai_helper"] = {"configured": bool(a.get("configured")), "up": bool(a.get("ever_up")) and not a.get("down")}
    except Exception:
        d["ai_helper"] = {"installed": False}
    ents = _one("SELECT count(*) AS n FROM entities", None)
    if ents is not None:
        d["intel"] = {"entities": ents.get("n"), "claims": (_one("SELECT count(*) AS n FROM claims", {}) or {}).get("n")}
    d["extensions"] = {"loaded": sorted(ext.EXTENSIONS), "failed": sorted(ext.FAILED)}
    d["generated_at"] = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    return _clean(d)


@router.get("/diagnostics")
def diagnostics():
    return build_diagnostics()


# ------------------------------------------------------------------ local docs (okf/)
DOCS = config.DOCS_DIR
# The pages most people want first; every other page is listed after them.
DOC_FIRST = ["start-here.md", "project/overview.md", "project/features.md", "data/netlog.md", "sources/catalog.md",
             "sources/trust-model.md", "environment.md",
             "architecture/deployment.md", "architecture/help.md"]
_FM = re.compile(r"\A---\n(.*?)\n---\n", re.S)


def _front(text: str) -> dict:
    m = _FM.match(text)
    out = {}
    if m:
        for line in m.group(1).splitlines():
            k, _, v = line.partition(":")
            if k.strip() in ("title", "description", "type"):
                out[k.strip()] = v.strip().strip('"')
    return out


def _doc_path(rel: str) -> Path:
    rel = (rel or "").strip().lstrip("/")
    if not rel.endswith(".md") or ".." in Path(rel).parts or "\\" in rel or "\x00" in rel:
        raise HTTPException(404, "no such page")
    p = (DOCS / rel).resolve()
    try:
        p.relative_to(DOCS.resolve())
    except ValueError:
        raise HTTPException(404, "no such page")
    if not p.is_file():
        raise HTTPException(404, "no such page")
    return p


@router.get("/docs")
def docs_list():
    if not DOCS.is_dir():
        return {"available": False, "docs": []}
    out = []
    for p in sorted(DOCS.rglob("*.md")):
        rel = p.relative_to(DOCS).as_posix()
        if rel in ("log.md",) or rel.startswith(("references/", "sources/candidates/")):
            continue
        try:
            fm = _front(p.read_text(errors="replace")[:2000])
        except OSError:
            continue
        out.append({"path": rel, "title": fm.get("title") or rel, "description": fm.get("description", ""),
                    "section": rel.split("/")[0] if "/" in rel else ""})
    first = {p: i for i, p in enumerate(DOC_FIRST)}
    out.sort(key=lambda d: (first.get(d["path"], 99), d["section"], d["title"].lower()))
    return {"available": True, "docs": out}


@router.get("/docs/{rel:path}")
def docs_page(rel: str):
    p = _doc_path(rel)
    text = p.read_text(errors="replace")
    fm = _front(text)
    body = _FM.sub("", text, count=1)
    return {"path": p.relative_to(DOCS.resolve()).as_posix(), "title": fm.get("title") or rel,
            "description": fm.get("description", ""), "markdown": body}

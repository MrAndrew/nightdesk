"""Settings › About › Copy diagnostics: a plain-text summary a tester can paste into a GitHub issue.

It says what helps to understand a problem (version, how it was installed, the machine, which switches are on, how
the sources and the local AI are doing, what failed) and nothing about the user: every address, MAC, local host
name, home-folder path, key and token is removed before the text leaves the app (scrub). Counts only, never rows.
okf/architecture/api.md#diagnostics
"""
from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
import sys
from pathlib import Path

from . import config

# keys the app can be given; their values are removed wherever they appear
SECRET_VARS = ("ABUSECH_AUTH_KEY", "RANSOMWARELIVE_API_KEY", "QDRANT_API_KEY", "CLOUDFLARE_RADAR_TOKEN", "CARTO_API_KEY",
               "OSINTHUB_PASSWORD", "AI_TOKEN", "HLTA_AUTH_HASH")
_LOCAL_SUFFIXES = (".lan", ".local", ".home", ".internal", ".localdomain", ".home.arpa", ".corp", ".intranet",
                   ".localhost", ".private")

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![\w:])")
_MAC = re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])")
_HOST = re.compile(r"(?<![\w.-])([A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9-]{1,63})*)(?![\w-])")
_KV_SECRET = re.compile(r"(?i)\b(key|token|secret|password|passwd|auth|authorization|bearer|apikey|api_key)(\s*[=:]\s*|\s+)"
                        r"(\"[^\"]*\"|'[^']*'|[^\s&,;]+)")
_LONG_TOKEN = re.compile(r"(?<![\w/.-])[A-Za-z0-9_+/=-]{32,}(?![\w/.-])")
_QUERY = re.compile(r"(https?://[^\s?#\"']+)\?[^\s#\"']*")


def _ip_ok(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _local_names() -> set[str]:
    names = set()
    for n in (socket.gethostname(), platform.node()):
        if n:
            names |= {n.lower(), n.split(".")[0].lower()}
    names |= {h.lower() for h in config.ALLOWED_HOSTS if h and h not in ("localhost", "127.0.0.1", "::1")}
    return {n for n in names if len(n) >= 3 and n not in ("localhost", "nightdesk.localhost")}


def scrub(text: str) -> str:
    """Remove addresses, MACs, local host names, home-folder paths, keys and tokens from a piece of text."""
    if not text:
        return text
    for v in [(os.environ.get(var) or "").strip() for var in SECRET_VARS] + _saved_keys():
        if len(v) >= 4:
            text = text.replace(v, "<secret>")
    text = _QUERY.sub(lambda m: m.group(1) + "?…", text)
    text = _KV_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}<secret>", text)
    text = _LONG_TOKEN.sub("<secret>", text)
    for p, mark in _path_marks():
        text = text.replace(p, mark)
    text = _MAC.sub("<mac>", text)
    text = _IPV6.sub(lambda m: "<ip>" if ":" in m.group(0) and _ip_ok(m.group(0)) else m.group(0), text)
    text = _IPV4.sub(lambda m: "<ip>" if _ip_ok(m.group(0)) else m.group(0), text)
    local = _local_names()

    def host(m: re.Match) -> str:
        h = m.group(1)
        low = h.lower()
        if low.endswith(_LOCAL_SUFFIXES) or low in local or low.split(".")[0] in local and "." in low:
            return "<host>"
        return h
    return _HOST.sub(host, text)


def _saved_keys() -> list[str]:
    """Keys saved in Settings rather than given as settings (the chat server's API key)."""
    try:
        from .ai import chatconn
        k = chatconn._saved_key().get("key")
        return [str(k).strip()] if k else []
    except Exception:
        return []


def _path_marks() -> list[tuple[str, str]]:
    """Folders a report must not name, longest first: the data folder, the database folder, this checkout, home."""
    out: dict[str, str] = {}
    home = str(Path.home())
    for p, mark in ((config.LAKE, "<data>"), (config.DB_PATH.parent, "<db>"), (config.ROOT, "<app>"), (home, "~")):
        for v in {str(p), os.path.realpath(p)}:
            if len(v) > 1:
                out.setdefault(v.rstrip("/"), mark)
    return sorted(out.items(), key=lambda kv: -len(kv[0]))


def _install() -> str:
    from .netlog.ingest import in_docker
    if in_docker():
        return "Docker"
    if (config.ROOT / ".git").exists() or (config.ROOT / "pyproject.toml").exists():
        return "from the source (uv run)"
    return "the nightdesk package"


def _machine() -> str:
    if sys.platform == "darwin":
        osname = f"macOS {platform.mac_ver()[0] or '?'}"
    elif sys.platform.startswith("linux"):
        osname = "Linux " + platform.release()
    else:
        osname = f"{platform.system()} {platform.release()}"
    return f"{osname} ({platform.machine()}), Python {platform.python_version()}"


def _sources() -> list[str]:
    from . import scheduler
    from .sources import SOURCES
    on, ok, bad, off = [], 0, [], 0
    for s in SOURCES.values():
        if s.withheld:
            continue
        if not scheduler.is_enabled(s):
            off += 1
            continue
        on.append(s.id)
        st = scheduler.state(s.id)
        if st.get("status") == "error":
            bad.append(f"  - {s.id}: {scrub(str(st.get('message') or 'error'))[:200]}")
        else:
            ok += 1
    lines = [f"Sources: {len(on)} on ({ok} without errors, {len(bad)} with errors), {off} off"]
    return lines + bad


def _ai() -> str:
    try:
        from .ai import client, setup
        st = client.status()
        up = bool(st.get("ever_up")) and not st.get("down")
        chosen = setup.chosen_models()
        where = "turned on in Settings" if setup.enabled() else ("expected (AI_HELPER)" if st.get("configured") else "off")
        models = f", models: {', '.join(chosen)}" if chosen else ""
        expected = setup.enabled() or st.get("configured")
        err = f", last error: {scrub(str(st.get('last_error')))[:160]}" if st.get("last_error") and not up and expected else ""
        c = st.get("chat") or {}
        if c.get("via") in ("ollama", "lmstudio", "other"):
            from .ai import chatconn
            place = "this computer or network" if c.get("is_local") else "the internet"
            health = "not answering" if c.get("down") else "answering" if c.get("ever_up") else "not used yet"
            chat = f"chat: {c['via']} on {place} ({chatconn.host_of(c.get('url') or '')}), model {c.get('model')}, {health}"
        else:
            chat = f"chat: {c.get('via') or 'off'}"
        return f"Local AI: {where}{models}, helper {'answering' if up else 'not answering'}{err}; {chat}"
    except Exception as e:
        return f"Local AI: could not check ({type(e).__name__})"


def _counts() -> str:
    from . import db

    def n(sql: str) -> str:
        try:
            return f"{db.query(sql)[0]['n']:,}"
        except Exception:
            return "?"
    return (f"Data: {n('SELECT count(*) AS n FROM events')} events, "
            f"{n('SELECT count(*) AS n FROM articles')} articles, "
            f"{n('SELECT count(*) AS n FROM devices')} network devices")


def _extensions() -> list[str]:
    from . import ext
    st = ext.status()
    loaded = [e["name"] for e in st["extensions"]]
    out = [f"Extensions: {', '.join(loaded) or 'none'}"]
    for mod, err in (st.get("failed_imports") or {}).items():
        out.append(f"  - {mod} did not load: {scrub(str(err))[:200]}")
    for e in st["extensions"]:
        for err in (e.get("errors") or [])[-3:]:
            out.append(f"  - {e['name']}: {scrub(str(err))[:200]}")
    return out


def report(version: str, commit: str | None) -> str:
    """The whole summary, already scrubbed."""
    reach = "this computer only" if config.HOST in ("127.0.0.1", "localhost", "::1") else "other devices (password)"
    lines = [
        "Night Desk diagnostics (addresses, host names, folders and keys are removed)",
        f"Version: {version}" + (f" (commit {commit})" if commit else ""),
        f"Installed: {_install()}",
        f"Machine: {_machine()}",
        f"Switches: offline mode {'on' if config.OFFLINE else 'off'}, SQL console {'on' if config.SQL_CONSOLE else 'off'}, "
        f"reached from {reach}",
        _counts(),
        *_sources(),
        _ai(),
        *_extensions(),
    ]
    return scrub("\n".join(lines)) + "\n"

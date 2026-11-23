"""IP geolocation (DB-IP Lite, CC-BY 4.0) and country centroids (Natural Earth)."""
from __future__ import annotations

import ipaddress
import json
from functools import lru_cache

import maxminddb

from . import config

_reader = None
_asn_reader = None


def _asn_db():
    global _asn_reader
    if _asn_reader is None and config.ASN_DB.exists():
        _asn_reader = maxminddb.open_database(str(config.ASN_DB))
    return _asn_reader


@lru_cache(maxsize=200_000)
def asn_for_ip(ip: str) -> tuple[str, str] | None:
    """Return ("AS15169", "Google LLC") for an IP, or None."""
    db = _asn_db()
    if db is None:
        return None
    try:
        rec = db.get(ip)
    except ValueError:
        return None
    if not rec or not rec.get("autonomous_system_number"):
        return None
    return f"AS{rec['autonomous_system_number']}", rec.get("autonomous_system_organization") or ""


def _db():
    global _reader
    if _reader is None and config.GEOIP_DB.exists():
        _reader = maxminddb.open_database(str(config.GEOIP_DB))
    return _reader


@lru_cache(maxsize=200_000)
def locate_ip(ip: str) -> dict | None:
    """Return {lat, lon, country, city} for an IP, or None."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    db = _db()
    if db is None:
        return None
    rec = db.get(ip)
    if not rec or "location" not in rec:
        return None
    loc = rec["location"]
    return {
        "lat": loc.get("latitude"),
        "lon": loc.get("longitude"),
        "country": (rec.get("country") or {}).get("iso_code"),
        "city": ((rec.get("city") or {}).get("names") or {}).get("en"),
    }


@lru_cache(maxsize=1)
def countries() -> dict[str, dict]:
    """ISO2 -> {name, lat, lon}."""
    out: dict[str, dict] = {}
    if not config.COUNTRIES_GEOJSON.exists():
        return out
    data = json.loads(config.COUNTRIES_GEOJSON.read_text())
    for f in data["features"]:
        p = f["properties"]
        iso = p.get("ISO_A2_EH") or p.get("ISO_A2")
        if not iso or iso == "-99":
            continue
        out[iso] = {"name": p.get("NAME"), "lat": p.get("LABEL_Y"), "lon": p.get("LABEL_X")}
    return out


@lru_cache(maxsize=1)
def country_name_index() -> list[tuple[str, str]]:
    """(lowercase name, ISO2) sorted longest first, for tagging free text."""
    idx = [(v["name"].lower(), k) for k, v in countries().items() if v.get("name")]
    extra = {"united states": "US", "u.s.": "US", "usa": "US", "uk": "GB", "britain": "GB",
             "russian": "RU", "chinese": "CN", "iranian": "IR", "north korea": "KP",
             "north korean": "KP", "south korea": "KR", "israeli": "IL", "ukrainian": "UA"}
    idx += list(extra.items())
    return sorted(idx, key=lambda t: -len(t[0]))


def tag_countries(text: str) -> list[str]:
    t = f" {text.lower()} "
    found: list[str] = []
    for name, iso in country_name_index():
        if f" {name} " in t or f" {name}," in t or f" {name}'" in t or f" {name}." in t:
            if iso not in found:
                found.append(iso)
    return found

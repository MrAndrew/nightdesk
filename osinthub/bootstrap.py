"""Fetch reference datasets on first start so a fresh install works with no manual steps."""
from __future__ import annotations

import asyncio
import datetime as dt
import gzip
import json
import logging
import shutil
from pathlib import Path

import httpx

from . import config

log = logging.getLogger("osinthub.bootstrap")


def _months_back(n: int) -> list[str]:
    d = dt.date.today().replace(day=1)
    out = []
    for _ in range(n):
        out.append(d.strftime("%Y-%m"))
        d = (d - dt.timedelta(days=1)).replace(day=1)
    return out


def _dbip(kind: str) -> list[str]:
    # DB-IP publishes a new Lite file each month; fall back to earlier months if this one isn't out yet.
    return [f"https://download.db-ip.com/free/dbip-{kind}-lite-{m}.mmdb.gz" for m in _months_back(3)]


REFERENCE = [
    (config.GEOIP_DB, _dbip("city"), True),
    (config.ASN_DB, _dbip("asn"), True),
    (config.COUNTRIES_GEOJSON, ["https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson"], False),
]


# TeleGeography's cable data is opt-in (pre-alpha terms review): their map is CC BY-SA but they say the underlying data
# is for subscribers, so it is never fetched at start. The world map downloads it once when the user first turns the
# cable layer on (POST /api/geo/cables/fetch), and credits TeleGeography wherever cables are drawn.
CABLES = {
    config.CABLES_GEOJSON: "https://www.submarinecablemap.com/api/v3/cable/cable-geo.json",
    config.LANDINGS_GEOJSON: "https://www.submarinecablemap.com/api/v3/landing-point/landing-point-geo.json",
}
CABLES_CAP = 64_000_000   # decoded bytes per file (the cable file was a few MB in 2026)
_cables_lock = asyncio.Lock()


class CablesUnavailable(Exception):
    """The cable data could not be downloaded; the message says why in plain words."""


def cables_present() -> bool:
    return all(p.exists() and p.stat().st_size > 0 for p in CABLES)


async def fetch_cables() -> bool:
    """Download the cable and landing-point files that are missing (the user turned the layer on). True when something
    was downloaded. Raises CablesUnavailable in offline mode or when TeleGeography cannot be reached."""
    if config.OFFLINE:
        raise CablesUnavailable("Offline mode is on, so the cable data is not downloaded.")
    from .sources import caps
    async with _cables_lock:
        missing = [(p, u) for p, u in CABLES.items() if not p.exists() or p.stat().st_size == 0]
        if not missing:
            return False
        async with httpx.AsyncClient(headers={"User-Agent": config.USER_AGENT}, timeout=120) as client:
            for path, url in missing:
                try:
                    r = await caps.get(client, url, "telegeography", cap=CABLES_CAP)
                    r.raise_for_status()
                    if not isinstance(json.loads(r.content), dict):
                        raise ValueError("not a GeoJSON object")
                except Exception as e:
                    log.warning("could not fetch %s: %s", url, e)
                    raise CablesUnavailable("TeleGeography's cable map could not be reached. Try again later.") from e
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_name(path.name + ".part")
                tmp.write_bytes(r.content)
                tmp.replace(path)
                log.info("saved %s (%.1f MB)", path, path.stat().st_size / 1e6)
        return True


async def ensure_reference_data() -> None:
    missing = [(p, urls, gz) for p, urls, gz in REFERENCE if not p.exists() or p.stat().st_size == 0]
    if not missing:
        return
    if config.OFFLINE:
        log.info("offline: not downloading %d missing reference file(s)", len(missing))
        return
    async with httpx.AsyncClient(headers={"User-Agent": config.USER_AGENT}, timeout=300, follow_redirects=True) as client:
        for path, urls, gz in missing:
            for url in urls:
                try:
                    log.info("downloading reference data %s", url)
                    tmp = path.with_suffix(path.suffix + ".part")
                    async with client.stream("GET", url) as r:
                        r.raise_for_status()
                        with tmp.open("wb") as fh:
                            async for chunk in r.aiter_bytes(1 << 20):
                                fh.write(chunk)
                    if gz:
                        # Decompress into a sibling .tmp and rename only on success, so a truncated download never
                        # leaves a partial .mmdb in place (which would read as present and never be fetched again).
                        out_tmp = path.with_name(path.name + ".tmp")
                        with gzip.open(tmp, "rb") as src, out_tmp.open("wb") as dst:
                            shutil.copyfileobj(src, dst)
                        out_tmp.replace(path)
                        tmp.unlink()
                    else:
                        tmp.replace(path)
                    log.info("saved %s (%.1f MB)", path, path.stat().st_size / 1e6)
                    break
                except Exception as e:  # try the next mirror / month
                    log.warning("could not fetch %s: %s", url, e)
                    Path(str(path) + ".part").unlink(missing_ok=True)
                    path.with_name(path.name + ".tmp").unlink(missing_ok=True)
            else:
                log.warning("reference file %s unavailable; related features degrade gracefully", path.name)

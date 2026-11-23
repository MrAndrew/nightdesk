"""Vulnerability intelligence: FIRST EPSS scores and CISA's CSAF advisories.

* `epss` (this module): the daily EPSS file, every scored CVE. The latest score of every CVE lives in the
  `epss` table; the lake keeps a record per CVE only when its probability changes; events exist only for
  the CVEs the app already shows. Docs: okf/sources/current/epss.md
* `cisa_advisories` (class in feeds.py): CISA's CSAF 2.0 advisories from github.com/cisagov/CSAF. The CSAF
  parsing, fetching and the `advisory_cves` table live here. Docs: okf/sources/current/cisa_advisories.md
"""
from __future__ import annotations

import asyncio
import csv
import datetime as dt
import gzip
import io
import json
import logging
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from .. import config, db
from . import caps
from .base import Event, Source, Unchanged, now, to_ts
from .registry import register

log = logging.getLogger("osinthub.sources.vulns")

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


class Offline(RuntimeError):
    """Raised by the fetch helpers in offline mode (the scheduler skips before calling them)."""


async def _get(client: httpx.AsyncClient, url: str, sid: str, **kw) -> httpx.Response:
    """GET url, read with the source's byte cap (caps.py: decoded bytes, TooLarge over it)."""
    if config.OFFLINE:
        raise Offline(f"offline mode: not fetching {url}")
    r = await caps.get(client, url, sid, **kw)
    if not r.is_redirect:
        r.raise_for_status()
    return r


# =========================================================================== EPSS
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_DATED = re.compile(r"epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz")
EPSS_HEADER = re.compile(r"^#\s*model_version:\s*(?P<model>[^,\s]+)\s*,\s*score_date:\s*(?P<date>\S+)")
EPSS_MIN_ROWS = 100_000   # first load only: the file holds every scored CVE (402,199 on 2026-11-09)
EPSS_MIN_SHARE = 0.9      # later loads: at least 90% of the CVEs already loaded, else a partial download


def epss_pct(p: float | None) -> str:
    """A probability as a short percentage: 0.97 -> 97.0%, 0.04753 -> 4.75%, 0.00046 -> 0.05%."""
    if p is None:
        return "—"
    x = p * 100
    return f"{x:.1f}%" if x >= 10 else f"{x:.2f}%"


_EPSS_MEMO: dict[str, Any] = {"key": None, "val": None}


def parse_epss(raw: bytes) -> tuple[dict, list[tuple[str, float, float]]]:
    """(meta, rows) from the EPSS CSV (gzipped or plain). meta = {model_version, score_date, rows, rejected};
    rows = [(cve, epss, percentile)], one per CVE, junk rejected (bad id, value outside 0..1). Raises on a
    file without the model header or with implausibly few rows, so a broken download fails the run instead
    of deleting most CVEs from the list."""
    key = (id(raw), len(raw), raw[:64], raw[-64:])
    if _EPSS_MEMO["key"] == key:     # prepare(), parse() and records() see the same payload: parse it once
        return _EPSS_MEMO["val"]
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", "replace")
    lines = text.splitlines()
    m = EPSS_HEADER.match(lines[0]) if lines else None
    if not m:
        raise ValueError("EPSS file has no '#model_version:...,score_date:...' header line")
    meta = {"model_version": m.group("model"), "score_date": to_ts(m.group("date")).isoformat()}
    reader = csv.reader(lines[1:])
    head = next(reader, None)
    if not head or [h.strip().lower() for h in head[:3]] != ["cve", "epss", "percentile"]:
        raise ValueError(f"EPSS file has unexpected columns: {head}")
    rows: list[tuple[str, float, float]] = []
    seen: set[str] = set()
    rejected = 0
    for r in reader:
        if len(r) < 3:
            rejected += 1
            continue
        cve = r[0].strip().upper()
        try:
            e, p = float(r[1]), float(r[2])
        except ValueError:
            rejected += 1
            continue
        if not CVE_ID.match(cve) or not (0.0 <= e <= 1.0) or not (0.0 <= p <= 1.0) or cve in seen:
            rejected += 1
            continue
        seen.add(cve)
        rows.append((cve, e, p))
    if not rows:
        raise ValueError("EPSS file has no valid rows")
    meta["rows"], meta["rejected"] = len(rows), rejected
    _EPSS_MEMO.update(key=key, val=(meta, rows))
    return meta, rows


def epss_latest_date() -> dt.date | None:
    """Score date of the EPSS file loaded last (None before the first load)."""
    try:
        r = db.query("SELECT max(score_date) AS d FROM epss")
    except Exception:
        return None
    d = r[0]["d"] if r else None
    return d.date() if isinstance(d, dt.datetime) else d


def epss_lookup(cves: list[str]) -> dict[str, dict]:
    """Latest EPSS per CVE id (upper case): {epss, percentile, score_date, since, prev_epss, model_version}."""
    ids = sorted({c.upper() for c in cves if c})
    if not ids:
        return {}
    out: dict[str, dict] = {}
    for i in range(0, len(ids), 5000):
        chunk = ids[i:i + 5000]
        for r in db.query(f"""SELECT cve, epss, percentile, score_date, since, prev_epss, model_version FROM epss
                              WHERE cve IN ({','.join('?' * len(chunk))})""", chunk):
            out[r.pop("cve")] = r
    return out


@register
class Epss(Source):
    id = "epss"
    name = "FIRST EPSS exploit prediction scores"
    provider = "FIRST EPSS SIG · Empirical Security"
    homepage = "https://www.first.org/epss"
    description = ("Daily probability (0-1) that each CVE will see exploitation activity in the next 30 days, with its "
                   "percentile, for every scored CVE. Shown next to CVSS and KEV wherever CVEs appear.")
    category = "vuln"
    # The file is published once a day (about 12:00-13:30 UTC). Each run asks for the current file's name (one
    # small redirect) and downloads it only when that day is not loaded yet: one 2.8 MB download a day, at most
    # 3 hours after publication. FIRST: "pulling this file once per day is more efficient than querying the API".
    interval = 3 * 3600
    license = "Free to use with attribution: EPSS by FIRST (https://www.first.org/epss), scores by Empirical Security"
    raw_ext = "csv"
    windowed = False   # the file is the whole scored population: a CVE that leaves it was removed (rejected CVEs)

    _expected_date: str | None = None   # the day the redirect named; the file's header must agree

    async def fetch(self, client):
        self._expected_date = None
        r = await _get(client, EPSS_URL, self.id, timeout=60, follow_redirects=False)
        if r.is_redirect:
            loc = r.headers.get("location") or ""
            m = EPSS_DATED.search(loc)
            # The table is replaced only after a run fully succeeds (commit()), so "already loaded" here means the
            # lake delta, the record hashes and the table all hold that day; a failed run is retried for real.
            have = epss_latest_date()
            if m and have and dt.date.fromisoformat(m.group(1)) <= have:
                raise Unchanged(f"EPSS scores for {m.group(1)} already loaded")
            self._expected_date = m.group(1) if m else None
            r = await _get(client, urljoin(EPSS_URL, loc), self.id, timeout=180, follow_redirects=True)
            r.raise_for_status()
        body = r.content
        return caps.inflate_capped(body, caps.EPSS_INFLATED_CAP, "the EPSS file") if body[:2] == b"\x1f\x8b" else body

    def _checked(self, raw):
        """parse_epss() plus the checks that need state: the header's day matches the file the redirect named, and
        the file holds at least 90% of the CVEs already loaded (a cut-off download would otherwise delete the rest
        from the table and record them as removed in the lake)."""
        meta, rows = parse_epss(raw)
        if self._expected_date and meta["score_date"][:10] != self._expected_date:
            raise ValueError(f"EPSS file header says {meta['score_date'][:10]} but the server named {self._expected_date}")
        stored = stored_epss_rows()
        if not stored and len(rows) < EPSS_MIN_ROWS:
            raise ValueError(f"EPSS file has only {len(rows):,} valid rows (expected over {EPSS_MIN_ROWS:,} on a first load)")
        if stored and len(rows) < EPSS_MIN_SHARE * stored and not os.environ.get("OSINTHUB_EPSS_ALLOW_SHRINK"):
            raise ValueError(f"EPSS file has {len(rows):,} CVEs, under {EPSS_MIN_SHARE:.0%} of the {stored:,} loaded; "
                             "treating it as a partial download (if FIRST really dropped that many, restart once "
                             "with OSINTHUB_EPSS_ALLOW_SHRINK=1)")
        return meta, rows

    def stored_count(self) -> int:
        return stored_epss_rows()

    def records(self, raw):
        # Only the probability is kept per CVE. The percentile is a rank against the whole population and moves
        # for ~97% of CVEs every day as new CVEs are scored; it is recomputable from the replayed probabilities.
        # So a CVE is stored again only when its probability changes (~3,500 a day) or it is new.
        meta, rows = self._checked(raw)
        return [("#meta", {"model_version": meta["model_version"], "score_date": meta["score_date"]})] + \
               [(cve, {"epss": e}) for cve, e, _p in rows]

    def parse(self, raw):
        """No events: an EPSS score is enrichment of a CVE, not something that happened. It is served from the
        `epss` table wherever a CVE is shown, and never counts as activity (timeline, ticker, totals, mentions)."""
        self._checked(raw)
        return []

    def commit(self, raw, collected_at):
        """Replace the `epss` table with this file, last, after the lake delta and the run's bookkeeping succeeded:
        latest score of every CVE, the date its probability last changed (`since`) and the probability before that
        change (`prev_epss`). An older file than the one loaded is ignored. Also removes EPSS events and entity
        mentions left by an earlier version (EPSS no longer makes events)."""
        purge_epss_events()
        meta, rows = self._checked(raw)
        score_ts = dt.datetime.fromisoformat(meta["score_date"])
        have = db.query("SELECT max(score_date) AS d FROM epss")[0]["d"]
        if have is not None and have > score_ts:
            log.warning("EPSS file for %s is older than the loaded %s; table left as it is", score_ts, have)
            return
        tmp = config.TMP_DIR / f"epss-{os.getpid()}.csv"
        with tmp.open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["cve", "epss", "percentile"])
            w.writerows(rows)
        try:
            with db._write_lock:
                cur = db.cursor()
                cur.execute(f"""CREATE OR REPLACE TEMP TABLE _epss_new AS
                    SELECT n.cve, n.epss, n.percentile, ?::TIMESTAMPTZ AS score_date, ? AS model_version,
                           CASE WHEN o.cve IS NOT NULL AND o.epss = n.epss THEN o.since ELSE ?::TIMESTAMPTZ END AS since,
                           CASE WHEN o.cve IS NULL THEN NULL WHEN o.epss = n.epss THEN o.prev_epss ELSE o.epss END AS prev_epss
                    FROM read_csv('{db._q(tmp)}', header=true,
                                  columns={{'cve': 'VARCHAR', 'epss': 'DOUBLE', 'percentile': 'DOUBLE'}}) n
                    LEFT JOIN epss o ON o.cve = n.cve""", [score_ts, meta["model_version"], score_ts])
                try:
                    with db.tx(cur):
                        cur.execute("DELETE FROM epss")
                        cur.execute("INSERT INTO epss SELECT cve, epss, percentile, score_date, model_version, since, prev_epss "
                                    "FROM _epss_new ORDER BY cve")   # sorted: point lookups by cve skip most row groups
                finally:
                    cur.execute("DROP TABLE IF EXISTS _epss_new")
        finally:
            tmp.unlink(missing_ok=True)


def stored_epss_rows() -> int:
    try:
        return int(db.query("SELECT count(*) AS n FROM epss")[0]["n"])
    except Exception:
        return 0


def purge_epss_events() -> int:
    """Remove `epss` events and everything derived from them (round-1 versions made one per app CVE): the events,
    their entity mentions and link marks, and the CVE entities' first/last seen widened by them. Idempotent; a no-op
    once clean. Run at startup and before each EPSS load, so neither the linker nor a rebuild can pick them up."""
    n = db.query("SELECT count(*) AS n FROM events WHERE source = 'epss'")[0]["n"]
    has_m = db.has_table("mentions")
    stale = db.query("SELECT count(*) AS n FROM mentions WHERE ref_type = 'event' AND ref_id LIKE 'epss:%'")[0]["n"] if has_m else 0
    if not n and not stale:
        return 0
    lock = None
    try:
        from ..entities.store import claims_lock
        lock = claims_lock()
    except Exception:
        pass
    if lock:
        lock.acquire()
    try:
        with db._write_lock:
            cur = db.cursor()
            if has_m:
                cur.execute("""CREATE OR REPLACE TEMP TABLE _epss_ents AS SELECT DISTINCT entity_id FROM mentions
                               WHERE ref_type = 'event' AND ref_id LIKE 'epss:%'""")
                cur.execute("DELETE FROM mentions WHERE ref_type = 'event' AND ref_id LIKE 'epss:%'")
                if db.has_table("entity_linked"):
                    cur.execute("DELETE FROM entity_linked WHERE ref_type = 'event' AND ref_id LIKE 'epss:%'")
                if db.has_table("entities"):
                    # first/last seen back to what the remaining mentions say (entities with none keep theirs)
                    cur.execute("""UPDATE entities SET first_seen = m.f, last_seen = m.l
                                   FROM (SELECT entity_id, min(ts) AS f, max(ts) AS l FROM mentions
                                         WHERE entity_id IN (SELECT entity_id FROM _epss_ents) AND ts IS NOT NULL
                                         GROUP BY 1) m
                                   WHERE entities.id = m.entity_id""")
                cur.execute("DROP TABLE IF EXISTS _epss_ents")
            cur.execute("DELETE FROM events WHERE source = 'epss'")
    finally:
        if lock:
            lock.release()
    log.info("removed %d EPSS events and %d entity mentions made by an earlier version", n, stale)
    return n + stale


# =========================================================================== CISA CSAF advisories
CSAF_BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/"
CSAF_FOLDERS = ("OT", "IT", "VA")             # TLP:WHITE subfolders: ICS (ICSA/ICSMA), IT and VA advisories
CSAF_WINDOW_DAYS = 90                          # advisories published or revised in the last 90 days
CSAF_MAX_DOWNLOADS = 300                       # per run; the first run fetches the window (~190), later runs a few
CSAF_CONCURRENCY = 4
CSAF_ERRORS = "__errors__"
_SEV = {"critical": 0.95, "high": 0.8, "medium": 0.55, "moderate": 0.55, "low": 0.3, "none": 0.1}
MAX_PRODUCTS_PER_CVE = 8          # product families per CVE (after collapsing model numbers)


def _csaf_cache() -> Path:
    return Path(config.LAKE) / "cache" / "csaf"


def parse_changes(text: str) -> list[tuple[str, dt.datetime]]:
    """CSAF changes.csv ("path","timestamp" per line, newest first) -> [(path, ts)]; junk lines skipped."""
    out = []
    for r in csv.reader(io.StringIO(text)):
        if len(r) < 2 or not r[0].strip().endswith(".json"):
            continue
        p = r[0].strip()
        if p.startswith("/") or ".." in p:
            continue
        try:
            t = dt.datetime.fromisoformat(r[1].strip().replace("Z", "+00:00"))
        except ValueError:
            continue
        out.append((p, t if t.tzinfo else t.replace(tzinfo=dt.UTC)))
    return out


def _cache_index() -> dict:
    f = _csaf_cache() / "index.json"
    try:
        return json.loads(f.read_text())
    except (OSError, ValueError):
        return {}


def _cache_save(index: dict) -> None:
    d = _csaf_cache()
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "index.json.part"
    tmp.write_text(json.dumps(index, sort_keys=True))
    tmp.replace(d / "index.json")


def _cache_file(key: str) -> Path:
    return _csaf_cache() / (key.replace("/", "__") + ".gz")


async def fetch_csaf(client: httpx.AsyncClient, window_days: int = CSAF_WINDOW_DAYS) -> bytes:
    """The advisories CISA published or revised in the window, as {"docs": {folder/path: csaf}, ...}.

    Uses CSAF's directory distribution: each folder's changes.csv (path + last change) is fetched every run, and
    a document is downloaded only when it is new or its changes.csv time moved. Unchanged documents come from a
    local cache (<lake>/cache/csaf/), so a run is 3 small requests plus the new or revised advisories."""
    cutoff = now() - dt.timedelta(days=window_days)
    errors: dict[str, str] = {}
    want: dict[str, dt.datetime] = {}
    for folder in CSAF_FOLDERS:
        try:
            r = await _get(client, f"{CSAF_BASE}{folder}/white/changes.csv", "cisa_advisories", timeout=60, follow_redirects=True)
            rows = parse_changes(r.text)
        except caps.TooLarge:   # an oversized response fails the run: nothing partial is stored
            raise
        except Exception as e:
            errors[f"{folder}/changes.csv"] = f"{type(e).__name__}: {e}"[:200]
            continue
        for path, t in rows:
            if t >= cutoff:
                want[f"{folder}/{path}"] = t
    if not want and errors:
        raise RuntimeError("; ".join(f"{k}: {v}" for k, v in errors.items()))
    index = _cache_index()
    docs: dict[str, Any] = {}
    todo = []
    for key, t in want.items():
        c = index.get(key)
        if c and c.get("ts") == t.isoformat() and _cache_file(key).exists():
            try:
                docs[key] = json.loads(gzip.decompress(_cache_file(key).read_bytes()))
                continue
            except (OSError, ValueError):
                pass
        todo.append(key)
    todo.sort(key=lambda k: want[k], reverse=True)          # newest first if the per-run cap bites
    skipped = todo[CSAF_MAX_DOWNLOADS:]
    sem = asyncio.Semaphore(CSAF_CONCURRENCY)

    async def one(key: str):
        folder, path = key.split("/", 1)
        async with sem:
            try:
                r = await _get(client, f"{CSAF_BASE}{folder}/white/{path}", "cisa_advisories", timeout=60, follow_redirects=True)
                doc = r.json()
                if not (doc.get("document") or {}).get("tracking", {}).get("id"):
                    raise ValueError("not a CSAF document (no document.tracking.id)")
            except caps.TooLarge:
                raise
            except Exception as e:
                errors[key] = f"{type(e).__name__}: {e}"[:200]
                old = _cache_file(key)
                if old.exists():   # keep serving the cached (older) revision
                    try:
                        docs[key] = json.loads(gzip.decompress(old.read_bytes()))
                    except (OSError, ValueError):
                        pass
                return
            docs[key] = doc
            _cache_file(key).parent.mkdir(parents=True, exist_ok=True)
            _cache_file(key).write_bytes(gzip.compress(json.dumps(doc).encode(), compresslevel=6, mtime=0))
            index[key] = {"ts": want[key].isoformat()}

    await asyncio.gather(*(one(k) for k in todo[:CSAF_MAX_DOWNLOADS]))
    for key in list(index):            # forget documents that left the window
        if key not in want:
            _cache_file(key).unlink(missing_ok=True)
            index.pop(key, None)
    _cache_save(index)
    if skipped:
        log.info("CSAF: %d documents left for the next run (per-run cap %d)", len(skipped), CSAF_MAX_DOWNLOADS)
    out: dict[str, Any] = {"window_days": window_days, "docs": docs}
    if errors:
        out[CSAF_ERRORS] = errors
    return json.dumps(out).encode()


def _note(doc: dict, *titles: str, category: str | None = None) -> str | None:
    want = {t.lower() for t in titles}
    for n in doc.get("notes") or []:
        if (n.get("title") or "").strip().lower() in want or (category and n.get("category") == category):
            t = (n.get("text") or "").strip()
            if t:
                return t
    return None


def _products(tree: dict) -> dict[str, tuple[str | None, str | None]]:
    """product_id -> (vendor, product name) from a CSAF product tree's branches and relationships."""
    out: dict[str, tuple[str | None, str | None]] = {}

    def walk(branches, vendor=None, product=None):
        for b in branches or []:
            cat, name = b.get("category"), (b.get("name") or "").strip() or None
            v, p = vendor, product
            if cat == "vendor":
                v = name
            elif cat in ("product_name", "product_family") and p is None:
                p = name
            elif cat == "product_name":
                p = name
            if isinstance(b.get("product"), dict) and b["product"].get("product_id"):
                out[b["product"]["product_id"]] = (v, p or b["product"].get("name"))
            walk(b.get("branches"), v, p)
    walk(tree.get("branches"))
    for fp in tree.get("full_product_names") or []:
        if fp.get("product_id") and fp["product_id"] not in out:
            out[fp["product_id"]] = (None, fp.get("name"))
    for rel in tree.get("relationships") or []:
        fp = rel.get("full_product_name") or {}
        ref = out.get(rel.get("product_reference")) or (None, None)
        if fp.get("product_id"):
            out.setdefault(fp["product_id"], ref if ref != (None, None) else (None, fp.get("name")))
    return out


def _strip_vendor(vendor: str | None, product: str | None) -> str | None:
    if product and vendor and product.lower().startswith(vendor.lower() + " "):
        return product[len(vendor) + 1:].strip() or product
    return product


_MODEL_CUT = re.compile(r"\s+(?:model|models|type|series|part|p/n|sku|firmware|version|versions|ver\.?|release|v\d)\b.*$", re.I)
_PAREN = re.compile(r"\s*[\(\[][^)\]]*[\)\]]")


def product_family(vendor: str | None, product: str | None) -> str | None:
    """A CSAF product name reduced to its family, so model numbers and editions don't each become a product:
    "MELSEC MX Controller MX-R model MXR300-16" -> "MELSEC MX Controller MX-R", "PowerSYSTEM Center 2024" ->
    "PowerSYSTEM Center", "Mendix SAML (Mendix 10 compatible)" -> "Mendix SAML", "EPICS Base release" -> "EPICS Base".
    Trailing tokens with digits go (model codes, years); a name made only of such tokens is kept as it is (TRO600)."""
    p = _strip_vendor(vendor, product)
    if not p:
        return None
    p = _PAREN.sub("", p).strip()
    p = _MODEL_CUT.sub("", p).strip()
    toks = p.split()
    while len(toks) > 1 and any(ch.isdigit() for ch in toks[-1]):
        toks.pop()
    return " ".join(toks).strip(" -,:;/") or _strip_vendor(vendor, product)


def product_name(vendor: str | None, family: str) -> str:
    """Entity name of a product: "<vendor> <family>", without repeating a vendor the family already names."""
    if (not vendor or family.lower() == vendor.lower() or family.lower().startswith(vendor.lower() + " ")
            or family.split()[0].lower() == vendor.split()[0].lower()):   # "InterSystems IRIS" by "InterSystems Corporation"
        return family
    return f"{vendor} {family}"


def _cvss(v: dict) -> tuple[float | None, str | None, str | None]:
    """Highest CVSS base score of a CSAF vulnerability: (score, severity, version)."""
    best = (None, None, None)
    for s in v.get("scores") or []:
        for k in ("cvss_v4", "cvss_v3", "cvss_v2"):
            c = s.get(k)
            if not isinstance(c, dict):
                continue
            try:
                score = float(c.get("baseScore"))
            except (TypeError, ValueError):
                continue
            if not (0.0 <= score <= 10.0):
                continue
            if best[0] is None or score > best[0]:
                sev = c.get("baseSeverity")
                best = (score, sev.lower() if isinstance(sev, str) else None, str(c.get("version") or k[-2:].replace("_", "")))
    return best


def _web_url(doc: dict, tracking_id: str, key: str | None) -> str:
    refs = doc.get("references") or []
    for r in refs:
        u = r.get("url") or ""
        if r.get("category") == "self" and u.startswith("https://www.cisa.gov/"):
            return u
    for r in refs:
        u = r.get("url") or ""
        if u.startswith("https://www.cisa.gov/") and tracking_id.lower() in u.lower():
            return u
    if key:   # IT/VA advisories have no cisa.gov page: the document on GitHub
        folder, path = key.split("/", 1)
        return f"https://github.com/cisagov/CSAF/blob/develop/csaf_files/{folder}/white/{path}"
    return f"https://github.com/cisagov/CSAF/search?q={tracking_id}"


def advisory_kind(tracking_id: str) -> str:
    t = tracking_id.upper()
    # Never a bare two-letter word: "IT" would be read as Italy's country code by tag consumers.
    return ("ICS medical advisory" if t.startswith("ICSMA") else "ICS advisory" if t.startswith("ICSA")
            else "IT advisory" if t.startswith("VA") else "advisory")


def csaf_summary(doc: dict, key: str | None = None) -> dict | None:
    """The fields the app uses from one CSAF document, or None if it is not a usable advisory."""
    d = doc.get("document") or {}
    tr = d.get("tracking") or {}
    tid = (tr.get("id") or "").strip().upper()
    title = re.sub(r"\s+", " ", (d.get("title") or "")).strip()
    if not tid or not title:
        return None
    if (tr.get("status") or "final").lower() not in ("final", "interim"):
        return None   # drafts are not published advisories
    prods = _products(doc.get("product_tree") or {})
    cves: dict[str, dict] = {}
    vendors: list[str] = []
    for v in doc.get("vulnerabilities") or []:
        cve = (v.get("cve") or "").strip().upper()
        if not CVE_ID.match(cve):
            continue
        score, sev, ver = _cvss(v)
        ps = v.get("product_status") or {}
        pids = list(dict.fromkeys((ps.get("known_affected") or []) + (ps.get("first_affected") or []) + (ps.get("last_affected") or [])))
        pairs = []
        for pid in pids:
            ven, prod = prods.get(pid, (None, None))
            prod = product_family(ven, prod)
            if ven and ven not in vendors:
                vendors.append(ven)
            if prod and (ven, prod) not in pairs:
                pairs.append((ven, prod))
        cw = v.get("cwe") or {}
        o = cves.setdefault(cve, {"cve": cve, "cvss": None, "severity": None, "cvss_version": None,
                                  "cwe": cw.get("id"), "title": (v.get("title") or "").strip() or None, "products": []})
        if score is not None and (o["cvss"] is None or score > o["cvss"]):
            o["cvss"], o["severity"], o["cvss_version"] = score, sev, ver
        for p in pairs:
            if p not in o["products"]:
                o["products"].append(p)
    for ven, _ in prods.values():
        if ven and ven not in vendors:
            vendors.append(ven)
    scores = [c["cvss"] for c in cves.values() if c["cvss"] is not None]
    agg = ((d.get("aggregate_severity") or {}).get("text") or "").strip().lower() or None
    revs = tr.get("revision_history") or []
    last_rev = max(revs, key=lambda r: str(r.get("date") or ""), default={}) if revs else {}
    return {
        "id": tid, "title": title, "kind": advisory_kind(tid), "key": key,
        "published": tr.get("initial_release_date"), "updated": tr.get("current_release_date") or tr.get("initial_release_date"),
        "version": str(tr.get("version") or ""), "revision": (last_rev.get("summary") or "").strip() or None,
        "url": _web_url(d, tid, key), "vendors": vendors,
        "cves": list(cves.values()), "cvss_max": max(scores) if scores else None, "aggregate_severity": agg,
        "summary": _note(d, "summary", "advisory summary", "risk evaluation", category="summary"),
        "sectors": _note(d, "critical infrastructure sectors"),
        "hq": _note(d, "company headquarters location"),
    }


def _version_key(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v or "0"))


def csaf_advisories(raw: bytes) -> dict[str, tuple[dict, dict]]:
    """tracking id -> (summary, document): one per advisory, the latest revision when the same advisory is in
    two folders (some VA advisories are in both IT/ and VA/)."""
    data = json.loads(raw)
    best: dict[str, tuple[dict, dict]] = {}
    for key in sorted(data.get("docs") or {}):
        doc = data["docs"][key]
        s = csaf_summary(doc, key) if isinstance(doc, dict) else None
        if not s:
            continue
        cur = best.get(s["id"])
        rank = (str(s["updated"] or ""), _version_key(s["version"]), -CSAF_FOLDERS.index(key.split("/", 1)[0]) if key.split("/", 1)[0] in CSAF_FOLDERS else -9)
        if cur is None or rank > cur[2]:
            best[s["id"]] = (s, doc, rank)
    return {k: (v[0], v[1]) for k, v in best.items()}


def store_advisory_cves(advisories: dict[str, tuple[dict, dict]]) -> None:
    """Upsert `advisory_cves` (one row per advisory and CVE) for the advisories in a payload. Rows of advisories
    that left the fetch window stay: the table is the history of what CISA said about each CVE."""
    if not advisories:
        return
    rows = []
    for tid, (s, _doc) in advisories.items():
        for c in s["cves"]:
            rows.append({"advisory": tid, "cve": c["cve"], "cvss": c["cvss"], "cvss_version": c["cvss_version"],
                         "severity": c["severity"], "cwe": c["cwe"],
                         "vendors": sorted({v for v, _ in c["products"] if v} or set(s["vendors"][:5])),
                         "products": list(dict.fromkeys(product_name(v, p) for v, p in c["products"]))[:MAX_PRODUCTS_PER_CVE],
                         "title": s["title"], "kind": s["kind"], "published": s["published"], "updated": s["updated"],
                         "url": s["url"]})
    ids = list(advisories)
    tmp = config.TMP_DIR / f"advisory-cves-{os.getpid()}.ndjson"
    with tmp.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    cols = ("{'advisory': 'VARCHAR', 'cve': 'VARCHAR', 'cvss': 'DOUBLE', 'cvss_version': 'VARCHAR', 'severity': 'VARCHAR', "
            "'cwe': 'VARCHAR', 'vendors': 'VARCHAR[]', 'products': 'VARCHAR[]', 'title': 'VARCHAR', 'kind': 'VARCHAR', "
            "'published': 'TIMESTAMPTZ', 'updated': 'TIMESTAMPTZ', 'url': 'VARCHAR'}")
    try:
        with db._write_lock:
            cur = db.cursor()
            with db.tx(cur):
                cur.execute(f"DELETE FROM advisory_cves WHERE advisory IN ({','.join('?' * len(ids))})", ids)
                if rows:
                    cur.execute(f"""INSERT INTO advisory_cves SELECT advisory, cve, cvss, cvss_version, severity, cwe, vendors,
                                    products, title, kind, published, updated, url
                                    FROM read_json('{db._q(tmp)}', format='newline_delimited', columns={cols})""")
    finally:
        tmp.unlink(missing_ok=True)


def advisory_event(source_id: str, s: dict) -> Event:
    cves = [c["cve"] for c in s["cves"]]
    sev = (s["cvss_max"] / 10.0) if s["cvss_max"] is not None else _SEV.get(s["aggregate_severity"] or "", 0.6)
    vend = ", ".join(s["vendors"][:3]) + (f" +{len(s['vendors']) - 3}" if len(s["vendors"]) > 3 else "")
    head = f"{s['id']} · {s['kind']}" + (f" · {vend}" if vend else "") + \
        (f" · {len(cves)} CVE{'s' if len(cves) != 1 else ''}" if cves else "") + \
        (f" · CVSS {s['cvss_max']:.1f}" if s["cvss_max"] is not None else "")
    upd = ""
    if s["updated"] and s["published"] and str(s["updated"])[:10] != str(s["published"])[:10]:
        upd = f" · updated {str(s['updated'])[:10]} (first published {str(s['published'])[:10]})"
    body = re.sub(r"\s+", " ", s.get("summary") or "").strip()
    summary = (head + upd + (f". {body}" if body else "") + (f" CVEs: {', '.join(cves[:12])}" + (" …" if len(cves) > 12 else "") if cves else ""))
    hq = None
    if s.get("hq"):
        from .. import geo
        ccs = geo.tag_countries(s["hq"])
        hq = ccs[0] if ccs else None
    tags = ["CISA", s["kind"]] + s["vendors"][:5] + cves[:20] + ([hq] if hq else [])
    return Event(
        source=source_id, kind="advisory", key=(s["id"],), ts=to_ts(s["updated"] or s["published"]),
        title=f"{s['id']}: {s['title']}", summary=summary[:600], category="news", severity=round(sev, 4),
        value=s["cvss_max"], url=s["url"], tags=list(dict.fromkeys(t for t in tags if t)),
    )


# =========================================================================== cross-links for the event drawer
ADVISORY_ID = re.compile(r"^((?:ICSMA|ICSA|VA)-\d{2}-\d{3}-\d{2,3}[A-Z]?)\b", re.I)


def _stories_for(cves: list[str], advisory: str | None, limit: int = 12) -> list[dict]:
    """News stories covering an advisory or CVEs: articles that mention one of the CVEs (entities layer) or name
    the advisory id in their title or text. Corroboration, not duplication: the advisory stays one event."""
    if not db.has_table("articles") or not db.has_table("stories"):
        return []
    hits: dict[str, set] = {}
    if cves and db.has_table("mentions"):
        ents = [f"cve:{c.lower()}" for c in cves]
        for r in db.query(f"""SELECT a.story_id, m.entity_id FROM mentions m JOIN articles a ON m.ref_type = 'article' AND m.ref_id = a.id
                              WHERE m.entity_id IN ({','.join('?' * len(ents))}) AND a.story_id IS NOT NULL
                                AND a.source_id IS DISTINCT FROM 'cisa_advisories'""", ents):
            hits.setdefault(r["story_id"], set()).add(r["entity_id"].split(":", 1)[1].upper())
    if advisory:
        pat = f"%{advisory}%"
        # the advisory's own page, queued as an article from its event, is not coverage of it
        for r in db.query("""SELECT DISTINCT story_id FROM articles WHERE story_id IS NOT NULL
                             AND source_id IS DISTINCT FROM 'cisa_advisories'
                             AND (title ILIKE ? OR dek ILIKE ? OR text ILIKE ?)""", [pat, pat, pat]):
            hits.setdefault(r["story_id"], set()).add(advisory)
    if not hits:
        return []
    ids = list(hits)
    rows = db.query(f"""SELECT id, title, article_count, source_count, first_seen, last_seen FROM stories
                        WHERE id IN ({','.join('?' * len(ids))}) ORDER BY last_seen DESC, id LIMIT ?""", ids + [limit])
    for r in rows:
        r["matched"] = sorted(hits[r["id"]])
        for k in ("first_seen", "last_seen"):
            if isinstance(r[k], dt.datetime):
                r[k] = r[k].isoformat()
    return rows


def event_vuln_context(e: dict) -> dict:
    """For the event drawer: the CVEs an advisory, KEV, NVD or EPSS event is about, enriched (CVSS, KEV, EPSS,
    advisories), and the news stories covering them. Empty for other events."""
    from ..news.api import cve_enrichment
    kind, title = e.get("kind"), e.get("title") or ""
    advisory = None
    if kind == "advisory" and e.get("source") == "cisa_advisories":
        m = ADVISORY_ID.match(title)
        advisory = m.group(1).upper() if m else None
        cves = [r["cve"] for r in db.query("SELECT cve FROM advisory_cves WHERE advisory = ? ORDER BY cvss DESC NULLS LAST, cve",
                                           [advisory])] if advisory else []
        if not cves:
            cves = [str(t).upper() for t in e.get("tags") or [] if CVE_ID.match(str(t).upper())]
    elif kind in ("kev", "cve"):
        cves = [m.upper() for m in CVE_IN_TEXT.findall(title)][:1]
    else:
        return {}
    cves = list(dict.fromkeys(cves))[:50]
    return {"cves": cve_enrichment(cves) if cves else [], "stories": _stories_for(cves, advisory), "advisory_id": advisory}

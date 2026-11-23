"""Search documents built from the warehouse and the lake: one per CVE, one per news/social event.

The same text feeds both the embedding index (osinthub/ai/indexer.py) and the keyword index
(osinthub/search.py), so vector and keyword search see the same words.

CVE documents merge NVD and CISA KEV: CVE id, vendor and product, KEV vulnerability name,
the full English description (events keep only the first 600 characters, so it comes from
the lake records), affected products from CPEs, CWE weakness names, CVSS and exploitation.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import re
import threading
from pathlib import Path

from .. import config, db
from ..sources.text import unentity

log = logging.getLogger("osinthub.ai.docs")

DOC_VERSION = "cve-v1"  # bump when the document text changes, so everything is re-embedded
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# Names of the most common CWEs, so a question in plain words ("cross-site scripting",
# "path traversal") meets CVEs whose record only carries the id.
CWE_NAMES = {
    "CWE-20": "Improper Input Validation", "CWE-22": "Path Traversal", "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection", "CWE-79": "Cross-site Scripting (XSS)", "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection", "CWE-95": "Eval Injection", "CWE-119": "Memory Buffer Overflow",
    "CWE-120": "Classic Buffer Overflow", "CWE-121": "Stack-based Buffer Overflow", "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read", "CWE-134": "Format String", "CWE-190": "Integer Overflow",
    "CWE-200": "Information Exposure", "CWE-269": "Improper Privilege Management", "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control", "CWE-285": "Improper Authorization", "CWE-287": "Improper Authentication",
    "CWE-288": "Authentication Bypass Using an Alternate Path", "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-295": "Improper Certificate Validation", "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Brute Force / Excessive Authentication Attempts", "CWE-311": "Missing Encryption",
    "CWE-312": "Cleartext Storage of Sensitive Information", "CWE-319": "Cleartext Transmission",
    "CWE-326": "Inadequate Encryption Strength", "CWE-327": "Broken Cryptographic Algorithm",
    "CWE-345": "Insufficient Verification of Data Authenticity", "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition", "CWE-400": "Uncontrolled Resource Consumption (Denial of Service)",
    "CWE-401": "Memory Leak", "CWE-416": "Use After Free", "CWE-425": "Forced Browsing",
    "CWE-434": "Unrestricted File Upload", "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data", "CWE-532": "Sensitive Information in Log Files",
    "CWE-601": "Open Redirect", "CWE-611": "XML External Entity (XXE)", "CWE-639": "Insecure Direct Object Reference (IDOR)",
    "CWE-668": "Exposure of Resource to Wrong Sphere", "CWE-693": "Protection Mechanism Failure",
    "CWE-704": "Type Confusion", "CWE-732": "Incorrect Permission Assignment", "CWE-770": "Resource Allocation Without Limits",
    "CWE-787": "Out-of-bounds Write", "CWE-798": "Hard-coded Credentials", "CWE-843": "Type Confusion",
    "CWE-862": "Missing Authorization", "CWE-863": "Incorrect Authorization", "CWE-916": "Weak Password Hash",
    "CWE-918": "Server-Side Request Forgery (SSRF)", "CWE-922": "Insecure Storage of Sensitive Information",
    "CWE-1021": "Clickjacking", "CWE-1236": "CSV Injection", "CWE-1321": "Prototype Pollution",
    "CWE-1333": "Regular Expression Denial of Service (ReDoS)", "CWE-80": "Basic Cross-site Scripting",
    "CWE-74": "Injection", "CWE-91": "XML Injection", "CWE-117": "Log Injection", "CWE-209": "Error Message Information Leak",
    "CWE-259": "Hard-coded Password", "CWE-266": "Incorrect Privilege Assignment", "CWE-305": "Authentication Bypass",
    "CWE-384": "Session Fixation", "CWE-415": "Double Free", "CWE-427": "Uncontrolled Search Path (DLL hijacking)",
    "CWE-428": "Unquoted Search Path", "CWE-444": "HTTP Request Smuggling", "CWE-521": "Weak Password Requirements",
    "CWE-552": "Files Accessible to External Parties", "CWE-613": "Insufficient Session Expiration",
    "CWE-617": "Reachable Assertion", "CWE-640": "Weak Password Recovery", "CWE-674": "Uncontrolled Recursion",
    "CWE-697": "Incorrect Comparison", "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-776": "XML Entity Expansion", "CWE-824": "Uninitialized Pointer", "CWE-835": "Infinite Loop",
    "CWE-908": "Uninitialized Resource", "CWE-912": "Hidden Functionality (Backdoor)", "CWE-940": "Improper Channel Verification",
    "CWE-1188": "Insecure Default Initialization",
}

_lock = threading.Lock()
_cache: dict = {"key": None, "docs": {}}


def _files(source: str) -> list[Path]:
    d = config.RAW_DIR / source
    if not d.exists():
        return []
    return sorted(p for p in d.rglob("*.gz") if not p.name.endswith(".events.ndjson.gz"))


def _iter_records(path: Path):
    """Provider records from a records file (put lines) or a full payload file."""
    try:
        if path.name.endswith(".records.ndjson.gz"):
            with gzip.open(path, "rt") as fh:
                for line in fh:
                    r = json.loads(line)
                    if r.get("op") == "put":
                        data = r.get("data")
                        yield from (data if isinstance(data, list) else [data])
        elif path.name.endswith(".json.gz"):
            with gzip.open(path, "rt") as fh:
                yield from (json.load(fh).get("vulnerabilities") or [])
    except Exception as e:  # a damaged file must not stop indexing
        log.warning("skipping %s: %s", path, e)


_UNKNOWN = {"unknown", "n/a", "na", "-", "*", "unspecified"}


def _cpe_products(cve: dict) -> list[str]:
    out = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                parts = (m.get("criteria") or "").split(":")
                if len(parts) > 5 and m.get("vulnerable", True):
                    out.append(" ".join(p for p in parts[3:5] if p.lower() not in _UNKNOWN).replace("_", " "))
    return out


def lake_details() -> dict[str, dict]:
    """CVE id -> merged details from NVD and KEV records in the lake (latest file wins)."""
    det: dict[str, dict] = {}
    for p in _files("nvd_recent"):
        for item in _iter_records(p):
            c = (item or {}).get("cve") or {}
            cid = c.get("id")
            if not cid:
                continue
            d = det.setdefault(cid, {})
            desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), None)
            desc = unentity(desc) if desc else desc   # the raw NVD record: entities decoded as the events are
            if desc:
                d["description"] = desc
            cwes = [x["value"] for w in c.get("weaknesses") or [] for x in w.get("description") or []
                    if str(x.get("value", "")).startswith("CWE-")]
            if cwes:
                d["cwes"] = cwes
            prods = [" ".join(x for x in (a.get("vendor"), a.get("product")) if x and x.lower() not in _UNKNOWN)
                     for aff in c.get("affected") or [] for a in aff.get("affectedData") or []]
            prods += _cpe_products(c)
            if prods:
                d["products"] = prods
            d["status"] = c.get("vulnStatus")
    for p in _files("cisa_kev"):
        for v in _iter_records(p):
            cid = (v or {}).get("cveID")
            if not cid:
                continue
            d = det.setdefault(cid, {})
            d["kev"] = {k: v.get(k) for k in ("vendorProject", "product", "vulnerabilityName", "shortDescription",
                                               "knownRansomwareCampaignUse", "dateAdded")}
            if v.get("cwes"):
                d["cwes"] = list(dict.fromkeys((d.get("cwes") or []) + list(v["cwes"])))
    return det


def _dedupe(xs):
    seen, out = set(), []
    for x in xs:
        k = x.lower().strip()
        if k and k not in seen:
            seen.add(k)
            out.append(x.strip())
    return out


def cve_docs() -> dict[str, dict]:
    """CVE id -> {"text", "title", "url", "snippet", "payload", "hash"}. Cached until data changes."""
    files = _files("nvd_recent") + _files("cisa_kev")
    stamp = db.query("SELECT count(*) AS n, max(stored_at) AS s, max(ingested_at) AS i FROM events "
                     "WHERE kind IN ('cve', 'kev')")[0]
    key = (tuple((str(p), p.stat().st_mtime) for p in files), stamp["n"], str(stamp["s"]))
    with _lock:
        if _cache["key"] == key:
            return _cache["docs"]
    rows = db.query("""SELECT id, source, kind, title, summary, severity, value, url, tags, ts
                       FROM events WHERE kind IN ('cve', 'kev') ORDER BY ts""")
    det = lake_details()
    by_cve: dict[str, dict] = {}
    for r in rows:
        m = CVE_RE.search(r["title"] or "")
        if not m:
            continue
        cid = m.group(0).upper()
        e = by_cve.setdefault(cid, {"events": [], "summary": None, "cvss": None, "kev": False, "tags": []})
        e["events"].append(r["id"])
        if r["kind"] == "kev":
            e["kev"] = True
            e["kev_title"] = r["title"]
            e["kev_summary"] = r["summary"]
            e["tags"] += [t for t in r["tags"] or [] if t != "ransomware"]
            e["ransomware"] = "ransomware" in (r["tags"] or [])
        else:
            e["summary"] = r["summary"]
            e["cvss"] = r["value"]
            e["sev_label"] = (r["tags"] or [None])[0]
        e["ts"] = r["ts"]
    docs = {}
    for cid, e in by_cve.items():
        d = det.get(cid, {})
        kev = d.get("kev") or {}
        vendor_product = " ".join(x for x in (kev.get("vendorProject"), kev.get("product")) if x) \
            or " ".join(e["tags"][:2])
        products = _dedupe(([vendor_product] if vendor_product else []) + (d.get("products") or []))[:8]
        name = (kev.get("vulnerabilityName") or "").strip() or None
        desc = d.get("description") or e.get("summary") or ""
        kev_desc = kev.get("shortDescription") or ""
        cwes = _dedupe(d.get("cwes") or [])
        lines = [f"{cid}: " + (name or (products[0] if products else "vulnerability"))]
        if products:
            lines.append("Affected products: " + "; ".join(products))
        if desc:
            lines.append(desc)
        if kev_desc and kev_desc.strip() not in desc:
            lines.append(kev_desc)
        if cwes:
            lines.append("Weakness: " + "; ".join(f"{c} {CWE_NAMES[c]}" if c in CWE_NAMES else c for c in cwes))
        sev = []
        if e.get("cvss"):
            sev.append(f"CVSS {e['cvss']}" + (f" ({e['sev_label']})" if e.get("sev_label") else ""))
        if e["kev"]:
            sev.append("Known exploited vulnerability in the CISA KEV catalog, actively exploited in the wild")
        if e.get("ransomware") or (kev.get("knownRansomwareCampaignUse") or "").lower() == "known":
            sev.append("used in ransomware campaigns")
        if sev:
            lines.append(". ".join(sev) + ".")
        text = "\n".join(lines)
        title = f"{cid} · {name or (products[0] if products else '')}".rstrip(" ·")
        snippet = (desc or kev_desc)[:280]
        docs[cid] = {
            "id": cid, "text": text, "title": title, "snippet": snippet,
            # Fields for keyword search (BM25F weights in osinthub/keyword.py).
            "fields": {"id": cid, "name": name or "", "products": "; ".join(products),
                       "body": "\n".join(lines[1:])},
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
            "hash": hashlib.sha1(f"{DOC_VERSION}\n{text}".encode()).hexdigest()[:16],
            "payload": {"cve": cid, "title": title, "kev": e["kev"], "cvss": e.get("cvss"),
                        "events": e["events"], "ts": str(e.get("ts"))},
        }
    with _lock:
        _cache.update(key=key, docs=docs)
    return docs


EVENT_KINDS = ("news", "social")
_ev_cache: dict = {"key": None, "docs": {}}


def event_docs() -> dict[str, dict]:
    """Event id -> document for news and social events."""
    stamp = db.query(f"SELECT count(*) AS n, max(stored_at) AS s FROM events WHERE kind IN {EVENT_KINDS}")[0]
    key = (stamp["n"], str(stamp["s"]))
    with _lock:
        if _ev_cache["key"] == key:
            return _ev_cache["docs"]
    rows = db.query(f"""SELECT id, source, kind, title, summary, url, ts FROM events
                        WHERE kind IN {EVENT_KINDS} AND coalesce(title, '') <> ''""")
    docs = {}
    for r in rows:
        title = (r["title"] or "").strip()
        summary = (r["summary"] or "").strip()
        text = summary if summary.startswith(title[:80]) else f"{title}\n{summary}"
        text = re.sub(r"&nbsp;|&amp;", " ", text)[:4000]
        docs[r["id"]] = {
            "id": r["id"], "text": text, "title": title.split("\n")[0][:200], "snippet": summary[:280],
            "fields": {"title": title.split("\n")[0][:300], "body": text},
            "url": r["url"], "hash": hashlib.sha1(f"ev-v1\n{text}".encode()).hexdigest()[:16],
            "payload": {"title": title.split("\n")[0][:200], "source": r["source"], "kind": r["kind"],
                        "url": r["url"], "ts": str(r["ts"])},
        }
    with _lock:
        _ev_cache.update(key=key, docs=docs)
    return docs

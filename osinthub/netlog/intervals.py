"""indicator_intervals: when each threat indicator was listed, replayed from the lake's record deltas.

raw/<source>/YYYY/MM/DD/HHMMSS.records.ndjson.gz holds {"key", "op": "put", "data"} and {"key", "op": "del"}
lines. A put opens an interval for its key (or continues an open one); a del closes it at the file's time.
Processing is incremental; a file that appears out of order makes that source replay from scratch.
"""
from __future__ import annotations

import datetime as dt
import gzip
import json
import logging
import re
from functools import lru_cache
from pathlib import Path

from .. import config, db
from . import ipnum, util

log = logging.getLogger("osinthub.netlog.ti")

# source id -> (category, extractor). Categories drive severities (matcher.RULES).
SOURCES: dict[str, str] = {
    "feodo_c2": "c2",
    "spamhaus_drop": "drop",
    "spamhaus_edrop": "drop",
    "et_compromised": "compromised",
    "cins_army": "reputation",
    "blocklist_de": "attacker",
    "dshield_top": "scanner",
    "tor_exits": "tor",
    "cisa_kev": "kev",
    "threatfox": "c2",
    "sslbl": "c2",
    "urlhaus": "reputation",
}
# Trust tier per source (okf/sources/trust-model.md): A authority, B established, C community, D unverified.
TIERS = {"feodo_c2": "B", "spamhaus_drop": "A", "spamhaus_edrop": "A", "et_compromised": "B", "cins_army": "C",
         "blocklist_de": "C", "dshield_top": "B", "tor_exits": "A", "cisa_kev": "A", "threatfox": "B", "sslbl": "B",
         "urlhaus": "B", "reported": "D"}
DOMAIN_CATEGORIES = {"c2", "reputation"}  # lists whose domain keys are indicators (ThreatFox, URLhaus)
# Threat-category sources whose records are not indicators of malicious infrastructure.
NOT_INDICATORS = {"ransomware_live"}
# abuse.ch sources: one record can give several indicators (a URL and its host), each with its own category.
ABUSECH = {"threatfox", "urlhaus", "sslbl"}
# Windowed sources never say when an indicator stops being bad, so a listing ends this long after the last
# record that listed it (or the provider's own last_seen, if later). ThreatFox itself expires IOCs after 6
# months; C2 addresses churn far faster. okf/data/netlog.md#abusech
TTL_DAYS = {("threatfox", "ip"): 30, ("threatfox", "domain"): 90, ("threatfox", "url"): 90, ("threatfox", "hash"): 180,
            ("urlhaus", "ip"): 30, ("urlhaus", "domain"): 30, ("urlhaus", "url"): 30}
TTL_SOURCES = {s for s, _ in TTL_DAYS}
C2_MIN_CONFIDENCE = 75
_TS_RE = re.compile(r"(\d{4})/(\d{2})/(\d{2})/(\d{6})\.records\.ndjson\.gz$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")


def _threat_sources() -> dict[str, str]:
    """Known threat lists plus any other registered source in the 'threat' category."""
    out = dict(SOURCES)
    try:
        from ..sources import SOURCES as REG
        for sid, s in REG.items():
            if sid not in out and sid not in NOT_INDICATORS and getattr(s, "category", None) == "threat":
                out[sid] = "listed"
    except Exception:
        pass
    return out


def _file_ts(path: Path) -> dt.datetime | None:
    m = _TS_RE.search(path.as_posix())
    if not m:
        return None
    y, mo, d, hms = m.groups()
    return dt.datetime(int(y), int(mo), int(d), int(hms[:2]), int(hms[2:4]), int(hms[4:]), tzinfo=util.UTC)


# Shared-hosting and dynamic-DNS suffixes (from the Public Suffix List's private section), used on their own when
# the lake has no ref/public_suffix_list.dat yet, so names under them stay separately registrable and are never
# taken for the popular parent (evil.duckdns.org is not duckdns.org).
BUNDLED_SUFFIXES = frozenset("""
duckdns.org no-ip.org no-ip.com no-ip.biz no-ip.info ddns.net hopto.org zapto.org sytes.net serveftp.com servebeer.com
myftp.biz myftp.org redirectme.net servehttp.com dynu.net freeddns.org ddnsfree.com dyndns.org dynalias.com homeip.net
mooo.com afraid.org chickenkiller.com strangled.net linkpc.net kozow.com ooguy.com accesscam.org camdvr.org
github.io gitlab.io bitbucket.io pages.dev workers.dev netlify.app vercel.app herokuapp.com azurewebsites.net
blogspot.com web.app firebaseapp.com appspot.com r2.dev ngrok.io ngrok-free.app ngrok.app trycloudflare.com
onrender.com glitch.me repl.co replit.dev 000webhostapp.com weebly.com wixsite.com wordpress.com
s3.amazonaws.com cloudfront.net azureedge.net web.core.windows.net blob.core.windows.net
""".split())


@lru_cache(maxsize=1)
def _psl() -> frozenset:
    """Public Suffix List entries (ICANN and private, so duckdns.org and github.io count as suffixes). Without the
    file, the bundled shared-hosting and dynamic-DNS suffixes, with a warning (GATE["psl"])."""
    p = config.REF_DIR / "public_suffix_list.dat"
    out = set()
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("//"):
                out.add(line.lstrip("!*.").lower())
    except OSError:
        pass
    if not out:
        log.warning("no %s: the abuse.ch gate uses its bundled shared/dynamic-DNS suffixes", p.name)
        GATE["psl"] = "bundled fallback (ref/public_suffix_list.dat missing)"
        return BUNDLED_SUFFIXES
    GATE["psl"] = f"{p.name} ({len(out):,} entries)"
    return frozenset(out | BUNDLED_SUFFIXES)


def _registrable(d: str) -> str:
    """eTLD+1 of a name ('evil.duckdns.org' with the PSL; without it, the last two labels)."""
    labels = d.split(".")
    psl = _psl()
    for i in range(len(labels)):
        if ".".join(labels[i:]) in psl:
            return ".".join(labels[max(i - 1, 0):])
    return ".".join(labels[-2:])


def shared_domain(d: str) -> str | None:
    """The allowlisted (popular or shared-infrastructure) domain that owns d, else None. Only names at or below
    d's registrable domain count, so github.com, raw.githubusercontent.com and cdn.discordapp.com are shared, but
    evil.duckdns.org or x.github.io (separately registrable names under a public suffix) are not."""
    from . import allowlist
    allow = allowlist.domains()
    labels, reg = d.split("."), _registrable(d)
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in allow:
            return cand
        if cand == reg:
            break
    return None


GATE: dict = {"dropped": 0, "demoted": 0, "url_host_skipped": 0, "sample": [], "psl": None, "since": None}


def _gate(kind: str, value: str, direct: bool) -> tuple[str, str | None]:
    """Shared-infrastructure gate for abuse.ch addresses and names: ("keep" | "drop" | "demote", reason).

    Private, loopback, special-purpose addresses and public resolvers are never indicators. A big cloud/CDN/platform
    ASN is shared hosting: a direct IOC there is kept but demoted to reputation (medium), a URL's host there is not
    an indicator. A popular or shared domain (github.com, discordapp.com, the Tranco top list) is never one."""
    from . import allowlist
    try:
        if kind == "ip":
            why = allowlist.benign_ip(value)
            if not why:
                return "keep", None
            if why.startswith("AS") and direct:
                return "demote", why
            return "drop", why
        if kind == "domain":
            why = shared_domain(value)
            return ("drop", f"shared domain {why}") if why else ("keep", None)
    except Exception as e:  # the gate must never let an error through as "keep"
        return "drop", f"gate error: {type(e).__name__}"
    return "keep", None


def _note_gate(action: str, kind: str, value: str, why: str | None, source: str) -> None:
    key = {"drop": "dropped", "demote": "demoted", "host": "url_host_skipped"}[action]
    GATE[key] += 1
    GATE["since"] = GATE["since"] or util.now().isoformat()   # counters are per process, from this time
    if len(GATE["sample"]) < 20:
        GATE["sample"].append({"source": source, "kind": kind, "value": value, "action": action, "why": why,
                               "at": util.now().isoformat()})


def _abusech_values(source: str, key: str, data) -> list[tuple]:
    """(kind, value, meta, category) for one ThreatFox, URLhaus or SSLBL record, after the shared-infrastructure
    gate (_gate). okf/data/netlog.md#abusech"""
    out = []
    for kind, value, meta, cat in _abusech_raw(source, key, data):
        if kind in ("ip", "domain"):
            direct = not meta.get("from_url")
            act, why = _gate(kind, value, direct)
            if act == "drop":
                _note_gate("drop" if direct else "host", kind, value, why, source)
                continue
            if act == "demote" and cat in ("c2", "malware"):
                _note_gate("demote", kind, value, why, source)
                meta, cat = {**meta, "shared_hosting": why}, "reputation"
        elif kind == "url":
            hk = "ip" if ipnum.is_ip(value.split("/", 1)[0]) else "domain"
            if hk == "ip":   # a URL on a private or loopback address is never an indicator
                act, why = _gate("ip", value.split("/", 1)[0], True)
                if act == "drop":
                    _note_gate("drop", kind, value, why, source)
                    continue
        out.append((kind, value, meta, cat))
    return out


def _abusech_raw(source: str, key: str, data) -> list[tuple]:
    from ..sources import abusech as ab
    if not isinstance(data, dict):
        return []
    out: list[tuple] = []
    if source == "sslbl":
        sha1 = str(data.get("sha1") or key or "").lower()
        if re.fullmatch(r"[0-9a-f]{40}", sha1):
            first = ab.utc(data.get("listing_date"))
            out.append(("hash", sha1, {"malware": ab.sslbl_family(data.get("reason")), "reason": data.get("reason"),
                                       "hash_type": "sha1", "what": "TLS certificate",
                                       "first_seen": first.isoformat() if first else None}, "c2"))
        return out
    if source == "threatfox":
        ioc = ab.tf_ioc(data)
        if not ioc:
            return []
        tt = (data.get("threat_type") or "").lower()
        try:
            conf = int(data.get("confidence_level"))
        except (TypeError, ValueError):
            conf = 50
        first, last = ab.utc(data.get("first_seen")), ab.utc(data.get("last_seen"))
        # C2 at confidence 75+ is c2 (high; 50 is the community default, so it is not enough on its own); weaker C2
        # reports and delivery infrastructure are reputation (medium); a sample hash is malware (high on a download).
        cat = "malware" if "hash" in ioc["type"] else "c2" if tt == "botnet_cc" and conf >= C2_MIN_CONFIDENCE else "reputation"
        meta = {"malware": ab.tf_family(data), "malware_id": data.get("malware"), "threat_type": tt, "confidence": conf,
                "ioc_type": ioc["type"], "ioc_id": str(data.get("id")), "port": ioc.get("port"),
                "first_seen": first.isoformat() if first else None, "last_seen": last.isoformat() if last else None,
                "reference": f"https://threatfox.abuse.ch/ioc/{data.get('id')}/"}
        meta = {k: v for k, v in meta.items() if v not in (None, "")}
        if ioc["type"] == "ip:port":
            out.append(("ip", ioc["ip"], meta, cat))
        elif ioc["type"] == "domain":
            out.append(("domain", ioc["host"], meta, cat))
        elif ioc["type"] == "url":
            out.append(("url", ioc["url"], meta, cat))
            out.append((ioc["host_kind"], ioc["host"], {**meta, "from_url": True}, cat))
        else:
            out.append(("hash", ioc["hash"], {**meta, "hash_type": ioc["type"].replace("_hash", "")}, cat))
        return out
    if source == "urlhaus":
        nu = ab.norm_url(data.get("url"))
        if not nu or (data.get("url_status") or "").lower() == "offline":
            return []
        added = ab.utc(data.get("date_added") or data.get("dateadded"))
        meta = {"malware": ab.uh_family(data.get("tags")), "status": (data.get("url_status") or "unknown").lower(),
                "threat": data.get("threat"), "url_id": str(data.get("id")), "tags": ab._tags(data.get("tags"))[:8],
                "first_seen": added.isoformat() if added else None, "reference": data.get("urlhaus_reference")}
        meta = {k: v for k, v in meta.items() if v not in (None, "", [])}
        out.append(("url", nu[2], meta, "reputation"))
        out.append((nu[0], nu[1], {**meta, "from_url": True}, "reputation"))
        return out
    return []


def _closes(source: str, data) -> bool:
    """A put that ends the listing: URLhaus marks a URL offline (it no longer serves malware)."""
    return source == "urlhaus" and isinstance(data, dict) and (data.get("url_status") or "").lower() == "offline"


def _values(source: str, category: str, key: str, data) -> list[tuple[str, str, dict]]:
    """(kind, value, meta) for one provider record."""
    if source in ABUSECH:
        return _abusech_values(source, key, data)
    if category == "kev":
        return [("cve", key.upper(), {"name": (data or {}).get("vulnerabilityName")} if isinstance(data, dict) else {})] \
            if _CVE_RE.match(key or "") else []
    recs = data if isinstance(data, list) else [data]
    meta: dict = {}
    cands: list[str] = []
    for r in recs:
        if isinstance(r, dict):
            for f in ("ip_address", "ip", "cidr", "ioc", "ip_port", "value", "dst_ip", "address"):
                if r.get(f):
                    cands.append(str(r[f]))
            for f in ("malware", "status", "port", "sblid", "attacks", "firstseen", "first_seen", "last_online",
                      "as_name", "country", "rir", "threat_type"):
                if r.get(f) is not None:
                    meta[f] = r[f]
        elif isinstance(r, str):
            cands.append(r)
    cands.append(key or "")
    for c in cands:
        c = c.strip()
        v = c
        if c.count(":") == 1 and "." in c:          # "198.51.100.7:443"
            v = c.split(":", 1)[0]
        elif c.startswith("[") and "]:" in c:        # "[2001:db8::1]:443"
            v = c[1:c.index("]")]
        if "/" in v:
            r = ipnum.net_range(v)
            if r:
                return [("cidr", r[2], meta)]
        elif ipnum.is_ip(v):
            return [("ip", ipnum.canonical(v), meta)]
        elif category in DOMAIN_CATEGORIES and _DOMAIN_RE.match(v.lower().rstrip(".")):
            return [("domain", v.lower().rstrip("."), meta)]
    return []


def _ivk(key: str, kind: str, value: str, multi: bool) -> str:
    """Identity of an open interval: the record key, or for multi-indicator sources key + kind + value."""
    return f"{key}\x1f{kind}\x1f{value}" if multi else key


def _expires(source: str, kind: str, ts: dt.datetime, meta: dict) -> str | None:
    days = TTL_DAYS.get((source, kind))
    if not days:
        return None
    last = ts
    for f in ("last_seen", "first_seen"):
        try:
            t = dt.datetime.fromisoformat(str(meta.get(f))) if meta.get(f) else None
        except ValueError:
            t = None
        if t and t > last and t <= ts + dt.timedelta(days=1):   # a provider time in the future is not trusted
            last = t
    return (last + dt.timedelta(days=days)).isoformat()


def _provider_start(meta: dict, ts: dt.datetime) -> dt.datetime:
    """When the provider says the indicator was listed (ThreatFox first_seen, URLhaus date_added, SSLBL listing
    date), if that is before our record file: contacts in between are detections, not "historical"."""
    try:
        t = dt.datetime.fromisoformat(str(meta.get("first_seen"))) if meta.get("first_seen") else None
    except ValueError:
        t = None
    return t if t and t < ts else ts


def _replay(source: str, category: str, files: list[tuple[Path, dt.datetime]], open_iv: dict[str, dict]) -> tuple[list[dict], dict]:
    """Apply record files in order. Returns (closed intervals, still-open intervals by identity).

    Most lists give one indicator per record key. abuse.ch records can give several (a URL and its host), so
    their open intervals are tracked per (key, kind, value); a put that no longer yields one closes it.
    Windowed abuse.ch listings also end at their TTL (meta.expires), and a URLhaus URL ends when it goes offline."""
    closed: list[dict] = []
    multi = source in ABUSECH
    by_key: dict[str, set[str]] = {}
    for ik, iv in open_iv.items():
        by_key.setdefault(iv["key"], set()).add(ik)

    def close(ik: str, end, path):
        cur = open_iv.pop(ik, None)
        if cur is None:
            return
        by_key.get(cur["key"], set()).discard(ik)
        cur["end"], cur["end_path"] = end, path
        closed.append(cur)

    for path, ts in files:
        try:
            with gzip.open(path, "rt") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    key, op = str(rec.get("key")), rec.get("op")
                    if op == "put":
                        data = rec.get("data")
                        if multi and _closes(source, data):
                            for ik in list(by_key.get(key, ())):
                                close(ik, ts, str(path))
                            continue
                        vals = _values(source, category, key, data)
                        if not multi:
                            cur = open_iv.get(key)
                            if not vals:
                                continue
                            kind, value, meta = vals[0][:3]
                            if cur is None:
                                open_iv[key] = {"source": source, "kind": kind, "value": value, "start": ts, "end": None,
                                                "key": key, "category": category, "meta": meta,
                                                "start_path": str(path), "end_path": None}
                                by_key.setdefault(key, set()).add(key)
                            else:
                                cur["meta"] = meta or cur["meta"]
                            continue
                        want = {}
                        for v in vals:
                            kind, value, meta = v[:3]
                            want.setdefault(_ivk(key, kind, value, True), (kind, value, meta, v[3] if len(v) > 3 else category))
                        for ik in list(by_key.get(key, ())):
                            if ik not in want:           # the record no longer gives this indicator
                                close(ik, ts, str(path))
                        for ik, (kind, value, meta, cat) in want.items():
                            meta = dict(meta)
                            exp = _expires(source, kind, ts, meta)
                            if exp:
                                meta["expires"] = exp
                            cur = open_iv.get(ik)
                            start = _provider_start(meta, ts)   # the provider's own listing time, when earlier
                            if cur is not None and cur["meta"].get("expires") and \
                                    dt.datetime.fromisoformat(cur["meta"]["expires"]) <= ts:
                                close(ik, dt.datetime.fromisoformat(cur["meta"]["expires"]), None)   # lapsed
                                cur, start = None, ts   # a renewed listing starts now, after the lapsed one
                            if cur is None:
                                open_iv[ik] = {"source": source, "kind": kind, "value": value, "start": start, "end": None,
                                               "key": key, "category": cat, "meta": meta,
                                               "start_path": str(path), "end_path": None}
                                by_key.setdefault(key, set()).add(ik)
                            else:
                                cur["meta"], cur["category"] = meta, cat
                    elif op == "del":
                        for ik in list(by_key.get(key, ())):
                            close(ik, ts, str(path))
        except (OSError, EOFError) as e:
            log.warning("cannot read %s: %s", path, e)
    # windowed listings whose TTL has passed
    now = util.now()
    for ik, iv in list(open_iv.items()):
        exp = (iv.get("meta") or {}).get("expires")
        if exp and dt.datetime.fromisoformat(exp) <= now:
            close(ik, dt.datetime.fromisoformat(exp), None)
    return closed, open_iv


def _expire_open() -> dict[str, int]:
    """Close open TTL listings whose expiry has passed, even when no new record file arrived."""
    out = {}
    for source in sorted(TTL_SOURCES):
        n = db.query("""SELECT count(*) AS n FROM indicator_intervals WHERE source = ? AND "end" IS NULL
                        AND try_cast(json_extract_string(meta, '$.expires') AS TIMESTAMPTZ) <= now()""", [source])[0]["n"]
        if n:
            with db._write_lock:
                db.cursor().execute("""UPDATE indicator_intervals
                    SET "end" = try_cast(json_extract_string(meta, '$.expires') AS TIMESTAMPTZ)
                    WHERE source = ? AND "end" IS NULL
                      AND try_cast(json_extract_string(meta, '$.expires') AS TIMESTAMPTZ) <= now()""", [source])
            out[source] = int(n)
    return out


def _write(cur, rows: list[dict]) -> None:
    if not rows:
        return
    out = []
    for r in rows:
        if r["kind"] in ("ip", "cidr"):
            lo, hi, _ = ipnum.net_range(r["value"])
        else:
            lo = hi = None
        out.append({**r, "lo": None if lo is None else str(lo), "hi": None if hi is None else str(hi),
                    "meta": json.dumps(r.get("meta") or {}, default=str)})
    p = util.scratch("ti")
    util.write_ndjson(p, out)
    try:
        src = util.read_src(p, {"source": "VARCHAR", "kind": "VARCHAR", "value": "VARCHAR", "start": "TIMESTAMPTZ",
                                "end": "TIMESTAMPTZ", "key": "VARCHAR", "category": "VARCHAR", "lo": "VARCHAR",
                                "hi": "VARCHAR", "meta": "VARCHAR", "start_path": "VARCHAR", "end_path": "VARCHAR"})
        cur.execute(f"""INSERT INTO indicator_intervals SELECT source, kind, value, "start", "end", key, category,
                        lo::UHUGEINT, hi::UHUGEINT, meta, start_path, end_path FROM {src}""")
    finally:
        p.unlink(missing_ok=True)


def refresh(full: bool = False) -> dict:
    """Bring indicator_intervals up to date with the lake. Returns {source: files applied}; {} if unchanged."""
    with util.LOCK:
        changed: dict[str, int] = {}
        seen = {r["path"]: r for r in db.query("SELECT source, path FROM netlog_ti_files")}
        for source, category in _threat_sources().items():
            d = config.RAW_DIR / source
            if not d.is_dir():
                continue
            files = sorted((p, ts) for p in d.glob("*/*/*/*.records.ndjson.gz") if (ts := _file_ts(p)))
            files.sort(key=lambda t: t[1])
            new = [(p, ts) for p, ts in files if str(p) not in seen]
            if not new and not full:
                continue
            done = [ts for p, ts in files if str(p) in seen]
            rebuild = full or (done and new and min(ts for _, ts in new) < max(done))
            with db._write_lock:
                cur = db.cursor()
                if rebuild:
                    todo, open_iv = files, {}
                    cur.execute("DELETE FROM indicator_intervals WHERE source = ?", [source])
                    cur.execute("DELETE FROM netlog_ti_files WHERE source = ?", [source])
                else:
                    todo = new
                    open_iv = {_ivk(r["key"], r["kind"], r["value"], source in ABUSECH): {**r, "meta": json.loads(r["meta"] or "{}")}
                               for r in util.rows_of(cur,
                               """SELECT source, kind, value, "start", "end", key, category, meta, start_path, end_path
                                  FROM indicator_intervals WHERE source = ? AND "end" IS NULL""", [source])}
                closed, still = _replay(source, category, todo, open_iv)
                with db.tx(cur):
                    cur.execute('DELETE FROM indicator_intervals WHERE source = ? AND "end" IS NULL', [source])
                    _write(cur, closed + list(still.values()))
                    cur.executemany("INSERT OR REPLACE INTO netlog_ti_files VALUES (?, ?, ?, NULL, NULL)",
                                    [(source, str(p), ts) for p, ts in todo])
            changed[source] = len(todo)
        try:
            for source, n in _expire_open().items():
                changed[f"{source}_expired"] = n
        except Exception as e:
            _note_error("listing expiry", e)
        STATUS["last_refresh"] = util.now().isoformat()
        try:
            n_rep = _reported()
        except Exception as e:
            _note_error("reported IOCs", e)
            n_rep = 0
        if n_rep:
            changed["reported"] = n_rep
        if changed:
            log.info("indicator intervals updated: %s", changed)
        return changed


STATUS: dict = {"last_refresh": None, "errors": [], "reported": {"state": "not run"},
                "abusech_gate": GATE}   # abuse.ch indicators dropped or demoted by the shared-infrastructure gate


def _note_error(where: str, e: Exception) -> None:
    msg = f"{where}: {type(e).__name__}: {e}"[:400]
    log.warning("netlog threat intervals: %s", msg)
    STATUS["errors"] = (STATUS["errors"] + [{"at": util.now().isoformat(), "error": msg}])[-20:]


# Claims that make an address or domain an indicator: it is used by, talks to or hosts a threat.
# Descriptive claims (located_in, in-prefix, registered_to, ...) never do.
IOC_PREDICATES = {"uses", "communicates_with", "c2", "command_and_control", "hosts", "drops", "downloads_from",
                  "indicator_of", "indicates", "beacons_to", "exfiltrates_to", "delivers", "attributed_to"}
THREAT_TYPES = ("actor", "malware", "campaign", "tool", "intrusion_set", "intrusion-set")
IOC_ROLES = {"ioc", "indicator", "appendix", "defanged", "c2", "infrastructure"}
NON_REPORT_REFS = ("netlog",)
HALF_LIFE_DAYS = {"ip": 30, "cidr": 30, "url": 60, "domain": 120}   # okf/data/entities.md#scoring
EXPIRE_HALF_LIVES = 2                       # weight below 0.25: the report has expired
_IOC_HEADING = re.compile(r"(indicators?\s+of\s+compromise|\biocs?\b|\bappendix\b|network\s+indicators|"
                          r"\bc2\s+(servers?|domains?|infrastructure)|command[- ]and[- ]control\s+(servers?|domains?))", re.I)


def _refang(text: str) -> str:
    try:
        from ..entities.iocs import refang
        return refang(text)
    except Exception:
        t = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)", ".", text, flags=re.I)
        t = re.sub(r"\bhxxp", "http", t, flags=re.I)
        return re.sub(r"\[:\]|\[://\]", lambda m: m.group(0)[1:-1], t)


def _occurrences(text: str, value: str) -> list[int]:
    rx = re.compile(r"(?<![\w.\-])" + re.escape(value) + r"(?![\w\-]|\.\w)", re.I)
    return [m.start() for m in rx.finditer(text)]


def _article_context(text: str | None, value: str) -> str | None:
    """Why a text presents value as an indicator ("defanged", "ioc section", "ioc-dense paragraph"), else None.

    The text is refanged first (any subset of [.], (.), [dot], hxxp, [:]), so partial defanging counts and the
    heading and paragraph checks see the real value."""
    if not text:
        return None
    ref = _refang(text)
    pos = _occurrences(ref, value)
    if not pos:
        return None
    if len(pos) > len(_occurrences(text, value)):
        return "defanged"
    head = _IOC_HEADING.search(ref)
    if head and any(p > head.start() for p in pos):
        return "ioc section"
    try:
        from ..entities.extract import _is_appendix
        for p in pos:
            ps = ref.rfind("\n\n", 0, p) + 1
            pe = ref.find("\n\n", p)
            if _is_appendix(ref[ps: pe if pe > 0 else len(ref)]):
                return "ioc-dense paragraph"
    except Exception:
        pass
    return None


CORROBORATING = ("c2", "drop", "compromised", "reputation", "listed", "malware")


def _independent(items: list[tuple]) -> int:
    """Distinct original publishers: reports sharing a publisher or a story (syndicated copies, reprints
    of one vendor's list) are one source."""
    parent: dict = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for pub, story in items:
        a = find(("pub", pub))
        if story:
            parent[find(("story", story))] = a
    return len({find(("pub", pub)) for pub, _ in items})


_LAST_INPUT: dict = {}


def _reported() -> int:
    """IOCs reported in articles (osinthub.entities), conservatively. See okf/data/netlog.md#reported-iocs.

    * Only reports that present the value as an indicator count: a mention whose role is an IOC role, an
      article where the value is defanged, under an IOC/appendix heading or in an IOC-dense paragraph, or a
      reported claim tying it to an actor or malware. A domain merely named in an article does not.
    * Popular domains (Tranco top 20k and a built-in list) and benign infrastructure (public resolvers,
      big CDN/cloud ASNs, private ranges) are dropped.
    * One independent source: category `reported` (low). Two or more, or also on a threat list:
      `reported_corroborated` (medium). Never high.
    * Each interval ends two half-lives after the last report (IP 60 days, domain 240).
    Failures are logged and shown by GET /api/netlog/status.
    """
    import importlib.util
    from . import allowlist
    if importlib.util.find_spec("osinthub.entities") is None:
        STATUS["reported"] = {"state": "entities package not installed"}
        return 0
    tables = db.tables()
    if not {"entities", "mentions"} <= tables:
        STATUS["reported"] = {"state": "entities tables not created yet"}
        return 0
    try:
        sig_parts = [db.query("SELECT count(*) AS n, max(ts) AS t FROM mentions")[0]]
        if "claims" in tables:
            sig_parts.append(db.query("SELECT count(*) AS n, max(last_seen) AS t FROM claims")[0])
        if "articles" in tables:
            sig_parts.append(db.query("SELECT count(*) AS n, max(fetched_at) AS t FROM articles")[0])
        sig_parts.append({"tranco": allowlist.tranco_count(), "day": util.now().date().isoformat(),
                          "lists": db.query("SELECT count(*) AS n FROM indicator_intervals WHERE source <> 'reported'")[0]["n"]})
        input_sig = json.dumps(sig_parts, default=str)
    except Exception:
        input_sig = None
    if input_sig and input_sig == _LAST_INPUT.get("sig"):
        return 0   # nothing the loader reads has changed
    _LAST_INPUT["sig"] = input_sig
    counts: dict = {"candidates": 0, "not_indicator_context": 0, "allowlisted_domain": 0, "benign_infrastructure": 0,
                    "invalid": 0, "kept": 0, "corroborated": 0, "multi_source": 0, "expired": 0}
    reports: dict = {}   # (kind, value) -> {"key", "sources": {src: ts}, "how": set()}
    try:
        ments = db.query(f"""
            SELECT e.type AS kind, coalesce(e.name, split_part(e.id, ':', 2)) AS value, e.id AS key,
                   m.ref_type, m.ref_id, m.role, coalesce(m.ts, e.first_seen) AS ts
            FROM entities e JOIN mentions m ON m.entity_id = e.id
            WHERE e.type IN ('ip', 'domain', 'cidr') AND m.ref_type NOT IN {NON_REPORT_REFS}""")
        # Events from threat lists are already list intervals; events from news, advisories and social
        # sources are reports, judged on their title and summary text.
        list_sources = set(_threat_sources())
        evs = {}
        ev_ids = sorted({m["ref_id"] for m in ments if m["ref_type"] == "event"})
        for i in range(0, len(ev_ids), 500):
            chunk = ev_ids[i:i + 500]
            for r in db.query(f"""SELECT id, source, coalesce(title, '') || '\n\n' || coalesce(summary, '') AS text
                                  FROM events WHERE id IN ({','.join('?' * len(chunk))})""", chunk):
                evs[r["id"]] = r
        arts = {}
        if "articles" in tables:
            ids = sorted({m["ref_id"] for m in ments if m["ref_type"] == "article"})
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                for r in db.query(f"SELECT id, source, story_id, text FROM articles WHERE id IN ({','.join('?' * len(chunk))})", chunk):
                    arts[r["id"]] = r
        claims = []
        if "claims" in tables:  # one source per publisher listed in the claim
            claims = db.query(f"""
                WITH r AS (SELECT * FROM claims WHERE origin = 'reported'
                           AND lower(replace(predicate, '-', '_')) IN {tuple(sorted(IOC_PREDICATES))}),
                c AS (SELECT subj AS eid, sources, first_seen, last_seen FROM r
                       WHERE split_part(obj, ':', 1) IN {THREAT_TYPES}
                      UNION ALL SELECT obj, sources, first_seen, last_seen FROM r
                       WHERE split_part(subj, ':', 1) IN {THREAT_TYPES})
                SELECT split_part(eid, ':', 1) AS kind, substr(eid, length(split_part(eid, ':', 1)) + 2) AS value,
                       eid AS key, sources, first_seen, last_seen
                FROM c WHERE split_part(eid, ':', 1) IN ('ip', 'domain', 'cidr')""")
    except Exception as e:
        _note_error("reported IOCs", e)
        STATUS["reported"] = {"state": "error", "error": str(e)[:300]}
        return 0

    def add(kind, value, key, src, ts, how):
        if ts is None:
            return
        r = reports.setdefault((kind, str(value).lower().strip()),
                               {"key": key, "sources": {}, "how": set(), "last": ts, "items": []})
        pub, story = src if isinstance(src, tuple) else (src, None)
        r["sources"][pub] = min(r["sources"].get(pub, ts), ts)
        r["items"].append((pub, story))
        r["last"] = max(r["last"], ts)
        r["how"].add(how)

    counts["list_events"] = 0
    for m in ments:
        if m["ref_type"] == "event" and (evs.get(m["ref_id"]) or {}).get("source") in list_sources:
            counts["list_events"] += 1
            continue
        counts["candidates"] += 1
        how = None
        doc = arts.get(m["ref_id"]) if m["ref_type"] == "article" else evs.get(m["ref_id"]) if m["ref_type"] == "event" else None
        if (m["role"] or "").lower() in IOC_ROLES:
            how = f"role {m['role']}"
        elif doc:
            how = _article_context(doc.get("text"), str(m["value"]))
        if not how:
            counts["not_indicator_context"] += 1
            continue
        art = arts.get(m["ref_id"]) or evs.get(m["ref_id"]) or {}
        add(m["kind"], m["value"], m["key"], (art.get("source") or f"{m['ref_type']}:{m['ref_id']}", art.get("story_id")),
            m["ts"], how)
    for c in claims:
        counts["candidates"] += 1
        for src in (c["sources"] or ["claim"]):
            add(c["kind"], c["value"], c["key"], src, c["first_seen"], "reported claim")
            if c["last_seen"]:
                add(c["kind"], c["value"], c["key"], src, c["last_seen"], "reported claim")

    # Corroboration only by lists of malicious infrastructure; a Tor exit listing says nothing about malice.
    listed = {r["value"] for r in db.query(f"""SELECT DISTINCT value FROM indicator_intervals
        WHERE category IN {CORROBORATING} AND kind IN ('ip', 'cidr', 'domain')""")}
    tor = {r["value"] for r in db.query("SELECT DISTINCT value FROM indicator_intervals WHERE category = 'tor'")}
    now = util.now()
    out = []
    dropped: list = []
    for (kind, v), r in reports.items():
        if kind == "ip":
            if not ipnum.is_ip(v):
                counts["invalid"] += 1
                continue
            v = ipnum.canonical(v)
            why = allowlist.benign_ip(v)
        elif kind == "cidr":
            nr = ipnum.net_range(v)
            if not nr:
                counts["invalid"] += 1
                continue
            v = nr[2]
            why = allowlist.benign_cidr(v)
        else:
            v = v.rstrip(".")
            if not _DOMAIN_RE.match(v):
                counts["invalid"] += 1
                continue
            why = allowlist.benign_domain(v)
            if why:
                counts["allowlisted_domain"] += 1
                if len(dropped) < 20:
                    dropped.append({"value": v, "why": f"allowlisted ({why})"})
                continue
        if why:
            counts["benign_infrastructure"] += 1
            if len(dropped) < 20:
                dropped.append({"value": v, "why": why})
            continue
        n_src = _independent(r["items"])
        corroborated = v in listed
        if v in tor:
            cat = "reported_tor"
            counts["tor_exit"] = counts.get("tor_exit", 0) + 1
        else:
            cat = "reported_corroborated" if (corroborated or n_src >= 2) else "reported"
        start = min(r["sources"].values())
        end = r["last"] + dt.timedelta(days=HALF_LIFE_DAYS.get(kind, 60) * EXPIRE_HALF_LIVES)
        counts["kept"] += 1
        counts["corroborated"] += corroborated
        counts["multi_source"] += n_src >= 2
        counts["expired"] += end <= now
        out.append({"source": "reported", "kind": kind, "value": v, "start": start, "end": end if end <= now else None,
                    "key": r["key"], "category": cat,
                    "meta": {"sources": sorted(r["sources"]), "independent_sources": n_src, "corroborated_by_list": corroborated,
                             "context": sorted(r["how"]), "last_report": r["last"], "expires": end},
                    "start_path": None, "end_path": None})
    STATUS["reported"] = {"state": "ok", "at": util.now().isoformat(), "indicators": counts["kept"],
                          "active": counts["kept"] - counts["expired"], "counts": counts, "dropped_sample": dropped,
                          "tranco_domains": allowlist.tranco_count(),
                          "builtin_domains": len(allowlist.builtin_domains()), "allowlist_domains": len(allowlist.domains())}
    sig = sorted((o["value"], str(o["start"]), str(o["end"]), o["category"]) for o in out)
    prev = sorted((r["value"], str(r["start"]), str(r["end"]), r["category"]) for r in db.query(
        """SELECT value, "start", "end", category FROM indicator_intervals WHERE source = 'reported'"""))
    if sig == prev:
        return 0
    with db._write_lock:
        cur = db.cursor()
        cur.execute("DELETE FROM indicator_intervals WHERE source = 'reported'")
        _write(cur, out)
    return max(1, len(out))


def lookup_value(etype: str, value: str) -> tuple[str, str] | None:
    """An entity's (type, value) as indicator_intervals stores it: canonical IP, lower-case domain without a
    trailing dot, malware URL as host/path?query, lower-case hash; None for other types."""
    v = (value or "").strip()
    if etype == "ip":
        c = ipnum.canonical(v)
        return ("ip", c) if c else None
    if etype == "domain":
        return ("domain", v.lower().rstrip(".")) if v else None
    if etype == "url":
        from ..sources.abusech import norm_url
        nu = norm_url(_refang(v))
        return ("url", nu[2]) if nu else None
    if etype in ("hash", "md5", "sha1", "sha256"):
        return ("hash", v.lower()) if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", v) else None
    return None


def listed(pairs: list[tuple[str, str]]) -> dict[tuple[str, str], list[dict]]:
    """Which threat lists hold each (entity type, value), now or before: one entry per source with its category,
    whether it is listed now, the listing period and the malware family. Reported IOCs (our own article
    extraction) are left out, so this is independent corroboration. An IP inside a listed CIDR and a domain
    under a listed parent domain count. Used by story IoC tables and entity pages."""
    want = {}
    for et, v in pairs:
        k = lookup_value(et, v)
        if k:
            want.setdefault(k, []).append((et, v))
    out: dict[tuple[str, str], list[dict]] = {}
    if not want:
        return out
    exact = [list(k) for k in want]
    rows = db.query("""WITH w AS (SELECT unnest(?) AS kv), q AS (SELECT kv[1] AS kind, kv[2] AS value FROM w)
                       SELECT q.kind AS qkind, q.value AS qvalue, ii.source, ii.kind, ii.value, ii.category,
                              min(ii."start") AS first_listed, max(coalesce(ii."end", now())) AS last_listed,
                              bool_or(ii."end" IS NULL) AS active, any_value(json_extract_string(ii.meta, '$.malware')) AS malware,
                              any_value(json_extract_string(ii.meta, '$.list_name')) AS list_name
                       FROM q JOIN indicator_intervals ii ON ii.source <> 'reported' AND (
                            (ii.kind = q.kind AND ii.value = q.value)
                         OR (q.kind = 'domain' AND ii.kind = 'domain' AND ends_with(q.value, '.' || ii.value)))
                       GROUP BY ALL ORDER BY active DESC, ii.source""", [exact])
    cidr = [k for k in want if k[0] == "ip"]
    if cidr:
        nums = [[k[1], str(ipnum.ip_int(k[1]))] for k in cidr if ipnum.ip_int(k[1]) is not None]
        if nums:
            rows += db.query("""WITH w AS (SELECT unnest(?) AS kv), q AS (SELECT kv[1] AS value, kv[2]::UHUGEINT AS n FROM w)
                                SELECT 'ip' AS qkind, q.value AS qvalue, ii.source, ii.kind, ii.value, ii.category,
                                       min(ii."start") AS first_listed, max(coalesce(ii."end", now())) AS last_listed,
                                       bool_or(ii."end" IS NULL) AS active,
                                       any_value(json_extract_string(ii.meta, '$.malware')) AS malware,
                                       any_value(json_extract_string(ii.meta, '$.list_name')) AS list_name
                                FROM q JOIN indicator_intervals ii ON ii.kind = 'cidr' AND ii.source <> 'reported'
                                     AND q.n BETWEEN ii.lo AND ii.hi
                                GROUP BY ALL""", [nums])
    try:
        from ..sources import SOURCES as REG
    except Exception:
        REG = {}
    for r in rows:
        for orig in want.get((r["qkind"], r["qvalue"]), []):
            lst = out.setdefault(orig, [])
            if any(x["source"] == r["source"] and x["value"] == r["value"] for x in lst):
                continue
            own = r["source"].startswith("own:")   # your own lists (ownlists.py): tier U
            lst.append({"source": r["source"], "name": f"your list '{r['list_name']}'" if own and r.get("list_name")
                        else getattr(REG.get(r["source"]), "name", r["source"]),
                        "tier": "U" if own else TIERS.get(r["source"], "C"), "category": r["category"], "kind": r["kind"], "value": r["value"],
                        "active": bool(r["active"]), "first_listed": r["first_listed"],
                        "last_listed": None if r["active"] else r["last_listed"], "malware": r["malware"]})
    return out


def summary() -> list[dict]:
    return db.query("""SELECT source, category, kind, count(*) AS intervals,
                              count(*) FILTER (WHERE "end" IS NULL) AS active,
                              min("start") AS first, max(coalesce("end", "start")) AS last
                       FROM indicator_intervals GROUP BY ALL ORDER BY source""")

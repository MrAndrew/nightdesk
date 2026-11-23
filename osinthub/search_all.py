"""Global search: one query, grouped results from everything Night Desk keeps (GET /api/search).

    everything(q, per=5, only=None) -> {"q", "mode", "took_ms", "groups": [{id, label, total, more, items}]}

Groups are pluggable: ``register_group(id, label, fn, order)`` where ``fn(q, ctx) -> (items, total)``. Built in,
in order of usefulness to a home-lab owner: network incidents, devices, stories, articles, entities, CVEs, sources
and settings pages, notes, feed items. (The web client adds app commands; see web/js/core/search.js.) A group whose
best hit names the query exactly (an indicator, a device's IP or name, an entity's name, a CVE id) moves ahead of
groups without one, keeping that order among themselves.

Every item says why it matched: ``why = {"field": "Malware", "text": "QakBot"}`` (the field in words and the value
that matched), so the client can show and highlight it. ``exact`` marks a hit that names the query.

Works offline and without the AI helper: incidents, devices, stories, sources, settings and notes are keyword
matches; articles, entities, CVEs and feed items use the hybrid searchers in osinthub/search.py, which fall back to
keywords (``mode: "keyword"``) when no query embedding is available.

Notes: the built-in ``note`` group reads the ``notes`` table when the notes package has created it, and is empty
otherwise; the notes package may replace it with ``register_group("note", "Notes", fn, 70)``.
Contract: okf/architecture/web-client.md#global-search
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
import time
from collections.abc import Callable
from urllib.parse import quote

from . import apiutil, db, search

log = logging.getLogger("osinthub.search_all")

GroupFn = Callable[[str, "Ctx"], "tuple[list[dict], int]"]
GROUPS: dict[str, dict] = {}
PER_MAX = 50


def register_group(gid: str, label: str, fn: GroupFn, order: int = 50) -> None:
    """Add (or replace) a result group. fn(q, ctx) returns (items, total); items carry type, id, title, href or
    the fields the client opens them by, and why = {field, text}."""
    GROUPS[gid] = {"id": gid, "label": label, "fn": fn, "order": order}


# ------------------------------------------------------------------ query helpers
_WORD = re.compile(r"[^a-z0-9.:_/@-]+")
_HEX = re.compile(r"[^0-9a-f]")


def norm(s) -> str:
    """Lower-case, punctuation folded to spaces (keeping . : / @ - _ that live inside IPs, MACs and domains)."""
    return " " + _WORD.sub(" ", str(s or "").lower()).replace("-", " ").replace("_", " ").strip() + " "


class Ctx:
    """One query, parsed once and shared by every group (with a lazily computed query vector)."""

    def __init__(self, q: str, per: int):
        self.q = q.strip()
        self.per = per
        self.ql = self.q.lower()
        self.toks = [t for t in norm(self.q).split() if t]
        self.ip = _ip(self.q)
        self.mac = _mac(self.q)
        if self.mac:   # any MAC spelling (dashes, dots, bare) is one value, never its two-digit pieces
            self.toks = [self.mac]
        self.cve = self.q.upper() if re.fullmatch(r"CVE-\d{4}-\d{4,}", self.q, re.I) else None
        self.domain = self.ql if (not self.ip and re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", self.ql)) else None
        self._qvec, self._have_vec = None, False
        self.alt = _prefix_query(self)   # the query with each word's longer forms added ('log4j' -> 'log4j log4j2')
        self.device_hits: dict[str, dict] | None = None   # filled by the device group, read by incidents

    def qvec(self):
        if not self._have_vec:
            self._have_vec = True
            try:
                self._qvec = search.query_vector(self.q)
            except Exception:
                self._qvec = None
        return self._qvec

    def hit(self, text) -> bool:
        """Every query word appears in the text (word-folded), so 'living room tv' finds 'demo-living-room-tv'."""
        t = norm(text)
        return bool(self.toks) and all(w in t for w in self.toks)

    def equal(self, text) -> bool:
        return norm(text).strip() == " ".join(self.toks)


def _ip(q: str) -> str | None:
    try:
        return str(ipaddress.ip_address(q.strip().strip("[]")))
    except ValueError:
        return None


def _mac(q: str) -> str | None:
    h = _HEX.sub("", q.lower())
    if len(h) == 12 and re.fullmatch(r"[0-9a-f]{2}([:.\-]?[0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", q.strip().lower()):
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))
    return None


def _clip(s, n: int = 160) -> str:
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _around(text: str, words: list[str], n: int = 150) -> str:
    """A slice of text around the first query word, for the 'why' line."""
    s = re.sub(r"\s+", " ", str(text or "")).strip()
    lo = s.lower()
    at = min((p for p in (lo.find(w) for w in words) if p >= 0), default=-1)
    if at < 0 or len(s) <= n:
        return _clip(s, n)
    start = max(0, at - n // 3)
    out = s[start:start + n]
    return ("…" if start else "") + out + ("…" if start + n < len(s) else "")


def _table(name: str) -> bool:
    try:
        return db.has_table(name)
    except Exception:
        return False


_jsonable = apiutil.jsonable


# ------------------------------------------------------------------ devices
_dev_cache: dict = {"key": None, "rows": []}
_dev_lock = threading.Lock()


def _device_rows() -> list[dict]:
    """Every current device (merged-away ids folded into the device they joined), with what to call it and every
    address it has had. Cached until devices, labels or merges change."""
    from .netlog import devices as D
    D.ensure_tables()
    key = tuple(db.query("""SELECT (SELECT count(*) FROM devices) a, (SELECT max(last_seen) FROM devices) b,
        (SELECT count(*) FROM netlog_device_labels) c, (SELECT max(updated_at) FROM netlog_device_labels) d,
        (SELECT count(*) FROM netlog_device_merges) e, (SELECT count(*) FROM netlog_ipdev) f""")[0].values())
    with _dev_lock:
        if _dev_cache["key"] == key:
            return _dev_cache["rows"]
    resolve = D.merge_resolver()
    labels = D.labels()
    hist: dict[str, set] = {}
    for r in db.query("SELECT device, ip FROM netlog_ipdev"):
        hist.setdefault(resolve(r["device"]), set()).add(r["ip"])
    out = []
    for r in db.query("SELECT id, mac, ips, hostnames, evidence, last_seen FROM devices"):
        if resolve(r["id"]) != r["id"]:
            continue
        try:
            r["evidence"] = json.loads(r.get("evidence") or "{}")
        except ValueError:
            r["evidence"] = {}
        p = D.present(r, labels.get(r["id"]))
        ips = list(dict.fromkeys([*(r.get("ips") or []), *sorted(hist.get(r["id"], ()))]))
        mac = (r.get("mac") or (r["id"][4:] if r["id"].startswith("mac:") else "") or "").lower()
        out.append({"id": r["id"], "name": p["name"], "name_source": p["name_source"], "type": p.get("type"),
                    "owner": p.get("owner"), "note": p.get("note"), "label": (p.get("label") or {}).get("name"),
                    "ips": ips, "mac": mac, "hostnames": r.get("hostnames") or [],
                    "vendor": (p.get("naming") or {}).get("vendor"), "fragment": p.get("fragment"),
                    "last_seen": _jsonable(r.get("last_seen"))})
    with _dev_lock:
        _dev_cache.update(key=key, rows=out)
    return out


def _match_device(d: dict, c: Ctx) -> tuple[float, str, str, bool] | None:
    """(score, field, value, exact) for the best field of a device that matches the query, or None."""
    if c.ip:
        for ip in d["ips"]:
            if ip == c.ip:
                return 1.0, "IP address", ip, True
    if c.mac and d["mac"] == c.mac:
        return 1.0, "MAC address", d["mac"], True
    fields = [("Your name" if d["name_source"] == "you" else "Name", d["name"], 0.9),
              ("Owner", d["owner"], 0.75), ("Type", d["type"], 0.55), ("Your note", d["note"], 0.6)]
    fields += [("Name you gave it", d["label"], 0.9)] if d["label"] and d["label"] != d["name"] else []
    fields += [("Hostname", h, 0.7) for h in d["hostnames"][:20]]
    fields += [("Maker", d["vendor"], 0.5)] if d["vendor"] else []
    best = None
    for field, val, w in fields:
        if not val:
            continue
        if c.equal(val):
            s = (w + 0.1, field, str(val), True)
        elif c.hit(val):
            s = (w, field, str(val), False)
        else:
            continue
        if best is None or s[0] > best[0]:
            best = s
    if best:
        return best
    if len(c.ql) >= 3:   # part of an address: '10.86.24' or a MAC prefix
        for ip in d["ips"]:
            if ip.startswith(c.ql) or (len(c.ql) >= 6 and c.ql in ip):
                return 0.45, "IP address", ip, False
        if d["mac"] and len(_HEX.sub("", c.ql)) >= 4 and re.fullmatch(r"[0-9a-f:.\-]+", c.ql) and \
                _HEX.sub("", c.ql) in _HEX.sub("", d["mac"]):
            return 0.45, "MAC address", d["mac"], False
    return None


def devices_group(q: str, c: Ctx) -> tuple[list[dict], int]:
    hits = []
    for d in _device_rows():
        m = _match_device(d, c)
        if m:
            hits.append((m, d))
    hits.sort(key=lambda x: (-x[0][0], bool(x[1]["fragment"]), str(x[1]["name"]).lower()))
    c.device_hits = {d["id"]: {"name": d["name"], "field": m[1], "value": m[2], "exact": m[3]} for m, d in hits}
    items = []
    for (score, field, val, exact), d in hits[: c.per]:
        sub = [x for x in (d["type"], d["owner"] and f"owner {d['owner']}", d["ips"][0] if d["ips"] else None) if x]
        items.append({"type": "device", "id": d["id"], "title": d["name"], "sub": " · ".join(sub),
                      "href": f"#network/devices/{quote(d['id'], safe=':')}", "score": round(score, 3), "exact": exact,
                      "why": {"field": field, "text": val}, "last_seen": d["last_seen"], "fragment": bool(d["fragment"])})
    return items, len(hits)


# ------------------------------------------------------------------ network incidents
_SEVR = {"high": 3, "medium": 2, "low": 1, "info": 0}
_EV_KEYS = ("indicator", "device", "sample", "also_listed", "rule", "state", "sinkhole", "capped", "original_severity")


def _leaf(ev, c: Ctx, path: str = "") -> tuple[str, str] | None:
    """The first string in the evidence that holds the query, as (key, value)."""
    if isinstance(ev, dict):
        for k, v in ev.items():
            r = _leaf(v, c, k)
            if r:
                return r
    elif isinstance(ev, list):
        for v in ev[:50]:
            r = _leaf(v, c, path)
            if r:
                return r
    elif isinstance(ev, (str, int, float)) and not isinstance(ev, bool):
        s = str(ev)
        if (c.ip and s == c.ip) or c.hit(s):
            return path, s
    return None


_EV_FIELD = {"malware": "Malware", "observed": "Seen in your logs", "hostnames": "Hostname", "home_ips": "Home address",
             "query": "DNS lookup", "server_name": "Server name", "sources": "Reported by", "name": "Device",
             "resp_h": "Address", "orig_h": "Address", "category": "Kind", "list_name": "Your list", "signature": "Signature"}


def _alert_match(a: dict, c: Ctx) -> tuple[float, str, str, bool] | None:
    ev = a["evidence"]
    ind = a.get("indicator") or ""
    meta = ((ev.get("indicator") or {}).get("meta") or {}) if isinstance(ev, dict) else {}
    observed = ((ev.get("indicator") or {}).get("observed") or []) if isinstance(ev, dict) else []
    mw = meta.get("malware")
    if mw and c.equal(mw):
        return 1.0, "Malware", str(mw), True
    if ind and (c.ql == ind.lower() or (c.ip and c.ip == ind)):
        return 1.0, "Indicator", ind, True
    for o in observed:
        if (c.ip and str(o) == c.ip) or c.ql == str(o).lower():
            return 0.98, "Seen in your logs", str(o), True
    dh = (c.device_hits or {}).get(a.get("device") or "")
    if dh:
        return (0.95 if dh["exact"] else 0.8), "Device", dh["name"] + (f" · {dh['field']} {dh['value']}" if dh["value"] != dh["name"] else ""), dh["exact"]
    if mw and c.hit(mw):
        return 0.9, "Malware", str(mw), False
    if ind and c.hit(ind):
        return 0.85, "Indicator", ind, False
    if c.hit(a.get("title")):
        return 0.7, "Alert", _around(a["title"], c.toks), False
    lf = _leaf(ev, c)
    if lf:
        return 0.5, _EV_FIELD.get(lf[0], "Evidence"), _clip(lf[1], 120), False
    if c.ip and c.ip in json.dumps(ev):
        return 0.5, "Evidence", c.ip, False
    return None


def incidents_group(q: str, c: Ctx) -> tuple[list[dict], int]:
    from .netlog import incidents as I
    I.ensure()
    if c.device_hits is None:   # the device group did not run (only=incident): work out device hits here
        cc = Ctx(q, PER_MAX)
        devices_group(q, cc)
        c.device_hits = cc.device_hits
    toks = c.toks or [c.ql]
    hay = "lower(concat_ws(' ', title, indicator, device, CAST(evidence AS VARCHAR)))"
    conds = " AND ".join(f"contains({hay}, ?)" for _ in toks)
    devs = list(c.device_hits or {})
    rows = db.query(f"""SELECT id, coalesce(incident, id) AS inc, device, indicator, title, evidence FROM alerts
                        WHERE ({conds}) OR list_contains(?::VARCHAR[], device)""", [*toks, devs])
    best: dict[str, tuple] = {}
    for a in rows:
        try:
            a["evidence"] = json.loads(a["evidence"] or "{}")
        except (TypeError, ValueError):
            a["evidence"] = {}
        m = _alert_match(a, c)
        if m and (a["inc"] not in best or m[0] > best[a["inc"]][0]):
            best[a["inc"]] = m
    if not best:
        return [], 0
    inc = db.query(I.incidents_sql("WHERE coalesce(incident, id) IN (SELECT unnest(?::VARCHAR[]))"), [list(best)])
    for r in inc:
        try:
            r["evidence"] = json.loads(r["evidence"] or "{}")
        except (TypeError, ValueError):
            r["evidence"] = {}
    try:
        from .netlog.api import _name_alerts
        _name_alerts(inc)
    except Exception:
        pass
    open_first = {"new": 0, "ack": 1, "expected": 2, "dismissed": 3}
    inc.sort(key=lambda r: str(r["last_ts"]), reverse=True)   # most recent first among equals (the sort below is stable)
    inc.sort(key=lambda r: (-best.get(r["inc"], (0,))[0], open_first.get(r["state"], 4), -_SEVR.get(r["severity"], 0)))
    items = []
    for r in inc[: c.per]:
        score, field, val, exact = best.get(r["inc"], (0, "", "", False))
        ev = r["evidence"] if isinstance(r["evidence"], dict) else {}
        ev = {k: ev[k] for k in _EV_KEYS if k in ev}
        if isinstance(ev.get("sample"), list):
            ev["sample"] = ev["sample"][:3]
        items.append(_jsonable({
            "type": "incident", "id": r["id"], "title": r.get("title") or r.get("indicator"), "href": f"#network/alerts/{quote(r['id'], safe='')}",
            "score": round(score, 3), "exact": exact, "why": {"field": field, "text": val},
            "severity": r["severity"], "state": r["state"], "demo": bool(r["demo"]), "kind": r["kind"],
            "device": r["device"], "device_name": r.get("device_name"), "indicator": r["indicator"], "source": r["source"],
            "rule": r["rule"], "direction": r["direction"], "evidence": ev, "ts": r["ts"], "last_ts": r["last_ts"],
            "days": r["days"], "n_alerts": r["n_alerts"]}))
    return items, len(inc)


# ------------------------------------------------------------------ stories
_story_cache: dict = {"key": None, "docs": {}}
_story_lock = threading.Lock()


def _story_docs() -> dict:
    key = tuple(db.query("SELECT count(*) n, max(updated_at) u FROM stories")[0].values())
    with _story_lock:
        if _story_cache["key"] == key:
            return _story_cache["docs"]
    docs = {}
    for r in db.query("SELECT id, title, summary, last_seen, article_count, source_count, sources FROM stories"):
        docs[r["id"]] = {"fields": {"title": r["title"] or "", "body": f"{r['summary'] or ''} {' '.join(r['sources'] or [])}"},
                         "title": r["title"] or "", "summary": r["summary"] or "", "last_seen": _jsonable(r["last_seen"]),
                         "articles": r["article_count"], "outlets": r["source_count"]}
    with _story_lock:
        _story_cache.update(key=key, docs=docs)
    return docs


def stories_group(q: str, c: Ctx) -> tuple[list[dict], int]:
    docs = _story_docs()
    if not docs:
        return [], 0
    hits = [(i, sc) for i, sc in search.keyword_index("story", docs).search(q, PER_MAX)
            if _keep(c, {}, docs[i]["title"], docs[i]["fields"]["body"])]
    items = []
    for sid, s in hits[: c.per]:
        d = docs[sid]
        in_title = c.hit(d["title"])
        items.append({"type": "story", "id": sid, "title": d["title"], "href": f"#news/story/{quote(sid, safe='')}",
                      "score": round(s, 3), "exact": c.equal(d["title"]),
                      "why": {"field": "Headline", "text": d["title"]} if in_title else {"field": "Summary", "text": _around(d["summary"], c.toks)},
                      "sub": f"{d['articles'] or 0} article{'s' if (d['articles'] or 0) != 1 else ''} · {d['outlets'] or 0} outlet{'s' if (d['outlets'] or 0) != 1 else ''}",
                      "ts": d["last_seen"]})
    return items, len(hits)


# ------------------------------------------------------------------ hybrid searchers (articles, entities, CVEs, feed items)
def _words(text) -> list[str]:
    return re.findall(r"[a-z0-9]+", str(text or "").lower())


def _tier(c: Ctx, text) -> int:
    """0: every query word is a word of the name or title; 1: each starts one (a prefix, 'log4j' in 'Log4j2');
    2: neither (the hit is in the body or by meaning)."""
    qw, ww = _words(c.ql), _words(text)
    if not qw or not ww:
        return 2
    if all(w in ww for w in qw):
        return 0
    return 1 if all(any(x.startswith(w) for x in ww) for w in qw) else 2


def _search_type(t: str, q: str, c: Ctx, k: int) -> list[dict]:
    if t == "entity":
        return _entity_rows(q, c, k)
    from . import ext
    ext.load_all()
    fn = search.SEARCHERS.get(t)
    return fn(q, c.qvec(), k) if fn else []


def _semantic(t: str, q: str, c: Ctx, k: int, name=lambda r: r.get("title")) -> list[dict]:
    """A hybrid searcher's hits, plus the hits for the query's longer word forms (ranked after them), then
    ordered by how well the name or title holds the query: whole words, then word prefixes, then the rest."""
    out = _search_type(t, q, c, k)
    if c.alt and c.alt != q:
        have = {r["id"] for r in out}
        for r in _search_type(t, c.alt, c, k):
            if r["id"] not in have:
                r["score"] = round(float(r.get("score") or 0) * 0.9, 4)
                r["prefix"] = True
                out.append(r)
    mode = "hybrid" if c.qvec() is not None else "keyword"
    for r in out:
        r.setdefault("mode", mode)
    out.sort(key=lambda r: _tier(c, name(r)))   # stable: the searcher's order inside each tier
    return out[:k]


# ------------------------------------------------------------------ entity index, refreshed in the background
_ent: dict = {"good": None, "checked": 0.0, "busy": False}
_ent_lock = threading.Lock()


def _entity_snapshot(build: bool = False):
    """The entity corpus with its keyword index ready. A merge or new entities rebuild it in a background
    thread; until that finishes, searches use the last complete one (merged ids still resolve through
    overrides.resolve), so nobody waits seconds for the rebuild."""
    from .entities import searcher as S

    def refresh():
        try:
            c = S.corpus()
            snap = dict(c)
            snap["bm"] = f"entity@{id(c['docs'])}"
            search.keyword_index(snap["bm"], snap["docs"])
            old = _ent["good"]
            _ent["good"] = snap
            if old and old["bm"] != snap["bm"]:
                search._bm25.pop(old["bm"], None)
        finally:
            _ent["busy"] = False

    if _ent["good"] is None or build:
        with _ent_lock:
            if _ent["good"] is None or build:
                _ent["busy"] = True
                refresh()
        return _ent["good"]
    now = time.time()
    if now - _ent["checked"] > 5 and not _ent["busy"]:
        _ent["checked"], _ent["busy"] = now, True
        threading.Thread(target=refresh, name="search-entity-refresh", daemon=True).start()
    return _ent["good"]


def _entity_rows(q: str, c: Ctx, k: int) -> list[dict]:
    from .entities.searcher import exact_ids
    snap = _entity_snapshot()
    docs = snap["docs"]
    out = []
    for i, sc, cos, kw in search.hybrid(snap["bm"], docs, "entities", q, c.qvec(), k, lambda qs: exact_ids(snap, qs)):
        d = docs[i]
        out.append({"type": "entity", "id": i, "title": d["title"], "score": round(sc, 4), "snippet": d["snippet"],
                    "match": {"vector": cos, "keyword": round(kw, 3)}})
    return out


def _keep(c: Ctx, r: dict, *texts) -> bool:
    """Keyword hits must hold the whole query: every word of a multi-word query, or the literal value of an IP,
    MAC, CVE, domain or hash (BM25 alone would match '02:4e:44:…' to any text with '44' in it). Hits found by
    meaning (the AI helper's vectors) are kept as they are."""
    if (r.get("match") or {}).get("vector") is not None:
        return True
    hay = " ".join(str(t or "") for t in texts)
    if c.ip or c.mac or c.cve or c.domain or re.fullmatch(r"[0-9a-f]{32,64}", c.ql):
        return (c.mac or c.ql) in hay.lower()
    if len(c.toks) >= 2:
        return c.hit(hay)
    return True


def _why_text(c: Ctx, title: str, body: str, title_field: str, body_field: str, r: dict) -> dict:
    if c.hit(title):
        return {"field": title_field, "text": title}
    if body and any(w in norm(body) for w in c.toks):
        return {"field": body_field, "text": _around(body, c.toks)}
    if (r.get("match") or {}).get("vector") is not None or r.get("mode") == "hybrid":
        return {"field": "By meaning", "text": _clip(body or title, 140)}
    return {"field": body_field, "text": _clip(body or title, 140)}


def articles_group(q: str, c: Ctx) -> tuple[list[dict], int]:
    rows = [r for r in _semantic("article", q, c, PER_MAX) if _keep(c, r, r.get("title"), r.get("snippet"))]
    items = []
    for r in rows[: c.per]:
        items.append({"type": "article", "id": r["id"], "title": r.get("title") or r["id"], "href": f"#news/article/{quote(str(r['id']), safe='')}",
                      "score": r.get("score"), "exact": False, "mode": r.get("mode"),
                      "why": _why_text(c, r.get("title") or "", r.get("snippet") or "", "Headline", "Text", r),
                      "source": r.get("source"), "tier": r.get("tier"), "ts": r.get("published")})
    return items, len(rows)


def _probe_ids(c: Ctx) -> list[str]:
    if c.ip:
        return [f"ip:{c.ip}"]
    if c.domain:
        return [f"domain:{c.domain}"]
    if c.cve:
        return [f"cve:{c.cve.lower()}"]
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", c.ql):
        return [f"hash:{c.ql}"]
    if ":" in c.ql and re.fullmatch(r"[a-z]+:\S+", c.ql):
        return [c.ql]
    return []


def _aka_name(docs: dict, r: dict) -> str:
    text = (docs.get(r["id"]) or {}).get("text") or ""
    return f"{r.get('title') or ''} {text.split(' aka ', 1)[1].split('. ', 1)[0] if ' aka ' in text else ''}"


def entities_group(q: str, c: Ctx) -> tuple[list[dict], int]:
    from .entities import overrides
    docs = _entity_snapshot()["docs"]
    rows = [r for r in _semantic("entity", q, c, PER_MAX, lambda r: _aka_name(docs, r))
            if _keep(c, r, r["id"], r.get("title"), (docs.get(r["id"]) or {}).get("text"), r.get("snippet"))]
    probes = []
    for pid in _probe_ids(c):
        rid = overrides.resolve(pid)
        if rid in docs and not any(overrides.resolve(r["id"]) == rid for r in rows):
            probes.append({"type": "entity", "id": rid, "title": docs[rid]["title"], "score": 1.0, "snippet": docs[rid]["snippet"]})
    seen, items, total = set(), [], 0
    for r in probes + rows:
        rid = overrides.resolve(r["id"])   # merged entities answer under the id they live under now
        if rid in seen:
            continue
        seen.add(rid)
        total += 1
        if len(items) >= c.per:
            continue
        d = docs.get(rid) or {}
        title = d.get("title") or r.get("title") or rid
        name_hit = c.equal(title) or c.ql == rid
        text = d.get("text") or ""
        aka = text.split(" aka ", 1)[1].split(". ", 1)[0] if " aka " in text else ""
        if name_hit or c.hit(title):
            why = {"field": "Name", "text": title}
        elif aka and c.hit(aka):
            alias = next((a for a in aka.split(", ") if c.hit(a)), aka)
            why = {"field": "Also known as", "text": alias}
        elif c.ql in rid.lower():
            why = {"field": "Value", "text": rid.split(":", 1)[-1]}
        else:
            snip = d.get("snippet") or r.get("snippet") or ""
            why = (_why_text(c, "", snip, "Name", "Description", r) if not re.fullmatch(r"[a-z]+:\S+", snip)
                   else {"field": "Name", "text": title})
        if rid != r["id"]:
            why = {**why, "merged_from": r["id"]}
        typ = rid.split(":", 1)[0]
        items.append({"type": "entity", "id": rid, "title": title, "entity_type": typ, "href": f"#entities/{quote(rid, safe=':')}",
                      "score": r.get("score"), "exact": bool(name_hit or r in probes or (aka and any(c.equal(a) for a in aka.split(", ")))),
                      "mode": r.get("mode"), "why": why, "mentions": d.get("mentions")})
    return items, total


def cves_group(q: str, c: Ctx) -> tuple[list[dict], int]:
    rows = [r for r in _semantic("cve", q, c, PER_MAX) if _keep(c, r, r["id"], r.get("title"), r.get("snippet"))]
    items = []
    for r in rows[: c.per]:
        title = re.sub(r"^CVE-\d+-\d+\s*·\s*", "", str(r.get("title") or ""))
        exact = bool(c.cve and c.cve == str(r["id"]).upper())
        why = {"field": "CVE id", "text": r["id"]} if exact else _why_text(c, title, r.get("snippet") or "", "Product", "Description", r)
        items.append({"type": "cve", "id": r["id"], "title": title or r["id"], "href": f"#entities/cve:{str(r['id']).lower()}",
                      "score": r.get("score"), "exact": exact, "mode": r.get("mode"), "why": why,
                      "kev": r.get("kev"), "cvss": r.get("cvss"), "epss": r.get("epss"), "epss_percentile": r.get("epss_percentile")})
    return items, len(rows)


def events_group(q: str, c: Ctx) -> tuple[list[dict], int]:
    rows = [r for r in _semantic("event", q, c, PER_MAX) if _keep(c, r, r.get("title"), r.get("snippet"))]
    items = []
    for r in rows[: c.per]:
        items.append({"type": "event", "id": r["id"], "title": r.get("title") or r["id"], "score": r.get("score"), "exact": False,
                      "mode": r.get("mode"), "why": _why_text(c, r.get("title") or "", r.get("snippet") or "", "Title", "Details", r),
                      "source": r.get("source"), "kind": r.get("kind"), "ts": r.get("ts")})
    return items, len(rows)


# ------------------------------------------------------------------ sources and settings pages
# Settings pages and the headings inside them (web/js/views/settings/*.js). `anchor` is the heading the client
# scrolls to; `words` are other words people use for it.
SETTINGS_PAGES = [
    ("sources", "Sources", None, "Choose your sources, turn them on or off, source health and what runs behind the scenes", "feeds feed pipeline health enable disable choose"),
    ("sources", "Sources", "Choose your sources", "The one-time choice of what Night Desk fetches", "first run choose onboarding"),
    ("home", "Home network", None, "Which addresses are yours, stale logs, silent devices", "network lan"),
    ("home", "Home network", "Home prefixes", "Addresses inside these prefixes are yours: outbound or inbound", "prefix prefixes subnet cidr ipv6 ipv4 home range addresses"),
    ("home", "Home network", "When logs count as stale", "How old logs may get before Night Desk says so", "stale freshness old late"),
    ("home", "Home network", "Silent devices", "How long a log sender may stay quiet before an alert", "silent sensor quiet sender"),
    ("home", "Home network", "Expected traffic", "Rules that hide traffic you expect", "expected rules suppress allow ignore mute"),
    ("data", "Data and retention", None, "Where the data lives, how big it is, and how long it is kept", "data storage lake disk size"),
    ("data", "Data and retention", "Where it lives", "The folder on this machine that holds everything", "folder path lake disk location"),
    ("data", "Data and retention", "Retention", "How long Night Desk keeps events and logs (nothing is deleted unless you set a limit)", "retention keep delete purge days limit"),
    ("data", "Data and retention", "Bring your own data", "Upload files and logs of your own", "upload import own data files"),
    ("display", "Display", None, "What Night Desk opens on and how it moves", "display look appearance"),
    ("display", "Display", "Open Night Desk on", "The page Night Desk opens on", "landing start home page default view"),
    ("display", "Display", "Motion", "Reduce animation", "motion animation reduce"),
    ("notifications", "Notifications", None, "Alerts sent outside Night Desk", "notify notifications push email"),
    ("about", "About", None, "Version, licences and credits", "about version licence license credits"),
]


def sources_group(q: str, c: Ctx) -> tuple[list[dict], int]:
    hits = []
    try:
        from .sources import SOURCES
        srcs = list(SOURCES.values())
    except Exception:
        srcs = []
    for s in srcs:
        d = s.describe()
        best = None
        for field, val, w in (("Source", d.get("name"), 0.95), ("Provider", d.get("provider"), 0.85), ("Source id", d.get("id"), 0.8),
                              ("Kind", d.get("category"), 0.4), ("About", d.get("description"), 0.5)):
            if val and (c.equal(val) or c.hit(val)):
                sc = (w + (0.05 if c.equal(val) else 0), field, _around(val, c.toks, 140) if field == "About" else str(val), c.equal(val))
                if best is None or sc[0] > best[0]:
                    best = sc
        if best:
            hits.append((best, {"type": "source", "id": d["id"], "title": d.get("name") or d["id"],
                                "sub": f"Source · {d.get('provider') or ''}".strip(" ·"),
                                "href": "#settings/sources", "target": d["id"]}))
    for sec, label, anchor, about, words in SETTINGS_PAGES:
        title = f"{label} › {anchor}" if anchor else label
        best = None
        # a heading row matches on its own words; the page's name finds the page row
        fields = (("Setting", anchor, 0.9), ("About", about, 0.55), ("Also called", words, 0.6)) if anchor else \
            (("Settings page", label, 0.85), ("About", about, 0.55), ("Also called", words, 0.6))
        for field, val, w in fields:
            if val and (c.equal(val) or c.hit(val)):
                if field == "Also called":   # a word people use for it: show the setting's own name
                    sc = (w, "Setting", anchor or label, False)
                else:
                    sc = (w + (0.05 if c.equal(val) else 0), field, _around(val, c.toks, 120) if field == "About" else str(val), c.equal(val))
                if best is None or sc[0] > best[0]:
                    best = sc
        if best:
            hits.append((best, {"type": "setting", "id": f"{sec}/{anchor or ''}", "title": title, "sub": f"Settings · {about}",
                                "href": f"#settings/{sec}", "anchor": anchor}))
    hits.sort(key=lambda x: (-x[0][0], x[1]["title"]))
    items = [{**it, "score": round(m[0], 3), "exact": m[3], "why": {"field": m[1], "text": m[2]}} for m, it in hits[: c.per]]
    return items, len(hits)


# ------------------------------------------------------------------ notes
_NOTE_ON = {"incident": "a network incident", "entity": "an entity", "story": "a story", "article": "an article"}


def notes_group(q: str, c: Ctx) -> tuple[list[dict], int]:
    if not _table("notes"):
        return [], 0
    toks = c.toks or [c.ql]
    hay = "lower(coalesce(title, '') || ' ' || body)"
    # incident notes are matched on their incident's title as it reads now (a renamed device), not only the stored one
    rows = db.query(f"""SELECT id, kind, item, title, body, updated_at FROM notes
                        WHERE ({' AND '.join(f'contains({hay}, ?)' for _ in toks)}) OR kind = 'incident'
                        ORDER BY updated_at DESC""", toks)
    now: dict = {}
    try:
        from .notes.store import incidents_now
        now = incidents_now([r["item"] for r in rows if r["kind"] == "incident"])
    except Exception:
        pass
    keep = []
    for r in rows:
        inc = now.get(r["item"]) if r["kind"] == "incident" else None
        cur = " ".join(str(inc.get(k) or "") for k in ("title", "device_name", "indicator")) if inc else ""
        text = f"{r['title'] or ''} {cur} {r['body']}".lower()
        if all(w in text for w in toks):
            if inc:
                r["incident"], r["title"] = inc, inc["title"] or r["title"]
            keep.append(r)
    rows = keep
    items = []
    # notes.store is always importable: disabling the notes extension skips its ext.py, not the module.
    from .notes.store import href as note_href
    for r in rows[: c.per]:
        in_body = any(w in str(r["body"]).lower() for w in toks)
        link = note_href(r["kind"], str(r["item"]))
        items.append({"type": "note", "id": r["id"], "title": r["title"] or f"Your note on {_NOTE_ON.get(r['kind'], 'an item')}", "kind": r["kind"],
                      "href": link, **({"incident": r["incident"]} if r.get("incident") else {}),
                      "score": 0.7, "exact": False, "ts": _jsonable(r["updated_at"]),
                      # a match on the title: the title shows it already, so the line says what the note is on
                      "why": {"field": "Your note", "text": _around(re.sub(r"[*_`#>]+", "", r["body"]), toks, 140)} if in_body
                      else {"field": "Note on", "text": _NOTE_ON.get(r["kind"], "an item")}})
    return items, len(rows)


register_group("incident", "Network incidents", incidents_group, 10)
register_group("device", "Devices", devices_group, 20)
register_group("story", "Stories", stories_group, 30)
register_group("article", "Articles", articles_group, 35)
register_group("entity", "Entities", entities_group, 40)
register_group("cve", "CVEs and exploited flaws", cves_group, 50)
register_group("source", "Sources and settings", sources_group, 60)
register_group("note", "Notes", notes_group, 70)
register_group("event", "Source items", events_group, 80)


# ------------------------------------------------------------------ word list: longer forms and close spellings
_voc: dict = {"key": None, "count": None, "sorted": [], "bylen": {}, "busy": False}
_voc_lock = threading.Lock()
_VOC_RE = re.compile(r"[a-z][a-z0-9]{2,}|[0-9][a-z0-9]*[a-z][a-z0-9]*")


def _voc_key():
    try:
        from .ai import docs as D
        cve = id(D._cache.get("docs"))
    except Exception:
        cve = None
    try:
        from .news import search as N
        news = id(N._index)
    except Exception:
        news = None
    return ((_ent["good"] or {}).get("bm"), cve, news, _story_cache["key"], _dev_cache["key"])


def _build_vocab() -> None:
    from collections import Counter
    cnt: Counter = Counter()

    def add(text, w: int = 1):
        for t in _VOC_RE.findall(str(text or "").lower()):
            cnt[t] += w
    key = _voc_key()
    try:
        for d in ((_ent["good"] or {}).get("docs") or {}).values():
            text = d.get("text") or ""
            add(d.get("title"), 3)
            if " aka " in text:
                add(text.split(" aka ", 1)[1].split(". ", 1)[0], 2)
    except Exception:
        pass
    try:
        from .ai import docs as D
        for d in (D._cache.get("docs") or {}).values():
            add(d.get("title"), 2)
    except Exception:
        pass
    try:
        from .news import search as N
        for t in ((N._index or {}).get("idf") or {}):
            if _VOC_RE.fullmatch(t):
                cnt[t] += 1
    except Exception:
        pass
    for d in (_story_cache["docs"] or {}).values():
        add(d["title"], 2)
    for _sec, label, anchor, about, words in SETTINGS_PAGES:
        add(f"{label} {anchor or ''} {about} {words}", 5)
    try:
        from .sources import SOURCES
        for x in SOURCES.values():
            add(f"{x.name} {x.provider} {x.id}", 5)
    except Exception:
        pass
    for d in _dev_cache["rows"] or []:
        add(f"{d['name']} {d['owner'] or ''} {' '.join(d['hostnames'][:5])}", 5)
    try:
        for r in db.query("SELECT DISTINCT json_extract_string(evidence, '$.indicator.meta.malware') AS m FROM alerts"):
            add(r["m"], 10)
    except Exception:
        pass
    bylen: dict[int, list[str]] = {}
    for w in cnt:
        bylen.setdefault(len(w), []).append(w)
    with _voc_lock:
        _voc.update(key=key, count=cnt, sorted=sorted(cnt), bylen=bylen)


def _vocab():
    """The word list (names, titles, aliases, article words, settings and sources). Built at warm-up (or on
    first use when there was none); rebuilt in the background when the indexes it reads change."""
    if _voc["count"] is None:
        if _warm["state"] in ("running", "vocab"):
            return None
        _build_vocab()
        return _voc
    if not _voc["busy"] and time.time() - _voc.get("at", 0) > 60 and _voc_key() != _voc["key"]:
        _voc["busy"], _voc["at"] = True, time.time()

        def bg():
            try:
                _build_vocab()
            finally:
                _voc["busy"] = False
        threading.Thread(target=bg, name="search-vocab", daemon=True).start()
    return _voc


def _completions(v: dict, w: str, n: int = 3) -> list[str]:
    import bisect
    words, out = v["sorted"], []
    i = bisect.bisect_left(words, w)
    while i < len(words) and words[i].startswith(w) and len(out) < 400:
        if words[i] != w:
            out.append(words[i])
        i += 1
    out.sort(key=lambda x: -v["count"][x])
    return out[:n]


def _prefix_query(c: Ctx) -> str | None:
    """The query with up to three longer forms added after each word of 4+ letters ('log4j' -> 'log4j log4j2
    log4jshell'), so word starts find names and titles; None when nothing longer exists."""
    if c.ip or c.mac or c.cve or len(c.q) > 80:
        return None
    v = _vocab()
    if not v:
        return None
    parts, changed = [], False
    for w in _words(c.q):
        parts.append(w)
        if len(w) >= 4:
            more = _completions(v, w)
            if more:
                parts += more
                changed = True
    return " ".join(parts) if changed else None


def _near(a: str, b: str) -> bool:
    """One edit apart: a letter changed, added, dropped, or two neighbours swapped."""
    la, lb = len(a), len(b)
    if la == lb:
        diff = []
        for i in range(la):
            if a[i] != b[i]:
                diff.append(i)
                if len(diff) > 2:
                    return False
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if abs(la - lb) != 1:
        return False
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def corrected(q: str) -> str | None:
    """The query with each unknown word of 5+ letters replaced by the most common known word one edit away
    ('qakbto' -> 'qakbot'), or None."""
    v = _vocab()
    if not v:
        return None
    out, changed = q.lower(), False
    for w in set(_words(q)):
        if len(w) < 5 or w in v["count"] or w.isdigit():
            continue
        best = None
        for n in (len(w) - 1, len(w), len(w) + 1):
            for x in v["bylen"].get(n, ()):
                if (x[0] == w[0] or x[1] == w[1]) and _near(w, x) and (best is None or v["count"][x] > v["count"][best]):
                    best = x
        if best:
            out = re.sub(rf"\b{re.escape(w)}\b", best, out)
            changed = True
    return out if changed else None


# ------------------------------------------------------------------ entry point
_warm: dict = {"state": None, "ready": set()}
SLOW = {"story", "article", "entity", "cve", "event"}   # groups whose index takes seconds to build


def _run(q: str, c: Ctx, wanted: list[dict], timings: dict) -> dict:
    # devices first: incidents also match through the devices a query names
    run = sorted(wanted, key=lambda g: (g["id"] != "device", g["order"]))
    res = {}
    for g in run:
        base = {"id": g["id"], "label": g["label"], "total": 0, "more": False, "items": []}
        if _warm["state"] == "running" and g["id"] in SLOW and g["id"] not in _warm["ready"]:
            res[g["id"]] = {**base, "warming": True}   # answer from what is ready; the client asks again
            continue
        t1 = time.perf_counter()
        try:
            items, total = g["fn"](q, c)
            res[g["id"]] = {**base, "total": total, "more": total > len(items), "items": items}
        except Exception as e:   # one broken group never takes search down
            log.warning("search group %s failed: %s", g["id"], e)
            res[g["id"]] = {**base, "error": "unavailable"}
        timings[g["id"]] = round(timings.get(g["id"], 0) + (time.perf_counter() - t1) * 1000, 1)
    return res


def everything(q: str, per: int = 5, only: list[str] | None = None) -> dict:
    t0 = time.perf_counter()
    q = (q or "").strip()[:200]
    per = max(1, min(int(per or 5), PER_MAX))
    out = {"q": q, "mode": "keyword", "groups": [], "took_ms": 0, "timings": {}}
    if len(q) < 2:
        return out
    c = Ctx(q, per)
    wanted = sorted((g for g in GROUPS.values() if not only or g["id"] in only), key=lambda g: g["order"])
    res = _run(q, c, wanted, out["timings"])
    # a word that appears nowhere: add the hits for the closest known spelling, after the exact ones
    if not (c.ip or c.mac or c.cve):
        q2 = corrected(q)
        if q2 and q2 != q.lower():
            res2 = _run(q2, Ctx(q2, per), wanted, out["timings"])
            for gid, g2 in res2.items():
                g = res[gid]
                have = {i["id"] for i in g["items"]}
                add = [{**i, "fuzzy": True, "exact": False, "why": {**(i.get("why") or {}), "near": q2}}
                       for i in g2["items"] if i["id"] not in have][: max(0, per - len(g["items"]))]
                g["items"] += add
                g["total"] += max(len(add), g2["total"] - len(have & {i["id"] for i in g2["items"]}))
                g["more"] = g["total"] > len(g["items"])
            out["corrected"] = q2
    if "cve" in res and "entity" in res:   # a CVE shows once, in the CVE group (which knows KEV and EPSS)
        cves = {f"cve:{str(i['id']).lower()}" for i in res["cve"]["items"]}
        ent = res["entity"]
        keep = [i for i in ent["items"] if i["id"] not in cves]
        ent["total"] -= len(ent["items"]) - len(keep)
        ent["items"] = keep
    groups = [res[g["id"]] for g in wanted if res[g["id"]]["items"] or res[g["id"]].get("error") or res[g["id"]].get("warming")]
    # a group whose best hit names the query exactly comes before groups without one (stable otherwise)
    groups.sort(key=lambda g: not any(i.get("exact") for i in g["items"][:1]))
    out["groups"] = groups
    if any(g.get("warming") for g in groups):
        out["warming"] = True
    out["mode"] = "hybrid" if c._have_vec and c._qvec is not None else "keyword"
    out["took_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return out


def warm() -> None:
    """Build the keyword indexes (entities, CVEs, articles, stories, feed items) and the word list at startup,
    one group at a time. Searches meanwhile answer from the groups that are ready and mark the others warming."""
    _warm["state"] = "running"
    try:
        c = Ctx("warm up", 1)
        c._have_vec = True   # keyword indexes only: never wait on the AI helper here
        for g in sorted(GROUPS.values(), key=lambda g: (g["id"] != "device", g["order"])):
            try:
                g["fn"]("warm up", c)
            except Exception as e:
                log.info("search warm-up of %s skipped: %s", g["id"], e)
            _warm["ready"].add(g["id"])
        _warm["state"] = "vocab"
        _build_vocab()
    finally:
        _warm["state"] = "done"


def start_warm() -> None:
    """Run warm() once, in a daemon thread (never holds up startup or shutdown)."""
    if _warm["state"] is None:
        _warm["state"] = "running"
        threading.Thread(target=warm, name="search-warm", daemon=True).start()

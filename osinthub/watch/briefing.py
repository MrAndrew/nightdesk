"""The Watch briefing: what changed since the marker, in a fixed order, from data already in the lake. No LLM.

Sections (each {id, title, count, items, link, empty}; `empty` holds "{since}" for the client to fill in with the
reader's local time):

  network   needs-you incidents new or changed since the marker, plus how current the logs are. Demo incidents
            only when there are no real ones (each marked demo).
  touches   news stories and KEV entries whose indicators or CVEs were seen on your network, and what touches the
            followed list (My stack, osinthub/stack.py): KEV entries, network incidents, EPSS jumps, ransomware victims.
  kev       KEV additions since the marker, highest EPSS first, with vendor, product and due date.
  follow    the watchlist digest since the marker.
  stories   the most-covered story clusters active since the marker.
  health    failing, stale or needed-but-off sources. Left out entirely when nothing is wrong.

Reference: okf/architecture/watch.md#briefing
"""
from __future__ import annotations

import datetime as dt
import json
import logging

from .. import apiutil, config, db
from . import marker

log = logging.getLogger("osinthub.watch")

MAX_ITEMS = 8
BIG_STORY_MIN_SOURCES = 2
KEV_SLACK_DAYS = 3          # a KEV row first stored after the marker counts if CISA dated it at most this long before
NEEDED = {                  # sources Watch itself relies on: off is a problem, not a choice
    "cisa_kev": "Newly exploited",
    "epss": "the exploit likelihood order of Newly exploited",
}


def _tables() -> set[str]:
    return db.tables()


_jsonable = apiutil.jsonable


def _section(sid: str, title: str, items: list, count: int | None, link: dict, empty: str, **extra) -> dict:
    return {"id": sid, "title": title, "count": len(items) if count is None else count, "items": items[:MAX_ITEMS],
            "link": link, "empty": empty, **extra}


# ------------------------------------------------------------------ a. your network
def _freshness() -> dict | None:
    try:
        from ..netlog.api import freshness
        f = freshness()
    except Exception as e:   # netlog package missing or its tables not there yet
        log.debug("watch: freshness unavailable: %s", e)
        return None
    srcs = f.get("sources") or []
    return {"newest": f.get("newest"), "age_s": f.get("age_s"), "stale": bool(f.get("stale")),
            "stale_sources": [s.get("label") for s in srcs if s.get("stale")],
            "has_logs": any(s.get("files") for s in srcs), "demo_loaded": bool((f.get("demo") or {}).get("loaded")),
            "stale_hours": f.get("stale_hours")}


def _incidents(t: dt.datetime | None, demo: bool) -> list[dict] | None:
    """Needs-you incidents (untriaged, not expected, high or medium) new or changed since t. None without the
    incidents layer (osinthub/netlog/incidents.py)."""
    try:
        from ..netlog import incidents
    except ImportError:
        return None
    incidents.ensure()
    where = f"WHERE state = 'new' AND severity IN ('high', 'medium') AND {'' if demo else 'NOT '}demo"
    if t is not None:   # None: every open one, new or not
        where += " AND (last_ts > ? OR created_at > ? OR updated_at > ?)"
    rows = db.query(incidents.incidents_sql("", where, incidents.ORDER, "LIMIT 200"), [t, t, t] if t is not None else [])
    for r in rows:
        try:
            r["evidence"] = json.loads(r.get("evidence") or "{}") if isinstance(r.get("evidence"), str) else (r.get("evidence") or {})
        except ValueError:
            r["evidence"] = {}
    try:
        from ..netlog.api import _name_alerts   # the user's device names, as in the alert list
        _name_alerts(rows)
    except Exception:
        pass
    out = []
    for r in rows:
        ev = r["evidence"]
        ind = ev.get("indicator") or {}
        out.append({"id": r["id"], "title": r.get("title"), "severity": r.get("severity"), "device": r.get("device"),
                    "device_name": r.get("device_name"), "indicator": r.get("indicator"), "kind": r.get("kind"),
                    "rule": r.get("rule"), "direction": r.get("direction"), "source": r.get("source"),
                    "category": ind.get("category"), "malware": (ind.get("meta") or {}).get("malware"),
                    "ts": r.get("ts"), "last_ts": r.get("last_ts"), "count": r.get("count"),
                    "reopened": bool(r.get("reopened")), "demo": bool(r.get("demo")),
                    # for the Network view's own headline wording (web/js/views/net/alert-text.js), without the bulk
                    "evidence": {k: v for k, v in ev.items() if k not in ("uids", "rows", "sample", "listing")},
                    "href": f"#network/alerts/{r['id']}"})
    return out


def network(t: dt.datetime) -> dict:
    fresh = _freshness()
    try:
        from ..netlog import incidents
        total = incidents.needs_you()
    except Exception:
        total = None
    items = _incidents(t, demo=False)
    demo = False
    if items is not None and not items and not (total or {}).get("needs_you"):
        d = _incidents(t, demo=True) or []
        if d:
            items, demo = d, True
    # needs-you incidents that are still open but not new since the marker: shown apart as "still open", so a
    # quiet day never reads as an all-clear while something needs you
    still: list[dict] = []
    if items is not None and not demo and (total or {}).get("needs_you"):
        new_ids = {i["id"] for i in items}
        still = [{**i, "still_open": True} for i in (_incidents(None, demo=False) or []) if i["id"] not in new_ids]
    return _section("network", "Your network", items or [], None, {"href": "#network/alerts", "label": "All alerts"},
                    "Nothing new on your network since {since}.", logs=fresh, demo=demo,
                    still_open=still[:MAX_ITEMS], still_open_count=len(still),
                    needs_you=(total or {}).get("needs_you"), available=items is not None)


# ------------------------------------------------------------------ c. newly exploited (KEV)
def _kev_rows(t: dt.datetime) -> list[dict]:
    return db.query("""SELECT id, ts, title, summary, tags, url, stored_at FROM events
                       WHERE source = 'cisa_kev' AND kind = 'kev'
                         AND (ts > ? OR (stored_at > ? AND ts > ? - to_microseconds(?)))
                       ORDER BY ts DESC, id""", [t, t, t, KEV_SLACK_DAYS * 86_400_000_000])


def _kev_item(r: dict, epss: dict, recs: dict) -> dict:
    cve = (r.get("title") or "").split(" ")[0].upper()
    tags = list(r.get("tags") or [])
    vendor = tags[0] if len(tags) > 0 and tags[0] != "ransomware" else ""
    product = tags[1] if len(tags) > 1 and tags[1] != "ransomware" else ""
    s = r.get("summary") or ""
    name = s.split(". ")[0] if s else ""
    pre = f"{vendor} {product} "
    if name.startswith(pre):
        name = name[len(pre):]
    rec = recs.get(cve) or {}
    e = epss.get(cve) or {}
    return {"id": r["id"], "cve": cve, "vendor": vendor, "product": product, "name": name,
            "added": r["ts"], "due": rec.get("dueDate"), "ransomware": "ransomware" in tags,
            "epss": e.get("epss"), "epss_percentile": e.get("percentile"), "href": f"#entities/cve:{cve.lower()}"}


def _kev_items(rows: list[dict]) -> list[dict]:
    cves = [(r.get("title") or "").split(" ")[0].upper() for r in rows]
    epss: dict = {}
    if "epss" in _tables():
        try:
            from ..sources.vulns import epss_lookup
            epss = epss_lookup(cves)
        except Exception as e:
            log.debug("watch: epss lookup failed: %s", e)
    try:
        from ..entities.link import kev_records   # due dates live only in CISA's records
        recs = kev_records()
    except Exception:
        recs = {}
    items = [_kev_item(r, epss, recs) for r in rows]
    items.sort(key=lambda i: -(i["epss"] if i["epss"] is not None else -1.0))   # stable: EPSS, then newest
    return items


def kev(t: dt.datetime) -> tuple[dict, list[dict]]:
    items = _kev_items(_kev_rows(t))
    return (_section("kev", "Newly exploited", items, None, {"href": "#ops", "label": "All exploited bugs in Ops"},
                     "No new exploited vulnerabilities since {since}."), items)


# ------------------------------------------------------------------ b. touches you
def _watchlist() -> dict:
    """The followed list (My stack, osinthub/stack.py): entities, keywords, vendors and products."""
    from .. import stack
    return stack.get()


def _following(w: dict) -> bool:
    return bool(w["entities"] or w["keywords"] or w.get("stack"))


def _alert_hits(tables: set[str]) -> dict[str, dict]:
    """Indicator (lower case) -> {devices, demo, alert} over every alert not dismissed: what your network touched."""
    if "alerts" not in tables:
        return {}
    has_demo = "demo" in {r["column_name"] for r in db.query(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'alerts'")}
    rows = db.query(f"""SELECT lower(indicator) AS k, count(DISTINCT device) AS devices,
                               bool_and({'coalesce(demo, false)' if has_demo else 'false'}) AS demo,
                               arg_max(id, last_ts) AS alert, max(last_ts) AS last_ts
                        FROM alerts WHERE indicator IS NOT NULL AND coalesce(status, 'new') <> 'dismissed'
                        GROUP BY 1""")
    return {r["k"]: r for r in rows}


def touches(t: dt.datetime, kev_items: list[dict]) -> dict:
    tables = _tables()
    hits = _alert_hits(tables)
    w = _watchlist()
    items: list[dict] = []
    seen: set[str] = set()

    def add(key, item):
        if key not in seen:
            seen.add(key)
            items.append(item)

    # KEV CVEs seen on your network (a software notice naming the CVE), any KEV entry, not only new ones,
    # when the sighting itself is since the marker
    if hits:
        cves = [k.upper() for k, h in hits.items() if k.startswith("cve-") and h["last_ts"] and h["last_ts"] > t]
        if cves:
            rows = db.query(f"""SELECT id, ts, title, summary, tags, url, stored_at FROM events
                                WHERE source = 'cisa_kev' AND kind = 'kev'
                                  AND upper(split_part(title, ' ', 1)) IN ({','.join('?' * len(cves))})""", cves)
            for k in _kev_items(rows):
                h = hits[k["cve"].lower()]
                add(f"kev:{k['cve']}", {**k, "type": "kev", "why": "network", "devices": h["devices"],
                                        "demo": bool(h["demo"]), "alert": h["alert"]})
    # news stories active since the marker naming an indicator or CVE seen on your network
    if hits and {"mentions", "articles", "stories", "entities"} <= tables:
        keys = list(hits)
        rows = db.query("""SELECT s.id, s.title, s.source_count, s.article_count, s.last_seen, e.name AS indicator,
                                   lower(e.name) AS k
                            FROM stories s JOIN articles a ON a.story_id = s.id
                            JOIN mentions m ON m.ref_type = 'article' AND m.ref_id = a.id
                            JOIN entities e ON e.id = m.entity_id
                            WHERE s.last_seen > ? AND e.type IN ('ip', 'domain', 'url', 'cve', 'hash')
                              AND lower(e.name) IN (SELECT unnest(?::VARCHAR[]))
                            QUALIFY row_number() OVER (PARTITION BY s.id ORDER BY e.name) = 1
                            ORDER BY s.source_count DESC, s.last_seen DESC, s.id LIMIT 50""", [t, keys])
        for r in rows:
            h = hits[r["k"]]
            add(f"story:{r['id']}", {"type": "story", "id": r["id"], "title": r["title"], "why": "network",
                                     "indicator": r["indicator"], "devices": h["devices"], "demo": bool(h["demo"]),
                                     "alert": h["alert"], "source_count": r["source_count"],
                                     "last_seen": r["last_seen"], "href": f"#news/story/{r['id']}"})
    # what you follow (osinthub/stack.py): new KEV entries for a followed vendor, product, CVE or word; network
    # incidents involving a followed entity (a QakBot C2 alert when you follow QakBot); EPSS jumps of followed CVEs;
    # ransomware victims that are a followed organisation or claimed by a followed group
    from .. import stack
    T = stack.Terms(w)
    still: list[dict] = []
    if not T.empty:
        names = lambda m: {x: T.name(x) for x in m}   # noqa: E731
        fresh = stack.followed_since(t)
        for k in kev_items:
            matched = T.record(k["vendor"], k["product"], k["cve"], k["name"])
            if matched:
                add(f"kev:{k['cve']}", {**k, "type": "kev", "why": "follow", "matched": matched, "matched_names": names(matched)})
        # just followed (after the marker): its exploited bugs from the last 30 days are news to you once
        if fresh:
            for k in _kev_items(stack.recent_kev_rows()):
                matched = [m for m in T.record(k["vendor"], k["product"], k["cve"], k["name"]) if m in fresh]
                if matched:
                    add(f"kev:{k['cve']}", {**k, "type": "kev", "why": "follow", "matched": matched,
                                            "matched_names": names(matched), "recent_follow": True})
        for a in stack.network_hits(T, t):
            a = {**a, "matched_names": names(a["matched"])}
            if a["still_open"] and set(a["matched"]) & fresh:
                # just followed: its open incidents are news to you, like its recent KEV entries
                add(f"alert:{a['id']}", {**a, "recent_follow": True})
            elif a["still_open"]:   # not new, but untriaged: shown apart and not counted, like Your network does
                still.append(a)
            else:
                add(f"alert:{a['id']}", a)
        try:
            for e in stack.epss_hits(T, t):
                add(f"epss:{e['cve']}", {**e, "matched_names": names(e["matched"])})
        except Exception as ex:
            log.debug("watch: epss jumps failed: %s", ex)
        for v in stack.victim_hits(T, t):
            add(f"victim:{v['id']}", {**v, "matched_names": names(v["matched"])})
    return _section("touches", "Touches you", items, None, {"href": "#network/alerts", "label": "Network alerts"},
                    "Nothing new touches your network or what you follow since {since}.",
                    following=_following(w), still_open=still[:MAX_ITEMS], still_open_count=len(still))


# ------------------------------------------------------------------ d. news you follow
def follow(t: dt.datetime) -> dict:
    w = _watchlist()
    items: list[dict] = []
    if _following(w):
        try:
            from ..news.api import watchlist_digest
            d = watchlist_digest(since=t.isoformat(), limit=50)
            items = [{"id": s["id"], "title": s.get("title"), "matched": s.get("matched") or [],
                      "matched_names": s.get("matched_names") or {},
                      "is_new": bool(s.get("is_new")), "new_articles": s.get("new_articles"),
                      "source_count": s.get("source_count"), "last_seen": s.get("last_seen"),
                      "href": f"#news/story/{s['id']}"} for s in d.get("stories") or []]
        except Exception as e:
            log.warning("watch: watchlist digest failed: %s", e)
    return _section("follow", "News you follow", items, None, {"href": "#settings/follow", "label": "What you follow"},
                    "Nothing new about what you follow since {since}." if _following(w)
                    else "You don't follow anything yet. Follow a vendor, product or group to see its news here.",
                    following=_following(w))


# ------------------------------------------------------------------ e. big stories
def big_stories(t: dt.datetime) -> dict:
    items: list[dict] = []
    n = 0
    if "stories" in _tables():
        n = db.query("SELECT count(*) AS n FROM stories WHERE last_seen > ? AND source_count >= ?",
                     [t, BIG_STORY_MIN_SOURCES])[0]["n"]
        rows = db.query("""SELECT id, title, source_count, article_count, first_seen, last_seen FROM stories
                           WHERE last_seen > ? AND source_count >= ?
                           ORDER BY source_count DESC, article_count DESC, last_seen DESC, id LIMIT 5""",
                        [t, BIG_STORY_MIN_SOURCES])
        items = [{**r, "is_new": bool(r["first_seen"] and r["first_seen"] > t), "href": f"#news/story/{r['id']}"}
                 for r in rows]
    return _section("stories", "Big stories", items, n, {"href": "#news", "label": "All news"},
                    "No story was picked up by several outlets since {since}.")


# ------------------------------------------------------------------ f. feed health
def health_problems(at: dt.datetime | None = None) -> tuple[list[dict], dict]:
    """Failing, stale, or needed-but-off sources; and a summary {enabled, fresh, offline}."""
    from .. import scheduler
    from ..sources import SOURCES
    at = at or marker.now()
    states = {r["id"]: r for r in db.query("SELECT * FROM source_state")}
    probs: list[dict] = []
    enabled = fresh = 0
    for s in SOURCES.values():
        st = states.get(s.id, {})
        on = scheduler.is_enabled(s)
        if s.unavailable():          # needs a key the user has not set: optional, never a problem here
            continue
        if not on:
            if s.id in NEEDED:
                probs.append({"id": s.id, "name": s.name, "problem": "off",
                              "text": f"Turned off, but {NEEDED[s.id]} needs it.", "href": "#sources"})
            continue
        enabled += 1
        status, last_ok = (st.get("status") or ""), st.get("last_ok")
        if config.OFFLINE:
            continue
        if status in ("error", "failed"):
            probs.append({"id": s.id, "name": s.name, "problem": "failing", "text": st.get("message") or "Its last run failed.",
                          "since": last_ok, "href": "#sources"})
            continue
        if s.mode == "batch" and last_ok is not None:
            limit = dt.timedelta(seconds=max(3 * (s.interval or 3600), 6 * 3600))
            if at - last_ok > limit:
                probs.append({"id": s.id, "name": s.name, "problem": "stale", "since": last_ok,
                              "text": "No fresh data for longer than usual.", "href": "#sources"})
                continue
        fresh += 1
    if config.OFFLINE:
        probs.insert(0, {"id": "offline", "name": "Offline mode", "problem": "offline", "href": "#sources",
                         "text": "Night Desk is not fetching anything, so nothing new will arrive."})
    return probs, {"enabled": enabled, "fresh": fresh, "offline": bool(config.OFFLINE)}


def health() -> tuple[dict | None, dict]:
    probs, summ = health_problems()
    if not probs:
        return None, summ
    return _section("health", "Source health", probs, None, {"href": "#settings/sources", "label": "Sources"}, ""), summ


# ------------------------------------------------------------------ the briefing
ORDER = ("network", "touches", "kev", "follow", "stories", "health")


def build(since: str | None = None) -> dict:
    m = marker.get()
    win = marker.window(m, since)
    t = marker.parse(win["since"])
    k, kev_items = kev(t)
    secs = [network(t), touches(t, kev_items), k, follow(t), big_stories(t)]
    h, summ = health()
    if h:
        secs.append(h)
    return _jsonable({"now": marker.now(), "marker": {k2: m[k2] for k2 in ("last_seen", "previous", "set_at")},
                      "window": win, "viewing_previous": since == "previous", "sections": secs, "feeds": summ,
                      "total": sum(s["count"] for s in secs if s["id"] != "health"),
                      "needs_you": secs[0].get("needs_you") or 0})

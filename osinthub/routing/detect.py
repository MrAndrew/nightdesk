"""Routing watch rules, per-watch state and the cards.

Each source hands its (already filtered) observations to one `ingest_*` function. The rules are simple and
explainable; each finding is an event with a plain title and summary, a level (`needs_you` or `info`), the source
that raised it and the watch it belongs to. There is at most one open event per watch and kind: a repeat finding
updates it ("seen"), and the source that opened it clears it when a later check no longer finds it. Events opened
by the RIS Live stream clear after a day without being seen again.

Needs you: an unexpected origin AS for a watched prefix (also a more-specific announced by another AS) measured
against a reference (its RPKI records, or the origins RIPEstat saw first), an RPKI-invalid announcement of a watched
prefix, a Radar hijack with confidence 8 or more, and a watched prefix not visible for GONE_AFTER (RIPEstat).
Information: Radar hijacks below confidence 8 and route leaks involving a watch, several origins seen by RIS Live
with no reference yet, new or lost upstream neighbours, update spikes against the watch's own 14-day baseline, a
visibility drop, more announced prefixes than usual.

State lives in the settings table: `routing.state` (per watch: checks, facts, baselines, events) and
`routing.roas` (the RPKI records that concern each watch). One lock serialises every read-modify-write.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import statistics
import threading

from .. import db
from . import watchlist

STATE_KEY = "routing.state"
ROAS_KEY = "routing.roas"

GONE_AFTER = dt.timedelta(hours=2)        # a watched prefix unseen this long needs you
STREAM_CLEAR_AFTER = dt.timedelta(days=1)
ADOPT_ORIGIN_AFTER = dt.timedelta(days=7)  # an origin announced this long counts as normal
CHANGE_WINDOW = dt.timedelta(days=1)       # a new or lost upstream stays an event this long
BASELINE = dt.timedelta(days=14)
SPIKE_FACTOR, SPIKE_MIN_PER_H, SPIKE_MIN_POINTS = 4.0, 60.0, 6
VIS_DROP, VIS_MIN_POINTS = 0.6, 4
COUNT_UP, COUNT_MIN_DIFF, COUNT_MIN_POINTS = 1.2, 5, 4
EVENTS_KEPT = 30

NEEDS_YOU, INFO = "needs_you", "info"
OWNED = {   # the kinds each source evaluates (and may therefore clear)
    "rpki_roas": {"rpki_invalid"},
    "cf_radar_bgp": {"radar_hijack", "radar_leak"},
    "ripestat": {"unexpected_origin", "rpki_invalid", "not_visible", "upstream_change", "update_spike",
                 "visibility_drop", "new_prefixes"},
    "ris_live": {"unexpected_origin", "rpki_invalid"},
}

_lock = threading.RLock()
UTC = dt.UTC


def _now() -> dt.datetime:
    return dt.datetime.now(UTC)


def _iso(t: dt.datetime) -> str:
    return t.astimezone(UTC).isoformat(timespec="seconds")


def _t(s) -> dt.datetime | None:
    if not s or s == "base":
        return None
    try:
        d = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def _load() -> dict:
    return db.get_setting(STATE_KEY, {}) or {}


def _save(st: dict) -> None:
    db.set_setting(STATE_KEY, st)


def roas() -> dict:
    return db.get_setting(ROAS_KEY, {}) or {}


def _w(st: dict, wid: str) -> dict:
    w = st.setdefault(wid, {})
    for k in ("checks", "facts", "base"):
        w.setdefault(k, {})
    w.setdefault("events", [])
    return w


def _name(w: dict) -> str:
    return w["id"] if w.get("label") in (None, "", w["id"]) else f"{w['label']} ({w['id']})"


def _as(n) -> str:
    return f"AS{n}"


def _aslist(ns) -> str:
    ns = sorted({int(n) for n in ns})
    s = ", ".join(_as(n) for n in ns[:4])
    return s + (f" and {len(ns) - 4} more" if len(ns) > 4 else "")


# ---------------------------------------------------------------- events: open, refresh, clear
def _open(ws: dict, wid: str, kind: str, level: str, sid: str, title: str, summary: str, detail=None) -> dict:
    now = _iso(_now())
    for e in ws["events"]:
        if e["kind"] == kind and not e.get("cleared"):
            e.update(seen=now, title=title, summary=summary, detail=detail)
            if level == NEEDS_YOU:
                e["level"] = NEEDS_YOU
            return e
    e = {"id": f"{wid}|{kind}|{now}", "watch": wid, "kind": kind, "level": level, "source": sid, "title": title,
         "summary": summary, "opened": now, "seen": now, "cleared": None, "detail": detail}
    ws["events"].append(e)
    open_ = [x for x in ws["events"] if not x.get("cleared")]
    done = sorted((x for x in ws["events"] if x.get("cleared")), key=lambda x: x["opened"])
    ws["events"] = sorted(open_ + done[-max(0, EVENTS_KEPT - len(open_)):], key=lambda x: x["opened"])
    return e


def _clear(ws: dict, sid: str, found: set[str]) -> None:
    """Clear the open events this source opened whose kind it evaluated and did not find now."""
    now = _iso(_now())
    for e in ws["events"]:
        if not e.get("cleared") and e["source"] == sid and e["kind"] in OWNED.get(sid, ()) and e["kind"] not in found:
            e["cleared"] = now


def _check(ws: dict, sid: str, ok: bool, why: str | None = None) -> None:
    ws["checks"][sid] = {"at": _iso(_now()), "ok": bool(ok), "why": why}


def sweep(st: dict | None = None) -> dict:
    """Drop the state of watches no longer listed and clear stream events not seen for a day."""
    own = st is None
    with _lock:
        st = _load() if own else st
        ids = {w["id"] for w in watchlist.load()}
        for wid in [k for k in st if k not in ids]:
            del st[wid]
        cut = _now() - STREAM_CLEAR_AFTER
        for ws in st.values():
            for e in ws.get("events", []):
                if not e.get("cleared") and e["source"] == "ris_live" and (_t(e["seen"]) or cut) <= cut:
                    e["cleared"] = _iso(_now())
        if own:
            _save(st)
        return st


def open_events(wid: str | None = None) -> list[dict]:
    st = _load()
    return [e for k, ws in st.items() if wid in (None, k) for e in ws.get("events", []) if not e.get("cleared")]


# ---------------------------------------------------------------- RPKI validation (RFC 6811, local)
def _net(p: str):
    try:
        return ipaddress.ip_network(p, strict=False)
    except ValueError:
        return None


def rpki_status(prefix: str, origin: int, records: list) -> str:
    """valid / invalid / unknown for an announcement, against ROAs [prefix, max_length, asn] that include every
    ROA covering the prefix (true for a watched prefix's own list)."""
    p = _net(prefix)
    if p is None:
        return "unknown"
    covering = [r for r in records if (n := _net(r[0])) is not None and n.version == p.version and p.subnet_of(n)]
    if not covering:
        return "unknown"
    if any(int(r[2]) == int(origin) and int(origin) != 0 and p.prefixlen <= int(r[1]) for r in covering):
        return "valid"
    return "invalid"


def _invalid_why(prefix: str, origin: int, records: list) -> str:
    p = _net(prefix)
    mine = [r for r in records if int(r[2]) == int(origin) and (n := _net(r[0])) is not None
            and n.version == p.version and p.subnet_of(n)]
    if mine:
        return f"its RPKI record lets {_as(origin)} announce it only up to /{max(int(r[1]) for r in mine)}, and this is a /{p.prefixlen}"
    allowed = sorted({int(r[2]) for r in records if (n := _net(r[0])) is not None and n.version == p.version and p.subnet_of(n)})
    return f"its RPKI record allows only {_aslist(allowed)}" if allowed else "its RPKI record does not allow it"


def _prefix_roas(wid: str) -> list | None:
    r = roas()
    if "_meta" not in r:
        return None   # the RPKI file has not been loaded: no local answer
    return (r.get(wid) or {}).get("roas", [])


# ---------------------------------------------------------------- shared prefix rules
def _expected(ws: dict) -> set[int]:
    return {int(x) for x in ws["base"].get("origins", [])}


def _origin_rules(w: dict, ws: dict, sid: str, anns: list[tuple[str, int]], found: set[str],
                  rpki_remote: dict | None = None) -> None:
    """Unexpected-origin and RPKI-invalid checks for announcements (prefix, origin) of a watched prefix or a
    more-specific of it.

    The reference ("usual") origins come from the RPKI records and from RIPEstat, whose first check learns them;
    never from the RIS Live stream, whose first message for a quiet prefix is usually the change itself. With no
    reference at all, stream sightings are information only ("no reference origin yet"), and an origin the stream
    keeps seeing for the whole 14-day baseline window becomes the reference. With a reference, an origin present for a
    week is adopted as normal."""
    if not anns:
        return
    now = _now()
    base = ws["base"]
    recs = _prefix_roas(w["id"])
    allowed = {int(r[2]) for r in (recs or [])}
    if sid != "ris_live" and "origins" not in base:
        base["origins"] = sorted({o for _, o in anns} | allowed)
        base["origins_at"] = _iso(now)
    seen = base.setdefault("ann", {})
    for p, o in anns:
        seen[f"{p}|{o}"] = _iso(now)
    for k in [k for k, t in seen.items() if (_t(t) or now) < now - dt.timedelta(days=2)]:
        del seen[k]
    newo = base.setdefault("new_origins", {})
    after = ADOPT_ORIGIN_AFTER if ("origins" in base or allowed) else BASELINE
    for o in list(newo):
        still = any(k.endswith(f"|{o}") for k in seen)
        if not still:
            del newo[o]
        elif (_t(newo[o]) or now) <= now - after:
            base["origins"] = sorted(set(base.get("origins", [])) | {int(o)})
            del newo[o]
    ref = _expected(ws) | allowed
    bad, invalid = [], []
    for p, o in anns:
        st = rpki_status(p, o, recs) if recs is not None else (rpki_remote or {}).get(f"{p}|{o}", "unknown")
        if st == "invalid":
            invalid.append((p, o))
        elif o not in ref and st != "valid":
            bad.append((p, o))
            newo.setdefault(str(o), _iso(now))
    name = _name(w)
    if invalid:
        p, o = invalid[0]
        why = _invalid_why(p, o, recs) if recs else "its RPKI record does not allow it"
        more = f" ({len(invalid) - 1} more like it)" if len(invalid) > 1 else ""
        _open(ws, w["id"], "rpki_invalid", NEEDS_YOU, sid, f"{name}: an announcement fails its RPKI check",
              f"{_as(o)} announced {p}, but {why}{more}. Networks that check RPKI will ignore it; others may send "
              f"traffic for it to {_as(o)}.", {"announcements": [[a, b] for a, b in invalid[:10]]})
        found.add("rpki_invalid")
    if bad and ref:
        p, o = bad[0]
        what = "a smaller part of it" if p != w["id"] else "it"
        more = f" ({len(bad) - 1} more like it)" if len(bad) > 1 else ""
        _open(ws, w["id"], "unexpected_origin", NEEDS_YOU, sid, f"{name}: announced by an unexpected network",
              f"{_as(o)} announced {what} ({p}){more}. It is usually announced by {_aslist(ref)}. This can be a "
              f"configuration mistake or a hijack.", {"announcements": [[a, b] for a, b in bad[:10]]})
        found.add("unexpected_origin")
    elif bad:
        heard = sorted({int(o) for o in newo})
        if len(heard) > 1:   # no reference: say what was seen, as information
            _open(ws, w["id"], "unexpected_origin", INFO, sid, f"{name}: announced by more than one network",
                  f"{_aslist(heard)} announced it. Night Desk has no reference origin for it yet (it is not signed "
                  f"with RPKI and RIPEstat is off), so it cannot tell which one is usual.",
                  {"announcements": [[a, b] for a, b in bad[:10]]})
            found.add("unexpected_origin")


def _history(base: dict, key: str, value: float) -> list[float]:
    """The baseline values of the last 14 days (before this one), then this value appended."""
    now = _now()
    h = [x for x in base.get(key, []) if (_t(x[0]) or now) >= now - BASELINE]
    vals = [float(x[1]) for x in h]
    h.append([_iso(now), value])
    base[key] = h[-400:]
    return vals


# ---------------------------------------------------------------- RPKI file
def ingest_rpki(records: list) -> int:
    """records: [prefix, max_length, asn] already filtered to the watchlist. Saves each watch's share, notes the
    check, and re-checks the announcements last seen for each watched prefix. Returns how many were kept."""
    with _lock:
        wl = watchlist.load()
        nets = watchlist.prefixes(wl)
        out: dict = {"_meta": {"at": _iso(_now())}}
        for w in wl:
            if w["kind"] == "asn":
                n = int(w["id"][2:])
                mine = [r for r in records if int(r[2]) == n]
                out[w["id"]] = {"count": len(mine), "roas": []}
            else:
                net = nets[w["id"]]
                mine = [r for r in records if (x := _net(r[0])) is not None and x.version == net.version and x.overlaps(net)]
                out[w["id"]] = {"count": len(mine), "roas": [[r[0], int(r[1]), int(r[2])] for r in mine]}   # all: a missing one would be a false "invalid"
        db.set_setting(ROAS_KEY, out)
        st = sweep(_load())
        for w in wl:
            ws = _w(st, w["id"])
            ws["id"] = w["id"]
            mine = out[w["id"]]
            ws["facts"]["rpki_roas"] = {"count": mine["count"],
                                        "asns": sorted({r[2] for r in mine["roas"]}) if w["kind"] == "prefix" else [],
                                        "max": max((r[1] for r in mine["roas"] if _net(r[0]) == nets.get(w["id"])), default=None)}
            found: set[str] = set()
            if w["kind"] == "prefix":
                anns = [(k.split("|")[0], int(k.split("|")[1])) for k in ws["base"].get("ann", {})]
                bad = [(p, o) for p, o in anns if rpki_status(p, o, mine["roas"]) == "invalid"]
                if bad:
                    p, o = bad[0]
                    _open(ws, w["id"], "rpki_invalid", NEEDS_YOU, "rpki_roas", f"{_name(w)}: an announcement fails its RPKI check",
                          f"{_as(o)} was last seen announcing {p}, but {_invalid_why(p, o, mine['roas'])}. Networks "
                          f"that check RPKI will ignore it.", {"announcements": [[a, b] for a, b in bad[:10]]})
                    found.add("rpki_invalid")
            _clear(ws, "rpki_roas", found)
            _check(ws, "rpki_roas", True)
        _save(st)
        return sum(v["count"] for k, v in out.items() if k != "_meta")


# ---------------------------------------------------------------- Cloudflare Radar
def _hijack_hits(w: dict, ev: dict) -> str | None:
    """'victim' / 'hijacker' / 'prefix' when a Radar hijack event involves the watch."""
    if w["kind"] == "asn":
        n = int(w["id"][2:])
        if n in {int(x) for x in ev.get("victim_asns") or [] if str(x).isdigit()}:
            return "victim"
        if str(ev.get("hijacker_asn", "")) == str(n):
            return "hijacker"
        return None
    net = ipaddress.ip_network(w["id"])
    for p in ev.get("prefixes") or []:
        x = _net(str(p))
        if x is not None and x.version == net.version and x.overlaps(net):
            return "prefix"
    return None


def _leak_hits(w: dict, ev: dict) -> bool:
    if w["kind"] != "asn":
        return False
    n = int(w["id"][2:])
    path = {str(x) for x in ev.get("leak_seg") or []} | {str(ev.get("leak_asn", ""))}
    return str(n) in path


def ingest_radar(hijacks: list[dict], leaks: list[dict]) -> list[dict]:
    """Match Radar's recent events to the watchlist (locally). Returns the matched events (for the lake)."""
    matched: list[dict] = []
    with _lock:
        wl = watchlist.load()
        st = sweep(_load())
        for w in wl:
            ws = _w(st, w["id"])
            ws["id"] = w["id"]
            found: set[str] = set()
            hs = [(ev, how) for ev in hijacks if (how := _hijack_hits(w, ev))]
            if hs:
                ev, how = max(hs, key=lambda x: (int(x[0].get("confidence_score") or 0), str(x[0].get("max_hijack_ts", ""))))
                conf = int(ev.get("confidence_score") or 0)
                pf = [str(p) for p in (ev.get("prefixes") or [])][:3]
                when = f"{str(ev.get('min_hijack_ts', ''))[:16].replace('T', ' ')} to {str(ev.get('max_hijack_ts', ''))[:16].replace('T', ' ')} UTC"
                who = f"AS{ev.get('hijacker_asn')}"
                title = (f"{_name(w)} named as the announcer in a possible hijack" if how == "hijacker"
                         else f"{_name(w)}: possible hijack reported by Cloudflare Radar")
                summary = (f"Cloudflare Radar saw {who} announce {', '.join(pf) or 'addresses'}, normally announced by "
                           f"{_aslist(ev.get('victim_asns') or []) or 'another network'} ({when}; confidence {conf} of 10"
                           f"{'; ' + str(len(hs) - 1) + ' more events' if len(hs) > 1 else ''}).")
                _open(ws, w["id"], "radar_hijack", NEEDS_YOU if conf >= 8 else INFO, "cf_radar_bgp", title, summary,
                      {"radar_id": ev.get("id"), "confidence": conf})
                found.add("radar_hijack")
                matched += [{"watch": w["id"], "type": "hijack", **e} for e, _ in hs]
            ls = [ev for ev in leaks if _leak_hits(w, ev)]
            if ls:
                ev = ls[0]
                seg = " ".join(f"AS{x}" for x in (ev.get("leak_seg") or [])[:6])
                _open(ws, w["id"], "radar_leak", INFO, "cf_radar_bgp",
                      f"{_name(w)}: involved in a route leak reported by Cloudflare Radar",
                      f"Cloudflare Radar saw AS{ev.get('leak_asn')} pass on routes it should have kept to itself"
                      f"{f' (path {seg})' if seg else ''}, affecting {ev.get('prefix_count', 'some')} prefixes "
                      f"from {ev.get('origin_count', 'some')} networks. Traffic may take a longer or wrong path.",
                      {"radar_id": ev.get("id")})
                found.add("radar_leak")
                matched += [{"watch": w["id"], "type": "leak", **e} for e in ls]
            _clear(ws, "cf_radar_bgp", found)
            ws["facts"]["cf_radar_bgp"] = {"hijacks": len(hs), "leaks": len(ls)}
            _check(ws, "cf_radar_bgp", True)
        _save(st)
    return matched


# ---------------------------------------------------------------- RIPEstat
def _vis(status: dict, version: int) -> tuple[int, int] | None:
    v = (status.get("visibility") or {}).get("v4" if version == 4 else "v6") or {}
    try:
        return int(v.get("ris_peers_seeing") or 0), int(v.get("total_ris_peers") or 0)
    except (TypeError, ValueError):
        return None


def _ripestat_prefix(w: dict, ws: dict, d: dict, found: set[str]) -> dict:
    now = _now()
    base = ws["base"]
    net = ipaddress.ip_network(w["id"])
    status = d.get("status") or {}
    origins = sorted({int(o["origin"]) for o in status.get("origins") or [] if str(o.get("origin", "")).isdigit()})
    anns = [(w["id"], o) for o in origins]
    for m in status.get("more_specifics") or []:
        p, o = m.get("prefix"), m.get("origin")
        if p and str(o).isdigit() and (x := _net(p)) is not None and x.version == net.version and x.subnet_of(net):
            anns.append((str(x), int(o)))
    _origin_rules(w, ws, "ripestat", anns, found, d.get("rpki") or {})
    seen = _vis(status, net.version)
    frac = (seen[0] / seen[1]) if seen and seen[1] else None
    facts = {"origins": origins, "more_specifics": len(anns) - len(origins), "visibility": frac}
    if origins and (frac is None or frac > 0):
        base["last_visible"] = _iso(now)
    else:
        last = _t((status.get("last_seen") or {}).get("time")) or _t(base.get("last_visible"))
        facts["last_seen"] = _iso(last) if last else None
        if last and now - last >= GONE_AFTER:
            hours = int((now - last).total_seconds() // 3600)
            _open(ws, w["id"], "not_visible", NEEDS_YOU, "ripestat", f"{_name(w)}: not visible on the internet",
                  f"RIPE's route collectors have not seen {w['id']} announced since {last.strftime('%d %b %H:%M')} UTC "
                  f"(about {hours} hours). People may not be able to reach it.")
            found.add("not_visible")
    if frac:
        hist = _history(base, "vis", frac)
        if len(hist) >= VIS_MIN_POINTS and frac < VIS_DROP * statistics.median(hist):
            _open(ws, w["id"], "visibility_drop", INFO, "ripestat", f"{_name(w)}: seen by fewer route collectors",
                  f"Seen by {frac:.0%} of RIPE's route-collector peers, against a usual {statistics.median(hist):.0%}. "
                  f"Some networks may have lost their route to it.")
            found.add("visibility_drop")
    return facts


def _ripestat_asn(w: dict, ws: dict, d: dict, found: set[str]) -> dict:
    now = _now()
    base = ws["base"]
    status = d.get("status") or {}
    space = status.get("announced_space") or {}
    try:
        count = int((space.get("v4") or {}).get("prefixes") or 0) + int((space.get("v6") or {}).get("prefixes") or 0)
    except (TypeError, ValueError):
        count = None
    facts: dict = {"prefixes": count}
    if count is not None and "status" in d:
        hist = _history(base, "counts", count)
        if len(hist) >= COUNT_MIN_POINTS:
            med = statistics.median(hist)
            if count >= COUNT_UP * med and count - med >= COUNT_MIN_DIFF:
                _open(ws, w["id"], "new_prefixes", INFO, "ripestat", f"{_name(w)}: announces more networks than usual",
                      f"It announces {count:,} prefixes now, against a usual {med:,.0f}. That is often a new customer "
                      f"or service, sometimes a mistake.")
                found.add("new_prefixes")
    nb = d.get("neighbours")
    if nb is not None:
        ups = sorted({int(n["asn"]) for n in nb.get("neighbours") or [] if n.get("type") == "left" and str(n.get("asn", "")).isdigit()})
        facts["upstreams"] = len(ups)
        known = base.setdefault("upstreams", {})
        first = not known
        for u in ups:
            k = str(u)
            if k not in known:
                known[k] = {"first": "base" if first else _iso(now)}
            known[k]["last"] = _iso(now)
        prev = set(base.get("upstreams_now", []))
        base["upstreams_now"] = ups
        for k in [k for k, v in known.items() if (_t(v.get("last")) or now) < now - BASELINE]:
            del known[k]
        new = [int(k) for k, v in known.items() if (t := _t(v.get("first"))) and t >= now - CHANGE_WINDOW]
        lost_now = {int(k) for k in prev} - set(ups)
        for u in lost_now:
            known[str(u)]["lost"] = _iso(now)
        lost = [int(k) for k, v in known.items() if int(k) not in ups and (t := _t(v.get("lost"))) and t >= now - CHANGE_WINDOW]
        if new or lost:
            parts = ([f"new: {_aslist(new)}"] if new else []) + ([f"gone: {_aslist(lost)}"] if lost else [])
            _open(ws, w["id"], "upstream_change", INFO, "ripestat", f"{_name(w)}: its upstream networks changed",
                  f"The networks it uses to reach the internet changed ({'; '.join(parts)}). Usually a planned "
                  f"change of provider; now and then a sign of trouble.")
            found.add("upstream_change")
    return facts


def _ripestat_updates(w: dict, ws: dict, d: dict, found: set[str]) -> float | None:
    up = d.get("updates")
    hours = float(d.get("hours") or 0)
    if up is None or hours <= 0:
        return None
    total = 0
    for u in up.get("updates") or []:
        try:
            total += int(u.get("announcements") or 0) + int(u.get("withdrawals") or 0)
        except (TypeError, ValueError):
            pass
    rate = total / hours
    hist = _history(ws["base"], "rates", rate)
    if len(hist) >= SPIKE_MIN_POINTS:
        med = statistics.median(hist)
        if rate >= SPIKE_MIN_PER_H and rate >= SPIKE_FACTOR * max(med, 1.0):
            _open(ws, w["id"], "update_spike", INFO, "ripestat", f"{_name(w)}: unusually many routing updates",
                  f"About {rate:,.0f} routing updates an hour since the last check, against a usual {med:,.0f} an hour "
                  f"over the past two weeks. Routes are being changed or are flapping.")
            found.add("update_spike")
    return rate


def ingest_ripestat(results: dict[str, dict]) -> None:
    """results: watch id -> {'ok', 'why', 'status', 'rpki', 'neighbours', 'updates', 'hours'}."""
    with _lock:
        wl = {w["id"]: w for w in watchlist.load()}
        st = sweep(_load())
        for wid, d in results.items():
            w = wl.get(wid)
            if not w:
                continue
            ws = _w(st, wid)
            ws["id"] = wid
            if not d.get("ok"):
                _check(ws, "ripestat", False, d.get("why") or "RIPEstat did not answer")
                continue
            found: set[str] = set()
            facts = (_ripestat_prefix if w["kind"] == "prefix" else _ripestat_asn)(w, ws, d, found)
            rate = _ripestat_updates(w, ws, d, found)
            if rate is not None:
                facts["updates_per_h"] = round(rate, 1)
            ws["facts"]["ripestat"] = facts
            _clear(ws, "ripestat", found)
            _check(ws, "ripestat", True)
        _save(st)


# ---------------------------------------------------------------- RIS Live (one announcement at a time)
def observe_announcements(anns: list[tuple[str, str, int]]) -> None:
    """anns: (watch id, prefix, origin) newly seen on the stream (each pair once per connection)."""
    with _lock:
        wl = {w["id"]: w for w in watchlist.load()}
        st = sweep(_load())
        by: dict[str, list] = {}
        for wid, p, o in anns:
            by.setdefault(wid, []).append((p, int(o)))
        for wid, items in by.items():
            w = wl.get(wid)
            if not w:
                continue
            ws = _w(st, wid)
            ws["id"] = wid
            if w["kind"] == "prefix":
                found: set[str] = set()
                _origin_rules(w, ws, "ris_live", items, found)
                f = ws["facts"].setdefault("ris_live", {})
                f["origins"] = sorted(set(f.get("origins", [])) | {o for p, o in items if p == wid})
            else:
                f = ws["facts"].setdefault("ris_live", {})
                f["prefixes_seen"] = int(f.get("prefixes_seen", 0)) + len(items)
            _check(ws, "ris_live", True)
        _save(st)


def note_check(sid: str, ok: bool, why: str | None = None) -> None:
    """Every watch was checked by sid (a stream that is up, an RPKI file that has not changed) or could not be."""
    with _lock:
        st = sweep(_load())
        for w in watchlist.load():
            ws = _w(st, w["id"])
            ws["id"] = w["id"]
            _check(ws, sid, ok, why)
        _save(st)


# ---------------------------------------------------------------- cards
def _ago_ok(chk: dict | None, within: dt.timedelta) -> bool:
    t = _t((chk or {}).get("at"))
    return bool(chk and chk.get("ok") and t and _now() - t <= within)


def _sentence(w: dict, ws: dict, on: set[str] = frozenset()) -> str:
    f = ws.get("facts", {})
    rp, rs, rl = f.get("rpki_roas"), f.get("ripestat"), f.get("ris_live")
    parts: list[str] = []
    if w["kind"] == "prefix":
        origins = (rs or {}).get("origins") or (rl or {}).get("origins") or []
        if rs or rl:
            parts.append(f"announced by {_aslist(origins)}" if origins else "not announced at the moment")
        if rs and rs.get("visibility"):
            parts.append(f"seen by {rs['visibility']:.0%} of RIPE's route collectors")
        if rp is not None:
            if rp.get("count"):
                mx = f" (up to /{rp['max']})" if rp.get("max") else ""
                parts.append(f"signed with RPKI for {_aslist(rp.get('asns') or [])}{mx}")
            else:
                parts.append("not signed with RPKI")
        if rl and not rs and not (rp or {}).get("count") and not ws.get("base", {}).get("origins"):
            parts.append("no reference origin yet (not signed with RPKI; RIPEstat can provide one)")
        if rp is not None and not (rs or rl):
            parts.append("no live updates for it yet" if "ris_live" in on or "ripestat" in on
                         else "turn on RIPEstat or RIS Live below to see who announces it")
    else:
        if rs and rs.get("prefixes") is not None:
            ups = f" through {rs['upstreams']} upstream network{'s' if rs.get('upstreams') != 1 else ''}" if rs.get("upstreams") is not None else ""
            parts.append(f"announces {rs['prefixes']:,} prefixes{ups}")
        if rl and rl.get("prefixes_seen"):
            parts.append(f"{rl['prefixes_seen']:,} live updates seen")
        if rp is not None:
            n = rp.get("count", 0)
            parts.append(f"{n:,} RPKI record{'s name' if n != 1 else ' names'} it as an allowed origin"
                         if rp.get("count") else "no RPKI records name it")
    if not parts:
        return "Checked; nothing to report."
    s = "; ".join(parts)
    return s[0].upper() + s[1:] + "."


def _short(w: dict, title: str) -> str:
    """The title without the watch's name in front, for a list inside that watch's own card."""
    pre = f"{_name(w)}: "
    t = title[len(pre):] if title.startswith(pre) else title
    return t[:1].upper() + t[1:]


SOURCE_NAMES = {"rpki_roas": "RPKI file", "cf_radar_bgp": "Cloudflare Radar", "ripestat": "RIPEstat", "ris_live": "RIS Live"}


def _source_state(chk: dict | None, interval: int) -> str:
    if not chk:
        return "pending"
    if not chk.get("ok"):
        return "failed"
    return "ok" if _ago_ok(chk, dt.timedelta(seconds=3 * max(interval or 3600, 3600))) else "stale"


def cards(sources: dict[str, dict]) -> list[dict]:
    """One card per watch. sources: id -> {'on': bool, 'interval': s, 'why': reason it cannot check or None}.

    Each source that is on gets its own state (ok, failed, stale, pending); the card shows the worst of them, so one
    working source (a quiet RIS Live connection) never hides another that could not check."""
    st = sweep()
    out = []
    on = {sid: s for sid, s in sources.items() if s.get("on")}
    why = next((s["why"] for s in on.values() if s.get("why")), None)
    for w in watchlist.load():
        ws = st.get(w["id"]) or {"checks": {}, "facts": {}, "events": []}
        ws = {**ws, "checks": ws.get("checks", {}), "facts": ws.get("facts", {})}
        evs = sorted(ws.get("events", []), key=lambda e: e["opened"], reverse=True)
        open_ = [e for e in evs if not e.get("cleared")]
        checks = ws["checks"]
        per = [{"source": sid, "name": SOURCE_NAMES.get(sid, sid), "state": _source_state(checks.get(sid), s.get("interval")),
                "at": (checks.get(sid) or {}).get("at"), "why": (checks.get(sid) or {}).get("why")} for sid, s in on.items()]
        states = {p["state"] for p in per}
        last = max((c["at"] for sid, c in checks.items() if c.get("ok") and sid in sources), default=None)
        failed = next((p for p in per if p["state"] == "failed"), None)
        if open_:
            top = sorted(open_, key=lambda e: (e["level"] != NEEDS_YOU, e["opened"]))[0]
            state, sentence = "changed", top["summary"]
        elif not on:
            state, sentence = "unchecked", "No routing source is on, so nothing checks this network. Turn one on below."
        elif failed:
            state, sentence = "unchecked", f"Couldn't check with {failed['name']}: {failed['why'] or 'it did not answer'}."
        elif why and states - {"ok"}:
            state, sentence = "unchecked", why
        elif "stale" in states:
            name = next(p["name"] for p in per if p["state"] == "stale")
            state, sentence = "unchecked", f"Couldn't check recently: {name}'s last successful check is too old."
        elif "pending" in states:   # a new watch: no "Normal" until every source that is on has looked at it
            waiting = [p["name"] for p in per if p["state"] == "pending"]
            state = "pending"
            sentence = (f"Checking… {', '.join(waiting)} {'has' if len(waiting) == 1 else 'have'} not looked at it yet."
                        if len(waiting) < len(per) else "Checking… the first check runs within a few minutes.")
        else:
            state, sentence = "normal", _sentence(w, ws, set(on))
        out.append({"id": w["id"], "kind": w["kind"], "label": w.get("label") or w["id"], "state": state,
                    "sentence": sentence, "last_checked": last, "checks": per,
                    "needs_you": sum(1 for e in open_ if e["level"] == NEEDS_YOU), "open": len(open_),
                    "events": [{**{k: e.get(k) for k in ("kind", "level", "source", "title", "summary", "opened", "seen", "cleared")},
                                "short": _short(w, e["title"])} for e in evs[:5]]})
    return out

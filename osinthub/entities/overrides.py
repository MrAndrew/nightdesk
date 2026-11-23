"""User overrides on entity identity: "Same as…" (merge), "Wrong type…" (retype) and "Not the same" (a
dismissed duplicate suggestion). Docs: okf/data/entities.md#overrides

A merge moves one entity's mentions and claims onto another, unions the names, and deletes the merged entity.
It is kept as one row in `entity_overrides` with a snapshot of what moved, so it can be undone, and as a
redirect (merged id -> kept id) that every writer in store.py applies: re-extraction, linking and reference
imports that produce the old id land on the kept entity instead of recreating the duplicate.
A retype is a merge into the same name under another type (created when it does not exist yet).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import threading

from .. import db
from . import store
from .normalize import GENERIC, entity_id, is_placeholder, key, stripped_key

# Named things a person can say are the same or of the wrong type. Indicators (IPs, hashes...) have no
# identity question: two different values are two different things.
NAMED_TYPES = ("actor", "campaign", "malware", "tool", "org", "vendor", "product", "sector", "country")
# Duplicate suggestions look only at the threat types, where one group's names are split today.
SUGGEST_TYPES = ("actor", "campaign", "malware", "tool")
RETYPE_TO = ("actor", "campaign", "malware", "tool", "org", "vendor", "product")

_lock = threading.RLock()
_redirects: dict[str, str] | None = None
_version = 0


class OverrideError(ValueError):
    """A request the user can fix (wrong ids, an undo out of order); the API turns it into a 400/409."""

    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def _j(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def _iso(v):
    if isinstance(v, dt.datetime):
        return (v if v.tzinfo else v.replace(tzinfo=dt.UTC)).isoformat()
    return v


def version() -> int:
    return _version


def invalidate() -> None:
    global _redirects, _version
    with _lock:
        _redirects = None
        _version += 1
    try:   # the search corpus caches names and aliases; rebuild it on the next query
        from . import searcher
        searcher._corpus["n"] = -1
        searcher._corpus["t"] = 0
    except Exception:
        pass


def redirects() -> dict[str, str]:
    """merged or retyped id -> the id it now lives under (chains followed)."""
    global _redirects
    with _lock:
        if _redirects is None:
            try:
                rows = db.cursor().execute(
                    "SELECT src, dst FROM entity_overrides WHERE action IN ('merge','retype') ORDER BY created_at").fetchall()
            except Exception:   # no table yet (a caller before ensure_schema)
                return {}
            m = {s: d for s, d in rows}
            out = {}
            for s in m:
                d, hops = m[s], 0
                while d in m and hops < 20 and d != s:
                    d, hops = m[d], hops + 1
                if d != s:
                    out[s] = d
            _redirects = out
        return _redirects


def resolve(eid: str) -> str:
    """The id an entity lives under now. Use it wherever a stored entity id is read (watchlists, links,
    bookmarks): stored lists are never rewritten, so an Undo needs no clean-up elsewhere."""
    return redirects().get(eid, eid) if eid else eid


def equivalents(eid: str) -> list[str]:
    """Every id that means the same entity now: the stored id, the id it lives under, and the ids merged into
    that one. Text that still carries an old id (story top_entities) matches through these."""
    if not eid:
        return []
    r = resolve(eid)
    return list(dict.fromkeys([eid, r, *sorted(s for s, d in redirects().items() if d == r)]))


# ------------------------------------------------------------------------------------------------ apply
def _ndjson_load(cur, rows: list[dict], tmp: str, kind: str) -> None:
    cols = {
        "claims": "{'id':'VARCHAR','subj':'VARCHAR','predicate':'VARCHAR','obj':'VARCHAR','origin':'VARCHAR','sources':'VARCHAR[]',"
                  "'confidence':'DOUBLE','first_seen':'TIMESTAMPTZ','last_seen':'TIMESTAMPTZ','evidence':'VARCHAR'}",
        "mentions": "{'entity_id':'VARCHAR','ref_type':'VARCHAR','ref_id':'VARCHAR','role':'VARCHAR','method':'VARCHAR',"
                    "'confidence':'DOUBLE','ts':'TIMESTAMPTZ'}",
    }[kind]
    p = store._ndjson(rows, tmp)
    try:
        cur.execute(f"CREATE OR REPLACE TEMP TABLE _{tmp} AS SELECT * FROM read_json('{store._q(p)}', format='newline_delimited', columns={cols})")
    finally:
        p.unlink(missing_ok=True)


def _claim_rows(cur, where: str, params) -> list[dict]:
    cols = ["id", "subj", "predicate", "obj", "origin", "sources", "confidence", "first_seen", "last_seen", "evidence"]
    rows = cur.execute(f"SELECT {', '.join(cols)} FROM claims WHERE {where}", params).fetchall()
    out = []
    for r in rows:
        d = dict(zip(cols, r))
        d["evidence"] = _j(d["evidence"]) or []
        d["sources"] = list(d["sources"] or [])
        d["first_seen"], d["last_seen"] = _iso(d["first_seen"]), _iso(d["last_seen"])
        out.append(d)
    return out


def _insert_claims(cur, rows: list[dict]) -> None:
    if not rows:
        return
    _ndjson_load(cur, [dict(r, evidence=json.dumps(r["evidence"])) for r in rows], "oc", "claims")
    cur.execute("""INSERT INTO claims SELECT id, subj, predicate, obj, origin, sources, confidence, first_seen, last_seen,
                   evidence::JSON FROM _oc""")
    cur.execute("DROP TABLE _oc")


def _insert_mentions(cur, rows: list[dict]) -> None:
    if not rows:
        return
    _ndjson_load(cur, rows, "om", "mentions")
    cur.execute("""INSERT INTO mentions SELECT n.entity_id, n.ref_type, n.ref_id, n.role, n.method, n.confidence, n.ts
                   FROM _om n ANTI JOIN mentions m USING (entity_id, ref_type, ref_id, role)""")
    cur.execute("DROP TABLE _om")


def _evk(e) -> str:
    """Identity of one evidence item (as store._dedupe_evidence; verdict items by their time)."""
    if not isinstance(e, dict):
        return json.dumps(e, sort_keys=True, default=str)
    return json.dumps([e.get("source"), e.get("ref_id"), e.get("quote"), e.get("verdict"), e.get("ts")], default=str)


def _merge_claim(a: dict, b: dict) -> dict:
    """Two claims on one (subj, predicate, obj, origin): sources unioned, evidence joined, seen times widened."""
    out = dict(b)
    out["sources"] = list(dict.fromkeys((b.get("sources") or []) + (a.get("sources") or [])))
    ev = (b.get("evidence") or []) + (a.get("evidence") or [])
    if out["origin"] == "user":   # a verdict history: latest last, newest kept
        ev = sorted([e for e in ev if isinstance(e, dict)], key=lambda e: str(e.get("ts") or ""))[-store.EVIDENCE_CAP:]
    else:
        ev = store._dedupe_evidence(ev)[:store.EVIDENCE_CAP]
    out["evidence"] = ev
    for k, f in (("first_seen", min), ("last_seen", max)):
        vs = [v for v in (a.get(k), b.get(k)) if v]
        out[k] = f(vs) if vs else None
    out["confidence"] = None if out["origin"] != "inferred" else b.get("confidence")
    return out


def _repoint_mentions(cur, frm: str, to: str) -> None:
    cur.execute("""INSERT INTO mentions SELECT ?, m.ref_type, m.ref_id, m.role, m.method, m.confidence, m.ts FROM mentions m
                   WHERE m.entity_id = ? AND NOT EXISTS (SELECT 1 FROM mentions d WHERE d.entity_id = ?
                         AND d.ref_type = m.ref_type AND d.ref_id = m.ref_id AND d.role = m.role)""", [to, frm, to])
    cur.execute("DELETE FROM mentions WHERE entity_id = ?", [frm])


def _repoint_claims(cur, frm: str, to: str) -> tuple[list, list, dict]:
    """Every claim on frm re-pointed onto to, merged with a claim to already holds; loops dropped.
    Returns (frm's original rows, to's rows they merged into, the written rows by id)."""
    old = _claim_rows(cur, "subj = ? OR obj = ?", [frm, frm])
    new: dict[str, dict] = {}
    for c in old:
        s = to if c["subj"] == frm else c["subj"]
        o = to if c["obj"] == frm else c["obj"]
        if s == o:
            continue
        cid = store.claim_id(s, c["predicate"], o, c["origin"])
        r = dict(c, id=cid, subj=s, obj=o, confidence=None if c["origin"] != "inferred" else c["confidence"])
        new[cid] = _merge_claim(r, new[cid]) if cid in new else r
    collided = _claim_rows(cur, "id IN (SELECT unnest(?))", [list(new)]) if new else []
    for c in collided:
        new[c["id"]] = _merge_claim(new[c["id"]], c)
    cur.execute("DELETE FROM claims WHERE subj = ? OR obj = ?", [frm, frm])
    if collided:
        cur.execute("DELETE FROM claims WHERE id IN (SELECT unnest(?))", [[c["id"] for c in collided]])
    _insert_claims(cur, list(new.values()))
    return old, collided, new


def _ts(v):
    if v is None or isinstance(v, dt.datetime):
        return v
    try:
        x = dt.datetime.fromisoformat(str(v))
        return x if x.tzinfo else x.replace(tzinfo=dt.UTC)
    except ValueError:
        return None


def _entity(cur, eid: str) -> dict | None:
    r = cur.execute("SELECT id, type, name, aliases, attrs, first_seen, last_seen FROM entities WHERE id = ?", [eid]).fetchall()
    if not r:
        return None
    i, t, n, al, at, f, l = r[0]
    return {"id": i, "type": t, "name": n, "aliases": list(al or []), "attrs": _j(at) or {}, "first_seen": _iso(f), "last_seen": _iso(l)}


def _oid(action: str, src: str, dst: str) -> str:
    now = dt.datetime.now(dt.UTC).isoformat()
    return hashlib.sha1(f"{action}|{src}|{dst}|{now}".encode()).hexdigest()[:16]


def _move(src: str, dst: str, action: str, note: str = "") -> dict:
    """Move everything of src onto dst (created from src when missing) and record the override."""
    now = dt.datetime.now(dt.UTC)
    with store._tx() as cur:
        a = _entity(cur, src)
        if a is None:
            raise OverrideError("That entity no longer exists (it may have been merged already).", 404)
        b = _entity(cur, dst)
        created = b is None
        if created:
            b = {"id": dst, "type": dst.split(":", 1)[0], "name": a["name"], "aliases": [], "attrs": {}, "first_seen": None, "last_seen": None}
        b_before = json.loads(json.dumps(b))
        # mentions: src's rows move unless dst already holds the same one
        mcols = ["entity_id", "ref_type", "ref_id", "role", "method", "confidence", "ts"]
        ments = [dict(zip(mcols, r)) for r in cur.execute(f"SELECT {', '.join(mcols)} FROM mentions WHERE entity_id = ?", [src]).fetchall()]
        for m in ments:
            m["ts"] = _iso(m["ts"])
        have = {tuple(r) for r in cur.execute("SELECT ref_type, ref_id, role FROM mentions WHERE entity_id = ?", [dst]).fetchall()}
        moved_m = [[m["ref_type"], m["ref_id"], m["role"]] for m in ments if (m["ref_type"], m["ref_id"], m["role"]) not in have]
        _repoint_mentions(cur, src, dst)
        # claims: re-pointed onto dst; a link between the two ends becomes a loop and is dropped
        old, collided, new = _repoint_claims(cur, src, dst)
        # what each written claim held right after the merge, so Undo can tell later additions apart
        coll = {c["id"] for c in collided}
        origin_of: dict[str, list[str]] = {}
        for c in old:
            sj = dst if c["subj"] == src else c["subj"]
            ob = dst if c["obj"] == src else c["obj"]
            if sj != ob:
                origin_of.setdefault(store.claim_id(sj, c["predicate"], ob, c["origin"]), []).append(c["id"])
        written = {cid: {"ev": [_evk(e) for e in r["evidence"]], "src": list(r["sources"] or []),
                         "both": cid in coll, "from": origin_of.get(cid, [])} for cid, r in new.items()}
        # the kept entity takes the other's names; its own name, type and facts win
        names = [a["name"], *a["aliases"]] if a["name"] else list(a["aliases"])
        added = [x for x in dict.fromkeys(names) if x and x != b["name"] and x not in b["aliases"]]
        attrs = {**(a["attrs"] if isinstance(a["attrs"], dict) else {}), **(b["attrs"] if isinstance(b["attrs"], dict) else {})}
        seen_f = min([_ts(v) for v in (a["first_seen"], b["first_seen"]) if _ts(v)], default=None)
        seen_l = max([_ts(v) for v in (a["last_seen"], b["last_seen"]) if _ts(v)], default=None)
        if created:
            added = [x for x in dict.fromkeys(a["aliases"]) if x and x != b["name"]]
            attrs = dict(a["attrs"]) if isinstance(a["attrs"], dict) else {}
            cur.execute("INSERT INTO entities VALUES (?, ?, ?, ?, ?::JSON, ?, ?)",
                        [dst, b["type"], b["name"], added, json.dumps(attrs), seen_f, seen_l])
        else:
            cur.execute("UPDATE entities SET aliases = ?, attrs = ?::JSON, first_seen = ?, last_seen = ? WHERE id = ?",
                        [b["aliases"] + added, json.dumps(attrs), seen_f, seen_l, dst])
        cur.execute("DELETE FROM entities WHERE id = ?", [src])
        cur.execute("DELETE FROM entity_dirty WHERE id = ?", [src])
        cur.execute("DELETE FROM entity_vec WHERE id IN (?, ?)", [src, dst])   # re-embed the kept one with its new aliases
        snap = {"src": a, "dst_before": b_before, "dst_created": created, "added_aliases": added,
                "mentions": ments, "moved_mentions": moved_m, "claims": old, "collided": collided, "new_claims": list(new),
                "written": written}
        oid = _oid(action, src, dst)
        cur.execute("INSERT INTO entity_overrides VALUES (?, ?, ?, ?, ?, ?, ?::JSON)",
                    [oid, action, src, dst, note[:1000], now, json.dumps(snap, default=str)])
    invalidate()
    store.mark_dirty([dst])
    return {"id": oid, "action": action, "src": src, "dst": dst, "src_name": a["name"], "dst_name": b["name"],
            "src_type": a["type"], "dst_type": b["type"],
            "dst_created": created, "mentions_moved": len(moved_m), "claims_moved": len(old)}


def merge(src: str, dst: str, note: str = "") -> dict:
    """"Same as…": src joins dst. Both must exist and be named things."""
    if not src or not dst or src == dst:
        raise OverrideError("Pick two different entities.")
    if resolve(src) != src:
        raise OverrideError("That entity was already merged into another one; reload and try again.", 409)
    dst = resolve(dst)
    if src == dst:
        raise OverrideError("These two are already one entity.")
    for x in (src, dst):
        if x.split(":", 1)[0] not in NAMED_TYPES:
            raise OverrideError("Only named things (threat actors, malware, tools, campaigns, organisations…) can be merged.")
    if not db.query("SELECT 1 FROM entities WHERE id = ?", [dst]):
        raise OverrideError("The entity to keep does not exist.", 404)
    return _move(src, dst, "merge", note)


def retype(src: str, new_type: str, note: str = "") -> dict:
    """"Wrong type…": the same name under another type (joins an existing entity of that type and name)."""
    src = resolve(src)
    t = src.split(":", 1)[0]
    if t not in NAMED_TYPES:
        raise OverrideError("Only named things can change type.")
    if new_type not in RETYPE_TO:
        raise OverrideError(f"New type must be one of: {', '.join(RETYPE_TO)}.")
    if new_type == t:
        raise OverrideError("It already has that type.")
    rows = db.query("SELECT name FROM entities WHERE id = ?", [src])
    if not rows:
        raise OverrideError("That entity no longer exists.", 404)
    dst = resolve(f"{new_type}:{src.split(':', 1)[1]}")
    if dst.split(":", 1)[0] != new_type or dst == src:
        dst = entity_id(new_type, rows[0]["name"] or src.split(":", 1)[1])
    return _move(src, dst, "retype", note)


def not_same(a: str, b: str, note: str = "") -> dict:
    """"Not the same": stop suggesting this pair."""
    if not a or not b or a == b:
        raise OverrideError("Pick two different entities.")
    x, y = sorted((a, b))
    if db.query("SELECT 1 FROM entity_overrides WHERE action = 'distinct' AND src = ? AND dst = ?", [x, y]):
        return {"action": "distinct", "src": x, "dst": y, "id": db.query(
            "SELECT id FROM entity_overrides WHERE action = 'distinct' AND src = ? AND dst = ?", [x, y])[0]["id"]}
    oid = _oid("distinct", x, y)
    store.execute("INSERT INTO entity_overrides VALUES (?, 'distinct', ?, ?, ?, now(), NULL)", [oid, x, y, note[:1000]])
    invalidate()
    return {"id": oid, "action": "distinct", "src": x, "dst": y}


_TYPE_WORD = {"actor": "threat actor", "org": "organisation"}


def _plan(cur, o: dict, s: dict) -> dict:
    """What happened on the kept entity since a merge, and where Undo puts it.
    * A later source, evidence item or verdict on a claim that came only from the merged entity goes back to it.
    * A later verdict on a link of the merged entity that the kept one did not have (a new verdict row) goes back.
    * Anything on a link both had cannot be split: it stays on the kept entity, and is listed before Undo."""
    src, dst = o["src"], o["dst"]
    written = s.get("written") or {}
    orig = {c["id"]: c for c in (s.get("claims") or [])}
    coll = {c["id"]: c for c in (s.get("collided") or [])}
    names = {r[0]: r[1] for r in cur.execute("SELECT id, name FROM entities WHERE id IN (?, ?)", [src, dst]).fetchall()}
    a_name = (s.get("src") or {}).get("name") or src.split(":", 1)[-1]
    d_name = names.get(dst) or dst.split(":", 1)[-1]
    if a_name.lower() == d_name.lower():           # one name, two entries: say which is which
        a_name, d_name = f"the {_TYPE_WORD.get(src.split(':', 1)[0], src.split(':', 1)[0])} {a_name}", \
            f"the {_TYPE_WORD.get(dst.split(':', 1)[0], dst.split(':', 1)[0])} {d_name}"
    back: dict[str, dict] = {}            # original claim id -> {"ev": [...], "src": [...]}, added to the restored row
    keep_b: dict[str, dict] = {}          # collided id -> additions kept on the kept entity's restored row
    stays: list[str] = []
    moved = 0
    cur_rows = {c["id"]: c for c in _claim_rows(cur, "id IN (SELECT unnest(?))", [list(written)])} if written else {}

    def other(c):
        x = c["obj"] if c["subj"] == dst else c["subj"]
        if x not in names:
            r = cur.execute("SELECT name FROM entities WHERE id = ?", [x]).fetchall()
            names[x] = r[0][0] if r and r[0][0] else x.split(":", 1)[-1]
        return names[x]

    for cid, w in written.items():
        c = cur_rows.get(cid)
        if not c:
            continue
        have = set(w.get("ev") or [])
        ev = [e for e in c["evidence"] if _evk(e) not in have]
        srcs = [x for x in c["sources"] if x not in set(w.get("src") or [])]
        if not ev and not srcs:
            continue
        if w.get("both") or not w.get("from"):
            keep_b[cid] = {"ev": ev, "src": srcs}
            what = "your verdict" if c["origin"] == "user" else f"{len(ev) or len(srcs)} new source item{'s' if (len(ev) or len(srcs)) != 1 else ''}"
            stays.append(f"{what[:1].upper() + what[1:]} on “{c['predicate'].replace('-', ' ')} {other(c)}”, a link both had")
        else:
            back[w["from"][0]] = {"ev": ev, "src": srcs}
            moved += len(ev) or 1
    # verdict rows made after the merge, on links that came from the merged entity
    from_a = {cid for cid, w in written.items() if w.get("from") and not w.get("both")}
    a_triples = {}
    for cid in from_a:
        oc = orig.get(written[cid]["from"][0])
        if oc:
            a_triples[(dst if oc["subj"] == src else oc["subj"], oc["predicate"], dst if oc["obj"] == src else oc["obj"])] = oc
    b_triples = {(c["subj"], c["predicate"], c["obj"]) for c in coll.values()}
    new_user = []
    for c in _claim_rows(cur, "origin = 'user' AND (subj = ? OR obj = ?) AND id NOT IN (SELECT unnest(?))", [dst, dst, list(written) or [""]]):
        k = (c["subj"], c["predicate"], c["obj"])
        if k in a_triples:
            oc = a_triples[k]
            new_user.append((c, oc["subj"], oc["obj"]))
            moved += 1
        elif k in b_triples:                       # a link both had: the verdict stays with the kept entity
            stays.append(f"Your verdict on “{c['predicate'].replace('-', ' ')} {other(c)}”, a link both had")
    return {"back": back, "keep_b": keep_b, "new_user": new_user, "stays": stays, "moved_back": moved,
            "src_name": a_name, "dst_name": d_name}


def _add(row: dict, ev: list, srcs: list) -> dict:
    out = dict(row)
    out["sources"] = list(dict.fromkeys(list(row.get("sources") or []) + list(srcs)))
    allev = list(row.get("evidence") or []) + list(ev)
    if row.get("origin") == "user":
        allev = sorted([e for e in allev if isinstance(e, dict)], key=lambda e: str(e.get("ts") or ""))[-store.EVIDENCE_CAP:]
    else:
        allev = store._dedupe_evidence(allev)[:store.EVIDENCE_CAP]
    out["evidence"] = allev
    return out


def undo_preview(oid: str) -> dict:
    """What Undo would do with changes made since the merge (see _plan), without doing it."""
    rows = db.query("SELECT * FROM entity_overrides WHERE id = ?", [oid])
    if not rows:
        raise OverrideError("Nothing to undo: that change is not on record.", 404)
    o = rows[0]
    if o["action"] == "distinct":
        return {"id": oid, "action": "distinct", "moved_back": 0, "stays": []}
    p = _plan(db.cursor(), o, _j(o["snapshot"]) or {})
    return {"id": oid, "action": o["action"], "src_name": p["src_name"], "dst_name": p["dst_name"],
            "moved_back": p["moved_back"], "stays": p["stays"]}


def undo(oid: str) -> dict:
    """Withdraw an override. A merge or retype can be undone while it is the latest change touching either
    entity; later merges into the same entity have to be undone first."""
    rows = db.query("SELECT * FROM entity_overrides WHERE id = ?", [oid])
    if not rows:
        raise OverrideError("Nothing to undo: that change is not on record.", 404)
    o = rows[0]
    if o["action"] == "distinct":
        store.execute("DELETE FROM entity_overrides WHERE id = ?", [oid])
        invalidate()
        return {"undone": oid, "action": "distinct", "src": o["src"], "dst": o["dst"]}
    src, dst = o["src"], o["dst"]
    later = db.query("""SELECT id, src, dst FROM entity_overrides WHERE action IN ('merge','retype') AND created_at > ?
                        AND (src IN (?, ?) OR dst IN (?, ?))""", [o["created_at"], src, dst, src, dst])
    if later:
        raise OverrideError("A later merge changed the same entity. Undo that one first.", 409)
    s = _j(o["snapshot"]) or {}
    with store._tx() as cur:
        if cur.execute("SELECT 1 FROM entities WHERE id = ?", [src]).fetchall():
            raise OverrideError("The merged entity has been created again; this merge can't be undone cleanly.", 409)
        plan = _plan(cur, o, s)
        for c, _sj, _ob in plan["new_user"]:        # later verdicts on the merged entity's links go back with it
            cur.execute("DELETE FROM claims WHERE id = ?", [c["id"]])
        # claims: the rewritten rows go, the originals of both sides come back
        if s.get("new_claims"):
            cur.execute("DELETE FROM claims WHERE id IN (SELECT unnest(?))", [s["new_claims"]])
        restore = [dict(c, confidence=c.get("confidence") if c.get("origin") in ("inferred", "user") else None)
                   for c in (s.get("claims") or []) + (s.get("collided") or [])]
        extra = {**plan["back"], **plan["keep_b"]}
        restore = [_add(c, extra[c["id"]]["ev"], extra[c["id"]]["src"]) if c["id"] in extra else c for c in restore]
        for c, sj, ob in plan["new_user"]:
            restore.append(dict(c, id=store.claim_id(sj, c["predicate"], ob, "user"), subj=sj, obj=ob))
        if restore:
            cur.execute("DELETE FROM claims WHERE id IN (SELECT unnest(?))", [[c["id"] for c in restore]])
        _insert_claims(cur, restore)
        # mentions: the moved ones go back
        for rt, ri, role in s.get("moved_mentions") or []:
            cur.execute("DELETE FROM mentions WHERE entity_id = ? AND ref_type = ? AND ref_id = ? AND role = ?", [dst, rt, ri, role])
        _insert_mentions(cur, s.get("mentions") or [])
        a = s["src"]
        cur.execute("INSERT INTO entities VALUES (?, ?, ?, ?, ?::JSON, ?, ?)",
                    [a["id"], a["type"], a["name"], a["aliases"], json.dumps(a["attrs"] or {}), _ts(a["first_seen"]), _ts(a["last_seen"])])
        if s.get("dst_created"):
            # anything that reached the new entity since moves to the restored one; then it goes
            _repoint_mentions(cur, dst, src)
            _repoint_claims(cur, dst, src)
            cur.execute("DELETE FROM entities WHERE id = ?", [dst])
        else:
            cur_al = cur.execute("SELECT aliases FROM entities WHERE id = ?", [dst]).fetchall()
            if cur_al:
                drop = set(s.get("added_aliases") or [])
                al = [x for x in (cur_al[0][0] or []) if x not in drop]
                b = s.get("dst_before") or {}
                cur.execute("UPDATE entities SET aliases = ?, attrs = ?::JSON, first_seen = ?, last_seen = ? WHERE id = ?",
                            [al, json.dumps(b.get("attrs") or {}), _ts(b.get("first_seen")), _ts(b.get("last_seen")), dst])
                cur.execute("""UPDATE entities SET first_seen = least(coalesce(first_seen, m.f), m.f), last_seen = greatest(coalesce(last_seen, m.l), m.l)
                               FROM (SELECT min(ts) AS f, max(ts) AS l FROM mentions WHERE entity_id = ?) m
                               WHERE entities.id = ? AND m.f IS NOT NULL""", [dst, dst])
        cur.execute("DELETE FROM entity_vec WHERE id IN (?, ?)", [src, dst])
        cur.execute("DELETE FROM entity_overrides WHERE id = ?", [oid])
    invalidate()
    store.mark_dirty([src, dst])
    return {"undone": oid, "action": o["action"], "src": src, "dst": dst, "moved_back": plan["moved_back"], "stays": plan["stays"]}


def listing(limit: int = 200) -> list[dict]:
    rows = db.query("""SELECT o.id, o.action, o.src, o.dst, o.note, o.created_at,
                              json_extract_string(o.snapshot, '$.src.name') AS src_name, d.name AS dst_name, s.name AS src_now
                       FROM entity_overrides o LEFT JOIN entities d ON d.id = o.dst LEFT JOIN entities s ON s.id = o.src
                       ORDER BY o.created_at DESC LIMIT ?""", [limit])
    out = []
    for r in rows:
        out.append({"id": r["id"], "action": r["action"], "src": r["src"], "dst": r["dst"], "note": r["note"] or "",
                    "ts": _iso(r["created_at"]), "src_name": r["src_name"] or r["src_now"] or r["src"].split(":", 1)[1],
                    "dst_name": r["dst_name"] or r["dst"].split(":", 1)[1]})
    return out


def merged_into(eid: str) -> list[dict]:
    """Entities merged or retyped into eid (for "Merged here … Undo")."""
    return [o for o in listing(1000) if o["action"] in ("merge", "retype") and resolve(o["dst"]) == eid]


# ------------------------------------------------------------------------------------------------ suggestions
_sugg_cache: dict = {"key": None, "items": []}


def _keys(name: str) -> set[str]:
    out = set()
    for k in (key(name or ""), stripped_key(name or "")):
        if len(k) >= 4 and k not in GENERIC and not k.isdigit():
            out.add(k)
    return out


def suggestions() -> list[dict]:
    """Likely duplicates among named threat entities: one name under two types (actor and malware "Akira"),
    or one entity listing another's name as an alias ("AgendaCrypt" aka "Qilin"). Pairs marked "Not the same"
    are left out. Most-mentioned first."""
    n = db.query(f"SELECT count(*) AS n FROM entities WHERE type IN {SUGGEST_TYPES}")[0]["n"]
    ck = (n, _version)
    if _sugg_cache["key"] == ck:
        return _sugg_cache["items"]
    ents = db.query(f"""SELECT e.id, e.type, e.name, e.aliases, coalesce(m.n, 0) AS mentions, coalesce(c.n, 0) AS claims
                        FROM entities e
                        LEFT JOIN (SELECT entity_id, count(*) AS n FROM mentions WHERE entity_id IN
                                   (SELECT id FROM entities WHERE type IN {SUGGEST_TYPES}) GROUP BY 1) m ON m.entity_id = e.id
                        LEFT JOIN (SELECT x, count(*) AS n FROM (SELECT subj AS x FROM claims WHERE origin <> 'inferred'
                                   UNION ALL SELECT obj FROM claims WHERE origin <> 'inferred') GROUP BY 1) c ON c.x = e.id
                        WHERE e.type IN {SUGGEST_TYPES}""")
    by_id = {e["id"]: e for e in ents}
    names: dict[str, list[str]] = {}
    aliases: dict[str, list[str]] = {}
    for e in ents:
        if is_placeholder(e["name"] or ""):
            continue
        for k in _keys(e["name"]):
            names.setdefault(k, []).append(e["id"])
        for a in e["aliases"] or []:
            for k in _keys(a):
                aliases.setdefault(k, []).append(e["id"])
    dismissed = {(r["src"], r["dst"]) for r in db.query("SELECT src, dst FROM entity_overrides WHERE action = 'distinct'")}
    pairs: dict[tuple, dict] = {}

    # strength: 0 the same name, 1 one lists the other's name (same type), 2 a similar name ("Akira" and
    # "Akira Stealer"), 3 an actor listing a malware or tool name (MISP often lists a group's tools as synonyms)
    def add(x, y, why, k, tier):
        a, b = sorted((x, y))
        if a == b or (a, b) in dismissed:
            return
        p = pairs.setdefault((a, b), {"reasons": [], "key": k, "tier": tier})
        p["tier"] = min(p["tier"], tier)
        if why not in p["reasons"]:
            p["reasons"].append(why)

    for k, ids in names.items():
        ids = list(dict.fromkeys(ids))
        if 1 < len(ids) <= 4:
            for i, x in enumerate(ids):
                for y in ids[i + 1:]:
                    tx, ty = x.split(":", 1)[0], y.split(":", 1)[0]
                    same = key(by_id[x]["name"] or "") == key(by_id[y]["name"] or "")
                    if same:
                        add(x, y, "same name" if tx == ty else "same name under two types", k, 0)
                    else:
                        add(x, y, "similar name", k, 2)
    for k, holders in aliases.items():
        named = names.get(k) or []
        if not named or len(set(holders)) > 4 or len(set(named)) > 4:
            continue
        for h in set(holders):
            for x in set(named):
                if h != x:
                    add(h, x, f"{by_id[h]['name']} lists “{by_id[x]['name']}” as another name", k,
                        1 if h.split(":", 1)[0] == x.split(":", 1)[0] else 3)
    items = []
    for (a, b), p in pairs.items():
        ea, eb = by_id[a], by_id[b]
        if not (ea["mentions"] or eb["mentions"]):
            continue          # two reference entries nothing has mentioned yet: they split no counts
        # the better-documented one is the suggested keeper
        keep, other = (ea, eb) if (ea["mentions"] + ea["claims"], ea["id"]) >= (eb["mentions"] + eb["claims"], eb["id"]) else (eb, ea)
        items.append({"id": f"{a}|{b}", "a": _brief(keep), "b": _brief(other), "reasons": p["reasons"],
                      "strength": ("strong", "strong", "possible", "weak")[p["tier"]], "tier": p["tier"],
                      "weight": ea["mentions"] + eb["mentions"] + ea["claims"] + eb["claims"]})
    # the surest first, then the most used
    items.sort(key=lambda x: (x["tier"], -x["weight"], x["id"]))
    _sugg_cache.update(key=ck, items=items)
    return items


def _brief(e: dict) -> dict:
    return {"id": e["id"], "type": e["type"], "name": e["name"], "mentions": e["mentions"], "claims": e["claims"],
            "aliases": list(e["aliases"] or [])[:6]}


def suggestions_for(eid: str) -> list[dict]:
    return [s for s in suggestions() if eid in (s["a"]["id"], s["b"]["id"])][:6]

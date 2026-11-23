"""Reference data: MITRE ATT&CK Enterprise (STIX) and MISP galaxies, cached in <lake>/ref/.

Downloaded once; with config.OFFLINE or no network the cached copy is used. Loaded into an
in-memory catalogue (entities, alias index, technique names, reported relations) that both
extraction and the database import use. Docs: okf/data/entities.md#reference-data
"""
from __future__ import annotations

import difflib
import json
import logging
import re
import threading
from collections import defaultdict
from pathlib import Path

from .. import config
from ..sources import caps
from .normalize import digits, entity_id, key, specific_tokens, stripped_key, tokens

log = logging.getLogger("osinthub.entities.ref")

REF = Path(config.REF_DIR)
FILES = {
    "attack": ("enterprise-attack.json",
               "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"),
    "misp_actor": ("misp-threat-actor.json", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"),
    "misp_malpedia": ("misp-malpedia.json", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json"),
    "misp_tool": ("misp-tool.json", "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/tool.json"),
    "psl": ("public_suffix_list.dat", "https://publicsuffix.org/list/public_suffix_list.dat"),
    "tlds": ("tlds-alpha-by-domain.txt", "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"),
}
SRC_ATTACK = "MITRE ATT&CK"
SRC_MISP = "MISP galaxy"


def offline() -> bool:
    return bool(config.OFFLINE)


def path(name: str) -> Path:
    return REF / FILES[name][0]


def ensure(names=None, timeout: float = 120) -> dict[str, str]:
    """Download missing reference files. Never raises; returns {name: status}."""
    import httpx
    out = {}
    for name in names or FILES:
        p = path(name)
        if p.exists() and p.stat().st_size > 0:
            out[name] = "cached"
            continue
        if offline():
            out[name] = "missing (offline)"
            continue
        try:
            # read with a size cap counted after decoding, redirects followed by hand (sources/caps.py)
            with httpx.Client(timeout=timeout, headers={"User-Agent": config.USER_AGENT}, follow_redirects=False) as c:
                r = caps.get_sync(c, FILES[name][1], f"ref_{name}")
                r.raise_for_status()
            tmp = p.with_suffix(p.suffix + ".part")
            tmp.write_bytes(r.content)
            tmp.replace(p)
            out[name] = f"downloaded {len(r.content)} bytes"
        except Exception as e:  # network down, proxy dead, ...
            out[name] = f"failed: {type(e).__name__}"
            log.warning("reference %s not downloaded: %s", name, e)
    return out


# ---------------------------------------------------------------- catalogue
class Catalog:
    def __init__(self):
        self.entities: dict[str, dict] = {}
        self.alias: dict[str, dict[str, int]] = defaultdict(dict)       # key -> {entity id: priority}
        self.salias: dict[str, dict[str, int]] = defaultdict(dict)      # stripped key -> {entity id: priority}
        self.tech_name: dict[str, str] = {}                             # T1059.001 -> "PowerShell"
        self.tech_full: dict[str, str] = {}                             # T1059.001 -> "Command and Scripting Interpreter: PowerShell"
        self.tech_by_name: dict[str, set[str]] = defaultdict(set)       # key(name) -> ids
        self.relations: list[tuple[str, str, str, str, str]] = []       # subj, predicate, obj, source, url
        self.tlds: set[str] = set()
        self.suffixes: set[str] = set()
        self._fuzzy_keys: dict[str, list[str]] = {}
        self.alias_text: dict[str, set[str]] = defaultdict(set)         # stripped key -> original strings
        self.malpedia: dict[str, str] = {}                              # Malpedia id (win.dridex) -> entity id

    # -- building
    def add(self, type_: str, name: str, aliases=(), attrs=None, eid: str | None = None, prio: int = 1) -> str:
        eid = eid or entity_id(type_, name)
        e = self.entities.get(eid)
        if e is None:
            e = self.entities[eid] = {"id": eid, "type": type_, "name": name, "aliases": [], "attrs": {}}
        for a in [name, *aliases]:
            a = (a or "").strip()
            if not a or len(a) > 80:
                continue
            if a != e["name"] and a not in e["aliases"]:
                e["aliases"].append(a)
            p = 0 if a == name else prio
            for idx, k in ((self.alias, key(a)), (self.salias, stripped_key(a))):
                if len(k) >= 2:
                    idx[k][eid] = min(p, idx[k].get(eid, 9))
            self.alias_text[stripped_key(a)].add(a)
        if attrs:
            for k, v in attrs.items():
                if v not in (None, "", []):
                    e["attrs"].setdefault(k, v)
        return eid

    # -- lookup
    def resolve(self, name: str, types=("actor", "malware", "tool", "campaign"), fuzzy: bool = True) -> str | None:
        """Entity id for a name: exact on normalised key, then generic-stripped key, then careful fuzzy."""
        if not name or not name.strip():
            return None
        for idx, k in ((self.alias, key(name)), (self.salias, stripped_key(name))):
            hit = self._best(idx.get(k), types)
            if hit:
                return hit
        if not fuzzy:
            return None
        return self._fuzzy(name, types)

    def _best(self, cands: dict[str, int] | None, types) -> str | None:
        if not cands:
            return None
        c = [(p, i) for i, p in cands.items() if self.entities[i]["type"] in types]
        if not c:
            return None
        c.sort(key=lambda x: (x[0], types.index(self.entities[x[1]]["type"]), x[1]))
        # A tie at the best priority between two entities is ambiguous only when neither is the
        # canonical holder of the name; canonical (priority 0) always wins.
        if len(c) > 1 and c[0][0] == c[1][0] and c[0][0] > 0 and self.entities[c[0][1]]["type"] == self.entities[c[1][1]]["type"]:
            # prefer the entity with more aliases (the better documented cluster)
            c.sort(key=lambda x: (x[0], -len(self.entities[x[1]]["aliases"])))
        return c[0][1]

    def _fuzzy(self, name: str, types) -> str | None:
        k = stripped_key(name)
        if len(k) < 6:
            return None
        tkey = ",".join(types)
        keys = self._fuzzy_keys.get(tkey)
        if keys is None:
            keys = [a for a, ids in self.salias.items() if any(self.entities[i]["type"] in types for i in ids)]
            self._fuzzy_keys[tkey] = keys
        qs, qg = _parts(name)
        for cand in difflib.get_close_matches(k, keys, n=5, cutoff=0.88):
            if digits(cand) != digits(k):               # APT28 is never APT29
                continue
            eid = self._best(self.salias[cand], types)
            if not eid:
                continue
            # The specific (non-generic) part must agree and the generic words must be the same,
            # so a shared "Bear" or "Spider" never joins two actors.
            for alias in self.alias_text.get(cand, ()):
                cs, cg = _parts(alias)
                # spelling may differ only by a plural or separators; one-letter-different names
                # (SimpleTea / SimplexTea) are different families
                if qs and cs and qg == cg and (qs == cs or qs.rstrip("s") == cs.rstrip("s")):
                    return eid
        return None

    def technique(self, text: str) -> str | None:
        """Map a technique name (or 'Parent: Sub' name, or an id) to an ATT&CK id."""
        m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", text or "", re.I)
        if m and m.group(0).upper() in self.tech_name:
            return m.group(0).upper()
        ids = self.tech_by_name.get(key(text or ""))
        if ids:
            return sorted(ids, key=lambda t: ("." in t, t))[0] if len(ids) > 1 else next(iter(ids))
        return None


def _parts(s: str) -> tuple[str, frozenset]:
    from .normalize import GENERIC
    spec, gen = [], set()
    for t in tokens(s):
        g = t[:-1] if t.endswith("s") and t[:-1] in GENERIC else t
        (gen.add(g) if g in GENERIC else spec.append(t))
    return "".join(spec), frozenset(gen)


_CAT: Catalog | None = None
_LOCK = threading.Lock()


def catalog() -> Catalog:
    global _CAT
    with _LOCK:
        if _CAT is None:
            _CAT = build()
        return _CAT


def reload() -> Catalog:
    global _CAT
    with _LOCK:
        _CAT = None
    return catalog()


def _load_json(name: str):
    p = path(name)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_bytes())
    except Exception as e:
        log.warning("could not read %s: %s", p, e)
        return None


def build() -> Catalog:
    cat = Catalog()
    _load_tlds(cat)
    attack = _load_json("attack")
    if attack:
        _load_attack(cat, attack)
    actor_by_misp: dict[str, str] = {}
    for name, type_ in (("misp_actor", "actor"), ("misp_malpedia", "malware"), ("misp_tool", "tool")):
        data = _load_json(name)
        if data:
            actor_by_misp.update(_load_misp(cat, data, type_))
    # MISP "uses" relations between galaxies
    data = _load_json("misp_actor")
    if data:
        for v in data.get("values", []):
            subj = actor_by_misp.get(v.get("uuid"))
            for r in v.get("related", []) or []:
                obj = actor_by_misp.get(r.get("dest-uuid"))
                if subj and obj and r.get("type") == "uses":
                    cat.relations.append((subj, "uses", obj, SRC_MISP, "https://github.com/MISP/misp-galaxy"))
    log.info("reference catalogue: %d entities, %d alias keys, %d techniques, %d relations",
             len(cat.entities), len(cat.alias), len(cat.tech_name), len(cat.relations))
    return cat


def _load_tlds(cat: Catalog):
    p = path("tlds")
    if p.exists():
        cat.tlds = {l.strip().lower() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")}
    p = path("psl")
    if p.exists():
        for l in p.read_text(encoding="utf-8").splitlines():
            l = l.strip()
            if l and not l.startswith("//"):
                l = l.lstrip("!*.")
                try:
                    cat.suffixes.add(l.encode("idna").decode().lower())
                except Exception:
                    cat.suffixes.add(l.lower())
                cat.tlds.add(l.rsplit(".", 1)[-1].lower())
    if not cat.tlds:   # minimal fallback so extraction still works on a lake with no reference data
        cat.tlds = set("com net org info biz io co ru cn de uk fr jp br in it nl xyz top online site club pw tk ml ga cf gq su "
                       "us ca au es pl ua kr tw hk sg ir kp vn id th tr me cc tv ws ly gov edu mil int app dev cloud live shop".split())


def _ext_id(o) -> str | None:
    for r in o.get("external_references", []) or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def _ext_url(o) -> str | None:
    for r in o.get("external_references", []) or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("url")
    return None


def _desc(s: str | None, n: int = 600) -> str | None:
    if not s:
        return None
    s = re.sub(r"\(Citation:[^)]*\)", "", s)
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    return re.sub(r"\s+", " ", s).strip()[:n]


def _load_attack(cat: Catalog, bundle) -> dict[str, str]:
    objs = [o for o in bundle.get("objects", []) if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in objs}
    stix: dict[str, str] = {}
    # techniques first, parents before subtechniques
    aps = sorted((o for o in objs if o["type"] == "attack-pattern" and _ext_id(o)), key=lambda o: _ext_id(o))
    for o in aps:
        tid = _ext_id(o)
        cat.tech_name[tid] = o["name"]
        parent = cat.tech_name.get(tid.split(".")[0]) if "." in tid else None
        full = f"{parent}: {o['name']}" if parent else o["name"]
        cat.tech_full[tid] = full
        tactics = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        eid = cat.add("technique", tid, aliases=[full] if full != o["name"] else [o["name"]],
                      attrs={"attack_id": tid, "title": full, "tactics": tactics, "url": _ext_url(o),
                             "description": _desc(o.get("description"))},
                      eid=entity_id("technique", tid))
        cat.entities[eid]["name"] = f"{tid} {full}"
        stix[o["id"]] = eid
        for n in {o["name"], full}:
            cat.tech_by_name[key(n)].add(tid)
    for o in objs:
        t = o["type"]
        if t == "intrusion-set":
            eid = cat.add("actor", o["name"], o.get("aliases") or [], prio=1,
                          attrs={"attack_id": _ext_id(o), "url": _ext_url(o), "description": _desc(o.get("description")),
                                 "ref": [SRC_ATTACK]})
            gid = _ext_id(o)
            if gid:
                cat.add("actor", o["name"], [gid], eid=eid, prio=1)
        elif t in ("malware", "tool"):
            type_ = "malware" if t == "malware" else "tool"
            eid = cat.add(type_, o["name"], o.get("x_mitre_aliases") or [], prio=1,
                          attrs={"attack_id": _ext_id(o), "url": _ext_url(o), "description": _desc(o.get("description")),
                                 "platforms": o.get("x_mitre_platforms"), "ref": [SRC_ATTACK]})
        elif t == "campaign":
            eid = cat.add("campaign", o["name"], o.get("aliases") or [], prio=1,
                          attrs={"attack_id": _ext_id(o), "url": _ext_url(o), "description": _desc(o.get("description")),
                                 "first_seen": o.get("first_seen"), "last_seen": o.get("last_seen"), "ref": [SRC_ATTACK]})
        else:
            continue
        stix[o["id"]] = eid
    # former names of revoked techniques point at their replacement ("Network Service Scanning")
    revoked = {o["id"]: o for o in bundle.get("objects", []) if o.get("type") == "attack-pattern" and o.get("revoked")}
    for o in bundle.get("objects", []):
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by" and o.get("source_ref") in revoked:
            new = stix.get(o.get("target_ref"))
            old_name = revoked[o["source_ref"]].get("name")
            if new and old_name and not cat.tech_by_name.get(key(old_name)):
                cat.tech_by_name[key(old_name)].add(new.split(":", 1)[1])
    for o in objs:
        if o["type"] != "relationship":
            continue
        s, d = stix.get(o.get("source_ref")), stix.get(o.get("target_ref"))
        if not s or not d:
            continue
        rt = o.get("relationship_type")
        st, dt_ = cat.entities[s]["type"], cat.entities[d]["type"]
        if rt == "uses" and st in ("actor", "campaign") and dt_ in ("malware", "tool", "technique"):
            cat.relations.append((s, "uses", d, SRC_ATTACK, _ext_url(by_id.get(o["source_ref"], {})) or "https://attack.mitre.org/"))
        elif rt == "attributed-to" and st == "campaign" and dt_ == "actor":
            cat.relations.append((s, "attributed-to", d, SRC_ATTACK, _ext_url(by_id.get(o["source_ref"], {})) or "https://attack.mitre.org/"))
    return stix


_PLATFORM = re.compile(r"\s*\((?:ELF|Windows|Win|OS ?X|macOS|Linux|Android|iOS|Python|Go|Golang|JavaScript|PowerShell|"
                       r"ESXi|VMware ESXi|Java|PHP|Rust|Mac|Symbian)\)$", re.I)


def _load_misp(cat: Catalog, data, type_: str) -> dict[str, str]:
    """Merge a MISP galaxy into the catalogue. Joins an existing entity only on an exact name
    or ATT&CK id match; returns {misp uuid: entity id}."""
    out = {}
    for v in data.get("values", []):
        name = _PLATFORM.sub("", (v.get("value") or "").strip())
        meta = v.get("meta") or {}
        if not name:
            continue
        syn = list(meta.get("synonyms") or [])
        if type_ == "actor":
            syn += [a.split(":")[0] for a in meta.get("name-attribution") or [] if a]
        types = (type_,) if type_ == "actor" else ("malware", "tool")
        # join: canonical name of an existing entity, or the single ATT&CK id among synonyms
        eid = cat._best({i: p for i, p in cat.alias.get(key(name), {}).items() if p <= 1}, types)
        if not eid:
            gids = {s for s in syn if re.fullmatch(r"[GS]\d{4}", s)}
            hits = {i for g in gids for i in cat.alias.get(key(g), {}) if cat.entities[i]["type"] in types}
            if len(gids) == 1 and len(hits) == 1:
                eid = hits.pop()
        attrs = {"description": _desc(v.get("description")), "ref": [SRC_MISP]}
        if type_ == "actor":
            attrs.update({"country": meta.get("country"), "state_sponsor": meta.get("cfr-suspected-state-sponsor"),
                          "victims": meta.get("cfr-suspected-victims"), "targets": meta.get("cfr-target-category"),
                          "incident_type": meta.get("cfr-type-of-incident"), "sectors": meta.get("targeted-sector"),
                          "motive": meta.get("motive")})
        else:
            attrs["kind"] = meta.get("type")
        # don't let a generic synonym ("RAT", "Agent") become an alias
        syn = [s for s in syn if s and (len(key(s)) >= 3 and (specific_tokens(s) or digits(s)))]
        if eid:
            cat.add(cat.entities[eid]["type"], cat.entities[eid]["name"], syn, eid=eid, prio=2)
            e = cat.entities[eid]
            for k, val in attrs.items():
                if k == "ref":
                    e["attrs"].setdefault("ref", [])
                    if SRC_MISP not in e["attrs"]["ref"]:
                        e["attrs"]["ref"].append(SRC_MISP)
                elif val not in (None, "", []) and k not in e["attrs"]:
                    e["attrs"][k] = val
        else:
            eid = cat.add(type_, name, syn, attrs=attrs, prio=2)
        out[v.get("uuid")] = eid
        for ref in meta.get("refs") or []:   # Malpedia ids: how ThreatFox names families (win.dridex)
            m = re.match(r"https?://malpedia\.caad\.fkie\.fraunhofer\.de/details/([a-z0-9]+\.[a-z0-9_]+)/?$", ref or "")
            if m:
                cat.malpedia.setdefault(m.group(1), eid)
        if type_ == "actor" and meta.get("country") and re.fullmatch(r"[A-Za-z]{2}", meta["country"]):
            cat.relations.append((eid, "attributed-to", entity_id("country", meta["country"]), SRC_MISP,
                                  "https://github.com/MISP/misp-galaxy/blob/main/clusters/threat-actor.json"))
    return out

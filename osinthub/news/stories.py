"""Story clustering: articles about the same event become one story. Method: okf/data/news.md#stories

For each new article, in published order:

1. **Syndication / near-duplicates.** Same canonical URL (translation suffix ignored), or MinHash
   Jaccard >= DUP_JACCARD over word 5-shingles, within DUP_WINDOW. A copy gets `dup_of`, joins the
   original's story and counts once for corroboration.
2. **Same event.** Similarity is embedding cosine + 0.5 x TF-IDF cosine of headline and lead (TF-IDF
   alone without embeddings). The bar it must clear drops when the two share strong keys (a CVE id,
   a named victim, product, malware, actor or incident in the headline or lead), and such pairs may be
   up to KEY_WINDOW apart instead of WINDOW. Round-ups and same-outlet series never merge.
3. **Assign.** Join the best-matching story whose articles the new one is close to (at least half of
   them; stops chaining), else start a story. Then merge stories that turn out to be one event.
Sponsored posts stay out of stories.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import re
from collections import Counter

import numpy as np

from .. import db
from .common import chat, ensure_schema
from .pipeline import jaccard_est

UTC = dt.UTC
WINDOW = dt.timedelta(days=4)
DUP_WINDOW = dt.timedelta(days=21)
DUP_JACCARD = 0.5
LEAD_WORDS = 120
# Similarity = cosine of mean embeddings + EMB_LEX_WEIGHT * TF-IDF cosine ("emb"), or the TF-IDF cosine
# alone when an article has no embedding ("lex"). The bar depends on what else the two share:
#   no shared key, within WINDOW            T[0]        (topic alone is not an event)
#   one shared rare key, within KEY_WINDOW  T[1]        (a CVE id, a named victim, malware, actor or incident)
#   two or more shared keys, KEY_WINDOW     T[2]
# The story-level guard uses the same bars minus GUARD_SLACK.
EMB_LEX_WEIGHT = 0.5
T = {"emb": (0.95, 0.86, 0.78), "lex": (0.21, 0.13, 0.07)}
GUARD_SLACK = {"emb": 0.07, "lex": 0.05}
KEY_WINDOW = dt.timedelta(days=14)
CVE_WINDOW = dt.timedelta(days=30)   # vendor research on one CVE keeps arriving for weeks
KEY_DF_MAX = 12          # a key named by more articles than this is too common to identify an event
ROUNDUP = re.compile(r"(weekly recap|week in review|weekly (round-?up|digest)|threatsday|this week in|month in security|"
                     r"monthly (round-?up|recap)|stormcast|newsletter|news ?wrap|in brief|round-?up|roundup|"
                     r"this month in security|threat intelligence highlights|apt activity report|ir trends)", re.I)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_TOK = re.compile(r"[a-z0-9][a-z0-9\-\.']*[a-z0-9]|[a-z0-9]")
STOP = set("""a an the and or of to in on for with by at from as is are was were be been being it its this that these those
which who whom what when where why how not no but if then than so such into over under about after before between
during while new says said also has have had will would can could may might more most other some any all their there
they them we our you your he she his her up out via per one two three just only very now first last week year years
company companies report reports researchers security cyber cybersecurity attack attacks attackers threat threats
data use used using including include includes according according-to like according
monday tuesday wednesday thursday friday saturday sunday mon tue wed thu fri sat sun january february march april
june july august september october november december jan feb mar apr jun jul aug sep sept oct nov dec 1st 2nd 3rd
release released update updated patch patches flaw flaws vulnerability vulnerabilities critical warns hackers""".split())
_URL = re.compile(r"https?://\S+")
_ORD = re.compile(r"^\d+(st|nd|rd|th)$")
SAME_OUTLET_PENALTY = {"lex": 0.10, "emb": 0.05}   # one outlet rarely runs two articles on one event

state = {"clustered": 0, "stories": 0, "summaries_llm": 0}


# ------------------------------------------------------------------ text features
def tokens(text: str) -> list[str]:
    out = []
    for t in _TOK.findall(_URL.sub(" ", text or "").lower()):
        t = t.strip(".'-")
        if t not in STOP and len(t) > 2 and not t.isdigit() and not _ORD.match(t):
            out.append(t)
    return out


def lead(title: str | None, text: str | None, dek: str | None) -> str:
    body = " ".join((text or dek or "").split()[:LEAD_WORDS])
    t = title or ""
    return f"{t} {t} {t} {body}"   # the headline weighs three times


class Tfidf:
    def __init__(self, docs: dict[str, str]):
        self.tf = {k: Counter(tokens(v)) for k, v in docs.items()}
        df = Counter()
        for c in self.tf.values():
            df.update(c.keys())
        n = max(1, len(self.tf))
        self.idf = {t: math.log((1 + n) / (1 + d)) + 1 for t, d in df.items()}
        self.vec = {}
        for k, c in self.tf.items():
            v = {t: (1 + math.log(f)) * self.idf[t] for t, f in c.items()}
            norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
            self.vec[k] = {t: x / norm for t, x in v.items()}

    def cos(self, a: str, b: str) -> float:
        va, vb = self.vec.get(a), self.vec.get(b)
        if not va or not vb:
            return 0.0
        if len(va) > len(vb):
            va, vb = vb, va
        return sum(x * vb.get(t, 0.0) for t, x in va.items())


_NAME = re.compile(r"[A-Za-z][A-Za-z0-9][A-Za-z0-9\-\.]*[A-Za-z0-9]")
_NOT_KEY_TYPES = ("ip", "domain", "url", "sha256", "sha1", "md5", "technique", "country", "sector", "region", "location")
COMMON_NAMES = set("""google microsoft apple android windows linux amazon aws azure cisa fbi nsa doj us usa uk eu europol
chrome github ai llm openai claude gemini iphone ios macos russia russian china chinese iran iranian north korea korean
ukraine ukrainian israel european america american""".split())


def _lead_text(r: dict, words: int = LEAD_WORDS * 2) -> str:
    return " ".join((r.get("text") or r.get("dek") or "").split()[:words])


def _proper_names(title: str, body: str) -> set[str]:
    """Title words that the body also writes capitalised mid-sentence: names of victims, products,
    malware and groups. Works for title-case headlines too, because the body decides (with the
    headline itself removed from the body, since some pages repeat it)."""
    out = set()
    if title:
        body = body.replace(title, " ")
    for w in _NAME.findall(title or ""):
        lw = w.lower()
        if lw in STOP or lw in COMMON_NAMES or len(lw) < 3 or lw.isdigit():
            continue
        if re.search(r"[a-z0-9,;:]\s+" + re.escape(w) + r"\b", body) and any(c.isupper() for c in w):
            out.add(f"name:{lw}")
    return out


_LEAD_NAME = re.compile(r"(?<=[a-z0-9,;:]\s)([A-Z][a-z]+[A-Z]?[\w\-]*|[A-Z]{2,}[a-z]+\w*)")
_GENERIC_CAPS = set("""the this that these they there their it its in on at for from with by and but or as an a if when while
after before during since however although according also meanwhile today yesterday monday tuesday wednesday thursday
friday saturday sunday january february march april may june july august september october november december
security cybersecurity researchers research company companies government police agency department ministry court
university bank group inc corp ltd llc team report reports cyber news blog windows linux""".split())


def _lead_names(title: str, lead: str) -> set[str]:
    """Proper names written mid-sentence in the lead (Danfoss, Colruyt, Delhaize): victims, vendors
    and places that tie two reports of one incident together even when their headlines differ."""
    if title:
        lead = lead.replace(title, " ")
    out = set()
    # Places are not event keys: skip names written after "in", "from", "near", "across", "of".
    places = {m.lower() for m in re.findall(r"\b(?:in|from|near|across|outside|based in)\s+([A-Z][a-z]+)", lead)}
    for w in _LEAD_NAME.findall(lead):
        if w.lower() in places:
            continue
        lw = w.lower().strip("-")
        if len(lw) >= 4 and lw not in _GENERIC_CAPS and lw not in COMMON_NAMES and lw not in STOP:
            out.add(f"lname:{lw}")
    return out


# Vulnerability and campaign nicknames: PHP2Shell, Log4Shell, Heartbleed, "Gheist"-style quoted names.
_NICK = re.compile(r"\b([A-Za-z]+\d+[A-Za-z]+\w*|[A-Z]\w*(?:Shell|Bleed|Hammer|Jack(?:ing)?|Leak|Drift|Storm|Gate))\b")
_QUOTED = re.compile(r"[\u2018\u201c'\"]([A-Z][\w\-]{2,30}(?: [A-Z][\w\-]{2,30})?)[\u2019\u201d'\"]")
_NOT_NICK = re.compile(r"^(cve|cwe|ms|kb|tls|ipv|win|x\d|t\d|q\d|h\d|top\d|\d)", re.I)


def _nicknames(title: str) -> set[str]:
    out = set()
    for w in _NICK.findall(title or ""):
        if not _NOT_NICK.match(w) and not re.fullmatch(r"[A-Za-z]{1,3}\d+", w) and len(w) >= 5:
            out.add(f"nick:{w.lower()}")
    for w in _QUOTED.findall(title or ""):
        out.add(f"nick:{w.lower()}")
    return out


DEMONYMS = {"american": "US", "canadian": "CA", "british": "GB", "english": "GB", "french": "FR", "german": "DE",
            "dutch": "NL", "belgian": "BE", "swedish": "SE", "norwegian": "NO", "danish": "DK", "finnish": "FI",
            "estonian": "EE", "polish": "PL", "spanish": "ES", "italian": "IT", "portuguese": "PT", "swiss": "CH",
            "austrian": "AT", "irish": "IE", "russian": "RU", "ukrainian": "UA", "belarusian": "BY", "chinese": "CN",
            "japanese": "JP", "korean": "KR", "taiwanese": "TW", "indian": "IN", "pakistani": "PK", "iranian": "IR",
            "israeli": "IL", "jordanian": "JO", "saudi": "SA", "emirati": "AE", "turkish": "TR", "egyptian": "EG",
            "nigerian": "NG", "brazilian": "BR", "mexican": "MX", "australian": "AU", "vietnamese": "VN",
            "indonesian": "ID", "filipino": "PH", "thai": "TH", "singaporean": "SG", "malaysian": "MY", "syrian": "SY"}


def title_places(title: str) -> set[str]:
    """Countries a headline names, by name or demonym ('Canadian', 'Jordanian')."""
    out = set()
    try:
        from .. import geo
        out |= set(geo.tag_countries(title or ""))
    except Exception:
        pass
    for w in re.findall(r"[A-Za-z]+", title or ""):
        c = DEMONYMS.get(w.lower())
        if c:
            out.add(c)
    return out


def article_keys(rows: list[dict]) -> dict[str, set[str]]:
    """Strong keys per article, from the headline and lead only (a CVE or name mentioned in passing
    further down is background):

    * CVE ids, when the lead names at most 4 (more means a patch round-up);
    * entities from the entities layer (actors, malware, campaigns, tools, organisations) whose name
      or an alias appears in the headline or lead;
    * proper names in the headline that the body also capitalises.

    Keys named by more than KEY_DF_MAX articles are dropped as too common.
    """
    out: dict[str, set[str]] = {}
    heads: dict[str, str] = {}
    for r in rows:
        head = f"{r['title'] or ''} {_lead_text(r)}"
        heads[r["id"]] = head.lower()
        cves = {c.upper() for c in CVE.findall(head)}
        # Every lead CVE is kept; `many_cves` marks patch round-ups, whose CVEs only count when the
        # other article is about few of them.
        keys = {f"cve:{c.lower()}" for c in cves}
        if len(cves) > 4:
            keys.add("_many_cves")
        keys |= _proper_names(r["title"] or "", _lead_text(r, 400))
        keys |= _lead_names(r["title"] or "", _lead_text(r, 150))
        keys |= _nicknames(r["title"] or "")
        out[r["id"]] = keys
    try:
        ids = [r["id"] for r in rows]
        if ids:
            ment = db.query(f"""SELECT DISTINCT m.ref_id, m.entity_id, e.name, e.aliases FROM mentions m
                                LEFT JOIN entities e ON e.id = m.entity_id
                                WHERE m.ref_type = 'article' AND m.ref_id IN ({','.join('?' * len(ids))})""", ids)
            for m in ment:
                eid = (m["entity_id"] or "").lower()
                etype = eid.split(":", 1)[0]
                if etype in _NOT_KEY_TYPES:
                    continue
                if etype == "cve":
                    continue  # CVEs are handled above, from the lead
                if etype in ACTOR_TYPES:
                    eid = "actor~" + eid   # identifies who, not which event
                names = [n for n in [m["name"], *(m["aliases"] or [])] if n and len(n) >= 3]
                head = heads.get(m["ref_id"], "")
                if names and any(re.search(r"\b" + re.escape(n.lower()) + r"\b", head) for n in names):
                    if (m["name"] or "").lower() not in COMMON_NAMES:
                        out.setdefault(m["ref_id"], set()).add(eid)
    except Exception:
        pass  # entities layer not built yet
    # A proper name that is an actor, malware or tool name is an actor key too.
    try:
        actor_names = {(r["n"] or "").lower() for r in db.query(
            f"SELECT name AS n FROM entities WHERE type IN ({','.join('?' * len(ACTOR_TYPES))})", list(ACTOR_TYPES))}
        actor_names |= {(a or "").lower() for r in db.query(
            f"SELECT aliases FROM entities WHERE type IN ({','.join('?' * len(ACTOR_TYPES))})", list(ACTOR_TYPES)) for a in (r["aliases"] or [])}
    except Exception:
        actor_names = set()
    for k, s_ in out.items():
        out[k] = {("actor~" + e if e.split(":", 1)[0] in ("name", "lname") and e.split(":", 1)[1] in actor_names else e)
                  for e in s_}
        # A nickname also typed as malware by the entities layer (PHP2Shell) stays an event key.
        nicks = {e[5:] for e in out[k] if e.startswith("nick:")}
        out[k] = {e for e in out[k] if not (e.startswith("actor~") and e.split(":")[-1] in nicks)}
    # Lead names must be real proper names: not ordinary words (the corpus also writes them in lower
    # case: "wave", "federal"), not places (France, Belgian) and not the outlet itself.
    lower_vocab = _lower_vocab(rows)
    for r in rows:
        k = r["id"]
        host = (r.get("url") or "").lower()
        keep = set()
        for e in out.get(k, set()):
            kind, _, v = e.partition(":")
            if kind in ("lname", "actor~lname"):
                if v in lower_vocab or v in DEMONYMS or title_places(v.title()) or (len(v) >= 5 and v in host):
                    continue
            keep.add(e)
        # Tokens of organisation entities, so "Ahold Delhaize" and "Delhaize" meet.
        for e in list(keep):
            if e.startswith("org:"):
                for tok in e[4:].split("-"):
                    if len(tok) >= 5 and tok not in _ORG_GENERIC and tok not in lower_vocab:
                        keep.add(f"otok:{tok}")
        out[k] = keep
    df = Counter(k for s_ in out.values() for k in s_)
    return {k: {e for e in s_ if e.startswith(("cve:", "_")) or df[e] <= KEY_DF_MAX} for k, s_ in out.items()}


_ORG_GENERIC = set("""group groups holdings holding international global systems system technologies technology services
service security networks network solutions software bank banks university college institute foundation agency
ministry department police office council company corporation limited national federal association""".split())


def _lower_vocab(rows: list[dict]) -> set[str]:
    """Words the corpus writes in lower case at least twice: ordinary words, not names."""
    c = Counter()
    for r in rows:
        c.update(re.findall(r"(?<![A-Za-z])([a-z][a-z\-]{3,})(?![A-Za-z])", (r.get("text") or r.get("dek") or "")[:4000]))
    return {w for w, n in c.items() if n >= 2}


ACTOR_TYPES = ("actor", "malware", "tool", "threat-actor", "intrusion-set")


# A headline naming three or more organisations in a list ("WorkOS, Northflank, Trigger.dev Disclose
# Hacks") covers several incidents.
_LIST_TITLE = re.compile(r"\b[A-Z][\w.\-]+(?:\s[A-Z][\w.\-]+)?,\s[A-Z][\w.\-]+(?:\s[A-Z][\w.\-]+)?,\s(?:and\s)?[A-Z][\w.\-]+")


_PLURAL_INCIDENTS = re.compile(r"\b(breaches|hacks|attacks|incidents|disclose|disclosures|outages|leaks|intrusions)\b", re.I)


def is_roundup(r: dict) -> bool:
    t = r.get("title") or ""
    return bool(ROUNDUP.search(t) or (_LIST_TITLE.search(t) and _PLURAL_INCIDENTS.search(t)))


# ------------------------------------------------------------------ clustering
def _load_corpus() -> list[dict]:
    return db.query("""SELECT a.id, a.url, a.title, a.text, a.dek, a.published, a.fetched_at, a.queued_at, a.source, a.canonical_url,
                              a.minhash, a.story_id, a.dup_of, a.clustered_at, a.status, a.role, a.sponsored, v.vec
                       FROM articles a LEFT JOIN article_vecs v ON v.article_id = a.id
                       WHERE a.status IS DISTINCT FROM 'skipped'""")


def _when(r) -> dt.datetime:
    return r["published"] or r["fetched_at"] or r["queued_at"]


class Scorer:
    def __init__(self, rows: list[dict]):
        self.rows = {r["id"]: r for r in rows}
        self.tfidf = Tfidf({r["id"]: lead(r["title"], r["text"], r["dek"]) for r in rows})
        self.keys = article_keys(rows)
        self.vec = {r["id"]: np.asarray(r["vec"], dtype=np.float32) for r in rows if r.get("vec") is not None}

    def shared(self, a: str, b: str) -> set[str]:
        ka, kb = self.keys.get(a, set()), self.keys.get(b, set())
        sh = {k for k in ka & kb if not k.startswith("_")}
        if "_many_cves" in ka and "_many_cves" in kb:
            sh = {k for k in sh if not k.startswith("cve:")}   # two round-ups sharing CVEs prove nothing
        return sh

    def pair(self, a: str, b: str) -> tuple[float, str]:
        """(similarity, kind) with kind 'emb' or 'lex'."""
        ra, rb = self.rows.get(a), self.rows.get(b)
        if ra and rb and is_series(ra, rb):
            return 0.0, "lex"
        kind = "emb" if (a in self.vec and b in self.vec) else "lex"
        lex = self.tfidf.cos(a, b)
        # Embeddings alone rate same-topic stories (two different fridge attacks) almost as high as
        # same-event ones; the lexical overlap of names, numbers and places separates them.
        sim = float(self.vec[a] @ self.vec[b]) + EMB_LEX_WEIGHT * lex if kind == "emb" else lex
        if ra and rb and ra["source"] and ra["source"] == rb["source"]:
            sim -= SAME_OUTLET_PENALTY[kind]
        return sim, kind

    def bar(self, a: str, b: str, kind: str) -> float | None:
        """The similarity needed for a and b to be one event, or None when they can't be."""
        ra, rb = self.rows[a], self.rows[b]
        if is_roundup(ra) or is_roundup(rb):
            return None
        gap = abs(_when(ra) - _when(rb))
        sh = self.shared(a, b)
        # Event keys (CVE, victim, product, incident) identify an event; actor keys (group, malware,
        # tool) only say who, so they count only alongside an event key or within the short window.
        ev = [k for k in sh if not k.startswith("actor~")]
        ac = [k for k in sh if k.startswith("actor~")]
        # Actor keys alone never lower the bar: one group runs many operations (two ShinyHunters
        # arrests are two events). With an event key they add weight.
        # A coined nickname (PHP2Shell) names one event, so it counts double.
        n = len(ev) + sum(1 for k in ev if k.startswith("nick:")) + (len(ac) if ev else 0)
        pa, pb = title_places(ra.get("title") or ""), title_places(rb.get("title") or "")
        if pa and pb and not (pa & pb) and not any(k.startswith(("cve:", "nick:")) for k in ev):
            # Different countries in the headlines (a Jordanian arrest, a Canadian arrest): names alone
            # don't make it one event; only the plain similarity bar applies.
            n = 0
            if gap > WINDOW:
                return None
        window = CVE_WINDOW if any(k.startswith("cve:") for k in ev) else KEY_WINDOW
        if n and gap <= window:
            return T[kind][2 if n >= 2 else 1]
        if gap <= WINDOW or _covers_research(ra, rb):
            return T[kind][0]
        return None

    def story_margin(self, a: str, members: list[str]) -> float | None:
        """Article against a story as a whole: cosine to the story's centroid (mean embedding of its
        original articles) + 0.5 x mean lexical cosine, against the bar for the keys the article shares
        with the story's nearest member. Catches reports that resemble the story more than any one
        of its articles."""
        mem = [m for m in members if m in self.rows and not self.rows[m].get("dup_of")] or [m for m in members if m in self.rows]
        if a not in self.vec or not mem or not all(m in self.vec for m in mem):
            return None
        c = np.mean([self.vec[m] for m in mem], axis=0)
        c /= (np.linalg.norm(c) or 1.0)
        sim = float(self.vec[a] @ c) + EMB_LEX_WEIGHT * (sum(self.tfidf.cos(a, m) for m in mem) / len(mem))
        if all(self.rows[m]["source"] == self.rows[a]["source"] for m in mem):
            sim -= SAME_OUTLET_PENALTY["emb"]
        bars = [b for m in mem if (b := self.bar(a, m, "emb")) is not None]
        return None if not bars else sim - min(bars)

    def margin(self, a: str, b: str) -> float | None:
        """similarity minus the bar (>= 0 means same event); None when they can't be."""
        s_, kind = self.pair(a, b)
        bar = self.bar(a, b, kind)
        return None if bar is None else s_ - bar

    def close(self, a: str, b: str) -> bool:
        """Looser test used to check an article against the rest of a story (anti-chaining guard)."""
        s_, kind = self.pair(a, b)
        bar = self.bar(a, b, kind)
        return bar is not None and s_ >= bar - GUARD_SLACK[kind]


def _series_key(title: str) -> tuple[str, frozenset]:
    t = _URL.sub(" ", title or "").lower()
    prefix = t.split(":", 1)[0].strip() if ":" in t else ""
    words = frozenset(w for w in re.findall(r"[a-z][a-z\-']+", t) if len(w) > 2 and (w not in STOP or w in ("release", "update")))
    return prefix, words


def is_series(ra: dict, rb: dict) -> bool:
    """Same outlet, recurring format (daily podcast, release notes, a multi-part series): titles that
    differ only in dates and numbers, or share a 'Series name:' prefix. Those are different events."""
    if not ra.get("source") or ra.get("source") != rb.get("source") or ra.get("title") == rb.get("title"):
        return False
    pa, wa = _series_key(ra["title"])
    pb, wb = _series_key(rb["title"])
    if wa and wa == wb:
        return True
    return bool(pa) and pa == pb and len(pa.split()) >= 2


_LANG_SUFFIX = re.compile(r"-(french|italian|spanish|german|japanese|portuguese|korean|chinese|arabic|fr|it|es|de|ja|pt)$")


def _base_url(u: str | None) -> str | None:
    """Canonical URL with a translation suffix on the last path segment removed
    (Dark Reading publishes translations at <slug>-italian, <slug>-french)."""
    if not u:
        return None
    head, _, last = u.rstrip("/").rpartition("/")
    return f"{head}/{_LANG_SUFFIX.sub('', last)}"


def is_dup(ra: dict, rb: dict) -> bool:
    """Syndicated or translated copy: same canonical URL (translation suffix ignored), or near-identical text."""
    if ra.get("canonical_url") and _base_url(ra["canonical_url"]) == _base_url(rb.get("canonical_url")):
        return True
    return jaccard_est(ra.get("minhash"), rb.get("minhash")) >= DUP_JACCARD


RESEARCH_WINDOW = dt.timedelta(days=21)


def _covers_research(a: dict, b: dict) -> bool:
    """News coverage of a research report often lands days or weeks later. Allow a longer window
    when one article is primary research and the other names that research team in its lead."""
    for r, n in ((a, b), (b, a)):
        if r.get("role") == "research" and n.get("role") != "research" and abs(_when(a) - _when(b)) <= RESEARCH_WINDOW:
            names = [x for x in RESEARCH_NAMES.get(r.get("source") or "", []) if x]
            head = " ".join((n.get("text") or n.get("dek") or "").split()[:LEAD_WORDS * 2])
            if any(x in head for x in names):
                return True
    return False


RESEARCH_NAMES = {"Unit 42": ["Unit 42"], "Cisco Talos": ["Talos"], "ESET Research": ["ESET"],
                  "Microsoft Threat Intelligence": ["Microsoft"], "Elastic Security Labs": ["Elastic Security Labs"],
                  "SANS ISC": ["SANS", "Internet Storm Center"], "Check Point Research": ["Check Point"]}


def _originals(members: list[str], by_id: dict) -> list[str]:
    return [m for m in members if m in by_id and not by_id[m].get("dup_of")]


def _fits(sc: Scorer, aid: str, members: list[str]) -> bool:
    """An article fits a story when it is close to at least half of the story's original articles."""
    mem = _originals(members, sc.rows) or members
    return sum(1 for m in mem if sc.close(aid, m)) * 2 >= len(mem)


def cluster_pending(limit: int = 2000) -> int:
    """Assign stories to new articles, then merge stories that turn out to cover one event."""
    ensure_schema()
    rows = _load_corpus()
    # Sponsored and promotional posts are kept out of stories (and so out of corroboration counts).
    spon = [r for r in rows if r.get("sponsored") and r["story_id"]]
    for r in spon:
        db.execute("UPDATE articles SET story_id = NULL, clustered_at = now() WHERE id = ?", [r["id"]])
        refresh_story(r["story_id"])
        r["story_id"] = None
    rows = [r for r in rows if not r.get("sponsored")]
    # Articles not fetched yet (or offline) cluster on title + feed summary; fetched ones on their text.
    pending = [r for r in rows if r["story_id"] is None and r["status"] != "skipped"]
    refetched = {r["story_id"] for r in rows if r["story_id"] and r["clustered_at"] is None}
    if refetched:
        for s_ in refetched:
            refresh_story(s_)
        db.execute("UPDATE articles SET clustered_at = now() WHERE story_id IS NOT NULL AND clustered_at IS NULL")
    if not pending:
        return 0
    sc = Scorer(rows)
    pending.sort(key=_when)
    members: dict[str, list[str]] = {}
    for r in rows:
        if r["story_id"]:
            members.setdefault(r["story_id"], []).append(r["id"])
    by_id = sc.rows
    touched: set[str] = set()
    done = 0
    for r in pending[:limit]:
        t = _when(r)
        horizon = max(DUP_WINDOW, CVE_WINDOW, KEY_WINDOW, RESEARCH_WINDOW)
        cands = [o for o in by_id.values() if o["id"] != r["id"] and o["story_id"] and abs(_when(o) - t) <= horizon]
        story, dup_of = None, None
        for o in sorted(cands, key=_when):
            if abs(_when(o) - t) <= DUP_WINDOW and is_dup(r, o):
                dup_of, story = (o["dup_of"] or o["id"]), o["story_id"]
                break
        if story is None:
            scored = []
            for o in cands:
                m = sc.margin(r["id"], o["id"])
                if m is not None and m >= 0:
                    scored.append((m, o["story_id"]))
            for sid in {o["story_id"] for o in cands}:
                m = sc.story_margin(r["id"], members.get(sid, []))
                if m is not None and m >= 0:
                    scored.append((m, sid))
            # Best-matching story first; fall back to the next one if the guard rejects it.
            for _, sid in sorted(scored, reverse=True):
                if _fits(sc, r["id"], members.get(sid, [])):
                    story = sid
                    break
        if story is None:
            story = f"story:{r['id']}"
        r["story_id"], r["dup_of"] = story, dup_of
        members.setdefault(story, []).append(r["id"])
        db.execute("UPDATE articles SET story_id = ?, dup_of = ?, clustered_at = now() WHERE id = ?", [story, dup_of, r["id"]])
        touched.add(story)
        done += 1
    touched |= merge_stories(sc, members, touched)
    for s_ in touched:
        refresh_story(s_)
    state["clustered"] += done
    return done


def merge_stories(sc: Scorer, members: dict[str, list[str]], touched: set[str]) -> set[str]:
    """Merge a touched story into another one when they turn out to cover the same event: an
    article pair across them passes the event test, and each story's articles fit the other.
    (Order matters in incremental clustering: two early reports can start two stories before a
    later article shows they are one.) Returns the stories that changed or disappeared."""
    changed: set[str] = set()
    queue = [s_ for s_ in touched if s_ in members]
    while queue:
        a = queue.pop()
        if a not in members:
            continue
        ma = _originals(members[a], sc.rows) or members[a]
        span_a = [_when(sc.rows[x]) for x in ma if x in sc.rows]
        if not span_a:
            continue
        best = None
        for b, mb_all in members.items():
            if b == a:
                continue
            mb = _originals(mb_all, sc.rows) or mb_all
            span_b = [_when(sc.rows[x]) for x in mb if x in sc.rows]
            if not span_b or min(span_b) - max(span_a) > CVE_WINDOW or min(span_a) - max(span_b) > CVE_WINDOW:
                continue
            links = [m for x in ma for y in mb if (m := sc.margin(x, y)) is not None and m >= 0]
            if not links:
                continue
            fit_a = sum(1 for x in ma if _fits(sc, x, mb))
            fit_b = sum(1 for y in mb if _fits(sc, y, ma))
            if fit_a * 2 >= len(ma) and fit_b * 2 >= len(mb):
                cand = (max(links), b)
                best = max(best, cand) if best else cand
        if best:
            b = best[1]
            keep, drop = (a, b) if len(members[a]) >= len(members[b]) else (b, a)
            for x in members[drop]:
                sc.rows[x]["story_id"] = keep
            db.execute("UPDATE articles SET story_id = ?, clustered_at = now() WHERE story_id = ?", [keep, drop])
            _carry_summary(drop, keep)
            members[keep] = members[keep] + members.pop(drop)
            changed |= {keep, drop}
            queue.append(keep)
    return changed


def _carry_summary(src: str, dst: str) -> None:
    """When stories merge, keep an LLM summary if only one of them had one (it is rewritten once the
    story has grown by half)."""
    rows = {r["id"]: r for r in db.query("SELECT id, summary, summary_by, summary_n FROM stories WHERE id IN (?, ?)", [src, dst])}
    s_, d_ = rows.get(src), rows.get(dst)
    if s_ and s_["summary_by"] == "llm" and (not d_ or d_["summary_by"] != "llm"):
        if d_:
            db.execute("UPDATE stories SET summary = ?, summary_by = 'llm', summary_n = ? WHERE id = ?",
                       [s_["summary"], s_["summary_n"], dst])
        else:   # refresh_story fills in the rest of the row and keeps an 'llm' summary
            db.execute("INSERT INTO stories (id, summary, summary_by, summary_n) VALUES (?, ?, 'llm', ?)",
                       [dst, s_["summary"], s_["summary_n"]])
    db.execute("DELETE FROM stories WHERE id = ?", [src])


def recluster_all() -> int:
    """Drop every story and cluster again from scratch (after a rule change).

    LLM summaries survive: a new story gets the summary of the old story it overlaps most
    (Jaccard >= 0.5 over member articles). It is kept as is when the membership is identical, and
    otherwise rewritten once the story has grown by half (summary_n keeps the old article count).
    """
    ensure_schema()
    old = {}
    for r in db.query("""SELECT s.id, s.summary, s.summary_n, list(a.id) AS members FROM stories s JOIN articles a ON a.story_id = s.id
                         WHERE s.summary_by = 'llm' GROUP BY ALL"""):
        old[r["id"]] = (set(r["members"]), r["summary"], r["summary_n"])
    db.execute("UPDATE articles SET story_id = NULL, dup_of = NULL, clustered_at = NULL")
    db.execute("DELETE FROM stories")
    n = cluster_pending(limit=10**9)
    if old:
        new = {r["id"]: set(r["members"]) for r in db.query(
            "SELECT story_id AS id, list(id) AS members FROM articles WHERE story_id IS NOT NULL GROUP BY 1")}
        used = set()
        for sid, mem in new.items():
            best = max(((len(mem & m) / len(mem | m), oid) for oid, (m, _, _) in old.items() if oid not in used and mem & m), default=None)
            if best and best[0] >= 0.5:
                _, summary, n_at = old[best[1]]
                same = best[0] == 1.0
                db.execute("UPDATE stories SET summary = ?, summary_by = 'llm', summary_n = ? WHERE id = ?",
                           [summary, len(mem) if same else min(n_at or len(mem), len(mem)), sid])
                used.add(best[1])
        state["summaries_kept"] = len(used)
    return n


def refresh_all() -> None:
    for r in db.query("SELECT id FROM stories"):
        refresh_story(r["id"])


# ------------------------------------------------------------------ story rows
def _top_entities(ids: list[str], texts: list[str]) -> list[dict]:
    try:
        rows = db.query(f"""SELECT m.entity_id AS id, any_value(e.name) AS name, any_value(e.type) AS type,
                                   count(DISTINCT m.ref_id) AS n
                            FROM mentions m LEFT JOIN entities e ON e.id = m.entity_id
                            WHERE m.ref_type = 'article' AND m.ref_id IN ({','.join('?' * len(ids))})
                            GROUP BY 1 ORDER BY n DESC, id LIMIT 12""", ids)
        if rows:
            return [{"id": r["id"], "name": r["name"] or r["id"].split(":", 1)[-1], "type": r["type"] or r["id"].split(":")[0], "articles": r["n"]} for r in rows]
    except Exception:
        pass
    c = Counter()
    for t in texts:
        c.update({x.upper() for x in CVE.findall(t or "")})
    return [{"id": f"cve:{k.lower()}", "name": k, "type": "cve", "articles": n} for k, n in c.most_common(8)]


def refresh_story(sid: str) -> None:
    arts = db.query("""SELECT id, title, dek, text, source, tier, role, published, fetched_at, queued_at, dup_of, status
                       FROM articles WHERE story_id = ? ORDER BY coalesce(published, fetched_at, queued_at)""", [sid])
    if not arts:
        db.execute("DELETE FROM stories WHERE id = ?", [sid])
        return
    originals = [a for a in arts if not a["dup_of"]] or arts
    # Lead: the earliest original, preferring one we could read.
    lead_a = next((a for a in originals if a["status"] == "ok"), originals[0])
    outlets = {}
    for a in originals:
        outlets.setdefault(a["source"] or "?", a["tier"] or "C")
    tiers = Counter(outlets.values())
    times = [_when(a) for a in arts]
    prev = db.query("SELECT summary, summary_by, summary_n FROM stories WHERE id = ?", [sid])
    summary, by, n_at = (prev[0]["summary"], prev[0]["summary_by"], prev[0]["summary_n"]) if prev else (None, None, None)
    if by != "llm":
        summary, by, n_at = _dek(lead_a), "dek", len(arts)
    db.execute("""INSERT OR REPLACE INTO stories (id, title, summary, summary_by, summary_n, lead_article, first_seen, last_seen,
                    article_count, source_count, tier_counts, sources, top_entities, updated_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now())""",
               [sid, lead_a["title"], summary, by, n_at, lead_a["id"], min(times), max(times), len(arts), len(outlets),
                json.dumps(dict(sorted(tiers.items()))), sorted(outlets), json.dumps(_top_entities([a["id"] for a in arts], [a["text"] or a["dek"] or "" for a in arts]))])


def _dek(a: dict) -> str | None:
    d = (a["dek"] or "").strip()
    if not d and a["text"]:
        d = " ".join(a["text"].split()[:60])
    d = re.sub(r"\s*(The post .* appeared first on .*|Continue reading.*|Read more.*)$", "", d)
    return d[:600] or None


def summarise_pending(limit: int = 5) -> int:
    """Local-LLM summaries for multi-article stories, written only while the AI helper is up.

    Rewritten when the story has grown by half since the last summary.
    """
    rows = db.query("""SELECT id, article_count, summary_n, summary_by FROM stories WHERE article_count >= 2
                       AND (summary_by IS DISTINCT FROM 'llm' OR article_count >= summary_n * 1.5)
                       ORDER BY last_seen DESC LIMIT ?""", [limit])
    n = 0
    for s in rows:
        arts = db.query("""SELECT source, title, coalesce(text, dek) AS body FROM articles WHERE story_id = ? AND dup_of IS NULL
                           ORDER BY coalesce(published, fetched_at) LIMIT 6""", [s["id"]])
        material = "\n\n".join(f"[{a['source']}] {a['title']}\n{' '.join((a['body'] or '').split()[:220])}" for a in arts)
        out = chat([
            {"role": "system", "content": "You summarise cyber-security news. Write 2-3 factual sentences covering what happened, "
                                          "who is affected and who is said to be responsible. Use only facts in the articles; "
                                          "say 'reportedly' for unconfirmed claims. No preamble."},
            {"role": "user", "content": material},
        ], max_tokens=220)
        if not out:
            return n
        out = re.sub(r"<think>.*?</think>", "", out, flags=re.S).strip()
        if out:
            db.execute("UPDATE stories SET summary = ?, summary_by = 'llm', summary_n = ? WHERE id = ?", [out[:1200], s["article_count"], s["id"]])
            n += 1
    state["summaries_llm"] += n
    return n

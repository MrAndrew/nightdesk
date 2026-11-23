"""Entity and claim extraction from free text (reports, articles, posts).

    extract(text, url=None, use_llm=True) -> {"iocs": {...}, "techniques": [...], "actors": [...],
                                              "malware": [...], "claims": [...]}

1. Deterministic: IOCs (iocs.py), explicit ATT&CK ids, and known actor/malware names spotted
   from the reference aliases.
2. LLM (osinthub.ai.client.chat, JSON schema, no thinking), chunked: actors, malware, tools,
   campaigns, victims, sectors, techniques described in the body and claims, each with a
   verbatim quote. Every quote is checked against the source (whitespace-normalised); claims and
   techniques whose quote is not in the text are dropped. Names go through the alias index.
3. Techniques come from attacker text only: cues, procedure-example proposals and model technique
   quotes skip defender text (hunting / detection / mitigation sections, query code, advice to the
   reader, analyst procedure; defender.py). IOCs, names and the model's input are unaffected.

Docs: okf/data/entities.md#extraction
"""
from __future__ import annotations

import json
import logging
import re
import time
import unicodedata

from .iocs import extract_iocs
from .normalize import key, specific_tokens
from .refdata import catalog

log = logging.getLogger("osinthub.entities.extract")

CHUNK_CHARS = 9000
OVERLAP = 400
PREDICATES = ["uses", "attributed-to", "targets", "exploits", "communicates-with", "drops", "delivers",
              "linked-to", "variant-of", "part-of", "operates", "hosts"]

# last-run stats, read by the eval and the docs (LLM seconds, chunk count)
LAST_STATS: dict = {}

SCHEMA = {
    "type": "object",
    "properties": {
        "actors": {"type": "array", "items": {"type": "string"}},
        "malware": {"type": "array", "items": {"type": "string"}},
        "tools": {"type": "array", "items": {"type": "string"}},
        "campaigns": {"type": "array", "items": {"type": "string"}},
        "victims": {"type": "array", "items": {"type": "string"}},
        "sectors": {"type": "array", "items": {"type": "string"}},
        "countries": {"type": "array", "items": {"type": "string"}},
        "techniques": {"type": "array", "items": {
            "type": "object",
            "properties": {"name": {"type": "string"}, "id": {"type": "string"}, "quote": {"type": "string"}},
            "required": ["name", "id", "quote"]}},
        "claims": {"type": "array", "items": {
            "type": "object",
            "properties": {"subject": {"type": "string"}, "predicate": {"type": "string", "enum": PREDICATES},
                           "object": {"type": "string"}, "quote": {"type": "string"}},
            "required": ["subject", "predicate", "object", "quote"]}},
    },
    "required": ["actors", "malware", "tools", "campaigns", "victims", "sectors", "countries", "techniques", "claims"],
}

SYSTEM = """You are a cyber threat intelligence analyst mapping one part of a report to structured data.
Rules:
- Only include what THIS text states. Never add knowledge from memory.
- actors: threat actor / APT group / intrusion-set names exactly as written (e.g. "Sednit", "UNC3886", "CL-STA-1178"). Not security vendors, victims or researchers.
- malware: every malware family, backdoor, implant, ransomware, loader, stealer, wiper or web shell named (proper names only, without words like "backdoor"). tools: offensive or dual-use tools the attackers ran (e.g. Cobalt Strike, Mimikatz, AdFind, Rclone, AnyDesk). Not legitimate services they abused (Discord, Slack, Dropbox) and not Windows binaries.
- campaigns: named operations. victims: named victim organisations. sectors: targeted industries. countries: targeted countries.
- techniques: map the attacker behaviour described in this part to MITRE ATT&CK Enterprise techniques. Be thorough: every distinct behaviour (initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, command and control, exfiltration, impact) that the text shows the attackers or their malware performing, typically 5 to 25 per part. Use the most specific official name (sub-technique when the text is specific, e.g. "PowerShell", "Windows Command Shell", "Spearphishing Attachment", "LSASS Memory", "Web Protocols", "Scheduled Task"), its id, and quote: a short exact span (4-15 words) copied character-for-character from the text showing it. Skip defensive advice, detection guidance and generic background.
- claims: up to 5 key relationships between named entities (actor uses malware, actor targets sector or country, campaign attributed-to actor, malware communicates-with a C2 domain or IP, actor exploits CVE). quote: an exact fragment (6-30 words) copied character-for-character from the text that states it.
- Quotes must be verbatim copies. If you cannot quote it, leave it out.
Return JSON only."""


# ---------------------------------------------------------------- quote verification
_QUOTE_MAP = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-",
                            "‑": "-", "‐": "-", " ": " ", "…": "..."})


def ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


class Source:
    """Source text with a loose index for finding quotes and returning the verbatim span."""

    def __init__(self, text: str):
        self.text = text
        self.norm = ws(text)
        # loose form: lowercase, unified punctuation, single spaces; with a map back into self.norm
        loose, idx = [], []
        prev_space = False
        for i, ch in enumerate(self.norm):
            c = unicodedata.normalize("NFKC", ch.translate(_QUOTE_MAP)).lower()
            if c.isspace():
                if prev_space:
                    continue
                prev_space = True
                c = " "
            else:
                prev_space = False
            for cc in c:
                loose.append(cc)
                idx.append(i)
        self.loose = "".join(loose)
        self.idx = idx

    def find(self, quote: str) -> str | None:
        """The verbatim (whitespace-normalised) source span for a quote, or None."""
        q = ws(quote).strip(" .\"'")
        if len(q) < 8:
            return None
        if q in self.norm:
            return q
        lq = ws(unicodedata.normalize("NFKC", q.translate(_QUOTE_MAP)).lower())
        lq = lq.replace("…", "...")
        pos = self.loose.find(lq)
        if pos < 0:
            # the model often drops or adds an ellipsis: accept the longest quoted piece if long enough
            parts = [p.strip() for p in re.split(r"\.\.\.|…", lq) if len(p.strip()) >= 25]
            for p in sorted(parts, key=len, reverse=True):
                pos = self.loose.find(p)
                if pos >= 0:
                    lq = p
                    break
        if pos < 0:
            return None
        a, b = self.idx[pos], self.idx[pos + len(lq) - 1] + 1
        span = self.norm[a:b]
        return span if span in self.norm else None


# ---------------------------------------------------------------- helpers
def chunks(text: str, size: int = CHUNK_CHARS, overlap: int = OVERLAP) -> list[str]:
    text = text or ""
    if len(text) <= size:
        return [text] if text.strip() else []
    paras = re.split(r"(\n\s*\n)", text)
    out, cur = [], ""
    for p in paras:
        if len(cur) + len(p) > size and cur.strip():
            out.append(cur)
            cur = cur[-overlap:] + p
        else:
            cur += p
        while len(cur) > size * 1.5:          # a single giant paragraph
            out.append(cur[:size])
            cur = cur[size - overlap:]
    if cur.strip():
        out.append(cur)
    return out


_BOILER = re.compile(r"^(share|tweet|related|subscribe|cookie|menu|search|log ?in|sign ?up|newsletter|follow us)\b", re.I)


def _clean_name(n: str) -> str:
    n = ws(n).strip(" .,;:\"'()[]")
    n = re.sub(r"^(the|a|an)\s+", "", n, flags=re.I)
    return n


def _resolve(name: str, types) -> tuple[str, str | None]:
    """(canonical display name, entity id or None) for a raw name. Placeholders ("unknown
    threat actor", "the attackers") resolve to nothing."""
    from .normalize import is_placeholder
    cat = catalog()
    n = _clean_name(name)
    if not n or len(n) > 80:
        return "", None
    if is_placeholder(n) and not cat.resolve(n, types=types, fuzzy=False):
        return "", None
    eid = cat.resolve(n, types=types)
    if eid:
        return cat.entities[eid]["name"], eid
    # strip a trailing generic word for display ("BirdCall backdoor" -> "BirdCall")
    t = n.split()
    while len(t) > 1 and t[-1].lower() in ("backdoor", "malware", "ransomware", "trojan", "loader", "stealer",
                                           "implant", "group", "family", "variant", "rat", "tool", "framework",
                                           "campaign", "operation", "apt", "infostealer", "downloader", "dropper"):
        t.pop()
    return " ".join(t), None


_COMMON = set("""agent covenant empire beacon backdoor loader dropper raccoon kitten panda bear spider shadow ghost
phantom hydra kraken venom viper cobra python snake turtle storm thunder lightning dragon tiger lion wolf fox
eagle hawk falcon raven crow phoenix titan atlas zeus apollo hermes mercury jupiter saturn neptune pluto
mars venus earth moon sun star nova comet orbit galaxy cosmos matrix nexus cipher enigma vector sigma alpha beta
gamma delta omega echo hunter ranger scout pilot sentinel guardian keeper warden monitor update service system
windows office outlook teams chrome edge firefox discord slack telegram github dropbox google microsoft apple
amazon cloud azure android linux windows macos ios network server client admin root user guest master
remote access shell command control proxy tunnel socks bridge relay gateway portal tor vpn ssh rdp smb ftp
http https dns mail email spam phishing exploit payload stealer miner banker worm wiper locker crypt
crypto bitcoin wallet bank cash money gold silver iron steel stone rock sand dust rain snow ice fire water air
team group gang crew squad unit force army legion order union alliance""".split())


def spot_names(text: str) -> tuple[list[str], list[str]]:
    """Known actor and malware/tool names spotted in the text by their reference aliases.
    Conservative: case-sensitive whole words; single common words need several mentions."""
    cat = catalog()
    found_a, found_m = {}, {}
    words = set(re.findall(r"[A-Za-z0-9][\w.\-]*[A-Za-z0-9]", text))
    lower_text = text
    for e in _spot_index():
        alias, eid, typ = e
        first = alias.split()[0]
        if first not in words:
            continue
        pat = r"(?<![\w\-])" + re.escape(alias) + r"(?![\w\-])"
        n = len(re.findall(pat, lower_text))
        if not n:
            continue
        single_common = (" " not in alias and alias.lower() in _COMMON)
        if single_common:
            continue
        need = 1 if (" " in alias or re.search(r"\d", alias) or (sum(c.isupper() for c in alias) >= 2)) else 2
        if n < need:
            continue
        name = cat.entities[eid]["name"]
        (found_a if typ == "actor" else found_m)[eid] = name
    return list(found_a.values()), list(found_m.values())


_SPOT: list | None = None


def _spot_index():
    global _SPOT
    if _SPOT is None:
        cat = catalog()
        out = []
        for e in cat.entities.values():
            if e["type"] not in ("actor", "malware", "tool"):
                continue
            for a in [e["name"], *e["aliases"]]:
                if len(a) < 4 or not re.search(r"[A-Za-z]", a) or a.lower() in _COMMON:
                    continue
                if re.fullmatch(r"[GS]\d{4}", a):
                    continue
                if a == a.lower():          # all-lowercase aliases are too often ordinary words
                    continue
                if not specific_tokens(a) and not re.search(r"\d", a):
                    continue
                out.append((a, e["id"], e["type"]))
        _SPOT = out
    return _SPOT


# ---------------------------------------------------------------- LLM
def _chat(messages, schema, max_tokens):
    try:
        from ..ai import client
    except Exception:
        return None
    try:
        return client.chat(messages, json_schema=schema, max_tokens=max_tokens, timeout=900)
    except TypeError:
        return client.chat(messages, json_schema=schema)
    except Exception as e:
        log.warning("LLM call failed: %s", e)
        return None


def _parse(s: str | None):
    if not s:
        return None
    s = s.strip()
    s = re.sub(r"^```(?:json)?|```$", "", s).strip()
    try:
        return json.loads(s)
    except ValueError:
        m = re.search(r"\{.*\}", s, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except ValueError:
                return None
    return None


PROMPT_VERSION = "v2"
_HEXRUN = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _is_appendix(part: str) -> bool:
    """IOC lists and ATT&CK tables: nothing for the model there, the deterministic pass covers them."""
    from .iocs import refang
    t = refang(part)
    ioc_chars = sum(len(m) for m in _HEXRUN.findall(t))
    ioc_chars += sum(len(m) for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t))
    ioc_chars += sum(len(m) for m in re.findall(r"\bhttps?://\S+", t))
    return ioc_chars > 0.35 * max(len(t), 1) or len(_TID.findall(t)) >= 12


def _cache_path(part: str):
    import hashlib
    from .. import config
    h = hashlib.sha1((PROMPT_VERSION + SYSTEM + part).encode()).hexdigest()
    return config.LAKE / "cache" / "entities-llm" / h[:2] / f"{h}.json"


def _cached(part: str):
    """LLM answers are cached per chunk, so re-ingesting a text (or a syndicated copy) is free."""
    try:
        p = _cache_path(part)
        return json.loads(p.read_text()) if p.exists() else None
    except Exception:
        return None


def _store_cache(part: str, out: dict) -> None:
    try:
        p = _cache_path(part)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out))
    except Exception:
        pass


def llm_extract(text: str, title: str | None = None) -> dict | None:
    parts = chunks(text)
    if not parts:
        return None
    merged = {k: [] for k in SCHEMA["required"]}
    t0 = time.time()
    ok = 0
    for i, part in enumerate(parts):
        if _is_appendix(part):
            LAST_STATS["skipped_appendix"] = LAST_STATS.get("skipped_appendix", 0) + 1
            continue
        head = f"Report title: {title}\n" if title else ""
        msgs = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"{head}Part {i + 1} of {len(parts)}:\n\n{part}"}]
        out = _cached(part)
        if out is None:
            out = _parse(_chat(msgs, SCHEMA, 2500))
            if out is not None:
                _store_cache(part, out)
        else:
            LAST_STATS["cache_hits"] = LAST_STATS.get("cache_hits", 0) + 1
        if out is None:
            if i == 0:
                # helper down (or not answering): don't spend time on the remaining chunks
                LAST_STATS.update(llm_seconds=round(time.time() - t0, 1), chunks=len(parts), ok=0)
                return None
            continue
        ok += 1
        for k in merged:
            v = out.get(k) or []
            if isinstance(v, list):
                merged[k].extend(v)
    LAST_STATS.update(llm_seconds=round(time.time() - t0, 1), chunks=len(parts), ok=ok)
    return merged


# ---------------------------------------------------------------- public
def _title_of(text: str) -> str | None:
    for line in (text or "").splitlines()[:60]:
        l = line.strip()
        if 20 <= len(l) <= 160 and not _BOILER.match(l) and " " in l:
            return l
    return None


def extract(text: str, url: str | None = None, use_llm: bool = True) -> dict:
    text = text or ""
    cat = catalog()
    iocs = extract_iocs(text, url)
    techniques: list[str] = []
    for m in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", text):
        tid = m.group(0)
        if tid in cat.tech_name and tid not in techniques:
            techniques.append(tid)
    from .techcues import cue_techniques
    # Technique evidence comes from attacker text only: hunting / detection / mitigation sections,
    # query code, advice to the reader and analyst procedure are blanked (defender.py).
    from .defender import defender_spans, mask
    dspans = defender_spans(text)
    att = mask(text, dspans)
    cue_quotes = {t: q for t, q in cue_techniques(att).items() if t in cat.tech_name}
    for tid in cue_quotes:
        if tid not in techniques:
            techniques.append(tid)
    spot_a, spot_m = spot_names(text)
    result = {"iocs": iocs, "techniques": techniques, "actors": list(spot_a), "malware": list(spot_m), "claims": [],
              "technique_quotes": dict(cue_quotes)}
    LAST_STATS.clear()
    LAST_STATS.update(llm_seconds=0.0, chunks=0, ok=0, llm=False,
                      defender_chars=sum(len(text[a:b].strip()) for a, b, _ in dspans))
    if not use_llm:
        return result
    raw = llm_extract(text, _title_of(text))
    if raw is None:
        return result
    LAST_STATS["llm"] = True
    src = Source(text)
    dropped = dropped_def = 0
    dflags = _defender_flags(src, text, dspans)

    def addu(lst, v):
        if v and v not in lst:
            lst.append(v)

    names: dict[str, str] = {}      # raw lowercase name -> canonical, for claims
    orgs: list[str] = []
    for n in raw.get("actors", []):
        if not isinstance(n, str):
            continue
        disp, eid = _resolve(n, ("actor", "campaign"))
        if eid and cat.entities[eid]["type"] == "campaign":
            continue
        if not disp or not _mentioned(disp, n, text):
            continue
        # A name is an actor when it is a known threat actor, or when the text attributes
        # malicious activity to it; otherwise (proxy services, vendors, platforms) it is an org.
        if eid or _attributed_malicious(n, src, raw.get("claims", [])):
            addu(result["actors"], disp)
        else:
            addu(orgs, disp)
        names[key(n)] = disp
    for field in ("malware", "tools"):
        for n in raw.get(field, []):
            if not isinstance(n, str) or _not_a_tool(n):
                continue
            disp, eid = _resolve(n, ("malware", "tool"))
            if field == "tools" and not eid:
                continue                      # unknown tool names stay in "tools" only
            if disp and _mentioned(disp, n, text):
                addu(result["malware"], disp)
                names[key(n)] = disp
    extra = {"campaigns": [], "victims": [], "sectors": [], "countries": [], "tools": [], "orgs": orgs}
    for n in raw.get("campaigns", []):
        if isinstance(n, str):
            disp, _ = _resolve(n, ("campaign",))
            if disp and _mentioned(disp, n, text):
                addu(extra["campaigns"], disp)
                names[key(n)] = disp
    for f in ("victims", "sectors", "countries"):
        for n in raw.get(f, []):
            if isinstance(n, str) and _clean_name(n):
                addu(extra[f], _clean_name(n)[:80])
    for n in raw.get("tools", []):
        if isinstance(n, str):
            disp, _ = _resolve(n, ("tool", "malware"))
            addu(extra["tools"], disp)

    tech_quotes = result["technique_quotes"]
    prov: dict[str, dict] = {t: {"src": {"cue" if t in cue_quotes else "id"}, "quotes": set()} for t in result["techniques"]}
    for t in raw.get("techniques", []):
        if not isinstance(t, dict):
            continue
        q = src.find(t.get("quote") or "")
        if not q:
            dropped += 1
            continue
        if dflags and _in_defender_text(src.norm, dflags, q):
            dropped_def += 1              # the model quoted a hunting query or advice, not the attacker
            continue
        tid = _map_technique(t.get("name") or "", t.get("id") or "")
        if not tid:
            continue
        p = prov.setdefault(tid, {"src": set(), "quotes": set()})
        p["src"].add("llm")
        p["quotes"].add(q)
        tech_quotes.setdefault(tid, q)
    for t, q in cue_quotes.items():
        prov[t]["quotes"].add(q) if t in prov else None
    result["techniques"] = select_techniques(prov)
    # Two tiers. Confirmed: explicit ids, cue + model agreement, and techniques whose evidence
    # matches ATT&CK procedure examples (procvec hard gate, plus its proposals). Suggested: the
    # rest of the model's techniques with a verified quote, kept apart from attribution.
    gated = gate_techniques(src, {t: prov[t] for t in result["techniques"]}, dflags)
    if gated is not None:
        keep, proposed = gated
        confirmed = [t for t in result["techniques"] if t in keep]
        for tid, sent in proposed.items():
            if tid not in confirmed and not any(_family(tid, t) for t in confirmed):
                confirmed.append(tid)
                prov.setdefault(tid, {"src": set(), "quotes": set()})["src"].add("knn")
                tech_quotes.setdefault(tid, sent)
        result["suggested_techniques"] = [t for t in result["techniques"]
                                          if t not in confirmed and "llm" in prov[t]["src"] and prov[t]["quotes"]]
        result["techniques"] = confirmed
    else:
        # no procedure index or embeddings: only doubly-backed techniques are confirmed
        strong = [t for t in result["techniques"] if "id" in prov[t]["src"] or {"cue", "llm"} <= prov[t]["src"]]
        result["suggested_techniques"] = [t for t in result["techniques"] if t not in strong and "llm" in prov[t]["src"]]
        result["techniques"] = strong + [t for t in result["techniques"] if t not in strong and "llm" not in prov[t]["src"]]
    result["technique_sources"] = {t: sorted(p["src"]) + [f"q{len(p['quotes'])}"] for t, p in prov.items()}

    seen = set()
    for c in raw.get("claims", []):
        if not isinstance(c, dict):
            continue
        q = src.find(c.get("quote") or "")
        subj, obj, pred = _clean_name(c.get("subject") or ""), _clean_name(c.get("object") or ""), c.get("predicate")
        if not q or not subj or not obj or pred not in PREDICATES:
            dropped += 1
            continue
        subj = names.get(key(subj), subj)
        obj = names.get(key(obj), obj)
        k = (key(subj), pred, key(obj))
        if k in seen:
            continue
        seen.add(k)
        result["claims"].append({"subject": subj, "predicate": pred, "object": obj, "quote": q})
    result.update(extra)
    LAST_STATS["dropped_unverified"] = dropped
    LAST_STATS["dropped_defender"] = dropped_def
    return result


_LEGIT = {"discord", "slack", "telegram", "github", "gitlab", "dropbox", "onedrive", "googledrive", "google", "microsoft",
          "microsoft365", "microsoft365outlook", "outlook", "office365", "teams", "zoom", "vmware", "virtualbox",
          "windows", "linux", "macos", "android", "ios", "chrome", "firefox", "edge", "virustotal", "aws", "azure",
          "cloudflare", "ngrokcom", "fileio", "mega", "whatsapp", "signal", "skype", "gmail", "yandex", "notepad",
          "explorer", "svchost", "rundll32", "regsvr32", "mshta", "wscript", "cscript", "msiexec", "lsass"}


def _not_a_tool(n: str) -> bool:
    k = key(n)
    return (not k or k in _LEGIT or bool(re.search(r"\.(exe|dll|sys|ps1|bat|cmd|vbs|js|lnk|zip|py|sh)$", n, re.I))
            or bool(re.fullmatch(r"[\w-]+\.[a-z]{2,}", n.strip(), re.I)) and " " not in n)


def select_techniques(prov: dict[str, dict]) -> list[str]:
    """Every candidate with a verified quote, an artefact cue or an explicit id; weak ones are
    then checked by verify_techniques()."""
    return [t for t, p in prov.items() if p["src"] & {"cue", "id"} or p["quotes"]]


_SENT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])")


def _family(a: str, b: str) -> bool:
    return a == b or a.split(".")[0] == b or b.split(".")[0] == a


def _sentence_of(src: Source, quote: str) -> str:
    """The whole (whitespace-normalised) sentence around a verified quote."""
    i = src.norm.find(quote)
    if i < 0:
        return quote
    a = max(src.norm.rfind(". ", 0, i) + 2, 0)
    b = src.norm.find(". ", i + len(quote))
    b = len(src.norm) if b < 0 else b + 1
    return src.norm[a:b][:600]


def _defender_flags(src: Source, text: str, spans) -> list[bool] | None:
    """Per-character defender flags aligned with src.norm, or None when there is no defender text."""
    if not spans:
        return None
    from .defender import norm_flags
    norm, flags = norm_flags(text, spans)
    return flags if norm == src.norm else None


def _mostly_defender(norm: str, flags: list[bool], a: int, b: int) -> bool:
    from .defender import mostly_defender
    return mostly_defender(norm, flags, a, b)


def _in_defender_text(norm: str, flags: list[bool], quote: str) -> bool:
    """True when every occurrence of the quote in norm is mostly defender text."""
    i = norm.find(quote)
    if i < 0:
        return False
    while i >= 0:
        if not _mostly_defender(norm, flags, i, i + len(quote)):
            return False
        i = norm.find(quote, i + 1)
    return True


def gate_techniques(src: Source, prov: dict[str, dict], dflags: list[bool] | None = None):
    """Hard gate against ATT&CK procedure examples (procvec.py). Techniques backed by two
    signals (cue and model, or an explicit id) pass; others pass when one of their evidence
    sentences has enough matching procedure examples among its neighbours. Every sentence can
    also propose a technique its close neighbours agree on, except defender text (dflags, from
    defender.py: hunting queries, detection tables, advice to the reader). Returns (kept ids,
    {proposed id: sentence}), or None when the index or embeddings are unavailable."""
    from . import procvec
    if procvec.load() is None:
        return None
    strong = {t for t, p in prov.items() if "id" in p["src"] or {"cue", "llm"} <= p["src"]}
    weak = [t for t in prov if t not in strong]
    ev = [(t, _sentence_of(src, q)) for t in weak for q in sorted(prov[t]["quotes"], key=len)[:3]]
    sents, pos = [], 0
    for x in _SENT.split(src.norm):
        i = src.norm.find(x, pos)
        pos = i + len(x) if i >= 0 else pos
        if 40 <= len(x) <= 600 and not (dflags and i >= 0 and _mostly_defender(src.norm, dflags, i, i + len(x))):
            sents.append(x)
    texts = [e for _, e in ev] + sents
    nbs = procvec.neighbours(texts) if texts else []
    if nbs is None:
        return None
    keep = set(strong)
    for (t, _), nb in zip(ev, nbs[:len(ev)]):
        if procvec.supports(t, nb):
            keep.add(t)
    proposed: dict[str, str] = {}
    for sent, nb in zip(sents, nbs[len(ev):]):
        tid = procvec.propose(nb)
        if tid and tid not in proposed:
            proposed[tid] = sent
    LAST_STATS["gate"] = {"checked": len(weak), "kept": len(keep) - len(strong), "proposed": len(proposed)}
    return keep, proposed


_MALICIOUS = re.compile(
    r"\b(?:threat actors?|threat groups?|apt|hack(?:ers?|ed|ing)|attack(?:s|ed|ers?|ing)?|compromis\w+|breach\w*|"
    r"exploit\w*|deploy\w*|infect\w*|phish\w*|steal\w*|stole|exfiltrat\w+|ransom\w*|extort\w*|espionage|"
    r"targe?t(?:s|ed|ing)?|malware|backdoor\w*|implant\w*|intrusions?|spear-?phish\w*|cybercrim\w+|"
    r"operators?|state-sponsored|nation-state|aligned|campaigns?|wiper|ddos)\b", re.I)


def _attributed_malicious(name: str, src: Source, claims: list) -> bool:
    """True when a sentence naming `name`, or a verified claim with it as subject, describes
    malicious activity."""
    n = _clean_name(name)
    if not n:
        return False
    for c in claims or []:
        if isinstance(c, dict) and key(c.get("subject") or "") == key(n) and c.get("predicate") in (
                "uses", "targets", "exploits", "attributed-to", "drops", "delivers", "operates"):
            q = src.find(c.get("quote") or "")
            if q and _MALICIOUS.search(q):
                return True
    pat = re.compile(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])", re.I)
    for sent in _SENT.split(src.norm):
        if pat.search(sent) and _MALICIOUS.search(pat.sub(" ", sent)):
            return True
    return False


def _mentioned(disp: str, raw_name: str, text: str) -> bool:
    """The model must not invent names: the raw name (or the canonical one) has to occur in the text."""
    t = text.lower()
    for n in (raw_name, disp):
        n = _clean_name(n).lower()
        if n and n in t:
            return True
    # loose: all specific tokens present
    toks = specific_tokens(raw_name)
    return bool(toks) and all(tok in t for tok in toks)


_TACTICS = {"reconnaissance", "resourcedevelopment", "initialaccess", "execution", "persistence", "privilegeescalation",
            "defenseevasion", "credentialaccess", "discovery", "lateralmovement", "collection", "commandandcontrol",
            "exfiltration", "impact"}


def _map_technique(name: str, tid: str) -> str | None:
    """ATT&CK id for the model's technique: by official (or former) name first. A parent name
    with one of its sub-technique ids gives that sub-technique. The model's id alone is used
    when the name is unknown (renamed techniques), unless the name is just a tactic."""
    cat = catalog()
    name = ws(re.sub(r"\bT\d{4}(?:\.\d{3})?\b", "", name or "")).strip(" :-()")
    by_name = cat.technique(name) if name else None
    if not by_name and ":" in name:
        by_name = cat.technique(name.split(":")[-1].strip())
    tid = (tid or "").strip().upper()
    valid = bool(re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid)) and tid in cat.tech_name
    if by_name:
        if valid and "." in tid and "." not in by_name and tid.split(".")[0] == by_name:
            return tid
        return by_name
    if valid and name and key(name) not in _TACTICS:
        return tid
    return None

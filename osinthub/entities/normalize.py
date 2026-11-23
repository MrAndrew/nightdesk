"""Entity ids, name normalisation and generic-word handling. Model: okf/data/entities.md"""
from __future__ import annotations

import re
import unicodedata

TYPES = ("ip", "prefix", "asn", "domain", "url", "hash", "cve", "product", "vendor", "malware", "actor",
         "campaign", "technique", "tool", "sector", "country", "org", "device")

# Words that say what kind of thing a name is rather than which one. They are stripped before
# exact matching ("LockBit ransomware" -> "lockbit") and never count as evidence in fuzzy matching,
# so "Fancy Bear" and "Venomous Bear" can't meet on "bear".
GENERIC = {
    "the", "group", "groups", "team", "gang", "crew", "apt", "actor", "actors", "threat", "hackers", "hacker",
    "operators", "operator", "affiliate", "affiliates", "cluster", "activity", "campaign", "operation",
    "ransomware", "malware", "trojan", "backdoor", "rat", "loader", "stealer", "infostealer", "botnet",
    "family", "variant", "implant", "dropper", "downloader", "framework", "toolkit", "kit", "tool",
    "worm", "wiper", "spyware", "banker", "banking", "miner", "payload", "beacon", "agent",
    # vendor naming-scheme animals and weather
    "bear", "panda", "kitten", "spider", "chollima", "tiger", "jackal", "buffalo", "leopard", "ocelot",
    "typhoon", "blizzard", "sleet", "sandstorm", "tempest", "hail", "rain", "dust", "cyclone", "flood", "storm",
    "unit", "apt-c", "ta", "unc", "dev", "temp",
}
STRIP_EDGES = {"the", "group", "team", "gang", "crew", "ransomware", "malware", "trojan", "backdoor", "rat",
               "loader", "stealer", "infostealer", "botnet", "family", "variant", "implant", "dropper",
               "downloader", "threat", "actor", "apt group", "hackers", "operators", "framework", "toolkit",
               "worm", "wiper", "spyware", "banker", "banking", "campaign", "operation", "activity", "cluster", "beacon"}


def fold(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    return s.lower().strip()


def slug(s: str) -> str:
    """Readable normalised name for ids: lowercase, runs of other characters become '-'."""
    s = re.sub(r"[^a-z0-9.:/_@-]+", "-", fold(s))
    return re.sub(r"-{2,}", "-", s).strip("-")


def key(s: str) -> str:
    """Lookup key: lowercase letters and digits only ("APT-28", "APT 28" -> "apt28")."""
    return re.sub(r"[^a-z0-9]", "", fold(s))


def tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", fold(s)) if t]


def stripped_key(s: str) -> str:
    """Key with generic leading/trailing words removed ("the Lazarus group" -> "lazarus")."""
    t = tokens(s)
    while len(t) > 1 and t[-1] in STRIP_EDGES:
        t.pop()
    while len(t) > 1 and t[0] in STRIP_EDGES:
        t.pop(0)
    return "".join(t)


def specific_tokens(s: str) -> list[str]:
    return [t for t in tokens(s) if t not in GENERIC]


def digits(s: str) -> str:
    return "".join(re.findall(r"\d+", s or ""))


def entity_id(type_: str, value: str) -> str:
    v = value.strip()
    if type_ in ("ip", "prefix", "hash", "domain"):
        v = v.lower()
    elif type_ == "cve":
        v = v.upper().replace("–", "-")
        return f"cve:{v.lower()}"
    elif type_ == "asn":
        n = re.sub(r"\D", "", v)
        return f"asn:as{n}"
    elif type_ == "country":
        return f"country:{v.lower()}"
    elif type_ == "technique":
        return f"technique:{v.upper()}"
    elif type_ == "url":
        return f"url:{v}"
    else:
        v = slug(v)
    return f"{type_}:{v}"


# Words that only describe an unnamed party; a name made only of these (plus GENERIC words)
# is a placeholder ("unknown threat actor", "the attackers", "Chinese hackers"), not an entity.
PLACEHOLDER = {"unknown", "unidentified", "unnamed", "unattributed", "undisclosed", "suspected", "likely", "possible",
               "new", "novel", "previously", "undocumented", "same", "this", "that", "these", "those", "an", "a",
               "attackers", "adversary", "adversaries", "cybercriminals", "criminals", "intruders", "perpetrators",
               "state", "sponsored", "nation", "linked", "aligned", "nexus", "based", "backed", "chinese", "china",
               "russian", "russia", "iranian", "iran", "north", "south", "korean", "korea", "vietnamese", "pakistani",
               "indian", "unc", "its", "their", "his", "her", "one", "two", "several", "multiple", "various", "other",
               "custom", "commodity", "generic", "financially", "motivated", "espionage", "ransom", "data", "info",
               "information", "remote", "access", "trojan", "attacker", "hacker", "hackers", "group", "groups",
               "dprk", "prc", "nk", "speaking", "affiliated", "related", "tied", "connected", "israeli", "turkish",
               "belarusian", "ukrainian", "american", "european", "western", "eastern", "middle", "east", "asian",
               "african", "latin", "arabic", "persian", "korean-speaking", "russian-speaking", "chinese-speaking"}


def is_placeholder(name: str) -> bool:
    toks = tokens(name)
    return not toks or all(t in GENERIC or t in PLACEHOLDER for t in toks)

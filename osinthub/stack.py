"""My stack: one list of what the user follows, matched across the whole app. Reference: okf/architecture/my-stack.md

The list (setting `news.watchlist`, the same one the v1.0 News watchlist used) holds three kinds of item:

  stack     vendors and products the user runs: {"vendor": "SonicWall", "product": "SMA"} (product may be empty)
  entities  entity ids (actor, malware, CVE, ASN, domain, ...), read through the user's merges (overrides.resolve)
  keywords  free words

Each item is matched, deterministically and without any model, against:

  * CISA KEV entries (vendor and product fields, CPE strings where present, names normalised),
  * news stories (whole-word text match; mentions for entities),
  * network incidents (indicator, the malware a feed names, followed words in the title, KEV CVEs of a followed product),
  * EPSS jumps of followed CVEs (and of KEV CVEs of a followed product),
  * ransomware victims whose name is a followed organisation, and victims claimed by a followed group.

False-positive guards: short names (three letters or fewer) and common words ("Progress", "Arm") only match a vendor
field exactly, or as written (case-sensitive) in a headline; a short product ("DSM", "SMA") needs its vendor too;
ransomware victim matching reads only the victim's name, never the group's ("Barracuda claims ...").

Endpoints under /api/stack; the old /api/news/watchlist endpoints keep working on the same list.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import unicodedata

from fastapi import APIRouter, Body, HTTPException, Query

from . import apiutil, db

router = APIRouter(prefix="/api/stack", tags=["stack"])
KEY = "news.watchlist"
ADDED_KEY = "stack.followed_at"   # label -> when it was followed, for the "you just followed it" look-back
LOOKBACK_DAYS = 30                # a new follow shows its exploited bugs from the last 30 days once, until Caught up
MAX_ITEMS = 500
EPSS_JUMP = 0.05            # a rise of at least 5 points of probability ...
EPSS_HIGH = 0.10            # ... or crossing the 10% line most often cited (FIRST EPSS FAQ)

# Corporate words dropped from the end of a vendor name, so "Palo Alto Networks" and "Palo Alto" are one vendor.
_SUFFIX = {"inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "llc", "plc", "gmbh",
           "ag", "sa", "bv", "oy", "ab", "networks", "systems", "software", "technologies", "technology",
           "communications", "group", "holdings", "international", "foundation", "project"}
# Names that are also everyday words: matched only in a vendor field, or as written in a headline.
COMMON = {"progress", "arm", "apple", "oracle", "zoom", "box", "slack", "target", "square", "shell", "edge", "office",
          "windows", "chrome", "server", "network", "cloud", "mail", "exchange", "outlook", "teams", "word", "excel",
          "access", "git", "go", "node", "spring", "struts", "log", "digital", "total", "micro", "trend", "android",
          "linux", "google", "home", "assistant", "plex", "docker", "kibana", "elastic", "fortra", "unity", "ivy",
          "magento", "drupal", "joomla", "jenkins", "redis", "mongo", "nginx", "apache", "openssl", "bash", "sudo",
          "citrix", "cisco", "samsung", "huawei", "lenovo", "dell", "asus", "acer", "netgear", "linksys", "belkin",
          "honeywell", "siemens", "schneider", "rockwell", "intel", "amd", "nvidia", "qualcomm", "mediatek"} - {
          # distinctive vendor names that are fine as plain words
          "cisco", "samsung", "huawei", "lenovo", "netgear", "linksys", "belkin", "honeywell", "siemens", "schneider",
          "rockwell", "nvidia", "qualcomm", "mediatek", "citrix", "kibana", "magento", "drupal", "joomla", "jenkins",
          "redis", "nginx", "openssl", "docker", "plex", "elastic", "google", "linux", "android", "intel", "dell",
          "asus", "acer", "apache"}

# Words that say what kind of thing a product is, not which one: never enough on their own to match across vendors.
GENERIC = {"router", "routers", "multiple", "products", "product", "devices", "device", "firmware", "server", "servers",
           "appliance", "appliances", "camera", "cameras", "nas", "switch", "switches", "firewall", "firewalls", "vpn",
           "application", "applications", "system", "systems", "software", "platform", "web", "management", "manager",
           "console", "gateway", "client", "os", "home", "cloud", "media", "network", "networks", "access", "point",
           "modem", "modems", "http", "https", "my", "the", "and", "for", "secure", "connect", "center", "suite", "plugin", "service"}
# Vendors so broad that a bare mention in a news body says little: their news counts only in a headline.
BROAD = {"microsoft", "apple", "google", "cisco", "oracle", "adobe", "linux", "android", "amazon", "ibm", "samsung",
         "intel", "meta", "mozilla", "vmware", "sap", "hp", "dell"}
# Product names people say without the vendor ("Windows", "Chrome"): the vendor they imply, matched as vendor+product.
PRODUCT_VENDOR = {"windows": "Microsoft", "exchange": "Microsoft", "exchangeserver": "Microsoft", "outlook": "Microsoft",
                  "sharepoint": "Microsoft", "office": "Microsoft", "edge": "Microsoft", "chrome": "Google",
                  "googlechrome": "Google", "dsm": "Synology", "diskstationmanager": "Synology", "unifi": "Ubiquiti",
                  "fortios": "Fortinet", "fortigate": "Fortinet", "esxi": "VMware", "vcenter": "VMware",
                  "netscaler": "Citrix", "routeros": "MikroTik", "qts": "QNAP", "panos": "Palo Alto Networks",
                  "pfsense": "Netgate", "macos": "Apple", "safari": "Apple", "webkit": "Apple"}
# Other names KEV and NVD use for the same product (compact key -> alternative names).
PRODUCT_ALIASES = {"dsm": ["DiskStation Manager", "DiskStation"], "diskstationmanager": ["DSM"],
                   "chrome": ["Chromium"], "googlechrome": ["Chromium"], "exchangeserver": ["Exchange"],
                   "netscaler": ["NetScaler ADC", "Application Delivery Controller", "ADC"],
                   "mycloud": ["My Cloud", "MyCloud"], "fortios": ["FortiOS", "FortiProxy"],
                   "esxi": ["ESXi", "vSphere"], "webkit": ["WebKit", "Multiple Products"],
                   "httpserver": ["HTTP Server", "httpd"], "mediaserver": ["Media Server", "Plex Media Server"]}

# Common home-lab gear for the "What do you run?" chips: (vendor, product).
HOMELAB = [
    ("Synology", "DSM"), ("QNAP", "QTS"), ("Ubiquiti", "UniFi"), ("Netgate", "pfSense"), ("OPNsense", ""),
    ("TrueNAS", ""), ("Proxmox", "VE"), ("Home Assistant", ""), ("Plex", "Media Server"), ("OpenSSH", ""),
    ("MikroTik", "RouterOS"), ("TP-Link", ""), ("Netgear", ""), ("ASUS", ""), ("Fortinet", "FortiOS"),
    ("SonicWall", "SMA"), ("OpenWrt", ""), ("Pi-hole", ""), ("Jellyfin", ""), ("Nextcloud", ""), ("Docker", ""),
    ("WireGuard", ""), ("Tailscale", ""), ("Western Digital", "My Cloud"), ("Zyxel", ""), ("D-Link", ""),
    ("VMware", "ESXi"), ("Microsoft", "Exchange Server"), ("Ivanti", "Connect Secure"), ("Citrix", "NetScaler"),
    ("Palo Alto Networks", "PAN-OS"), ("Apache", "HTTP Server"), ("Cisco", ""), ("Raspberry Pi", ""),
]

CPE_RE = re.compile(r"cpe:2\.3:[aho]:([^:\s]+):([^:\s]+)", re.I)
INDICATOR_TYPES = {"ip", "domain", "url", "hash", "cve", "prefix", "asn"}
NAMED_TYPES = {"actor", "malware", "tool", "campaign"}


# ====================================================================================== normalisation
def tokens(s: str | None) -> list[str]:
    """Lower-case ASCII word tokens: "D-Link" -> ["d", "link"], "Ubiquiti UniFi" -> ["ubiquiti", "unifi"]."""
    s = unicodedata.normalize("NFKD", str(s or "")).encode("ascii", "ignore").decode().lower().replace("&", " and ")
    return re.findall(r"[a-z0-9]+", s)


def vtokens(s: str | None) -> list[str]:
    """Vendor tokens without trailing corporate words ("Cisco Systems, Inc." -> ["cisco"])."""
    t = tokens(s)
    while len(t) > 1 and t[-1] in _SUFFIX:
        t.pop()
    return t


def compact(t: list[str]) -> str:
    return "".join(t)


def ambiguous(t: list[str]) -> bool:
    """Too short or too common to find safely in free text."""
    c = compact(t)
    return len(c) <= 3 or (len(t) == 1 and c in COMMON)


def seq_in(p: list[str], h: list[str], model_suffix: bool = True) -> bool:
    """True when the tokens p appear as a run in h. The last token may carry a model number ("sma" finds
    "sma1000"), and spacing may differ ("sonic os" finds "sonicos" and back)."""
    if not p or not h:
        return False
    n, cp = len(p), compact(p)
    eq = lambda a, b: a == b or (len(a) > 3 and (a == b + "s" or b == a + "s"))   # noqa: E731
    for i in range(len(h)):
        if len(h[i:i + n]) == n and all(eq(x, y) for x, y in zip(h[i:i + n], p)):
            return True
        if model_suffix and h[i:i + n - 1] == p[:-1] and i + n - 1 < len(h):
            last = h[i + n - 1]
            if len(p[-1]) >= 2 and last.startswith(p[-1]) and last[len(p[-1]):].isdigit():
                return True
        acc = ""   # a run of tokens that spells the phrase without its spaces, or the other way round
        for j in range(i, min(len(h), i + 4)):
            acc += h[j]
            if acc == cp and (j > i or n > 1):
                return True
            if len(acc) >= len(cp):
                break
    return False


def distinctive(t: list[str]) -> bool:
    """A product name safe to match without its vendor: not short, not an everyday word, not only generic words."""
    return not ambiguous(t) and len(compact(t)) >= 5 and any(x not in GENERIC for x in t)


def vendor_eq(a: str | None, b: str | None) -> bool:
    ta, tb = vtokens(a), vtokens(b)
    if not ta or not tb:
        return False
    if compact(ta) == compact(tb):
        return True
    if ambiguous(ta) or ambiguous(tb):
        return False
    return seq_in(ta, tb, model_suffix=False) or seq_in(tb, ta, model_suffix=False)


def label(item: dict) -> str:
    return " ".join(x for x in (item.get("vendor"), item.get("product")) if x).strip()


def parse_cpes(text: str | None) -> list[tuple[str, str]]:
    return [(v.replace("_", " "), p.replace("_", " ")) for v, p in CPE_RE.findall(text or "") if v != "*" and p != "*"]


def word_re(name: str, case: bool = False, model: bool = False) -> re.Pattern | None:
    """A whole-word pattern for a name in free text; spacing and hyphens between its words may vary."""
    parts = re.findall(r"[A-Za-z0-9]+", unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode())
    if not parts:
        return None
    body = r"[\s\-_./]*".join(re.escape(p) for p in parts)
    return re.compile(rf"(?<![A-Za-z0-9]){body}{r'[0-9]*' if model else ''}(?![A-Za-z0-9])", 0 if case else re.I)


# ====================================================================================== storage
def _clean_stack(items) -> list[dict]:
    out, seen = [], set()
    for x in items or []:
        if isinstance(x, str):
            x = split_label(x)
        if not isinstance(x, dict):
            continue
        v, p = str(x.get("vendor") or "").strip()[:80], str(x.get("product") or "").strip()[:120]
        if not v and p:
            v, p = p, ""
        if not v:
            continue
        k = (compact(vtokens(v)), compact(tokens(p)))
        if k in seen:
            continue
        seen.add(k)
        out.append({"vendor": v, "product": p})
    return sorted(out, key=lambda i: label(i).lower())


def get() -> dict:
    w = db.get_setting(KEY, {}) or {}
    return {"entities": list(w.get("entities") or []), "keywords": list(w.get("keywords") or []),
            "stack": _clean_stack(w.get("stack"))}


def save(w: dict) -> dict:
    ent = [str(x).strip() for x in w.get("entities") or [] if str(x).strip()]
    kw = [str(x).strip()[:120] for x in w.get("keywords") or [] if str(x).strip()]
    st = _clean_stack(w.get("stack"))
    if len(ent) > MAX_ITEMS or len(kw) > MAX_ITEMS or len(st) > MAX_ITEMS:
        raise HTTPException(400, f"at most {MAX_ITEMS} entities, {MAX_ITEMS} keywords and {MAX_ITEMS} products")
    # one entry per entity: an id merged into one already followed is the same follow
    keep: list[str] = []
    for e in sorted(set(ent)):
        if not any(_same_entity(e, k) for k in keep):
            keep.append(e)
    kws: dict[str, str] = {}
    for k in kw:
        kws.setdefault(k.lower(), k)
    out = {"entities": keep, "keywords": sorted(kws.values(), key=str.lower), "stack": st}
    db.set_setting(KEY, out)
    return out


_equivalents = apiutil.entity_equivalents
_resolve = apiutil.entity_resolve


def _same_entity(a: str, b: str) -> bool:
    return a.lower() == b.lower() or _resolve(a).lower() == _resolve(b).lower()


def known_vendors() -> list[str]:
    """Vendor names the app knows (KEV, CISA advisories, vendor entities, home-lab list), most frequent first."""
    names: dict[str, int] = {}
    for v, _p in HOMELAB:
        names.setdefault(v, 0)
    tables = _tables()
    if "events" in tables:
        for r in db.query("""SELECT tags[1] AS v, count(*) AS n FROM events WHERE source = 'cisa_kev' AND len(tags) > 0
                             AND tags[1] <> 'ransomware' GROUP BY 1"""):
            names[r["v"]] = names.get(r["v"], 0) + r["n"]
    if "entities" in tables:
        for r in db.query("SELECT name FROM entities WHERE type = 'vendor' AND name IS NOT NULL"):
            names.setdefault(r["name"], 0)
    return [k for k, _ in sorted(names.items(), key=lambda kv: (-kv[1], kv[0].lower()))]


def split_label(text: str) -> dict:
    """Free text to {vendor, product}: a known vendor at the start becomes the vendor ("Synology DSM" ->
    Synology / DSM); otherwise the whole text is one name."""
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    t = tokens(text)
    best = None
    for v in known_vendors():
        vt = tokens(v)
        if vt and t[:len(vt)] == vt and (best is None or len(vt) > len(tokens(best))):
            best = v
    if best and len(tokens(best)) < len(t):
        # keep the user's own spelling of the product: drop as many leading words as the vendor has
        words = text.split(" ")
        n, acc = 0, []
        for i, w in enumerate(words):
            acc += tokens(w)
            if len(acc) >= len(tokens(best)):
                n = i + 1
                break
        return {"vendor": best, "product": " ".join(words[n:]).strip()}
    return {"vendor": text, "product": ""}


def _tables() -> set[str]:
    return db.tables()


# ====================================================================================== terms
_SENTENCE_START = re.compile(r"(^|[.!?:;\n]\s*|[\"“‘(]\s*)$")


def hit(pat, title: str = "", body: str = "") -> bool:
    """One text pattern against a headline and body. Mode "amb" (short or everyday names): the headline only, as
    written, and not as a sentence's first word ("Progress report: ..."); "title" (very broad vendors): the headline
    only; "": anywhere."""
    _lb, ps, word, mode = pat
    title = title or ""
    if mode == "amb":
        m = ps[0].search(title)
        acronym = word.isupper()   # "HP" leads a headline as a name; "Progress" may just start a sentence
        while m and not acronym and _SENTENCE_START.search(title[:m.start()]):
            m = ps[0].search(title, m.end())
        return bool(m) and all(p.search(title) for p in ps[1:])
    hay = title if mode == "title" else f"{title}\n{body or ''}"
    return all(p.search(hay) for p in ps)


class Terms:
    """The followed list compiled once for matching. Labels: "stack:<label>", the entity id as followed, or
    "keyword:<word>" (the shape the v1.0 digest used for `matched`)."""

    def __init__(self, w: dict | None = None):
        self.w = w if w is not None else get()
        self.names: dict[str, str] = {}             # label -> display name
        self.stack = []                             # (label, vendor tokens, product tokens, item)
        self.alts: dict[str, list[list[str]]] = {}  # label -> alternative product token lists (aliases)
        for it in self.w["stack"]:
            lb = f"stack:{label(it)}"
            self.names[lb] = label(it)
            vt, pt = vtokens(it["vendor"]), tokens(it["product"])
            implied = PRODUCT_VENDOR.get(compact(tokens(it["vendor"]))) if not pt else None
            if implied:   # "Windows" is Microsoft Windows, "Chrome" is Google Chrome
                vt, pt = vtokens(implied), tokens(it["vendor"])
            self.alts[lb] = [tokens(a) for a in PRODUCT_ALIASES.get(compact(pt), [])]
            self.stack.append((lb, vt, pt, {**it, "_vendor": implied or it["vendor"], "_product": it["vendor"] if implied else it["product"]}))
        self.keywords = []
        for k in self.w["keywords"]:
            lb = f"keyword:{k}"
            self.names[lb] = k
            self.keywords.append((lb, tokens(k), k))
        self.cves: dict[str, str] = {}              # CVE id (upper) -> label
        self.indicators: dict[str, str] = {}        # ip / domain / url / hash value (lower) -> label
        self.named: list[tuple[str, list[str], str]] = []   # (label, name tokens, type) for actor/malware/tool/...
        self.orgs: list[tuple[str, list[str], str]] = []    # (label, tokens, name): organisations
        self.vendor_entities: list[tuple[str, dict]] = []   # vendor/product entities, matched like stack items
        self.equiv: dict[str, list[str]] = {}
        rows = {}
        ids = {i for e in self.w["entities"] for i in _equivalents(e)}
        if ids and "entities" in _tables():
            for r in db.query(f"SELECT id, type, name, aliases FROM entities WHERE id IN ({','.join('?' * len(ids))})", list(ids)):
                rows[r["id"]] = r
        for e in self.w["entities"]:
            same = _equivalents(e)
            self.equiv[e] = same
            typ = e.split(":", 1)[0]
            for i in same:
                r = rows.get(i) or {"id": i, "type": i.split(":", 1)[0], "name": i.split(":", 1)[-1], "aliases": []}
                typ = r.get("type") or typ
                nm = r.get("name") or i.split(":", 1)[-1]
                if e not in self.names or i == _resolve(e):
                    self.names[e] = nm
                if typ == "cve":
                    self.cves[nm.upper()] = e
                elif typ in INDICATOR_TYPES:
                    self.indicators[nm.lower()] = e
                    if typ == "asn":
                        self.indicators[nm.lower().removeprefix("as")] = e
                elif typ == "vendor":
                    self.vendor_entities.append((e, {"vendor": nm, "product": ""}))
                elif typ == "product":
                    self.vendor_entities.append((e, {"vendor": nm, "product": "", "whole": True}))
                elif typ == "org":
                    self.orgs.append((e, vtokens(nm), nm))
                else:
                    for n in [nm, *(r.get("aliases") or [])]:
                        t = tokens(n)
                        if t and (len(compact(t)) >= 4 or n == nm):
                            self.named.append((e, t, typ))

    @property
    def empty(self) -> bool:
        return not (self.w["entities"] or self.w["keywords"] or self.w["stack"])

    def name(self, lb: str) -> str:
        return self.names.get(lb) or lb.split(":", 1)[-1]

    # -------------------------------------------------------------------------------- vendor / product
    @staticmethod
    def product_hit(vt: list[str], pt: list[str], kv: str, kp: str, whole: bool = False, alts=()) -> bool:
        """A followed vendor (vt) and optional product (pt, or one of its aliases `alts`) against one record's vendor
        and product fields. Without the vendor, only a distinctive product name in a single-vendor row counts:
        "routers" never matches TP-Link's "Multiple Routers"."""
        kvt, kpt = vtokens(kv), tokens(kp)
        if whole:   # a product entity's name already carries its vendor ("Cisco SD-WAN")
            return seq_in(vt, tokens(f"{kv} {kp}"), model_suffix=False) or (
                bool(kvt) and vt[:len(kvt)] == kvt and seq_in(vt[len(kvt):], kpt))
        v_ok = bool(kvt) and (compact(vt) == compact(kvt) or (not ambiguous(vt) and vendor_eq(" ".join(vt), kv)))
        multi = "multiple" in kvt or "multiple" in kpt
        if not pt:
            # a single name: the vendor, or a distinctive product name ("UniFi", "OpenSSH")
            return v_ok or (distinctive(vt) and not multi and seq_in(vt, kpt))
        names = [pt, *alts]
        # an everyday-word product ("Exchange", "Windows") must lead the product name: "Internet Key Exchange" is not it
        p_ok = any(seq_in(x, kpt[:len(x) + 1] if ambiguous(x) else kpt) for x in names)
        if v_ok:
            return p_ok
        return not multi and any(distinctive(x) and seq_in(x, kpt) for x in names)

    def record(self, vendor: str = "", product: str = "", cve: str = "", text: str = "", cpes=()) -> list[str]:
        """Labels of the followed items that one vulnerability record (KEV row, NVD record) touches."""
        out: list[str] = []
        pairs = [(vendor or "", product or "")] + list(cpes or []) + parse_cpes(text)
        for lb, vt, pt, _it in self.stack:
            if any(self.product_hit(vt, pt, v, p, alts=self.alts.get(lb, ())) for v, p in pairs if v or p):
                out.append(lb)
        for lb, it in self.vendor_entities:
            vt = vtokens(it["vendor"]) if not it.get("whole") else tokens(it["vendor"])
            if any(self.product_hit(vt, [], v, p, whole=bool(it.get("whole"))) for v, p in pairs if v or p):
                out.append(lb)
        if cve and cve.upper() in self.cves:
            out.append(self.cves[cve.upper()])
        hay = tokens(" ".join([cve or "", vendor or "", product or "", text or ""]))
        for lb, kt, _k in self.keywords:
            if kt and (seq_in(kt, hay, model_suffix=False) if not ambiguous(kt) else seq_in(kt, tokens(f"{vendor} {product}"), False)):
                out.append(lb)
        return list(dict.fromkeys(out))

    # -------------------------------------------------------------------------------- free text
    def _text_patterns(self):
        """(label, [patterns that must all match], prefilter word) for news and alert titles."""
        if hasattr(self, "_pats"):
            return self._pats
        pats = []

        def name_pat(name: str, t: list[str], model=False):
            amb = ambiguous(t)
            return word_re(name, case=amb, model=model), amb

        for lb, vt, pt, it in self.stack:
            ven, prod = it["_vendor"], it["_product"]
            v, va = name_pat(ven, vt)
            broad = "title" if compact(vt) in BROAD else ""
            if not prod:
                if v:
                    pats.append((lb, [v], ven, "amb" if va else broad))
                continue
            p, pa = name_pat(prod, pt, model=True)
            if not p:
                continue
            if distinctive(pt):
                pats.append((lb, [p], prod, ""))   # a distinctive product name stands alone
            elif v:
                pats.append((lb, [v, p], ven, "amb" if va else ""))
            for alt in PRODUCT_ALIASES.get(compact(pt), []):
                ap = word_re(alt, case=ambiguous(tokens(alt)), model=True)
                if ap and distinctive(tokens(alt)):
                    pats.append((lb, [ap], alt, ""))
                elif ap and v:
                    pats.append((lb, [v, ap], ven, "amb" if va else ""))
        for lb, it in self.vendor_entities:
            t = tokens(it["vendor"])
            v, va = name_pat(it["vendor"], t)
            if v:
                pats.append((lb, [v], it["vendor"], "amb" if va else "title" if compact(t) in BROAD else ""))
        for lb, kt, k in self.keywords:
            p, pa = name_pat(k, kt)
            if p:
                pats.append((lb, [p], k, "amb" if pa else ""))
        for lb, t, _typ in self.named:
            nm = " ".join(t)
            p, pa = name_pat(nm, t)
            if p and not pa:
                pats.append((lb, [p], nm, ""))
        self._pats = pats
        return pats

    def text(self, title: str = "", body: str = "") -> list[str]:
        """Labels whose names appear in a headline (title) or its body. Ambiguous names count only in the title,
        as written."""
        return list(dict.fromkeys(pat[0] for pat in self._text_patterns() if hit(pat, title, body)))

    # -------------------------------------------------------------------------------- organisations, groups
    def victim(self, victim: str, group: str) -> list[str]:
        out = []
        vt = vtokens(victim)
        for lb, _vtk, _ptk, it in self.stack:
            if vendor_eq(it["vendor"], victim) or (not ambiguous(vtokens(it["vendor"])) and seq_in(vtokens(it["vendor"]), vt, False)):
                out.append(lb)
        for lb, ot, _nm in self.orgs:
            if ot and (compact(ot) == compact(vt) or (not ambiguous(ot) and seq_in(ot, vt, False))):
                out.append(lb)
        for lb, kt, _k in self.keywords:
            if kt and not ambiguous(kt) and seq_in(kt, vt, False):
                out.append(lb)
        gt = compact(tokens(group))
        for lb, t, _typ in self.named:   # "lockbit5" is LockBit; "lockbitx" is not
            c = compact(t)
            if gt and c and (gt == c or (gt.startswith(c) and gt[len(c):].isdigit())):
                out.append(lb)
        return list(dict.fromkeys(out))

    def malware(self, name: str) -> list[str]:
        c = compact(tokens(name))
        return list(dict.fromkeys(lb for lb, t, _typ in self.named if c and compact(t) == c))


# ====================================================================================== matches across the app
def _kev_rows(where: str = "", params=()) -> list[dict]:
    if "events" not in _tables():
        return []
    return db.query(f"""SELECT id, ts, title, summary, tags, url, stored_at FROM events
                        WHERE source = 'cisa_kev' AND kind = 'kev' {where} ORDER BY ts DESC, id""", list(params))


def kev_fields(r: dict) -> dict:
    cve = (r.get("title") or "").split(" ")[0].upper()
    tags = list(r.get("tags") or [])
    vendor = tags[0] if len(tags) > 0 and tags[0] != "ransomware" else ""
    product = tags[1] if len(tags) > 1 and tags[1] != "ransomware" else ""
    return {"cve": cve, "vendor": vendor, "product": product, "summary": r.get("summary") or ""}


def kev_hits(T: Terms, rows: list[dict] | None = None) -> dict[str, list[str]]:
    """CVE id -> labels, over KEV rows (all of them by default)."""
    out = {}
    for r in rows if rows is not None else _kev_rows():
        f = kev_fields(r)
        m = T.record(f["vendor"], f["product"], f["cve"], f["summary"])
        if m:
            out[f["cve"]] = m
    return out


def network_hits(T: Terms, t: dt.datetime | None) -> list[dict]:
    """Open network incidents that involve something followed: its indicator, the malware a feed names for it, a
    followed name in its title, or a KEV CVE of a followed product. New or changed since t first, then the ones
    still waiting for you."""
    if T.empty:
        return []
    try:
        from .netlog import incidents
        incidents.ensure()
        rows = db.query(incidents.incidents_sql("", "WHERE state IN ('new', 'ack')", incidents.ORDER, "LIMIT 2000"))
    except Exception:
        return []
    kev = None
    out = []
    for r in rows:
        try:
            ev = json.loads(r.get("evidence") or "{}") if isinstance(r.get("evidence"), str) else (r.get("evidence") or {})
        except ValueError:
            ev = {}
        ind = ev.get("indicator") or {}
        meta = ind.get("meta") or {}
        value = str(r.get("indicator") or "")
        matched: list[str] = []
        for v in [value, *(ind.get("observed") or [])]:
            lb = T.indicators.get(str(v).lower()) or T.cves.get(str(v).upper())
            if lb:
                matched.append(lb)
        if meta.get("malware"):
            matched += T.malware(str(meta["malware"]))
            matched += [pat[0] for pat in T._text_patterns() if pat[0].startswith("keyword:") and all(p.search(str(meta["malware"])) for p in pat[1])]
        matched += T.text(r.get("title") or "")
        if value.upper().startswith("CVE-") and (T.stack or T.vendor_entities or T.keywords):
            if kev is None:
                kev = kev_hits(T)
            matched += kev.get(value.upper(), [])
        matched = list(dict.fromkeys(matched))
        if not matched:
            continue
        new = t is None or any(x and x > t for x in (r.get("last_ts"), r.get("created_at"), r.get("updated_at")))
        out.append({"type": "alert", "why": "follow", "id": r["id"], "title": r.get("title"), "severity": r.get("severity"),
                    "device": r.get("device"), "indicator": value, "kind": r.get("kind"), "rule": r.get("rule"),
                    "direction": r.get("direction"), "source": r.get("source"), "malware": meta.get("malware"),
                    "category": ind.get("category"), "ts": r.get("ts"), "last_ts": r.get("last_ts"),
                    "count": r.get("count"), "demo": bool(r.get("demo")), "still_open": not new,
                    "state": r.get("state"), "matched": matched,
                    "evidence": {k: v for k, v in ev.items() if k not in ("uids", "rows", "sample", "listing")},
                    "href": f"#network/alerts/{r['id']}"})
    try:
        from .netlog.api import _name_alerts
        _name_alerts(out)
    except Exception:
        pass
    out.sort(key=lambda i: (i["still_open"], i["demo"]))
    return out


def epss_hits(T: Terms, t: dt.datetime, kev: dict[str, list[str]] | None = None) -> list[dict]:
    """Followed CVEs (and KEV CVEs of followed products) whose EPSS rose sharply since t."""
    if T.empty or "epss" not in _tables():
        return []
    want: dict[str, list[str]] = {c: [lb] for c, lb in T.cves.items()}
    for c, lbs in (kev if kev is not None else kev_hits(T)).items():
        want.setdefault(c, []).extend(x for x in lbs if x not in want.get(c, []))
    if not want:
        return []
    rows = db.query(f"""SELECT cve, epss, percentile, prev_epss, since FROM epss
                        WHERE upper(cve) IN ({','.join('?' * len(want))}) AND since > ? AND prev_epss IS NOT NULL
                          AND (epss - prev_epss >= ? OR (prev_epss < ? AND epss >= ?))
                        ORDER BY epss - prev_epss DESC, cve""", list(want) + [t, EPSS_JUMP, EPSS_HIGH, EPSS_HIGH])
    return [{"type": "epss", "why": "follow", "cve": r["cve"].upper(), "epss": r["epss"], "epss_percentile": r["percentile"],
             "prev_epss": r["prev_epss"], "since": r["since"], "matched": want[r["cve"].upper()],
             "href": f"#entities/cve:{r['cve'].lower()}"} for r in rows]


def victim_hits(T: Terms, t: dt.datetime) -> list[dict]:
    """Ransomware victims posted since t that are a followed organisation, or claimed by a followed group."""
    if T.empty or "events" not in _tables():
        return []
    out = []
    for r in db.query("""SELECT id, ts, title, tags, url, country FROM events WHERE source = 'ransomware_live'
                         AND ts > ? ORDER BY ts DESC, id LIMIT 5000""", [t]):
        title = r.get("title") or ""
        group, _, victim = title.partition(" claims ")
        if not victim:
            continue
        group = (list(r.get("tags") or []) or [group])[0] or group
        m = T.victim(victim, group)
        if m:
            out.append({"type": "victim", "why": "follow", "id": r["id"], "victim": victim, "group": group,
                        "ts": r["ts"], "country": r.get("country"), "matched": m, "title": title})
    return out


def story_hits(T: Terms, t: dt.datetime) -> dict[str, set[str]]:
    """Story id -> labels for news since t that names a followed product, vendor, group or entity by name (the
    digest adds mentions and keywords itself)."""
    pats = [p for p in T._text_patterns() if p[0].startswith(("stack:",)) or (p[0] in {x[0] for x in T.vendor_entities})]
    if not pats or not {"articles", "stories"} <= _tables():
        return {}
    hits: dict[str, set[str]] = {}
    for pat in pats:
        lb, _ps, word, mode = pat
        # a cheap prefilter on the first word, then the whole-word check in Python
        first = (re.findall(r"[A-Za-z0-9]+", word) or [word])[0]
        col = "title" if mode else "concat_ws(' ', title, dek, text)"
        rows = db.query(f"""SELECT id, story_id, title, dek, text FROM articles WHERE story_id IS NOT NULL
                            AND coalesce(published, queued_at) > ? AND {col} ILIKE ? ESCAPE '\\'""", [t, apiutil.like(first)])
        for r in rows:
            if hit(pat, r.get("title") or "", " ".join(str(r.get(k) or "") for k in ("dek", "text"))):
                hits.setdefault(r["story_id"], set()).add(lb)
    return hits


# ====================================================================================== suggestions
def suggest(q: str = "", limit: int = 12) -> list[dict]:
    """Vendors and products to follow: from KEV, CISA advisories, vendor/product entities and common home-lab gear.
    Each {vendor, product, label, kev (KEV entries that match it), from}."""
    w = get()
    have = {(compact(vtokens(i["vendor"])), compact(tokens(i["product"]))) for i in w["stack"]}
    qt = tokens(q)
    cands: dict[tuple[str, str], dict] = {}

    def add(v, p, src, n=0):
        v, p = (v or "").strip(), (p or "").strip()
        if not v:
            return
        k = (compact(vtokens(v)), compact(tokens(p)))
        c = cands.setdefault(k, {"vendor": v, "product": p, "label": label({"vendor": v, "product": p}), "from": src, "n": 0})
        c["n"] += n

    for v, p in HOMELAB:
        add(v, p, "homelab")
    tables = _tables()
    if "events" in tables:
        for r in db.query("""SELECT tags[1] AS v, tags[2] AS p, count(*) AS n FROM events WHERE source = 'cisa_kev'
                             AND len(tags) > 0 AND tags[1] <> 'ransomware' GROUP BY 1, 2"""):
            add(r["v"], "", "kev", r["n"])
            if r["p"] and r["p"] != "ransomware":
                add(r["v"], r["p"], "kev", r["n"])
    if "advisory_cves" in tables:
        try:
            for r in db.query("""SELECT v, count(*) AS n FROM (SELECT unnest(vendors) AS v FROM advisory_cves) GROUP BY 1"""):
                add(r["v"], "", "advisory", r["n"])
        except Exception:
            pass
    if "entities" in tables and qt:
        for r in db.query("SELECT name FROM entities WHERE type = 'vendor' AND name ILIKE ? ESCAPE '\\' LIMIT 50", [apiutil.like(q.strip())]):
            add(r["name"], "", "nvd")
    out = []
    for k, c in cands.items():
        if k in have:
            continue
        lt = tokens(c["label"])
        # every word typed is the start of some word of the name ("syn ds" finds Synology DSM)
        if qt and not (compact(lt).startswith(compact(qt)) or all(any(x.startswith(q1) for x in lt) for q1 in qt)):
            continue
        out.append(c)

    def rank(c):
        lt = tokens(c["label"])
        starts = bool(qt) and compact(lt).startswith(compact(qt))
        return (not starts, c["from"] != "homelab", bool(c["product"]) if qt else 0, -c["n"], c["label"].lower())
    out.sort(key=rank)
    out = out[:limit]
    # how many KEV entries each one would match (the count shown next to a suggestion)
    if out and "events" in tables:
        rows = _kev_rows()
        for c in out:
            T = Terms({"entities": [], "keywords": [], "stack": [{"vendor": c["vendor"], "product": c["product"]}]})
            c["kev"] = len(kev_hits(T, rows))
    for c in out:
        c.pop("n", None)
    return out


def quick(limit: int = 12) -> list[dict]:
    """First-run "What do you run?" chips: common home-lab gear not followed yet, with its KEV count."""
    w = get()
    have = {(compact(vtokens(i["vendor"])), compact(tokens(i["product"]))) for i in w["stack"]}
    have_v = {compact(vtokens(i["vendor"])) for i in w["stack"] if not i["product"]}
    rows = _kev_rows()
    out = []
    for v, p in HOMELAB:
        k = (compact(vtokens(v)), compact(tokens(p)))
        if k in have or k[0] in have_v:
            continue
        T = Terms({"entities": [], "keywords": [], "stack": [{"vendor": v, "product": p}]})
        out.append({"vendor": v, "product": p, "label": label({"vendor": v, "product": p}), "kev": len(kev_hits(T, rows))})
        if len(out) >= limit:
            break
    return out


# ====================================================================================== public view
def public(counts: bool = False) -> dict:
    w = get()
    T = Terms(w)
    out = {**w, "names": {e: T.name(e) for e in w["entities"]}, "equivalents": T.equiv,
           "count": len(w["entities"]) + len(w["keywords"]) + len(w["stack"])}
    if counts:
        rows = _kev_rows()
        per: dict[str, int] = {}
        for lbs in kev_hits(T, rows).values():
            for lb in lbs:
                per[lb] = per.get(lb, 0) + 1
        out["kev_counts"] = per
    return out


def _entity_key(w: dict, eid: str) -> str | None:
    return next((e for e in w["entities"] if _same_entity(e, eid)), None)


def follow(body: dict) -> dict:
    w = get()
    added, existing = False, None
    if body.get("entity"):
        eid = str(body["entity"]).strip()
        if ":" not in eid:
            raise HTTPException(400, "an entity id looks like type:value")
        existing = _entity_key(w, eid)
        if not existing:
            w["entities"].append(eid)
            added = True
    elif body.get("keyword"):
        k = str(body["keyword"]).strip()
        existing = next((x for x in w["keywords"] if x.lower() == k.lower()), None)
        if not existing:
            w["keywords"].append(k)
            added = True
    elif body.get("vendor") or body.get("product") or body.get("text"):
        it = split_label(body["text"]) if body.get("text") else {"vendor": body.get("vendor") or "", "product": body.get("product") or ""}
        it = (_clean_stack([it]) or [None])[0]
        if not it:
            raise HTTPException(400, "name a vendor or product")
        k = (compact(vtokens(it["vendor"])), compact(tokens(it["product"])))
        existing = next((label(x) for x in w["stack"] if (compact(vtokens(x["vendor"])), compact(tokens(x["product"]))) == k), None)
        if not existing:
            w["stack"].append(it)
            added = True
        body = {**body, **it}
    else:
        raise HTTPException(400, "follow an entity, a keyword, or a vendor/product")
    if added:
        save(w)
        lb = (f"stack:{label(body)}" if body.get("vendor") else
              f"keyword:{body['keyword'].strip()}" if body.get("keyword") else str(body.get("entity")).strip())
        at = db.get_setting(ADDED_KEY, {}) or {}
        at[lb] = dt.datetime.now(dt.UTC).isoformat()
        db.set_setting(ADDED_KEY, {k: v for k, v in at.items() if k in _labels(w)})
    res = {**public(), "added": added, "already": existing}
    if body.get("vendor") and added:
        T = Terms({"entities": [], "keywords": [], "stack": [{"vendor": body["vendor"], "product": body.get("product") or ""}]})
        res["kev"] = len(kev_hits(T))
    return res


def _labels(w: dict) -> set[str]:
    return {f"stack:{label(i)}" for i in w["stack"]} | {f"keyword:{k}" for k in w["keywords"]} | set(w["entities"])


def followed_since(t: dt.datetime) -> set[str]:
    """Labels followed after t (the marker): their recent past is still news to the user."""
    out = set()
    for k, v in (db.get_setting(ADDED_KEY, {}) or {}).items():
        try:
            if dt.datetime.fromisoformat(v) > t:
                out.add(k)
        except (TypeError, ValueError):
            pass
    return out & _labels(get())


def recent_kev_rows() -> list[dict]:
    return _kev_rows("AND ts > now() - to_days(?)", [LOOKBACK_DAYS])


def unfollow(body: dict) -> dict:
    w = get()
    key = str(body.get("key") or "")
    if body.get("entity") or (key and not key.startswith(("keyword:", "stack:"))):
        eid = str(body.get("entity") or key)
        w["entities"] = [e for e in w["entities"] if not _same_entity(e, eid)]
    elif body.get("keyword") or key.startswith("keyword:"):
        k = str(body.get("keyword") or key[8:]).lower()
        w["keywords"] = [x for x in w["keywords"] if x.lower() != k]
    elif body.get("vendor") or key.startswith("stack:"):
        it = {"vendor": body.get("vendor") or "", "product": body.get("product") or ""} if body.get("vendor") else split_label(key[6:])
        lb = key[6:].lower() if key.startswith("stack:") else None
        k = (compact(vtokens(it["vendor"])), compact(tokens(it["product"])))
        w["stack"] = [x for x in w["stack"] if label(x).lower() != lb
                      and (compact(vtokens(x["vendor"])), compact(tokens(x["product"]))) != k]
    else:
        raise HTTPException(400, "unfollow what?")
    save(w)
    return public()


# ====================================================================================== endpoints
@router.get("")
def get_stack(counts: bool = False):
    """The followed list: {entities, keywords, stack, names, equivalents, count[, kev_counts]}."""
    return public(counts)


@router.put("")
def put_stack(body: dict = Body(...)):
    """Replace the list. A field left out keeps its current value."""
    w = get()
    for k in ("entities", "keywords", "stack"):
        if k in body:
            w[k] = body.get(k) or []
    save(w)
    return public()


@router.post("/follow")
def post_follow(body: dict = Body(...)):
    """Follow one thing: {entity} | {keyword} | {vendor, product} | {text} (free text split into vendor and
    product). An entity merged into one already followed is not added twice."""
    return follow(body)


@router.post("/unfollow")
def post_unfollow(body: dict = Body(...)):
    """Unfollow one thing: {key} (as in `matched`) | {entity} (any id of a merged entity) | {keyword} | {vendor, product}."""
    return unfollow(body)


@router.get("/suggest")
def get_suggest(q: str = "", limit: int = Query(12, ge=1, le=50)):
    return {"items": suggest(q, limit)}


@router.get("/quick")
def get_quick(limit: int = Query(12, ge=1, le=40)):
    return {"items": quick(limit)}


@router.post("/match")
def post_match(body: dict = Body(...)):
    """Which followed items each record touches. Body {items: [{key, vendor?, product?, cve?, text?, title?,
    cpe?: [..], entities?: [ids]}]} -> {matches: {key: [{key, name}]}} (keys with no match are left out)."""
    items = body.get("items") or []
    if len(items) > 5000:
        raise HTTPException(400, "at most 5000 items")
    T = Terms()
    out = {}
    if not T.empty:
        for it in items:
            m = T.record(str(it.get("vendor") or ""), str(it.get("product") or ""), str(it.get("cve") or ""),
                         str(it.get("text") or ""), parse_cpes(" ".join(it.get("cpe") or [])))
            if it.get("title"):
                m += T.text(str(it["title"]))
            for e in it.get("entities") or []:
                k = _entity_key(T.w, str(e))
                if k:
                    m.append(k)
            m = list(dict.fromkeys(m))
            if m:
                out[str(it.get("key"))] = [{"key": x, "name": T.name(x)} for x in m]
    return {"matches": out}


@router.get("/kev")
def get_kev_matches():
    """Every CISA KEV entry that touches the followed list: {matches: {CVE id: [{key, name}]}} (a GET, so the KEV
    list can mark its rows "You follow ..." without sending them)."""
    T = Terms()
    if T.empty:
        return {"matches": {}}
    return {"matches": {c: [{"key": x, "name": T.name(x)} for x in m] for c, m in kev_hits(T).items()}}


@router.get("/matches")
def get_matches(since: str | None = None):
    """Everything that touches the followed list since `since` (default: the app's marker window)."""
    from .watch import marker
    t = marker.parse(marker.window(marker.get(), since)["since"])
    return _jsonable(matches(t))


def matches(t: dt.datetime) -> dict:
    T = Terms()
    if T.empty:
        return {"since": t, "kev": [], "network": [], "epss": [], "victims": [], "names": {}}
    kev_all = kev_hits(T)
    new_kev = kev_hits(T, _kev_rows("AND (ts > ? OR stored_at > ?)", [t, t]))
    return {"since": t, "kev": [{"cve": c, "matched": m} for c, m in new_kev.items()],
            "network": network_hits(T, t), "epss": epss_hits(T, t, kev_all), "victims": victim_hits(T, t),
            "names": dict(T.names)}


_jsonable = apiutil.jsonable

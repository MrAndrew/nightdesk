"""Keyword retrieval for hybrid search: an analyser with security vocabulary and a field-weighted
BM25 (BM25F) whose scores are comparable across corpora.

Analysis (the same for documents and queries):
* lower-case word tokens, stop words removed, a light suffix stemmer (inject/injection/injected);
* **concept tokens** (``~rce``, ``~sqli``, ``~unauth`` ...) added wherever a phrase for a common
  vulnerability class appears, so "RCE", "remote code execution" and "run arbitrary code" meet;
* **vendor tokens** (``~v:microsoft``) added for well-known product names, so "Exchange" or
  "FortiGate" also matches the vendor's records, and spelling variants (D-Link / DLink) meet.

Scores: ``search()`` returns ``(id, score)`` with score = BM25F / the score of an ideal
document holding every query term once, squashed to 0..1. A document matching one of five query
words scores far below one matching all five, whichever corpus it is in, so results from
different types can be merged on score.
Architecture: okf/architecture/local-ai.md#search
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict

_TOKEN = re.compile(r"cve-\d{4}-\d+|cwe-\d+|[a-z0-9][a-z0-9._+-]*[a-z0-9]|[a-z0-9]")
STOP = set("""a an and are as at be by can could does for from has have how i in is it its of on or that the this to
was were what when where which who why will with via into any all than then there these those their they them
our we you your my me do did done so if but not no one some such using used use uses about after before over without
under also may might would should must been being let lets get gets got there's i'm it's someone something
vulnerability vulnerabilities vulnerable flaw flaws issue issues bug bugs cve affects affected affecting allow allows
allowed allowing which""".split())

# Suffix rules, first match wins; the stem must keep at least 4 characters.
_SUFFIXES = (("ational", "ate"), ("izations", "ize"), ("ization", "ize"), ("isation", "ize"), ("ations", ""),
             ("ation", ""), ("ution", "ut"), ("ating", ""), ("ated", ""), ("ates", ""), ("ments", ""), ("ment", ""),
             ("ings", ""), ("ing", ""), ("ions", ""), ("ion", ""), ("ities", ""), ("ity", ""), ("ies", "y"),
             ("ers", ""), ("er", ""), ("ed", ""), ("es", ""), ("ly", ""), ("s", ""), ("ate", ""))


def stem(t: str) -> str:
    if len(t) <= 4 or any(c.isdigit() for c in t) or t.startswith("~"):
        return t
    for suf, rep in _SUFFIXES:
        if t.endswith(suf) and len(t) - len(suf) + len(rep) >= 4:
            t = t[: len(t) - len(suf)] + rep
            break
    if len(t) > 4 and t.endswith("e"):
        t = t[:-1]
    return t


# Vulnerability classes. Each pattern runs on lower-cased text.
CONCEPTS: dict[str, list[str]] = {
    "rce": [r"\brce\b", r"remote[\s-]+code[\s-]+exec", r"code[\s-]+execution", r"arbitrary[\s-]+code",
            r"(execute|execution of|run|running)\s+(of\s+)?(arbitrary|malicious|their own|attacker[\s-]controlled)\s+(code|programs?|payloads?)"],
    "sqli": [r"\bsqli\b", r"sql[\s-]*injection", r"(inject|run|execut|arbitrary|malicious|craft)\w*\s+(\w+\s+)?sql\b",
             r"\bsql\s+(commands?|queries|query|statements?)", r"database\s+quer"],
    "xss": [r"\bxss\b", r"cross[\s-]*site[\s-]*scripting", r"(inject|execut|run)\w*\s+(arbitrary\s+)?(web\s+|java)?scripts?",
            r"malicious\s+(java)?scripts?", r"script\s+injection"],
    "csrf": [r"\b[cx]srf\b", r"cross[\s-]*site[\s-]*request[\s-]*forgery"],
    "ssrf": [r"\bssrf\b", r"server[\s-]*side[\s-]*request[\s-]*forgery"],
    "authbypass": [r"auth\w*\s+bypass", r"bypass\w*\s+(the\s+|any\s+)?(auth\w*|login|log[\s-]in|2fa|mfa|sign[\s-]?in|password)",
                   r"(improper|broken|missing)\s+authentication", r"without\s+(knowing|needing)\s+(the\s+|a\s+)?password"],
    "unauth": [r"\bunauth\w*", r"without\s+(any\s+)?(authentication|authenticating|logging\s+in|a\s+login|login|credentials|an\s+account|being\s+logged\s+in|signing\s+in|a\s+password)",
               r"\bpre[\s-]?auth\w*", r"\banonymous", r"not\s+(logged|signed)\s+in", r"\bno\s+(login|credentials|account|authentication)"],
    "privesc": [r"privileges?\s+escalation", r"escalat\w*\s+(\w+\s+)?privileges?", r"elevat\w*\s+(of\s+)?(\w+\s+)?privileges?",
                r"\b(gain|obtain|get)\w*\s+(\w+\s+)?(root|admin\w*|system|elevated|higher)\s*(privileges?|access|rights)?",
                r"\blpe\b", r"\beop\b", r"become\s+(an\s+)?(admin|root)"],
    "dos": [r"denial[\s-]+of[\s-]+service", r"\bdos\b", r"\bcrash\w*", r"\bhang\w*", r"resource\s+exhaustion",
            r"(consum|exhaust)\w*\s+(\w+\s+)?(memory|cpu|resources|disk)", r"infinite\s+loop", r"assertion\s+fail",
            r"reachable\s+assertion", r"\bknock\w*\s+(\w+\s+)?offline", r"take\s+(\w+\s+)?down"],
    "pathtrav": [r"(path|directory)\s+traversal", r"\.\./", r"(read|access|download|retrieve)\w*\s+arbitrary\s+(local\s+)?files?",
                 r"arbitrary\s+file\s+(read|download|access|retrieval)", r"local\s+file\s+inclusion", r"\blfi\b"],
    "fileupload": [r"(arbitrary|unrestricted|malicious|dangerous)\s+file\s+uploads?", r"upload\w*\s+(an\s+)?(arbitrary|malicious|dangerous|executable)\s+(\w+\s+)?files?",
                   r"file\s+upload", r"upload\w*\s+(a\s+)?(web\s*shell|php)"],
    "deser": [r"deseriali[sz]", r"unseriali[sz]", r"untrusted\s+(serialized\s+)?data"],
    "memcorrupt": [r"buffer\s+overflow", r"(heap|stack)[\s-]*(based\s+)?(buffer\s+)?overflow", r"out[\s-]+of[\s-]+bounds\s+write",
                   r"memory\s+corruption", r"overflow", r"memory[\s-]safety"],
    "oobread": [r"out[\s-]+of[\s-]+bounds\s+read", r"over[\s-]?read", r"read\s+past"],
    "uaf": [r"use[\s-]+after[\s-]+free", r"\buaf\b", r"double[\s-]+free", r"dangling\s+pointer",
            r"freed\s+(memory|data|objects?|buffers?)", r"after\s+(it\s+(is|has\s+been|was)\s+|being\s+)?freed"],
    "cmdinj": [r"command\s+injection", r"\bos\s+command", r"(execut|run|inject)\w*\s+(arbitrary\s+)?(os\s+|shell\s+|system\s+)?commands?",
               r"shell\s+(commands?|metacharacters)", r"arbitrary\s+commands?"],
    "codeinj": [r"code\s+injection", r"eval\s+injection", r"template\s+injection", r"\bssti\b", r"expression\s+(language\s+)?injection", r"\bognl\b"],
    "infodisc": [r"information\s+(disclosure|exposure|leak)", r"\bleak\w*", r"(disclos|expos|reveal|retriev|obtain|read)\w*\s+(\w+\s+){0,3}(sensitive|private|confidential|secret)",
                 r"sensitive\s+(information|data)", r"(disclos|expos)\w*\s+(\w+\s+){0,2}(credentials?|tokens?|passwords?|api\s+keys?)"],
    "creds": [r"hard[\s-]?coded\s+(credentials?|passwords?|keys?|secrets?)", r"default\s+(credentials?|passwords?)",
              r"(static|embedded|built[\s-]in)\s+(keys?|credentials?|passwords?|accounts?)"],
    "xxe": [r"\bxxe\b", r"xml\s+external\s+entit"],
    "redirect": [r"open\s+redirect", r"redirect\w*\s+(\w+\s+){0,3}(arbitrary|malicious|attacker|external|untrusted)\s+(\w+\s+)?(urls?|sites?|websites?|domains?|pages?)"],
    "kev": [r"actively\s+exploited", r"exploited\s+in\s+the\s+wild", r"known\s+exploited", r"\bzero[\s-]?days?\b", r"\b0[\s-]?days?\b",
            r"under\s+(active\s+)?exploitation", r"\bkev\b", r"being\s+exploited"],
    "typeconf": [r"type\s+confusion"],
    "idor": [r"\bidor\b", r"insecure\s+direct\s+object", r"(other|another|any)\s+users?'?s?\s+(data|records|accounts?|information|files|orders|profiles?|messages)",
             r"enumerat\w*\s+(user|account|record)"],
    "authz": [r"missing\s+authori[sz]ation", r"capability\s+check", r"(broken|improper|incorrect|insufficient)\s+(access\s+control|authori[sz]ation|permissions?)",
              r"without\s+(proper\s+)?(authori[sz]ation|permission\s+checks?|access\s+checks?)", r"\blow[\s-]privileged?", r"subscriber[\s-](level|role)",
              r"(contributor|author|subscriber)[\s-](level|role)"],
    "ransom": [r"ransomware"],
    "race": [r"race\s+condition", r"\btoctou\b", r"time[\s-]of[\s-]check"],
    "nullderef": [r"null\s+(pointer\s+)?dereference", r"null\s+pointer"],
    "protopoll": [r"prototype\s+pollution"],
    "smuggle": [r"request\s+smuggling", r"desync"],
    "crypto": [r"(weak|broken|insecure|risky)\s+(crypto\w*|encryption|ciphers?|hash\w*|algorithms?)", r"clear[\s-]?text", r"plain[\s-]?text\s+(password|credential|storage|transmission)",
               r"certificate\s+validation", r"improper\s+(certificate|signature)\s+(validation|verification)"],
    "session": [r"session\s+(fixation|hijack)", r"insufficient\s+session\s+expiration"],
    "csvinj": [r"csv\s+injection", r"formula\s+injection"],
    "redos": [r"\bredos\b", r"regular\s+expression\s+denial", r"catastrophic\s+backtracking"],
    "mitm": [r"man[\s-]in[\s-]the[\s-]middle", r"\bmitm\b", r"adversary[\s-]in[\s-]the[\s-]middle", r"intercept\w*\s+(\w+\s+)?traffic"],
    "backdoor": [r"backdoor", r"hidden\s+(functionality|account)"],
    "supplychain": [r"supply[\s-]chain", r"malicious\s+packages?", r"typosquat"],
    "spoof": [r"spoof", r"fake\s+(content|pages?|sites?|ui|dialogs?|prompts?|address)", r"impersonat", r"\bphishing\b",
              r"(ui|user\s+interface)\s+(redress|misrepresentation)", r"misrepresent"],
    "sfb": [r"security\s+feature\s+bypass", r"mark[\s-]of[\s-]the[\s-]web", r"\bmotw\b", r"smartscreen",
            r"bypass\w*\s+(\w+\s+)?(security|protection|sandbox|safeguards?|mitigations?)", r"sandbox\s+escape", r"escape\w*\s+(\w+\s+)?sandbox"],
    # Kinds of software, so "a browser" or "a mobile OS" meets the product names.
    "browser": [r"\bbrowsers?\b", r"\bchrome\b", r"\bchromium\b", r"\bfirefox\b", r"\bsafari\b", r"\bwebkit\b",
                r"microsoft\s+edge", r"\bopera\b", r"\bmshtml\b", r"web\s+(pages?|content)", r"html\s+pages?"],
    "mobileos": [r"\bandroid\b", r"\bios\b(?!\s+x[er])", r"\bipados\b", r"\bharmonyos\b", r"\bemui\b",
                 r"mobile\s+(os|operating|devices?|phones?)", r"smart\s*phones?", r"\bphones?\b"],
    "cms": [r"content\s+management", r"\bcms\b", r"\bdrupal\b", r"\bjoomla\b", r"\bwordpress\b", r"\btypo3\b"],
    "kernel": [r"\bkernel\b", r"\bwin32k\b", r"\bdrivers?\b", r"\bring\s*0\b"],
    "domain": [r"active\s+directory", r"domain\s+controllers?", r"domain\s+services", r"\bkerberos\b", r"\bntlm\b", r"\bldap\b"],
    "sop": [r"same[\s-]origin", r"origin\s+polic", r"cross[\s-]origin", r"\bcors\b"],
    "dllhijack": [r"dll\s+(hijack|search[\s-]order|side[\s-]?loading|planting)", r"uncontrolled\s+search\s+path", r"unquoted\s+(service\s+)?(search\s+)?path"],
}

# Product names that imply a vendor, plus spelling variants. Pattern -> vendor token.
VENDORS: dict[str, list[str]] = {
    "microsoft": [r"\bmicrosoft\b", r"\bwindows\b", r"\boutlook\b", r"\bexchange\s+server", r"\bsharepoint\b", r"\bms\s?office\b",
                  r"microsoft\s+office", r"\bazure\b", r"\bhyper-v\b", r"\biis\b", r"\.net\b", r"\bwin32k\b", r"\bmsmq\b", r"\bmshtml\b",
                  r"\bsmbv?\d?\b", r"\bntlm\b", r"\bactive\s+directory\b", r"\bpowershell\b", r"\bdefender\b", r"\bentra\b"],
    "google": [r"\bgoogle\b", r"\bchrome\b", r"\bchromium\b", r"\bandroid\b", r"\bv8\b", r"\bpixel\b", r"\bangle\b", r"\bskia\b", r"\bdawn\b"],
    "apple": [r"\bapple\b", r"\bios\b(?!\s+xe)", r"\bipados\b", r"\bmacos\b", r"\bsafari\b", r"\bwebkit\b", r"\biphones?\b", r"\bipads?\b",
              r"\btvos\b", r"\bwatchos\b", r"\bvisionos\b", r"\bmac\s+os\b"],
    "cisco": [r"\bcisco\b", r"\bios\s+xe\b", r"\bios\s+xr\b", r"\basa\b", r"\bfirepower\b", r"\bwebex\b", r"\banyconnect\b", r"\bmeraki\b", r"\bnx-os\b",
              r"\bsmall\s+business\s+rv", r"\bise\b"],
    "fortinet": [r"\bfortinet\b", r"\bforti[a-z]+\b"],
    "paloalto": [r"\bpalo\s*alto\b", r"\bpan-?os\b", r"\bglobalprotect\b", r"\bcortex\s+xdr\b", r"\bprisma\b"],
    "citrix": [r"\bcitrix\b", r"\bnetscaler\b", r"\bxenapp\b", r"\bxendesktop\b", r"\bsharefile\b"],
    "vmware": [r"\bvmware\b", r"\besxi\b", r"\bvcenter\b", r"\bvsphere\b", r"\bworkspace\s+one\b", r"\baria\b", r"\bbroadcom\b"],
    "ivanti": [r"\bivanti\b", r"\bconnect\s+secure\b", r"\bpulse\s+(connect\s+)?secure\b", r"\bpolicy\s+secure\b", r"\bepmm\b", r"\bmobileiron\b"],
    "atlassian": [r"\batlassian\b", r"\bconfluence\b", r"\bjira\b", r"\bbitbucket\b", r"\bbamboo\b"],
    "f5": [r"\bf5\b", r"\bbig-?ip\b"],
    "apache": [r"\bapache\b", r"\bstruts\b", r"\btomcat\b", r"\blog4j\b", r"\bactivemq\b", r"\bofbiz\b", r"\bsuperset\b", r"\bhttpd\b", r"\bsolr\b",
               r"\bairflow\b", r"\bkafka\b", r"\bcommons\s+text\b"],
    "oracle": [r"\boracle\b", r"\bweblogic\b", r"\be-business\s+suite\b", r"\bpeoplesoft\b", r"\bjava\s+se\b", r"\bmysql\b"],
    "sap": [r"\bsap\b", r"\bnetweaver\b"],
    "juniper": [r"\bjuniper\b", r"\bjunos\b"],
    "sonicwall": [r"\bsonicwall\b", r"\bsonicos\b"],
    "dlink": [r"\bd[\s-]?link\b"],
    "tplink": [r"\btp[\s-]?link\b"],
    "zyxel": [r"\bzyxel\b"],
    "netgear": [r"\bnetgear\b"],
    "qnap": [r"\bqnap\b"],
    "synology": [r"\bsynology\b"],
    "wordpress": [r"\bwordpress\b", r"\bwp\b", r"\bwoocommerce\b", r"\belementor\b"],
    "linux": [r"\blinux\b"],
    "adobe": [r"\badobe\b", r"\bacrobat\b", r"\bcoldfusion\b", r"\bmagento\b", r"\bexperience\s+manager\b"],
    "mozilla": [r"\bmozilla\b", r"\bfirefox\b", r"\bthunderbird\b"],
    "gitlab": [r"\bgitlab\b"],
    "jenkins": [r"\bjenkins\b"],
    "samsung": [r"\bsamsung\b", r"\bexynos\b"],
    "qualcomm": [r"\bqualcomm\b", r"\bsnapdragon\b"],
    "arm": [r"\barm\s+mali\b", r"\bmali\s+gpu\b"],
    "openssh": [r"\bopenssh\b", r"\bsshd\b"],
    "openssl": [r"\bopenssl\b"],
}

_CONCEPT_RX = [(f"~{k}", re.compile("|".join(v))) for k, v in CONCEPTS.items()]
_VENDOR_RX = [(f"~v:{k}", re.compile("|".join(v))) for k, v in VENDORS.items()]


_POSSESSIVE = re.compile(r"(\w)['’]s\b")
_CAMEL = re.compile(r"\b[A-Za-z][a-z]+(?:[A-Z][a-z]+)+\b")
_CAMEL_PART = re.compile(r"[A-Z]?[a-z]+")


def analyze(text: str) -> list[str]:
    """Tokens of a text: stemmed words (hyphenated words also split), concept and vendor tokens."""
    text = _POSSESSIVE.sub(r"\1", text or "")  # "Google's" -> "Google"
    low = text.lower()
    out = []
    for m in _CAMEL.finditer(text):  # "BackgroundFetch" also matches "background fetch"
        out += [stem(p.lower()) for p in _CAMEL_PART.findall(m.group(0)) if p.lower() not in STOP]
    for m in _TOKEN.finditer(low):
        t = m.group(0).strip("._-")
        if not t or t in STOP:
            continue
        out.append(stem(t))
        if "-" in t and not t.startswith(("cve-", "cwe-")):  # "cross-site" also matches "cross site"
            out += [stem(p) for p in t.split("-") if p and p not in STOP]
    for tok, rx in _CONCEPT_RX:
        n = len(rx.findall(low))
        out += [tok] * min(n, 3)
    for tok, rx in _VENDOR_RX:
        if rx.search(low):
            out.append(tok)
    return out


# Field weights for BM25F. Documents without "fields" are indexed as one body field.
FIELD_WEIGHTS = {"id": 4.0, "name": 2.5, "title": 2.0, "products": 2.5, "body": 1.0}


class BM25F:
    def __init__(self, docs: dict[str, dict], k1: float = 1.2, b: float = 0.75):
        self.k1, self.b = k1, b
        self.tf: dict[str, dict[str, float]] = {}
        self.dl: dict[str, float] = {}
        self.df: Counter = Counter()
        self.post: dict[str, list[str]] = defaultdict(list)
        for i, d in docs.items():
            fields = d.get("fields") or {"body": d.get("text", "")}
            tf: dict[str, float] = defaultdict(float)
            length = 0.0
            for f, text in fields.items():
                w = FIELD_WEIGHTS.get(f, 1.0)
                toks = analyze(text if isinstance(text, str) else " ".join(map(str, text or [])))
                length += w * len(toks)
                for t in toks:
                    tf[t] += w
            self.tf[i] = dict(tf)
            self.dl[i] = length
            for t in tf:
                self.df[t] += 1
                self.post[t].append(i)
        self.n = max(len(docs), 1)
        self.avg = (sum(self.dl.values()) / self.n) or 1.0

    def idf(self, t: str) -> float:
        df = self.df.get(t, 0)
        return math.log(1 + (self.n - df + 0.5) / (df + 0.5))

    def search(self, q: str, k: int) -> list[tuple[str, float]]:
        """[(id, score in 0..1)], best first. See the module docstring for the scale."""
        qt = Counter(analyze(q))
        if not qt:
            return []
        scores: dict[str, float] = defaultdict(float)
        ideal = 0.0
        for t, qn in qt.items():
            w = min(qn, 2)  # a query repeating a concept leans on it, but only a little
            idf = self.idf(t)
            ideal += w * idf
            for i in self.post.get(t, ()):
                tf = self.tf[i][t]
                norm = 1 - self.b + self.b * self.dl[i] / self.avg
                scores[i] += w * idf * tf * (self.k1 + 1) / (tf + self.k1 * norm)
        if ideal <= 0:
            return []
        ranked = sorted(scores.items(), key=lambda x: -x[1])[:k]
        # x = 1 means "as good as a document holding every query term once"; squash to 0..1.
        return [(i, (s / ideal) / (s / ideal + 0.5)) for i, s in ranked]

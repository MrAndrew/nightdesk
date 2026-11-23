"""Deterministic IOC extraction: IPv4/IPv6, domains, URLs, hashes and CVEs, with refanging and
precision filters. Docs: okf/data/entities.md#extraction
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .refdata import catalog

# ---------------------------------------------------------------- refanging
_ZW = re.compile("[\u200b\u200c\u200d\u2060\ufeff\xad]")
_DEFANG = [
    (re.compile(r"\bh(?:xx|\*\*|XX|xX|Xx)p(s?)(?=\s*(?:\[:\]|:|\[://\]))", re.I), r"http\1"),
    (re.compile(r"\bf(?:xp|\*p)\b", re.I), "ftp"),
    (re.compile(r"\[:\]//|\[://\]|\(://\)|\{://\}"), "://"),
    (re.compile(r"\[:\]|\(:\)|\{:\}"), ":"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}|<\s*\.\s*>", re.I), "."),
    (re.compile(r"(?<=[a-z0-9])\\\.(?=[a-z0-9])", re.I), "."),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\[\s*@\s*\]|\[\s*at\s*\]", re.I), "@"),
]
_DEFANG_MARK = re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)|\[:\]|\[://\]|\bhxxp|\\\.", re.I)


def refang(text: str) -> str:
    t = _ZW.sub("", text or "")
    t = t.replace("–", "-").replace("‑", "-").replace("‐", "-")
    for rx, rep in _DEFANG:
        t = rx.sub(rep, t)
    return t


# ---------------------------------------------------------------- patterns
_IPV4 = re.compile(r"(?<![\w.\-])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\w.]*\d)(?!\.\w)")
_IPV6 = re.compile(r"(?<![\w:.])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})(?![\w:])", re.I)
_HASH = re.compile(r"(?<![0-9a-zA-Z_])([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9a-zA-Z_])")
_CVE = re.compile(r"\bCVE[-–‑ ](\d{4})[-–‑ ](\d{4,7})\b", re.I)
_URL = re.compile(r"\b((?:https?|ftp)://[^\s<>\"'`\]\[{}|\\^]+)", re.I)
_DOMAIN = re.compile(r"(?<![\w@.\-/\\])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9\-]{2,59}|[a-z]{2,63}))(?![\w\-]|\.[a-z0-9])", re.I)
_EMAIL_DOMAIN = re.compile(r"[\w.+\-]+@((?:[a-z0-9\-]+\.)+[a-z]{2,63})", re.I)

# File extensions that are never TLDs, and ones that collide with real TLDs.
FILE_EXT = set("""exe dll sys drv ocx cpl scr com bat cmd ps1 psm1 psd1 vbs vbe js jse wsf wsh hta lnk msi msp mst jar class
py pyc pl rb sh bash zsh php asp aspx jsp cgi go rs c h cpp hpp cs java kt swift lua
doc docx docm dot dotm xls xlsx xlsm xlsb ppt pptx pptm pdf rtf odt txt csv log ini cfg conf config xml json yaml yml
zip rar 7z gz tgz bz2 xz tar iso img vhd vhdx cab arj lzh ace dmg pkg deb rpm apk ipa
png jpg jpeg gif bmp svg ico tif tiff webp mp3 mp4 mov avi mkv wav dat bin tmp bak db sqlite dmp elf so dylib ko
html htm css map md rst one onepkg chm inf reg evtx etl pcap pcapng eml msg""".split())

# Hosts that appear as links in reports but are not indicators: social share links, CDNs and
# asset hosts, standards bodies, reference databases, and the big platforms (as bare domains).
BENIGN = set("""twitter.com x.com t.co facebook.com fb.com linkedin.com lnkd.in instagram.com youtube.com youtu.be reddit.com
tiktok.com pinterest.com tumblr.com whatsapp.com telegram.me mastodon.social bsky.app threads.net medium.com
google.com googleapis.com gstatic.com googletagmanager.com google-analytics.com doubleclick.net googleusercontent.com
ggpht.com googlesyndication.com googleadservices.com recaptcha.net
cloudflare.com cloudflareinsights.com cdnjs.cloudflare.com jsdelivr.net unpkg.com akamaized.net akamaihd.net
fastly.net fastly.com cloudfront.net azureedge.net edgekey.net edgesuite.net bootstrapcdn.com jquery.com fontawesome.com
fonts.net typekit.net gravatar.com wp.com wordpress.com wordpress.org w.org s.w.org schema.org w3.org ogp.me
gmpg.org purl.org xmlns.com creativecommons.org
mitre.org attack.mitre.org cve.org cve.mitre.org nvd.nist.gov nist.gov first.org cisa.gov us-cert.gov ic3.gov
virustotal.com any.run hybrid-analysis.com urlscan.io shodan.io censys.io abuse.ch bazaar.abuse.ch malpedia.caad.fkie.fraunhofer.de
github.com githubusercontent.com raw.githubusercontent.com gist.github.com gitlab.com stackoverflow.com
microsoft.com msrc.microsoft.com learn.microsoft.com docs.microsoft.com support.microsoft.com apple.com support.apple.com
wikipedia.org archive.org web.archive.org bit.ly
hubspot.com hsforms.com hs-scripts.com hs-analytics.net marketo.com mktoresp.com pardot.com salesforce.com
addthis.com sharethis.com disqus.com feedburner.com feeds.feedburner.com vimeo.com
detection.fyi sigmasearchengine.com fofa.info zoomeye.org greynoise.io alienvault.com otx.alienvault.com threatfox.abuse.ch
urlhaus.abuse.ch python.org pypi.org npmjs.com nodejs.org socket.io mozilla.org apache.org w3schools.com
example.com example.org example.net localhost""".split())

# Words before a dotted number that make it a version, not an address.
_VERSION_CTX = re.compile(r"(?:\bv|\bver\.?|\bversions?|\brelease|\bbuild|\bupdate|\bpatch|\bfirmware|\bkb|\bsdk|\bfixed in|"
                          r"\bprior to|\bbefore|\bthrough|\bup to|\bupgrade to|\bos|\bios|\bandroid|"
                          r"\bchrome|\bfirefox|\bwindows|\bkernel|\bpython|\bjava|\bnode|\bphp|\bopenssl|\bapache|\bnginx|\b\w+/)\s*$", re.I)


# After a number: "8.0.5.2 and later", "8.0.5.2 or earlier", "8.0.5.2 build ..."
_VERSION_AFTER = re.compile(r"^\s*(?:and|or) (?:later|earlier|above|below|newer|older|prior)\b|^\s*(?:release|build|version)\b", re.I)
# Words that make a nearby address an indicator
_IP_CTX = re.compile(r"\b(?:c2|c&c|command and control|ip|ips|address(?:es)?|connect\w*|server|hosts?|beacon\w*|callback|"
                     r"resolv\w*|dns|infrastructure|contacted|communicat\w*)\b", re.I)
_IOC_SECTION = re.compile(r"\b(?:indicators? of compromise|iocs?)\b", re.I)


def _registered(host: str) -> str:
    """eTLD+1 using the cached Public Suffix List."""
    cat = catalog()
    parts = host.lower().strip(".").split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in cat.suffixes:
            return ".".join(parts[max(i - 1, 0):])
    return ".".join(parts[-2:])


def _benign_host(host: str, own: set[str]) -> bool:
    h = host.lower().strip(".")
    if h.startswith("www."):
        h = h[4:]
    reg = _registered(h)
    if h in BENIGN or reg in BENIGN or reg in own or h in own:
        return True
    labels = h.split(".")
    # asset hosts of any site: cdn., static., assets., img., fonts.
    if labels[0] in ("cdn", "static", "assets", "img", "images", "fonts", "media", "cdn1", "cdn2", "s", "js", "css") and len(labels) > 2:
        return True
    return False


def _valid_domain(d: str, defanged: bool) -> bool:
    cat = catalog()
    d = d.lower().strip(".")
    labels = d.split(".")
    if len(labels) < 2 or len(d) > 253:
        return False
    tld = labels[-1]
    if tld not in cat.tlds:
        return False
    if any(l.startswith("-") or l.endswith("-") for l in labels):
        return False
    if all(l.isdigit() for l in labels):
        return False
    if not defanged:
        if tld in FILE_EXT:                      # report.zip, script.py, README.md
            return False
        if any(l in FILE_EXT for l in labels[1:-1]):   # invoice.pdf.zip, a.exe.ru
            return False
        if len(labels) == 2 and len(labels[0]) == 1:   # e.g, i.e
            return False
        if d in cat.suffixes:                    # a bare public suffix like co.uk
            return False
    return True


def _clean_url(u: str) -> str:
    u = u.rstrip(".,;:!?'\"”’»")
    # unbalanced closing brackets belong to the sentence
    for o, c in (("(", ")"), ("[", "]"), ("{", "}")):
        while u.endswith(c) and u.count(c) > u.count(o):
            u = u[:-1].rstrip(".,;:!?")
    return u


def _norm_url(u: str) -> str:
    try:
        sp = urlsplit(u)
        host = (sp.hostname or "").lower()
        netloc = host + (f":{sp.port}" if sp.port else "")
        rest = u[len(sp.scheme) + 3 + len(sp.netloc):]
        return f"{sp.scheme.lower()}://{netloc}{rest}"
    except ValueError:
        return u


OVERLAY_NETS = [ipaddress.ip_network("200::/7")]   # Yggdrasil mesh addresses are not on the internet


def _public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    if ip.version == 6 and any(ip in n for n in OVERLAY_NETS):
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved
                or ip.is_link_local or (ip.version == 4 and str(ip).endswith(".255")))


def own_domains(url: str | None) -> set[str]:
    if not url:
        return set()
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return set()
    if not host:
        return set()
    reg = _registered(host)
    out = {host, reg}
    # vendors often host research on a sister domain sharing the brand label (unit42.paloaltonetworks.com /
    # paloaltonetworks.com, securelist.com is Kaspersky's but can't be inferred, so only the brand label)
    return out


def extract_iocs(text: str, url: str | None = None) -> dict[str, list[str]]:
    raw = text or ""
    t = refang(raw)
    own = own_domains(url)
    out: dict[str, list[str]] = {k: [] for k in ("ip", "domain", "url", "sha256", "sha1", "md5", "cve")}
    seen: dict[str, set] = {k: set() for k in out}

    def add(kind, v):
        if v not in seen[kind]:
            seen[kind].add(v)
            out[kind].append(v)

    # Strings that were defanged in the source are deliberate indicators.
    defanged = set()
    for frag in raw.split():
        if _DEFANG_MARK.search(frag):
            rf = refang(frag)
            for d in _DOMAIN.findall(rf):
                defanged.add(d.lower())
            for ip in _IPV4.findall(rf):
                defanged.add(ip)
            for u in _URL.findall(rf):
                nu = _norm_url(_clean_url(u))
                defanged.add(nu)
                try:
                    h = (urlsplit(nu).hostname or "").lower()
                except ValueError:
                    h = ""
                if h:
                    defanged.add(h)
                    if not _public_ip(h) and _valid_domain(h, True):
                        add("domain", h)          # the host of a defanged URL is an indicator too

    doc_ioc_ctx = bool(defanged) or bool(_IOC_SECTION.search(t))

    # URLs
    url_spans = []
    for m in _URL.finditer(t):
        u = _clean_url(m.group(1))
        nu = _norm_url(u)
        try:
            host = (urlsplit(nu).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        url_spans.append((m.start(), m.start() + len(u)))
        is_ip = _public_ip(host)
        if not is_ip and not _valid_domain(host, nu in defanged):
            continue
        if nu not in defanged and _benign_host(host, own):
            continue
        add("url", nu)

    # IPv4
    for m in _IPV4.finditer(t):
        ip = m.group(1)
        pre = t[max(0, m.start() - 24):m.start()]
        if _VERSION_CTX.search(pre) or _VERSION_AFTER.match(t[m.end():m.end() + 24]):
            continue
        if all(int(o) <= 31 for o in ip.split(".")) and not doc_ioc_ctx \
                and not _IP_CTX.search(t[max(0, m.start() - 80):m.end() + 80]):
            continue                              # small-octet dotted quads with no IOC context are versions
        if not _public_ip(ip):
            continue
        if re.match(r"/\d{1,2}\b", t[m.end():m.end() + 3]):
            continue                              # a CIDR block, not a host
        add("ip", ip)
    # IPv6
    for m in _IPV6.finditer(t):
        s = m.group(1)
        if s.count(":") < 2 or not re.search(r"[0-9a-f]{1,4}:[0-9a-f]{0,4}:", s, re.I):
            continue
        if re.fullmatch(r"[\d:]+", s) and s.count(":") <= 3:   # times like 12:30:45
            continue
        try:
            ip = ipaddress.IPv6Address(s)
        except ValueError:
            continue
        if ip.is_global and not ip.ipv4_mapped and _public_ip(str(ip)):
            if re.match(r"/\d{1,3}\b", t[m.end():m.end() + 4]):
                continue
            add("ip", str(ip))

    # domains (including URL hosts written in the text)
    for m in _DOMAIN.finditer(t):
        d = m.group(1).lower().rstrip(".")
        is_def = d in defanged
        orig = m.group(1)
        if not is_def and orig != orig.lower() and orig != orig.upper():
            continue                              # ASP.NET-like mixed case identifiers, Foo.Bar namespaces
        if not is_def and orig == orig.upper() and len(orig) < 12:
            continue                              # U.S, A.M style abbreviations
        if not _valid_domain(d, is_def):
            continue
        if not is_def and _benign_host(d, own):
            continue
        nxt = t[m.end():m.end() + 1]
        if not is_def and nxt in ("(", "=", "[", "{"):
            continue                              # code: subprocess.call(...), obj.attr = ...
        add("domain", d)
    # hashes
    for h in _HASH.findall(t):
        hl = h.lower()
        if len(set(hl)) < 6 or hl.isdigit() or re.fullmatch(r"[a-f]+", hl):
            continue
        add({32: "md5", 40: "sha1", 64: "sha256"}[len(hl)], hl)
    # CVEs
    for y, n in _CVE.findall(t):
        if 1999 <= int(y) <= 2100:
            add("cve", f"CVE-{y}-{n}")
    return out

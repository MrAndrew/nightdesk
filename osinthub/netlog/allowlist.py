"""Benign domains and infrastructure that reported IOCs are never matched against.

* Popular domains: the Tranco top list (top 20,000), downloaded once to <lake>/ref/tranco-top20k.csv
  when online and used offline afterwards, plus a built-in list (NTP pools, OS and browser update hosts,
  the entities package's benign link hosts).
* Benign infrastructure: public DNS resolvers and the big CDN, cloud and platform ASNs (via the
  existing DB-IP ASN lookup, so it works offline).

Docs: okf/data/netlog.md#reported-iocs
"""
from __future__ import annotations

import io
import ipaddress
import logging
import zipfile
from functools import lru_cache
from pathlib import Path

from .. import config

log = logging.getLogger("osinthub.netlog.allowlist")

TRANCO_URL = "https://tranco-list.eu/download/daily/top-1m.csv.zip"   # robots.txt allows /download/
TRANCO_LINE = 300                 # a line is `rank,domain`; a domain name is at most 253 characters
TRANCO_FILE = config.REF_DIR / "tranco-top20k.csv"
TRANCO_N = 20_000
BUILTIN_FILE = Path(__file__).parent / "fixtures" / "top-domains.txt"   # offline fallback shipped in the repo

BUILTIN_DOMAINS = set("""
pool.ntp.org ntp.org time.apple.com time.windows.com time.google.com time.cloudflare.com time.nist.gov ntp.ubuntu.com
time.facebook.com time.aws.com chrony.eu
dns.google one.one.one.one cloudflare-dns.com dns.quad9.net quad9.net opendns.com doh.opendns.com nextdns.io
windowsupdate.com update.microsoft.com msftconnecttest.com msftncsi.com delivery.mp.microsoft.com
apple.com icloud.com mzstatic.com push.apple.com captive.apple.com gsp-ssl.ls.apple.com
gstatic.com connectivitycheck.gstatic.com googleapis.com googlevideo.com ytimg.com ggpht.com
ubuntu.com canonical.com snapcraft.io debian.org fedoraproject.org archlinux.org
mozilla.org mozilla.net firefox.com digicert.com letsencrypt.org lencr.org sectigo.com globalsign.com
github.com githubusercontent.com github.io githubassets.com
akamai.net akamaiedge.net akamaihd.net akamaized.net edgekey.net edgesuite.net cloudfront.net fastly.net
fastlylb.net azureedge.net azurefd.net trafficmanager.net cloudapp.net amazonaws.com
nflxvideo.net nflxso.net nflximg.net netflix.com spotify.com scdn.co
""".split())

# Public resolvers (v4 and v6).
RESOLVERS = """8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220
94.140.14.14 94.140.15.15 76.76.2.0 76.76.10.0 185.228.168.9 64.6.64.6 64.6.65.6
2001:4860:4860::8888 2001:4860:4860::8844 2606:4700:4700::1111 2606:4700:4700::1001 2620:fe::fe 2620:fe::9
2620:119:35::35 2620:119:53::53""".split()

# Not documentation ranges: tests stand them in for public addresses.
_LOCAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                            "fc00::/7", "fe80::/10")]

# Big CDN, cloud and platform networks: a report naming one of their addresses is not, alone, enough.
BENIGN_ASNS = {
    "AS13335": "Cloudflare", "AS209242": "Cloudflare", "AS15169": "Google", "AS396982": "Google Cloud",
    "AS16509": "Amazon", "AS14618": "Amazon", "AS8075": "Microsoft", "AS8068": "Microsoft",
    "AS20940": "Akamai", "AS16625": "Akamai", "AS54113": "Fastly", "AS32934": "Meta", "AS714": "Apple",
    "AS6185": "Apple", "AS2906": "Netflix", "AS40027": "Netflix", "AS15133": "Edgio", "AS22822": "Edgio",
    "AS36459": "GitHub", "AS13414": "Twitter/X", "AS46489": "Twitch", "AS19551": "Incapsula",
    "AS60068": "CDN77", "AS3356": "Lumen", "AS6939": "Hurricane Electric",
}


def ensure_tranco(force: bool = False) -> dict:
    """Download the Tranco list once (online only) and keep the top 20k domains under ref/."""
    if TRANCO_FILE.exists() and not force:
        return {"ok": True, "path": str(TRANCO_FILE), "cached": True}
    if config.OFFLINE:
        return {"ok": False, "reason": "offline; using the built-in allowlist"}
    import httpx

    from ..sources import caps
    try:
        # the zip is read with the same byte cap as every source download (caps.CAPS["ref_tranco"]), and only the
        # first TRANCO_N lines of the list inside it are unpacked, each at most TRANCO_LINE characters
        with httpx.Client(headers={"User-Agent": config.USER_AGENT}, timeout=120) as client:
            r = caps.get_sync(client, TRANCO_URL, "ref_tranco")
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            name = zf.namelist()[0]
            with zf.open(name) as fh:
                text = io.TextIOWrapper(fh, encoding="utf-8")
                lines = []
                for _ in range(TRANCO_N):
                    line = text.readline(TRANCO_LINE)
                    if not line:
                        break
                    lines.append(line.strip())
        TRANCO_FILE.parent.mkdir(parents=True, exist_ok=True)
        part = TRANCO_FILE.with_suffix(".part")
        part.write_text("\n".join(lines) + "\n")
        part.replace(TRANCO_FILE)
        domains.cache_clear()
        return {"ok": True, "path": str(TRANCO_FILE), "domains": len(lines)}
    except Exception as e:
        log.warning("Tranco download failed: %s", e)
        return {"ok": False, "reason": f"{type(e).__name__}: {e}"[:200]}


@lru_cache(maxsize=1)
def domains() -> frozenset:
    out = set(BUILTIN_DOMAINS)
    try:
        from ..entities.iocs import BENIGN
        out |= {d.lower() for d in BENIGN}
    except Exception:
        pass
    out |= set(builtin_domains())
    if TRANCO_FILE.exists():
        for line in TRANCO_FILE.read_text().splitlines():
            d = line.split(",", 1)[-1].strip().lower()
            if d:
                out.add(d)
    return frozenset(out)


@lru_cache(maxsize=1)
def builtin_domains() -> tuple:
    try:
        return tuple(l.strip().lower() for l in BUILTIN_FILE.read_text().splitlines() if l.strip() and not l.startswith("#"))
    except OSError:
        return ()


def tranco_count() -> int:
    if not TRANCO_FILE.exists():
        return 0
    return sum(1 for _ in TRANCO_FILE.open())


def benign_domain(d: str) -> str | None:
    """The allowlisted domain covering d (d itself or a parent), else None."""
    d = d.lower().rstrip(".")
    labels = d.split(".")
    allow = domains()
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in allow:
            return cand
    return None


def benign_ip(ip: str) -> str | None:
    """Why an address is benign infrastructure ("resolver", "AS15169 Google", "private"), else None."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if str(a) in RESOLVERS:
        return "public resolver"
    if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or any(a in n for n in _LOCAL):
        return "private or special-purpose address"
    try:
        from .. import geo
        asn = geo.asn_for_ip(str(a))
    except Exception:
        asn = None
    if asn and asn[0] in BENIGN_ASNS:
        return f"{asn[0]} {BENIGN_ASNS[asn[0]]}"
    return None


def benign_cidr(cidr: str) -> str | None:
    try:
        n = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    if n.num_addresses > 65536:
        return "too broad for a reported indicator"
    return benign_ip(str(n.network_address))

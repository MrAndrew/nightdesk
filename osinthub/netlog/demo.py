"""Demo network logs: a day of an invented home network with planted contacts to indicators that are listed
*right now* in this lake, so the user can try import, devices, matching, alerts and the evidence chain without a
Zeek sensor, and see each feature produce what it should.

The demo home lives on its own prefixes (DEMO_PREFIXES, never used by real networks here) with locally
administered MACs and "demo-" hostnames, so its devices and alerts never mix with the user's own. Loading it
(`load`) imports one tar.gz bundle with origin "demo"; `verify` checks every planted scenario against the alert
it produced; `unload` removes the demo rows, matches, alerts, aggregates and stored files and puts the home
prefixes back. Reference: okf/data/netlog.md#demo-data.

    uv run python -m osinthub.netlog.demo --base http://127.0.0.1:8787 load|verify|unload|bundle OUT.tar.gz
"""
from __future__ import annotations

import datetime as dt
import io
import ipaddress
import json
import logging
import random
import tarfile
from pathlib import Path

from .. import db
from . import ipnum, util
from ..sources.base import key_steps

log = logging.getLogger(__name__)

STATE_KEY = "netlog_demo"
BUNDLE = "night-desk-demo"
DEMO_V4 = "10.86.24.0/24"
DEMO_V6 = "fd4e:6400:d35c::/48"
DEMO_PREFIXES = [DEMO_V4, DEMO_V6]
ROUTER = "10.86.24.1"
RESOLVER = "1.1.1.1"
FIXTURE = Path(__file__).parent / "fixtures" / "popular-sites.json"   # hand-made, documentation addresses

# name, IPv4, MAC (locally administered 02:4e:44 = "ND"), role
DEVICES = [
    ("demo-laptop", "10.86.24.21", "02:4e:44:00:00:21", "laptop"),
    ("demo-phone", "10.86.24.22", "02:4e:44:00:00:22", "phone"),
    ("demo-living-room-tv", "10.86.24.30", "02:4e:44:00:00:30", "tv"),
    ("demo-thermostat", "10.86.24.41", "02:4e:44:00:00:41", "iot"),
    ("demo-doorbell", "10.86.24.42", "02:4e:44:00:00:42", "iot"),
    ("demo-nas", "10.86.24.50", "02:4e:44:00:00:50", "nas"),
    ("demo-gaming-pc", "10.86.24.60", "02:4e:44:00:00:60", "pc"),
]
DEV = {d[0]: d for d in DEVICES}
SEV_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


def eui64(mac: str) -> str:
    """The SLAAC address a device with this MAC takes in the demo /64 (so devices can link IPv6 by MAC)."""
    b = [int(x, 16) for x in mac.split(":")]
    b[0] ^= 0x02
    iid = b[:3] + [0xFF, 0xFE] + b[3:]
    groups = [f"{iid[i] << 8 | iid[i + 1]:x}" for i in range(0, 8, 2)]
    return str(ipaddress.ip_address("fd4e:6400:d35c:1:" + ":".join(groups)))


# Every scenario the demo can plant: id -> (title, the list it needs, how many active entries it needs). A
# scenario whose list has no usable entry right now is left out, never faked; `skipped` says why and what to do.
SCENARIOS = {
    "feodo_c2": ("The TV calling a botnet controller", "feodo_c2", 1),
    "feodo_retro": ("Contact before the listing, inside the provider's active period", "feodo_c2", 1),
    "drop_cidr": ("Connection into a hijacked network on Spamhaus DROP", "spamhaus_drop", 1),
    "et_compromised": ("IoT device talking to a known-compromised host", "et_compromised", 1),
    "attacker_accepted": ("Attacker's SSH session to the NAS was accepted", "blocklist_de", 1),
    "scanner_probe": ("Internet scanner probes, unanswered", "dshield_top", 1),
    "cins_inbound": ("Bad-reputation host knocks on the doorbell camera", "cins_army", 1),
    "p2p_cap": ("Torrent peer on a blocklist, lowered by the P2P cap", "cins_army", 2),
    "tor_exit": ("Tor in use on the gaming PC", "tor_exits", 1),
    "reported_ip": ("Address named in the news as a sign of attack", "reported", 1),
    "reported_domain": ("Phone looked up a domain from a threat report", "reported", 1),
    "sslbl_cert": ("A botnet controller's certificate seen in a secure connection", "sslbl", 1),
    "kev_notice": ("Known-exploited vulnerability on the NAS", "cisa_kev", 1),
    "suricata_alert": ("Suricata alert from the doorbell camera", "suricata", 0),
    "historical": ("Contact after the address left its list", "history", 0),
}


def _skip_reason(sid: str, source: str, need: int) -> dict:
    """Why a scenario could not be planted, in plain words, with the fix: {reason, fix, cause, list, action}.
    cause groups scenarios with the same cause (several lists never downloaded); action is a hint for the UI:
    'sources' (turn a feed on, or wait for it there), 'key', 'news', 'wait' or None."""
    from .. import config
    from ..sources import SOURCES
    if sid == "feodo_retro":
        return {"reason": "None of the botnet controllers listed right now has provider dates that allow a "
                          "contact before its listing.", "fix": "Try loading the demo again another day.",
                "cause": "retro", "list": None, "action": None}
    if source == "history":
        return {"reason": "No address has dropped off a threat list yet.",
                "fix": "This appears once the lists have refreshed a few times (a day or so).",
                "cause": "history", "list": None, "action": "wait"}
    if source == "reported":
        return {"reason": "No address or domain has been named as a sign of attack in a news story yet.",
                "fix": "These come from the security news; reload the demo once News has stories.",
                "cause": "news", "list": None, "action": "news"}
    src = SOURCES.get(source)
    name = src.name if src else source
    st = (db.query("SELECT * FROM source_state WHERE id = ?", [source]) or [{}])[0]
    enabled = (src.default_enabled if src else False) if st.get("enabled") is None else bool(st["enabled"])
    base = {"list": name, "source": source}
    if src is not None and src.unavailable():
        key = src.needs_key or "an API key"
        what = "the abuse.ch key" if "ABUSECH" in key.upper() else "its API key"
        # plain language in the text; the setting's name only in `tech` (a hover title)
        return {**base, "reason": f"{name} needs {what}.", "fix": f"Get {what}, {key_steps()}, and turn it on in Sources.",
                "tech": f"The setting is {key}.", "cause": "key", "action": "key"}
    if not enabled:
        return {**base, "reason": f"{name} is off.", "cause": "off", "action": "sources",
                "fix": "Turn it on in Sources, wait for its first download, then reload the demo."}
    if not st.get("last_ok"):
        if config.OFFLINE:
            return {**base, "reason": f"{name} has never been downloaded, and fetching is off (offline mode).",
                    "fix": "Restart Night Desk with offline mode turned off so the lists can download.", "cause": "offline", "action": None}
        return {**base, "reason": f"{name} has not finished its first download yet.", "cause": "first", "action": "sources",
                "fix": "Wait a few minutes (or use Run now in Sources), then reload the demo."}
    return {**base, "reason": f"{name} has {'fewer than two' if need > 1 else 'no'} usable entries listed right now.",
            "fix": "Try again after its next update.", "cause": "empty", "action": None}


def skipped(plan: list[dict]) -> list[dict]:
    """The scenarios that are not in the plan, each with its reason and fix. A scenario that depends on another
    one that was left out (the retro match needs the botnet controller) gives that one's reason."""
    have = {p["id"] for p in plan}
    out = []
    for sid, (title, src, need) in SCENARIOS.items():
        if sid in have:
            continue
        r = _skip_reason("feodo_c2" if sid == "feodo_retro" and "feodo_c2" not in have else sid, src, need)
        out.append({"id": sid, "title": title, "source": src, **r})
    return out


# ------------------------------------------------------------------ choosing real indicators
def _active(source: str, kind: str = "ip", rnd: random.Random | None = None, where: str = "", n: int = 1) -> list[dict]:
    rows = db.query(f"""SELECT source, kind, value, key, category, "start", meta FROM indicator_intervals
                        WHERE source = ? AND kind = ? AND "end" IS NULL {where}
                        ORDER BY value LIMIT 400""", [source, kind])
    if not rows:
        return []
    rnd = rnd or random.Random(0)
    pick = rnd.sample(rows, min(n, len(rows)))
    for r in pick:
        r["meta"] = json.loads(r["meta"] or "{}") if isinstance(r["meta"], str) else (r["meta"] or {})
    return pick


def popular_domains() -> list[dict]:
    """The well-known sites the demo devices browse: a short hand-made list whose addresses are documentation
    addresses (198.51.100.100-185, 203.0.113.100-185, 2001:db8:5000::/40), so the demo runs offline and ships no
    third-party ranking. They sit outside the home prefixes, so they read as remote sites."""
    return [d for d in json.loads(FIXTURE.read_text())["domains"] if d.get("a")]


def _when(rnd: random.Random, now: dt.datetime, start: dt.datetime | None, lo_h: float = 1.0, hi_h: float = 20.0) -> float:
    """An epoch time in the last day, at least 10 minutes after the listing started and before now."""
    floor = (start + dt.timedelta(minutes=10)) if start else now - dt.timedelta(hours=hi_h)
    t = now - dt.timedelta(hours=rnd.uniform(lo_h, hi_h))
    if t < floor:
        t = floor + (now - floor) * rnd.uniform(.2, .6)
    return min(t, now - dt.timedelta(minutes=5)).timestamp()


def _host_in(cidr: str, rnd: random.Random) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses <= 2:
        return str(net.network_address)
    return str(net.network_address + rnd.randint(1, min(net.num_addresses - 2, 250)))


def _rules():
    from .matcher import RULES
    return RULES


# ------------------------------------------------------------------ building the logs
class _Logs:
    def __init__(self) -> None:
        self.files: dict[str, list[dict]] = {k: [] for k in ("conn", "dns", "ssl", "http", "files", "dhcp", "notice", "eve")}
        self.n = 0

    def uid(self, planted: bool) -> str:
        self.n += 1
        return f"{'CND' if planted else 'CNB'}{self.n:08d}"

    def conn(self, ts: float, src: str, sp: int, dst: str, dp: int, *, proto="tcp", service=None, state="SF",
             dur=1.2, ob=900, rb=4200, mac=None, planted=False, uid=None) -> str:
        u = uid or self.uid(planted)
        r = {"ts": round(ts, 6), "uid": u, "id.orig_h": src, "id.orig_p": sp, "id.resp_h": dst, "id.resp_p": dp,
             "proto": proto, "duration": dur, "orig_bytes": ob, "resp_bytes": rb, "conn_state": state,
             "history": {"SF": "ShADadFf", "S0": "S", "REJ": "Sr"}.get(state, "ShAD"), "orig_pkts": max(1, ob // 500),
             "resp_pkts": 0 if state in ("S0", "REJ") else max(1, rb // 1200), "_path": "conn"}
        if service:
            r["service"] = service
        if mac:
            r["orig_l2_addr"] = mac
        self.files["conn"].append(r)
        return u

    def dns(self, ts: float, src: str, name: str, answers: list[str], planted=False) -> str:
        u = self.uid(planted)
        self.files["dns"].append({"ts": round(ts, 6), "uid": u, "id.orig_h": src, "id.orig_p": random.randint(1024, 65535),
                                  "id.resp_h": RESOLVER, "id.resp_p": 53, "proto": "udp", "trans_id": self.n % 65535,
                                  "query": name, "qtype_name": "AAAA" if answers and ":" in answers[0] else "A",
                                  "rcode_name": "NOERROR", "answers": answers, "TTLs": [300.0] * len(answers), "_path": "dns"})
        return u


def build(now: dt.datetime | None = None, seed: int = 11) -> tuple[dict[str, bytes], list[dict]]:
    """(log files by name, plan). Each plan item is one planted scenario with what it should produce."""
    now = now or util.now()
    rnd = random.Random(seed)
    L = _Logs()
    RULES = _rules()
    plan: list[dict] = []
    t0 = (now - dt.timedelta(hours=24)).timestamp()

    def item(sid, title, story, device, source, indicator, uids, severity, rule=None, rule_suffix=None, feature="", entity=None):
        plan.append({"id": sid, "title": title, "story": story, "device": device, "source": source,
                     "indicator": indicator, "uids": uids, "expect": {"severity": severity, "rule": rule,
                     "rule_suffix": rule_suffix}, "feature": feature, "entity": entity})

    # --- devices: DHCP leases (identity by MAC, with hostnames) and the laptop's IPv6 address
    for name, ip4, mac, _ in DEVICES:
        L.files["dhcp"].append({"ts": t0 + rnd.uniform(0, 300), "uids": [L.uid(False)], "client_addr": ip4,
                                "server_addr": ROUTER, "mac": mac, "host_name": name, "assigned_addr": ip4,
                                "lease_time": 86400.0, "msg_types": ["REQUEST", "ACK"], "_path": "dhcp"})
    lap6 = eui64(DEV["demo-laptop"][2])

    # --- ordinary traffic: DNS and TLS to popular sites (frozen addresses, so it runs offline)
    doms = popular_domains()
    for name, ip4, mac, role in DEVICES:
        fav = rnd.sample(doms, 25)
        for _ in range({"laptop": 160, "phone": 140, "pc": 120, "tv": 80, "nas": 50}.get(role, 30)):
            d = rnd.choice(fav)
            ts = t0 + rnd.uniform(600, 86000)
            v6 = name == "demo-laptop" and d["aaaa"] and rnd.random() < .35
            dst = rnd.choice(d["aaaa"] if v6 else d["a"])
            host = d["domain"] if rnd.random() < .5 else "www." + d["domain"]
            L.dns(ts, ip4, host, d["aaaa"][:1] if v6 else d["a"][:2])
            src = lap6 if v6 else ip4
            u = L.conn(ts + .05, src, rnd.randint(49152, 65535), dst, 443, service="ssl", dur=rnd.uniform(.3, 40),
                       ob=rnd.randint(600, 9000), rb=rnd.randint(2000, 400000), mac=mac)
            L.files["ssl"].append({"ts": ts + .06, "uid": u, "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst,
                                   "id.resp_p": 443, "version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256",
                                   "server_name": host, "established": True, "_path": "ssl"})
        for k in range(24):   # NTP and the router
            L.conn(t0 + k * 3600 + rnd.uniform(0, 60), ip4, 123, "162.159.200.1", 123, proto="udp", service="ntp",
                   dur=.02, ob=48, rb=48, mac=mac)

    tv, lap, nas, pc = DEV["demo-living-room-tv"][1], DEV["demo-laptop"][1], DEV["demo-nas"][1], DEV["demo-gaming-pc"][1]

    # 1. Feodo C2: the TV beacons to a botnet controller every 30 minutes, after looking up a name for it
    for f in _active("feodo_c2", rnd=rnd):
        port = int(f["meta"].get("port") or (f["key"].rsplit(":", 1)[-1] if ":" in f["key"] else 443))
        start = _when(rnd, now, f["start"], 6, 9)
        uids = [L.dns(start - 1, tv, "cdn-tvfirmware-update.example", [f["value"]], planted=True)]
        for k in range(6):
            uids.append(L.conn(start + k * 1800 + rnd.uniform(-20, 20), tv, rnd.randint(40000, 60000), f["value"], port,
                               service="ssl", dur=4.1, ob=1400, rb=3100, mac=DEV["demo-living-room-tv"][2], planted=True))
        mal = f["meta"].get("malware")
        item("feodo_c2", "The TV calling a botnet controller",
             f"The living-room TV looked up a firmware-looking name that resolved to {f['value']}, then connected to it "
             f"every 30 minutes. Feodo Tracker lists that address as a {mal or 'botnet'} controller.",
             "demo-living-room-tv", "feodo_c2", f["value"], uids, "high", RULES[("c2", "outbound")][0],
             feature="List match (outbound, high); DNS lookup and connection merged into one alert", entity=mal)
        # 1b. the same controller, contacted months ago while the provider says it was active: a retro match
        fs, lo = f["meta"].get("first_seen"), f["meta"].get("last_online")
        try:
            a = dt.datetime.fromisoformat(str(fs)).replace(tzinfo=dt.UTC)
            b = min(dt.datetime.fromisoformat(str(lo)[:10]).replace(tzinfo=dt.UTC) + dt.timedelta(days=1), f["start"])
        except (TypeError, ValueError):
            a = b = None
        if a and b and b - a > dt.timedelta(days=2):
            ts = (a + (b - a) / 2).timestamp()
            u = L.conn(ts, DEV["demo-thermostat"][1], 51000, f["value"], port, service="ssl", dur=3, ob=900, rb=2000,
                       mac=DEV["demo-thermostat"][2], planted=True)
            item("feodo_retro", "Contact before the listing, inside the provider's active period",
                 f"The thermostat reached {f['value']} on {dt.datetime.fromtimestamp(ts, dt.UTC):%Y-%m-%d}, before "
                 "Night Desk listed it but while Feodo Tracker says it was active.",
                 "demo-thermostat", "feodo_c2", f["value"], [u], "low", "c2_retro", feature="Found with the provider's own dates, before our copy listed it")

    # 2. Spamhaus DROP: the laptop talks to an address inside a hijacked netblock
    for d in _active("spamhaus_drop", "cidr", rnd):
        ip = _host_in(d["value"], rnd)
        u = L.conn(_when(rnd, now, d["start"]), lap, 52811, ip, 443, service="ssl", dur=12, ob=5200, rb=88000,
                   mac=DEV["demo-laptop"][2], planted=True)
        item("drop_cidr", "Connection into a hijacked network on Spamhaus DROP",
             f"The laptop connected to {ip}, which is inside {d['value']} on Spamhaus DROP (a range run by criminals).",
             "demo-laptop", "spamhaus_drop", d["value"], [u], "high", RULES[("drop", "outbound")][0],
             feature="Address inside a listed range")

    # 3. ET compromised host: the thermostat calls home to it
    for d in _active("et_compromised", rnd=rnd):
        u = L.conn(_when(rnd, now, d["start"]), DEV["demo-thermostat"][1], 41522, d["value"], 443, service="ssl",
                   dur=2, ob=700, rb=1900, mac=DEV["demo-thermostat"][2], planted=True)
        item("et_compromised", "IoT device talking to a known-compromised host",
             f"The thermostat connected to {d['value']}, on the Emerging Threats compromised-hosts list.",
             "demo-thermostat", "et_compromised", d["value"], [u], RULES[("compromised", "outbound")][1],
             RULES[("compromised", "outbound")][0], feature="List match (outbound, medium)")

    # 4. blocklist.de attacker logs in to the NAS over SSH and moves data: accepted inbound escalates
    for d in _active("blocklist_de", rnd=rnd):
        u = L.conn(_when(rnd, now, d["start"]), d["value"], 50322, nas, 22, service="ssh", dur=740, ob=1_600_000,
                   rb=1_300_000, planted=True)
        item("attacker_accepted", "Attacker's SSH session to the NAS was accepted",
             f"{d['value']} (blocklist.de: brute-force attacker) connected to the NAS on port 22 and the session ran "
             "12 minutes with over 1 MB each way.",
             "demo-nas", "blocklist_de", d["value"], [u], "medium", rule_suffix="_inbound_accepted",
             feature="Inbound escalation: an accepted session with significant data")

    # 5. DShield scanner probes that went unanswered: info
    for d in _active("dshield_top", rnd=rnd):
        base = _when(rnd, now, d["start"])
        uids = [L.conn(base + k * 7, d["value"], 40000 + k, ip4, p, state="S0", dur=0, ob=0, rb=0, planted=True)
                for k, (p, ip4) in enumerate([(23, nas), (445, nas), (3389, pc)])]
        item("scanner_probe", "Internet scanner probes, unanswered",
             f"{d['value']} (DShield top scanner) probed telnet, SMB and RDP. Nothing answered.",
             None, "dshield_top", d["value"], uids, RULES[("scanner", "inbound")][1], RULES[("scanner", "inbound")][0],
             feature="Inbound noise stays info; one alert per scanner per day")

    # 6. CINS reputation: refused inbound probe, low
    cins = _active("cins_army", rnd=rnd, n=2)
    if cins:
        d = cins[0]
        u = L.conn(_when(rnd, now, d["start"]), d["value"], 61000, DEV["demo-doorbell"][1], 8080, state="REJ",
                   dur=0, ob=0, rb=0, planted=True)
        item("cins_inbound", "Bad-reputation host knocks on the doorbell camera",
             f"{d['value']} (CINS Army) tried port 8080 on the doorbell and was refused.",
             None, "cins_army", d["value"], [u], RULES[("reputation", "inbound")][1], RULES[("reputation", "inbound")][0],
             feature="List match (inbound, low)")

    # 7. P2P swarm: the NAS seeds a torrent; one peer is on CINS. The cap lowers it to low.
    if len(cins) > 1:
        d = cins[1]
        base = _when(rnd, now, d["start"], 2, 6)
        peers = [f"198.51.100.{10 + k}" for k in range(18)] + [d["value"]]
        uids = []
        for k, p in enumerate(peers):
            u = L.conn(base + k * 90, nas, 51413, p, rnd.randint(20000, 60000), proto="udp", dur=30, ob=40000,
                       rb=900000, mac=DEV["demo-nas"][2], planted=p == d["value"])
            if p == d["value"]:
                uids.append(u)
        item("p2p_cap", "Torrent peer on a blocklist, lowered by the P2P cap",
             f"The NAS swapped data with 19 peers high port to high port within the hour. One, {d['value']}, is on "
             "CINS Army. Residential peers on blocklists are expected in a swarm, so the alert is lowered to low.",
             "demo-nas", "cins_army", d["value"], uids, "low", rule_suffix="_p2p", feature="Lowered for file-sharing swarms")

    # 8. Tor exit: the gaming PC uses Tor
    for d in _active("tor_exits", rnd=rnd):
        u = L.conn(_when(rnd, now, d["start"]), pc, 50777, d["value"], 9001, dur=900, ob=80000, rb=2_400_000,
                   mac=DEV["demo-gaming-pc"][2], planted=True)
        item("tor_exit", "Tor in use on the gaming PC",
             f"The gaming PC held a 15-minute connection to {d['value']}, a Tor exit relay.",
             "demo-gaming-pc", "tor_exits", d["value"], [u], RULES[("tor", "outbound")][1], RULES[("tor", "outbound")][0],
             feature="Tor list (low)")

    # 9. An address named as an IOC in the news
    rep = (_active("reported", rnd=rnd, where="AND category = 'reported_corroborated'")
           or _active("reported", rnd=rnd, where="AND category = 'reported'"))
    for d in rep:
        u = L.conn(_when(rnd, now, d["start"]), lap, 53990, d["value"], 443, service="ssl", dur=6, ob=2100, rb=30000,
                   mac=DEV["demo-laptop"][2], planted=True)
        src = ", ".join(d["meta"].get("sources") or []) or "a security news story"
        item("reported_ip", "Address named in the news as a sign of attack",
             f"The laptop connected to {d['value']}, listed as an indicator of compromise by {src}.",
             "demo-laptop", "reported", d["value"], [u], RULES[(d["category"], "outbound")][1],
             RULES[(d["category"], "outbound")][0], feature="Addresses named in the news, linked to the story")

    # 10. A domain named as an IOC in the news: the phone looks it up
    repd = (_active("reported", "domain", rnd, "AND category = 'reported_corroborated'")
            or _active("reported", "domain", rnd, "AND category = 'reported'"))
    for d in repd:
        u = L.dns(_when(rnd, now, d["start"]), DEV["demo-phone"][1], "login." + d["value"], ["203.0.113.80"], planted=True)
        item("reported_domain", "Phone looked up a domain from a threat report",
             f"The phone looked up login.{d['value']}. Its parent domain {d['value']} was published as a sign of attack.",
             "demo-phone", "reported", d["value"], [u], RULES[(d["category"], "dns")][1], RULES[(d["category"], "dns")][0],
             feature="Domain match on a subdomain, DNS intent")

    # 11. SSL Blacklist: the laptop received a botnet C2 certificate
    for d in _active("sslbl", "hash", rnd):
        ip = "198.51.100.200"
        cu = L.conn(_when(rnd, now, d["start"]), lap, 54100, ip, 443, service="ssl", dur=3, ob=800, rb=5000,
                    mac=DEV["demo-laptop"][2], planted=True)
        ts = [r for r in L.files["conn"] if r["uid"] == cu][0]["ts"]
        fu = "FND" + cu[3:]
        L.files["files"].append({"ts": ts + .2, "fuid": fu, "uid": cu, "tx_hosts": [ip], "rx_hosts": [lap],
                                 "conn_uids": [cu], "source": "SSL", "depth": 0, "analyzers": ["X509", "SHA1", "MD5"],
                                 "mime_type": "application/x-x509-user-cert", "seen_bytes": 1012, "sha1": d["value"],
                                 "_path": "files"})
        mal = d["meta"].get("malware")
        item("sslbl_cert", "A botnet controller's certificate seen in a secure connection",
             f"The laptop's TLS session to {ip} presented a certificate whose SHA1 is on abuse.ch SSL Blacklist "
             f"({mal or 'C2'}).", "demo-laptop", "sslbl", d["value"], [cu], "high",
             feature="Certificate fingerprint match", entity=mal)

    # 12. CISA KEV: the NAS runs software with a known-exploited CVE (a notice names it)
    for d in _active("cisa_kev", "cve", rnd):
        u = L.uid(True)
        L.files["notice"].append({"ts": _when(rnd, now, d["start"]), "uid": u, "id.orig_h": nas, "id.orig_p": 445,
                                  "id.resp_h": ROUTER, "id.resp_p": 50001, "src": nas, "dst": ROUTER,
                                  "note": "Software::Vulnerable_Version",
                                  "msg": f"demo-nas is running a version vulnerable to {d['value']}", "_path": "notice"})
        item("kev_notice", "Known-exploited vulnerability on the NAS",
             f"A Zeek notice says the NAS runs software vulnerable to {d['value']}, which CISA lists as exploited in the wild.",
             "demo-nas", "cisa_kev", d["value"], [u], "low", RULES[("kev", "outbound")][0],
             feature="CVE in a notice, linked to its EPSS score", entity=d["value"])

    # 13. Suricata EVE alert from the doorbell (no list needed: the IDS said so)
    ts = _when(rnd, now, None, 1, 8)
    fid = 9_100_000_000_000 + rnd.randint(0, 999_999)
    L.files["eve"].append({"timestamp": dt.datetime.fromtimestamp(ts, dt.UTC).isoformat(), "flow_id": fid,
                           "event_type": "alert", "src_ip": DEV["demo-doorbell"][1], "src_port": 49822,
                           "dest_ip": "203.0.113.45", "dest_port": 80, "proto": "TCP", "direction": "to_server",
                           "alert": {"action": "allowed", "gid": 1, "signature_id": 2099001, "rev": 1,
                                     "signature": "DEMO Night Desk IoT camera beaconing to unknown C2", "category":
                                     "A Network Trojan was detected", "severity": 1},
                           "app_proto": "http"})
    item("suricata_alert", "Suricata alert from the doorbell camera",
         "Suricata flagged the doorbell's HTTP traffic with a severity-1 signature.", "demo-doorbell", "suricata",
         "2099001", [str(fid)], "high", "ids_signature", feature="IDS alerts (Suricata EVE)")

    # 14. Historical: contact with an address after it left its list
    hist = db.query("""SELECT i.source, i.value, i."end" FROM indicator_intervals i
                       WHERE i.kind = 'ip' AND i."end" IS NOT NULL AND i."end" < now() - INTERVAL 3 HOUR
                         AND i.source IN ('dshield_top', 'blocklist_de', 'cins_army', 'et_compromised', 'tor_exits')
                         AND NOT EXISTS (SELECT 1 FROM indicator_intervals j WHERE j.value = i.value
                                         AND (j."end" IS NULL OR j."end" > i."end"))
                       ORDER BY i."end" DESC LIMIT 1""")
    for h in hist:
        ts = min(h["end"] + dt.timedelta(hours=1), now - dt.timedelta(minutes=20)).timestamp()
        u = L.conn(ts, pc, 51999, h["value"], 443, service="ssl", dur=2, ob=600, rb=1500, mac=DEV["demo-gaming-pc"][2],
                   planted=True)
        item("historical", "Contact after the address left its list",
             f"The gaming PC reached {h['value']} an hour after {h['source']} dropped it. That is kept as history (info), "
             "not raised as a threat.", "demo-gaming-pc", h["source"], h["value"], [u], "info", "historical",
             feature="Time-aware matching: listings have a start and an end")

    files = {}
    names = {"eve": "eve.json"}
    for k, rows in L.files.items():
        if rows:
            rows.sort(key=lambda r: r.get("ts") or r.get("timestamp"))
            files[names.get(k, f"{k}.log")] = ("\n".join(json.dumps(r) for r in rows) + "\n").encode()
    return files, plan


def bundle(files: dict[str, bytes], plan: list[dict]) -> bytes:
    """A tar.gz of the logs plus README.txt (members starting with "." are skipped by the importer)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        readme = README.format(v4=DEMO_V4, v6=DEMO_V6, n=len(plan)).encode()
        for name, data in [*sorted(files.items()), (".README.txt", readme), (".plan.json", json.dumps(plan, indent=1, default=str).encode())]:
            ti = tarfile.TarInfo(f"{BUNDLE}/{name}")
            ti.size, ti.mtime = len(data), int(util.now().timestamp())
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


README = """Night Desk demo logs

A day of an invented home network on {v4} and {v6}, in Zeek JSON (plus one Suricata EVE alert),
with {n} planted contacts to indicators that were listed in this Night Desk when the bundle was made.
.plan.json says what each one should produce.

Easiest: Network > Import > Demo data > Load demo. It sets things up, checks every scenario and can remove it all.
If you import this file by hand instead, add {v4} and {v6} to the home prefixes first.
"""


# ------------------------------------------------------------------ load, verify, unload
def state() -> dict | None:
    return db.get_setting(STATE_KEY)


def _demo_files(cur=None) -> list[dict]:
    sql = "SELECT id, name, path FROM netlog_files WHERE origin = 'demo' OR name LIKE ?"
    return util.rows_of(cur, sql, [BUNDLE + "%"]) if cur is not None else db.query(sql, [BUNDLE + "%"])


def load(seed: int | None = None) -> dict:
    """Generate the demo from today's indicators and import it. Refused while a demo is loaded."""
    from . import importer, intervals
    with util.LOCK:
        if state() or _demo_files():
            raise ValueError("demo data is already loaded; remove it first")
        intervals.refresh()   # choose from the lists as they are now
        files, plan = build(seed=seed if seed is not None else random.randint(1, 10_000))
        s = util.settings()
        added = []
        if s.get("home_prefixes"):   # explicit prefixes: add the demo's (auto mode already covers private ranges)
            added = [p for p in DEMO_PREFIXES if p not in s["home_prefixes"]]
            if added:
                s["home_prefixes"] = util.unique_prefixes(s["home_prefixes"] + added)
                util.save_settings(s)
        db.set_setting(STATE_KEY, {"loaded_at": util.now().isoformat(), "prefixes_added": added, "plan": plan,
                                   "skipped": skipped(plan), "status": "loading"})
        try:
            res = importer.import_any(io.BytesIO(bundle(files, plan)), f"{BUNDLE}.tar.gz", origin="demo")
        except Exception:
            unload()
            raise
        st = state() or {}
        st.update({"status": "loaded", "files": [m.get("file_id") for m in res.get("members", [])],
                   "rows": res.get("rows"), "import_errors": res.get("warnings")})
        db.set_setting(STATE_KEY, st)
    return {"import": {k: res.get(k) for k in ("rows", "inserted", "log_types", "warnings")}, **verify()}


def verify() -> dict:
    """Check each planted scenario against the alert that holds its rows."""
    st = state()
    if not st:
        return {"loaded": False, "scenarios": []}
    files = [f["id"] for f in _demo_files()]
    out = []
    for p in st.get("plan", []):
        hits = db.query("""SELECT DISTINCT a.id, a.rule, a.severity, a.title, a.source, a.status
                           FROM netlog_matches m JOIN alerts a ON a.id = m.alert_id
                           WHERE m.uid IN (SELECT unnest(?::VARCHAR[])) AND (m.source = ? OR a.source = ?)
                           ORDER BY a.severity""", [p["uids"], p["source"], p["source"]])
        e = p["expect"]
        best = max(hits, key=lambda h: SEV_RANK.get(h["severity"], -1)) if hits else None
        ok, why = False, "no alert"
        if best:
            ok = best["severity"] == e["severity"]
            why = f"severity {best['severity']}, expected {e['severity']}"
            if ok and e.get("rule") and best["rule"] != e["rule"]:
                ok, why = False, f"rule {best['rule']}, expected {e['rule']}"
            if ok and e.get("rule_suffix") and not str(best["rule"]).endswith(e["rule_suffix"]):
                ok, why = False, f"rule {best['rule']}, expected one ending {e['rule_suffix']}"
            if ok:
                why = "as expected"
        out.append({**{k: p[k] for k in ("id", "title", "story", "device", "source", "indicator", "feature", "entity")},
                    "expect": e, "ok": ok, "why": why,
                    "alert": {k: best[k] for k in ("id", "rule", "severity", "title", "status")} if best else None})
    # false positives: high or medium alerts that hold only ordinary demo rows
    fp = db.query("""SELECT DISTINCT a.id, a.rule, a.severity, a.title FROM netlog_matches m JOIN alerts a ON a.id = m.alert_id
                     WHERE m.rk IN (SELECT rk FROM netlog WHERE file_id IN (SELECT unnest(?::VARCHAR[])))
                       AND a.severity IN ('high', 'medium')
                       AND NOT EXISTS (SELECT 1 FROM netlog_matches m2 WHERE m2.alert_id = a.id AND m2.uid LIKE 'CND%')
                       AND NOT EXISTS (SELECT 1 FROM netlog_matches m3 WHERE m3.alert_id = a.id
                                       AND m3.rk IN (SELECT rk FROM netlog WHERE log_type LIKE 'eve_%'))""", [files])
    devices = db.query("""SELECT id, hostnames, ips, confidence FROM devices
                          WHERE list_has_any(hostnames, ?::VARCHAR[])""", [[d[0] for d in DEVICES]])
    return {"loaded": True, "loaded_at": st.get("loaded_at"), "status": st.get("status"), "prefixes": DEMO_PREFIXES,
            "prefixes_added": st.get("prefixes_added", []), "files": len(files), "rows": st.get("rows"),
            "passed": sum(1 for o in out if o["ok"]), "total": len(out), "scenarios": out,
            "possible": len(SCENARIOS), "skipped": st.get("skipped", []),
            "top_alert": _top_alert(out), "your_changes": your_changes(),
            "false_positives": util.jsonable(fp), "devices": {"found": len(devices), "expected": len(DEVICES)}}


def _top_alert(out: list[dict]) -> str | None:
    """The alert to land on after loading: the most severe one a passing scenario produced (the planted botnet
    beacon on a full lake, the doorbell's IDS alert on an empty one)."""
    best = max((o for o in out if o.get("alert")), default=None,
               key=lambda o: (o["ok"], SEV_RANK.get(o["alert"]["severity"], -1), o["id"] == "feodo_c2"))
    return best["alert"]["id"] if best else None


DEMO_MACS = {d[2] for d in DEVICES}


def _in_demo(ip: str) -> bool:
    n = ipnum.ip_int(ip)
    if n is None:
        return False
    for p in DEMO_PREFIXES:
        r = ipnum.net_range(p)
        if r and r[0] <= n <= r[1]:
            return True
    return False


def is_demo_device(did: str | None) -> bool:
    """A device id (mac:<mac> or ip:<ip>) of the demo's invented home: one of its MACs, or an address on its prefixes."""
    if not did or ":" not in did:
        return False
    kind, val = did.split(":", 1)
    if kind == "mac":
        return val.lower() in DEMO_MACS
    return kind == "ip" and _in_demo(val)


def _indicator_is_real(cur, value: str) -> bool:
    """The indicator appears in something that is not the demo: a non-demo alert, a list entry (any threat list or
    your own lists) or a log row from a non-demo file."""
    v = str(value)
    if cur.execute("SELECT 1 FROM alerts WHERE indicator = ? AND NOT coalesce(demo, false) LIMIT 1", [v]).fetchone():
        return True
    if cur.execute("SELECT 1 FROM indicator_intervals WHERE value = ? OR lower(value) = lower(?) LIMIT 1", [v, v]).fetchone():
        return True
    return bool(cur.execute("""SELECT 1 FROM netlog n JOIN netlog_files f ON f.id = n.file_id
                               WHERE coalesce(f.origin, '') <> 'demo'
                                 AND (n.orig_h = ? OR n.resp_h = ? OR lower(n.query) = lower(?) OR lower(n.server_name) = lower(?)
                                      OR lower(n.host) = lower(?))
                               LIMIT 1""", [v] * 5).fetchone())


def _rule_text(r: dict, names: dict) -> str:
    parts = []
    if r.get("device"):
        parts.append(names.get(r["device"]) or r["device"])
    if r.get("indicator"):
        parts.append(r["indicator"])
    if r.get("kind"):
        parts.append(f"any {r['kind']} alert")
    return " + ".join(parts) or "a rule"


def removal_plan(cur) -> dict:
    """The one source of truth for what removing the demo does to things the user made (the confirmation shows it,
    unload() does it). Decided by what each thing REFERENCES, never by where it was created:

    * a device name is removed when its device is a demo device;
    * a merge of two demo devices is removed; a device of yours merged into a demo device is un-merged (it stands
      alone again); a demo device merged into one of yours is dropped (the demo side is gone, yours is unchanged);
    * an expected-traffic rule is removed only when it cannot match anything that is not the demo: it is scoped to a
      demo device (no real traffic can carry a demo device's id), or it has no device and its indicator appears in
      no non-demo alert, list entry or log row. Every other rule stays, so a hidden real incident never reappears.

    An indicator seen nowhere at all (a rule made ahead of time) is not demo-only and stays.
    Returns {remove: {labels, merges, rules}, unmerge, keep: {rules}}, each a list of {id, text}."""
    from . import devices, incidents
    devices.ensure_tables(cur)
    incidents.ensure(cur)
    names = {r[0]: r[1] for r in cur.execute(
        "SELECT d.id, coalesce(l.name, d.hostnames[1], d.id) FROM devices d LEFT JOIN netlog_device_labels l ON l.id = d.id").fetchall()}
    for i, n in cur.execute("SELECT id, name FROM netlog_device_labels WHERE name IS NOT NULL").fetchall():
        names[i] = n
    out = {"remove": {"labels": [], "merges": [], "rules": []}, "unmerge": [], "keep": {"rules": []}}
    def dev_name(i, given=None):
        # a person-readable device name, never a raw MAC or id: the name you gave, its hostname, else
        # "Unnamed device · f8:f0" (the same fallback the device list uses)
        n = given or names.get(i)
        if n and n != i and not str(n).startswith(("mac:", "ip:", "duid:")):
            return str(n)
        tail = str(i).split(":", 1)[-1]
        return f"Unnamed device · {tail[-5:]}" if str(i).startswith("mac:") else f"Unnamed device · {tail}"
    for i, n in cur.execute("SELECT id, name FROM netlog_device_labels").fetchall():
        if is_demo_device(i):
            out["remove"]["labels"].append({"id": i, "text": n or dev_name(i)})
    for src, dst, src_name in cur.execute("SELECT src, dst, src_name FROM netlog_device_merges").fetchall():
        ds, dd = is_demo_device(src), is_demo_device(dst)
        a, b = dev_name(src, src_name), dev_name(dst)
        if ds:
            txt = f"{a} merged into {b}" if a != b else f"{a} (a second record of the same demo device) merged away"
            out["remove"]["merges"].append({"id": src, "text": txt})
        elif dd:
            out["unmerge"].append({"id": src, "dst": dst, "text": f"{a} stands alone again"})
    demo_alerts = {r[0] for r in cur.execute("SELECT id FROM alerts WHERE coalesce(demo, false)").fetchall()}
    demo_inds = {r[0] for r in cur.execute("SELECT DISTINCT indicator FROM alerts WHERE coalesce(demo, false)").fetchall() if r[0]}
    cols = [c[0] for c in cur.execute("SELECT id, device, indicator, kind, from_alert FROM netlog_rules LIMIT 0").description]
    for row in cur.execute("SELECT id, device, indicator, kind, from_alert FROM netlog_rules").fetchall():
        r = dict(zip(cols, row))
        item = {"id": r["id"], "text": _rule_text(r, names)}
        if r["device"]:
            if is_demo_device(r["device"]):
                out["remove"]["rules"].append(item)
            continue   # scoped to a device of yours: always kept, never even listed
        ind = r["indicator"]
        in_demo = bool(ind) and ind in demo_inds
        if in_demo and not _indicator_is_real(cur, ind):
            out["remove"]["rules"].append(item)   # its only reference is an indicator seen nowhere but the demo
        elif in_demo or r["from_alert"] in demo_alerts:
            out["keep"]["rules"].append({**item, "why": "its indicator is also in your own logs, alerts or lists"
                                         if in_demo else "its indicator is not from the demo"})
    return out


def your_changes() -> dict:
    """The removal plan for the confirmation (see removal_plan)."""
    try:
        from . import devices, incidents
        devices.ensure_tables()
        incidents.ensure()
        return removal_plan(db.cursor())
    except Exception:
        log.exception("demo: reading the user's demo changes failed")
        return {"remove": {"labels": [], "merges": [], "rules": []}, "unmerge": [], "keep": {"rules": []}}


def _forget_devices(loaded_at) -> int:
    """New-device memory: drop the demo devices and any device first noticed while the demo was loaded that is gone
    with it. When nothing real is left, the learning baseline starts over with the user's first real import."""
    from . import newdev
    with util.LOCK, db._write_lock:
        cur = db.cursor()
        cur.execute(newdev.SCHEMA)
        drop = [r[0] for r in cur.execute("""SELECT id FROM netlog_known_devices k
                                             WHERE how = 'demo' OR (noticed_at >= ?::TIMESTAMPTZ
                                                   AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.id = k.id))""",
                                          [loaded_at]).fetchall()]
        drop += [r[0] for r in cur.execute("SELECT id FROM netlog_known_devices").fetchall() if is_demo_device(r[0])]
        drop = list(dict.fromkeys(drop))
        if drop:
            cur.execute("DELETE FROM netlog_known_devices WHERE id IN (SELECT unnest(?::VARCHAR[]))", [drop])
        if not cur.execute("SELECT count(*) FROM netlog_known_devices").fetchone()[0]:
            st = newdev._state(cur)
            if any(k in st for k in ("baseline_at", "first_log", "seen_until")):
                for k in ("baseline_at", "first_log", "seen_until"):
                    st.pop(k, None)
                newdev._save(cur, st)
    return len(drop)


def unload() -> dict:
    """Remove every demo row, match, alert, stored file and aggregate, and the home prefixes the demo added; with
    them the names, merges and expected-traffic rules made only for demo devices or alerts, and the demo devices'
    place in the new-device memory (see removal_plan, _forget_devices)."""
    from . import devices, matcher
    st = state() or {}
    with util.LOCK:
        with db._write_lock:
            cur = db.cursor()
            cur.execute(devices.AGG_SQL)
            files = _demo_files(cur)
            ids = [f["id"] for f in files]
            n_rows = n_alerts = 0
            plan = removal_plan(cur)
            rm = plan["remove"]
            with db.tx(cur):
                for table, col, key in (("netlog_device_labels", "id", "labels"), ("netlog_device_merges", "src", "merges"),
                                        ("netlog_rules", "id", "rules")):
                    if rm[key]:
                        cur.execute(f"DELETE FROM {table} WHERE {col} IN (SELECT unnest(?::VARCHAR[]))", [[x["id"] for x in rm[key]]])
                if plan["unmerge"]:   # a device of yours merged into a demo device stands alone again
                    cur.execute("DELETE FROM netlog_device_merges WHERE src IN (SELECT unnest(?::VARCHAR[]))",
                                [[x["id"] for x in plan["unmerge"]]])
            unmerged_ips = [r[0] for r in cur.execute("SELECT DISTINCT ip FROM netlog_ipdev WHERE device IN (SELECT unnest(?::VARCHAR[]))",
                                                      [[x["dst"] for x in plan["unmerge"]]]).fetchall()] if plan["unmerge"] else []
            if ids:
                cur.execute("CREATE OR REPLACE TEMP TABLE _nl_demo AS SELECT rk FROM netlog WHERE file_id IN (SELECT unnest(?::VARCHAR[]))", [ids])
                alert_ids = {r[0] for r in cur.execute(
                    "SELECT DISTINCT alert_id FROM netlog_matches WHERE rk IN (SELECT rk FROM _nl_demo)").fetchall() if r[0]}
                cur.execute("BEGIN")
                try:
                    cur.execute("DELETE FROM netlog_matches WHERE rk IN (SELECT rk FROM _nl_demo)")
                    n_rows = cur.execute("DELETE FROM netlog WHERE rk IN (SELECT rk FROM _nl_demo)").fetchone()[0]
                    cur.execute("DELETE FROM netlog_files WHERE id IN (SELECT unnest(?::VARCHAR[]))", [ids])
                    before = {r[0] for r in cur.execute("SELECT id FROM alerts").fetchall()}
                    matcher._refresh_alerts(cur, alert_ids)
                    gone = before - {r[0] for r in cur.execute("SELECT id FROM alerts").fetchall()}
                    n_alerts = len(gone)
                    if gone:
                        cur.executemany("DELETE FROM netlog_alert_status WHERE id = ?", [(i,) for i in gone])
                    for p in DEMO_PREFIXES:
                        r = ipnum.net_range(p)
                        if r:
                            cur.execute("DELETE FROM netlog_ipnum WHERE n BETWEEN ?::UHUGEINT AND ?::UHUGEINT", [str(r[0]), str(r[1])])
                    cur.execute("COMMIT")
                except Exception:
                    cur.execute("ROLLBACK")
                    raise
                finally:
                    cur.execute("DROP TABLE IF EXISTS _nl_demo")
        for f in files:
            try:
                Path(f["path"]).unlink(missing_ok=True)
            except (OSError, TypeError):
                pass
        added = st.get("prefixes_added") or []
        if added:
            s = util.settings()
            s["home_prefixes"] = [p for p in s.get("home_prefixes", []) if p not in added]
            util.save_settings(s)
        if files or rm["merges"] or plan["unmerge"]:   # aggregates are per hour and IP, not per file: rebuild them from what is left, in one pass
            if files:
                devices.reaggregate_all()
            devices.rebuild()
        if unmerged_ips:   # its rows match as its own device again
            devices._rematch_ips(unmerged_ips)
        forgot = _forget_devices(st.get("loaded_at") or "1970-01-01T00:00:00+00:00")
        db.execute("DELETE FROM settings WHERE key = ?", [STATE_KEY])
    util.publish_alerts({"demo_removed": True})
    return {"removed_files": len(files), "removed_rows": int(n_rows), "removed_alerts": n_alerts, "prefixes_removed": added,
            "removed_labels": len(rm["labels"]), "removed_merges": len(rm["merges"]), "removed_rules": len(rm["rules"]),
            "unmerged": len(plan["unmerge"]), "kept_rules": len(plan["keep"]["rules"]), "plan": plan,
            "forgot_devices": forgot}


def _cli() -> None:
    import argparse
    import sys

    import httpx
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:8787")
    ap.add_argument("action", choices=["load", "verify", "unload", "bundle"])
    ap.add_argument("out", nargs="?", help="bundle: where to write the tar.gz")
    a = ap.parse_args()
    with httpx.Client(base_url=a.base, timeout=600) as c:
        if a.action == "bundle":
            r = c.get("/api/netlog/demo/bundle")
            r.raise_for_status()
            Path(a.out or f"{BUNDLE}.tar.gz").write_bytes(r.content)
            print("wrote", a.out or f"{BUNDLE}.tar.gz")
            return
        r = {"load": c.post, "verify": c.get, "unload": c.delete}[a.action]("/api/netlog/demo")
        if r.status_code >= 400:
            sys.exit(f"{r.status_code}: {r.text}")
        d = r.json()
        for s in d.get("scenarios", []):
            print(("PASS " if s["ok"] else "FAIL ") + s["id"].ljust(18) + s["title"] + ("" if s["ok"] else f"  ({s['why']})"))
        if "total" in d:
            print(f"{d['passed']}/{d['total']} scenarios; {len(d['false_positives'])} high/medium alerts on ordinary traffic")
        else:
            print(json.dumps(d, indent=1))


if __name__ == "__main__":
    _cli()

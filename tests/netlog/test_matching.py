"""Matching contacts against the lists, end to end in-process (record files -> intervals -> import -> alerts), on
cases ported from the critic's adversarial runs (tests/eval/critic/netlog_adversarial.py, netlog_r2.py) with
documentation addresses and invented .example domains:

* time-aware: a contact before the listing is no alert, one while listed is, one between a removal and a re-listing
  is not; a contact before our copy listed it but inside the provider's own active dates is a retro match (low);
* direction: a listed scanner refused (S0/REJ) is at most low, an accepted inbound session with data is not ignored;
* DNS: a lookup from home whose answer is listed alerts, the same lookup by a machine outside home does not;
* names: a listed domain in a CNAME chain, a subdomain of it (any case, trailing dot), a TLS SNI or an HTTP Host
  alerts; a name that only contains it does not.

    uv run --with pytest pytest tests/netlog/test_matching.py -q
"""
from __future__ import annotations

import datetime as dt
import gzip
import io
import json

from _lake import conn, dns, make_lake
LAKE = make_lake("matching")

import pytest  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.netlog import importer, intervals, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
UTC = dt.UTC
L = (dt.datetime.now(UTC) - dt.timedelta(days=2)).replace(microsecond=0)   # when our copy of the lists was fetched
H, OUTSIDE = "192.0.2.10", "203.0.113.200"                               # a home device; a machine not at home
C2, C2_RELISTED, C2_RETRO = "198.51.100.10", "198.51.100.20", "198.51.100.30"
SCAN, ATTACKER = "198.51.100.70", "198.51.100.71"
D_CNAME, D_SNI, D_HOST = "cname-c2.example", "sni-c2.example", "host-c2.example"
RANK = {None: -1, "info": 0, "low": 1, "medium": 2, "high": 3}


def at(t: dt.datetime, hours: float = 0) -> float:
    return (t + dt.timedelta(hours=hours)).timestamp()


def rec(source: str, when: dt.datetime, lines: list[dict]) -> None:
    p = config.RAW_DIR / source / when.strftime("%Y/%m/%d") / f"{when.strftime('%H%M%S')}.records.ndjson.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt") as fh:
        fh.writelines(json.dumps(x) + "\n" for x in lines)


def feodo(ip: str, **data) -> dict:
    return {"key": f"{ip}:443", "op": "put", "data": {"ip_address": ip, "port": 443, "malware": "ExampleBot", **data}}


def threatfox(i: int, domain: str) -> dict:
    return {"key": str(i), "op": "put", "data": {"id": i, "ioc": domain, "ioc_type": "domain", "threat_type": "botnet_cc",
                                                  "malware_printable": "ExampleBot", "confidence_level": 100}}


def ssl(ts: float, src: str, dst: str, sni: str, uid: str) -> dict:
    return {"ts": ts, "uid": uid, "id.orig_h": src, "id.orig_p": 50100, "id.resp_h": dst, "id.resp_p": 443,
            "version": "TLSv12", "server_name": sni, "established": True}


def http(ts: float, src: str, dst: str, host: str, uid: str) -> dict:
    return {"ts": ts, "uid": uid, "id.orig_h": src, "id.orig_p": 50200, "id.resp_h": dst, "id.resp_p": 80,
            "trans_depth": 1, "method": "GET", "host": host, "uri": "/gate.php", "status_code": 200}


@pytest.fixture(scope="module")
def sev():
    """uid -> the strongest alert (severity, rule) whose evidence names it."""
    rec("feodo_c2", L, [feodo(C2), feodo(C2_RELISTED),
                        feodo(C2_RETRO, first_seen=(L - dt.timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S"),
                              last_online=(L - dt.timedelta(days=20)).strftime("%Y-%m-%d"))])
    rec("feodo_c2", L + dt.timedelta(hours=2), [{"key": f"{C2_RELISTED}:443", "op": "del"}])
    rec("feodo_c2", L + dt.timedelta(hours=4), [feodo(C2_RELISTED)])
    rec("threatfox", L, [threatfox(1, D_CNAME), threatfox(2, D_SNI), threatfox(3, D_HOST)])
    rec("dshield_top", L, [{"key": SCAN, "op": "put", "data": {"ip": SCAN, "attacks": 999}}])
    rec("blocklist_de", L, [{"key": ATTACKER, "op": "put", "data": ATTACKER}])
    intervals.refresh()
    s = util.settings()
    s["home_prefixes"] = ["192.0.2.0/24"]
    util.save_settings(s)
    rows = [
        conn(at(L, -1), H, C2, uid="BEFORE"), conn(at(L, 1), H, C2, uid="WHILE"),
        conn(at(L, 1), H, C2_RELISTED, uid="RE1"), conn(at(L, 3), H, C2_RELISTED, uid="REGAP"),
        conn(at(L, 5), H, C2_RELISTED, uid="RE2"),
        conn(at(L - dt.timedelta(days=40)), H, C2_RETRO, uid="RETRO"),     # provider: active 60..20 days before L
        conn(at(L - dt.timedelta(days=10)), H, C2_RETRO, uid="NORETRO"),   # after the provider's last sighting
        conn(at(L, 6), SCAN, H, 22, state="REJ", orig_bytes=0, resp_bytes=0, uid="SCANREJ"),
        conn(at(L, 6.1), SCAN, H, 23, state="S0", orig_bytes=0, resp_bytes=0, uid="SCANS0"),
        conn(at(L, 6.2), ATTACKER, H, 3389, orig_bytes=5_000_000, resp_bytes=2_000_000, uid="INBOUND"),
        dns(at(L, 7), H, "lookup.example", [C2], uid="DNSHOME"),
        dns(at(L, 7.1), OUTSIDE, "lookup2.example", [C2], uid="DNSOUT"),
        dns(at(L, 8), H, "www.innocent.example", ["cdn.innocent.example", D_CNAME, "203.0.113.49"], uid="CNAME"),
        dns(at(L, 8.1), H, "a.b." + D_CNAME + ".", ["203.0.113.50"], uid="SUBDOM"),
        dns(at(L, 8.2), H, D_CNAME + ".attacker-free.example", ["203.0.113.51"], uid="NOTSUB"),
        ssl(at(L, 9), H, "203.0.113.52", D_SNI.upper(), "SNI"),
        ssl(at(L, 9.1), H, "203.0.113.53", "x." + D_SNI + ".", "SNISUB"),
        http(at(L, 9.2), H, "203.0.113.54", D_HOST + ":8080", "HOST"),
    ]
    res = importer.import_any(io.BytesIO("".join(json.dumps(r) + "\n" for r in rows).encode()), "matching.log",
                              origin="upload")
    assert not res.get("error") and res["inserted"] == len(rows), res
    out: dict[str, tuple[str, str]] = {}
    for a in db.query("SELECT severity, rule, evidence FROM alerts"):
        for u in json.loads(a["evidence"]).get("uids") or []:
            if RANK[a["severity"]] > RANK[(out.get(u) or (None, None))[0]]:
                out[u] = (a["severity"], a["rule"])
    return out


def level(sev, uid) -> str | None:
    return (sev.get(uid) or (None, None))[0]


# uid -> (the lowest, the highest) severity its strongest alert may have; None: no alert at all
EXPECT = {
    # time-aware listings
    "BEFORE": (None, "info"), "WHILE": ("high", "high"),
    "RE1": ("high", "high"), "REGAP": (None, "info"), "RE2": ("high", "high"),
    "RETRO": ("low", "low"), "NORETRO": (None, "info"),
    # direction
    "SCANREJ": (None, "low"), "SCANS0": (None, "low"), "INBOUND": ("medium", "high"),
    # DNS from home only
    "DNSHOME": ("high", "high"), "DNSOUT": (None, "low"),
    # names: CNAME chain, subdomain, SNI, Host
    "CNAME": ("high", "high"), "SUBDOM": ("high", "high"), "NOTSUB": (None, None),
    "SNI": ("high", "high"), "SNISUB": ("high", "high"), "HOST": ("high", "high"),
}


def test_every_contact_gets_the_right_alert(sev):
    bad = [f"{uid}: got {sev.get(uid)}, want {lo}..{hi}" for uid, (lo, hi) in EXPECT.items()
           if not RANK[lo] <= RANK[level(sev, uid)] <= RANK[hi]]
    assert not bad, "\n".join(bad)


def test_rules_say_why(sev):
    assert sev["RETRO"][1] == "c2_retro"                          # found with the provider's own dates
    assert sev["REGAP"][1] == sev["NORETRO"][1] == "historical"   # kept as history, not raised as a threat
    assert sev["CNAME"][1] == "c2_dns" and sev["INBOUND"][1] == "attacker_inbound_accepted"

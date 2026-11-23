"""End-to-end smoke test for netlog against a running server and its (scratch) lake.

Uses documentation addresses and invented MACs only. It writes a Feodo record delta into the lake,
so never point it at a real lake.

    uv run python tests/eval/netlog/selftest.py --base http://127.0.0.1:8804 --lake /path/to/scratch-lake
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import os
import sys
import time
from pathlib import Path

import httpx

UTC = dt.UTC
C2 = "203.0.113.66"          # becomes a listed C2 during the test
LATE = "203.0.113.77"        # listed only after its logs are imported (re-hunt)
HOME4, HOME6 = "192.0.2.0/24", "2001:db8:1::/48"
MAC_A, MAC_B = "02:00:5e:10:00:0a", "02:00:5e:10:00:0b"
EUI = "2001:db8:1:1:ff:5eff:fe10:c"      # EUI-64 of 02:ff:5e:10:00:0c


def _records(lake: Path, ts: dt.datetime, puts: list[dict], dels: list[str]) -> Path:
    p = lake / "raw" / "feodo_c2" / ts.strftime("%Y/%m/%d") / f"{ts.strftime('%H%M%S')}.records.ndjson.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt") as fh:
        for r in puts:
            fh.write(json.dumps({"key": f"{r['ip_address']}:{r['port']}", "op": "put", "data": r}) + "\n")
        for k in dels:
            fh.write(json.dumps({"key": k, "op": "del"}) + "\n")
    return p


def _conn(ts, uid, oh, rh, rp, op=50000, mac=None, **kw):
    r = {"ts": ts.timestamp(), "uid": uid, "id.orig_h": oh, "id.orig_p": op, "id.resp_h": rh, "id.resp_p": rp,
         "proto": "tcp", "conn_state": "SF", "history": "ShADadFf", "orig_bytes": 500, "resp_bytes": 900, "duration": 1.5}
    if mac:
        r["orig_l2_addr"] = mac
    r.update(kw)
    return r


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--lake", required=True)
    a = ap.parse_args()
    lake = Path(a.lake)
    c = httpx.Client(base_url=a.base.rstrip("/"), timeout=120)
    fails: list[str] = []

    def check(name, ok, info=""):
        print(("PASS " if ok else "FAIL ") + name + (f"  ({info})" if info and not ok else ""))
        if not ok:
            fails.append(name)

    now = dt.datetime.now(UTC).replace(microsecond=0)
    listed = now - dt.timedelta(hours=3)
    _records(lake, listed, [{"ip_address": C2, "port": 443, "status": "offline", "malware": "SelfTest"}], [])
    c.put("/api/netlog/settings", json={"home_prefixes": [HOME4, HOME6]}).raise_for_status()
    c.post("/api/netlog/indicators/refresh").raise_for_status()

    t_before, t_after = listed - dt.timedelta(minutes=30), listed + dt.timedelta(minutes=30)
    tag = str(int(time.time()))
    conn = [
        _conn(t_before, f"Cpre{tag}", "192.0.2.10", C2, 443, mac=MAC_A),           # before listing: historical
        _conn(t_after, f"Cpost{tag}", "192.0.2.10", C2, 443, mac=MAC_A),           # listed: high
        _conn(t_after, f"Cin{tag}", C2, "192.0.2.11", 22, op=40000),               # inbound from C2: low
        _conn(t_after, f"Clate{tag}", "192.0.2.11", LATE, 8080, mac=MAC_B),        # listed later
        _conn(t_after, f"Ceui{tag}", EUI, "2001:db8:ffff::1", 443),
        _conn(t_after, f"Cben{tag}", "192.0.2.10", "198.51.100.20", 443, mac=MAC_A),
    ]
    dhcp = [{"ts": (now - dt.timedelta(hours=5)).timestamp(), "uids": [f"Cd{tag}"], "client_addr": "192.0.2.11",
             "server_addr": "192.0.2.1", "mac": MAC_B, "host_name": "selftest-b", "assigned_addr": "192.0.2.11",
             "lease_time": 86400.0, "msg_types": ["REQUEST", "ACK"], "duration": 0.1}]
    dns = [{"ts": t_after.timestamp(), "uid": f"Cdns{tag}", "id.orig_h": "192.0.2.10", "id.orig_p": 5353,
            "id.resp_h": "192.0.2.1", "id.resp_p": 53, "proto": "udp", "trans_id": 7, "query": "bad.example",
            "qtype_name": "A", "rcode_name": "NOERROR", "answers": [C2], "TTLs": [60.0]}]
    other = [{"ts": t_after.timestamp(), "fuid": f"F{tag}", "uid": f"Cpost{tag}", "id.orig_h": C2, "id.orig_p": 443,
              "id.resp_h": "192.0.2.10", "id.resp_p": 50000, "source": "SSL", "depth": 0, "analyzers": ["X509"],
              "mime_type": "application/x-x509-user-cert", "seen_bytes": 900},
             {"ts": t_after.timestamp(), "id": f"F{tag}", "certificate.version": 3, "certificate.subject": "CN=bad.example"},
             {"ts": t_after.timestamp(), "host": "192.0.2.10"},
             {"ts": t_after.timestamp(), "uid": f"Cpost{tag}", "id.orig_h": "192.0.2.10", "id.orig_p": 1, "id.resp_h": C2,
              "id.resp_p": 443, "name": "bad_TCP_checksum", "notice": False, "peer": "zeek"},
             {"ts": t_after.timestamp(), "something_new": 1, "other": "x"}]

    def post(name, data: bytes):
        r = c.post("/api/netlog/import", files=[("files", (name, data))])
        r.raise_for_status()
        return r.json()["files"][0]

    nd = "\n".join(json.dumps(x) for x in conn).encode()
    r1 = post(f"conn-{tag}.log", nd)
    check("ndjson import", r1.get("inserted") == len(conn), r1)
    r2 = post(f"conn-{tag}.log.gz", gzip.compress(nd))
    check("same content gzipped is a duplicate file", r2.get("duplicate") is True, r2)
    r3 = post(f"dhcp-{tag}.json", json.dumps(dhcp).encode())
    check("JSON array import", r3.get("format") == "array" and r3.get("inserted") == 1, r3)
    r4 = post(f"dns-{tag}.log", gzip.compress("\n".join(json.dumps(x) for x in dns).encode()))
    check("gz import", r4.get("inserted") == 1, r4)
    r5 = post(f"mixed-{tag}.log", "\n".join(json.dumps(x) for x in other).encode())
    lt = r5.get("log_types", {})
    check("log type detection", all(lt.get(k) == 1 for k in ("files", "x509", "known_hosts", "weird", "unknown")), lt)
    r6 = post(f"rows-{tag}.log", ("\n".join(json.dumps(x) for x in conn[:2]) + "\n").encode())
    check("row dedup across files", r6.get("inserted") == 0 and r6.get("duplicates") == 2, r6)
    r7 = post(f"zeek-{tag}.tsv", b"#separator \\x09\n#fields\tts\n")
    check("TSV rejected with a reason", "TSV" in (r7.get("error") or ""), r7)

    al = c.get("/api/netlog/alerts", params={"limit": 0, "indicator": C2}).json()
    by = {(x["rule"], x["severity"]) for x in al}
    check("listed outbound is high", ("c2_outbound", "high") in by, by)
    check("pre-listing contact is historical info", ("historical", "info") in by, by)
    check("inbound from C2 is low", ("c2_inbound", "low") in by, by)
    rules = {r for x in al for r in x["evidence"]["rule"].get("rules", [])}
    check("DNS answer is outbound intent, merged with the connection", "c2_dns" in rules
          and any(f"Cdns{tag}" in x["evidence"]["uids"] and x["severity"] == "high" for x in al), rules)
    hi = [x for x in al if x["rule"] == "c2_outbound"]
    if hi:
        ev = hi[0]["evidence"]
        check("evidence chain", f"Cpost{tag}" in ev["uids"] and ev["interval"]["start"] and ev["device"]["id"] == f"mac:{MAC_A}"
              and ev["rule"]["id"] == "c2_outbound" and ev["source"] == "feodo_c2", ev)
        check("historical never high", all(x["severity"] == "info" for x in al if x["rule"] == "historical"))

    # Re-hunt: LATE gets listed now, its contact (at t_after) is before that, so only historical...
    _records(lake, now - dt.timedelta(hours=1), [{"ip_address": LATE, "port": 8080, "status": "online"}], [])
    rh = c.post("/api/netlog/rehunt").json()
    late = c.get("/api/netlog/alerts", params={"limit": 0, "indicator": LATE}).json()
    check("re-hunt picks up new listing (out of order file replays)", rh.get("changed") and late, rh)
    check("contact before new listing stays historical", late and all(x["severity"] == "info" for x in late), late)

    devs = {d["id"]: d for d in c.get("/api/netlog/devices").json()}
    check("MAC identity from conn l2", f"mac:{MAC_A}" in devs)
    check("DHCP hostname", "selftest-b" in (devs.get(f"mac:{MAC_B}") or {}).get("hostnames", []))
    check("EUI-64 address grouped to MAC", any(EUI in d["ips"] and d["confidence"] == "derived" for d in devs.values()))

    if hi:
        aid = hi[0]["id"]
        c.patch(f"/api/netlog/alerts/{aid}", json={"status": "ack"}).raise_for_status()
        c.post("/api/netlog/rehunt").raise_for_status()
        st = c.get(f"/api/netlog/alerts/{aid}").json()
        check("status survives re-hunt", st["status"] == "ack", st.get("status"))
    s = c.get("/api/netlog/connections", params={"q": "bad.example"}).json()
    check("connection text search", s["total"] >= 1, s["total"])
    for f in ("talkers", "ports", "services", "countries", "asns"):
        check(f"stats/top {f}", c.get("/api/netlog/stats/top", params={"field": f}).status_code == 200)
    check("timeline", c.get("/api/netlog/stats/timeline", params={"bucket": "hour"}).status_code == 200)

    inbox = lake / "inbox" / "zeek"
    inbox.mkdir(parents=True, exist_ok=True)
    (inbox / f"inbox-{tag}.log").write_bytes(json.dumps(_conn(now, f"Cinbox{tag}", "192.0.2.12", "198.51.100.9", 443)).encode())
    settled = time.time() - 600   # the inbox reads a file only once it has stopped changing
    os.utime(inbox / f"inbox-{tag}.log", (settled, settled))
    res = c.post("/api/netlog/inbox/scan").json()
    check("inbox import", any(r.get("inserted") == 1 for r in res["files"]), res)   # kept or deleted: the inbox setting decides
    print("OK" if not fails else f"{len(fails)} FAILED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

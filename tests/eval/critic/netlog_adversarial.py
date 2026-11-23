#!/usr/bin/env python3
"""Critic's adversarial cases for osinthub/netlog. Documentation addresses only.

Writes invented threat-list record files (dated 2026-11-06) into a SCRATCH lake, imports crafted
Zeek logs into a server running on that lake, and prints PASS/FAIL per case.

    uv run python tests/eval/critic/netlog_adversarial.py --base http://127.0.0.1:8812 \
        --lake $TMPDIR/hlta-scratch/<you>
"""
from __future__ import annotations

import argparse, gzip, io, json, sys, time
from datetime import UTC, datetime
from pathlib import Path
import urllib.request

HOME = ["192.0.2.0/24", "2001:db8:1::/48"]
RANK = {None: -1, "info": 0, "low": 1, "medium": 2, "high": 3}


def T(hms: str) -> float:
    return datetime.fromisoformat(f"2026-11-06T{hms}+00:00").timestamp()


def req(base, method, path, body=None, files=None):
    data, hdr = None, {}
    if files is not None:
        b = "----critic" + str(time.time_ns())
        buf = io.BytesIO()
        for name, content in files:
            buf.write(f"--{b}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{name}\"\r\n"
                      "Content-Type: application/octet-stream\r\n\r\n".encode())
            buf.write(content); buf.write(b"\r\n")
        buf.write(f"--{b}--\r\n".encode())
        data, hdr = buf.getvalue(), {"Content-Type": f"multipart/form-data; boundary={b}"}
    elif body is not None:
        data, hdr = json.dumps(body).encode(), {"Content-Type": "application/json"}
    r = urllib.request.Request(base + path, data=data, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(r, timeout=600) as resp:
            return json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return {"http_error": e.code, "body": e.read().decode()[:300]}


def conn(uid, ts, oh, rh, rp, op=50000, state="SF", ob=1200, rb=3400, dur=2.0, **kw):
    d = {"ts": ts, "uid": uid, "id.orig_h": oh, "id.orig_p": op, "id.resp_h": rh, "id.resp_p": rp,
         "proto": "tcp", "service": "ssl", "duration": dur, "orig_bytes": ob, "resp_bytes": rb,
         "conn_state": state, "history": "ShADadFf", "orig_pkts": 10, "resp_pkts": 10}
    d.update(kw)
    return d


def dns(uid, ts, oh, query, answers, rh="192.0.2.1"):
    return {"ts": ts, "uid": uid, "id.orig_h": oh, "id.orig_p": 53000, "id.resp_h": rh, "id.resp_p": 53,
            "proto": "udp", "trans_id": 4242, "query": query, "qtype": 1, "qtype_name": "A",
            "rcode_name": "NOERROR", "answers": answers, "TTLs": [60.0] * len(answers)}


def nd(rows):
    return ("\n".join(r if isinstance(r, str) else json.dumps(r) for r in rows) + "\n").encode()


def write_records(lake: Path):
    def w(src, hms, lines):
        p = lake / "raw" / src / "2026/11/06" / f"{hms}.records.ndjson.gz"
        p.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(p, "wt") as fh:
            for l in lines:
                fh.write(json.dumps(l) + "\n")
    def feo(ip, port=443):
        key = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        return {"key": key, "op": "put", "data": {"ip_address": ip, "port": port, "status": "online", "malware": "CriticBot"}}
    w("feodo_c2", "100000", [feo(i) for i in ("198.51.100.10", "2001:db8:bad::10", "198.51.100.20", "203.0.113.255",
                                              "198.51.100.30", "198.51.100.40", "198.51.100.50")])
    w("feodo_c2", "120000", [{"key": "198.51.100.20:443", "op": "del"}])
    w("feodo_c2", "140000", [feo("198.51.100.20")])
    w("spamhaus_drop", "100000", [{"key": c, "op": "put", "data": [{"cidr": c, "sblid": "SBL0CRITIC"}]}
                                  for c in ("2001:db8:bad:1::/64", "203.0.113.64/26")])
    w("dshield_top", "100000", [{"key": "198.51.100.70", "op": "put", "data": {"ip": "198.51.100.70", "attacks": 999}}])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True); ap.add_argument("--lake", required=True, type=Path)
    ap.add_argument("--huge", type=int, default=400_000)
    a = ap.parse_args()
    base = a.base.rstrip("/")
    if "hlta-scratch" not in str(a.lake):
        sys.exit("refusing: --lake must be a scratch lake")
    req(base, "PUT", "/api/netlog/settings", {"home_prefixes": HOME})
    write_records(a.lake)
    print("refresh:", json.dumps(req(base, "POST", "/api/netlog/indicators/refresh"))[:300])

    H4, H6 = "192.0.2.10", "2001:db8:1::5"
    main_rows = [
        conn("CV6A", T("11:00:00"), H6, "2001:db8:bad::10", 443),
        conn("CV6B", T("11:01:00"), H6, "2001:0DB8:0BAD:0000:0000:0000:0000:0010", 443),
        conn("CDRLO", T("11:02:00"), H6, "2001:db8:bad:1::", 443),
        conn("CDRHI", T("11:02:01"), H6, "2001:db8:bad:1:ffff:ffff:ffff:ffff", 443),
        conn("CDRX1", T("11:02:02"), H6, "2001:db8:bad:2::", 443),
        conn("CDRX2", T("11:02:03"), H6, "2001:db8:bad:0:ffff:ffff:ffff:ffff", 443),
        conn("C4LO", T("11:03:00"), H4, "203.0.113.64", 443),
        conn("C4HI", T("11:03:01"), H4, "203.0.113.127", 443),
        conn("C4X1", T("11:03:02"), H4, "203.0.113.63", 443),
        conn("C4X2", T("11:03:03"), H4, "203.0.113.128", 443),
        conn("CMAP", T("11:04:00"), H4, "::ffff:198.51.100.10", 443),
        conn("CSPAN", T("09:59:00"), H4, "198.51.100.30", 443, dur=7200.0, ob=5_000_000, rb=9_000_000),
        conn("CSTART", T("10:00:00"), H4, "198.51.100.10", 443),
        conn("CRA1", T("11:00:00"), H4, "198.51.100.20", 443),
        conn("CRAEND", T("12:00:00"), H4, "198.51.100.20", 443),
        conn("CRA2", T("13:00:00"), H4, "198.51.100.20", 443),
        conn("CRA3", T("15:00:00"), H4, "198.51.100.20", 443),
        dns("CSAME", T("11:09:59"), "192.0.2.11", "same.example", ["198.51.100.10"]),
        conn("CSAME", T("11:10:00"), "192.0.2.11", "198.51.100.10", 443),
        conn("SCN1", T("11:30:00"), "198.51.100.70", "192.0.2.10", 22, op=51515, dur=900.0, ob=5_000_000, rb=2_000_000),
        conn("C2IN", T("11:31:00"), "198.51.100.50", "192.0.2.10", 3389, op=51516, dur=900.0, ob=5_000_000, rb=2_000_000),
        dns("DNSO", T("11:32:00"), "192.0.2.11", "c2only.example", ["198.51.100.40"]),
        dns("DNSX", T("11:33:00"), "203.0.113.200", "x.example", ["198.51.100.10"]),
        conn("D255", T("11:34:00"), "192.0.2.12", "203.0.113.255", 8080),
        conn("HP1", T("11:40:00"), "203.0.113.7", "198.51.100.10", 443),
    ]
    ts_rows = [
        conn("TS1", str(T("11:20:00")), H4, "198.51.100.10", 443),
        conn("TS2", "2026-11-06T11:21:00", H4, "198.51.100.10", 443),
        conn("TS3", "2026-11-06T12:22:00+01:00", H4, "198.51.100.10", 443),
        conn("TS4", int(T("11:23:00") * 1000), H4, "198.51.100.10", 443),
        conn("TS5", "2026-11-06T11:24:00Z", H4, "198.51.100.10", 443),
    ]
    mal = nd([conn("MAL1", T("11:50:00"), H4, "198.51.100.10", 443), "this is not json",
              '{"ts": 1, "uid": "MALX", ', conn("MAL2", T("11:51:00"), H4, "198.51.100.10", 443), "[1,2,3]",
              conn("MAL4", T("11:52:00"), H4, "198.51.100.10", 443)])
    gzm = gzip.compress(nd([conn("GZ1", T("11:55:00"), H4, "198.51.100.10", 443)])) + \
          gzip.compress(nd([conn("GZ2", T("11:56:00"), H4, "198.51.100.10", 443)]))
    eve = nd([{"timestamp": "2026-11-06T11:57:00.000000+0000", "event_type": "flow", "src_ip": H4, "src_port": 50001,
               "dest_ip": "198.51.100.10", "dest_port": 443, "proto": "TCP", "flow_id": 1}])
    res = {}
    def imp(name, content):
        t0 = time.time(); r = req(base, "POST", "/api/netlog/import", files=[(name, content)])
        f = (r.get("files") or [{}])[0] if isinstance(r, dict) else {}
        res[name] = f
        print(f"import {name}: {time.time()-t0:.1f}s rows={f.get('rows')} inserted={f.get('inserted')} "
              f"dup={f.get('duplicate')} types={f.get('log_types')} err={f.get('error')}")
        return f
    imp("main.log", nd(main_rows))
    imp("ts.log", nd(ts_rows))
    imp("malformed.log", mal)
    imp("multimember.log.gz", gzm)
    imp("eve.json", eve)
    imp("empty.log", b"")
    r1 = imp("malformed-again.log", mal); r2 = imp("malformed-again.log.gz", gzip.compress(mal))
    # huge JSON array
    arr = [conn(f"HG{i:07d}", T("16:00:00") + i * 0.01, f"192.0.2.{20 + i % 200}", f"198.18.{i % 250}.{1 + i % 200}", 443)
           for i in range(a.huge)] + [conn("HUGE1", T("16:59:00"), H4, "198.51.100.10", 443)]
    blob = json.dumps(arr).encode(); print(f"huge array: {len(blob)/1e6:.0f} MB")
    imp("huge-array.json", blob)

    def alerts():
        return req(base, "GET", "/api/netlog/alerts?limit=0")
    def sev_by_uid(al):
        out = {}
        for x in al:
            for u in (x.get("evidence") or {}).get("uids") or []:
                if RANK[x["severity"]] > RANK[out.get(u)]:
                    out[u] = x["severity"]
        return out
    def stored(uid):
        r = req(base, "GET", f"/api/netlog/connections?uid={uid}&limit=10")
        return r.get("rows", [])
    s = sev_by_uid(alerts())
    checks = []
    def chk(name, ok, got):
        checks.append((name, ok, got))
    hi = lambda u: s.get(u) == "high"
    none = lambda u: s.get(u) in (None, "info")
    for u in ("CV6A", "CV6B", "CDRLO", "CDRHI", "C4LO", "C4HI", "CMAP", "CSTART", "CRA1", "CRA3", "DNSO", "HUGE1", "GZ1", "GZ2",
              "MAL1", "MAL2", "MAL4"):
        chk(f"{u} high", hi(u), s.get(u))
    for u in ("CDRX1", "CDRX2", "C4X1", "C4X2", "CRAEND", "CRA2"):
        chk(f"{u} not high/medium", none(u), s.get(u))
    chk("CSPAN (starts 60s before listing, 2h/14MB while listed) >= medium", RANK[s.get("CSPAN")] >= 2, s.get("CSPAN"))
    chk("D255 C2 at x.y.z.255 high", hi("D255"), s.get("D255"))
    chk("DNSX external client lookup not high", s.get("DNSX") not in ("high", "medium"), s.get("DNSX"))
    chk("SCN1 accepted 7MB inbound from scanner > info", RANK[s.get("SCN1")] >= 1, s.get("SCN1"))
    chk("C2IN accepted 7MB inbound RDP from C2 >= medium", RANK[s.get("C2IN")] >= 2, s.get("C2IN"))
    same = stored("CSAME"); chk("CSAME conn+dns both stored", len(same) == 2, [r["log_type"] for r in same])
    for u, want in (("TS1", "11:20:00"), ("TS2", "11:21:00"), ("TS3", "11:22:00"), ("TS4", "11:23:00"), ("TS5", "11:24:00")):
        rows = stored(u); got = rows[0]["ts"] if rows else None
        try:
            g = datetime.fromisoformat(got).astimezone(UTC)
            ok = g.strftime("%H:%M:%S") == want and g.day == 6 and g.year == 2026
        except (TypeError, ValueError):
            ok = False
        chk(f"{u} ts parsed as 2026-11-06T{want}Z (or rejected loudly)", ok or (not rows), got)
    m = res["malformed.log"]
    chk("malformed: 3 good rows kept", m.get("inserted") == 3, m.get("inserted"))
    chk("malformed: rejected lines reported", any(k in json.dumps(m) for k in ("skipped", "rejected", "invalid", "bad_lines")), list(m))
    chk("multi-member gz: 2 rows", res["multimember.log.gz"].get("inserted") == 2, res["multimember.log.gz"].get("inserted"))
    chk("eve.json rejected or warned", bool(res["eve.json"].get("error") or res["eve.json"].get("warning")), res["eve.json"].get("log_types"))
    chk("eve.json C2 flow alerts or is refused", bool(res["eve.json"].get("error")) or s.get("1") == "high", None)
    chk("empty file -> error", bool(res["empty.log"].get("error")), res["empty.log"].get("error"))
    chk("re-import plain duplicate", r1.get("duplicate") is True, r1.get("duplicate"))
    chk("re-import gz duplicate", r2.get("duplicate") is True, r2.get("duplicate"))
    chk("huge array imported", (res["huge-array.json"].get("inserted") or 0) >= a.huge, res["huge-array.json"].get("error") or res["huge-array.json"].get("inserted"))
    chk("HP1 before home change: low (unknown direction)", s.get("HP1") == "low", s.get("HP1"))
    # alert detail evidence chain for CSAME
    al = alerts()
    a_same = [x for x in al if "CSAME" in (x["evidence"].get("uids") or [])]
    if a_same:
        d = req(base, "GET", f"/api/netlog/alerts/{a_same[0]['id']}")
        chk("CSAME alert: related has conn+dns", len(d.get("related") or []) == 2, [r["log_type"] for r in d.get("related") or []])
        chk("evidence names the listing file", "start_path" in json.dumps(d), sorted(d.keys()))
        chk("CSAME dns+conn in one alert", len(a_same) == 1, [x["rule"] for x in a_same])
    # home prefixes changed after import
    req(base, "PUT", "/api/netlog/settings", {"home_prefixes": HOME + ["203.0.113.0/28"]})
    s2 = sev_by_uid(alerts()); chk("HP1 after 203.0.113.0/28 added: high", s2.get("HP1") == "high", s2.get("HP1"))
    hp = [x for x in alerts() if "HP1" in x["evidence"].get("uids", []) and x["severity"] == "high"]
    if hp:
        req(base, "PATCH", f"/api/netlog/alerts/{hp[0]['id']}", {"status": "ack"})
    req(base, "PUT", "/api/netlog/settings", {"home_prefixes": HOME})
    s3 = sev_by_uid(alerts()); chk("HP1 after prefix removed: back to low", s3.get("HP1") == "low", s3.get("HP1"))
    req(base, "PUT", "/api/netlog/settings", {"home_prefixes": HOME + ["203.0.113.0/28"]})
    hp2 = [x for x in alerts() if hp and x["id"] == hp[0]["id"]]
    chk("ack survives prefix toggle", bool(hp2) and hp2[0]["status"] == "ack", hp2[0]["status"] if hp2 else None)
    # NAT: single WAN IP as the only home address
    req(base, "PUT", "/api/netlog/settings", {"home_prefixes": ["203.0.113.9/32"]})
    imp("nat.log", nd([conn("NAT1", T("17:10:00"), "203.0.113.9", "198.51.100.10", 443, op=40001),
                       conn("NAT2", T("17:11:00"), "203.0.113.9", "198.51.100.10", 443, op=40002)]))
    sn = [x for x in alerts() if "NAT1" in x["evidence"].get("uids", [])]
    chk("NAT single IP: high alert, device ip:203.0.113.9", bool(sn) and sn[0]["severity"] == "high", [(x["severity"], x["device"]) for x in sn])
    req(base, "PUT", "/api/netlog/settings", {"home_prefixes": HOME})
    fails = 0
    print()
    for n, ok, got in checks:
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {n}  -> {got}")
    print(f"\n{len(checks) - fails}/{len(checks)} passed")


if __name__ == "__main__":
    main()

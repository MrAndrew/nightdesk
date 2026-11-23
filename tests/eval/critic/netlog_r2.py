#!/usr/bin/env python3
"""Round-2 critic cases for osinthub/netlog. Documentation addresses and .example names only.

Writes invented threat-list record files (dated 2026-11-08) into a SCRATCH lake, imports crafted Zeek and
Suricata EVE logs into a server running on that lake, and prints PASS/FAIL (or GAP for missing features).

    uv run python tests/eval/critic/netlog_r2.py --base http://127.0.0.1:8814 \
        --lake $TMPDIR/hlta-scratch/<you>
    # optional, with the server STOPPED: add a 'reported' domain mention for the SNI/Host case
    uv run python tests/eval/critic/netlog_r2.py --seed-reported --lake $TMPDIR/hlta-scratch/<you>
    # latency on whatever is in the lake (run zeek_planted.py --perf first for 1M rows)
    uv run python tests/eval/critic/netlog_r2.py --base ... --lake ... --latency-only
"""
from __future__ import annotations

import argparse, gzip, io, json, statistics, sys, tarfile, time, urllib.parse, urllib.request
from datetime import UTC, datetime
from pathlib import Path

HOME = ["192.0.2.0/24", "2001:db8:1::/48"]
RANK = {None: -1, "info": 0, "low": 1, "medium": 2, "high": 3}
DAY = "2026-11-08"
C2A, C2B, C2EVE, C2TOCL, C2MAP, C2NAT, C2DRIFT, C2LATE, C2AUTO, C2MAPPED_LIST = (
    "198.51.100.110", "198.51.100.111", "198.51.100.112", "198.51.100.113", "198.51.100.114",
    "198.51.100.115", "198.51.100.116", "198.51.100.120", "198.51.100.121", "198.51.100.117")
SCAN = "198.51.100.170"
D_CNAME, D_SNI, D_HOST, D_REP = "cname-c2.example", "sni-c2.example", "host-c2.example", "reported-c2.example"


def T(hms: str, day: str = DAY) -> float:
    return datetime.fromisoformat(f"{day}T{hms}+00:00").timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def req(base, method, path, body=None, files=None, raw=False, timeout=900):
    data, hdr = None, {}
    if files is not None:
        b = "----critic2" + str(time.time_ns())
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
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            out = resp.read()
            return (resp.status, out) if raw else json.loads(out or b"null")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        return (e.code, body) if raw else {"http_error": e.code, "body": body}


def g(base, path, **params):
    return req(base, "GET", path + ("?" + urllib.parse.urlencode(params) if params else ""))


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


def ssl(uid, ts, oh, rh, sni):
    return {"ts": ts, "uid": uid, "id.orig_h": oh, "id.orig_p": 50444, "id.resp_h": rh, "id.resp_p": 443,
            "version": "TLSv12", "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "server_name": sni,
            "established": True, "ja3": "0123456789abcdef0123456789abcdef"}


def http(uid, ts, oh, rh, host, uri="/gate.php", ua="curl/8.0 (x86_64)"):
    return {"ts": ts, "uid": uid, "id.orig_h": oh, "id.orig_p": 50555, "id.resp_h": rh, "id.resp_p": 80,
            "trans_depth": 1, "method": "POST", "host": host, "uri": uri, "user_agent": ua, "status_code": 200}


def eve(event_type, ts, src, sport, dst, dport, flow_id, **kw):
    d = {"timestamp": iso(ts), "flow_id": flow_id, "event_type": event_type, "src_ip": src, "src_port": sport,
         "dest_ip": dst, "dest_port": dport, "proto": "TCP"}
    d.update(kw)
    return d


def nd(rows):
    return ("\n".join(r if isinstance(r, str) else json.dumps(r) for r in rows) + "\n").encode()


def write_rec(lake: Path, src: str, hms: str, lines: list[dict], day: str = DAY):
    p = lake / "raw" / src / day.replace("-", "/") / f"{hms}.records.ndjson.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt") as fh:
        for l in lines:
            fh.write(json.dumps(l) + "\n")


def feo(ip, port=443):
    key = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    return {"key": key, "op": "put", "data": {"ip_address": ip, "port": port, "status": "online", "malware": "CriticBot2"}}


def tfx(domain):
    return {"key": domain, "op": "put", "data": {"ioc": domain, "threat_type": "botnet_cc", "malware": "CriticBot2"}}


def write_records(lake: Path):
    write_rec(lake, "feodo_c2", "100000", [feo(i) for i in (C2A, C2B, C2EVE, C2TOCL, C2MAP, C2NAT, C2DRIFT)]
              + [feo("::ffff:" + C2MAPPED_LIST)])
    write_rec(lake, "feodo_c2", "120000", [{"key": f"{C2B}:443", "op": "del"}, {"key": f"{C2EVE}:443", "op": "del"}])
    write_rec(lake, "threatfox", "100000", [tfx(d) for d in (D_CNAME, D_SNI, D_HOST)])
    write_rec(lake, "dshield_top", "100000", [{"key": SCAN, "op": "put", "data": {"ip": SCAN, "attacks": 9999}}]
              + [{"key": f"198.51.100.{180 + i}", "op": "put", "data": {"ip": f"198.51.100.{180 + i}", "attacks": 50}}
                 for i in range(20)])


def seed_reported(lake: Path):
    import duckdb
    c = duckdb.connect(str(lake / "db" / "hub.duckdb"))
    # Entity tables are keyless (DuckDB ART-index workaround), so replace by delete-then-insert.
    c.execute("DELETE FROM entities WHERE id = ?", [f"domain:{D_REP}"])
    c.execute("DELETE FROM mentions WHERE entity_id = ? AND ref_id = 'critic-r2-article'", [f"domain:{D_REP}"])
    c.execute("INSERT INTO entities (id, type, name, aliases, attrs, first_seen, last_seen) VALUES "
              "(?, 'domain', ?, [], '{}', ?, ?)", [f"domain:{D_REP}", D_REP, datetime.fromtimestamp(T("09:00:00"), UTC),
                                                    datetime.fromtimestamp(T("09:00:00"), UTC)])
    c.execute("INSERT INTO mentions VALUES (?, 'article', 'critic-r2-article', 'ioc', 'regex', 0.9, ?)",
              [f"domain:{D_REP}", datetime.fromtimestamp(T("09:00:00"), UTC)])
    c.close()
    print("seeded reported domain", D_REP)


# ------------------------------------------------------------------------------------------------- latency
def latency(base: str, n: int = 20) -> list[tuple[str, float, float]]:
    s = g(base, "/api/netlog/summary")
    print(f"latency on {s.get('rows'):,} rows")
    cases = [
        ("aggregate group=resp_h", "/api/netlog/aggregate", {"group": "resp_h"}),
        ("aggregate group=orig_h,resp_p", "/api/netlog/aggregate", {"group": "orig_h,resp_p"}),
        ("aggregate group=device", "/api/netlog/aggregate", {"group": "device"}),
        ("aggregate group=raw.ja3 log_type:ssl", "/api/netlog/aggregate", {"group": "raw.ja3", "query": "log_type:ssl"}),
        ("aggregate group=resp_p q-filtered", "/api/netlog/aggregate",
         {"group": "resp_p", "query": "log_type:conn -conn_state:S0,REJ orig_bytes:>1000"}),
        ("timeline hour", "/api/netlog/stats/timeline", {"bucket": "hour"}),
        ("timeline 5m split=log_type", "/api/netlog/stats/timeline", {"bucket": "5m", "split": "log_type"}),
        ("timeline hour split=device", "/api/netlog/stats/timeline", {"bucket": "hour", "split": "device"}),
        ("connections limit=100", "/api/netlog/connections", {"limit": 100}),
        ("connections ip CIDR", "/api/netlog/connections", {"query": "ip:198.51.100.0/24", "limit": 100}),
        ("connections text word", "/api/netlog/connections", {"query": "example", "limit": 100}),
        ("connections raw field", "/api/netlog/connections", {"query": "raw.history:ShADadFf resp_p:443", "limit": 100}),
    ]
    out = []
    for name, path, p in cases:
        ts = []
        for _ in range(n):
            t0 = time.perf_counter(); r = g(base, path, **p); ts.append((time.perf_counter() - t0) * 1000)
            if isinstance(r, dict) and r.get("http_error"):
                print("  ERR", name, r); break
        ts.sort()
        p95 = ts[min(len(ts) - 1, int(round(0.95 * len(ts))) - 1)]
        out.append((name, statistics.median(ts), p95))
        print(f"  {'OK  ' if p95 < 500 else 'SLOW'} {name:42s} p50 {statistics.median(ts):7.0f} ms  p95 {p95:7.0f} ms")
    return out


# ------------------------------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base"); ap.add_argument("--lake", required=True, type=Path)
    ap.add_argument("--seed-reported", action="store_true"); ap.add_argument("--latency-only", action="store_true")
    ap.add_argument("--auto-wait", type=int, default=100, help="seconds to wait for the background TI poll")
    a = ap.parse_args()
    if not any(k in str(a.lake) for k in ("hlta-scratch", "scratchpad/lakes")):
        sys.exit("refusing: --lake must be a scratch lake")
    if a.seed_reported:
        return seed_reported(a.lake)
    base = a.base.rstrip("/")
    if a.latency_only:
        latency(base); return
    checks: list[tuple[str, str, object]] = []

    def chk(name, ok, got, gap=False):
        checks.append((name, "PASS" if ok else ("GAP" if gap else "FAIL"), got))

    def imp(name, content):
        t0 = time.time(); r = req(base, "POST", "/api/netlog/import", files=[(name, content)])
        f = (r.get("files") or [{}])[0] if isinstance(r, dict) and "files" in r else {"error": r}
        print(f"import {name}: {time.time()-t0:.1f}s inserted={f.get('inserted')} types={f.get('log_types')} "
              f"err={str(f.get('error'))[:120]}")
        f["_s"] = time.time() - t0
        return f

    def alerts():
        return req(base, "GET", "/api/netlog/alerts?limit=0")

    def by_uid(al):
        out: dict = {}
        for x in al:
            for u in (x.get("evidence") or {}).get("uids") or []:
                out.setdefault(str(u), []).append(x)
        return out

    def top(lst):
        return max((x["severity"] for x in lst or []), key=lambda s: RANK[s], default=None)

    req(base, "PUT", "/api/netlog/settings", {"home_prefixes": HOME})
    write_records(a.lake)
    print("refresh:", json.dumps(req(base, "POST", "/api/netlog/indicators/refresh"))[:300])
    ivs = g(base, "/api/netlog/indicators", value=D_SNI)
    chk("threatfox domain becomes an interval", bool(ivs) and isinstance(ivs, list), ivs if not ivs else len(ivs))
    mapped_iv = g(base, "/api/netlog/indicators", value=C2MAPPED_LIST)
    chk("feed listing ::ffff:a.b.c.d is findable by the plain IPv4", bool(mapped_iv), mapped_iv)

    H = "192.0.2.30"
    # 1. Suricata EVE: flows, alerts, packet-direction alerts, long-lived flows, CNAME DNS, TLS SNI
    eve_rows = [
        eve("flow", T("11:00:30"), H, 50001, C2A, 443, 9100000000000001, app_proto="tls",
            flow={"pkts_toserver": 10, "pkts_toclient": 9, "bytes_toserver": 2000, "bytes_toclient": 5000,
                  "start": iso(T("11:00:00")), "end": iso(T("11:00:30")), "age": 30, "state": "closed"}),
        eve("alert", T("11:05:00"), H, 50002, C2A, 443, 9100000000000002,
            alert={"action": "allowed", "gid": 1, "signature_id": 2999001, "signature": "ET MALWARE CriticBot2 CnC Beacon",
                   "category": "A Network Trojan was detected", "severity": 1}, direction="to_server"),
        # alert raised on the C2's *response* packet: src/dest are packet direction, flow is home -> C2
        eve("alert", T("11:06:00"), C2TOCL, 443, H, 50003, 9100000000000003,
            alert={"action": "allowed", "signature_id": 2999002, "signature": "ET MALWARE CriticBot2 CnC Response",
                   "category": "A Network Trojan was detected", "severity": 1},
            direction="to_client", flow={"src_ip": H, "dest_ip": C2TOCL, "src_port": 50003, "dest_port": 443,
                                         "start": iso(T("11:05:59"))}),
        # signature alert to an unlisted address (Security Onion's Alerts page is built on these)
        eve("alert", T("11:07:00"), H, 50004, "203.0.113.44", 80, 9100000000000004,
            alert={"action": "allowed", "signature_id": 2999003, "signature": "ET MALWARE Generic Stealer Exfil POST",
                   "category": "A Network Trojan was detected", "severity": 1}, direction="to_server"),
        # long-lived flow: started 11:00 while C2EVE listed (10:00-12:00), logged at 13:00 after removal
        eve("flow", T("13:00:00"), H, 50005, C2EVE, 443, 9100000000000005, app_proto="tls",
            flow={"bytes_toserver": 900000, "bytes_toclient": 4000000, "start": iso(T("11:00:00")),
                  "end": iso(T("13:00:00")), "age": 7200, "state": "closed"}),
        # EVE DNS with a CNAME chain to the threatfox domain
        eve("dns", T("11:08:00"), H, 53001, "192.0.2.1", 53, 9100000000000006, proto="UDP",
            dns={"version": 2, "type": "answer", "rrname": "www.innocent.example", "rrtype": "A", "rcode": "NOERROR",
                 "answers": [{"rrname": "www.innocent.example", "rrtype": "CNAME", "rdata": D_CNAME},
                             {"rrname": D_CNAME, "rrtype": "A", "rdata": "203.0.113.45"}]}),
        eve("tls", T("11:09:00"), H, 50006, "203.0.113.46", 443, 9100000000000007,
            tls={"sni": D_SNI, "version": "TLS 1.2"}),
    ]
    # 2. Mixed-type bundles
    mixed = [conn("MXC1", T("11:10:00"), H, C2A, 443), dns("MXD1", T("11:10:01"), H, "mixed.example", [C2A]),
             ssl("MXS1", T("11:10:02"), H, "203.0.113.47", D_SNI), http("MXH1", T("11:10:03"), H, "203.0.113.48", D_HOST),
             eve("flow", T("11:10:04"), H, 50007, C2A, 443, 9100000000000008,
                 flow={"bytes_toserver": 100, "bytes_toclient": 100, "age": 1, "state": "closed"})]
    zeek_tsv = (b"#separator \\x09\n#fields\tts\tuid\tid.orig_h\n#types\ttime\tstring\taddr\n"
                + f"{T('11:11:00')}\tMXTSV\t{H}\n".encode())
    member_a = gzip.compress(nd(mixed[:2]))
    member_b = gzip.compress(nd(mixed[2:] + [conn("MXMM1", T("11:10:05"), H, "203.0.113.70", 443)]))
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        for nm, rows in (("conn.log", [conn("TARC1", T("11:12:00"), H, C2A, 443)]),
                         ("dns.log", [dns("TARD1", T("11:12:01"), H, "tar.example", [C2A])])):
            data = nd(rows); ti = tarfile.TarInfo(nm); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
    # 3. Long-lived Zeek sessions crossing a removal (C2B listed 10:00-12:00)
    longs = [conn("LLX1", T("11:30:00"), H, C2B, 443, dur=7200.0, ob=4_000_000, rb=9_000_000),   # starts in, ends after
             conn("LLX2", T("09:30:00"), H, C2B, 443, dur=4 * 3600.0, ob=4_000_000, rb=9_000_000),  # spans whole listing
             conn("LLX3", T("12:30:00"), H, C2B, 443, dur=60.0)]                                   # after removal
    # 4. IPv4-mapped IPv6
    mapped = [conn("MAP1", T("11:20:00"), "::ffff:192.0.2.40", "::ffff:" + C2MAP, 443),
              conn("MAP2", T("11:21:00"), "192.0.2.40", C2MAPPED_LIST, 443),
              conn("MAP3", T("11:22:00"), "::ffff:192.0.2.41", "198.51.100.250", 443, ob=1, rb=1)]
    # 5. DNS CNAME chains (Zeek): CNAME target listed; the final A record is unlisted
    cname = [dns("CN1", T("11:25:00"), H, "www.innocent.example", ["cdn.innocent.example", D_CNAME, "203.0.113.49"]),
             dns("CN2", T("11:25:30"), H, "a.b." + D_CNAME + ".", ["203.0.113.50"]),       # trailing dot, subdomain
             dns("CN3", T("11:26:00"), H, "cname-c2.example.attacker-free.example", ["203.0.113.51"])]  # not a subdomain
    # 6. SNI / Host
    names = [ssl("SN1", T("11:27:00"), H, "203.0.113.52", D_SNI.upper()),
             ssl("SN2", T("11:27:10"), H, "203.0.113.53", "x." + D_SNI + "."),
             http("HT1", T("11:27:20"), H, "203.0.113.54", D_HOST),
             http("HT2", T("11:27:30"), H, "203.0.113.55", D_HOST + ":8080"),
             ssl("RP1", T("11:27:40"), H, "203.0.113.56", D_REP),
             http("RP2", T("11:27:50"), H, "203.0.113.57", D_REP)]
    # 7. Many devices behind one IP: 8 MACs take turns on 192.0.2.50 (l2 evidence), each contacts C2NAT once
    macs = [f"00:00:5e:00:53:{0x40 + i:02x}" for i in range(8)]
    nat = []
    for k in range(16):
        i = k % 8
        nat.append(conn(f"NAT{k:02d}", T("11:00:00") + k * 600, "192.0.2.50", C2NAT, 443,
                        orig_l2_addr=macs[i], resp_l2_addr="00:00:5e:00:53:01"))

    imp("eve-r2.json", nd(eve_rows))
    f_mixed = imp("mixed-bundle.log", nd(mixed))
    f_mm = imp("mixed-multimember.log.gz", member_a + member_b)
    f_tsv = imp("mixed-with-tsv.log", nd(mixed[:1]) + zeek_tsv)
    f_tar = imp("zeek-logs.tar.gz", tar_buf.getvalue())
    imp("long.log", nd(longs)); imp("mapped.log", nd(mapped)); imp("cname.log", nd(cname))
    imp("names.log", nd(names)); imp("nat-many.log", nd(nat))

    al = alerts(); U = by_uid(al)
    # EVE
    chk("EVE flow to C2 -> high", top(U.get("9100000000000001")) == "high", top(U.get("9100000000000001")))
    chk("EVE alert to C2 (to_server) -> high", top(U.get("9100000000000002")) == "high", top(U.get("9100000000000002")))
    chk("EVE alert on C2's to_client packet (flow is home->C2) -> high", top(U.get("9100000000000003")) == "high",
        [(x["severity"], x["rule"]) for x in U.get("9100000000000003") or []])
    sig = [x for x in al if "Stealer" in json.dumps(x)]
    chk("Suricata signature alert (unlisted dest) surfaces as an HLTA alert", bool(sig), len(sig), gap=True)
    sa = g(base, "/api/netlog/aggregate", group="raw.alert.signature", query="log_type:eve_alert")
    chk("EVE signatures groupable via raw.alert.signature",
        isinstance(sa, dict) and any("Stealer" in str(x.get("key")) for x in sa.get("groups", [])), sa if "http_error" in sa else len(sa.get("groups", [])))
    chk("EVE long flow started while listed, logged after removal -> >= medium",
        RANK[top(U.get("9100000000000005"))] >= 2, [(x["severity"], x["rule"]) for x in U.get("9100000000000005") or []])
    row = (g(base, "/api/netlog/connections", uid="9100000000000005").get("rows") or [{}])[0]
    chk("EVE flow ts is flow.start (11:00), not the log time (13:00)", str(row.get("ts", "")).startswith(f"{DAY}T11:00"), row.get("ts"))
    chk("EVE DNS CNAME rdata naming a C2 domain -> high", top(U.get("9100000000000006")) == "high",
        top(U.get("9100000000000006")))
    chk("EVE TLS SNI of C2 domain -> high", top(U.get("9100000000000007")) == "high", top(U.get("9100000000000007")))
    # mixed bundles
    want = {"conn", "dns", "ssl", "http", "eve_flow"}
    chk("mixed NDJSON: all 5 types detected", want <= set((f_mixed.get("log_types") or {}).keys()), f_mixed.get("log_types"))
    chk("mixed multi-member gz: all 6 rows read (5 dup rk)", (f_mm.get("rows") or 0) == 6 and f_mm.get("inserted") == 1, (f_mm.get("rows"), f_mm.get("inserted")))
    chk("NDJSON with trailing TSV block: JSON kept, TSV reported", (f_tsv.get("inserted") is not None and not f_tsv.get("error")
        and (f_tsv.get("skipped_lines") or 0) + len(f_tsv.get("warnings") or []) >= 1) or "TSV" in str(f_tsv.get("error")), (f_tsv.get("inserted"), f_tsv.get("skipped"), f_tsv.get("error")))
    tar_ok = (f_tar.get("inserted") or 0) >= 2 or ("tar" in str(f_tar.get("error")).lower())
    chk("tar.gz of conn.log+dns.log: imported or refused with a tar-specific message", tar_ok,
        (f_tar.get("inserted"), str(f_tar.get("error"))[:100], f_tar.get("log_types")))
    chk("C2 contact inside tar.gz alerts high", top(U.get("TARC1")) == "high", top(U.get("TARC1")), gap=True)
    for u, w in (("MXC1", "high"), ("MXD1", "high"), ("MXS1", "high"), ("MXH1", "high")):
        chk(f"mixed {u} -> {w}", top(U.get(u)) == w, top(U.get(u)))
    # long-lived
    chk("LLX1 starts while listed, runs past removal -> high", top(U.get("LLX1")) == "high", top(U.get("LLX1")))
    chk("LLX2 spans whole listing (4h, 13MB) -> >= medium", RANK[top(U.get("LLX2"))] >= 2,
        [(x["severity"], x["rule"]) for x in U.get("LLX2") or []])
    chk("LLX3 after removal -> not high/medium", RANK[top(U.get("LLX3"))] <= 1, top(U.get("LLX3")))
    # IPv4-mapped
    chk("MAP1 ::ffff:home -> ::ffff:C2 -> high (home recognised)", top(U.get("MAP1")) == "high",
        [(x["severity"], x["rule"], x["direction"]) for x in U.get("MAP1") or []])
    chk("MAP2 plain IPv4 vs feed listing ::ffff:IPv4 -> high", top(U.get("MAP2")) == "high", top(U.get("MAP2")))
    q4 = g(base, "/api/netlog/connections", query=f"ip:{C2MAP}")
    chk("ip:<v4> finds rows logged as ::ffff:<v4>", q4.get("total", 0) >= 1, q4.get("total"))
    qc = g(base, "/api/netlog/connections", query="ip:198.51.100.250/32")
    chk("ip:<v4>/32 CIDR finds ::ffff:<v4> rows", qc.get("total", 0) >= 1, qc.get("total"))
    devs = g(base, "/api/netlog/devices", q="192.0.2.41", limit=10)
    mdevs = g(base, "/api/netlog/devices", q="::ffff:192.0.2.41", limit=10)
    chk("::ffff:192.0.2.41 and 192.0.2.41 are one device", len(devs) + len(mdevs) <= 1 or
        (devs and mdevs and devs[0]["id"] == mdevs[0]["id"]), [d["id"] for d in devs] + [d["id"] for d in mdevs])
    # CNAME
    chk("CN1 Zeek CNAME in answers names C2 domain -> high", top(U.get("CN1")) == "high", top(U.get("CN1")))
    chk("CN2 query 'a.b.<c2>.' (trailing dot) -> high", top(U.get("CN2")) == "high", top(U.get("CN2")))
    chk("CN3 lookalike (c2 domain as a label prefix) -> no alert", RANK[top(U.get("CN3"))] <= 0, top(U.get("CN3")))
    # SNI / Host
    chk("SN1 uppercase SNI -> high", top(U.get("SN1")) == "high", top(U.get("SN1")))
    chk("SN2 subdomain SNI with trailing dot -> high", top(U.get("SN2")) == "high", top(U.get("SN2")))
    chk("HT1 http Host -> high", top(U.get("HT1")) == "high", top(U.get("HT1")))
    chk("HT2 http Host with :port -> high", top(U.get("HT2")) == "high", top(U.get("HT2")))
    rep = g(base, "/api/netlog/indicators", value=D_REP)
    if rep:
        chk("RP1 SNI of a reported domain -> low alert", top(U.get("RP1")) == "low", top(U.get("RP1")))
        chk("RP2 Host of a reported domain -> low alert", top(U.get("RP2")) == "low", top(U.get("RP2")))
    else:
        checks.append(("reported-domain cases (run --seed-reported with the server stopped)", "SKIP", None))
    # many devices behind one IP
    nat_al = [x for x in al if x["indicator"] == C2NAT]
    want_dev = {f"mac:{m}" for m in macs} | set(macs)
    got_dev = {x["device"] for x in nat_al}
    chk("8 MACs sharing 192.0.2.50: one alert per MAC device", len(got_dev & want_dev) == 8,
        (len(nat_al), sorted(got_dev)[:4]))
    wrong = []
    for x in nat_al:
        for u in x["evidence"].get("uids") or []:
            k = int(u[3:]); exp = macs[k % 8]
            if exp not in str(x["device"]):
                wrong.append((u, x["device"]))
    chk("each NAT uid attributed to the MAC that held the IP then", not wrong, wrong[:4])
    d0 = f"mac:{macs[0]}" if any(d.startswith("mac:") for d in got_dev) else macs[0]
    agg = g(base, "/api/netlog/aggregate", group="device", query=f"device:{d0} ip:{C2NAT}")
    keys = [x["key"] for x in agg.get("groups", [])] if isinstance(agg, dict) else agg
    chk("device:<mac0> filter + group=device shows only mac0 (filter is time-aware)", keys == [d0], keys)
    cnt = g(base, "/api/netlog/connections", query=f"device:{d0} ip:{C2NAT}", limit=0)
    chk("device:<mac0> returns only mac0's 2 rows", cnt.get("total") == 2, cnt.get("total"))

    # 8. ten imports in a row: drift
    drift = []
    base_sum = g(base, "/api/netlog/summary")
    for i in range(10):
        rows = [conn(f"DR{i}C2", T("14:00:00") + i * 60, "192.0.2.60", C2DRIFT, 443)]
        rows += [conn(f"DR{i}B{j:04d}", T("14:00:00") + i * 60 + j * 0.01, "2001:db8:1::d61", f"203.0.113.{100 + j % 50}", 443)
                 for j in range(1000)]
        rows += [dns(f"DR{i}D", T("14:00:00") + i * 60, "192.0.2.60", "drift.example", [C2DRIFT])]
        f = imp(f"drift-{i}.log", nd(rows))
        s = g(base, "/api/netlog/summary")
        a_ = [x for x in alerts() if x["indicator"] == C2DRIFT]
        tot = g(base, "/api/netlog/aggregate", group="log_type", query="uid:DR*").get("total")
        drift.append((f.get("inserted"), s["rows"] - base_sum["rows"], len(a_), sum(x["count"] for x in a_), tot))
    exp = [(1002, 1002 * (i + 1), 1, 2 * (i + 1), 1002 * (i + 1)) for i in range(10)]
    chk("10 drift imports: inserted/rows/alerts/alert rows/aggregate exact each step", drift == exp,
        [d for d, e in zip(drift, exp) if d != e][:3] or drift[-1])
    before = [(x["id"], x["count"], x["severity"]) for x in alerts() if x["indicator"] == C2DRIFT]
    for _ in range(2):
        req(base, "POST", "/api/netlog/rehunt?days=3650")
    after = [(x["id"], x["count"], x["severity"]) for x in alerts() if x["indicator"] == C2DRIFT]
    chk("2 full re-hunts change nothing", before == after, (before, after))
    rd = req(base, "POST", "/api/netlog/import", files=[("drift-3.log.gz", gzip.compress(nd(
        [conn("DR3C2", T("14:03:00"), "192.0.2.60", C2DRIFT, 443)] +
        [conn(f"DR3B{j:04d}", T("14:03:00") + j * 0.01, "2001:db8:1::d61", f"203.0.113.{100 + j % 50}", 443) for j in range(1000)] +
        [dns("DR3D", T("14:03:00"), "192.0.2.60", "drift.example", [C2DRIFT])])))])
    chk("re-import of drift-3 as .gz is a duplicate", (rd.get("files") or [{}])[0].get("duplicate") is True,
        (rd.get("files") or [{}])[0].get("duplicate"))
    dv = g(base, "/api/netlog/devices", q="2001:db8:1::d61", limit=5)
    chk("device 2001:db8:1::d61 conns == 10000 after 10 imports", bool(dv) and dv[0].get("conns") == 10000,
        dv[0].get("conns") if dv else None)

    # 9. re-hunt after a feed delta: traffic first, listing later
    imp("late.log", nd([conn("LATE1", T("15:00:00"), H, C2LATE, 443), conn("AUTO1", T("15:30:00"), H, C2AUTO, 443)]))
    s0 = top(by_uid(alerts()).get("LATE1"))
    write_rec(a.lake, "feodo_c2", "143000", [feo(C2LATE)])
    rr = req(base, "POST", "/api/netlog/indicators/refresh")
    s1 = top(by_uid(alerts()).get("LATE1"))
    chk("listing delta (14:30) after import: LATE1 none -> high after refresh", s0 in (None, "info") and s1 == "high", (s0, s1, rr.get("changed") if isinstance(rr, dict) else rr))
    # backfill: a file that sorts before already-applied ones
    write_rec(a.lake, "feodo_c2", "110000", [{"key": f"{C2A}:443", "op": "del"}])
    req(base, "POST", "/api/netlog/indicators/refresh")
    iv = g(base, "/api/netlog/indicators", value=C2A, source="feodo_c2")
    ends = [x.get("end") for x in iv] if isinstance(iv, list) else iv
    chk("backfilled del (11:00) closes C2A interval on replay", any(e and "T11:00" in str(e) for e in ends), ends)
    mx = top(by_uid(alerts()).get("MXC1"))
    chk("MXC1 (11:10, after backfilled removal) drops to info/historical", RANK[mx] <= 0, mx)
    # automatic: background TI poll without calling refresh
    write_rec(a.lake, "feodo_c2", "150000", [feo(C2AUTO)])
    t0 = time.time(); auto = None
    while time.time() - t0 < a.auto_wait:
        auto = top(by_uid(alerts()).get("AUTO1"))
        if auto == "high":
            break
        time.sleep(5)
    chk(f"background poll re-hunts within {a.auto_wait}s (AUTO1 -> high)", auto == "high", (auto, round(time.time() - t0)))

    # 10. alert explosion: 50k hits from one scanner + 20 scanners x 500
    rows = [conn(f"SC{i:05d}", T("16:00:00") + i * 0.5, SCAN, f"192.0.2.{1 + i % 250}", [22, 23, 445, 3389][i % 4],
                 op=40000 + i % 20000, state="S0", ob=0, rb=0, dur=0.0) for i in range(50_000)]
    rows += [conn(f"SM{i:05d}", T("17:00:00") + i * 0.3, f"198.51.100.{180 + i % 20}", f"192.0.2.{1 + i % 250}", 22,
                  op=41000 + i, state="REJ", ob=0, rb=0, dur=0.0) for i in range(10_000)]
    n_before = len(alerts())
    f = imp("scanners.log.gz", gzip.compress(nd(rows)))
    al = alerts()
    sc = [x for x in al if x["indicator"] == SCAN]
    many = [x for x in al if x["indicator"].startswith("198.51.100.1") and 180 <= int(x["indicator"].rsplit(".", 1)[1]) < 200]
    chk("50k hits from one scanner -> 1 info alert", len(sc) == 1 and sc[0]["severity"] == "info" and sc[0]["count"] == 50_000,
        [(x["severity"], x["count"], x["rule"]) for x in sc][:3])
    chk("20 scanners x 500 -> 20 alerts, none above info", len(many) == 20 and all(x["severity"] == "info" for x in many),
        (len(many), {x["severity"] for x in many}))
    chk("new alerts from 60k scanner rows <= 21", len(al) - n_before <= 21, len(al) - n_before)
    if sc:
        d = req(base, "GET", f"/api/netlog/alerts/{sc[0]['id']}", raw=True)
        chk("scanner alert detail payload < 2 MB", d[0] == 200 and len(d[1]) < 2_000_000, (d[0], len(d[1])))
        chk("evidence uids capped at 200", len(sc[0]["evidence"].get("uids", [])) <= 200, len(sc[0]["evidence"].get("uids", [])))
    ag = g(base, "/api/netlog/alerts/aggregate", group="rule", query="-severity:info")
    chk("alerts/aggregate -severity:info hides scanner noise", isinstance(ag, dict) and not any(
        x["key"] == "scanner_inbound" for x in ag.get("groups", [])), [x["key"] for x in ag.get("groups", [])][:8])
    chk("scanner import (60k rows) < 10 s", f.get("_s", 99) < 10, round(f.get("_s", 99), 1))

    # 11. query grammar: injection, quoting, unicode, exclude-only
    total = g(base, "/api/netlog/summary")["rows"]
    inj = [
        ("raw.x');DROP TABLE netlog;--:1", "connections"),
        ("raw.a'b:1", "connections"),
        ("ts) OR (1=1:1", "connections"),
        ("log_type:conn' OR '1'='1", "connections"),
        ("raw.\"x\":1", "connections"),
        ("raw.x\\\":1", "connections"),
        ("raw.$..*:1", "connections"),
        ("raw..:1", "connections"),
        ("raw.-:1", "connections"),
    ]
    for q, _ in inj:
        st, body = req(base, "GET", "/api/netlog/connections?" + urllib.parse.urlencode({"query": q, "limit": 1}), raw=True)
        ok = st == 400 or (st == 200 and json.loads(body)["total"] == 0)
        chk(f"injection query {q!r}: 400 or 0 rows, never 500", ok, (st, body[:100]))
    for path, p in (("/api/netlog/aggregate", {"group": "raw.x');DROP TABLE netlog;--"}),
                    ("/api/netlog/aggregate", {"group": "resp_h", "distinct": "uid) FROM netlog; --"}),
                    ("/api/netlog/stats/timeline", {"split": "raw.a'b"}),
                    ("/api/netlog/stats/top", {"field": "1; DROP TABLE netlog"}),
                    ("/api/netlog/alerts", {"query": "evidence.x'):1"}),
                    ("/api/netlog/alerts/aggregate", {"group": "evidence.a\"b"}),
                    ("/api/netlog/connections", {"order": "asc; DROP TABLE netlog", "limit": 1}),
                    ("/api/netlog/stats/timeline", {"since_hours": "1) HOUR; DROP TABLE netlog; --"})):
        st, body = req(base, "GET", path + "?" + urllib.parse.urlencode(p), raw=True)
        chk(f"injection {path} {p}: no 500", st in (200, 400, 422), (st, body[:80]))
    chk("netlog intact after injection attempts", g(base, "/api/netlog/summary")["rows"] == total, total)
    # quoting
    r = g(base, "/api/netlog/connections", query='raw.user_agent:"curl/8.0 (x86_64)"', limit=5)
    chk('quoted value with spaces/parens matches', r.get("total", 0) >= 1, r.get("total", r))
    st, body = req(base, "GET", "/api/netlog/connections?" + urllib.parse.urlencode({"query": 'host:"unterminated'}), raw=True)
    chk("unbalanced quote -> 400 not 500", st == 400, (st, body[:80]))
    st, body = req(base, "GET", "/api/netlog/connections?" + urllib.parse.urlencode({"query": "uri:*\\*", "limit": 1}), raw=True)
    chk("backslash in wildcard -> no 500", st in (200, 400), (st, body[:120]))
    r_any = g(base, "/api/netlog/connections", query="gate_php", limit=1)
    chk("text word 'gate_php' does not match 'gate.php' (_ is literal)", r_any.get("total") == 0, r_any.get("total"))
    r_pct = g(base, "/api/netlog/connections", q="%", limit=1)
    chk("q=% is a literal percent (not match-all)", r_pct.get("total", 0) < total, (r_pct.get("total"), total))
    for q in (f"{D_HOST}:8080", "http://host-c2.example/gate.php", "[2001:db8::1]:443"):
        st, body = req(base, "GET", "/api/netlog/connections?" + urllib.parse.urlencode({"query": q, "limit": 1}), raw=True)
        chk(f"free text with a colon {q!r} searches text (not 400 unknown field)", st == 200, (st, body[:90]))
    r = g(base, "/api/netlog/connections", query=f'"{D_HOST}:8080"', limit=1)
    chk("quoted free text with colon finds HT2", r.get("total", 0) >= 1, r.get("total", r))
    # unicode
    imp("unicode.log", nd([http("UNI1", T("18:00:00"), H, "203.0.113.60", "bücher.example", uri="/naïve/日本"),
                           ssl("UNI2", T("18:00:01"), H, "203.0.113.61", "xn--bcher-kva.example")]))
    for q, want in (("host:bücher.example", 1), ("host:BÜCHER.EXAMPLE", 1), ("日本", 1), ("uri:*日本*", 1), ("text:naïve", 1)):
        r = g(base, "/api/netlog/connections", query=q, limit=5)
        chk(f"unicode {q!r} -> {want}", r.get("total") == want, r.get("total", r))
    # exclude-only
    total = g(base, "/api/netlog/summary")["rows"]
    lt = {x["key"]: x["count"] for x in g(base, "/api/netlog/aggregate", group="log_type", limit=0)["groups"]}
    r = g(base, "/api/netlog/connections", query="-log_type:dns", limit=1)
    chk("exclude-only -log_type:dns total == all - dns", r.get("total") == total - lt.get("dns", 0), (r.get("total"), total - lt.get("dns", 0)))
    r = g(base, "/api/netlog/connections", query="-ip:198.51.100.0/24 -ip:203.0.113.0/24 -ip:192.0.2.0/24", limit=1)
    r2 = g(base, "/api/netlog/connections", query="ip:198.51.100.0/24,203.0.113.0/24,192.0.2.0/24", limit=1)
    chk("exclude-only CIDRs + include CIDRs partition the rows", (r.get("total") or 0) + (r2.get("total") or 0) == total,
        (r.get("total"), r2.get("total"), total))
    r = g(base, "/api/netlog/connections", not_ip=C2A, limit=1); r2 = g(base, "/api/netlog/connections", ip=C2A, limit=1)
    chk("not_ip + ip partition the rows", r.get("total", 0) + r2.get("total", 0) == total, (r.get("total"), r2.get("total"), total))
    r = g(base, "/api/netlog/connections", query="-raw.alert.signature:*", limit=1)
    chk("-raw.alert.signature:* keeps rows without the field", r.get("total") == total - (lt.get("eve_alert", 0)), (r.get("total"), total))
    r = g(base, "/api/netlog/aggregate", group="resp_p", query="-resp_p:<1024 -resp_p:null", limit=5)
    chk("exclude-only numeric '-resp_p:<1024' leaves only >= 1024", isinstance(r, dict) and all((x["key"] or 0) >= 1024 for x in r.get("groups", [])),
        [x["key"] for x in r.get("groups", [])][:5] if isinstance(r, dict) else r)
    r = g(base, "/api/netlog/alerts", query="-severity:info,low", limit=0)
    chk("alerts exclude-only -severity:info,low", isinstance(r, list) and all(x["severity"] in ("high", "medium") for x in r), len(r))
    # ip literal normalisation
    r1 = g(base, "/api/netlog/connections", query="ip:2001:DB8:0:0:0:0:0:5", limit=1)
    imp("v6norm.log", nd([conn("V6N", T("18:10:00"), "2001:db8:1::5", "2001:db8:bad::99", 443)]))
    r1 = g(base, "/api/netlog/connections", query="ip:2001:DB8:BAD:0:0:0:0:99", limit=1)
    chk("ip:<uncompressed uppercase IPv6> finds the row", r1.get("total") == 1, r1.get("total", r1))
    r1 = g(base, "/api/netlog/connections", query="resp_h:2001:0db8:0bad::0099", limit=1)
    chk("resp_h:<zero-padded IPv6> finds the row", r1.get("total") == 1, r1.get("total", r1))
    # hunt-class shape checks (Security Onion Hunt / Dashboards / Alerts)
    r = g(base, "/api/netlog/aggregate", group="resp_p", order="asc", limit=3)
    asc = [x["count"] for x in r.get("groups", [])] if isinstance(r, dict) else []
    chk("aggregate supports 'fewest occurrences' (ascending)", asc == sorted(asc) and len(asc) == 3 and asc[0] <= asc[-1] and
        asc[0] == min(x["count"] for x in g(base, "/api/netlog/aggregate", group="resp_p", limit=0)["groups"]), asc, gap=True)
    r = g(base, "/api/netlog/aggregate", group="resp_p", limit=5, offset=5)
    r0 = g(base, "/api/netlog/aggregate", group="resp_p", limit=10)
    chk("aggregate paging (offset) for group tables", isinstance(r, dict) and [x["key"] for x in r["groups"]] ==
        [x["key"] for x in r0["groups"]][5:10], None, gap=True)
    r = g(base, "/api/netlog/connections", order="bytes", limit=3)
    b = [(x.get("orig_bytes") or 0) + (x.get("resp_bytes") or 0) for x in r.get("rows", [])]
    chk("connections sortable by a column (bytes)", b == sorted(b, reverse=True) and b and b[0] >= 13_000_000, b, gap=True)
    tl = g(base, "/api/netlog/stats/timeline", bucket="day", query=f"ip:{SCAN}")
    al_day = sum(sum((x.get("alerts") or {}).values()) for x in tl)
    chk("log timeline alert overlay respects the query filter", al_day <= 2, al_day)

    # report
    fails = gaps = 0
    print()
    for n, st, got in checks:
        fails += st == "FAIL"; gaps += st == "GAP"
        print(f"{st:4s}  {n}  -> {json.dumps(got, default=str)[:220]}")
    print(f"\n{sum(1 for c in checks if c[1] == 'PASS')}/{len(checks)} passed, {fails} FAIL, {gaps} GAP")


if __name__ == "__main__":
    main()

"""Benign-traffic false-positive check: a day of ordinary home traffic to well-known sites.

The home network uses documentation prefixes and invented MACs. External names and addresses come
from fixtures/popular-sites.json: a hand-made list of well-known sites on documentation addresses (not
their real ones), so the check runs offline. It checks the rules and the allowlist, not real addresses against the
lists. Traffic includes DNS lookups (via public resolvers), TLS with SNI, some HTTP,
NTP to pool servers, and long-lived streaming sessions.

    uv run python tests/eval/netlog/benign_check.py --base http://127.0.0.1:8804

Pass: 0 high or medium alerts. Low alerts are listed with their rule and indicator so each can be explained.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import gzip
import json
import random
import sys
from pathlib import Path

import httpx

FIXTURE = Path(__file__).resolve().parents[3] / "osinthub" / "netlog" / "fixtures" / "popular-sites.json"
HOME = ["192.0.2.0/24", "2001:db8:1::/48"]
RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
NTP = [("0.pool.ntp.org", "162.159.200.1"), ("time.apple.com", "17.253.4.125"), ("time.windows.com", "20.101.57.9"),
       ("time.google.com", "216.239.35.0")]


def generate(seed: int = 7, day: str | None = None) -> tuple[bytes, dict]:
    rnd = random.Random(seed)
    doms = [d for d in json.loads(FIXTURE.read_text())["domains"] if d["a"]]
    base = dt.datetime.fromisoformat((day or dt.date.today().isoformat()) + "T00:00:00+00:00").timestamp()
    devices = [(f"192.0.2.{10 + i}", f"2001:db8:1:1::{10 + i:x}", f"00:00:5e:00:53:{0x80 + i:02x}") for i in range(12)]
    rows: list[dict] = []
    n = 0

    def uid():
        nonlocal n
        n += 1
        return f"CB{n:010d}"

    for ip4, ip6, mac in devices:
        rows.append({"ts": base + rnd.random() * 60, "uids": [uid()], "client_addr": ip4, "server_addr": "192.0.2.1",
                     "mac": mac, "host_name": f"home-{mac[-2:]}", "assigned_addr": ip4, "lease_time": 86400.0,
                     "msg_types": ["REQUEST", "ACK"]})
        favourites = rnd.sample(doms, 40)
        for _ in range(400):
            d = rnd.choice(favourites) if rnd.random() < 0.8 else rnd.choice(doms)
            t = base + rnd.random() * 86400
            v6 = bool(d["aaaa"]) and rnd.random() < 0.3
            src = ip6 if v6 else ip4
            dst = rnd.choice(d["aaaa"] if v6 else d["a"])
            name = d["domain"] if rnd.random() < 0.5 else "www." + d["domain"]
            res = rnd.choice(RESOLVERS)
            u = uid()
            rows.append({"ts": t, "uid": u, "id.orig_h": ip4, "id.orig_p": rnd.randint(1024, 65535), "id.resp_h": res,
                         "id.resp_p": 53, "proto": "udp", "trans_id": rnd.randint(1, 65535), "query": name,
                         "qtype_name": "AAAA" if v6 else "A", "rcode_name": "NOERROR",
                         "answers": d["aaaa"] if v6 else d["a"], "TTLs": [300.0] * len(d["aaaa"] if v6 else d["a"])})
            rows.append({"ts": t, "uid": u, "id.orig_h": ip4, "id.orig_p": 53000, "id.resp_h": res, "id.resp_p": 53,
                         "proto": "udp", "service": "dns", "duration": 0.02, "orig_bytes": 40, "resp_bytes": 120,
                         "conn_state": "SF", "history": "Dd", "orig_l2_addr": mac})
            long = rnd.random() < 0.05
            u = uid()
            rows.append({"ts": t + 0.05, "uid": u, "id.orig_h": src, "id.orig_p": rnd.randint(1024, 65535),
                         "id.resp_h": dst, "id.resp_p": 443, "proto": "tcp", "service": "ssl",
                         "duration": rnd.uniform(1800, 7200) if long else rnd.uniform(0.2, 60),
                         "orig_bytes": rnd.randint(500, 20000), "resp_bytes": rnd.randint(2000, 5_000_000 if long else 400_000),
                         "conn_state": "SF", "history": "ShADadFf", "orig_l2_addr": mac})
            rows.append({"ts": t + 0.06, "uid": u, "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst, "id.resp_p": 443,
                         "version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256", "server_name": name, "established": True})
            if rnd.random() < 0.05:
                u = uid()
                rows.append({"ts": t + 0.1, "uid": u, "id.orig_h": ip4, "id.orig_p": rnd.randint(1024, 65535),
                             "id.resp_h": d["a"][0], "id.resp_p": 80, "trans_depth": 1, "method": "GET", "host": name,
                             "uri": "/", "user_agent": "Mozilla/5.0", "status_code": 301})
        for k in range(24):
            host, ntp = NTP[k % len(NTP)]
            rows.append({"ts": base + k * 3600 + rnd.random() * 60, "uid": uid(), "id.orig_h": ip4, "id.orig_p": 123,
                         "id.resp_h": ntp, "id.resp_p": 123, "proto": "udp", "service": "ntp", "duration": 0.03,
                         "orig_bytes": 48, "resp_bytes": 48, "conn_state": "SF", "history": "Dd", "orig_l2_addr": mac})
    rows.sort(key=lambda r: r["ts"])
    data = gzip.compress(("\n".join(json.dumps(r) for r in rows) + "\n").encode())
    return data, {"rows": len(rows), "domains": len(doms), "devices": len(devices)}


def seed_reports(lake: Path) -> None:
    """With the server STOPPED: add two invented articles that report popular domains and addresses the way
    real write-ups do (named in prose, linked as references, and listed in an IOC appendix)."""
    import duckdb
    doms = [d for d in json.loads(FIXTURE.read_text())["domains"] if d["a"]]
    pop = [d["domain"] for d in doms[:6]]
    ips = ["8.8.8.8", "1.1.1.1"] + [d["a"][0] for d in doms[:4]] + [d["a"][0] for d in doms[-6:]]
    now = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    c = duckdb.connect(str(lake / "db" / "hub.duckdb"),   # no extension downloads
                       config={"autoinstall_known_extensions": False, "autoload_known_extensions": False})
    texts = {
        "benign-check-a": ("Vendor A", "Attackers abused " + ", ".join(pop[:3]) + " and public DNS 8.8.8.8 for staging.\n\n"
                           "Indicators of Compromise\n\n" + "\n".join(i.replace(".", "[.]") for i in ips)
                           + "\n" + "\n".join(p.replace(".", "[.]") for p in pop[3:])),
        "benign-check-b": ("Vendor B", "Reference: see https://" + pop[0] + "/security and " + pop[1] + ".\n\n"
                           "The loader resolved " + doms[-1]["domain"] + " during testing."),
    }
    for aid, (src, text) in texts.items():
        c.execute("DELETE FROM articles WHERE id = ?", [aid])
        c.execute("""INSERT INTO articles (id, url, source, title, published, fetched_at, text, status)
                     VALUES (?, ?, ?, ?, ?, ?, ?, 'ok')""", [aid, f"https://vendor.example/{aid}", src, aid, now, now, text])
        vals = [("domain", d) for d in pop + [doms[-1]["domain"]]] + [("ip", i) for i in ips]
        for kind, v in vals:
            eid = f"{kind}:{v}"
            # plain inserts: the entities tables have no primary key
            c.execute("INSERT INTO entities (id, type, name, aliases, attrs, first_seen, last_seen) "
                      "SELECT ?, ?, ?, [], '{}', ?, ? WHERE NOT EXISTS (SELECT 1 FROM entities WHERE id = ?)",
                      [eid, kind, v, now, now, eid])
            c.execute("INSERT INTO mentions SELECT ?, 'article', ?, 'mentioned', 'regex', 0.9, ? WHERE NOT EXISTS "
                      "(SELECT 1 FROM mentions WHERE entity_id = ? AND ref_id = ?)", [eid, aid, now, eid, aid])
    c.close()
    print(f"seeded 2 articles naming {len(pop) + 1} popular domains and {len(ips)} addresses")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base")
    ap.add_argument("--seed-reports", type=Path, metavar="LAKE", help="with the server stopped, seed invented reports")
    ap.add_argument("--day", help="YYYY-MM-DD of the traffic (default today, so reported IOCs are in their interval)")
    a = ap.parse_args()
    if a.seed_reports:
        seed_reports(a.seed_reports)
        return 0
    c = httpx.Client(base_url=a.base.rstrip("/"), timeout=600)
    c.put("/api/netlog/settings", json={"home_prefixes": HOME}).raise_for_status()
    c.post("/api/netlog/indicators/refresh").raise_for_status()
    data, info = generate(day=a.day)
    r = c.post("/api/netlog/import", files=[("files", ("benign-sites.log.gz", data))]).json()["files"][0]
    print(f"imported {r.get('inserted')} rows ({info['domains']} domains, {info['devices']} devices) err={r.get('error')}")
    alerts = c.get("/api/netlog/alerts", params={"limit": 0}).json()
    mine = [x for x in alerts if any(str(u).startswith("CB") for u in x["evidence"].get("uids") or [])]
    sev = collections.Counter(x["severity"] for x in mine)
    print("alerts by severity:", dict(sev))
    for x in sorted(mine, key=lambda x: x["severity"]):
        if x["severity"] != "info":
            ind = x["evidence"]["indicator"]
            print(f"  {x['severity']:6s} {x['rule']:28s} {x['indicator']:40s} {x['source']} "
                  f"{json.dumps(ind.get('meta'), default=str)[:120]}")
    st = c.get("/api/netlog/status").json().get("reported")
    print("reported loader:", json.dumps(st, default=str)[:600])
    ok = sev.get("high", 0) == 0 and sev.get("medium", 0) == 0
    print("PASS" if ok else "FAIL", "(0 high/medium required)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

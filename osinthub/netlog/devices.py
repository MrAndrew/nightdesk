"""Home prefixes and devices.

A device is identified by its MAC when one is known (DHCP, conn l2 fields, or an EUI-64 IPv6 address),
otherwise by its IP. IPv6 privacy addresses without MAC evidence are linked to a MAC device in the same
/64 (or, less surely, any MAC device) when their behaviour (names looked up, SNI, destinations) matches.
netlog_ipdev records which device held each home IP from when, so alerts use the device at the time.

The user's names, types, owners and notes (netlog_device_labels) and merges (netlog_device_merges) are kept apart
from the rebuilt tables, keyed by device id, so they survive every rebuild and re-import. A merge is applied while
rebuilding: the merged device's addresses are recorded under the device it was merged into.
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
from collections import Counter, defaultdict

from .. import db
from . import ipnum, util

EPOCH = "1970-01-01 00:00:00+00"

IPDEV_SQL = """CREATE TABLE IF NOT EXISTS netlog_ipdev (ip VARCHAR, from_ts TIMESTAMPTZ, device VARCHAR,
               how VARCHAR, confidence VARCHAR)"""


# ------------------------------------------------------------------ IP numbers
def update_ipnum(cur, where: str = "", params: list | tuple = ()) -> int:
    """Add every IP seen in netlog rows (orig, resp, DNS answers) to netlog_ipnum. Caller holds the write lock."""
    w = f"WHERE {where}" if where else ""
    new = [r[0] for r in cur.execute(f"""
        WITH r AS (SELECT orig_h, resp_h, answers FROM netlog {w}),
        ips AS (SELECT orig_h AS ip FROM r UNION SELECT resp_h FROM r
                UNION SELECT unnest(answers) FROM r WHERE answers IS NOT NULL)
        SELECT ip FROM ips WHERE ip IS NOT NULL AND (ip LIKE '%.%.%.%' OR ip LIKE '%:%')
          AND ip NOT IN (SELECT ip FROM netlog_ipnum)""", list(params)).fetchall()]
    rows = []
    for ip in new:
        if ipnum.special(ip):
            continue
        n = ipnum.ip_int(ip)
        if n is not None:
            rows.append({"ip": ip, "n": str(n), "v6": ":" in ip and not ip.startswith("::ffff:")})
    if not rows:
        return 0
    p = util.scratch("ipnum")
    util.write_ndjson(p, rows)
    try:
        cur.execute(f"""INSERT OR IGNORE INTO netlog_ipnum SELECT ip, n::UHUGEINT, v6
                        FROM {util.read_src(p, {'ip': 'VARCHAR', 'n': 'VARCHAR', 'v6': 'BOOLEAN'})}""")
    finally:
        p.unlink(missing_ok=True)
    return len(rows)


# ------------------------------------------------------------------ home prefixes
def suggest(limit: int = 3) -> list[dict]:
    """The most frequent originator /24s and /64s in conn logs: likely home prefixes."""
    total = db.query("SELECT count(*) AS n FROM netlog WHERE log_type = 'conn' AND orig_h IS NOT NULL")[0]["n"] or 0
    if not total:
        return []
    v4 = db.query(r"""SELECT regexp_extract(orig_h, '^(\d+\.\d+\.\d+)\.\d+$', 1) || '.0/24' AS prefix, count(*) AS n
                      FROM netlog WHERE log_type = 'conn' AND orig_h LIKE '%.%.%.%' AND orig_h NOT LIKE '%:%'
                      GROUP BY 1 HAVING prefix <> '.0/24' ORDER BY n DESC LIMIT ?""", [limit])
    c6: Counter = Counter()
    for r in db.query("""SELECT orig_h, count(*) AS n FROM netlog WHERE log_type = 'conn' AND orig_h LIKE '%:%'
                         GROUP BY 1 ORDER BY n DESC LIMIT 50000"""):
        p = ipnum.prefix_of(r["orig_h"])
        if p and not p.startswith("fe80"):
            c6[p] += r["n"]
    out = [{"prefix": r["prefix"], "rows": r["n"], "share": round(r["n"] / total, 3)} for r in v4]
    out += [{"prefix": p, "rows": n, "share": round(n / total, 3)} for p, n in c6.most_common(limit)]
    return [o for o in sorted(out, key=lambda o: -o["rows"]) if o["share"] >= 0.05]


def effective_prefixes() -> tuple[list[str], str]:
    """(prefixes, how): the user's setting, or private ranges plus the top suggested /24 and /64."""
    s = util.settings()
    if s.get("home_prefixes"):
        return list(s["home_prefixes"]), "settings"
    sug = suggest(2)
    best4 = [o["prefix"] for o in sug if ":" not in o["prefix"]][:1]
    best6 = [o["prefix"] for o in sug if ":" in o["prefix"]][:1]
    return util.unique_prefixes(list(ipnum.PRIVATE) + best4 + best6), "auto"


def home_table(cur) -> list[str]:
    """Create temp table _nl_home(lo, hi) for the effective home prefixes. Returns the prefixes."""
    prefs, _ = effective_prefixes()
    cur.execute("CREATE OR REPLACE TEMP TABLE _nl_home (prefix VARCHAR, lo UHUGEINT, hi UHUGEINT)")
    vals = []
    for p in prefs:
        r = ipnum.net_range(p)
        if r:
            vals.append((r[2], str(r[0]), str(r[1])))
    if vals:
        cur.executemany("INSERT INTO _nl_home VALUES (?, ?::UHUGEINT, ?::UHUGEINT)", vals)
    cur.execute("""CREATE OR REPLACE TEMP TABLE _nl_homeip AS
                   SELECT DISTINCT i.ip, i.n, i.v6 FROM netlog_ipnum i JOIN _nl_home h ON i.n BETWEEN h.lo AND h.hi""")
    return prefs


# ------------------------------------------------------------------ per-file aggregates
# Devices are rebuilt from these small tables, not from netlog, so an import only scans its own rows.
AGG_SQL = """
CREATE TABLE IF NOT EXISTS netlog_agg_files (file_id VARCHAR PRIMARY KEY, added_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS netlog_agg_ip (ip VARCHAR, side VARCHAR, hr TIMESTAMPTZ, log_type VARCHAR, rows BIGINT,
    bo BIGINT, bi BIGINT, t0 TIMESTAMPTZ, t1 TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS netlog_agg_peer (orig_h VARCHAR, resp_h VARCHAR, day TIMESTAMPTZ, conns BIGINT, bytes BIGINT);
CREATE TABLE IF NOT EXISTS netlog_agg_name (ip VARCHAR, name VARCHAR, day TIMESTAMPTZ, n BIGINT);
CREATE TABLE IF NOT EXISTS netlog_agg_mac (ip VARCHAR, mac VARCHAR, how VARCHAR, first_ts TIMESTAMPTZ, last_ts TIMESTAMPTZ, rows BIGINT);
CREATE TABLE IF NOT EXISTS netlog_agg_host (key VARCHAR, name VARCHAR);
"""
CONN_TYPES = "('conn', 'eve_flow')"


def aggregate_file(cur, file_id: str) -> None:
    """Fold one file's rows into the aggregate tables. Caller holds the write lock."""
    _aggregate(cur, "file_id = ? AND ts IS NOT NULL", [file_id])
    cur.execute("INSERT OR REPLACE INTO netlog_agg_files VALUES (?, now())", [file_id])


def _aggregate(cur, w: str, p: list) -> None:
    cur.execute(f"""INSERT INTO netlog_agg_ip
        SELECT orig_h, 'o', date_trunc('hour', ts), log_type, count(*), sum(orig_bytes), sum(resp_bytes), min(ts), max(ts)
        FROM netlog WHERE {w} AND orig_h IS NOT NULL GROUP BY ALL
        UNION ALL
        SELECT resp_h, 'r', date_trunc('hour', ts), log_type, count(*), sum(resp_bytes), sum(orig_bytes), min(ts), max(ts)
        FROM netlog WHERE {w} AND resp_h IS NOT NULL GROUP BY ALL""", p * 2)
    cur.execute(f"""INSERT INTO netlog_agg_peer
        SELECT orig_h, resp_h, date_trunc('day', ts), count(*), sum(coalesce(orig_bytes, 0) + coalesce(resp_bytes, 0))
        FROM netlog WHERE {w} AND log_type IN {CONN_TYPES} AND orig_h IS NOT NULL AND resp_h IS NOT NULL GROUP BY ALL""", p)
    cur.execute(f"""INSERT INTO netlog_agg_name
        SELECT orig_h, coalesce(query, server_name, host), date_trunc('day', ts), count(*)
        FROM netlog WHERE {w} AND orig_h IS NOT NULL AND coalesce(query, server_name, host) IS NOT NULL
          AND log_type IN ('dns', 'ssl', 'http', 'eve_dns', 'eve_tls', 'eve_http') GROUP BY ALL""", p)
    cur.execute(f"""INSERT INTO netlog_agg_mac
        SELECT ip, mac, how, min(ts), max(ts), count(*) FROM (
            SELECT orig_h AS ip, mac, 'l2' AS how, ts FROM netlog WHERE {w} AND log_type IN {CONN_TYPES} AND mac IS NOT NULL
            UNION ALL SELECT resp_h, resp_mac, 'l2', ts FROM netlog WHERE {w} AND log_type IN {CONN_TYPES} AND resp_mac IS NOT NULL
            UNION ALL SELECT coalesce(json_extract_string(raw, '$.assigned_addr'), orig_h,
                                      json_extract_string(raw, '$.requested_addr')), mac, 'dhcp', ts
                      FROM netlog WHERE {w} AND log_type = 'dhcp' AND mac IS NOT NULL)
        WHERE ip IS NOT NULL AND ip <> '0.0.0.0' AND mac NOT IN ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff')
        GROUP BY ip, mac, how, date_trunc('minute', ts)""", p * 3)
    cur.execute(f"""INSERT INTO netlog_agg_host
        SELECT DISTINCT 'mac:' || mac, hostname FROM netlog WHERE {w} AND log_type = 'dhcp' AND mac IS NOT NULL AND hostname IS NOT NULL
        UNION SELECT DISTINCT 'mac:' || lower(json_extract_string(raw, '$.mac')), lower(json_extract_string(raw, '$.dhcp_host_name'))
              FROM netlog WHERE {w} AND log_type = 'known_devices' AND json_extract_string(raw, '$.dhcp_host_name') IS NOT NULL
        UNION SELECT DISTINCT 'ip:' || a, query FROM (SELECT query, unnest(answers) AS a FROM netlog
              WHERE {w} AND log_type IN ('dns', 'eve_dns') AND answers IS NOT NULL AND query IS NOT NULL)
        UNION SELECT DISTINCT 'ipn:' || orig_h, hostname FROM netlog   -- a DNS sinkhole's name for its client
              WHERE {w} AND log_type = 'dns' AND hostname IS NOT NULL AND orig_h IS NOT NULL""", p * 4)


def reaggregate_all() -> int:
    """Rebuild every aggregate from all of netlog in one pass (after rows were deleted). Returns files folded in."""
    with util.LOCK, db._write_lock:
        cur = db.cursor()
        cur.execute(AGG_SQL)
        with db.tx(cur):
            for t in ("netlog_agg_ip", "netlog_agg_peer", "netlog_agg_name", "netlog_agg_mac", "netlog_agg_host", "netlog_agg_files"):
                cur.execute(f"DELETE FROM {t}")
            _aggregate(cur, "ts IS NOT NULL", [])
            n = cur.execute("""INSERT INTO netlog_agg_files SELECT DISTINCT file_id, now() FROM netlog
                               WHERE file_id IS NOT NULL""").fetchone()[0]
    return int(n)


def _backfill(cur) -> int:
    todo = [r[0] for r in cur.execute("""SELECT DISTINCT file_id FROM netlog
                                         WHERE file_id NOT IN (SELECT file_id FROM netlog_agg_files)""").fetchall()]
    for f in todo:
        aggregate_file(cur, f)
        update_ipnum(cur, "file_id = ?", [f])
    return len(todo)


# ------------------------------------------------------------------ rebuild
def rebuild() -> dict:
    """Recompute netlog_ipmap, netlog_ipdev and devices from the per-file aggregates.

    Files not yet aggregated (a new import, or a lake from before aggregates existed) are folded in first;
    only their own rows are scanned.
    """
    with util.LOCK, db._write_lock:
        cur = db.cursor()
        cur.execute(IPDEV_SQL)
        cur.execute(AGG_SQL)
        ensure_tables(cur)
        # One transaction: a failure part-way leaves the previous devices, ipmap and ipdev in place.
        with db.tx(cur):
            out = _rebuild(cur)
        return out


def _rebuild(cur) -> dict:
    _backfill(cur)
    prefs = home_table(cur)
    bcast = set()
    for p in prefs:
        try:
            n = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        if n.version == 4 and n.prefixlen <= 30:
            bcast.add(str(n.broadcast_address))
    homes = {r[0]: bool(r[1]) for r in cur.execute(
        "SELECT ip, v6 FROM _nl_homeip WHERE ip IN (SELECT ip FROM netlog_agg_ip)").fetchall() if r[0] not in bcast}
    cur.execute("CREATE OR REPLACE TEMP TABLE _nl_dev_ips (ip VARCHAR)")
    if homes:  # prefixes that match no IPs: no devices (executemany refuses an empty list)
        cur.executemany("INSERT INTO _nl_dev_ips VALUES (?)", [(i,) for i in homes])
    # MAC evidence. A MAC seen in front of non-home IPs is a router, not a device.
    ev = util.rows_of(cur, """
        WITH gw AS (SELECT DISTINCT mac FROM netlog_agg_mac WHERE how = 'l2' AND ip NOT IN (SELECT ip FROM _nl_homeip))
        SELECT ip, mac, how, min(first_ts) AS first_ts, max(last_ts) AS last_ts, sum(rows) AS rows FROM netlog_agg_mac
        WHERE ip IN (SELECT ip FROM _nl_dev_ips) AND (how <> 'l2' OR mac NOT IN (SELECT mac FROM gw))
        GROUP BY ALL""")
    # Time-resolved MAC evidence (per minute) decides which MAC held an IP when.
    segs: dict[str, list] = defaultdict(list)
    for ip, mac, how, t0, t1 in cur.execute("""
            WITH gw AS (SELECT DISTINCT mac FROM netlog_agg_mac WHERE how = 'l2' AND ip NOT IN (SELECT ip FROM _nl_homeip))
            SELECT ip, mac, how, first_ts, last_ts FROM netlog_agg_mac
            WHERE ip IN (SELECT ip FROM _nl_dev_ips) AND (how <> 'l2' OR mac NOT IN (SELECT mac FROM gw))
            ORDER BY ip, first_ts, how""").fetchall():
        segs[ip].append((mac, how, t0, t1))
    mapped = {e["ip"] for e in ev}
    for ip, v6 in homes.items():
        if v6 and ip not in mapped and (m := ipnum.eui64_mac(ip)):
            ev.append({"ip": ip, "mac": m, "how": "eui64", "first_ts": None, "last_ts": None, "rows": 0})
            mapped.add(ip)
    # IPv6 addresses without MAC evidence: link by /64 and behaviour.
    behav = _link_by_behaviour(cur, homes, ev)
    ev += behav
    conf = {"dhcp": "certain", "l2": "certain", "eui64": "derived", "behaviour": "probable"}
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in ev:
        if e["ip"] in homes:
            by_ip[e["ip"]].append(e)
    ipdev = []
    for ip in homes:
        runs = _runs(segs.get(ip, []))
        if not runs:
            evs = by_ip.get(ip, [])   # eui64 or behaviour: one holder for all time
            if evs:
                e = evs[0]
                ipdev.append({"ip": ip, "from_ts": EPOCH, "device": f"mac:{e['mac']}", "how": e["how"],
                              "confidence": conf[e["how"]]})
            else:
                ipdev.append({"ip": ip, "from_ts": EPOCH, "device": f"ip:{ip}", "how": "ip", "confidence": "ip-only"})
            continue
        for frm, mac, how in runs:
            ipdev.append({"ip": ip, "from_ts": frm or EPOCH, "device": f"mac:{mac}", "how": how,
                          "confidence": conf[how]})
    # The user's merges: a merged device's addresses belong to the device it was merged into.
    ensure_tables(cur)
    resolve = merge_resolver(cur)
    merged: dict[str, dict] = defaultdict(lambda: {"from": set(), "ips": []})
    for r in ipdev:
        to = resolve(r["device"])
        if to != r["device"]:
            merged[to]["from"].add(r["device"])
            if r["device"].startswith("ip:"):
                merged[to]["ips"].append({"ip": r["ip"], "how": "merged", "basis": f"merged by you from {r['device'][3:]}",
                                          "first_ts": None, "last_ts": None, "rows": None, "score": None})
            r["device"] = to
    cur.execute("DELETE FROM netlog_ipmap")
    cur.execute("DELETE FROM netlog_ipdev")
    if ev:
        p = util.scratch("ipmap")
        util.write_ndjson(p, [{**e, "confidence": {"certain": 1.0, "derived": 0.9, "probable": e.get("score", 0.6)}
                               [conf[e["how"]]]} for e in ev])
        try:
            cur.execute(f"""INSERT INTO netlog_ipmap SELECT ip, mac, first_ts, last_ts, how, confidence, rows FROM
                {util.read_src(p, {'ip': 'VARCHAR', 'mac': 'VARCHAR', 'first_ts': 'TIMESTAMPTZ', 'last_ts': 'TIMESTAMPTZ',
                                   'how': 'VARCHAR', 'confidence': 'DOUBLE', 'rows': 'BIGINT'})}""")
        finally:
            p.unlink(missing_ok=True)
    if ipdev:
        p = util.scratch("ipdev")
        util.write_ndjson(p, ipdev)
        try:
            cur.execute(f"""INSERT INTO netlog_ipdev SELECT * FROM
                {util.read_src(p, {'ip': 'VARCHAR', 'from_ts': 'TIMESTAMPTZ', 'device': 'VARCHAR', 'how': 'VARCHAR',
                                   'confidence': 'VARCHAR'})}""")
        finally:
            p.unlink(missing_ok=True)
    MERGED.clear()
    MERGED.update(merged)
    n = _stats(cur, ev)
    return {"devices": n, "home_ips": len(homes)}


def _runs(segs: list[tuple]) -> list[tuple]:
    """(from_ts, mac, how) changes of holder for one IP, from time-ordered (mac, how, first, last) evidence.

    A DHCP lease takes effect at its own time. Otherwise a change of MAC takes effect halfway between the
    last sighting of the old MAC and the first of the new one, so each row goes to the MAC seen closest in time.
    """
    runs: list[list] = []
    for mac, how, t0, t1 in segs:
        if runs and runs[-1][0] == mac:
            runs[-1][3] = max(runs[-1][3], t1)
            continue
        runs.append([mac, how, t0, t1])
    out = []
    for i, (mac, how, t0, _t1) in enumerate(runs):
        if i == 0:
            frm = None
        elif how == "dhcp":
            frm = t0
        else:
            prev_end = runs[i - 1][3]
            frm = prev_end + (t0 - prev_end) / 2 if t0 > prev_end else t0
        out.append((frm, mac, how))
    return out


CANDIDATES: dict[str, list] = {}  # lone IPv6 address -> best behaviour matches that were not sure enough


def _link_by_behaviour(cur, homes: dict[str, bool], ev: list[dict]) -> list[dict]:
    """Link IPv6 addresses without MAC evidence to a MAC device by the names they use.

    Each lone address's names (DNS queries, TLS SNI, HTTP hosts) are compared with each MAC device's,
    weighted by rarity across devices (a name every device uses says nothing). The address joins the
    best device when that device explains most of its weighted names, clearly better than the runner-up,
    and was active at the same time.
    """
    import math
    CANDIDATES.clear()
    mapped = {e["ip"] for e in ev}
    lone = [ip for ip, v6 in homes.items() if v6 and ip not in mapped]
    if not lone:
        return []
    mac_ips: dict[str, set] = defaultdict(set)
    for e in ev:
        mac_ips[e["mac"]].add(e["ip"])
    if not mac_ips:
        return []
    cur.execute("CREATE OR REPLACE TEMP TABLE _nl_tok_ips (ip VARCHAR)")
    cur.executemany("INSERT INTO _nl_tok_ips VALUES (?)", [(i,) for i in set(lone) | {i for s in mac_ips.values() for i in s}])
    toks: dict[str, Counter] = defaultdict(Counter)
    days: dict[str, set] = defaultdict(set)
    for ip, tok, day, n in cur.execute("""
            SELECT ip, name, day, sum(n) FROM netlog_agg_name WHERE ip IN (SELECT ip FROM _nl_tok_ips)
            GROUP BY ALL""").fetchall():
        toks[ip][tok] += n
        days[ip].add(day)
    cur.execute("DROP TABLE _nl_tok_ips")
    dev_toks = {m: set().union(*(toks.get(i, Counter()).keys() for i in ips)) for m, ips in mac_ips.items()}
    dev_days = {m: set().union(*(days.get(i, set()) for i in ips)) for m, ips in mac_ips.items()}
    dev_p64 = {m: {ipnum.prefix_of(i) for i in ips if ":" in i} for m, ips in mac_ips.items()}
    df: Counter = Counter()
    for t in dev_toks.values():
        df.update(t)
    nd = len(dev_toks)
    idf = lambda name: math.log((nd + 1) / (df.get(name, 0) + 0.5))
    out = []
    for ip in lone:
        t = toks.get(ip)
        if not t or len(t) < 2:
            continue
        w = {k: idf(k) for k in t}
        total = sum(w.values()) or 1.0
        p64 = ipnum.prefix_of(ip)
        scored = []
        for m, dt_ in dev_toks.items():
            if not dt_ or (days[ip] and dev_days[m] and not (days[ip] & dev_days[m])):
                continue
            cov = sum(v for k, v in w.items() if k in dt_) / total
            scored.append((cov, p64 in dev_p64[m], m))
        if not scored:
            continue
        scored.sort(reverse=True)
        CANDIDATES[ip] = [{"mac": m, "names_explained": round(c, 2), "same_64": sm} for c, sm, m in scored[:3]]
        best, same, mac = scored[0]
        second = scored[1][0] if len(scored) > 1 else 0.0
        if best >= 0.6 and best - second >= 0.2:
            out.append({"ip": ip, "mac": mac, "how": "behaviour", "first_ts": None, "last_ts": None, "rows": 0,
                        "score": round(min(0.9, 0.3 + 0.6 * (best - second)), 2),
                        "basis": ("same /64, " if same else "") + f"names {best:.0%} explained vs {second:.0%} runner-up"})
    return out


MERGED: dict[str, dict] = {}  # device -> {from: merged device ids, ips: evidence rows}, from the last rebuild


def _stats(cur, ev: list[dict]) -> int:
    resolve, merged = merge_resolver(cur), MERGED
    cur.execute("""CREATE OR REPLACE TEMP TABLE _nl_obs AS
        WITH o AS (SELECT ip, hr, log_type, sum(rows) AS rows, sum(bo) AS bo, sum(bi) AS bi, min(t0) AS t0, max(t1) AS t1
                   FROM netlog_agg_ip WHERE ip IN (SELECT ip FROM _nl_dev_ips) GROUP BY ALL)
        SELECT o.*, d.device FROM o ASOF JOIN netlog_ipdev d ON d.ip = o.ip AND o.hr >= d.from_ts""")
    base = util.rows_of(cur, f"""
        SELECT device, list(DISTINCT ip ORDER BY ip) AS ips, min(t0) AS first_seen, max(t1) AS last_seen,
               sum(rows) AS rows, sum(rows) FILTER (WHERE log_type IN {CONN_TYPES}) AS conns,
               coalesce(sum(bo) FILTER (WHERE log_type IN {CONN_TYPES}), 0) AS bytes_out,
               coalesce(sum(bi) FILTER (WHERE log_type IN {CONN_TYPES}), 0) AS bytes_in
        FROM _nl_obs GROUP BY device""")
    dests = defaultdict(list)
    for r in util.rows_of(cur, """
        WITH p AS (SELECT orig_h, resp_h, day, sum(conns) AS conns, sum(bytes) AS bytes FROM netlog_agg_peer
                   WHERE orig_h IN (SELECT ip FROM _nl_dev_ips) AND resp_h NOT IN (SELECT ip FROM _nl_homeip) GROUP BY ALL)
        SELECT d.device, p.resp_h AS ip, sum(p.bytes) AS bytes, sum(p.conns) AS conns
        FROM p ASOF JOIN netlog_ipdev d ON d.ip = p.orig_h AND p.day + INTERVAL 1 DAY > d.from_ts
        GROUP BY d.device, p.resp_h
        QUALIFY row_number() OVER (PARTITION BY d.device ORDER BY sum(p.bytes) DESC, sum(p.conns) DESC, p.resp_h) <= 10
        ORDER BY d.device, bytes DESC, conns DESC, ip"""):
        dests[r["device"]].append({"ip": r["ip"], "bytes": int(r["bytes"] or 0), "conns": int(r["conns"])})
    names = defaultdict(list)
    for r in util.rows_of(cur, """
        WITH n AS (SELECT ip, name, day, sum(n) AS n FROM netlog_agg_name WHERE ip IN (SELECT ip FROM _nl_dev_ips) GROUP BY ALL)
        SELECT d.device, n.name, sum(n.n) AS n FROM n ASOF JOIN netlog_ipdev d ON d.ip = n.ip AND n.day + INTERVAL 1 DAY > d.from_ts
        GROUP BY d.device, n.name QUALIFY row_number() OVER (PARTITION BY d.device ORDER BY sum(n.n) DESC, n.name) <= 10
        ORDER BY d.device, n DESC, n.name"""):
        names[r["device"]].append({"name": r["name"], "n": int(r["n"])})
    # Names the device gave itself (DHCP, known_devices) come before names other hosts resolved to its address.
    own_dhcp, own_dns = defaultdict(set), defaultdict(set)
    for r in util.rows_of(cur, "SELECT DISTINCT key, name FROM netlog_agg_host WHERE key LIKE 'mac:%' AND name IS NOT NULL"):
        own_dhcp[resolve(r["key"])].add(r["name"])
    for r in util.rows_of(cur, """SELECT DISTINCT d.device, h.name FROM netlog_agg_host h
                                  JOIN netlog_ipdev d ON 'ip:' || d.ip = h.key WHERE h.key LIKE 'ip:%'"""):
        own_dns[r["device"]].add(r["name"])
    # A DNS sinkhole's name for its client (Pi-hole client.name, AdGuard client id) ranks with the device's own names.
    for r in util.rows_of(cur, """SELECT DISTINCT d.device, h.name FROM netlog_agg_host h
                                  JOIN netlog_ipdev d ON 'ipn:' || d.ip = h.key WHERE h.key LIKE 'ipn:%'"""):
        own_dhcp[resolve(r["device"])].add(r["name"])
    own = {k: list(dict.fromkeys(sorted(own_dhcp.get(k, ())) + sorted(own_dns.get(k, set()) - own_dhcp.get(k, set()))))
           for k in set(own_dhcp) | set(own_dns)}
    vendors = _vendors(cur, resolve)
    evid = defaultdict(list)
    for e in sorted(ev, key=lambda e: (e["ip"], e["how"], str(e["first_ts"]))):   # stable order across rebuilds
        evid[resolve(f"mac:{e['mac']}")].append({"ip": e["ip"], "how": e["how"], "basis": e.get("basis"),
                                                 "first_ts": e["first_ts"], "last_ts": e["last_ts"], "rows": e["rows"],
                                                 "score": e.get("score")})
    for dev, m in merged.items():
        evid[dev] += m["ips"]
    # Readable names: a candidate several devices share (a Bonjour service name, "espressif") identifies none of them.
    cands = {b["device"]: name_candidates(own.get(b["device"], [])) for b in base}
    shared = Counter(n.lower() for c in cands.values() for n in {x["name"] for x in c["names"]})
    conf_rank = {"certain": 3, "derived": 2, "probable": 1}
    out = []
    for b in base:
        dev = b["device"]
        is_mac = dev.startswith("mac:")
        hows = [x["how"] for x in evid.get(dev, [])]
        cmap = {"dhcp": "certain", "l2": "certain", "eui64": "derived", "behaviour": "probable"}
        if not is_mac:
            confidence = "ip-only"
        else:
            confidence = max((cmap[h] for h in hows if h in cmap), key=lambda c: conf_rank[c], default="certain")
        naming = auto_naming(dev, b["ips"] or [], cands[dev], shared, vendors.get(dev))
        if dev in merged:
            naming["merged_from"] = sorted(merged[dev]["from"])
        out.append({**b, "id": dev, "identity": "mac" if is_mac else "ip", "mac": dev[4:] if is_mac else None,
                    "hostnames": own.get(dev, [])[:20], "top_dests": json.dumps(dests.get(dev, [])),
                    "top_names": json.dumps(names.get(dev, [])), "confidence": confidence,
                    "evidence": json.dumps({"ips": evid.get(dev, []), "naming": naming,
                                            **({"v6_candidates": CANDIDATES[dev[3:]],
                                                "note": "IPv6 address without MAC evidence; behaviour did not single out a device"}
                                               if not is_mac and dev[3:] in CANDIDATES else {})}, default=str)})
    prev = util.rows_of(cur, "SELECT id, ips, first_seen, last_seen FROM devices")   # for the new-device rule
    cur.execute("DELETE FROM devices")
    if out:
        p = util.scratch("devices")
        util.write_ndjson(p, out)
        try:
            cur.execute(f"""INSERT INTO devices SELECT id, identity, mac, ips, hostnames, first_seen, last_seen, rows, conns,
                bytes_out, bytes_in, top_dests, top_names, confidence, evidence FROM
                {util.read_src(p, {'id': 'VARCHAR', 'identity': 'VARCHAR', 'mac': 'VARCHAR', 'ips': 'VARCHAR[]',
                                   'hostnames': 'VARCHAR[]', 'first_seen': 'TIMESTAMPTZ', 'last_seen': 'TIMESTAMPTZ',
                                   'rows': 'BIGINT', 'conns': 'BIGINT', 'bytes_out': 'BIGINT', 'bytes_in': 'BIGINT',
                                   'top_dests': 'VARCHAR', 'top_names': 'VARCHAR', 'confidence': 'VARCHAR',
                                   'evidence': 'VARCHAR'})}""")
        finally:
            p.unlink(missing_ok=True)
    cur.execute("DROP TABLE IF EXISTS _nl_obs")
    cur.execute("DROP TABLE IF EXISTS _nl_dev_ips")
    # first sightings: a device not seen before raises "New device joined" (newdev.py)
    from . import newdev
    try:
        LAST_NEW.clear()
        LAST_NEW.update(newdev.detect(cur, prev))
    except Exception:
        import logging
        logging.getLogger("osinthub.netlog").exception("netlog: new-device check failed")
    return len(out)


LAST_NEW: dict = {}   # what the last rebuild's new-device check did (newdev.detect)


# ------------------------------------------------------------------ the user's labels and merges
LABEL_SQL = """
CREATE TABLE IF NOT EXISTS netlog_device_labels (id VARCHAR PRIMARY KEY, name VARCHAR, type VARCHAR, owner VARCHAR,
    note VARCHAR, updated_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS netlog_device_merges (src VARCHAR PRIMARY KEY, dst VARCHAR, created_at TIMESTAMPTZ,
    src_name VARCHAR);   -- what the merged device was called when it was merged
"""
TYPES = {"laptop": "Laptop or computer", "phone": "Phone or tablet", "tv": "TV or streamer", "iot": "Smart-home gadget",
         "server": "Server or NAS", "console": "Game console", "network": "Network gear", "other": "Other"}
LABEL_MAX = {"name": 60, "owner": 60, "note": 280}
_tables_ok = threading.Event()


def ensure_tables(cur=None) -> None:
    if _tables_ok.is_set():
        return
    if cur is None:
        with db._write_lock:
            db.cursor().execute(LABEL_SQL)
    else:
        cur.execute(LABEL_SQL)
    _tables_ok.set()


def labels(ids: list[str] | None = None) -> dict[str, dict]:
    """{device id: {name, type, owner, note, updated_at}} for the given ids (all when None)."""
    ensure_tables()
    if ids is not None and not ids:
        return {}
    w, p = ("WHERE id IN (SELECT unnest(?::VARCHAR[]))", [list(ids)]) if ids is not None else ("", [])
    return {r.pop("id"): r for r in util.jsonable(db.query(f"SELECT * FROM netlog_device_labels {w}", p))}


def set_label(did: str, body: dict) -> dict:
    """Save the user's name / type / owner / note for a device (only the keys given; '' or null clears one)."""
    ensure_tables()
    cur = labels([did]).get(did) or {}
    rec = {k: cur.get(k) for k in ("name", "type", "owner", "note")}
    for k in ("name", "owner", "note"):
        if k in body:
            v = body[k]
            if v is not None and not isinstance(v, str):
                raise ValueError(f"{k} must be text")
            v = " ".join((v or "").split()) if k != "note" else (v or "").strip()
            if len(v) > LABEL_MAX[k]:
                raise ValueError(f"{k} is longer than {LABEL_MAX[k]} characters")
            rec[k] = v or None
    if "type" in body:
        t = body["type"] or None
        if t is not None and t not in TYPES:
            raise ValueError(f"type must be one of {', '.join(TYPES)}")
        rec["type"] = t
    with db._write_lock:
        c = db.cursor()
        if any(rec.values()):
            c.execute("INSERT OR REPLACE INTO netlog_device_labels VALUES (?, ?, ?, ?, ?, now())",
                      [did, rec["name"], rec["type"], rec["owner"], rec["note"]])
        else:
            c.execute("DELETE FROM netlog_device_labels WHERE id = ?", [did])
    return rec


def merges(names: bool = False) -> dict:
    """{src: dst} for every merge, or {src: {dst, src_name, created_at}} with names=True."""
    ensure_tables()
    rows = db.query("SELECT src, dst, src_name, created_at FROM netlog_device_merges")
    return {r["src"]: (util.jsonable({k: r[k] for k in ("dst", "src_name", "created_at")}) if names else r["dst"]) for r in rows}


def merge_resolver(cur=None):
    """A function: device id -> the device it ends up in after the user's merges (chains followed, cycles ignored)."""
    ensure_tables(cur)
    rows = (cur.execute("SELECT src, dst FROM netlog_device_merges").fetchall() if cur is not None
            else [(r["src"], r["dst"]) for r in db.query("SELECT src, dst FROM netlog_device_merges")])
    m = dict(rows)

    def resolve(d: str) -> str:
        seen = {d}
        while d in m and m[d] not in seen:
            d = m[d]
            seen.add(d)
        return d
    return resolve


def _rematch_ips(ips: list[str]) -> None:
    """Re-match the rows of these home addresses so their alerts move to the device that now holds them."""
    from . import matcher
    ips = sorted(set(ips))
    if not ips or not db.query("SELECT 1 FROM netlog LIMIT 1"):
        return
    for i in range(0, len(ips), 500):
        part = ips[i:i + 500]
        q = ",".join("?" * len(part))
        matcher.match(f"orig_h IN ({q}) OR resp_h IN ({q})", [*part, *part], settings=True)   # a device change


def _ips_of(did: str) -> list[str]:
    return [r["ip"] for r in db.query("SELECT DISTINCT ip FROM netlog_ipdev WHERE device = ?", [did])]


def merge(src: str, dst: str) -> dict:
    """Merge device src into dst (the same machine seen twice). Rebuilds devices and re-matches their rows."""
    ensure_tables()
    if src == dst:
        raise ValueError("a device cannot be merged into itself")
    have = {r["id"] for r in db.query("SELECT id FROM devices WHERE id IN (?, ?)", [src, dst])}
    if src not in have or dst not in have:
        raise LookupError("no such device")
    if merge_resolver()(dst) == src:
        raise ValueError("that device is already merged into this one")
    ips = _ips_of(src)
    src_name = (display_names([src]).get(src) or {}).get("name")
    with util.LOCK:
        with db._write_lock:
            db.cursor().execute("INSERT OR REPLACE INTO netlog_device_merges VALUES (?, ?, now(), ?)", [src, dst, src_name])
        res = rebuild()
        _rematch_ips(ips)
    return {"src": src, "dst": dst, "devices": res}


def unmerge(src: str) -> dict:
    """Undo a merge: src becomes its own device again."""
    ensure_tables()
    m = merges()
    if src not in m:
        raise LookupError("that device is not merged")
    ips = _ips_of(merge_resolver()(src))
    with util.LOCK:
        with db._write_lock:
            db.cursor().execute("DELETE FROM netlog_device_merges WHERE src = ?", [src])
        res = rebuild()
        _rematch_ips(ips)
    return {"src": src, "dst": m[src], "devices": res}


# ------------------------------------------------------------------ readable names
# Many names a home network reveals are not names: mDNS service records ("_airplay._tcp.local", a UUID instance),
# reverse-DNS ("....ip6.arpa"), hex ids. They stay in the evidence, never as the label.
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_HEXID = re.compile(r"^[0-9a-f$:\-]{8,}$", re.I)
_IPISH = re.compile(r"\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}")
_SVC = re.compile(r"(?:^|\.)_([a-z0-9-]+)", re.I)
LOCAL_SUFFIX = re.compile(r"\.(local|lan|home|localdomain|home\.arpa|internal|station)$", re.I)
SVC_TYPE = {"googlecast": "tv", "androidtvremote2": "tv", "apple-mobdev2": "phone", "adisk": "server", "smb": "server",
            "afpovertcp": "server", "nfs": "server", "ipp": "other", "ipps": "other", "printer": "other",
            "pdl-datastream": "other", "hap": "iot", "matter": "iot", "matterc": "iot", "spotify-connect": "iot"}
APPLE_SVC = {"companion-link", "apple-mobdev2", "apple-pairable", "asquic", "gamed", "sleep-proxy", "airplay", "raop",
             "homekit", "touch-able", "device-info"}
KEYWORDS = [  # (regex on the name, type); first match wins, so a TV or computer word beats a phone word
    (r"\btv\b|-tv\b|tv-|_tv\b|roku|chromecast|fire-?tv|firestick|bravia|apple-?tv|shield|webos|tizen|vizio", "tv"),
    (r"\bmac\b|macbook|imac|mac-?mini|mac-?pro|mac-?studio|laptop|desktop|thinkpad|surface|\bpc\b|-pc\b|windows|workstation|"
     r"chromebook|mbp", "laptop"),
    (r"iphone|android|pixel|galaxy|phone|ipad|tablet|kindle", "phone"),
    (r"xbox|playstation|\bps[345]\b|nintendo|steamdeck|steam-deck", "console"),
    (r"\bnas\b|synology|diskstation|qnap|truenas|unraid|server|raspberry|\bpi\b|homeassistant|home-assistant", "server"),
    (r"router|firewalla|gateway|unifi|ubnt|eero|orbi|deco|mesh|access-?point|\bap\b|switch|modem|openwrt|pfsense|opnsense", "network"),
    (r"thermostat|nest|wyze|bulb|plug|camera|\bcam\b|doorbell|chime|ring|echo|alexa|\bhue\b|espressif|\besp|tuya|"
     r"shelly|sonos|homepod|speaker|sensor|smart|tado|ecobee|kasa|meross|lock|vacuum|roomba|printer", "iot"),
]


# Names that say what a device is but not which one ("iPhone", "android", "localhost", "ESP_1A2B3C"): never the label on
# their own (many homes have several); they become the fallback's hint instead. okf/data/netlog.md#device-names
GENERIC = {"mac": "Mac", "macbook": "MacBook", "imac": "iMac", "iphone": "iPhone", "ipad": "iPad", "android": "Android",
           "localhost": None, "router": "router", "gateway": "router", "phone": "phone", "tablet": "tablet",
           "laptop": "laptop", "desktop": "computer", "pc": "computer", "computer": "computer", "tv": "TV",
           "printer": "printer", "camera": "camera", "galaxy": "Samsung Galaxy", "pixel": "Google Pixel",
           "chromecast": "Chromecast", "roku": "Roku", "echo": "Amazon Echo", "homepod": "HomePod", "ap": "access point",
           "device": None, "unknown": None, "host": None, "client": None, "living": None,
           "raspberrypi": "Raspberry Pi", "linux": "Linux", "windows": "Windows", "debian": "Linux", "ubuntu": "Linux"}
_GENERIC_RX = [(re.compile(r"^esp[_-]?[0-9a-f]{4,}$", re.I), "ESP chip (smart-home)"),
               (re.compile(r"^android[_-][0-9a-f]{6,}$", re.I), "Android"),
               (re.compile(r"^(?:galaxy|iphone|ipad|pixel)[_-]?\d{0,2}$", re.I), None),
               (re.compile(r"^(?:dhcp|host|client|unknown)[_-]?[0-9a-f]*$", re.I), None)]


def generic_hint(name: str) -> tuple[bool, str | None]:
    """(True, hint) when a readable name only says what kind of device it is, else (False, None)."""
    k = (name or "").strip().lower()
    if k in GENERIC:
        return True, GENERIC[k]
    for rx, hint in _GENERIC_RX:
        if rx.match(k):
            if hint is None:
                base = re.sub(r"[_-]?\d+$", "", k)
                hint = GENERIC.get(base)
            return True, hint
    return False, None


def clean_name(raw: str) -> tuple[str | None, list[str]]:
    """(the readable part of a name or None, the mDNS service types in it)."""
    s = (raw or "").strip().rstrip(".")
    services = [m.group(1).lower() for m in _SVC.finditer(s)]
    services = [x for x in services if x not in ("tcp", "udp", "sub")]
    if s.lower().endswith(".arpa") and not s.lower().endswith(".home.arpa"):
        return None, services
    if "._" in s or s.startswith("_"):
        s = "" if s.startswith("_") else s.split("._", 1)[0]
    s = LOCAL_SUFFIX.sub("", s).strip()
    if (not s or _UUID.search(s) or _HEXID.match(s) or _IPISH.search(s) or len(s) > 40 or "$" in s
            or not re.search(r"[a-z]", s, re.I) or s.count(".") >= 2):
        return None, services
    return s, services


def name_candidates(hostnames: list[str]) -> dict:
    """Readable names (in the order given, DHCP first) and every mDNS service type seen among a device's names."""
    names, services, junk = [], [], []
    for h in hostnames:
        n, svc = clean_name(h)
        services += svc
        if n and n.lower() not in {x["name"].lower() for x in names}:
            names.append({"name": n, "raw": h, "service": "._" in h or h.startswith("_")})
        elif not n:
            junk.append(h)
    return {"names": names, "services": list(dict.fromkeys(services)), "junk": junk}


def guess_type(text: list[str], services: list[str]) -> str | None:
    for n in text:
        for rx, t in KEYWORDS:
            if re.search(rx, n, re.I):
                return t
    for s in services:
        if s in SVC_TYPE:
            return SVC_TYPE[s]
    return None


def short_id(did: str) -> str:
    v = did.split(":", 1)[1] if ":" in did else did
    if did.startswith("mac:"):
        return ":".join(v.split(":")[-2:])
    if ":" in v:  # IPv6: the last group
        return "…" + v.rsplit(":", 1)[-1]
    return v


def auto_naming(did: str, ips: list[str], cands: dict, shared: Counter, vendor: str | None) -> dict:
    """The name the evidence supports (or None), a type guess, and the parts of a readable fallback."""
    name, why, chosen, ghint = None, None, None, None
    for c in cands["names"]:
        n_shared = shared.get(c["name"].lower(), 0) > 1
        if c["service"] and n_shared:
            continue   # a Bonjour name several devices answer to
        gen, gh = generic_hint(c["name"])
        if gen:        # "iPhone", "mac", "localhost": says what, not which
            ghint = ghint or gh
            continue
        name, why = (f"{c['name']} · {short_id(did)}", "shared") if n_shared else (c["name"], "device")
        chosen = c["name"]
        break
    # The type follows the name shown: "kitchen-ipad" is a tablet even when the device also answers to a laptop's name.
    tguess = (guess_type([chosen], []) if chosen else None) or \
        guess_type([c["name"] for c in cands["names"]] + [vendor or ""], cands["services"])
    hint = ghint or vendor
    if not hint and set(cands["services"]) & APPLE_SVC:
        hint = "Apple device"
    if not hint and tguess:
        hint = TYPES[tguess].lower()
    mac = did[4:] if did.startswith("mac:") else None
    if not hint and mac:
        try:
            hint = "private address" if int(mac.split(":")[0], 16) & 2 else None
        except ValueError:
            pass
    fragment = (did.startswith("ip:") and ":" in did[3:] and not name)
    if not hint and fragment:
        hint = "IPv6 address"
    return {"name": name, "why": why, "type_guess": tguess, "hint": hint, "short": short_id(did),
            "names": [c["name"] for c in cands["names"]][:12], "services": cands["services"][:12],
            "junk": cands["junk"][:20], "fragment": fragment}


def _vendors(cur, resolve) -> dict[str, str]:
    """MAC vendor where a log names it (Zeek known_devices with a vendor field)."""
    out = {}
    try:
        for k, v in cur.execute("""SELECT DISTINCT 'mac:' || lower(json_extract_string(raw, '$.mac')),
                                          json_extract_string(raw, '$.vendor') FROM netlog
                                   WHERE log_type = 'known_devices' AND json_extract_string(raw, '$.vendor') IS NOT NULL""").fetchall():
            if k and v:
                out[resolve(k)] = str(v)[:40]
    except Exception:
        pass
    return out


def _silent_v4(did: str, row: dict, src: str) -> bool:
    """An IPv4 address with no hardware address, no name and no bytes either way (a DHCP probe, a one-off ARP-ish
    sighting): as little evidence as an IPv6 fragment, so it folds under Unidentified with them."""
    if not did.startswith("ip:") or ":" in did[3:] or src != "fallback":
        return False
    if row.get("bytes_out") is None and row.get("bytes_in") is None:
        return False   # a caller without traffic numbers (display_names) never folds
    return (row.get("bytes_out") or 0) + (row.get("bytes_in") or 0) == 0


def present(row: dict, label: dict | None = None, merged_into: str | None = None) -> dict:
    """A device row (evidence parsed) with what to call it: the user's label first, else the readable evidence,
    else 'Unnamed device · <hint> · <short id>'. Adds name, name_source, type, type_source, owner, note, fragment."""
    ev = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    nm = ev.get("naming") or {}
    did = row.get("id") or ""
    label = label or {}
    if not nm:   # a device built before naming existed: work it out from its hostnames
        nm = auto_naming(did, row.get("ips") or [], name_candidates(row.get("hostnames") or []), Counter(), None)
    elif nm.get("name"):   # built by an older rule: a generic name is a hint, and the type follows the name
        base = nm["name"].split(" · ")[0]
        gen, gh = generic_hint(base)
        if gen:
            nm = {**nm, "name": None, "why": None, "hint": gh or nm.get("hint")}
        elif (tg := guess_type([base], [])) and tg != nm.get("type_guess"):
            nm = {**nm, "type_guess": tg}
    if label.get("name"):
        name, src = label["name"], "you"
    elif nm.get("name"):
        name, src = nm["name"], "device"
    else:
        name, src = " · ".join(x for x in ("Unnamed device", nm.get("hint"), nm.get("short") or short_id(did)) if x), "fallback"
    typ, tsrc = (label["type"], "you") if label.get("type") else (nm.get("type_guess"), "guess" if nm.get("type_guess") else None)
    row.update(name=name, name_source=src, type=typ, type_source=tsrc, owner=label.get("owner"), note=label.get("note"),
               label={k: label.get(k) for k in ("name", "type", "owner", "note")} if label else None,
               fragment=(bool(nm.get("fragment")) or _silent_v4(did, row, src)) and not label and not nm.get("merged_from"),
               merged_from=nm.get("merged_from") or [], naming=nm)
    if merged_into:
        row["merged_into"] = merged_into
    return row


def display_names(ids: list[str]) -> dict[str, dict]:
    """{device id: {name, type, owner}} for ids that are (or were merged into) current devices."""
    ids = [i for i in dict.fromkeys(ids) if i]
    if not ids:
        return {}
    resolve = merge_resolver()
    real = {i: resolve(i) for i in ids}
    rows = db.query("SELECT id, ips, hostnames, evidence FROM devices WHERE id IN (SELECT unnest(?::VARCHAR[]))",
                    [list(set(real.values()))])
    lab = labels(list(set(real.values())))
    by = {}
    for r in rows:
        try:
            r["evidence"] = json.loads(r.get("evidence") or "{}")
        except ValueError:
            r["evidence"] = {}
        p = present(r, lab.get(r["id"]))
        by[r["id"]] = {"id": r["id"], "name": p["name"], "name_source": p["name_source"], "type": p["type"],
                       "owner": p["owner"], "hint": (p.get("naming") or {}).get("hint")}
    out = {}
    for i, j in real.items():
        if j in by:
            out[i] = by[j]
        elif lab.get(i, {}).get("name"):
            out[i] = {"id": i, "name": lab[i]["name"], "name_source": "you", "type": lab[i].get("type"), "owner": lab[i].get("owner")}
    return out


def similar(did: str, limit: int = 5) -> list[dict]:
    """Other devices that answer to one of this device's readable names: likely the same machine (merge candidates)."""
    rows = db.query("SELECT id, evidence FROM devices")
    names: dict[str, set] = {}
    for r in rows:
        try:
            nm = (json.loads(r["evidence"] or "{}").get("naming") or {})
        except ValueError:
            continue
        names[r["id"]] = {n.lower() for n in nm.get("names") or []}
    mine = names.get(did) or set()
    out = [{"id": k, "shared": sorted(v & mine)[:3]} for k, v in names.items() if k != did and v & mine]
    out.sort(key=lambda o: (not o["id"].startswith("mac:"), -len(o["shared"]), o["id"]))
    got = display_names([o["id"] for o in out[:limit]])
    return [{**o, "name": got.get(o["id"], {}).get("name", o["id"])} for o in out[:limit]]

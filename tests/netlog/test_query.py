"""Search logs filters (osinthub/netlog/query.py): how `not_*` lists are parsed, and what a query string finds through
GET /api/netlog/connections on a small temporary lake: free text is literal (a `%` or `_` is not a wildcard, `*` is),
an `ip:` CIDR matches either end of a connection or a DNS answer (IPv4 and IPv6), comma lists include any of their values, and a
leading `-` excludes.

    uv run --with pytest pytest tests/netlog/test_query.py -q
"""
from __future__ import annotations

import time

from _lake import client, conn, dns, make_lake, ndjson
LAKE = make_lake("query")

from osinthub import db  # noqa: E402
from osinthub.netlog import api, importer, ipnum, query as Q  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
C = client(api.router)
T0 = time.time() - 3600
ROWS = [
    dns(T0, "192.0.2.20", "100%_off.example", ["198.51.100.80"], uid="QPCT"),
    dns(T0 + 1, "192.0.2.20", "100x1off.example", ["198.51.100.81"], uid="QDECOY"),     # matches if % and _ were wildcards
    conn(T0 + 2, "192.0.2.10", "198.51.100.7", 443, uid="QV4"),
    conn(T0 + 3, "192.0.2.11", "203.0.113.9", 8053, proto="udp", uid="QUDP"),
    conn(T0 + 4, "2001:db8::5", "2001:db8:bad::10", 443, uid="QV6"),
    dns(T0 + 5, "2001:db8::5", "v6only.example", ["2001:db8:feed::25"], resolver="2001:db8::53", uid="QDNS6"),
]
assert importer.import_any(ndjson(ROWS), "query.log", origin="upload")["inserted"] == len(ROWS)   # as an upload: matched, indexed


def found(query: str) -> set[str]:
    r = C.get("/api/netlog/connections", params={"query": query, "limit": 0})
    assert r.status_code == 200, (query, r.text)
    return {x["uid"] for x in r.json()["rows"]}


def test_queries_find_exactly_their_rows():
    want = {
        "100%_off": {"QPCT"},                                     # free text is literal
        "query:100%_off.example": {"QPCT"},
        "query:100*": {"QPCT", "QDECOY"},                         # * is the one wildcard
        "ip:198.51.100.7": {"QV4"},
        "ip:198.51.100.80": {"QPCT"},                              # an address also matches a DNS answer
        "ip:198.51.100.0/25": {"QV4", "QPCT", "QDECOY"},          # a CIDR matches either end or a DNS answer
        "ip:192.0.2.8/30": {"QV4", "QUDP"},
        "ip:2001:db8:bad::/48": {"QV6"},
        "ip:2001:0DB8:0BAD:0000:0000:0000:0000:0010": {"QV6"},    # any spelling of an address
        "port:443": {"QV4", "QV6"},
        "port:443,8053": {"QV4", "QV6", "QUDP"},                  # a list includes any of its values
        "resp_h:198.51.100.7,203.0.113.9": {"QV4", "QUDP"},
        "log_type:conn -proto:udp": {"QV4", "QV6"},               # a leading - excludes
        "-log_type:dns -ip:2001:db8::/32": {"QV4", "QUDP"},
        "orig_bytes:>100 resp_p:<1000": {"QV4", "QV6"},
    }
    bad = {q: (got, w) for q, w in want.items() if (got := found(q)) != w}
    assert not bad, bad
    assert C.get("/api/netlog/connections", params={"query": "ip:300.1.2.0/24"}).status_code == 400
    assert C.get("/api/netlog/connections", params={"query": 'query:"unbalanced'}).status_code == 400


def test_a_cidr_also_matches_dns_answers():
    # okf/data/netlog.md#hunt-queries: an ip: CIDR matches the originator, the responder or a DNS answer
    assert found("ip:198.51.100.64/26") == {"QPCT", "QDECOY"}
    assert found("ip:198.51.100.80/32") == {"QPCT"}
    assert found("ip:2001:db8:feed::/48") == {"QDNS6"}                 # an IPv6 answer
    assert found("ip:2001:db8:feed::/48,198.51.100.7/32") == {"QDNS6", "QV4"}
    assert found("log_type:dns -ip:198.51.100.64/26") == {"QDNS6"}     # and an exclusion leaves those rows out
    assert found("ip:203.0.113.128/25") == set()                       # nothing in that range anywhere


# ---------------------------------------------------------------- not_* lists (no database)
def _neg_terms(**kw):
    return Q._terms(Q.excludes(**kw))


def test_not_lists_with_spaces_stay_exclusions():  # api-audit-009
    for spelling in ("192.0.2.122,192.0.2.159", "192.0.2.122, 192.0.2.159", " 192.0.2.122 ,192.0.2.159, "):
        assert _neg_terms(not_ip=spelling) == [(True, "ip", ["192.0.2.122"]), (True, "ip", ["192.0.2.159"])]
    assert _neg_terms(not_port="53, 443") == [(True, "port", ["53"]), (True, "port", ["443"])]
    assert _neg_terms(not_log_type="dns,  ssl") == [(True, "log_type", ["dns"]), (True, "log_type", ["ssl"])]
    assert _neg_terms(not_device="Living room TV, nas") == [(True, "device", ["Living room TV"]), (True, "device", ["nas"])]
    assert _neg_terms(not_device='say "hi"') == [(True, "device", ['say "hi"'])]
    assert _neg_terms(not_ip="2001:db8::1, 10.0.0.0/8") == [(True, "ip", ["2001:db8::1"]), (True, "ip", ["10.0.0.0/8"])]
    assert Q.excludes(not_ip=" , ", not_port="") == ""


def test_a_broad_cidr_stays_fast_with_dns_answers():
    """Every part of the ip: CIDR clause is a hash semi-join, so a /32 holding 32,768 known addresses costs what a
    narrow range does (round 1 checked a list of the whole range against every DNS row: seconds, not milliseconds).
    Its own in-memory database: 600,000 rows, a third of them DNS rows with answers. Documentation ranges only:
    the broad range is IPv6 2001:db8::/32, the answers-only range 203.0.113.0/24."""
    import duckdb
    base = ipnum.net_range("2001:db8::/32")[0]
    v6 = "'2001:db8:' || printf('%x', {a}) || ':' || printf('%x', {b}) || '::' || printf('%x', {c})"
    c = duckdb.connect()
    c.execute(f"""CREATE TABLE netlog AS SELECT i AS rk, '192.0.2.' || (i % 250) AS orig_h,
                 CASE WHEN i % 3 = 0 THEN '192.0.2.53' ELSE {v6.format(a='i % 16', b='i // 16 % 64', c='i // 1024 % 32')} END AS resp_h,
                 CASE WHEN i % 3 = 0 THEN [{v6.format(a='i % 16', b='i // 7 % 64', c='i // 448 % 32')}, '203.0.113.' || (i % 200)] END AS answers
                 FROM range(600000) t(i)""")
    c.execute(f"""CREATE TABLE netlog_ipnum AS
                 SELECT ip, (281470681743360 + (p[1]::BIGINT << 24) + (p[2]::BIGINT << 16)
                        + (p[3]::BIGINT << 8) + p[4]::BIGINT)::UHUGEINT AS n
                 FROM (SELECT ip, string_split(ip, '.')::INTEGER[] AS p FROM (
                       SELECT orig_h AS ip FROM netlog UNION SELECT resp_h FROM netlog UNION SELECT unnest(answers) FROM netlog)
                       WHERE NOT contains(ip, ':'))
                 UNION ALL
                 SELECT {v6.format(a='a', b='b', c='z')}, {base}::UHUGEINT + (a::UHUGEINT << 80) + (b::UHUGEINT << 64) + z::UHUGEINT
                 FROM range(16) t1(a), range(64) t2(b), range(32) t3(z)""")
    assert c.execute("SELECT count(*) FROM netlog_ipnum WHERE ip LIKE '2001:db8:%'").fetchone()[0] == 32768
    assert c.execute("SELECT count(*) FROM netlog WHERE resp_h NOT LIKE '192.0.2.%' AND resp_h NOT LIKE '2001:db8:%'").fetchone()[0] == 0

    def run(cidr: str, neg: bool = False) -> tuple[float, int]:
        p: list = []
        clause = Q.log_term("ip", [cidr], p)
        where = f"NOT coalesce({clause}, false)" if neg else clause
        best = 9.0
        for _ in range(3):
            t = time.perf_counter()
            n = c.execute(f"SELECT count(*) FROM netlog WHERE {where}", p).fetchone()[0]
            best = min(best, time.perf_counter() - t)
        return best, n

    assert run("2001:db8::/32")[1] == 600000 and run("2001:db8::/32", neg=True)[1] == 0    # every row: an end or an answer
    assert run("203.0.113.0/24")[1] == 200000                                                # only answers
    assert 0 < run("2001:db8:8::/45")[1] < 600000                                            # half the third group
    for cidr in ("2001:db8::/32", "2001:db8:8::/45", "203.0.113.0/24"):
        for neg in (False, True):
            took, _ = run(cidr, neg)
            assert took < 0.5, (cidr, neg, took)   # about 0.01 s; round 1 took seconds here

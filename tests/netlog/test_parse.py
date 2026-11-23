"""Reading log files (osinthub/netlog/importer.py), no server: every timestamp form Zeek or a converter writes lands on
the same instant, NDJSON and a JSON array read the same, a multi-member gzip is read whole, malformed lines are
counted and skipped (good rows kept), Suricata EVE flow and alert records map to the netlog columns the right way
round, and a file that is not a network log is refused with a reason. Cases from the critic's adversarial runs.

    uv run --with pytest pytest tests/netlog/test_parse.py -q
"""
from __future__ import annotations

import datetime as dt
import gzip
import io
import json

from _lake import conn, make_lake
LAKE = make_lake("parse")

from osinthub import db  # noqa: E402
from osinthub.netlog import importer  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
T = dt.datetime(2026, 11, 6, 11, 20, tzinfo=dt.UTC)
E = T.timestamp()
H, C2 = "192.0.2.10", "198.51.100.10"


def imp(body: bytes, name: str = "conn.log") -> dict:
    return importer.import_any(io.BytesIO(body), name, origin="upload", match=False)


def nd(rows: list) -> bytes:
    return "".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows).encode()


def row(uid: str) -> dict:
    r = db.query("SELECT ts, log_type, orig_h, orig_p, resp_h, resp_p, proto, server_name, query FROM netlog WHERE uid = ?",
                 [uid])
    assert len(r) == 1, (uid, r)
    return r[0]


def test_every_timestamp_form_is_the_same_instant():
    forms = {"S": E, "SSTR": str(E), "MS": int(E * 1e3), "US": int(E * 1e6), "NS": int(E * 1e9),
             "ISO": "2026-11-06T11:20:00", "ISOZ": "2026-11-06T11:20:00Z", "OFFSET": "2026-11-06T12:20:00+01:00",
             "FRAC": "2026-11-06T11:20:00.000000+0000"}
    res = imp(nd([conn(v, H, C2, uid=f"TS{k}") for k, v in forms.items()]), "ts.log")
    assert res["inserted"] == len(forms) and not res.get("bad_ts"), res
    bad = {k: row(f"TS{k}")["ts"] for k in forms if row(f"TS{k}")["ts"] != T}
    assert not bad, bad
    res = imp(nd([conn("yesterday", H, C2, uid="TSBAD")]), "badts.log")   # kept, flagged, never matched
    assert res["inserted"] == 1 and res["bad_ts"] == 1 and row("TSBAD")["ts"] is None


def test_ndjson_and_a_json_array_read_the_same():
    a = [conn(E + i, H, C2, uid=f"ND{i}") for i in range(3)]
    b = [conn(E + i, H, C2, uid=f"AR{i}") for i in range(3)]
    ra, rb = imp(nd(a), "nd.log"), imp(json.dumps(b).encode(), "array.json")
    assert ra["inserted"] == rb["inserted"] == 3, (ra, rb)
    for i in range(3):
        x, y = row(f"ND{i}"), row(f"AR{i}")
        assert x == y, (x, y)


def test_multi_member_gzip_is_read_whole():
    body = gzip.compress(nd([conn(E, H, C2, uid="GZ1")])) + gzip.compress(nd([conn(E + 1, H, C2, uid="GZ2")]))
    res = imp(body, "conn.log.gz")
    assert res["inserted"] == 2, res
    again = imp(body, "conn-copy.log.gz")
    assert again["duplicate"] is True and again["inserted"] == 0


def test_malformed_lines_are_counted_and_good_rows_kept():
    body = nd([conn(E, H, C2, uid="MAL1"), "this is not json", '{"ts": 1, "uid": "MALX", ',
               conn(E + 1, H, C2, uid="MAL2"), "[1,2,3]", conn(E + 2, H, C2, uid="MAL3")])
    res = imp(body, "malformed.log")
    assert res["inserted"] == 3 and res["skipped_lines"] == 3, res
    assert any("skipped" in w for w in res["warnings"]), res["warnings"]


def test_eve_flow_and_alert_map_the_right_way_round():
    flow = {"timestamp": "2026-11-06T13:00:00.000000+0000", "flow_id": 9100000000000001, "event_type": "flow",
            "src_ip": H, "src_port": 50001, "dest_ip": C2, "dest_port": 443, "proto": "TCP", "app_proto": "tls",
            "flow": {"start": "2026-11-06T11:20:00.000000+0000", "bytes_toserver": 1200, "bytes_toclient": 3400,
                     "state": "closed", "age": 7200}}
    # an alert on the C2's reply packet: the packet runs C2 -> home, the flow home -> C2
    alert = {"timestamp": "2026-11-06T11:21:00.000000+0000", "flow_id": 9100000000000002, "event_type": "alert",
             "src_ip": C2, "src_port": 443, "dest_ip": H, "dest_port": 50002, "proto": "TCP", "direction": "to_client",
             "flow": {"src_ip": H, "dest_ip": C2, "src_port": 50002, "dest_port": 443},
             "alert": {"action": "allowed", "gid": 1, "signature_id": 2099002, "rev": 1, "severity": 1,
                       "signature": "Example C2 beacon", "category": "A Network Trojan was detected"}}
    tls = {"timestamp": "2026-11-06T11:22:00.000000+0000", "flow_id": 9100000000000003, "event_type": "tls",
           "src_ip": H, "src_port": 50003, "dest_ip": C2, "dest_port": 443, "proto": "TCP",
           "tls": {"sni": "SNI-C2.example.", "version": "TLS 1.2"}}
    res = imp(nd([flow, alert, tls]), "eve.json")
    assert not res.get("error") and res["inserted"] == 3, res
    assert {"eve_flow", "eve_alert", "eve_tls"} <= set(res["log_types"]), res["log_types"]
    f = row("9100000000000001")
    assert f["ts"] == T and (f["orig_h"], f["resp_h"], f["resp_p"]) == (H, C2, 443)   # the flow's start, not log time
    a = row("9100000000000002")
    assert (a["orig_h"], a["resp_h"], a["resp_p"]) == (H, C2, 443), a                  # home is the originator
    assert row("9100000000000003")["server_name"] == "sni-c2.example"


def test_files_that_are_not_network_logs_are_refused_with_a_reason():
    for body, name, words in ((nd([{"name": "x", "value": 1}, {"name": "y", "value": 2}]), "inventory.json",
                               "not a Zeek or Suricata EVE log"),
                              (b"ts\tuid\tid.orig_h\n1\tC1\t192.0.2.1\n", "conn.tsv", "not a Zeek JSON log"),
                              (b"", "empty.log", "")):
        res = imp(body, name)
        assert res.get("error") and words in res["error"] and not res.get("inserted"), (name, res)

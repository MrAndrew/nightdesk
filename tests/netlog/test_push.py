"""Push uploads (osinthub/netlog/ingest.py) on a temporary lake: tokens, limits, lockout, import, TLS.

    uv run --with pytest pytest tests/netlog/test_push.py -q

No network beyond loopback; the listener test binds a free port on 127.0.0.1.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import socket
import ssl
import threading
import time
import unittest
from pathlib import Path

for k in ("OSINTHUB_INGEST", "OSINTHUB_INGEST_HOST", "OSINTHUB_INGEST_PORT", "OSINTHUB_INGEST_CERT", "OSINTHUB_INGEST_KEY"):
    os.environ.pop(k, None)
from _lake import make_lake  # noqa: E402
LAKE = make_lake("ingest")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.netlog import ingest  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)

ui = FastAPI()
ui.include_router(ingest.mgmt, prefix="/api/netlog")
UI = TestClient(ui)
DEV = TestClient(ingest.build_app())


def conn_log(n: int, seed: int = 0) -> bytes:
    t0 = time.time() - 3600
    return "".join(json.dumps({"ts": t0 + i, "uid": f"C{seed}x{i}", "id.orig_h": "192.0.2.10", "id.orig_p": 40000 + i,
                               "id.resp_h": "198.51.100.7", "id.resp_p": 443, "proto": "tcp", "conn_state": "SF"}) + "\n"
                   for i in range(n)).encode()


def new_sender(name: str, **kw) -> tuple[str, str]:
    r = UI.post("/api/netlog/ingest/senders", json={"name": name, **kw})
    assert r.status_code == 200, r.text
    return r.json()["sender"]["id"], r.json()["token"]


def auth(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


class Tokens(unittest.TestCase):
    def test_token_is_shown_once_and_stored_hashed(self):
        sid, tok = new_sender("hash check")
        self.assertTrue(tok.startswith("hlta_") and len(tok) > 40)
        listed = UI.get("/api/netlog/ingest").json()["senders"]
        s = next(x for x in listed if x["id"] == sid)
        self.assertNotIn("token_sha256", s)
        self.assertEqual(s["token_hint"], tok[-4:])
        stored = json.dumps(db.get_setting(ingest.SENDERS_KEY))
        self.assertNotIn(tok, stored)
        self.assertIn(hashlib.sha256(tok.encode()).hexdigest(), stored)

    def test_unknown_and_missing_tokens_are_refused(self):
        self.assertEqual(DEV.get("/ingest/check").status_code, 401)
        self.assertEqual(DEV.get("/ingest/check", headers=auth("hlta_nope")).status_code, 401)
        ingest._fails.clear()

    def test_rotate_revokes_the_old_token(self):
        sid, old = new_sender("rotate me")
        self.assertEqual(DEV.get("/ingest/check", headers=auth(old)).status_code, 200)
        new = UI.post(f"/api/netlog/ingest/senders/{sid}/rotate").json()["token"]
        self.assertEqual(DEV.get("/ingest/check", headers=auth(old)).status_code, 401)
        self.assertEqual(DEV.get("/ingest/check", headers=auth(new)).status_code, 200)
        UI.delete(f"/api/netlog/ingest/senders/{sid}")
        self.assertEqual(DEV.get("/ingest/check", headers=auth(new)).status_code, 401)
        ingest._fails.clear()

    def test_pause_and_address_allowlist(self):
        sid, tok = new_sender("fenced", allow_cidrs="192.0.2.1")
        # TestClient's peer is "testclient", which is in no allowed network
        self.assertEqual(DEV.get("/ingest/check", headers=auth(tok)).status_code, 403)
        UI.patch(f"/api/netlog/ingest/senders/{sid}", json={"allow_cidrs": [], "paused": True})
        self.assertEqual(DEV.get("/ingest/check", headers=auth(tok)).status_code, 423)
        self.assertEqual(UI.patch(f"/api/netlog/ingest/senders/{sid}", json={"allow_cidrs": "not-an-ip"}).status_code, 400)

    def test_lockout_after_repeated_bad_tokens(self):
        _, tok = new_sender("locked out")
        codes = [DEV.get("/ingest/check", headers=auth("hlta_wrong")).status_code for _ in range(ingest.FAIL_LIMIT)]
        self.assertEqual(codes[-1], 401)
        self.assertEqual(DEV.get("/ingest/check", headers=auth(tok)).status_code, 429)  # even a good token, for a while
        ingest._blocked.clear()
        ingest._fails.clear()
        self.assertEqual(DEV.get("/ingest/check", headers=auth(tok)).status_code, 200)

    def test_duplicate_names_rejected(self):
        new_sender("Same Name")
        self.assertEqual(UI.post("/api/netlog/ingest/senders", json={"name": "same name"}).status_code, 400)


class Uploads(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sid, cls.tok = new_sender("uploader")

    def test_upload_imports_with_push_origin(self):
        # wait=1 holds the reply until the import worker (a background task in the app) is done
        stop = threading.Event()

        def worker():
            while not stop.is_set():
                ingest.process_pending()
                ingest.WAKE.wait(0.2)
                ingest.WAKE.clear()
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        try:
            r = DEV.post("/ingest?wait=1", headers={**auth(self.tok), "X-HLTA-Name": "conn.log.gz"},
                         content=gzip.compress(conn_log(25, 1)))
        finally:
            stop.set()
            t.join(5)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["inserted"], 25)
        f = db.query("SELECT origin, rows, inserted, status FROM netlog_files WHERE origin = 'push:uploader' AND name = 'conn.log.gz'")
        self.assertEqual(f[0]["inserted"], 25)
        s = next(x for x in ingest.senders() if x["id"] == self.sid)
        self.assertGreaterEqual(s["uploads"], 1)
        self.assertGreaterEqual(s["rows"], 25)

    def test_put_with_name_in_path_and_bad_content_is_parked(self):
        r = DEV.put("/ingest/../../etc/notes.txt", headers=auth(self.tok), content=b"this is not json\n")
        self.assertIn(r.status_code, (202, 404))  # a router may normalise the path away; either way nothing escapes
        r = DEV.put("/ingest/notes.txt", headers=auth(self.tok), content=b"this is not json\n")
        self.assertEqual(r.status_code, 202)
        ingest.process_pending()
        failed = list((ingest.PUSH_DIR / "failed").rglob("*notes.txt"))
        self.assertTrue(failed)
        for p in (ingest.PUSH_DIR).rglob("*"):
            self.assertTrue(str(p.resolve()).startswith(str(ingest.PUSH_DIR.resolve())))
        up = next(u for u in ingest.recent_uploads() if u["name"] == "notes.txt")
        self.assertEqual(up["status"], "error")

    def test_limits(self):
        c = ingest.cfg()
        ingest.save_cfg({**c, "max_mb": 1})
        try:
            r = DEV.post("/ingest", headers=auth(self.tok), content=b"x" * (1_100_000))
            self.assertEqual(r.status_code, 413)
            self.assertFalse([p for p in (ingest.PUSH_DIR / self.sid).glob("*")
                              if p.is_file() and "notes" not in p.name and "conn" not in p.name])
        finally:
            ingest.save_cfg(c)
        self.assertEqual(DEV.post("/ingest", headers=auth(self.tok), content=b"").status_code, 400)
        self.assertEqual(DEV.post("/ingest", headers=auth(self.tok), files={"f": ("a.log", b"{}\n")}).status_code, 415)

    def test_duplicate_upload_is_harmless(self):
        body = conn_log(5, 2)
        for _ in range(2):
            DEV.post("/ingest", headers={**auth(self.tok), "X-HLTA-Name": "dup.log"}, content=body)
        ingest.process_pending()
        rows = db.query("SELECT count(*) AS n FROM netlog WHERE uid LIKE 'C2x%'")[0]["n"]
        self.assertEqual(rows, 5)


class Settings(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(UI.put("/api/netlog/ingest", json={"port": 80}).status_code, 400)
        self.assertEqual(UI.put("/api/netlog/ingest", json={"host": "example.com"}).status_code, 400)
        self.assertFalse(UI.get("/api/netlog/ingest").json()["config"]["enabled"])  # off by default

    def test_listener_serves_tls_with_the_advertised_pin(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        d = UI.put("/api/netlog/ingest", json={"enabled": True, "host": "127.0.0.1", "port": port, "tls": True}).json()
        try:
            self.assertTrue(d["status"]["running"], d["status"])
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE   # we check the pin ourselves, like curl --pinnedpubkey
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, ctx.wrap_socket(raw) as tls:
                der = tls.getpeercert(binary_form=True)
                tls.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                reply = tls.recv(4096)
            self.assertIn(b"200 OK", reply)
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            spki = x509.load_der_x509_certificate(der).public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            self.assertEqual("sha256//" + base64.b64encode(hashlib.sha256(spki).digest()).decode(), d["tls"]["pin"])
            key = Path(ingest.cert_paths()[1])
            self.assertEqual(key.stat().st_mode & 0o077, 0)  # private key readable by the owner only
        finally:
            d = UI.put("/api/netlog/ingest", json={"enabled": False}).json()
        self.assertFalse(d["status"]["running"])


class SilenceAlerts(unittest.TestCase):
    """Cadence learning and the sensor_silent alert lifecycle, with controlled clocks."""

    def make(self, name, every=300.0, n=10, end=None):
        sid, _ = new_sender(name)
        end = end or time.time()
        with ingest._lock:
            s = ingest._find(sid)
            s["checkins"] = [end - every * (n - 1 - i) for i in range(n)]
            s["last_seen"] = ingest._iso(end)
        return sid, end

    def alert(self, sid):
        rows = db.query("SELECT * FROM alerts WHERE rule = 'sensor_silent' AND id LIKE ?", [f"silent:{sid}:%"])
        return rows[0] if rows else None

    def test_cadence_and_threshold(self):
        sid, _ = self.make("cadence 5m")
        s = ingest._find(sid)
        self.assertAlmostEqual(ingest.cadence(s)[0], 300, delta=1)
        self.assertAlmostEqual(ingest.threshold(s)[0], 900, delta=1)       # 5-min cron: alert after 15 min
        s2 = ingest._find(self.make("cadence 1h", every=3600)[0])
        self.assertAlmostEqual(ingest.threshold(s2)[0], 3 * 3600, delta=1)  # hourly: 3 h
        s3 = ingest._find(self.make("cadence 1d", every=86400)[0])
        self.assertAlmostEqual(ingest.threshold(s3)[0], 30 * 3600, delta=1)  # daily: 30 h

    def test_bursts_count_as_one_run_and_learning_needs_three_gaps(self):
        sid, _ = new_sender("bursty")
        s = ingest._find(sid)
        t = time.time()
        s["checkins"] = [t - 900, t - 890, t - 600, t - 300]  # 2 real gaps, plus a burst
        self.assertEqual(ingest.cadence(s), (None, 2))
        self.assertEqual(ingest.health(s, t + 5000, since=0)["state"], "learning")
        self.assertEqual(ingest.evaluate(now=t + 5000, since=0)["opened"], [])

    def test_open_escalate_resolve(self):
        sid, end = self.make("garage fw")
        self.assertNotIn("garage fw", ingest.evaluate(now=end + 600, since=0)["opened"])   # late, not yet silent
        self.assertEqual(ingest.health(ingest._find(sid), end + 600, since=0)["state"], "late")
        self.assertIn("garage fw", ingest.evaluate(now=end + 1000, since=0)["opened"])
        a = self.alert(sid)
        self.assertEqual((a["severity"], a["status"], a["indicator"], a["source"]), ("medium", "new", "garage fw", "ingest"))
        self.assertEqual(json.loads(a["evidence"])["state"], "open")
        self.assertEqual(ingest.evaluate(now=end + 1100, since=0)["opened"], [])           # one alert per outage
        ingest.evaluate(now=end + 25 * 3600, since=0)
        self.assertEqual(self.alert(sid)["severity"], "high")                               # a day of silence
        with ingest._lock:
            ingest._find(sid)["checkins"].append(end + 25 * 3600 + 30)
        self.assertIn("garage fw", ingest.evaluate(now=end + 25 * 3600 + 40, since=0)["resolved"])
        a = self.alert(sid)
        ev = json.loads(a["evidence"])
        self.assertEqual((a["severity"], ev["state"]), ("low", "resolved"))
        self.assertGreater(ev["gap_s"], 24 * 3600)
        self.assertIsNone(ingest._find(sid)["outage"])
        self.assertEqual(db.query("SELECT count(*) AS n FROM alerts WHERE id LIKE ?", [f"silent:{sid}:%"])[0]["n"], 1)

    def test_no_alert_right_after_night_desk_or_the_listener_starts(self):
        sid, end = self.make("restart case")
        # Night Desk was down from end+60 to end+900: the device could not reach it, so wait a full threshold
        self.assertEqual(ingest.evaluate(now=end + 1000, since=end + 900)["opened"], [])
        self.assertIn("restart case", ingest.evaluate(now=end + 1900, since=end + 900)["opened"])

    def test_paused_and_off_never_alert(self):
        sid, end = self.make("paused one")
        UI.patch(f"/api/netlog/ingest/senders/{sid}", json={"paused": True})
        sid2, _ = self.make("muted one", end=end)
        UI.patch(f"/api/netlog/ingest/senders/{sid2}", json={"alert_after_min": 0})
        res = ingest.evaluate(now=end + 99999, since=0)
        self.assertNotIn("paused one", res["opened"])
        self.assertNotIn("muted one", res["opened"])
        self.assertEqual(UI.patch(f"/api/netlog/ingest/senders/{sid2}", json={"alert_after_min": 1}).status_code, 400)

    def test_manual_threshold(self):
        sid, end = self.make("manual", every=300)
        UI.patch(f"/api/netlog/ingest/senders/{sid}", json={"alert_after_min": 60})
        self.assertNotIn("manual", ingest.evaluate(now=end + 1800, since=0)["opened"])
        self.assertIn("manual", ingest.evaluate(now=end + 3700, since=0)["opened"])

    def test_heartbeat_records_a_checkin_and_resolves(self):
        sid, end = self.make("heartbeat", end=time.time() - 3600)
        tok = UI.post(f"/api/netlog/ingest/senders/{sid}/rotate").json()["token"]
        self.assertIn("heartbeat", ingest.evaluate(now=time.time(), since=0)["opened"])
        n = len(ingest._find(sid)["checkins"])
        self.assertEqual(DEV.get("/ingest/check", headers=auth(tok)).status_code, 200)
        self.assertEqual(len(ingest._find(sid)["checkins"]), n + 1)
        self.assertIn("heartbeat", ingest.evaluate(now=time.time() + 1, since=0)["resolved"])

    def test_alert_detail_endpoint(self):
        from osinthub.netlog.api import alert_detail
        sid, end = self.make("detail fw")
        ingest.evaluate(now=end + 1000, since=0)
        d = alert_detail(self.alert(sid)["id"])
        self.assertEqual(d["rows"], [])
        self.assertEqual(d["sender_now"]["id"], sid)
        self.assertEqual(d["evidence"]["sender"]["name"], "detail fw")

    def test_threat_rehunt_leaves_silence_alerts_alone(self):
        from osinthub.netlog import matcher
        sid, end = self.make("rehunt fw")
        ingest.evaluate(now=end + 1000, since=0)
        matcher.match("true")
        self.assertIsNotNone(self.alert(sid))


if __name__ == "__main__":
    unittest.main()

"""v1.2 sqlgate round 2: with the SQL console on, no answer names a host path or a secret, even where the app's own
tables store them. The lake sits where the default `./lake` would put it for an owner who starts Night Desk in
~/Projects/nd (here a temporary folder standing in for the home folder). The demo network data, an upload, a watched
inbox outside the lake and stored paths fill the tables; every console answer is scanned for the real paths.
The app's own folder (config.ROOT) is set to a folder inside that stand-in home too, so the tests prove the same thing
wherever the clone sits: under the real home folder or outside it (/private/tmp, /src in CI), where the real checkout
is by design not hidden.
Secrets: the notification webhook (with its token) and the log-sender token live in the settings table, which the
console refuses.

    uv run --with pytest pytest tests/security/test_v12_sqlgate_paths.py -q
"""
from __future__ import annotations

import atexit
import io
import json
import os
import pwd
import shutil
import tempfile
import unittest
from pathlib import Path

REAL_HOME = pwd.getpwuid(os.getuid()).pw_dir
FAKE_HOME = Path(os.path.realpath(tempfile.mkdtemp(prefix="nd-test-sqlgate-home-")))
atexit.register(shutil.rmtree, FAKE_HOME, ignore_errors=True)
LAKE = FAKE_HOME / "Projects" / "nd" / "lake"
LAKE.mkdir(parents=True)
INBOX = FAKE_HOME / "zeek-logs"
INBOX.mkdir()
APP = FAKE_HOME / "Code" / "night-desk"   # the app's folder in the stand-in home (not the lake's parent: see below)

from _lake import make_lake  # noqa: E402
make_lake("sqlgate-paths", disable="news,entities,ai", OSINTHUB_SQL_CONSOLE="1", HOME=str(FAKE_HOME),
          OSINTHUB_LAKE=str(LAKE))

from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
import osinthub.api as A  # noqa: E402
from osinthub.netlog import importer, ingest  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

REAL_ROOT = config.ROOT
config.ROOT = APP    # only the console's path marks read it here; the real checkout may sit outside every home folder
assert config.LAKE == LAKE and str(Path.home()) == str(FAKE_HOME) and config.SQL_CONSOLE
db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL + importer.LEDGER_SQL)
C = TestClient(A.app, base_url="http://localhost")
H = {"Origin": "http://localhost"}

# Every spelling of a folder the console must never show (also the /var form of a /private/var temp folder).
PATHS = {REAL_HOME, str(FAKE_HOME), str(LAKE), str(config.DB_PATH.parent), str(config.ROOT)}
PATHS |= {p.replace("/private/var/", "/var/", 1) for p in PATHS if p.startswith("/private/var/")}
PATHS |= {p.replace("/", "\\") for p in PATHS}
WEBHOOK = "http://gotify.lan/message?token=invented-AbCdtok123"


def post_sql(q):
    return C.post("/api/sql", json={"sql": q}, headers=H)


def leaks(text: str) -> list[str]:
    return [p for p in PATHS if p in text]


# --- fill the tables with the paths and secrets the app really stores
r = C.post("/api/netlog/demo", headers=H)
assert r.status_code == 200, r.text
r = C.post("/api/upload", files={"file": ("up.csv", io.BytesIO(b"ip,label\n192.0.2.44,test\n"), "text/csv")},
           data={"label": "mine"}, headers=H)
assert r.status_code == 200, r.text
r = C.put("/api/netlog/inbox", json={"path": str(INBOX)}, headers=H)
assert r.status_code == 200, r.text
r = C.put("/api/notify", json={"url": WEBHOOK, "preset": "gotify"}, headers=H)
assert r.status_code == 200, r.text
SENDER, SENDER_TOKEN = ingest.create_sender("garage router")
SENDER_HASH = ingest._hash(SENDER_TOKEN)
SECRETS = ["invented-AbCdtok123", SENDER_TOKEN, SENDER_HASH]
db.execute("""INSERT INTO events (id, source, kind, ts, title, summary, raw_path, tags) VALUES
    ('p1', 'upload', 'indicator', now(), 'stored', ?, ?, ?)""",
           [f"seen in {REAL_HOME}/x and {config.ROOT}/web and C:{str(LAKE).replace('/', chr(92))}\\raw",
            f"{config.DB_PATH.parent}/hub.duckdb", [f"{LAKE}/raw/a", f"{FAKE_HOME}/notes.txt"]])

TABLES = [t for (t,) in db.cursor().execute(
    "SELECT table_name FROM duckdb_tables() WHERE schema_name = 'main' AND NOT internal ORDER BY 1").fetchall()]


class Redaction(unittest.TestCase):
    def test_the_tables_really_hold_paths(self):
        """The check below is only meaningful if the stored data has the paths in it."""
        rows = db.query("SELECT path FROM netlog_files")
        self.assertTrue(rows and all(str(LAKE) in r["path"] for r in rows))
        self.assertIn(str(INBOX), json.dumps(db.get_setting("netlog_inbox")))
        self.assertTrue(db.query("SELECT 1 FROM events WHERE raw_path LIKE ?", [f"{LAKE}%"]))

    def test_every_table_and_its_summary_shows_no_path(self):
        self.assertIn("netlog_files", TABLES)
        self.assertIn("settings", TABLES)
        ran = 0
        for t in TABLES:
            for q in (f'SELECT * FROM "{t}"', f'SUMMARIZE "{t}"', f'DESCRIBE "{t}"', f'SELECT * FROM main."{t}" LIMIT 3'):
                r = post_sql(q)
                self.assertEqual(leaks(r.text), [], f"{q} -> {r.text[:300]}")
                for sec in SECRETS:
                    self.assertNotIn(sec, r.text, q)
                if t == "settings":
                    self.assertEqual(r.status_code, 400, q)
                elif not t.startswith("_"):
                    self.assertEqual(r.status_code, 200, f"{q} -> {r.text[:200]}")
                    ran += 1
        self.assertGreater(ran, 40)

    def test_paths_become_placeholders(self):
        rows = post_sql("SELECT path FROM netlog_files").json()["rows"]
        self.assertTrue(rows and all(r[0].startswith("<lake>/raw/") for r in rows), rows[:2])
        r = post_sql("SELECT summary, raw_path, tags FROM events WHERE id = 'p1'").json()["rows"][0]
        self.assertEqual(r[0], "seen in ~/x and <app>/web and C:<lake>\\raw")
        self.assertEqual(r[1], "<db>/hub.duckdb")
        self.assertEqual(r[2], ["<lake>/raw/a", "~/notes.txt"])
        r = post_sql("SELECT raw_path FROM events WHERE source = 'upload' AND id <> 'p1' LIMIT 1").json()["rows"]
        self.assertTrue(r and r[0][0].startswith("<lake>/uploads/"), r)
        s = post_sql("SELECT max(raw_path) AS m FROM events").json()
        self.assertTrue(s["rows"][0][0].startswith(("<lake>", "<db>")))

    def test_inside_json_text_structs_and_column_names(self):
        q = (f"SELECT json_object('path', '{INBOX}') AS j, {{'p': '{LAKE}/tmp'}} AS s, "
             f"map(['{FAKE_HOME}/k'], ['{config.ROOT}']) AS m, 1 AS \"{LAKE}/col\"")
        r = post_sql(q)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(leaks(r.text), [])
        j = r.json()
        self.assertEqual(j["columns"][-1], "<lake>/col")
        self.assertEqual(json.loads(j["rows"][0][0]), {"path": "~/zeek-logs"})
        self.assertEqual(j["rows"][0][1], {"p": "<lake>/tmp"})
        self.assertEqual(j["rows"][0][2], {"~/k": "<app>"})

    def test_only_whole_paths_are_rewritten(self):
        lake = str(LAKE)
        q = (f"SELECT 'https://example.com{lake}/x' AS u, '{lake}-old/x' AS sib, '{lake}x' AS longer, "
             f"'see {lake}.' AS dot, 'plain text' AS t")
        row = post_sql(q).json()["rows"][0]
        self.assertEqual(row[0], f"https://example.com{lake}/x")   # inside a longer name (a URL path): left alone
        self.assertEqual(row[1], "~/Projects/nd/lake-old/x")      # not the lake, but under the home folder
        self.assertEqual(row[2], "~/Projects/nd/lakex")
        self.assertEqual(row[3], "see <lake>.")
        self.assertEqual(row[4], "plain text")

    def test_the_real_checkout_is_hidden_only_inside_a_home_folder(self):
        try:
            config.ROOT = REAL_ROOT
            in_home = any(str(REAL_ROOT.resolve()).startswith(os.path.realpath(h) + "/") for h in (REAL_HOME, FAKE_HOME))
            row = post_sql(f"SELECT '{REAL_ROOT}/web' AS w").json()["rows"][0]
            self.assertEqual(row[0], "<app>/web" if in_home else f"{REAL_ROOT}/web")
        finally:
            config.ROOT = APP

    def test_marks_longest_first_and_root_never_a_mark(self):
        marks = A._sql_path_marks()
        self.assertEqual([len(m) for m, _ in marks], sorted((len(m) for m, _ in marks), reverse=True))
        self.assertNotIn("", [m for m, _ in marks])
        self.assertNotIn("/", [m for m, _ in marks])
        self.assertEqual(dict(marks)[str(config.DB_PATH.parent)], "<db>")
        self.assertEqual(dict(marks)[str(LAKE)], "<lake>")
        self.assertEqual(dict(marks)[str(FAKE_HOME)], "~")
        self.assertEqual(dict(marks)[str(APP)], "<app>")


class Secrets(unittest.TestCase):
    def test_the_secrets_are_really_stored(self):
        self.assertEqual(db.get_setting("notify.config")["url"], WEBHOOK)
        self.assertIn(SENDER_HASH, json.dumps(db.get_setting(ingest.SENDERS_KEY)))

    def test_settings_refused_in_every_spelling(self):
        for q in ["SELECT value FROM settings WHERE key = 'notify.config'", "SELECT * FROM main.settings",
                  'SELECT * FROM "SETTINGS"', "TABLE settings", "FROM settings", "SUMMARIZE settings",
                  "DESCRIBE settings", "SHOW settings", "WITH s AS (SELECT * FROM settings) SELECT * FROM s",
                  "SELECT (SELECT max(value) FROM settings)", "SELECT * FROM events WHERE id IN (SELECT key FROM settings)",
                  f"SELECT * FROM {db.cursor().execute('SELECT current_database()').fetchone()[0]}.main.settings",
                  "PIVOT settings ON key IN ('notify.config') USING max(value)",
                  "SELECT * FROM pragma_storage_info('settings')"]:
            r = post_sql(q)
            self.assertEqual(r.status_code, 400, f"{q} -> {r.text[:200]}")
            for sec in SECRETS:
                self.assertNotIn(sec, r.text, q)
        self.assertIn("holds the app's own settings, some of them secret",
                      post_sql("SELECT * FROM settings").json()["detail"])

    def test_catalog_shows_settings_columns_but_never_values(self):
        for q in ["SELECT * FROM pragma_table_info('settings')", "SELECT * FROM information_schema.columns",
                  "SELECT * FROM duckdb_tables()", "SELECT * FROM duckdb_columns()", "SHOW ALL TABLES"]:
            r = post_sql(q)
            self.assertEqual(r.status_code, 200, f"{q} -> {r.text[:200]}")
            for sec in SECRETS:
                self.assertNotIn(sec, r.text, q)

    def test_the_app_still_masks_and_reads_them(self):
        n = C.get("/api/notify").json()
        self.assertNotIn("invented-AbCdtok123", json.dumps(n))
        self.assertIn('"url_set": true', json.dumps(n))


if __name__ == "__main__":
    unittest.main()


class WithNames(unittest.TestCase):
    """Fix round 3 lead fix: a CTE is scoped to its own query, so a WITH name that reuses a table or system name must
    not unlock that table elsewhere in the same text (sqlgate-r2 failure 1)."""

    def test_a_with_name_cannot_unlock_settings_or_system_views(self):
        for name in ["settings", "SETTINGS", '"settings"', "pg_settings", "duckdb_databases", "pragma_database_list",
                     "duckdb_logs", "pg_prepared_statements", "events", "duckdb_settings"]:
            bare = name.strip('"').lower()
            for q in [f"SELECT s.* FROM (WITH {name} AS (SELECT 1) SELECT 1) q, {bare} s",
                      f"SELECT s.value FROM (WITH {name} AS (SELECT 1) SELECT 1) q, settings s WHERE s.key = 'notify.config'",
                      f"WITH a AS (WITH {name} AS (SELECT 1) SELECT 1) SELECT * FROM a, {bare}"]:
                r = post_sql(q)
                self.assertEqual(r.status_code, 400, f"{q} -> {r.text[:200]}")
                for sec in SECRETS:
                    self.assertNotIn(sec, r.text, q)

    def test_ordinary_with_names_still_work(self):
        r = post_sql("WITH q1 AS (SELECT count(*) AS n FROM events) SELECT n FROM q1")
        self.assertEqual(r.status_code, 200, r.text[:200])
        r = post_sql("WITH a AS (SELECT 1 AS x), b AS (SELECT x + 1 AS y FROM a) SELECT y FROM b")
        self.assertEqual(r.status_code, 200, r.text[:200])


class OnePartPaths(unittest.TestCase):
    """In the Docker image the app lives at /app, the lake at /data and the home folder is /root: those one-part paths
    are ordinary text in logs and URLs and are never rewritten (sqlgate-r2 failure 2)."""

    def test_docker_like_roots_leave_data_alone(self):
        old = (config.ROOT, config.LAKE, config.DB_PATH)
        try:
            config.ROOT, config.LAKE, config.DB_PATH = Path("/app"), Path("/data"), Path("/data/db/hub.duckdb")
            red = A._sql_redactor()
            for v in ["/app/login.php", "GET /app/admin HTTP/1.1", "/data/export.csv", "/root/.ssh/id_rsa probe",
                      '{"uri": "/app/x"}', "Attackers wiped /data/db", "/data/db/hub.duckdb"]:
                self.assertEqual(red(v), v)                    # outside the home folder nothing is rewritten
            self.assertEqual(red(f"{FAKE_HOME}/notes.txt"), "~/notes.txt")      # the home folder still is
        finally:
            config.ROOT, config.LAKE, config.DB_PATH = old

"""SQL console sandbox: table allowlist, no DuckDB extension downloads, lake-only file access.

Every table a console query names (with its catalog and schema, and every SHOW target) must be a CTE of the query or
an existing table or view of the app's database, so a file path or URL in any spelling ("/dir/x".csv, globs,
s3://...) is refused before anything runs. Every DuckDB the app opens has extension auto-install and auto-load off,
and the app database may touch files only in the lake and its own folder.

    uv run --with pytest pytest tests/security/test_sql_allowlist.py -q
"""
from __future__ import annotations

import atexit
import http.server
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

LAKE = tempfile.mkdtemp(prefix="sql-allow-test-")
os.environ["OSINTHUB_LAKE"] = LAKE
os.environ["OSINTHUB_OFFLINE"] = "1"
os.environ["OSINTHUB_SQL_CONSOLE"] = "1"   # off by default since v1.2
os.environ["OSINTHUB_DISABLE_EXT"] = "news,entities,netlog,ai"
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import duckdb  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
import osinthub.api as A  # noqa: E402

db.connect()
C = TestClient(A.app, base_url="http://localhost")
db.execute("""INSERT INTO events (id, source, kind, ts, title, severity, country, ip) VALUES
    ('p1', 'feodo', 'c2', TIMESTAMPTZ '2026-01-01 00:00:00+00', 'a', 5, 'US', '192.0.2.1'),
    ('p2', 'cisa_kev', 'kev', TIMESTAMPTZ '2026-01-03 00:00:00+00', 'c', 9, 'US', '198.51.100.3')""")

# real files the sandbox must never hand back (in this module's own temp folder, outside the lake)
BAIT = Path(tempfile.mkdtemp(prefix="sql-allow-bait-")) / "bait.csv"
BAIT.write_text("a,b\nSECRET42,1\nSECRET43,2\n")
B = str(BAIT)
D = str(BAIT.parent)
atexit.register(shutil.rmtree, LAKE, True)          # scratch data goes when the module's process ends
atexit.register(shutil.rmtree, D, True)
(BAIT.parent / "bait.json").write_text('{"k": "SECRETJSON"}\n')
with duckdb.connect() as _c:
    _c.execute(f"COPY (SELECT 'SECRETPQ' AS a) TO '{D}/bait.parquet' (FORMAT parquet)")


class _Listener(http.server.BaseHTTPRequestHandler):
    """A loopback stand-in for the internet: the extension repository and every URL a test names point here."""
    hits: list[str] = []

    def do_GET(self):
        _Listener.hits.append(self.path)
        self.send_response(404)
        self.end_headers()
    do_HEAD = do_GET

    def log_message(self, *a):
        pass


NET = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Listener)
threading.Thread(target=NET.serve_forever, daemon=True).start()
NET_URL = f"http://127.0.0.1:{NET.server_address[1]}"
# an empty extension folder (in the lake: DuckDB may only touch the lake), so nothing installed on this machine loads
EXT_DIR = tempfile.mkdtemp(dir=LAKE)
db.connect().execute(f"SET extension_directory = '{EXT_DIR}'")
db.connect().execute(f"SET autoinstall_extension_repository = '{NET_URL}'")
db.connect().execute(f"SET custom_extension_repository = '{NET_URL}'")


def post_sql(q):
    return C.post("/api/sql", json={"sql": q})


class TableAllowlist(unittest.TestCase):
    def rejected(self, q):
        r = post_sql(q)
        self.assertEqual(r.status_code, 400, f"should block: {q} -> {r.status_code} {r.text[:200]}")
        self.assertIn("not allowed", r.text.lower(), q)
        for secret in ("SECRET4", "SECRETJSON", "SECRETPQ", "root:"):
            self.assertNotIn(secret, r.text, q)

    def test_schema_qualified_file_paths_refused(self):
        for f in ("csv", "json", "parquet", '"csv"'):
            for q in [
                f'SELECT * FROM "{D}/bait".{f}',
                f'FROM "{D}/bait".{f}',
                f'TABLE "{D}/bait".{f}',
                f'DESCRIBE "{D}/bait".{f}',
                f'DESCRIBE TABLE "{D}/bait".{f}',
                f'SUMMARIZE "{D}/bait".{f}',
                f'SHOW "{D}/bait".{f}',
                f'SELECT * FROM range(1) r, "{D}/bait".{f}',
                f'SELECT * FROM events WHERE id IN (SELECT a FROM "{D}/bait".{f})',
                f'WITH q AS (SELECT * FROM "{D}/bait".{f}) SELECT * FROM q',
                f'SELECT * FROM "{D}/*".{f}',
                f'SELECT * FROM "{D}"."bait".{f}',
                f'SELECT * FROM "{D}/x"."bait".{f}',
                f'UNPIVOT "{D}/bait".{f} ON a INTO NAME n VALUE v',
            ]:
                self.rejected(q)
        for q in [
            f'PIVOT "{D}/bait".csv ON a IN (\'SECRET42\', \'SECRET43\') USING sum(b)',
            f'SELECT * FROM "{D}/bait".csv PIVOT (sum(b) FOR a IN (\'SECRET42\', \'SECRET43\'))',
            f'UNPIVOT "{D}/bait".json ON k INTO NAME n VALUE v',
            f'SELECT a FROM "{D}/bait" . "csv"',
            f'SELECT/**/a FROM/**/"{D}/bait"/**/./**/csv',
            f'SELECT * FROM main."{D}/bait.csv"',
            f'SELECT * FROM "{D}/bait.csv"',
            f"SELECT * FROM '{D}/bait.csv'",
            f'SELECT * FROM "{D}/bait.csv".gz',
            "SELECT * FROM bait.csv",
            '''SELECT * FROM "pyproject".toml''',
            f'SELECT * FROM "{LAKE}/../x".csv',
            f'SELECT * FROM (WITH csv AS (SELECT 1) SELECT * FROM csv), "{D}/bait".csv',
            f'WITH "{D}/bait.csv" AS (SELECT 1 AS a) SELECT * FROM "{D}/bait.csv"',
            f'WITH bait AS (SELECT 1 AS a) SELECT * FROM "{D}".bait',
            f'SHOW TABLES FROM "{D}"',
            f'SELECT * FROM (DESCRIBE "{D}/bait".csv)',
            f'SELECT * FROM (SUMMARIZE "{D}/bait".csv)',
        ]:
            self.rejected(q)

    def test_file_in_the_lake_also_refused(self):
        # the allowlist is about table names, not directories: even a file inside the lake is not a table
        inside = Path(LAKE) / "tmp" / "lakebait.csv"
        inside.parent.mkdir(exist_ok=True)
        inside.write_text("a\nLAKESECRET\n")
        for q in [f"SELECT * FROM '{inside}'", f'SELECT * FROM "{inside.with_suffix("")}".csv']:
            r = post_sql(q)
            self.assertEqual(r.status_code, 400, q)
            self.assertNotIn("LAKESECRET", r.text)

    def test_url_spellings_refused_without_network(self):
        before = len(_Listener.hits)
        for q in [
            f'SELECT * FROM "{NET_URL}/x".csv',
            f"SELECT * FROM '{NET_URL}/x.csv'",
            f'SELECT * FROM "{NET_URL}/x.csv"',
            f'PIVOT "{NET_URL}/x".parquet ON a IN (1) USING count(*)',
            'SELECT * FROM "s3://bucket/x".parquet',
            'SELECT * FROM "https://198.51.100.7/x".json',
            f'DESCRIBE "{NET_URL}/x".csv',
            f'SHOW "{NET_URL}/x".csv',
        ]:
            self.rejected(q)
        self.assertEqual(_Listener.hits[before:], [])

    def test_sql_auto_complete_no_longer_allowed(self):
        r = post_sql("SELECT * FROM sql_auto_complete('SEL')")
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("not allowed", r.text.lower())
        self.assertNotIn("sql_auto_complete", A.SQL_TABLE_FUNCS_OK)

    def test_real_tables_views_and_ctes_still_allowed(self):
        cat = post_sql("SELECT current_database()").json()["rows"][0][0]
        for q in [
            "SELECT count(*) FROM events", "SELECT count(*) FROM main.events", f"SELECT count(*) FROM {cat}.main.events",
            f"SELECT count(*) FROM {cat}.events", 'SELECT count(*) FROM "main"."events"', "SELECT count(*) FROM EVENTS",
            "SELECT count(*) FROM information_schema.tables", "SELECT count(*) FROM information_schema.columns",
            "TABLE events", "DESCRIBE events", "DESCRIBE TABLE events", "SUMMARIZE events", "SHOW events",
            "SHOW TABLES", "SHOW ALL TABLES", "SHOW DATABASES", "SHOW", "DESCRIBE", "FROM events LIMIT 1",
            "DESCRIBE SELECT 1 AS n", "SUMMARIZE SELECT * FROM events",
            "WITH x AS (SELECT 1 AS n) SELECT * FROM x",
            "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 3) SELECT * FROM t",
            "PIVOT events ON kind IN ('c2') USING count(*)", "SELECT * FROM duckdb_tables()",
            "SELECT count(*) FROM events e JOIN range(2) r ON true",
        ]:
            r = post_sql(q)
            self.assertEqual(r.status_code, 200, f"{q} -> {r.status_code} {r.text[:200]}")
        self.assertEqual(post_sql("SELECT count(*) FROM events WHERE id IN ('p1', 'p2')").json()["rows"], [[2]])
        r = post_sql("SELECT * FROM no_such_table_xyz")
        self.assertEqual(r.status_code, 400)

    def test_query_the_check_cannot_see_into_is_not_run(self):
        # the old "unparseable DESCRIBE / SHOW runs unchecked" branch is gone: only checked text runs
        old = A._sql_refs
        A._sql_refs = lambda s: None
        try:
            for q in ["DESCRIBE events", "SHOW TABLES", "TABLE events", f'SUMMARIZE "{D}/bait".csv']:
                r = post_sql(q)
                self.assertEqual(r.status_code, 400, q)
                self.assertNotIn("SECRET4", r.text)
        finally:
            A._sql_refs = old


class NoExtensionDownloads(unittest.TestCase):
    def test_app_connections_have_autoinstall_and_autoload_off(self):
        rows = dict(db.connect().execute(
            "SELECT name, value FROM duckdb_settings() WHERE name IN "
            "('autoinstall_known_extensions', 'autoload_known_extensions')").fetchall())
        self.assertEqual(rows, {"autoinstall_known_extensions": "false", "autoload_known_extensions": "false"})
        self.assertLessEqual({"autoinstall_known_extensions": False, "autoload_known_extensions": False}.items(),
                             db.DUCKDB_CONFIG.items())
        import inspect
        from osinthub import vectors
        from osinthub.sources import upload
        for mod in (vectors, upload):
            self.assertIn("DUCKDB_CONFIG", inspect.getsource(mod), mod.__name__)
        root = Path(A.__file__).parent
        for p in root.rglob("*.py"):    # every duckdb.connect( in the app passes the config
            for line in p.read_text().splitlines():
                if "duckdb.connect(" in line and not line.lstrip().startswith("#"):
                    self.assertIn("DUCKDB_CONFIG", line, f"{p.relative_to(root)}: {line.strip()}")

    def test_vector_and_upload_connections_have_autoinstall_off(self):
        from osinthub import vectors
        v = vectors.DuckDBBackend(Path(LAKE) / "db" / "vectors-test.duckdb")
        rows = dict(v.conn.execute("SELECT name, value FROM duckdb_settings() WHERE name IN "
                                   "('autoinstall_known_extensions', 'autoload_known_extensions')").fetchall())
        self.assertEqual(set(rows.values()), {"false"})
        v.conn.close()

    def test_builtin_extensions_cover_the_app(self):
        rows = dict(db.connect().execute(
            "SELECT extension_name, install_mode FROM duckdb_extensions() WHERE loaded").fetchall())
        for ext in ("json", "parquet", "icu", "core_functions"):
            self.assertEqual(rows.get(ext), "STATICALLY_LINKED", ext)

    def test_extension_triggers_fail_without_any_request(self):
        before = len(_Listener.hits)
        cur = db.connect().cursor()   # the app's own connection, bypassing the console's checks
        for q in ["SELECT * FROM sql_auto_complete('SEL')", f"SELECT * FROM '{NET_URL}/x.csv'",
                  f"SELECT * FROM read_csv('{NET_URL}/x.csv')", "SELECT * FROM 's3://bucket/x.parquet'",
                  "SELECT st_point(1, 2)", "SELECT * FROM read_xlsx('x.xlsx')"]:
            with self.assertRaises(duckdb.Error, msg=q):
                cur.execute(q).fetchall()
        self.assertEqual(_Listener.hits[before:], [])
        self.assertEqual(list(Path(EXT_DIR).rglob("*")), [])


class LakeOnlyFileAccess(unittest.TestCase):
    """Defence in depth: even a query that skipped the console's checks reads files only in the lake."""

    def test_settings(self):
        rows = dict(db.connect().execute("SELECT name, value FROM duckdb_settings() WHERE name IN "
                                         "('enable_external_access', 'allowed_directories')").fetchall())
        self.assertEqual(rows["enable_external_access"], "false")
        self.assertIn(str(Path(LAKE).resolve()), rows["allowed_directories"])
        with self.assertRaises(duckdb.Error):
            db.connect().execute("SET enable_external_access = true")

    def test_outside_the_lake_refused_inside_works(self):
        cur = db.connect().cursor()
        for q in [f"SELECT * FROM read_csv('{B}')", f'SELECT * FROM "{D}/bait".csv', "SELECT * FROM read_text('/etc/passwd')",
                  f"SELECT * FROM read_csv('{LAKE}/../tmp/x.csv')", f"COPY (SELECT 1) TO '{D}/out.csv'",
                  f"ATTACH '{D}/x.duckdb' AS x"]:
            with self.assertRaises(duckdb.Error, msg=q):
                cur.execute(q).fetchall()
        self.assertFalse(Path(D, "out.csv").exists())
        self.assertFalse(Path(D, "x.duckdb").exists())
        inside = Path(LAKE) / "tmp" / "inside.csv"
        inside.parent.mkdir(exist_ok=True)
        inside.write_text("a\n1\n")
        self.assertEqual(cur.execute(f"SELECT * FROM read_csv('{inside}')").fetchall(), [(1,)])
        cur.execute(f"COPY (SELECT 2 AS a) TO '{Path(LAKE) / 'tmp' / 'out.parquet'}' (FORMAT parquet)")

    def test_app_loaders_still_work(self):
        # the app's own file paths (lake tmp/ scratch, raw/ batches, uploads/) are inside the allowed folders
        from osinthub.sources.upload import ingest_file
        up = Path(LAKE) / "uploads" / "t.csv"
        up.parent.mkdir(exist_ok=True)
        up.write_text("ip,title\n192.0.2.9,x\n")
        self.assertEqual([e.ip for e in ingest_file(up, "t")], ["192.0.2.9"])
        r = C.post("/api/upload", files={"file": ("u.csv", b"ip,title\n198.51.100.9,y\n", "text/csv")},
                   data={"label": "u"})
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertEqual(r.json()["rows"], 1)


if __name__ == "__main__":
    unittest.main()

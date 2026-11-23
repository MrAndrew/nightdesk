"""The SQL console (/api/sql) is a sandbox: no file or URL reads (table functions or replacement scans), no DDL,
no statement stacking, a size and a time limit, generic errors, and every DuckDB type comes back as JSON.

    uv run --with pytest pytest tests/security/test_sql_console.py -q
"""
from __future__ import annotations

import unittest

from _lake import make_lake
LAKE = make_lake("sql", disable="news,entities,netlog,ai", OSINTHUB_SQL_CONSOLE="1")

from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
import osinthub.api as A  # noqa: E402

db.connect()
C = TestClient(A.app, base_url="http://localhost")


def post_sql(q, **headers):
    return C.post("/api/sql", json={"sql": q}, headers=headers)


class SqlConsoleSandbox(unittest.TestCase):
    def test_file_and_url_read_functions_blocked(self):
        for q in [
            "SELECT content FROM read_text('/etc/passwd')",
            "SELECT * FROM read_csv('http://169.254.169.254/latest/meta-data/')",
            "FROM read_blob('/etc/hosts')",
            "SELECT * FROM glob('/etc/*')",
            "SELECT * FROM read_json_auto('/tmp/x.json')",
            "WITH x AS (SELECT content FROM read_text('/etc/passwd')) SELECT * FROM x",
            "SELECT * FROM read_parquet('/tmp/x.parquet')",
        ]:
            r = post_sql(q)
            self.assertEqual(r.status_code, 400, f"should block: {q} -> {r.status_code} {r.text}")
            self.assertIn("not allowed", r.text.lower(), q)

    def test_replacement_scan_file_and_url_read_blocked(self):
        # a string literal in FROM is a DuckDB replacement scan (BASE_TABLE whose name is the path)
        for q in [
            "SELECT * FROM '/etc/passwd'",
            "SELECT * FROM 'secret.csv'",
            "FROM '/tmp/x.json'",
            "SELECT col_b FROM '/abs/secret.csv'",
            "SELECT * FROM 'https://169.254.169.254/latest/meta-data/x.json'",
            "SELECT * FROM 'http://127.0.0.1:8790/v1/models.json'",
            "WITH x AS (SELECT * FROM '/abs/secret.csv') SELECT * FROM x",
            "SELECT * FROM '/lake/raw/events.ndjson.gz'",
        ]:
            r = post_sql(q)
            self.assertEqual(r.status_code, 400, f"should block replacement scan: {q} -> {r.status_code}")
            self.assertIn("not allowed", r.text.lower(), q)

    def test_cte_and_real_tables_still_allowed(self):
        self.assertEqual(post_sql("WITH x AS (SELECT 1 AS n) SELECT * FROM x").status_code, 200)
        self.assertEqual(post_sql("SELECT count(*) FROM events e JOIN range(2) r ON true").status_code, 200)

    def test_oversize_query_rejected(self):
        self.assertEqual(post_sql("SELECT " + "1," * 20000 + "1").status_code, 400)

    def test_ddl_and_stacking_blocked(self):
        for q in ["DROP TABLE events", "ATTACH 'x.db' AS y", "COPY events TO '/tmp/x.csv'",
                  "INSTALL httpfs", "SELECT 1; SELECT 2", "PRAGMA database_list"]:
            self.assertEqual(post_sql(q).status_code, 400, q)

    def test_normal_queries_allowed(self):
        r = post_sql("SELECT 1 AS a, 2 AS b")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["rows"], [[1, 2]])
        self.assertEqual(post_sql("SELECT * FROM range(3)").status_code, 200)  # safe compute-only table func
        self.assertEqual(post_sql("SELECT count(*) FROM events").status_code, 200)

    def test_every_duckdb_type_serialises(self):
        # these used to crash the JSON encoder with a plain-text 500 after the query had succeeded
        cases = {
            "SELECT DATE '2024-01-02' v": "2024-01-02",
            "SELECT TIME '12:34:56' v": "12:34:56",
            "SELECT TIMESTAMP '2024-01-01 00:00:00' v": "2024-01-01T00:00:00",
            "SELECT 1.25::DECIMAL(10,2) v": 1.25,
            "SELECT 12345678901234567890.123::DECIMAL(38,3) v": "12345678901234567890.123",
            "SELECT INTERVAL 1 DAY v": "1 day, 0:00:00",
            "SELECT '00000000-0000-0000-0000-000000000001'::UUID v": "00000000-0000-0000-0000-000000000001",
            "SELECT '\\xAA\\xFFx'::BLOB v": "\\xAA\\xFFx",
            "SELECT 'nan'::DOUBLE v": "NaN",
            "SELECT 'inf'::DOUBLE v": "Infinity",
            "SELECT '-inf'::FLOAT v": "-Infinity",
            "SELECT [DATE '2024-01-02', NULL] v": ["2024-01-02", None],
            "SELECT {'a': 1.5::DECIMAL(4,2)} v": {"a": 1.5},
        }
        for q, want in cases.items():
            r = post_sql(q)
            self.assertEqual(r.status_code, 200, f"{q} -> {r.status_code} {r.text[:120]}")
            self.assertEqual(r.json()["rows"], [[want]], q)
        r = post_sql("SUMMARIZE SELECT 1.5::DECIMAL(4,2) AS x, current_date AS d")
        self.assertEqual(r.status_code, 200, r.text[:200])

    def test_runaway_query_times_out(self):
        old = A.SQL_TIMEOUT_S
        A.SQL_TIMEOUT_S = 1.0
        try:
            r = post_sql("WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM t WHERE n < 900000000) SELECT count(*) FROM t")
            self.assertEqual(r.status_code, 400, r.text)
            self.assertIn("time limit", r.text.lower())
        finally:
            A.SQL_TIMEOUT_S = old
        # connection still usable afterwards
        self.assertEqual(post_sql("SELECT 7").json()["rows"], [[7]])

    def test_errors_are_generic(self):
        r = post_sql("SELECT no_such_column_xyz FROM events")
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("no_such_column_xyz", r.text)  # DuckDB error detail not echoed to the client
        self.assertNotIn("Error", r.text)
        # an unknown table is caught before DuckDB runs anything: a plain message naming only what the user typed
        r = post_sql("SELECT * FROM no_such_table_xyz")
        self.assertEqual(r.status_code, 400)
        self.assertIn("no table or view named no_such_table_xyz", r.json()["detail"])
        self.assertNotIn("Catalog", r.text)

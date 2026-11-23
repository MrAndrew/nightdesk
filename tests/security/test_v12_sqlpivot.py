"""SQL console PIVOT / UNPIVOT: the forms DuckDB parses as one SELECT run over the app's own tables, the sandbox
stays shut, and the statement that runs is always the exact text that was checked (osinthub/api.py, _sql_check).

A PIVOT without an IN list parses as DuckDB's MULTI statement (a hidden query for the values runs first), which the
check cannot see into, so it is refused with a hint to list the values.

    uv run --with pytest pytest tests/security/test_v12_sqlpivot.py -q
"""
from __future__ import annotations

import http.server
import tempfile
import threading
import unittest
from pathlib import Path

import duckdb

from _lake import make_lake
LAKE = make_lake("sqlpivot", disable="news,entities,netlog,ai", OSINTHUB_SQL_CONSOLE="1")

from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
import osinthub.api as A  # noqa: E402

db.connect()
C = TestClient(A.app, base_url="http://localhost")
db.execute("""INSERT INTO events (id, source, kind, ts, title, severity, country, ip) VALUES
    ('p1', 'feodo', 'c2', TIMESTAMPTZ '2026-01-01 00:00:00+00', 'a', 5, 'US', '192.0.2.1'),
    ('p2', 'feodo', 'c2', TIMESTAMPTZ '2026-01-02 00:00:00+00', 'b', 7, 'DE', '192.0.2.2'),
    ('p3', 'cisa_kev', 'kev', TIMESTAMPTZ '2026-01-03 00:00:00+00', 'c', 9, 'US', '198.51.100.3'),
    ('p4', 'threatfox', 'ioc', TIMESTAMPTZ '2026-01-04 00:00:00+00', 'd', 3, 'NL', '203.0.113.4')""")

# a real file the sandbox must never hand back (in this module's own temp folder)
BAIT = Path(tempfile.mkdtemp()) / "bait.csv"
BAIT.write_text("a,b\nSECRET42,1\nSECRET43,2\n")
B = str(BAIT)
D = str(BAIT.parent)
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
EXT_DIR = tempfile.mkdtemp(dir=LAKE)   # an empty extension folder (in the lake: DuckDB may only touch the lake), so nothing installed on this machine can be loaded either
db.connect().execute(f"SET extension_directory = '{EXT_DIR}'")
db.connect().execute(f"SET autoinstall_extension_repository = '{NET_URL}'")
db.connect().execute(f"SET custom_extension_repository = '{NET_URL}'")


def post_sql(q):
    return C.post("/api/sql", json={"sql": q})


def rows_by_first(r):
    cols = r.json()["columns"]
    return cols, {row[0]: dict(zip(cols, row)) for row in r.json()["rows"]}


class PivotAllowed(unittest.TestCase):
    def ok(self, q):
        r = post_sql(q)
        self.assertEqual(r.status_code, 200, f"{q} -> {r.status_code} {r.text[:200]}")
        return r

    def test_simplified_pivot_with_in_list(self):
        r = self.ok("PIVOT events ON kind IN ('c2', 'kev') USING count(*) GROUP BY source ORDER BY source")
        cols, by = rows_by_first(r)
        self.assertEqual(cols, ["source", "c2", "kev"])
        self.assertEqual(by["feodo"]["c2"], 2)
        self.assertEqual(by["cisa_kev"]["kev"], 1)
        for q in [
            "PIVOT events ON kind IN ('c2', 'kev')",
            "pivot events on kind in ('c2') using count(*) group by source;",
            "PIVOT events ON kind IN ('c2', 'kev'), country IN ('US', 'DE') USING max(severity) GROUP BY source",
            "PIVOT events ON kind IN ('c2') USING count(*) AS n, max(severity) AS top GROUP BY source",
            "PIVOT events ON kind IN ('c2', 'kev') USING count(*) GROUP BY source  -- per feed",
            "PIVOT_WIDER events ON kind IN ('c2', 'kev') USING count(*) GROUP BY source",
            "DESCRIBE PIVOT events ON kind IN ('c2', 'kev') USING count(*) GROUP BY source",
            "SUMMARIZE PIVOT events ON kind IN ('c2', 'kev') USING count(*) GROUP BY source",
        ]:
            self.ok(q)

    def test_sql_standard_pivot(self):
        r = self.ok("SELECT * FROM (SELECT source, kind FROM events) PIVOT (count(*) FOR kind IN ('c2', 'kev', 'ioc'))")
        cols, by = rows_by_first(r)
        self.assertEqual(cols, ["source", "c2", "kev", "ioc"])
        self.assertEqual(by["threatfox"]["ioc"], 1)
        self.ok("FROM events PIVOT (count(*) FOR kind IN ('c2', 'kev') GROUP BY source)")

    def test_pivot_in_cte_subquery_and_join(self):
        r = self.ok("WITH p AS (PIVOT events ON kind IN ('c2', 'kev') USING count(*) GROUP BY source) "
                    "SELECT source, c2 FROM p ORDER BY c2 DESC")
        self.assertEqual(r.json()["rows"][0], ["feodo", 2])
        self.ok("SELECT * FROM (PIVOT events ON country IN ('US', 'DE') USING count(*) GROUP BY kind) t WHERE kind = 'c2'")
        self.ok("SELECT count(*) FROM events e JOIN (PIVOT events ON kind IN ('c2') USING count(*) GROUP BY source) p USING (source)")
        self.ok("WITH e AS (SELECT * FROM events WHERE severity > 4) PIVOT e ON kind IN ('c2', 'kev') USING count(*) GROUP BY source")
        self.ok("PIVOT (FROM events PIVOT (count(*) FOR kind IN ('c2', 'kev') GROUP BY source, country)) "
                "ON country IN ('US', 'DE') USING sum(c2)")

    def test_unpivot(self):
        r = self.ok("UNPIVOT (SELECT source, count(*)::DOUBLE AS n, max(severity) AS worst FROM events GROUP BY source) "
                    "ON n, worst INTO NAME metric VALUE v ORDER BY source, metric")
        self.assertEqual(r.json()["columns"], ["source", "metric", "v"])
        self.assertIn(["feodo", "n", 2.0], r.json()["rows"])
        self.ok("SELECT * FROM (SELECT id, severity, value FROM events) UNPIVOT (v FOR metric IN (severity, value))")
        self.ok("WITH u AS (UNPIVOT (SELECT id, severity, lat FROM events) ON severity, lat INTO NAME k VALUE v) SELECT * FROM u")
        self.ok("PIVOT_LONGER (SELECT id, severity, lat FROM events) ON severity, lat INTO NAME k VALUE v")

    def test_row_cap_applies(self):
        r = self.ok("PIVOT (SELECT r % 3 AS k, r FROM range(12000) t(r)) ON k IN (0, 1, 2) USING count(*) GROUP BY r")
        self.assertEqual(len(r.json()["rows"]), 5000)

    def test_timeout_applies(self):
        old = A.SQL_TIMEOUT_S
        A.SQL_TIMEOUT_S = 1.0
        try:
            r = post_sql("PIVOT (WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 900000000) "
                         "SELECT n % 2 AS k FROM t) ON k IN (0, 1) USING count(*)")
            self.assertEqual(r.status_code, 400, r.text)
            self.assertIn("time limit", r.text.lower())
        finally:
            A.SQL_TIMEOUT_S = old
        self.assertEqual(post_sql("SELECT 7").json()["rows"], [[7]])

    def test_no_temporary_enums_left(self):
        for _ in range(3):
            self.ok("PIVOT events ON kind IN ('c2', 'kev') USING count(*)")
        r = self.ok("SELECT count(*) FROM duckdb_types() WHERE starts_with(type_name, '__pivot_enum_')")
        self.assertEqual(r.json()["rows"], [[0]])

    def test_infinity_flags_still_work(self):
        r = self.ok("SELECT 'infinity'::DATE AS d, DATE '2024-01-02' AS e")
        self.assertEqual(r.json()["rows"], [["infinity", "2024-01-02"]])
        r = self.ok("PIVOT (SELECT 'x' AS k, 'infinity'::TIMESTAMP AS t) ON k IN ('x') USING max(t)")
        self.assertEqual(r.json()["rows"], [["infinity"]])

    def test_keyword_named_struct_fields_without_file_reads_run(self):
        r = self.ok("SELECT ({'pivot': 'p'}).pivot || ({'on': 'abc'}).on[({'case': 1}).case] AS v")
        self.assertEqual(r.json()["rows"], [["pa"]])
        self.ok("SELECT ({'using': 1}).using AS u, ({'in': 2}).in AS i, ({'unpivot': 3}).unpivot AS x FROM events")


class PivotSandbox(unittest.TestCase):
    def rejected(self, q, word="not allowed"):
        r = post_sql(q)
        self.assertEqual(r.status_code, 400, f"should block: {q} -> {r.status_code} {r.text[:200]}")
        self.assertIn(word, r.text.lower(), q)
        self.assertNotIn("secret4", r.text.lower(), q)
        self.assertNotIn("root:", r.text.lower(), q)

    def test_in_less_pivot_refused_with_a_hint(self):
        for q in [
            "PIVOT events ON kind USING count(*)",
            "PIVOT events ON kind",
            "PIVOT events ON kind IN ('c2'), country USING count(*)",
            "WITH p AS (PIVOT events ON kind USING count(*)) SELECT * FROM p",
            "SELECT * FROM (PIVOT events ON kind)",
            "DESCRIBE PIVOT events ON kind",
            "PIVOT_WIDER events ON kind",
            "PIVOT events ON kind IN (SELECT DISTINCT kind FROM events)",
            "PIVOT events ON kind USING count(*) GROUP BY source UNION ALL PIVOT events ON kind USING count(*)",
        ]:
            r = post_sql(q)
            self.assertEqual(r.status_code, 400, f"{q} -> {r.status_code} {r.text[:200]}")
            self.assertIn("needs its column values listed", r.text, q)
            self.assertIn("SELECT DISTINCT kind FROM events", r.text, q)

    def test_evaluator_bypass_r1(self):
        # round 1: struct fields named pivot / on / case made a rewritten copy hide read_csv; the original ran
        for q in [
            f"WITH q AS (PIVOT events ON kind) SELECT a, b, substring(({{'pivot':'p'}}).pivot || ({{'on':'abc'}}).on[({{'case':1}}).case], 1) FROM read_csv('{B}')",
            "WITH q AS (PIVOT events ON kind) SELECT *, substring(({'pivot':'p'}).pivot || ({'on':'abc'}).on[({'case':1}).case], 1) FROM read_text('/etc/passwd')",
        ]:
            self.rejected(q, "values listed")
        for q in [
            f"WITH q AS (PIVOT events ON kind IN ('c2')) SELECT a, b, substring(({{'pivot':'p'}}).pivot || ({{'on':'abc'}}).on[({{'case':1}}).case], 1) FROM read_csv('{B}')",
            "WITH q AS (PIVOT events ON kind IN ('c2')) SELECT *, substring(({'pivot':'p'}).pivot || ({'on':'abc'}).on[({'case':1}).case], 1) FROM read_text('/etc/passwd')",
            f"SELECT a, b, substring(({{'pivot':'p'}}).pivot || ({{'on':'abc'}}).on[({{'case':1}}).case], 1) FROM read_csv('{B}')",
            f"SELECT * FROM '{B}' WHERE ({{'pivot': 1}}).pivot = 1",
        ]:
            self.rejected(q)

    def test_keyword_named_fields_and_aliases_with_file_reads(self):
        fields = ["pivot", "on", "using", "in", "case", "unpivot", "pivot_wider", "for", "into", "name", "value"]
        for f in fields:
            exprs = [f"({{'{f}': 1}}).{f}", f"({{'{f}': [1, 2]}}).{f}[1]", f"[1, 2][({{'{f}': 1}}).{f}]"]
            for e in exprs:
                for q in [
                    f"SELECT {e} AS x, a FROM read_csv('{B}')",
                    f"SELECT a, {e} AS \"{f}\" FROM '{B}'",
                    f"PIVOT (SELECT a, {e} AS k FROM read_csv('{B}')) ON k IN (1) USING first(a)",
                    f"PIVOT events ON kind IN ('c2') USING first((SELECT max(a) FROM read_csv('{B}') WHERE {e} = 1))",
                    f"WITH t AS (PIVOT events ON kind IN ('c2')) SELECT {e}, * FROM t, read_text('/etc/passwd')",
                    f"SELECT * FROM (SELECT {e} AS k, a FROM read_csv('{B}')) PIVOT (count(*) FOR k IN (1))",
                    f"UNPIVOT (SELECT {e} AS k, a FROM read_csv('{B}')) ON k INTO NAME n VALUE v",
                    f"WITH q AS (PIVOT events ON kind) SELECT {e}, a FROM read_csv('{B}')",
                ]:
                    r = post_sql(q)
                    self.assertEqual(r.status_code, 400, f"should block: {q} -> {r.status_code} {r.text[:200]}")
                    self.assertNotIn("SECRET4", r.text, q)
                    self.assertNotIn("root:", r.text, q)

    def test_file_and_url_sources_blocked(self):
        for q in [
            f"PIVOT read_csv('{B}') ON a IN ('SECRET42')",
            f"PIVOT read_csv('{B}') ON a IN ('SECRET42') USING count(*) GROUP BY b",
            f"PIVOT '{B}' ON a IN ('SECRET42')",
            "PIVOT 'https://198.51.100.7/x.parquet' ON a IN ('1') USING count(*)",
            "PIVOT (FROM read_text('/etc/passwd')) ON filename IN ('x')",
            "PIVOT (SELECT * FROM '/etc/passwd') ON column0 IN ('x')",
            "PIVOT events ON kind IN ('c2') USING max((SELECT content FROM read_text('/etc/passwd')))",
            f"PIVOT events ON kind IN ('c2') USING count(*) ORDER BY (SELECT 1 FROM read_csv('{B}'))",
            f"PIVOT events e JOIN read_csv('{B}') r ON true ON kind IN ('c2')",
            f"WITH p AS (PIVOT '{B}' ON a IN ('SECRET42')) SELECT * FROM p",
            "SELECT * FROM (PIVOT read_blob('/etc/hosts') ON filename IN ('x'))",
            f"SELECT * FROM events JOIN (PIVOT '{B}' ON a IN ('SECRET42')) p ON true",
            f"SELECT * FROM read_csv('{B}') PIVOT (count(*) FOR a IN ('SECRET42'))",
            f"SELECT * FROM '{B}' PIVOT (count(*) FOR a IN ('SECRET42'))",
            "FROM glob('/etc/*') PIVOT (count(*) FOR file IN ('a'))",
            f"UNPIVOT read_csv('{B}') ON a, b INTO NAME k VALUE v",
            f"UNPIVOT '{B}' ON a, b INTO NAME k VALUE v",
            f"SELECT * FROM '{B}' UNPIVOT (v FOR k IN (a, b))",
            "PIVOT_WIDER read_parquet('x.parquet') ON a IN ('1')",
            f"PIVOT_LONGER '{B}' ON a, b INTO NAME k VALUE v",
            f"DESCRIBE PIVOT read_csv('{B}') ON a IN ('1')",
            f"SUMMARIZE PIVOT '{B}' ON a IN ('1')",
            f"PIVOT events ON kind IN ('c2') UNION ALL PIVOT '{B}' ON a IN ('SECRET42')",
        ]:
            self.rejected(q)

    def test_file_reads_behind_in_less_pivot_never_run(self):
        for q in [f"PIVOT read_csv('{B}') ON a", f"PIVOT '{B}' ON a", "PIVOT (FROM read_text('/etc/passwd')) ON filename",
                  f"WITH a AS (FROM '{B}') PIVOT a ON a"]:
            self.rejected(q, "values listed")

    def test_writes_and_stacking_blocked(self):
        for q in [
            "PIVOT events ON kind IN ('c2'); DROP TABLE events",
            "PIVOT events ON kind USING count(*); SELECT 1",
            "CREATE TABLE x AS PIVOT events ON kind",
            "CREATE TYPE e AS ENUM ('a')",
            "INSERT INTO events PIVOT events ON kind",
            "COPY (PIVOT events ON kind IN ('c2')) TO 'out.csv'",
            "EXPORT DATABASE 'x'",
            "PIVOT events ON kind IN ('c2') USING count(*) GROUP BY source /* ; */ ; ATTACH 'x.db'",
        ]:
            self.rejected(q, "only single read-only")

    def test_invalid_pivot_sql_still_rejected(self):
        # DuckDB itself cannot parse these, so they are refused before anything runs
        for q in ["PIVOT events ON kind IN ('c2'), (SELECT 1 FROM read_text('/etc/passwd'))",
                  "PIVOT events ON kind IN ('c2') USING count(*) GROUP BY (SELECT content FROM read_text('/etc/passwd'))",
                  "PIVOT events ON kind IN ('c2') USING count(*) GROUP BY ALL",
                  "PIVOT events, 'secret.csv' ON kind"]:
            self.assertEqual(post_sql(q).status_code, 400, q)

    def test_checked_text_is_the_text_run(self):
        # the handler runs exactly what _sql_check returned: the input, only trimmed of spaces and a final ';'
        self.assertEqual(A._sql_check("  PIVOT events ON kind IN ('c2') ;"), "PIVOT events ON kind IN ('c2') ")
        self.assertFalse(hasattr(A, "_sql_pivot_probe"))


class TableAllowlist(unittest.TestCase):
    """Round 3: every table a console query names must be a CTE of the query or a real table or view of the app's
    database; a file path or URL in any spelling is refused before anything runs."""

    def rejected(self, q):
        r = post_sql(q)
        self.assertEqual(r.status_code, 400, f"should block: {q} -> {r.status_code} {r.text[:200]}")
        self.assertIn("not allowed", r.text.lower(), q)
        for secret in ("SECRET4", "SECRETJSON", "SECRETPQ"):
            self.assertNotIn(secret, r.text, q)

    def test_schema_qualified_file_paths_refused(self):
        for f in ("csv", "json", "parquet", '"csv"'):
            for q in [
                f'SELECT * FROM "{D}/bait".{f}',
                f'FROM "{D}/bait".{f}',
                f'TABLE "{D}/bait".{f}',
                f'DESCRIBE "{D}/bait".{f}',
                f'SUMMARIZE "{D}/bait".{f}',
                f'SHOW "{D}/bait".{f}',
                f'SELECT * FROM range(1) r, "{D}/bait".{f}',
                f'SELECT * FROM events WHERE id IN (SELECT a FROM "{D}/bait".{f})',
                f'WITH q AS (SELECT * FROM "{D}/bait".{f}) SELECT * FROM q',
                f'SELECT * FROM "{D}/*".{f}',
                f'SELECT * FROM "{D}"."bait".{f}',
                f'UNPIVOT "{D}/bait".{f} ON a INTO NAME n VALUE v',
            ]:
                self.rejected(q)
        for q in [
            f'PIVOT "{D}/bait".csv ON a IN (\'SECRET42\', \'SECRET43\') USING sum(b)',
            f'SELECT * FROM "{D}/bait".csv PIVOT (sum(b) FOR a IN (\'SECRET42\', \'SECRET43\'))',
            f'WITH q AS (PIVOT "{D}/bait".csv ON a IN (\'SECRET42\') USING sum(b)) SELECT * FROM q',
            f'UNPIVOT "{D}/bait".json ON k INTO NAME n VALUE v',
            f'SELECT a FROM "{D}/bait" . "csv"',
            f'SELECT/**/a FROM/**/"{D}/bait"/**/./**/csv',
            f'SELECT * FROM main."{D}/bait.csv"',
            f'SELECT * FROM "{D}/bait.csv"',
            f"SELECT * FROM '{D}/bait.csv'",
            "SELECT * FROM bait.csv",
            f'SELECT * FROM (WITH csv AS (SELECT 1) SELECT * FROM csv), "{D}/bait".csv',
            f'WITH "{D}/bait.csv" AS (SELECT 1 AS a) SELECT * FROM "{D}/bait.csv"',
            f'DESCRIBE PIVOT "{D}/bait".csv ON a IN (\'x\')',
        ]:
            self.rejected(q)

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

    def test_real_tables_views_and_ctes_still_allowed(self):
        cat = post_sql("SELECT current_database()").json()["rows"][0][0]
        for q in [
            "SELECT count(*) FROM events", "SELECT count(*) FROM main.events", f"SELECT count(*) FROM {cat}.main.events",
            f"SELECT count(*) FROM {cat}.events", 'SELECT count(*) FROM "main"."events"', "SELECT count(*) FROM EVENTS",
            "SELECT count(*) FROM information_schema.tables", "SELECT count(*) FROM information_schema.columns",
            "TABLE events", "DESCRIBE events", "SUMMARIZE events", "SHOW events", "SHOW TABLES", "SHOW ALL TABLES",
            "SHOW DATABASES", "SHOW", "DESCRIBE", "FROM events LIMIT 1",
            "WITH x AS (SELECT 1 AS n) SELECT * FROM x", "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 3) SELECT * FROM t",
            "PIVOT events ON kind IN ('c2') USING count(*)", "SELECT * FROM duckdb_tables()",
        ]:
            r = post_sql(q)
            self.assertEqual(r.status_code, 200, f"{q} -> {r.status_code} {r.text[:200]}")
        r = post_sql("SELECT * FROM no_such_table_xyz")
        self.assertEqual(r.status_code, 400)


class NoExtensionDownloads(unittest.TestCase):
    """Round 3: DuckDB never installs or auto-loads an extension, so nothing reaches extensions.duckdb.org."""

    def test_app_connections_have_autoinstall_and_autoload_off(self):
        rows = dict(db.connect().execute(
            "SELECT name, value FROM duckdb_settings() WHERE name IN "
            "('autoinstall_known_extensions', 'autoload_known_extensions')").fetchall())
        self.assertEqual(rows, {"autoinstall_known_extensions": "false", "autoload_known_extensions": "false"})
        self.assertFalse(db.DUCKDB_CONFIG["autoinstall_known_extensions"])
        self.assertFalse(db.DUCKDB_CONFIG["autoload_known_extensions"])
        from osinthub import vectors
        import inspect
        from osinthub.sources import upload
        self.assertIn("config=db.DUCKDB_CONFIG", inspect.getsource(vectors))
        self.assertIn("config=DUCKDB_CONFIG", inspect.getsource(upload))

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
    """Round 3, defence in depth: even a query that skipped the console's checks reads files only in the lake."""

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
                  f"SELECT * FROM read_csv('{LAKE}/../tmp/x.csv')", f"COPY (SELECT 1) TO '{D}/out.csv'"]:
            with self.assertRaises(duckdb.Error, msg=q):
                cur.execute(q).fetchall()
        self.assertFalse(Path(D, "out.csv").exists())
        inside = Path(LAKE) / "tmp" / "inside.csv"
        inside.parent.mkdir(exist_ok=True)
        inside.write_text("a\n1\n")
        self.assertEqual(cur.execute(f"SELECT * FROM read_csv('{inside}')").fetchall(), [(1,)])
        cur.execute(f"COPY (SELECT 2 AS a) TO '{Path(LAKE) / 'tmp' / 'out.parquet'}' (FORMAT parquet)")


if __name__ == "__main__":
    unittest.main()

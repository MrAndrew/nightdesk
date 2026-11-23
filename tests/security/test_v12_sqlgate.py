"""v1.2 sqlgate: the SQL console is off unless OSINTHUB_SQL_CONSOLE=1 (or OSINTHUB_DEBUG=1), and when on it never
shows a server path: settings, database files and the environment are refused, and DuckDB's own folders live in the
lake. The app's own panels that used to ask the console have GETs that work with it off.

    uv run --with pytest pytest tests/security/test_v12_sqlgate.py -q
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

from _lake import ROOT, make_lake
LAKE = make_lake("sqlgate", disable="news,entities,netlog,ai")   # no OSINTHUB_SQL_CONSOLE: the default, off

from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
import osinthub.api as A  # noqa: E402

db.connect()
C = TestClient(A.app, base_url="http://localhost")
db.execute("""INSERT INTO events (id, source, kind, ts, title, asn, tags) VALUES
    ('g1', 'cisa_kev', 'kev', TIMESTAMPTZ '2026-01-03 00:00:00+00', 'CVE-2026-0001 Example product flaw', NULL, ['vendor']),
    ('g2', 'cisa_kev', 'kev', TIMESTAMPTZ '2026-01-04 00:00:00+00', 'CVE-2026-0002 Another flaw', NULL, ['vendor']),
    ('g3', 'feodo', 'c2', TIMESTAMPTZ '2026-01-05 00:00:00+00', 'c2 at 192.0.2.9', 'AS64496', ['org:Example Net', 'c2']),
    ('g4', 'feodo', 'c2', TIMESTAMPTZ '2026-01-06 00:00:00+00', 'c2 at 192.0.2.10', 'AS64497', ['c2'])""")

HOME = str(Path.home())
LAKE_PATHS = {str(Path(LAKE)), str(Path(LAKE).resolve()), str(config.DB_PATH), str(config.DB_PATH.resolve())}
OFF = "The SQL console is off. Start Night Desk with OSINTHUB_SQL_CONSOLE=1 to turn it on."


def post_sql(q):
    return C.post("/api/sql", json={"sql": q})


def flags(**env) -> dict:
    """config.SQL_CONSOLE and config.DEBUG as a fresh process sees them with these variables (and no inherited ones)."""
    e = {k: v for k, v in os.environ.items() if k not in ("OSINTHUB_SQL_CONSOLE", "OSINTHUB_DEBUG")}
    e.update(env)
    out = subprocess.run([sys.executable, "-c", "from osinthub import config; print(config.SQL_CONSOLE, config.DEBUG)"],
                         cwd=ROOT, env=e, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    console, debug = out.stdout.split()
    return {"console": console == "True", "debug": debug == "True"}


class TheSetting(unittest.TestCase):
    def test_off_by_default_on_with_either_variable(self):
        self.assertEqual(flags(), {"console": False, "debug": False})
        self.assertEqual(flags(OSINTHUB_SQL_CONSOLE="1"), {"console": True, "debug": False})
        self.assertEqual(flags(OSINTHUB_SQL_CONSOLE="true"), {"console": True, "debug": False})
        self.assertEqual(flags(OSINTHUB_DEBUG="1"), {"console": True, "debug": True})
        self.assertEqual(flags(OSINTHUB_SQL_CONSOLE="0"), {"console": False, "debug": False})
        self.assertEqual(flags(OSINTHUB_SQL_CONSOLE=""), {"console": False, "debug": False})


class ConsoleOff(unittest.TestCase):
    def setUp(self):
        self.assertFalse(config.SQL_CONSOLE)

    def test_sql_is_refused_with_how_to_turn_it_on(self):
        for q in ["SELECT 1", "SELECT * FROM events", "SELECT table_name FROM information_schema.tables",
                  "SELECT current_setting('secret_directory')", ""]:
            r = post_sql(q)
            self.assertEqual(r.status_code, 403, q)
            self.assertEqual(r.json()["detail"], OFF)

    def test_health_and_about_say_off(self):
        self.assertIs(C.get("/api/health").json()["sql_console"], False)
        self.assertIs(C.get("/api/settings/about").json()["sql_console"], False)

    def test_the_panels_own_lookups_still_work(self):
        self.assertEqual(C.get("/api/kev/ids").json(), {"ids": ["CVE-2026-0001", "CVE-2026-0002"]})
        r = C.get("/api/asn/orgs", params={"asn": "AS64496,as64497,AS64498"}).json()
        self.assertEqual(r, {"orgs": {"AS64496": "Example Net", "AS64497": "", "AS64498": ""}})
        self.assertEqual(C.get("/api/asn/orgs").json(), {"orgs": {}})
        for bad in ["AS1' OR 1=1 --", "x", ",".join(f"AS{i}" for i in range(201))]:
            self.assertEqual(C.get("/api/asn/orgs", params={"asn": bad}).status_code, 400, bad[:30])

    def test_the_client_hides_the_console_when_off(self):
        """The entry points depend on /api/health's sql_console: the gear menu item carries .needs-sql (hidden by
        app.css until the shell sets data-sql-console="on"), the palette command and More lists filter on it, and
        Explorer shows the explanation instead of the console."""
        web = ROOT / "web"
        self.assertIn('class="mi needs-sql" role="menuitem" href="#explorer"', (web / "index.html").read_text())
        self.assertIn('html:not([data-sql-console="on"]) .needs-sql { display: none !important; }',
                      (web / "css" / "app.css").read_text())
        shell = (web / "js" / "core" / "shell.js").read_text()
        self.assertIn("when: sqlConsoleOn, run: go('explorer')", shell)
        self.assertIn("dataset.sqlConsole = sqlConsoleOn() ? 'on' : 'off'", shell)
        self.assertIn("href !== '#explorer' || sqlConsoleOn()", (web / "js" / "core" / "mshell.js").read_text())
        ex = (web / "js" / "views" / "explorer.js").read_text()
        self.assertIn(OFF, ex)
        self.assertIn("h?.sql_console !== true", ex)
        # nothing outside Explorer itself asks the console any more
        callers = [p.relative_to(web).as_posix() for p in (web / "js").rglob("*.js")
                   if "api.sql(" in p.read_text() and p.name != "explorer.js"]
        self.assertEqual(callers, [])


class Docker(unittest.TestCase):
    def test_compose_passes_both_switches_default_off_and_env_example_lists_them(self):
        compose = (ROOT / "docker-compose.yml").read_text()
        example = (ROOT / ".env.example").read_text()
        deploy = (ROOT / "okf" / "architecture" / "deployment.md").read_text()
        for k in ("OSINTHUB_SQL_CONSOLE", "OSINTHUB_DEBUG"):
            self.assertIn(f"{k}: ${{{k}:-0}}", compose)
            self.assertRegex(example, rf"(?m)^# {k}=0$")
            self.assertIn(f"| `{k}` | `0` |", deploy)


class HelpWhenOff(unittest.TestCase):
    def test_guide_glossary_and_tour_follow_the_console_state(self):
        web = ROOT / "web" / "js"
        guides = (web / "help" / "guides.js").read_text()
        self.assertIn("off: '<b>It is off now.</b> The SQL console is off. Start Night Desk with", guides)
        desk = (web / "help" / "desk.js").read_text()
        self.assertIn("g.steps.map(sqlStep)", desk)
        self.assertIn("g.where.filter(sqlWhere)", desk)
        tour = (web / "core" / "tour.js").read_text()
        self.assertIn("view === 'explorer' && !sqlConsoleOn() ? 'explorer-off' : view", tour)
        self.assertIn("{ sel: '.ex-off', title: 'SQL console', body: 'The SQL console is off.", tour)


class ConsoleOn(unittest.TestCase):
    """With the console on (as OSINTHUB_SQL_CONSOLE=1 sets it), nothing it returns names a server path."""

    def setUp(self):
        config.SQL_CONSOLE = True

    def tearDown(self):
        config.SQL_CONSOLE = False

    def assertNoPath(self, r, q):
        for p in (HOME, *LAKE_PATHS):
            self.assertNotIn(p, r.text, f"{q} -> {r.text[:300]}")
        self.assertNotIn(".duckdb/", r.text, q)

    def refused(self, q, word="server settings"):
        r = post_sql(q)
        self.assertEqual(r.status_code, 400, f"should refuse: {q} -> {r.status_code} {r.text[:300]}")
        self.assertIn(word, r.json()["detail"], q)
        self.assertNoPath(r, q)
        return r

    def test_health_and_about_say_on(self):
        self.assertIs(C.get("/api/health").json()["sql_console"], True)
        self.assertIs(C.get("/api/settings/about").json()["sql_console"], True)
        self.assertEqual(post_sql("SELECT 1 AS n").json()["rows"], [[1]])

    def test_evaluator_r3_probes_refused(self):
        for q in [
            "SELECT current_setting('secret_directory')",
            "SELECT name, value FROM duckdb_settings() WHERE value LIKE '%Users%'",
            "SELECT name, setting FROM pg_settings WHERE setting LIKE '%Users%'",
            "SELECT * FROM duckdb_databases()", "SELECT path FROM duckdb_databases", "SELECT * FROM pragma_database_list",
            "SELECT current_setting('allowed_directories')", "SELECT current_setting('allowed_paths')",
            "SELECT current_setting('temp_directory')", "SELECT current_setting('home_directory')",
        ]:
            self.refused(q)

    def test_every_blocked_function_refused_in_any_spelling(self):
        for f in sorted(A.SQL_FUNCS_BLOCKED):
            for q in [f"SELECT {f}()", f"SELECT * FROM {f}()", f"SELECT {f}('x', 'y')", f"FROM {f}()",
                      f'SELECT "{f.upper()}"(\'x\')', f"SELECT system.main.{f}('x')", f"SELECT 'x'.{f}()",
                      f"SELECT (SELECT {f}('x'))", f"WITH q AS (SELECT {f}('x') AS v) SELECT * FROM q",
                      f"SELECT list_transform([1], lambda i: {f}('x'))", f"SELECT * FROM events WHERE title = {f}('x')",
                      f"SELECT 1 FROM range(1) r, {f}() s"]:
                self.refused(q)

    def test_blocked_system_views_refused(self):
        for v in sorted(A.SQL_BLOCKED_VIEWS):
            for q in [f"SELECT * FROM {v}", f"FROM {v}", f"TABLE {v}", f"SUMMARIZE {v}", f"DESCRIBE {v}",
                      f"SELECT * FROM system.main.{v}", f"SELECT * FROM pg_catalog.{v}", f"SELECT * FROM main.{v}",
                      f"WITH q AS (SELECT * FROM {v}) SELECT * FROM q", f"SELECT (SELECT count(*) FROM {v})"]:
                r = post_sql(q)
                self.assertEqual(r.status_code, 400, f"{q} -> {r.text[:200]}")
                self.assertNoPath(r, q)

    def test_allowed_introspection_shows_no_path(self):
        """Every catalog view and table function the console allows, read in full, never names the lake or home."""
        queries = [f"SELECT * FROM {s}.{v}" for s, v in sorted(A.SQL_SYSTEM_VIEWS_OK)]
        for f in sorted(A.SQL_TABLE_FUNCS_OK - {"range", "generate_series", "unnest", "repeat", "values",
                                                "pragma_table_info"}):
            queries.append(f"SELECT * FROM {f}()")
        queries += ["SELECT * FROM pragma_table_info('events')",
                    "SHOW TABLES", "SHOW ALL TABLES", "SHOW DATABASES", "SHOW", "DESCRIBE", "SUMMARIZE events",
                    "SELECT current_database(), current_schema(), version(), current_query()"]
        ok = 0
        for q in queries:
            r = post_sql(q)
            self.assertIn(r.status_code, (200, 400), q)
            ok += r.status_code == 200
            self.assertNoPath(r, q)
        self.assertGreater(ok, len(queries) - 3, "the safe catalog views and functions should run")

    def test_refusals_and_errors_never_echo_a_path(self):
        lake = str(Path(LAKE).resolve())
        for q in [f"SELECT * FROM '{lake}/db/hub.duckdb'", f'SELECT * FROM "{lake}/tmp/x".csv',
                  f"SELECT * FROM read_text('{HOME}/.duckdb/x')", f'SELECT * FROM "{lake}/x"()',
                  f"SELECT * FROM read_csv('{lake}/x.csv')", f"ATTACH '{lake}/x.duckdb'",
                  "SELECT * FROM no_such_table", "SELECT no_such_column FROM events",
                  f"SELECT '{lake}' || 1::DATE", "SELECT error('x')", f"SHOW '{lake}'"]:
            r = post_sql(q)
            self.assertEqual(r.status_code, 400, q)
            self.assertNoPath(r, q)

    def test_the_explorer_schema_queries_and_examples_still_run(self):
        scope = "table_catalog = current_database() AND table_schema = 'main'"
        for q in [f"SELECT table_name FROM information_schema.tables WHERE {scope} ORDER BY table_name",
                  f"SELECT table_name, column_name, data_type FROM information_schema.columns WHERE {scope}",
                  "SELECT 'events' AS t, count(*) AS n FROM \"events\"", "SELECT * FROM duckdb_tables()",
                  "SELECT * FROM pg_catalog.pg_tables", "SELECT * FROM sqlite_master"]:
            r = post_sql(q)
            self.assertEqual(r.status_code, 200, f"{q} -> {r.text[:200]}")

    def test_clearer_messages(self):
        self.assertIn("no table or view named evnets", post_sql("SELECT * FROM evnets").json()["detail"])
        self.assertIn("SHOW lists tables and databases only", post_sql("SHOW SCHEMAS").json()["detail"])
        self.assertIn("server settings", post_sql("SELECT * FROM pg_settings").json()["detail"])


class DuckDBFoldersInTheLake(unittest.TestCase):
    """DuckDB's own default folders (~/.duckdb/...) point into the database's folder, persistent secrets are off."""

    def test_settings(self):
        rows = dict(db.connect().execute("SELECT name, value FROM duckdb_settings()").fetchall())
        here = str(config.DB_PATH.parent)
        for k in ("home_directory", "secret_directory"):
            self.assertTrue(rows[k].startswith(here), f"{k} = {rows[k]}")
        self.assertEqual(rows["allow_persistent_secrets"], "false")
        if not str(Path(LAKE).resolve()).startswith(HOME):   # a lake under the home folder names it, by design
            leaks = {k: v for k, v in rows.items() if HOME in str(v)}
            self.assertEqual(leaks, {})

    def test_vectors_and_upload_connections_share_the_config(self):
        import inspect
        from osinthub import vectors
        from osinthub.sources import upload
        self.assertIn("config=db.DUCKDB_CONFIG", inspect.getsource(vectors))
        self.assertIn("config=DUCKDB_CONFIG", inspect.getsource(upload))
        self.assertTrue(db.DUCKDB_CONFIG["secret_directory"].startswith(str(config.DB_PATH.parent)))
        self.assertFalse(db.DUCKDB_CONFIG["allow_persistent_secrets"])


if __name__ == "__main__":
    unittest.main()

"""Pre-public fix round, lane pf-sql.

SQL console: an infinite DATE or TIMESTAMP shows as "infinity" / "-infinity" at any depth inside LIST, ARRAY,
STRUCT, TUPLE, MAP and UNION values, not as the 9999-12-31 / 0001-01-01 DuckDB's client turns it into, while real
extreme dates stay dates (osinthub/api.py, _sql_inf_mask / _sql_inf_apply).

Every DuckDB the app opens is shut off from files it does not need (osinthub/db.py, restrict): the app database reads
only the lake and its own folder, the vector index no file at all, an upload's CSV reader only that one upload. For
each, a read of a file outside the lake (and, where the feature needs none, inside it) is refused, the network and
extension downloads are off, and the restriction cannot be lifted again.

    uv run --with pytest pytest tests/security/test_v12_pf_sql.py -q
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import duckdb

from _lake import make_lake
LAKE = make_lake("pfsql", disable="news,entities,netlog,ai", OSINTHUB_SQL_CONSOLE="1")

from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
import osinthub.api as A  # noqa: E402
from osinthub.sources import upload  # noqa: E402

db.connect()
C = TestClient(A.app, base_url="http://localhost")
INF, NINF = "infinity", "-infinity"

OUTSIDE = Path(tempfile.mkdtemp()) / "outside.csv"       # this module's temp folder: not in the lake
OUTSIDE.write_text("a,b\nSECRET-OUTSIDE,1\n")
INSIDE = Path(LAKE) / "raw" / "inside.csv"
INSIDE.parent.mkdir(parents=True, exist_ok=True)
INSIDE.write_text("a,b\nIN-LAKE,1\n")
assert not OUTSIDE.resolve().is_relative_to(Path(LAKE).resolve())
assert Path(LAKE, os.path.relpath(OUTSIDE, LAKE)).read_text() == OUTSIDE.read_text()


class NestedInfinity(unittest.TestCase):
    def rows(self, q):
        r = C.post("/api/sql", json={"sql": q})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["rows"]

    def test_lists_and_arrays(self):
        self.assertEqual(self.rows("SELECT [DATE 'infinity', DATE '2024-01-02', NULL, DATE '-infinity'] l, "
                                   "['infinity'::TIMESTAMP, '2020-01-01']::TIMESTAMP[2] a"),
                         [[[INF, "2024-01-02", None, NINF], [INF, "2020-01-01T00:00:00"]]])

    def test_real_extreme_dates_stay_dates(self):
        self.assertEqual(self.rows("SELECT [DATE '9999-12-31', DATE '0001-01-01', DATE 'infinity'] l, "
                                   "{'t': TIMESTAMP '9999-12-31 23:59:59.999999'} s"),
                         [[["9999-12-31", "0001-01-01", INF], {"t": "9999-12-31T23:59:59.999999"}]])

    def test_structs_and_tuples(self):
        self.assertEqual(self.rows("SELECT {'a': DATE 'infinity', 'b': 1, 'it''s x': TIMESTAMPTZ '-infinity', "
                                   "'c': DATE '2024-01-03'} s, ROW(1, TIMESTAMP_NS 'infinity', 'x') t"),
                         [[{"a": INF, "b": 1, "it's x": NINF, "c": "2024-01-03"}, [1, INF, "x"]]])

    def test_maps(self):
        self.assertEqual(self.rows("SELECT MAP([DATE 'infinity', DATE '2024-01-01'], [TIMESTAMP '-infinity', NULL]) m, "
                                   "MAP(['k'], [[DATE 'infinity']]) v, MAP([[DATE '-infinity']], [1]) lk"),
                         [[{INF: NINF, "2024-01-01": None}, {"k": [INF]}, {"key": [[NINF]], "value": [1]}]])

    def test_an_infinite_key_next_to_a_real_last_day_keeps_both(self):
        """DuckDB's client folds both keys into one Python date: the map is rebuilt from its entries. (Map keys are
        str() of the value, as before: a timestamp key keeps its space.)"""
        self.assertEqual(self.rows("SELECT MAP([DATE 'infinity', DATE '9999-12-31', DATE '-infinity', DATE '0001-01-01'], "
                                   "[1, 2, 3, 4]) m, MAP([TIMESTAMP '9999-12-31 23:59:59.999999', TIMESTAMP 'infinity'], "
                                   "['real', 'inf']) t"),
                         [[{INF: 1, "9999-12-31": 2, NINF: 3, "0001-01-01": 4},
                           {"9999-12-31 23:59:59.999999": "real", INF: "inf"}]])

    def test_unions(self):
        self.assertEqual(self.rows("SELECT union_value(d := DATE 'infinity')::UNION(n INT, d DATE) u UNION ALL "
                                   "SELECT union_value(n := 5)::UNION(n INT, d DATE)"), [[INF], [5]])
        self.assertEqual(self.rows("SELECT union_value(l := [TIMESTAMP_MS '-infinity'])::UNION(s STRUCT(x DATE), l TIMESTAMP_MS[]) u"),
                         [[[NINF]]])

    def test_any_depth(self):
        q = ("SELECT [{'a': [MAP(['k'], [{'d': [DATE 'infinity', DATE '-infinity']}])], 'b': ROW(TIMESTAMP_S 'infinity')}] deep, "
             "NULL::DATE[][] n, [NULL::STRUCT(d DATE)] ns, 'infinity'::DATE plain")
        self.assertEqual(self.rows(q),
                         [[[{"a": [{"k": {"d": [INF, NINF]}}], "b": [INF]}], None, [None], INF]])

    def test_columns_without_dates_untouched(self):
        self.assertEqual(self.rows("SELECT [1, 2] l, {'a': 'infinity'} s, 'x' t"), [[[1, 2], {"a": "infinity"}, "x"]])

    def test_many_rows(self):
        r = self.rows("SELECT i, [CASE WHEN i % 2 = 0 THEN DATE 'infinity' ELSE DATE '2024-01-01' END] l FROM range(3000) t(i) ORDER BY i")
        self.assertEqual(len(r), 3000)
        self.assertEqual(r[0], [0, [INF]])
        self.assertEqual(r[1], [1, ["2024-01-01"]])


def reads(con, path: Path) -> list:
    return con.execute(f"SELECT * FROM read_csv_auto('{path}')").fetchall()


class Locked(unittest.TestCase):
    """Shared checks: no file outside the lake, no network, no extension download or auto-load, no way back."""

    def assert_locked(self, con, inside_ok: bool, settings_locked: bool = True):
        for q in [f"SELECT * FROM read_csv_auto('{OUTSIDE}')", f"SELECT * FROM read_text('{OUTSIDE}')",
                  f"SELECT * FROM '{OUTSIDE}'", f"SELECT * FROM glob('{OUTSIDE.parent}/*')",
                  f"SELECT * FROM read_text('{LAKE}/{os.path.relpath(OUTSIDE, LAKE)}')",   # ../ out of the lake
                  "SELECT * FROM read_text('http://127.0.0.1:9/x.csv')", f"COPY (SELECT 1) TO '{OUTSIDE.parent}/w.csv'"]:
            with self.assertRaises(duckdb.Error, msg=q) as cm:
                con.execute(q).fetchall()
            self.assertNotIn("SECRET-OUTSIDE", str(cm.exception))
        self.assertFalse((OUTSIDE.parent / "w.csv").exists())
        if inside_ok:
            self.assertEqual(reads(con, INSIDE), [("IN-LAKE", 1)])
        else:
            with self.assertRaises(duckdb.PermissionException):
                reads(con, INSIDE)
        rows = dict(con.execute("SELECT name, value FROM duckdb_settings() WHERE name IN ('enable_external_access', "
                                "'autoinstall_known_extensions', 'autoload_known_extensions')").fetchall())
        self.assertEqual(rows, {"enable_external_access": "false", "autoinstall_known_extensions": "false",
                                "autoload_known_extensions": "false"})
        for q in ["SET enable_external_access = true", f"SET allowed_directories = ['{OUTSIDE.parent}/']",
                  f"SET allowed_paths = ['{OUTSIDE}']"]:
            with self.assertRaises(duckdb.Error, msg=q):
                con.execute(q)
        with self.assertRaises(duckdb.PermissionException):
            reads(con, OUTSIDE)
        if settings_locked:   # nothing changes these connections' settings later: every one is frozen
            for q in ["SET autoload_known_extensions = true", "SET autoinstall_known_extensions = true",
                      "SET lock_configuration = false", "RESET lock_configuration", "SET GLOBAL threads = 8"]:
                with self.assertRaises(duckdb.Error, msg=q):
                    con.execute(q)
            self.assertEqual(con.execute("SELECT current_setting('autoload_known_extensions')").fetchone()[0], False)


class AppDatabase(Locked):
    def test_reads_the_lake_only(self):
        # its cursors set the time zone, so its settings are not frozen (the console cannot run SET anyway)
        self.assert_locked(db.cursor(), inside_ok=True, settings_locked=False)


class VectorIndex(Locked):
    def test_reads_no_file_at_all_and_still_works(self):
        from osinthub import vectors
        v = vectors.DuckDBBackend(Path(LAKE) / "db" / "vectors-pfsql.duckdb")
        try:
            self.assert_locked(v.conn, inside_ok=False)
            vec = [1.0] + [0.0] * (vectors.DIM - 1)
            self.assertEqual(v.upsert("c", [{"id": "a", "vector": vec, "payload": {"k": "x"}}]), 1)
            self.assertEqual(v.count("c"), 1)
            self.assertEqual([h["id"] for h in v.search("c", vec, k=1, flt={"k": "x"})], ["a"])
            v.conn.execute("CHECKPOINT")   # its own file, .wal and spill folder stay usable
        finally:
            v.conn.close()


class UploadReader(Locked):
    def test_reads_only_the_upload_itself(self):
        up = config.UPLOAD_DIR / "2026" / "01" / "01" / "000000-up.csv"
        up.parent.mkdir(parents=True, exist_ok=True)
        up.write_text("ip,title\n192.0.2.9,x\n198.51.100.7,y\n")
        sibling = up.with_name("000001-other.csv")          # another upload in the same folder
        sibling.write_text("a,b\nOTHER-UPLOAD,1\n")
        opened = []
        real = duckdb.connect

        def spy(*a, **k):
            opened.append(real(*a, **k))
            return opened[-1]
        rows = upload._csv_rows(up)
        try:
            duckdb.connect = spy
            self.assertEqual(next(rows), ["ip", "title"])
        finally:
            duckdb.connect = real
        self.assertEqual(len(opened), 1)
        con = opened[0]
        self.assertEqual(next(rows), ("192.0.2.9", "x"))     # the reader is open, half way through the file
        self.assert_locked(con, inside_ok=False)
        with self.assertRaises(duckdb.PermissionException):
            reads(con, sibling)
        self.assertEqual(reads(con, up), [("192.0.2.9", "x"), ("198.51.100.7", "y")])
        spill = Path(con.execute("SELECT current_setting('temp_directory')").fetchone()[0])
        self.assertEqual(spill.resolve().parent, (config.TMP_DIR / "duckdb-upload").resolve())   # its own folder
        self.assertTrue(spill.is_dir())
        self.assertEqual(list(rows), [("198.51.100.7", "y")])
        self.assertFalse(spill.exists())                     # removed with the reader
        events = upload.ingest_file(up, "t")                 # and an upload still reads
        self.assertEqual([e.ip for e in events], ["192.0.2.9", "198.51.100.7"])


class EveryConnection(unittest.TestCase):
    def test_every_duckdb_the_app_opens_is_restricted_and_tested_here(self):
        """A new DuckDB connection in the app needs its own restriction and a test above: each duckdb.connect( is
        matched by a restrict( call in the same file, and nothing uses DuckDB's unrestricted default connection
        (duckdb.sql / query / execute / read_* / from_*) or imports connect under another name."""
        import re
        root = Path(A.__file__).parent
        sites, default_conn = {}, []
        for p in sorted(root.rglob("*.py")):
            text, rel = p.read_text(), p.relative_to(root).as_posix()
            code = "\n".join(ln.split("#")[0] for ln in text.splitlines())
            if n := len(re.findall(r"\bduckdb\s*\.\s*connect\s*\(", code)):
                sites[rel] = n
                self.assertEqual(len(re.findall(r"\brestrict\(", code)) - (rel == "db.py"), n, rel)   # db.py defines it
            default_conn += [f"{rel}: {m}" for m in re.findall(
                r"\bduckdb\s*\.\s*(?:sql|query|execute|executemany|read_\w+|from_\w+|values|table|view|"
                r"default_connection|cursor|install_extension|load_extension)\s*\(|from\s+duckdb\s+import\s+[^\n]*", code)]
        self.assertEqual(sites, {"db.py": 1, "sources/upload.py": 1, "vectors.py": 1})
        self.assertEqual(default_conn, [])


if __name__ == "__main__":
    unittest.main()

"""Archive and compression limits on every import path (CWE-409): gzip bombs, zip member size, count and forged
central directories, tar long-name/size/type desync and PAX overrides; a normal archive still imports.

    uv run --with pytest pytest tests/security/test_archives.py -q
"""
from __future__ import annotations

import gzip
import unittest

from _lake import make_lake
LAKE = make_lake("archives")

from osinthub import db  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)


class DecompressionBombs(unittest.TestCase):
    """Uploaded archives/gzip must not expand unboundedly (CWE-409)."""

    def test_gzip_bomb_rejected_without_storing(self):
        import io
        from osinthub.netlog import importer as IMP
        old = IMP.MAX_UNCOMPRESSED
        IMP.MAX_UNCOMPRESSED = 4000
        try:
            payload = (b'{"ts":1,"uid":"x","_path":"conn"}\n' * 500)  # ~16 KB decompressed > 4 KB cap
            res = IMP.import_any(io.BytesIO(gzip.compress(payload)), "bomb.log.gz", origin="test", match=False)
            self.assertIn("rejected", (res.get("error") or ""), res)
            self.assertEqual(res.get("inserted"), 0)
            # nothing was left on disk for it
            self.assertFalse(list((IMP.LAKE_DIR).rglob("*bomb*")))
        finally:
            IMP.MAX_UNCOMPRESSED = old

    def test_zip_member_over_cap_rejected(self):
        import io, zipfile
        from osinthub.netlog import importer as IMP
        old = IMP.MAX_UNCOMPRESSED
        IMP.MAX_UNCOMPRESSED = 4000
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("big.log", '{"ts":1}\n' * 2000)  # ~18 KB declared > 4 KB cap
            buf.seek(0)
            res = IMP.import_any(buf, "b.zip", origin="test", match=False)
            self.assertTrue([m for m in res.get("members", []) if "rejected" in (m.get("error") or "")], res)
        finally:
            IMP.MAX_UNCOMPRESSED = old

    def test_zip_entry_count_rejected_before_parse(self):
        import io, zipfile
        from osinthub.netlog import importer as IMP
        old = IMP.MAX_BUNDLE_MEMBERS
        IMP.MAX_BUNDLE_MEMBERS = 50
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for i in range(200):
                    z.writestr(f"e{i}.log", "")   # zero-length: would be skipped by the per-entry filter
            buf.seek(0)
            res = IMP.import_any(buf, "many.zip", origin="test", match=False)
            self.assertIn("entries", (res.get("error") or ""), res)  # caught by the EOCD pre-check
            self.assertEqual(res.get("members"), [])
        finally:
            IMP.MAX_BUNDLE_MEMBERS = old

    def test_zip_forged_count_still_rejected_by_size_cd(self):
        import io, struct, zipfile
        from osinthub.netlog import importer as IMP
        old = IMP.MAX_BUNDLE_MEMBERS
        IMP.MAX_BUNDLE_MEMBERS = 50
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for i in range(300):
                    z.writestr(f"e{i}.log", "")
            data = buf.getvalue()
            i = data.rfind(b"PK\x05\x06")
            forged = data[:i + 10] + struct.pack("<H", 1) + data[i + 12:]  # lie: total entries = 1
            res = IMP.import_any(io.BytesIO(forged), "forged.zip", origin="test", match=False)
            self.assertIn("entries", (res.get("error") or ""), res)  # caught via size_of_central_directory
        finally:
            IMP.MAX_BUNDLE_MEMBERS = old

    def test_tar_oversized_longname_header_rejected(self):
        import io, tarfile
        from osinthub.netlog import importer as IMP
        old = IMP.TAR_MAX_META
        IMP.TAR_MAX_META = 100   # a 3 KB long-name header then exceeds the extended-header cap
        try:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as t:   # a 3 KB name forces a long-name/PAX header
                ti = tarfile.TarInfo("x" * 3000 + ".log"); ti.size = 0
                t.addfile(ti, io.BytesIO(b""))
            buf.seek(0)
            res = IMP.import_any(buf, "long.tar", origin="test", match=False)
            self.assertIn("rejected", (res.get("error") or ""), res)
        finally:
            IMP.TAR_MAX_META = old

    def test_plain_tar_over_size_cap_rejected(self):
        import io, tarfile
        from osinthub.netlog import importer as IMP
        old = IMP.MAX_TAR_DECOMPRESSED
        IMP.MAX_TAR_DECOMPRESSED = 2048   # tiny, so a small plain tar exceeds the structural cap
        try:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as t:   # uncompressed
                for i in range(5):
                    data = b"{}\n" * 300
                    ti = tarfile.TarInfo(f"m{i}.log"); ti.size = len(data)
                    t.addfile(ti, io.BytesIO(data))
            buf.seek(0)
            res = IMP.import_any(buf, "big.tar", origin="test", match=False)
            self.assertIn("rejected", (res.get("error") or ""), res)
        finally:
            IMP.MAX_TAR_DECOMPRESSED = old

    def test_tar_nonregular_type_size_desync_rejected(self):
        import io, tarfile
        from osinthub.netlog import importer as IMP
        old = IMP.TAR_MAX_META
        IMP.TAR_MAX_META = 100
        try:
            d = tarfile.TarInfo("adir/"); d.type = tarfile.DIRTYPE; d.size = 5000   # dir with a bogus size
            lng = tarfile.TarInfo("././@LongLink"); lng.type = tarfile.GNUTYPE_LONGNAME; lng.size = 5000
            data = d.tobuf(format=tarfile.GNU_FORMAT) + lng.tobuf(format=tarfile.GNU_FORMAT) + b"A" * 5120
            res = IMP.import_any(io.BytesIO(data), "evil.tar", origin="test", match=False)
            self.assertIn("rejected", (res.get("error") or ""), res)  # the dir size must not hide the long-name header
        finally:
            IMP.TAR_MAX_META = old

    def test_pax_override_detector(self):
        from osinthub.netlog import importer as IMP
        self.assertTrue(IMP._pax_has_override(b"17 size=12345678\n"))          # size override → desync lever
        self.assertTrue(IMP._pax_has_override(b"26 GNU.sparse.realsize=99\n"))  # sparse → desync lever
        self.assertTrue(IMP._pax_has_override(b"garbage no-length"))            # unparseable → refuse
        self.assertFalse(IMP._pax_has_override(b"10 path=x\n"))                 # long path is fine
        self.assertFalse(IMP._pax_has_override(b"\x00\x00"))                    # padding

    def test_normal_tar_gz_still_imports(self):
        import io, tarfile
        from osinthub.netlog import importer as IMP
        payload = (b'{"ts":1762000000.0,"uid":"c1","id.orig_h":"192.0.2.1","id.resp_h":"198.51.100.1",'
                   b'"proto":"tcp","_path":"conn"}\n') * 3
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            ti = tarfile.TarInfo("conn.log"); ti.size = len(payload)
            t.addfile(ti, io.BytesIO(payload))
        buf.seek(0)
        res = IMP.import_any(buf, "logs.tar.gz", origin="test", match=False)
        self.assertIsNone(res.get("error"), res)
        self.assertGreaterEqual(res.get("inserted", 0), 1)   # streaming r| path reads members fine

    def test_zip_fails_closed_when_index_indeterminate(self):
        import io, zipfile
        from osinthub.netlog import importer as IMP
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.log", "{}\n")
        buf.seek(0)
        orig = IMP._zip_entry_count
        IMP._zip_entry_count = staticmethod(lambda fh: None)   # index we cannot validate
        try:
            res = IMP.import_any(buf, "x.zip", origin="test", match=False)
            self.assertIn("could not be validated", (res.get("error") or ""), res)  # fail closed, not parsed
        finally:
            IMP._zip_entry_count = orig

    def test_tar_member_cap_counts_skipped_entries(self):
        import io, tarfile
        from osinthub.netlog import importer as IMP
        old = IMP.MAX_BUNDLE_MEMBERS
        IMP.MAX_BUNDLE_MEMBERS = 50
        try:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as t:
                for i in range(200):
                    ti = tarfile.TarInfo(f"e{i}.log"); ti.size = 0
                    t.addfile(ti, io.BytesIO(b""))
            buf.seek(0)
            res = IMP.import_any(buf, "many.tar", origin="test", match=False)
            self.assertIn("more than", (res.get("error") or ""), res)
        finally:
            IMP.MAX_BUNDLE_MEMBERS = old

"""L3 (v1.2 housekeeping) backend-feature regressions.

3.2: entity merge/undo no longer swallows a failing `DELETE FROM entity_vec`. In DuckDB a failed statement
aborts the whole transaction, so the old `try/except: pass` turned a real error into a misleading
"transaction is aborted" failure on the next statement (or a silent rollback of a merge thought to have
succeeded). The real error must surface, and the merge must roll back cleanly.

    uv run --with pytest pytest tests/entities/test_v12_hk_feat.py -q
"""
from __future__ import annotations

import pytest

from _lake import make_lake
LAKE = make_lake("entities-v12-feat")

from osinthub import db  # noqa: E402
from osinthub.entities import overrides, store  # noqa: E402

db.connect()
store.ensure_schema()

SRC, DST = "malware:ixfeatsrc", "malware:ixfeatdst"


def _fresh():
    overrides.invalidate()
    with store._tx() as cur:
        cur.execute("DELETE FROM entity_overrides WHERE src IN (?, ?) OR dst IN (?, ?)", [SRC, DST, SRC, DST])
        cur.execute("DELETE FROM entities WHERE id IN (?, ?)", [SRC, DST])
    store.upsert_entities([
        {"id": SRC, "type": "malware", "name": "IxFeatSrc"},
        {"id": DST, "type": "malware", "name": "IxFeatDst"},
    ])


class _Boom(RuntimeError):
    pass


class _Cur:
    """Wraps the real cursor; raises on any statement that touches entity_vec, passes the rest through."""

    def __init__(self, real):
        self._real = real

    def execute(self, sql, *a, **k):
        if "entity_vec" in sql.lower():
            raise _Boom("entity_vec boom")
        return self._real.execute(sql, *a, **k)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_merge_surfaces_a_failing_entity_vec_delete(monkeypatch):
    _fresh()
    real = db.cursor()
    monkeypatch.setattr(db, "cursor", lambda: _Cur(real))

    # The real cause (the entity_vec failure) is what propagates — not a later "transaction aborted" error.
    with pytest.raises(_Boom, match="entity_vec boom"):
        overrides.merge(SRC, DST)

    monkeypatch.undo()
    # The aborted merge rolled back: both entities are still there and separate.
    assert db.query("SELECT 1 FROM entities WHERE id = ?", [SRC]), "src must survive a rolled-back merge"
    assert db.query("SELECT 1 FROM entities WHERE id = ?", [DST]), "dst must survive a rolled-back merge"
    assert not db.query("SELECT 1 FROM entity_overrides WHERE src = ? AND dst = ?", [SRC, DST])


def test_merge_without_the_fault_still_succeeds():
    _fresh()
    out = overrides.merge(SRC, DST)
    assert out
    assert not db.query("SELECT 1 FROM entities WHERE id = ?", [SRC]), "merged entity is gone"
    assert db.query("SELECT 1 FROM entities WHERE id = ?", [DST]), "kept entity remains"
    overrides.invalidate()

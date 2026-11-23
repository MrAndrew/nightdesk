"""Vector index with a Qdrant backend and a DuckDB fallback.

    upsert(collection, [{"id": str, "vector": [float]*1024, "payload": {...}}])
    search(collection, vector, k=10, filter=None) -> [{"id", "score", "payload"}]
    count(collection) -> int
    delete(collection, ids) / drop(collection)

Collections: ``cves``, ``articles`` (chunks), ``entities``, ``events``. Vectors are a derived
index: everything here can be rebuilt from the lake (osinthub/ai/indexer.py), so deleting
the Qdrant storage or ``db/vectors.duckdb`` only costs a re-embed.

Backend choice (``OSINTHUB_VECTORS``): ``qdrant``, ``duckdb``, or ``auto`` (Qdrant when it
answers, else DuckDB; rechecked every 30 s). ``filter`` is ``{payload_field: value | [values]}``.
Architecture: okf/architecture/local-ai.md#vectors
"""
from __future__ import annotations

import json
import math
import logging
import threading
import time
import uuid
from typing import Any

import httpx

from . import config, db

log = logging.getLogger("osinthub.vectors")

DIM = config.EMBED_DIM
COLLECTIONS = ("cves", "articles", "entities", "events")
_NS = uuid.UUID("6f1d3c3e-6a39-4d5e-9a64-0e8d9a1f5b21")


def check_vector(v, what: str = "vector") -> list[float]:
    """A finite float list of length DIM, or ValueError naming the problem."""
    try:
        out = [float(x) for x in v]
    except (TypeError, ValueError) as e:
        raise ValueError(f"{what}: not a list of numbers ({e})") from None
    if len(out) != DIM:
        raise ValueError(f"{what}: dimension {len(out)}, expected {DIM}")
    if not all(math.isfinite(x) for x in out):
        raise ValueError(f"{what}: contains NaN or infinity")
    if not any(out):
        raise ValueError(f"{what}: all zeros (cosine undefined)")
    return out


def _validate(items: list[dict]) -> list[dict]:
    out = []
    for it in items:
        if it.get("id") in (None, ""):
            raise ValueError("vector item without an id")
        out.append({**it, "vector": check_vector(it.get("vector") or [], f"vector for id {it['id']!r}")})
    return out


def point_uuid(collection: str, id_: str) -> str:
    return str(uuid.uuid5(_NS, f"{collection}:{id_}"))


# ------------------------------------------------------------------ Qdrant (REST)
class QdrantBackend:
    name = "qdrant"

    def __init__(self, url: str = config.QDRANT_URL, api_key: str | None = config.QDRANT_API_KEY):
        headers = {"api-key": api_key} if api_key else {}
        # Local service: never route through HTTP(S)_PROXY.
        self.http = httpx.Client(base_url=url, headers=headers, trust_env=False,
                                 timeout=httpx.Timeout(30.0, connect=0.5))
        self._known: set[str] = set()
        self.prefix = config.QDRANT_PREFIX

    def ping(self) -> bool:
        try:
            return self.http.get("/collections", timeout=httpx.Timeout(1.0, connect=0.5)).status_code == 200
        except httpx.HTTPError:
            return False

    def _ensure(self, c: str) -> None:
        if c in self._known:
            return
        r = self.http.get(f"/collections/{self.prefix}{c}")
        if r.status_code == 404:
            r = self.http.put(f"/collections/{self.prefix}{c}", json={"vectors": {"size": DIM, "distance": "Cosine"},
                                                          "on_disk_payload": True})
            if r.status_code not in (200, 409):
                r.raise_for_status()
        else:
            r.raise_for_status()
        self._known.add(c)

    def upsert(self, c: str, items: list[dict]) -> int:
        self._ensure(c)
        for i in range(0, len(items), 256):
            pts = [{"id": point_uuid(c, str(it["id"])), "vector": list(it["vector"]),
                    "payload": {**(it.get("payload") or {}), "_id": str(it["id"])}} for it in items[i:i + 256]]
            self.http.put(f"/collections/{self.prefix}{c}/points", params={"wait": "true"}, json={"points": pts}).raise_for_status()
        return len(items)

    @staticmethod
    def _filter(flt: dict | None) -> dict | None:
        if not flt:
            return None
        must = []
        for k, v in flt.items():
            must.append({"key": k, "match": {"any": list(v)} if isinstance(v, (list, tuple, set)) else {"value": v}})
        return {"must": must}

    def search(self, c: str, vector, k: int = 10, flt: dict | None = None) -> list[dict]:
        body: dict[str, Any] = {"vector": list(vector), "limit": k, "with_payload": True}
        f = self._filter(flt)
        if f:
            body["filter"] = f
        r = self.http.post(f"/collections/{self.prefix}{c}/points/search", json=body)
        if r.status_code == 404:
            return []
        r.raise_for_status()
        out = []
        for h in r.json().get("result", []):
            p = h.get("payload") or {}
            out.append({"id": p.pop("_id", h["id"]), "score": float(h["score"]), "payload": p})
        return out

    def count(self, c: str) -> int:
        r = self.http.post(f"/collections/{self.prefix}{c}/points/count", json={"exact": True})
        if r.status_code == 404:
            return 0
        r.raise_for_status()
        return int(r.json()["result"]["count"])

    def delete(self, c: str, ids: list[str]) -> None:
        if not ids:
            return
        r = self.http.post(f"/collections/{self.prefix}{c}/points/delete", params={"wait": "true"},
                           json={"points": [point_uuid(c, str(i)) for i in ids]})
        if r.status_code != 404:
            r.raise_for_status()

    def drop(self, c: str) -> None:
        self.http.delete(f"/collections/{self.prefix}{c}")
        self._known.discard(c)


# ------------------------------------------------------------------ DuckDB (no extensions)
class DuckDBBackend:
    """FLOAT[1024] arrays and array_cosine_similarity (built into DuckDB; no extension download).

    Brute force, which is fine for the tens of thousands of vectors a home lab produces. Uses its
    own file (``db/vectors.duckdb``) so the warehouse stays small and the index is disposable.
    """
    name = "duckdb"

    def __init__(self, path=config.VECTORS_DB):
        import duckdb
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(path), config=db.DUCKDB_CONFIG)   # no extension downloads
        db.restrict(self.conn, lock=True)   # it only ever reads its own table: no other file, no network
        self.lock = threading.Lock()
        self.conn.execute(f"""CREATE TABLE IF NOT EXISTS vectors (
            collection VARCHAR, id VARCHAR, vector FLOAT[{DIM}], payload JSON,
            PRIMARY KEY (collection, id))""")

    def ping(self) -> bool:
        return True

    def upsert(self, c: str, items: list[dict]) -> int:
        if not items:
            return 0
        rows = [(c, str(it["id"]), [float(x) for x in it["vector"]], json.dumps(it.get("payload") or {}, default=str))
                for it in items]
        with self.lock:
            cur = self.conn.cursor()
            with db.tx(cur):
                cur.executemany(f"INSERT OR REPLACE INTO vectors VALUES (?, ?, ?::FLOAT[{DIM}], ?)", rows)
        return len(items)

    def search(self, c: str, vector, k: int = 10, flt: dict | None = None) -> list[dict]:
        where, params = ["collection = ?"], [c]
        for key, v in (flt or {}).items():
            vals = list(v) if isinstance(v, (list, tuple, set)) else [v]
            where.append(f"json_extract_string(payload, ?) IN ({','.join('?' * len(vals))})")
            params += [f"$.{key}", *[str(x) if not isinstance(x, bool) else str(x).lower() for x in vals]]
        with self.lock:
            cur = self.conn.cursor()
            rows = cur.execute(
                f"SELECT id, array_cosine_similarity(vector, ?::FLOAT[{DIM}]) AS s, payload FROM vectors "
                f"WHERE {' AND '.join(where)} ORDER BY s DESC LIMIT ?", [list(vector), *params, k]).fetchall()
        return [{"id": i, "score": float(s), "payload": json.loads(p) if p else {}} for i, s, p in rows]

    def count(self, c: str) -> int:
        with self.lock:
            return int(self.conn.cursor().execute("SELECT count(*) FROM vectors WHERE collection = ?", [c]).fetchone()[0])

    def delete(self, c: str, ids: list[str]) -> None:
        if not ids:
            return
        with self.lock:
            self.conn.cursor().execute(f"DELETE FROM vectors WHERE collection = ? AND id IN ({','.join('?' * len(ids))})",
                                       [c, *ids])

    def drop(self, c: str) -> None:
        with self.lock:
            self.conn.cursor().execute("DELETE FROM vectors WHERE collection = ?", [c])


# ------------------------------------------------------------------ selection
_backends: dict[str, Any] = {}
_choice: tuple[float, str] = (0.0, "")
_sel_lock = threading.Lock()


def _get(name: str):
    with _sel_lock:
        b = _backends.get(name)
        if b is None:
            b = _backends[name] = QdrantBackend() if name == "qdrant" else DuckDBBackend()
        return b


def backend():
    """The active backend. ``auto`` prefers Qdrant and re-probes every 30 s."""
    global _choice
    mode = config.VECTORS
    if mode in ("qdrant", "duckdb"):
        return _get(mode)
    t, name = _choice
    if time.monotonic() - t > 30 or not name:
        name = "qdrant" if _get("qdrant").ping() else "duckdb"
        if name != _choice[1]:
            log.info("vector backend: %s", name)
        _choice = (time.monotonic(), name)
    return _get(name)


def backend_name() -> str:
    return backend().name


def upsert(collection: str, items: list[dict]) -> int:
    """Insert or replace items. Raises ValueError for a wrong dimension, NaN/inf or a missing id."""
    return backend().upsert(collection, _validate(items))


def search(collection: str, vector, k: int = 10, filter: dict | None = None) -> list[dict]:
    """Nearest items by cosine. A malformed query vector raises ValueError; an unavailable
    backend is logged and returns []."""
    vector = check_vector(vector, "query vector")
    try:
        return backend().search(collection, vector, k, filter)
    except Exception as e:
        log.warning("vector search on %s failed: %s", collection, e)
        return []


def count(collection: str) -> int:
    try:
        return backend().count(collection)
    except Exception as e:
        log.warning("vector count on %s failed: %s", collection, e)
        return 0


def delete(collection: str, ids: list[str]) -> None:
    backend().delete(collection, ids)


def drop(collection: str) -> None:
    backend().drop(collection)


def status() -> dict:
    b = backend()
    return {"mode": config.VECTORS, "backend": b.name,
            "url": config.QDRANT_URL if b.name == "qdrant" else str(config.VECTORS_DB),
            "counts": {c: count(c) for c in COLLECTIONS}}


# ------------------------------------------------------------------ what is embedded
# Kept next to the DuckDB index (db/vectors.duckdb) per backend, so indexers only embed new or
# changed documents and catch up after the AI helper or Qdrant was down.
def _track():
    b = _get("duckdb")
    with b.lock:
        b.conn.execute("""CREATE TABLE IF NOT EXISTS vector_index (
            backend VARCHAR, collection VARCHAR, id VARCHAR, hash VARCHAR, embedded_at TIMESTAMPTZ DEFAULT now(),
            PRIMARY KEY (backend, collection, id))""")
    return b


def indexed(collection: str, backend_name: str | None = None) -> dict[str, str]:
    """{id: doc hash} of what the active (or named) backend holds for a collection."""
    b = _track()
    name = backend_name or backend().name
    with b.lock:
        rows = b.conn.cursor().execute("SELECT id, hash FROM vector_index WHERE backend = ? AND collection = ?",
                                       [name, collection]).fetchall()
    return dict(rows)


def mark_indexed(collection: str, hashes: dict[str, str], backend_name: str | None = None) -> None:
    if not hashes:
        return
    b = _track()
    name = backend_name or backend().name
    with b.lock:
        cur = b.conn.cursor()
        cur.executemany("INSERT OR REPLACE INTO vector_index VALUES (?, ?, ?, ?, now())",
                        [(name, collection, i, h) for i, h in hashes.items()])


def reset_indexed(collection: str, backend_name: str | None = None) -> None:
    b = _track()
    name = backend_name or backend().name
    with b.lock:
        b.conn.cursor().execute("DELETE FROM vector_index WHERE backend = ? AND collection = ?", [name, collection])


def unmark_indexed(collection: str, ids: list[str], backend_name: str | None = None) -> None:
    if not ids:
        return
    b = _track()
    name = backend_name or backend().name
    with b.lock:
        cur = b.conn.cursor()
        for j in range(0, len(ids), 500):
            part = ids[j:j + 500]
            cur.execute(f"DELETE FROM vector_index WHERE backend = ? AND collection = ? AND id IN ({','.join('?' * len(part))})",
                        [name, collection, *part])

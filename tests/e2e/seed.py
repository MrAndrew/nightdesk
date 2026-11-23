"""Seed an empty scratch lake with the small synthetic news the E2E journeys read (run BEFORE the server starts).

    OSINTHUB_LAKE=/tmp/x/lake python tests/e2e/seed.py

Network data does not need seeding: the journeys load the built-in demo (POST /api/netlog/demo) and import their own
Zeek fixture through the inbox folder. News has no offline source, so this puts two synthetic research reports
(tests/e2e/fixtures/news.json: documentation addresses, .example domains, an invented CVE) into the lake as fetched
articles and runs the app's own pipeline on them (chunks, entity extraction, story clustering), with the checked-in
ATT&CK/MISP reference fixture (tests/entities/fixtures/ref: APT28) as the lake's reference data. Three invented NVD
CVEs with entity-encoded descriptions (tests/sources/fixtures/unescape/nvd_cves.json) are loaded through the source's
own parse() for the escaping journey (test_escaping.py). Nothing here
touches the network: OSINTHUB_OFFLINE=1 and the AI helper points at the discard port.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


@contextlib.contextmanager
def stored_extractions(by_article: dict):
    """While seeding, an article with a stored `extraction` (the shape extract() returns after the local model ran)
    gets that result instead of the offline pass, so the app's own ingest stores its mentions and claims exactly
    as it would online (`"llm": false` adds the stored fields to the offline pass without marking it a model run).
    `technique_names` stands in for ATT&CK names the small reference fixture does not carry."""
    from osinthub.entities import extract as ex, ingest
    real = ingest.extract
    texts = {}

    def fake(text, url=None, use_llm=True):
        aid = texts.get(url)
        if aid is None:
            return real(text, url, use_llm=use_llm)
        out = real(text, url, use_llm=False)
        x = by_article[aid]
        out.update({k: v for k, v in x.items() if k not in ("technique_names", "llm")})
        out["technique_quotes"] = {**out.get("technique_quotes", {}), **x.get("technique_quotes", {})}
        if x.get("llm", True):       # "llm": false keeps the article's offline methods (only the stored techniques added)
            ex.LAST_STATS.update(llm=True, chunks=1, ok=1)
        return out

    from osinthub import db
    for aid in by_article:
        r = db.query("SELECT url FROM articles WHERE id = ?", [aid])
        if r:
            texts[r[0]["url"]] = aid
    ingest.extract = fake
    try:
        yield
    finally:
        ingest.extract = real
    for x in by_article.values():
        for tid, name in (x.get("technique_names") or {}).items():
            db.execute("UPDATE entities SET name = ? WHERE id = ?", [name, f"technique:{tid}"])


def main() -> None:
    lake = os.environ.get("OSINTHUB_LAKE")
    if not lake:
        raise SystemExit("set OSINTHUB_LAKE to the scratch lake to seed")
    os.environ["OSINTHUB_OFFLINE"] = "1"
    os.environ["OSINTHUB_NEWS_NO_VECTORS"] = "1"
    os.environ["AI_URL"] = "http://127.0.0.1:9"
    os.environ.setdefault("OSINTHUB_VECTORS", "duckdb")
    ref = Path(lake) / "ref"
    ref.mkdir(parents=True, exist_ok=True)
    for f in (ROOT / "tests" / "entities" / "fixtures" / "ref").glob("*.json"):
        shutil.copyfile(f, ref / f.name)
    sys.path.insert(0, str(ROOT))

    from osinthub import db
    from osinthub.entities import store
    from osinthub.news import pipeline, stories
    from osinthub.news.common import ensure_schema

    db.connect()
    ensure_schema()
    store.ensure_schema()
    now = dt.datetime.now(dt.UTC)
    fx = json.loads((HERE / "fixtures" / "news.json").read_text())
    for a in fx["articles"]:
        text = " ".join(a["paragraphs"])
        db.execute("""INSERT INTO articles (id, url, source, title, text, published, fetched_at, status, tier, role,
                      dek) VALUES (?, ?, ?, ?, ?, ?, ?, 'ok', ?, ?, ?)""",
                   [a["id"], a["url"], a["source"], a["title"], text, now - dt.timedelta(hours=a["hours_ago"]),
                    now - dt.timedelta(hours=a["hours_ago"]), a["tier"], a["role"], a["dek"]])
    pipeline.prepare_pending()
    with stored_extractions({a["id"]: a["extraction"] for a in fx["articles"] if a.get("extraction")}):
        pipeline.ingest_entities_pending(limit=50)
    stories.cluster_pending()
    # Entity-encoded provider text (lane v12-unescape): NVD descriptions such as '&lt;img src=x onerror=...&gt;' go
    # through the source's own parse() and are loaded like a run, so test_escaping.py can check they show as text.
    from osinthub import scheduler
    from osinthub.sources import SOURCES
    nvd = SOURCES["nvd_recent"]
    cves = nvd.parse((ROOT / "tests" / "sources" / "fixtures" / "unescape" / "nvd_cves.json").read_bytes())
    for i, e in enumerate(cves):
        e.ts = now - dt.timedelta(minutes=30 + 5 * i)   # inside every panel's default time range
    scheduler._load(nvd, scheduler._rows(cves, None, now), None)
    st = db.query("SELECT count(*) AS n FROM stories")[0]["n"]
    ents = db.query("SELECT count(DISTINCT entity_id) AS n FROM mentions")[0]["n"]
    print(json.dumps({"articles": len(fx["articles"]), "stories": st, "entities": ents, "cves": len(cves)}))


if __name__ == "__main__":
    main()

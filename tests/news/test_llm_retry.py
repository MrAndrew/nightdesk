"""Articles ingested while the AI helper is down are revisited for the LLM pass once it is back
(api-audit-011). Temporary lake, AI helper on a dead port, then a fake helper answer; no network.

    uv run --with pytest pytest tests/news/test_llm_retry.py -q
"""
import json

from _lake import make_lake
LAKE = make_lake("news-llm")

from osinthub import db  # noqa: E402
from osinthub.ai import client  # noqa: E402
from osinthub.news import pipeline  # noqa: E402
from osinthub.news.common import ensure_schema  # noqa: E402

ensure_schema()
db.connect()
TEXT = ("Researchers said the Volt Example group breached Acme Shipping, a logistics firm in Norway. "
        "The intrusion started with a phishing email. ") * 6


def _article(aid, unique=False):
    """unique: a text of its own, so the per-chunk LLM answer cache cannot answer for it."""
    db.execute("""INSERT INTO articles (id, url, source, title, text, published, status, tier, role)
                  VALUES (?, ?, 'Talos', 'Volt Example breaches Acme', ?, now(), 'ok', 'B', 'research')""",
               [aid, f"https://x.example/{aid}", TEXT + (f" Case {aid}." if unique else "")])


def _row(aid):
    return db.query("SELECT entities_at, entities_llm_missed FROM articles WHERE id = ?", [aid])[0]


def _llm_mentions(aid):
    return db.query("SELECT count(*) AS n FROM mentions WHERE ref_id = ? AND method = 'llm'", [aid])[0]["n"]


ANSWER = {"actors": [], "malware": [], "tools": [], "campaigns": [], "victims": ["Acme Shipping"],
          "sectors": ["logistics"], "countries": ["Norway"], "techniques": [], "claims": []}


def test_helper_down_marks_article_for_revisit_then_llm_pass_runs():
    _article("a1")
    client._down_until = 0.0
    assert pipeline.ingest_entities_pending(5) == 1
    r = _row("a1")
    assert r["entities_at"] is not None, "deterministic results are stored and the article is not stuck"
    assert r["entities_llm_missed"] is not None, "the missed LLM pass is recorded"
    assert _llm_mentions("a1") == 0

    # Still down: nothing is retried (and the call does not hammer the helper).
    assert pipeline.ingest_entities_pending(5) == 0

    # Helper back. Before the retry delay nothing happens; after it the article is ingested again.
    client._down_until = 0.0
    calls = []
    orig = client.chat
    client.chat = lambda *a, **k: calls.append(1) or json.dumps(ANSWER)
    try:
        assert pipeline.ingest_entities_pending(5) == 0 and not calls
        db.execute("UPDATE articles SET entities_llm_missed = now() - INTERVAL 11 MINUTE WHERE id = 'a1'")
        assert pipeline.ingest_entities_pending(5) == 1 and calls
    finally:
        client.chat = orig
    assert _row("a1")["entities_llm_missed"] is None
    assert _llm_mentions("a1") > 0, "victims/sectors/countries from the LLM pass are stored"
    assert pipeline.ingest_entities_pending(5) == 0, "done: not revisited again"


def test_helper_answering_is_not_marked():
    _article("a2")
    client._down_until = 0.0
    orig = client.chat
    client.chat = lambda *a, **k: json.dumps(ANSWER)
    try:
        assert pipeline.ingest_entities_pending(5) == 1
    finally:
        client.chat = orig
    assert _row("a2")["entities_llm_missed"] is None


def _tries(aid):
    return db.query("SELECT entities_llm_tries AS t FROM articles WHERE id = ?", [aid])[0]["t"]


def test_timeout_or_http_error_while_up_is_retried_with_backoff():  # api-audit-011 recheck
    # client.chat returns None without marking the helper down on a timeout, a 4xx/5xx or an unusable reply
    _article("a3", unique=True)
    client._down_until = 0.0
    orig = client.chat
    calls = []
    client.chat = lambda *a, **k: calls.append(1) and None
    try:
        assert pipeline.ingest_entities_pending(5) == 1 and calls
        assert not client.is_down()
        r = _row("a3")
        assert r["entities_at"] is not None and r["entities_llm_missed"] is not None, "marked for a later LLM pass"
        assert _tries("a3") == 1
        # first retry after LLM_RETRY_MIN; it fails again, so the next wait doubles (20 minutes)
        db.execute("UPDATE articles SET entities_llm_missed = now() - INTERVAL 11 MINUTE WHERE id = 'a3'")
        calls.clear()
        assert pipeline.ingest_entities_pending(5) == 0 and calls and _tries("a3") == 2
        db.execute("UPDATE articles SET entities_llm_missed = now() - INTERVAL 11 MINUTE WHERE id = 'a3'")
        calls.clear()
        assert pipeline.ingest_entities_pending(5) == 0 and not calls, "backing off: not tried after 11 minutes"
        db.execute("UPDATE articles SET entities_llm_missed = now() - INTERVAL 21 MINUTE WHERE id = 'a3'")
        assert pipeline.ingest_entities_pending(5) == 0 and calls and _tries("a3") == 3
        # helper answers again: the LLM pass runs and the counters clear
        client.chat = lambda *a, **k: json.dumps(ANSWER)
        db.execute("UPDATE articles SET entities_llm_missed = now() - INTERVAL 1 DAY WHERE id = 'a3'")
        assert pipeline.ingest_entities_pending(5) == 1
    finally:
        client.chat = orig
    assert _row("a3")["entities_llm_missed"] is None and _tries("a3") is None and _llm_mentions("a3") > 0


def test_outage_does_not_count_as_a_try():
    _article("a4", unique=True)
    client._down_until = 0.0  # the dead AI_URL: connection refused marks the helper down
    assert pipeline.ingest_entities_pending(5) == 1
    assert _row("a4")["entities_llm_missed"] is not None and _tries("a4") is None
    db.execute("UPDATE articles SET entities_at = now(), entities_llm_missed = NULL WHERE id = 'a4'")


def test_failing_ingest_backs_off_and_does_not_starve_others():  # api-audit-r2-006
    from osinthub import entities as ent
    db.execute("UPDATE articles SET entities_at = coalesce(entities_at, now()), entities_llm_missed = NULL")
    for i in range(5):
        _article(f"bad{i}", unique=True)
    for i in range(3):
        _article(f"old{i}", unique=True)
        db.execute("UPDATE articles SET published = now() - INTERVAL 2 HOUR WHERE id = ?", [f"old{i}"])
    orig_ingest, orig_chat = ent.ingest_text, client.chat
    client.chat = lambda *a, **k: json.dumps(ANSWER)

    def flaky(kind, ref, *a, **k):
        if ref.startswith("bad"):
            raise RuntimeError("simulated failure")
        return orig_ingest(kind, ref, *a, **k)
    ent.ingest_text = flaky
    try:
        client._down_until = 0.0
        assert pipeline.ingest_entities_pending(5) == 0          # the 5 newest fail
        assert pipeline.ingest_entities_pending(5) == 3          # next cycle: they wait, the older ones go
        assert all(_row(f"old{i}")["entities_at"] is not None for i in range(3))
        assert pipeline.ingest_entities_pending(5) == 0          # still backing off: nothing selected
        fails = db.query("SELECT min(entities_fails) AS a, max(entities_fails) AS b FROM articles WHERE id LIKE 'bad%'")[0]
        assert fails == {"a": 1, "b": 1}
        db.execute("UPDATE articles SET entities_failed_at = now() - INTERVAL 11 MINUTE WHERE id LIKE 'bad%'")
        _article("fresh", unique=True)
        ent.ingest_text = orig_ingest
        # after the wait they are tried again, but a fresh article comes first
        got = db.query("SELECT id FROM articles WHERE status = 'ok' AND entities_at IS NULL AND "
                       f"{pipeline._backoff('entities_fails', 'entities_failed_at')} "
                       "ORDER BY coalesce(entities_fails, 0) > 0, published DESC NULLS LAST LIMIT 1")
        assert got[0]["id"] == "fresh"
        assert pipeline.ingest_entities_pending(10) == 6
        r = db.query("SELECT count(*) AS n FROM articles WHERE id LIKE 'bad%' AND entities_fails IS NULL "
                     "AND entities_at IS NOT NULL")[0]["n"]
        assert r == 5, "success clears the failure count"
    finally:
        ent.ingest_text, client.chat = orig_ingest, orig_chat


def _long_article(aid):
    """Several LLM chunks (extract.CHUNK_CHARS is 9000), each paragraph unique so nothing comes from the cache."""
    text = "\n\n".join(f"Paragraph {i} of {aid}: " + TEXT for i in range(60))
    db.execute("""INSERT INTO articles (id, url, source, title, text, published, status, tier, role)
                  VALUES (?, ?, 'Talos', 'Volt Example breaches Acme', ?, now(), 'ok', 'B', 'research')""",
               [aid, f"https://x.example/{aid}", text])


def test_partial_llm_miss_is_retried():  # evaluator round 1: a later chunk failing lost its entities
    from osinthub.entities.extract import LAST_STATS
    db.execute("UPDATE articles SET entities_at = coalesce(entities_at, now()), entities_llm_missed = NULL")
    _long_article("p1")
    client._down_until = 0.0
    orig = client.chat
    calls = []
    client.chat = lambda *a, **k: json.dumps(ANSWER) if not calls.append(1) and len(calls) == 1 else None
    try:
        assert pipeline.ingest_entities_pending(5) == 1
        assert LAST_STATS["chunks"] >= 3 and LAST_STATS["ok"] == 1, LAST_STATS
        assert _row("p1")["entities_llm_missed"] is not None and _tries("p1") == 1, "partly answered: retried"
        calls.clear()
        client.chat = lambda *a, **k: calls.append(1) or json.dumps(ANSWER)
        db.execute("UPDATE articles SET entities_llm_missed = now() - INTERVAL 11 MINUTE WHERE id = 'p1'")
        assert pipeline.ingest_entities_pending(5) == 1
        assert len(calls) == LAST_STATS["chunks"] - 1, "the answered chunk comes from the cache"
    finally:
        client.chat = orig
    assert _row("p1")["entities_llm_missed"] is None and _tries("p1") is None


def test_refetch_with_new_text_resets_the_retry_counters():  # coordinator round 3
    import types
    from osinthub.news import fetcher
    _article("rf1", unique=True)
    db.execute("""UPDATE articles SET entities_at = now(), entities_llm_missed = NULL, entities_llm_tries = 6,
                  entities_fails = 3, entities_failed_at = now() WHERE id = 'rf1'""")   # given up on the old text
    row = db.query("SELECT * FROM articles WHERE id = 'rf1'")[0]
    para = "<p>" + " ".join(f"Volt Example breached victim number {i} in the logistics sector." for i in range(40)) + "</p>"
    resp = types.SimpleNamespace(url="https://x.example/rf1", status_code=200, headers={})

    def counters():
        return db.query("""SELECT entities_at, entities_llm_missed, entities_llm_tries, entities_fails, entities_failed_at,
                           text FROM articles WHERE id = 'rf1'""")[0]
    same = f"<html><head><title>t</title></head><body><article>{para}</article></body></html>"
    assert fetcher._store("rf1", row, same, resp, refetch=True) in ("updated", "ok")
    c = counters()
    assert "victim number 39" in c["text"], "new text stored"
    assert (c["entities_at"], c["entities_llm_missed"], c["entities_llm_tries"], c["entities_fails"],
            c["entities_failed_at"]) == (None,) * 5, "fresh retries for the new text"
    # an unchanged re-fetch keeps the counters (nothing new to extract)
    db.execute("UPDATE articles SET entities_at = now(), entities_llm_tries = 6 WHERE id = 'rf1'")
    row = db.query("SELECT * FROM articles WHERE id = 'rf1'")[0]
    assert fetcher._store("rf1", row, same, resp, refetch=True) == "unchanged"
    assert counters()["entities_llm_tries"] == 6
    db.execute("UPDATE articles SET entities_at = now(), entities_llm_tries = NULL WHERE id = 'rf1'")


def test_llm_gives_up_after_max_tries():  # evaluator round 1: an always-timing-out text is not retried forever
    db.execute("UPDATE articles SET entities_at = coalesce(entities_at, now()), entities_llm_missed = NULL")
    _article("g1", unique=True)
    client._down_until = 0.0
    orig = client.chat
    calls = []
    client.chat = lambda *a, **k: calls.append(1) and None
    try:
        pipeline.ingest_entities_pending(5)
        for k in range(2, pipeline.LLM_MAX_TRIES + 1):
            assert _row("g1")["entities_llm_missed"] is not None and _tries("g1") == k - 1
            db.execute("UPDATE articles SET entities_llm_missed = now() - INTERVAL 2 DAY WHERE id = 'g1'")
            pipeline.ingest_entities_pending(5)
        assert _tries("g1") == pipeline.LLM_MAX_TRIES and _row("g1")["entities_llm_missed"] is None, "given up"
        assert _row("g1")["entities_at"] is not None, "deterministic results kept"
        calls.clear()
        assert pipeline.ingest_entities_pending(5) == 0 and not calls, "not tried again"
    finally:
        client.chat = orig

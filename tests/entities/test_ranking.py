"""How entities are ranked, without a database: claim confidence bands (who said it, how often, with what evidence)
and the keyword ranking of the `entity` searcher (names and aliases first, then descriptions, popular before obscure).

    uv run --with pytest pytest tests/entities/test_ranking.py -q
"""
from __future__ import annotations

import unittest

from _lake import make_lake
LAKE = make_lake("ranking")

from osinthub.entities.scoring import assess, band  # noqa: E402


def ev(source, tier, quote=None, llm=True, story=None):
    e = {"source": source, "tier": tier}
    if quote:
        e["quote"] = quote
    if llm:
        e["method"] = "llm"
    if story:
        e["story_id"] = story
    return e


class Bands(unittest.TestCase):
    def check(self, evidence, expect, sources=(), observed=False):
        conf, b, why = assess(evidence, list(sources), observed)
        self.assertEqual(b, expect, why)
        self.assertEqual(band(conf), expect)
        return conf, why

    def test_low(self):
        self.check([ev("blog.example", "C", "q1")], "low")
        self.check([ev("x.social", "D", "q1")], "low")
        self.check([ev("vendor.example", "B", "q1")], "low")          # one model-extracted article

    def test_moderate(self):
        self.check([], "moderate", sources=["MITRE ATT&CK"])          # one curated tier-B source
        self.check([ev("a.example", "C", "q1"), ev("b.example", "C", "q2")], "moderate")
        self.check([ev("vendor.example", "B", "q1"), ev("blog.example", "C", "q2")], "moderate")

    def test_high(self):
        conf, why = self.check([ev("vendor-a.example", "B", "q1"), ev("cert.example", "A", "q2")], "high")
        self.assertIn("2 sources: A, B", why)
        self.check([ev("blog.example", "C", "q1")], "high", observed=True)

    def test_syndicated_copies_count_once(self):
        same = "APT99 used the loader against banks"
        self.check([ev("vendor-a.example", "B", same), ev("aggregator.example", "B", same)], "low")
        self.check([ev("vendor-a.example", "B", "q1"), ev("vendor-a.example", "B", "q2")], "low")   # same publisher
        self.check([ev("a.example", "B", "q1", story="s1"), ev("b.example", "B", "q2", story="s1")], "high")  # two outlets

    def test_more_sources_rank_higher_within_band(self):
        two, _ = self.check([ev("a.example", "B", "q1"), ev("b.example", "B", "q2")], "high")
        three, _ = self.check([ev("a.example", "B", "q1"), ev("b.example", "B", "q2"), ev("c.example", "A", "q3")], "high")
        self.assertGreater(three, two)


from osinthub.entities import searcher  # noqa: E402

# (id, type, name, aliases, description, mentions)
ROWS = [
    ("actor:lazarus-group", "actor", "Lazarus Group",
     ["Guardians of Peace", "Operation Troy", "G0082", "Bluenoroff", "Dark Seoul", "Hidden Cobra", "ZINC", "Labyrinth Chollima"],
     "Lazarus Group is a North Korean state-sponsored cyber threat group attributed to the Reconnaissance General Bureau. "
     "It has been active since at least 2009 and is known for destructive attacks and financial theft. " * 3, 169),
    ("malware:unidentified-077-lazarus-downloader", "malware", "Unidentified 077 (Lazarus Downloader)", [], "A downloader.", 0),
    ("malware:lazarus-loader", "malware", "LazarusLoader", [], "Lazarus loader", 1),
    ("domain:lazarus.example", "domain", "lazarus.example", [], None, 50),
    ("malware:qakbot", "malware", "QakBot", ["QBot", "Qakbot", "Pinkslipbot"], "Banking trojan.", 40),
    ("tool:akbot", "tool", "Akbot", ["Qakbot", "Qbot"], "IRC bot.", 2),
    ("actor:volt-typhoon", "actor", "Volt Typhoon", ["Bronze Silhouette"], "PRC actor.", 30),
    ("org:voltnet-inc", "org", "VoltNet Inc", [], None, 1),
    ("actor:apt28", "actor", "APT28", ["Fancy Bear", "Sofacy", "Group 74", "The Group", "APT 28"], "Russian GRU unit.", 90),
    ("org:the-constant-company", "org", "The Constant Company", [], None, 3),
    ("tool:win-tool-kms", "tool", "Win.Tool.Kmsauto", [], None, 1),
    ("org:team-inverse", "org", "TEAM INVERSE LLC", [], None, 1),
]


class FakeCursor:
    def execute(self, *a, **k):
        return self

    def fetchall(self):
        return list(ROWS)


class FakeDB:
    def query(self, *a, **k):
        return [{"n": len(ROWS)}]

    def cursor(self):
        return FakeCursor()


class EntityRanking(unittest.TestCase):
    def setUp(self):
        self._db = searcher.db
        searcher.db = FakeDB()
        searcher._corpus.update(t=0, n=-1, docs={})

    def tearDown(self):
        searcher.db = self._db

    def ids(self, q):
        return [r["id"] for r in searcher.search_entities(q, None, 10)]

    def test_single_word_finds_group_name(self):
        for q in ("lazarus", "Lazarus", "LAZARUS", "lazarus group", "the Lazarus group"):
            self.assertEqual(self.ids(q)[0], "actor:lazarus-group", q)

    def test_name_beats_alias(self):
        self.assertEqual(self.ids("qakbot")[:2], ["malware:qakbot", "tool:akbot"])

    def test_word_prefix(self):
        self.assertEqual(self.ids("volt")[0], "actor:volt-typhoon")

    def test_alias_and_id(self):
        self.assertEqual(self.ids("fancy bear")[0], "actor:apt28")
        self.assertEqual(self.ids("actor:apt28")[0], "actor:apt28")

    def test_iocs_get_no_name_like_match(self):
        # a domain whose first label is the query is not promoted ahead of the actor
        self.assertLess(self.ids("lazarus").index("actor:lazarus-group"), self.ids("lazarus").index("domain:lazarus.example")
                        if "domain:lazarus.example" in self.ids("lazarus") else 99)

    def test_generic_words_get_no_name_tiers(self):
        # "the", "group", "team", "apt", "win" name nothing on their own: no entity is bumped to the exact score
        for q in ("the", "group", "team", "apt", "win", "operation", "the group"):
            bumped = [r["id"] for r in searcher.search_entities(q, None, 10) if r["score"] >= 0.99]
            self.assertEqual(bumped, [], q)
        self.assertEqual(self.ids("apt 28")[0], "actor:apt28")

    def test_scores_keep_tier_order(self):
        res = searcher.search_entities("lazarus", None, 10)
        scores = [r["score"] for r in res]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertLessEqual(max(s for r, s in zip(res, scores) if r["id"] != "actor:lazarus-group"), scores[0])

"""Story clustering on a small synthetic corpus in a temporary lake (no network, no AI helper).

    uv run --with pytest pytest tests/news/test_stories.py -q

Checks: a shared CVE in the lead lets two differently worded reports a week apart merge; same-topic
different events stay apart; round-ups never merge; sponsored posts get no story; a translated copy
is a duplicate and counted once; LLM summaries survive a recluster.
"""
import sys

from _lake import make_lake
LAKE = make_lake("news")

from osinthub import db  # noqa: E402
from osinthub.news import stories  # noqa: E402
from osinthub.news.common import ensure_schema  # noqa: E402
from osinthub.news.pipeline import minhash  # noqa: E402

ensure_schema()
import random  # noqa: E402
WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec "
         "romeo sierra tango uniform victor whiskey xray yankee zulu").split()


def filler(seed):
    """Unrelated body text, different per article, so only the lead decides."""
    r = random.Random(seed)
    return " ".join(r.choice(WORDS) + str(r.randint(0, 999)) for _ in range(200))


def art(i, source, title, text, day, canon=None, sponsored=None):
    db.execute("""INSERT INTO articles (id, url, source, title, text, published, status, canonical_url, minhash, sponsored, tier)
                  VALUES (?, ?, ?, ?, ?, ?, 'ok', ?, ?, ?, 'B')""",
               [i, f"https://{source.lower().replace(' ', '')}.example/{i}", source, title, " ".join([text] * 6) + " " + filler(i),
                f"2026-10-{day:02d}T12:00:00Z", canon or f"https://{source.lower()}.example/{i}", minhash(text + filler(i)), sponsored])


def test_story_clustering():
    art("a1", "Talos", "Two critical RCEs in PHP core",
        "Two remote code execution flaws, CVE-2026-109618 and CVE-2026-109619, affect the PHP interpreter used by most web hosts.", 21)
    art("a2", "Unit42", "Threat Brief: Critical Vulnerabilities in PHP",
        "Unit 42 observed exploitation attempts against CVE-2026-109618 and CVE-2026-109619 in PHP deployments worldwide.", 29)
    art("b1", "NewsA", "Cyberattack hits French blood banks",
        "Hackers changed temperature settings on refrigeration systems at the Etablissement Francais du Sang blood banks in France.", 4)
    art("b2", "NewsB", "Supermarket fridges warmed in new wave of attacks across Europe",
        "Attackers remotely changed refrigeration controls at Colruyt and Coop supermarkets in Belgium and Sweden.", 4)
    art("c1", "NewsA", "Weekly Recap: PHP flaws, botnets and more",
        "This week CVE-2026-109618 and CVE-2026-109619 in PHP, a botnet takedown and more.", 28)
    art("d1", "NewsB", "Sponsored: Why your SOC needs our platform",
        "Sponsored by ExampleCorp. CVE-2026-109618 shows why PHP patching matters.", 22, sponsored="byline")
    art("e1", "DR", "Cyber Vulnerabilities Besiege Italy", "Italian organisations face a wave of attacks without a clear cause.", 15,
        canon="https://dr.example/cyber-vulnerabilities-besiege-italy")
    art("e2", "DR", "L'Italia e afflitta da vulnerabilita", "Le organizzazioni italiane affrontano un'ondata di attacchi.", 16,
        canon="https://dr.example/cyber-vulnerabilities-besiege-italy-italian")

    art("f1", "NewsA", "Police arrest Jordanian teen linked to ShinyHunters extortion",
        "Police in Amman arrested a 17-year-old Jordanian suspected of helping the ShinyHunters extortion group leak stolen data.", 10)
    art("f2", "NewsB", "Canadian executive charged over ShinyHunters extortion site",
        "Prosecutors in Toronto charged a Canadian negotiation-firm executive with running the ShinyHunters extortion site.", 11)
    art("g1", "NewsA", "Exposed to PHP2Shell? Experts weigh in",
        "Security experts explain how organisations exposed to PHP2Shell should prioritise patching their PHP servers.", 23)
    art("g2", "NewsC", "PHP2Shell: what to know about two critical PHP flaws",
        "PHP2Shell is the name given to two critical flaws in PHP that attackers began exploiting within days.", 26)

    fails = []


    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name + (f"  {detail}" if not cond else ""))
        if not cond:
            fails.append(name)


    def sid(i):
        return db.query("SELECT story_id FROM articles WHERE id = ?", [i])[0]["story_id"]


    stories.cluster_pending()
    check("shared CVE in the lead merges reports 8 days apart", sid("a1") == sid("a2"), (sid("a1"), sid("a2")))
    check("same-topic different incidents stay apart", sid("b1") != sid("b2"))
    check("same actor, different arrests in different countries stay apart", sid("f1") != sid("f2"))
    check("a shared vulnerability nickname merges reports", sid("g1") == sid("g2"), (sid("g1"), sid("g2")))
    check("round-up does not join the story", sid("c1") != sid("a1"))
    check("sponsored post has no story", sid("d1") is None)
    check("translation is a duplicate in the same story", sid("e1") == sid("e2") and
          db.query("SELECT dup_of FROM articles WHERE id='e2'")[0]["dup_of"] == "e1")
    st = db.query("SELECT source_count, article_count FROM stories WHERE id = ?", [sid("e1")])[0]
    check("duplicate counted once", st["source_count"] == 1 and st["article_count"] == 2, st)

    db.execute("UPDATE stories SET summary = 'LLM SUMMARY', summary_by = 'llm', summary_n = 2 WHERE id = ?", [sid("a1")])
    stories.recluster_all()
    row = db.query("SELECT summary, summary_by FROM stories WHERE id = ?", [sid("a1")])[0]
    check("LLM summary survives a recluster", row["summary"] == "LLM SUMMARY" and row["summary_by"] == "llm", row)

    print("ALL PASS" if not fails else f"{len(fails)} FAILED")
    assert not fails, f"{len(fails)} failed: {fails}"


if __name__ == "__main__":
    try:
        test_story_clustering()
    except AssertionError:
        sys.exit(1)

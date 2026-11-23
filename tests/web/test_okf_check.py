"""The OKF bundles pass tools/okf_check.py (frontmatter, index and log shape, links), as CI checks on every push.

    uv run --with pytest pytest tests/web/test_okf_check.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import okf_check  # noqa: E402


def test_the_bundles_are_clean(capsys):
    assert okf_check.main([]) == 0, capsys.readouterr().out


def test_the_checker_catches_what_it_should(tmp_path):
    b = tmp_path / "okf"
    (b / "a").mkdir(parents=True)
    (b / "index.md").write_text("---\nokf_version: \"0.2\"\n---\n\n* [A](/a/page.md) - x\n* [Gone](/a/gone.md) - y\n")
    (b / "a" / "index.md").write_text("---\ntype: Index\n---\n")
    (b / "a" / "page.md").write_text("---\ntitle: no type\n---\n")
    (b / "a" / "bare.md").write_text("no frontmatter\n")
    (b / "log.md").write_text("# Log\n\n## 2026-01-01\n\n* x\n\n## 2026-02-01\n\n* y\n\n## Later\n")
    errs = "\n".join(okf_check.check_bundle(b, public=True))
    for want in ("broken link /a/gone.md", "an index.md has no frontmatter", "frontmatter needs a non-empty type",
                 "a concept needs YAML frontmatter", "newest first", "'## YYYY-MM-DD'"):
        assert want in errs, (want, errs)

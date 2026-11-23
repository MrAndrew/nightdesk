#!/usr/bin/env python3
"""Check the OKF bundles (Open Knowledge Format v0.2) before a merge: run by CI on every pull request and push.

    python3 tools/okf_check.py                 # okf/, and private/okf/ when it is there
    python3 tools/okf_check.py --public        # also fail if private/ exists (the public repo's CI)

Checks, per bundle (standard library only):
* every concept (each .md except index.md and log.md) starts with YAML frontmatter with a non-empty `type`;
* `index.md` files have no frontmatter, except the bundle's root index, which may hold only `okf_version`;
* `log.md` has `## YYYY-MM-DD` headings, newest first;
* every link to a .md file resolves: `/x.md` from the bundle root, anything else from the page's own folder
  (anchors are not checked); the public bundle never links into `private/`.
Exit 0 when clean, 1 with one line per problem. Rules for contributors: CONTRIBUTING.md#documentation
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
DATE_H = re.compile(r"^## (\d{4}-\d{2}-\d{2})\s*$")


def frontmatter(text: str) -> dict | None:
    """The top-level keys of a leading `---` block (values as raw strings), or None when there is none."""
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    if end < 0:
        return {}
    out = {}
    for line in text[4:end].splitlines():
        m = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip("'\"")
    return out


def check_bundle(bundle: Path, public: bool) -> list[str]:
    errs: list[str] = []
    base = ROOT if bundle.resolve().is_relative_to(ROOT) else bundle.parent
    rel = lambda p: p.resolve().relative_to(base.resolve()).as_posix()  # noqa: E731
    for page in sorted(bundle.rglob("*.md")):
        text = page.read_text(encoding="utf-8", errors="replace")
        fm = frontmatter(text)
        if page.name == "index.md":
            if page.parent == bundle:
                if fm is not None and set(fm) - {"okf_version"}:
                    errs.append(f"{rel(page)}: the root index may only carry okf_version in its frontmatter")
            elif fm is not None:
                errs.append(f"{rel(page)}: an index.md has no frontmatter")
        elif page.name == "log.md":
            if fm is not None:
                errs.append(f"{rel(page)}: log.md has no frontmatter")
            dates = [m.group(1) for line in text.splitlines() if (m := DATE_H.match(line))]
            bad = [line for line in text.splitlines() if line.startswith("## ") and not DATE_H.match(line)]
            if bad:
                errs.append(f"{rel(page)}: log headings must be '## YYYY-MM-DD' (found {bad[0]!r})")
            if dates != sorted(dates, reverse=True):
                errs.append(f"{rel(page)}: log dates must be newest first")
        else:
            if fm is None:
                errs.append(f"{rel(page)}: a concept needs YAML frontmatter")
            elif not fm.get("type"):
                errs.append(f"{rel(page)}: frontmatter needs a non-empty type")
        body = re.sub(r"```.*?```", "", text, flags=re.S)
        for target in LINK.findall(body):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                continue
            path = target.split("#")[0]
            if not path.endswith(".md"):
                continue
            dest = (bundle / path.lstrip("/")) if path.startswith("/") else (page.parent / path)
            dest = dest.resolve()
            if public and (ROOT / "private") in dest.parents:
                errs.append(f"{rel(page)}: links into private/ ({target})")
            elif not dest.is_file():
                errs.append(f"{rel(page)}: broken link {target}")
    return errs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--public", action="store_true", help="the public repo: private/ must not exist")
    a = ap.parse_args(argv)
    errs = check_bundle(ROOT / "okf", public=True)
    priv = ROOT / "private"
    if a.public and priv.exists():
        errs.append("private/ is in the public repo: the export must remove it")
    if (priv / "okf").is_dir():
        errs += check_bundle(priv / "okf", public=False)
    for errline in errs:
        print(errline)
    print(f"okf check: {'clean' if not errs else f'{len(errs)} problems'}", file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main())

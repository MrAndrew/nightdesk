"""The generated source docs stay in step with their generator (tools/okf_sources.py): a full run into a temporary
folder writes every page byte-identical to the committed page, and never writes a hand-written source page. Edit the
generator's inputs (MEASURED notes, HAND_ENTRIES, the registry descriptions), never a generated page by hand.

    uv run --with pytest pytest tests/web/test_okf_generator.py -q
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEN = ROOT / "tools" / "okf_sources.py"


def _hand_written() -> set[str]:
    for node in ast.parse(GEN.read_text()).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "HAND_WRITTEN" for t in node.targets):
            return set(ast.literal_eval(node.value))
    raise AssertionError("HAND_WRITTEN not found in tools/okf_sources.py")


def test_generator_output_matches_the_committed_docs():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "okf"
        env = {k: v for k, v in os.environ.items() if not k.startswith("OSINTHUB_")}
        env.update(OSINTHUB_LAKE=str(Path(tmp) / "lake"), OSINTHUB_OFFLINE="1", AI_URL="http://127.0.0.1:9")
        r = subprocess.run([sys.executable, str(GEN), "--out", str(out)], cwd=ROOT, env=env, capture_output=True,
                           text=True, timeout=120)
        assert r.returncode == 0, r.stderr[-2000:]
        written = sorted(p.relative_to(out) for p in out.rglob("*.md"))
        assert len(written) > 30, written
        hand = _hand_written()
        assert hand >= {"epss", "cisa_advisories", "ris_live"}
        for sid in hand:
            assert not (out / "sources" / "current" / f"{sid}.md").exists(), f"the generator wrote hand-written {sid}.md"
        drift = [str(rel) for rel in written
                 if not (ROOT / "okf" / rel).exists() or (ROOT / "okf" / rel).read_bytes() != (out / rel).read_bytes()]
        assert not drift, f"generated pages differ from okf/ (edit the generator inputs, then regenerate): {drift}"
        assert f"wrote {len(list(out.rglob('*.md')))} files" in r.stdout, r.stdout

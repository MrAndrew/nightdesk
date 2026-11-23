"""A small slice of the MISP Malpedia galaxy (same shape as <lake>/ref/misp-malpedia.json) for the abuse.ch tests,
so family resolution works without the lake's reference data."""
from __future__ import annotations

import json
from pathlib import Path

FAMILIES = [("Dridex", "win.dridex", []), ("QakBot", "win.qakbot", ["Qbot", "Quakbot"]), ("Mozi", "elf.mozi", []),
            ("PureLogs Stealer", "win.purelogs", []), ("Cobalt Strike", "win.cobalt_strike", ["CobaltStrike", "BEACON"]),
            ("Agent Tesla", "win.agent_tesla", ["AgentTesla"]), ("Vidar", "win.vidar", [])]


def install(lake: str) -> None:
    from osinthub.entities import refdata
    ref = Path(lake) / "test-ref"
    ref.mkdir(exist_ok=True)
    (ref / "misp-malpedia.json").write_text(json.dumps({"values": [
        {"value": v, "uuid": f"u-{i}", "description": "",
         "meta": {"refs": [f"https://malpedia.caad.fkie.fraunhofer.de/details/{m}"], "synonyms": syn}}
        for i, (v, m, syn) in enumerate(FAMILIES)]}))
    refdata.REF = ref
    refdata._CAT = None
    try:
        from osinthub.sources import abusech
        abusech.known_family.cache_clear()
    except Exception:
        pass

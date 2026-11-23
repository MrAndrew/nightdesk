# Netlog manual eval scripts

Standalone httpx CLIs for the network-log pipeline, run by hand against a **running server and its scratch
lake**. The app does not import them. They were moved here out of `osinthub/netlog/` so the package ships no
dev tooling. All of them use documentation addresses (`192.0.2.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and
invented MACs; `selftest.py` writes a Feodo record delta into the lake, so never point these at a real lake.

| Script | What it checks | Run |
|---|---|---|
| `selftest.py` | End-to-end smoke: Zeek formats, file and row dedup, type detection, rules, re-hunt, devices (L2/DHCP/EUI-64), status persistence, search, stats and the inbox. | `uv run python tests/eval/netlog/selftest.py --base http://127.0.0.1:<port> --lake <scratch lake>` |
| `benign_check.py` | False positives: a day of ordinary home traffic to well-known sites (`osinthub/netlog/fixtures/popular-sites.json`, a hand-made list on documentation addresses, so it runs offline; it tests the rules and the allowlist, not real addresses against the lists). Pass: 0 high or medium alerts; low alerts are listed with their rule and indicator. `--seed-reports <lake>` (server stopped) adds two invented single-source reports first. | `uv run python tests/eval/netlog/benign_check.py --base http://127.0.0.1:<port>` |
| `regress_two_seeds.py` | Two planted sets (different seeds) imported into one lake: every planted positive uid of both sets is in a high or medium alert, merged alerts union their uids, and evidence counts agree. Uses `../zeek_planted.py --out-dir` for the files. | `uv run python tests/eval/netlog/regress_two_seeds.py --base http://127.0.0.1:<port> --seeds 1 2` |

The planted-traffic scorer itself is `tests/eval/zeek_planted.py` (see [the eval README](../README.md)).

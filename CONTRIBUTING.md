# Contributing to Night Desk

Thanks for helping. Night Desk is in **pre-alpha**: the most useful contributions right now are bug reports,
feedback and feed or log-format requests, through the [issue forms](.github/ISSUE_TEMPLATE). Keep your own network
out of anything you post: use **Settings › About › Copy diagnostics** and `nightdesk-redact` for log samples.

Security problems go privately, as [SECURITY.md](SECURITY.md) explains, never in a public issue.

## Code contributions

Night Desk is under the PolyForm Noncommercial licence for the pre-alpha and is meant to move to Apache-2.0 later.
That move is only simple while the maintainer holds every right, so **a code pull request from outside needs a short
contributor agreement first** (it lets the maintainer relicense your contribution). Open an issue before you start on
anything large, so we can agree on the approach and the agreement before you spend the time.

## What a pull request includes

1. **The change and its tests.** New behaviour gets a test in `tests/`; a fixed bug gets the test that would have
   caught it.
2. **The documentation.** `okf/` is the project's knowledge bundle, in the
   [Open Knowledge Format](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md) v0.2.
   It describes how Night Desk works and what was decided, and it ships with every release. Update the page for what
   you change; start from [`okf/start-here.md`](okf/start-here.md) and [`okf/index.md`](okf/index.md).
3. **Say when the change is a decision** (a new behaviour, a changed default, something dropped): one line in the
   pull request's description. The maintainers keep the decision log; user-facing changes go in the changelog of
   each release.
4. **No real network data and no secrets.** Tests, fixtures and docs use documentation addresses (`192.0.2.0/24`,
   `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), the demo home (`10.86.24.0/24`) or invented values. The
   release scan fails otherwise.

The full rules (offline means zero egress, feed terms, no new dependencies, plain-language UI, 390 px phone width)
are in [start here](okf/start-here.md#hard-rules).

## Documentation

* Every page except `index.md` starts with YAML frontmatter with a non-empty `type`; also give it a
  `title` and a one-sentence `description`.
* `index.md` files list their pages as `* [Title](path) - description` and carry no frontmatter (the root index may
  hold `okf_version`).
* Link pages with bundle-absolute paths (`/architecture/api.md`); a link to a page that does not exist fails CI.

## What CI checks

Every pull request and push runs [`.github/workflows/ci.yml`](.github/workflows/ci.yml):

| Check | Run it yourself | What it means |
|---|---|---|
| OKF bundles | `python3 tools/okf_check.py` | The documentation rules above. |
| Release scan | `python3 tools/release_scan.py` | No home folder, user name, LAN host or drive name, real address, MAC, key or token in any tracked file. |
| Lint | `uvx ruff check osinthub tests tools` | Faults only (unused names, loop closures and the like); there is no formatter, so keep the surrounding style. |
| Unit and API tests | `uv run --with pytest pytest -q -p no:cacheprovider tests --ignore=tests/soak --ignore=tests/eval` | About 20 s. |
| Browser journeys | `uv run --with playwright --with pytest pytest -q -p no:cacheprovider tests/e2e` | About 2 minutes; needs `uv run --with playwright playwright install chromium` once. |

Locally, `tools/gate.sh <port> <label>` runs the tests and journeys plus a smoke walk of every page.

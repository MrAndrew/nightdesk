#!/bin/zsh
# scratch-server.sh NAME PORT SECONDS : a throwaway Night Desk from this checkout, in the foreground.
# Offline, AI helper and Qdrant pointed at nothing, DuckDB vectors, its own lake ${ND_LAKES:-$TMPDIR/nd-lakes}/NAME
# (recreated; seeded with the synthetic news fixture, or a clone of ND_LAKE_BASE=/path/to/lake), and a hard time limit
# (~/.claude/bin/ttl when present). Never port 8787. Details: tests/e2e/server.py, okf/architecture/testing.md
# Start it in the background, note its PID, and stop it with `kill PID` (the whole process group goes).
set -e
NAME=$1; PORT=$2; SECS=${3:-7200}
[ -n "$NAME" ] && [ -n "$PORT" ] || { echo "usage: scratch-server.sh NAME PORT [SECONDS]"; exit 2; }
[ "$PORT" = "8787" ] && { echo "refusing port 8787 (the live app)"; exit 1; }
ROOT=${0:A:h:h}
LAKES=${ND_LAKES:-${TMPDIR:-/tmp}/nd-lakes}
cd $ROOT
FROM=(); [ -n "$ND_LAKE_BASE" ] && FROM=(--from "$ND_LAKE_BASE")  # two words: zsh does not split ${..:+a b}
exec uv run --quiet python tests/e2e/server.py --port $PORT --lake $LAKES/$NAME --ttl $SECS "${FROM[@]}"

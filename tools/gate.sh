#!/bin/zsh
# gate.sh PORT LABEL [WORKTREE] : the merge gate for a checkout (default: this one). The older argument order
# gate.sh WORKTREE PORT LABEL also works.
#   1. the unit/integration suite (pytest tests, without soak/eval; tests/e2e is skipped there)
#   2. the E2E journeys (tests/e2e: their own scratch server on a free port in ND_E2E_PORTS)
#   3. smoke.py and deeplinks.py (side by side) against a scratch server on PORT with the demo loaded; the server
#      boots in the background while 1 and 2 run
# Output (logs, screenshots) in ${ND_GATE_OUT:-$TMPDIR/nd-gates}/LABEL. Prints "pytest exit N", "E2E exit N",
# "SMOKE PASS|FAIL" and "RESULT PASS|FAIL" (deeplinks); stops its server and checks the port is free.
if [ -d "$1" ]; then WT=$1; PORT=$2; LABEL=$3; else PORT=$1; LABEL=$2; WT=${3:-${0:A:h:h}}; fi
[ -n "$PORT" ] && [ -n "$LABEL" ] || { echo "usage: gate.sh PORT LABEL [WORKTREE]"; exit 2; }
[ "$PORT" = "8787" ] && { echo "refusing port 8787 (the live app)"; exit 2; }
OUT=${ND_GATE_OUT:-${TMPDIR:-/tmp}/nd-gates}/$LABEL; rm -rf $OUT; mkdir -p $OUT
LAKES=$OUT/lakes
cd $WT || exit 2
# the scratch server for smoke/deeplinks boots while the suites run
ND_LAKES=$LAKES $WT/tools/scratch-server.sh gate-$LABEL $PORT 1800 > $OUT/server.log 2>&1 &
SPID=$!
echo "== pytest"; uv run --quiet --with pytest pytest -q -p no:cacheprovider tests --ignore=tests/soak --ignore=tests/eval > $OUT/pytest.txt 2>&1; PT=$?; tail -3 $OUT/pytest.txt
echo "== e2e"; ND_E2E_ARTIFACTS=$OUT/e2e ND_E2E_TMP=$OUT uv run --quiet --with playwright --with pytest pytest -q -p no:cacheprovider tests/e2e > $OUT/e2e.txt 2>&1; ET=$?; tail -3 $OUT/e2e.txt
echo "== server"
for i in {1..90}; do curl -sf http://127.0.0.1:$PORT/api/health >/dev/null && break; sleep 1; done
curl -s -o /dev/null -w "health %{http_code}\n" http://127.0.0.1:$PORT/api/health
curl -s -X POST -H "Origin: http://127.0.0.1:$PORT" http://127.0.0.1:$PORT/api/netlog/demo -o $OUT/demo.json -w "demo %{http_code}\n"
# smoke and deeplinks are independent read-mostly walks: run them side by side
ND_ALLOW_WRITES=1 ND_BASE=http://127.0.0.1:$PORT uv run --quiet --with playwright python tests/e2e/smoke.py $OUT/smoke > $OUT/smoke.txt 2>&1 &
SMP=$!
ND_ALLOW_WRITES=1 ND_BASE=http://127.0.0.1:$PORT uv run --quiet --with playwright python tests/e2e/deeplinks.py > $OUT/deeplinks.txt 2>&1 &
DLP=$!
wait $SMP $DLP
tail -3 $OUT/smoke.txt
grep -m1 "RESULT" $OUT/deeplinks.txt || tail -2 $OUT/deeplinks.txt
kill $SPID 2>/dev/null
for i in {1..30}; do lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null || break; sleep 0.5; done
lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null && echo "WARN port $PORT still listening (server pid $SPID)" || echo "port $PORT free"
grep -q "Traceback" $OUT/server.log && echo "server log has tracebacks: $(grep -c Traceback $OUT/server.log)"
rm -rf $LAKES
echo "pytest exit $PT"
echo "E2E exit $ET"

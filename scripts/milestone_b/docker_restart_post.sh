#!/usr/bin/env bash
# Docker restart recovery, part 2 of 2: run after restarting Docker Desktop.
# Checks that the daemon really restarted, that recovery failed the in-flight scan safely and
# removed its holder, fetcher, tmpfs staging volume and workspace, and that new scans work.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
STATE="$STATE_DIR/restart-state.json"
[ -f "$STATE" ] || { echo "NOT RUN: run docker_restart_pre.sh first" >&2; exit 3; }
read -r scan holder volume before < <(python3 -c 'import json,sys; d=json.load(open(sys.argv[1]));
print(d["scan_id"], d["holder"], d["volume"], d["runner_started_at"])' "$STATE")

for _ in $(seq 1 150); do docker info >/dev/null 2>&1 && break; sleep 2; done
docker info >/dev/null 2>&1 || { echo "Docker is not running" >&2; exit 3; }
RUNNER="${PROJECT}-scan-runner-1"
after=$(docker inspect -f '{{.State.StartedAt}}' "$RUNNER" 2>/dev/null || echo "gone")
paused=$(docker inspect -f '{{.State.Paused}}' "$RUNNER" 2>/dev/null || echo "gone")
if [ "$after" = "$before" ] && [ "$paused" = "true" ]; then
  echo "FAIL: the runner is still the paused container from before: Docker was not restarted" >&2
  exit 1
fi
echo "PASS Docker restarted (runner StartedAt $before -> $after)"

# Postgres, the API and the chain have no restart policy: bring the stack back. The chain is
# in-memory, so up.sh redeploys the contract (old anchors are gone, as documented).
"$(dirname "${BASH_SOURCE[0]}")/up.sh" >/dev/null
. "$STATE_DIR/chain.env"

fail=0
status=""; code=""
for _ in $(seq 1 120); do
  read -r status code < <(curl -fsS "$API/scans/$scan" | python3 -c 'import json,sys
d=json.load(sys.stdin); print(d["status"], (d.get("error") or {}).get("code", "-"))')
  [ "$status" = "failed" ] && break
  sleep 5
done
if [ "$status" = "failed" ] && [ "$code" = "runner_interrupted" ]; then
  echo "PASS in-flight scan $scan failed safely ($code)"
else
  echo "FAIL in-flight scan $scan: status=$status code=$code"; fail=1
fi
# Orphans are removed by the runner's reconcile pass (every RUNNER_RECONCILE_SECONDS).
for _ in $(seq 1 24); do
  left=$(docker ps -aq --filter "label=io.provenancex.scan-id=$scan")
  vol=$(docker volume ls -q --filter "name=^$volume\$")
  [ -z "$left" ] && [ -z "$vol" ] && break
  sleep 5
done
[ -z "$left" ] && echo "PASS holder and fetcher containers removed" || { echo "FAIL containers left: $left"; fail=1; }
[ -z "$vol" ] && echo "PASS tmpfs staging volume removed" || { echo "FAIL staging volume left: $vol"; fail=1; }
if docker exec "$RUNNER" test -e "/app/workspace/$scan"; then
  echo "FAIL workspace of $scan still exists"; fail=1
else
  echo "PASS workspace removed"
fi

echo "Running fresh end-to-end scans after the restart"
API="$API" PROJECT="$PROJECT" STATE_DIR="$STATE_DIR" \
  "$REPO/backend/.venv/bin/python" "$REPO/scripts/milestone_b/verify_e2e.py" || fail=1
[ "$fail" -eq 0 ] && echo "DOCKER RESTART RECOVERY: PASSED" || echo "DOCKER RESTART RECOVERY: FAILED"
exit "$fail"

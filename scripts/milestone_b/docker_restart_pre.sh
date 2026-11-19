#!/usr/bin/env bash
# Docker restart recovery, part 1 of 2 (needs a manual Docker Desktop restart in between).
#
# Leaves a real scan in flight: a Hugging Face scan is submitted, and as soon as its fetcher is
# running the scan-runner is frozen (docker pause), so the scan stays RUNNING with its staging
# holder, fetcher container and tmpfs staging volume alive. Then restart Docker Desktop from
# Windows and run docker_restart_post.sh. Requires the stack from up.sh.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
command -v curl >/dev/null || { echo "NOT RUN: curl is missing" >&2; exit 3; }
curl -fsS "$API/health/ready" >/dev/null || { echo "NOT RUN: start the stack: up.sh" >&2; exit 3; }

RUNNER="${PROJECT}-scan-runner-1"
scan=$(curl -fsS -X POST "$API/scans/model" \
  --data-urlencode "source_url=https://huggingface.co/sshleifer/tiny-gpt2" \
  --data-urlencode "revision=5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])')
echo "Submitted scan $scan"
for _ in $(seq 1 300); do
  if [ "$(docker inspect -f '{{.State.Running}}' "px-fetch-$scan" 2>/dev/null)" = "true" ]; then
    break
  fi
  sleep 0.2
done
[ "$(docker inspect -f '{{.State.Running}}' "px-fetch-$scan" 2>/dev/null)" = "true" ] || {
  echo "The fetcher never started; inspect: docker logs $RUNNER" >&2; exit 1; }
docker pause "$RUNNER" >/dev/null
echo "Runner paused while scan $scan was downloading"

status=$(curl -fsS "$API/scans/$scan" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
holder="px-ana-$scan-hold"; volume="px-stg-$scan"
[ "$status" = "running" ] || { echo "Expected a RUNNING scan, got $status" >&2; exit 1; }
[ "$(docker inspect -f '{{.State.Running}}' "$holder")" = "true" ] || { echo "No holder" >&2; exit 1; }
docker volume inspect "$volume" >/dev/null || { echo "No staging volume" >&2; exit 1; }
started=$(docker inspect -f '{{.State.StartedAt}}' "$RUNNER")
python3 - "$STATE_DIR/restart-state.json" "$scan" "$holder" "$volume" "$started" <<'PY'
import json, sys
path, scan, holder, volume, started = sys.argv[1:6]
json.dump({"scan_id": scan, "holder": holder, "volume": volume,
           "runner_started_at": started}, open(path, "w"), indent=2)
PY
cat <<MSG

PRE-RESTART STATE RECORDED ($STATE_DIR/restart-state.json)
  scan $scan: RUNNING, holder $holder running, staging volume $volume present, runner paused.

Now restart Docker Desktop from Windows (tray icon -> Restart, or Troubleshoot -> Restart).
When Docker is running again, run:  scripts/milestone_b/docker_restart_post.sh
MSG

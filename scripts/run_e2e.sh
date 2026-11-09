#!/usr/bin/env bash
# Run the end-to-end test on a disposable Postgres and Hardhat chain. Local only.
#
# Exit codes: 0 passed, 1 failed, 3 NOT RUN (a prerequisite or OSV was unavailable).
# The Hardhat test key is read from the chain's logs into a shell variable. It is never printed
# or written to a file. These keys are public, and this chain is erased when the script ends.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

PROJECT="provenancex-e2e"
DB_PORT=15434
CHAIN_PORT=18545
NOT_RUN=3

not_run() {
  echo "E2E NOT RUN: $1" >&2
  exit "$NOT_RUN"
}

for tool in docker syft curl; do
  command -v "$tool" >/dev/null || not_run "$tool is not installed"
done
[ -x backend/.venv/bin/pytest ] || not_run "backend/.venv is missing"
docker info >/dev/null 2>&1 || not_run "Docker is not running"

for port in "$DB_PORT" "$CHAIN_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    not_run "port $port is in use"
  fi
done

osv_status=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' \
  -d '{"package":{"name":"idna","ecosystem":"PyPI"},"version":"3.10"}' \
  https://api.osv.dev/v1/query) || not_run "OSV could not be reached"
[ "$osv_status" = "200" ] || not_run "OSV returned HTTP $osv_status"

# Shell values override the git-ignored .env, for this script only.
export POSTGRES_USER=provenancex POSTGRES_PASSWORD=provenancex-e2e POSTGRES_DB=provenancex
export POSTGRES_HOST_PORT="$DB_PORT" BLOCKCHAIN_HOST_PORT="$CHAIN_PORT"

compose() {
  docker compose -p "$PROJECT" --project-directory "$REPO" -f "$REPO/docker-compose.yml" "$@"
}

report_dir=$(mktemp -d)
cleanup() {
  if ! compose --profile chain-deploy down -v --remove-orphans >/dev/null 2>&1; then
    echo "Warning: could not remove the disposable project $PROJECT" >&2
  fi
  rm -rf "$report_dir"
}
trap cleanup EXIT

echo "Starting the disposable database and chain"
compose up --build --wait --wait-timeout 300 postgres hardhat

HARDHAT_KEY=$(compose logs --no-log-prefix hardhat | awk '/Private Key:/ && !k { k = $3 } END { print k }')
[[ "$HARDHAT_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]] || {
  echo "Could not read a test key from the chain logs" >&2
  exit 1
}
export BLOCKCHAIN_PRIVATE_KEY="$HARDHAT_KEY"

deployed=$(compose --profile chain-deploy run --rm -T hardhat-deploy)
contract=$(sed -n 's/.*"contract_address":"\(0x[0-9a-fA-F]\{40\}\)".*/\1/p' <<<"$deployed")
[ -n "$contract" ] || {
  echo "The contract was not deployed" >&2
  exit 1
}

export DATABASE_URL="postgresql+psycopg://provenancex:provenancex-e2e@127.0.0.1:$DB_PORT/provenancex"
export BLOCKCHAIN_PROVIDER=web3 BLOCKCHAIN_RPC_URL="http://127.0.0.1:$CHAIN_PORT"
export BLOCKCHAIN_CONTRACT_ADDRESS="$contract" BLOCKCHAIN_ANCHOR_ON_SCAN=false
export SBOM_PROVIDER=syft VULN_PROVIDER=osv NVD_ENABLED=false SANDBOX_PROVIDER=disabled
export MODEL_PATH=../ml/models
export PROVENANCEX_CHAIN_TESTS=1 PROVENANCEX_NETWORK_TESTS=1
export PROVENANCEX_E2E_REPORT="$report_dir/report.jsonl"

cd backend
.venv/bin/alembic upgrade head

echo "Running the end-to-end test. This takes a few minutes."
set +e
output=$(.venv/bin/pytest -q -rs -p no:cacheprovider tests/e2e 2>&1)
status=$?
set -e
printf '%s\n' "$output"

if [ -s "$PROVENANCEX_E2E_REPORT" ]; then
  echo "Observed results (wiring checks on benign fixtures, not detection results):"
  cat "$PROVENANCEX_E2E_REPORT"
fi

if [ "$status" -eq 0 ] && grep -qE '[0-9]+ skipped' <<<"$output"; then
  not_run "a test was skipped, so the run is not a pass"
fi
exit "$status"

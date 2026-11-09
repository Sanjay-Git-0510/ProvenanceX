#!/usr/bin/env bash
# One-command demo: a separate Compose project beside any development stack.
#
# Exit codes: 0 demo running, 1 failed, 3 DEMO NOT RUN (a prerequisite was unavailable).
# Remove it with: make demo-down
# The Hardhat test key is read from the chain's logs into a shell variable. This script never
# prints it or writes it to a file. It is a public test key, and the chain is erased with the demo.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

PROJECT="provenancex-demo"
UI_PORT=15173
API_PORT=18080
DB_PORT=15435
CHAIN_PORT=18546
NOT_RUN=3

not_run() {
  echo "DEMO NOT RUN: $1" >&2
  exit "$NOT_RUN"
}

for tool in docker curl python3; do
  command -v "$tool" >/dev/null || not_run "$tool is not installed"
done
docker info >/dev/null 2>&1 || not_run "Docker is not running"

for port in "$UI_PORT" "$API_PORT" "$DB_PORT" "$CHAIN_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    not_run "port $port is in use. If an earlier demo is running, use: make demo-down"
  fi
done

osv_status=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' \
  -d '{"package":{"name":"idna","ecosystem":"PyPI"},"version":"3.10"}' \
  https://api.osv.dev/v1/query) || not_run "OSV could not be reached. The demo needs internet access"
[ "$osv_status" = "200" ] || not_run "OSV returned HTTP $osv_status"

# Shell values override the git-ignored .env, for this script only.
export POSTGRES_USER=provenancex POSTGRES_PASSWORD=provenancex-demo POSTGRES_DB=provenancex
export BLOCKCHAIN_PROVIDER=web3 BLOCKCHAIN_ANCHOR_ON_SCAN=true
export SBOM_PROVIDER=syft VULN_PROVIDER=osv NVD_ENABLED=false HF_PROVIDER=hf
export SANDBOX_PROVIDER=disabled

compose() {
  docker compose -p "$PROJECT" --project-directory "$REPO" \
    -f "$REPO/docker-compose.yml" -f "$REPO/docker-compose.demo.yml" "$@"
}

started=0
cleanup() {
  if [ "$started" -ne 1 ] && ! compose --profile chain-deploy down -v --remove-orphans >/dev/null 2>&1; then
    echo "Warning: could not remove the project $PROJECT. Try: make demo-down" >&2
  fi
}
trap cleanup EXIT

echo "Starting the demo database and chain"
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
export BLOCKCHAIN_CONTRACT_ADDRESS="$contract"

echo "Building and starting the API and the UI"
compose up --build --wait --wait-timeout 600 api frontend

echo "Seeding the demo with benign fixtures"
python3 "$REPO/scripts/seed_demo.py" --api-url "http://127.0.0.1:$API_PORT/api/v1"

started=1
echo
echo "Demo running. UI: http://localhost:$UI_PORT  API: http://localhost:$API_PORT/api/v1"
echo "Remove it with: make demo-down"

#!/usr/bin/env bash
# Build the sandbox images and start the Milestone B verification stack (project "pxmb").
# Exit 3: NOT RUN (Docker unavailable). Remove it with scripts/milestone_b/down.sh.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
docker info >/dev/null 2>&1 || { echo "NOT RUN: Docker is not running" >&2; exit 3; }

compose --profile analyzer-image build analyzer-image
compose --profile fetcher-image build fetcher-image
compose up --build --wait --wait-timeout 300 postgres hardhat

KEY=$(compose logs --no-log-prefix hardhat | awk '/Private Key:/ && !k { k = $3 } END { print k }')
[[ "$KEY" =~ ^0x[0-9a-fA-F]{64}$ ]] || { echo "No Hardhat test key in the chain logs" >&2; exit 1; }
export BLOCKCHAIN_PRIVATE_KEY="$KEY"
deployed=$(compose --profile chain-deploy run --rm -T hardhat-deploy)
contract=$(sed -n 's/.*"contract_address":"\(0x[0-9a-fA-F]\{40\}\)".*/\1/p' <<<"$deployed")
[ -n "$contract" ] || { echo "The contract was not deployed" >&2; exit 1; }
export BLOCKCHAIN_CONTRACT_ADDRESS="$contract"
# Local Hardhat test key only (public, erased with the chain); kept outside the repository.
umask 077
printf 'export BLOCKCHAIN_PRIVATE_KEY=%s\nexport BLOCKCHAIN_CONTRACT_ADDRESS=%s\n' \
  "$KEY" "$contract" >"$STATE_DIR/chain.env"

compose up --build --wait --wait-timeout 600 egress-proxy api scan-runner
echo "Stack $PROJECT is up: API $API"

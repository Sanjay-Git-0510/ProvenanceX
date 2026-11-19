#!/usr/bin/env bash
# Remove the Milestone B verification stack, its volumes and networks (only project "pxmb").
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
compose --profile chain-deploy down -v --remove-orphans
for v in $(docker volume ls -q --filter "label=io.provenancex.instance=$PROJECT"); do
  docker volume rm -f "$v"
done
rm -f "$STATE_DIR/chain.env" "$STATE_DIR/restart-state.json"

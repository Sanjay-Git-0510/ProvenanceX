# Shared settings for the Milestone B verification stack: a separate Compose project with its own
# ports, volumes and networks, beside (never instead of) a development stack. Source it.
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export PROJECT="${PXMB_PROJECT:-pxmb}"
export API_PORT="${PXMB_API_PORT:-18180}"
export API="http://127.0.0.1:${API_PORT}/api/v1"
export STATE_DIR="${PXMB_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/provenancex-milestone-b}"
mkdir -p "$STATE_DIR"

export POSTGRES_USER=provenancex POSTGRES_PASSWORD=provenancex-mb POSTGRES_DB=provenancex
export POSTGRES_HOST_PORT="${PXMB_DB_PORT:-15535}" BLOCKCHAIN_HOST_PORT="${PXMB_CHAIN_PORT:-18646}"
export API_HOST_PORT="$API_PORT" FRONTEND_HOST_PORT="${PXMB_UI_PORT:-15273}"
export ANALYZER_WORKSPACE_VOLUME="${PROJECT}_workspace" ANALYZER_INSTANCE="${PROJECT}"
export FETCHER_NETWORK="${PROJECT}_fetch" EGRESS_NETWORK="${PROJECT}_egress"
export SBOM_PROVIDER=syft VULN_PROVIDER=osv NVD_ENABLED=false HF_PROVIDER=hf
export SANDBOX_PROVIDER=disabled
export BLOCKCHAIN_PROVIDER=web3 BLOCKCHAIN_ANCHOR_ON_SCAN=true
DOCKER_SOCKET_GID="${DOCKER_SOCKET_GID:-$(stat -c %g /var/run/docker.sock 2>/dev/null || echo 0)}"
export DOCKER_SOCKET_GID

compose() {
  docker compose -p "$PROJECT" --project-directory "$REPO" -f "$REPO/docker-compose.yml" "$@"
}

# The chain key and contract are read back from the state directory after `up.sh`.
if [ -f "$STATE_DIR/chain.env" ]; then
  # shellcheck disable=SC1091
  . "$STATE_DIR/chain.env"
fi

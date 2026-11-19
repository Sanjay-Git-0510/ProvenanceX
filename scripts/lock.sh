#!/usr/bin/env bash
# Regenerate the hash-locked requirement files (audit finding M6) inside the same digest-pinned
# Python 3.12 base the images use, so markers and wheels match the containers.
#   make lock
# Inputs (edit these):   backend/requirements*.txt
# Outputs (generated):   backend/requirements.lock, requirements-ml.lock,
#                        requirements-analyzer.lock, requirements-fetcher.lock
# Every image installs the .lock files with `pip install --require-hashes`.
# Existing pins are kept unless an input changes (pip-compile without --upgrade). To seed or
# hold pins, pass a pip constraints file: LOCK_CONSTRAINTS=path/to/constraints.txt make lock
set -euo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE="python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0"
PIP_TOOLS="pip-tools==7.7.0"
EXTRA=""
if [ -n "${LOCK_CONSTRAINTS:-}" ]; then
  cp "$LOCK_CONSTRAINTS" "$REPO/backend/.lock-constraints.txt"
  EXTRA="--constraint .lock-constraints.txt"
  trap 'rm -f "$REPO/backend/.lock-constraints.txt"' EXIT
fi
docker run --rm -v "$REPO/backend:/src" -w /src "$BASE" sh -euc "
  pip install -q --root-user-action=ignore '$PIP_TOOLS'
  compile() { pip-compile -q --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url \
    --no-header --annotation-style=line \"\$@\"; }
  compile $EXTRA -o requirements.lock requirements.txt
  compile $EXTRA --constraint requirements.lock -o requirements-ml.lock requirements-ml.txt
  compile -o requirements-analyzer.lock requirements-analyzer.txt
  compile -o requirements-fetcher.lock requirements-fetcher.txt
  chown $(id -u):$(id -g) requirements*.lock
"
echo "Lock files written to backend/requirements*.lock"

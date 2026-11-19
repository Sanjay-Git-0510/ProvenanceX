# ProvenanceX analyzer sandbox: every step that reads untrusted artifact content runs here.
#
# Build (from the repo root):
#   docker build -f docker/analyzer/Dockerfile -t provenancex-analyzer:0.1.0 backend
# or:  docker compose --profile analyzer-image build analyzer-image
#
# The image holds no secrets and no database, HTTP or chain clients. Runtime restrictions
# (no network, read-only root, non-root user, cap-drop ALL, no-new-privileges, memory/CPU/pids
# limits, noexec tmpfs) are applied by backend/app/analysis/hardening.py at `docker create` time
# and verified with `docker inspect` before the container starts.

# --- Stage 1: fetch Syft (curl never reaches the final image) ---------------------------------
FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0 AS syft
# The version and the per-arch SHA-256 are pinned (same values as backend/Dockerfile).
ARG SYFT_VERSION=1.57.0
ARG SYFT_SHA256_AMD64=9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704
ARG SYFT_SHA256_ARM64=410cbfa0ae0f63246bc0057843760b1de2833cd23919e025e368fd7681308cdb
ARG TARGETARCH=amd64
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sha="${SYFT_SHA256_AMD64}" ;; \
      arm64) sha="${SYFT_SHA256_ARM64}" ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    tarball="syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    curl -sSfL -o "/tmp/${tarball}" \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${tarball}"; \
    echo "${sha}  /tmp/${tarball}" | sha256sum -c -; \
    tar -xzf "/tmp/${tarball}" -C /usr/local/bin syft

# --- Stage 2: the analyzer -------------------------------------------------------------------
FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    TMPDIR=/tmp \
    PX_ANALYZER_WORKER=1

COPY --from=syft /usr/local/bin/syft /usr/local/bin/syft
# Hash-locked (audit finding M6): an unlisted or altered wheel fails the build.
COPY requirements-analyzer.lock /opt/px/requirements-analyzer.lock
RUN pip install --require-hashes --no-deps -r /opt/px/requirements-analyzer.lock \
    && syft version >/dev/null

# Application code only (no tests, no .env). Read-only for everyone.
COPY app /opt/px/app
RUN chmod -R a-w,a+rX /opt/px \
    && cd /opt/px && python -B -c "import app.sandbox_worker.__main__, app.sandbox_worker.collect"

# I1: strip setuid/setgid bits (su, mount, passwd, ...); nothing here ever needs them.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
    && ! find / -xdev -perm /6000 -type f | grep -q .

# The real uid comes from `docker create --user` and is never 0.
USER 65534:65534
WORKDIR /opt/px
ENTRYPOINT ["python", "-B", "-m", "app.sandbox_worker"]

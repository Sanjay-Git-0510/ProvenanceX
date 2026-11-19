FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# No git: the API and the scan-runner never clone or download artifacts. Downloads run only in
# the isolated fetcher image (docker/fetcher, Milestone B, audit finding H1).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Syft (SBOM generation, app/scanners/sbom/syft.py). The version and the per-arch SHA-256
# are pinned. Values come from the release's syft_<ver>_checksums.txt; update both together.
ARG SYFT_VERSION=1.57.0
ARG SYFT_SHA256_AMD64=9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704
ARG SYFT_SHA256_ARM64=410cbfa0ae0f63246bc0057843760b1de2833cd23919e025e368fd7681308cdb
ARG TARGETARCH=amd64
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
    tar -xzf "/tmp/${tarball}" -C /usr/local/bin syft; \
    rm "/tmp/${tarball}"; \
    syft version

RUN groupadd --system app && useradd --system --gid app --home /app app

# requirements-ml.txt holds the exact versions the saved models were built with.
COPY requirements.txt requirements-ml.txt ./
RUN pip install -r requirements.txt -r requirements-ml.txt

COPY . .
RUN mkdir -p /app/workspace && chown -R app:app /app

# --- scan-runner: the API image plus a pinned Docker CLI. It is the only service that gets the
# Docker socket (see docker-compose.yml). It has no HTTP port and never reads artifact content
# itself: it launches the analyzer sandbox (docker/analyzer) for every content-reading step.
# The CLI SHA-256 values were computed from download.docker.com on 2026-11-18 (Docker does not
# publish checksums for the static tarballs); update version and hashes together.
FROM base AS runner
ARG DOCKER_CLI_VERSION=27.5.1
ARG DOCKER_CLI_SHA256_AMD64=4f798b3ee1e0140eab5bf30b0edc4e84f4cdb53255a429dc3bbae9524845d640
ARG DOCKER_CLI_SHA256_ARM64=e6b53725a73763ab3f988c73f8772eaed429754c1a579db5ff11f21990fd1817
ARG TARGETARCH=amd64
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) arch=x86_64; sha="${DOCKER_CLI_SHA256_AMD64}" ;; \
      arm64) arch=aarch64; sha="${DOCKER_CLI_SHA256_ARM64}" ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -sSfL -o /tmp/docker.tgz \
      "https://download.docker.com/linux/static/stable/${arch}/docker-${DOCKER_CLI_VERSION}.tgz"; \
    echo "${sha}  /tmp/docker.tgz" | sha256sum -c -; \
    tar -xzf /tmp/docker.tgz -C /tmp docker/docker; \
    install -m 0755 /tmp/docker/docker /usr/local/bin/docker; \
    rm -rf /tmp/docker.tgz /tmp/docker
USER app
CMD ["python", "-m", "app.runner"]

# --- api (default target): no Docker CLI, no socket. It only queues scans.
FROM base AS api
USER app

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# git is required for hardened shallow clones of GitHub sources (app/scanners/git_fetch.py).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates \
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

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN mkdir -p /app/workspace && chown -R app:app /app
USER app

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

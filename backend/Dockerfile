# ProvenanceX API and scan-runner images (audit finding M6: supply chain).
#
#   docker compose build api scan-runner        (targets: api, runner)
#
# - Every base is pinned by digest; the same base as the sandbox images (docker/*).
# - Python packages come only from the hash-locked files (backend/requirements*.lock, `make
#   lock`), installed with --require-hashes --no-deps: an unlisted or altered wheel fails.
# - curl, gnupg and apt metadata exist only in the docker-cli build stage; the final images
#   have no downloader and no build tools.
# - setuid/setgid bits are stripped from every file in the final images (audit finding I1).
# - Syft is not here: it runs only in the analyzer sandbox's `sbom` mode (docker/analyzer).
#
# Constraint (documented): the runner image cannot be smaller than the ML stack. The runner runs
# the risk stage (Random Forest / Isolation Forest / XGBoost / SHAP over the saved models), so
# numpy, scikit-learn, xgboost (with its NCCL wheel), skops and shap stay in both images; the
# runner adds only the Docker CLI.

ARG PY_BASE=python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0

# --- Docker CLI for the runner, from Docker's GPG-signed apt repository ---------------------
# Two independent checks: apt verifies the package against the repository's signed index with a
# key whose fingerprint is pinned here, and the .deb must also match the SHA-256 pinned below
# (read from that signed index on 2026-11-19). Update version, hashes and fingerprint together.
FROM ${PY_BASE} AS docker-cli
ARG DOCKER_GPG_FINGERPRINT=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
ARG DOCKER_CLI_VERSION=5:27.5.1-1~debian.12~bookworm
ARG DOCKER_CLI_DEB_SHA256_AMD64=4ddc7a54df16f80edb14e422ac875cff7ad505acca733564b8363d668bf691e0
ARG DOCKER_CLI_DEB_SHA256_ARM64=7aa5aa042ddab7bf937951f968508cd040a7fed393302a338bf12c1c78ce16db
ARG TARGETARCH=amd64
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    case "${TARGETARCH}" in \
      amd64) sha="${DOCKER_CLI_DEB_SHA256_AMD64}" ;; \
      arm64) sha="${DOCKER_CLI_DEB_SHA256_ARM64}" ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/docker.asc https://download.docker.com/linux/debian/gpg; \
    fpr="$(gpg --show-keys --with-colons /tmp/docker.asc | awk -F: '$1=="fpr"{print $10; exit}')"; \
    [ "${fpr}" = "${DOCKER_GPG_FINGERPRINT}" ] || { echo "Docker key fingerprint ${fpr} is not pinned" >&2; exit 1; }; \
    install -d -m 0755 /etc/apt/keyrings; \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg /tmp/docker.asc; \
    echo "deb [arch=${TARGETARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list; \
    apt-get update; \
    cd /tmp; \
    apt-get download "docker-ce-cli=${DOCKER_CLI_VERSION}"; \
    deb="$(ls /tmp/docker-ce-cli_*.deb)"; \
    echo "${sha}  ${deb}" | sha256sum -c -; \
    dpkg-deb -x "${deb}" /tmp/cli; \
    install -D -m 0755 /tmp/cli/usr/bin/docker /out/docker; \
    /out/docker --version

# --- Shared runtime ----------------------------------------------------------------------------
FROM ${PY_BASE} AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# No git and no curl: the API and the scan-runner never clone or download artifacts. Downloads
# run only in the isolated fetcher image (docker/fetcher, Milestone B, audit finding H1).
RUN groupadd --system app && useradd --system --gid app --home /app app

# requirements-ml.lock holds the exact versions the saved models were built with.
COPY requirements.lock requirements-ml.lock ./
RUN pip install --require-hashes --no-deps -r requirements.lock -r requirements-ml.lock \
    && pip check

COPY . .
# I1: no setuid/setgid binaries (su, mount, passwd, ...) remain; the services never need them.
RUN mkdir -p /app/workspace && chown -R app:app /app \
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
    && ! find / -xdev -perm /6000 -type f | grep -q .

# --- scan-runner: the shared runtime plus the verified Docker CLI. It is the only service that
# gets the Docker socket (see docker-compose.yml). It has no HTTP port and never reads artifact
# content itself: it launches the analyzer and fetcher sandboxes for that.
FROM base AS runner
COPY --from=docker-cli /out/docker /usr/local/bin/docker
USER app
CMD ["python", "-m", "app.runner"]

# --- api (default target): no Docker CLI, no socket. It only queues scans and jobs.
FROM base AS api
USER app

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

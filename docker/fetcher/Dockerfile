# ProvenanceX fetcher: downloads GitHub repositories and Hugging Face models for one scan
# (Milestone B, audit finding H1). It replaces the downloads that used to run in the scan-runner.
#
# Build (from the repo root):
#   docker build -f docker/fetcher/Dockerfile -t provenancex-fetcher:0.1.0 backend
# or:  docker compose --profile fetcher-image build fetcher-image
#
# The image holds no secrets, no Docker CLI and no database, chain or ML clients. Runtime
# restrictions are applied by backend/app/fetch/hardening.py at `docker create` time and verified
# with `docker inspect` before the container starts: the internal fetch network (no route out
# except the egress proxy), read-only root, non-root user, cap-drop ALL, no-new-privileges,
# memory/CPU/pids limits, a noexec /tmp, and the scan's kernel-capped tmpfs staging volume as
# the only writable mount.
FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    TMPDIR=/tmp \
    PX_FETCH_WORKER=1

# git (hardened shallow clones) and CA certificates only.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git --version

# Hash-locked (audit finding M6): an unlisted or altered wheel fails the build.
COPY requirements-fetcher.lock /opt/px/requirements-fetcher.lock
RUN pip install --require-hashes --no-deps -r /opt/px/requirements-fetcher.lock

# Application code only (no tests, no .env). Read-only for everyone.
COPY app /opt/px/app
RUN chmod -R a-w,a+rX /opt/px \
    && cd /opt/px && python -B -c "import app.fetch_worker.__main__, app.fetch_worker.run, app.scanners.hf.client"

# I1: strip setuid/setgid bits (su, mount, passwd, ...); nothing here ever needs them.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
    && ! find / -xdev -perm /6000 -type f | grep -q .

# The real uid comes from `docker create --user` and is never 0.
USER 65534:65534
WORKDIR /opt/px
ENTRYPOINT ["python", "-B", "-m", "app.fetch_worker"]

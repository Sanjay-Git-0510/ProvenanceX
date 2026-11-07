# ProvenanceX

ProvenanceX is a defensive security platform for software and AI/ML supply chains. It
takes a software repo or package, or an AI model artifact, and does the following:

1. Collects multi-layer evidence: SBOM, vulnerabilities, provenance, static analysis, sandbox behavior and graph.
2. Produces an explainable **0–1 risk score** and an **ALLOW / REVIEW / BLOCK** decision.
3. Anchors compact evidence on a local blockchain.

> **Status: Phase 1, software ingestion.** A software artifact can be submitted as a GitHub URL or a ZIP upload.
> It is fetched or extracted safely, hashed with SHA-256, and its manifests are detected.
> No SBOM, vulnerability, risk or blockchain stages exist yet. See [docs/implementation-plan.md](docs/implementation-plan.md).

- Architecture: [docs/architecture.md](docs/architecture.md)
- Binding project contract: [CLAUDE.md](CLAUDE.md)

## Prerequisites

The development machine is Windows with WSL2 Ubuntu. Keep the repo on the Linux filesystem, for example `~/provenancex`, and not under `/mnt/c`.

| Tool | Version | Notes |
|---|---|---|
| Docker Desktop | recent | Turn on **Settings → Resources → WSL Integration** for your distro so `docker` works inside WSL |
| Python | 3.12 recommended | Containers use 3.12. Local 3.14 works for Phase 0. |
| Node.js | 22 LTS or newer | For the frontend |
| Git | any | |
| Syft | — | Needed from Phase 2. A mock provider is used if it is missing. |

## Quickstart (Docker)

```bash
cp .env.example .env          # then edit POSTGRES_PASSWORD and DATABASE_URL
docker compose up --build -d
curl http://localhost:8000/api/v1/health/ready
# {"status":"ready","db":"ok","version":"0.1.0"}
open http://localhost:5173    # UI shell; the header badge shows API and DB status
```

The API container runs `alembic upgrade head` on startup.

## Local development (without Docker)

```bash
# Backend
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/uvicorn app.main:app --reload      # needs DATABASE_URL pointing at a running Postgres

# Frontend
cd frontend
npm install
npm run dev                                   # proxies /api to localhost:8000
```

## Tests and lint

```bash
make lint            # ruff (backend) + eslint (frontend)
make test            # pytest + vitest
cd frontend && npm run build
```

Backend integration tests (`-m integration`) need a reachable PostgreSQL at `DATABASE_URL`.
Without one they are **skipped with an explicit reason**. In CI they run against a Postgres service, and any skip fails the build.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | Liveness: `{status, version}` |
| GET | `/api/v1/health/ready` | Readiness (DB check). Returns 503 with `{"error": {...}}` when the DB is down. |
| POST | `/api/v1/scans/software` | Start a software scan (multipart form, see below). Returns **202** `{scan_id, artifact_id, status}`. |
| GET | `/api/v1/scans/{scan_id}` | Scan status, normalized artifact record, ingest evidence, and a structured error if the scan failed |

Every error uses the envelope `{"error": {"code", "message", "details"}}`.

### Starting a software scan

Send exactly one of `source_url` or `file`:

```bash
# GitHub repository (https://github.com/<owner>/<repo> only), optional branch/tag/full commit SHA
curl -F source_url=https://github.com/psf/requests -F revision=v2.32.3 \
     http://localhost:8000/api/v1/scans/software

# ZIP upload (optional display name)
curl -F file=@project.zip -F name=my-project http://localhost:8000/api/v1/scans/software

curl http://localhost:8000/api/v1/scans/<scan_id>
```

The scan runs in the background. Its status moves `queued → running → completed | failed`.
`artifact.sha256` is a deterministic **content digest** (`provenancex-tree-v1`; see
`backend/app/core/hashing.py`), so the same files produce the same hash whether they came from a ZIP or a git clone.
For uploads, `ingest.archive_sha256` is the hash of the raw ZIP bytes.

Input safety:
- URLs: https only, `github.com` allowlist, and the host must resolve to a public IP.
- ZIPs: rejected for path traversal, absolute paths, symlinks, special files, encryption, duplicate entries, decompression bombs, or size and file-count limits.
- git: shallow clone, hooks, submodules, redirects and LFS disabled, with a timeout and size cap.

## Safety

ProvenanceX treats every scanned artifact as untrusted and never executes it on the host.
See the trust boundaries in [docs/architecture.md](docs/architecture.md#3-trust-boundaries).
Do not commit secrets. Only `.env.example` is tracked.

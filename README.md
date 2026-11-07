# ProvenanceX

ProvenanceX is a defensive security platform for software and AI/ML supply chains. It
takes a software repo or package, or an AI model artifact, and does the following:

1. Collects multi-layer evidence: SBOM, vulnerabilities, provenance, static analysis, sandbox behavior and graph.
2. Produces an explainable **0–1 risk score** and an **ALLOW / REVIEW / BLOCK** decision.
3. Anchors compact evidence on a local blockchain.

> **Status: Phase 0, the skeleton.** Only health checks, the DB connection, migrations and the UI shell work so far.
> No scanning is implemented yet. See [docs/implementation-plan.md](docs/implementation-plan.md).

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

## API (Phase 0)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | Liveness: `{status, version}` |
| GET | `/api/v1/health/ready` | Readiness (DB check). Returns 503 with `{"error": {...}}` when the DB is down. |

Every error uses the envelope `{"error": {"code", "message", "details"}}`.

## Safety

ProvenanceX treats every scanned artifact as untrusted and never executes it on the host.
See the trust boundaries in [docs/architecture.md](docs/architecture.md#3-trust-boundaries).
Do not commit secrets. Only `.env.example` is tracked.

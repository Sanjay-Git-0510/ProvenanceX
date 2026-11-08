# ProvenanceX Handoff

## STATUS

_Last updated: 2026-11-08_

- **Phase 0 (foundation): complete.**
- **Phase 1 (software ingestion, SHA-256, URL/upload validation, safe workspace): complete.**
- **Deferred Docker-dependent checks: all passed.**
  - `docker compose build` and `docker compose up --wait`: api, postgres and frontend all healthy
  - `GET /api/v1/health/ready`: 200, `"db":"ok"`
  - `alembic current`: `0002 (head)`
  - Postgres integration tests (`tests/integration`): 5/5 passed
  - Live GitHub clone test (`PROVENANCEX_NETWORK_TESTS=1`): passed
  - Full backend suite with integration and network tests enabled: 240 passed, 0 skipped
- **Postgres host port is configurable** via `POSTGRES_HOST_PORT` (default `5432`).
  On this dev machine it is set to `5433` in the local `.env` (not committed), because a
  Windows PostgreSQL service (`postgresql-x64-18`) already holds 5432. Host-side tools and
  tests must use the same port in `DATABASE_URL`, e.g.
  `postgresql+psycopg://provenancex:provenancex@127.0.0.1:5433/provenancex`.
- Fixes made while running the deferred checks:
  - `frontend/Dockerfile`: `/app` is now owned by the `node` user, so the Vite dev server can start
  - `docker-compose.yml`: added a frontend healthcheck

## Next step

**Phase 2:** Syft/CycloneDX, SBOM parsing, OSV/NVD adapters, findings, dependency graph.
Under the agent rules in `CLAUDE.md`, inspect the repo and propose the Phase 2 file list
for approval before implementing anything.

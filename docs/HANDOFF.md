# ProvenanceX Handoff

## STATUS

_Last updated: 2026-11-08_

- **Phase 0 (foundation): complete.**
- **Phase 1 (software ingestion, SHA-256, URL/upload validation, safe workspace): complete.**
- **Phase 2 (Syft/CycloneDX SBOM, OSV/NVD, findings, dependency graph): complete.**
  - The evidence stages `sbom`, `graph` and `vulnerabilities` run after ingestion. Each one records
    `status` / `provider` / `source` in `Scan.stages`. A failed stage never fails the scan, and it
    never falls back to mock data.
  - New endpoints: `GET /api/v1/scans/{id}/findings` (filters: category, severity, source; paging)
    and `GET /api/v1/scans/{id}/graph`.
  - Migration `0003`: `components`, `findings`, `graph_nodes`, `graph_edges`, `scans.stages`,
    `scans.bom_sha256`.
  - Syft 1.57.0 is pinned and SHA-256-verified in `backend/Dockerfile` and in CI.
  - Mock data in `backend/app/scanners/mock_data/` is real Syft and OSV output recorded for the
    benign fixtures, always tagged `source="mock"`.
- **Verified on this machine (2026-11-08):**
  - `ruff check` / `ruff format --check`: clean
  - `pytest -m "not network"`: 376 passed. 6 Postgres tests skipped until Compose was up. With
    Compose Postgres on 5433, `tests/integration`: 10 passed.
  - `PROVENANCEX_NETWORK_TESTS=1 pytest -m network`: 3 passed (GitHub clone, live OSV, live NVD)
  - `alembic downgrade 0002 && alembic upgrade head` on Compose Postgres: OK
  - `docker compose build` + `up --wait`: all healthy. Syft 1.57.0 is in the API image, and
    `alembic current` = `0003 (head)`.
  - Live end-to-end runs through the Docker API:
    - npm fixture ZIP: 4 components, 10 OSV findings, `transitive_depth` 3
    - `github.com/pallets/flask`: 117 components, 52 findings, NVD enriched 10 of 17 unscored CVEs
- **CI fix:** CI had been failing since Phase 1, because the one `network` test was *skipped* and
  the job fails on any skip. CI now runs `pytest -m "not network"`, which deselects those tests.
- **Postgres host port** is configurable via `POSTGRES_HOST_PORT` (default `5432`). It is `5433` in
  the local `.env` because a Windows PostgreSQL service holds 5432. Host-side tests use
  `DATABASE_URL=postgresql+psycopg://provenancex:provenancex@127.0.0.1:5433/provenancex`.

- **Phase 3 (AI/model ingestion, AI-BOM, lineage graph, ProvenanceRecord, root-package cleanup):
  complete, uncommitted on `main`. Awaiting review.**
  - `POST /api/v1/scans/model` takes a Hugging Face URL or a model-directory ZIP. Stages: `aibom`,
    `graph` (`graph_kind="lineage"`), `vulnerabilities`, `provenance`. Provenance also runs for
    software scans.
  - Migration `0004`: `provenance_records`. New dependency: `pyyaml` (SafeLoader only).
  - Files are only parsed. Pickles go through `pickletools`. A security test fails if `app/`
    imports pickle, torch, joblib, dill or safetensors.
  - The project's own package is merged into the graph root and left out of OSV queries.
- **Phase 3 verified on this machine (2026-11-08), Compose Postgres on 5433:**
  - `ruff check` / `ruff format --check`: clean
  - `pytest -m "not network"`: 887 passed, 0 skipped
  - `PROVENANCEX_NETWORK_TESTS=1 pytest -m network`: 7 passed (GitHub, OSV, NVD, Hugging Face)
  - `alembic downgrade 0003 && alembic upgrade head`, then `alembic check`: OK, no drift
  - `docker compose build` + `up --wait`: all healthy, `alembic current` = `0004 (head)`
  - Live runs through the Docker API:
    - `hf-internal-testing/tiny-random-gpt2`: 10 of 10 files downloaded and hash-verified, lineage
      graph, `download_integrity: pass`. A rescan reported `hash_changed=false`.
    - LoRA fixture ZIP: lineage has `fine_tuned_from` and `trained_on`; OSV found 2 advisories on
      the pinned `requests==2.32.3`.
    - npm fixture ZIP: root package `demo-app` merged, `express` at depth 1, 3 packages queried
      with `project_root_packages: 1`, 10 OSV findings.

## Known limitations (documented in architecture.md §4)
- Dependencies are never installed or resolved. If a project has no lockfile (bare
  requirements.txt), transitive dependencies are unknown, and the API reports
  `transitive_resolution="none"` plus a limitation message.
- CVSS v4 is not scored locally. NVD fills in scores, up to `NVD_MAX_LOOKUPS` per scan.
- Hugging Face weights over `HF_MAX_FILE_MB` or the total budget are not hashed locally. They carry
  the Hub-reported hash, marked unverified.
- Signature and attestation files are detected by name only, so `signed` stays `null`.
- Gated and private Hugging Face repositories are unsupported (no token).
- OSV covers only exactly pinned runtime requirements in model repositories.
- GGUF and ONNX files are identified but not parsed.
- Hugging Face download redirects accept any `*.hf.co` host (up to 5 dots), accepted for the MVP
  because CDN hostnames vary. It relies on Hugging Face's ownership of `hf.co`. The https,
  no-credentials, no-port, no-IP-literal and public-address checks still apply to every hop.
- Hugging Face downloads follow up to 5 redirect hops (`MAX_REDIRECTS`), accepted for the MVP.

## As-built differences from the approved Phase 3 plan
- Download redirects allow up to 5 hops (`MAX_REDIRECTS`); the plan said 3.
- The redirect allowlist also accepts any `*.hf.co` host (up to 5 dots), because Hugging Face CDN
  hostnames vary; the plan described a fixed list.
- Not created: `app/schemas/aibom.py` (the AI-BOM is a plain JSON document),
  `hf_mock_repo/hf_api_recorded.json`, and the `hf_api_base` setting (the host is fixed in code).
- `docker-compose.yml` also changed, to pass the `HF_*` and model-limit settings to the API.

## Next step

**Phase 4:** static analysis features, Docker sandbox and telemetry parser. Not started. Under the
agent rules in `CLAUDE.md`, inspect the repo and propose the Phase 4 file list for approval before
implementing anything.

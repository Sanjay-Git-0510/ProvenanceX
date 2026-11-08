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

**Phase 4, Milestone C:** Docker sandbox. Wait for the go-ahead. The approved plan is in
`~/.claude/plans/pasted-content-id-c960-read-claude-md-iridescent-lobster.md`. Phase 5 is not
started.

## Phase 4 progress

- **Milestone B (telemetry parser): complete, uncommitted on `main`. Awaiting review.**
  - `app/scanners/sandbox/telemetry.py` parses `provenancex-trace-v1` bundles into `network_count`,
    `process_count`, `file_write_count`, `syscall_count`, `external_destination_count` and
    `resource_spike`. `behavior_findings.py` builds `category="behavioral"` findings with no CVSS.
  - Parser and findings only. It is **not wired into the pipeline yet**; that happens in Milestone C.
    Nothing has been executed, and all test traces are hand-written and labeled synthetic.
  - Bundles are untrusted. Bad envelopes raise `sandbox_trace_error`. Malformed lines are counted,
    and text inside quoted strace strings cannot create network or file events.
  - A feature with no evidence is `null`, never 0 or false.
  - Limitations: with no network, hostnames never resolve, so destinations known only by name are
    undercounted. Code under observation can detect tracing or forge its own trace lines, so quiet
    telemetry is not proof of safety.
  - Verified on this machine (2026-11-08), Compose Postgres on 5433: `ruff check` and
    `ruff format --check` clean; `pytest -m "not network"` 1292 passed, 0 skipped.
  - Not in the plan's file list: `app/core/errors.py` gained `SANDBOX_TRACE_ERROR`.
- **Milestone A (static analysis): complete and committed.**
  - New stage `static` (pipeline step 9) runs after `provenance` for software and model scans.
    Code is only parsed with `ast` or text rules, never imported or run.
  - Features are in `stages.static.features`: `dangerous_import_count`, `suspicious_api_count`,
    `script_presence`, `archive_anomaly`, and supporting counts.
  - Findings are `category="static"` with `details.kind` of `dangerous_import`, `suspicious_api`,
    `install_script` or `archive_anomaly`, and no CVSS. No migration.
  - When a budget is hit the stage is `partial` and lists what was skipped, so a 0 is only a clean
    result when `counts.not_analyzed` is also 0.
- **Milestone A verified on this machine (2026-11-08), Compose Postgres on 5433:**
  - `ruff check` / `ruff format --check`: clean
  - `pytest -m "not network"`: 1126 passed, 0 skipped
  - `docker compose build api` + `up --wait`: healthy
  - Live runs through the Docker API:
    - `github.com/pallets/flask`: 236 files analyzed, 7 suspicious API calls, 5 findings
    - `hf-internal-testing/tiny-random-gpt2`: 10 files analyzed, no scripts, 0 static-stage findings
    - Upload containing NUL bytes and a lone surrogate: stored on PostgreSQL without error
- **Differences from the plan:** `getattr` with a plain variable name is flagged only on sensitive
  modules (`os`, `subprocess`, `builtins`, ...), because `getattr(obj, name)` is common in ordinary
  code. Computed names are always flagged. `docker-compose.yml` also passes the `STATIC_*` settings.
- **Static limitations:** aliases are tracked per file without scopes, so heavily obfuscated code
  can evade the rules. `getattr` is flagged only on sensitive modules or computed names, so other
  getattr-based obfuscation can be missed. Nested tar, 7z and rar archives are flagged but not
  inspected. A match shows what code can do and is not evidence of malice.

# ProvenanceX Implementation Plan

Each phase follows the same loop: inspect the repo, list the files, **wait for approval**, implement, then run tests, lint and build.
After that, report what passed, what failed and what remains, and wait for the go-ahead.

## Phase 0: Repository and skeleton ✅
- Monorepo layout: `backend/`, `frontend/`, `contracts/`, `ml/`, `docs/`, `.github/`
- FastAPI app factory, settings, logging and structured errors
- `/api/v1/health` (liveness) and `/api/v1/health/ready` (DB check)
- SQLAlchemy engine and session, Alembic with an empty baseline `0001`
- React (Vite, JS) shell: routes for all 10 pages as labeled placeholders, an API service layer, and a health badge
- Docker Compose (postgres, api, frontend) and CI (lint, tests with Postgres, build)
- **Exit:** backend and frontend tests and lint pass, the frontend builds, and `docker compose up` returns ready

## Phase 1: Software ingestion ✅
As built, the scan endpoint takes a multipart form and runs ingestion as a background task. The artifact `sha256` is the
`provenancex-tree-v1` content digest, plus `archive_sha256` for uploads. The workspace is removed on failure and kept on success.

- `app/security/url_validation.py`:
  - https only, `github.com` allowlist (plus `huggingface.co` for Phase 3)
  - DNS resolution, then rejection of private, loopback, link-local and reserved IPs
- `app/security/archive.py`: safe ZIP extraction that rejects traversal, absolute paths, symlinks, bombs (compression ratio and total size), and file-count overflow
- `app/pipeline/workspace.py`: a per-scan temporary directory under `WORKSPACE_ROOT` with guaranteed cleanup
- `app/scanners/git_fetch.py`:
  - `git clone --depth 1 --no-recurse-submodules -c core.hooksPath=/dev/null`, with a timeout and a size cap
  - Optional branch, tag or commit
- `app/core/hashing.py`: streaming SHA-256 for files and a deterministic directory digest
- Manifest detection (requirements.txt, pyproject, package.json and similar)
- `Artifact` and `Scan` models, migration `0002`
- `POST /api/v1/scans/software` (URL or ZIP upload), `GET /api/v1/scans/{id}`
- **Tests:** hashing vectors, malicious ZIP fixtures generated in the tests, bad URLs (http, other hosts, IP literals, userinfo tricks), oversize, timeout, and API integration

## Phase 2: SBOM, vulnerabilities and dependency graph ✅
As built, the evidence stages run after ingestion in the same background task, and each one records its status in `Scan.stages`.
A failed stage does not fail the scan. Syft 1.57.0 is pinned and checksum-verified in the API image and in CI.
Migration `0003`. See architecture.md §4 "Phase 2 evidence stages" for the details and known limitations.

- A Syft adapter (CLI to CycloneDX JSON) with a mock, and a CycloneDX parser that produces `Component` records
- OSV (batch query) and NVD adapters with mocks. They keep the source, ID, severity and CVSS, and use timeouts and retries.
- `Finding` records with `category="vulnerability"`
- A NetworkX builder (`depends_on`, `transitive_depends_on`) and graph features: dependency_count, transitive_depth, centrality
- `GraphNode`/`GraphEdge` models and the `/findings` and `/graph` endpoints

## Phase 3: AI/model ingestion ✅
As built, a model scan runs the stages `aibom`, `graph` (`graph_kind="lineage"`), `vulnerabilities` and `provenance`.
The provenance stage also runs for software scans, and the root-package cleanup is included. Migration `0004`.
See architecture.md §4 "Phase 3 AI/ML evidence stages" for the details and known limitations.

- Hugging Face fetch: metadata through the API plus an allowlisted file download, with no code execution
- File inventory and serialization detection (safetensors, pickle, PT, ONNX, GGUF, and so on)
- Pickle opcode scanning with `pickletools`
- Config parsing, model-card completeness, adapter (LoRA) metadata, and lineage (base model, datasets)
- AI-BOM JSON, the model lineage graph (`derived_from`, `fine_tuned_from`, `trained_on`, `bundled_with`)
- `POST /api/v1/scans/model` and the `ProvenanceRecord` model

## Phase 4: Static analysis and sandbox
- AST-based import and API scanning that flags `os.system`, `subprocess`, `eval`/`exec`, network, `ctypes` and similar
- Detection of scripts, install hooks and archive anomalies
- A Docker sandbox adapter with the full hardening set from architecture.md §3, plus a mock
- The sandbox image (`docker/sandbox/`)
- A telemetry parser that produces the behavior features

## Phase 5: Dataset and models
- `ml/scripts/` generators that build feature records from benign fixtures and controlled tamperings. These are **labeled synthetic** in metadata.
- A family-grouped split
- RF (primary), XGBoost and Isolation Forest, with saved artifacts and preprocessing
- An evaluation report with precision, recall, F1, ROC-AUC, FPR and FNR, a rules-only baseline, and a per-layer ablation

## Phase 6: Fusion, policy and explanations
- `app/risk/policy_config.py` (weights and thresholds), fusion, policy, SHAP top factors
- The `/risk` and `/evidence` endpoints. When no model exists, the rule-based fallback reports "ML model unavailable".

## Phase 7: Blockchain
- `contracts/ProvenanceEvidence.sol`, the Hardhat config and deploy script, and the `hardhat` Compose service
- A web3.py adapter with a mock, `BlockchainEvidence`, `/blockchain`, and `POST /verify`
- Verification states: VERIFIED, MISMATCH, NOT ANCHORED and UNKNOWN. The tests prove that a changed artifact hash produces MISMATCH.

## Phase 8: Dashboard
- Apply `docs/design/lumora-reference.md`, built only on real API data
- Graph visualization, findings filters, timeline, risk/SHAP panel, blockchain panel, and the CI/CD page

## Phase 9: CI gate and end-to-end
- A GitHub Actions gate that fails only on BLOCK (REVIEW is optional)
- End-to-end fixtures, the full test run, demo instructions, and pinned dependencies

### Cleanup
- **Root-package OSV lookup (from Phase 2).** Syft lists a lockfile project's own package (for
  example the root `""` entry of `package-lock.json`) as an ordinary component. That causes two
  problems:
  - It is queried in OSV, so a public package with the same name and version can produce
    unrelated advisories.
  - In the graph it becomes a top-level node, so the project's direct dependencies appear at
    depth 2.

  Detect the project's own package from the manifest name and version (for example
  `package.json` `name`/`version`, or `pyproject.toml` `[project]`) and treat it as the artifact
  root. Leave it out of the OSV lookup. Add a fixture test that covers both effects. See
  `docs/architecture.md` §4, "Known limitations".

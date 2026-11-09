# ProvenanceX Handoff

## STATUS

_Last updated: 2026-11-09_

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
  complete and committed.**
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
- **Phase 4 (static analysis, telemetry parser, Docker sandbox, security hardening): complete and
  committed.** Milestones A, B and C plus the post-review hardening are done. Final results:
  `pytest -m "not network and not sandbox"` 1477 passed, 0 skipped;
  `PROVENANCEX_SANDBOX_TESTS=1 pytest -m sandbox` 35 passed. Details are under "Phase 4 progress".
- **Phase 5 (dataset, models, evaluation): complete and committed.** Milestones A, B and C are done.
  Final results: `pytest -m "not network and not sandbox"` 1770 passed, 0 failed, 0 skipped,
  42 deselected. `pytest -m network` and `pytest -m sandbox` were not run for Phase 5. Details are
  under "Phase 5 progress".
- **Phase 6 (fusion, policy, SHAP, explanation API): complete and committed**, including
  `GET /api/v1/scans/{scan_id}/evidence`. Details are under "Phase 6 progress".
  - **Last full run:** `pytest -m "not network and not sandbox"`, Python 3.14, Compose Postgres:
    2034 passed, 0 failed, 0 skipped.
  - **Not run:** the 42 network and sandbox tests, frontend tests, the suite on Python 3.12, the CI
    workflow, and a scan with the sandbox enabled.
  - The PostgreSQL tests need the `DATABASE_URL` documented under "Verified on this machine" above
    (`postgresql+psycopg://provenancex:provenancex@127.0.0.1:5433/provenancex`). Without it they skip.

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

- **The Compose `workspace` volume holds untrusted artifacts.** Scanned files stay in the
  `provenancex_workspace` named volume, in Docker's storage, until `docker compose down -v` removes
  it. Only the `api` service mounts it, and nothing in the application executes its contents.
- **The `workspace` volume is not mounted `noexec`.** Docker's local volume driver applies mount
  options only with a backing device or tmpfs, and tmpfs would lose the files on restart. Accepted
  for the MVP. Do not run files from this volume by hand.
- **Scans made before the `workspace` volume existed report UNKNOWN**
  (`offchain_evidence_unavailable`) if anchored, because their files were lost with the old container.

## As-built differences from the approved Phase 3 plan
- Download redirects allow up to 5 hops (`MAX_REDIRECTS`); the plan said 3.
- The redirect allowlist also accepts any `*.hf.co` host (up to 5 dots), because Hugging Face CDN
  hostnames vary; the plan described a fixed list.
- Not created: `app/schemas/aibom.py` (the AI-BOM is a plain JSON document),
  `hf_mock_repo/hf_api_recorded.json`, and the `hf_api_base` setting (the host is fixed in code).
- `docker-compose.yml` also changed, to pass the `HF_*` and model-limit settings to the API.

## Next step

**Phase 8 is complete and committed (latest: Milestone C, `a17a016`). Phase 9 Milestone A (CI gate) is done and
waiting for the owner's commit and first GitHub run.** See "Phase 9 progress". Milestones B (end-to-end fixtures)
and C (demo and docs) are not started; waiting for the go-ahead.

Standing notes:
- Do not adjust any weight, threshold or hyperparameter after looking at test-split results.
- Null evidence must lower confidence and never read as clean. See the false-positive finding below.
- On the host, set `MODEL_PATH=../ml/models` when running from `backend/`. Compose mounts
  `ml/models` read-only at `/app/ml/models`.

## Notes for Phases 7 and 8: `risk_score` can be null

`GET /scans/{id}/risk` has `status` of `pending`, `computed` or `not_computed`, with `reason`
(`code`, `message`) unless computed. `risk_score` is null, never 0, in three cases:

| Case | `status` | `reason.code` | `decision` |
|---|---|---|---|
| Scan queued or running | `pending` | `scan_queued`, `scan_running` | null |
| Scan failed, or the computation errored (nothing stored) | `not_computed` | `scan_failed`, `risk_computation_error` | null |
| Scan completed, no rule layer could be scored | `not_computed` | `no_rule_layer_scored` | REVIEW, or BLOCK if a hard rule fired |

**Phase 7 (blockchain):**
- A null score must never be anchored as 0, and the contract and web3.py adapter must keep "no score"
  distinct from a real 0 (for example an explicit `hasScore` flag). Choose the encoding in the Phase 7
  plan and test it, including through verification.
- A `RiskDecision` row can have a null `risk_score` and a real decision. Handle that row explicitly.
- Mock scans still report a `bom_sha256`, so check `mock.mock_stages` from `/evidence` before
  anchoring.
- `pending`, `scan_failed` and `risk_computation_error` have no `RiskDecision` row and nothing to
  anchor. Report them as NOT ANCHORED.

**Phase 8 (dashboard):**
- Show "Not computed" or "Pending" with `reason.message`. Never render null as 0, 0%, an empty gauge
  or LOW, and never derive a risk band from a null score.
- `decision` is independent of the score: show a null score beside REVIEW or BLOCK when both occur.
  `decision` is null while pending or failed, so show no ALLOW/REVIEW/BLOCK badge then.
- Null applies to each value in `scores` too, and each has its own `reason`.
- An ALLOW can occur without vulnerability or behavioral evidence. Show the "not evaluated" layers
  (`not_evaluated_layers`) beside every ALLOW.
- A decision can flip between scans of unchanged content when confidence crosses the ALLOW minimum
  (currently 0.60). Show the confidence and the evaluated layers so a flip is not read as a change in
  the artifact. See "Decisions can flip between scans" in `docs/architecture.md`.
- Factors with `evaluated=false` describe missing evidence and must look different from measured
  factors. Show `training_data.notice` wherever ML output appears, and label `contains_mock_evidence`.

## Phase 9 progress

- **Milestone A (CI gate): complete, not yet committed.**
  - New: `scripts/ci_gate.py` (standard library only), `.github/workflows/provenancex-gate.yml`,
    `backend/tests/unit/test_ci_gate.py`, `backend/tests/unit/test_gate_workflow.py`. Changed: `ci.yml` and the
    Makefile (ruff covers `scripts/`; new `make gate`), `pages/CiCd.jsx` and its test, `CLAUDE.md`, `README.md`.
  - **Owner decisions (2026-11-09), recorded in `CLAUDE.md` as deliberate extensions of "fails only on BLOCK":**
    REVIEW with a null risk score exits 2, and mock evidence exits 2 unless `--allow-mock` is set. The end-to-end
    test stays local only.
  - **Exit codes:** 0 ALLOW, or REVIEW by default, with a real score. 1 BLOCK, or REVIEW with `--fail-on-review`.
    2 failed scan, timeout, API error, no or unrecognized decision, null score on ALLOW or REVIEW, or mock evidence
    without `--allow-mock`. Mock is checked before BLOCK, so a BLOCK built on mock evidence is also exit 2. A
    missing mock flag counts as mock.
  - **Job summary:** decision, score, confidence, not-evaluated and partial layers, hard rules fired, mock label,
    ML status, training-data notice. It writes only validated identifiers and escaped server notices, and no
    artifact-derived text. The script sends no credentials and follows no redirects.
  - **Workflow:** `pull_request` and `workflow_dispatch`, `permissions: contents: read`, no secrets, no
    `pull_request_target`, `persist-credentials: false`. It scans `simple_python_project` by default, not this
    repository, whose test fixtures would skew the result. Trained models are git-ignored, so results on a runner
    are rule-based and report "ML model unavailable".
  - **Action pin:** `actions/checkout@11d5960a326750d5838078e36cf38b85af677262` (`v4`), read from the GitHub API
    and confirmed with `git ls-remote` on 2026-11-09. It is the only action in the workflow, so none is listed as
    not verified. `ci.yml` keeps its existing tags, because only new actions were in scope.
  - **Beyond the approved list:** `CiCd.jsx` changed more than its text. The page must not contradict the two owner
    decisions, so its outcome now follows the same order as `evaluate` in the script.
  - **Verified on this machine (2026-11-09), Compose Postgres on 5433:**
    - The exact CI ruff commands, now including `scripts/`: clean. `alembic check`: no drift
    - `pytest -m "not network and not sandbox and not chain"`, including Postgres, Python 3.14: 2554 passed,
      0 failed, 0 skipped, 72 deselected
    - `npm run lint`: clean. `npm test -- --run`: 483 passed, 0 failed, 0 skipped (20 files). `npm run build`:
      succeeded; no CDN host in the build output
    - `npx hardhat test` in the Compose image: 32 passing. `check-abi.js`: match (17 entries)
    - Breaking the code on purpose made tests fail in all 36 cases, after one gap was closed: the redirect test
      could not see a followed redirect, so it was rewritten. One case (allowing special files) was caught as a
      hang on a FIFO rather than a failed assertion. Each change was restored
    - **Gate against a disposable Compose API** (separate project and ports, real Syft and OSV, removed afterwards;
      the models were mounted, so ML was available, unlike on a runner). These are wiring checks on benign
      fixtures, not detection results:

      | Fixture | Options | Decision | Score | Confidence | Exit |
      |---|---|---|---|---|---|
      | `simple_python_project` | none | REVIEW | 0.483 | 0.630 | 0 |
      | `lora_adapter` | `--kind model` | REVIEW | 0.451 | 0.688 | 0 |
      | `remote_code_model` | `--kind model --fail-on-review` | REVIEW | 0.520 | 0.475 | 1 |
      | `simple_python_project`, mock SBOM and OSV | none | REVIEW | 0.350 | 0.341 | 2 |
      | `simple_python_project`, mock SBOM and OSV | `--allow-mock` | REVIEW | 0.350 | 0.341 | 0 |
    - The script's `--help` ran on Python 3.12.16 in the API image
  - **Not run:** the GitHub run of the new workflow, and CI on GitHub (both need a push); a live BLOCK through the
    gate (exit 1 on BLOCK is tested against a fake server and the real schema; the live BLOCK fixture is Milestone B);
    the gate's test suite on Python 3.12; `pytest -m network`, `sandbox` and `chain` (the 72 deselected; no code they
    cover changed); frontend checks on Node 22; the pages in a browser (the CI/CD page changed).

## Phase 8 progress

- **Milestone C (graph, blockchain, CI/CD, Settings, accessibility): complete and committed (`a17a016`).**
  - **Packages added, exact versions, `--ignore-scripts`:** `@dagrejs/dagre` 3.1.3 (with `@dagrejs/graphlib` 4.0.6)
    and, dev only, `jest-axe` 11.0.0 (with 13 test-only transitive packages). No other dependency changed.
  - New: `components/graph/` (`GraphCanvas`, `GraphControls`, `GraphLegend`, `NodeInspector`, `GraphTable`,
    `GraphView`), `components/blockchain/` (`VerificationPanel`, `FieldComparisonTable`, `AnchorRecord`),
    `lib/graphLayout.js`, `hooks/useGraph.js`, `hooks/useVerification.js`, and tests `graphLayout`, `graph`,
    `BlockchainEvidence`, `CiCd`, `Settings`, `a11y`. `pages/PagePlaceholder.jsx` was removed.
  - **Graph:** `normalizeGraph` is the only code that reads `attributes`; components receive named, sanitized
    fields. Above 300 visible nodes the drawing is replaced by a notice and the tables stay complete. The SVG is
    one labelled image, and `GraphTable` is the keyboard and screen-reader equivalent. A scan opened on the wrong
    graph page gets a link to the right one.
  - **Verification:** `POST /verify` runs only from the button. A failed request or a response with no state is
    `failed`: it shows the error and "Not checked yet", never UNKNOWN. Field results come only from the API's
    per-field `status`, and an unrecognized status never reads as a match. Results are not kept across scan
    changes or reloads. There is no Anchor button or `/anchor` call.
  - **Mock IDs:** `HashValue kind="mockTx"` accepts only `^mock-tx-[0-9a-f]{32}$` and draws its own "mock" label.
    The `tx` format is unchanged. `AnchorRecord` picks `mockTx` only for a mock record.
  - **CI/CD:** shows the rule and the selected scan's decision. It calls `GET /risk`, so an older scan stores a
    result on first read, as on Risk Analysis. No pipeline-run data exists, and the page says so.
  - **Settings:** health and version only, read-only.
  - **Changes to existing code and tests:** `VerificationBadge` wording; `RecentScansTable` caption, because it
    duplicated the panel name (a real axe `landmark-unique` violation from Milestone B); `CiCd.jsx` added to the
    allowlist in `risk.test.jsx` of files that may mention ALLOW.
  - **Scan Details** still links to Blockchain Evidence, so Verify lives on one page (owner decision).
  - **Known issue, not changed:** `npm audit` reports 5 advisories (2 critical, 3 moderate) in `react-router`,
    `react-router-dom`, `vitest`, `@vitest/mocker` and `tinypool`. The count was the same before these packages
    were added. Not triaged; `react-router` ships at runtime.
  - **Verified on this machine (2026-11-09), host Node 26:**
    - `npm run lint`: clean. `npm run build`: succeeded; no CDN host in the build output
    - `npm test -- --run`: 478 passed, 0 failed, 0 skipped (20 files), including jest-axe on all 10 pages
    - Breaking the code on purpose made tests fail in all 22 cases, after one gap was closed: removing the
      not-evaluated layers on CI/CD first passed, so a stricter test was added. Each change was restored
  - **Not run:** the pages in a real browser (the owner checks this; layout, responsiveness and SVG rendering are
    unchecked, because jsdom has no layout), comparison with a live API response (the API was not running, so
    fields were checked against the backend schemas and code), a frontend image build, frontend checks on Node 22
    (the CI version), the CI workflow on GitHub, ruff and pytest (no backend file changed). jest-axe cannot measure
    colour contrast in jsdom; the token test covers it.

- **Milestone B (core pages): complete and committed (`da1c3f9`).**
  - Real pages on the real API: Dashboard, New Scan, Scan Details, Findings, Risk Analysis. New hooks
    `useScan`, `useScanSelection`, `useFindings`; `lib/policyDisplay.js`; `components/{scan,risk,findings}/`;
    `styles/pages.css`; page tests plus `src/test/helpers.jsx`. No new npm package.
  - **Added beyond the approved list:** `risk/DecisionDisplay.jsx` (the only importer of `DecisionBadge`, so
    an ALLOW cannot appear without `AllowCaveat`), `scan/ScanCounts.jsx`, and a sanitized `/evidence` call on
    Risk Analysis, because `/risk` has no artifact type and graph links need one.
  - **ALLOW guard:** `expectEveryAllowHasCaveat` in `src/test/helpers.jsx` fails if a rendered ALLOW lacks its
    confidence, not-evaluated layers or flip notice. Tests prove it fails on a bare badge. A source test
    fails if anything but `DecisionDisplay` imports `DecisionBadge`.
  - **The Dashboard ALLOW count** spans many scans, so its caveat gives their confidence range and says the
    layers are listed on each scan. Each ALLOW table row fetches its real layers.
  - **Threshold:** `ALLOW_MIN_CONFIDENCE` is compared by a test with `min_allow_confidence` in the backend policy.
  - **Writes:** Scan Details sends GET requests only, to `/evidence`, `/risk` (after the scan finishes) and
    `/findings`, and never calls `/verify` or `/anchor`. The only side effect is the existing behaviour that
    `GET /risk` stores a result on first read for an older scan. The Dashboard calls `/risk` for ALLOW rows
    only, which already have a stored decision, so listing computes nothing. Risk Analysis does the same
    first-read computation when an older scan is chosen.
  - **Not derived:** no LOW/MEDIUM/HIGH risk band, because the API gives only a confidence label.
  - **Scan Details links** to `/graph`, `/lineage` and `/blockchain`, which were placeholders until Milestone C.
  - **Verified on this machine (2026-11-09), host Node 26:**
    - `npm run lint`: clean. `npm run build`: succeeded; no CDN host in the build output
    - `npm test -- --run`: 375 passed, 0 failed, 0 skipped (14 files)
    - Breaking the code on purpose made tests fail in all 11 valid cases, including ALLOW without its caveat,
      empty layers, `/risk` on every row, `/risk` while running, a POST to `/risk`, threshold drift, null score
      as 0, a raw `details` blob, unsanitized text, hidden mock labels and polling while hidden
    - Field names were compared with one real stored `/risk` and `/evidence` response from the running API.
      That check caught the `sandbox` finding source and the name-ordered stages
  - **Not run:** the pages in a real browser (the owner checks this before committing), a frontend image build,
    frontend checks on Node 22 (the CI version), the CI workflow on GitHub, ruff and pytest (no backend file
    changed).

- **Milestone A (frontend foundation): complete and committed (`3a8d26f`).**
  - **Packages added (exact versions, nothing else):** `@fontsource-variable/onest` 5.3.1,
    `@fontsource/ibm-plex-mono` 5.3.0 (Latin 400 and 500 only), `lucide-react` 1.70.0.
  - New: `styles/{tokens,layout,components}.css`; `components/ui/` (`Button`, `Badge`, `DecisionBadge`,
    `VerificationBadge`, `MockLabel`, `Panel`, `DataTable`, `Pagination`, `LoadingState`, `ErrorState`,
    `HashValue`, `Modal`); `hooks/useApi.js`; `lib/{format,sanitizeDisplay,evidenceLinks}.js`; tests
    `tokens.contrast`, `ui`, `api`, `sanitizeDisplay`, `format`. Pages are still placeholders.
  - **Dropped from the plan:** `lib/recentScans.js`, because `GET /scans` replaced the browser-local list.
  - **Rules enforced by tests:** AA contrast on actual backgrounds, including glass over the lightest
    backdrop; type, spacing and motion scales; no gradients, external URLs or raw HTML in the source; glass
    only through the approved classes, with a solid fallback. The glass-class test lists `Layout.jsx` and
    `StatusBadge.jsx`, so add the hero file to it in Milestone B.
  - **Null handling:** a null decision or score shows "Not computed yet", and a real 0 stays 0.
    `HashValue` shows a value only as plain text after it matches its format (`sha256`, `commit`, `tx`,
    `address`, `uuid`); anything else shows "Invalid format" and the value is not displayed.
  - **For Milestone C:** the mock chain's `tx_hash` is `mock-tx-<hex>`, which fails the `tx` format and
    so shows "Invalid format". Decide whether to add a labeled mock format.
  - **For Milestone B:** `/findings` and `/graph` are not sanitized by the backend, so render named fields
    through `sanitizeDisplay` and never render `details` or `attributes` as a blob.
  - No backend, contract, ML, Compose or CI file changed.
  - **Verified on this machine (2026-11-09), host Node 26:**
    - `npm run lint`: clean
    - `npm test -- --run`: 240 passed, 0 failed, 0 skipped (6 files)
    - `npm run build`: succeeded; no CDN host in the build output
    - Breaking the code on purpose made tests fail in all 10 cases, including null risk as 0, null decision
      as ALLOW, no hash format check, low-contrast text, thin glass and an added gradient. Each was restored
  - **Not run:** the app in a real browser (none is installed here, so layout, responsiveness, blur and
    rendered fonts are unchecked), a frontend image build, frontend checks on Node 22 (the CI version), the
    CI workflow on GitHub, ruff and pytest (no backend file changed).

- **Milestone 0 (`GET /api/v1/scans`): complete and committed (`f97d169`).** Read-only and paginated, newest
  first (`created_at`, then `id`). `limit` defaults to 20, maximum 100; optional `offset` and `status`.
  - New: `app/schemas/scan_list.py`, `tests/api/test_scans_list.py`. Changed: `app/api/scans.py`, one
    Postgres test in `tests/integration/test_db_connection.py`.
  - The query selects only the returned columns, so ingest metadata, error details, stages and
    `source_url` are never read. Every string passes through the `/evidence` `sanitize`.
  - It reads stored `RiskDecision` rows only. `decision`, `risk_score` and `confidence` are null when no
    row exists, including an older completed scan that `/risk` has not computed yet. `GET /risk` is what
    computes such a result, and the list does not call it.
  - No migration, and no weight, threshold or other backend logic changed. `created_at` has no index,
    which is acceptable at MVP scan counts.
  - **Owner decisions (2026-11-09), also in `CLAUDE.md`:** dark theme only; glass on the header, controls,
    Scan Details hero and modal backdrop only; no Anchor button. The "truncated" note in
    `docs/design/lumora-reference.md` was wrong and is corrected.
  - **Milestone A installs, exact versions only:** `@fontsource-variable/onest` 5.3.1,
    `@fontsource/ibm-plex-mono` 5.3.0, `lucide-react` 1.70.0. Milestone C: `@dagrejs/dagre` 3.1.3 and
    `jest-axe` (dev). No external CDNs. Show what `npm install` adds.
  - **Verified on this machine (2026-11-09), Python 3.14, Compose Postgres on 5433:**
    - The exact CI ruff commands: clean. `alembic check`: no drift
    - `pytest -m "not network and not sandbox and not chain"`, including Postgres: 2422 passed, 0 failed,
      0 skipped, 72 deselected
    - Breaking the code on purpose made tests fail: no sanitizer (9), null score as 0 (5), oldest first
      (2), an extra selected column (`test_sensitive_columns_are_not_queried`). The code was then restored
  - **Not run:** `pytest -m network`, `sandbox` and `chain` (the 72 deselected; no code they cover changed),
    Python 3.12, frontend checks (frontend unchanged), the CI workflow on GitHub, and the endpoint through
    the Compose API (the running image predates it; rebuild with `docker compose build api`).

## Phase 7 progress

- **Milestone C (verification API and pipeline wiring): complete, not yet committed.**
  - New: `app/blockchain/verification.py`, `app/api/blockchain.py`, `app/pipeline/anchor_stage.py`,
    `tests/unit/test_blockchain_verification.py`, `tests/api/test_scans_blockchain.py`,
    `tests/security/test_blockchain_boundaries.py`. Endpoints: `POST /scans/{id}/anchor`,
    `GET /scans/{id}/blockchain` (stored data only) and `POST /scans/{id}/verify`.
  - **Verification** (rules in `docs/architecture.md`): VERIFIED, MISMATCH, NOT ANCHORED or UNKNOWN, always
    with a `reason`. Each field reports `stored` (the anchor row), `source_table` (the live table),
    `recomputed` (a file digest for the three hashes, otherwise the re-encoded live value) and `chain`.
    `source_table` was added so a changed `Artifact.sha256` cannot pass while the file stays intact. A ninth
    comparison covers `record_hash`.
  - **Anchor step:** runs after `mark_completed`, through a guard so that it cannot fail the scan. With
    `BLOCKCHAIN_ANCHOR_ON_SCAN=false` (the default) the `anchor` stage is `skipped`. Tx hashes stay out of
    stage entries because the `/evidence` sanitizer would redact them.
  - **Compose:** named volume `workspace:/app/workspace`, `api` only.
  - **Different from the approved list:** the volume assertion and its negative cases are in
    `tests/unit/test_sandbox_hardening.py`, not `test_compose_settings.py`, because that is where the real
    hardening test lives. `tests/conftest.py` also gained `write_scan_evidence`. No weight or threshold changed.
  - **Verified on this machine (2026-11-09), Compose Postgres on 5433:**
    - The exact CI ruff commands: clean. `alembic check`: no drift (no migration in this milestone)
    - `pytest -m "not network and not sandbox and not chain"`, including Postgres: 2386 passed, 0 failed,
      0 skipped, 72 deselected, on Python 3.14 and 3.12.16 (disposable API-image container)
    - `pytest -m chain` on the Compose chain and Postgres: 30 passed, 0 failed, 0 skipped, on 3.14 and 3.12.16.
      Covers tampering on the real chain and a reset that removes the anchor's block (`evm_snapshot`/`evm_revert`)
    - `npx hardhat test`: 32 passing. `check-abi.js`: match (17 entries)
    - Breaking four verifier rules on purpose made 41, 5, 3 and 3 tests fail; the code was then restored
    - **Compose end-to-end, benign fixture, real Syft and OSV, test key in a shell variable only:** NOT ANCHORED
      before anchoring; anchored (`web3`, REVIEW, 0.483452); second anchor 409; VERIFIED; still VERIFIED after
      recreating the API container; MISMATCH (`artifact_hash`, `record_hash`) after editing one file; VERIFIED
      once restored; UNKNOWN (`chain_unavailable`) with Hardhat stopped. The scan, its files and the Hardhat
      container were removed afterwards, and the API was recreated on default settings. This checks the wiring on
      one benign fixture and is not a detection result.
  - **Not run:** `pytest -m network` and `pytest -m sandbox` (the other 42 deselected), frontend checks
    (frontend unchanged), the CI workflow on GitHub. A wrong chain ID was tested with a fake web3 only, because
    the local chain is always 31337.

- **Milestone B (web3.py adapter and anchoring): complete and committed (`21a89f7`).** The service layer
  only; Milestone C added the endpoints and pipeline step.
  - New: `app/blockchain/{base,encoding,web3_provider,mock,anchoring}.py`, `abi.json`,
    `app/schemas/blockchain.py`, migration `0006` (`blockchain_evidence`), `contracts/scripts/check-abi.js`,
    four `tests/unit/test_blockchain_*.py` files, `tests/integration/test_chain_live.py` (marker `chain`,
    `PROVENANCEX_CHAIN_TESTS=1`). Pin: `web3==8.0.0`. Settings: `BLOCKCHAIN_PROVIDER` (default
    `disabled`), `BLOCKCHAIN_ANCHOR_ON_SCAN` (default `false`), `BLOCKCHAIN_TIMEOUT_SECONDS`.
  - **Record:** hashes, status, version and mock flags come from `build_evidence`. Score, decision and
    timestamp come from the stored `RiskDecision`, because `/evidence` has neither score nor decision.
    The timestamp is `RiskDecision.created_at` in UTC seconds, not the block time.
  - **Record hash:** `provenancex-anchor-v1`, SHA-256 of canonical JSON of the eight encoded values.
    Off-chain only. Golden vectors in the tests were computed with `sha256sum`.
  - **Refusals (nothing is sent):** unfinished scan, no decision, missing artifact hash, any hash failing
    `^[0-9a-f]{64}$` (also all zeros, a trailing newline, or a sanitizer redaction marker), mock evidence
    on the real chain (`contains_mock_evidence`, which covers stages, findings, components and
    provenance), provider disabled, non-local RPC, chain id other than 31337, no contract code, a key that
    is not the anchorer.
  - **Send sequence:** a `pending` row is committed first, then an existing on-chain anchor is adopted if
    identical, otherwise one is sent and all eight fields are read back before `confirmed`. A failed send
    becomes `failed` and can be retried. A `pending` row older than 3 x `BLOCKCHAIN_TIMEOUT_SECONDS` counts
    as abandoned. A scan can be anchored only once.
  - **Mock chain:** `source="mock"`, `mock-tx-...` ids, block fields null, process-wide ledger lost on
    exit. It may hold mock evidence, labeled. Selected only by `BLOCKCHAIN_PROVIDER=mock`.
  - **Added within the approved scope:** columns `error_code` and `reserved_at`, an `anchor_invalid_record`
    error for a bad score, version, timestamp or id, a 256-anchor read limit, and an HTTP session that ignores
    proxy variables and does not follow redirects.
  - **Verified on this machine (2026-11-09), Compose Postgres on 5433:**
    - The exact CI ruff commands: clean
    - `alembic upgrade head`, `downgrade 0005` (table removed), `upgrade head`, `alembic check`: OK, no drift
    - `pytest -m "not network and not sandbox and not chain"`, including Postgres: 2236 passed, 0 failed,
      0 skipped, 55 deselected, on Python 3.14 and on Python 3.12.16 (disposable API-image container)
    - `pytest -m chain` against the Compose chain and Postgres, freshly deployed contract: 13 passed, 0 failed,
      0 skipped, on Python 3.14 and 3.12.16. The node's test key was held only in a shell variable.
    - `npx hardhat test`: 32 passing. `check-abi.js`: match (17 entries); a modified ABI exited 1
    - `docker compose build hardhat api` and `up --wait api`: healthy, `web3` 8.0.0 in the image, `alembic
      current` = `0006 (head)`, provider `disabled`, on-scan `false`, RPC `http://hardhat:8545`
  - **Not run:** `pytest -m network` and `pytest -m sandbox` (the other 42 deselected; no code they cover
    changed), frontend tests (frontend unchanged), the CI workflow on GitHub.
  - **Limitation:** one web3 process lock serializes sends, so several API workers sharing one key could
    collide on a nonce. Such a send fails and is recorded as `failed`, then can be retried.

- **Milestone A (contract and Hardhat): complete and committed (`a11e58a`).** At that point nothing
  in `backend/app` used the chain.
  - New: `contracts/` Hardhat project (`contracts/ProvenanceEvidence.sol`, `test/`, `scripts/deploy.js`,
    `hardhat.config.js`, `package.json`, `package-lock.json`, `Dockerfile`, `.dockerignore`),
    `backend/tests/unit/test_compose_chain.py`, Compose services `hardhat` and `hardhat-deploy`
    (profile `chain-deploy`), a `contracts` CI job, `BLOCKCHAIN_HOST_PORT`.
  - **Encoding (see `contracts/README.md`):** `riskScore` is a `uint32` score x 1,000,000, with
    `NO_SCORE = type(uint32).max` for null. Zero `bytes32` means an absent BOM or provenance hash.
    `artifactHash` must be non-zero. Decisions are `ALLOW=1`, `REVIEW=2`, `BLOCK=3`.
  - **Append-only, deployer-only:** `anchor` is the only state-changing function, and only the
    deployer can call it. Each anchor emits one `EvidenceAnchored` event.
  - **Decisions (user, 2026-11-09):** Compose workspace as a named volume, missing files give UNKNOWN;
    zero marker plus `missing_evidence` for an absent BOM or provenance hash; Hardhat 2.29.1.
  - **Different from the approved plan:** `@nomicfoundation/hardhat-toolbox` is not installed. It needs
    18 peer packages, most unused here. Only `hardhat-ethers` and `hardhat-chai-matchers` are used.
  - **Hardhat and the image:** Node 22 by digest (the host's Node 26 was not used). `npm ci
    --ignore-scripts`. The contract is compiled at build time, so both services run read-only and the
    deploy uses `--no-compile`.
  - **Verified on this machine (2026-11-09), Compose Postgres on 5433:** see README "Local chain" for
    how to repeat these.
    - The exact CI ruff commands: clean
    - `npx hardhat test` in the Node 22 image: 32 passing, both with a compile and on a read-only
      filesystem with `--no-compile`
    - `pytest -m "not network and not sandbox"`, including Postgres, on Python 3.14: 2053
      passed, 0 failed, 0 skipped, 42 deselected (19 new tests in `test_compose_chain.py`)
    - `alembic current` = `0005 (head)` (no migration in this milestone)
    - Compose: `hardhat` healthy, user `node`, read-only root, all capabilities dropped, port bound to
      127.0.0.1. A deploy with no key failed with a clear message. A deploy with the node's test key
      (held only in a shell variable) returned a contract address on chain 31337. A non-local
      `BLOCKCHAIN_RPC_URL` was refused.
  - **Follow-up checks after Milestone A (2026-11-09), no code changed, no failures:**
    - `PROVENANCEX_NETWORK_TESTS=1 pytest -m network`, Python 3.14: 7 passed, 0 failed, 0 skipped
    - `PROVENANCEX_SANDBOX_TESTS=1 pytest -m sandbox`, Python 3.14, real containers: 35 passed,
      0 failed, 0 skipped
    - Frontend on host Node 26: `npm run lint` clean; `npm test -- --run` 16 passed; `npm run build`
      succeeded
    - Python 3.12.16, disposable container from `provenancex-api:latest` (repo mounted read-only, only
      pytest added), Compose Postgres on 5433: `pytest -m "not network and not sandbox"` 2053 passed,
      0 failed, 0 skipped, 42 deselected; `pytest -m network` 7 passed, 0 failed, 0 skipped
  - **Still not run:** `pytest -m sandbox` on Python 3.12 (the API image has no Docker, by design),
    frontend checks on Node 22 (the CI version), the CI workflow on GitHub (including the new job).
  - **Known issue:** `npm audit` reports 23 advisories (11 low, 4 moderate, 8 high) in the dependency
    tree of the Hardhat dev tooling. The tooling runs only locally and the chain is bound to loopback.
    Not triaged or fixed; `npm audit fix` was not run.
  - **Limitation:** the chain runs in memory, so a restart erases all anchors and the contract.
    Milestone C must report this as UNKNOWN (`chain_state_lost`).

## Phase 6 progress

- **`GET /api/v1/scans/{id}/evidence`: complete and committed.**
  - New: `app/api/evidence_view.py`, `app/schemas/evidence.py`, `tests/api/test_scans_evidence.py`,
    and a Postgres test in `tests/integration/test_db_connection.py`. `app/schemas/risk.py` gained
    `no_result_training_label`. The README and `docs/architecture.md` are updated.
  - `/evidence` is read-only and never computes risk. Findings and components page separately, at most
    200 per page, default 50. Group counts cover all rows, not just the page.
  - **Allowlisted fields:** left out are finding `details`, component `properties`, provenance check
    `data`, stage error `details`, `error_details`, `ingest_metadata` and stage file names.
  - **Sanitizer:** every string then passes through `sanitize`, which redacts host paths and
    secret-like values and cuts strings at 1024 characters. `sanitized` reports the counts, so a
    redacted name or title is visible as such. It is pattern-based: it reduces leakage from
    artifact-derived text and cannot recognize every possible secret.
  - No weight or threshold changed.
  - **Verified on this machine (2026-11-09), Compose Postgres on 5433:**
    - The exact CI ruff commands: clean. `alembic check`: no drift (no migration was needed)
    - `pytest -m "not network and not sandbox"`, including Postgres, on Python 3.14: 2034 passed,
      0 failed, 0 skipped, 42 deselected
    - Removing the redaction patterns at runtime made 13 tests fail, including the leak test
    - Rebuilt Compose API (Python 3.12), on stored real scans at the maximum page size: Flask 55,667
      bytes (60 findings, 117 components), Hugging Face 12,129 bytes (4 findings, 0 components). Both
      had 44 features, the model version and the synthetic label, with 0 redactions and no host path.
      An unknown scan returned 404.
  - **Not run:** `pytest -m network`, `pytest -m sandbox` (the 42 deselected), frontend tests, the
    pytest suite on Python 3.12, the CI workflow on GitHub, and a scan with the sandbox enabled.
  - **Hardening test (added after Milestone C):** the no-docker-socket test also rejects `tmpfs`,
    `volumes_from`, `devices`, `privileged`, `cap_add`, and `host` for `network_mode`, `pid` or `ipc`,
    with negative cases. It reads the base `docker-compose.yml` only.

- **Milestone C (risk stage, parity, ML in the API image): complete and committed.**
  - New: `app/pipeline/risk_stage.py`, `tests/api/test_feature_parity.py`,
    `tests/unit/test_compose_settings.py`. The `risk` stage runs after the sandbox in both pipelines
    and never fails the scan. `GET /risk` still computes a result for older scans, or when the
    stage failed.
  - **Comparison snapshot:** saved in `stages.risk.comparison_snapshot` (`config_sha256`,
    `max_centrality`, `attestation_present`, `edge_count`). Edges are not copied, because they are
    already in `graph_edges`. This replaces the Milestone B limitation: `config_changed` now has a
    value on a later scan, once the prior scan has a saved digest. A prior scan from before this
    change has none, so its next scan still reports `not_determinable`.
  - **Model version:** stored on each decision as `models-sha256:<16 hex>`, over every model,
    threshold and preprocessing file (replaces Milestone B's Random Forest-only `rf-sha256:`). It
    is null when no model was used.
  - **Python 3.12 check** (throwaway `python:3.12-slim`, real models, 301-row fixed matrix, same
    library versions as 3.14, no retraining): XGBoost and Isolation Forest identical. Random Forest
    differed by at most 1.1e-16 with the saved `n_jobs=-1`, but 8 repeat runs in one process also
    gave 8 different results on either version, so that is parallel averaging. With `n_jobs=1` the
    3.14 and 3.12 outputs are bit-for-bit identical, and no flag changed in any run. Decision (user,
    2026-11-09): treat this as passing, and set `n_jobs=1` on the loaded forest at runtime, in
    memory only. The model files are unchanged.
  - **Feature parity test:** 48 artifact states across software (GitHub, upload), model
    (Hugging Face, upload) and LoRA run through the real pipelines. Only external tools are replaced,
    using the generator's own SBOM, advisories and trace. Features, null reasons and the
    `transform_features` matrix all match the generator. A mutation that ignored the saved config
    digest made it fail.
  - **Image and env:** `requirements-ml.txt` is installed in the API image; `ml/models` is mounted
    read-only; 33 missing settings were added to the Compose `api` environment. A new test keeps
    Compose, `.env.example` and `Settings` in step; the blockchain settings are left for Phase 7.
  - **Existing tests changed:** two stage-set tests now include `risk`, and
    `test_compose_api_has_no_docker_socket` now allows exactly the one read-only models mount
    instead of no volumes.
  - **Compose API, Python 3.12, models loaded, sandbox disabled, real SBOM/OSV/Hugging Face:**

    | Scan | /risk | risk_score | Decision | Confidence | ML probability | CVSS max |
    |---|---|---|---|---|---|---|
    | github.com/pallets/flask | computed | 0.700 | REVIEW | 0.79 HIGH | 0.987 | 8.8 |
    | Python fixture ZIP | computed | 0.483 | REVIEW | 0.63 MEDIUM | 0.972 | 5.3 |
    | hf tiny-random-gpt2, first scan | computed | 0.306 | REVIEW (insufficient evidence) | 0.594 MEDIUM | 0.520 | null |
    | hf tiny-random-gpt2, rescan | computed | 0.301 | ALLOW | 0.606 MEDIUM | 0.465 | null |

    All four: `ml_status=available`, SHAP available, stored `model_version`, labeled synthetic. These
    are wiring checks on a handful of artifacts, not detection results.
  - **Observed, not acted on** (no parameter was changed):
    - The re-check of Milestone A's confidence finding is above. The same model went from REVIEW to
      ALLOW only because `config_changed` became known, moving confidence from 0.594 past the 0.60
      minimum.
    - That ALLOW has its vulnerability and behavioral layers unevaluated: the repo has no pinned
      dependencies and the sandbox was off. The vulnerability layer is not required for AI artifacts
      under the current hand-set policy.
    - The Random Forest gave 0.97 to 0.99 on two benign projects with real advisories. That output
      means "not benign" under the synthetic labels, which include vulnerable, and is not malice.
  - **Dataset:** `generate_records(200, 42)` after the generator refactor reproduced the recorded
    `dataset_sha256` (`d01885bf...`).
  - **Verified on this machine (2026-11-09), Compose Postgres on 5433:**
    - The exact CI ruff commands: clean
    - `pytest -m "not network and not sandbox"`, including Postgres, on Python 3.14: 1961 passed,
      0 failed, 0 skipped, 42 deselected
    - `alembic current` = `0005 (head)` on host and in the API container; `alembic check`: no drift
    - `docker compose build api` + `up --wait`: healthy. All 60 Compose variables match `Settings`
      inside the container.
  - **Not run:** `pytest -m network`, `pytest -m sandbox` (the 42 deselected), frontend tests, the
    pytest suite on Python 3.12, a `frontend` image build, the CI workflow on GitHub, and a scan with
    the sandbox enabled.
- **Milestone B (SHAP, RiskDecision, `/risk`): complete and committed.**
  - New: `app/risk/model_runtime.py`, `explain.py`, `service.py`, `app/schemas/risk.py`, migration
    `0005` (`risk_decisions`), `GET /api/v1/scans/{id}/risk`, the `shap==0.54.1` pin,
    `tests/unit/test_risk_explain.py`, `tests/api/test_scans_risk.py`, and new Postgres tests in
    `tests/integration/test_db_connection.py`.
  - **shap compatibility check: passed** on Python 3.14 with shap 0.54.1 and scikit-learn 1.9.1,
    on the saved 300-tree forest loaded through `load_bundle`: no warnings, output shape `(n, 79, 4)`,
    maximum additivity error against `predict_proba` about 2e-15.
  - Models load only through `load_bundle`, and a test checks the `app/risk` imports. ML packages
    are imported lazily, so without them the API still starts and reports "ML model unavailable".
  - SHAP explains the Random Forest probability of any non-benign class, not the ProvenanceX risk.
    A feature's factor is the sum over its encoded columns. Factors are marked `evaluated=false`
    with a `null_reason` when the feature had no value.
  - **Design decisions to review:**
    - The result is computed on the first `GET /risk` of a completed scan, then stored and reused.
      It is not a pipeline stage yet, and a stored result does not change if models are retrained.
    - Live comparison features are rebuilt from the database against the prior scan the provenance
      stage used. `version_consistency` reads the kept workspace, and is null if it is gone.
    - Dataset scans report ML unavailable, because the models were trained only on software, model
      and LoRA records.
  - **Limitation:** `config_changed` is always null (`not_determinable`) on live scans, because
    config digests are not persisted.
  - **Beyond the approved list:** `app/ml/preprocessing.py` gained `transform_features` and a public
    `feature_columns`, so a live scan can be encoded without a labeled `FeatureRecord`. Training
    behavior is unchanged.
  - **Verified on this machine (2026-11-09), Python 3.14, Compose Postgres on 5433:**
    - The exact CI ruff commands (`backend/` and `ml/scripts/`): clean
    - `alembic upgrade head`, `downgrade 0004` (table removed), `upgrade head`, `alembic check`: OK,
      no drift
    - `pytest -m "not network and not sandbox"`, including the Postgres tests: 1945 passed, 0 failed,
      0 skipped, 42 deselected
    - Smoke run of `/risk` with the saved models on the benign fixture ZIP, SQLite and mock SBOM/OSV:
      200, `computed`, SHAP available. It checks the wiring only and is not a detection result.
  - **Not run:** `pytest -m network`, `pytest -m sandbox` (the 42 deselected), frontend tests, Docker
    builds, any test on Python 3.12, and `/risk` through the Compose API.
- **Milestone A (fusion and policy): complete and committed.**
  - New: `app/risk/policy_config.py`, `types.py`, `layers.py`, `fusion.py`, `policy.py`,
    `sensitivity.py`, `ml/scripts/fusion_sensitivity.py`, the generated
    `ml/reports/fusion_sensitivity.{md,json}`, `tests/risk_helpers.py` and five `test_risk_*` files.
    Design and the ML trade-off are in `docs/architecture.md`. Pure logic; not wired into scans.
  - Weights, thresholds and hard rules are **hand-set research parameters, not tuned or validated**.
  - **Added beyond the plan:**
    - ML is limited to the rule-only decision band, so ML cannot change the decision in either
      direction, for any weights. The approved numeric cap alone would not have guaranteed that.
    - `risk_score` is null when no rule layer can be scored, so Phase 7 must handle a null score.
    - `sensitivity.py`, its script and `risk_helpers.py` were not in the original file list.
  - **Sensitivity (synthetic validation split, 348 records, analysis only):** baseline ALLOW 92,
    REVIEW 173, BLOCK 83. Each layer weight changed at most 3 decisions at +/-20%; `max_blend`
    changed 12 at 0.8x and 14 at 1.2x; ML weights changed none, by construction. The test split was
    not used. The result is in a separate report because `evaluation_report.md` is generated.
  - **Observed, not acted on:** with the sandbox off, a first scan using test-helper evidence
    scored confidence 0.67 when `revision_pinned` and `version_consistency` were known (ALLOW), and
    0.59 when they were not, as is likely for an upload (REVIEW). Measured on helper inputs, not
    real scans. Re-check in Milestone C.
  - **Verified on this machine (2026-11-09), Python 3.14:**
    - The exact CI ruff commands (`backend/` and `ml/scripts/`): clean
    - **Milestone A total: 1906 passing, 0 failed, 0 skipped, 42 deselected**, from two runs:
      - `pytest -m "not network and not sandbox"` without Postgres: 1899 passed, 7 skipped
      - `pytest tests/integration/test_db_connection.py` against Compose Postgres on 5433: those
        7 passed, 0 skipped
    - The PostgreSQL tests need the `DATABASE_URL` documented in this file (under "Verified on this
      machine"), because the local `.env` does not set the database user or password. Without it
      they skip.
    - `fusion_sensitivity.py`: ran end to end and wrote the report
  - **Not run:** `pytest -m network`, `pytest -m sandbox`, frontend tests, Docker builds, and any
    test on Python 3.12.
  - **Test count:** Milestone A added 136 tests to the 1770 recorded for Phase 5: 130 in the
    `test_risk_*` files, plus 6 because the unsafe-loader security test
    (`test_application_code_has_no_unsafe_loader`) runs once per application file and Milestone A
    added six risk modules. Confirmed by diffing `pytest --collect-only` against commit `203dab8`.

## Phase 5 progress

- **Milestone C (evaluation): complete and committed.**
  - New: `app/ml/evaluation.py`, `baselines.py`, `ablation.py`, `reporting.py`,
    `ml/scripts/evaluate_models.py`, and the generated `ml/reports/evaluation_report.{md,json}`.
    Every number in those reports is written by the script from a real run; see them for results.
  - **The data is synthetic, and the results do not measure real-world detection.**
  - No threshold or hyperparameter changed after seeing test results. Retraining experiments pick
    thresholds on their own validation split by the Milestone B procedure. Retraining at seed 42
    reproduced the saved thresholds within 1e-9. An exact comparison failed on floating-point noise
    from parallel tree averaging.
  - **Findings to carry forward (figures in the report):**
    - Random Forest flags far more benign records when the hash comparison is missing. The report
      measures this; the base-rate explanation is not proven.
    - Isolation Forest is near chance on this data, so it should not carry much fusion weight.
    - Unseen tampering is detected much worse than seen tampering (leave-one-recipe-out).
    - A flag-everything detector already scores high F1 here, because most records are not benign.
    - The expected strong rules result on the vulnerable class was only partly borne out: the label
      implies `vulnerable_count` > 0, but the reverse holds for only about half of the records.
  - **Verified on this machine (2026-11-08), Compose Postgres on 5433:**
    - The exact CI ruff command (`backend/` and `ml/scripts/`): clean
    - `pytest -m "not network and not sandbox"`: 1770 passed, 0 failed, 0 skipped, 42 deselected
    - `evaluate_models.py`: ran end to end and wrote the report
  - **Not run:** `pytest -m network`, `pytest -m sandbox` (the 42 deselected), frontend tests, Docker
    builds, and any test on Python 3.12.
  - Beyond the approved list: `tests/ml_helpers.py`, a flag-everything reference row, and a
    false-positive breakdown by hash comparison, which was added after reading test results. It
    only reports; it changed no model or threshold.
- **Milestone B (training): complete and committed.**
  - New: `app/ml/preprocessing.py`, `training.py`, `artifacts.py`, `ml/scripts/train_models.py`.
    CI ruff now covers `backend/` and `ml/scripts/`.
  - Trained with `--seed 42` on 1629 train records (409 benign for Isolation Forest), with 348
    validation records used for thresholds. 79 columns. The five no-source features were dropped as
    all-null. Models are in git-ignored `ml/models/`; regenerate them with the script.
  - Thresholds, chosen on validation: RF 0.4488, XGBoost 0.2733, Isolation Forest 0.5987. The
    validation F1 and FPR stored beside them justify the threshold only. They are synthetic and
    were optimized on those same records, so they are **not evaluation results**.
  - The test split was not read: test rows are dropped unparsed, and a test covers this.
  - skops loads with an explicit list (only `sklearn.tree._tree.Tree` beyond its defaults). Bytes are
    hashed and parsed from one read. Library versions must match the manifest.
  - **Verified on this machine (2026-11-08), Compose Postgres on 5433:**
    - The exact CI ruff command (`backend/` and `ml/scripts/`): clean
    - `pytest -m "not network and not sandbox"`: 1701 passed, 0 failed, 0 skipped, 42 deselected
    - `train_models.py`: trained, saved, then reloaded through `load_bundle`
  - **Not run:** `pytest -m network`, `pytest -m sandbox` (the 42 deselected), frontend tests, Docker
    builds, and any test on Python 3.12. Artifacts were built on Python 3.14; loading them on 3.12
    in Phase 6 is untested. The CI workflow change has not run on GitHub yet.
  - **Limitations:** the manifest is unsigned, so `ml/models/` must stay trusted. The API image does
    not include the ML packages yet (Phase 6). The Makefile `lint` target still covers only `backend/`.
- **Milestone A (dataset generation): complete and committed.**
  - Python 3.14.4 wheel check passed for numpy 2.5.4, scikit-learn 1.9.1, xgboost 3.4.1, skops 0.16.0
    and shap 0.54.1 (install only). The same versions have Python 3.12 wheels (download checked).
    `backend/requirements-ml.txt` pins numpy, scikit-learn, xgboost and skops. shap is not installed yet.
  - New: `app/ml/feature_schema.py`, `features.py`, `comparison.py`, `app/ml/dataset/`,
    `ml/scripts/generate_dataset.py`, seeds in `tests/fixtures/ml/`.
  - `features.py` reads the `Scan.stages` shape for reuse in Phase 6. It is not wired into the pipeline.
  - Generated with `--families 200 --seed 42`: 2333 records, labels {'benign': 585, 'provenance_weak': 578, 'suspicious': 785, 'vulnerable': 385},
    splits {'test': 356, 'train': 1629, 'validation': 348}, `dataset_sha256` `d01885bf8a1517923f43c1511fae23589fdabf14cbb72099d1a370d2f8388ab8`. Output is in git-ignored `ml/data/`.
  - `malicious_known_bad` has no records, so the models can make no malware-detection claim.
  - 340 records keep their label although the evidence was not observed
    (`label_evidence_observable=false`). They are expected to be missed.
  - Nothing is executed and the sandbox is not used. SBOMs, `SYNTH-*` advisories and traces are
    generated; the real parsers process the files, SBOMs and traces.
  - **Verified on this machine (2026-11-08), Compose Postgres on 5433:**
    - `ruff check` / `ruff format --check` (backend and `ml/scripts`): clean
    - `pytest -m "not network and not sandbox"`: 1614 passed, 0 failed, 0 skipped, 42 deselected
  - **Not run:** `pytest -m network`, `pytest -m sandbox` (the 42 deselected; no code they cover
    changed), frontend tests, Docker builds. Tests ran on Python 3.14 only, not 3.12.
  - **Added after auditing the generated data, beyond the approved list:**
    - Prior-scan availability is drawn independently of the label. Its null rate had ranged from 13%
      to 43% by label, which leaked the label.
    - `docs_update` (benign) and `vulnerable_new_release` variants, `hash_changed_same_commit` and
      `revision_pinned` features, and `Recipe.needs_prior`.
    - Traces use a public address literal, because the parser ignores reserved ranges. It is only
      parsed, never contacted.
  - **Limitations:** see `ml/README.md`. `version_consistency` nulls still vary by label (about 32%
    for provenance_weak, 43% for the others), because the mismatch recipe needs a release tag. The
    benign/tampered overlap is designed, not observed.

## Phase 4 progress

- **Milestone C (Docker sandbox) and post-review hardening: complete and committed.**
  - New optional stage `sandbox` (pipeline step 10). `SANDBOX_PROVIDER=disabled` is the default;
    `mock` is labeled `source="mock"` and is never a fallback.
  - Build the image: `docker build -t provenancex-sandbox:0.1.0 docker/sandbox`. It uses a base image
    pinned by digest, a pinned strace, and no secrets.
  - Targets: software runs a root `setup.py`. Models load pickles with stdlib `pickle` and import
    `auto_map` modules. npm scripts are not run.
  - `strace` works under the full flag set with no `SYS_PTRACE` and no seccomp change.
  - **After the security review, these fixes were added:**
    - Container stderr is byte-capped like stdout (`SANDBOX_MAX_STDERR_KB`).
    - The stage is `partial`, with `incomplete_reasons`, when a target is killed (exit -9) or the
      trace has malformed lines.
    - `SANDBOX_MAX_CONCURRENT` limits concurrent runs per API process, with
      `SANDBOX_QUEUE_TIMEOUT_SECONDS`; a run that cannot get a slot is `unavailable`.
    - The supervisor reports the kernel's `oom_kill` count, used by the memory test.
  - **Rule for Phase 6:** treat a sandbox `error` or `partial` as "not evaluated / lower confidence",
    never as quiet.
  - **Verified on this machine (2026-11-08), Compose Postgres on 5433, after the fixes:**
    - `ruff check` / `ruff format --check` (backend and `docker/sandbox`): clean
    - `pytest -m "not network and not sandbox"`: 1477 passed, 0 skipped
    - `PROVENANCEX_SANDBOX_TESTS=1 pytest -m sandbox`: 35 passed, in real containers. This covers a
      probe that walks `/proc/self/mountinfo`, blocked paths (IPv6, `AF_VSOCK`, `AF_PACKET`, raw
      sockets, user namespaces, `io_uring`, `ptrace` on PID 1), 6 negative controls, a required
      OOM kill at the default 512 MB and 128 pids, and `setsid` detach under the timeout.
  - **Verified before the fixes, not re-run after them:** `pytest -m network` 7 passed; `docker compose
    build` and the `sandbox-image` profile build OK; API on the host with `SANDBOX_PROVIDER=docker` gave
    `completed` with 0 malformed lines; Compose API gave `unavailable`. The running Compose API image
    predates these fixes.
  - **Limitations (details in architecture.md):**
    - **Do not run real malware through this sandbox on the host.**
    - The sandbox needs the API on the host with Docker (`unavailable` in Compose).
    - Observed code can kill the tracer, rewrite `/trace` and write to the bundle through `/proc/1/fd`.
      A careful rewrite of the trace can still look complete.
    - `/dev/mqueue` is writable, in-memory and private to the container.
    - A kernel or container escape is outside this boundary. The sandbox runs as the workspace
      owner's uid (never 0). That user is in `docker` and `sudo`, with WSL interop and `/mnt/c`
      available, so an escape can lead to root in WSL and to Windows files.
    - The host API has Docker access, which is root-equivalent, while it parses untrusted input.
    - Failures of `docker kill` and `docker rm -f` are only logged. The image is trusted by tag.
    - Live sandbox tests do not run in CI.
  - Also changed outside the plan's file list: the `network` and `sandbox` test gates now check real
    pytest markers, because keyword matching skipped a unit test whose parameter was `"sandbox"`.
- **Milestone B (telemetry parser): complete and committed.**
  - `app/scanners/sandbox/telemetry.py` parses `provenancex-trace-v1` bundles into `network_count`,
    `process_count`, `file_write_count`, `syscall_count`, `external_destination_count` and
    `resource_spike`. `behavior_findings.py` builds `category="behavioral"` findings with no CVSS.
  - Parser and findings, wired into the pipeline by Milestone C. Its unit-test traces are
    hand-written and labeled synthetic.
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

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
- **Phase 6 (fusion, policy, SHAP, explanation API): in progress.** Milestone A is complete and
  awaiting commit. Milestones B and C are not started. Details are under "Phase 6 progress".

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

**Phase 6 Milestone B (SHAP, explanation API, RiskDecision):** not started. Wait for the go-ahead.
The approved file list is B: `app/risk/model_runtime.py`, `explain.py`, `service.py`,
`app/schemas/risk.py`, migration `0005`, the `/risk` route, the `shap` pin and tests.

Notes for the rest of Phase 6:
- Do not adjust any weight, threshold or hyperparameter after looking at test-split results.
- Null evidence must lower confidence and never read as clean. See the false-positive finding below.
- Loading artifacts built on Python 3.14 from the 3.12 API image is untested. Milestone C needs
  Docker Desktop running, because this machine has no Python 3.12. If the check fails, stop and ask.
- Check `shap` 0.54.1 against scikit-learn 1.9.1 first in Milestone B. If incompatible, stop and ask.

## Phase 6 progress

- **Milestone A (fusion and policy): complete, awaiting commit.**
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

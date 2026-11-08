# ProvenanceX Architecture

ProvenanceX is a defensive supply-chain security platform for software and AI/ML artifacts.
It collects multi-layer evidence, produces an explainable 0–1 risk score and an
ALLOW / REVIEW / BLOCK decision, and anchors compact evidence on a local blockchain.

`CLAUDE.md` is the binding contract; `docs/spec.md` gives background detail.

## 1. Components

```
┌──────────────┐  HTTP/JSON  ┌─────────────────────────────┐   SQL   ┌────────────┐
│ React (Vite, │ ──────────> │ FastAPI  /api/v1            │ ──────> │ PostgreSQL │
│ plain JS)    │             │  ├─ api/      (routers)     │         └────────────┘
└──────────────┘             │  ├─ pipeline/ (orchestrator)│  web3.py ┌──────────┐
                             │  ├─ security/ (input safety)│ ───────> │ Hardhat  │
  GitHub Actions gate ─────> │  ├─ scanners/ graph/ ml/    │          └──────────┘
  (Phase 9)                  │  ├─ risk/  blockchain/      │  Docker  ┌──────────┐
                             │  └─ db/  core/              │ ───────> │ Sandbox  │
                             └─────────────────────────────┘          └──────────┘
```

| Component | Tech | Responsibility |
|---|---|---|
| API | FastAPI + Pydantic | Input validation, scan endpoints, structured errors |
| Pipeline | Python module | Runs the 22 steps in CLAUDE.md's fixed order |
| Security | `app/security` | URL allowlist, SSRF checks, archive validation, size/count limits |
| Scanners | `app/scanners` | SBOM (Syft/CycloneDX), AI-BOM, OSV/NVD, provenance, static, sandbox |
| Graph | NetworkX | Dependency and model-lineage graphs, graph features |
| ML | scikit-learn, XGBoost, SHAP | Feature vectors, RF (primary), XGB (comparison), Isolation Forest, explanations |
| Risk | `app/risk` | Configurable cross-layer fusion and policy |
| Blockchain | Solidity + Hardhat + web3.py | Anchor and verify compact evidence |
| DB | PostgreSQL, SQLAlchemy 2, Alembic | Persist all evidence and decisions |
| Frontend | React, react-router | Security dashboard (styled in Phase 8) |

## 2. Pipeline (fixed order)

```
1 receive → 2 workspace → 3 sha256 → 4 SBOM (software) / 5 AI-BOM (model)
→ 6 graph → 7 OSV/NVD → 8 provenance → 9 static → 10 sandbox (optional)
→ 11 features → 12 RF/XGB → 13 IsoForest → 14 fusion → 15 risk_score
→ 16 policy → 17 SHAP → 18 persist → 19 anchor → 20 verify API
→ 21 React view → 22 CI gate
```

Each stage writes structured evidence, which keeps every part of the final score traceable.
CVSS, the ML probability, the anomaly score and the ProvenanceX risk score stay **separate, labeled values**.

## 3. Trust boundaries

1. **Every artifact is untrusted.** Downloads, uploads, archives and model files are only parsed, never executed on the host. `pickle.load`, `torch.load` and `trust_remote_code` are forbidden. Pickles are inspected with `pickletools` opcode parsing.
2. **Input boundary (`app/security`):**
   - URLs: https only, allowlist limited to `github.com` and `huggingface.co`, and private, loopback and link-local IPs are rejected after DNS resolution.
   - Git clones: shallow, no submodules, hooks disabled, with size and time limits.
   - Archives: path traversal, absolute paths, symlinks and decompression bombs are rejected, and `MAX_ARTIFACT_SIZE_MB` and `MAX_ARTIFACT_FILES` are enforced.
3. **Sandbox boundary:** dynamic analysis runs only in a disposable Docker container with these restrictions:
   - no network by default, and a read-only artifact mount
   - non-root user, `cap_drop: ALL` and `no-new-privileges`
   - pids, memory and CPU limits, plus a hard timeout
   - no Docker socket mount
4. **Chain boundary:** only these fields go on-chain: `artifact_id, artifact_hash, bom_hash, provenance_hash, risk_score, decision, scanner_version, timestamp`. Everything else stays off-chain.
5. **Secrets:** environment variables only. `.env.example` holds placeholders, and the chain key is a local Hardhat dev key.

## 4. Adapters and mocks

Each external integration sits behind a small interface (`typing.Protocol`) and has two providers:

| Integration | Real provider | Mock provider |
|---|---|---|
| SBOM | Syft CLI → CycloneDX JSON (`app/scanners/sbom/syft.py`) | recorded Syft SBOM (`app/scanners/sbom/mock.py`) |
| Vulnerabilities | OSV querybatch + `/v1/vulns/{id}` (`app/scanners/vulns/osv.py`), NVD CVE API for missing CVSS only (`nvd.py`) | recorded real OSV records (`app/scanners/vulns/mock.py`) |
| Hugging Face | Hub API + capped, verified download (`app/scanners/hf/client.py`) | synthetic benign fixture repo (`app/scanners/hf/mock.py`) |
| Sandbox | Docker CLI as an argv list (`app/scanners/sandbox/docker_provider.py`) | synthetic bundle (`app/scanners/sandbox/mock.py`) |
| Chain | web3.py → Hardhat | in-memory ledger |

Mock output always carries `source="mock"`. The API returns that tag (`is_mock`, `contains_mock`)
and the UI shows it. Providers are chosen with env vars (`SBOM_PROVIDER`, `VULN_PROVIDER`, `HF_PROVIDER`) and
built by `app/pipeline/providers.py`. **A mock is never a silent fallback.** If a real tool or
service is missing, the stage is recorded as `unavailable`.
When no trained model exists, the pipeline uses the rule-based score and reports
`"ML model unavailable"`.

### Phase 2 evidence stages

Each stage (`app/pipeline/{sbom,graph,vuln}_stage.py`) runs through `execute_stage`
(`app/pipeline/stages.py`). The stage persists its rows and records a status entry in
`Scan.stages`. On failure it rolls back its own rows and records a structured error. It never
raises, and it never swallows an exception without logging it.

- **SBOM.** Syft runs as an argv list with a timeout and output cap. Its cwd is the trusted
  workspace (so it never loads a `.syft.yaml` from the artifact). It gets an env allowlist (no app
  secrets) and runs with online enrichment off. The parser treats the SBOM as untrusted. It caps
  size, counts and string lengths, turns deep nesting into a parse error, drops edges to unknown
  refs, and renames refs that use reserved prefixes (`artifact:`, `provenancex:`). The raw SBOM is
  stored off-chain at `<workspace>/sbom.cdx.json` (mode 0600). Its SHA-256 is `Scan.bom_sha256`,
  which becomes `bom_hash` in Phase 7.
- **Graph.** The root `artifact:root` node has `depends_on` edges to top-level packages. SBOM edges
  between packages are `transitive_depends_on`. Edge `origin` is `sbom`, `inferred_top_level`
  or `inferred_unreachable`. Features: dependency_count, direct/transitive counts,
  transitive_depth, degree and betweenness centrality, cycles, and `transitive_resolution`
  (`none | partial | complete`). Dependencies are never installed or resolved. A bare
  `requirements.txt` therefore gives `transitive_resolution="none"`, and the API states that
  limitation.
- **Vulnerabilities.** Components with a versioned purl are queried in OSV. Records that share
  ids or aliases (GHSA/PYSEC/CVE) are merged, so one issue counts once. CVSS v3 base scores are
  computed from vectors (`cvss.py`, FIRST spec formulas). CVSS v4 is not scored locally, and NVD
  fills in scores where it can (rate-limited and capped). Findings are
  `category="vulnerability"`, `details.kind="known_vulnerability"`. The stage then fills the graph
  features `vulnerable_count`, `vulnerability_count` and `cvss_max`. If the lookup did not run,
  these stay `null`. They are never reported as 0.

- **Root package.** Syft reports a lockfile project's own package (e.g. the root entry of
  `package-lock.json`) as a component. `detect_project_packages` reads the name and version from
  the top-level `package.json` or `pyproject.toml`. A component with the same ecosystem, name and
  version is merged into `artifact:root`, so direct dependencies are at depth 1, and it is left
  out of OSV queries. A manifest without a version matches on the name alone.

Known limitation: lockfiles that list dev or test dependencies are included as-is.

### Phase 3 AI/ML evidence stages

`POST /api/v1/scans/model` runs `app/pipeline/model.py`, which shares its failure and cleanup
handling with the software pipeline (`app/pipeline/lifecycle.py`). Nothing from the artifact is
executed, imported or deserialized. No `torch`, `safetensors` or `huggingface_hub` library is
used, and a test (`tests/security/test_model_inputs.py`) fails if `app/` imports one.

- **Hugging Face fetch (`app/scanners/hf/client.py`).**
  - The host is fixed in code, and no token is sent. Gated or private repositories return
    `hf_access_denied`.
  - Redirects are followed manually, at most 5 hops. Each hop must be https, with no credentials,
    port or IP literal. Its host must be on the fixed list in `url_validation.py` (the
    `cdn-lfs*.huggingface.co` and `cas-bridge.xethub.hf.co` hosts, or any `*.hf.co` host), and
    every address it resolves to must be public.
  - Listing paths are validated like ZIP entries. Files are written with `O_EXCL` under
    `workspace/src`, smallest first, with per-file, total and time budgets.
  - Each download is verified against the Hub listing (LFS SHA-256 or git blob SHA-1). A mismatch
    deletes the file and becomes a HIGH provenance finding.
  - `hf_manifest_digest` covers the full remote listing, including files too large to download.
- **AI-BOM (`aibom` stage).** `app/scanners/model/` builds the file inventory and detects the
  serialization format from magic bytes. It parses safetensors headers with bounds checks, scans
  pickles and PyTorch ZIP members with `pickletools.genops`, and reads configs, adapter metadata,
  model cards (`yaml.SafeLoader`, anchors and aliases rejected) and custom-code listings. The
  document is stored off-chain at `<workspace>/aibom.json` (mode 0600). Its SHA-256 is
  `Scan.bom_sha256`, the same `bom_hash` slot an SBOM uses. Static findings are
  `category="static"` with no CVSS.
- **Lineage graph (`graph` stage, `graph_kind="lineage"`).** Node keys are `model:`, `dataset:`,
  `adapter:`, `config:`, `file:` and `package:`. Edges are `derived_from`, `fine_tuned_from`,
  `trained_on`, `bundled_with` and `requires`, each with an `origin`. Features include
  `lineage_completeness` (a research heuristic) and `suspicious_lineage` rule flags.
- **Vulnerabilities.** OSV runs on exactly pinned runtime requirements. With no pinned
  requirement, the stage is `skipped` with a reason.
- **Provenance (`app/provenance/checks.py`, both pipelines).** Each check is
  `pass | fail | unknown | info`, and only `fail` becomes a Finding. The canonical record is stored
  at `<workspace>/provenance.json` (mode 0600). Its SHA-256 is `ProvenanceRecord.record_sha256`,
  which becomes `provenance_hash` in Phase 7. `hash_changed` compares with the most recent earlier
  completed scan of the same source and is `null` when there is none. A changed hash on the same
  commit is a HIGH failure. A changed hash on a new commit is `info`.

Known limitations:
- Weights over `HF_MAX_FILE_MB` or the total budget are not hashed locally. They carry the
  Hub-reported hash, marked unverified, and a `content_coverage: unknown` check.
- Signature and attestation files are detected by name and not verified, so `signed` is `null`.
- Gated and private repositories are unsupported.
- OSV covers only exactly pinned runtime requirements.
- GGUF and ONNX files are identified but their internals are not parsed.
- Deep analysis of bundled Python code (AST) is Phase 4. Phase 3 records only that it is present.
- The Hugging Face download redirect allowlist accepts any `*.hf.co` host (up to 5 dots in the
  name), accepted for the MVP because Hugging Face CDN hostnames vary. Any host under `hf.co` is
  trusted as a download source, so the control relies on Hugging Face's ownership of that domain.
  The https, no-credentials, no-port, no-IP-literal and public-address checks still apply to
  every hop, and downloaded content is verified against the Hub listing.
- Hugging Face downloads follow up to 5 redirect hops (`MAX_REDIRECTS`), accepted for the MVP.

### Phase 4 static analysis (`static` stage, step 9)

`app/scanners/static/` runs for software and model scans, after provenance. Artifact code is only
parsed, never imported or run.

- **Python** (`python_ast.py`): `ast`, with a per-file alias table that follows `import os as o`,
  `from os import system`, `run = os.system`, `__import__("os")` and `getattr(os, "system")`.
  `.ipynb` code cells are parsed the same way. Unparseable Python falls back to text rules.
- **Other scripts** (`text_scan.py`): bounded line-based rules for shell, batch, PowerShell and
  JavaScript. Files without an extension are routed by their shebang.
- **Install hooks** (`install_hooks.py`): npm lifecycle scripts and `setup.py` (`cmdclass` overrides
  rank higher). `auto_map` targets are counted but reported by the AI-BOM stage.
- **Archive anomalies** (`archive_anomaly.py`): nested ZIP-family files are read through the central
  directory only and never decompressed. Also disguised executables, double extensions, and upload
  entries near the compression limit.

Features are stored in `stages.static.features`. Findings are `category="static"` with no CVSS, one
per rule and file, capped at `STATIC_MAX_FINDINGS` (features still count every occurrence). When a
budget is hit the stage is `partial` and lists the skipped files. Artifact text is sanitized before
storage, because PostgreSQL rejects NUL bytes and lone surrogates.

Known limitations:
- Aliases are tracked per file without scopes, so heavily obfuscated code can evade these rules.
- `getattr` is flagged only on sensitive modules (`os`, `subprocess`, `builtins`, `sys`, `socket`,
  `ctypes`, `importlib`) or when the attribute name is computed (concatenation, f-string, call),
  because `getattr(obj, name)` is common in ordinary code. Other getattr-based obfuscation, such as
  a plain variable name on an object that holds a dangerous callable, can be missed.
- Nested tar, 7z and rar archives are flagged but not inspected.

### Phase 4 telemetry parser

`app/scanners/sandbox/telemetry.py` reads a recorded `provenancex-trace-v1` bundle (run metadata,
`strace -f` text lines and cgroup resource samples) and produces the Behavior feature group.
`behavior_findings.py` turns the result into `category="behavioral"` findings with no CVSS.

A bundle is untrusted, because the code under observation influences it. Size and line counts are
capped, a bad envelope raises `sandbox_trace_error`, and malformed lines or samples are counted and
skipped. Arguments are split with a quote-aware tokenizer and addresses are read only from the
position that holds them, so text inside a quoted string cannot create events. Evidence is bounded
and sanitized for PostgreSQL, while the features count every occurrence. `external_destination_count`
counts distinct globally routable IP and port pairs. A feature with no evidence is `null`.

Known limitations:
- With no network, hostnames never resolve, so destinations known only by name are undercounted.
- Code under observation can detect tracing or forge its own trace lines. Quiet telemetry is not
  proof of safety.

### Phase 4 Docker sandbox (`sandbox` stage, step 10, optional)

`SANDBOX_PROVIDER` is `disabled` (default), `docker` or `mock`. A mock is never a fallback.

**What runs.** `docker/sandbox/supervisor.py` picks a fixed set of targets, and nothing in the
artifact can add one. Software: a regular `setup.py` at the root. Model: stdlib `pickle.load` of
pickle files and of `*.pkl` members in ZIP weights (at most 8), and `importlib.import_module` of
`auto_map` modules that exist in the artifact (at most 8). Each target runs under `strace -f`.

**Enforcement.** `hardening.build_docker_argv` writes the command, and `hardening.assert_hardened`
independently re-parses it against an allowlist before every launch, failing closed. No setting can
relax these.

| Boundary | Setting |
|---|---|
| Network off | `--network=none` (not configurable) |
| Read-only artifact | `--mount type=bind,...,dst=/artifact,readonly`; `--read-only` root filesystem |
| Non-root | `--user <workspace owner uid>:<gid>`, refused if 0 |
| Capabilities | `--cap-drop=ALL`, with `--cap-add` and `--privileged` rejected |
| No privilege gain | `--security-opt=no-new-privileges`, default seccomp profile |
| Resources | `--pids-limit`, `--memory` with equal `--memory-swap`, `--cpus`, `--ulimit=core=0` |
| Hard timeout | Supervisor timeout, then a host deadline, then `docker kill` |
| No Docker socket | One mount only; anything containing `docker.sock` is rejected |
| Writable space | Size-limited `noexec,nosuid,nodev` tmpfs at `/tmp` and `/trace`, plus `/dev/mqueue` (in-memory and private to the container). `--ipc=none` removes the writable `/dev/shm`. A live probe walks `/proc/self/mountinfo` and fails on any other writable mount. |
| Host exposure | Stdout and stderr are each byte-capped on the host, and `SANDBOX_MAX_CONCURRENT` limits how many containers run at once (per API process) |

`strace` works with these flags, without `SYS_PTRACE` or a seccomp change. Live probes
(`tests/integration/test_sandbox_live.py`) verify each boundary inside the real container.

**Trace path.** Target output is redirected to files in `/tmp`, but that does not isolate the
bundle: targets run as the same uid, so they can write to the supervisor's stdout and stderr
through `/proc/1/fd` and can alter `/trace`. The bundle is therefore untrusted. The supervisor writes
it to its own stdout, which the host reads with a byte cap and a deadline. The host stores it at
`<workspace>/sandbox/trace.json` (0600). PostgreSQL gets the features, findings and the trace's
SHA-256. The raw trace never goes on-chain.

**Cleanup.** `--rm`, a unique `px-sbx-<scan_id>` name, and `docker rm -f` in a `finally` block.

**Failure.** The scan always completes. `disabled` gives `skipped`. Docker or the image missing
gives `unavailable`. A refused command or bad mount source gives `error` with no container started.
A missing, oversized or malformed trace gives `error` (`sandbox_trace_error`). A timeout, a target
killed with exit -9, or malformed trace lines give `partial`, with `incomplete_reasons`. Behavior
features stay `null` when nothing was observed.

**Rule for Phase 6.** Risk scoring must treat a sandbox `error` or `partial` as "not evaluated /
lower confidence", never as quiet. A zero count from a tampered run is not evidence of safety.

Known limitations and residual risk:
- **Do not run real malware through this sandbox on the host.** It is for controlled fixtures and
  development. Use benign or controlled samples only. Analyzing real malware needs a disposable VM
  with no route to anything you care about.
- **A kernel or container escape is outside this boundary.** Containers share the host (WSL2) kernel,
  and the sandbox runs as the workspace owner's uid (never 0). On a typical development machine that
  user is in the `docker` and `sudo` groups, and WSL interop and `/mnt/c` are available, so an escape
  can lead to root in WSL and to Windows files. The sandbox is a mitigation, not a proof of isolation.
- **The host API has Docker access, which is root-equivalent, while it parses untrusted input.** A
  parser bug in that process is not contained by the sandbox and has the same escalation path. This
  follows from running real sandboxes with the API on the host.
- **Cleanup can fail.** Failures of `docker kill` and `docker rm -f` are only logged. With a hung
  Docker daemon, a container stays until its own supervisor exits.
- **The image is trusted by tag.** `assert_hardened` checks the flags but not which image runs, so
  anyone who can retag `provenancex-sandbox:0.1.0` or set `SANDBOX_IMAGE` controls the image.
- `SANDBOX_MAX_CONCURRENT` applies per API process, so running several API workers multiplies it.
- **The sandbox needs the API running on the host with Docker.** In Compose the API has no Docker
  socket by design, so the stage reports `unavailable`.
- **Observed code can interfere with its own trace.** It runs as the same uid as the supervisor and
  tracer, so it can kill `strace`, wipe or rewrite `/trace`, and write to the bundle stream through
  `/proc/1/fd`. Quiet telemetry is not proof of safety. Tampering that leaves a killed target or
  malformed lines gives `partial`, and a broken bundle gives `error`. A careful rewrite of the trace
  can still look complete.
- Only Python and pickle targets run. npm lifecycle scripts are not executed. Pickles that need torch
  or other absent packages fail on import, which appears as a non-zero target exit code.
- If the API process crashes mid-run, the host cleanup cannot run. The supervisor's own timeout still
  ends the container; a container whose supervisor also hung would need removing by hand.

### Phase 5 dataset, models and evaluation

Code is in `backend/app/ml/`, command-line entry points in `ml/scripts/`. None of it is wired into the
scan pipeline yet (Phase 6). The API image does not include the ML packages.

- **Dataset:** synthetic records from the real parsers over generated artifacts and controlled
  tampering. Nothing is executed. Splits are by artifact family.
- **Models:** Random Forest (primary), XGBoost (comparison), Isolation Forest, on one matrix with
  explicit null indicators. Artifacts use skops and JSON, never pickle or joblib, and are verified
  against a SHA-256 manifest on load.
- **Evaluation:** `ml/reports/`, generated from real runs on synthetic data. It does not measure
  real-world detection.

Details are in `ml/README.md`.

## 5. Data model (PostgreSQL)

| Entity | Key fields | Phase |
|---|---|---|
| Artifact | id, artifact_type, name, version, source, source_url, sha256, collected_at | 1 |
| Scan | id, artifact_id, status, scanner_version, started_at, finished_at, error | 1 |
| Scan (Phase 2 additions) | stages (per-stage status JSON), bom_sha256 | 2 |
| Component | id, scan_id, bom_ref, name, version, component_type, ecosystem, purl, licenses, source, properties | 2 |
| Finding | id, scan_id, component_id, category (vulnerability/static/behavioral/provenance), identifier, aliases, title, severity, severity_source, cvss_score, cvss_vector, cvss_version, source, details | 2 |
| GraphNode / GraphEdge | scan_id, node_key, node_type, label, component_id, attributes / source_key, target_key, relation, origin | 2–3 |
| ProvenanceRecord | id, scan_id, source_known, revision_pinned, resolved_commit, signed, signature_files_present, provenance_present, hash_changed, previous_scan_id, lineage_completeness, checks, record_sha256, source | 3 |
| RiskDecision | scan_id, risk_score, decision, layer_scores, ml_probability, anomaly_score, model_version, explanation | 6 |
| BlockchainEvidence | scan_id, tx_hash, artifact_hash, bom_hash, provenance_hash, block_number, anchored_at | 7 |

Tables are added through Alembic migrations in the phase that first uses them.

## 6. Errors

Every API error uses one envelope:

```json
{"error": {"code": "database_unavailable", "message": "Database is not reachable", "details": null}}
```

Unhandled exceptions are logged with a traceback and returned as a generic `internal_error`, so no internals leak to the client.

## 7. Phase numbering

`CLAUDE.md` (phases 0–9) is authoritative. `docs/spec.md` §13 splits the same work into 0–12:

| CLAUDE.md | spec.md §13 |
|---|---|
| 0 Repo + skeleton | 0 |
| 1 Software ingestion | 1 |
| 2 SBOM, OSV/NVD, graph | 2, 3 |
| 3 AI ingestion + lineage | 4 |
| 4 Static + sandbox | 5, 6 |
| 5 Dataset + models + evaluation | 7, 8 |
| 6 Fusion, policy, SHAP | 8, 9 |
| 7 Blockchain | 10 |
| 8 Dashboard | 11 |
| 9 CI gate, E2E, docs | 12 |

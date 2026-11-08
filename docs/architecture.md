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
| Sandbox | Docker SDK | fixture telemetry |
| Chain | web3.py → Hardhat | in-memory ledger |

Mock output always carries `source="mock"`. The API returns that tag (`is_mock`, `contains_mock`)
and the UI shows it. Providers are chosen with env vars (`SBOM_PROVIDER`, `VULN_PROVIDER`) and
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

Known limitations: Syft reports a lockfile project's own package (e.g. the root entry of
`package-lock.json`) as a component, so that package's direct dependencies appear at depth 2. It
is also queried in OSV, so a public package with the same name and version could produce
unrelated advisories. Lockfiles that list dev or test dependencies are included as-is.

## 5. Data model (PostgreSQL)

| Entity | Key fields | Phase |
|---|---|---|
| Artifact | id, artifact_type, name, version, source, source_url, sha256, collected_at | 1 |
| Scan | id, artifact_id, status, scanner_version, started_at, finished_at, error | 1 |
| Scan (Phase 2 additions) | stages (per-stage status JSON), bom_sha256 | 2 |
| Component | id, scan_id, bom_ref, name, version, component_type, ecosystem, purl, licenses, source, properties | 2 |
| Finding | id, scan_id, component_id, category (vulnerability/static/behavioral/provenance), identifier, aliases, title, severity, severity_source, cvss_score, cvss_vector, cvss_version, source, details | 2 |
| GraphNode / GraphEdge | scan_id, node_key, node_type, label, component_id, attributes / source_key, target_key, relation, origin | 2–3 |
| ProvenanceRecord | id, scan_id, source_known, signed, provenance_present, hash_changed, lineage_completeness | 2–3 |
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

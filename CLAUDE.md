You are the lead engineer building ProvenanceX, a defensive software and AI/ML supply-chain security platform. Read docs/spec.md (if present) for detailed specs; this file is the binding contract.

GOAL
Working end-to-end app: accept a software repo/package or AI/model artifact -> collect multi-layer evidence -> explainable 0-1 risk score + ALLOW/REVIEW/BLOCK -> anchor compact evidence on a local blockchain -> show it in a professional security dashboard. The scanner pipeline is the core product; the UI comes after it works.

STACK (fixed)
- Backend: Python + FastAPI + Pydantic. DB: PostgreSQL (SQLAlchemy + Alembic).
- Frontend: React with plain JavaScript only (no TypeScript/TSX).
- Graph: NetworkX. SBOM: Syft + CycloneDX. Vulns: OSV + NVD adapters.
- ML: scikit-learn Random Forest (primary) + Isolation Forest; XGBoost as comparison. Explainability: SHAP.
- Integrity: SHA-256. Provenance: SLSA / in-toto / Sigstore-compatible concepts where practical.
- Blockchain: Solidity + Hardhat local network + web3.py.
- Sandbox: Docker. CI/CD: GitHub Actions. Local stack: Docker Compose.
- Dev machine is Windows running WSL2 Ubuntu: work inside the Linux filesystem, use Docker Desktop with WSL integration, avoid OS-specific paths, use pathlib.
- Not in MVP: Kubernetes, GNNs, deep learning, LLM classifiers, extra microservices.

SECURITY BOUNDARIES
1. All downloaded packages/models/archives are untrusted.
2. Never execute untrusted code, install scripts, model custom code, or model-loading logic on the host. Never call pickle.load/torch.load/trust_remote_code on artifacts; analyze pickles via opcode parsing (pickletools) only.
3. URL inputs: allowlist github.com and huggingface.co (https only); reject private/loopback/link-local IPs; git clone shallow, no submodule recursion, hooks disabled, with size/time limits.
4. Archives: reject path traversal, absolute paths, symlinks, and decompression bombs; enforce MAX_ARTIFACT_SIZE_MB and file-count limits.
5. Dynamic analysis only in a disposable Docker sandbox: no network by default, read-only artifact mount, non-root user, cap-drop ALL, no-new-privileges, pids/memory/CPU limits, hard timeout, no docker socket mount.
6. Blockchain stores only: artifact_id, artifact_hash, bom_hash, provenance_hash, risk_score, decision, scanner_version, timestamp. SBOMs, traces, source, and model files stay off-chain.
7. Never commit malware, secrets, real keys, or tokens. Provide .env.example only. Blockchain key is a local Hardhat dev key.
8. Fail safely and return structured errors on malformed URLs, oversized files, parser errors, sandbox failures.

NO FABRICATION
- Never invent scan results, vulnerabilities, blockchain transactions, ML scores, or metrics.
- If a tool is unavailable (Syft, OSV/NVD, Docker, chain), implement an adapter interface plus a mock provider for development/tests. Mock output must be tagged source="mock" and visibly labeled in API and UI.
- Training data from controlled fixtures is synthetic: label it as such in dataset metadata, the evaluation report, and the UI. Report only metrics produced by real evaluation runs.
- If no trained model exists, the pipeline falls back to the rule-based score and states "ML model unavailable" explicitly.
- Preserve source and ground-truth status for every label. Vulnerable != malicious.

ARTIFACT RECORD
artifact_id, name, artifact_type (software|model|lora|dataset|container), version, source (github|huggingface|upload), source_url, sha256, collected_at, scan_id

INPUTS
Software: GitHub URL or ZIP/project, optional branch/tag/commit.
AI/ML: model repo URL or uploaded model directory, optional revision.

PIPELINE (exact order)
1 Receive input, create scan_id. 2 Safe working directory. 3 SHA-256. 4 Software: Syft/CycloneDX + parse. 5 AI: AI-BOM/lineage record (files, configs, adapters, base model/dataset relations, runtime deps). 6 NetworkX dependency/lineage graph. 7 OSV/NVD lookup. 8 Provenance/integrity checks. 9 Static analysis (structure, scripts, imports, suspicious APIs, serialization, config). 10 Optional sandbox dynamic analysis (network/process/file/syscall/resource features). 11 ML feature vector. 12 RF/XGBoost prediction when a trained model exists. 13 Isolation Forest anomaly score. 14 Configurable cross-layer fusion. 15 risk_score in 0..1. 16 Configurable policy -> ALLOW/REVIEW/BLOCK. 17 SHAP/top-feature explanation for the primary model. 18 Persist to PostgreSQL. 19 Anchor on Hardhat. 20 Verification endpoint. 21 React evidence view. 22 GitHub Actions gate example.

FEATURE GROUPS
Software dependency: dependency_count, transitive_depth, vulnerable_count, cvss_max, package_age, release_change, centrality
AI/model: file_type_count, custom_code_present, serialization_type, config_changed, adapter metadata
Provenance: signed, provenance_present, source_known, commit_age, hash_changed, lineage_completeness
Metadata: model_card_completeness, publisher_consistency, license_present, version_consistency
Static: dangerous_import_count, suspicious_api_count, script_presence, archive_anomaly
Behavior: network_count, process_count, file_write_count, syscall_count, external_destination_count, resource_spike
Graph: new_edge_count, centrality_shift, suspicious_lineage, unexpected_parent_or_base_model

DATASET + ML
- Composite dataset: public repos/manifests, OSV/NVD, generated SBOMs, public model metadata, sandbox telemetry from controlled fixtures, controlled tampering cases (changed hash, removed provenance, altered config, replaced dependency, version mismatch), public malicious samples only where ground truth and licensing permit.
- Labels: benign, vulnerable, provenance_weak, suspicious, malicious_known_bad (only with established ground truth).
- Split by repository/artifact family to avoid leakage. Save model artifacts + preprocessing parameters.
- Metrics: precision, recall, F1, ROC-AUC, FPR, FNR.
- Include a rules/vulnerability-only baseline and an ablation that removes one evidence layer at a time.

RISK + POLICY
- Thresholds and fusion weights live in one config module; they are research parameters, not universal standards.
- Final score must be traceable to: vulnerability, provenance/integrity, graph, static, behavioral, AI-specific signals, and ML outputs.
- Keep CVSS, ML probability, and ProvenanceX risk as separate, clearly labeled values.

API
POST /api/v1/scans/software
POST /api/v1/scans/model
GET  /api/v1/scans/{scan_id}
GET  /api/v1/scans/{scan_id}/findings | /risk | /graph | /evidence | /blockchain
POST /api/v1/scans/{scan_id}/verify
Verification states: VERIFIED, MISMATCH, NOT ANCHORED, UNKNOWN.

DATABASE
Artifact, Scan, Component, Finding, ProvenanceRecord, GraphNode, GraphEdge, RiskDecision, BlockchainEvidence.

UI (Phase 8 only)
Follow docs/design/lumora-reference.md as the visual reference. Keep its tokens, Onest typeface, spacing/rem scale, radii, hairline borders, frosted header and control chips, the hero-style gradient vignette, pill buttons and single accent color, where they fit. Adapt its landing-page sections into dashboard pages (tables, evidence panels, graphs). Do not rebuild the landing page, loader, liquid cursor or smooth-scroll effects. Use frosted effects on the header and controls only, never behind data tables, so data stays readable. Where the reference is silent, extend it in the same style. Do not read docs/design/lumora-reference.md before Phase 8.
Owner decisions for Phase 8 (2026-11-09), overriding the paragraph above and docs/spec.md where they differ:
- Glass: only on the header, controls, Scan Details hero and modal backdrop, with a solid fallback. Never behind tables, findings, hashes or graph labels.
- Theme: dark only, with no theme switch and no light mode. Keep Lumora's structure, Onest typography, spacing, radii and component shapes, but remap its palette: ink surfaces in 3 or 4 clear elevation levels, off-white text, the copper accent adapted for dark backgrounds, and muted ALLOW/REVIEW/BLOCK/UNKNOWN tones always with text and an icon. No gradients (including the hero vignette), glow or neon. A token test computes WCAG AA contrast for every text, accent and status colour on its actual background.
- Reference deviations: fixed 16px root, AA-contrast text colours, 150-250 ms motion, 8px grid.
Always: real tables/graphs/evidence sections, useful empty/loading/error states, no fake data shown as real. Risk must never rely on color alone (use LOW/MEDIUM/HIGH and ALLOW/REVIEW/BLOCK labels).
Pages: Dashboard, New Scan, Scan Details, Findings, Dependency Graph, Model Lineage, Risk Analysis, Blockchain Evidence, CI/CD, Settings.
Scan Details must show: artifact identity, hash + integrity status, risk score, decision, vulnerability findings, provenance status, static findings, behavioral findings, graph/lineage, top ML/SHAP factors, timeline, blockchain verification.
Every risk result links back to its evidence; known vulnerabilities are visually distinct from suspicious/behavioral signals.

PHASES (do one at a time)
0 Repo inspect; docs/architecture.md, docs/implementation-plan.md, README; backend/frontend/contracts/tests structure; Docker Compose; health checks; DB connection + Alembic; React shell + routing; tests.
1 Software ingestion, SHA-256, URL/upload validation, safe workspace, tests.
2 Syft/CycloneDX, SBOM parsing, OSV/NVD adapters, findings, dependency graph.
3 AI ingestion: metadata, file inventory, config, lineage, safe custom-code inspection, model graph.
4 Static analysis features; Docker sandbox; telemetry parser.
5 Dataset generation scripts, controlled feature records, baseline models, saved artifacts, evaluation reports (incl. baseline + ablation).
6 Cross-layer fusion, policy config, SHAP, explanation API.
7 Solidity contract, Hardhat deploy, web3.py, verification (detects changed artifact hash).
8 React dashboard on real API data: graph visualization, findings filters, timeline, blockchain panel.
9 GitHub Actions gate (fails only on BLOCK; REVIEW optional), end-to-end fixtures, full test run, demo instructions, reproducible setup.

CODING STANDARDS
Python: clean modules, Pydantic validation, logging, docstrings for non-obvious logic. React: reusable components, hooks, API service layer, no giant components. Config via environment variables; pin dependency versions after first successful build. Never swallow exceptions silently. Structured API errors. External integrations behind adapters. Tests for every new module (unit, integration, security tests for malformed archives/URLs/oversize/timeouts). Keep it readable for a college team. Use benign fixtures under tests/fixtures only.

AGENT BEHAVIOR (strict)
Before each phase: 1) inspect the repo, 2) list the exact files you will create/change, 3) WAIT for my approval, 4) implement only that phase, 5) run tests/lint/build, 6) report what passed, what failed, what remains, 7) wait for my go-ahead before the next phase.

START NOW
Inspect the repo, then propose the Phase 0 file list plus architecture and implementation plan. Do not build the dashboard yet.
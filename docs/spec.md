ProvenanceX - Implementation Guide
PROVENANCEX
Implementation Guide + Master Coding-Agent Prompt
AI-Assisted Blockchain-Anchored Framework for Software and AI/ML Supply-Chain 
Integrity and Risk Detection
Purpose of this document
This is a build specification you can give to Cursor, Kiro, Cline or another coding agent. It explains exactly 
what goes into the pipeline, what evidence is collected, how the ML dataset is formed, how risk is produced, 
how blockchain is used, how the backend is organized, what the UI should contain, and how to build the 
system in safe phases.
Audience: college mini-project team building a working prototype with Python/FastAPI + PostgreSQL + 
React.js + ML + local blockchain + Docker.
Source basis: your supplied ProvenanceX 15-page project guide. Current developer-tool information in this document was 
checked on 29 September 2026 using official sources.
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
ProvenanceX | Software + AI/ML Supply-Chain Security
1. Project at a Glance
ProvenanceX is a defensive security platform for two connected supply chains: traditional software 
and AI/ML artifacts. The central idea is not to use machine learning or blockchain as isolated 
buzzwords. The system collects multiple evidence layers - vulnerabilities, dependencies/lineage, 
provenance, integrity, static findings and sandbox behavior - then produces an explainable risk 
decision. Blockchain stores only compact evidence of the scan so the evidence can be checked later.
Simple explanation
Think of ProvenanceX as a security checkpoint. A package or model arrives at the checkpoint; the system 
checks its identity, ingredients, origin, known weaknesses, code, relationships and observed behavior. It then 
estimates risk and says ALLOW, REVIEW or BLOCK.
What makes the project different
 It treats both software packages/containers and AI models/LoRA adapters/datasets/configs as first-class 
artifacts.
 It combines static, provenance, graph and dynamic evidence instead of relying only on a CVE scanner.
 ML estimates risk from the combined evidence; it does not replace vulnerability intelligence.
 Blockchain is an audit/integrity layer, not the detection engine.
 The output is explainable: the dashboard should show which evidence contributed to the risk decision.
Primary project flow
USER INPUT
   |
   +--> Software: GitHub repo / ZIP / package project
   |
   +--> AI/ML: model repository / model artifact / LoRA adapter
   |
   v
Artifact ingestion -> SHA-256 -> BOM/lineage -> dependency graph
        -> vulnerability checks -> provenance -> static checks
        -> isolated sandbox (optional/controlled) -> feature extraction
        -> ML risk engine -> cross-layer risk fusion
        -> ALLOW / REVIEW / BLOCK -> blockchain evidence -> dashboard/CI gate
ProvenanceX - Implementation Guide
2. Inputs, Outputs and Data Contracts
2.1 Software input
For the MVP, accept either a public GitHub repository URL or an uploaded ZIP/project directory. The 
repository is copied into a disposable work area; never execute unknown code directly on the host.
Input
Example
Purpose
Repository URL
https://github.com/org/project
Fetch source and manifests
ZIP/project
project.zip
Local scan path
Optional branch/commit
main / abc123
Reproducible scan target
Artifact type
2.2 AI/ML input
software
Select software pipeline
For the MVP, accept an AI model repository URL or a packaged model directory. The system should 
inspect model metadata, files, configuration, optional custom code and lineage information without 
trusting the artifact.
Input
Example
Purpose
Model repository
Hugging Face URL
Fetch model metadata/artifacts
Model directory
model/
Local controlled scan
Artifact type
model / LoRA / dataset
Select AI pipeline
Revision/version
2.3 Normalized artifact record
{
commit or tag
"artifact_id": "scanable-id",
"name": "example-artifact",
"artifact_type": "software|model|lora|dataset|container",
"version": "1.0.0",
"source": "github|huggingface|upload",
"source_url": "...",
"sha256": "...",
"collected_at": "...",
"scan_id": "..."
}
2.4 Final output
Reproducibility and integrity
Output
Meaning
Risk score (0-1)
Overall estimated risk after cross-layer fusion
Decision
Findings
ALLOW / REVIEW / BLOCK according to configured policy
Vulnerabilities, provenance gaps, static findings, integrity 
issues, anomalies
Evidence
Raw structured scanner results and feature values
Graph
Dependency/model-lineage relationships
Explanation
Important features contributing to the ML result
Blockchain evidence
Hashes + score + decision + version + timestamp
Scan status
Queued / Running / Completed / Failed
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
3. End-to-End Pipeline - What Happens After the User Clicks Scan
1. Receive input: FastAPI receives the software or AI artifact reference and creates a scan_id.
2. Isolate the workspace: Copy/download the artifact to a disposable workspace. For dynamic analysis, 
use a separate Docker/VM sandbox.
3. Identify and hash: Compute SHA-256 for the artifact. This becomes the digital fingerprint used for 
integrity checking.
4. Generate BOM evidence: Software: generate SBOM with Syft/CycloneDX. AI: generate a model/AI-BOM 
record containing model files, adapters, configs, data and dependencies where known.
5. Build dependency/lineage graph: Represent components/models/datasets as nodes and relationships 
such as depends-on, derived-from, fine-tuned-from or trained-on as edges.
6. Run vulnerability intelligence: Resolve packages and versions against OSV/NVD and attach known 
vulnerability identifiers, severity and CVSS values where available.
7. Run provenance/integrity checks: Check source identity, signatures/provenance when available, 
commit/revision details, hash changes and lineage completeness.
8. Run static analysis: Inspect manifests, archive contents, scripts, imports, dangerous/suspicious APIs, 
model file types, serialization and configuration.
9. Run controlled dynamic analysis: In a disposable sandbox, observe process, file, network, syscall and 
resource behavior. Keep networking restricted and use test artifacts.
10. Extract ML features: Convert all evidence into numeric/categorical features such as vulnerable_count, 
cvss, hash_changed, custom_code_present and network_count.
11. Predict with ML: Use supervised models such as Random Forest/XGBoost when labels exist and 
Isolation Forest for anomaly detection.
12. Fuse evidence: Combine scanner outputs and ML predictions into a final risk score. Keep the fusion 
parameters configurable and validate them empirically.
13. Apply policy: Map the risk/evidence to ALLOW, REVIEW or BLOCK. Thresholds are project policy 
parameters, not universal security standards.
14. Anchor evidence: Hash the artifact/BOM/provenance record and write compact evidence to a local 
Ethereum-compatible blockchain.
15. Persist results: Store structured results in PostgreSQL and expose them through FastAPI.
16. Display and gate: React shows the result and GitHub Actions/MLOps can consume the decision as a 
pipeline gate.
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
ProvenanceX | Software + AI/ML Supply-Chain Security
4. Scanner Modules and Implementation Details
4.1 Software SBOM module
Use Syft to enumerate packages/components and export a CycloneDX-compatible SBOM. Parse the 
SBOM into your normalized internal schema.
software input
   -> Syft
   -> CycloneDX SBOM
   -> parse components
   -> Component records
   -> vulnerability lookup
4.2 AI/Model-BOM module
There is no need to force AI artifacts into a software-package-only shape. Create an AI-oriented record 
that captures files, model framework, serialization type, configs, adapters, base model and lineage 
relationships when they are available.
model repo
   -> metadata collector
   -> file inventory
   -> config parser
   -> custom-code detector
   -> lineage extractor
   -> AI-BOM / lineage JSON
4.3 Vulnerability module
The vulnerability module is an intelligence lookup layer. It answers: 'Does this known 
package/version correspond to a known vulnerability?' It should preserve the source, identifier, 
severity and CVSS information. Do not convert a CVSS score directly into a statement that the artifact 
is malicious.
package_name + version
        |
        +--> OSV
        |
        +--> NVD
        |
        v
finding {
  id,
  package,
  affected_version,
  severity,
  cvss,
  source
}
ProvenanceX - Implementation Guide
4.4 Provenance/integrity module
Check whether the source is known, provenance/signing information is present, the expected revision 
is being scanned, the artifact hash matches the expected revision, and the model/package lineage is 
complete enough for the use case.
4.5 Static analysis module
Use safe parsing. Inspect files rather than executing them. For Python packages and model 
repositories, inspect imports, scripts, archive members, serialization format, suspicious APIs, 
configuration and custom code presence.
4.6 Dynamic sandbox module
Dynamic analysis should be isolated. The sandbox should record structured telemetry such as 
process_count, network_count, file_write_count, syscall_count, resource spikes and external 
destinations. Store raw traces outside the blockchain.
Safety boundary
Never execute downloaded packages/models directly on the Windows host. Use disposable containers/VMs, 
restricted networking, snapshots and controlled test artifacts.
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
ProvenanceX | Software + AI/ML Supply-Chain Security
5. Dependency and Model-Lineage Graph
Use NetworkX for the MVP. The same graph abstraction should work for both software and AI.
5.1 Node types
 repository
 package
 container
 model
 LoRA adapter
 dataset
 configuration
 artifact
5.2 Edge types
 depends_on
 transitive_depends_on
 derived_from
 fine_tuned_from
 trained_on
 bundled_with
 produced_by
5.3 Software example
Application
  |
  +--> Flask
  |      |
  |      +--> Werkzeug
  |
  +--> requests
         |
         +--> urllib3
5.4 AI example
FineTunedModel
  |
  +--> derived_from --> BaseModel
  |
  +--> trained_on   --> DatasetA
  |
  +--> uses         --> LoRAAdapter
  |
  +--> requires     --> torch
Graph features for ML can include dependency_count, transitive_depth, centrality, new_edge_count, 
centrality_shift, suspicious lineage, unexpected parent/base model and other reproducible graph 
statistics.
ProvenanceX - Implementation Guide
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
6. ML Dataset - How to Build the Training Data
Most important idea
Do not train the model on only 'package name -> vulnerability'. The project needs a feature table describing 
multiple evidence layers for each artifact.
6.1 Composite dataset strategy
Data source
What you collect
How it becomes training data
Public software repositories
Manifests, package metadata, repository 
metadata
Generate SBOM + dependency features
OSV / NVD
Known vulnerabilities, severity, CVSS
Use only when licensing/ground truth are 
clear
Attach vulnerability features/labels
Hugging Face model repositories
Metadata, model files, configs, lineage
Generate AI/model features
Sandbox traces
Network/process/file/syscall/resource 
observations
Convert traces to behavior features
Controlled tampering
Changed hash, altered config, missing 
provenance, replaced dependency, 
version mismatch
Create reproducible labeled cases
Documented research samples
Publicly documented 
malicious/suspicious artifacts, where 
permitted
6.2 Recommended row structure
artifact_id
artifact_type
dependency_count
transitive_depth
vulnerable_count
cvss_max
package_age
release_change
hash_changed
provenance_present
signature_present
lineage_completeness
file_type_count
custom_code_present
serialization_type
config_changed
model_card_completeness
publisher_consistency
license_present
dangerous_import_count
suspicious_api_count
script_presence
network_count
process_count
file_write_count
syscall_count
resource_spike
new_edge_count
centrality_shift
graph_anomaly
label
ProvenanceX | Software + AI/ML Supply-Chain Security
6.3 Labels
ProvenanceX - Implementation Guide
Use categories supported by your evaluation corpus and ground truth: benign, vulnerable, 
provenance-weak, suspicious/behaviorally-suspicious, and malicious/known-bad only where ground 
truth is established. A vulnerable artifact should not automatically be labeled malicious.
6.4 Train/validation/test split
Avoid leakage. Where possible, keep related repositories or artifact families together within a split. Do 
not let near-identical versions of the same artifact appear in both training and test sets.
6.5 Models
Model
Role
Input
Output
Random Forest
Main supervised baseline
Feature vector
Class probabilities/label
XGBoost
Supervised comparison model Feature vector
Class probabilities/label
Isolation Forest
Anomaly detection
Mostly-normal feature vectors Anomaly score
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
ProvenanceX | Software + AI/ML Supply-Chain Security
7. Risk Scoring and Decision Logic
7.1 Distinguish the three kinds of scores
Score What it means Example
CVSS Severity of a known vulnerability 8.2 for a specific vulnerability
ML prediction What the trained model estimates from 
features probability of a class / anomaly score
ProvenanceX risk Cross-layer risk after fusion 0.00 - 1.00
7.2 Example feature-to-risk path
Evidence:
  vulnerable_count = 2
  cvss_max = 8.2
  hash_changed = 1
  provenance_present = 0
  custom_code_present = 1
  network_count = 5
  process_count = 3
  graph_anomaly = 0.78
        |
        v
Feature preprocessing
        |
        +--> Random Forest / XGBoost
        +--> Isolation Forest
        |
        v
Cross-layer fusion
        |
        v
risk_score = 0.00 .. 1.00
        |
        v
Policy engine
        |
        +--> ALLOW
        +--> REVIEW
        +--> BLOCK
7.3 Fusion design
For the MVP, implement two layers: (1) individual model/scanner scores normalized to comparable 
ranges and (2) a fusion component that produces the final risk. Start with a transparent baseline 
fusion, then tune/learn the parameters using validation data. Keep every parameter configurable in 
one policy/config module.
7.4 Explainability
Use SHAP for the supervised model that becomes the primary risk classifier. The API should return 
the top contributing features so the frontend can explain the result in plain language.
{
ProvenanceX - Implementation Guide
"risk_score": 0.82,
"decision": "BLOCK",
"top_factors": [
{"feature": "hash_changed", "direction": "up"},
{"feature": "network_count", "direction": "up"},
{"feature": "cvss_max", "direction": "up"},
{"feature": "provenance_present", "direction": "down"}
]
}
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
8. Blockchain and Provenance Evidence
Use blockchain as an integrity/audit layer. It should not contain source code, model files, datasets, full 
SBOMs or large sandbox traces.
8.1 What goes on-chain
Field
Example
artifact_id
model-123
artifact_hash
SHA-256 digest
bom_hash
SHA-256 of BOM JSON
provenance_hash
SHA-256 of provenance/scan record
risk_score
0.82
decision
BLOCK
scanner_version
v1.0.0
timestamp
8.2 Implementation
UTC timestamp
1. Run a local Hardhat Ethereum-compatible network during development.
2. Write a minimal Solidity contract with a recordScan/artifactEvidence function and a verify/read 
function.
3. Deploy the contract with Hardhat.
4. Use web3.py from FastAPI to submit the compact record.
5. Store the returned transaction hash with the database record.
6. Keep large evidence off-chain in PostgreSQL/files/object storage.
8.3 Verification
stored artifact-> recompute SHA-256-> compare with recorded artifact_hash-> recompute BOM/provenance hashes-> read blockchain record-> compare score/decision/version/timestamp-> report VERIFIED or MISMATCH
Important
Blockchain proves that the recorded evidence trail is difficult to rewrite unnoticed. It does not prove that the 
original scanner was correct. The scanner, model and policy still need evaluation.
ProvenanceX | Software + AI/ML Supply-Chain Security
9. Backend, API and Database Design
ProvenanceX - Implementation Guide
9.1 Project structure
provenancex/
  backend/
    app/
      main.py
      api/
        scans.py
        artifacts.py
        findings.py
        risk.py
        graphs.py
        blockchain.py
      scanners/
        software.py
        ai_model.py
        vulnerabilities.py
        provenance.py
        static.py
        sandbox.py
      graph/
        builder.py
      ml/
        features.py
        train.py
        predict.py
        explain.py
      blockchain/
        contract.py
        verify.py
      db/
        database.py
        models.py
        schemas.py
    tests/
    scripts/
  frontend/
    src/
      pages/
      components/
      services/
      hooks/
      charts/
      graph/
  ml/
    data/
    models/
    notebooks/
  contracts/
    ProvenanceEvidence.sol
  docker/
  .github/workflows/
  docs/
ProvenanceX | Software + AI/ML Supply-Chain Security
9.2 PostgreSQL entities
ProvenanceX - Implementation Guide
Entity
Key fields
Artifact
Scan
Component
Finding
ProvenanceRecord
GraphNode / GraphEdge
RiskDecision
BlockchainEvidence
id, type, name, version, source, sha256, created_at
id, artifact_id, status, scanner_version, started_at, finished_at
id, scan_id, name, version, ecosystem
id, scan_id, type, severity, source, identifier, cvss, details
id, scan_id, source, signed, provenance_present, hash_changed, 
lineage_completeness
scan_id, node/edge identifiers, relationship
scan_id, risk_score, decision, model_version, explanation
scan_id, tx_hash, artifact_hash, bom_hash, provenance_hash, 
timestamp
9.3 Suggested FastAPI endpoints
POST /api/v1/scans/software
POST /api/v1/scans/model
GET  /api/v1/scans/{scan_id}
GET  /api/v1/scans/{scan_id}/findings
GET  /api/v1/scans/{scan_id}/risk
GET  /api/v1/scans/{scan_id}/graph
GET  /api/v1/scans/{scan_id}/evidence
GET  /api/v1/scans/{scan_id}/blockchain
POST /api/v1/scans/{scan_id}/verify
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
10. UI/UX Specification - Cybersecurity Security Console, Not Generic CRUD
Design direction
Make the product look like a serious security-analysis platform with a modern SaaS finish. It should feel 
engineered and purposeful, not like a template generated by an AI design tool.
10.1 Visual language






Dark neutral base with restrained accent colors only for state: risk, warning, success and neutral 
information.
Use a dense but readable layout: left navigation, top status bar, evidence panels, tables and graphs.
Use real data-like content and clear labels; avoid meaningless decorative cards.
Use subtle borders, depth, hover states and micro-interactions rather than heavy gradients or excessive 
glow.
Avoid Matrix rain, hacker clichés, giant neon text, excessive glassmorphism, giant circular gauges and 
generic 'AI dashboard' styling.
Prefer a compact risk badge + numeric score + evidence summary over a huge decorative gauge.
10.2 Main navigation
ProvenanceX
Dashboard
New Scan
Software Supply Chain
AI/ML Supply Chain
Findings
Dependency Graph
Model Lineage
Risk Analysis
Blockchain Evidence
CI/CD
Settings
10.3 Dashboard





Scan counts and status summary.
Recent scans table: artifact, type, risk, decision, timestamp.
Risk distribution or trend using compact charts.
Latest blocking/review findings.
Quick 'New Scan' action.
10.4 New Scan page
New Security Scan
Artifact type
[ Software ] [ AI / ML ]
Software source
[ GitHub URL / Upload ZIP ]
ProvenanceX | Software + AI/ML Supply-Chain Security
AI source
[ Model repository / Upload model ]
ProvenanceX - Implementation Guide
Revision (optional)
[ branch / tag / commit ]
[ Start Scan ]
10.5 Scan result page
Artifact: example-model     Scan: #1042
Risk: 0.82                   Decision: BLOCK
Evidence summary
  Vulnerabilities    2 findings
  Provenance
         Weak / incomplete
  Integrity
          HASH MISMATCH
  Static analysis    Suspicious custom code
  Behavior
           Unexpected network activity
Why this score?
  Top contributing features (SHAP)
Dependency / Model lineage
  Interactive graph
Timeline
  Ingested -> BOM -> scan -> risk -> decision -> blockchain
Blockchain evidence
  Artifact hash [verified]
  BOM hash
      [verified]
  Tx hash
       0x...
ProvenanceX | Software + AI/ML Supply-Chain Security
11. UI Components and Pages in More Detail
ProvenanceX - Implementation Guide
Page
Must show
Primary action
Dashboard
Recent scans, risk distribution, 
block/review counts
Open scan / start scan
New Scan
Scan Details
Artifact type, source, revision/upload
Risk, decision, evidence, findings, 
explanation
Start scan
Open finding
Inspect node/edge
Inspect lineage
Compare evidence
Verify evidence
View gate details
Verify / inspect evidence
Findings
Filterable findings table
Dependency Graph
Model Lineage
Nodes, edges, suspicious relationships
Base model, adapter, dataset, config 
relationships
Risk Analysis
Feature values, ML output, SHAP factors
Blockchain
Hashes, tx, verification state
CI/CD
11.1 Interaction rules

Gate status and recent pipeline results
Every risk result must link back to the evidence that caused it.




Clicking a finding should open its details without losing scan context.
Graph nodes should reveal metadata and related findings.
The UI must distinguish 'known vulnerability' from 'suspicious/behavioral signal'.
Verification status should be explicit: VERIFIED, MISMATCH, NOT ANCHORED or UNKNOWN.
11.2 Accessibility and usability




Readable text sizes and strong contrast.
Do not rely only on color to express risk; use labels such as LOW/MEDIUM/HIGH and 
ALLOW/REVIEW/BLOCK.
Loading states must show scan progress.
Errors must explain what failed and what can be retried.
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
ProvenanceX | Software + AI/ML Supply-Chain Security
12. CI/CD, Docker and Testing
12.1 GitHub Actions gate
git push / pull request
        |
        v
GitHub Actions
        |
        v
ProvenanceX scanner
        |
        v
risk + policy
   |         |
 ALLOW    REVIEW/BLOCK
   |         |
continue    stop/review
For the MVP, the workflow can call the FastAPI scan endpoint or run a CLI scanner directly. The CI 
gate should fail only when the configured policy says BLOCK; REVIEW can optionally require manual 
approval.
12.2 Docker Compose services
services:
  api          -> FastAPI
  postgres     -> PostgreSQL
  frontend     -> React
  hardhat      -> local blockchain
  sandbox      -> isolated analysis runner
12.3 Testing layers
 Unit tests: hash functions, parsers, feature extraction, scoring helpers, policy decisions.
 Integration tests: FastAPI + PostgreSQL, OSV/NVD lookup adapters, graph builder, blockchain 
write/read.
 End-to-end tests: submit a benign fixture and verify the full scan/report path.
 Security tests: malformed archives, missing fields, invalid URLs, oversized files, timeouts and sandbox 
failure behavior.
12.4 Reproducible fixtures
Keep small test artifacts inside the repository under tests/fixtures. Use benign fixtures and controlled 
mutations created specifically for your test suite. Do not commit real malware or unsafe research 
samples into the application repository.
ProvenanceX - Implementation Guide
ProvenanceX | Software + AI/ML Supply-Chain Security
13. Recommended Build Order - Do This in Phases
Phase Name Deliverable
Phase 0 Repository + architecture
Create monorepo, Docker Compose, 
FastAPI skeleton, React shell, PostgreSQL 
connection, configuration and logging.
Phase 1 Software ingestion
Accept GitHub URL/ZIP, copy to safe 
workspace, compute SHA-256, identify 
manifests.
Phase 2 SBOM + vulnerability Run Syft/CycloneDX, parse components, 
query OSV/NVD, create findings.
Phase 3 Dependency graph Build NetworkX graph and expose JSON 
graph endpoint.
Phase 4 AI/model ingestion
Accept model source, collect 
metadata/files/config, generate AI-BOM 
and lineage.
Phase 5 Static analysis Package/model code checks and 
suspicious-structure features.
Phase 6 Sandbox
Disposable container/VM behavior 
collection with strict timeouts and 
restricted network.
Phase 7 ML dataset
Generate feature records, labels, 
train/validation/test split, baseline 
models.
Phase 8 ML + SHAP
Train Random Forest/XGBoost, Isolation 
Forest anomaly model, persist model 
artifacts, return explanations.
Phase 9 Risk fusion + policy
Fuse evidence/model outputs, 
configurable policy, 
ALLOW/REVIEW/BLOCK.
Phase 10 Blockchain Hardhat network, Solidity evidence 
contract, web3.py write/verify endpoints.
Phase 11 Dashboard
Scan detail, findings, graph, lineage, 
SHAP explanation, blockchain 
verification.
Phase 12 CI/CD + evaluation
GitHub Actions gate, baseline 
comparison, metrics, ablation study, 
documentation.
MVP checkpoint
By the middle of the project, you should already be able to scan at least one software repository and one AI 
model artifact, generate structured evidence, calculate a basic risk result and show it through the API. 
Blockchain and polish come after the detection pipeline works.
ProvenanceX - Implementation Guide
14. Evaluation and Demonstration Plan
14.1 Baselines
7. Rules/vulnerability-only baseline.
8. Static-only ML baseline.
9. Dynamic-only ML baseline.
10. Provenance/graph-only baseline.
11. Proposed multi-layer fusion model.
14.2 Metrics
Metric
Why it matters
Precision
How often positive detections are correct
Recall
How many relevant risky cases are detected
F1
Balance of precision and recall
ROC-AUC
Ranking quality of the classifier
False-positive rate
How often safe artifacts are flagged
False-negative rate
How often risky artifacts are missed
Detection latency
Time from input to decision
Scanner coverage
How much of the artifact/evidence space is inspected
Sandbox overhead
Cost in time/resources of dynamic testing
Blockchain verification latency
Cost of audit verification
CI/CD gate accuracy
14.3 Demo scenarios
Whether policy decisions match expected labels/ground truth
Scenario
Evidence pattern
Expected interpretation
Vulnerable but otherwise normal
Known CVE/CVSS; provenance and 
behavior normal
Vulnerable case, not automatically 
malicious
Provenance weak
No major CVE; missing provenance/hash 
change
Review / provenance concern
Behaviorally suspicious
Few known weaknesses; unusual 
process/network behavior
Suspicious behavioral case
Multi-signal
14.4 Ablation study
Vulnerability + integrity/provenance 
issue + suspicious behavior
High-risk case under configured policy
Compare the full model to versions with one layer removed at a time: remove provenance, graph, 
behavior, static evidence, etc. Report how F1, false positives and other metrics change. This tests 
whether each layer contributes measurable value.
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
15. Practical Setup Checklist
15.1 Local software







Python 3.x for backend/scanners/ML.
Node.js + npm for React frontend.
PostgreSQL.
Docker Desktop.
Git.
Syft.
Hardhat + Node.js for local blockchain.
15.2 Python packages (initial)
fastapi
uvicorn
pydantic
sqlalchemy
psycopg
networkx
scikit-learn
xgboost
shap
requests/httpx
python-multipart
web3
pytest
Pin versions after the first successful environment build. Keep a requirements.txt/lockfile so the 
scanner can be reproduced.
15.3 Environment variables
DATABASE_URL=postgresql://...
OSV_API_BASE=...
NVD_API_KEY=...             
# optional; only if your chosen NVD integration needs it
BLOCKCHAIN_RPC_URL=http://...
BLOCKCHAIN_CONTRACT_ADDRESS=...
BLOCKCHAIN_PRIVATE_KEY=... # local development key only
SANDBOX_TIMEOUT_SECONDS=...
MAX_ARTIFACT_SIZE_MB=...
MODEL_PATH=...
Secrets
Never commit private keys, API keys or real credentials. Use .env locally and .env.example as the template.
ProvenanceX | Software + AI/ML Supply-Chain Security
16. Rules for the Coding Agent
ProvenanceX - Implementation Guide












Do not build a fake demo with hard-coded scan results.
Implement real module boundaries so the scanner outputs structured evidence.
Use adapters for OSV/NVD, Syft and blockchain so integrations can be mocked in tests.
Never execute untrusted source, packages or models on the host machine.
Do not put large artifacts or secrets on-chain.
Do not silently invent vulnerability labels. Preserve source and confidence/ground-truth status.
Keep scoring and policy thresholds configurable.
Use type-safe validation at API boundaries even though the frontend is JavaScript.
Write tests for each stage before moving to the next major stage.
After each phase, run the relevant tests and update README/docs.
Do not introduce Kubernetes unless the core MVP is already working.
Do not introduce deep learning, GNNs, LLM-based security classification or unnecessary microservices 
into the first working MVP.
Definition of done








One software repository can be scanned end-to-end.
One AI/model artifact can be scanned end-to-end.
The system creates structured evidence and feature records.
At least one supervised ML model and one anomaly model run successfully.
The dashboard shows the evidence and explanation behind the decision.
Blockchain verification succeeds for an anchored scan.
A later artifact hash mismatch can be detected.
The project runs from documented setup steps.
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
17. Current Free / Lower-Cost Coding-Agent Options (Checked 29 Sep 2026)
Pricing and availability change, so treat this section as a dated snapshot.
Tool
Current free availability
Useful for this project
Important caveat
Cursor Hobby
Free, limited Agent/Composer 
usage
Very good all-in-one 
editor/agent workflow
Free plan has usage limits
Kiro
Free tier; eligible students at 
participating universities may 
get 1 year free with 1,000 
credits/month
Strong spec-first workflow for 
a large multi-module project
Free plan has its own usage 
limits
Student offer requires 
eligibility; free tier still has 
limits
Cline
Extension is free/open source
Excellent for controlled, step
by-step agentic coding in VS 
Code; can use external or local 
model providers
The extension is free, but 
model inference can have 
separate cost unless you use a 
free/local provider
Amazon Q Developer
Perpetual free tier with 
monthly limits
Good IDE/CLI assistant, useful 
for backend, tests and 
debugging
Free tier is limited; current 
docs note IDE plugin support 
is planned to end Apr 30 2027
Devin Desktop (formerly 
Windsurf)
Free $0 plan
Full IDE + coding-agent 
experience
Practical recommendation
For a student building this project, check Kiro Students first because the current student program can provide 
a large free allowance at eligible universities. If not eligible, Cursor Hobby is still useful for planning and small 
agent tasks; Cline is a strong free/open-source editor agent when paired with a suitable model provider. Do not 
rely on old recommendations for Roo Code or the old Gemini CLI individual free tier: those offerings 
changed/ended in 2026.
Official sources







Cursor pricing: https://cursor.com/pricing
Cursor India Start: https://cursor.com/start
Kiro pricing: https://kiro.dev/pricing/
Kiro Students: https://kiro.dev/blog/students-2026/
Cline docs: https://github.com/cline/cline
Amazon Q Developer free tier: https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/q-tiers.html
Devin Desktop / Windsurf successor: https://devin.ai/desktop
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
18. MASTER PROMPT FOR CURSOR / KIRO / CLINE
How to use
Paste the prompt below into your coding agent at the root of a new empty repository. Ask the agent to work 
phase-by-phase and wait for tests to pass before moving forward. The prompt is intentionally strict so the 
agent builds the real security pipeline rather than a UI mock.
You are the lead engineer responsible for building ProvenanceX, a defensive software and AI/ML supply-chain security platform.
PROJECT GOAL
Build a working end-to-end application that accepts a software repository/package or an AI/model artifact, collects multi-layer security evidence, 
produces an explainable 0-1 risk score and ALLOW/REVIEW/BLOCK decision, records compact evidence on a local blockchain, and exposes the result 
through a professional cybersecurity dashboard.
TECHNOLOGY CONSTRAINTS- Backend: Python + FastAPI.- Database: PostgreSQL.- Frontend: React.js with plain JavaScript only. Do NOT use TypeScript or TSX.- Graph: NetworkX.- Software BOM: Syft + CycloneDX.- Vulnerability intelligence: OSV + NVD adapters.- ML: scikit-learn Random Forest + Isolation Forest; XGBoost as a comparison model.- Explainability: SHAP.- Integrity: SHA-256.- Provenance concepts: SLSA / in-toto / Sigstore-compatible concepts where practical.- Sandbox: Docker or an isolated VM; never execute untrusted artifacts directly on the host.- Blockchain: Solidity + Hardhat local network + web3.py.- CI/CD: GitHub Actions.- Use Docker Compose for the local multi-service stack.- Keep the first MVP simple; do not add Kubernetes, GNNs, deep learning or an LLM classifier unless explicitly requested later.
SECURITY BOUNDARIES
1. Treat every downloaded package/model/source archive as untrusted.
2. Never execute unknown code, package install scripts, model custom code, or model loading logic on the Windows host.
3. Dynamic tests must run only inside a disposable sandbox with strict timeouts, resource limits and restricted networking.
4. Use safe parsers for archives and model metadata.
5. Do not commit malicious samples, secrets, real private keys or API tokens.
6. Blockchain must store only compact evidence: artifact_hash, bom_hash, provenance_hash, risk_score, decision, scanner_version and timestamp.
7. Store large SBOMs, traces, source and model files off-chain.
8. Fail safely on malformed URLs, oversized files, parser errors and sandbox failures.
CORE INPUTS
Software:- GitHub repository URL or uploaded ZIP/project.- Optional branch/tag/commit.
AI/ML:- Model repository URL or uploaded model directory.- Optional revision/version.
NORMALIZED ARTIFACT RECORD
artifact_id
name
artifact_type
version
source
source_url
sha256
collected_at
scan_id
ProvenanceX | Software + AI/ML Supply-Chain Security
PIPELINE
ProvenanceX - Implementation Guide
Implement the pipeline in this exact order:
1. Receive input and create scan_id.
2. Create safe working directory.
3. Compute SHA-256.
4. Software: run Syft/CycloneDX and parse SBOM.
5. AI: create AI-BOM/model-lineage record from model files, configs, adapters, dataset/base-model relationships and runtime dependencies where 
available.
6. Build NetworkX dependency/lineage graph.
7. Query OSV/NVD for known package vulnerabilities.
8. Run provenance/integrity checks.
9. Run static analysis on package/model structure, scripts, imports, suspicious APIs, serialization and config.
10. Optionally run controlled dynamic analysis in sandbox and collect network/process/file/syscall/resource features.
11. Convert evidence into an ML feature vector.
12. Run Random Forest/XGBoost supervised prediction when labels exist.
13. Run Isolation Forest anomaly detection.
14. Combine evidence/model outputs in a configurable cross-layer fusion component.
15. Produce risk_score in 0..1.
16. Apply configurable policy to produce ALLOW/REVIEW/BLOCK.
17. Generate SHAP/top-feature explanation for the primary supervised model.
18. Persist scan/evidence/findings/risk data in PostgreSQL.
19. Anchor compact hashes + score + decision on Hardhat/local blockchain.
20. Expose verification endpoint.
21. Display the complete evidence story in React.
22. Provide a GitHub Actions example gate.
IMPORTANT ML DATASET DESIGN
Do NOT train on only package name -> vulnerability.
Build a composite feature dataset from:- public software repositories and package manifests- OSV/NVD vulnerability intelligence- generated software SBOMs- public AI/model repository metadata- model file/config/lineage information- sandbox telemetry generated from controlled fixtures- controlled tampering cases such as changed hash, removed provenance, altered config, replaced dependency, version inconsistency- public malicious/suspicious research samples only where ground truth and licensing permit
Use feature groups:
Software dependency:
dependency_count, transitive_depth, vulnerable_count, cvss_max, package_age, release_change, centrality
AI/model:
file_type_count, custom_code_present, serialization_type, tensor/config changes, adapter metadata
Provenance:
signed, provenance_present, source_known, commit_age, hash_changed, lineage_completeness
Metadata:
model_card_completeness, publisher_consistency, license_present, version_consistency
Static:
dangerous_import_count, suspicious_api_count, script_presence, archive_anomaly
Behavior:
network_count, process_count, file_write_count, syscall_count, external_destination_count, resource_spike
Graph:
new_edge_count, centrality_shift, suspicious_lineage, unexpected_parent_or_base_model
LABELS
Use:
benign
vulnerable
provenance_weak
suspicious
ProvenanceX | Software + AI/ML Supply-Chain Security
malicious_known_bad
ProvenanceX - Implementation Guide
Only use malicious_known_bad where ground truth is established. Do not equate vulnerability with maliciousness.
ML- Train Random Forest as the main supervised baseline.- Train XGBoost as a comparison.- Train Isolation Forest for anomaly detection.- Add train/validation/test split by repository/artifact family where possible.- Store model artifacts and preprocessing parameters.- Add metrics: precision, recall, F1, ROC-AUC, false-positive rate, false-negative rate.- Add SHAP explanations for the primary supervised model.- Include a rule/vulnerability-only baseline for evaluation.- Add an ablation experiment that removes one evidence layer at a time.
RISK
Keep policy thresholds configurable. Do not hard-code them as universal security standards.
The final score must be traceable to:- vulnerability evidence- provenance/integrity- graph evidence- static analysis- behavioral analysis- AI-specific model signals- ML outputs
API
Implement:
POST /api/v1/scans/software
POST /api/v1/scans/model
GET /api/v1/scans/{scan_id}
GET /api/v1/scans/{scan_id}/findings
GET /api/v1/scans/{scan_id}/risk
GET /api/v1/scans/{scan_id}/graph
GET /api/v1/scans/{scan_id}/evidence
GET /api/v1/scans/{scan_id}/blockchain
POST /api/v1/scans/{scan_id}/verify
DATABASE
Create normalized tables for:
Artifact
Scan
Component
Finding
ProvenanceRecord
GraphNode
GraphEdge
RiskDecision
BlockchainEvidence
UI REQUIREMENTS
The frontend must look like a professional cybersecurity product, not a generic full-stack CRUD app and not an obvious AI-generated dashboard.
STYLE:- dark neutral security-console aesthetic- restrained accent colors- strong information hierarchy- real tables, graphs and evidence sections- subtle borders and depth- compact risk indicators- clear typography
ProvenanceX | Software + AI/ML Supply-Chain Security
- concise micro-interactions
ProvenanceX - Implementation Guide- useful empty/loading/error states
AVOID:- huge gradients- excessive glassmorphism- Matrix code rain- hacker-movie visuals- oversized glowing headings- fake terminal animations- repetitive cards for every metric- meaningless 3D decorations- generic SaaS template look- fake data presented as real scan output
PAGES:
1. Dashboard
2. New Scan
3. Scan Details
4. Findings
5. Dependency Graph
6. Model Lineage
7. Risk Analysis
8. Blockchain Evidence
9. CI/CD
10. Settings
SCAN DETAILS PAGE MUST SHOW- artifact identity- hash and integrity status- risk score- decision- vulnerability findings- provenance status- static findings- behavioral findings- graph/lineage- top ML/SHAP factors- timeline- blockchain verification
IMPLEMENTATION PROCESS
Do not try to write the whole system in one giant change.
PHASE 0- Inspect repository.- Create /docs/architecture.md, /docs/implementation-plan.md and README.- Create backend/frontend/contracts/test structure.- Create Docker Compose.- Add health checks.- Create database connection and basic migration mechanism.- Create React shell and routing.- Run tests.
PHASE 1- Build software artifact ingestion and SHA-256.- Add upload/URL validation.- Add safe workspace handling.- Write unit/integration tests.
ProvenanceX | Software + AI/ML Supply-Chain Security
PHASE 2
ProvenanceX - Implementation Guide- Integrate Syft/CycloneDX.- Parse SBOM.- Add OSV/NVD adapters.- Store findings.- Add dependency graph.
PHASE 3- Build AI artifact ingestion.- Add model metadata, file inventory, config and lineage.- Add safe custom-code inspection.- Add model graph.
PHASE 4- Add static analysis feature extraction.- Add controlled Docker sandbox.- Add behavior telemetry parser.
PHASE 5- Add dataset generation scripts.- Generate controlled feature records.- Train baseline models.- Save preprocessing/model artifacts.- Add evaluation reports.
PHASE 6- Add cross-layer fusion.- Add policy configuration.- Add SHAP.- Add explanation API.
PHASE 7- Add Solidity evidence contract.- Deploy to Hardhat.- Add web3.py integration.- Add verification.
PHASE 8- Build the React dashboard with real API data.- Add graph visualization.- Add findings filters.- Add scan timeline.- Add blockchain verification panel.
PHASE 9- Add GitHub Actions gate.- Add end-to-end fixtures.- Run full test suite.- Write demo instructions.- Produce a reproducible local setup.
CODING STANDARDS- Python: clean modules, Pydantic validation, logging, error handling, docstrings for non-obvious logic.- React: reusable components, hooks, API service layer, no inline giant components.- Use environment variables for configuration.- Never swallow exceptions silently.- Return structured errors from the API.- Keep external integrations behind adapters so they can be mocked.- Add tests for every new module.
ProvenanceX | Software + AI/ML Supply-Chain Security
- Keep code readable for a college project team; do not over-engineer into dozens of microservices.
ProvenanceX - Implementation Guide
AGENT BEHAVIOR
Before making major changes:
1. Inspect the current repository.
2. Tell me the exact files you will create/change.
3. Implement one phase.
4. Run tests/lint/build checks.
5. Report what passed and what remains.
6. Only then proceed to the next phase.
When a third-party tool is unavailable, implement a clean adapter/interface and a mock provider for development rather than hard-coding fake final 
results.
DO NOT fabricate scan results, vulnerabilities, blockchain transactions or ML scores.
START NOW
First, inspect the repository and create the architecture + implementation plan for Phase 0. Do not jump directly into building the dashboard. The 
scanner pipeline is the core product.
ProvenanceX | Software + AI/ML Supply-Chain Security
ProvenanceX - Implementation Guide
ProvenanceX | Software + AI/ML Supply-Chain Security
19. Final Build Checklist
 Software repo or ZIP accepted. □
 AI model source or model directory accepted. □
 SHA-256 calculated for every scanned artifact. □
 Software SBOM generated and parsed. □
 AI-BOM/model-lineage record generated. □
 OSV/NVD lookup produces structured findings. □
 Dependency/lineage graph generated. □
 Static feature extraction works. □
 Sandbox telemetry works for controlled fixtures. □
 Feature dataset can be generated from scan evidence. □
 Random Forest trained and loaded for prediction. □
 Isolation Forest trained and loaded. □
 XGBoost comparison is available. □
 Final risk score is 0-1 and traceable. □
 ALLOW/REVIEW/BLOCK policy is configurable. □
 SHAP/top-factor explanation shown. □
 PostgreSQL persists evidence. □
 Hardhat contract stores compact evidence. □
 Verification detects a changed artifact hash. □
 React dashboard shows evidence, graph and decision. □
 GitHub Actions gate example works. □
 README can reproduce the local environment. □
 Tests pass for core pipeline. □
20. Source Notes
Project basis: ProvenanceX - Combined Software and AI Supply-Chain Security guide supplied in this 
conversation (15 pages). The project guide defines the unified software + AI artifact model, multi-layer 
evidence pipeline, ML design, dataset strategy, blockchain evidence model, CI/CD flow and 12-week 
roadmap.
The current coding-tool section was checked against official product documentation on 29 September 2026. Tool 
prices/free tiers can change after this date.
 https://cursor.com/pricing
 https://cursor.com/start
 https://kiro.dev/pricing/
 https://kiro.dev/blog/students-2026/
 https://github.com/cline/cline
 https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/q-tiers.html
 https://devin.ai/desktop
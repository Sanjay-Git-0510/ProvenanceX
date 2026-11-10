# ProvenanceX User Guide

A hands-on tour for a beginner. You start a throwaway copy of ProvenanceX, scan harmless test files, and see how
each result is produced.

**Everything here uses the separate demo project** (`provenancex-demo`), with its own ports, containers, database and
chain, so a development stack on the normal ports keeps running with its data untouched. The one shared item is the
image tag `provenancex-hardhat:0.1.0`, which `make demo` and `make e2e` may rebuild from your current checkout.

**How this guide was checked (2026-11-09).** The commands were run on the development machine (WSL2 Ubuntu, Docker
Compose v5.7.0, Python 3.14 in `backend/.venv`), and the expected output is what they printed. Anything that could not
be run says **Not run**. In particular, no browser was available, so **every click path is Not run**: the page names
and button labels come from the frontend source, and the data behind them was checked through the API.

**Read these results correctly.** All results here are wiring checks on harmless synthetic fixtures. They show that
the parts of the system work together. They do not measure how well ProvenanceX detects real attacks. Scan IDs, hashes
and timestamps will differ on your machine, and OSV data is live, so a new advisory can change a score.

## 1. Start the demo

### Prerequisites

| Need | Notes |
|---|---|
| Docker with Compose | On Windows, use Docker Desktop with WSL integration turned on. The demo override needs a recent Compose (tested with v5.7.0) |
| `python3` (3.11 or newer) and `curl` | Used by the demo script and the commands below |
| Internet access | The demo stops if it cannot reach OSV |
| Free ports | 15173, 18080, 15435 and 18546 |
| Trained models (optional) | `ml/models/` is git-ignored. Without it, scans say "ML model unavailable" and SHAP is empty. See [Troubleshooting](#4-troubleshooting) |

Keep the repository on the Linux filesystem (for example `~/provenancex`), not under `/mnt/c`.

### Commands

```bash
cd ~/provenancex
make demo
```

The first build takes several minutes. With cached layers it took about 50 seconds here. It ends like this:

```text
Results (wiring checks on synthetic fixtures, not detection results):
  demo-software_clean: decision=REVIEW score=0.478 confidence=0.630 not_evaluated=behavioral anchor=confirmed scan=...
  demo-software_risky_config: decision=REVIEW score=0.529 confidence=0.630 not_evaluated=behavioral anchor=confirmed scan=...
  demo-model_clean: decision=REVIEW score=0.350 confidence=0.488 not_evaluated=vulnerability,behavioral anchor=confirmed scan=...
  demo-model_risky_config: decision=REVIEW score=0.495 confidence=0.488 not_evaluated=vulnerability,behavioral anchor=confirmed scan=...
  demo-model_dangerous_global: decision=BLOCK score=0.721 confidence=0.488 not_evaluated=vulnerability,behavioral anchor=confirmed scan=...

Demo running. UI: http://localhost:15173  API: http://localhost:18080/api/v1
Remove it with: make demo-down
```

| Service | Address (all bound to 127.0.0.1) |
|---|---|
| Dashboard | <http://localhost:15173> |
| API | <http://localhost:18080/api/v1> |
| PostgreSQL | port 15435 |
| Hardhat chain | port 18546 |

### When you finish

```bash
make demo-down
```

This removes only the demo's containers, network and volumes, including every scan you made in the tour. The images
built for the demo (`provenancex-demo-api`, `provenancex-demo-frontend`, and the shared `provenancex-hardhat:0.1.0`)
stay until you remove them by hand.

## 2. Set up your terminal

Paste this once, in the terminal you will use for the tour. It sets the demo's addresses and adds a few small helpers.

```bash
cd ~/provenancex
export API=http://localhost:18080/api/v1
export PROVENANCEX_API_URL=http://127.0.0.1:18080/api/v1
export F=backend/tests/fixtures/e2e
DEMO="docker compose -p provenancex-demo --project-directory . -f docker-compose.yml -f docker-compose.demo.yml"

# scan software|model FOLDER NAME: zip a folder, upload it, print the new scan ID.
scan() {
  local zip; zip=$(mktemp -u --suffix=.zip)
  python3 -m zipfile -c "$zip" "$2"/*
  curl -s -F file=@"$zip" -F name="$3" "$API/scans/$1" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])'
  rm -f "$zip"
}

# find_scan NAME: print the newest scan with this name.
find_scan() {
  curl -s "$API/scans?limit=100" | python3 -c '
import json,sys
print(next(i["scan_id"] for i in json.load(sys.stdin)["items"] if i["artifact"]["name"]==sys.argv[1]))' "$1"
}

# stages ID: the scan status, then each pipeline stage in the order it ran.
stages() {
  curl -s "$API/scans/$1" | python3 -c '
import json,sys
d=json.load(sys.stdin); print("status:", d["status"])
for name,s in sorted((d["stages"] or {}).items(), key=lambda x:x[1].get("started_at") or x[1].get("finished_at")):
    print("  %-16s%-11s%s" % (name, s["status"], s.get("reason") or ""))'
}

# wait_scan ID: wait until the scan has finished.
wait_scan() {
  until curl -s "$API/scans/$1" | python3 -c '
import json,sys
sys.exit(0 if json.load(sys.stdin)["status"] in ("completed","failed") else 1)'; do sleep 1; done
}

# risk ID: the decision, why it was made, and each evidence layer.
risk() {
  curl -s "$API/scans/$1/risk" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("decision=%s basis=%s risk=%.3f rule_only=%.3f confidence=%.3f (%s)" % (d["decision"], d["decision_basis"], d["risk_score"], d["rule_only_score"], d["confidence"], d["confidence_label"]))
for r in d["decision_reasons"]: print("  reason:", r)
print("  hard rules fired:", [r["rule_id"] for r in d["hard_rules"]["fired"]])
print("  not evaluated:", d["not_evaluated_layers"])
for l in d["layers"]:
    s="none" if l["score"] is None else "%.3f" % l["score"]
    print("  %-22s%-15s%-7s" % (l["layer"], l["status"], s), [x["name"] for x in l.get("signals",[])])'
}

# findings ID: every finding, highest CVSS first.
findings() {
  curl -s "$API/scans/$1/findings" | python3 -c '
import json,sys
for f in json.load(sys.stdin)["items"]:
    print("  %-14s%-8scvss=%s  %s" % (f["category"], f["severity"], f["cvss"]["score"], f["identifier"]))'
}

# verify ID: ask for verification and print the state and any field that does not match.
verify() {
  curl -s -X POST "$API/scans/$1/verify" | python3 -c '
import json,sys
d=json.load(sys.stdin); print(d["state"], "-", d["reason"]["code"], "-", d["reason"]["message"])
print("  fields:", {f["field"]:f["status"] for f in d["fields"] if f["status"]!="match"} or "all match" if d["fields"] else "none compared")'
}
```

> **Keep `PROVENANCEX_API_URL` set.** The gate script's default address is port 8000, which is the development stack.
> Exporting this variable points the gate at the demo instead.

## 3. Guided tour

### a. Scan the clean software fixture and watch the timeline

**In the dashboard (Not run):**
1. Open <http://localhost:15173> and choose **New Scan**.
2. Under **Artifact** pick **Software**. Under **Source** pick **Upload ZIP**.
3. In **ZIP file**, choose a ZIP of the files in `backend/tests/fixtures/e2e/software_clean`. The files must be at the
   top level of the ZIP.
4. Enter a **Display name** and click **Start scan**. You land on **Scan Details**.
5. The **Timeline** panel lists each stage with its status as the scan runs. The **Artifact identity and integrity**
   panel shows the hash.

**With curl:**

```bash
A=$(scan software $F/software_clean tour-software-clean)
echo "$A"
stages "$A"
wait_scan "$A"
sleep 2
stages "$A"
risk "$A"
findings "$A"
```

**Expected output** (first `stages` varies with timing):

```text
status: completed
  sbom            completed
  graph           completed
  vulnerabilities completed
  provenance      completed
  static          completed
  sandbox         skipped    sandbox disabled (SANDBOX_PROVIDER=disabled)
  risk            completed
  anchor          completed
decision=REVIEW basis=score risk=0.478 rule_only=0.421 confidence=0.630 (MEDIUM)
  reason: Rule-only score 0.421 is in the REVIEW band
  hard rules fired: []
  not evaluated: ['behavioral']
  vulnerability         evaluated      0.539   ['cvss_max', 'vulnerable_count']
  provenance_integrity  partial        0.435   ['provenance_present', 'source_known', 'revision_pinned']
  graph                 partial        0.000   []
  static                evaluated      0.050   ['script_presence']
  behavioral            not_evaluated  none    []
  ai_specific           not_applicable none    []
  ml_supervised         evaluated      0.972   []
  ml_anomaly            evaluated      0.517   []
  vulnerability MEDIUM  cvss=5.3  GHSA-65pc-fj4g-8rjx
  provenance    LOW     cvss=None  PX-PROV-NO-ATTESTATION
  provenance    LOW     cvss=None  PX-PROV-NO-SIGNATURE
  provenance    LOW     cvss=None  PX-PROV-SOURCE-UNKNOWN
```

The scan took about 4 seconds here.

**Why a "clean" fixture gets REVIEW.** It is harmless, but the evidence is not spotless. Its one dependency,
`idna==3.10`, has a real OSV advisory, and an upload has no known origin. Together they put the rule-only score at
0.421, inside the REVIEW band (0.35 up to 0.70). `behavioral` is not evaluated because the sandbox is off, and that
means "not checked", not "clean".

> **What is happening inside.**
> Steps 1 to 3 (receive, safe workspace, SHA-256): `app/api/scans.py`, `app/security/archive.py`, `app/core/hashing.py`.
> Step 4 (SBOM): `app/pipeline/sbom_stage.py`, `app/scanners/sbom/syft.py`.
> Step 6 (graph): `app/pipeline/graph_stage.py`, `app/graph/dependency_graph.py`.
> Step 7 (OSV): `app/pipeline/vuln_stage.py`, `app/scanners/vulns/osv.py`. The demo turns NVD off.
> Step 8 (provenance): `app/pipeline/provenance_stage.py`, `app/provenance/checks.py`.
> Step 9 (static): `app/pipeline/static_stage.py`, `app/scanners/static/analyzer.py`.
> Step 10 (sandbox): `app/pipeline/sandbox_stage.py`, skipped by default.
> Steps 11 to 18 (features, ML, fusion, policy, SHAP, saving): `app/pipeline/risk_stage.py`, `app/risk/service.py`.
> The order is fixed in `app/pipeline/software.py`, and the Timeline panel is `frontend/src/components/scan/Timeline.jsx`.

### b. Scan the risky-config fixture and see the hard rule

**In the dashboard (Not run):** On the **Dashboard**, open `demo-software_risky_config` from **Recent scans**. In
**Risk Analysis**, the **Hard rules** panel lists the rule that fired.

**With curl:** the demo already scanned this fixture.

```bash
B=$(find_scan demo-software_risky_config)
risk "$B"
findings "$B"
```

**Expected output:**

```text
decision=REVIEW basis=score risk=0.529 rule_only=0.484 confidence=0.630 (MEDIUM)
  reason: install_hook_present: The artifact declares install-time hooks
  reason: Rule-only score 0.484 is in the REVIEW band
  hard rules fired: ['install_hook_present']
  not evaluated: ['behavioral']
  vulnerability         evaluated      0.539   ['cvss_max', 'vulnerable_count']
  provenance_integrity  partial        0.435   ['provenance_present', 'source_known', 'revision_pinned']
  graph                 partial        0.000   []
  static                evaluated      0.525   ['script_presence', 'install_hook_count']
  behavioral            not_evaluated  none    []
  ai_specific           not_applicable none    []
  ml_supervised         evaluated      0.968   []
  ml_anomaly            evaluated      0.526   []
  vulnerability MEDIUM  cvss=5.3  GHSA-65pc-fj4g-8rjx
  provenance    LOW     cvss=None  PX-PROV-NO-ATTESTATION
  provenance    LOW     cvss=None  PX-PROV-NO-SIGNATURE
  provenance    LOW     cvss=None  PX-PROV-SOURCE-UNKNOWN
  static        MEDIUM  cvss=None  PX-STATIC-INSTALL-CMDCLASS
```

The only difference from step a is a `setup.py` whose `cmdclass` overrides the install command. It does nothing and
is never run. The static layer rose from 0.050 to 0.525, and a hard rule fired. `basis=score` appears because the
score band was already REVIEW, so the hard rule did not make the decision any stricter.

> **What is happening inside.** Step 9: `app/scanners/static/install_hooks.py` finds the hook by parsing `setup.py`.
> Step 16: `app/risk/policy.py` applies the hard rule, which is defined in `app/risk/policy_config.py`.

### c. Scan a model fixture and read the AI-specific layers

**In the dashboard (Not run):** Open `demo-model_risky_config`, then **Risk Analysis**, and read the
`ai_specific` row in **Evidence layers**. **Model Lineage** shows the graph.

**With curl:**

```bash
C=$(find_scan demo-model_risky_config)
stages "$C"
risk "$C"
findings "$C"
curl -s "$API/scans/$C/graph" | python3 -c '
import json,sys
d=json.load(sys.stdin); print(d["graph_kind"], "lineage_completeness:", d["features"]["lineage_completeness"])
for e in d["edges"]: print(" ", e["source"], "--"+e["relation"]+"->", e["target"], "("+e["origin"]+")")'
```

**Expected output:**

```text
status: completed
  aibom           completed
  graph           completed
  vulnerabilities skipped    no exactly pinned runtime dependencies (name==version) to look up
  provenance      completed
  static          completed
  sandbox         skipped    sandbox disabled (SANDBOX_PROVIDER=disabled)
  risk            completed
  anchor          completed
decision=REVIEW basis=score risk=0.495 rule_only=0.462 confidence=0.488 (MEDIUM)
  reason: install_hook_present: The artifact declares install-time hooks
  reason: custom_model_code: The model ships custom code
  reason: Rule-only score 0.462 is in the REVIEW band
  hard rules fired: ['install_hook_present', 'custom_model_code']
  not evaluated: ['vulnerability', 'behavioral']
  vulnerability         not_evaluated  none    []
  provenance_integrity  partial        0.435   ['provenance_present', 'source_known', 'revision_pinned']
  graph                 partial        0.000   []
  static                evaluated      0.525   ['script_presence', 'install_hook_count']
  behavioral            not_evaluated  none    []
  ai_specific           partial        0.460   ['custom_code_present', 'model_card_completeness']
  ml_supervised         evaluated      0.736   []
  ml_anomaly            evaluated      0.591   []
  provenance    LOW     cvss=None  PX-PROV-NO-ATTESTATION
  provenance    LOW     cvss=None  PX-PROV-NO-SIGNATURE
  provenance    LOW     cvss=None  PX-PROV-SOURCE-UNKNOWN
  static        MEDIUM  cvss=None  PX-REMOTE-CODE-REQUIRED
lineage lineage_completeness: 0.6667
  artifact:root --bundled_with-> file:config.json (inventory)
  artifact:root --bundled_with-> file:configuration_custom.py (inventory)
  artifact:root --bundled_with-> file:modeling_custom.py (inventory)
  artifact:root --derived_from-> model:example-org/base-model (model_card)
```

How to read it:
- `custom_code_present` means `config.json` has an `auto_map` that points at Python files in the model. They are
  listed and parsed, never imported.
- `install_hook_present` fires because `auto_map` targets count as install hooks.
- `vulnerability` is not evaluated because the fixture pins no dependencies. That is missing evidence.
- Confidence 0.488 is below 0.60, so this scan could never be ALLOW, whatever its score.
- The lineage is **declared by the artifact**. Parent models are not fetched or confirmed.

> **What is happening inside.** Step 5 (AI-BOM): `app/pipeline/aibom_stage.py`, `app/scanners/model/aibom.py`,
> `custom_code.py`, `model_card.py`. Step 6 (lineage): `app/pipeline/lineage_stage.py`, `app/graph/lineage_graph.py`.
> The AI-specific layer is scored in `app/risk/layers.py`, and the order is fixed in `app/pipeline/model.py`.

### d. See the BLOCK scan and why

**In the dashboard (Not run):** Open `demo-model_dangerous_global`. On **Scan Details**, the **Static** findings show
the pickle finding. **Risk Analysis** shows the hard rule and its evidence link.

**With curl:**

```bash
D=$(find_scan demo-model_dangerous_global)
risk "$D"
findings "$D"
```

**Expected output:**

```text
decision=BLOCK basis=score risk=0.721 rule_only=0.701 confidence=0.488 (MEDIUM)
  reason: dangerous_pickle_globals: A pickle references globals that can execute code
  reason: Rule-only score 0.701 is in the BLOCK band
  hard rules fired: ['dangerous_pickle_globals']
  not evaluated: ['vulnerability', 'behavioral']
  vulnerability         not_evaluated  none    []
  provenance_integrity  partial        0.435   ['provenance_present', 'source_known', 'revision_pinned']
  graph                 partial        0.000   []
  static                evaluated      0.900   ['pickle_dangerous_global_count']
  behavioral            not_evaluated  none    []
  ai_specific           partial        0.370   ['serialization_type', 'model_card_completeness']
  ml_supervised         evaluated      0.717   []
  ml_anomaly            evaluated      0.600   []
  static        LOW     cvss=None  PX-CODE-EXECUTING-FORMAT
  static        HIGH    cvss=None  PX-PICKLE-DANGEROUS-IMPORT
  provenance    LOW     cvss=None  PX-PROV-NO-ATTESTATION
  provenance    LOW     cvss=None  PX-PROV-NO-SIGNATURE
  provenance    LOW     cvss=None  PX-PROV-SOURCE-UNKNOWN
```

The fixture's `weights.pkl` is only a few bytes: a
reference to `os.system` and a `STOP`, with no call. The demo creates it in a temporary folder and it is never loaded.
The hard rule alone would have forced BLOCK. Here the score reached the BLOCK band too, so `basis` says `score`. A
static finding has no CVSS, because it is a suspicious signal and not a known vulnerability.

> **What is happening inside.** Step 5: `app/scanners/model/pickle_scan.py` walks the opcodes with `pickletools` and
> never unpickles. Step 16: `dangerous_pickle_globals` in `app/risk/policy_config.py`, applied in `app/risk/policy.py`.

### e. Findings, graphs and Risk Analysis

**In the dashboard (Not run):**
- **Findings**: choose a scan in **Scan (latest 100)**, then filter by category, severity or source. Known
  vulnerabilities carry a CVSS value, and static or provenance findings do not.
- **Dependency Graph** (software) or **Model Lineage** (models): choose a scan. Use **Search nodes**, **Node type** and
  **Relation**, and read **Graph features** and **Limitations**. A table below the drawing lists every node and edge.
- **Risk Analysis**: choose a scan. **Separate measures** shows the four scores, **Evidence layers** the layer
  breakdown, and **ML factors (SHAP)** the model factors. **Features with no value** lists missing evidence.

You can link straight to a scan, for example `http://localhost:15173/risk?scan=<scan_id>`.

**With curl:**

```bash
E=$(find_scan demo-software_clean)
curl -s "$API/scans/$E/findings?category=vulnerability" | python3 -c '
import json,sys
f=json.load(sys.stdin)["items"][0]; print(f["identifier"], f["aliases"], f["severity"], f["cvss"]["score"], "source="+f["source"])'
curl -s "$API/scans/$E/graph" | python3 -c '
import json,sys
d=json.load(sys.stdin); print(d["graph_kind"], [n["label"] for n in d["nodes"]], d["features"]["transitive_resolution"])
print(d["limitations"][0])'
curl -s "$API/scans/$E/risk" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for k,v in d["scores"].items(): print("%-18s%.3f  %s" % (k, v["value"], v["label"]))
x=d["explanation"]; print("SHAP explains:", x["explains"]); print("base", round(x["base_value"],3), "output", round(x["model_output"],3))
for t in x["top_factors"][:3]: print("  %-26svalue=%-7sevaluated=%-6s%+.3f" % (t["feature"], t["value"], t["evaluated"], t["shap_contribution"]))
print(d["training_data"]["notice"])'
```

**Expected output:**

```text
GHSA-65pc-fj4g-8rjx ['CVE-2026-45409', 'PYSEC-2026-215'] MEDIUM 5.3 source=osv
dependency ['demo-software_clean', 'idna@3.10'] none
The SBOM declares no package-to-package edges (e.g. a bare requirements.txt). Transitive dependencies are unknown: dependencies are never installed or resolved.
provenancex_risk  0.478  ProvenanceX risk (0 to 1, fused from the evidence layers)
cvss_max          5.300  Highest CVSS base score among known advisories (0 to 10)
ml_probability    0.972  Random Forest probability of any non-benign class (not the risk score)
anomaly_score     0.517  Isolation Forest anomaly score (higher is more unusual; not the risk score)
SHAP explains: Random Forest probability of any non-benign class (not the ProvenanceX risk score)
base 0.75 output 0.972
  vulnerable_count          value=1      evaluated=True  +0.137
  cvss_max                  value=5.3    evaluated=True  +0.130
  source_known              value=False  evaluated=True  -0.031
These models were trained on synthetic data. Their outputs do not measure real-world detection and they make no malware-detection claim.
```

The four numbers measure different things, so do not compare them directly. An ML probability of 0.972 on a harmless
project means "not benign under the synthetic training labels", and those labels include "vulnerable". It does not mean
"97% malicious". SHAP explains the Random Forest output only, not the ProvenanceX risk score. A factor with
`evaluated=False` shows how the model reacts to missing evidence, and says nothing about the artifact.

> **What is happening inside.** Step 11: `app/ml/features.py`. Step 12: `app/risk/model_runtime.py`. Step 13: the
> Isolation Forest, in the same file. Step 14: `app/risk/fusion.py`. Step 17: `app/risk/explain.py`. The page is
> `frontend/src/pages/RiskAnalysis.jsx`.

### f. Anchor, verify, tamper, restore, stop the chain

The demo anchors every scan automatically, so asking again is refused:

```bash
curl -s -w '\nHTTP %{http_code}\n' -X POST "$API/scans/$A/anchor"
verify "$A"
```

```text
{"error":{"code":"anchor_already_exists","message":"This scan is already anchored","details":null}}
HTTP 409
VERIFIED - verified - Every value matches
  fields: all match
```

To anchor by hand, recreate only the demo API with automatic anchoring off. The parentheses keep the settings,
including the public Hardhat test key, out of your terminal session.

```bash
(
  export POSTGRES_USER=provenancex POSTGRES_PASSWORD=provenancex-demo POSTGRES_DB=provenancex
  export BLOCKCHAIN_PROVIDER=web3 BLOCKCHAIN_ANCHOR_ON_SCAN=false SBOM_PROVIDER=syft VULN_PROVIDER=osv
  export NVD_ENABLED=false HF_PROVIDER=hf SANDBOX_PROVIDER=disabled
  export BLOCKCHAIN_CONTRACT_ADDRESS=$(docker exec provenancex-demo-api-1 printenv BLOCKCHAIN_CONTRACT_ADDRESS)
  export BLOCKCHAIN_PRIVATE_KEY=$(docker exec provenancex-demo-api-1 printenv BLOCKCHAIN_PRIVATE_KEY)
  $DEMO up -d --wait --no-deps api
)
V=$(scan software $F/software_clean tour-manual-anchor)
wait_scan "$V"
sleep 2
verify "$V"
curl -s -o /dev/null -w 'anchor HTTP %{http_code}\n' -X POST "$API/scans/$V/anchor"
verify "$V"
```

```text
NOT ANCHORED - no_anchor - This scan has not been anchored
  fields: none compared
anchor HTTP 200
VERIFIED - verified - Every value matches
  fields: all match
```

Now change one file in the scan's workspace, inside the demo's API container:

```bash
docker exec provenancex-demo-api-1 sh -c "echo '# tampered' >> /app/workspace/$V/src/main.py"
verify "$V"
```

```text
MISMATCH - evidence_mismatch - Changed: artifact_hash, record_hash
  fields: {'artifact_hash': 'mismatch', 'record_hash': 'mismatch'}
```

Remove the added line. The file is byte-for-byte the same again, so the hash matches:

```bash
docker exec provenancex-demo-api-1 sed -i '$d' "/app/workspace/$V/src/main.py"
verify "$V"
```

```text
VERIFIED - verified - Every value matches
  fields: all match
```

Stop the chain:

```bash
$DEMO stop hardhat
verify "$V"
```

```text
UNKNOWN - chain_unavailable - The chain could not be reached
  fields: {'artifact_id': 'unavailable', ... 'record_hash': 'unavailable'}
```

(The nine fields all print as `unavailable`. The output is shortened here.)

Starting it again does **not** bring the anchors back, because the chain lives in memory:

```bash
$DEMO start hardhat
sleep 6
verify "$V"
```

```text
UNKNOWN - chain_state_lost - The contract no longer exists on the chain
  fields: {'artifact_id': 'unavailable', ... 'record_hash': 'unavailable'}
```

To get a working chain again, run `make demo-down` and then `make demo`. Step g works without one.

**In the dashboard (Not run):** The page is **Blockchain Evidence**. Choose a scan and click **Verify** after each
change. The result and a per-field table appear in the **Verification** panel, and the **Anchor record** panel shows
the stored data. The UI has no Anchor button.

VERIFIED means the record has not changed since it was anchored. It does not mean the scanner was right or the
artifact is safe.

> **What is happening inside.** Step 19 (anchor): `app/pipeline/anchor_stage.py`, `app/blockchain/anchoring.py`,
> `app/blockchain/web3_provider.py`, `contracts/contracts/ProvenanceEvidence.sol`. Only eight fields go on-chain.
> Step 20 (verify): `app/blockchain/verification.py` recomputes the three hashes from the files and compares them with
> the database row, the live tables and the chain.

### g. Run the CI gate and see every exit code

The gate zips a folder, uploads it, waits for the decision and sets its exit code. Without `GITHUB_STEP_SUMMARY`, it
prints the job summary to the terminal on one line. With it, the summary goes to that file, as in GitHub Actions.

**Exit 0: passes (REVIEW passes by default)**

```bash
python3 scripts/ci_gate.py $F/software_clean --name tour-gate-0 | tail -1; echo "exit=${PIPESTATUS[0]}"
```

```text
ProvenanceX gate: PASS (exit 0): The decision is REVIEW, which passes by default
exit=0
```

**Exit 1: fails (REVIEW with `--fail-on-review`), with the job summary**

```bash
SUMMARY=$(mktemp)
GITHUB_STEP_SUMMARY=$SUMMARY python3 scripts/ci_gate.py $F/software_risky_config --name tour-gate-1 --fail-on-review | tail -1
echo "exit=${PIPESTATUS[0]}"
cat "$SUMMARY"
```

```text
ProvenanceX gate: FAIL (exit 1): The decision is REVIEW and --fail-on-review is set
exit=1
## ProvenanceX gate

**FAIL** (exit 1): The decision is REVIEW and \-\-fail\-on\-review is set

Scan ID: `...`

| Field | Value |
| --- | --- |
| Decision | REVIEW |
| ProvenanceX risk score | 0.529 |
| Confidence | 0.630 (MEDIUM) |
| Not-evaluated layers | behavioral |
| Partial layers | provenance\_integrity, graph |
| Hard rules fired | install\_hook\_present |
| Mock evidence | None |
| ML status | available |
| Training data | These models were trained on synthetic data\. Their outputs do not measure real\-world detection and they make no malware\-detection claim\. |

A not-evaluated layer is missing evidence, not a clean result. Decisions come from hand-set research parameters.
```

**Exit 1: a live BLOCK.** This builds the same inert pickle reference the demo uses, in a temporary folder.

```bash
T=$(mktemp -d)
cp $F/model_clean/* "$T"/
printf 'cos\nsystem\n.' > "$T/weights.pkl"
python3 scripts/ci_gate.py "$T" --kind model --name tour-gate-block | tail -1; echo "exit=${PIPESTATUS[0]}"
rm -rf "$T"
```

```text
ProvenanceX gate: FAIL (exit 1): The decision is BLOCK
exit=1
```

**Exit 2: no trustworthy result.** A pass is never assumed.

```bash
python3 scripts/ci_gate.py $F/software_clean --api-url http://127.0.0.1:1/api/v1 | tail -1; echo "exit=${PIPESTATUS[0]}"
python3 scripts/ci_gate.py $F/software_clean --name tour-gate-timeout --timeout 0 --poll 0 | tail -1; echo "exit=${PIPESTATUS[0]}"
```

```text
ProvenanceX gate: INCONCLUSIVE (exit 2): The API could not be reached
exit=2
ProvenanceX gate: INCONCLUSIVE (exit 2): The scan did not finish before the timeout
exit=2
```

**Exit 2 from mock evidence, and `--allow-mock`.** This recreates the demo API with labeled mock providers:

```bash
(
  export POSTGRES_USER=provenancex POSTGRES_PASSWORD=provenancex-demo POSTGRES_DB=provenancex
  export BLOCKCHAIN_PROVIDER=disabled BLOCKCHAIN_ANCHOR_ON_SCAN=false SBOM_PROVIDER=mock VULN_PROVIDER=mock
  export NVD_ENABLED=false HF_PROVIDER=hf SANDBOX_PROVIDER=disabled
  $DEMO up -d --wait --no-deps api
)
python3 scripts/ci_gate.py $F/software_clean --name tour-gate-mock | tail -1; echo "exit=${PIPESTATUS[0]}"
python3 scripts/ci_gate.py $F/software_clean --name tour-gate-mock --allow-mock | tail -1; echo "exit=${PIPESTATUS[0]}"
```

```text
ProvenanceX gate: INCONCLUSIVE (exit 2): The REVIEW decision used mock evidence, and --allow-mock was not set
exit=2
ProvenanceX gate: PASS (exit 0): The decision is REVIEW, which passes by default
exit=0
```

**Exit 3 does not come from the gate.** `scripts/ci_gate.py` only uses 0, 1 and 2. Exit 3 means **NOT RUN**, and it comes
from `scripts/demo.sh` and `scripts/run_e2e.sh`. Starting a second demo while one is running shows it, and leaves the
running demo alone:

```bash
scripts/demo.sh; echo "exit=$?"
```

```text
DEMO NOT RUN: port 15173 is in use. If an earlier demo is running, use: make demo-down
exit=3
```

Through `make`, the shell sees a different number. `make` prints `Error 3` but exits with its own failure code, 2. The
same applies to `make gate`, where a gate exit of 1 or 2 also becomes 2. To read the real code in a script, call the
script directly.

| Exit | From | Meaning |
|---|---|---|
| 0 | gate | ALLOW, or REVIEW by default, with a real score |
| 1 | gate | BLOCK, or REVIEW with `--fail-on-review` |
| 2 | gate | Failed scan, timeout, API error, no decision, null score on ALLOW or REVIEW, or mock evidence without `--allow-mock` |
| 3 | `demo.sh`, `run_e2e.sh` | NOT RUN: a prerequisite was unavailable |

**The GitHub workflow is Not run.** `.github/workflows/provenancex-gate.yml` runs only on a pull request or by hand.

> **What is happening inside.** Step 22: `scripts/ci_gate.py`. The `evaluate` function holds the exit-code rules, and
> the workflow is `.github/workflows/provenancex-gate.yml`. Mock output is tagged `source="mock"` by the adapters in
> `app/scanners/sbom/mock.py` and `app/scanners/vulns/mock.py`.

When you are done, run `make demo-down`.

## 4. Troubleshooting

| Symptom | Cause | Fix | Checked how |
|---|---|---|---|
| `DEMO NOT RUN: port 15173 is in use` (or another demo port) | An earlier demo, or another program, holds the port | `make demo-down`. If that is not it, find the program with `ss -ltnp \| grep 15173` | Run: second start while a demo was up |
| `DEMO NOT RUN: OSV could not be reached` | No internet, or OSV is down | Check your connection and try again. The demo does not fall back to mock data | Run, with a fake `curl` that always fails |
| `DEMO NOT RUN: Docker is not running` | Docker Desktop is stopped, or WSL integration is off | Start Docker Desktop and turn on **Settings → Resources → WSL Integration** for your distro | Run, with a fake `docker` that always fails. Real Docker was not stopped |
| `ml.status` is `unavailable`, with `ML model unavailable: Missing model artifact: manifest.json`, and the gate says `ML model unavailable (rule-based score)` | `ml/models/` is missing (it is git-ignored, so a fresh clone has none) | The scan still works, on rules only. To train: the three commands below | Message seen by pointing the demo API at a missing folder. The training commands were **Not run**, to protect the existing models |
| Verify says `UNKNOWN`, `chain_state_lost` | Hardhat restarted, and its chain lives in memory | `make demo-down`, then `make demo` | Run (step f) |
| Verify says `UNKNOWN`, `chain_unavailable` | Hardhat is stopped | `$DEMO start hardhat` brings the chain back but not the anchors, so restart the demo | Run (step f) |
| Verify or Anchor says `chain_provider_disabled` / `blockchain_disabled` | The API is running with `BLOCKCHAIN_PROVIDER=disabled` | Use the demo, or see "Local chain" in `README.md` | Run (after step g's mock setup) |
| `make demo` printed `Error 3`, but `$?` is 2 | `make` reports its own exit code | Run `scripts/demo.sh` to see 3 | Run |
| The gate reached the wrong stack | `PROVENANCEX_API_URL` was not set, so it used port 8000 | Repeat [section 2](#2-set-up-your-terminal) or pass `--api-url` | Read from `scripts/ci_gate.py`. Never run against port 8000 |

Training commands (from the repository root, **Not run** for this guide):

```bash
backend/.venv/bin/python ml/scripts/generate_dataset.py --families 200 --seed 42
backend/.venv/bin/python ml/scripts/train_models.py --seed 42
backend/.venv/bin/python ml/scripts/evaluate_models.py
```

## 5. Test commands

Start the demo first, because the Postgres and Hardhat commands below use it instead of a development stack. The
`pytest` run writes to the database, and the demo's is disposable. `DEMO` comes from section 2.

```bash
export DATABASE_URL=postgresql+psycopg://provenancex:provenancex-demo@127.0.0.1:15435/provenancex
```

| What | Command | What it proves | Result here |
|---|---|---|---|
| Python lint | `cd backend && .venv/bin/ruff check . ../ml/scripts ../scripts --config pyproject.toml` | No lint errors in backend, ML or scripts | Passed |
| Python format | `cd backend && .venv/bin/ruff format --check . ../ml/scripts ../scripts --config pyproject.toml` | Code is consistently formatted | Passed |
| Migrations | `cd backend && .venv/bin/alembic upgrade head && .venv/bin/alembic check` | Migrations apply, and the models match the schema | Passed, no drift |
| Backend tests | `cd backend && MODEL_PATH=../ml/models .venv/bin/pytest -q -m "not network and not sandbox and not chain"` | Unit, API, security and Postgres integration tests | 2616 passed, 0 failed, 0 skipped, 78 deselected |
| Live services | `cd backend && PROVENANCEX_NETWORK_TESTS=1 MODEL_PATH=../ml/models .venv/bin/pytest -q -m "network and not chain"` | Real GitHub, OSV, NVD and Hugging Face calls work | 7 passed |
| Sandbox | `cd backend && PROVENANCEX_SANDBOX_TESTS=1 .venv/bin/pytest -q -m sandbox` | Each isolation boundary holds in a real container. Needs `docker build -t provenancex-sandbox:0.1.0 docker/sandbox` | 35 passed |
| Chain | `cd backend && PROVENANCEX_CHAIN_TESTS=1 .venv/bin/pytest -q -m "chain and not network"`, with `BLOCKCHAIN_RPC_URL=http://127.0.0.1:18546`, a freshly deployed `BLOCKCHAIN_CONTRACT_ADDRESS` and the node's `BLOCKCHAIN_PRIVATE_KEY` | Anchoring and verification on a real local chain, including tampering | 30 passed |
| Frontend lint | `cd frontend && npm run lint` | No ESLint errors | Passed |
| Frontend tests | `cd frontend && npm test -- --run` | Components, the API layer, accessibility and colour contrast, in jsdom (no real browser or layout) | 483 passed in 20 files |
| Frontend build | `cd frontend && npm run build` | The production bundle builds | Passed |
| Contract tests | `$DEMO run --rm --no-deps hardhat npx hardhat test --no-compile` | The Solidity contract's rules: append-only, deployer-only, eight fields | 32 passing |
| ABI check | `docker run --rm -v "$PWD/backend/app/blockchain/abi.json:/tmp/abi.json:ro" provenancex-hardhat:0.1.0 node scripts/check-abi.js /tmp/abi.json` | The backend's contract interface matches the compiled contract | Matches, 17 entries |
| End to end | `scripts/run_e2e.sh` (or `make e2e`) | The real API, Postgres, Syft, live OSV, chain, tampering and a live BLOCK through the gate. Uses its own disposable project and ports. Exit 0 passed, 1 failed, 3 NOT RUN | Exit 0 |

None of these tests measures detection accuracy on real attacks. All ML data is synthetic, and there are no real
malware samples.

`npm ci` (from the README) was **Not run**, to leave the existing `node_modules` in place. These checks ran on Node 26
and Python 3.14 on the host. CI uses Node 22 and Python 3.12, and that combination was **Not run**.

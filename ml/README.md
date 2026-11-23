# ml/

Dataset generation, training and evaluation for ProvenanceX.

- `scripts/`: command-line entry points (see `scripts/README.md`). The logic is in
  `backend/app/ml/`.
- `data/`: generated feature datasets (git-ignored)
- `models/`: trained models and preprocessing parameters (git-ignored)
- `reports/`: evaluation report written by a script from a real run (tracked)

## Data policy

- **The dataset is synthetic.** Every record comes from generated fixtures and controlled
  tampering. That is stated in the dataset metadata, and will be in the evaluation report and the UI.
- Every label keeps its source and ground-truth status (`synthetic_by_construction`).
  *Vulnerable* does not mean *malicious*.
- `malicious_known_bad` requires established ground truth. Synthetic data cannot provide it, so
  the class has **no records** and the validator rejects any synthetic record that claims it.
- Splits are by artifact family, so variants of one family never cross train/validation/test.
- Only metrics from real evaluation runs are reported.

## How records are made

Each family is a small fictional project or model. Files are written to a temporary directory and
go through the real parsers: the static analyzer, AI-BOM analysis, CycloneDX parser, dependency
and lineage graphs, provenance checks, and the telemetry parser. **Nothing is imported, loaded,
installed or run**, the sandbox is not started, and the network is not used.

These inputs are generated rather than observed: SBOM documents, `SYNTH-*` advisories and their
CVSS values, and sandbox traces. Addresses in traces are text that is only parsed.

| Recipe | Label | What changes |
|---|---|---|
| `docs_update` | benign | new commit, README edit |
| `inject_advisories` | vulnerable | synthetic advisories on some packages |
| `changed_hash` | provenance_weak | content differs on the same commit |
| `removed_provenance` | provenance_weak | attestation and signature files removed |
| `version_mismatch` | provenance_weak | requested release tag disagrees with the manifest |
| `altered_config` | suspicious | model config changed |
| `replaced_dependency` | suspicious | a package swapped for a look-alike name |
| `suspicious_code` | suspicious | inert code that static rules flag |
| `suspicious_behavior` | suspicious | generated trace with external connections |

When several recipes apply, the label is the most severe: suspicious, then provenance_weak, then
vulnerable. A label comes only from the recipes applied, never from thresholding features.

## Null features

A null feature means **not evaluated**. It is never 0 or False, and `null_reasons` records why:

| Reason | Meaning |
|---|---|
| `no_data_source` | the pipeline has no collector for it |
| `not_applicable` | does not apply to this artifact type |
| `stage_not_run`, `stage_partial`, `stage_error`, `stage_unavailable`, `stage_skipped` | the stage did not complete, so its whole layer is null |
| `mock_evidence` | the stage used mock data |
| `no_prior_scan` | a comparison feature with nothing to compare against |
| `not_determinable` | the stage ran but cannot give a value (for example `cvss_max` with no scored advisory) |

These five features have no data source and are null in every record: `package_age`,
`release_change`, `commit_age`, `publisher_consistency`, `signed`.

## Known limits of this dataset

- Stage failures and missing priors are drawn independently of the label, so missing evidence
  does not reveal it. The exception is `version_consistency`: it needs a release tag, and the
  `version_mismatch` recipe only applies to tagged families, so its null rate is lower for
  provenance_weak (about 32%, against about 43% for the other labels).
- A label is kept even when its evidence was not observed (`label_evidence_observable=false`), for
  example a behavior recipe where the sandbox did not run. Those records are expected to be missed.
- Benign families deliberately overlap tampered ones (no attestation, subprocess use, pickle
  weights, new edges in a legitimate release), but the overlap is designed, not observed.

## How models handle nulls

All three models get the same numeric matrix (`backend/app/ml/preprocessing.py`):

- Each feature has `<name>__is_null`: 1 when the feature was not evaluated, otherwise 0.
- A null value is filled with the **training-set median**, so it is never read as a measured 0.
- Categorical features are one-hot encoded. A null or unseen category is all 0.
- A feature null in every training record is dropped and listed in `preprocessing.json` as
  `dropped_all_null`.

## Models

| Model | Role | Fitted on |
|---|---|---|
| Random Forest | primary, 4 classes | train |
| XGBoost | comparison, 4 classes | train |
| Isolation Forest | anomaly score | benign train records only |

- **Split use:** medians, categories and models use train. Thresholds use validation. Training
  does not read the test split: test rows are discarded unparsed, and `train_models` refuses them.
- **Thresholds are research parameters.** RF and XGBoost maximize validation F1 for benign vs. any
  risk. Isolation Forest flags at most 5% of benign validation records.
- A model output is not the ProvenanceX risk score, and neither is CVSS.

## Saved artifacts (`ml/models/`, git-ignored)

| File | Format |
|---|---|
| `random_forest.skops`, `isolation_forest.skops` | skops |
| `xgboost.json` | XGBoost native JSON |
| `preprocessing.json`, `thresholds.json`, `training_metadata.json` | plain JSON |
| `manifest.json` | SHA-256 and size of each file, plus library versions |

Pickle and joblib are never used. `load_bundle` verifies every digest, then parses the bytes it
verified. skops gets an explicit type list (only `sklearn.tree._tree.Tree` beyond its defaults),
and any other type is refused before anything is built. Loading also refuses different library
versions, unexpected manifest entries and symlinks.

The manifest is not signed. It catches corruption and partial replacement, but anyone who can
rewrite the whole directory can rewrite the manifest too, so `ml/models/` must stay trusted.

## Evaluation

`ml/reports/evaluation_report.md` and `.json` are written by `ml/scripts/evaluate_models.py` from a
real run. Never edit them by hand. The report opens with what synthetic data means for the claims.

- Primary results use the saved models and their validation thresholds on the untouched test split.
- Repeated splits, ablation and leave-one-recipe-out retrain, and pick thresholds on their own
  validation split by the same procedure. Nothing is chosen after seeing test results.
- Undefined metrics are `n/a`, never 0.
- Baselines report how many records they could not evaluate.

### Fusion sensitivity

`ml/reports/fusion_sensitivity.md` and `.json` are written by `ml/scripts/fusion_sensitivity.py`.
Each fusion weight, and the blend parameter, is moved by plus and minus 20 percent, one at a time,
and changed ALLOW/REVIEW/BLOCK decisions are counted on the 348 synthetic validation records.

This is analysis only. Nothing is fitted, test rows are discarded unparsed, and it does not show
that the hand-set weights or any decision are correct. Observed: each layer weight changed at most
3 of 348 decisions, and the blend parameter changed 12 (at 0.8x) and 14 (at 1.2x). ML weights
changed none, by construction, because ML cannot change the decision. Validation records hold
features only, so rules needing findings or provenance checks are not exercised.

## Real-world dataset (realworld-v1)

Separate from the synthetic data above. Code: `backend/app/ml/realworld/` (manifest, dedup; no network) and `backend/app/dataset_collection/` (adapters, collector, scan step; never imported by service code). Output:
`ml/data/realworld/` (tracked: public metadata only).

**Sources (metadata only; no artifact is downloaded at collection):**

| Source | Used for | Data license |
|---|---|---|
| GitHub Advisory Database (`api.github.com/advisories`) | known_vulnerable (reviewed), confirmed_malicious (malware) | CC-BY-4.0 |
| OSV (`api.osv.dev`) | version check and corroboration | CC-BY-4.0 (OSV-native); upstream terms vary |
| NVD (`services.nvd.nist.gov`) | CVE status, corroboration only (capped) | public NVD data |
| GitHub REST | repo age, verified org, releases, tags, commit signatures | each repo's own license |
| Hugging Face Hub API | org verification, age, Hub security scan, license tag | each repo's own license |

**Labels:**

| Label | Rule | Ground truth | Scanned? |
|---|---|---|---|
| known_vulnerable | a reviewed GHSA/OSV advisory covers that exact version | established | yes |
| benign | no advisory for that version AND (verified org OR signed release commit) AND repo ≥ 365 d, release ≥ 180 d (HF: ≥ 180 d, Hub scan done and clean) | criteria_based | yes, if within budget |
| suspicious | the Hub security scan flags files | third_party_flag | **never** |
| confirmed_malicious | a GHSA malware advisory names the package | established | **never** (metadata only) |
| unknown | anything else | none | no; excluded from training |

A missing advisory never means benign. Seeds (`seeds-v1.json`) are identifiers only.

**Families (leakage):** one GitHub repo (`github:owner/repo`), one registry package, one HF base
model plus its fine-tunes and adapters (`hf:<base>`), one HF dataset. Records are deduplicated by
artifact type + identifier + revision; a label conflict keeps the most severe label.

**Known gaps:** a GHSA advisory labels the package's *own* code, but the scanner's vulnerability
features describe its *dependencies*, so `known_vulnerable` may not be observable in features.
There is no advisory source for Hugging Face repos, so no HF artifact can be known_vulnerable.
Malicious rows have no features by design. GitHub's "verified" signature also covers commits
signed by GitHub's web flow, not only maintainer keys.

**Scan step:** `ml/scripts/scan_realworld.py` submits scan-eligible rows to the local API (loopback
only), so the normal sandboxed runner does the work. At most 200 rows in total; resumable. A row is
usable for training only if the scan completed with a feature vector and no mock evidence.

**Status (2026-11-23, final for manifest v1):** all 152 scan-eligible rows attempted; 147 completed
(24 benign, 123 known_vulnerable). 5 failed closed on the scan limits and are not retried:
`artifact_too_large` (microsoft/TypeScript, tsparticles/tsparticles, mlflow/mlflow; 200 MB cap) and
`too_many_files` (home-assistant/core, nocobase/nocobase; 20 000-file cap). `EGRESS_IDLE_TIMEOUT_SECONDS`
stays at 60 by owner decision. More rows need a new collection run, not more retries.

**Training (`ml/scripts/train_realworld.py`):** benign vs known_vulnerable, per artifact type,
family-based splits, thresholds chosen on validation only, test scored once. A type needs ≥ 15
usable rows per class and ≥ 3 per class in each split; otherwise no model is written and that type
keeps the rule-based / REVIEW fallback. Outputs: `ml/models/realworld/<type>/` (git-ignored) and
`ml/reports/realworld_{evaluation_report.md,evaluation_report.json,model_card.md}`. These models are
research measurements. Software scans load `ml/models/realworld/software` only when its SHA-256
digests verify and the quality gates in `app/ml/realworld/runtime.py` pass (≥ 150 labelled rows,
≥ 30 test rows per class, RF test F1 ≥ rules-only, ROC-AUC 95% CI lower bound > 0.5); otherwise they
fall back to the synthetic models with ML out of the decision band. The synthetic loader refuses a
real-world model directory.

**Current results (software only, 147 rows; test split = 5 benign + 24 vulnerable):**

| Model | F1 | ROC-AUC | PR-AUC | FPR | FNR |
|---|---|---|---|---|---|
| Random Forest | 0.89 | 0.63 | 0.87 | 1.00 | 0.04 |
| XGBoost | 0.92 | 0.85 | 0.97 | 0.80 | 0.00 |
| Rules-only baseline | 0.89 | 0.54 | 0.84 | 1.00 | 0.04 |
| Vulnerability-only | 0.76 | 0.73 | 0.93 | 0.40 | 0.33 |

High F1 reflects class imbalance (123 vs 24): RF flags all 5 benign test rows (FPR 1.00), like the
rules-only baseline. Over 20 re-drawn family splits: RF mean F1 0.90 (std 0.02) and mean ROC-AUC
0.50; rules-only mean F1 0.86. RF test ROC-AUC 95% CI is [0.29, 0.92], so the model does not beat
chance reliably. **Runtime gates fail** (147 < 150 rows; 5 and 24 test rows per class < 30; CI lower
bound 0.29 ≤ 0.5): the real-world model is not loaded.

**Policy calibration (`ml/scripts/calibrate_policy.py` → `ml/reports/policy_calibration.{md,json}`):**
analysis only; `provenancex-policy-v2-handset` is unchanged. Calibrating REVIEW thresholds/weights
needs ≥ 300 labelled real rows and ≥ 100 per class (have 147; benign 24). Calibrating BLOCK
additionally needs established ground-truth confirmed_malicious or tampered rows with scan features
(have 0). On the 147 rows the current policy flags 92% of benign and passes 12% of vulnerable rows.

**Evidence gaps:** model, LoRA and dataset have no usable rows (no model); no malicious-class model
(metadata only by owner decision); every row is a first scan (comparison features null); behavior
features null while the dynamic sandbox is off; known_vulnerable is visible in dependency features
for only 63/123 rows. The full list is in the evaluation report.

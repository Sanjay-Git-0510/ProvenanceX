# ml/

Dataset generation, training and evaluation for ProvenanceX.

- `scripts/`: command-line entry points (see `scripts/README.md`). The logic is in
  `backend/app/ml/`.
- `data/`: generated feature datasets (git-ignored)
- `models/`: trained models and preprocessing parameters (git-ignored)

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

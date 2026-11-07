# ml/

This directory will hold dataset generation scripts, feature records, trained model artifacts and evaluation reports.
They arrive in **Phase 5**.

- `data/`: generated feature datasets (git-ignored)
- `models/`: trained models and preprocessing parameters (git-ignored)

## Data policy

- Any record generated from controlled fixtures or tampering cases is **synthetic**. That label is recorded in the dataset metadata, the evaluation report and the UI.
- Every label keeps its source and ground-truth status. *Vulnerable* does not mean *malicious*.
- `malicious_known_bad` is used only where ground truth is established.
- Splits are made by repository or artifact family to avoid leakage.
- Only metrics from real evaluation runs are reported.

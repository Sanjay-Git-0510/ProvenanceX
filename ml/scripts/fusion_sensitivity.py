#!/usr/bin/env python3
"""Move each fusion weight by +/-20% and count changed decisions on the validation split.

Analysis only. Nothing is fitted, and test rows are discarded unparsed by the loader.

Run with the backend virtualenv, after train_models.py:
    backend/.venv/bin/python ml/scripts/fusion_sensitivity.py
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.ml.artifacts import load_bundle  # noqa: E402
from app.ml.preprocessing import transform  # noqa: E402
from app.ml.training import anomaly_scores, load_training_records, risk_scores  # noqa: E402
from app.risk.policy_config import POLICY_VERSION  # noqa: E402
from app.risk.sensitivity import (  # noqa: E402
    inputs_from_validation,
    render_markdown,
    run_sensitivity,
)
from app.risk.types import MlOutputs  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=REPO_ROOT / "ml" / "data")
    parser.add_argument("--models", type=Path, default=REPO_ROOT / "ml" / "models")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "ml" / "reports")
    args = parser.parse_args()

    _, validation, dataset_metadata = load_training_records(args.data)
    bundle = load_bundle(args.models)
    if bundle.metadata["dataset_sha256"] != dataset_metadata["dataset_sha256"]:
        raise SystemExit("The saved models were not trained on this dataset")

    matrix = transform(bundle.preprocessing, validation)
    forest = risk_scores(bundle.random_forest.predict_proba(matrix))
    anomaly = anomaly_scores(bundle.isolation_forest, matrix)
    outputs = [
        MlOutputs(
            rf_risk_probability=float(rf),
            anomaly_score=float(score),
            rf_threshold=bundle.thresholds.random_forest.value,
            anomaly_threshold=bundle.thresholds.isolation_forest.value,
        )
        for rf, score in zip(forest, anomaly, strict=True)
    ]
    result = run_sensitivity(inputs_from_validation(validation, outputs))
    result.update(
        synthetic=True,
        split="validation",
        dataset_sha256=dataset_metadata["dataset_sha256"],
        policy_version=POLICY_VERSION,
    )
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "fusion_sensitivity.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.out / "fusion_sensitivity.md").write_text(
        render_markdown(result, dataset_metadata["dataset_sha256"], POLICY_VERSION),
        encoding="utf-8",
    )
    print(f"Wrote {args.out / 'fusion_sensitivity.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

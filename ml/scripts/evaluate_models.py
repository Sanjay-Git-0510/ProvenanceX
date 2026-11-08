#!/usr/bin/env python3
"""Evaluate the ProvenanceX models on the SYNTHETIC dataset and write ml/reports/.

Run with the backend virtualenv, after train_models.py:
    backend/.venv/bin/python ml/scripts/evaluate_models.py
"""

import argparse
import json
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.ml.ablation import (  # noqa: E402
    evaluate_split,
    run_ablation,
    run_leave_one_recipe_out,
    summarize,
)
from app.ml.artifacts import load_bundle, read_manifest  # noqa: E402
from app.ml.baselines import evaluate_baselines  # noqa: E402
from app.ml.evaluation import (  # noqa: E402
    benign_flag_rate_by_hash_comparison,
    evaluate_bundle,
    flag_everything_reference,
)
from app.ml.feature_schema import FeatureRecord  # noqa: E402
from app.ml.reporting import (  # noqa: E402
    build_report,
    thresholds_match,
    vulnerable_label_stats,
    write_report,
)
from app.ml.training import TrainingConfig, read_verified_dataset  # noqa: E402

SPLIT_REPEATS = 5


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=REPO_ROOT / "ml" / "data")
    parser.add_argument("--models", type=Path, default=REPO_ROOT / "ml" / "models")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "ml" / "reports")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)

    body, dataset_metadata = read_verified_dataset(args.data)
    records = [FeatureRecord.model_validate_json(line) for line in body.splitlines()]
    bundle = load_bundle(args.models)
    if bundle.metadata["dataset_sha256"] != dataset_metadata["dataset_sha256"]:
        raise SystemExit("The saved models were not trained on this dataset")

    test = [record for record in records if record.split == "test"]
    primary = {
        "test_records": len(test),
        "thresholds": bundle.thresholds.model_dump(mode="json"),
        "models": evaluate_bundle(bundle, test),
        "baselines": evaluate_baselines(test),
        "reference_flag_everything": flag_everything_reference(test),
        "random_forest_benign_flag_rate_by_hash_comparison": benign_flag_rate_by_hash_comparison(
            bundle.random_forest,
            bundle.preprocessing,
            test,
            bundle.thresholds.random_forest.value,
        ),
    }

    # The primary seed comes first and matches the saved models' split.
    first_seed = int(dataset_metadata["seed"])
    seeds = [first_seed + offset for offset in range(SPLIT_REPEATS)]
    config = TrainingConfig(**bundle.metadata["training_config"])
    runs = [evaluate_split(records, seed, config, dataset_metadata) for seed in seeds]
    summary = summarize([{"models": run["models"], "baselines": run["baselines"]} for run in runs])
    reproduced = thresholds_match(runs[0]["thresholds"], primary["thresholds"])

    report = build_report(
        dataset_metadata=dataset_metadata,
        model_metadata=bundle.metadata,
        manifest=read_manifest(args.models),
        primary=primary,
        repeated_runs=runs,
        repeated_summary=summary,
        ablation=run_ablation(records, seeds, config),
        leave_one_recipe_out=run_leave_one_recipe_out(records, seeds, config),
        vulnerable_stats=vulnerable_label_stats(records),
        primary_thresholds_reproduced=reproduced,
    )
    write_report(report, args.out)
    print(json.dumps({"synthetic": True, "seeds": seeds, "reproduced": reproduced}))
    print(f"Wrote {args.out / 'evaluation_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

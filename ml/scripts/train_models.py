#!/usr/bin/env python3
"""Train the ProvenanceX models on the SYNTHETIC dataset. Reads no test records.

Run with the backend virtualenv, after generate_dataset.py:
    backend/.venv/bin/python ml/scripts/train_models.py --seed 42
"""

import argparse
import json
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.ml.artifacts import load_bundle, save_bundle  # noqa: E402
from app.ml.training import TrainingConfig, load_training_records, train_models  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=REPO_ROOT / "ml" / "data")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "ml" / "models")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)
    train, validation, metadata = load_training_records(args.data)
    bundle = train_models(train, validation, metadata, TrainingConfig(seed=args.seed))
    manifest = save_bundle(bundle, args.out)
    reloaded = load_bundle(args.out)  # proves the saved set verifies and loads
    print(
        json.dumps(
            {
                "synthetic": bundle.metadata["synthetic"],
                "train_records": len(train),
                "validation_records": len(validation),
                "columns": len(reloaded.preprocessing.columns),
                "dropped_all_null": reloaded.preprocessing.dropped_all_null,
                "thresholds_selected_on_validation": reloaded.thresholds.model_dump(),
                "files": sorted(manifest["files"]),
                "out": str(args.out),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

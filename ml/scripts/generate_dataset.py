#!/usr/bin/env python3
"""Generate the SYNTHETIC ProvenanceX feature dataset.

Run from anywhere with the backend virtualenv:
    backend/.venv/bin/python ml/scripts/generate_dataset.py --families 200 --seed 42
"""

import argparse
import json
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.ml.dataset.generator import generate_records, write_dataset  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--families", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "ml" / "data")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)
    records = generate_records(args.families, args.seed)
    metadata = write_dataset(records, args.seed, args.out)
    summary = {k: metadata[k] for k in ("record_count", "family_count", "label_counts")}
    print(json.dumps({"synthetic": True, **summary, "out": str(args.out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

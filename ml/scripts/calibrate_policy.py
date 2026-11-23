#!/usr/bin/env python3
"""Empirical calibration analysis of the current policy on REAL-WORLD rows (analysis only).

    backend/.venv/bin/python -I ml/scripts/calibrate_policy.py

Reads ml/data/realworld/{manifest,features}-realworld-v1.jsonl and, as a separate labelled
section, ml/reports/fusion_sensitivity.json (synthetic). Writes
ml/reports/policy_calibration.{md,json}. Never changes the policy.
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.ml.realworld.dataset import load_rows  # noqa: E402
from app.ml.realworld.manifest import DATASET_VERSION  # noqa: E402
from app.risk.calibration import render_markdown, run_calibration  # noqa: E402
from app.risk.types import RiskInputs  # noqa: E402

DATA = REPO_ROOT / "ml" / "data" / "realworld"
REPORTS = REPO_ROOT / "ml" / "reports"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPORTS)
    args = parser.parse_args()
    loaded = load_rows(
        DATA / f"manifest-{DATASET_VERSION}.jsonl", DATA / f"features-{DATASET_VERSION}.jsonl"
    )
    rows = [r for r in loaded.rows if r.artifact_type == "software"]
    if not rows:
        print("No usable real-world software rows; nothing to analyse.")
        return 3
    inputs = [
        RiskInputs(
            artifact_type=r.artifact_type,
            features=r.features,
            null_reasons=r.null_reasons,
            ml=None,
            ml_unavailable_reason="excluded from the calibration analysis",
            record_id=r.record_id,
        )
        for r in rows
    ]
    result = run_calibration(inputs, [str(r.label) for r in rows])
    meta = json.loads((DATA / f"manifest-{DATASET_VERSION}.metadata.json").read_text())
    result.update(
        synthetic=False,
        dataset_version=DATASET_VERSION,
        manifest_sha256=meta["manifest_sha256"],
        scan_eligible_in_manifest=meta["scan_eligible_count"],
    )
    synthetic_path = REPORTS / "fusion_sensitivity.json"
    synthetic = json.loads(synthetic_path.read_text()) if synthetic_path.exists() else None
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "policy_calibration.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (args.out / "policy_calibration.md").write_text(render_markdown(result, synthetic))
    print(json.dumps({"rows": result["rows"], "sufficiency": result["sufficiency"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

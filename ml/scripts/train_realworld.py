#!/usr/bin/env python3
"""Train and evaluate REAL-WORLD models per artifact type, where real labelled data suffices.

    backend/.venv/bin/python -I ml/scripts/train_realworld.py

Reads ml/data/realworld/{manifest,features}-realworld-v1.jsonl. Writes models to
ml/models/realworld/<type>/ and ml/reports/realworld_{evaluation_report,model_card}.{md,json}.
Never reads the synthetic dataset.
"""

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.ml.realworld.dataset import (  # noqa: E402
    InsufficientData,
    assign_splits,
    load_rows,
    sufficiency,
    with_splits,
)
from app.ml.realworld.manifest import DATASET_VERSION, read_manifest  # noqa: E402
from app.ml.realworld.report import render_model_card, render_report  # noqa: E402
from app.ml.realworld.train_eval import (  # noqa: E402
    Config,
    ablation,
    evaluate_split,
    repeated_splits,
    save_models,
    top_features,
    train,
)

DATA = REPO_ROOT / "ml" / "data" / "realworld"
MODELS = REPO_ROOT / "ml" / "models" / "realworld"
REPORTS = REPO_ROOT / "ml" / "reports"


def _observability(rows) -> dict[str, object]:
    def share(label: str) -> str:
        mine = [r for r in rows if str(r.label) == label]
        hit = sum(1 for r in mine if (r.features.get("vulnerable_count") or 0) > 0)
        return f"{hit}/{len(mine)}"

    return {
        "known_vulnerable_rows_with_vulnerable_count_gt_0": share("known_vulnerable"),
        "benign_rows_with_vulnerable_count_gt_0": share("benign"),
        "note": "vulnerable_count counts dependency advisories; the label is the package's own",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    cfg = Config(seed=args.seed)
    manifest_path = DATA / f"manifest-{DATASET_VERSION}.jsonl"
    features_path = DATA / f"features-{DATASET_VERSION}.jsonl"
    meta = json.loads((DATA / f"manifest-{DATASET_VERSION}.metadata.json").read_text())

    loaded = load_rows(manifest_path, features_path)
    raw_rows = [json.loads(x) for x in features_path.read_text().splitlines() if x.strip()]
    manifest = read_manifest(manifest_path)
    suff = sufficiency(loaded.rows)
    results: dict = {
        "dataset_version": DATASET_VERSION,
        "manifest_sha256": meta["manifest_sha256"],
        "config": asdict(cfg),
        "feature_rows_read": len(raw_rows),
        "usable_rows": len(loaded.rows),
        "excluded": dict(sorted(loaded.excluded.items())),
        "scan_outcomes": dict(sorted(Counter(r["scan_status"] for r in raw_rows).items())),
        "sufficiency": suff,
        "models": {},
    }
    gaps = []
    for kind, s in suff.items():
        if not s["sufficient"]:
            gaps.append(f"{kind}: no model; {s['reason']} (rule-based / REVIEW fallback kept)")
            continue
        rows = [r for r in loaded.rows if r.artifact_type == kind]
        try:
            parts = with_splits(rows, assign_splits(rows, cfg.seed))
            models = train(parts["train"], parts["validation"], cfg)
        except (InsufficientData, ValueError) as exc:
            gaps.append(f"{kind}: no model; {exc}")
            continue
        report = {
            "seed": cfg.seed,
            "split_counts": {k: dict(Counter(str(r.label) for r in v)) for k, v in parts.items()},
            "observability": _observability(rows),
            "validation": evaluate_split(models, parts["validation"], cfg),
            "test": evaluate_split(models, parts["test"], cfg, bootstrap=True),
            "ablation": ablation(parts, cfg),
            "top_features": top_features(models),
            "thresholds": {k: v.model_dump() for k, v in models.thresholds.items()},
        }
        report["repeated"] = repeated_splits(rows, cfg)
        report["artifact_manifest"] = save_models(
            models,
            MODELS / kind,
            {
                "artifact_type": kind,
                "labels": ["benign", "known_vulnerable"],
                "synthetic": False,
                "dataset_version": DATASET_VERSION,
                "manifest_sha256": meta["manifest_sha256"],
                "config": asdict(cfg),
                "split_counts": report["split_counts"],
                "train_record_ids": sorted(r.record_id for r in parts["train"]),
            },
        )
        results["models"][kind] = report

    by_type = Counter((r.artifact_type, str(r.label)) for r in manifest)
    gaps += [
        f"confirmed_malicious: {by_type[('package', 'confirmed_malicious')]} registry packages, "
        "metadata only by owner decision; no feature rows, so no malicious-class model. Malware "
        "stays with rules + REVIEW.",
        "suspicious: no record carried a Hub 'unsafe' flag in this collection; no class.",
        "Hugging Face: no advisory database exists for Hub repositories, so no model, LoRA or "
        "dataset can be known_vulnerable; benign HF models exceeded the 600 MB scan budget.",
        f"unknown: {sum(n for (t, lab), n in by_type.items() if lab == 'unknown')} manifest rows "
        "failed the benign criteria and are excluded (missing evidence is not benign).",
        "known_vulnerable labels the package's own code; the scanner's vulnerability features "
        "describe dependencies, so the label may not be visible in the features (see the "
        "label evidence check per model).",
        "Benign is criteria-based, not ground truth: a package with an undisclosed flaw can pass.",
        "Every real row is a first scan: hash/config/graph comparison features are null "
        "(no_prior_scan); behavior features are null while the dynamic sandbox is disabled.",
        "Seeds are popular projects and advisories are recent: the sample is not representative "
        "of all packages.",
    ]
    results["evidence_gaps"] = gaps

    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "realworld_evaluation_report.json").write_text(
        json.dumps(results, indent=2, sort_keys=True, default=str) + "\n"
    )
    (REPORTS / "realworld_evaluation_report.md").write_text(render_report(results))
    (REPORTS / "realworld_model_card.md").write_text(render_model_card(results))
    summary = {
        "usable_rows": results["usable_rows"],
        "models": list(results["models"]),
        "excluded": results["excluded"],
    }
    for kind, r in results["models"].items():
        summary[kind] = {
            name: {k: r["test"][name][k] for k in ("f1", "roc_auc", "pr_auc", "fpr", "fnr")}
            for name in r["test"]
        }
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

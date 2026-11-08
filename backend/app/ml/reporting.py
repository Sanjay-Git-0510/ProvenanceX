"""Build the evaluation report. Markdown is rendered only from the JSON result of a real run."""

import json
import math
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from app.ml.feature_schema import NOT_EVALUATED_FEATURES, FeatureRecord, Label

REPORT_FORMAT = "provenancex-evaluation-report-v1"
SYNTHETIC_WARNING = (
    "SYNTHETIC DATA: every number in this report comes from generated fixtures and controlled "
    "tampering. It does not measure detection of real-world attacks."
)
SYNTHETIC_MEANING = (
    "Labels are true by construction, and the features come from the same recipes that assign "
    "the labels. Scores therefore show whether the pipeline can recover the signals that were "
    "injected, not how it would perform on real packages or models. Benign and tampered records "
    "overlap by design, not because that overlap was observed. No real malware was used, so "
    "malicious_known_bad has no records and no result here is a malware-detection claim. "
    '"Any risk" means any non-benign label, and vulnerable does not mean malicious. Advisories, '
    "CVSS values and sandbox traces are generated. Do not cite these numbers as real-world "
    "accuracy."
)
VULNERABLE_NOTE = (
    "vulnerable_count nearly determines the vulnerable label, so the rules baseline is expected "
    "to do well on that class. Good results on that class are not evidence that the models "
    "learned anything beyond a lookup of that one feature."
)
FALSE_POSITIVE_NOTE = (
    "A record with no hash comparison (no prior scan, or the provenance stage failed) carries "
    "less evidence, and most training records are non-benign. A higher flag rate on those benign "
    "records is consistent with the model falling back on that base rate. This table measures "
    "the difference; it does not prove the cause."
)
RULES_VULNERABLE_NOTE = (
    "The rules baseline predicts the most severe class among the rules that fired, so a "
    "vulnerable record where a static or behavior rule also fires is predicted suspicious. The "
    "vulnerability-only baseline predicts vulnerable for every record with advisories, including "
    "those that carry a more severe label."
)
THRESHOLD_POLICY = (
    "Primary results use the saved models and the thresholds already chosen on validation. "
    "Retraining experiments (repeated splits, ablation, leave-one-recipe-out) pick a threshold on "
    "their own validation split by the same procedure, with the same fixed hyperparameters. No "
    "threshold or hyperparameter was changed after seeing test results."
)
ISOLATION_NOTE = (
    "Isolation Forest outputs one anomaly score and has no classes. Its per-class rows measure "
    "each risk class against benign records only, so they are not comparable to the one-vs-rest "
    "rows of the classifiers."
)
BASELINE_NOTE = (
    "Baselines learn nothing. A rule whose feature is null cannot fire. 'Evaluated only' covers "
    "records the baseline could evaluate; 'all records' counts the rest as not flagged. ROC-AUC "
    "for baselines uses a coarse score (vulnerable_count, or the number of rules fired)."
)
THRESHOLD_TOLERANCE = 1e-9
METRICS = ("precision", "recall", "f1", "roc_auc", "fpr", "fnr")
MODEL_TITLES = {
    "random_forest": "Random Forest (primary)",
    "xgboost": "XGBoost (comparison)",
    "isolation_forest": "Isolation Forest (anomaly)",
}
BASELINE_TITLES = {
    "vulnerability_only": "Vulnerability-only baseline",
    "rules_only": "Rules-only baseline",
}


def thresholds_match(first: dict[str, Any], second: dict[str, Any]) -> bool:
    """Equal within THRESHOLD_TOLERANCE; parallel tree averaging adds floating-point noise."""
    return first.keys() == second.keys() and all(
        math.isclose(first[name]["value"], second[name]["value"], abs_tol=THRESHOLD_TOLERANCE)
        and first[name]["criterion"] == second[name]["criterion"]
        for name in first
    )


def vulnerable_label_stats(records: Sequence[FeatureRecord]) -> dict[str, Any]:
    """Measure how closely vulnerable_count tracks the vulnerable label across all records."""
    evaluated = [r for r in records if r.features["vulnerable_count"] is not None]
    labeled = [r for r in evaluated if r.label == Label.VULNERABLE]
    with_advisories = [r for r in evaluated if r.features["vulnerable_count"] > 0]
    labeled_hits = sum(r.features["vulnerable_count"] > 0 for r in labeled)
    relabeled = sum(r.label != Label.VULNERABLE for r in with_advisories)
    return {
        "records_with_vulnerable_count": len(evaluated),
        "vulnerable_label_records": len(labeled),
        "vulnerable_label_with_count_above_zero": labeled_hits,
        "share_of_vulnerable_label_with_count_above_zero": (
            labeled_hits / len(labeled) if labeled else None
        ),
        "records_with_count_above_zero": len(with_advisories),
        "count_above_zero_with_a_more_severe_label": relabeled,
        "share_of_count_above_zero_labeled_vulnerable": (
            (len(with_advisories) - relabeled) / len(with_advisories) if with_advisories else None
        ),
        "explanation": (
            "Records with advisories that also had a more severe recipe applied carry that more "
            "severe label, so count > 0 alone does not imply the vulnerable label."
        ),
    }


def build_report(
    *,
    dataset_metadata: dict[str, Any],
    model_metadata: dict[str, Any],
    manifest: dict[str, Any],
    primary: dict[str, Any],
    repeated_runs: list[dict[str, Any]],
    repeated_summary: dict[str, Any],
    ablation: dict[str, Any],
    leave_one_recipe_out: dict[str, Any],
    vulnerable_stats: dict[str, Any],
    primary_thresholds_reproduced: bool,
) -> dict[str, Any]:
    if dataset_metadata.get("synthetic") is not True:
        raise ValueError("This report is written for the synthetic dataset only")
    return {
        "format": REPORT_FORMAT,
        "synthetic": True,
        "warning": SYNTHETIC_WARNING,
        "what_synthetic_means": SYNTHETIC_MEANING,
        "vulnerable_label_note": VULNERABLE_NOTE,
        "vulnerable_label_stats": vulnerable_stats,
        "threshold_policy": THRESHOLD_POLICY,
        "isolation_forest_note": ISOLATION_NOTE,
        "baseline_note": BASELINE_NOTE,
        "dataset": {
            key: dataset_metadata.get(key)
            for key in (
                "format",
                "dataset_sha256",
                "seed",
                "record_count",
                "family_count",
                "label_counts",
                "split_counts",
                "ground_truth_status",
                "label_evidence_unobservable",
            )
        },
        "not_evaluated_features": list(NOT_EVALUATED_FEATURES),
        "models": {
            "dataset_sha256": model_metadata.get("dataset_sha256"),
            "training_config": model_metadata.get("training_config"),
            "python_version": manifest.get("python_version"),
            "library_versions": manifest.get("library_versions"),
        },
        "primary_test_results": primary,
        "repeated_family_splits": {
            "seeds": [run["seed"] for run in repeated_runs],
            "test_records_per_seed": [run["test_records"] for run in repeated_runs],
            "primary_thresholds_reproduced_by_retraining": primary_thresholds_reproduced,
            "summary": repeated_summary,
            "runs": repeated_runs,
        },
        "layer_ablation": ablation,
        "leave_one_recipe_out": leave_one_recipe_out,
    }


def _num(value: Any) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _spread(summary: dict[str, Any] | None) -> str:
    if summary is None:
        return "n/a"
    return f"{summary['mean']:.3f} ± {summary['std']:.3f}"


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines.extend("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    return [*lines, ""]


def _metric_row(name: str, metrics: dict[str, Any] | None) -> list[str]:
    if metrics is None:
        return [name, *["n/a"] * len(METRICS)]
    return [name, *[_num(metrics.get(key)) for key in METRICS]]


def _headers(first: str) -> list[str]:
    return [first, "Precision", "Recall", "F1", "ROC-AUC", "FPR", "FNR"]


def _class_table(block: dict[str, Any]) -> list[str]:
    rows = [_metric_row(name, m) for name, m in block["per_class"].items()]
    rows.append(_metric_row("**macro**", block["macro"]))
    return _table(_headers("Class"), rows)


def _render_primary(results: dict[str, Any]) -> list[str]:
    out = ["## Primary test results (saved models, validation thresholds)", ""]
    binary_rows = []
    for key, title in MODEL_TITLES.items():
        model = results["models"][key]
        binary_rows.append(_metric_row(title, model["binary"]))
        binary_rows.append(
            _metric_row(f"{title}, observable labels only", model["binary_observable_only"])
        )
    reference = results["reference_flag_everything"]
    binary_rows.append(_metric_row("Reference: flag every record", reference))
    out += [
        "### Binary: benign vs. any risk",
        "",
        f"{reference['support']} of {reference['records']} test records are non-benign, so "
        "precision and F1 run high even for a detector that flags everything. The reference row "
        "shows that floor; FPR, FNR and ROC-AUC are less affected by this imbalance.",
        "",
        *_table(_headers("Model"), binary_rows),
    ]
    for key in ("random_forest", "xgboost"):
        model = results["models"][key]
        out += [
            f"### {MODEL_TITLES[key]}: per class (top predicted class, one-vs-rest)",
            "",
            *_class_table(model["multiclass"]),
        ]
    split = results["random_forest_benign_flag_rate_by_hash_comparison"]
    out += [
        "### Random Forest false positives by hash comparison",
        "",
        FALSE_POSITIVE_NOTE,
        "",
        *_table(
            ["Benign test records", "Records", "Flagged", "Flag rate"],
            [
                [title, split[key]["records"], split[key]["flagged"], _num(split[key]["rate"])]
                for key, title in (
                    ("comparison_available", "Hash comparison available"),
                    ("comparison_missing", "Hash comparison missing"),
                )
            ],
        ),
    ]
    iforest = results["models"]["isolation_forest"]
    out += [
        f"### {MODEL_TITLES['isolation_forest']}: each risk class vs. benign",
        "",
        ISOLATION_NOTE,
        "",
        *_class_table(iforest["class_vs_benign"]),
    ]
    return out


def _render_baselines(results: dict[str, Any]) -> list[str]:
    out = ["## Baselines on the primary test split", "", BASELINE_NOTE, ""]
    coverage = [
        [
            title,
            base["records"],
            base["could_not_evaluate"],
            base["partially_evaluated"],
        ]
        for name, title in BASELINE_TITLES.items()
        for base in [results["baselines"][name]]
    ]
    out += _table(["Baseline", "Records", "Could not evaluate", "Partially evaluated"], coverage)
    rows = []
    for name, title in BASELINE_TITLES.items():
        base = results["baselines"][name]
        rows.append(
            _metric_row(f"{title}, evaluated only", base["evaluated_records_only"]["binary"])
        )
        rows.append(
            _metric_row(
                f"{title}, all records", base["all_records_unevaluated_not_flagged"]["binary"]
            )
        )
    out += ["### Binary: benign vs. any risk", "", *_table(_headers("Baseline"), rows)]
    for name, title in BASELINE_TITLES.items():
        block = results["baselines"][name]["evaluated_records_only"]["multiclass"]
        out += [f"### {title}: per class, evaluated records only", "", *_class_table(block)]
    return out


def _vulnerable_class(baseline: dict[str, Any]) -> dict[str, Any]:
    return baseline["evaluated_records_only"]["multiclass"]["per_class"]["vulnerable"]


def _render_vulnerable(report: dict[str, Any]) -> list[str]:
    stats = report["vulnerable_label_stats"]
    baselines = report["primary_test_results"]["baselines"]
    labeled_count = (
        stats["records_with_count_above_zero"] - stats["count_above_zero_with_a_more_severe_label"]
    )
    rows = [
        [
            "Vulnerable-label records with `vulnerable_count` > 0",
            f"{stats['vulnerable_label_with_count_above_zero']} / "
            f"{stats['vulnerable_label_records']}",
            _num(stats["share_of_vulnerable_label_with_count_above_zero"]),
        ],
        [
            "Records with `vulnerable_count` > 0 that carry the vulnerable label",
            f"{labeled_count} / {stats['records_with_count_above_zero']}",
            _num(stats["share_of_count_above_zero_labeled_vulnerable"]),
        ],
    ]
    return [
        "## The vulnerable label",
        "",
        report["vulnerable_label_note"],
        "",
        *_table(["Measured on all records with the feature", "Count", "Share"], rows),
        stats["explanation"],
        "",
        "Measured baseline results on the vulnerable class (primary test split). Compare these "
        "with the expectation above:",
        "",
        *_table(
            _headers("Baseline"),
            [
                _metric_row(title, _vulnerable_class(baselines[key]))
                for key, title in BASELINE_TITLES.items()
            ],
        ),
        RULES_VULNERABLE_NOTE,
        "",
    ]


def _binary_summary_row(title: str, summary: dict[str, Any]) -> list[str]:
    return [title, *[_spread(summary.get(key)) for key in METRICS]]


def _render_repeated(block: dict[str, Any]) -> list[str]:
    summary = block["summary"]
    out = [
        "## Repeated family splits (mean ± standard deviation)",
        "",
        f"Seeds: {block['seeds']}. Test records per seed: {block['test_records_per_seed']}. Each "
        "seed retrains every model on a new family split, so records in another seed's test set "
        "can appear in training here. This measures sensitivity to the split.",
        "",
        "Retraining at the primary seed reproduced the saved thresholds (within 1e-9): "
        f"**{block['primary_thresholds_reproduced_by_retraining']}**.",
        "",
    ]
    binary = [
        _binary_summary_row(title, summary["models"][key]["binary"])
        for key, title in MODEL_TITLES.items()
    ]
    binary += [
        _binary_summary_row(
            f"{title}, evaluated only",
            summary["baselines"][key]["evaluated_records_only"]["binary"],
        )
        for key, title in BASELINE_TITLES.items()
    ]
    out += ["### Binary: benign vs. any risk", "", *_table(_headers("Model"), binary)]
    macro = [
        _binary_summary_row(title, summary["models"][key]["multiclass"]["macro"])
        for key, title in MODEL_TITLES.items()
        if key != "isolation_forest"
    ]
    macro.append(
        _binary_summary_row(
            f"{MODEL_TITLES['isolation_forest']}, class vs. benign",
            summary["models"]["isolation_forest"]["class_vs_benign"]["macro"],
        )
    )
    macro += [
        _binary_summary_row(
            f"{title}, evaluated only",
            summary["baselines"][key]["evaluated_records_only"]["multiclass"]["macro"],
        )
        for key, title in BASELINE_TITLES.items()
    ]
    coverage = [
        [
            title,
            _spread(summary["baselines"][key]["could_not_evaluate"]),
            _spread(summary["baselines"][key]["partially_evaluated"]),
        ]
        for key, title in BASELINE_TITLES.items()
    ]
    out += ["### Macro average", "", *_table(_headers("Model"), macro)]
    out += [
        "### Baseline coverage per seed",
        "",
        *_table(["Baseline", "Could not evaluate", "Partially evaluated"], coverage),
    ]
    return out


def _render_ablation(block: dict[str, Any]) -> list[str]:
    full = block["all_layers"]
    rows = [
        [
            "(none: all layers)",
            _spread(full["binary"]["f1"]),
            _spread(full["binary"]["roc_auc"]),
            _spread(full["binary"]["fpr"]),
            _spread(full["binary"]["fnr"]),
            _spread(full["macro"]["f1"]),
        ]
    ]
    rows += [
        [
            layer,
            _spread(entry["change_from_all_layers"]["binary"]["f1"]),
            _spread(entry["change_from_all_layers"]["binary"]["roc_auc"]),
            _spread(entry["change_from_all_layers"]["binary"]["fpr"]),
            _spread(entry["change_from_all_layers"]["binary"]["fnr"]),
            _spread(entry["change_from_all_layers"]["macro"]["f1"]),
        ]
        for layer, entry in block["removed"].items()
    ]
    return [
        "## Layer ablation (Random Forest)",
        "",
        f"Across seeds {block['seeds']}. The first row is the absolute value with all layers. "
        "Other rows are the **change** when that layer is removed (removed minus all layers), so "
        "a negative F1 change or a positive FPR/FNR change means the layer was helping.",
        "",
        *_table(
            [
                "Layer removed",
                "Binary F1",
                "Binary ROC-AUC",
                "Binary FPR",
                "Binary FNR",
                "Macro F1",
            ],
            rows,
        ),
    ]


def _render_recipes(block: dict[str, Any]) -> list[str]:
    rows = []
    for recipe, entry in block["recipes"].items():
        if entry["summary"] is None:
            rows.append([recipe, entry["runs"], *["n/a"] * 6])
            continue
        held = entry["summary"]["held_out_of_training"]
        seen = entry["summary"]["seen_in_training"]
        rows.append(
            [
                recipe,
                entry["runs"],
                _spread(held["all"]["recall"]),
                _spread(held["observable_only"]["recall"]),
                _spread(seen["all"]["recall"]),
                _spread(seen["observable_only"]["recall"]),
                _spread(held["all"]["fpr"]),
                _spread(held["all"]["roc_auc"]),
            ]
        )
    return [
        "## Leave-one-recipe-out (Random Forest)",
        "",
        f"Across seeds {block['seeds']}. Each tampering case is removed from training and "
        "validation, then records made with only that recipe are scored against benign test "
        "records. 'Seen' is the same records scored by a model trained with the recipe. "
        "Detection here is benign vs. any risk. 'Observable' excludes records whose evidence "
        "was not collected.",
        "",
        *_table(
            [
                "Recipe",
                "Runs",
                "Recall, unseen",
                "Recall, unseen, observable",
                "Recall, seen",
                "Recall, seen, observable",
                "FPR, unseen",
                "ROC-AUC, unseen",
            ],
            rows,
        ),
    ]


def render_markdown(report: dict[str, Any]) -> str:
    """Render from the report dictionary only, so the two files cannot disagree."""
    dataset = report["dataset"]
    models = report["models"]
    lines = [
        "# ProvenanceX evaluation report",
        "",
        f"> **WARNING: {report['warning']}**",
        ">",
        f"> {report['what_synthetic_means']}",
        "",
        "Generated by `ml/scripts/evaluate_models.py`. Do not edit by hand.",
        "",
        "## Dataset",
        "",
        *_table(
            ["Item", "Value"],
            [
                ["Records", dataset["record_count"]],
                ["Families", dataset["family_count"]],
                ["Labels", dataset["label_counts"]],
                ["Primary split", dataset["split_counts"]],
                ["Ground truth", dataset["ground_truth_status"]],
                [
                    "Records whose label evidence was not observed",
                    dataset["label_evidence_unobservable"],
                ],
                ["Dataset SHA-256", f"`{dataset['dataset_sha256']}`"],
                ["Python", models["python_version"]],
                ["Libraries", models["library_versions"]],
            ],
        ),
        "## Features not evaluated",
        "",
        "These features have no data source in the pipeline. They are null in every record and "
        "were not used by any model:",
        "",
        *[f"- `{name}`" for name in report["not_evaluated_features"]],
        "",
        "## Threshold policy",
        "",
        report["threshold_policy"],
        "",
        *_render_vulnerable(report),
        *_render_primary(report["primary_test_results"]),
        *_render_baselines(report["primary_test_results"]),
        *_render_repeated(report["repeated_family_splits"]),
        *_render_ablation(report["layer_ablation"]),
        *_render_recipes(report["leave_one_recipe_out"]),
    ]
    return "\n".join(lines).rstrip("\n") + "\n"


def write_report(report: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "evaluation_report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "evaluation_report.md").write_text(render_markdown(report), encoding="utf-8")

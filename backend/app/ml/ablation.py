"""Retraining experiments: repeated family splits, layer ablation, leave-one-recipe-out.

Each run fits on its own train split and picks its threshold on its own validation split, by
the same procedure as Milestone B with the same fixed hyperparameters. Test records are only
scored. Nothing is chosen after looking at test results.
"""

from collections.abc import Sequence
from dataclasses import replace
from statistics import mean, stdev
from typing import Any

import numpy as np

from app.ml.baselines import evaluate_baselines
from app.ml.dataset.splits import assign_family_splits
from app.ml.dataset.tampering import TAMPERING_CASES
from app.ml.evaluation import (
    binary_metrics,
    binary_truth,
    evaluate_bundle,
    evaluate_classifier,
    observable_mask,
)
from app.ml.feature_schema import FEATURE_NAMES, FeatureRecord, Label, Layer, features_in_layer
from app.ml.preprocessing import PreprocessingParams, transform
from app.ml.training import (
    ThresholdChoice,
    TrainingConfig,
    choose_risk_threshold,
    fit_forest,
    fit_supervised_and_preprocess,
    risk_scores,
    train_models,
)

ABLATION_METRICS = ("precision", "recall", "f1", "roc_auc", "fpr", "fnr")


def resplit(records: Sequence[FeatureRecord], seed: int) -> list[FeatureRecord]:
    """Return copies assigned to a new family split. The originals are not changed."""
    families = {record.family_id: record.artifact_type for record in records}
    splits = assign_family_splits(families, seed)
    return [record.model_copy(update={"split": splits[record.family_id]}) for record in records]


def partition(records: Sequence[FeatureRecord]) -> dict[str, list[FeatureRecord]]:
    parts: dict[str, list[FeatureRecord]] = {"train": [], "validation": [], "test": []}
    for record in records:
        parts[record.split].append(record)
    return parts


def _forest_fit(
    train: list[FeatureRecord],
    validation: list[FeatureRecord],
    cfg: TrainingConfig,
    feature_names: Sequence[str],
) -> tuple[PreprocessingParams, Any, ThresholdChoice]:
    params, x_train, y_train = fit_supervised_and_preprocess(train, cfg, feature_names)
    forest = fit_forest(x_train, y_train, cfg)
    scores = risk_scores(forest.predict_proba(transform(params, validation)))
    return params, forest, choose_risk_threshold(scores, binary_truth(validation))


def evaluate_split(
    records: Sequence[FeatureRecord], seed: int, cfg: TrainingConfig, metadata: dict[str, Any]
) -> dict[str, Any]:
    """Train all models on one family split and score its test records."""
    parts = partition(resplit(records, seed))
    bundle = train_models(parts["train"], parts["validation"], metadata, replace(cfg, seed=seed))
    return {
        "seed": seed,
        "test_records": len(parts["test"]),
        "models": evaluate_bundle(bundle, parts["test"]),
        "baselines": evaluate_baselines(parts["test"]),
        "thresholds": bundle.thresholds.model_dump(mode="json"),
    }


def summarize(runs: Sequence[Any]) -> Any:
    """Collapse same-shaped results into mean, standard deviation, min, max and n per number."""
    dicts = [run for run in runs if isinstance(run, dict)]
    if dicts:
        return {key: summarize([run[key] for run in dicts]) for key in dicts[0]}
    values = [float(run) for run in runs if isinstance(run, int | float)]
    if not values:
        return None
    return {
        "mean": mean(values),
        "std": stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
        "n": len(values),
    }


def _forest_metrics(forest: Any, params: PreprocessingParams, test, threshold: float) -> dict:
    return evaluate_classifier(forest, transform(params, test), test, threshold)


def _ablation_row(result: dict[str, Any]) -> dict[str, Any]:
    binary = result["binary"]
    macro = result["multiclass"]["macro"]
    return {
        "binary": {key: binary[key] for key in ABLATION_METRICS},
        "macro": {key: macro[key] for key in ABLATION_METRICS},
    }


def _delta(row: dict[str, Any], full: dict[str, Any]) -> dict[str, Any]:
    """How much the metric changed when the layer was removed (ablated minus full)."""
    return {
        view: {
            key: None
            if row[view][key] is None or full[view][key] is None
            else row[view][key] - full[view][key]
            for key in ABLATION_METRICS
        }
        for view in ("binary", "macro")
    }


def _ablation_score(
    parts: dict[str, list[FeatureRecord]], cfg: TrainingConfig, names: Sequence[str]
) -> dict[str, Any]:
    params, forest, choice = _forest_fit(parts["train"], parts["validation"], cfg, names)
    return _ablation_row(_forest_metrics(forest, params, parts["test"], choice.value))


def run_ablation(
    records: Sequence[FeatureRecord], seeds: Sequence[int], cfg: TrainingConfig
) -> dict[str, Any]:
    """Random Forest with all layers, then with each layer removed, across the seeds."""
    all_runs: list[dict[str, Any]] = []
    layer_runs: dict[str, list[dict[str, Any]]] = {str(layer): [] for layer in Layer}
    layer_deltas: dict[str, list[dict[str, Any]]] = {str(layer): [] for layer in Layer}
    for seed in seeds:
        parts = partition(resplit(records, seed))
        run_cfg = replace(cfg, seed=seed)

        full = _ablation_score(parts, run_cfg, FEATURE_NAMES)
        all_runs.append(full)
        for layer in Layer:
            removed = set(features_in_layer(layer))
            names = [name for name in FEATURE_NAMES if name not in removed]
            row = _ablation_score(parts, run_cfg, names)
            layer_runs[str(layer)].append(row)
            layer_deltas[str(layer)].append(_delta(row, full))
    return {
        "model": "random_forest",
        "seeds": list(seeds),
        "all_layers": summarize(all_runs),
        "removed": {
            layer: {
                "features_removed": list(features_in_layer(Layer(layer))),
                "metrics": summarize(layer_runs[layer]),
                "change_from_all_layers": summarize(layer_deltas[layer]),
            }
            for layer in layer_runs
        },
    }


def _recipe_scores(
    forest: Any,
    params: PreprocessingParams,
    target: list[FeatureRecord],
    benign: list[FeatureRecord],
    threshold: float,
) -> dict[str, Any]:
    rows = [*target, *benign]
    positive = np.asarray([True] * len(target) + [False] * len(benign))
    scores = risk_scores(forest.predict_proba(transform(params, rows)))
    flagged = scores >= threshold
    visible = observable_mask(rows)
    return {
        "all": binary_metrics(positive, flagged, scores),
        "observable_only": binary_metrics(positive[visible], flagged[visible], scores[visible]),
    }


def _uses_recipe(record: FeatureRecord, recipe: str) -> bool:
    return recipe in record.applied_recipes


def _recipe_run(
    parts: dict[str, list[FeatureRecord]], recipe: str, cfg: TrainingConfig, full: tuple
) -> dict[str, Any] | None:
    """Train without one recipe, then measure detection of records made only with it."""
    target = [r for r in parts["test"] if r.applied_recipes == [recipe]]
    benign = [r for r in parts["test"] if r.label == Label.BENIGN]
    if not target or not benign:
        return None
    train = [r for r in parts["train"] if not _uses_recipe(r, recipe)]
    validation = [r for r in parts["validation"] if not _uses_recipe(r, recipe)]
    params, forest, choice = _forest_fit(train, validation, cfg, FEATURE_NAMES)
    return {
        "held_out_of_training": _recipe_scores(forest, params, target, benign, choice.value),
        "seen_in_training": _recipe_scores(full[1], full[0], target, benign, full[2].value),
    }


def run_leave_one_recipe_out(
    records: Sequence[FeatureRecord], seeds: Sequence[int], cfg: TrainingConfig
) -> dict[str, Any]:
    """For each tampering case, compare detection when unseen in training and when seen."""
    runs: dict[str, list[dict[str, Any]]] = {recipe: [] for recipe in TAMPERING_CASES}
    for seed in seeds:
        parts = partition(resplit(records, seed))
        run_cfg = replace(cfg, seed=seed)
        full = _forest_fit(parts["train"], parts["validation"], run_cfg, FEATURE_NAMES)
        for recipe in TAMPERING_CASES:
            result = _recipe_run(parts, recipe, run_cfg, full)
            if result is not None:
                runs[recipe].append(result)
    return {
        "model": "random_forest",
        "seeds": list(seeds),
        "recipes": {
            recipe: {"runs": len(results), "summary": summarize(results) if results else None}
            for recipe, results in runs.items()
        },
    }

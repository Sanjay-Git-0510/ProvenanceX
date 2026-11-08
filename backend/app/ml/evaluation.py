"""Metrics computed from model outputs. Nothing here fits or tunes anything.

A metric that is undefined (for example precision when nothing was flagged) is None, never 0.
"""

from collections.abc import Sequence
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from app.ml.feature_schema import FeatureRecord, Label
from app.ml.preprocessing import PreprocessingParams, transform
from app.ml.training import (
    BENIGN_INDEX,
    LABEL_ORDER,
    ModelBundle,
    anomaly_scores,
    encode_labels,
    risk_scores,
)

METRIC_KEYS = ("precision", "recall", "f1", "roc_auc", "fpr", "fnr")


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _auc(is_positive: np.ndarray, scores: np.ndarray | None) -> float | None:
    if scores is None or is_positive.all() or not is_positive.any():
        return None
    return float(roc_auc_score(is_positive, scores))


def binary_metrics(
    is_positive: np.ndarray, flagged: np.ndarray, scores: np.ndarray | None = None
) -> dict[str, Any]:
    """Precision, recall, F1, ROC-AUC, FPR and FNR, with the raw counts behind them."""
    tp = int(np.sum(flagged & is_positive))
    fp = int(np.sum(flagged & ~is_positive))
    tn = int(np.sum(~flagged & ~is_positive))
    fn = int(np.sum(~flagged & is_positive))
    return {
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "roc_auc": _auc(is_positive, scores),
        "fpr": _ratio(fp, fp + tn),
        "fnr": _ratio(fn, fn + tp),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "support": tp + fn,
        "records": tp + fp + tn + fn,
    }


def macro_average(per_class: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The mean over classes where each metric is defined; the count used is recorded."""
    macro: dict[str, Any] = {}
    for key in METRIC_KEYS:
        values = [m[key] for m in per_class.values() if m[key] is not None]
        macro[key] = float(np.mean(values)) if values else None
        macro[f"{key}_classes"] = len(values)
    return macro


def per_class_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, class_scores: np.ndarray
) -> dict[str, Any]:
    """One-vs-rest metrics per class plus the macro average."""
    per_class = {
        str(label): binary_metrics(y_true == index, y_pred == index, class_scores[:, index])
        for index, label in enumerate(LABEL_ORDER)
    }
    return {"per_class": per_class, "macro": macro_average(per_class)}


def binary_truth(records: Sequence[FeatureRecord]) -> np.ndarray:
    """True for any non-benign label. "Any risk" is not a claim that the artifact is malicious."""
    return encode_labels(list(records)) != BENIGN_INDEX


def observable_mask(records: Sequence[FeatureRecord]) -> np.ndarray:
    return np.asarray([r.label_evidence_observable for r in records], dtype=bool)


def _binary_views(
    records: Sequence[FeatureRecord], flagged: np.ndarray, scores: np.ndarray
) -> dict[str, Any]:
    truth = binary_truth(records)
    visible = observable_mask(records)
    return {
        "binary": binary_metrics(truth, flagged, scores),
        "binary_observable_only": binary_metrics(truth[visible], flagged[visible], scores[visible]),
    }


def evaluate_classifier(
    model: Any, matrix: np.ndarray, records: Sequence[FeatureRecord], threshold: float
) -> dict[str, Any]:
    """Multiclass metrics use the top class; binary metrics use the given threshold."""
    probabilities = model.predict_proba(matrix)
    y_true = encode_labels(list(records))
    y_pred = np.argmax(probabilities, axis=1)
    scores = risk_scores(probabilities)
    return {
        "threshold": threshold,
        "multiclass": per_class_metrics(y_true, y_pred, probabilities),
        **_binary_views(records, scores >= threshold, scores),
    }


def evaluate_anomaly(
    model: IsolationForest,
    matrix: np.ndarray,
    records: Sequence[FeatureRecord],
    threshold: float,
) -> dict[str, Any]:
    """Isolation Forest has no classes, so "per class" means each risk class against benign."""
    scores = anomaly_scores(model, matrix)
    flagged = scores >= threshold
    labels = np.asarray([r.label for r in records])
    per_class: dict[str, dict[str, Any]] = {}
    for label in LABEL_ORDER:
        if label == Label.BENIGN:
            continue
        keep = (labels == label) | (labels == Label.BENIGN)
        per_class[str(label)] = binary_metrics(labels[keep] == label, flagged[keep], scores[keep])
    return {
        "threshold": threshold,
        "class_vs_benign": {"per_class": per_class, "macro": macro_average(per_class)},
        **_binary_views(records, flagged, scores),
    }


def flag_everything_reference(records: Sequence[FeatureRecord]) -> dict[str, Any]:
    """What a detector that flags every record would score, as a floor for reading F1."""
    truth = binary_truth(records)
    return binary_metrics(truth, np.ones(truth.shape, dtype=bool))


def benign_flag_rate_by_hash_comparison(
    model: Any, params: PreprocessingParams, records: Sequence[FeatureRecord], threshold: float
) -> dict[str, Any]:
    """How often benign records are flagged, split by whether hash_changed was evaluated."""
    benign = [record for record in records if record.label == Label.BENIGN]

    def rate(rows: list[FeatureRecord]) -> dict[str, Any]:
        if not rows:
            return {"records": 0, "flagged": 0, "rate": None}
        scores = risk_scores(model.predict_proba(transform(params, rows)))
        flagged = int(np.sum(scores >= threshold))
        return {"records": len(rows), "flagged": flagged, "rate": flagged / len(rows)}

    return {
        "comparison_available": rate([r for r in benign if r.features["hash_changed"] is not None]),
        "comparison_missing": rate([r for r in benign if r.features["hash_changed"] is None]),
    }


def evaluate_bundle(bundle: ModelBundle, records: Sequence[FeatureRecord]) -> dict[str, Any]:
    """Score all three models with the thresholds stored in the bundle."""
    matrix = transform(bundle.preprocessing, records)
    return {
        "random_forest": evaluate_classifier(
            bundle.random_forest, matrix, records, bundle.thresholds.random_forest.value
        ),
        "xgboost": evaluate_classifier(
            bundle.xgboost, matrix, records, bundle.thresholds.xgboost.value
        ),
        "isolation_forest": evaluate_anomaly(
            bundle.isolation_forest, matrix, records, bundle.thresholds.isolation_forest.value
        ),
    }

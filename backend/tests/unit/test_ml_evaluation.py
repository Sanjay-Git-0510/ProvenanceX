"""Metrics: correct arithmetic, and undefined results are None rather than 0."""

import numpy as np
import pytest

from app.ml.evaluation import (
    benign_flag_rate_by_hash_comparison,
    binary_metrics,
    binary_truth,
    evaluate_anomaly,
    evaluate_classifier,
    flag_everything_reference,
    macro_average,
    observable_mask,
    per_class_metrics,
)
from app.ml.training import LABEL_ORDER
from tests.ml_helpers import record


def test_binary_metrics_known_values():
    positive = np.array([True, True, True, False, False])
    flagged = np.array([True, True, False, True, False])
    scores = np.array([0.9, 0.8, 0.2, 0.7, 0.1])
    result = binary_metrics(positive, flagged, scores)
    assert result["tp"] == 2 and result["fp"] == 1 and result["tn"] == 1 and result["fn"] == 1
    assert result["precision"] == pytest.approx(2 / 3)
    assert result["recall"] == pytest.approx(2 / 3)
    assert result["f1"] == pytest.approx(2 / 3)
    assert result["fpr"] == pytest.approx(1 / 2)
    assert result["fnr"] == pytest.approx(1 / 3)
    assert result["roc_auc"] == pytest.approx(5 / 6)


def test_undefined_metrics_are_none_not_zero():
    positive = np.array([False, False])
    result = binary_metrics(positive, np.array([False, False]), np.array([0.1, 0.2]))
    assert result["precision"] is None
    assert result["recall"] is None
    assert result["roc_auc"] is None
    assert result["fnr"] is None
    assert result["fpr"] == 0.0


def test_no_scores_means_no_auc():
    positive = np.array([True, False])
    assert binary_metrics(positive, positive)["roc_auc"] is None


def test_empty_input_is_all_undefined():
    empty = np.array([], dtype=bool)
    result = binary_metrics(empty, empty, np.array([]))
    assert result["records"] == 0
    assert result["f1"] is None


def test_macro_skips_undefined_and_counts_classes():
    metrics = {
        "a": dict.fromkeys(("precision", "recall", "f1", "roc_auc", "fpr", "fnr"), 0.5),
        "b": {**dict.fromkeys(("recall", "f1", "roc_auc", "fpr", "fnr"), 1.0), "precision": None},
    }
    macro = macro_average(metrics)
    assert macro["precision"] == 0.5
    assert macro["precision_classes"] == 1
    assert macro["recall"] == 0.75
    assert macro["recall_classes"] == 2


def test_macro_all_undefined_is_none():
    metrics = {"a": dict.fromkeys(("precision", "recall", "f1", "roc_auc", "fpr", "fnr"))}
    assert macro_average(metrics)["f1"] is None


def test_per_class_covers_all_labels():
    y_true = np.array([0, 1, 2, 3])
    scores = np.eye(4)
    result = per_class_metrics(y_true, y_true, scores)
    assert list(result["per_class"]) == [str(label) for label in LABEL_ORDER]
    assert result["macro"]["f1"] == 1.0


def test_binary_truth_treats_every_non_benign_label_as_risk():
    rows = [record(label=label) for label in LABEL_ORDER]
    assert binary_truth(rows).tolist() == [False, True, True, True]


def test_observable_mask():
    rows = [record(observable=True), record(observable=False)]
    assert observable_mask(rows).tolist() == [True, False]


class _FixedClassifier:
    def __init__(self, probabilities):
        self.probabilities = np.asarray(probabilities, dtype=float)

    def predict_proba(self, _matrix):
        return self.probabilities


def test_classifier_uses_top_class_and_given_threshold():
    rows = [record(label="benign"), record(label="suspicious")]
    model = _FixedClassifier([[0.7, 0.1, 0.1, 0.1], [0.4, 0.0, 0.0, 0.6]])
    result = evaluate_classifier(model, np.zeros((2, 1)), rows, threshold=0.5)
    assert result["threshold"] == 0.5
    assert result["binary"]["tp"] == 1
    assert result["binary"]["fp"] == 0
    assert result["multiclass"]["per_class"]["suspicious"]["recall"] == 1.0


def test_classifier_threshold_changes_only_binary_view():
    rows = [record(label="benign"), record(label="suspicious")]
    model = _FixedClassifier([[0.7, 0.1, 0.1, 0.1], [0.4, 0.0, 0.0, 0.6]])
    low = evaluate_classifier(model, np.zeros((2, 1)), rows, threshold=0.1)
    high = evaluate_classifier(model, np.zeros((2, 1)), rows, threshold=0.5)
    assert low["binary"]["fp"] == 1
    assert high["binary"]["fp"] == 0
    assert low["multiclass"] == high["multiclass"]


class _FixedForest:
    def __init__(self, scores):
        self.scores = np.asarray(scores, dtype=float)

    def score_samples(self, _matrix):
        return -self.scores


def test_anomaly_compares_each_class_with_benign_only():
    rows = [
        record(label="benign"),
        record(label="benign"),
        record(label="suspicious"),
        record(label="vulnerable"),
    ]
    result = evaluate_anomaly(_FixedForest([0.1, 0.9, 0.8, 0.2]), np.zeros((4, 1)), rows, 0.5)
    per_class = result["class_vs_benign"]["per_class"]
    assert set(per_class) == {"vulnerable", "provenance_weak", "suspicious"}
    assert per_class["suspicious"]["records"] == 3
    assert per_class["suspicious"]["recall"] == 1.0
    assert per_class["vulnerable"]["recall"] == 0.0
    assert per_class["provenance_weak"]["recall"] is None


def test_observable_view_excludes_unobserved_records():
    rows = [
        record(label="benign"),
        record(label="suspicious"),
        record(label="suspicious", observable=False),
    ]
    model = _FixedClassifier([[1, 0, 0, 0], [0, 0, 0, 1], [1, 0, 0, 0]])
    result = evaluate_classifier(model, np.zeros((3, 1)), rows, 0.5)
    assert result["binary"]["recall"] == 0.5
    assert result["binary_observable_only"]["recall"] == 1.0


def test_flag_everything_reference():
    rows = [record(label="benign"), record(label="suspicious"), record(label="vulnerable")]
    result = flag_everything_reference(rows)
    assert result["recall"] == 1.0
    assert result["fpr"] == 1.0
    assert result["precision"] == pytest.approx(2 / 3)


def test_benign_flag_rate_splits_on_hash_comparison(monkeypatch):
    monkeypatch.setattr("app.ml.evaluation.transform", lambda _params, rows: rows)

    class Model:
        def predict_proba(self, rows):
            return np.array(
                [[0.1 if r.features["hash_changed"] is None else 0.9, 0, 0, 0] for r in rows]
            )

    rows = [
        record(label="benign", hash_changed=False),
        record(label="benign"),
        record(label="suspicious"),
    ]
    result = benign_flag_rate_by_hash_comparison(Model(), None, rows, 0.5)
    assert result["comparison_available"] == {"records": 1, "flagged": 0, "rate": 0.0}
    assert result["comparison_missing"] == {"records": 1, "flagged": 1, "rate": 1.0}


def test_benign_flag_rate_with_no_records(monkeypatch):
    result = benign_flag_rate_by_hash_comparison(None, None, [record(label="suspicious")], 0.5)
    assert result["comparison_missing"]["rate"] is None

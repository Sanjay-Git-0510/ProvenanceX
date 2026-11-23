"""Phase 4: real-world evaluation helpers, repeated splits, ablation and saved-model reload.

Rows are constructed test inputs (see test_realworld_training.make_rows), not collected data.
"""

import hashlib
import json

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from app.ml.artifacts import _load_skops, _load_xgboost
from app.ml.feature_schema import Layer
from app.ml.preprocessing import PreprocessingParams
from app.ml.realworld.dataset import assign_splits, with_splits
from app.ml.realworld.train_eval import (
    Config,
    Trained,
    _bootstrap,
    _calibration,
    _pr_auc,
    _threshold_table,
    ablation,
    evaluate_scores,
    repeated_splits,
    save_models,
    scores,
    train,
)
from app.ml.training import ThresholdChoice
from tests.unit.test_realworld_training import make_rows

SMALL = Config(
    rf_estimators=10,
    xgb_estimators=10,
    iforest_estimators=10,
    repeated_seeds=3,
    bootstrap_resamples=20,
)


@pytest.fixture(scope="module")
def trained():
    rows = make_rows(25, 50)
    parts = with_splits(rows, assign_splits(rows, SMALL.seed))
    return parts, train(parts["train"], parts["validation"], SMALL)


# --- metric helpers -------------------------------------------------------------------------


def test_calibration_bins_and_brier_on_known_values():
    y = np.array([0, 0, 1, 1])
    p = np.array([0.1, 0.15, 0.9, 1.0])
    cal = _calibration(y, p)
    assert cal["brier"] == pytest.approx(0.0106, abs=1e-4)
    assert cal["bins"] == [
        {"bin": "0.0-0.2", "n": 2, "mean_predicted": 0.125, "observed_positive_rate": 0.0},
        {"bin": "0.8-1.0", "n": 2, "mean_predicted": 0.95, "observed_positive_rate": 1.0},
    ]  # p == 1.0 lands in the last bin; empty bins are left out


def test_threshold_table_counts_scores_at_threshold_as_flagged():
    y = np.array([0, 0, 1, 1])
    s = np.array([0.2, 0.5, 0.5, 0.9])
    table = _threshold_table(y, s, [0.5, 0.95])
    assert table[0] == {"threshold": 0.5, "precision": 2 / 3, "recall": 1.0, "fpr": 0.5, "fnr": 0.0}
    assert table[1]["recall"] == 0.0 and table[1]["fpr"] == 0.0


def test_single_class_metrics_are_none_not_invented():
    y = np.zeros(4, dtype=int)
    s = np.array([0.1, 0.2, 0.7, 0.9])
    assert _pr_auc(y, s) is None
    boot = _bootstrap(y, s, 0.5, 10, 0)
    assert boot["roc_auc_95ci"] is None  # ROC-AUC needs both classes
    # F1 = 2TP / (2TP + FP + FN) is defined (0) once a benign row is flagged
    assert boot["f1_95ci"] == [0.0, 0.0]
    assert _bootstrap(y, np.zeros(4), 0.5, 10, 0)["f1_95ci"] is None  # nothing to count


def test_evaluate_scores_on_all_benign_rows():
    rows = make_rows(4, 0)
    result = evaluate_scores(rows, np.array([0.1, 0.6, 0.2, 0.9]), 0.5, probability=False)
    assert result["roc_auc"] is None and result["pr_auc"] is None
    assert result["confusion_matrix"] == {"tp": 0, "fp": 2, "tn": 2, "fn": 0}
    assert result["no_prior_scan"] == {"benign_rows": 4, "false_positives": 2, "fpr": 0.5}


def test_bootstrap_interval_is_ordered_and_bounded():
    rng = np.random.default_rng(1)
    y = np.array([0, 1] * 10)
    s = np.clip(y * 0.6 + rng.random(20) * 0.5, 0, 1)
    boot = _bootstrap(y, s, 0.5, 200, 7)
    lo, hi = boot["f1_95ci"]
    assert 0.0 <= lo <= hi <= 1.0
    assert boot == _bootstrap(y, s, 0.5, 200, 7)  # seeded, so repeatable


# --- repeated splits and ablation -------------------------------------------------------------


def test_repeated_splits_summarize_and_leave_caller_rows_alone():
    rows = make_rows(25, 50)
    before = [r.split for r in rows]
    out = repeated_splits(rows, SMALL)
    assert [r.split for r in rows] == before
    assert out["seeds"] == 3
    rf = out["summary"]["random_forest"]["f1"]
    assert rf["n"] + out["skipped"] == 3
    assert rf["min"] <= rf["mean"] <= rf["max"]
    assert set(out["summary"]) == {"random_forest", "xgboost", "rules_only", "vulnerability_only"}


def test_repeated_splits_skip_seeds_without_enough_rows():
    out = repeated_splits(make_rows(4, 40), SMALL)  # too few benign rows for any split
    assert out["skipped"] == 3 and out["summary"] == {}


def test_ablation_has_one_entry_per_layer(trained):
    parts, _ = trained
    out = ablation(parts, SMALL)
    assert [entry["removed_layer"] for entry in out] == [str(layer) for layer in Layer]
    for entry in out:
        assert "error" in entry or {"f1", "roc_auc", "pr_auc", "fpr"} <= set(entry)


# --- saved models -----------------------------------------------------------------------------


def test_saved_models_reload_with_same_scores(trained, tmp_path):
    parts, models = trained
    manifest = save_models(models, tmp_path, {"synthetic": False}, {})
    raw = {name: (tmp_path / name).read_bytes() for name in manifest["files"]}
    for name, entry in manifest["files"].items():
        assert hashlib.sha256(raw[name]).hexdigest() == entry["sha256"]
    thresholds = {
        k: ThresholdChoice.model_validate(v) for k, v in json.loads(raw["thresholds.json"]).items()
    }
    reloaded = Trained(
        preprocessing=PreprocessingParams.model_validate_json(raw["preprocessing.json"]),
        random_forest=_load_skops(raw["random_forest.skops"], "rf", RandomForestClassifier),
        xgboost=_load_xgboost(raw["xgboost.json"]),
        isolation_forest=_load_skops(raw["isolation_forest.skops"], "if", IsolationForest),
        thresholds=thresholds,
    )
    assert thresholds == models.thresholds
    want, got = scores(models, parts["test"]), scores(reloaded, parts["test"])
    for name in want:
        np.testing.assert_allclose(got[name], want[name], rtol=1e-6)

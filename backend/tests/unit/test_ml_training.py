"""Training: splits are respected, thresholds come from validation, the test set is unread."""

import hashlib
import json

import numpy as np
import pytest

from app.ml.dataset.generator import generate_records, write_dataset
from app.ml.feature_schema import Label
from app.ml.preprocessing import transform
from app.ml.training import (
    BENIGN_INDEX,
    LABEL_ORDER,
    ThresholdChoice,
    TrainingConfig,
    anomaly_scores,
    choose_anomaly_threshold,
    choose_risk_threshold,
    encode_labels,
    load_training_records,
    risk_scores,
    train_models,
)

CONFIG = TrainingConfig(rf_estimators=15, xgb_estimators=10, iforest_estimators=15, n_jobs=1)
META = {"synthetic": True, "notice": "SYNTHETIC", "dataset_sha256": "abc"}


@pytest.fixture(scope="module")
def records():
    return generate_records(60, 7)


@pytest.fixture(scope="module")
def parts(records):
    train = [r for r in records if r.split == "train"]
    validation = [r for r in records if r.split == "validation"]
    test = [r for r in records if r.split == "test"]
    return train, validation, test


@pytest.fixture(scope="module")
def bundle(parts):
    return train_models(parts[0], parts[1], META, CONFIG)


def test_all_three_models_predict_valid_output(bundle, parts):
    matrix = transform(bundle.preprocessing, parts[1])
    for model in (bundle.random_forest, bundle.xgboost):
        probabilities = model.predict_proba(matrix)
        assert probabilities.shape == (len(parts[1]), len(LABEL_ORDER))
        assert np.allclose(probabilities.sum(axis=1), 1.0)
    assert anomaly_scores(bundle.isolation_forest, matrix).shape == (len(parts[1]),)


def test_known_bad_is_not_a_trained_class():
    assert Label.MALICIOUS_KNOWN_BAD not in LABEL_ORDER


def test_isolation_forest_sees_only_benign_training_rows(bundle, parts):
    expected = sum(r.label == Label.BENIGN for r in parts[0])
    assert bundle.metadata["benign_train_record_count"] == expected
    assert bundle.isolation_forest.max_samples_ == min(256, expected)


def test_metadata_records_synthetic_and_split_use(bundle, parts):
    meta = bundle.metadata
    assert meta["synthetic"] is True
    assert meta["notice"] == "SYNTHETIC"
    assert meta["train_record_count"] == len(parts[0])
    assert meta["primary_model"] == "random_forest"
    assert meta["split_use"]["test"] == "not read during training"


def test_all_thresholds_are_from_validation(bundle):
    for choice in bundle.thresholds.model_dump().values():
        assert choice["selected_on"] == "validation"


def test_validation_records_do_not_change_fitted_medians(parts):
    train, validation, _ = parts
    first = train_models(train, validation, META, CONFIG)
    second = train_models(train, validation[: len(validation) // 2], META, CONFIG)
    assert first.preprocessing == second.preprocessing


def test_training_is_repeatable(parts, bundle):
    again = train_models(parts[0], parts[1], META, CONFIG)
    matrix = transform(bundle.preprocessing, parts[1])
    assert np.array_equal(
        bundle.random_forest.predict_proba(matrix), again.random_forest.predict_proba(matrix)
    )
    assert bundle.thresholds == again.thresholds


@pytest.mark.parametrize("position", ["train", "validation"])
def test_train_models_refuses_test_records(parts, position):
    train, validation, test = parts
    bad_train = [*train, test[0]] if position == "train" else train
    bad_validation = [*validation, test[0]] if position == "validation" else validation
    with pytest.raises(ValueError, match="Expected only"):
        train_models(bad_train, bad_validation, META, CONFIG)


def test_empty_validation_is_refused(parts):
    with pytest.raises(ValueError, match="empty"):
        train_models(parts[0], [], META, CONFIG)


def test_missing_class_in_train_is_refused(parts):
    train = [r for r in parts[0] if r.label != Label.VULNERABLE]
    with pytest.raises(ValueError, match="every trained label"):
        train_models(train, parts[1], META, CONFIG)


def test_encode_labels_refuses_known_bad(parts):
    row = parts[0][0].model_copy(update={"label": Label.MALICIOUS_KNOWN_BAD})
    with pytest.raises(ValueError, match="outside"):
        encode_labels([row])


def test_risk_score_is_one_minus_benign():
    probabilities = np.zeros((1, len(LABEL_ORDER)))
    probabilities[0, BENIGN_INDEX] = 0.25
    assert risk_scores(probabilities)[0] == 0.75


def test_risk_threshold_separates_when_possible():
    scores = np.array([0.1, 0.2, 0.8, 0.9])
    choice = choose_risk_threshold(scores, np.array([False, False, True, True]))
    assert 0.2 < choice.value <= 0.8
    assert choice.validation_f1 == 1.0
    assert choice.validation_fpr == 0.0


def test_risk_threshold_tie_prefers_lower_fpr():
    scores = np.array([0.1, 0.5, 0.5, 0.9])
    choice = choose_risk_threshold(scores, np.array([False, False, True, True]))
    flagged = scores >= choice.value
    assert flagged.tolist() == [False, True, True, True]


@pytest.mark.parametrize("values", [[False, False], [True, True]])
def test_risk_threshold_needs_both_classes(values):
    with pytest.raises(ValueError, match="both"):
        choose_risk_threshold(np.array([0.1, 0.2]), np.array(values))


def test_anomaly_threshold_respects_target():
    scores = np.linspace(0, 1, 100)
    choice = choose_anomaly_threshold(scores, 0.05)
    assert np.mean(scores >= choice.value) <= 0.05
    assert choice.validation_fpr <= 0.05
    assert choice.validation_f1 is None


def test_anomaly_threshold_can_flag_nothing():
    choice = choose_anomaly_threshold(np.array([0.5, 0.5]), 0.0)
    assert choice.validation_fpr == 0.0


def test_anomaly_threshold_needs_benign_records():
    with pytest.raises(ValueError, match="benign"):
        choose_anomaly_threshold(np.array([]), 0.05)


def test_threshold_model_cannot_claim_test_selection():
    with pytest.raises(ValueError):
        ThresholdChoice(value=0.5, selected_on="test", criterion="x", validation_fpr=0.0)


# ------------------------------------------------------------------ dataset loading
def _write(records, directory):
    write_dataset(records, 7, directory)


def test_loader_returns_only_train_and_validation(records, tmp_path):
    _write(records, tmp_path)
    train, validation, metadata = load_training_records(tmp_path)
    assert {r.split for r in train} == {"train"}
    assert {r.split for r in validation} == {"validation"}
    assert metadata["synthetic"] is True
    assert len(train) + len(validation) < len(records)


def test_loader_never_parses_test_rows(records, tmp_path):
    """A test row that would fail validation proves test rows are not decoded into records."""
    _write(records, tmp_path)
    path = tmp_path / "dataset.jsonl"
    lines = path.read_bytes().splitlines()
    index = next(i for i, line in enumerate(lines) if json.loads(line)["split"] == "test")
    lines[index] = b'{"split": "test", "features": "not a valid record"}'
    body = b"\n".join(lines) + b"\n"
    path.write_bytes(body)
    meta_path = tmp_path / "dataset_metadata.json"
    metadata = json.loads(meta_path.read_text())
    metadata["dataset_sha256"] = hashlib.sha256(body).hexdigest()
    meta_path.write_text(json.dumps(metadata))
    train, _, _ = load_training_records(tmp_path)
    assert train


def test_test_rows_cannot_influence_the_models(records, tmp_path):
    """Replacing every test row must leave the training inputs identical."""
    _write(records, tmp_path / "a")
    without_test = [r for r in records if r.split != "test"]
    _write(without_test, tmp_path / "b")
    first = load_training_records(tmp_path / "a")
    second = load_training_records(tmp_path / "b")
    assert first[0] == second[0]
    assert first[1] == second[1]


def test_loader_refuses_altered_dataset(records, tmp_path):
    _write(records, tmp_path)
    with (tmp_path / "dataset.jsonl").open("ab") as handle:
        handle.write(b"\n")
    with pytest.raises(ValueError, match="digest"):
        load_training_records(tmp_path)


def test_loader_refuses_unknown_format(records, tmp_path):
    _write(records, tmp_path)
    (tmp_path / "dataset_metadata.json").write_text('{"format": "other"}')
    with pytest.raises(ValueError, match="format"):
        load_training_records(tmp_path)

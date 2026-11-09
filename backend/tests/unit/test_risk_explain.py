"""SHAP factors and model loading, using a small model trained on generated synthetic records."""

import ast
import json
from pathlib import Path

import numpy as np
import pytest

from app.ml.artifacts import MANIFEST_NAME, RANDOM_FOREST_NAME, save_bundle
from app.ml.feature_schema import FEATURE_NAMES, NOT_EVALUATED_FEATURES, NullReason
from app.ml.training import TrainingConfig, train_models
from app.risk import explain as explain_module
from app.risk import model_runtime
from app.risk.explain import explain_random_forest, not_evaluated_features
from app.risk.model_runtime import (
    ModelUnavailable,
    encode_features,
    load_models,
    score_row,
)
from tests.unit.test_ml_artifacts import generate_records

CONFIG = TrainingConfig(rf_estimators=10, xgb_estimators=5, iforest_estimators=10, n_jobs=1)
META = {"synthetic": True, "notice": "SYNTHETIC", "dataset_sha256": "abc"}


@pytest.fixture(scope="module")
def records():
    return generate_records(60, 7)


@pytest.fixture(scope="module")
def saved_dir(records, tmp_path_factory):
    train = [r for r in records if r.split == "train"]
    validation = [r for r in records if r.split == "validation"]
    directory = tmp_path_factory.mktemp("models")
    save_bundle(train_models(train, validation, META, CONFIG), directory)
    return directory


@pytest.fixture(autouse=True)
def empty_cache():
    model_runtime.clear_cache()
    yield
    model_runtime.clear_cache()


def _validation_record(records):
    return next(r for r in records if r.split == "validation")


def _explain(saved_dir, record, **kwargs):
    models = load_models(saved_dir)
    row = encode_features(models, record.features)
    outputs = score_row(models, row)
    result = explain_random_forest(
        models, row, record.features, record.null_reasons, outputs.rf_risk_probability, **kwargs
    )
    return models, outputs, result


def test_factors_add_up_to_the_model_probability(saved_dir, records):
    models, outputs, _ = _explain(saved_dir, _validation_record(records))
    row = encode_features(models, _validation_record(records).features)
    values, base = explain_module._risk_shap_values(models, row)
    totals = explain_module._feature_totals(models, values)
    assert base + sum(totals.values()) == pytest.approx(outputs.rf_risk_probability, abs=1e-9)


def test_top_factors_are_ranked_and_limited(saved_dir, records):
    _, _, result = _explain(saved_dir, _validation_record(records), top_n=3)
    assert result["status"] == "available"
    sizes = [abs(f["shap_contribution"]) for f in result["top_factors"]]
    assert len(sizes) <= 3
    assert sizes == sorted(sizes, reverse=True)


def test_null_features_are_marked_not_evaluated(saved_dir):
    features = dict.fromkeys(FEATURE_NAMES)
    reasons = dict.fromkeys(FEATURE_NAMES, NullReason.STAGE_ERROR)
    models = load_models(saved_dir)
    row = encode_features(models, features)
    outputs = score_row(models, row)
    result = explain_random_forest(models, row, features, reasons, outputs.rf_risk_probability)
    assert result["top_factors"]
    assert all(f["evaluated"] is False for f in result["top_factors"])
    assert all(f["value"] is None for f in result["top_factors"])
    assert all(f["null_reason"] == "stage_error" for f in result["top_factors"])
    assert "missing evidence" in result["note"]


def test_features_without_a_model_column_are_reported(saved_dir, records):
    record = _validation_record(records)
    listed = {
        i["feature"]: i
        for i in not_evaluated_features(
            load_models(saved_dir), record.features, record.null_reasons
        )
    }
    for name in NOT_EVALUATED_FEATURES:
        assert listed[name]["in_model"] is False
        assert listed[name]["null_reason"] == "no_data_source"


def test_values_are_plain_json(saved_dir, records):
    _, _, result = _explain(saved_dir, _validation_record(records))
    json.dumps(result)


def test_shap_failure_is_reported_and_no_factor_invented(saved_dir, records, monkeypatch):
    def broken(*_args):
        raise RuntimeError("boom")

    monkeypatch.setattr(explain_module, "_risk_shap_values", broken)
    _, _, result = _explain(saved_dir, _validation_record(records))
    assert result["status"] == "unavailable"
    assert result["top_factors"] == []
    assert "RuntimeError" in result["message"]


def test_missing_shap_package_is_reported(saved_dir, records, monkeypatch):
    def missing(*_args):
        raise ImportError("shap")

    monkeypatch.setattr(explain_module, "_risk_shap_values", missing)
    _, _, result = _explain(saved_dir, _validation_record(records))
    assert result["status"] == "unavailable"
    assert "not installed" in result["message"]


def test_missing_directory_is_unavailable(tmp_path):
    with pytest.raises(ModelUnavailable, match="manifest"):
        load_models(tmp_path / "absent")


def test_tampered_model_is_refused(saved_dir, tmp_path):
    for path in saved_dir.iterdir():
        (tmp_path / path.name).write_bytes(path.read_bytes())
    target = tmp_path / RANDOM_FOREST_NAME
    target.write_bytes(target.read_bytes() + b"x")
    with pytest.raises(ModelUnavailable, match="SHA-256 mismatch"):
        load_models(tmp_path)


def test_models_are_cached_until_the_manifest_changes(saved_dir, tmp_path, monkeypatch):
    for path in saved_dir.iterdir():
        (tmp_path / path.name).write_bytes(path.read_bytes())
    first = load_models(tmp_path)
    assert load_models(tmp_path) is first
    manifest_path = tmp_path / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["files"][RANDOM_FOREST_NAME]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ModelUnavailable):
        load_models(tmp_path)


def test_random_forest_scoring_is_repeatable(saved_dir, records):
    models = load_models(saved_dir)
    assert models.bundle.random_forest.n_jobs == 1
    row = encode_features(models, _validation_record(records).features)
    first = models.bundle.random_forest.predict_proba(row).tobytes()
    assert models.bundle.random_forest.predict_proba(row).tobytes() == first


def test_model_version_covers_every_file():
    files = {"a": {"sha256": "1"}, "b": {"sha256": "2"}}
    changed = {"a": {"sha256": "1"}, "b": {"sha256": "3"}}
    assert model_runtime.model_version(files) != model_runtime.model_version(changed)


def test_scores_are_separate_python_floats(saved_dir, records):
    models = load_models(saved_dir)
    outputs = score_row(models, encode_features(models, _validation_record(records).features))
    assert type(outputs.rf_risk_probability) is float
    assert type(outputs.anomaly_score) is float
    assert np.isfinite(outputs.anomaly_score)
    assert outputs.model_version.startswith("models-sha256:")


def test_risk_package_loads_models_only_through_load_bundle():
    root = Path(model_runtime.__file__).parent
    banned = {"pickle", "joblib", "dill", "skops", "torch", "cloudpickle"}
    for path in root.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            assert not {n.split(".")[0] for n in names} & banned, path.name
    source = (root / "model_runtime.py").read_text(encoding="utf-8")
    assert "load_bundle(model_dir)" in source
    assert "load_model(" not in source

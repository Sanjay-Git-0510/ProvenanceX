"""Artifacts: round trip, and refusal of anything altered, unlisted or untrusted."""

import ast
import json
import os
from collections import OrderedDict
from pathlib import Path

import numpy as np
import pytest
import skops.io as sio

from app.ml import artifacts
from app.ml.artifacts import (
    ARTIFACT_NAMES,
    ISOLATION_FOREST_NAME,
    MANIFEST_NAME,
    METADATA_NAME,
    PREPROCESSING_NAME,
    RANDOM_FOREST_NAME,
    THRESHOLDS_NAME,
    TRUSTED_SKOPS_TYPES,
    XGBOOST_NAME,
    ModelArtifactError,
    load_bundle,
    read_verified,
    save_bundle,
)
from app.ml.dataset.generator import generate_records
from app.ml.preprocessing import transform
from app.ml.training import TrainingConfig, train_models

CONFIG = TrainingConfig(rf_estimators=10, xgb_estimators=5, iforest_estimators=10, n_jobs=1)
META = {"synthetic": True, "notice": "SYNTHETIC", "dataset_sha256": "abc"}


@pytest.fixture(scope="module")
def bundle():
    records = generate_records(60, 7)
    train = [r for r in records if r.split == "train"]
    validation = [r for r in records if r.split == "validation"]
    trained = train_models(train, validation, META, CONFIG)
    return trained, validation


@pytest.fixture
def saved(bundle, tmp_path):
    save_bundle(bundle[0], tmp_path)
    return tmp_path


def rewrite_manifest_hash(directory: Path, name: str) -> None:
    """Simulates an attacker who also fixes the manifest, so only later checks can refuse."""
    path = directory / MANIFEST_NAME
    manifest = json.loads(path.read_text())
    manifest["files"][name]["sha256"] = artifacts._digest((directory / name).read_bytes())
    path.write_text(json.dumps(manifest))


def test_round_trip_gives_identical_predictions(bundle, saved):
    trained, validation = bundle
    loaded = load_bundle(saved)
    matrix = transform(trained.preprocessing, validation)
    assert np.array_equal(
        trained.random_forest.predict_proba(matrix), loaded.random_forest.predict_proba(matrix)
    )
    assert np.allclose(trained.xgboost.predict_proba(matrix), loaded.xgboost.predict_proba(matrix))
    assert np.array_equal(
        trained.isolation_forest.score_samples(matrix),
        loaded.isolation_forest.score_samples(matrix),
    )
    assert loaded.preprocessing == trained.preprocessing
    assert loaded.thresholds == trained.thresholds


def test_formats_are_skops_and_json_not_pickle(saved):
    assert (saved / RANDOM_FOREST_NAME).read_bytes()[:2] == b"PK"
    assert (saved / ISOLATION_FOREST_NAME).read_bytes()[:2] == b"PK"
    assert (saved / XGBOOST_NAME).read_bytes()[:1] == b"{"
    json.loads((saved / PREPROCESSING_NAME).read_text())


def test_manifest_lists_every_artifact_and_is_synthetic(saved):
    manifest = json.loads((saved / MANIFEST_NAME).read_text())
    assert set(manifest["files"]) == ARTIFACT_NAMES
    assert manifest["synthetic"] is True
    assert set(manifest["library_versions"]) == {"scikit-learn", "xgboost", "skops", "numpy"}


@pytest.mark.parametrize("name", sorted(ARTIFACT_NAMES))
def test_any_changed_byte_is_refused_before_parsing(saved, name, monkeypatch):
    def forbid(*_args, **_kwargs):
        raise AssertionError("parsed an unverified artifact")

    monkeypatch.setattr(sio, "loads", forbid)
    monkeypatch.setattr(sio, "get_untrusted_types", forbid)
    raw = bytearray((saved / name).read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    (saved / name).write_bytes(bytes(raw))
    with pytest.raises(ModelArtifactError, match="SHA-256"):
        load_bundle(saved)


@pytest.mark.parametrize("name", sorted(ARTIFACT_NAMES))
def test_missing_artifact_is_refused(saved, name):
    (saved / name).unlink()
    with pytest.raises(ModelArtifactError, match="Missing"):
        load_bundle(saved)


def test_missing_manifest_is_refused(saved):
    (saved / MANIFEST_NAME).unlink()
    with pytest.raises(ModelArtifactError, match="Missing"):
        load_bundle(saved)


@pytest.mark.parametrize("content", ["{not json", "[]", '{"format": "other"}'])
def test_bad_manifest_is_refused(saved, content):
    (saved / MANIFEST_NAME).write_text(content)
    with pytest.raises(ModelArtifactError):
        load_bundle(saved)


def _edit_manifest(directory, change):
    path = directory / MANIFEST_NAME
    manifest = json.loads(path.read_text())
    change(manifest)
    path.write_text(json.dumps(manifest))


def test_manifest_with_missing_entry_is_refused(saved):
    _edit_manifest(saved, lambda m: m["files"].pop(XGBOOST_NAME))
    with pytest.raises(ModelArtifactError, match="expected files"):
        load_bundle(saved)


@pytest.mark.parametrize("extra", ["../../etc/passwd", "/etc/passwd", "evil.skops"])
def test_manifest_with_extra_path_is_refused(saved, extra):
    _edit_manifest(saved, lambda m: m["files"].update({extra: {"sha256": "0"}}))
    with pytest.raises(ModelArtifactError, match="expected files"):
        load_bundle(saved)


def test_symlinked_artifact_is_refused(saved, tmp_path_factory):
    outside = tmp_path_factory.mktemp("o") / "x"
    outside.write_bytes((saved / RANDOM_FOREST_NAME).read_bytes())
    (saved / RANDOM_FOREST_NAME).unlink()
    os.symlink(outside, saved / RANDOM_FOREST_NAME)
    with pytest.raises(ModelArtifactError, match="regular file"):
        load_bundle(saved)


def test_symlinked_manifest_is_refused(saved, tmp_path_factory):
    outside = tmp_path_factory.mktemp("o") / "m"
    outside.write_bytes((saved / MANIFEST_NAME).read_bytes())
    (saved / MANIFEST_NAME).unlink()
    os.symlink(outside, saved / MANIFEST_NAME)
    with pytest.raises(ModelArtifactError, match="regular file"):
        load_bundle(saved)


def test_oversized_artifact_is_refused(saved, monkeypatch):
    monkeypatch.setattr(artifacts, "MAX_ARTIFACT_BYTES", 8)
    with pytest.raises(ModelArtifactError, match="too large"):
        load_bundle(saved)


def test_library_version_change_is_refused(saved):
    _edit_manifest(saved, lambda m: m["library_versions"].update({"numpy": "0.0"}))
    with pytest.raises(ModelArtifactError, match="Library versions"):
        load_bundle(saved)


class _NotTrusted:
    """A class defined here, which skops must report as untrusted."""


def test_untrusted_type_is_refused_even_with_a_valid_hash(saved, monkeypatch):
    built = []

    payload = sio.dumps(OrderedDict(a=_NotTrusted()))
    (saved / RANDOM_FOREST_NAME).write_bytes(payload)
    rewrite_manifest_hash(saved, RANDOM_FOREST_NAME)
    real_loads = sio.loads
    monkeypatch.setattr(sio, "loads", lambda *a, **k: built.append(1) or real_loads(*a, **k))
    with pytest.raises(ModelArtifactError, match="untrusted types"):
        load_bundle(saved)
    assert built == []


def test_wrong_trusted_model_type_is_refused(bundle, saved):
    (saved / RANDOM_FOREST_NAME).write_bytes(sio.dumps(bundle[0].isolation_forest))
    rewrite_manifest_hash(saved, RANDOM_FOREST_NAME)
    with pytest.raises(ModelArtifactError, match="is not a RandomForestClassifier"):
        load_bundle(saved)


@pytest.mark.parametrize("name", [RANDOM_FOREST_NAME, ISOLATION_FOREST_NAME, XGBOOST_NAME])
def test_malformed_model_with_valid_hash_is_refused(saved, name):
    (saved / name).write_bytes(b"not a model")
    rewrite_manifest_hash(saved, name)
    with pytest.raises(ModelArtifactError, match="could not be parsed"):
        load_bundle(saved)


@pytest.mark.parametrize("name", [PREPROCESSING_NAME, THRESHOLDS_NAME, METADATA_NAME])
def test_malformed_json_with_valid_hash_is_refused(saved, name):
    (saved / name).write_text("{bad")
    rewrite_manifest_hash(saved, name)
    with pytest.raises(ModelArtifactError, match="malformed"):
        load_bundle(saved)


def test_threshold_claiming_test_selection_is_refused(saved):
    document = json.loads((saved / THRESHOLDS_NAME).read_text())
    document["random_forest"]["selected_on"] = "test"
    (saved / THRESHOLDS_NAME).write_text(json.dumps(document))
    rewrite_manifest_hash(saved, THRESHOLDS_NAME)
    with pytest.raises(ModelArtifactError, match="malformed"):
        load_bundle(saved)


def test_changed_label_order_is_refused(saved):
    document = json.loads((saved / METADATA_NAME).read_text())
    document["label_order"].reverse()
    (saved / METADATA_NAME).write_text(json.dumps(document))
    rewrite_manifest_hash(saved, METADATA_NAME)
    with pytest.raises(ModelArtifactError, match="label order"):
        load_bundle(saved)


def test_column_width_mismatch_is_refused(saved):
    document = json.loads((saved / PREPROCESSING_NAME).read_text())
    document["columns"].append("extra")
    (saved / PREPROCESSING_NAME).write_text(json.dumps(document))
    rewrite_manifest_hash(saved, PREPROCESSING_NAME)
    with pytest.raises(ModelArtifactError, match="width"):
        load_bundle(saved)


def test_interrupted_save_cannot_verify(bundle, saved):
    (saved / MANIFEST_NAME).unlink()
    with pytest.raises(ModelArtifactError):
        read_verified(saved)


def test_save_replaces_a_previous_manifest(bundle, saved):
    before = (saved / MANIFEST_NAME).read_text()
    save_bundle(bundle[0], saved)
    assert json.loads((saved / MANIFEST_NAME).read_text())["format"] == json.loads(before)["format"]
    load_bundle(saved)


def test_trusted_list_is_explicit_and_minimal():
    assert TRUSTED_SKOPS_TYPES == ("sklearn.tree._tree.Tree",)


def test_source_never_uses_blanket_trust():
    """Every sio.loads call must pass the explicit list, never trusted=True."""
    tree = ast.parse(Path(artifacts.__file__).read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("load", "loads")
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "sio"
    ]
    assert len(calls) == 1
    trusted = next(k.value for k in calls[0].keywords if k.arg == "trusted")
    assert not isinstance(trusted, ast.Constant)

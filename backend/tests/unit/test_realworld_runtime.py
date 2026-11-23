"""Gated, digest-verified runtime loading of the real-world software model, and its fallback.

The model files here are trained on generated rows only to exercise the loader. Passing gate
numbers are written by the test, never claimed as a real evaluation.
"""

import json
import os
from pathlib import Path

import pytest

from app.core.config import Settings
from app.ml.realworld.dataset import assign_splits, with_splits
from app.ml.realworld.runtime import (
    EVALUATION_NAME,
    MIN_LABELLED_ROWS,
    MIN_TEST_ROWS_PER_CLASS,
    RealWorldUnavailable,
    evaluate_gates,
    load_realworld_software,
)
from app.ml.realworld.train_eval import Config, save_models, train
from app.risk import model_runtime, service
from app.risk.summary import REALWORLD_NOTE, SYNTHETIC_NOTE
from tests.unit.test_realworld_training import make_rows
from tests.unit.test_risk_explain import CONFIG, META, generate_records

PASSING = {
    "labelled_rows": MIN_LABELLED_ROWS,
    "test_class_counts": {"benign": MIN_TEST_ROWS_PER_CLASS, "known_vulnerable": 31},
    "test_f1": 0.70,
    "rules_only_test_f1": 0.60,
    "test_roc_auc_95ci": [0.55, 0.9],
}
META_RW = {
    "artifact_type": "software",
    "labels": ["benign", "known_vulnerable"],
    "synthetic": False,
    "dataset_version": "test",
}


@pytest.fixture(autouse=True)
def _clean_cache():
    model_runtime.clear_cache()
    yield
    model_runtime.clear_cache()


@pytest.fixture(scope="module")
def trained():
    rows = make_rows(40, 40)
    parts = with_splits(rows, assign_splits(rows, 42))
    return train(
        parts["train"],
        parts["validation"],
        Config(rf_estimators=10, xgb_estimators=10, iforest_estimators=20),
    )


def _bundle(trained, directory: Path, summary=PASSING, metadata=META_RW) -> Path:
    save_models(trained, directory, metadata, summary)
    return directory


def _rewrite_manifest(directory: Path, change) -> None:
    path = directory / "manifest.json"
    manifest = json.loads(path.read_text())
    change(manifest)
    path.write_text(json.dumps(manifest))


# --- gates ---------------------------------------------------------------------------------


def test_gates_pass_only_when_every_gate_passes():
    assert evaluate_gates(PASSING).passed


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"labelled_rows": MIN_LABELLED_ROWS - 1}, "labelled rows"),
        ({"labelled_rows": True}, "labelled rows"),
        ({"test_class_counts": {"benign": 29, "known_vulnerable": 40}}, "benign"),
        ({"test_class_counts": {"benign": 40}}, "known_vulnerable"),
        ({"test_f1": 0.59}, "rules-only baseline"),
        ({"test_f1": None}, "rules-only baseline"),
        ({"rules_only_test_f1": None}, "rules-only baseline"),
        ({"test_roc_auc_95ci": [0.5, 0.9]}, "not > 0.5"),
        ({"test_roc_auc_95ci": [0.0, 1.0]}, "not > 0.5"),
        ({"test_roc_auc_95ci": None}, "not > 0.5"),
        ({"test_roc_auc_95ci": ["0.9", 1.0]}, "not > 0.5"),
    ],
)
def test_each_gate_fails_closed(change, reason):
    result = evaluate_gates({**PASSING, **change})
    assert not result.passed
    assert any(reason in r for r in result.reasons)


def test_a_stored_passed_flag_is_ignored():
    assert not evaluate_gates({"passed": True}).passed
    assert not evaluate_gates(["not", "an", "object"]).passed


def test_the_current_real_world_report_does_not_pass_the_gates():
    """The committed real-world evaluation (44 rows) is far below the gates."""
    report_path = (
        Path(__file__).resolve().parents[3] / "ml/reports/realworld_evaluation_report.json"
    )
    if not report_path.exists():
        pytest.skip("no real-world report in this checkout")
    software = json.loads(report_path.read_text())["models"]["software"]
    summary = {
        "labelled_rows": sum(sum(c.values()) for c in software["split_counts"].values()),
        "test_class_counts": software["split_counts"]["test"],
        "test_f1": software["test"]["random_forest"]["f1"],
        "rules_only_test_f1": software["test"]["rules_only"]["f1"],
        "test_roc_auc_95ci": software["test"]["random_forest"]["bootstrap"]["roc_auc_95ci"],
    }
    assert not evaluate_gates(summary).passed


# --- verification --------------------------------------------------------------------------


def test_a_passing_bundle_loads(trained, tmp_path):
    bundle = load_realworld_software(_bundle(trained, tmp_path))
    assert bundle.metadata["synthetic"] is False
    assert list(bundle.random_forest.classes_) == [0, 1]
    assert bundle.thresholds.random_forest.value is not None


def test_failing_gates_refuse_before_any_model_file_is_parsed(trained, tmp_path, monkeypatch):
    _bundle(trained, tmp_path, summary={**PASSING, "labelled_rows": 44})
    import app.ml.artifacts as artifacts

    def boom(*_a, **_k):
        raise AssertionError("a model file was parsed before the gates passed")

    monkeypatch.setattr(artifacts, "_load_skops", boom)
    with pytest.raises(RealWorldUnavailable, match="quality gates not met"):
        load_realworld_software(tmp_path)


@pytest.mark.parametrize(
    "name",
    [
        "random_forest.skops",
        "preprocessing.json",
        "thresholds.json",
        EVALUATION_NAME,
        "training_metadata.json",
    ],
)
def test_a_changed_file_is_refused(trained, tmp_path, name):
    _bundle(trained, tmp_path)
    path = tmp_path / name
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(
        RealWorldUnavailable, match=f"SHA-256 mismatch for real-world model file {name}"
    ):
        load_realworld_software(tmp_path)


def test_raising_the_gate_numbers_without_updating_the_digest_is_refused(trained, tmp_path):
    _bundle(trained, tmp_path, summary={**PASSING, "labelled_rows": 44})
    (tmp_path / EVALUATION_NAME).write_text(json.dumps(PASSING))
    with pytest.raises(RealWorldUnavailable, match="SHA-256 mismatch"):
        load_realworld_software(tmp_path)


def test_missing_extra_and_symlinked_files_are_refused(trained, tmp_path):
    _bundle(trained, tmp_path)
    (tmp_path / "xgboost.json").unlink()
    with pytest.raises(RealWorldUnavailable, match="missing real-world model file"):
        load_realworld_software(tmp_path)

    other = tmp_path / "b"
    _bundle(trained, other)
    _rewrite_manifest(other, lambda m: m["files"].update({"extra.bin": {"sha256": "0" * 64}}))
    with pytest.raises(RealWorldUnavailable, match="expected files"):
        load_realworld_software(other)

    linked = tmp_path / "c"
    _bundle(trained, linked)
    target = linked / "thresholds.json"
    real = linked / "thresholds.real"
    target.rename(real)
    os.symlink(real, target)
    with pytest.raises(RealWorldUnavailable, match="not a regular file"):
        load_realworld_software(linked)


@pytest.mark.parametrize(
    "change",
    [
        lambda m: m.update({"format": "provenancex-models-v1"}),
        lambda m: m.update({"synthetic": True}),
        lambda m: m.pop("synthetic"),
        lambda m: m.update({"library_versions": {"scikit-learn": "0.0"}}),
    ],
)
def test_manifest_claims_are_checked(trained, tmp_path, change):
    _bundle(trained, tmp_path)
    _rewrite_manifest(tmp_path, change)
    with pytest.raises(RealWorldUnavailable):
        load_realworld_software(tmp_path)


@pytest.mark.parametrize(
    "metadata",
    [
        {**META_RW, "artifact_type": "model"},
        {**META_RW, "synthetic": True},
        {**META_RW, "labels": ["benign", "confirmed_malicious"]},
    ],
)
def test_only_a_real_benign_vs_vulnerable_software_model_is_accepted(trained, tmp_path, metadata):
    _bundle(trained, tmp_path, metadata=metadata)
    with pytest.raises(RealWorldUnavailable, match="not a benign/known_vulnerable software model"):
        load_realworld_software(tmp_path)


def test_a_bundle_from_before_the_gates_is_refused(trained, tmp_path):
    _bundle(trained, tmp_path)
    (tmp_path / EVALUATION_NAME).unlink()
    _rewrite_manifest(tmp_path, lambda m: m["files"].pop(EVALUATION_NAME))
    with pytest.raises(RealWorldUnavailable, match="expected files"):
        load_realworld_software(tmp_path)


# --- runtime selection and fallback --------------------------------------------------------


@pytest.fixture(scope="module")
def synthetic_dir(tmp_path_factory):
    from app.ml.artifacts import save_bundle
    from app.ml.training import train_models

    records = generate_records(60, 7)
    train_rows = [r for r in records if r.split == "train"]
    validation = [r for r in records if r.split == "validation"]
    directory = tmp_path_factory.mktemp("models")
    save_bundle(train_models(train_rows, validation, META, CONFIG), directory)
    return directory


def _models_root(tmp_path, synthetic_dir, trained, summary=PASSING) -> Path:
    import shutil

    root = tmp_path / "models"
    shutil.copytree(synthetic_dir, root)
    save_models(trained, root / "realworld" / "software", META_RW, summary)
    return root


def _settings(root: Path, enabled=True) -> Settings:
    return Settings(_env_file=None, model_path=root, realworld_models_enabled=enabled)


def test_software_uses_the_real_world_model_only_when_it_passes(tmp_path, synthetic_dir, trained):
    models, note = service._select_models(
        "software", _settings(_models_root(tmp_path, synthetic_dir, trained))
    )
    assert note is None
    assert models.model_version.startswith("realworld-sha256:")
    label = service._training_label(models, note)
    assert label["label"] == "real-world"
    assert "not malicious" in label["notice"]


def test_failing_gates_fall_back_to_the_synthetic_models_and_say_why(
    tmp_path, synthetic_dir, trained
):
    root = _models_root(tmp_path, synthetic_dir, trained, summary={**PASSING, "labelled_rows": 44})
    models, note = service._select_models("software", _settings(root))
    assert not models.model_version.startswith("realworld")
    assert "quality gates not met" in note
    label = service._training_label(models, note)
    assert label["label"] == "synthetic"
    assert "Real-world model not used: quality gates not met" in label["notice"]


def test_a_tampered_real_world_model_falls_back(tmp_path, synthetic_dir, trained):
    root = _models_root(tmp_path, synthetic_dir, trained)
    path = root / "realworld" / "software" / "random_forest.skops"
    path.write_bytes(path.read_bytes()[:-1])
    models, note = service._select_models("software", _settings(root))
    assert not models.model_version.startswith("realworld")
    assert "SHA-256 mismatch" in note


def test_tampering_after_a_successful_load_is_caught(tmp_path, synthetic_dir, trained):
    root = _models_root(tmp_path, synthetic_dir, trained)
    settings = _settings(root)
    assert service._select_models("software", settings)[0].model_version.startswith("realworld")
    rw = root / "realworld" / "software"
    _rewrite_manifest(rw, lambda m: m["files"]["thresholds.json"].update({"sha256": "0" * 64}))
    models, note = service._select_models("software", settings)
    assert not models.model_version.startswith("realworld")
    assert "SHA-256 mismatch" in note


def test_no_real_world_model_installed_falls_back(tmp_path, synthetic_dir):
    models, note = service._select_models("software", _settings(synthetic_dir))
    assert not models.model_version.startswith("realworld")
    assert "no real-world software model is installed" in note


@pytest.mark.parametrize("artifact_type", ["model", "lora", "dataset"])
def test_ai_artifacts_never_use_the_real_world_model(
    tmp_path, synthetic_dir, trained, artifact_type
):
    models, note = service._select_models(
        artifact_type, _settings(_models_root(tmp_path, synthetic_dir, trained))
    )
    assert not models.model_version.startswith("realworld")
    assert note is None


def test_the_setting_turns_it_off(tmp_path, synthetic_dir, trained):
    root = _models_root(tmp_path, synthetic_dir, trained)
    models, note = service._select_models("software", _settings(root, enabled=False))
    assert not models.model_version.startswith("realworld")
    assert note is None


def test_no_model_at_all_is_ml_unavailable(tmp_path):
    with pytest.raises(model_runtime.ModelUnavailable):
        service._select_models("software", _settings(tmp_path / "nothing"))


def test_summary_note_matches_the_model_used():
    from app.risk.summary import build_summary

    class _A:  # minimal stand-in: build_summary only reads these attributes
        evidence_status = []
        policy_version = "provenancex-policy-v2-handset"
        risk_score = 0.2
        decision = "REVIEW"
        decision_basis = "score_band"
        reasons = []
        confidence = 0.6
        confidence_label = "MEDIUM"
        layers = []
        contributions = []
        hard_rules_fired = []
        hard_rules_not_evaluated = []

    real = build_summary(_A(), None, {"label": "real-world"})
    synthetic = build_summary(_A(), None, {"label": "synthetic"})
    assert REALWORLD_NOTE in real.notes and SYNTHETIC_NOTE not in real.notes
    assert SYNTHETIC_NOTE in synthetic.notes and REALWORLD_NOTE not in synthetic.notes

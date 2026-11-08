"""Experiments: thresholds never see test data, layers and recipes really are removed."""

from dataclasses import replace

import pytest

from app.ml import ablation
from app.ml.ablation import (
    evaluate_split,
    partition,
    resplit,
    run_ablation,
    run_leave_one_recipe_out,
    summarize,
)
from app.ml.dataset.generator import generate_records
from app.ml.dataset.splits import find_family_leaks
from app.ml.dataset.tampering import TAMPERING_CASES
from app.ml.feature_schema import Label, Layer, features_in_layer
from app.ml.training import TrainingConfig

CONFIG = TrainingConfig(rf_estimators=10, xgb_estimators=5, iforest_estimators=10, n_jobs=1)
META = {"synthetic": True, "notice": "SYNTHETIC", "dataset_sha256": "abc"}
SEEDS = [7, 8]


@pytest.fixture(scope="module")
def records():
    return generate_records(60, 7)


def test_resplit_keeps_families_whole_and_leaves_originals_alone(records):
    before = [r.split for r in records]
    moved = resplit(records, 99)
    assert find_family_leaks((r.family_id, r.split) for r in moved) == {}
    assert [r.split for r in records] == before
    assert [r.split for r in moved] != before


def test_resplit_with_generation_seed_matches_original(records):
    assert [r.split for r in resplit(records, 7)] == [r.split for r in records]


def test_evaluate_split_reports_all_models_and_baselines(records):
    result = evaluate_split(records, 7, CONFIG, META)
    assert set(result["models"]) == {"random_forest", "xgboost", "isolation_forest"}
    assert set(result["baselines"]) == {"vulnerability_only", "rules_only"}
    assert result["test_records"] == sum(r.split == "test" for r in records)


def test_thresholds_do_not_depend_on_test_labels(records):
    """Changing every test label must change the scores but never the thresholds."""
    original = evaluate_split(records, 7, CONFIG, META)
    target = {r.record_id for r in partition(resplit(records, 7))["test"]}
    flipped = [
        r.model_copy(update={"label": Label.SUSPICIOUS}) if r.record_id in target else r
        for r in records
    ]
    changed = evaluate_split(flipped, 7, CONFIG, META)
    assert changed["thresholds"] == original["thresholds"]
    assert (
        changed["models"]["random_forest"]["binary"]
        != original["models"]["random_forest"]["binary"]
    )


def test_summarize_mean_and_spread():
    result = summarize([{"a": {"b": 1.0}}, {"a": {"b": 3.0}}])
    assert result["a"]["b"]["mean"] == 2.0
    assert result["a"]["b"]["min"] == 1.0
    assert result["a"]["b"]["max"] == 3.0
    assert result["a"]["b"]["n"] == 2
    assert result["a"]["b"]["std"] == pytest.approx(2**0.5)


def test_summarize_skips_undefined_and_reports_n():
    result = summarize([{"a": None}, {"a": 2.0}])
    assert result["a"]["n"] == 1
    assert summarize([{"a": None}, {"a": None}])["a"] is None


def test_summarize_ignores_text():
    assert summarize([{"a": "x"}, {"a": "x"}])["a"] is None


def _capture_fits(monkeypatch):
    calls = []
    real = ablation._forest_fit

    def spy(train, validation, cfg, names):
        calls.append({"train": train, "validation": validation, "names": list(names)})
        return real(train, validation, cfg, names)

    monkeypatch.setattr(ablation, "_forest_fit", spy)
    return calls


def test_ablation_covers_every_layer_and_removes_its_features(records, monkeypatch):
    calls = _capture_fits(monkeypatch)
    result = run_ablation(records, SEEDS, CONFIG)
    assert set(result["removed"]) == {str(layer) for layer in Layer}
    assert len(calls) == len(SEEDS) * (len(Layer) + 1)
    for layer, call in zip(Layer, calls[1 : len(Layer) + 1], strict=True):
        assert not set(features_in_layer(layer)) & set(call["names"])


def test_ablation_reports_change_from_all_layers(records):
    result = run_ablation(records, SEEDS[:1], CONFIG)
    entry = result["removed"]["vulnerability"]
    full = result["all_layers"]["binary"]["f1"]["mean"]
    assert entry["change_from_all_layers"]["binary"]["f1"]["mean"] == pytest.approx(
        entry["metrics"]["binary"]["f1"]["mean"] - full
    )


def test_leave_one_recipe_out_removes_recipe_from_train_and_validation(records, monkeypatch):
    calls = _capture_fits(monkeypatch)
    result = run_leave_one_recipe_out(records, SEEDS[:1], CONFIG)
    assert set(result["recipes"]) == set(TAMPERING_CASES)
    recipe_calls = calls[1:]
    assert len(recipe_calls) == sum(1 for e in result["recipes"].values() if e["runs"])
    used = [name for name, entry in result["recipes"].items() if entry["runs"]]
    for name, call in zip(used, recipe_calls, strict=True):
        assert all(name not in r.applied_recipes for r in call["train"])
        assert all(name not in r.applied_recipes for r in call["validation"])


def test_leave_one_recipe_out_never_fits_on_test(records, monkeypatch):
    calls = _capture_fits(monkeypatch)
    run_leave_one_recipe_out(records, SEEDS[:1], CONFIG)
    for call in calls:
        assert {r.split for r in call["train"]} == {"train"}
        assert {r.split for r in call["validation"]} == {"validation"}


def test_seen_and_unseen_scores_use_the_same_records(records):
    result = run_leave_one_recipe_out(records, SEEDS[:1], CONFIG)
    entry = next(e for e in result["recipes"].values() if e["runs"])
    held = entry["summary"]["held_out_of_training"]["all"]
    seen = entry["summary"]["seen_in_training"]["all"]
    assert held["records"]["mean"] == seen["records"]["mean"]
    assert held["support"]["mean"] == seen["support"]["mean"]


def test_experiments_keep_fixed_hyperparameters(records, monkeypatch):
    seen = []
    real = ablation.fit_forest

    def spy(matrix, labels, cfg):
        seen.append(cfg)
        return real(matrix, labels, cfg)

    monkeypatch.setattr(ablation, "fit_forest", spy)
    run_ablation(records, SEEDS[:1], CONFIG)
    assert all(cfg == replace(CONFIG, seed=SEEDS[0]) for cfg in seen)

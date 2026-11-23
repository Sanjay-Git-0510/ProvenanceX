"""Phase 3: real-world row loading, family splits, sufficiency, training and evaluation.

The rows here are constructed test inputs (not collected data) that only exercise the code.
"""

import json

import numpy as np
import pytest

from app.ml.feature_schema import FEATURE_NAMES, NOT_EVALUATED_FEATURES
from app.ml.realworld.dataset import (
    FEATURE_ROWS_FORMAT,
    InsufficientData,
    RealRow,
    assign_splits,
    load_rows,
    sufficiency,
    with_splits,
)
from app.ml.realworld.manifest import DATASET_VERSION, GroundTruth, RealLabel, write_manifest
from app.ml.realworld.report import render_model_card, render_report
from app.ml.realworld.train_eval import (
    Config,
    evaluate_split,
    rules_only_scores,
    save_models,
    train,
)
from tests.realworld_helpers import record


def features(vulnerable_count=0, deps=10):
    out = {name: None for name in FEATURE_NAMES}
    out.update(dependency_count=deps, vulnerable_count=vulnerable_count, script_presence=False)
    return out


def reasons(feats):
    return {
        name: "no_prior_scan" if name == "hash_changed" else "stage_not_run"
        for name, value in feats.items()
        if value is None
    }


def make_rows(n_benign, n_vuln, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n_benign + n_vuln):
        vuln = i >= n_benign
        f = features(int(rng.integers(1, 4)) if vuln else 0, int(rng.integers(5, 50)))
        rows.append(
            RealRow(
                record_id=f"rw-{i:03d}",
                family_id=f"github:o/r{i}",
                artifact_type="software",
                label=RealLabel.KNOWN_VULNERABLE if vuln else RealLabel.BENIGN,
                features=f,
                null_reasons=reasons(f),
                sha256=f"{i:064x}",
                scan_id=f"s{i}",
            )
        )
    return rows


# --- loading ---------------------------------------------------------------------------------


def write_inputs(tmp_path, feature_rows):
    recs = [
        record(),
        record(
            artifact_identifier="github.com/o/vuln",
            record_id="rw-vuln",
            family_id="github:o/vuln",
            label=RealLabel.KNOWN_VULNERABLE,
            ground_truth_status=GroundTruth.ESTABLISHED,
        ),
        record(
            artifact_identifier="github.com/o/unk",
            record_id="rw-unk",
            family_id="github:o/unk",
            label=RealLabel.UNKNOWN,
            ground_truth_status=GroundTruth.NONE,
            scan_eligible=False,
        ),
    ]
    write_manifest(recs, tmp_path, {})
    manifest = tmp_path / f"manifest-{DATASET_VERSION}.jsonl"
    feats = tmp_path / "features.jsonl"
    feats.write_text("".join(json.dumps(r) + "\n" for r in feature_rows))
    return manifest, feats, recs


def frow(rec, **over):
    f = features(1 if rec.label == RealLabel.KNOWN_VULNERABLE else 0)
    row = {
        "format": FEATURE_ROWS_FORMAT,
        "dataset_version": DATASET_VERSION,
        "record_id": rec.record_id,
        "family_id": rec.family_id,
        "label": str(rec.label),
        "usable_for_training": True,
        "scan_status": "completed",
        "features": f,
        "null_reasons": reasons(f),
        "sha256": rec.record_id.ljust(64, "0")[:64],
        "scan_id": "s",
    }
    row.update(over)
    return row


def test_load_rows_keeps_only_usable_trainable_valid_rows(tmp_path):
    _, _, recs = write_inputs(tmp_path, [])
    benign, vuln, unk = recs
    bad_features = features()
    bad_features[NOT_EVALUATED_FEATURES[0]] = 1.0  # a no-data-source feature with a value
    rows = [
        frow(benign),
        frow(vuln),
        frow(unk),
        frow(vuln, record_id="rw-missing"),
        frow(benign, usable_for_training=False, scan_status="failed"),
        frow(benign, format="provenancex-feature-dataset-v1"),  # the synthetic format
        frow(vuln, features=bad_features),
        frow(vuln, label="benign"),
    ]
    manifest, feats, _ = write_inputs(tmp_path, rows)
    result = load_rows(manifest, feats)
    assert sorted(r.record_id for r in result.rows) == sorted([benign.record_id, "rw-vuln"])
    assert result.excluded["label_not_trainable:unknown"] == 1
    assert result.excluded["not_in_manifest"] == 1
    assert result.excluded["not_usable:failed"] == 1
    assert result.excluded["wrong_format_or_version"] == 1
    assert result.excluded["invalid_feature_vector"] == 1
    assert result.excluded["label_or_family_mismatch"] == 1


def test_duplicate_content_is_dropped(tmp_path):
    _, _, recs = write_inputs(tmp_path, [])
    benign, vuln, _ = recs
    manifest, feats, _ = write_inputs(
        tmp_path, [frow(benign, sha256="f" * 64), frow(vuln, sha256="f" * 64)]
    )
    result = load_rows(manifest, feats)
    assert len(result.rows) == 1 and result.excluded["duplicate_content_sha256"] == 1


# --- sufficiency and splits --------------------------------------------------------------------


def test_sufficiency_reports_gaps():
    s = sufficiency(make_rows(10, 40))
    assert s["software"]["sufficient"] is False and "benign" in s["software"]["reason"]
    assert s["model"]["rows"] == 0 and s["model"]["sufficient"] is False
    assert sufficiency(make_rows(20, 40))["software"]["sufficient"] is True


def test_family_split_has_no_leak_and_is_stratified():
    rows = make_rows(20, 40)
    rows[1].family_id = rows[0].family_id  # two revisions of one repository
    split_of = assign_splits(rows, 42)
    assert split_of[rows[0].record_id] == split_of[rows[1].record_id]
    parts = with_splits(rows, split_of)
    for split in parts.values():
        assert {r.target for r in split} == {0, 1}
    assert split_of == assign_splits(rows, 42)  # deterministic


def test_split_refuses_too_few_per_class():
    with pytest.raises(InsufficientData):
        assign_splits(make_rows(4, 40), 42)


# --- training and evaluation -------------------------------------------------------------------


def test_train_evaluate_and_save(tmp_path):
    rows = make_rows(25, 50)
    parts = with_splits(rows, assign_splits(rows, 42))
    cfg = Config(
        rf_estimators=20,
        xgb_estimators=20,
        iforest_estimators=20,
        repeated_seeds=2,
        bootstrap_resamples=20,
    )
    models = train(parts["train"], parts["validation"], cfg)
    assert {t.selected_on for t in models.thresholds.values()} == {"validation"}
    result = evaluate_split(models, parts["test"], cfg, bootstrap=True)
    for name in (
        "random_forest",
        "xgboost",
        "isolation_forest",
        "rules_only",
        "vulnerability_only",
    ):
        assert result[name]["records"] == len(parts["test"])
        assert result[name]["no_prior_scan"]["benign_rows"] == sum(
            1 for r in parts["test"] if r.target == 0
        )
    rf = result["random_forest"]
    assert "brier" in rf["calibration"] and rf["threshold_analysis"]
    assert rf["bootstrap"]["resamples"] == 20
    manifest = save_models(models, tmp_path / "m", {"synthetic": False}, {})
    assert manifest["synthetic"] is False
    assert set(manifest["files"]) == {
        "preprocessing.json",
        "random_forest.skops",
        "isolation_forest.skops",
        "xgboost.json",
        "thresholds.json",
        "training_metadata.json",
        "evaluation_summary.json",
    }


def test_preprocessing_refuses_non_train_rows():
    rows = make_rows(20, 40)
    parts = with_splits(rows, assign_splits(rows, 42))
    with pytest.raises(ValueError, match="train split"):
        train(parts["validation"], parts["validation"], Config(rf_estimators=5))


def test_rules_only_counts_fired_rules_and_unevaluable_rows():
    rows = make_rows(1, 1)
    rows[0].features = {name: None for name in FEATURE_NAMES}
    fired, evaluated = rules_only_scores(rows)
    assert list(evaluated) == [False, True]
    assert fired[1] >= 1  # vulnerable_count > 0 fires


def test_reports_render_without_models():
    results = {
        "manifest_sha256": "x",
        "dataset_version": DATASET_VERSION,
        "feature_rows_read": 0,
        "usable_rows": 0,
        "excluded": {},
        "scan_outcomes": {},
        "sufficiency": sufficiency([]),
        "models": {},
        "evidence_gaps": ["gap one"],
    }
    assert "gap one" in render_report(results)
    assert "no model was trained" in render_model_card(results)


def test_model_card_states_runtime_gate_result():
    model = {
        "test": {
            "random_forest": {"f1": 0.9, "roc_auc": 0.6, "fpr": 1.0, "records": 29},
            "rules_only": {"f1": 0.9, "fpr": 1.0},
        },
        "runtime_gates": {"passed": False, "reasons": ["labelled rows 147 < 150"]},
    }
    card = render_model_card({"models": {"software": model}, "evidence_gaps": []})
    assert "not wired in" not in card
    assert "software runtime quality gates: fail, not loaded: labelled rows 147 < 150." in card
    model["runtime_gates"] = {"passed": True, "reasons": []}
    card = render_model_card({"models": {"software": model}, "evidence_gaps": []})
    assert "software runtime quality gates: pass, loaded." in card

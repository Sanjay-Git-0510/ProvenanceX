"""The report: warning first, required statements present, numbers only from the result."""

import copy
import json

import pytest

from app.ml.ablation import (
    evaluate_split,
    run_ablation,
    run_leave_one_recipe_out,
    summarize,
)
from app.ml.baselines import evaluate_baselines
from app.ml.dataset.generator import dataset_metadata, generate_records
from app.ml.evaluation import flag_everything_reference
from app.ml.feature_schema import NOT_EVALUATED_FEATURES
from app.ml.reporting import (
    SYNTHETIC_WARNING,
    build_report,
    render_markdown,
    thresholds_match,
    vulnerable_label_stats,
    write_report,
)
from app.ml.training import TrainingConfig
from tests.ml_helpers import record

CONFIG = TrainingConfig(rf_estimators=10, xgb_estimators=5, iforest_estimators=10, n_jobs=1)
SEEDS = [7, 8]


@pytest.fixture(scope="module")
def report():
    records = generate_records(60, 7)
    metadata = dataset_metadata(records, 7, "abc")
    runs = [evaluate_split(records, seed, CONFIG, metadata) for seed in SEEDS]
    test = [r for r in records if r.split == "test"]
    primary = {
        "test_records": len(test),
        "thresholds": runs[0]["thresholds"],
        "models": runs[0]["models"],
        "baselines": evaluate_baselines(test),
        "reference_flag_everything": flag_everything_reference(test),
        "random_forest_benign_flag_rate_by_hash_comparison": {
            "comparison_available": {"records": 4, "flagged": 1, "rate": 0.25},
            "comparison_missing": {"records": 0, "flagged": 0, "rate": None},
        },
    }
    return build_report(
        dataset_metadata=metadata,
        model_metadata={"dataset_sha256": "abc", "training_config": {}},
        manifest={"python_version": "3", "library_versions": {}},
        primary=primary,
        repeated_runs=runs,
        repeated_summary=summarize(
            [{"models": r["models"], "baselines": r["baselines"]} for r in runs]
        ),
        ablation=run_ablation(records, SEEDS, CONFIG),
        leave_one_recipe_out=run_leave_one_recipe_out(records, SEEDS, CONFIG),
        vulnerable_stats=vulnerable_label_stats(records),
        primary_thresholds_reproduced=True,
    )


def test_report_starts_with_the_synthetic_warning(report):
    lines = render_markdown(report).splitlines()
    assert lines[0] == "# ProvenanceX evaluation report"
    assert lines[2] == f"> **WARNING: {SYNTHETIC_WARNING}**"
    assert "Labels are true by construction" in lines[4]
    assert report["synthetic"] is True


def test_report_states_the_vulnerable_label_relationship(report):
    text = render_markdown(report)
    assert "vulnerable_count nearly determines the vulnerable label" in text
    assert "the rules baseline is expected to do well on that class" in text
    assert "Measured baseline results on the vulnerable class" in text


def test_report_lists_not_evaluated_features(report):
    text = render_markdown(report)
    assert "## Features not evaluated" in text
    for name in NOT_EVALUATED_FEATURES:
        assert f"- `{name}`" in text


@pytest.mark.parametrize(
    "heading",
    [
        "## Primary test results",
        "## Baselines on the primary test split",
        "## Repeated family splits",
        "## Layer ablation",
        "## Leave-one-recipe-out",
        "## Threshold policy",
    ],
)
def test_report_has_every_section(report, heading):
    assert heading in render_markdown(report)


def test_report_shows_baseline_coverage_and_reference(report):
    text = render_markdown(report)
    assert "Could not evaluate" in text
    assert "Reference: flag every record" in text


def test_markdown_numbers_come_from_the_result(report):
    changed = copy.deepcopy(report)
    changed["primary_test_results"]["models"]["random_forest"]["binary"]["f1"] = 0.123456
    assert "0.123" in render_markdown(changed)
    assert render_markdown(changed) != render_markdown(report)


def test_false_positive_split_is_rendered(report):
    text = render_markdown(report)
    assert "False positives by hash comparison".lower() in text.lower()
    assert "| Hash comparison available | 4 | 1 | 0.250 |" in text
    assert "| Hash comparison missing | 0 | 0 | n/a |" in text


def test_rendering_is_deterministic(report):
    assert render_markdown(report) == render_markdown(copy.deepcopy(report))


def test_undefined_metric_renders_as_na(report):
    changed = copy.deepcopy(report)
    changed["primary_test_results"]["models"]["random_forest"]["binary"]["precision"] = None
    assert "n/a" in render_markdown(changed)


def test_non_synthetic_dataset_is_refused(report):
    with pytest.raises(ValueError, match="synthetic"):
        build_report(
            dataset_metadata={"synthetic": False},
            model_metadata={},
            manifest={},
            primary={},
            repeated_runs=[],
            repeated_summary={},
            ablation={},
            leave_one_recipe_out={},
            vulnerable_stats={},
            primary_thresholds_reproduced=True,
        )


def test_write_report_creates_matching_files(report, tmp_path):
    write_report(report, tmp_path)
    saved = json.loads((tmp_path / "evaluation_report.json").read_text())
    assert saved["synthetic"] is True
    assert (tmp_path / "evaluation_report.md").read_text() == render_markdown(saved)


def _thresholds(value):
    return {"random_forest": {"value": value, "criterion": "c"}}


def test_thresholds_match_ignores_rounding_noise():
    assert thresholds_match(_thresholds(0.44882948122306243), _thresholds(0.4488294812230625))


def test_thresholds_match_detects_real_differences():
    assert not thresholds_match(_thresholds(0.4), _thresholds(0.41))
    assert not thresholds_match(_thresholds(0.4), {"xgboost": {"value": 0.4, "criterion": "c"}})
    other = {"random_forest": {"value": 0.4, "criterion": "d"}}
    assert not thresholds_match(_thresholds(0.4), other)


def test_vulnerable_stats_measure_both_directions():
    rows = [
        record(label="vulnerable", vulnerable_count=1),
        record(label="suspicious", vulnerable_count=2),
        record(label="benign", vulnerable_count=0),
        record(label="vulnerable"),
    ]
    stats = vulnerable_label_stats(rows)
    assert stats["records_with_vulnerable_count"] == 3
    assert stats["vulnerable_label_with_count_above_zero"] == 1
    assert stats["share_of_vulnerable_label_with_count_above_zero"] == 1.0
    assert stats["records_with_count_above_zero"] == 2
    assert stats["count_above_zero_with_a_more_severe_label"] == 1
    assert stats["share_of_count_above_zero_labeled_vulnerable"] == 0.5


def test_vulnerable_stats_handle_no_records():
    stats = vulnerable_label_stats([])
    assert stats["share_of_vulnerable_label_with_count_above_zero"] is None
    assert stats["share_of_count_above_zero_labeled_vulnerable"] is None

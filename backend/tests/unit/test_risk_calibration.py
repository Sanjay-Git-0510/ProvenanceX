"""Policy calibration analysis: sufficiency rule, rates and that the policy is never changed."""

import pytest

from app.risk import calibration
from app.risk.calibration import (
    MIN_REAL_ROWS,
    MIN_ROWS_PER_CLASS,
    render_markdown,
    run_calibration,
    sufficiency,
)
from app.risk.policy_config import DEFAULT_POLICY, POLICY_VERSION
from app.risk.types import RiskInputs
from tests.unit.test_realworld_training import make_rows


def _inputs(rows):
    return [
        RiskInputs(artifact_type="software", features=r.features, null_reasons=r.null_reasons)
        for r in rows
    ]


def test_sufficiency_needs_rows_per_class_and_block_ground_truth():
    s = sufficiency({"benign": 24, "known_vulnerable": 27})
    assert not s["review_calibration_allowed"] and not s["block_calibration_allowed"]
    assert "249 more labelled real rows" in s["missing_for_review"][0]
    enough = {"benign": MIN_ROWS_PER_CLASS + 50, "known_vulnerable": MIN_REAL_ROWS}
    s = sufficiency(enough)
    assert s["review_calibration_allowed"]
    assert not s["block_calibration_allowed"]
    assert any("confirmed_malicious or tampered" in m for m in s["missing_for_block"])
    assert sufficiency({**enough, "confirmed_malicious": 5})["block_calibration_allowed"]


def test_one_class_short_blocks_calibration():
    s = sufficiency({"benign": 99, "known_vulnerable": 400})
    assert not s["review_calibration_allowed"]
    assert any("1 more benign" in m for m in s["missing_for_review"])


def test_rates_match_the_decisions():
    rows = make_rows(10, 10)
    result = run_calibration(_inputs(rows), [str(r.label) for r in rows], resamples=50)
    cur = result["current_policy"]
    benign = cur["decisions_by_label"].get("benign", {})
    flagged_benign = benign.get("REVIEW", 0) + benign.get("BLOCK", 0)
    assert cur["fp"] == flagged_benign and cur["fp"] + cur["tn"] == 10
    assert cur["fpr"] == flagged_benign / 10
    assert result["policy_version"] == POLICY_VERSION
    assert len(result["review_threshold_sweep"]) == len(calibration.REVIEW_SWEEP)
    fprs = [r["fpr"] for r in result["review_threshold_sweep"]]
    assert fprs == sorted(fprs, reverse=True)  # a higher threshold never flags more benign rows


def test_the_policy_object_is_not_changed():
    before = (
        DEFAULT_POLICY.review_threshold,
        DEFAULT_POLICY.block_threshold,
        dict(DEFAULT_POLICY.weights),
    )
    rows = make_rows(5, 5)
    run_calibration(_inputs(rows), [str(r.label) for r in rows], resamples=10)
    assert before == (
        DEFAULT_POLICY.review_threshold,
        DEFAULT_POLICY.block_threshold,
        dict(DEFAULT_POLICY.weights),
    )


def test_malicious_or_unknown_labels_are_refused():
    rows = make_rows(2, 2)
    with pytest.raises(ValueError, match="Only benign and known_vulnerable"):
        run_calibration(_inputs(rows), ["benign", "benign", "unknown", "confirmed_malicious"])
    with pytest.raises(ValueError):
        run_calibration([], [])


def test_report_keeps_synthetic_separate_and_states_hand_set():
    rows = make_rows(5, 5)
    result = run_calibration(_inputs(rows), [str(r.label) for r in rows], resamples=10)
    result["scan_eligible_in_manifest"] = 152
    text = render_markdown(result, {"records": 348, "baseline_decisions": {"ALLOW": 95}})
    assert "ANALYSIS ONLY. The policy was not changed" in text
    assert "stays hand-set and uncalibrated" in text
    assert "only 152 scan-eligible rows" in text
    real, synthetic = text.split("## Synthetic sensitivity analysis (separate, SYNTHETIC DATA)")
    assert "348" in synthetic and "348" not in real
    assert "Vulnerable is not malicious" in real

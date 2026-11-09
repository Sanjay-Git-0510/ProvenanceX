"""Fusion: traceable, bounded, and missing evidence is left out rather than averaged as 0."""

import pytest

from app.risk.fusion import confidence, confidence_label, fuse
from app.risk.layers import build_layers
from app.risk.policy_config import DEFAULT_POLICY, RiskLayer
from app.risk.types import ConfidenceLabel
from tests.risk_helpers import make_inputs, ml_outputs

BAD = {"install_hook_count": 1, "provenance_removed": True, "vulnerable_count": 2, "cvss_max": 7.5}


def fused(inputs, policy=DEFAULT_POLICY):
    return fuse(build_layers(inputs, policy), policy)


def layers(inputs):
    return build_layers(inputs, DEFAULT_POLICY)


@pytest.mark.parametrize(
    "inputs",
    [
        make_inputs(),
        make_inputs(**BAD),
        make_inputs(ml=ml_outputs(0.99, 0.9), **BAD),
        make_inputs(ml=ml_outputs(1.0, 1.0)),
        make_inputs(ml=ml_outputs(0.0, 0.0), **BAD),
        make_inputs(drop_layers=[RiskLayer.BEHAVIORAL], ml=ml_outputs(), **BAD),
    ],
)
def test_contributions_add_up_to_the_score_within_bounds(inputs):
    result = fused(inputs)
    total = sum(c.contribution for c in result.contributions) + result.ml_band_adjustment
    assert total == pytest.approx(result.risk_score, abs=1e-12)
    assert 0.0 <= result.risk_score <= 1.0


def test_missing_layer_does_not_dilute_the_score():
    complete = fused(make_inputs(install_hook_count=1))
    missing = fused(make_inputs(install_hook_count=1, drop_layers=[RiskLayer.BEHAVIORAL]))
    assert missing.risk_score > complete.risk_score


def test_no_rule_layer_means_no_score_rather_than_zero():
    result = fused(make_inputs(drop_layers=list(RiskLayer), ml=ml_outputs()))
    assert result.risk_score is None
    assert result.contributions == []


def test_highest_rule_layer_is_marked():
    result = fused(make_inputs(install_hook_count=1))
    top = [c for c in result.contributions if c.highest_rule_layer]
    assert [c.layer for c in top] == [RiskLayer.STATIC]


def test_ml_stays_out_of_the_highest_layer_term():
    result = fused(make_inputs(ml=ml_outputs(1.0, 1.0)))
    assert all(
        c.layer not in (RiskLayer.ML_SUPERVISED, RiskLayer.ML_ANOMALY)
        for c in result.contributions
        if c.highest_rule_layer
    )


def test_high_ml_cannot_leave_the_allow_band():
    result = fused(make_inputs(ml=ml_outputs(1.0, 1.0)))
    assert result.rule_only_score == 0.0
    assert result.risk_score < DEFAULT_POLICY.review_threshold


def test_low_ml_cannot_pull_a_score_below_its_band():
    plain = fused(make_inputs(archive_anomaly=1))
    assert plain.risk_score >= DEFAULT_POLICY.review_threshold
    result = fused(make_inputs(archive_anomaly=1, ml=ml_outputs(0.0, 0.0)))
    assert result.risk_score >= DEFAULT_POLICY.review_threshold


def test_ml_band_adjustment_is_recorded_when_the_limit_applies():
    # An oversized ML weight dilutes the mean below REVIEW, so the band limit must lift it back.
    heavy_ml = DEFAULT_POLICY.with_scaled_weight(RiskLayer.ML_SUPERVISED, 20)
    result = fused(make_inputs(archive_anomaly=1, ml=ml_outputs(0.0, 0.0)), heavy_ml)
    assert result.ml_band_adjustment > 0
    assert result.risk_score == pytest.approx(DEFAULT_POLICY.review_threshold)


def test_full_evidence_has_full_confidence():
    assert confidence(layers(make_inputs())) == pytest.approx(1.0)


def test_each_missing_layer_lowers_confidence():
    full = confidence(layers(make_inputs()))
    assert confidence(layers(make_inputs(drop_layers=[RiskLayer.BEHAVIORAL]))) < full


def test_partial_stage_gives_less_confidence_than_complete():
    from app.ml.feature_schema import NullReason

    partial = make_inputs(drop_layers=[RiskLayer.BEHAVIORAL], drop_reason=NullReason.STAGE_PARTIAL)
    skipped = make_inputs(drop_layers=[RiskLayer.BEHAVIORAL])
    full = make_inputs()
    assert confidence(layers(skipped)) < confidence(layers(partial)) < confidence(layers(full))


def test_ml_adds_no_confidence():
    without = confidence(layers(make_inputs(drop_layers=[RiskLayer.STATIC])))
    with_ml = confidence(layers(make_inputs(drop_layers=[RiskLayer.STATIC], ml=ml_outputs())))
    assert with_ml == without


def test_not_applicable_layers_do_not_lower_confidence():
    assert confidence(layers(make_inputs("software"))) == pytest.approx(1.0)


@pytest.mark.parametrize(
    ("value", "label"),
    [
        (0.1, ConfidenceLabel.LOW),
        (0.4, ConfidenceLabel.MEDIUM),
        (0.74, ConfidenceLabel.MEDIUM),
        (0.75, ConfidenceLabel.HIGH),
    ],
)
def test_confidence_labels(value, label):
    assert confidence_label(value, DEFAULT_POLICY) == label

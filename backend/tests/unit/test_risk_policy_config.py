"""The policy module holds the parameters, and rejects inconsistent ones."""

from dataclasses import replace

import pytest

import app.risk.policy_config as config
from app.ml.feature_schema import FEATURE_NAMES
from app.risk.policy_config import DEFAULT_POLICY, FEATURE_LAYERS, PolicyConfig, RiskLayer


def test_docstring_states_parameters_are_hand_set_and_not_validated():
    doc = " ".join(config.__doc__.split())
    assert "HAND-SET RESEARCH PARAMETERS" in doc
    assert "have not been tuned or validated" in doc
    assert "ML alone cannot change the decision" in doc


def test_every_feature_belongs_to_a_layer():
    assert set(FEATURE_LAYERS) == set(FEATURE_NAMES)


def test_signals_and_rules_reference_known_features():
    assert {s.feature for s in DEFAULT_POLICY.signals} <= set(FEATURE_NAMES)
    for rule in DEFAULT_POLICY.hard_rules:
        for predicate in rule.predicates:
            assert predicate.feature is None or predicate.feature in FEATURE_NAMES


def test_isolation_forest_has_the_smallest_weight():
    weights = DEFAULT_POLICY.weights
    assert weights[RiskLayer.ML_ANOMALY] == min(weights.values())


def test_scaled_weight_changes_only_that_weight():
    scaled = DEFAULT_POLICY.with_scaled_weight(RiskLayer.STATIC, 1.2)
    assert scaled.weights[RiskLayer.STATIC] == pytest.approx(0.24)
    assert scaled.weights[RiskLayer.GRAPH] == DEFAULT_POLICY.weights[RiskLayer.GRAPH]
    assert DEFAULT_POLICY.weights[RiskLayer.STATIC] == pytest.approx(0.20)


@pytest.mark.parametrize(
    "change",
    [
        {"review_threshold": 0.8},
        {"block_threshold": 1.5},
        {"max_blend": 1.5},
        {"min_allow_confidence": -0.1},
        {"partial_credit": 2.0},
        {"medium_confidence": 0.9},
        {"weights": {RiskLayer.STATIC: 1.0}},
        {"weights": {**DEFAULT_POLICY.weights, RiskLayer.STATIC: 0.0}},
        {"weights": {**DEFAULT_POLICY.weights, RiskLayer.ML_ANOMALY: -0.1}},
    ],
)
def test_invalid_parameters_are_refused(change):
    with pytest.raises(ValueError):
        replace(PolicyConfig(), **change)

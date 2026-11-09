"""Decisions: hard rules, evidence gates, justified ALLOWs and ML's limited role."""

import itertools
from dataclasses import replace

import pytest
from pydantic import ValidationError

from app.ml.feature_schema import NullReason
from app.risk.policy import assess_risk
from app.risk.policy_config import DEFAULT_POLICY, ML_UNAVAILABLE_MESSAGE, RiskLayer
from app.risk.types import LayerStatus, RiskAssessment
from tests.risk_helpers import finding, make_inputs, ml_outputs

SANDBOX_OFF = {"drop_layers": [RiskLayer.BEHAVIORAL]}


def fired(result):
    return {rule.rule_id for rule in result.hard_rules_fired}


def test_clean_complete_scan_is_allowed_with_its_reason():
    result = assess_risk(make_inputs())
    assert result.decision == "ALLOW"
    assert result.allow_reason
    assert result.not_evaluated_layers == [RiskLayer.ML_SUPERVISED, RiskLayer.ML_ANOMALY]


def test_sandbox_off_allow_states_layers_and_confidence():
    result = assess_risk(make_inputs(**SANDBOX_OFF))
    assert result.decision == "ALLOW"
    assert result.confidence >= 0.60
    assert RiskLayer.BEHAVIORAL in result.not_evaluated_layers
    assert "behavioral" in result.allow_reason
    assert f"{result.confidence:.2f}" in result.allow_reason


def test_sandbox_off_below_minimum_confidence_is_review():
    strict = replace(DEFAULT_POLICY, min_allow_confidence=0.95)
    result = assess_risk(make_inputs(**SANDBOX_OFF), strict)
    assert result.decision == "REVIEW"
    assert result.decision_basis == "insufficient_evidence"
    assert result.allow_reason is None


def test_allow_at_exactly_the_minimum_confidence():
    value = assess_risk(make_inputs(**SANDBOX_OFF)).confidence
    result = assess_risk(
        make_inputs(**SANDBOX_OFF), replace(DEFAULT_POLICY, min_allow_confidence=value)
    )
    assert result.decision == "ALLOW"


def test_an_allow_without_a_reason_cannot_be_built():
    data = assess_risk(make_inputs()).model_dump()
    data["allow_reason"] = None
    with pytest.raises(ValidationError):
        RiskAssessment.model_validate(data)


@pytest.mark.parametrize("layer", [RiskLayer.VULNERABILITY, RiskLayer.PROVENANCE, RiskLayer.STATIC])
def test_software_required_layer_missing_prevents_allow(layer):
    result = assess_risk(make_inputs(drop_layers=[layer]))
    assert result.decision == "REVIEW"
    assert str(layer) in " ".join(result.reasons)


@pytest.mark.parametrize("layer", [RiskLayer.PROVENANCE, RiskLayer.STATIC, RiskLayer.AI_SPECIFIC])
def test_model_required_layer_missing_prevents_allow(layer):
    assert assess_risk(make_inputs("model", drop_layers=[layer])).decision == "REVIEW"


def test_model_without_a_vulnerability_lookup_can_still_be_allowed():
    result = assess_risk(make_inputs("model", drop_layers=[RiskLayer.VULNERABILITY]))
    assert result.decision == "ALLOW"
    assert RiskLayer.VULNERABILITY in result.not_evaluated_layers


def test_no_evidence_is_review_with_no_score():
    result = assess_risk(make_inputs(drop_layers=list(RiskLayer)))
    assert result.risk_score is None
    assert result.decision == "REVIEW"
    assert result.decision_basis == "insufficient_evidence"


def test_partial_sandbox_is_listed_as_not_evaluated():
    result = assess_risk(
        make_inputs(drop_layers=[RiskLayer.BEHAVIORAL], drop_reason=NullReason.STAGE_PARTIAL)
    )
    assert RiskLayer.BEHAVIORAL in result.not_evaluated_layers
    assert RiskLayer.BEHAVIORAL in result.partial_layers
    behavioral = next(r for r in result.layers if r.layer == RiskLayer.BEHAVIORAL)
    assert behavioral.status == LayerStatus.PARTIAL


def test_only_mock_evidence_cannot_be_allowed():
    result = assess_risk(
        make_inputs(
            drop_layers=[
                RiskLayer.VULNERABILITY,
                RiskLayer.PROVENANCE,
                RiskLayer.STATIC,
                RiskLayer.GRAPH,
                RiskLayer.BEHAVIORAL,
            ],
            drop_reason=NullReason.MOCK_EVIDENCE,
            findings=[finding(source="mock")],
        )
    )
    assert result.decision == "REVIEW"
    assert result.risk_score is None


@pytest.mark.parametrize(
    ("artifact", "overrides", "rule", "decision"),
    [
        ("software", {"hash_changed_same_commit": True}, "hash_consistency_failed", "BLOCK"),
        ("model", {"pickle_dangerous_global_count": 2}, "dangerous_pickle_globals", "BLOCK"),
        (
            "software",
            {"sensitive_file_access_count": 1, "external_destination_count": 1},
            "sensitive_access_with_external_destination",
            "BLOCK",
        ),
        ("software", {"install_hook_count": 1}, "install_hook_present", "REVIEW"),
        ("software", {"archive_anomaly": 1}, "archive_anomaly", "REVIEW"),
        ("model", {"custom_code_present": True}, "custom_model_code", "REVIEW"),
        ("software", {"shell_spawn_count": 1}, "shell_spawn", "REVIEW"),
        ("software", {"external_destination_count": 1}, "external_destination", "REVIEW"),
        ("software", {"provenance_removed": True}, "provenance_removed", "REVIEW"),
        ("model", {"unexpected_parent_or_base_model": True}, "unexpected_base_model", "REVIEW"),
        (
            "software",
            {"vulnerable_count": 1, "cvss_max": 9.0},
            "critical_known_vulnerability",
            "REVIEW",
        ),
    ],
)
def test_hard_rules(artifact, overrides, rule, decision):
    result = assess_risk(make_inputs(artifact, **overrides))
    assert rule in fired(result)
    assert result.decision == decision


@pytest.mark.parametrize(
    ("artifact", "check", "rule"),
    [
        ("software", "hash_consistency", "hash_consistency_failed"),
        ("model", "download_integrity", "download_integrity_failed"),
    ],
)
def test_failed_checks_force_block(artifact, check, rule):
    result = assess_risk(make_inputs(artifact, checks=[{"name": check, "status": "fail"}]))
    assert rule in fired(result)
    assert result.decision == "BLOCK"


def test_hard_block_holds_even_when_the_model_says_benign():
    result = assess_risk(make_inputs(hash_changed_same_commit=True, ml=ml_outputs(0.0, 0.0)))
    assert result.decision == "BLOCK"
    assert result.decision_basis == "hard_rule"


def test_normal_update_is_not_a_hard_failure():
    result = assess_risk(make_inputs(hash_changed=True, hash_changed_same_commit=False))
    assert fired(result) == set()
    assert result.decision == "ALLOW"


def test_vulnerability_alone_is_never_a_hard_block():
    result = assess_risk(make_inputs(vulnerable_count=50, cvss_max=10.0))
    assert fired(result) == {"critical_known_vulnerability"}
    assert result.hard_rules_fired[0].decision == "REVIEW"
    assert result.decision == "REVIEW"


def test_partial_sandbox_finding_fires_its_hard_rule():
    result = assess_risk(
        make_inputs(
            drop_layers=[RiskLayer.BEHAVIORAL],
            drop_reason=NullReason.STAGE_PARTIAL,
            findings=[finding()],
        )
    )
    assert "shell_spawn" in fired(result)
    assert result.decision == "REVIEW"


def test_mock_finding_fires_no_hard_rule():
    result = assess_risk(
        make_inputs(
            drop_layers=[RiskLayer.BEHAVIORAL],
            drop_reason=NullReason.MOCK_EVIDENCE,
            findings=[finding(source="mock")],
        )
    )
    assert "shell_spawn" not in fired(result)


def test_unevaluated_hard_rules_are_listed():
    result = assess_risk(make_inputs(**SANDBOX_OFF))
    assert "shell_spawn" in result.hard_rules_not_evaluated
    assert "custom_model_code" not in result.hard_rules_not_evaluated  # not applicable


EVIDENCE_CASES = [
    {},
    {"install_hook_count": 1},
    {"archive_anomaly": 1, "provenance_removed": True},
    {"hash_changed_same_commit": True},
    {"vulnerable_count": 3, "cvss_max": 7.5},
    {"source_known": False, "dangerous_import_count": 2},
    {"drop_layers": [RiskLayer.STATIC]},
    {"drop_layers": [RiskLayer.BEHAVIORAL]},
]


@pytest.mark.parametrize(
    ("evidence", "ml"),
    list(itertools.product(EVIDENCE_CASES, [(0.0, 0.0), (0.5, 0.5), (1.0, 1.0)])),
)
def test_ml_never_changes_the_decision(evidence, ml):
    without = assess_risk(make_inputs(**evidence))
    with_ml = assess_risk(make_inputs(ml=ml_outputs(*ml), **evidence))
    assert with_ml.decision == without.decision


def test_ml_cannot_change_the_decision_even_with_a_huge_weight():
    policy = replace(
        DEFAULT_POLICY, weights={**DEFAULT_POLICY.weights, RiskLayer.ML_SUPERVISED: 100.0}
    )
    assert assess_risk(make_inputs(ml=ml_outputs(1.0, 1.0)), policy).decision == "ALLOW"


def test_ml_unavailable_is_stated_and_rules_still_decide():
    result = assess_risk(make_inputs(install_hook_count=1))
    assert result.ml.status == "unavailable"
    assert result.ml.message == ML_UNAVAILABLE_MESSAGE
    assert result.decision == "REVIEW"


def test_ml_unavailable_reason_is_included():
    inputs = replace(make_inputs(), ml_unavailable_reason="manifest mismatch")
    assert assess_risk(inputs).ml.message == f"{ML_UNAVAILABLE_MESSAGE}: manifest mismatch"


def test_scores_stay_separate():
    result = assess_risk(make_inputs(vulnerable_count=1, cvss_max=7.5, ml=ml_outputs(0.8, 0.6)))
    assert result.cvss_max == 7.5
    assert result.ml.rf_risk_probability == 0.8
    assert result.ml.anomaly_score == 0.6
    assert result.ml.xgb_risk_probability == 0.8
    assert result.risk_score not in (7.5, 0.8, 0.6)


def test_xgboost_has_no_effect_on_the_score():
    first = make_inputs(install_hook_count=1, ml=ml_outputs())
    second = replace(first, ml=replace(first.ml, xgb_risk_probability=0.01))
    assert assess_risk(first).risk_score == assess_risk(second).risk_score


def test_ml_flags_use_the_saved_thresholds():
    result = assess_risk(make_inputs(ml=ml_outputs(0.45, 0.5)))
    assert result.ml.rf_flagged is True
    assert result.ml.anomaly_flagged is False


def test_missing_hash_comparison_adds_a_reliability_note():
    inputs = make_inputs(hash_changed=None, ml=ml_outputs())
    notes = assess_risk(inputs).ml.reliability_notes
    assert any("hash comparison" in note for note in notes)
    assert any("synthetic" in note for note in notes)


def test_high_score_blocks_without_a_hard_rule():
    policy = replace(DEFAULT_POLICY, hard_rules=())
    result = assess_risk(
        make_inputs(
            install_hook_count=2,
            archive_anomaly=1,
            dangerous_import_count=4,
            suspicious_api_count=4,
            provenance_removed=True,
            source_known=False,
            vulnerable_count=4,
            cvss_max=9.8,
            shell_spawn_count=2,
            sensitive_file_access_count=2,
        ),
        policy,
    )
    assert result.decision == "BLOCK"
    assert result.decision_basis == "score"

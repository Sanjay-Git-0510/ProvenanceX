"""Layer results: missing evidence is never clean, and every score traces to its signals."""

import pytest

from app.ml.feature_schema import NullReason
from app.risk.layers import build_layers
from app.risk.policy_config import DEFAULT_POLICY, RiskLayer
from app.risk.types import LayerStatus
from tests.risk_helpers import finding, make_inputs


def layer(inputs, name):
    return next(r for r in build_layers(inputs, DEFAULT_POLICY) if r.layer == name)


def test_clean_evidence_is_evaluated_with_score_zero():
    result = layer(make_inputs(), RiskLayer.STATIC)
    assert result.status == LayerStatus.EVALUATED
    assert result.score == 0.0
    assert result.coverage == 1.0


@pytest.mark.parametrize(
    "reason",
    [
        NullReason.STAGE_SKIPPED,
        NullReason.STAGE_ERROR,
        NullReason.STAGE_UNAVAILABLE,
        NullReason.STAGE_NOT_RUN,
        NullReason.MOCK_EVIDENCE,
    ],
)
def test_missing_stage_is_not_evaluated_not_zero(reason):
    result = layer(
        make_inputs(drop_layers=[RiskLayer.BEHAVIORAL], drop_reason=reason), RiskLayer.BEHAVIORAL
    )
    assert result.status == LayerStatus.NOT_EVALUATED
    assert result.score is None
    assert result.coverage == 0.0
    assert set(result.not_evaluated.values()) == {str(reason)}


def test_quiet_partial_stage_has_no_score_and_reduced_coverage():
    result = layer(
        make_inputs(drop_layers=[RiskLayer.BEHAVIORAL], drop_reason=NullReason.STAGE_PARTIAL),
        RiskLayer.BEHAVIORAL,
    )
    assert result.status == LayerStatus.PARTIAL
    assert result.score is None
    assert result.coverage == DEFAULT_POLICY.partial_credit


def test_partial_stage_findings_can_raise_the_score():
    result = layer(
        make_inputs(
            drop_layers=[RiskLayer.BEHAVIORAL],
            drop_reason=NullReason.STAGE_PARTIAL,
            findings=[finding(severity="HIGH")],
        ),
        RiskLayer.BEHAVIORAL,
    )
    assert result.score == pytest.approx(0.70)
    assert result.signals[0].finding_id == "id-PX-BEHAV-SHELL-SPAWN"


def test_mock_findings_are_never_scored():
    result = layer(
        make_inputs(
            drop_layers=[RiskLayer.BEHAVIORAL],
            drop_reason=NullReason.STAGE_PARTIAL,
            findings=[finding(source="mock")],
        ),
        RiskLayer.BEHAVIORAL,
    )
    assert result.score is None
    assert result.mock_findings_ignored == 1
    assert result.evidence_finding_ids == []


def test_completed_stage_findings_link_as_evidence_without_double_counting():
    result = layer(
        make_inputs(shell_spawn_count=1, findings=[finding()]),
        RiskLayer.BEHAVIORAL,
    )
    assert result.score == pytest.approx(0.40)
    assert result.evidence_finding_ids == ["id-PX-BEHAV-SHELL-SPAWN"]


def test_signals_combine_as_noisy_or():
    result = layer(make_inputs(install_hook_count=1, archive_anomaly=1), RiskLayer.STATIC)
    assert result.score == pytest.approx(1 - 0.5 * 0.4)


def test_ai_layer_is_not_applicable_to_software():
    result = layer(make_inputs(), RiskLayer.AI_SPECIFIC)
    assert result.status == LayerStatus.NOT_APPLICABLE
    assert result.score is None


def test_cvss_is_not_missing_when_no_component_is_vulnerable():
    result = layer(make_inputs(), RiskLayer.VULNERABILITY)
    assert result.status == LayerStatus.EVALUATED
    assert result.coverage == 1.0


def test_cvss_scales_the_vulnerability_layer():
    result = layer(make_inputs(vulnerable_count=1, cvss_max=8.0), RiskLayer.VULNERABILITY)
    assert result.score == pytest.approx(1 - 0.2 * 0.98)


def test_advisory_without_cvss_still_scores():
    result = layer(make_inputs(vulnerable_count=1), RiskLayer.VULNERABILITY)
    assert result.score == pytest.approx(1 - 0.98 * 0.5)


def test_first_scan_lowers_provenance_coverage_but_keeps_a_score():
    inputs = make_inputs(hash_changed=None, hash_changed_same_commit=None, provenance_removed=None)
    reasons = dict(inputs.null_reasons) | {
        "hash_changed": NullReason.NO_PRIOR_SCAN,
    }
    result = layer(
        type(inputs)(inputs.artifact_type, inputs.features, reasons), RiskLayer.PROVENANCE
    )
    assert result.status == LayerStatus.PARTIAL
    assert result.score == 0.0
    assert 0 < result.coverage < 1
    assert result.not_evaluated["hash_changed"] == "no_prior_scan"


def test_failed_download_integrity_raises_provenance():
    result = layer(
        make_inputs("model", checks=[{"name": "download_integrity", "status": "fail"}]),
        RiskLayer.PROVENANCE,
    )
    assert result.score == pytest.approx(0.95)


def test_features_without_a_collector_do_not_lower_coverage():
    result = layer(make_inputs(), RiskLayer.PROVENANCE)
    assert result.coverage == 1.0
    assert result.not_evaluated["signed"] == "no_data_source"


def test_ml_layers_absent_without_a_model():
    results = build_layers(make_inputs(), DEFAULT_POLICY)
    ml = [r for r in results if r.layer == RiskLayer.ML_SUPERVISED]
    assert ml[0].status == LayerStatus.NOT_EVALUATED
    assert ml[0].score is None

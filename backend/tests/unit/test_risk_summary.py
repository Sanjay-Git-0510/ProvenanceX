"""Phase 7: the explanation summary only rearranges stored values and states its limits."""

from app.risk.policy import assess_risk
from app.risk.policy_config import RiskLayer
from app.risk.summary import HANDSET_NOTE, LEGACY_NOTE, SYNTHETIC_NOTE, build_summary, risk_level
from app.risk.types import RiskAssessment
from tests.risk_helpers import make_inputs


def test_clean_allow_summary():
    result = assess_risk(make_inputs())
    s = build_summary(result, None)
    assert s.decision == "ALLOW" and s.risk_score == result.risk_score
    assert s.risk_level == "LOW"
    assert s.decision_reasons == result.reasons
    assert s.critical_findings == [] and s.confirmed_evidence is False
    assert s.evidence_completeness.confidence == result.confidence
    assert "static" in s.evidence_completeness.evaluated_layers
    assert HANDSET_NOTE in s.notes and SYNTHETIC_NOTE in s.notes and LEGACY_NOTE not in s.notes
    assert s.ml_factors.status == "unavailable" and s.ml_factors.factors == []


def test_top_factors_are_ranked_and_trace_layer_signals():
    result = assess_risk(make_inputs(source_known=False, dangerous_import_count=3))
    s = build_summary(result, None)
    contributions = [f.contribution for f in s.top_factors]
    assert contributions == sorted(contributions, reverse=True) and contributions[0] > 0
    names = {sig["name"] for f in s.top_factors for sig in f.top_signals}
    assert {"source_known", "dangerous_import_count"} <= names


def test_block_lists_critical_findings_and_confirmed_evidence():
    checks = [{"name": "hash_consistency", "status": "fail"}]
    s = build_summary(assess_risk(make_inputs(hash_changed_same_commit=True, checks=checks)), None)
    assert s.decision == "BLOCK"
    assert [c["rule_id"] for c in s.critical_findings] == ["hash_consistency_failed"]
    assert s.confirmed_evidence is True
    assert all(item.state != "confirmed_tampering" for item in s.missing_evidence)


def test_missing_evidence_lists_gaps_but_not_known_vulnerabilities():
    result = assess_risk(
        make_inputs(drop_layers=[RiskLayer.BEHAVIORAL], vulnerable_count=1, cvss_max=5.0)
    )
    s = build_summary(result, None)
    gap_states = {item.state for item in s.missing_evidence}
    assert "missing_evidence" in gap_states and "known_vulnerability" not in gap_states
    assert "known_vulnerability" in {item.state for item in s.evidence_status}
    assert "behavioral" in s.evidence_completeness.not_evaluated_layers


def test_no_evidence_has_no_score_or_level():
    s = build_summary(assess_risk(make_inputs(drop_layers=list(RiskLayer))), None)
    assert s.risk_score is None and s.risk_level is None and s.decision == "REVIEW"


def test_available_shap_is_passed_through_and_capped():
    shap = {
        "status": "available",
        "explains": "Random Forest probability (not the ProvenanceX risk score)",
        "note": "evaluated=false factors describe missing evidence",
        "top_factors": [{"feature": f"f{i}", "shap_contribution": 0.1} for i in range(8)],
    }
    s = build_summary(assess_risk(make_inputs()), shap)
    assert s.ml_factors.status == "available"
    assert len(s.ml_factors.factors) == 5
    assert "not the ProvenanceX risk score" in s.ml_factors.explains


def test_failed_shap_message_is_kept():
    shap = {"status": "unavailable", "message": "SHAP explanation failed: ValueError"}
    s = build_summary(assess_risk(make_inputs()), shap)
    assert s.ml_factors.message == "SHAP explanation failed: ValueError"


def test_result_stored_by_policy_v1_is_marked_legacy():
    data = assess_risk(make_inputs()).model_dump()
    data.pop("evidence_status")
    data["policy_version"] = "provenancex-policy-v1-handset"
    s = build_summary(RiskAssessment.model_validate(data), None)
    assert LEGACY_NOTE in s.notes and s.confirmed_evidence is None
    assert s.policy_version == "provenancex-policy-v1-handset"


def test_risk_level_bands():
    assert [risk_level(v) for v in (None, 0.0, 0.35, 0.69, 0.70, 1.0)] == [
        None,
        "LOW",
        "MEDIUM",
        "MEDIUM",
        "HIGH",
        "HIGH",
    ]

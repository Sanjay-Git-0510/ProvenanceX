"""Phase 7: evidence states keep missing, weak and unverified evidence apart from confirmed
tampering or dangerous behaviour, and none of the unconfirmed states can BLOCK on its own."""

import itertools
from dataclasses import replace

import pytest

from app.ml.feature_schema import NullReason
from app.risk.policy import assess_risk
from app.risk.policy_config import RiskLayer
from tests.risk_helpers import make_inputs


def states(result):
    return {item.state: item for item in result.evidence_status}


def with_reasons(inputs, **reasons):
    return replace(inputs, null_reasons={**inputs.null_reasons, **reasons})


def test_clean_complete_scan_has_no_confirmed_or_gap_state():
    result = assess_risk(make_inputs())
    assert result.evidence_status == []


def test_weak_provenance_is_named_and_not_confirmed():
    result = assess_risk(make_inputs(source_known=False, provenance_present=False))
    item = states(result)["weak_provenance"]
    assert item.confirmed is False
    assert set(item.items) == {"source_known", "provenance_present"}
    assert "not evidence of tampering" in item.note
    assert result.decision != "BLOCK"


def test_no_prior_scan_is_its_own_state_not_missing_evidence():
    inputs = with_reasons(
        make_inputs(hash_changed=None, hash_changed_same_commit=None, provenance_removed=None),
        hash_changed=NullReason.NO_PRIOR_SCAN,
        hash_changed_same_commit=NullReason.NO_PRIOR_SCAN,
        provenance_removed=NullReason.NO_PRIOR_SCAN,
    )
    found = states(assess_risk(inputs))
    assert set(found["no_prior_scan"].items) == {
        "hash_changed",
        "hash_changed_same_commit",
        "provenance_removed",
    }
    assert found["no_prior_scan"].confirmed is False
    assert "missing_evidence" not in found and "confirmed_tampering" not in found


def test_hash_change_from_a_new_commit_is_not_tampering():
    result = assess_risk(make_inputs(hash_changed=True, hash_changed_same_commit=False))
    assert "confirmed_tampering" not in states(result)
    assert result.decision != "BLOCK"


def test_same_commit_hash_change_is_confirmed_tampering_and_blocks():
    checks = [{"name": "hash_consistency", "status": "fail"}]
    result = assess_risk(make_inputs(hash_changed_same_commit=True, checks=checks))
    item = states(result)["confirmed_tampering"]
    assert item.confirmed is True and item.items == ["hash_consistency_failed"]
    assert result.decision == "BLOCK"


def test_failed_download_integrity_is_confirmed_tampering():
    checks = [{"name": "download_integrity", "status": "fail"}]
    result = assess_risk(make_inputs("model", checks=checks))
    assert states(result)["confirmed_tampering"].items == ["download_integrity_failed"]


def test_unknown_integrity_check_is_unverified_not_failed():
    checks = [{"name": "download_integrity", "status": "unknown"}]
    result = assess_risk(make_inputs("model", checks=checks))
    found = states(result)
    assert found["integrity_unverified"].items == ["download_integrity"]
    assert found["integrity_unverified"].confirmed is False
    assert "confirmed_tampering" not in found
    assert result.decision != "BLOCK"


def test_dangerous_pickle_is_dangerous_behavior_not_proof_of_intent():
    result = assess_risk(make_inputs("model", pickle_dangerous_global_count=2))
    item = states(result)["dangerous_behavior"]
    assert item.confirmed is True and item.items == ["dangerous_pickle_globals"]
    assert "not proof of malicious intent" in item.note
    assert result.decision == "BLOCK"


def test_known_vulnerability_is_not_malicious():
    result = assess_risk(make_inputs(vulnerable_count=2, cvss_max=7.5))
    item = states(result)["known_vulnerability"]
    assert item.confirmed is False and "does not mean malicious" in item.note
    assert "dangerous_behavior" not in states(result)


def test_skipped_stage_is_missing_evidence_with_its_reason():
    result = assess_risk(make_inputs(drop_layers=[RiskLayer.BEHAVIORAL]))
    item = states(result)["missing_evidence"]
    assert item.confirmed is False
    assert "network_count (stage_skipped)" in item.items
    assert "not clean" in item.note


@pytest.mark.parametrize(
    "drop, weak",
    list(
        itertools.product(
            [(), (RiskLayer.BEHAVIORAL,), (RiskLayer.STATIC, RiskLayer.GRAPH)],
            [
                {},
                {"source_known": False, "provenance_present": False},
                {"source_known": False, "revision_pinned": False, "version_consistency": False},
            ],
        )
    ),
)
@pytest.mark.parametrize("artifact", ["software", "model"])
def test_missing_or_weak_evidence_alone_never_blocks(artifact, drop, weak):
    result = assess_risk(make_inputs(artifact, drop_layers=list(drop), **weak))
    assert result.decision != "BLOCK"
    assert not any(item.confirmed for item in result.evidence_status)


def test_no_evidence_at_all_is_review_never_allow_or_block():
    result = assess_risk(make_inputs(drop_layers=list(RiskLayer)))
    assert result.decision == "REVIEW"
    assert states(result)["missing_evidence"].items

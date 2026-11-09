"""Anchoring rules: what may be anchored, what is refused, and how retries behave."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.blockchain.anchoring import anchor_scan
from app.blockchain.base import AnchorRecord, ChainAnchor
from app.blockchain.encoding import record_hash
from app.blockchain.mock import MockChainProvider
from app.core.errors import AppError, ErrorCode
from app.db.models import (
    AnchorStatus,
    Artifact,
    BlockchainEvidence,
    Component,
    Finding,
    FindingCategory,
    RiskDecision,
    Scan,
    utcnow,
)
from tests.conftest import make_anchorable_scan

DECISION_TIME = int(datetime(2026, 11, 9, 12, 0, 30, tzinfo=UTC).timestamp())


class RealLikeChain(MockChainProvider):
    """A ledger reporting source="web3", to exercise the rules for the real chain."""

    source = "web3"

    def __init__(self):
        super().__init__()
        self.submits = 0

    def submit(self, record):
        self.submits += 1
        return replace(super().submit(record), source="web3")


@pytest.fixture
def chain():
    return RealLikeChain()


@pytest.fixture
def session(session_factory):
    with session_factory() as active:
        yield active


def _refused(session, scan_id, provider, settings) -> AppError:
    with pytest.raises(AppError) as caught:
        anchor_scan(session, scan_id, provider, settings)
    return caught.value


def _row(session, scan_id) -> BlockchainEvidence | None:
    session.expire_all()
    return session.scalars(
        select(BlockchainEvidence).where(BlockchainEvidence.scan_id == scan_id)
    ).first()


def _artifact_id(session, scan_id):
    return session.get(Scan, scan_id).artifact_id


def test_anchors_the_eight_stored_fields(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    result = anchor_scan(session, scan_id, chain, test_settings)
    assert result.status == "confirmed"
    assert result.source == "web3"
    assert result.is_mock is False
    assert result.artifact_id == _artifact_id(session, scan_id)
    assert (result.artifact_hash, result.bom_hash, result.provenance_hash) == (
        "a" * 64,
        "b" * 64,
        "c" * 64,
    )
    assert (result.risk_score, result.risk_score_scaled) == (0.7, 700_000)
    assert result.decision == "REVIEW"
    assert result.scanner_version == "0.1.0"
    assert result.evidence_timestamp == DECISION_TIME
    assert result.missing_evidence == []
    assert result.adopted_existing_anchor is False
    assert chain.submits == 1


def test_row_is_confirmed_with_the_receipt(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    result = anchor_scan(session, scan_id, chain, test_settings)
    row = _row(session, scan_id)
    assert row.status == AnchorStatus.CONFIRMED
    assert row.tx_hash == result.tx_hash
    assert row.record_hash == result.record_hash
    assert row.anchor_index == 0
    assert row.anchored_at is not None
    assert row.error_code is None


def test_null_score_is_anchored_as_null_not_zero(session, chain, test_settings):
    scan_id = make_anchorable_scan(session, score=None, decision="BLOCK")
    result = anchor_scan(session, scan_id, chain, test_settings)
    assert result.risk_score is None
    assert result.risk_score_scaled is None
    assert result.decision == "BLOCK"
    assert _row(session, scan_id).risk_score_scaled is None
    assert chain.anchors(result.artifact_id)[0].record.risk_score_scaled is None


def test_real_zero_score_stays_zero(session, chain, test_settings):
    scan_id = make_anchorable_scan(session, score=0.0, decision="ALLOW")
    result = anchor_scan(session, scan_id, chain, test_settings)
    assert result.risk_score_scaled == 0
    assert _row(session, scan_id).risk_score_scaled == 0


def test_null_and_zero_scores_have_different_record_hashes(session, chain, test_settings):
    null, zero = (
        anchor_scan(
            session, make_anchorable_scan(session, score=score), RealLikeChain(), test_settings
        )
        for score in (None, 0.0)
    )
    assert (null.risk_score_scaled, zero.risk_score_scaled) == (None, 0)
    base = AnchorRecord(uuid4(), "a" * 64, None, None, None, "REVIEW", "0.1.0", 1)
    assert record_hash(base) != record_hash(replace(base, risk_score_scaled=0))


@pytest.mark.parametrize(
    ("hashes", "missing"),
    [
        ({"bom_sha256": None}, ["bom_hash"]),
        ({"provenance_sha256": None}, ["provenance_hash"]),
        ({"bom_sha256": None, "provenance_sha256": None}, ["bom_hash", "provenance_hash"]),
    ],
)
def test_absent_evidence_is_listed_and_never_clean(session, chain, test_settings, hashes, missing):
    scan_id = make_anchorable_scan(session, **hashes)
    result = anchor_scan(session, scan_id, chain, test_settings)
    assert result.missing_evidence == missing
    row = _row(session, scan_id)
    if "bom_hash" in missing:
        assert row.bom_hash is None
    if "provenance_hash" in missing:
        assert row.provenance_hash is None


@pytest.mark.parametrize("status", ["queued", "running", "failed"])
def test_unfinished_scans_are_refused(session, chain, test_settings, status):
    scan_id = make_anchorable_scan(session, status=status)
    failure = _refused(session, scan_id, chain, test_settings)
    assert failure.code == "anchor_scan_not_completed"
    assert chain.submits == 0
    assert _row(session, scan_id) is None


def test_scan_without_a_decision_is_refused(session, chain, test_settings):
    scan_id = make_anchorable_scan(session, with_decision=False)
    assert _refused(session, scan_id, chain, test_settings).code == "anchor_no_decision"
    assert chain.submits == 0


def test_missing_artifact_hash_is_always_refused(session, chain, test_settings):
    scan_id = make_anchorable_scan(session, artifact_sha256=None)
    assert _refused(session, scan_id, chain, test_settings).code == "anchor_missing_artifact_hash"
    assert chain.submits == 0


@pytest.mark.parametrize(
    "hashes",
    [
        {"artifact_sha256": "0" * 64},
        {"artifact_sha256": "A" * 64},
        {"artifact_sha256": "a" * 63},
        {"bom_sha256": "0" * 64},
        {"bom_sha256": "not-a-hash"},
        {"provenance_sha256": "0" * 64},
        {"provenance_sha256": "G" * 64},
        # The evidence sanitizer turns this value into a redaction marker.
        {"bom_sha256": "0x" + "ab" * 32},
    ],
)
def test_invalid_hashes_are_refused(session, chain, test_settings, hashes):
    scan_id = make_anchorable_scan(session, **hashes)
    assert _refused(session, scan_id, chain, test_settings).code == "anchor_invalid_hash"
    assert chain.submits == 0
    assert _row(session, scan_id) is None


def test_invalid_scanner_version_is_refused(session, chain, test_settings):
    scan_id = make_anchorable_scan(session, scanner_version="v" * 33)
    assert _refused(session, scan_id, chain, test_settings).code == "anchor_invalid_record"


def _mock_stage(session):
    return make_anchorable_scan(session, stages={"sbom": {"status": "completed", "source": "mock"}})


def _mock_finding(session):
    scan_id = make_anchorable_scan(session)
    session.add(
        Finding(
            scan_id=scan_id,
            category=FindingCategory.STATIC,
            identifier="X",
            severity="LOW",
            source="mock",
        )
    )
    session.commit()
    return scan_id


def _mock_component(session):
    scan_id = make_anchorable_scan(session)
    session.add(
        Component(scan_id=scan_id, bom_ref="r", name="n", component_type="library", source="mock")
    )
    session.commit()
    return scan_id


@pytest.mark.parametrize("build", [_mock_stage, _mock_finding, _mock_component])
def test_mock_evidence_is_refused_on_the_real_chain(session, chain, test_settings, build):
    scan_id = build(session)
    assert _refused(session, scan_id, chain, test_settings).code == "anchor_refused_mock_evidence"
    assert chain.submits == 0
    assert _row(session, scan_id) is None


def test_mock_chain_can_hold_mock_evidence_and_is_labeled(session, test_settings):
    scan_id = _mock_stage(session)
    result = anchor_scan(session, scan_id, MockChainProvider(), test_settings)
    assert result.is_mock is True
    assert result.source == "mock"
    assert result.tx_hash.startswith("mock-tx-")
    assert result.block_number is None
    assert _row(session, scan_id).source == "mock"


def test_disabled_provider_is_refused_with_no_fallback(session, test_settings):
    scan_id = make_anchorable_scan(session)
    failure = _refused(session, scan_id, None, test_settings)
    assert (failure.code, failure.status_code) == ("blockchain_disabled", 503)
    assert _row(session, scan_id) is None


def test_unknown_scan_is_not_found(session, chain, test_settings):
    assert _refused(session, uuid4(), chain, test_settings).code == "scan_not_found"


def test_a_scan_cannot_be_anchored_twice(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    anchor_scan(session, scan_id, chain, test_settings)
    assert _refused(session, scan_id, chain, test_settings).code == "anchor_already_exists"
    assert chain.submits == 1


def test_changed_values_cannot_be_re_anchored(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    anchor_scan(session, scan_id, chain, test_settings)
    decision = session.scalars(select(RiskDecision).where(RiskDecision.scan_id == scan_id)).one()
    decision.risk_score = 0.1
    session.commit()
    assert _refused(session, scan_id, chain, test_settings).code == "anchor_already_exists"
    assert chain.submits == 1


def _age_pending(session, scan_id, seconds):
    row = _row(session, scan_id)
    row.status = AnchorStatus.PENDING
    row.tx_hash = None
    row.reserved_at = utcnow() - timedelta(seconds=seconds)
    session.commit()


def test_recent_pending_row_blocks_a_second_send(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    anchor_scan(session, scan_id, chain, test_settings)
    _age_pending(session, scan_id, 1)
    assert _refused(session, scan_id, chain, test_settings).code == "anchor_in_progress"
    assert chain.submits == 1


def test_crash_after_send_adopts_the_anchor_without_resending(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    original = anchor_scan(session, scan_id, chain, test_settings)
    _age_pending(session, scan_id, 10_000)
    adopted = anchor_scan(session, scan_id, chain, test_settings)
    assert adopted.adopted_existing_anchor is True
    assert adopted.tx_hash == original.tx_hash
    assert adopted.status == "confirmed"
    assert chain.submits == 1


def test_stale_pending_with_nothing_on_chain_sends_once(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    anchor_scan(session, scan_id, MockChainProvider(), test_settings)
    _age_pending(session, scan_id, 10_000)
    result = anchor_scan(session, scan_id, chain, test_settings)
    assert result.adopted_existing_anchor is False
    assert result.source == "web3"
    assert chain.submits == 1


class FailingChain(RealLikeChain):
    def __init__(self, error):
        super().__init__()
        self.error = error

    def submit(self, record):
        raise self.error


def test_row_exists_as_pending_while_sending(session_factory, session, test_settings):
    scan_id = make_anchorable_scan(session)
    seen = []

    class Watching(RealLikeChain):
        def submit(self, record):
            with session_factory() as other:
                seen.append(_row(other, scan_id).status)
            return super().submit(record)

    anchor_scan(session, scan_id, Watching(), test_settings)
    assert seen == [AnchorStatus.PENDING]


def test_failed_send_is_recorded_and_can_be_retried(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    error = AppError(ErrorCode.CHAIN_UNAVAILABLE, "down", 503)
    assert _refused(session, scan_id, FailingChain(error), test_settings).code == (
        "chain_unavailable"
    )
    row = _row(session, scan_id)
    assert row.status == AnchorStatus.FAILED
    assert row.error_code == "chain_unavailable"
    assert row.tx_hash is None
    result = anchor_scan(session, scan_id, chain, test_settings)
    assert result.status == "confirmed"
    assert _row(session, scan_id).error_code is None


def test_unexpected_error_is_recorded_and_raised(session, test_settings):
    scan_id = make_anchorable_scan(session)
    with pytest.raises(RuntimeError):
        anchor_scan(session, scan_id, FailingChain(RuntimeError("boom")), test_settings)
    row = _row(session, scan_id)
    assert (row.status, row.error_code) == (AnchorStatus.FAILED, "internal_error")


def test_different_anchor_on_chain_is_a_conflict(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    anchor_scan(session, scan_id, chain, test_settings)
    _age_pending(session, scan_id, 10_000)
    decision = session.scalars(select(RiskDecision).where(RiskDecision.scan_id == scan_id)).one()
    decision.risk_score = 0.1
    session.commit()
    assert _refused(session, scan_id, chain, test_settings).code == "anchor_conflict"
    assert _row(session, scan_id).status == AnchorStatus.FAILED
    assert chain.submits == 1


def test_two_anchors_on_chain_is_a_conflict(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    result = anchor_scan(session, scan_id, chain, test_settings)
    chain.submit(chain.anchors(result.artifact_id)[0].record)
    _age_pending(session, scan_id, 10_000)
    assert _refused(session, scan_id, chain, test_settings).code == "anchor_conflict"


def test_read_back_difference_is_a_conflict(session, test_settings):
    class Corrupting(RealLikeChain):
        def anchors(self, artifact_id):
            found = super().anchors(artifact_id)
            return [ChainAnchor(a.index, replace(a.record, risk_score_scaled=1)) for a in found]

    scan_id = make_anchorable_scan(session)
    assert _refused(session, scan_id, Corrupting(), test_settings).code == "anchor_conflict"
    assert _row(session, scan_id).status == AnchorStatus.FAILED


def test_deleting_the_scan_removes_its_row(session, chain, test_settings):
    scan_id = make_anchorable_scan(session)
    anchor_scan(session, scan_id, chain, test_settings)
    scan = session.get(Scan, scan_id)
    artifact = session.get(Artifact, scan.artifact_id)
    assert scan.blockchain_evidence is not None
    session.delete(artifact.scans[0])
    session.commit()
    assert session.scalars(select(BlockchainEvidence)).all() == []

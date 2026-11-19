"""Scan ownership (audit finding M2): claim tokens, fenced writes, heartbeats, stale recovery.

These run on SQLite, which has no row locks; the lock-ordering and concurrent-runner races are
exercised against PostgreSQL in tests/integration/test_scan_ownership_pg.py.
"""

import threading
import time
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, update

from app.blockchain.anchoring import anchor_scan
from app.blockchain.mock import MockChainProvider
from app.core.errors import AppError, ErrorCode
from app.db.models import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    BlockchainEvidence,
    RiskDecision,
    Scan,
    ScanStatus,
    utcnow,
)
from app.pipeline import lifecycle
from app.pipeline.ownership import (
    ClaimLost,
    Heartbeat,
    ScanClaim,
    bind_claim,
    renew,
    transition,
    unbind_claim,
)
from app.pipeline.stages import StageStatus, execute_stage
from app.pipeline.workspace import create_workspace
from app.runner.queue import claim_next_scan, claim_scan, fail_stale_claims, recover_own_orphans
from tests.conftest import make_anchorable_scan


def _queued(session, kind=ArtifactType.SOFTWARE) -> uuid.UUID:
    scan = Scan(
        id=uuid.uuid4(),
        artifact=Artifact(artifact_type=kind, name="x", source=ArtifactSource.UPLOAD),
        status=ScanStatus.QUEUED,
        scanner_version="0.1.0",
    )
    session.add(scan)
    session.commit()
    return scan.id


def _recover(session_factory, scan_id) -> None:
    """Stale recovery by 'runner B': age the heartbeat, then run the recovery query."""
    with session_factory() as s:
        s.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(heartbeat_at=utcnow() - timedelta(hours=1))
        )
        s.commit()
        assert fail_stale_claims(s, 60) == [scan_id]


def _state(session_factory, scan_id) -> Scan:
    with session_factory() as s:
        return s.get(Scan, scan_id)


# ----------------------------------------------------------------------------- claiming
def test_claim_records_token_runner_and_heartbeat(session_factory):
    with session_factory() as s:
        sid = _queued(s)
        claim = claim_next_scan(s, "runner-a")
    assert claim is not None and claim.scan_id == sid and claim.runner_id == "runner-a"
    scan = _state(session_factory, sid)
    assert scan.status == ScanStatus.RUNNING
    assert scan.claim_token == claim.token
    assert scan.claimed_by == "runner-a"
    assert scan.heartbeat_at is not None and scan.claimed_at is not None


def test_each_claim_gets_a_fresh_token(session_factory):
    with session_factory() as s:
        a, b = _queued(s), _queued(s)
        first, second = claim_scan(s, a), claim_scan(s, b)
    assert first.token != second.token


# ----------------------------------------------------------------------------- fencing
def test_fenced_commit_succeeds_while_owned(session_factory):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
    with session_factory() as s:
        bind_claim(s, claim)
        s.get(Scan, claim.scan_id).ingest_metadata = {"ok": True}
        s.commit()
        unbind_claim(s)
    assert _state(session_factory, claim.scan_id).ingest_metadata == {"ok": True}


def test_replaced_claim_cannot_commit_and_the_loss_is_sticky(session_factory):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
    _recover(session_factory, claim.scan_id)
    with session_factory() as s:
        bind_claim(s, claim)
        s.get(Scan, claim.scan_id).ingest_metadata = {"late": True}
        with pytest.raises(ClaimLost):
            s.commit()
        s.rollback()
        assert claim.lost.is_set()
        with pytest.raises(ClaimLost):  # no further query needed
            s.commit()
        s.rollback()
        unbind_claim(s)
    scan = _state(session_factory, claim.scan_id)
    assert scan.ingest_metadata is None
    assert scan.status == ScanStatus.FAILED and scan.error_code == "runner_interrupted"


def test_unbound_sessions_are_not_fenced(session_factory):
    """The API and direct pipeline calls have no claim and keep working."""
    with session_factory() as s:
        sid = _queued(s)
        s.get(Scan, sid).ingest_metadata = {"api": 1}
        s.commit()
    assert _state(session_factory, sid).ingest_metadata == {"api": 1}


def test_stage_update_after_recovery_is_refused(session_factory):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
    _recover(session_factory, claim.scan_id)
    with session_factory() as s:
        bind_claim(s, claim)

        def body(scan):
            return None, StageStatus.COMPLETED, {"count": 1}

        with pytest.raises(ClaimLost):
            execute_stage(s, claim.scan_id, "sbom", body)
        s.rollback()
        unbind_claim(s)
    assert "sbom" not in (_state(session_factory, claim.scan_id).stages or {})


def test_transition_requires_the_current_token_and_running_status(session_factory):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
    stranger = ScanClaim(claim.scan_id, uuid.uuid4())
    with session_factory() as s:
        with pytest.raises(ClaimLost):
            transition(s, stranger, status=ScanStatus.COMPLETED)
        transition(s, claim, status=ScanStatus.COMPLETED, finished_at=utcnow())
        # Terminal states are written once: a second transition no longer matches RUNNING.
        with pytest.raises(ClaimLost):
            transition(s, claim, status=ScanStatus.FAILED)
    assert _state(session_factory, claim.scan_id).status == ScanStatus.COMPLETED


def test_record_failure_and_mark_completed_cannot_overwrite_recovery(session_factory):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
    _recover(session_factory, claim.scan_id)
    with session_factory() as s:
        with pytest.raises(ClaimLost):
            lifecycle.mark_completed(s, claim.scan_id, claim)
        with pytest.raises(ClaimLost):
            lifecycle.record_failure(s, claim.scan_id, "internal_error", "late", None, claim)
    scan = _state(session_factory, claim.scan_id)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_code == "runner_interrupted"


# ----------------------------------------------------------------------------- run_scan race
def _run_with_recovery_midway(session_factory, test_settings, *, decide=True):
    """Runner A runs a scan; runner B recovers it during A's evidence stages; A then finishes."""
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "runner-a")
    workspace = create_workspace(test_settings.workspace_root, claim.scan_id)
    anchored: list[uuid.UUID] = []

    def ingest(session, scan, ws):
        scan.ingest_metadata = {"files": 1}
        session.commit()
        return "ingested"

    def evidence(session, sid, ws, ingested):
        _recover(session_factory, sid)  # runner B takes over while A is still working
        if decide:
            session.add(
                RiskDecision(
                    scan_id=sid,
                    risk_score=0.1,
                    decision="ALLOW",
                    decision_basis="test",
                    confidence=0.5,
                    confidence_label="MEDIUM",
                    ml_status="unavailable",
                    policy_version="test",
                    layer_scores={},
                    explanation={},
                )
            )
            session.commit()

    lifecycle.run_scan(
        claim.scan_id,
        session_factory,
        test_settings,
        ingest,
        evidence,
        after_completed=lambda session, sid: anchored.append(sid),
        require_decision=True,
        claim=claim,
    )
    return claim, workspace, anchored


def test_runner_a_cannot_overwrite_runner_b_result(session_factory, test_settings):
    claim, workspace, anchored = _run_with_recovery_midway(session_factory, test_settings)
    scan = _state(session_factory, claim.scan_id)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_code == "runner_interrupted"
    assert scan.claim_token != claim.token
    assert scan.ingest_metadata == {"files": 1}  # written before recovery, while owned
    with session_factory() as s:
        assert (
            s.scalars(select(RiskDecision).where(RiskDecision.scan_id == scan.id)).first() is None
        )
    assert anchored == []  # never reached anchoring
    assert not workspace.root.exists()  # A removed only its own workspace


def test_owned_run_completes_normally(session_factory, test_settings):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "runner-a")
    create_workspace(test_settings.workspace_root, claim.scan_id)
    lifecycle.run_scan(
        claim.scan_id,
        session_factory,
        test_settings,
        lambda session, scan, ws: None,
        lambda session, sid, ws, ingested: None,
        claim=claim,
    )
    scan = _state(session_factory, claim.scan_id)
    assert scan.status == ScanStatus.COMPLETED and scan.started_at is not None


def test_ingest_failure_is_recorded_by_the_owner(session_factory, test_settings):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "runner-a")
    create_workspace(test_settings.workspace_root, claim.scan_id)

    def ingest(session, scan, ws):
        raise AppError(ErrorCode.EMPTY_ARTIFACT, "Artifact contains no files", 400)

    lifecycle.run_scan(
        claim.scan_id, session_factory, test_settings, ingest, lambda *a: None, claim=claim
    )
    scan = _state(session_factory, claim.scan_id)
    assert scan.status == ScanStatus.FAILED and scan.error_code == "empty_artifact"


# ----------------------------------------------------------------------------- anchoring
def test_old_claim_cannot_anchor(session_factory, test_settings):
    chain = MockChainProvider()
    submits: list[object] = []
    original = chain.submit
    chain.submit = lambda record: submits.append(record) or original(record)
    with session_factory() as s:
        scan_id = make_anchorable_scan(s)
        scan = s.get(Scan, scan_id)
        scan.claim_token = uuid.uuid4()  # runner B's token
        s.commit()
        old = ScanClaim(scan_id, uuid.uuid4())  # runner A's replaced token
        bind_claim(s, old)
        with pytest.raises(ClaimLost):
            anchor_scan(s, scan_id, chain, test_settings)
        s.rollback()
        unbind_claim(s)
        assert submits == []
        assert (
            s.scalars(
                select(BlockchainEvidence).where(BlockchainEvidence.scan_id == scan_id)
            ).first()
            is None
        )


def test_current_claim_can_anchor(session_factory, test_settings):
    chain = MockChainProvider()
    with session_factory() as s:
        scan_id = make_anchorable_scan(s)
        token = uuid.uuid4()
        s.get(Scan, scan_id).claim_token = token
        s.commit()
        bind_claim(s, ScanClaim(scan_id, token))
        assert anchor_scan(s, scan_id, chain, test_settings).status == "confirmed"
        unbind_claim(s)


# ----------------------------------------------------------------------------- heartbeat
def test_renew_moves_the_heartbeat_and_detects_replacement(session_factory):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
        s.execute(
            update(Scan)
            .where(Scan.id == claim.scan_id)
            .values(heartbeat_at=utcnow() - timedelta(minutes=5))
        )
        s.commit()
    before = _state(session_factory, claim.scan_id).heartbeat_at
    with session_factory() as s:
        assert renew(s, claim) is True
    assert _state(session_factory, claim.scan_id).heartbeat_at > before
    _recover(session_factory, claim.scan_id)
    with session_factory() as s:
        assert renew(s, claim) is False
    assert claim.lost.is_set()


def test_heartbeat_keeps_a_long_running_scan_from_going_stale(session_factory):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
    with Heartbeat(session_factory, claim, 0.05):
        for _ in range(6):  # a "scan" longer than the stale window
            time.sleep(0.25)
            with session_factory() as s:
                assert fail_stale_claims(s, 1) == []
    time.sleep(1.3)  # heartbeat stopped: the claim now goes stale
    with session_factory() as s:
        assert fail_stale_claims(s, 1) == [claim.scan_id]


def test_heartbeat_marks_the_claim_lost_after_recovery(session_factory):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
    _recover(session_factory, claim.scan_id)
    with Heartbeat(session_factory, claim, 0.05):
        assert claim.lost.wait(2)


# ----------------------------------------------------------------------------- recovery
def test_stale_recovery_uses_the_heartbeat_not_the_claim_age(session_factory):
    with session_factory() as s:
        long_running = claim_scan(s, _queued(s), "a")
        scan = s.get(Scan, long_running.scan_id)
        scan.claimed_at = utcnow() - timedelta(hours=3)  # claimed long ago...
        scan.heartbeat_at = utcnow()  # ...but still heartbeating
        s.commit()
        assert fail_stale_claims(s, 120) == []
        assert fail_stale_claims(s, 120, max_scan_seconds=3600) == [long_running.scan_id]
    scan = _state(session_factory, long_running.scan_id)
    assert scan.error_details == {"max_scan_seconds": 3600}
    assert "maximum scan duration" in scan.error_message
    assert scan.claim_token != long_running.token


def test_legacy_claims_without_heartbeat_fall_back_to_claim_time(session_factory):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
        scan = s.get(Scan, claim.scan_id)
        scan.heartbeat_at = None
        scan.claimed_at = utcnow() - timedelta(hours=2)
        s.commit()
        assert fail_stale_claims(s, 3600) == [claim.scan_id]


def test_recovery_is_idempotent(session_factory):
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
    _recover(session_factory, claim.scan_id)
    first = _state(session_factory, claim.scan_id)
    with session_factory() as s:
        assert fail_stale_claims(s, 60) == []
    again = _state(session_factory, claim.scan_id)
    assert (again.claim_token, again.finished_at) == (first.claim_token, first.finished_at)


def test_own_orphans_are_recovered_only_for_this_runner_and_when_quiet(session_factory):
    with session_factory() as s:
        mine_old = claim_scan(s, _queued(s), "runner-a")
        mine_fresh = claim_scan(s, _queued(s), "runner-a")
        mine_active = claim_scan(s, _queued(s), "runner-a")
        theirs = claim_scan(s, _queued(s), "runner-b")
        for c in (mine_old, mine_active, theirs):
            s.get(Scan, c.scan_id).heartbeat_at = utcnow() - timedelta(seconds=60)
        s.commit()
        got = recover_own_orphans(s, "runner-a", {mine_active.scan_id}, quiet_seconds=25)
    assert got == [mine_old.scan_id]
    assert _state(session_factory, mine_fresh.scan_id).status == ScanStatus.RUNNING
    assert _state(session_factory, mine_active.scan_id).status == ScanStatus.RUNNING
    assert _state(session_factory, theirs.scan_id).status == ScanStatus.RUNNING
    recovered = _state(session_factory, mine_old.scan_id)
    assert recovered.error_details == {"recovered_by": "runner_restart"}


def test_concurrent_heartbeat_and_fence_threads_do_not_corrupt_state(session_factory):
    """Smoke test: heartbeat thread + fenced writer on the same scan, then recovery."""
    with session_factory() as s:
        claim = claim_scan(s, _queued(s), "a")
    errors: list[BaseException] = []
    with Heartbeat(session_factory, claim, 0.02):

        def writer():
            try:
                with session_factory() as s:
                    bind_claim(s, claim)
                    for i in range(10):
                        s.get(Scan, claim.scan_id).ingest_metadata = {"i": i}
                        s.commit()
                    unbind_claim(s)
            except BaseException as exc:  # noqa: BLE001 - surfaced below
                errors.append(exc)

        t = threading.Thread(target=writer)
        t.start()
        t.join(10)
    assert errors == []
    assert _state(session_factory, claim.scan_id).ingest_metadata == {"i": 9}

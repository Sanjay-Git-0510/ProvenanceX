"""Scan ownership races on a real PostgreSQL (audit finding M2).

SQLite has no row locks, so these are the tests that prove the fence and stale recovery are
serialized by PostgreSQL itself: SELECT ... FOR UPDATE [SKIP LOCKED] under READ COMMITTED.

Isolation from real data: every test runs in a throwaway schema (search_path), created and
dropped here. The queue functions claim "the oldest QUEUED scan", so running them against the
developer's own tables would claim real scans; the private schema makes that impossible.
Skipped with a reason when DATABASE_URL is unreachable, like the other integration tests.
"""

import threading
import time
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select, text, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.blockchain.anchoring import anchor_scan
from app.blockchain.mock import MockChainProvider
from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode
from app.db.base import Base
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
    assert_owned,
    bind_claim,
    unbind_claim,
)
from app.pipeline.workspace import create_workspace
from app.runner.queue import claim_next_scan, claim_scan, fail_stale_claims
from tests.conftest import make_anchorable_scan

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def pg_factory():
    url = get_settings().database_url
    schema = f"px_own_{uuid.uuid4().hex[:12]}"
    admin = create_engine(url, connect_args={"connect_timeout": 3})
    try:
        with admin.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    except OperationalError as exc:
        admin.dispose()
        pytest.skip(f"PostgreSQL not reachable at DATABASE_URL: {exc.__class__.__name__}")
    engine = create_engine(
        url,
        connect_args={"connect_timeout": 3, "options": f"-csearch_path={schema}"},
        pool_size=12,
        max_overflow=4,
    )
    assert engine.dialect.name == "postgresql"
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    engine.dispose()
    with admin.begin() as conn:
        conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    admin.dispose()


@pytest.fixture(autouse=True)
def _empty_queue(pg_factory):
    with pg_factory() as s:
        s.execute(text("TRUNCATE artifacts CASCADE"))
        s.commit()


def _queued(factory, n=1) -> list[uuid.UUID]:
    ids = []
    with factory() as s:
        for _ in range(n):
            scan = Scan(
                id=uuid.uuid4(),
                artifact=Artifact(
                    artifact_type=ArtifactType.SOFTWARE, name="x", source=ArtifactSource.UPLOAD
                ),
                status=ScanStatus.QUEUED,
                scanner_version="0.1.0",
            )
            s.add(scan)
            ids.append(scan.id)
        s.commit()
    return ids


def _claim(factory, runner="runner-a") -> ScanClaim:
    (sid,) = _queued(factory)
    with factory() as s:
        return claim_scan(s, sid, runner)


def _age_heartbeat(factory, scan_id, seconds=3600):
    with factory() as s:
        s.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(heartbeat_at=utcnow() - timedelta(seconds=seconds))
        )
        s.commit()


def _scan(factory, scan_id) -> Scan:
    with factory() as s:
        return s.get(Scan, scan_id)


# ----------------------------------------------------------------------------- claiming
def test_concurrent_runners_claim_each_scan_exactly_once(pg_factory):
    ids = set(_queued(pg_factory, 40))
    claims: list[ScanClaim] = []
    lock = threading.Lock()
    start = threading.Barrier(6)

    def runner(name):
        start.wait()
        while True:
            with pg_factory() as s:
                got = claim_next_scan(s, name)
            if got is None:
                return
            with lock:
                claims.append(got)

    threads = [threading.Thread(target=runner, args=(f"r{i}",)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(c.scan_id for c in claims) == sorted(ids)
    assert len({c.token for c in claims}) == len(ids)
    with pg_factory() as s:
        rows = s.execute(select(Scan.id, Scan.claim_token, Scan.claimed_by)).all()
    by_id = {c.scan_id: c for c in claims}
    for sid, token, runner_id in rows:
        assert token == by_id[sid].token and runner_id == by_id[sid].runner_id


def test_concurrent_recoverers_recover_each_scan_once(pg_factory):
    claims = [_claim(pg_factory) for _ in range(10)]
    for c in claims:
        _age_heartbeat(pg_factory, c.scan_id)
    results: list[list[uuid.UUID]] = []
    start = threading.Barrier(4)

    def recover():
        start.wait()
        with pg_factory() as s:
            results.append(fail_stale_claims(s, 60))

    threads = [threading.Thread(target=recover) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    recovered = [sid for batch in results for sid in batch]
    assert sorted(recovered) == sorted(c.scan_id for c in claims)  # no duplicates


# ----------------------------------------------------------------------------- lock ordering
def test_recovery_skips_a_scan_whose_owner_is_mid_commit(pg_factory):
    claim = _claim(pg_factory)
    _age_heartbeat(pg_factory, claim.scan_id)  # looks stale, but the owner is committing now
    with pg_factory() as owner:
        bind_claim(owner, claim)
        owner.get(Scan, claim.scan_id).ingest_metadata = {"stage": "sbom"}
        owner.flush()
        assert_owned(owner)  # holds the row lock until commit
        with pg_factory() as recoverer:
            assert fail_stale_claims(recoverer, 60) == []  # SKIP LOCKED
        owner.commit()  # the owner's write lands
        with pg_factory() as recoverer:
            assert fail_stale_claims(recoverer, 60) == [claim.scan_id]
        owner.get(Scan, claim.scan_id).ingest_metadata = {"stage": "late"}
        with pytest.raises(ClaimLost):
            owner.commit()
        owner.rollback()
        unbind_claim(owner)
    scan = _scan(pg_factory, claim.scan_id)
    assert scan.status == ScanStatus.FAILED
    assert scan.ingest_metadata == {"stage": "sbom"}


def test_owner_commit_blocks_on_recovery_then_is_refused(pg_factory):
    claim = _claim(pg_factory)
    outcome: list[object] = []
    with pg_factory() as recoverer:
        scan = recoverer.scalars(
            select(Scan).where(Scan.id == claim.scan_id).with_for_update()
        ).one()
        scan.status = ScanStatus.FAILED
        scan.error_code = str(ErrorCode.RUNNER_INTERRUPTED)
        scan.claim_token = uuid.uuid4()
        recoverer.flush()  # replaced, not yet committed; the row stays locked

        def owner():
            with pg_factory() as s:
                bind_claim(s, claim)
                s.get(Scan, claim.scan_id).ingest_metadata = {"late": True}
                try:
                    s.commit()
                    outcome.append("committed")
                except ClaimLost:
                    s.rollback()
                    outcome.append("claim_lost")
                finally:
                    unbind_claim(s)

        t = threading.Thread(target=owner)
        t.start()
        time.sleep(0.7)
        assert t.is_alive(), "the owner's fenced commit must wait for the row lock"
        recoverer.commit()
    t.join(10)
    assert outcome == ["claim_lost"]
    scan = _scan(pg_factory, claim.scan_id)
    assert scan.status == ScanStatus.FAILED and scan.ingest_metadata is None


# ----------------------------------------------------------------------------- full race
def _decision(sid):
    return RiskDecision(
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


def test_runner_a_finishing_after_runner_b_recovered_changes_nothing(pg_factory, test_settings):
    """Start with A, expire A's claim, recover with B, let A finish, check B's result stands."""
    claim = _claim(pg_factory, "runner-a")
    workspace = create_workspace(test_settings.workspace_root, claim.scan_id)
    in_evidence, release = threading.Event(), threading.Event()
    anchored: list[uuid.UUID] = []

    def ingest(session, scan, ws):
        scan.ingest_metadata = {"files": 1}
        session.commit()

    def evidence(session, sid, ws, ingested):
        in_evidence.set()
        assert release.wait(20)
        session.add(_decision(sid))
        session.commit()  # fenced: refused

    def runner_a():
        with Heartbeat(pg_factory, claim, 0.2):
            lifecycle.run_scan(
                claim.scan_id,
                pg_factory,
                test_settings,
                ingest,
                evidence,
                after_completed=lambda s, sid: anchored.append(sid),
                require_decision=True,
                claim=claim,
            )

    a = threading.Thread(target=runner_a)
    a.start()
    assert in_evidence.wait(20)
    # A's runner "freezes" (e.g. a network partition): age its heartbeat; B recovers.
    _age_heartbeat(pg_factory, claim.scan_id)
    with pg_factory() as b:
        assert fail_stale_claims(b, 60) == [claim.scan_id]
    b_state = _scan(pg_factory, claim.scan_id)
    release.set()
    a.join(30)
    assert not a.is_alive()

    final = _scan(pg_factory, claim.scan_id)
    assert final.status == ScanStatus.FAILED
    assert final.error_code == "runner_interrupted"
    assert (final.claim_token, final.finished_at, final.error_message) == (
        b_state.claim_token,
        b_state.finished_at,
        b_state.error_message,
    )
    assert claim.lost.is_set()
    with pg_factory() as s:
        assert (
            s.scalars(select(RiskDecision).where(RiskDecision.scan_id == claim.scan_id)).first()
            is None
        )
    assert anchored == []
    assert not workspace.root.exists()


def test_heartbeat_keeps_a_long_scan_alive_on_postgres(pg_factory):
    claim = _claim(pg_factory)
    with Heartbeat(pg_factory, claim, 0.2):
        deadline = time.monotonic() + 3.0  # three times the stale window
        while time.monotonic() < deadline:
            with pg_factory() as s:
                assert fail_stale_claims(s, 1) == []
            time.sleep(0.25)
    time.sleep(1.5)
    with pg_factory() as s:
        assert fail_stale_claims(s, 1) == [claim.scan_id]
    assert _scan(pg_factory, claim.scan_id).claim_token != claim.token


# ----------------------------------------------------------------------------- anchoring
def test_old_claim_cannot_anchor_and_current_claim_anchors_once(pg_factory, test_settings):
    chain = MockChainProvider()
    submitted: list[object] = []
    original = chain.submit
    chain.submit = lambda record: submitted.append(record) or original(record)
    with pg_factory() as s:
        scan_id = make_anchorable_scan(s)
        current = uuid.uuid4()
        s.get(Scan, scan_id).claim_token = current
        s.commit()

    with pg_factory() as old:
        bind_claim(old, ScanClaim(scan_id, uuid.uuid4()))
        with pytest.raises(ClaimLost):
            anchor_scan(old, scan_id, chain, test_settings)
        old.rollback()
        unbind_claim(old)
    assert submitted == []
    with pg_factory() as s:
        assert (
            s.scalars(
                select(BlockchainEvidence).where(BlockchainEvidence.scan_id == scan_id)
            ).first()
            is None
        )

    with pg_factory() as owner:
        bind_claim(owner, ScanClaim(scan_id, current))
        assert anchor_scan(owner, scan_id, chain, test_settings).status == "confirmed"
        with pytest.raises(AppError) as again:
            anchor_scan(owner, scan_id, chain, test_settings)
        assert again.value.code == ErrorCode.ANCHOR_ALREADY_EXISTS
        unbind_claim(owner)
    assert len(submitted) == 1

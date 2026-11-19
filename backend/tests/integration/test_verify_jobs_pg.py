"""Verification-job races on a real PostgreSQL (Milestone C1, audit finding M5).

Proves what SQLite cannot: concurrent POSTs collapse onto one job (partial unique index), two
runners never claim the same job (FOR UPDATE SKIP LOCKED), and a runner whose job was recovered
as stale can never store its answer (conditional UPDATE on token + status). Runs in a throwaway
schema; skipped with a reason when DATABASE_URL is unreachable.
"""

import threading
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import sessionmaker

from app.api.blockchain import get_chain_provider
from app.api.scans import get_session_factory
from app.blockchain.anchoring import anchor_scan
from app.blockchain.mock import MockChainProvider
from app.core.config import get_settings
from app.db.base import Base
from app.db.models import VerificationRun, utcnow
from app.main import create_app
from app.schemas.blockchain import VerificationState
from app.verification.jobs import (
    claim_next_verification,
    enqueue,
    fail_stale_verifications,
    finish,
    unknown_response,
)
from tests.conftest import make_anchorable_scan

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def pg_factory():
    url = get_settings().database_url
    schema = f"px_ver_{uuid.uuid4().hex[:12]}"
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
        pool_size=24,
        max_overflow=8,
    )
    assert engine.dialect.name == "postgresql"
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    engine.dispose()
    with admin.begin() as conn:
        conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    admin.dispose()


@pytest.fixture(autouse=True)
def _empty(pg_factory):
    with pg_factory() as s:
        s.execute(text("TRUNCATE artifacts CASCADE"))
        s.commit()


@pytest.fixture
def settings(test_settings):
    return test_settings.model_copy(update={"scan_dispatch": "runner"})


def _anchored(factory, settings, n=1):
    chain = MockChainProvider()
    ids = []
    with factory() as s:
        for _ in range(n):
            scan_id = make_anchorable_scan(s)
            anchor_scan(s, scan_id, chain, settings)
            ids.append(scan_id)
    return ids


def _count(factory, **where):
    with factory() as s:
        stmt = select(func.count()).select_from(VerificationRun)
        for key, value in where.items():
            stmt = stmt.where(getattr(VerificationRun, key) == value)
        return s.scalar(stmt)


def test_the_partial_index_allows_one_active_job_per_scan(pg_factory, settings):
    (scan_id,) = _anchored(pg_factory, settings)
    with pg_factory() as s:
        s.add(VerificationRun(scan_id=scan_id, status="queued", requested_at=utcnow()))
        s.commit()
        s.add(VerificationRun(scan_id=scan_id, status="running", requested_at=utcnow()))
        with pytest.raises(IntegrityError):
            s.commit()
        s.rollback()
        # Finished rows do not count: history may hold any number of them.
        s.add(VerificationRun(scan_id=scan_id, status="completed", requested_at=utcnow()))
        s.add(VerificationRun(scan_id=scan_id, status="failed", requested_at=utcnow()))
        s.commit()


def test_twenty_parallel_posts_make_one_job(pg_factory, settings):
    (scan_id,) = _anchored(pg_factory, settings)
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: pg_factory
    app.dependency_overrides[get_chain_provider] = lambda: None
    client = TestClient(app)
    barrier = threading.Barrier(20)
    answers: list[tuple[int, str]] = []
    lock = threading.Lock()

    def post():
        barrier.wait()
        response = client.post(f"/api/v1/scans/{scan_id}/verify")
        with lock:
            answers.append((response.status_code, response.json().get("job_id")))

    threads = [threading.Thread(target=post) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert {code for code, _ in answers} == {202}
    assert len({job for _, job in answers}) == 1
    assert _count(pg_factory) == 1


def test_two_runners_never_claim_the_same_job(pg_factory, settings):
    scans = _anchored(pg_factory, settings, n=6)
    with pg_factory() as s:
        for scan_id in scans:
            enqueue(s, scan_id, settings)
    claimed: list[uuid.UUID] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def runner(name):
        barrier.wait()
        while True:
            with pg_factory() as s:
                claim = claim_next_verification(s, name)
            if claim is None:
                return
            with lock:
                claimed.append(claim.job_id)

    threads = [threading.Thread(target=runner, args=(f"r{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(claimed) == 6 and len(set(claimed)) == 6
    assert _count(pg_factory, status="running") == 6


def test_an_old_runner_cannot_overwrite_a_recovered_job(pg_factory, settings):
    (scan_id,) = _anchored(pg_factory, settings)
    with pg_factory() as s:
        enqueue(s, scan_id, settings)
        claim = claim_next_verification(s, "old")
        s.execute(
            update(VerificationRun)
            .where(VerificationRun.id == claim.job_id)
            .values(heartbeat_at=utcnow() - timedelta(hours=1))
        )
        s.commit()
    with pg_factory() as s:
        assert fail_stale_verifications(s, 60, 600) == [claim.job_id]
    with pg_factory() as s:
        fake_ok = unknown_response(scan_id, "verified", "forged").model_copy(
            update={"state": VerificationState.VERIFIED}
        )
        assert finish(s, claim, fake_ok) is False
    with pg_factory() as s:
        job = s.get(VerificationRun, claim.job_id)
        assert (job.status, job.state, job.reason_code) == (
            "failed",
            "UNKNOWN",
            "verify_interrupted",
        )


def test_stale_recovery_skips_a_job_locked_by_its_runner(pg_factory, settings):
    (scan_id,) = _anchored(pg_factory, settings)
    with pg_factory() as s:
        enqueue(s, scan_id, settings)
        claim = claim_next_verification(s, "r1")
        s.execute(
            update(VerificationRun)
            .where(VerificationRun.id == claim.job_id)
            .values(heartbeat_at=utcnow() - timedelta(hours=1))
        )
        s.commit()
    holder = pg_factory()
    holder.execute(
        select(VerificationRun).where(VerificationRun.id == claim.job_id).with_for_update()
    )
    try:
        with pg_factory() as s:
            assert fail_stale_verifications(s, 60, 600) == []
    finally:
        holder.rollback()
        holder.close()
    with pg_factory() as s:
        assert fail_stale_verifications(s, 60, 600) == [claim.job_id]


def test_pending_cap_holds_under_concurrency(pg_factory, settings):
    capped = settings.model_copy(update={"verify_max_pending": 3})
    scans = _anchored(pg_factory, capped, n=10)
    results: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(10)

    def post(scan_id):
        barrier.wait()
        try:
            with pg_factory() as s:
                enqueue(s, scan_id, capped)
            outcome = "queued"
        except Exception as exc:  # noqa: BLE001 - the outcome is asserted below
            outcome = getattr(exc, "code", type(exc).__name__)
        with lock:
            results.append(str(outcome))

    threads = [threading.Thread(target=post, args=(s,)) for s in scans]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # The advisory lock serializes count-then-insert: the cap is exact.
    assert results.count("queued") == 3
    assert results.count("verify_queue_full") == 7
    assert _count(pg_factory, status="queued") == 3

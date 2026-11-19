"""Asynchronous /verify (Milestone C1, audit finding M5): the API only queues; the runner answers.

SQLite here; the PostgreSQL concurrency cases are in tests/integration/test_verify_jobs_pg.py.
"""

from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.analysis.base import AnalyzerRun
from app.analysis.reconcile import AnalyzerContainer, OrphanReconciler
from app.api.blockchain import get_chain_provider
from app.api.scans import get_session_factory
from app.blockchain.anchoring import anchor_scan
from app.blockchain.mock import MockChainProvider
from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode
from app.db.models import VerificationRun, utcnow
from app.main import create_app
from app.pipeline.ownership import ClaimLost
from app.sandbox_worker.protocol import WorkerResult
from app.verification.executor import VerifyGuard, run_claimed_verification
from app.verification.jobs import (
    claim_next_verification,
    enqueue,
    fail_stale_verifications,
    finish,
    recover_own_verification_orphans,
    unknown_response,
)
from tests.conftest import make_anchorable_scan, write_scan_evidence


@pytest.fixture
def chain():
    return MockChainProvider()


@pytest.fixture
def runner_settings(test_settings):
    """The deployed dispatch: POST /verify only queues."""
    return test_settings.model_copy(update={"scan_dispatch": "runner"})


@pytest.fixture
def anchored(session_factory, test_settings, chain):
    with session_factory() as session:
        scan_id = make_anchorable_scan(session)
        write_scan_evidence(session, scan_id, test_settings)
        anchor_scan(session, scan_id, chain, test_settings)
    return scan_id


def _client(settings, session_factory, chain):
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    app.dependency_overrides[get_chain_provider] = lambda: chain
    return TestClient(app, raise_server_exceptions=False)


def _job(session_factory, job_id):
    with session_factory() as session:
        return session.get(VerificationRun, job_id)


class _Analyzer:
    """A rehash analyzer stub: returns given digests or raises."""

    name = "stub"

    def __init__(self, *, error=None, digests=None):
        self.error, self.digests, self.calls = error, digests, 0

    def run(self, job, mode):
        self.calls += 1
        assert mode == "rehash"
        if self.error is not None:
            raise self.error
        result = WorkerResult.model_validate(
            {
                "mode": "rehash",
                "status": "ok",
                "isolation_mode": "container",
                "isolation": {},
                "rehash": self.digests,
            }
        )
        return AnalyzerRun(result=result, record={"mode": "rehash", "provider": "stub"})


# --------------------------------------------------------------------------- API
def test_post_queues_a_job_and_reads_nothing(runner_settings, session_factory, chain, anchored):
    client = _client(runner_settings, session_factory, chain)
    posted = client.post(f"/api/v1/scans/{anchored}/verify")
    assert posted.status_code == 202
    body = posted.json()
    assert (body["status"], body["state"], body["result"]) == ("queued", None, None)
    got = client.get(f"/api/v1/scans/{anchored}/verifications/{body['job_id']}")
    assert got.status_code == 200 and got.json()["status"] == "queued"


def test_repeated_posts_reuse_the_active_job(runner_settings, session_factory, chain, anchored):
    client = _client(runner_settings, session_factory, chain)
    ids = {client.post(f"/api/v1/scans/{anchored}/verify").json()["job_id"] for _ in range(5)}
    assert len(ids) == 1


def test_pending_cap_answers_429(runner_settings, session_factory, chain, test_settings):
    settings = runner_settings.model_copy(update={"verify_max_pending": 2})
    client = _client(settings, session_factory, chain)
    scans = []
    with session_factory() as session:
        for _ in range(3):
            scan_id = make_anchorable_scan(session)
            anchor_scan(session, scan_id, chain, test_settings)
            scans.append(scan_id)
    assert [client.post(f"/api/v1/scans/{s}/verify").status_code for s in scans[:2]] == [202, 202]
    refused = client.post(f"/api/v1/scans/{scans[2]}/verify")
    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "verify_queue_full"


def test_a_scan_that_cannot_be_anchored_is_answered_at_once(
    runner_settings, session_factory, chain
):
    with session_factory() as session:
        scan_id = make_anchorable_scan(session, status="failed")
    response = _client(runner_settings, session_factory, chain).post(
        f"/api/v1/scans/{scan_id}/verify"
    )
    assert response.status_code == 200
    body = response.json()
    assert (body["status"], body["state"]) == ("completed", "NOT ANCHORED")
    assert body["result"]["reason"]["code"] == "scan_not_anchorable"


def test_unknown_scan_and_job_are_404(runner_settings, session_factory, chain, anchored):
    client = _client(runner_settings, session_factory, chain)
    assert client.post(f"/api/v1/scans/{uuid4()}/verify").status_code == 404
    missing = client.get(f"/api/v1/scans/{anchored}/verifications/{uuid4()}")
    assert missing.json()["error"]["code"] == "verification_not_found"
    job = client.post(f"/api/v1/scans/{anchored}/verify").json()["job_id"]
    other = client.get(f"/api/v1/scans/{uuid4()}/verifications/{job}")
    assert other.status_code == 404


def test_history_lists_every_job_newest_first(test_settings, session_factory, chain, anchored):
    client = _client(test_settings, session_factory, chain)  # inline: each job finishes
    first = client.post(f"/api/v1/scans/{anchored}/verify").json()["job_id"]
    second = client.post(f"/api/v1/scans/{anchored}/verify").json()["job_id"]
    history = client.get(f"/api/v1/scans/{anchored}/verifications").json()
    assert history["total"] == 2
    assert [item["job_id"] for item in history["items"]] == [second, first]
    assert all(item["state"] == "VERIFIED" for item in history["items"])
    assert all(item["result"]["state"] == "VERIFIED" for item in history["items"])


# --------------------------------------------------------------------------- queue
def test_a_job_is_claimed_once(session_factory, runner_settings, anchored):
    with session_factory() as session:
        enqueue(session, anchored, runner_settings)
        first = claim_next_verification(session, "r1")
        assert first is not None
        assert claim_next_verification(session, "r2") is None
    assert _job(session_factory, first.job_id).status == "running"


def test_finish_is_fenced_on_the_claim(session_factory, runner_settings, anchored):
    with session_factory() as session:
        enqueue(session, anchored, runner_settings)
        claim = claim_next_verification(session, "r1")
        session.execute(
            update(VerificationRun)
            .where(VerificationRun.id == claim.job_id)
            .values(heartbeat_at=utcnow() - timedelta(hours=1))
        )
        session.commit()
        assert fail_stale_verifications(session, 60, 600) == [claim.job_id]
        late = unknown_response(anchored, "verified", "late")
        assert finish(session, claim, late) is False
    job = _job(session_factory, claim.job_id)
    assert (job.status, job.state, job.reason_code) == ("failed", "UNKNOWN", "verify_interrupted")
    assert claim.claim.lost.is_set()


def test_a_job_past_its_ceiling_times_out(session_factory, runner_settings, anchored):
    with session_factory() as session:
        enqueue(session, anchored, runner_settings)
        claim = claim_next_verification(session, "r1")
        session.execute(
            update(VerificationRun)
            .where(VerificationRun.id == claim.job_id)
            .values(started_at=utcnow() - timedelta(hours=1))
        )
        session.commit()
        fail_stale_verifications(session, 60, 600)
    assert _job(session_factory, claim.job_id).reason_code == "verify_timeout"


def test_a_restarted_runner_recovers_its_own_jobs(session_factory, runner_settings, anchored):
    with session_factory() as session:
        enqueue(session, anchored, runner_settings)
        claim = claim_next_verification(session, "runner-a")
        assert recover_own_verification_orphans(session, "runner-b", 0) == []
        assert recover_own_verification_orphans(session, "runner-a", -1) == [claim.job_id]
    job = _job(session_factory, claim.job_id)
    assert (job.state, job.result["state"]) == ("UNKNOWN", "UNKNOWN")


def test_a_new_job_is_allowed_after_one_finishes(session_factory, runner_settings, anchored):
    with session_factory() as session:
        first, _ = enqueue(session, anchored, runner_settings)
        claim = claim_next_verification(session, "r1")
        finish(session, claim, unknown_response(anchored, "x", "y"))
        second, _ = enqueue(session, anchored, runner_settings)
    assert first.id != second.id


# --------------------------------------------------------------------------- executor
def _claimed(session_factory, settings, scan_id):
    with session_factory() as session:
        enqueue(session, scan_id, settings)
        return claim_next_verification(session, "r1")


def _ok_digests(**override):
    digests = {n: {"status": "ok", "sha256": "d" * 64} for n in ("artifact", "bom", "provenance")}
    digests.update(override)
    return digests


@pytest.mark.parametrize(
    "error",
    [
        AppError(ErrorCode.SANDBOX_FAILED, "boom", 502),
        AppError(ErrorCode.SANDBOX_UNAVAILABLE, "no docker", 503),
        AppError(ErrorCode.ANALYZER_OUTPUT_INVALID, "bad", 502),
    ],
)
def test_a_failed_rehash_answers_unknown(session_factory, runner_settings, anchored, chain, error):
    claim = _claimed(session_factory, runner_settings, anchored)
    run_claimed_verification(claim, session_factory, runner_settings, _Analyzer(error=error), chain)
    job = _job(session_factory, claim.job_id)
    assert (job.status, job.state, job.reason_code) == ("completed", "UNKNOWN", "rehash_failed")


def test_changed_digests_answer_mismatch(session_factory, runner_settings, anchored, chain):
    claim = _claimed(session_factory, runner_settings, anchored)
    run_claimed_verification(
        claim, session_factory, runner_settings, _Analyzer(digests=_ok_digests()), chain
    )
    job = _job(session_factory, claim.job_id)
    assert (job.state, job.reason_code) == ("MISMATCH", "evidence_mismatch")
    assert job.sandbox == {"runs": [{"mode": "rehash", "provider": "stub"}]}


def test_an_invalid_file_answers_mismatch(session_factory, runner_settings, anchored, chain):
    claim = _claimed(session_factory, runner_settings, anchored)
    digests = _ok_digests(provenance={"status": "invalid"})
    run_claimed_verification(
        claim, session_factory, runner_settings, _Analyzer(digests=digests), chain
    )
    assert _job(session_factory, claim.job_id).state == "MISMATCH"


def test_an_unexpected_error_fails_the_job_as_unknown(
    session_factory, runner_settings, anchored, chain, monkeypatch
):
    claim = _claimed(session_factory, runner_settings, anchored)

    def explode(*_args, **_kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr("app.verification.executor.verify_scan", explode)
    run_claimed_verification(claim, session_factory, runner_settings, _Analyzer(), chain)
    job = _job(session_factory, claim.job_id)
    assert (job.status, job.state, job.reason_code) == ("failed", "UNKNOWN", "verify_failed")


def test_a_lost_claim_stores_nothing(session_factory, runner_settings, anchored, chain):
    claim = _claimed(session_factory, runner_settings, anchored)
    analyzer = _Analyzer(error=ClaimLost(anchored))
    run_claimed_verification(claim, session_factory, runner_settings, analyzer, chain)
    job = _job(session_factory, claim.job_id)
    assert (job.status, job.state) == ("running", None)


def test_no_anchor_needs_no_rehash(session_factory, runner_settings, chain):
    with session_factory() as session:
        scan_id = make_anchorable_scan(session)  # anchorable but never anchored
    claim = _claimed(session_factory, runner_settings, scan_id)
    analyzer = _Analyzer(error=AssertionError("must not run"))
    run_claimed_verification(claim, session_factory, runner_settings, analyzer, chain)
    assert _job(session_factory, claim.job_id).state == "NOT ANCHORED"
    assert analyzer.calls == 0


# --------------------------------------------------------------------------- guard
class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_guard_fails_a_hung_job_and_exits(session_factory, runner_settings, anchored):
    claim = _claimed(session_factory, runner_settings, anchored)
    settings = runner_settings.model_copy(update={"runner_watchdog_exit_seconds": 0})
    calls, exits, clock = [], [], _Clock()

    def docker(args):
        calls.append(args)
        return 0, b"cid1\n" if args[0] == "ps" else b""

    guard = VerifyGuard(
        session_factory, claim, settings, docker=docker, exit_fn=exits.append, clock=clock
    )
    assert guard.check() is None
    clock.now = settings.verify_max_seconds + 1
    assert "VERIFY_MAX_SECONDS" in guard.check()
    guard.fire(guard.check())
    job = _job(session_factory, claim.job_id)
    assert (job.status, job.reason_code) == ("failed", "verify_timeout")
    assert any(f"io.provenancex.claim={claim.token}" in a for a in calls[0])
    assert ["rm", "--force", "cid1"] in calls
    assert exits == [75]


def test_guard_renews_the_heartbeat(session_factory, runner_settings, anchored):
    claim = _claimed(session_factory, runner_settings, anchored)
    with session_factory() as session:
        session.execute(
            update(VerificationRun)
            .where(VerificationRun.id == claim.job_id)
            .values(heartbeat_at=utcnow() - timedelta(hours=1))
        )
        session.commit()
    guard = VerifyGuard(
        session_factory, claim, runner_settings, docker=lambda a: (0, b""), poll_seconds=0.05
    )
    with guard:
        import time

        time.sleep(0.3)
    with session_factory() as session:
        job = session.scalars(
            select(VerificationRun).where(VerificationRun.id == claim.job_id)
        ).one()
        assert job.heartbeat_at.replace(tzinfo=None) > (utcnow() - timedelta(minutes=1)).replace(
            tzinfo=None
        )


# --------------------------------------------------------------------------- reconcile
def _rehash_container(scan_id, token, state="running"):
    return AnalyzerContainer(
        "cid", f"px-ana-{scan_id}-rehash", state, "i", scan_id, token, "rehash"
    )


def test_reconcile_keeps_a_live_rehash_container_only(session_factory, runner_settings, anchored):
    claim = _claimed(session_factory, runner_settings, anchored)
    reconciler = OrphanReconciler(runner_settings, docker=lambda a: (0, b""))
    with session_factory() as session:
        owners = reconciler._verify_ownership(session, [str(claim.token), "not-a-uuid"])
    assert set(owners) == {str(claim.token)}
    with session_factory() as session:
        finish(session, claim, unknown_response(anchored, "x", "y"))
        owners = reconciler._verify_ownership(session, [str(claim.token)])
    from app.analysis.reconcile import decide

    container = _rehash_container(anchored, str(claim.token))
    assert decide(container, owners[str(claim.token)], utcnow(), 120) == "remove"


def test_a_rehash_contradicting_the_recorded_tree_is_unknown(
    session_factory, runner_settings, anchored, chain
):
    """Same digest as anchored but other counts: the output contradicts itself (audit M4)."""
    from app.db.models import Scan

    with session_factory() as session:
        scan = session.get(Scan, anchored)
        scan.ingest_metadata = {"file_count": 1, "total_bytes": 25}
        session.commit()
        sha = scan.artifact.sha256
    claim = _claimed(session_factory, runner_settings, anchored)
    digests = _ok_digests(
        artifact={"status": "ok", "sha256": sha, "file_count": 7, "total_bytes": 9}
    )
    run_claimed_verification(
        claim, session_factory, runner_settings, _Analyzer(digests=digests), chain
    )
    job = _job(session_factory, claim.job_id)
    assert (job.state, job.reason_code) == ("UNKNOWN", "rehash_inconsistent")

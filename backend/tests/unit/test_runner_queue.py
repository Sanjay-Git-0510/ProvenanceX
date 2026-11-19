"""scan-runner queue: claim order, single claim, stale-claim recovery, dispatch by type."""

import uuid
from datetime import timedelta

from app.db.models import Artifact, ArtifactSource, ArtifactType, Scan, ScanStatus, utcnow
from app.runner import executor
from app.runner.queue import claim, claim_next, fail_stale_claims


def _scan(session, *, status=ScanStatus.QUEUED, created=None, kind=ArtifactType.SOFTWARE):
    scan = Scan(
        id=uuid.uuid4(),
        artifact=Artifact(artifact_type=kind, name="x", source=ArtifactSource.UPLOAD),
        status=status,
        scanner_version="0.1.0",
        created_at=created or utcnow(),
    )
    session.add(scan)
    session.commit()
    return scan.id


def test_claims_oldest_first_and_only_once(session_factory):
    with session_factory() as s:
        newer = _scan(s)
        older = _scan(s, created=utcnow() - timedelta(minutes=5))
        assert claim_next(s) == older
        assert claim_next(s) == newer
        assert claim_next(s) is None
        for sid in (older, newer):
            scan = s.get(Scan, sid)
            assert scan.status == ScanStatus.RUNNING and scan.claimed_at is not None


def test_only_queued_scans_are_claimed(session_factory):
    with session_factory() as s:
        done = _scan(s, status=ScanStatus.COMPLETED)
        assert claim_next(s) is None
        assert claim(s, done) is False
        queued = _scan(s)
        assert claim(s, queued) is True
        assert claim(s, queued) is False


def test_stale_claims_fail_with_a_clear_reason(session_factory):
    with session_factory() as s:
        stale = _scan(s, status=ScanStatus.RUNNING)
        fresh = _scan(s, status=ScanStatus.RUNNING)
        s.get(Scan, stale).claimed_at = utcnow() - timedelta(hours=2)
        s.get(Scan, fresh).claimed_at = utcnow()
        s.commit()
        assert fail_stale_claims(s, 3600) == [stale]
        scan = s.get(Scan, stale)
        assert scan.status == ScanStatus.FAILED and scan.error_code == "runner_interrupted"
        assert "Start a new scan" in scan.error_message
        assert s.get(Scan, fresh).status == ScanStatus.RUNNING


def test_dispatch_by_artifact_type(session_factory, test_settings, monkeypatch):
    seen = []
    monkeypatch.setattr(
        executor, "run_software_ingestion", lambda sid, *a: seen.append(("sw", sid))
    )
    monkeypatch.setattr(executor, "run_model_ingestion", lambda sid, *a: seen.append(("ai", sid)))
    with session_factory() as s:
        sw = _scan(s)
        ds = _scan(s, kind=ArtifactType.DATASET)
    executor.run_claimed_scan(sw, session_factory, test_settings)
    executor.run_claimed_scan(ds, session_factory, test_settings)
    assert seen == [("sw", sw), ("ai", ds)]

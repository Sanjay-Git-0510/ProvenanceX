"""Runs one claimed verification job in the scan-runner. Never raises.

1. The rehash analyzer container (mode `rehash`: network none, read-only mount of the scan's
   workspace, non-root, all limits, self-check, deadline) hashes the kept evidence. It only
   hashes bytes, with O_NOFOLLOW and inode checks, and returns three strictly validated digests.
2. The chain is read and compared by the unchanged logic in app/blockchain/verification.py.
3. The answer is stored with a conditional UPDATE on this runner's claim token.

A `VerifyGuard` thread renews the job's heartbeat and fails the job as UNKNOWN (verify_timeout)
if it runs past VERIFY_MAX_SECONDS or its sandbox step overruns its deadline; it then removes
the job's container and, if the job thread is still stuck, exits the process so Compose
restarts it (the same contract as the scan watchdog, app/runner/watchdog.py).
"""

import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.analysis.base import AnalysisJob, ContentAnalyzer, raise_if_error
from app.analysis.docker_cli import DockerRunner, make_docker_runner
from app.analysis.hardening import LABEL_CLAIM, LABEL_INSTANCE, LABEL_SCAN
from app.blockchain.base import ChainProvider
from app.blockchain.verification import DigestValue, Recomputed, verify_scan
from app.core.config import Settings
from app.core.errors import AppError
from app.db.models import ArtifactType, Scan
from app.pipeline.ownership import ClaimLost, claim_context
from app.pipeline.workspace import open_workspace
from app.runner.watchdog import EXIT_WATCHDOG
from app.sandbox_worker.protocol import DigestOut
from app.verification.jobs import TIMED_OUT, VerifyClaim, fail, finish, renew

logger = logging.getLogger(__name__)

_FIELD_OF = {"artifact": "artifact_hash", "bom": "bom_hash", "provenance": "provenance_hash"}


def _value(digest: DigestOut) -> str | DigestValue:
    if digest.status == "ok" and digest.sha256 is not None:
        return digest.sha256
    if digest.status == "invalid":
        return DigestValue.INVALID
    return DigestValue.UNAVAILABLE


def _counts_consistent(scan: Scan, artifact: DigestOut) -> bool:
    """When the tree digest equals the recorded one, its counts must match too."""
    meta = scan.ingest_metadata or {}
    if artifact.sha256 is None or artifact.sha256 != scan.artifact.sha256:
        return True  # a different digest is a MISMATCH, decided by the comparison
    recorded = (meta.get("file_count"), meta.get("total_bytes"))
    if None in recorded:
        return True  # nothing recorded to compare with
    return recorded == (artifact.file_count, artifact.total_bytes)


def rehash_digests(
    analyzer: ContentAnalyzer, scan: Scan, settings: Settings, records: list[dict[str, Any]]
) -> Recomputed:
    """Recompute the three digests in the rehash sandbox. Sandbox trouble is UNKNOWN, never OK."""
    try:
        workspace = open_workspace(Path(settings.workspace_root), scan.id)
    except AppError:
        return Recomputed(dict.fromkeys(_FIELD_OF.values(), DigestValue.UNAVAILABLE))
    is_software = scan.artifact.artifact_type == ArtifactType.SOFTWARE
    job = AnalysisJob(
        scan_id=scan.id,
        workspace=workspace,
        kind="software" if is_software else "model",
        has_upload=False,
    )
    try:
        run = analyzer.run(job, "rehash")
        records.append(run.record)
        raise_if_error(run)
    except ClaimLost:
        raise
    except AppError as exc:
        logger.warning("Rehash of scan %s failed: %s", scan.id, exc.code)
        return Recomputed.unavailable(
            "rehash_failed", f"The off-chain evidence could not be re-hashed ({exc.code})"
        )
    rehash = run.result.rehash
    if rehash is None:  # guaranteed by WorkerResult for an ok rehash result
        return Recomputed.unavailable("rehash_failed", "The rehash returned no digests")
    if not _counts_consistent(scan, rehash.artifact):
        # Same digest but different counts: the rehash output contradicts itself (audit M4).
        return Recomputed.unavailable(
            "rehash_inconsistent", "The rehash output contradicts the recorded tree; discarded"
        )
    return Recomputed({_FIELD_OF[name]: _value(getattr(rehash, name)) for name in _FIELD_OF})


def run_claimed_verification(
    claim: VerifyClaim,
    session_factory: sessionmaker[Session],
    settings: Settings,
    analyzer: ContentAnalyzer,
    provider: ChainProvider | None,
) -> None:
    def digests(scan: Scan) -> Recomputed:
        return rehash_digests(analyzer, scan, settings, claim.sandbox)

    try:
        with claim_context(claim.claim), session_factory() as session:
            result = verify_scan(session, claim.scan_id, provider, digests)
            session.rollback()  # read-only: release the snapshot before the fenced write
            finish(session, claim, result)
    except ClaimLost:
        logger.warning("Verification job %s lost its claim; no answer stored", claim.job_id)
    except Exception:
        logger.exception("Verification job %s failed", claim.job_id)
        try:
            with session_factory() as session:
                fail(session, claim, "verify_failed", "The verification job failed")
        except SQLAlchemyError:
            logger.exception("Could not record the failure of verification job %s", claim.job_id)


class VerifyGuard:
    """Heartbeat plus watchdog for one verification job (see the module docstring)."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        claim: VerifyClaim,
        settings: Settings,
        *,
        docker: DockerRunner | None = None,
        exit_fn: Callable[[int], None] = os._exit,
        clock: Callable[[], float] = time.monotonic,
        poll_seconds: float | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.claim = claim
        self.settings = settings
        self.grace = settings.runner_watchdog_grace_seconds
        self.docker = docker or make_docker_runner(settings.analyzer_docker_path)
        self.exit_fn = exit_fn
        self.clock = clock
        self.poll = poll_seconds if poll_seconds is not None else settings.runner_heartbeat_seconds
        self.started = clock()
        self.fired: str | None = None
        self._done = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name=f"verify-guard-{claim.job_id}", daemon=True
        )

    def check(self) -> str | None:
        step = self.claim.claim.steps.overdue(self.grace)
        if step is not None:
            return f"sandbox step {step} is past its deadline"
        if self.clock() - self.started > self.settings.verify_max_seconds:
            return "the job exceeded VERIFY_MAX_SECONDS"
        return None

    def _run(self) -> None:
        while not self._done.wait(self.poll):
            if self.claim.claim.lost.is_set():
                return
            reason = self.check()
            if reason is not None:
                self.fire(reason)
                return
            try:
                with self.session_factory() as session:
                    if not renew(session, self.claim):
                        return
            except SQLAlchemyError:
                logger.exception("Heartbeat of verification job %s failed", self.claim.job_id)

    def fire(self, reason: str) -> None:
        self.fired = reason
        logger.error("Verification job %s is hung (%s); failing it", self.claim.job_id, reason)
        try:
            with self.session_factory() as session:
                fail(session, self.claim, *TIMED_OUT)
        except SQLAlchemyError:
            logger.exception("Could not fail verification job %s", self.claim.job_id)
        self.claim.claim.mark_lost()
        self.cleanup()
        if not self._done.wait(self.settings.runner_watchdog_exit_seconds):
            logger.critical("Verification job %s did not unwind; exiting", self.claim.job_id)
            self.exit_fn(EXIT_WATCHDOG)

    def cleanup(self) -> None:
        """Remove only this job's containers (its scan id AND its claim token)."""
        code, raw = self.docker(
            [
                "ps",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"label={LABEL_INSTANCE}={self.settings.analyzer_instance_label}",
                "--filter",
                f"label={LABEL_SCAN}={self.claim.scan_id}",
                "--filter",
                f"label={LABEL_CLAIM}={self.claim.token}",
            ]
        )
        if code == 0:
            for cid in raw.decode("ascii", "replace").split():
                self.docker(["rm", "--force", cid])

    def __enter__(self) -> "VerifyGuard":
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._done.set()
        self._thread.join(timeout=max(5.0, self.poll * 2))


def run_verification_job(
    claim: VerifyClaim,
    session_factory: sessionmaker[Session],
    settings: Settings,
    analyzer: ContentAnalyzer,
    provider: ChainProvider | None,
) -> None:
    """Runner entry point: the guarded job."""
    with VerifyGuard(session_factory, claim, settings):
        run_claimed_verification(claim, session_factory, settings, analyzer, provider)

"""The pipeline's only doors to artifact content: the fetcher and analyzer sandboxes.

Each run (fetch, extract, analyze, persist, and the staging holder) is appended to Scan.sandbox,
so the API shows which isolated runs produced the evidence: provider, image, verified runtime
limits, exit code, duration. Failed runs are recorded too, before the error propagates and
run_scan fails the scan. No path here falls back to downloading or reading on the host.

Staging (audit finding L1): `staging_area` creates the scan's kernel-capped tmpfs volume and the
holder container that keeps it mounted, and removes both when the block ends, whatever happens
inside it (success, AppError, ClaimLost, any exception). The in-process test analyzer has no
staging volume; the workspace's src directory plays that role.
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy.orm import Session

from app.analysis.base import AnalysisJob, AnalyzerRun, ContentAnalyzer, raise_if_error
from app.analysis.staging import DockerStaging
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.db.models import Scan, utcnow
from app.fetch.base import (
    Fetcher,
    FetchJob,
    FetchRun,
    fetch_output_invalid,
    raise_if_fetch_error,
)
from app.pipeline.ownership import current_claim
from app.pipeline.retention import ensure_workspace_room
from app.sandbox_worker.protocol import AnalysisOut, Mode, TreeOut
from app.security.revision import is_commit_sha

logger = logging.getLogger(__name__)


def _record(session: Session, scan: Scan, provider: str, entry: dict[str, Any]) -> None:
    current = dict(scan.sandbox or {})
    runs = list(current.get("runs") or [])
    runs.append({**entry, "finished_at": utcnow().isoformat()})
    scan.sandbox = {**current, "provider": provider, "runs": runs}
    session.commit()


@dataclass(frozen=True)
class Staging:
    """Where this scan's artifact tree lives while it is processed."""

    volume: str | None  # the tmpfs staging volume; None in-process (workspace/src)
    uid: int | None = None
    gid: int | None = None


@contextmanager
def staging_area(
    session: Session, scan: Scan, settings: Settings, analyzer: ContentAnalyzer, job: AnalysisJob
) -> Iterator[Staging]:
    if not getattr(analyzer, "uses_staging", False):
        yield Staging(volume=None)
        return
    claim = current_claim()
    token = str(claim.token) if claim is not None and claim.scan_id == scan.id else "none"
    staging = DockerStaging(settings, engine=session.get_bind())
    try:
        # Docker and the analyzer image first, so a missing sandbox reports exactly that.
        analyzer._preflight()  # type: ignore[attr-defined]  # noqa: SLF001
        uid, gid = analyzer.workspace_owner(job)  # type: ignore[attr-defined]
        volume = staging.create(scan.id, token, uid, gid)
    except AppError as exc:
        _record(
            session,
            scan,
            analyzer.name,
            {
                "mode": "staging",
                "provider": analyzer.name,
                "status": "failed",
                "error_code": str(exc.code),
            },
        )
        raise
    held = replace(job, staging_volume=volume.name)
    try:
        try:
            record = analyzer.start_holder(held)  # type: ignore[attr-defined]
        except AppError as exc:
            _record(
                session,
                scan,
                analyzer.name,
                {
                    "mode": "hold",
                    "provider": analyzer.name,
                    "status": "failed",
                    "error_code": str(exc.code),
                },
            )
            raise
        _record(
            session,
            scan,
            analyzer.name,
            {
                **record,
                "staging": {"volume": volume.name, "size_mb": volume.size_mb, "type": "tmpfs"},
            },
        )
        yield Staging(volume=volume.name, uid=uid, gid=gid)
    finally:
        analyzer.stop_holder(held)  # type: ignore[attr-defined]
        if not staging.remove(volume.name):
            logger.warning("Staging volume %s not removed yet; reconcile will retry", volume.name)


def ensure_staged(analyzer: ContentAnalyzer, job: AnalysisJob) -> None:
    """The holder must still be running, or the tmpfs (and the artifact) is gone."""
    if job.staging_volume and not analyzer.holder_running(job):  # type: ignore[attr-defined]
        raise AppError(
            ErrorCode.SANDBOX_FAILED,
            "The staging holder stopped; the staged artifact is gone and was not analyzed",
            502,
            {"mode": "hold"},
        )


def run_sandboxed(
    session: Session, scan: Scan, analyzer: ContentAnalyzer, job: AnalysisJob, mode: Mode
) -> AnalyzerRun:
    """Run one analyzer mode. Raises AppError (the scan then fails) when no usable result exists."""
    try:
        if mode != "extract":
            ensure_staged(analyzer, job)
        run = analyzer.run(job, mode)
    except AppError as exc:
        _record(
            session,
            scan,
            analyzer.name,
            {
                "mode": mode,
                "provider": analyzer.name,
                "status": "failed",
                "error_code": str(exc.code),
            },
        )
        raise
    _record(session, scan, analyzer.name, {**run.record, "status": run.result.status})
    raise_if_error(run)
    return run


def fetch_artifact(session: Session, scan: Scan, fetcher: Fetcher, job: FetchJob) -> FetchRun:
    """Run the isolated fetcher. Raises AppError (the scan then fails) on any failure."""
    try:
        run = fetcher.run(job)
    except AppError as exc:
        _record(
            session,
            scan,
            fetcher.name,
            {
                "mode": "fetch",
                "provider": fetcher.name,
                "status": "failed",
                "error_code": str(exc.code),
            },
        )
        raise
    entry = {**run.record, "status": run.result.status, "source": job.source}
    if run.result.status == "ok":
        entry["fetched"] = {
            "file_count": run.result.file_count,
            "total_bytes": run.result.total_bytes,
            "commit_sha": run.result.commit_sha,
        }
    else:
        entry["error_code"] = run.result.error.code if run.result.error else None
    _record(session, scan, fetcher.name, entry)
    raise_if_fetch_error(run.result)
    # The fetcher is untrusted (it parsed network data): a pinned commit is checked here too.
    requested = (job.revision or "").lower()
    if is_commit_sha(requested) and len(requested) == len(run.result.commit_sha or ""):
        if run.result.commit_sha != requested:
            raise fetch_output_invalid("the fetched commit differs from the requested commit")
    return run


def extract_upload(
    session: Session, scan: Scan, analyzer: ContentAnalyzer, job: AnalysisJob
) -> None:
    run_sandboxed(session, scan, analyzer, job, "extract")


def analyze_tree(
    session: Session, scan: Scan, analyzer: ContentAnalyzer, job: AnalysisJob
) -> AnalysisOut:
    return run_sandboxed(session, scan, analyzer, job, "analyze").analysis


def persist_tree(
    session: Session,
    scan: Scan,
    analyzer: ContentAnalyzer,
    job: AnalysisJob,
    settings: Settings,
    analyzed: TreeOut,
) -> None:
    """Copy the analyzed tree into the persistent workspace (for /verify) and check it.

    The workspace budget is enforced first (oldest finished scans' trees are pruned), and the
    digest of what was written must equal the digest the analysis reported.
    """
    ensure_workspace_room(session, settings, analyzed.total_bytes, scan.id)
    run = run_sandboxed(session, scan, analyzer, job, "persist")
    persisted = run.result.persisted
    if (
        persisted is None
        or persisted.sha256 != analyzed.sha256
        or (persisted.file_count != analyzed.file_count)
    ):
        raise AppError(
            ErrorCode.DOWNLOAD_INTEGRITY_ERROR,
            "The persisted copy of the artifact does not match the analyzed tree",
            502,
            {"analyzed": analyzed.sha256, "persisted": persisted.sha256 if persisted else None},
        )

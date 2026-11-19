"""The pipeline's only door to artifact content: run the analyzer sandbox and record the run.

Each run (extract, analyze) is appended to Scan.sandbox, so the API shows which isolated runs
produced the evidence: provider, image, verified runtime limits, exit code, duration. Failed
runs are recorded too, before the error propagates and run_scan fails the scan. No path here
falls back to reading the artifact on the host.
"""

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.analysis.base import AnalysisJob, AnalyzerRun, ContentAnalyzer, raise_if_error
from app.core.errors import AppError
from app.db.models import Scan, utcnow
from app.sandbox_worker.protocol import AnalysisOut, Mode

logger = logging.getLogger(__name__)


def _record(session: Session, scan: Scan, provider: str, entry: dict[str, Any]) -> None:
    current = dict(scan.sandbox or {})
    runs = list(current.get("runs") or [])
    runs.append({**entry, "finished_at": utcnow().isoformat()})
    scan.sandbox = {**current, "provider": provider, "runs": runs}
    session.commit()


def run_sandboxed(
    session: Session, scan: Scan, analyzer: ContentAnalyzer, job: AnalysisJob, mode: Mode
) -> AnalyzerRun:
    """Run one analyzer mode. Raises AppError (the scan then fails) when no usable result exists."""
    try:
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


def extract_upload(
    session: Session, scan: Scan, analyzer: ContentAnalyzer, job: AnalysisJob
) -> None:
    run_sandboxed(session, scan, analyzer, job, "extract")


def analyze_tree(
    session: Session, scan: Scan, analyzer: ContentAnalyzer, job: AnalysisJob
) -> AnalysisOut:
    return run_sandboxed(session, scan, analyzer, job, "analyze").analysis

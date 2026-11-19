"""Runs one claimed scan through the pipeline for its artifact type. Never raises.

While the scan runs, a heartbeat thread renews the claim (app/pipeline/ownership.py) and a
watchdog thread (app/runner/watchdog.py) checks that the current sandbox step and the scan as a
whole are still within their deadlines. The pipeline's session is fenced on the claim token, so
if stale recovery or the watchdog replaces the claim, the run stops writing at its next commit.
"""

import logging
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.db.models import ArtifactType, Scan
from app.pipeline.model import run_model_ingestion
from app.pipeline.ownership import Heartbeat, ScanClaim, default_runner_id
from app.pipeline.providers import ScanProviders
from app.pipeline.software import run_software_ingestion
from app.runner.queue import claim_scan
from app.runner.watchdog import Watchdog

logger = logging.getLogger(__name__)


def run_claimed_scan(
    scan_id: UUID,
    session_factory: sessionmaker[Session],
    settings: Settings,
    providers: ScanProviders | None = None,
    claim: ScanClaim | None = None,
) -> None:
    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            logger.error("Claimed scan %s no longer exists", scan_id)
            return
        is_software = scan.artifact.artifact_type == ArtifactType.SOFTWARE
    runner = run_software_ingestion if is_software else run_model_ingestion
    if claim is None:
        runner(scan_id, session_factory, settings, providers)
        return
    with (
        Heartbeat(session_factory, claim, settings.runner_heartbeat_seconds),
        Watchdog(session_factory, claim, settings),
    ):
        runner(scan_id, session_factory, settings, providers, claim)


def run_inline_for_tests(
    scan_id: UUID,
    session_factory: sessionmaker[Session],
    settings: Settings,
    providers: ScanProviders | None = None,
) -> None:
    """SCAN_DISPATCH=inline_test: claim and run one scan in the calling process.

    Settings refuse inline_test outside APP_ENV=test, and the in-process analyzer it relies on
    refuses to run outside pytest, so this can never process artifacts in a deployed API.
    """
    with session_factory() as session:
        claim = claim_scan(session, scan_id, default_runner_id(settings.runner_id))
        if claim is None:
            logger.warning("Scan %s was not QUEUED; not run inline", scan_id)
            return
    run_claimed_scan(scan_id, session_factory, settings, providers, claim)

"""SCAN_DISPATCH=inline_test: answer one verification job in the calling process.

Settings refuse inline_test outside APP_ENV=test, and the in-process analyzer it uses refuses to
run outside pytest, so a deployed API never hashes or reads the chain for a verification.
"""

import logging
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from app.analysis.factory import build_analyzer
from app.blockchain.base import ChainProvider
from app.core.config import Settings
from app.pipeline.ownership import default_runner_id
from app.verification.executor import run_claimed_verification
from app.verification.jobs import claim_next_verification

logger = logging.getLogger(__name__)


def run_inline_verification_for_tests(
    job_id: UUID,
    session_factory: sessionmaker[Session],
    settings: Settings,
    chain: ChainProvider | None,
) -> None:
    with session_factory() as session:
        claim = claim_next_verification(session, default_runner_id(settings.runner_id), job_id)
    if claim is None:
        logger.warning("Verification job %s was not queued; not run inline", job_id)
        return
    run_claimed_verification(claim, session_factory, settings, build_analyzer(settings), chain)

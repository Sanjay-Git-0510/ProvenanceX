"""Blockchain endpoints: anchor a finished scan, read what is stored, and request verification.

POST /verify only queues a job (audit finding M5): the API never reads artifact files, hashes
anything or reads the chain for a verification. The scan-runner answers the job; clients poll
GET /verifications/{job_id}. GET /verifications lists the scan's verification history.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from app.api.scans import SessionFactoryDep, SettingsDep, _get_scan_or_404
from app.blockchain.anchoring import anchor_scan
from app.blockchain.base import ChainProvider
from app.blockchain.encoding import decode_score
from app.core.errors import AppError, ErrorCode
from app.db.models import AnchorStatus, BlockchainEvidence, VerificationRun
from app.pipeline.providers import build_chain_provider
from app.schemas.blockchain import (
    AnchorResult,
    BlockchainRecordResponse,
    StoredAnchorOut,
    VerificationHistory,
    VerificationJob,
    VerificationReason,
    VerificationResponse,
)
from app.verification.jobs import enqueue

router = APIRouter(prefix="/scans", tags=["blockchain"])

STORED_ONLY_NOTE = (
    "Stored data only. This is not a verification result: use POST /verify to compare it with "
    "the chain."
)


def get_chain_provider(settings: SettingsDep) -> ChainProvider | None:
    """Dependency so tests can inject a chain. None means BLOCKCHAIN_PROVIDER=disabled."""
    return build_chain_provider(settings)


ChainDep = Annotated[ChainProvider | None, Depends(get_chain_provider)]


def _stored(row: BlockchainEvidence) -> StoredAnchorOut:
    return StoredAnchorOut(
        status=row.status,
        source=row.source,
        is_mock=row.source == "mock",
        error_code=row.error_code,
        record_hash=row.record_hash,
        artifact_id=row.artifact_id,
        artifact_hash=row.artifact_hash,
        bom_hash=row.bom_hash,
        provenance_hash=row.provenance_hash,
        risk_score=decode_score(row.risk_score_scaled),
        risk_score_scaled=row.risk_score_scaled,
        decision=row.decision,
        scanner_version=row.scanner_version,
        evidence_timestamp=row.evidence_timestamp,
        missing_evidence=[
            name
            for name, value in (
                ("bom_hash", row.bom_hash),
                ("provenance_hash", row.provenance_hash),
            )
            if value is None
        ],
        tx_hash=row.tx_hash,
        block_number=row.block_number,
        block_hash=row.block_hash,
        anchor_index=row.anchor_index,
        chain_id=row.chain_id,
        contract_address=row.contract_address,
        anchored_at=row.anchored_at,
    )


@router.post("/{scan_id}/anchor", response_model=AnchorResult)
def post_anchor(
    scan_id: UUID, session_factory: SessionFactoryDep, settings: SettingsDep, chain: ChainDep
) -> AnchorResult:
    """Anchor a completed scan once. Refusals return a structured error and send nothing."""
    with session_factory() as session:
        return anchor_scan(session, scan_id, chain, settings)


@router.get("/{scan_id}/blockchain", response_model=BlockchainRecordResponse)
def get_blockchain(scan_id: UUID, session_factory: SessionFactoryDep) -> BlockchainRecordResponse:
    """What is stored about this scan's anchor. Makes no claim about the chain."""
    with session_factory() as session:
        _get_scan_or_404(session, scan_id)
        row = session.scalars(
            select(BlockchainEvidence).where(BlockchainEvidence.scan_id == scan_id)
        ).first()
        return BlockchainRecordResponse(
            scan_id=scan_id,
            anchor_recorded=row is not None and row.status == AnchorStatus.CONFIRMED,
            record=_stored(row) if row is not None else None,
            note=STORED_ONLY_NOTE,
        )


def _job(run: VerificationRun) -> VerificationJob:
    finished = run.state is not None and run.reason_code is not None
    return VerificationJob(
        job_id=run.id,
        scan_id=run.scan_id,
        status=run.status,  # type: ignore[arg-type]
        state=run.state if finished else None,  # type: ignore[arg-type]
        reason=(
            VerificationReason(code=run.reason_code or "", message=run.reason_message or "")
            if finished
            else None
        ),
        result=VerificationResponse.model_validate(run.result) if run.result else None,
        requested_at=run.requested_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


@router.post(
    "/{scan_id}/verify",
    status_code=202,
    response_model=VerificationJob,
    responses={200: {"model": VerificationJob}, 429: {"description": "verify_queue_full"}},
)
def post_verify(
    scan_id: UUID, session_factory: SessionFactoryDep, settings: SettingsDep, chain: ChainDep
) -> JSONResponse:
    """Queue a verification of this scan (202), or return its active job (202).

    A scan that can never have an anchor is answered at once with NOT ANCHORED (200).
    """
    with session_factory() as session:
        run, finished = enqueue(session, scan_id, settings)
        body = _job(run)
        job_id = run.id
    if not finished and settings.scan_dispatch == "inline_test":
        # Test suite only (Settings refuse inline_test outside APP_ENV=test); imported lazily so
        # the API never loads the runner in a deployment.
        from app.verification.inline import run_inline_verification_for_tests

        run_inline_verification_for_tests(job_id, session_factory, settings, chain)
    return JSONResponse(status_code=200 if finished else 202, content=body.model_dump(mode="json"))


@router.get("/{scan_id}/verifications/{job_id}", response_model=VerificationJob)
def get_verification(
    scan_id: UUID, job_id: UUID, session_factory: SessionFactoryDep
) -> VerificationJob:
    with session_factory() as session:
        run = session.get(VerificationRun, job_id)
        if run is None or run.scan_id != scan_id:
            _get_scan_or_404(session, scan_id)
            raise AppError(ErrorCode.VERIFICATION_NOT_FOUND, "Verification job not found", 404)
        return _job(run)


@router.get("/{scan_id}/verifications", response_model=VerificationHistory)
def list_verifications(
    scan_id: UUID,
    session_factory: SessionFactoryDep,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> VerificationHistory:
    """The scan's verification history, newest first."""
    with session_factory() as session:
        _get_scan_or_404(session, scan_id)
        where = VerificationRun.scan_id == scan_id
        total = session.scalar(select(func.count()).select_from(VerificationRun).where(where))
        rows = session.scalars(
            select(VerificationRun)
            .where(where)
            .order_by(VerificationRun.requested_at.desc(), VerificationRun.id)
            .limit(limit)
            .offset(offset)
        ).all()
        return VerificationHistory(scan_id=scan_id, items=[_job(r) for r in rows], total=total or 0)

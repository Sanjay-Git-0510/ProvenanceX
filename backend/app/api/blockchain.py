"""Blockchain endpoints: anchor a finished scan, read what is stored, and verify it."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.api.scans import SessionFactoryDep, SettingsDep, _get_scan_or_404
from app.blockchain.anchoring import anchor_scan
from app.blockchain.base import ChainProvider
from app.blockchain.encoding import decode_score
from app.blockchain.verification import verify_scan
from app.db.models import AnchorStatus, BlockchainEvidence
from app.pipeline.providers import build_chain_provider
from app.schemas.blockchain import (
    AnchorResult,
    BlockchainRecordResponse,
    StoredAnchorOut,
    VerificationResponse,
)

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


@router.post("/{scan_id}/verify", response_model=VerificationResponse)
def post_verify(
    scan_id: UUID, session_factory: SessionFactoryDep, settings: SettingsDep, chain: ChainDep
) -> VerificationResponse:
    """Recompute this scan's evidence and compare it with its anchor and the chain."""
    with session_factory() as session:
        return verify_scan(session, scan_id, chain, settings)

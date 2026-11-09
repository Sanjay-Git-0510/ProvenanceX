"""Anchor one finished scan: build its eight fields, apply the refusals, send, and confirm.

A row is written before anything is sent, so a crash after sending leaves evidence of the attempt.
A retry then adopts the matching on-chain anchor instead of sending a second one. An anchored scan
can never be re-anchored here, so changed database values cannot be laundered onto the chain.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.evidence_view import PageRequest, build_evidence
from app.blockchain.base import SOURCE_MOCK, AnchorReceipt, AnchorRecord, ChainProvider
from app.blockchain.encoding import (
    decode_score,
    encode_score,
    missing_evidence,
    record_hash,
    timestamp_seconds,
    validate_artifact_id,
    validate_decision,
    validate_hash,
    validate_optional_hash,
    validate_scanner_version,
)
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.db.models import (
    AnchorStatus,
    BlockchainEvidence,
    RiskDecision,
    Scan,
    ScanStatus,
    utcnow,
)
from app.schemas.blockchain import AnchorResult

logger = logging.getLogger(__name__)

# Evidence is summarized, so one row per section is enough; group counts cover every row.
_ONE_ROW = PageRequest(1, 0)
# A pending row is treated as abandoned after this many send timeouts.
_LEASE_TIMEOUTS = 3
_STATUS_CONFLICT = 409
_STATUS_UNAVAILABLE = 503
_STATUS_INVALID = 422


def _conflict(code: ErrorCode, message: str) -> AppError:
    return AppError(code, message, _STATUS_CONFLICT)


def build_record(session: Session, scan: Scan, provider: ChainProvider) -> AnchorRecord:
    """Build the record from stored evidence, or refuse with a structured error."""
    evidence = build_evidence(session, scan, _ONE_ROW, _ONE_ROW)
    if evidence.scan_status != ScanStatus.COMPLETED:
        raise _conflict(ErrorCode.ANCHOR_SCAN_NOT_COMPLETED, "Only completed scans can be anchored")
    decision = session.scalars(select(RiskDecision).where(RiskDecision.scan_id == scan.id)).first()
    if decision is None:
        raise _conflict(ErrorCode.ANCHOR_NO_DECISION, "The scan has no stored decision")
    if evidence.mock.contains_mock_evidence and provider.source != SOURCE_MOCK:
        raise _conflict(
            ErrorCode.ANCHOR_REFUSED_MOCK_EVIDENCE,
            "Scans containing mock evidence cannot be anchored on the real chain",
        )
    artifact_hash = evidence.hashes.artifact_sha256.value
    if artifact_hash is None:
        raise AppError(
            ErrorCode.ANCHOR_MISSING_ARTIFACT_HASH, "The artifact has no hash", _STATUS_INVALID
        )
    return AnchorRecord(
        artifact_id=validate_artifact_id(evidence.artifact.artifact_id),
        artifact_hash=validate_hash(artifact_hash, "artifact_hash"),
        bom_hash=validate_optional_hash(evidence.hashes.bom_sha256.value, "bom_hash"),
        provenance_hash=validate_optional_hash(
            evidence.hashes.provenance_record_sha256.value, "provenance_hash"
        ),
        risk_score_scaled=encode_score(decision.risk_score),
        decision=validate_decision(decision.decision),
        scanner_version=validate_scanner_version(evidence.scanner_version),
        timestamp=timestamp_seconds(decision.created_at),
    )


def _as_utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def _pending_values(record: AnchorRecord, digest: str, source: str) -> dict[str, Any]:
    return {
        "artifact_id": record.artifact_id,
        "artifact_hash": record.artifact_hash,
        "bom_hash": record.bom_hash,
        "provenance_hash": record.provenance_hash,
        "risk_score_scaled": record.risk_score_scaled,
        "decision": record.decision,
        "scanner_version": record.scanner_version,
        "evidence_timestamp": record.timestamp,
        "record_hash": digest,
        "status": AnchorStatus.PENDING,
        "source": source,
        "reserved_at": utcnow(),
        "error_code": None,
    }


def _in_progress() -> AppError:
    return _conflict(ErrorCode.ANCHOR_IN_PROGRESS, "An anchor is already being sent for this scan")


def _reserve(
    session: Session, scan_id: UUID, values: dict[str, Any], lease: timedelta
) -> BlockchainEvidence:
    """Claim the scan's single row. Concurrent callers lose on the constraint or the guard."""
    row = session.scalars(
        select(BlockchainEvidence).where(BlockchainEvidence.scan_id == scan_id)
    ).first()
    if row is None:
        row = BlockchainEvidence(scan_id=scan_id, **values)
        session.add(row)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise _in_progress() from None
        return row
    if row.status == AnchorStatus.CONFIRMED:
        raise _conflict(ErrorCode.ANCHOR_ALREADY_EXISTS, "This scan is already anchored")
    if row.status == AnchorStatus.PENDING and utcnow() - _as_utc(row.reserved_at) < lease:
        raise _in_progress()
    claimed = session.execute(
        update(BlockchainEvidence)
        .where(
            BlockchainEvidence.id == row.id,
            BlockchainEvidence.status == row.status,
            BlockchainEvidence.reserved_at == row.reserved_at,
        )
        .values(**values)
    )
    if claimed.rowcount != 1:
        session.rollback()
        raise _in_progress()
    session.commit()
    session.refresh(row)
    return row


def _send_or_adopt(provider: ChainProvider, record: AnchorRecord) -> tuple[AnchorReceipt, bool]:
    """Returns the receipt and whether an existing anchor was adopted."""
    existing = provider.anchors(record.artifact_id)
    if existing:
        if len(existing) != 1 or existing[0].record != record:
            raise _conflict(
                ErrorCode.ANCHOR_CONFLICT, "The chain holds a different anchor for this artifact"
            )
        return provider.receipt_for(record.artifact_id, existing[0].index), True
    receipt = provider.submit(record)
    stored = [a for a in provider.anchors(record.artifact_id) if a.index == receipt.anchor_index]
    if len(stored) != 1 or stored[0].record != record:
        raise _conflict(ErrorCode.ANCHOR_CONFLICT, "The anchor read back from the chain differs")
    return receipt, False


def _mark_failed(session: Session, row_id: UUID, code: str) -> None:
    try:
        session.rollback()
        row = session.get(BlockchainEvidence, row_id)
        if row is None:
            logger.error("Anchor row %s vanished while recording failure %s", row_id, code)
            return
        row.status = AnchorStatus.FAILED
        row.error_code = code
        session.commit()
    except SQLAlchemyError:
        logger.exception("Could not record anchor failure %s for row %s", code, row_id)
        session.rollback()


def _confirm(session: Session, row: BlockchainEvidence, receipt: AnchorReceipt) -> None:
    row.status = AnchorStatus.CONFIRMED
    row.tx_hash = receipt.tx_hash
    row.block_number = receipt.block_number
    row.block_hash = receipt.block_hash
    row.anchor_index = receipt.anchor_index
    row.chain_id = receipt.chain_id
    row.contract_address = receipt.contract_address
    row.anchored_at = receipt.anchored_at
    session.commit()


def _result(row: BlockchainEvidence, record: AnchorRecord, adopted: bool) -> AnchorResult:
    return AnchorResult(
        scan_id=row.scan_id,
        artifact_id=record.artifact_id,
        status=row.status,
        source=row.source,
        is_mock=row.source == SOURCE_MOCK,
        record_hash=row.record_hash,
        artifact_hash=record.artifact_hash,
        bom_hash=record.bom_hash,
        provenance_hash=record.provenance_hash,
        risk_score=decode_score(record.risk_score_scaled),
        risk_score_scaled=record.risk_score_scaled,
        decision=record.decision,
        scanner_version=record.scanner_version,
        evidence_timestamp=record.timestamp,
        missing_evidence=missing_evidence(record),
        adopted_existing_anchor=adopted,
        tx_hash=row.tx_hash,
        block_number=row.block_number,
        block_hash=row.block_hash,
        anchor_index=row.anchor_index,
        chain_id=row.chain_id,
        contract_address=row.contract_address,
        anchored_at=row.anchored_at,
    )


def anchor_scan(
    session: Session, scan_id: UUID, provider: ChainProvider | None, settings: Settings
) -> AnchorResult:
    """Anchor a scan. `provider=None` means BLOCKCHAIN_PROVIDER=disabled, and no mock steps in."""
    if provider is None:
        raise AppError(
            ErrorCode.BLOCKCHAIN_DISABLED, "Blockchain anchoring is disabled", _STATUS_UNAVAILABLE
        )
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise AppError(ErrorCode.SCAN_NOT_FOUND, "Scan not found", 404)
    record = build_record(session, scan, provider)
    digest = record_hash(record)
    lease = timedelta(seconds=settings.blockchain_timeout_seconds * _LEASE_TIMEOUTS)
    row = _reserve(session, scan_id, _pending_values(record, digest, provider.source), lease)
    row_id = row.id
    try:
        receipt, adopted = _send_or_adopt(provider, record)
    except AppError as exc:
        _mark_failed(session, row_id, str(exc.code))
        raise
    except Exception:
        logger.exception("Unexpected error while anchoring scan %s", scan_id)
        _mark_failed(session, row_id, ErrorCode.INTERNAL_ERROR)
        raise
    _confirm(session, row, receipt)
    logger.info("Scan %s anchored via %s (index %s)", scan_id, row.source, receipt.anchor_index)
    return _result(row, record, adopted)

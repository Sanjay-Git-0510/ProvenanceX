"""Verify one scan: recompute its evidence and compare it with the anchor and the chain.

VERIFIED means the record has not changed since it was anchored. It does not mean the scanner was
right or the artifact is safe. Chain trouble and missing off-chain files give UNKNOWN, never
VERIFIED. A definite difference gives MISMATCH even when something else could not be checked.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.blockchain.base import AnchorRecord, ChainAnchor, ChainProvider
from app.blockchain.encoding import (
    encode_score,
    record_hash,
    timestamp_seconds,
)
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.core.hashing import sha256_file, tree_digest
from app.db.models import (
    AnchorStatus,
    ArtifactType,
    BlockchainEvidence,
    ProvenanceRecord,
    RiskDecision,
    Scan,
    ScanStatus,
    utcnow,
)
from app.pipeline.aibom_stage import AIBOM_FILENAME
from app.pipeline.provenance_stage import PROVENANCE_FILENAME
from app.pipeline.sbom_stage import SBOM_FILENAME
from app.pipeline.workspace import open_workspace
from app.schemas.blockchain import (
    FieldComparison,
    VerificationReason,
    VerificationResponse,
    VerificationState,
)

logger = logging.getLogger(__name__)

NOTE = (
    "VERIFIED means this record has not changed since it was anchored. It does not show that the "
    "scanner was correct or that the artifact is safe."
)
_NO_CONTRACT = "no_contract"
HASH_FIELDS = ("artifact_hash", "bom_hash", "provenance_hash")


class _Value(Enum):
    """Outcomes that are not values, kept separate so that None can mean "absent"."""

    UNAVAILABLE = "unavailable"
    INVALID = "invalid"


def _public(value: Any) -> Any:
    return None if isinstance(value, _Value) else value


def _file_digest(path: Path) -> str | _Value:
    """A replaced file counts as changed. A file that is simply gone cannot be checked."""
    try:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            return _Value.INVALID
        if not path.exists():
            return _Value.UNAVAILABLE
        return sha256_file(path)
    except OSError as exc:
        logger.warning("Could not read off-chain evidence: %s", type(exc).__name__)
        return _Value.UNAVAILABLE


def _tree_digest(src: Path, max_files: int) -> str | _Value:
    if src.is_symlink():
        return _Value.INVALID
    if not src.is_dir():
        return _Value.UNAVAILABLE
    try:
        return tree_digest(src, max_files=max_files).sha256
    except AppError as exc:
        # Ingestion refuses symlinks and special files, so finding one means the tree changed.
        return _Value.INVALID if exc.code == ErrorCode.UNSAFE_CONTENT else _Value.UNAVAILABLE
    except OSError as exc:
        logger.warning("Could not read the artifact tree: %s", type(exc).__name__)
        return _Value.UNAVAILABLE


def _recompute_hashes(scan: Scan, settings: Settings) -> dict[str, str | _Value]:
    """Digest the off-chain files. Names are fixed here and never read from the database."""
    try:
        workspace = open_workspace(settings.workspace_root, scan.id)
    except AppError:
        return dict.fromkeys(HASH_FIELDS, _Value.UNAVAILABLE)
    is_software = scan.artifact.artifact_type == ArtifactType.SOFTWARE
    bom_name = SBOM_FILENAME if is_software else AIBOM_FILENAME
    return {
        "artifact_hash": _tree_digest(workspace.src_dir, settings.max_artifact_files),
        "bom_hash": _file_digest(workspace.root / bom_name),
        "provenance_hash": _file_digest(workspace.root / PROVENANCE_FILENAME),
    }


@dataclass(frozen=True)
class _Source:
    """Encoded values from the live tables, plus their raw form for display."""

    encoded: dict[str, Any]
    raw: dict[str, Any]


def _encoded(call: Any, value: Any) -> Any:
    try:
        return call(value)
    except (AppError, TypeError, ValueError, OverflowError):
        return _Value.INVALID


def _read_source(session: Session, scan: Scan) -> _Source:
    provenance = session.scalars(
        select(ProvenanceRecord).where(ProvenanceRecord.scan_id == scan.id)
    ).first()
    decision = session.scalars(select(RiskDecision).where(RiskDecision.scan_id == scan.id)).first()
    hashes = {
        "artifact_hash": scan.artifact.sha256,
        "bom_hash": scan.bom_sha256,
        "provenance_hash": provenance.record_sha256 if provenance else None,
    }
    raw = {
        "artifact_id": str(scan.artifact_id),
        **hashes,
        "risk_score": decision.risk_score if decision else None,
        "decision": str(decision.decision) if decision else None,
        "scanner_version": scan.scanner_version,
        "timestamp": decision.created_at.isoformat() if decision else None,
    }
    encoded = {
        "artifact_id": scan.artifact_id,
        **hashes,
        "risk_score": _encoded(encode_score, decision.risk_score) if decision else _Value.INVALID,
        "decision": str(decision.decision) if decision else _Value.INVALID,
        "scanner_version": scan.scanner_version,
        "timestamp": (
            _encoded(timestamp_seconds, decision.created_at) if decision else _Value.INVALID
        ),
    }
    return _Source(encoded, raw)


def _row_values(row: BlockchainEvidence | None) -> dict[str, Any]:
    if row is None:
        return {}
    return {
        "artifact_id": row.artifact_id,
        "artifact_hash": row.artifact_hash,
        "bom_hash": row.bom_hash,
        "provenance_hash": row.provenance_hash,
        "risk_score": row.risk_score_scaled,
        "decision": str(row.decision),
        "scanner_version": row.scanner_version,
        "timestamp": row.evidence_timestamp,
    }


def _chain_values(record: AnchorRecord | None) -> dict[str, Any]:
    if record is None:
        return {}
    return {
        "artifact_id": record.artifact_id,
        "artifact_hash": record.artifact_hash,
        "bom_hash": record.bom_hash,
        "provenance_hash": record.provenance_hash,
        "risk_score": record.risk_score_scaled,
        "decision": record.decision,
        "scanner_version": record.scanner_version,
        "timestamp": record.timestamp,
    }


def _record_digest(values: dict[str, Any]) -> str | _Value:
    if _Value.INVALID in values.values():
        return _Value.INVALID
    if _Value.UNAVAILABLE in values.values():
        return _Value.UNAVAILABLE
    return record_hash(
        AnchorRecord(
            artifact_id=values["artifact_id"],
            artifact_hash=values["artifact_hash"],
            bom_hash=values["bom_hash"],
            provenance_hash=values["provenance_hash"],
            risk_score_scaled=values["risk_score"],
            decision=values["decision"],
            scanner_version=values["scanner_version"],
            timestamp=values["timestamp"],
        )
    )


def _compare(
    stored: Any, source: Any, recomputed: Any, chain: Any, row_known: bool, chain_known: bool
) -> tuple[str, str | None]:
    if _Value.INVALID in (source, recomputed):
        return "mismatch", "A value is invalid or was replaced"
    known = [] if source is _Value.UNAVAILABLE else [source]
    if row_known:
        known.append(stored)
    if chain_known:
        known.append(chain)
    if recomputed is not _Value.UNAVAILABLE:
        known.append(recomputed)
    if any(value != known[0] for value in known):
        return "mismatch", "The values differ"
    if recomputed is _Value.UNAVAILABLE:
        return "unavailable", "The off-chain file could not be read"
    if not chain_known:
        return "unavailable", "The chain value could not be read"
    if not row_known:
        return "unavailable", "No stored anchor exists"
    return "match", None


def _build_fields(
    session: Session,
    scan: Scan,
    row: BlockchainEvidence | None,
    chain_record: AnchorRecord | None,
    settings: Settings,
) -> list[FieldComparison]:
    source = _read_source(session, scan)
    stored = _row_values(row)
    chain = _chain_values(chain_record)
    files = _recompute_hashes(scan, settings)
    row_known, chain_known = row is not None, chain_record is not None
    fields: list[FieldComparison] = []
    recomputed_values = dict(source.encoded)

    for name, encoded in source.encoded.items():
        is_file = name in HASH_FIELDS
        absent = (
            is_file and encoded is None and stored.get(name) is None and chain.get(name) is None
        )
        recomputed = files[name] if is_file and not absent else encoded
        recomputed_values[name] = recomputed
        if absent:
            status, detail = "absent", "This evidence was absent when anchored"
        else:
            status, detail = _compare(
                stored.get(name), encoded, recomputed, chain.get(name), row_known, chain_known
            )
        fields.append(
            FieldComparison(
                field=name,
                stored=_scalar(stored.get(name)),
                source_table=_scalar(source.raw[name]),
                recomputed=_scalar(_public(recomputed)),
                chain=_scalar(chain.get(name)),
                status=status,
                detail=detail,
            )
        )

    digest_source = _record_digest(source.encoded)
    digest_recomputed = _record_digest(recomputed_values)
    digest_chain = record_hash(chain_record) if chain_record else None
    digest_stored = row.record_hash if row else None
    status, detail = _compare(
        digest_stored, digest_source, digest_recomputed, digest_chain, row_known, chain_known
    )
    fields.append(
        FieldComparison(
            field="record_hash",
            stored=digest_stored,
            source_table=_public(digest_source),
            recomputed=_public(digest_recomputed),
            chain=digest_chain,
            status=status,
            detail=detail,
        )
    )
    return fields


def _scalar(value: Any) -> Any:
    return str(value) if isinstance(value, UUID) else value


@dataclass(frozen=True)
class _Context:
    session: Session
    scan: Scan
    row: BlockchainEvidence | None
    provider: ChainProvider | None
    settings: Settings


def _finish(
    context: _Context,
    state: VerificationState,
    code: str,
    message: str,
    chain_record: AnchorRecord | None = None,
) -> VerificationResponse:
    row = context.row
    fields = (
        _build_fields(context.session, context.scan, row, chain_record, context.settings)
        if row is not None or chain_record is not None
        else []
    )
    source = row.source if row else (context.provider.source if context.provider else None)
    return VerificationResponse(
        scan_id=context.scan.id,
        state=state,
        reason=VerificationReason(code=code, message=message),
        source=source,
        is_mock=source == "mock",
        fields=fields,
        missing_evidence=[f.field for f in fields if f.status == "absent"],
        tx_hash=row.tx_hash if row else None,
        block_number=row.block_number if row else None,
        block_hash=row.block_hash if row else None,
        anchor_index=row.anchor_index if row else None,
        chain_id=row.chain_id if row else None,
        contract_address=row.contract_address if row else None,
        verified_at=utcnow(),
        note=NOTE,
    )


def _chain_failure(context: _Context, exc: AppError) -> VerificationResponse:
    details = exc.details if isinstance(exc.details, dict) else {}
    if details.get("reason") == _NO_CONTRACT:
        return _unknown(context, "chain_state_lost", "The contract no longer exists on the chain")
    if exc.code == ErrorCode.CHAIN_UNAVAILABLE:
        return _unknown(context, "chain_unavailable", "The chain could not be reached")
    return _unknown(context, "chain_refused", "The configured chain was refused")


def _unknown(context: _Context, code: str, message: str) -> VerificationResponse:
    return _finish(context, VerificationState.UNKNOWN, code, message)


def _mismatch(
    context: _Context, code: str, message: str, chain_record: AnchorRecord | None = None
) -> VerificationResponse:
    return _finish(context, VerificationState.MISMATCH, code, message, chain_record)


def _not_anchored(context: _Context, code: str, message: str) -> VerificationResponse:
    return _finish(context, VerificationState.NOT_ANCHORED, code, message)


def _verify_confirmed(
    context: _Context, provider: ChainProvider, anchors: list[ChainAnchor]
) -> VerificationResponse:
    row = context.row
    assert row is not None  # noqa: S101 - narrowed by the caller
    if not anchors:
        block_changed = (
            row.block_number is None or provider.block_hash_at(row.block_number) != row.block_hash
        )
        if block_changed:
            return _unknown(context, "chain_state_lost", "The chain no longer holds this history")
        return _mismatch(context, "anchor_missing", "The anchor is missing from an intact chain")
    anchor = anchors[0]
    if len(anchors) != 1:
        return _mismatch(
            context,
            "anchor_count_mismatch",
            "The chain holds more than one anchor for this artifact",
            anchor.record,
        )
    receipt = provider.receipt_for(row.artifact_id, anchor.index)
    if (row.anchor_index, row.tx_hash, row.block_number, row.block_hash) != (
        anchor.index,
        receipt.tx_hash,
        receipt.block_number,
        receipt.block_hash,
    ):
        return _mismatch(
            context, "receipt_mismatch", "The stored receipt differs from the chain", anchor.record
        )
    result = _finish(
        context, VerificationState.VERIFIED, "verified", "Every value matches", anchor.record
    )
    statuses = {field.status for field in result.fields}
    if "mismatch" in statuses:
        changed = [field.field for field in result.fields if field.status == "mismatch"]
        reason = VerificationReason(
            code="evidence_mismatch", message=f"Changed: {', '.join(changed)}"
        )
        return result.model_copy(update={"state": VerificationState.MISMATCH, "reason": reason})
    if "unavailable" in statuses:
        reason = VerificationReason(
            code="offchain_evidence_unavailable",
            message="Off-chain evidence is missing, so the hashes could not all be recomputed",
        )
        return result.model_copy(update={"state": VerificationState.UNKNOWN, "reason": reason})
    return result


def _verify_on_chain(context: _Context, provider: ChainProvider) -> VerificationResponse:
    row = context.row
    artifact_id = row.artifact_id if row else context.scan.artifact_id
    chain_id, address = provider.location()
    anchors = provider.anchors(artifact_id)
    if row is None:
        if anchors:
            return _mismatch(
                context,
                "anchor_without_row",
                "The chain holds an anchor that has no stored record",
                anchors[0].record,
            )
        return _not_anchored(context, "no_anchor", "This scan has not been anchored")
    if row.source != provider.source:
        return _unknown(context, "provider_mismatch", "A different chain provider made this anchor")
    if row.status != AnchorStatus.CONFIRMED:
        if anchors:
            return _unknown(context, "anchor_unconfirmed", "The anchor was never confirmed")
        return _not_anchored(context, "anchor_not_confirmed", "The anchor attempt did not finish")
    if (row.chain_id, row.contract_address) != (chain_id, address):
        return _unknown(context, "contract_changed", "This anchor is on a different contract")
    return _verify_confirmed(context, provider, anchors)


def verify_scan(
    session: Session, scan_id: UUID, provider: ChainProvider | None, settings: Settings
) -> VerificationResponse:
    """Return the verification state. Chain trouble is a state, never an error response."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise AppError(ErrorCode.SCAN_NOT_FOUND, "Scan not found", 404)
    row = session.scalars(
        select(BlockchainEvidence).where(BlockchainEvidence.scan_id == scan_id)
    ).first()
    context = _Context(session, scan, row, provider, settings)
    has_decision = session.scalars(
        select(RiskDecision.id).where(RiskDecision.scan_id == scan_id)
    ).first()
    if row is None and (scan.status != ScanStatus.COMPLETED or has_decision is None):
        return _not_anchored(context, "scan_not_anchorable", "This scan cannot have an anchor")
    if provider is None:
        return _unknown(context, "chain_provider_disabled", "Blockchain anchoring is disabled")
    try:
        return _verify_on_chain(context, provider)
    except AppError as exc:
        return _chain_failure(context, exc)
    except Exception:
        logger.exception("Unexpected error while verifying scan %s", scan_id)
        return _unknown(context, "chain_unavailable", "The chain could not be read")

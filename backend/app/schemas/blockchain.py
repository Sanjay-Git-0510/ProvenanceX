"""API-facing shape of an anchor. CVSS and ML probability are never part of it."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel


class AnchorResult(BaseModel):
    scan_id: UUID
    artifact_id: UUID
    status: str
    source: str
    is_mock: bool
    record_hash: str
    artifact_hash: str
    bom_hash: str | None
    provenance_hash: str | None
    # The ProvenanceX risk score. None means no score was computed, never 0.
    risk_score: float | None
    risk_score_scaled: int | None
    decision: str
    scanner_version: str
    evidence_timestamp: int
    # Evidence that was absent when anchored. An absent hash does not mean clean.
    missing_evidence: list[str]
    adopted_existing_anchor: bool
    tx_hash: str | None
    block_number: int | None
    block_hash: str | None
    anchor_index: int | None
    chain_id: int | None
    contract_address: str | None
    anchored_at: datetime | None


class StoredAnchorOut(BaseModel):
    """The stored anchor row. It says what was recorded, not whether it still holds."""

    status: str
    source: str
    is_mock: bool
    error_code: str | None
    record_hash: str
    artifact_id: UUID
    artifact_hash: str
    bom_hash: str | None
    provenance_hash: str | None
    risk_score: float | None
    risk_score_scaled: int | None
    decision: str
    scanner_version: str
    evidence_timestamp: int
    missing_evidence: list[str]
    tx_hash: str | None
    block_number: int | None
    block_hash: str | None
    anchor_index: int | None
    chain_id: int | None
    contract_address: str | None
    anchored_at: datetime | None


class BlockchainRecordResponse(BaseModel):
    scan_id: UUID
    anchor_recorded: bool
    record: StoredAnchorOut | None
    note: str


class VerificationState(StrEnum):
    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    NOT_ANCHORED = "NOT ANCHORED"
    UNKNOWN = "UNKNOWN"


class VerificationReason(BaseModel):
    code: str
    message: str


class FieldComparison(BaseModel):
    """One field, as held in each place.

    stored: the anchor row. source_table: the live value in the scan's own tables.
    recomputed: a fresh file digest for the three hashes, otherwise the re-encoded live value.
    chain: the value read from the chain. Null means absent or not readable; see status.
    """

    field: str
    stored: Any
    source_table: Any
    recomputed: Any
    chain: Any
    status: Literal["match", "mismatch", "absent", "unavailable"]
    detail: str | None


class VerificationResponse(BaseModel):
    scan_id: UUID
    state: VerificationState
    reason: VerificationReason
    source: str | None
    is_mock: bool
    fields: list[FieldComparison]
    missing_evidence: list[str]
    tx_hash: str | None
    block_number: int | None
    block_hash: str | None
    anchor_index: int | None
    chain_id: int | None
    contract_address: str | None
    verified_at: datetime
    note: str

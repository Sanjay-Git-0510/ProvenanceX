"""API-facing shape of an anchor. CVSS and ML probability are never part of it."""

from datetime import datetime
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

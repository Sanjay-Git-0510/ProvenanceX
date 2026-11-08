"""Provenance API schema (pipeline step 8)."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.db.models import ProvenanceRecord


class ProvenanceCheckOut(BaseModel):
    name: str
    status: str  # pass | fail | unknown | info
    evidence: str
    severity: str | None = None  # ProvenanceX rule severity for failed checks (not CVSS)
    identifier: str | None = None
    data: dict[str, Any] = {}


class ProvenanceOut(BaseModel):
    """Tri-state values: null means "could not be determined", never "no"."""

    source_known: bool
    revision_pinned: bool
    resolved_commit: str | None
    signed: bool | None  # null until signatures are actually verified
    signature_files_present: bool  # detected by name, not verified
    provenance_present: bool  # attestation detected by name, not verified
    hash_changed: bool | None
    previous_scan_id: UUID | None
    lineage_completeness: float | None
    record_sha256: str
    source: str
    is_mock: bool
    checks: list[ProvenanceCheckOut]
    created_at: datetime

    @classmethod
    def from_row(cls, row: ProvenanceRecord) -> "ProvenanceOut":
        return cls(
            source_known=row.source_known,
            revision_pinned=row.revision_pinned,
            resolved_commit=row.resolved_commit,
            signed=row.signed,
            signature_files_present=row.signature_files_present,
            provenance_present=row.provenance_present,
            hash_changed=row.hash_changed,
            previous_scan_id=row.previous_scan_id,
            lineage_completeness=row.lineage_completeness,
            record_sha256=row.record_sha256,
            source=row.source,
            is_mock=row.source == "mock",
            checks=[ProvenanceCheckOut.model_validate(c) for c in row.checks or []],
            created_at=row.created_at,
        )

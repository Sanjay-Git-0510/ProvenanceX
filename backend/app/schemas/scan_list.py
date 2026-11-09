"""The GET /scans response: one bounded, sanitized summary row per scan.

Fields are allowlisted, so file paths, ingest metadata and error details never enter it.
risk_score, decision and confidence are null when no RiskDecision is stored, never 0.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.db.models import ArtifactSource, ArtifactType, RiskVerdict, ScanStatus
from app.schemas.evidence import Page

DEFAULT_SCAN_PAGE = 20
MAX_SCAN_PAGE = 100


class ScanListArtifact(BaseModel):
    name: str
    artifact_type: ArtifactType
    source: ArtifactSource


class ScanListItem(BaseModel):
    scan_id: UUID
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None
    artifact: ScanListArtifact
    decision: RiskVerdict | None
    risk_score: float | None
    confidence: float | None


class ScanListResponse(BaseModel):
    page: Page
    items: list[ScanListItem]

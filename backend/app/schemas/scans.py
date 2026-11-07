"""Scan API schemas, including the normalized artifact record from CLAUDE.md."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.db.models import ArtifactSource, ArtifactType, Scan, ScanStatus


class ScanCreatedResponse(BaseModel):
    scan_id: UUID
    artifact_id: UUID
    status: ScanStatus


class ArtifactRecord(BaseModel):
    """The normalized artifact record. sha256 is the provenancex-tree-v1 content digest."""

    artifact_id: UUID
    name: str
    artifact_type: ArtifactType
    version: str | None
    source: ArtifactSource
    source_url: str | None
    sha256: str | None
    collected_at: datetime | None
    scan_id: UUID


class ManifestOut(BaseModel):
    path: str
    ecosystem: str
    kind: str


class IngestSummary(BaseModel):
    file_count: int
    total_bytes: int
    tree_digest_version: str
    archive_sha256: str | None = None
    commit_sha: str | None = None
    revision_requested: str | None = None
    manifests: list[ManifestOut] = []
    manifests_truncated: bool = False


class ScanErrorOut(BaseModel):
    code: str
    message: str
    details: Any = None


class ScanResponse(BaseModel):
    scan_id: UUID
    status: ScanStatus
    scanner_version: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    artifact: ArtifactRecord
    ingest: IngestSummary | None
    error: ScanErrorOut | None

    @classmethod
    def from_scan(cls, scan: Scan) -> "ScanResponse":
        artifact = scan.artifact
        error = (
            ScanErrorOut(
                code=scan.error_code, message=scan.error_message or "", details=scan.error_details
            )
            if scan.error_code
            else None
        )
        return cls(
            scan_id=scan.id,
            status=scan.status,
            scanner_version=scan.scanner_version,
            created_at=scan.created_at,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            artifact=ArtifactRecord(
                artifact_id=artifact.id,
                name=artifact.name,
                artifact_type=artifact.artifact_type,
                version=artifact.version,
                source=artifact.source,
                source_url=artifact.source_url,
                sha256=artifact.sha256,
                collected_at=artifact.collected_at,
                scan_id=scan.id,
            ),
            ingest=IngestSummary.model_validate(scan.ingest_metadata)
            if scan.ingest_metadata
            else None,
            error=error,
        )

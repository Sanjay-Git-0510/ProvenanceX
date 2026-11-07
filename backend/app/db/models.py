"""ORM models.

Domain tables are added in the phase that first uses them:
Artifact, Scan (Phase 1); Component, Finding, GraphNode, GraphEdge (Phase 2);
ProvenanceRecord (Phase 2/3); RiskDecision (Phase 6); BlockchainEvidence (Phase 7).

Column types are portable (Uuid, JSON->JSONB on PostgreSQL, non-native enums with CHECK
constraints), so the API tests can run on SQLite while production uses PostgreSQL.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

JSONType = JSON().with_variant(JSONB(), "postgresql")


class ArtifactType(StrEnum):
    SOFTWARE = "software"
    MODEL = "model"
    LORA = "lora"
    DATASET = "dataset"
    CONTAINER = "container"


class ArtifactSource(StrEnum):
    GITHUB = "github"
    HUGGINGFACE = "huggingface"
    UPLOAD = "upload"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


def _enum(enum_cls: type[StrEnum], name: str) -> Enum:
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=32,
        values_callable=lambda cls: [member.value for member in cls],
        validate_strings=True,
    )


def utcnow() -> datetime:
    return datetime.now(UTC)


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    artifact_type: Mapped[ArtifactType] = mapped_column(_enum(ArtifactType, "artifact_type"))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[ArtifactSource] = mapped_column(_enum(ArtifactSource, "artifact_source"))
    source_url: Mapped[str | None] = mapped_column(String(2048))
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scans: Mapped[list["Scan"]] = relationship(back_populates="artifact")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    artifact_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[ScanStatus] = mapped_column(
        _enum(ScanStatus, "scan_status"), default=ScanStatus.QUEUED, index=True
    )
    scanner_version: Mapped[str] = mapped_column(String(32))
    revision_requested: Mapped[str | None] = mapped_column(String(255))
    ingest_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    error_details: Mapped[Any | None] = mapped_column(JSONType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    artifact: Mapped[Artifact] = relationship(back_populates="scans")

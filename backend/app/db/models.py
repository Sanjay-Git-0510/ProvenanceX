"""ORM models.

Domain tables are added in the phase that first uses them:
Artifact, Scan (Phase 1); Component, Finding, GraphNode, GraphEdge (Phase 2);
ProvenanceRecord (Phase 3); RiskDecision (Phase 6); BlockchainEvidence (Phase 7).

Column types are portable (Uuid, JSON->JSONB on PostgreSQL, non-native enums with CHECK
constraints), so the API tests can run on SQLite while production uses PostgreSQL.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
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


class FindingCategory(StrEnum):
    VULNERABILITY = "vulnerability"
    STATIC = "static"
    BEHAVIORAL = "behavioral"
    PROVENANCE = "provenance"


class RiskVerdict(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class AnchorStatus(StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
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
    # Per-stage status of the Phase 2+ pipeline (sbom, graph, vulnerabilities, ...).
    # Each entry: {status, provider, source, started_at, finished_at, error, counts, ...}.
    stages: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    # SHA-256 of the raw SBOM document as produced (off-chain file; hash anchored in Phase 7).
    bom_sha256: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    artifact: Mapped[Artifact] = relationship(back_populates="scans")
    components: Mapped[list["Component"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    graph_nodes: Mapped[list["GraphNode"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    graph_edges: Mapped[list["GraphEdge"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    provenance: Mapped["ProvenanceRecord | None"] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    risk_decision: Mapped["RiskDecision | None"] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    blockchain_evidence: Mapped["BlockchainEvidence | None"] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )


class Component(Base):
    """A package/component enumerated from the SBOM (one row per SBOM component per scan)."""

    __tablename__ = "components"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    bom_ref: Mapped[str] = mapped_column(String(2048))
    name: Mapped[str] = mapped_column(String(1024))
    version: Mapped[str | None] = mapped_column(String(512))
    component_type: Mapped[str] = mapped_column(String(32))
    ecosystem: Mapped[str | None] = mapped_column(String(64))
    purl: Mapped[str | None] = mapped_column(String(2048))
    licenses: Mapped[list[str] | None] = mapped_column(JSONType)
    # Which tool produced the record: "syft" or "mock".
    source: Mapped[str] = mapped_column(String(16))
    properties: Mapped[dict[str, Any] | None] = mapped_column(JSONType)

    scan: Mapped[Scan] = relationship(back_populates="components")


class Finding(Base):
    """A piece of evidence. Phase 2 writes category=vulnerability (known advisories).

    cvss_score is the advisory's CVSS base score. It is NOT the ProvenanceX risk score and
    a vulnerable component is not evidence of malicious intent.
    """

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    component_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("components.id", ondelete="SET NULL"), index=True
    )
    category: Mapped[FindingCategory] = mapped_column(
        _enum(FindingCategory, "finding_category"), index=True
    )
    identifier: Mapped[str] = mapped_column(String(128))
    aliases: Mapped[list[str] | None] = mapped_column(JSONType)
    title: Mapped[str | None] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    severity_source: Mapped[str | None] = mapped_column(String(32))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    # Provider that produced the finding: "osv", "nvd" or "mock".
    source: Mapped[str] = mapped_column(String(16), index=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    component: Mapped[Component | None] = relationship()


class GraphNode(Base):
    __tablename__ = "graph_nodes"
    __table_args__ = (UniqueConstraint("scan_id", "node_key", name="uq_graph_nodes_scan_key"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    node_key: Mapped[str] = mapped_column(String(2048))
    node_type: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(String(1024))
    component_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("components.id", ondelete="SET NULL")
    )
    attributes: Mapped[dict[str, Any] | None] = mapped_column(JSONType)

    scan: Mapped[Scan] = relationship(back_populates="graph_nodes")


class GraphEdge(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (Index("ix_graph_edges_scan_source", "scan_id", "source_key"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    source_key: Mapped[str] = mapped_column(String(2048))
    target_key: Mapped[str] = mapped_column(String(2048))
    relation: Mapped[str] = mapped_column(String(32))
    # "sbom" (declared in the SBOM) or "inferred_top_level" (root -> package with no dependents).
    origin: Mapped[str] = mapped_column(String(32))
    attributes: Mapped[dict[str, Any] | None] = mapped_column(JSONType)

    scan: Mapped[Scan] = relationship(back_populates="graph_edges")


class ProvenanceRecord(Base):
    """Provenance/integrity evidence for one scan (pipeline step 8).

    Tri-state booleans: None means "could not be determined", never "no". `signed` stays
    None until signatures are actually verified; detected signature or attestation files
    are reported separately. `record_sha256` is the SHA-256 of the canonical record JSON
    and becomes `provenance_hash` when evidence is anchored (Phase 7).
    """

    __tablename__ = "provenance_records"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True
    )
    source_known: Mapped[bool] = mapped_column(Boolean)
    revision_pinned: Mapped[bool] = mapped_column(Boolean)
    resolved_commit: Mapped[str | None] = mapped_column(String(64))
    signed: Mapped[bool | None] = mapped_column(Boolean)
    signature_files_present: Mapped[bool] = mapped_column(Boolean)
    provenance_present: Mapped[bool] = mapped_column(Boolean)
    hash_changed: Mapped[bool | None] = mapped_column(Boolean)
    previous_scan_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    lineage_completeness: Mapped[float | None] = mapped_column(Float)
    checks: Mapped[list[dict[str, Any]]] = mapped_column(JSONType)
    record_sha256: Mapped[str] = mapped_column(String(64))
    # Producer of the record: "provenancex" (rule checks over collected evidence).
    source: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="provenance")


class RiskDecision(Base):
    """The stored risk result for one scan (pipeline steps 11-18).

    risk_score is NULL when no rule layer could be scored; it is never stored as 0 in that
    case. cvss_max, ml_probability, anomaly_score and risk_score are separate measures.
    """

    __tablename__ = "risk_decisions"
    __table_args__ = (
        CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 1)",
            name="ck_risk_decisions_score_range",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True
    )
    risk_score: Mapped[float | None] = mapped_column(Float)
    rule_only_score: Mapped[float | None] = mapped_column(Float)
    decision: Mapped[RiskVerdict] = mapped_column(_enum(RiskVerdict, "risk_verdict"), index=True)
    decision_basis: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(Float)
    confidence_label: Mapped[str] = mapped_column(String(16))
    cvss_max: Mapped[float | None] = mapped_column(Float)
    ml_status: Mapped[str] = mapped_column(String(16))
    ml_probability: Mapped[float | None] = mapped_column(Float)
    xgb_probability: Mapped[float | None] = mapped_column(Float)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    model_version: Mapped[str | None] = mapped_column(String(128))
    policy_version: Mapped[str] = mapped_column(String(64))
    layer_scores: Mapped[dict[str, Any]] = mapped_column(JSONType)
    # The full assessment, SHAP factors, training-data label and evidence references.
    explanation: Mapped[dict[str, Any]] = mapped_column(JSONType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="risk_decision")


class BlockchainEvidence(Base):
    """What was anchored for one scan, and where (pipeline step 19).

    risk_score_scaled is NULL when no score was computed; it is never stored as 0 in that case.
    A NULL bom_hash or provenance_hash means that evidence was absent. Only a `confirmed` row
    means an anchor exists. Mock rows have source="mock" and no chain fields.
    """

    __tablename__ = "blockchain_evidence"
    __table_args__ = (
        CheckConstraint(
            "risk_score_scaled IS NULL "
            "OR (risk_score_scaled >= 0 AND risk_score_scaled <= 1000000)",
            name="ck_blockchain_evidence_score_range",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True
    )
    artifact_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    artifact_hash: Mapped[str] = mapped_column(String(64))
    bom_hash: Mapped[str | None] = mapped_column(String(64))
    provenance_hash: Mapped[str | None] = mapped_column(String(64))
    risk_score_scaled: Mapped[int | None] = mapped_column(Integer)
    decision: Mapped[RiskVerdict] = mapped_column(_enum(RiskVerdict, "anchored_verdict"))
    scanner_version: Mapped[str] = mapped_column(String(32))
    # UTC seconds of the stored decision: the anchored timestamp, not the block time.
    evidence_timestamp: Mapped[int] = mapped_column(BigInteger)
    # Deterministic hash of the eight fields (app/blockchain/encoding.py). Off-chain only.
    record_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[AnchorStatus] = mapped_column(_enum(AnchorStatus, "anchor_status"))
    # Provider that handled the anchor: "web3" or "mock".
    source: Mapped[str] = mapped_column(String(16))
    error_code: Mapped[str | None] = mapped_column(String(64))
    tx_hash: Mapped[str | None] = mapped_column(String(128))
    block_number: Mapped[int | None] = mapped_column(BigInteger)
    block_hash: Mapped[str | None] = mapped_column(String(66))
    anchor_index: Mapped[int | None] = mapped_column(Integer)
    chain_id: Mapped[int | None] = mapped_column(BigInteger)
    contract_address: Mapped[str | None] = mapped_column(String(42))
    anchored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reserved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="blockchain_evidence")

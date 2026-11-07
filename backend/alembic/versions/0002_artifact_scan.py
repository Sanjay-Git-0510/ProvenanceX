"""Artifact and Scan tables.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-07
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def _enum(name: str, *values: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True, length=32)


def upgrade() -> None:
    op.create_table(
        "artifacts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "artifact_type",
            _enum("artifact_type", "software", "model", "lora", "dataset", "container"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(255), nullable=True),
        sa.Column(
            "source", _enum("artifact_source", "github", "huggingface", "upload"), nullable=False
        ),
        sa.Column("source_url", sa.String(2048), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "artifact_id",
            sa.Uuid(),
            sa.ForeignKey("artifacts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "status",
            _enum("scan_status", "queued", "running", "completed", "failed"),
            nullable=False,
        ),
        sa.Column("scanner_version", sa.String(32), nullable=False),
        sa.Column("revision_requested", sa.String(255), nullable=True),
        sa.Column("ingest_metadata", JSONType, nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("error_details", JSONType, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scans_artifact_id", "scans", ["artifact_id"])
    op.create_index("ix_scans_status", "scans", ["status"])


def downgrade() -> None:
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_artifact_id", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_artifacts_sha256", table_name="artifacts")
    op.drop_table("artifacts")

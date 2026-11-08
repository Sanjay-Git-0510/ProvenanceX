"""Provenance records (pipeline step 8).

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-08
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "provenance_records",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("source_known", sa.Boolean(), nullable=False),
        sa.Column("revision_pinned", sa.Boolean(), nullable=False),
        sa.Column("resolved_commit", sa.String(64), nullable=True),
        sa.Column("signed", sa.Boolean(), nullable=True),
        sa.Column("signature_files_present", sa.Boolean(), nullable=False),
        sa.Column("provenance_present", sa.Boolean(), nullable=False),
        sa.Column("hash_changed", sa.Boolean(), nullable=True),
        sa.Column("previous_scan_id", sa.Uuid(), nullable=True),
        sa.Column("lineage_completeness", sa.Float(), nullable=True),
        sa.Column("checks", JSONType, nullable=False),
        sa.Column("record_sha256", sa.String(64), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_provenance_records_scan_id", "provenance_records", ["scan_id"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_provenance_records_scan_id", table_name="provenance_records")
    op.drop_table("provenance_records")

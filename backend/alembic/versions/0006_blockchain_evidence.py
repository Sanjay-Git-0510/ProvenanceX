"""Blockchain evidence (pipeline step 19).

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "blockchain_evidence",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("artifact_id", sa.Uuid(), nullable=False),
        sa.Column("artifact_hash", sa.String(64), nullable=False),
        sa.Column("bom_hash", sa.String(64), nullable=True),
        sa.Column("provenance_hash", sa.String(64), nullable=True),
        sa.Column("risk_score_scaled", sa.Integer(), nullable=True),
        sa.Column(
            "decision",
            sa.Enum(
                "ALLOW",
                "REVIEW",
                "BLOCK",
                name="anchored_verdict",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("scanner_version", sa.String(32), nullable=False),
        sa.Column("evidence_timestamp", sa.BigInteger(), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "confirmed",
                "failed",
                name="anchor_status",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("tx_hash", sa.String(128), nullable=True),
        sa.Column("block_number", sa.BigInteger(), nullable=True),
        sa.Column("block_hash", sa.String(66), nullable=True),
        sa.Column("anchor_index", sa.Integer(), nullable=True),
        sa.Column("chain_id", sa.BigInteger(), nullable=True),
        sa.Column("contract_address", sa.String(42), nullable=True),
        sa.Column("anchored_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "risk_score_scaled IS NULL "
            "OR (risk_score_scaled >= 0 AND risk_score_scaled <= 1000000)",
            name="ck_blockchain_evidence_score_range",
        ),
    )
    op.create_index("ix_blockchain_evidence_scan_id", "blockchain_evidence", ["scan_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_blockchain_evidence_scan_id", table_name="blockchain_evidence")
    op.drop_table("blockchain_evidence")

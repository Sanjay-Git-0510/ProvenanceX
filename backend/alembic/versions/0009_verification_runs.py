"""Verification jobs (Milestone C1, audit finding M5): POST /verify queues a row here and a
scan-runner answers it. Additive: scans and anchors are untouched, and downgrade only drops the
new table.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
ACTIVE = "status IN ('queued', 'running')"


def upgrade() -> None:
    op.create_table(
        "verification_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Uuid(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=True),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column("reason_message", sa.Text(), nullable=True),
        sa.Column("result", JSONType, nullable=True),
        sa.Column("sandbox", JSONType, nullable=True),
        sa.Column("claim_token", sa.Uuid(), nullable=True),
        sa.Column("claimed_by", sa.String(length=128), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="ck_verification_runs_status",
        ),
        sa.CheckConstraint(
            "state IS NULL OR state IN ('VERIFIED', 'MISMATCH', 'NOT ANCHORED', 'UNKNOWN')",
            name="ck_verification_runs_state",
        ),
    )
    op.create_index("ix_verification_runs_scan_id", "verification_runs", ["scan_id"])
    op.create_index(
        "ix_verification_runs_status_requested", "verification_runs", ["status", "requested_at"]
    )
    # One queued or running job per scan: concurrent POSTs collapse onto one job.
    op.create_index(
        "uq_verification_runs_active_scan",
        "verification_runs",
        ["scan_id"],
        unique=True,
        postgresql_where=sa.text(ACTIVE),
    )


def downgrade() -> None:
    op.drop_index("uq_verification_runs_active_scan", table_name="verification_runs")
    op.drop_index("ix_verification_runs_status_requested", table_name="verification_runs")
    op.drop_index("ix_verification_runs_scan_id", table_name="verification_runs")
    op.drop_table("verification_runs")

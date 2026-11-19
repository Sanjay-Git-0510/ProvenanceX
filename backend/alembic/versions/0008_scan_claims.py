"""Scan claim ownership: claim token, claiming runner and heartbeat (Milestone A.1, M2).

Additive and nullable, so it is safe on a live database: rows claimed before this migration
have no token or heartbeat. Stale recovery falls back to claimed_at for them, and a runner
that claimed under the old code cannot be fenced (it predates fencing), only failed.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("claim_token", sa.Uuid(), nullable=True))
    op.add_column("scans", sa.Column("claimed_by", sa.String(length=128), nullable=True))
    op.add_column("scans", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    # Stale recovery scans RUNNING rows by heartbeat.
    op.create_index("ix_scans_status_heartbeat", "scans", ["status", "heartbeat_at"])


def downgrade() -> None:
    op.drop_index("ix_scans_status_heartbeat", table_name="scans")
    op.drop_column("scans", "heartbeat_at")
    op.drop_column("scans", "claimed_by")
    op.drop_column("scans", "claim_token")

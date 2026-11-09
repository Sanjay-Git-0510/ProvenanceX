"""Risk decisions (pipeline steps 14-18).

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "risk_decisions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("rule_only_score", sa.Float(), nullable=True),
        sa.Column(
            "decision",
            sa.Enum(
                "ALLOW",
                "REVIEW",
                "BLOCK",
                name="risk_verdict",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("decision_basis", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("confidence_label", sa.String(16), nullable=False),
        sa.Column("cvss_max", sa.Float(), nullable=True),
        sa.Column("ml_status", sa.String(16), nullable=False),
        sa.Column("ml_probability", sa.Float(), nullable=True),
        sa.Column("xgb_probability", sa.Float(), nullable=True),
        sa.Column("anomaly_score", sa.Float(), nullable=True),
        sa.Column("model_version", sa.String(128), nullable=True),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("layer_scores", JSONType, nullable=False),
        sa.Column("explanation", JSONType, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 1)",
            name="ck_risk_decisions_score_range",
        ),
    )
    op.create_index("ix_risk_decisions_scan_id", "risk_decisions", ["scan_id"], unique=True)
    op.create_index("ix_risk_decisions_decision", "risk_decisions", ["decision"])


def downgrade() -> None:
    op.drop_index("ix_risk_decisions_decision", table_name="risk_decisions")
    op.drop_index("ix_risk_decisions_scan_id", table_name="risk_decisions")
    op.drop_table("risk_decisions")

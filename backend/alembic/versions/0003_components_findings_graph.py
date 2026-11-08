"""Components, findings, dependency graph; per-stage scan status and SBOM hash.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-08
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("scans", sa.Column("stages", JSONType, nullable=True))
    op.add_column("scans", sa.Column("bom_sha256", sa.String(64), nullable=True))

    op.create_table(
        "components",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("bom_ref", sa.String(2048), nullable=False),
        sa.Column("name", sa.String(1024), nullable=False),
        sa.Column("version", sa.String(512), nullable=True),
        sa.Column("component_type", sa.String(32), nullable=False),
        sa.Column("ecosystem", sa.String(64), nullable=True),
        sa.Column("purl", sa.String(2048), nullable=True),
        sa.Column("licenses", JSONType, nullable=True),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("properties", JSONType, nullable=True),
    )
    op.create_index("ix_components_scan_id", "components", ["scan_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "component_id",
            sa.Uuid(),
            sa.ForeignKey("components.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "category",
            sa.Enum(
                "vulnerability",
                "static",
                "behavioral",
                "provenance",
                name="finding_category",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("identifier", sa.String(128), nullable=False),
        sa.Column("aliases", JSONType, nullable=True),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("severity_source", sa.String(32), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(255), nullable=True),
        sa.Column("cvss_version", sa.String(8), nullable=True),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("details", JSONType, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_component_id", "findings", ["component_id"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_source", "findings", ["source"])

    op.create_table(
        "graph_nodes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("node_key", sa.String(2048), nullable=False),
        sa.Column("node_type", sa.String(32), nullable=False),
        sa.Column("label", sa.String(1024), nullable=False),
        sa.Column(
            "component_id",
            sa.Uuid(),
            sa.ForeignKey("components.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("attributes", JSONType, nullable=True),
        sa.UniqueConstraint("scan_id", "node_key", name="uq_graph_nodes_scan_key"),
    )
    op.create_index("ix_graph_nodes_scan_id", "graph_nodes", ["scan_id"])

    op.create_table(
        "graph_edges",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("source_key", sa.String(2048), nullable=False),
        sa.Column("target_key", sa.String(2048), nullable=False),
        sa.Column("relation", sa.String(32), nullable=False),
        sa.Column("origin", sa.String(32), nullable=False),
        sa.Column("attributes", JSONType, nullable=True),
    )
    op.create_index("ix_graph_edges_scan_id", "graph_edges", ["scan_id"])
    op.create_index("ix_graph_edges_scan_source", "graph_edges", ["scan_id", "source_key"])


def downgrade() -> None:
    op.drop_table("graph_edges")
    op.drop_table("graph_nodes")
    op.drop_table("findings")
    op.drop_table("components")
    op.drop_column("scans", "bom_sha256")
    op.drop_column("scans", "stages")

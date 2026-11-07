"""ORM models.

Domain tables are added in the phase that first uses them:
Artifact, Scan (Phase 1); Component, Finding, GraphNode, GraphEdge (Phase 2);
ProvenanceRecord (Phase 2/3); RiskDecision (Phase 6); BlockchainEvidence (Phase 7).
"""

from app.db.base import Base  # noqa: F401  (re-exported for Alembic)

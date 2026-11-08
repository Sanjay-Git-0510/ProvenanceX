"""Graph API schemas: software dependency graph and AI model-lineage graph."""

from typing import Any
from uuid import UUID

from pydantic import BaseModel


class GraphNodeOut(BaseModel):
    key: str
    node_type: str
    label: str
    component_id: UUID | None
    attributes: dict[str, Any]


class GraphEdgeOut(BaseModel):
    source: str
    target: str
    relation: str
    # dependency: sbom | inferred_top_level | inferred_unreachable
    # lineage: adapter_config | model_card | config | inventory | requirements
    origin: str
    attributes: dict[str, Any] | None = None


class GraphResponse(BaseModel):
    scan_id: UUID
    root_key: str
    graph_kind: str | None  # dependency | lineage (None if the graph stage did not run)
    source: str | None  # syft | aibom | mock
    is_mock: bool
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]
    features: dict[str, Any] | None
    limitations: list[str]
    stage: dict[str, Any] | None

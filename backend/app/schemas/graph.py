"""Dependency graph API schemas."""

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
    origin: str  # sbom | inferred_top_level | inferred_unreachable


class GraphResponse(BaseModel):
    scan_id: UUID
    root_key: str
    source: str | None  # syft | mock (from the SBOM stage)
    is_mock: bool
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]
    features: dict[str, Any] | None
    limitations: list[str]
    stage: dict[str, Any] | None

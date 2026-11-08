"""Pipeline step 6 (software): NetworkX dependency graph, GraphNode/GraphEdge rows."""

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models import GraphEdge, GraphNode, Scan
from app.graph.dependency_graph import build_dependency_graph
from app.pipeline.sbom_stage import SbomStageOutput
from app.pipeline.stages import StageStatus, execute_stage

STAGE = "graph"
_NODE_FIELDS = ("node_type", "label")

_LIMITATIONS = {
    "none": "The SBOM declares no package-to-package edges (e.g. a bare requirements.txt). "
    "Transitive dependencies are unknown: dependencies are never installed or resolved.",
    "partial": "Some packages have no declared dependency edges; transitive data is incomplete.",
}


def run_graph_stage(
    session: Session, scan_id: UUID, sbom: SbomStageOutput, root_label: str
) -> dict[str, Any] | None:
    def body(scan: Scan) -> tuple[dict[str, Any], StageStatus, dict[str, Any]]:
        parsed = sbom.parsed
        dg = build_dependency_graph(
            root_label,
            parsed.components,
            parsed.edges,
            parsed.root_ref,
            project_refs=sbom.root_package_refs,
        )
        for key, data in dg.graph.nodes(data=True):
            session.add(
                GraphNode(
                    scan_id=scan.id,
                    node_key=key,
                    node_type=data["node_type"],
                    label=str(data["label"])[:1024],
                    component_id=sbom.component_ids.get(key),
                    attributes={k: v for k, v in data.items() if k not in _NODE_FIELDS},
                )
            )
        for src, dst, data in dg.graph.edges(data=True):
            session.add(
                GraphEdge(
                    scan_id=scan.id,
                    source_key=src,
                    target_key=dst,
                    relation=data["relation"],
                    origin=data["origin"],
                )
            )
        resolution = dg.features["transitive_resolution"]
        fields: dict[str, Any] = {
            "source": sbom.source,
            "graph_kind": "dependency",
            "edges_source": "sbom",
            "features": dg.features,
            "counts": {
                "nodes": dg.graph.number_of_nodes(),
                "edges": dg.graph.number_of_edges(),
            },
            "limitations": [_LIMITATIONS[resolution]] if resolution in _LIMITATIONS else [],
        }
        return dg.features, StageStatus.COMPLETED, fields

    return execute_stage(session, scan_id, STAGE, body, provider="networkx")

"""Pipeline step 6 (AI/ML): NetworkX model-lineage graph, GraphNode/GraphEdge rows.

It is stored under the same stage name ("graph") and tables as the software dependency
graph, with graph_kind="lineage", so GET /scans/{id}/graph serves both.
"""

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models import GraphEdge, GraphNode, Scan
from app.graph.lineage_graph import build_lineage_graph
from app.pipeline.aibom_stage import AiBomStageOutput
from app.pipeline.stages import StageStatus, execute_stage

STAGE = "graph"
_NODE_FIELDS = ("node_type", "label")
_EDGE_FIELDS = ("relation", "origin")


def run_lineage_stage(
    session: Session,
    scan_id: UUID,
    aibom: AiBomStageOutput,
    root_label: str,
    artifact_type: str,
    repo_id: str | None,
) -> dict[str, Any] | None:
    def body(scan: Scan) -> tuple[dict[str, Any], StageStatus, dict[str, Any]]:
        lg = build_lineage_graph(root_label, artifact_type, aibom.analysis, repo_id)
        component_ids = aibom.vuln_input.component_ids
        for key, data in lg.graph.nodes(data=True):
            session.add(
                GraphNode(
                    scan_id=scan.id,
                    node_key=key[:2048],
                    node_type=data["node_type"],
                    label=str(data["label"])[:1024],
                    component_id=component_ids.get(key),
                    attributes={k: v for k, v in data.items() if k not in _NODE_FIELDS},
                )
            )
        for src, dst, data in lg.graph.edges(data=True):
            session.add(
                GraphEdge(
                    scan_id=scan.id,
                    source_key=src[:2048],
                    target_key=dst[:2048],
                    relation=data["relation"],
                    origin=data["origin"],
                    attributes={k: v for k, v in data.items() if k not in _EDGE_FIELDS} or None,
                )
            )
        limitations = [
            "Lineage is declared by the artifact. Parent models and datasets are not fetched, "
            "so lineage_depth counts declared hops only."
        ]
        if lg.features["file_nodes_truncated"]:
            limitations.append("Only the first file nodes are shown; the inventory is larger.")
        fields: dict[str, Any] = {
            "source": aibom.source,
            "graph_kind": "lineage",
            "edges_source": "aibom",
            "features": lg.features,
            "counts": {
                "nodes": lg.graph.number_of_nodes(),
                "edges": lg.graph.number_of_edges(),
            },
            "limitations": limitations,
        }
        return lg.features, StageStatus.COMPLETED, fields

    return execute_stage(session, scan_id, STAGE, body, provider="networkx")

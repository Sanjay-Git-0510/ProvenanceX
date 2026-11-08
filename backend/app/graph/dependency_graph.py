"""NetworkX dependency graph for software artifacts, plus graph features.

Structure:
- one `artifact` root node (key ROOT_KEY) for the scanned artifact
- one `package` node per SBOM component (key = the component's bom-ref)
- SBOM edges (origin="sbom") exactly as declared in the CycloneDX `dependencies`
- root edges: root dependencies declared in the SBOM are used as-is (origin="sbom").
  Any package that still has no dependent is linked to the root
  (origin="inferred_top_level"). Packages reachable only through a cycle are also
  linked to the root ("inferred_unreachable"), so every package has a depth.

Edge relation: `depends_on` for root -> package, and `transitive_depends_on` for every
package -> package edge (the artifact reaches those through another package).

Honesty about missing data: no dependency is ever installed or resolved. If the SBOM
declares no package -> package edges (for example a bare requirements.txt), then
transitive_resolution="none" and transitive_depth=1 means "unknown beyond direct", not
"has no transitive dependencies".
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import networkx as nx

ROOT_KEY = "artifact:root"
EXACT_BETWEENNESS_MAX_NODES = 2000
BETWEENNESS_SAMPLE_K = 200

_TYPE_MAP = {"container": "container", "machine-learning-model": "model", "data": "dataset"}


class ComponentLike(Protocol):
    bom_ref: str
    name: str
    version: str | None
    component_type: str
    purl: str | None
    ecosystem: str | None


@dataclass
class DependencyGraph:
    graph: nx.DiGraph
    features: dict[str, Any]


def _node_type(component_type: str) -> str:
    return _TYPE_MAP.get(component_type, "package")


def build_dependency_graph(
    root_label: str,
    components: Sequence[ComponentLike],
    edges: Iterable[tuple[str, str]],
    root_ref: str | None = None,
) -> DependencyGraph:
    """Build the graph and compute structural features (vulnerability features come later)."""
    g = nx.DiGraph()
    g.add_node(ROOT_KEY, node_type="artifact", label=root_label)
    for comp in components:
        g.add_node(
            comp.bom_ref,
            node_type=_node_type(comp.component_type),
            label=f"{comp.name}@{comp.version}" if comp.version else comp.name,
            name=comp.name,
            version=comp.version,
            purl=comp.purl,
            ecosystem=comp.ecosystem,
        )
    packages = [c.bom_ref for c in components]

    sbom_pkg_edges = 0
    for src, dst in edges:
        if dst not in g or dst == ROOT_KEY:
            continue
        if src == root_ref and root_ref is not None:
            g.add_edge(ROOT_KEY, dst, relation="depends_on", origin="sbom")
        elif src in g:
            g.add_edge(src, dst, relation="transitive_depends_on", origin="sbom")
            sbom_pkg_edges += 1

    # Packages nobody depends on (root edges count as dependents) are top-level.
    for node in packages:
        if g.in_degree(node) == 0:
            g.add_edge(ROOT_KEY, node, relation="depends_on", origin="inferred_top_level")

    # Packages only reachable through a dependency cycle get a root edge too.
    reachable = nx.descendants(g, ROOT_KEY)
    for node in packages:
        if node not in reachable:
            g.add_edge(ROOT_KEY, node, relation="depends_on", origin="inferred_unreachable")
            reachable |= nx.descendants(g, node) | {node}

    return DependencyGraph(graph=g, features=_structural_features(g, packages, sbom_pkg_edges))


def _structural_features(g: nx.DiGraph, packages: list[str], sbom_pkg_edges: int) -> dict[str, Any]:
    depth = nx.single_source_shortest_path_length(g, ROOT_KEY)
    for node, d in depth.items():
        g.nodes[node]["depth"] = d

    pkg_graph = g.subgraph(packages)
    n = pkg_graph.number_of_nodes()
    degree = nx.degree_centrality(pkg_graph) if n > 1 else dict.fromkeys(packages, 0.0)
    approximate = n > EXACT_BETWEENNESS_MAX_NODES
    if n > 2:
        betweenness = nx.betweenness_centrality(
            pkg_graph,
            k=BETWEENNESS_SAMPLE_K if approximate else None,
            seed=0 if approximate else None,
            normalized=True,
        )
    else:
        betweenness = dict.fromkeys(packages, 0.0)
    for node in packages:
        g.nodes[node]["degree_centrality"] = round(degree.get(node, 0.0), 6)
        g.nodes[node]["betweenness_centrality"] = round(betweenness.get(node, 0.0), 6)
        g.nodes[node]["dependents"] = pkg_graph.in_degree(node)
        g.nodes[node]["dependencies"] = pkg_graph.out_degree(node)

    touched = {u for u, v in pkg_graph.edges} | {v for u, v in pkg_graph.edges}
    if sbom_pkg_edges == 0:
        resolution = "none"
    elif all(p in touched for p in packages):
        resolution = "complete"
    else:
        resolution = "partial"

    pkg_depths = [depth[p] for p in packages if p in depth]
    origins = [d.get("origin") for _, _, d in g.edges(data=True)]
    return {
        "dependency_count": len(packages),
        "direct_dependency_count": sum(1 for d in pkg_depths if d == 1),
        "transitive_dependency_count": sum(1 for d in pkg_depths if d >= 2),
        "transitive_depth": max(pkg_depths, default=0),
        "transitive_resolution": resolution,
        "edge_count": g.number_of_edges(),
        "sbom_edge_count": origins.count("sbom"),
        "inferred_edge_count": len(origins) - origins.count("sbom"),
        "max_degree_centrality": round(max(degree.values(), default=0.0), 6),
        "max_betweenness_centrality": round(max(betweenness.values(), default=0.0), 6),
        "betweenness_approximate": approximate,
        "cycles_present": not nx.is_directed_acyclic_graph(pkg_graph),
        # Filled in by the vulnerability stage. None means "not looked up", not zero.
        "vulnerable_count": None,
        "vulnerability_count": None,
        "cvss_max": None,
    }

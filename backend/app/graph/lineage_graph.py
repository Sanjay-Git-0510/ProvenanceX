"""NetworkX model-lineage graph for AI/ML artifacts, plus lineage features.

Node keys (ROOT_KEY is shared with the dependency graph):
  artifact:root          the scanned model / adapter / dataset
  model:<hub id>         declared base model(s)
  dataset:<hub id>       declared training datasets
  adapter:<dir>          a nested PEFT adapter (an adapter_config.json below the top level)
  file:<path>            weights, config and code files bundled in the artifact
  package:pypi/<name>    runtime dependencies (the same key is the Component bom_ref)

Edges (relation / origin):
  fine_tuned_from  root|adapter -> model   (adapter_config, or a card with an adapter/finetune
                                            relation)
  derived_from     root -> model            (model card, or a weak config _name_or_path hint)
  trained_on       root -> dataset          (model card)
  bundled_with     root -> file|adapter     (inventory)
  requires         root -> package          (requirements.txt / card library_name)

Lineage is what the artifact declares. Parents are not fetched, so lineage_depth counts
only the declared hops. The completeness score is a research heuristic (fraction of the
checks in LINEAGE_CHECKS that pass), not a standard.
"""

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import networkx as nx

from app.graph.dependency_graph import ROOT_KEY
from app.scanners.model.aibom import ModelAnalysis

MAX_FILE_NODES = 300
LINEAGE_CHECKS = (
    "model_card_present",
    "license_declared",
    "base_model_declared",
    "datasets_declared",
    "weights_hash_known",
    "config_present",
)
_FILE_NODE_CATEGORIES = {"weights": "model_file", "config": "configuration", "code": "code"}


@dataclass
class LineageGraph:
    graph: nx.DiGraph
    features: dict[str, Any]


def package_key(name: str) -> str:
    return f"package:pypi/{name}"


def _norm(value: str) -> str:
    return value.strip().lower()


def build_lineage_graph(
    root_label: str, artifact_type: str, analysis: ModelAnalysis, repo_id: str | None = None
) -> LineageGraph:
    g = nx.DiGraph()
    g.add_node(ROOT_KEY, node_type="artifact", label=root_label, artifact_type=artifact_type)

    top_adapter = next((a for a in analysis.adapters if "/" not in a["config"]), None)
    nested = [a for a in analysis.adapters if "/" in a["config"]]
    card_bases = {_norm(b) for b in analysis.card.metadata.get("base_model", [])}

    for ref in analysis.base_models:
        key = f"model:{ref.ref_id}"
        g.add_node(key, node_type="model", label=ref.ref_id, declared_revision=ref.revision)
        # A base declared only by a nested adapter belongs to that adapter, not the root.
        nested_only = (
            ref.origin == "adapter_config"
            and "/" in (ref.declared_by or "")
            and _norm(ref.ref_id) not in card_bases
        )
        if not nested_only:
            g.add_edge(
                ROOT_KEY,
                key,
                relation=ref.relation,
                origin=ref.origin,
                confidence=ref.confidence,
                declared_by=ref.declared_by,
            )

    for adapter in nested:
        adir = str(PurePosixPath(adapter["config"]).parent)
        akey = f"adapter:{adir}"
        g.add_node(akey, node_type="lora_adapter", label=adir, peft_type=adapter.get("peft_type"))
        g.add_edge(ROOT_KEY, akey, relation="bundled_with", origin="inventory")
        base = adapter.get("base_model")
        if isinstance(base, str) and f"model:{base}" in g:
            g.add_edge(
                akey,
                f"model:{base}",
                relation="fine_tuned_from",
                origin="adapter_config",
                confidence="declared",
                declared_by=adapter["config"],
            )

    for ref in analysis.datasets:
        key = f"dataset:{ref.ref_id}"
        g.add_node(key, node_type="dataset", label=ref.ref_id)
        g.add_edge(ROOT_KEY, key, relation="trained_on", origin=ref.origin, confidence="declared")

    file_nodes = 0
    files_truncated = False
    for f in analysis.inventory:
        node_type = _FILE_NODE_CATEGORIES.get(f.category)
        if node_type is None:
            continue
        if file_nodes >= MAX_FILE_NODES:
            files_truncated = True
            break
        key = f"file:{f.path}"
        g.add_node(
            key,
            node_type=node_type,
            label=f.path,
            serialization=f.serialization,
            downloaded=f.downloaded,
            size=f.size,
        )
        g.add_edge(ROOT_KEY, key, relation="bundled_with", origin="inventory")
        file_nodes += 1

    library = analysis.card.metadata.get("library_name")
    declared_names = {r.name for r in analysis.runtime_deps}
    packages: dict[str, str | None] = {}
    for req in analysis.runtime_deps:  # a pinned entry wins over an unpinned duplicate
        packages[req.name] = req.version or packages.get(req.name)
    if isinstance(library, str) and library and library.lower() not in packages:
        packages[library.lower()] = None
    for name, version in sorted(packages.items()):
        key = package_key(name)
        g.add_node(
            key,
            node_type="package",
            label=f"{name}=={version}" if version else name,
            name=name,
            version=version,
            ecosystem="pypi",
            pinned=version is not None,
        )
        origin = "requirements" if name in declared_names else "model_card"
        g.add_edge(ROOT_KEY, key, relation="requires", origin=origin)

    features = _features(g, analysis, repo_id, files_truncated, top_adapter)
    return LineageGraph(graph=g, features=features)


def _suspicious(
    analysis: ModelAnalysis, repo_id: str | None, top_adapter: dict[str, Any] | None
) -> list[dict[str, str]]:
    flags: list[dict[str, str]] = []
    card_bases = {_norm(b) for b in analysis.card.metadata.get("base_model", [])}
    adapter_base = top_adapter.get("base_model") if top_adapter else None
    if isinstance(adapter_base, str) and card_bases and _norm(adapter_base) not in card_bases:
        flags.append(
            {
                "flag": "adapter_base_mismatch",
                "detail": f"adapter_config base {adapter_base!r} is not among the model card "
                f"base_model values {sorted(card_bases)}",
            }
        )
    declared = {_norm(b.ref_id) for b in analysis.base_models if b.confidence == "declared"}
    for ref in analysis.base_models:
        if ref.confidence == "weak" and declared and _norm(ref.ref_id) not in declared:
            flags.append(
                {
                    "flag": "config_parent_mismatch",
                    "detail": f"{ref.declared_by} names {ref.ref_id!r}, which differs from the "
                    "declared base model(s)",
                }
            )
    if repo_id and any(_norm(b.ref_id) == _norm(repo_id) for b in analysis.base_models):
        flags.append({"flag": "self_reference", "detail": "the artifact names itself as parent"})
    if analysis.local_path_references:
        flags.append(
            {
                "flag": "local_path_parent",
                "detail": "a parent is given as a local filesystem path, so lineage cannot be "
                "traced: " + ", ".join(analysis.local_path_references[:3]),
            }
        )
    return flags


def _features(
    g: nx.DiGraph,
    analysis: ModelAnalysis,
    repo_id: str | None,
    files_truncated: bool,
    top_adapter: dict[str, Any] | None,
) -> dict[str, Any]:
    weights = [f for f in analysis.inventory if f.category == "weights"]
    meta = analysis.card.metadata
    checks = {
        "model_card_present": analysis.card.present,
        "license_declared": bool(meta.get("license")),
        "base_model_declared": bool(analysis.base_models),
        "datasets_declared": bool(analysis.datasets),
        "weights_hash_known": bool(weights) and all(f.sha256 or f.remote_sha256 for f in weights),
        "config_present": any(c.valid for c in analysis.configs),
    }
    flags = _suspicious(analysis, repo_id, top_adapter)
    lineage_relations = ("fine_tuned_from", "derived_from", "trained_on")
    lineage_edges = [(u, v) for u, v, d in g.edges(data=True) if d["relation"] in lineage_relations]
    depth = 0
    if lineage_edges:
        sub = g.edge_subgraph(lineage_edges)
        if ROOT_KEY in sub:
            lengths = nx.single_source_shortest_path_length(sub, ROOT_KEY)
            depth = max(lengths.values(), default=0)
    return {
        "graph_kind": "lineage",
        "node_count": g.number_of_nodes(),
        "edge_count": g.number_of_edges(),
        "base_model_count": len(analysis.base_models),
        "dataset_count": len(analysis.datasets),
        "adapter_present": bool(analysis.adapters),
        "adapter_count": len(analysis.adapters),
        "is_adapter": top_adapter is not None,
        "lineage_depth": depth,
        "lineage_checks": checks,
        "lineage_completeness": round(sum(checks.values()) / len(checks), 4),
        "suspicious_lineage": flags,
        "unexpected_parent_or_base_model": any(
            f["flag"] in ("adapter_base_mismatch", "config_parent_mismatch", "self_reference")
            for f in flags
        ),
        "runtime_dependency_count": sum(
            1 for _, d in g.nodes(data=True) if d.get("node_type") == "package"
        ),
        "file_nodes_truncated": files_truncated,
        # Filled in by the vulnerability stage. None means "not looked up", not zero.
        "vulnerable_count": None,
        "vulnerability_count": None,
        "cvss_max": None,
    }

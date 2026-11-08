from dataclasses import dataclass

from app.graph.dependency_graph import ROOT_KEY, build_dependency_graph
from app.scanners.sbom.cyclonedx import parse_cyclonedx
from tests.conftest import FIXTURES


@dataclass
class C:
    bom_ref: str
    name: str
    version: str | None = "1.0"
    component_type: str = "library"
    purl: str | None = None
    ecosystem: str | None = None


def _comps(*refs):
    return [C(r, r) for r in refs]


def _edge_attrs(dg, u, v):
    return dg.graph.edges[u, v]


def test_flat_graph_has_no_transitive_data():
    dg = build_dependency_graph("app", _comps("a", "b"), [])
    f = dg.features
    assert f["dependency_count"] == 2 and f["direct_dependency_count"] == 2
    assert f["transitive_depth"] == 1 and f["transitive_resolution"] == "none"
    assert f["inferred_edge_count"] == 2 and f["sbom_edge_count"] == 0
    assert _edge_attrs(dg, ROOT_KEY, "a") == {
        "relation": "depends_on",
        "origin": "inferred_top_level",
    }
    # vulnerability features are unknown until the vulnerability stage fills them
    assert f["vulnerable_count"] is None and f["cvss_max"] is None


def test_chain_depth_relations_and_centrality():
    # app -> a -> b -> c ; a -> c
    dg = build_dependency_graph("app", _comps("a", "b", "c"), [("a", "b"), ("b", "c"), ("a", "c")])
    f = dg.features
    assert f["transitive_depth"] == 2  # c is reachable at depth 2 via a -> c
    assert f["direct_dependency_count"] == 1 and f["transitive_dependency_count"] == 2
    assert f["transitive_resolution"] == "complete"
    assert _edge_attrs(dg, "a", "b")["relation"] == "transitive_depends_on"
    assert _edge_attrs(dg, ROOT_KEY, "a")["relation"] == "depends_on"
    assert dg.graph.nodes["c"]["depth"] == 2
    assert dg.graph.nodes["c"]["dependents"] == 2
    # b is not on a shortest path (a -> c is direct); in a pure chain it is.
    assert dg.graph.nodes["b"]["betweenness_centrality"] == 0
    chain = build_dependency_graph("app", _comps("a", "b", "c"), [("a", "b"), ("b", "c")])
    assert chain.graph.nodes["b"]["betweenness_centrality"] > 0
    assert f["cycles_present"] is False


def test_partial_resolution_when_some_packages_have_no_edges():
    dg = build_dependency_graph("app", _comps("a", "b", "lonely"), [("a", "b")])
    assert dg.features["transitive_resolution"] == "partial"


def test_cycle_only_component_attached_to_root():
    dg = build_dependency_graph("app", _comps("x", "y"), [("x", "y"), ("y", "x")])
    f = dg.features
    assert f["cycles_present"] is True
    origins = {d["origin"] for _, _, d in dg.graph.out_edges(ROOT_KEY, data=True)}
    assert origins == {"inferred_unreachable"}
    assert dg.graph.out_degree(ROOT_KEY) == 1  # one attachment makes the whole cycle reachable
    assert all("depth" in dg.graph.nodes[n] for n in ("x", "y"))


def test_declared_root_edges_used():
    dg = build_dependency_graph(
        "app", _comps("a", "b", "orphan"), [("ROOT", "a"), ("a", "b")], root_ref="ROOT"
    )
    assert _edge_attrs(dg, ROOT_KEY, "a")["origin"] == "sbom"
    assert _edge_attrs(dg, ROOT_KEY, "orphan")["origin"] == "inferred_top_level"
    assert not dg.graph.has_edge(ROOT_KEY, "b")


def test_empty_sbom():
    dg = build_dependency_graph("app", [], [])
    assert dg.features["dependency_count"] == 0 and dg.features["transitive_depth"] == 0
    assert list(dg.graph.nodes) == [ROOT_KEY]


def test_node_types_and_labels():
    comps = [
        C("img", "alpine", "3.19", "container"),
        C("m", "bert", None, "machine-learning-model"),
    ]
    dg = build_dependency_graph("app", comps, [])
    assert dg.graph.nodes["img"]["node_type"] == "container"
    assert dg.graph.nodes["img"]["label"] == "alpine@3.19"
    assert dg.graph.nodes["m"]["node_type"] == "model" and dg.graph.nodes["m"]["label"] == "bert"
    assert dg.graph.nodes[ROOT_KEY]["node_type"] == "artifact"


def test_real_syft_npm_graph():
    parsed = parse_cyclonedx(
        (FIXTURES / "sbom" / "syft_npm_lock.cdx.json").read_bytes(),
        max_bytes=10**7,
        max_components=100,
    )
    dg = build_dependency_graph("demo", parsed.components, parsed.edges, parsed.root_ref)
    f = dg.features
    assert f["dependency_count"] == 4
    assert f["transitive_depth"] == 3  # demo-app -> express -> body-parser -> qs
    assert f["transitive_resolution"] == "complete"
    assert f["sbom_edge_count"] == 4


def test_large_graph_uses_approximate_betweenness():
    n = 2100
    comps = _comps(*[f"p{i}" for i in range(n)])
    edges = [(f"p{i}", f"p{i + 1}") for i in range(n - 1)]
    f = build_dependency_graph("app", comps, edges).features
    assert f["betweenness_approximate"] is True
    assert f["transitive_depth"] == n

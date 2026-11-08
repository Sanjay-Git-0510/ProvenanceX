"""Root-package cleanup: the scanned project's own package is the artifact root."""

import json
from dataclasses import dataclass

import pytest

from app.graph.dependency_graph import ROOT_KEY, build_dependency_graph
from app.pipeline.sbom_stage import SbomStageOutput, match_project_packages
from app.pipeline.vuln_stage import build_queries
from app.scanners.manifests import (
    MAX_PROJECT_MANIFEST_BYTES,
    ProjectPackage,
    detect_project_packages,
    normalize_package_name,
)
from app.scanners.sbom.cyclonedx import ParsedComponent, ParsedSbom
from tests.model_helpers import write


def component(ref, name, version="1.0.0", ecosystem="npm", purl="auto") -> ParsedComponent:
    if purl == "auto":
        purl = f"pkg:{ecosystem}/{name}@{version}"
    return ParsedComponent(
        bom_ref=ref,
        name=name,
        version=version,
        component_type="library",
        purl=purl,
        ecosystem=ecosystem,
        licenses=(),
        cpe=None,
        found_by="test",
        locations=(),
    )


# ------------------------------------------------------------------ detection
def test_package_json(tmp_path):
    write(tmp_path / "package.json", json.dumps({"name": "demo-app", "version": "1.2.3"}))
    assert detect_project_packages(tmp_path) == [
        ProjectPackage("npm", "demo-app", "1.2.3", "package.json")
    ]


def test_package_json_without_version(tmp_path):
    write(tmp_path / "package.json", json.dumps({"name": "demo"}))
    assert detect_project_packages(tmp_path)[0].version is None


def test_pyproject_project_table(tmp_path):
    write(tmp_path / "pyproject.toml", '[project]\nname = "my_pkg"\nversion = "0.1"\n')
    assert detect_project_packages(tmp_path) == [
        ProjectPackage("pypi", "my_pkg", "0.1", "pyproject.toml")
    ]


def test_pyproject_poetry_table(tmp_path):
    write(tmp_path / "pyproject.toml", '[tool.poetry]\nname = "poet"\nversion = "2.0"\n')
    assert detect_project_packages(tmp_path)[0].name == "poet"


def test_project_table_wins_over_poetry(tmp_path):
    write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "real"\n[tool.poetry]\nname = "other"\n',
    )
    assert [p.name for p in detect_project_packages(tmp_path)] == ["real"]


def test_both_manifests_are_reported(tmp_path):
    write(tmp_path / "package.json", json.dumps({"name": "js"}))
    write(tmp_path / "pyproject.toml", '[project]\nname = "py"\n')
    assert {(p.ecosystem, p.name) for p in detect_project_packages(tmp_path)} == {
        ("npm", "js"),
        ("pypi", "py"),
    }


def test_only_top_level_manifests_count(tmp_path):
    write(tmp_path / "packages/inner/package.json", json.dumps({"name": "inner"}))
    assert detect_project_packages(tmp_path) == []


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("package.json", "{not json"),
        ("package.json", "[1, 2]"),
        ("package.json", json.dumps({"name": 7})),
        ("package.json", json.dumps({"name": "   "})),
        ("package.json", "[" * 100_000),
        ("package.json", b"\xff\xfe\x00bad"),
        ("pyproject.toml", "not = = toml"),
        ("pyproject.toml", b"\xff\xfe\x00bad"),
        ("pyproject.toml", "[tool]\nother = 1\n"),
        ("pyproject.toml", 'project = "a string"\n'),
        ("pyproject.toml", '[project]\nname = ["x"]\n'),
    ],
)
def test_malformed_manifests_are_ignored(tmp_path, name, content):
    write(tmp_path / name, content)
    assert detect_project_packages(tmp_path) == []


def test_oversized_manifest_is_ignored(tmp_path):
    padding = " " * (MAX_PROJECT_MANIFEST_BYTES + 1)
    write(tmp_path / "package.json", '{"name": "x"}' + padding)
    assert detect_project_packages(tmp_path) == []


def test_symlinked_manifest_is_not_followed(tmp_path):
    outside = write(tmp_path / "outside" / "package.json", json.dumps({"name": "stolen"}))
    root = tmp_path / "repo"
    root.mkdir()
    (root / "package.json").symlink_to(outside)
    assert detect_project_packages(root) == []


def test_long_names_are_bounded(tmp_path):
    write(tmp_path / "package.json", json.dumps({"name": "x" * 1000}))
    assert len(detect_project_packages(tmp_path)[0].name) == 255


# ------------------------------------------------------------------ matching
@pytest.mark.parametrize(
    ("ecosystem", "name", "expected"),
    [
        ("pypi", "My_Package.Name", "my-package-name"),
        ("pypi", "a--b__c", "a-b-c"),
        ("npm", "@Scope/My_Pkg", "@scope/my_pkg"),
        (None, "ABC", "abc"),
    ],
)
def test_normalize(ecosystem, name, expected):
    assert normalize_package_name(ecosystem, name) == expected


def test_match_same_name_and_version():
    comps = [component("r", "demo-app"), component("d", "dep")]
    project = ProjectPackage("npm", "demo-app", "1.0.0", "package.json")
    assert match_project_packages(comps, [project]) == frozenset({"r"})


def test_match_applies_pep503_normalization():
    comps = [component("r", "my-pkg", "0.1", "pypi")]
    project = ProjectPackage("pypi", "My_Pkg", "0.1", "pyproject.toml")
    assert match_project_packages(comps, [project]) == frozenset({"r"})


def test_no_match_across_ecosystems():
    comps = [component("r", "demo", ecosystem="pypi")]
    project = ProjectPackage("npm", "demo", "1.0.0", "package.json")
    assert match_project_packages(comps, [project]) == frozenset()


def test_different_version_of_same_name_is_a_real_dependency():
    comps = [component("old", "demo", "0.9.0")]
    project = ProjectPackage("npm", "demo", "1.0.0", "package.json")
    assert match_project_packages(comps, [project]) == frozenset()


def test_manifest_without_version_matches_on_name():
    comps = [component("r", "demo", "3.0.0")]
    project = ProjectPackage("npm", "demo", None, "package.json")
    assert match_project_packages(comps, [project]) == frozenset({"r"})


# ------------------------------------------------------------------ graph
@dataclass
class C:
    bom_ref: str
    name: str
    version: str | None = "1.0.0"
    component_type: str = "library"
    purl: str | None = None
    ecosystem: str | None = "npm"


def graph():
    comps = [C("self", "demo-app"), C("a", "a"), C("b", "b")]
    return build_dependency_graph(
        "artifact",
        comps,
        [("self", "a"), ("a", "b")],
        project_refs=frozenset({"self"}),
    )


def test_project_package_merges_into_the_artifact_root():
    dg = graph()
    assert "self" not in dg.graph
    assert dg.graph.nodes[ROOT_KEY]["root_packages"][0]["bom_ref"] == "self"
    assert dg.features["root_package_count"] == 1


def test_direct_dependencies_are_at_depth_one():
    dg = graph()
    assert dg.graph.nodes["a"]["depth"] == 1 and dg.graph.nodes["b"]["depth"] == 2
    edge = dg.graph.edges[ROOT_KEY, "a"]
    assert edge == {"relation": "depends_on", "origin": "sbom"}
    assert dg.graph.edges["a", "b"]["relation"] == "transitive_depends_on"


def test_project_is_not_counted_as_a_dependency():
    assert graph().features["dependency_count"] == 2


def test_without_project_refs_the_package_remains_a_node():
    dg = build_dependency_graph("artifact", [C("self", "demo-app"), C("a", "a")], [("self", "a")])
    assert "self" in dg.graph and dg.features["root_package_count"] == 0
    assert dg.graph.nodes["a"]["depth"] == 2


# ------------------------------------------------------------------ vulnerability lookup
def sbom(root_refs=frozenset()):
    parsed = ParsedSbom(
        spec_version="1.6",
        root_ref=None,
        root_name="x",
        tools=[],
        components=[component("self", "demo-app"), component("dep", "lodash", "4.17.20")],
        edges=[],
    )
    return SbomStageOutput(parsed, {}, "mock", root_refs)


def test_project_package_is_excluded_from_vulnerability_queries():
    queries, skipped = build_queries(sbom(frozenset({"self"})))
    assert [q.ref for q in queries] == ["dep"]
    assert skipped["project_root_packages"] == 1


def test_all_packages_queried_when_no_root_identified():
    queries, skipped = build_queries(sbom())
    assert {q.ref for q in queries} == {"self", "dep"}
    assert skipped["project_root_packages"] == 0

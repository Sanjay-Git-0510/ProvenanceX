"""Comparison features between two scans and across declared versions."""

import json
import os

import networkx as nx
import pytest

from app.ml.comparison import (
    MAX_MANIFEST_BYTES,
    ScanSnapshot,
    compare_snapshots,
    config_digest,
    declared_versions,
    graph_edges,
    max_centrality,
    version_consistency,
)


def snap(config="a", edges=(("r", "x"),), centrality=0.2, attested=True):
    return ScanSnapshot(config, frozenset(edges), centrality, attested)


def test_identical_scans_show_no_change():
    assert compare_snapshots(snap(), snap()) == {
        "config_changed": False,
        "new_edge_count": 0,
        "centrality_shift": 0.0,
        "provenance_removed": False,
    }


def test_each_change_is_detected():
    current = snap("b", (("r", "x"), ("r", "y")), 0.5, False)
    result = compare_snapshots(snap(), current)
    assert result == {
        "config_changed": True,
        "new_edge_count": 1,
        "centrality_shift": 0.3,
        "provenance_removed": True,
    }


def test_attestation_appearing_is_not_removal():
    assert compare_snapshots(snap(attested=False), snap())["provenance_removed"] is False


@pytest.mark.parametrize("side", ["prior", "current"])
def test_missing_evidence_is_none_not_unchanged(side):
    empty = ScanSnapshot(None, frozenset(), None, None)
    result = (
        compare_snapshots(empty, snap()) if side == "prior" else compare_snapshots(snap(), empty)
    )
    assert result["config_changed"] is None
    assert result["centrality_shift"] is None
    assert result["provenance_removed"] is None


def test_config_digest_tracks_content_and_ignores_other_files(tmp_path):
    assert config_digest(tmp_path) is None
    (tmp_path / "config.json").write_text("{}")
    first = config_digest(tmp_path)
    (tmp_path / "notes.txt").write_text("x")
    assert config_digest(tmp_path) == first
    (tmp_path / "config.json").write_text('{"a": 1}')
    assert config_digest(tmp_path) != first


def test_config_digest_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("secret")
    src = tmp_path / "src"
    src.mkdir()
    os.symlink(outside, src / "config.json")
    assert config_digest(src) is None


def test_graph_edges_compare_by_label():
    g = nx.DiGraph()
    g.add_node("id-1", label="a@1")
    g.add_node("id-2", label="b@2")
    g.add_edge("id-1", "id-2")
    assert graph_edges(g) == frozenset({("a@1", "b@2")})


def test_max_centrality():
    g = nx.DiGraph()
    g.add_node("a")
    assert max_centrality(g) is None
    g.add_node("b", betweenness_centrality=0.4)
    assert max_centrality(g) == 0.4


def test_version_consistency_states():
    assert version_consistency({}) is None
    assert version_consistency({"tag": "1.0"}) is None
    assert version_consistency({"tag": "1.0", "pkg": "1.0"}) is True
    assert version_consistency({"tag": "2.0", "pkg": "1.0"}) is False


def test_declared_versions_reads_manifests_and_tag(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.0"\n')
    (tmp_path / "package.json").write_text(json.dumps({"version": "V1.2.0"}))
    assert declared_versions(tmp_path, "v1.2.0") == {
        "pyproject.toml": "1.2.0",
        "package.json": "1.2.0",
        "release_tag": "1.2.0",
    }


@pytest.mark.parametrize("revision", ["main", "a" * 40, "1234567", None])
def test_non_release_revisions_are_not_versions(tmp_path, revision):
    assert declared_versions(tmp_path, revision) == {}


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("pyproject.toml", "not = = toml"),
        ("package.json", "{bad json"),
        ("package.json", "[1, 2]"),
        ("package.json", '{"version": 7}'),
        ("config.json", "[" * 200000),
        ("pyproject.toml", "project = 1"),
    ],
)
def test_malformed_manifests_yield_no_version(tmp_path, name, content):
    (tmp_path / name).write_text(content)
    assert declared_versions(tmp_path, None) == {}


def test_oversized_manifest_is_not_read(tmp_path):
    (tmp_path / "package.json").write_bytes(b" " * (MAX_MANIFEST_BYTES + 1))
    assert declared_versions(tmp_path, None) == {}

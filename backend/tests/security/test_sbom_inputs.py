"""Hostile SBOM and advisory inputs: they must fail safely with structured errors or be
bounded. They must never crash, hang or allocate without limit."""

import json

import pytest

from app.core.errors import AppError, ErrorCode
from app.graph.dependency_graph import build_dependency_graph
from app.scanners.sbom.cyclonedx import parse_cyclonedx
from app.scanners.vulns.osv import normalize_osv

MAX = 10**7


def _parse(raw: bytes, max_components=1000):
    return parse_cyclonedx(raw, max_bytes=MAX, max_components=max_components)


def _doc(**extra):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", **extra}


def test_deeply_nested_json_is_parse_error():
    raw = (
        b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "x": '
        + b"[" * 200_000
        + b"]" * 200_000
        + b"}"
    )
    with pytest.raises(AppError) as exc:
        _parse(raw)
    assert exc.value.code == ErrorCode.SBOM_PARSE_ERROR


def test_huge_dependency_list_capped():
    deps = [{"ref": str(i), "dependsOn": []} for i in range(2000)]
    with pytest.raises(AppError) as exc:
        _parse(json.dumps(_doc(dependencies=deps)).encode())
    assert exc.value.code == ErrorCode.SBOM_PARSE_ERROR


def test_huge_depends_on_list_rejected():
    deps = [{"ref": "a", "dependsOn": ["b"] * 20_000}]
    comps = [{"bom-ref": "a", "type": "library", "name": "a"}]
    with pytest.raises(AppError) as exc:
        _parse(json.dumps(_doc(components=comps, dependencies=deps)).encode())
    assert exc.value.code == ErrorCode.SBOM_PARSE_ERROR


def test_overlong_strings_rejected():
    comps = [{"bom-ref": "a", "type": "library", "name": "n" * 5000}]
    with pytest.raises(AppError) as exc:
        _parse(json.dumps(_doc(components=comps)).encode())
    assert exc.value.code == ErrorCode.SBOM_PARSE_ERROR


@pytest.mark.parametrize(
    "components",
    [
        [{"bom-ref": 5, "type": "library", "name": "a"}],
        [{"type": ["library"], "name": "a"}],
        [None],
        ["string-component"],
        [{"type": "library", "name": "a", "properties": "not-a-list"}],
    ],
)
def test_wrong_types_rejected(components):
    with pytest.raises(AppError) as exc:
        _parse(json.dumps(_doc(components=components)).encode())
    assert exc.value.code == ErrorCode.SBOM_PARSE_ERROR


def test_hostile_refs_do_not_escape_or_crash():
    # Path-like and injection-like refs are stored as opaque strings, never used as paths.
    refs = ["../../etc/passwd", "'; DROP TABLE components; --", "<script>", "artifact:root"]
    comps = [{"bom-ref": r, "type": "library", "name": f"n{i}"} for i, r in enumerate(refs)]
    deps = [{"ref": refs[0], "dependsOn": refs[1:]}]
    parsed = _parse(json.dumps(_doc(components=comps, dependencies=deps)).encode())
    dg = build_dependency_graph("app", parsed.components, parsed.edges, parsed.root_ref)
    # A component pretending to be the root key cannot hijack the artifact root node.
    assert dg.graph.nodes["artifact:root"]["node_type"] == "artifact"
    assert dg.graph.nodes["artifact:root"]["label"] == "app"
    assert parsed.stats["renamed_reserved_refs"] == 1
    renamed = next(c for c in parsed.components if c.name == "n3")
    assert renamed.bom_ref.startswith("provenancex:renamed:")
    # The edge to the renamed component survives under its new ref.
    assert (refs[0], renamed.bom_ref) in parsed.edges
    assert "<script>" in dg.graph


def test_spoofed_generated_ref_cannot_collide():
    comps = [
        {"type": "library", "name": "auto"},  # gets provenancex:generated:0
        {"bom-ref": "provenancex:generated:0", "type": "library", "name": "spoof"},
    ]
    parsed = _parse(json.dumps(_doc(components=comps)).encode())
    assert sorted(c.name for c in parsed.components) == ["auto", "spoof"]
    assert len({c.bom_ref for c in parsed.components}) == 2


def test_dense_cycles_terminate():
    n = 60
    comps = [{"bom-ref": str(i), "type": "library", "name": str(i)} for i in range(n)]
    deps = [{"ref": str(i), "dependsOn": [str(j) for j in range(n) if j != i]} for i in range(n)]
    parsed = _parse(json.dumps(_doc(components=comps, dependencies=deps)).encode())
    dg = build_dependency_graph("app", parsed.components, parsed.edges)
    assert dg.features["cycles_present"] is True
    assert dg.features["dependency_count"] == n


def test_hostile_osv_record_is_bounded():
    doc = {
        "id": "X" * 1000,
        "aliases": ["A" * 1000] * 500,
        "summary": "s" * 100_000,
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/" + "A" * 10_000}],
        "affected": [{"ranges": [{"events": [{"fixed": "1"}] * 1000}] * 100}] * 100,
        "references": [{"url": "https://x/" + "a" * 5000}] * 1000,
        "database_specific": {"severity": {"nested": "dict"}, "cwe_ids": "not-a-list"},
    }
    adv = normalize_osv(doc, "osv")
    assert len(adv.identifier) <= 128
    assert len(adv.aliases) <= 50 and all(len(a) <= 128 for a in adv.aliases)
    assert adv.summary is not None and len(adv.summary) <= 500
    assert adv.cvss_score is None and adv.severity == "UNKNOWN"
    assert len(adv.references) <= 10
    assert len(adv.affected_ranges) <= 400
    assert adv.cwe_ids == ()


def test_osv_record_with_garbage_fields():
    adv = normalize_osv(
        {"id": "OK-1", "severity": "nope", "affected": "nope", "references": [1, None]}, "osv"
    )
    assert adv.identifier == "OK-1" and adv.severity == "UNKNOWN"

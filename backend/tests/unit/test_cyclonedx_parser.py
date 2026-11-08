import json

import pytest

from app.core.errors import AppError, ErrorCode
from app.scanners.sbom.cyclonedx import parse_cyclonedx, purl_ecosystem
from tests.conftest import FIXTURES

SBOM_DIR = FIXTURES / "sbom"


def _parse(doc, **kw):
    raw = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
    return parse_cyclonedx(
        raw, max_bytes=kw.get("max_bytes", 10**7), max_components=kw.get("max_components", 1000)
    )


def _doc(components=(), dependencies=None, spec="1.6", root=None):
    doc = {"bomFormat": "CycloneDX", "specVersion": spec, "components": list(components)}
    if dependencies is not None:
        doc["dependencies"] = dependencies
    if root:
        doc["metadata"] = {"component": root}
    return doc


def test_real_syft_npm_lock_output():
    parsed = _parse((SBOM_DIR / "syft_npm_lock.cdx.json").read_bytes())
    names = sorted(c.name for c in parsed.components)
    assert names == ["body-parser", "demo-app", "express", "qs"]
    assert parsed.stats["excluded_file_components"] == 1
    assert len(parsed.edges) == 4
    assert parsed.spec_version == "1.7"
    assert any(t.startswith("syft@") for t in parsed.tools)
    qs = next(c for c in parsed.components if c.name == "qs")
    assert qs.ecosystem == "npm"
    assert qs.found_by == "javascript-lock-cataloger"
    assert qs.locations == ("/package-lock.json",)


def test_real_syft_requirements_output_has_no_edges():
    parsed = _parse((SBOM_DIR / "syft_requirements_only.cdx.json").read_bytes())
    assert sorted(c.name for c in parsed.components) == ["flask", "requests"]
    assert parsed.edges == []
    assert all(c.ecosystem == "pypi" for c in parsed.components)


def test_cyclonedx_14_tools_list_and_licenses():
    doc = _doc(
        [
            {
                "bom-ref": "a",
                "type": "library",
                "name": "a",
                "version": "1",
                "purl": "pkg:pypi/a@1",
                "licenses": [{"license": {"id": "MIT"}}, {"expression": "Apache-2.0 OR MIT"}],
            }
        ],
        spec="1.4",
    )
    doc["metadata"] = {"tools": [{"vendor": "x", "name": "legacy-tool", "version": "2"}]}
    parsed = _parse(doc)
    assert parsed.tools == ["legacy-tool@2"]
    assert parsed.components[0].licenses == ("MIT", "Apache-2.0 OR MIT")


def test_missing_bom_ref_is_generated_and_duplicates_dropped():
    parsed = _parse(
        _doc(
            [
                {"type": "library", "name": "noref"},
                {"bom-ref": "x", "type": "library", "name": "x"},
                {"bom-ref": "x", "type": "library", "name": "x-dup"},
            ]
        )
    )
    assert [c.name for c in parsed.components] == ["noref", "x"]
    assert parsed.components[0].bom_ref.startswith("provenancex:generated:")
    assert parsed.stats["generated_refs"] == 1
    assert parsed.stats["duplicate_refs"] == 1


def test_edges_filtered_unknown_selfloop_duplicate():
    comps = [{"bom-ref": r, "type": "library", "name": r} for r in ("a", "b")]
    deps = [
        {"ref": "a", "dependsOn": ["b", "b", "a", "ghost"]},
        {"ref": "ghost", "dependsOn": ["a"]},
    ]
    parsed = _parse(_doc(comps, deps))
    assert parsed.edges == [("a", "b")]
    assert parsed.stats["edges_duplicate"] == 1
    assert parsed.stats["edges_self_loop"] == 1
    assert parsed.stats["edges_unknown_ref"] == 2


def test_root_edges_kept_and_root_not_a_component():
    root = {"bom-ref": "root", "type": "application", "name": "app"}
    comps = [root, {"bom-ref": "a", "type": "library", "name": "a"}]
    parsed = _parse(_doc(comps, [{"ref": "root", "dependsOn": ["a"]}], root=root))
    assert parsed.root_ref == "root"
    assert [c.bom_ref for c in parsed.components] == ["a"]
    assert parsed.edges == [("root", "a")]


def test_invalid_purl_dropped_and_counted():
    parsed = _parse(_doc([{"bom-ref": "a", "type": "library", "name": "a", "purl": "not a purl"}]))
    assert parsed.components[0].purl is None
    assert parsed.stats["invalid_purls"] == 1


@pytest.mark.parametrize(
    ("purl", "eco"),
    [
        ("pkg:pypi/flask@3.0.3", "pypi"),
        ("pkg:npm/%40scope/x@1", "npm"),
        ("pkg:Maven/g/a@1", "maven"),
        (None, None),
        ("", None),
        ("pypi/flask", None),
        ("pkg:/x", None),
        ("pkg:py pi/x", None),
    ],
)
def test_purl_ecosystem(purl, eco):
    assert purl_ecosystem(purl) == eco


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b'"str"',
        b"{}",
        b'{"bomFormat": "SPDX", "specVersion": "2.3"}',
        b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": {"a": 1}}',
        b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "no-type"}]}',
        b"\xff\xfe\x00garbage",
    ],
)
def test_malformed_documents_raise_parse_error(raw):
    with pytest.raises(AppError) as exc:
        _parse(raw)
    assert exc.value.code == ErrorCode.SBOM_PARSE_ERROR


def test_oversize_rejected_before_decoding():
    with pytest.raises(AppError) as exc:
        _parse(b"{" + b" " * 2000 + b"}", max_bytes=1000)
    assert exc.value.code == ErrorCode.SBOM_TOO_LARGE


def test_component_count_capped():
    comps = [{"bom-ref": str(i), "type": "library", "name": str(i)} for i in range(11)]
    with pytest.raises(AppError) as exc:
        _parse(_doc(comps), max_components=10)
    assert exc.value.code == ErrorCode.SBOM_PARSE_ERROR

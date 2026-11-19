"""Analyzer output is untrusted: size-capped, strictly parsed and schema-validated."""

import json

import pytest

from app.analysis.base import AnalyzerRun, parse_worker_output, raise_if_error
from app.core.errors import AppError
from app.sandbox_worker.protocol import RESULT_FORMAT
from tests.analyzer_helpers import ISOLATED, minimal_analysis

CAP = 1024 * 1024


def _doc(**overrides):
    doc = {
        "format": RESULT_FORMAT,
        "mode": "analyze",
        "status": "ok",
        "isolation_mode": "container",
        "isolation": ISOLATED,
        "analysis": minimal_analysis(),
    }
    doc.update(overrides)
    return doc


def _invalid(raw: bytes, mode="analyze", cap=CAP) -> str:
    with pytest.raises(AppError) as info:
        parse_worker_output(raw, cap, mode)
    assert info.value.code == "analyzer_output_invalid"
    return info.value.details["reason"]


def test_valid_output_parses():
    result = parse_worker_output(json.dumps(_doc()).encode(), CAP, "analyze")
    assert result.analysis.tree.file_count == 1


def test_empty_and_oversized_are_rejected():
    assert _invalid(b"") == "empty output"
    assert _invalid(json.dumps(_doc()).encode(), cap=10) == "output exceeds the size limit"


@pytest.mark.parametrize(
    "raw",
    [
        b"{not json",
        b'{"a": NaN}',
        b'{"a": Infinity}',
        b"[" * 100_000 + b"]" * 100_000,
        b"\xff\xfe",
    ],
)
def test_malformed_json_is_rejected(raw):
    _invalid(raw)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(unexpected="field"),
        lambda d: d.update(format="other-v9"),
        lambda d: d["analysis"]["tree"].update(sha256="../../etc"),
        lambda d: d["analysis"]["tree"].update(file_count=-1),
        lambda d: d["analysis"].update(file_paths=["x" * 5000]),
        lambda d: d.update(status="error"),  # error status without an error
        lambda d: d.update(error={"code": "Bad Code!", "message": "x"}, status="error"),
        lambda d: d.pop("analysis"),
        lambda d: d.update(isolation_mode="host"),
        lambda d: d["analysis"].update(config_sha256="not-a-hash"),
    ],
)
def test_schema_violations_are_rejected(mutate):
    doc = _doc()
    mutate(doc)
    _invalid(json.dumps(doc).encode())


def test_wrong_mode_is_rejected():
    assert _invalid(json.dumps(_doc()).encode(), mode="extract") == "output is for a different mode"


def test_error_result_maps_known_codes_and_hides_unknown_ones():
    def run(code):
        doc = _doc(status="error", error={"code": code, "message": "m", "details": None})
        doc.pop("analysis")
        return AnalyzerRun(parse_worker_output(json.dumps(doc).encode(), CAP, "analyze"))

    with pytest.raises(AppError) as info:
        raise_if_error(run("unsafe_archive"))
    assert info.value.code == "unsafe_archive"
    with pytest.raises(AppError) as info:
        raise_if_error(run("made_up_code"))
    assert info.value.code == "internal_error"

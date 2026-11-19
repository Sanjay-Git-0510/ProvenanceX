"""Milestone C2 (audit M4, L4, L5): strict evidence typing, contradiction checks, the separate
SBOM container, bind mounts anchored to WORKSPACE_ROOT, bounded details and escaped stderr."""

import copy
import json
import logging
import uuid

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.analysis.consistency import (
    UPLOAD_LABEL,
    check_analysis,
    check_same_tree,
    check_sbom_locations,
)
from app.analysis.docker_analyzer import DockerAnalyzer
from app.analysis.hardening import (
    AnalyzerLimits,
    AnalyzerSpec,
    MountSpec,
    assert_create_hardened,
    build_create_argv,
)
from app.api.scans import get_scan_providers, get_session_factory
from app.core.bounded import MAX_DETAILS_BYTES, bounded_details, clamp_details, printable_excerpt
from app.core.config import get_settings
from app.core.errors import AppError
from app.main import create_app
from app.pipeline.providers import ScanProviders
from app.sandbox_worker.protocol import RESULT_FORMAT, AnalysisOut, TreeOut, WorkerResult
from app.scanners.hf.mock import MockHfProvider
from app.scanners.sbom.base import SbomResult
from app.scanners.sbom.mock import MockSbomProvider
from app.scanners.vulns.mock import MockVulnProvider
from tests.analyzer_helpers import ISOLATED, FakeDocker, analyzer_settings, make_job, worker_output
from tests.conftest import attach_test_analyzer, build_zip

TREE = {"sha256": "a" * 64, "file_count": 3, "total_bytes": 30}
FILES = ["app.py", "requirements.txt", "lib/util.py"]
FEATURES = {
    "dangerous_import_count": 1,
    "suspicious_api_count": 0,
    "script_presence": True,
    "archive_anomaly": 0,
    "script_count": 2,
    "bytecode_count": 0,
    "native_binary_count": 0,
    "files_analyzed": 3,
    "parse_errors": 0,
    "install_hook_count": 0,
    "pickle_dangerous_global_count": None,
}


def _static(**override):
    doc = {
        "features": dict(FEATURES),
        "findings": [
            {
                "rule": {"id": "PX1", "kind": "dangerous_import", "severity": "HIGH", "title": "t"},
                "file": "app.py",
                "occurrences": 1,
                "lines": [3],
                "cells": [],
                "symbols": ["os.system"],
            }
        ],
        "findings_truncated": False,
        "not_analyzed": [],
        "not_analyzed_count": 0,
        "limitations": [],
    }
    doc.update(override)
    return doc


def _analysis(**override) -> AnalysisOut:
    data = {
        "tree": TREE,
        "file_paths": list(FILES),
        "manifests": [{"path": "requirements.txt", "ecosystem": "pypi", "kind": "requirements"}],
        "static": _static(),
    }
    data.update(override)
    return AnalysisOut.model_validate(data)


def _invalid(fn, *args):
    with pytest.raises(AppError) as info:
        fn(*args)
    assert info.value.code == "analyzer_output_invalid"
    return info.value


# --------------------------------------------------------------------------- trees
def test_identical_trees_pass_and_any_difference_fails():
    ref = TreeOut.model_validate(TREE)
    check_same_tree(ref, TreeOut.model_validate(TREE), "persist")
    for key, value in (("sha256", "b" * 64), ("file_count", 4), ("total_bytes", 31)):
        _invalid(check_same_tree, ref, TreeOut.model_validate({**TREE, key: value}), "sbom")
    _invalid(check_same_tree, ref, None, "sbom")


# --------------------------------------------------------------------------- analysis
def test_a_consistent_analysis_passes():
    check_analysis(_analysis())


def test_findings_about_the_upload_itself_are_allowed():
    static = _static()
    static["findings"][0]["file"] = UPLOAD_LABEL
    check_analysis(_analysis(static=static))


@pytest.mark.parametrize(
    "override",
    [
        {"file_paths": FILES[:2]},  # fewer paths than file_count
        {"file_paths": [*FILES[:2], "app.py"]},  # duplicate
        {"file_paths": ["/etc/passwd", *FILES[1:]]},
        {"file_paths": ["../escape", *FILES[1:]]},
        {"manifests": [{"path": "package.json", "ecosystem": "npm", "kind": "manifest"}]},
        {
            "project_packages": [
                {"ecosystem": "npm", "name": "x", "version": None, "manifest": "package.json"}
            ]
        },
    ],
)
def test_file_list_contradictions_are_refused(override):
    _invalid(check_analysis, _analysis(**override))


def _static_with(**features):
    static = _static()
    static["features"].update(features)
    return static


@pytest.mark.parametrize(
    "static",
    [
        _static(findings=[{**_static()["findings"][0], "file": "elsewhere.py"}]),
        _static(not_analyzed=[{"file": "ghost.bin", "reason": "too large"}], not_analyzed_count=1),
        _static(not_analyzed=[{"file": "app.py", "reason": "x"}], not_analyzed_count=0),
        _static_with(files_analyzed=4),
        _static_with(script_count=4),
        _static_with(script_presence=False),
        _static_with(parse_errors=4),
        _static_with(dangerous_import_count=0),  # a finding the counts do not cover
        _static(
            findings=[
                {
                    **_static()["findings"][0],
                    "rule": {**_static()["findings"][0]["rule"], "kind": "x"},
                }
            ]
        ),
    ],
)
def test_static_contradictions_are_refused(static):
    _invalid(check_analysis, _analysis(static=static))


@pytest.mark.parametrize(
    "features",
    [
        {**FEATURES, "extra_feature": 1},  # unknown key
        {k: v for k, v in FEATURES.items() if k != "parse_errors"},  # missing key
        {**FEATURES, "dangerous_import_count": -1},
        {**FEATURES, "dangerous_import_count": 10**12},
        {**FEATURES, "dangerous_import_count": True},  # a bool is not a count
        {**FEATURES, "dangerous_import_count": 1.5},
        {**FEATURES, "script_presence": 1},
    ],
)
def test_static_features_are_strictly_typed(features):
    _invalid(check_analysis, _analysis(static=_static(features=features)))


def test_a_truncated_not_analyzed_path_may_be_a_prefix():
    long = "d/" + "x" * 600
    analysis = _analysis(
        tree={**TREE, "file_count": 4},
        file_paths=[*FILES, long],
        static=_static(not_analyzed=[{"file": long[:512], "reason": "r"}], not_analyzed_count=1),
    )
    check_analysis(analysis)


def test_undecodable_names_compare_equal_across_decoders():
    analysis = _analysis(
        file_paths=["a�.py", *FILES[1:]],
        static=_static(findings=[{**_static()["findings"][0], "file": "a?.py"}]),
    )
    check_analysis(analysis)


# --------------------------------------------------------------------------- AI-BOM
def _file(path, downloaded=True, category="weights"):
    return {
        "path": path,
        "size": 10,
        "category": category,
        "downloaded": downloaded,
        "sha256": "c" * 64 if downloaded else None,
        "serialization": "safetensors",
        "serialization_verified": downloaded,
        "remote_sha256": None,
        "hash_verified": None,
        "skip_reason": None if downloaded else "too large",
        "format_mismatch": None,
        "analysis": {},
    }


def _aibom():
    files = [_file("model.safetensors"), _file("config.json", category="config")]
    return {
        "format": "provenancex-aibom-v1",
        "files": files,
        "configs": [
            {
                "path": "config.json",
                "kind": "model",
                "valid": True,
                "fields": {"model_type": "gpt2", "layers": [1, 2]},
                "auto_map": {},
                "error": None,
            }
        ],
        "model_card": {
            "present": False,
            "source": None,
            "metadata": {},
            "fields_present": [],
            "sections_present": [],
            "completeness": 0.0,
            "issues": [],
        },
        "custom_code": {
            "scripts": [],
            "bytecode": [],
            "native_binaries": [],
            "auto_map": {},
            "requirements": [],
            "requirement_files": [],
            "truncated": False,
        },
        "base_models": [],
        "datasets": [],
        "adapters": [],
        "frameworks": [],
        "local_path_references": [],
        "limitations": [],
        "summary": {
            "file_count": 2,
            "files_downloaded": 2,
            "weight_file_count": 1,
            "file_type_count": 2,
            "code_executing_formats": [],
            "unverified_possibly_pickle": 0,
            "custom_code_present": False,
            "model_card_completeness": None,
            "license": None,
        },
    }


def _model(aibom):
    return _analysis(
        tree={**TREE, "file_count": 2},
        file_paths=["model.safetensors", "config.json"],
        manifests=[],
        static=None,
        aibom=aibom,
    )


def test_a_consistent_aibom_passes():
    check_analysis(_model(_aibom()))


def _mutated(change):
    doc = copy.deepcopy(_aibom())
    change(doc)
    return doc


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["files"].append(_file("ghost.bin")),  # downloaded but not in the tree
        lambda d: d["files"].__setitem__(0, _file("model.safetensors", downloaded=False)),
        lambda d: d["files"].append(_file("config.json", category="config")),  # duplicate
        lambda d: d["configs"][0].__setitem__("path", "other.json"),
        lambda d: d["configs"][0]["fields"].__setitem__("nested", {"a": 1}),  # not a scalar
        lambda d: d["configs"][0]["fields"].__setitem__("long", list(range(65))),
        lambda d: d["custom_code"]["scripts"].append("evil.py"),
        lambda d: d["summary"].__setitem__("file_count", 1),
        lambda d: d["summary"].__setitem__("files_downloaded", 1),
        lambda d: d["summary"].__setitem__("weight_file_count", 0),
        lambda d: d["summary"].__setitem__("custom_code_present", True),
        lambda d: d["summary"].__setitem__("unexpected", 1),
        lambda d: d["summary"].__setitem__("model_card_completeness", 1.5),
        lambda d: d["model_card"].__setitem__("completeness", -0.1),
        lambda d: d["files"][0].__setitem__("size", -1),
    ],
)
def test_aibom_contradictions_and_bad_types_are_refused(change):
    _invalid(check_analysis, _model(_mutated(change)))


def test_remote_only_files_outside_the_tree_are_fine():
    doc = _mutated(lambda d: d["files"].append(_file("big.bin", downloaded=False)))
    doc["summary"]["file_count"] = 3
    doc["summary"]["weight_file_count"] = 2
    check_analysis(_model(doc))


# --------------------------------------------------------------------------- SBOM
def test_sbom_locations_must_be_in_the_tree():
    check_sbom_locations(["/requirements.txt", "/lib/util.py"], FILES)
    _invalid(check_sbom_locations, ["/etc/passwd"], FILES)
    _invalid(check_sbom_locations, ["/../requirements.txt"], FILES)


def _result(mode, **extra):
    return {
        "format": RESULT_FORMAT,
        "mode": mode,
        "status": "ok",
        "isolation_mode": "container",
        "isolation": ISOLATED,
        **extra,
    }


SBOM_DESC = {
    "size": 2,
    "sha256": "d" * 64,
    "source": "syft",
    "tool_name": "syft",
    "tool_version": "1",
    "format": "cyclonedx-json",
}


def test_the_analyze_container_can_no_longer_carry_an_sbom():
    analysis = {"tree": TREE, "file_paths": FILES, "sbom": SBOM_DESC}
    with pytest.raises(ValidationError):
        WorkerResult.model_validate(_result("analyze", analysis=analysis))


def test_an_sbom_run_has_exactly_one_outcome():
    run = {"tree": TREE, "sbom_provider": "syft", "sbom": SBOM_DESC}
    assert WorkerResult.model_validate(_result("sbom", sbom_run=run)).sbom_run
    err = {"code": "sbom_failed", "message": "x"}
    for bad in ({**run, "sbom_error": err}, {"tree": TREE, "sbom_provider": "syft"}):
        with pytest.raises(ValidationError):
            WorkerResult.model_validate(_result("sbom", sbom_run=bad))
    with pytest.raises(ValidationError):
        WorkerResult.model_validate(_result("analyze", sbom_run=run))


class _ForgedSyft:
    """Real-looking Syft output whose component sits outside the scanned tree."""

    name = "syft"

    def generate(self, src, scratch):
        doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "x",
                    "version": "1",
                    "purl": "pkg:pypi/x@1",
                    "bom-ref": "x",
                    "properties": [{"name": "syft:location:0:path", "value": "/etc/shadow"}],
                }
            ],
        }
        return SbomResult(json.dumps(doc).encode(), "syft", "syft", "1.0")


def test_an_sbom_located_outside_the_tree_fails_its_stage(test_settings, session_factory):
    providers = ScanProviders(
        sbom=_ForgedSyft(), vulns=MockVulnProvider(), nvd=None, hf=MockHfProvider()
    )
    attach_test_analyzer(providers, test_settings)
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    app.dependency_overrides[get_scan_providers] = lambda: providers
    client = TestClient(app, raise_server_exceptions=False)
    data = build_zip([("requirements.txt", "x==1\n")])
    posted = client.post(
        "/api/v1/scans/software", files={"file": ("a.zip", data, "application/zip")}
    )
    body = client.get(f"/api/v1/scans/{posted.json()['scan_id']}").json()
    stage = body["stages"]["sbom"]
    assert stage["status"] != "completed"
    assert stage["error"]["code"] == "analyzer_output_invalid"
    assert body["stages"]["graph"]["status"] == "skipped"


def test_the_pipeline_refuses_an_sbom_container_with_another_tree(
    test_settings, session_factory, monkeypatch
):
    """A forged sbom run (different tree digest) fails the whole scan, fail closed."""
    from app.analysis.inprocess import InProcessTestAnalyzer

    original = InProcessTestAnalyzer.run

    def forged(self, job, mode):
        run = original(self, job, mode)
        if mode == "sbom":
            tree = run.result.sbom_run.tree.model_copy(update={"sha256": "f" * 64})
            sbom_run = run.result.sbom_run.model_copy(update={"tree": tree})
            run.result = run.result.model_copy(update={"sbom_run": sbom_run})
        return run

    monkeypatch.setattr(InProcessTestAnalyzer, "run", forged)
    providers = ScanProviders(
        sbom=MockSbomProvider(), vulns=MockVulnProvider(), nvd=None, hf=MockHfProvider()
    )
    attach_test_analyzer(providers, test_settings)
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    app.dependency_overrides[get_scan_providers] = lambda: providers
    client = TestClient(app, raise_server_exceptions=False)
    data = build_zip([("a.py", "x = 1\n")])
    posted = client.post(
        "/api/v1/scans/software", files={"file": ("a.zip", data, "application/zip")}
    )
    body = client.get(f"/api/v1/scans/{posted.json()['scan_id']}").json()
    assert body["status"] == "failed"
    assert body["error"]["code"] == "analyzer_output_invalid"


# --------------------------------------------------------------------------- L4
SCAN = uuid.UUID("12345678-1234-1234-1234-123456789abc")
LIMITS = AnalyzerLimits(timeout_seconds=60, memory_mb=512, cpus=1.0, pids=64, tmp_mb=64)


def _argv(source, subdir="input", target="/input", mode="extract"):
    mounts = (MountSpec("bind", source, target, subdir, True, SCAN),)
    if mode == "extract":
        mounts = (
            *mounts,
            MountSpec("volume", f"px-stg-{SCAN}", "/out/src", "staging", False, SCAN),
        )
    spec = AnalyzerSpec(SCAN, mode, "img:1", 1000, 1000, mounts, LIMITS)
    return build_create_argv("docker", spec)


def test_binds_must_sit_directly_under_workspace_root():
    assert assert_create_hardened(_argv(f"/srv/ws/{SCAN}/input"), workspace_root="/srv/ws")
    for source in (f"/etc/{SCAN}/input", f"/srv/ws/x/{SCAN}/input", f"/srv/wsx/{SCAN}/input"):
        with pytest.raises(AppError):
            assert_create_hardened(_argv(source), workspace_root="/srv/ws")


def test_binds_are_refused_without_a_workspace_root():
    with pytest.raises(AppError):
        assert_create_hardened(_argv(f"/srv/ws/{SCAN}/input"))


def test_scan_root_binds_are_anchored_too():
    good = _argv(f"/srv/ws/{SCAN}", "scan", "/evidence", "rehash")
    assert assert_create_hardened(good, workspace_root="/srv/ws") == "rehash"
    with pytest.raises(AppError):
        assert_create_hardened(
            _argv(f"/home/{SCAN}", "scan", "/evidence", "rehash"), workspace_root="/srv/ws"
        )


# --------------------------------------------------------------------------- L5
def test_details_are_bounded():
    assert bounded_details({"a": [1, 2]}) == {"a": [1, 2]}
    for bad in ({"x": "y" * MAX_DETAILS_BYTES}, {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}):
        with pytest.raises(ValueError):
            bounded_details(bad)
    assert clamp_details({"x": "y" * 10_000}) == {"details_omitted": "too large or not plain JSON"}


def test_oversized_worker_details_invalidate_the_result():
    error = {"code": "boom", "message": "m", "details": {"x": "y" * 10_000}}
    with pytest.raises(ValidationError):
        WorkerResult.model_validate({**_result("analyze"), "status": "error", "error": error})


def test_excerpts_cannot_forge_log_lines():
    raw = b"Traceback\n\x1b[31mFAKE LOG LINE\r\n\xff\xfe" + b"z" * 1000
    text = printable_excerpt(raw)
    assert "\n" not in text and "\r" not in text and "\x1b" not in text
    assert text.startswith("Traceback\\x0a") and len(text) <= 300


def test_container_stderr_is_logged_escaped(tmp_path, monkeypatch):
    fake = FakeDocker(tmp_path, monkeypatch)
    fake.configure(
        start="ok",
        output_file=str(worker_output(tmp_path / "out", "extract")),
        stderr="line1\nINJECTED 2026 CRITICAL fake\x1b[0m",
    )
    settings = analyzer_settings(tmp_path, fake.path)
    records: list[logging.LogRecord] = []
    handler = logging.Handler(level=logging.WARNING)
    handler.emit = records.append  # type: ignore[method-assign]
    target = logging.getLogger("app.analysis.docker_analyzer")
    target.addHandler(handler)
    old_level, target.level = target.level, logging.WARNING
    # configure_logging (dictConfig) in other tests may have disabled existing loggers.
    old_disabled, target.disabled = target.disabled, False
    try:
        DockerAnalyzer(settings).run(make_job(settings), "extract")
    finally:
        target.removeHandler(handler)
        target.setLevel(old_level)
        target.disabled = old_disabled
    logged = [r.getMessage() for r in records if "stderr" in r.getMessage()]
    assert logged and all("\n" not in m and "\x1b" not in m for m in logged)
    assert "INJECTED" in logged[0]  # still useful, just escaped

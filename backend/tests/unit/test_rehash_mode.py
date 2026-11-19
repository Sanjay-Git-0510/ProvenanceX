"""The `rehash` analyzer mode (Milestone C1, audit finding M5): what it hashes, how it refuses
swapped files, its strict output schema, and its container allowlist."""

import json
import os
import uuid

import pytest
from pydantic import ValidationError

from app.analysis.base import AnalysisJob, build_request
from app.analysis.docker_analyzer import DockerAnalyzer
from app.analysis.hardening import (
    AnalyzerLimits,
    AnalyzerSpec,
    MountSpec,
    assert_create_hardened,
    build_create_argv,
    resolve_workspace_dir,
)
from app.core.errors import AppError, ErrorCode
from app.core.hashing import sha256_file, tree_digest
from app.pipeline.workspace import create_workspace
from app.sandbox_worker.collect import run_rehash
from app.sandbox_worker.protocol import RESULT_FORMAT, DigestOut, WorkerResult
from app.security.sandbox_guard import inprocess_test_context
from tests.analyzer_helpers import ISOLATED, FakeDocker, analyzer_settings, worker_output

SCAN = uuid.UUID("12345678-1234-1234-1234-123456789abc")
LIMITS = AnalyzerLimits(timeout_seconds=60, memory_mb=512, cpus=1.0, pids=64, tmp_mb=64)


# --------------------------------------------------------------------------- hashing
def test_sha256_file_refuses_a_symlink(tmp_path):
    target = tmp_path / "real"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(AppError) as info:
        sha256_file(link)
    assert info.value.code == ErrorCode.UNSAFE_CONTENT


def test_sha256_file_refuses_a_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(AppError) as info:
        sha256_file(fifo)
    assert info.value.code == ErrorCode.UNSAFE_CONTENT


def test_sha256_file_refuses_a_file_swapped_after_listing(tmp_path):
    path = tmp_path / "a"
    path.write_text("one")
    listed = os.lstat(path)
    path.unlink()
    path.write_text("two")  # a new inode under the same name
    with pytest.raises(AppError) as info:
        sha256_file(path, listed)
    assert info.value.code == ErrorCode.UNSAFE_CONTENT


def test_tree_digest_is_unchanged_and_enforces_a_byte_cap(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    first = tree_digest(tmp_path)
    assert first.sha256 == tree_digest(tmp_path).sha256 and first.total_bytes == 5
    with pytest.raises(AppError) as info:
        tree_digest(tmp_path, max_bytes=4)
    assert info.value.code == ErrorCode.ARTIFACT_TOO_LARGE


# --------------------------------------------------------------------------- worker
@pytest.fixture
def evidence(test_settings):
    workspace = create_workspace(test_settings.workspace_root, uuid.uuid4())
    (workspace.src_dir / "app.py").write_text("print('x')\n")
    (workspace.root / "sbom.cdx.json").write_text("{}")
    (workspace.root / "provenance.json").write_text("{}")
    return workspace


def _rehash(settings, workspace, kind="software"):
    job = AnalysisJob(uuid.uuid4(), workspace, kind, has_upload=False)  # type: ignore[arg-type]
    with inprocess_test_context():
        return run_rehash(build_request(settings, job, "rehash"), workspace.root)


def test_rehash_returns_the_three_digests(test_settings, evidence):
    out = _rehash(test_settings, evidence)
    assert out["artifact"]["sha256"] == tree_digest(evidence.src_dir).sha256
    assert out["bom"]["sha256"] == sha256_file(evidence.root / "sbom.cdx.json")
    assert out["provenance"]["status"] == "ok"
    DigestOut.model_validate(out["artifact"])


def test_rehash_uses_the_aibom_for_a_model(test_settings, evidence):
    assert _rehash(test_settings, evidence, "model")["bom"] == {"status": "missing"}
    (evidence.root / "aibom.json").write_text("[]")
    assert _rehash(test_settings, evidence, "model")["bom"]["status"] == "ok"


def test_missing_evidence_is_missing_not_ok(test_settings, evidence):
    (evidence.root / "provenance.json").unlink()
    for path in evidence.src_dir.iterdir():
        path.unlink()
    evidence.src_dir.rmdir()
    out = _rehash(test_settings, evidence)
    assert out["artifact"] == {"status": "missing"}
    assert out["provenance"] == {"status": "missing"}


def test_symlinks_and_special_files_are_invalid(test_settings, evidence, tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("secret")
    (evidence.root / "sbom.cdx.json").unlink()
    (evidence.root / "sbom.cdx.json").symlink_to(outside)
    os.mkfifo(evidence.src_dir / "pipe")
    out = _rehash(test_settings, evidence)
    assert out["bom"] == {"status": "invalid"}
    assert out["artifact"] == {"status": "invalid"}


def test_a_swapped_tree_directory_is_invalid(test_settings, evidence, tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    for path in evidence.src_dir.iterdir():
        path.unlink()
    evidence.src_dir.rmdir()
    evidence.src_dir.symlink_to(real)
    assert _rehash(test_settings, evidence)["artifact"] == {"status": "invalid"}


def test_oversized_trees_are_unavailable(test_settings, evidence):
    small = test_settings.model_copy(update={"max_artifact_files": 1})
    (evidence.src_dir / "second.py").write_text("y")
    assert _rehash(small, evidence)["artifact"] == {"status": "unavailable"}


def test_rehash_refuses_to_run_on_the_host(test_settings, evidence):
    job = AnalysisJob(uuid.uuid4(), evidence, "software", has_upload=False)
    with pytest.raises(AppError):
        run_rehash(build_request(test_settings, job, "rehash"), evidence.root)


# --------------------------------------------------------------------------- schema
def _result(**rehash):
    digests = {
        name: {"status": "ok", "sha256": "c" * 64} for name in ("artifact", "bom", "provenance")
    }
    digests.update(rehash)
    return {
        "format": RESULT_FORMAT,
        "mode": "rehash",
        "status": "ok",
        "isolation_mode": "container",
        "isolation": ISOLATED,
        "rehash": digests,
    }


def test_valid_rehash_result_passes():
    assert WorkerResult.model_validate(_result()).rehash is not None


@pytest.mark.parametrize(
    "bad",
    [
        {"artifact": {"status": "ok"}},  # ok without a digest
        {"bom": {"status": "missing", "sha256": "c" * 64}},  # digest without ok
        {"bom": {"status": "ok", "sha256": "C" * 64}},  # not lowercase hex
        {"bom": {"status": "ok", "sha256": "c" * 63}},
        {"bom": {"status": "ok", "sha256": "c" * 64, "path": "/etc"}},  # unknown field
        {"provenance": {"status": "VERIFIED"}},
    ],
)
def test_malformed_rehash_results_are_refused(bad):
    with pytest.raises(ValidationError):
        WorkerResult.model_validate(_result(**bad))


def test_a_rehash_result_without_digests_is_refused():
    doc = _result()
    del doc["rehash"]
    with pytest.raises(ValidationError):
        WorkerResult.model_validate(doc)


def test_other_modes_cannot_carry_digests():
    doc = _result()
    doc["mode"] = "persist"
    doc["persisted"] = {"sha256": "c" * 64, "file_count": 1, "total_bytes": 1}
    with pytest.raises(ValidationError):
        WorkerResult.model_validate(doc)


# --------------------------------------------------------------------------- allowlist
def _spec(mounts) -> AnalyzerSpec:
    return AnalyzerSpec(SCAN, "rehash", "provenancex-analyzer:0.1.0", 1000, 1000, mounts, LIMITS)


def _refused(mounts):
    with pytest.raises(AppError) as info:
        assert_create_hardened(build_create_argv("docker", _spec(mounts)), workspace_root="/ws")
    assert info.value.code == "sandbox_refused"


@pytest.mark.parametrize(
    "mount",
    [
        MountSpec("bind", f"/ws/{SCAN}", "/evidence", "scan", True, SCAN),
        MountSpec("volume", "px_ws", "/evidence", "scan", True, SCAN),
    ],
)
def test_rehash_with_a_read_only_scan_mount_passes(mount):
    argv = build_create_argv("docker", _spec((mount,)))
    assert assert_create_hardened(argv, workspace_root="/ws") == "rehash"
    assert "--network=none" in argv


def test_a_writable_evidence_mount_is_refused():
    _refused((MountSpec("bind", f"/ws/{SCAN}", "/evidence", "scan", False, SCAN),))


def test_rehash_cannot_mount_staging_or_src():
    _refused((MountSpec("volume", f"px-stg-{SCAN}", "/evidence", "staging", True, SCAN),))
    _refused((MountSpec("bind", f"/ws/{SCAN}/src", "/evidence", "src", True, SCAN),))


def test_rehash_cannot_mount_another_scan():
    other = uuid.uuid4()
    _refused((MountSpec("bind", f"/ws/{other}", "/evidence", "scan", True, other),))


def test_other_modes_cannot_mount_the_whole_scan():
    spec = AnalyzerSpec(
        SCAN,
        "analyze",
        "provenancex-analyzer:0.1.0",
        1000,
        1000,
        (MountSpec("bind", f"/ws/{SCAN}", "/artifact", "scan", True, SCAN),),
        LIMITS,
    )
    with pytest.raises(AppError):
        assert_create_hardened(build_create_argv("docker", spec), workspace_root="/ws")


def test_scan_root_mount_source_must_be_this_scan(tmp_path):
    base = tmp_path / "ws"
    workspace = create_workspace(base, SCAN)
    resolved, _, _ = resolve_workspace_dir(workspace.root, base, SCAN)
    assert resolved == workspace.root
    with pytest.raises(AppError):
        resolve_workspace_dir(workspace.root, base, uuid.uuid4())


# --------------------------------------------------------------------------- docker path
def test_docker_rehash_mounts_only_the_scan_read_only(tmp_path, monkeypatch):
    fake = FakeDocker(tmp_path, monkeypatch)
    fake.configure(start="ok", output_file=str(worker_output(tmp_path / "out", "rehash")))
    settings = analyzer_settings(tmp_path, fake.path)
    workspace = create_workspace(settings.workspace_root, uuid.uuid4())
    scan_id = uuid.UUID(workspace.root.name)
    job = AnalysisJob(scan_id, workspace, "software", has_upload=False)
    run = DockerAnalyzer(settings).run(job, "rehash")
    assert run.result.rehash.artifact.sha256 == "b" * 64
    create = next(c for c in fake.calls() if c[0] == "create")
    mounts = [a for a in create if a.startswith("--mount=")]
    assert mounts == [f"--mount=type=bind,src={workspace.root},dst=/evidence,readonly"]
    assert f"--name=px-ana-{scan_id}-rehash" in create
    assert fake.calls()[-1] == ["rm", "-f", f"px-ana-{scan_id}-rehash"]
    assert json.loads((fake.state / "stdin.json").read_text())["mode"] == "rehash"

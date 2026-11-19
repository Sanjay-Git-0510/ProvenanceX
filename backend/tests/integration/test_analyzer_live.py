"""Live analyzer sandbox (real Docker, real image). Run with PROVENANCEX_SANDBOX_TESTS=1.

Needs: docker compose --profile analyzer-image build analyzer-image  (or: make analyzer-image)
"""

import io
import os
import shutil
import subprocess
import uuid
import zipfile

import pytest

from app.analysis.base import AnalysisJob
from app.analysis.docker_analyzer import DockerAnalyzer
from app.core.config import Settings
from app.core.hashing import tree_digest
from app.pipeline.providers import build_providers
from app.pipeline.workspace import create_workspace
from tests.analyzer_helpers import ISOLATED
from tests.conftest import SIMPLE_PROJECT, build_zip, symlink_info, zip_dir
from tests.model_helpers import reduce_pickle, torch_zip_bytes
from tests.security.test_no_host_fallback import _client, _post

pytestmark = pytest.mark.sandbox
IMAGE = "provenancex-analyzer:0.1.0"
DOCKER = shutil.which("docker") or "docker"


@pytest.fixture(scope="module", autouse=True)
def _image_present():
    if shutil.which("docker") is None:
        pytest.fail("docker CLI not found")
    done = subprocess.run(  # noqa: S603 - fixed argv
        [DOCKER, "image", "inspect", IMAGE], capture_output=True, check=False
    )
    if done.returncode != 0:
        pytest.fail(f"{IMAGE} is not built: make analyzer-image")


def _settings(tmp_path, **overrides) -> Settings:
    return Settings(
        _env_file=None,
        workspace_root=tmp_path / "ws",
        analyzer_image=IMAGE,
        sbom_provider="syft",
        **overrides,
    )


def _job(settings, data: bytes, kind="software", ctx=None) -> AnalysisJob:
    scan_id = uuid.uuid4()
    ws = create_workspace(settings.workspace_root, scan_id)
    ws.upload_path.write_bytes(data)
    return AnalysisJob(scan_id, ws, kind, True, model_context=ctx)


def _no_containers(scan_id) -> bool:
    out = subprocess.run(  # noqa: S603 - fixed argv
        [DOCKER, "ps", "-a", "-q", "--filter", f"name=px-ana-{scan_id}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip() == ""


def test_benign_upload_is_extracted_and_analyzed_in_isolation(tmp_path):
    settings = _settings(tmp_path)
    analyzer = DockerAnalyzer(settings)
    job = _job(settings, zip_dir(SIMPLE_PROJECT))
    extract = analyzer.run(job, "extract")
    analyze = analyzer.run(job, "analyze")
    for run in (extract, analyze):
        assert run.result.status == "ok"
        assert run.result.isolation == ISOLATED  # what the kernel granted, seen from inside
        assert run.record["runtime_verified"] is True  # what docker inspect reported
        assert run.record["runtime"]["network"] == "none"
    a = analyze.analysis
    assert a.tree.sha256 == tree_digest(SIMPLE_PROJECT).sha256
    assert a.sbom is not None and a.sbom.tool_name == "syft" and a.sbom.source == "syft"
    assert _no_containers(job.scan_id)


@pytest.mark.parametrize(
    ("entries", "code"),
    [
        ([("../escape.txt", "x")], "unsafe_archive"),
        ([("/abs.txt", "x")], "unsafe_archive"),
        ([(symlink_info("link"), "/etc/passwd")], "unsafe_archive"),
    ],
    ids=["traversal", "absolute", "symlink"],
)
def test_unsafe_archives_are_rejected_inside_the_sandbox(tmp_path, entries, code):
    settings = _settings(tmp_path)
    job = _job(settings, build_zip(entries))
    run = DockerAnalyzer(settings).run(job, "extract")
    assert run.result.status == "error" and run.result.error.code == code
    assert not (job.workspace.root / "escape.txt").exists()
    assert not (settings.workspace_root / "escape.txt").exists()
    assert list(job.workspace.src_dir.iterdir()) == []
    assert _no_containers(job.scan_id)


def test_decompression_bomb_is_rejected(tmp_path):
    settings = _settings(tmp_path, max_compression_ratio=50)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros.bin", b"\0" * (20 * 1024 * 1024))
    run = DockerAnalyzer(settings).run(_job(settings, buf.getvalue()), "extract")
    assert run.result.status == "error"
    assert run.result.error.code in ("unsafe_archive", "artifact_too_large")


def test_full_software_scan_through_the_real_sandbox(
    test_settings, session_factory, public_dns, tmp_path
):
    settings = test_settings.model_copy(
        update={
            "analyzer_provider": "docker",
            "analyzer_image": IMAGE,
            "workspace_root": tmp_path / "ws",
            "max_artifact_size_mb": 50,
        }
    )
    client = _client(settings, session_factory, build_providers(settings))
    body = _post(client, "/api/v1/scans/software", zip_dir(SIMPLE_PROJECT))
    assert body["status"] == "completed", body["error"]
    assert body["artifact"]["sha256"] == tree_digest(SIMPLE_PROJECT).sha256
    runs = body["sandbox"]["runs"]
    assert [r["mode"] for r in runs] == ["extract", "analyze"]
    assert all(r["runtime_verified"] and r["isolation"] == ISOLATED for r in runs)
    assert body["stages"]["static"]["status"] in ("completed", "partial")
    assert body["stages"]["risk"]["status"] == "completed"


def test_model_with_a_dangerous_pickle_is_flagged_through_the_sandbox(
    test_settings, session_factory, public_dns, tmp_path
):
    settings = test_settings.model_copy(
        update={
            "analyzer_provider": "docker",
            "analyzer_image": IMAGE,
            "workspace_root": tmp_path / "ws",
            "max_artifact_size_mb": 50,
        }
    )
    # Built by the suite's pickle helpers: bytes only; nothing here or in the sandbox loads it.
    payload = torch_zip_bytes(reduce_pickle(os.system, ("id",)))
    data = build_zip([("pytorch_model.bin", payload), ("config.json", '{"model_type": "x"}')])
    client = _client(settings, session_factory, build_providers(settings))
    body = _post(client, "/api/v1/scans/model", data)
    assert body["status"] == "completed", body["error"]
    findings = client.get(
        f"/api/v1/scans/{body['scan_id']}/findings", params={"category": "static"}
    ).json()
    assert any(f["identifier"].startswith("PX-PICKLE") for f in findings["items"])

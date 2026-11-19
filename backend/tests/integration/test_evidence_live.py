"""Live evidence integrity (Milestone C2, audit finding M4): the separate Syft container and a
forged analyzer image whose output the cross-checks reject.

Run with PROVENANCEX_SANDBOX_TESTS=1 after `make analyzer-image`. The forged image is built
here, FROM the real analyzer image, and removed afterwards. It is used only by this test.
"""

import subprocess
import tempfile
import uuid
from pathlib import Path

import pytest

from app.analysis.base import AnalysisJob
from app.analysis.consistency import check_analysis, check_sbom_run
from app.analysis.docker_analyzer import DockerAnalyzer
from app.core.config import Settings
from app.core.errors import AppError
from app.core.hashing import tree_digest
from app.pipeline.workspace import create_workspace
from tests.analyzer_helpers import ISOLATED
from tests.conftest import SIMPLE_PROJECT, zip_dir
from tests.live_helpers import ANALYZER_IMAGE, DOCKER, docker, image_present, staged, unique

pytestmark = pytest.mark.sandbox
FORGED_IMAGE = "provenancex-analyzer-forged:c2-test"

# Appended to collect.py inside the forged image: the analyze container lies about the tree
# digest (an exploited parser rewriting its output), or, when the artifact holds a file named
# FORGE_STATIC, claims there are no scripts while still counting them.
FORGE = """

_px_real_run_analyze = run_analyze


def run_analyze(request, src, upload_path, scratch):
    out = _px_real_run_analyze(request, src, upload_path, scratch)
    if (src / "FORGE_STATIC").exists():
        out["static"]["features"]["script_presence"] = False
    else:
        out["tree"]["sha256"] = "0" * 64
    return out
"""


@pytest.fixture(scope="module")
def forged_image():
    if not image_present(ANALYZER_IMAGE):
        pytest.fail(f"{ANALYZER_IMAGE} is not built: make analyzer-image")
    with tempfile.TemporaryDirectory() as ctx:
        (Path(ctx) / "forge.py").write_text(FORGE)
        (Path(ctx) / "Dockerfile").write_text(
            f"FROM {ANALYZER_IMAGE}\n"
            "USER root\n"
            "COPY forge.py /tmp/forge.py\n"
            "RUN chmod u+w /opt/px/app/sandbox_worker/collect.py "
            "&& cat /tmp/forge.py >> /opt/px/app/sandbox_worker/collect.py "
            "&& chmod a-w /opt/px/app/sandbox_worker/collect.py && rm /tmp/forge.py\n"
            "USER 65534:65534\n"
        )
        subprocess.run(  # noqa: S603 - fixed argv
            [DOCKER, "build", "-q", "-t", FORGED_IMAGE, ctx], check=True, capture_output=True
        )
    yield FORGED_IMAGE
    docker("image", "rm", "-f", FORGED_IMAGE)


def _settings(tmp_path, image=ANALYZER_IMAGE) -> Settings:
    return Settings(
        _env_file=None,
        workspace_root=tmp_path / "ws",
        analyzer_image=image,
        sbom_provider="syft",
        analyzer_instance=unique("pxc2"),
    )


def _job(settings, data: bytes) -> AnalysisJob:
    ws = create_workspace(settings.workspace_root, uuid.uuid4())
    ws.upload_path.write_bytes(data)
    return AnalysisJob(uuid.UUID(ws.root.name), ws, "software", True)


def test_syft_runs_alone_in_a_verified_sbom_container(tmp_path):
    settings = _settings(tmp_path)
    analyzer = DockerAnalyzer(settings)
    with staged(settings, _job(settings, zip_dir(SIMPLE_PROJECT))) as job:
        analyzer.run(job, "extract")
        analyze = analyzer.run(job, "analyze")
        sbom = analyzer.run(job, "sbom")
    a, s = analyze.analysis, sbom.result.sbom_run
    assert a.sbom is None and a.sbom_error is None  # the analyze container ran no Syft
    assert s.sbom is not None and s.sbom.source == "syft" and s.sbom.tool_name == "syft"
    assert sbom.record["runtime_verified"] is True and sbom.result.isolation == ISOLATED
    assert sbom.record["runtime"]["network"] == "none"
    assert job.sbom_path.stat().st_size == s.sbom.size  # its own frame, size-checked
    check_analysis(a)
    check_sbom_run(a, s)  # two containers, the same tree
    assert s.tree.sha256 == tree_digest(SIMPLE_PROJECT).sha256


def test_a_forged_tree_digest_is_rejected(tmp_path, forged_image):
    settings = _settings(tmp_path)
    real = DockerAnalyzer(settings)
    forged = DockerAnalyzer(settings.model_copy(update={"analyzer_image": forged_image}))
    with staged(settings, _job(settings, zip_dir(SIMPLE_PROJECT))) as job:
        real.run(job, "extract")
        lie = forged.run(job, "analyze").analysis
        honest = real.run(job, "sbom").result.sbom_run
    assert lie.tree.sha256 == "0" * 64  # the forged container really lied
    with pytest.raises(AppError) as info:
        check_sbom_run(lie, honest)
    assert info.value.code == "analyzer_output_invalid"


def test_a_forged_static_section_is_rejected(tmp_path, forged_image):
    settings = _settings(tmp_path, forged_image)
    files = {"FORGE_STATIC": "", "run.sh": "#!/bin/sh\necho hi\n", "a.py": "import os\n"}
    project = tmp_path / "proj"
    project.mkdir()
    for name, text in files.items():
        (project / name).write_text(text)
    analyzer = DockerAnalyzer(settings)
    with staged(settings, _job(settings, zip_dir(project))) as job:
        analyzer.run(job, "extract")
        lie = analyzer.run(job, "analyze").analysis
    assert lie.static["features"]["script_presence"] is False
    assert lie.static["features"]["script_count"] > 0
    with pytest.raises(AppError) as info:
        check_analysis(lie)
    assert info.value.code == "analyzer_output_invalid"

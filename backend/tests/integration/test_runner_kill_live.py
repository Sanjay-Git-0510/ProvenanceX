"""Runner killed mid-analysis, against real Docker (audit finding M1).

Run with PROVENANCEX_SANDBOX_TESTS=1 after `make analyzer-image`.

A helper process plays the scan-runner: it runs a real analyzer step through DockerAnalyzer
(create, verify, attach, send the request) on a CPU-throttled container. The test
kills the helper's whole process group with SIGKILL, as `docker kill` would kill the runner
container, so no `finally` runs. It then checks that:
  1. the analyzer container outlives the runner (the audit finding, reproduced);
  2. the container stops by itself at its in-container deadline;
  3. a restarted runner's recovery pass fails the scan, replaces its claim, removes the
     container and the workspace;
  4. containers of another deployment and unlabelled containers are left alone;
  5. repeating the pass is harmless.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import time
import uuid
from datetime import timedelta
from pathlib import Path

import pytest

from app.analysis.reconcile import OrphanReconciler
from app.core.config import Settings
from app.db.models import Artifact, ArtifactSource, ArtifactType, Scan, ScanStatus, utcnow
from app.pipeline.workspace import create_workspace
from app.runner.main import reconcile_once
from app.runner.queue import claim_scan
from app.sandbox_worker.protocol import EXIT_DEADLINE

pytestmark = pytest.mark.sandbox
IMAGE = "provenancex-analyzer:0.1.0"
DOCKER = shutil.which("docker") or "docker"
BACKEND = Path(__file__).resolve().parents[2]
DEADLINE = 8
THROTTLED_CPUS = "0.05"
RUNNER_ID = "kill-test-runner"

# The helper is a real runner step: DockerAnalyzer.run, unmodified, sends a real request. The
# container gets 5% of one CPU, so the worker is still busy (CPU-bound) long after the helper
# is killed: the situation in which, before the fix, nothing would ever stop it.
BUSY_RUNNER = textwrap.dedent(
    """
    import sys, uuid
    from pathlib import Path
    from app.analysis.base import AnalysisJob
    from app.analysis.docker_analyzer import DockerAnalyzer
    from app.core.config import Settings
    from app.pipeline.ownership import ScanClaim, claim_context
    from app.pipeline.workspace import Workspace

    scan_id, token, root, instance = sys.argv[1:5]
    settings = Settings(
        _env_file=None, workspace_root=Path(root), analyzer_image="%(image)s",
        analyzer_timeout_seconds=%(deadline)d, analyzer_extract_timeout_seconds=%(deadline)d,
        analyzer_host_grace_seconds=60, analyzer_cpus=%(cpus)s, analyzer_instance=instance,
        sbom_provider="syft",
    )
    job = AnalysisJob(uuid.UUID(scan_id), Workspace(Path(root) / scan_id), "software", False)
    print("STARTING", flush=True)
    with claim_context(ScanClaim(uuid.UUID(scan_id), uuid.UUID(token))):
        DockerAnalyzer(settings).run(job, "analyze")
    """
) % {"image": IMAGE, "deadline": DEADLINE, "cpus": THROTTLED_CPUS}


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv
        [DOCKER, *args], capture_output=True, text=True, timeout=60, check=False
    )


def _state(name: str) -> dict | None:
    done = _docker("inspect", "--format", "{{json .State}}", name)
    return json.loads(done.stdout) if done.returncode == 0 else None


@pytest.fixture(scope="module", autouse=True)
def _image_present():
    if shutil.which("docker") is None:
        pytest.fail("docker CLI not found")
    if _docker("image", "inspect", IMAGE).returncode != 0:
        pytest.fail(f"{IMAGE} is not built: make analyzer-image")


@pytest.fixture
def bystanders(request):
    """Containers that must survive: another deployment's analyzer and an unlabelled one."""
    suffix = uuid.uuid4().hex[:8]
    names = [f"px-kill-other-project-{suffix}", f"px-kill-unlabelled-{suffix}"]
    other_scan = str(uuid.uuid4())
    _docker(
        "create", "--name", names[0], "--network=none",
        "--label=io.provenancex.role=analyzer",
        "--label=io.provenancex.instance=some_other_project",
        f"--label=io.provenancex.scan-id={other_scan}",
        "--label=io.provenancex.claim=none", "--label=io.provenancex.mode=analyze",
        IMAGE, "--mode", "analyze",
    )  # fmt: skip
    _docker("create", "--name", names[1], "--network=none", IMAGE, "--mode", "analyze")
    yield names
    for name in names:
        _docker("rm", "--force", name)


def test_killed_runner_leaves_no_analyzer_behind(tmp_path, session_factory, bystanders):
    instance = f"px_kill_{uuid.uuid4().hex[:8]}"
    settings = Settings(
        _env_file=None,
        workspace_root=tmp_path / "ws",
        analyzer_image=IMAGE,
        analyzer_instance=instance,
        analyzer_timeout_seconds=DEADLINE,
        analyzer_extract_timeout_seconds=DEADLINE,
        runner_heartbeat_seconds=1,
        runner_stale_seconds=120,
    )
    with session_factory() as s:
        scan = Scan(
            id=uuid.uuid4(),
            artifact=Artifact(
                artifact_type=ArtifactType.SOFTWARE, name="kill", source=ArtifactSource.UPLOAD
            ),
            status=ScanStatus.QUEUED,
            scanner_version="0.1.0",
        )
        s.add(scan)
        s.commit()
        claim = claim_scan(s, scan.id, RUNNER_ID)
    workspace = create_workspace(settings.workspace_root, claim.scan_id)
    (workspace.src_dir / "app.py").write_text("print('benign fixture')\n")
    name = f"px-ana-{claim.scan_id}-analyze"

    runner = subprocess.Popen(  # noqa: S603 - benign helper script
        [sys.executable, "-c", BUSY_RUNNER, str(claim.scan_id), str(claim.token),
         str(settings.workspace_root), instance],
        cwd=BACKEND, stdout=subprocess.PIPE, text=True, start_new_session=True,
    )  # fmt: skip
    try:
        line = runner.stdout.readline()
        assert line.startswith("STARTING"), line
        for _ in range(300):
            if (_state(name) or {}).get("Running"):
                break
            time.sleep(0.1)
        time.sleep(1.0)  # the request has been delivered; the worker is busy
        os.killpg(runner.pid, signal.SIGKILL)  # the runner dies; its finally never runs
        runner.wait(10)
        killed_at = time.monotonic()

        # 1. The audit finding: the analyzer outlives its runner.
        state = _state(name)
        assert state is not None and state["Running"], "analyzer should still be running"

        # 2. It stops itself at its in-container deadline (exit 124), not by finishing.
        while (_state(name) or {}).get("Running") and time.monotonic() - killed_at < 60:
            time.sleep(0.5)
        state = _state(name)
        assert state is not None and not state["Running"]
        assert state["ExitCode"] == EXIT_DEADLINE
        assert time.monotonic() - killed_at < DEADLINE + 20

        # 3. A restarted runner recovers: the scan, its container and its workspace.
        with session_factory() as s:  # heartbeat silent long enough for startup recovery
            s.get(Scan, claim.scan_id).heartbeat_at = utcnow() - timedelta(seconds=30)
            s.commit()
        recovered, report = reconcile_once(
            session_factory, settings, RUNNER_ID, OrphanReconciler(settings)
        )
        assert recovered == [claim.scan_id]
        assert _state(name) is None, "orphaned analyzer container was not removed"
        assert len(report.removed) == 1
        assert not workspace.root.exists()
        with session_factory() as s:
            row = s.get(Scan, claim.scan_id)
            assert row.status == ScanStatus.FAILED and row.error_code == "runner_interrupted"
            assert row.claim_token != claim.token

        # 4. Nothing else was touched.
        for other in bystanders:
            assert _state(other) is not None, f"{other} must not be removed"

        # 5. Repeating the pass is harmless.
        recovered, report = reconcile_once(
            session_factory, settings, RUNNER_ID, OrphanReconciler(settings)
        )
        assert recovered == [] and report.removed == [] and report.error is None
    finally:
        if runner.poll() is None:
            os.killpg(runner.pid, signal.SIGKILL)
        _docker("rm", "--force", name)

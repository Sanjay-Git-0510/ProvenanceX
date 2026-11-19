"""Analyzer container lifetime (audit finding M1): labels, self-imposed limits, orphan cleanup.

The live version (real Docker, real runner kill) is tests/integration/test_runner_kill_live.py.
"""

import subprocess
import sys
import textwrap
import time
import uuid
from datetime import timedelta
from pathlib import Path

import pytest

from app.analysis.hardening import (
    LABEL_CLAIM,
    LABEL_INSTANCE,
    LABEL_SCAN,
    AnalyzerLimits,
    AnalyzerSpec,
    MountSpec,
    assert_create_hardened,
    build_create_argv,
)
from app.analysis.reconcile import (
    AnalyzerContainer,
    OrphanReconciler,
    ScanOwnership,
    decide,
)
from app.core.config import Settings
from app.core.errors import AppError
from app.db.models import Artifact, ArtifactSource, ArtifactType, Scan, ScanStatus, utcnow
from app.pipeline.ownership import ScanClaim, claim_context
from app.pipeline.workspace import create_workspace
from app.runner.main import reconcile_once
from app.runner.queue import claim_scan
from app.sandbox_worker.protocol import EXIT_CPU_LIMIT, EXIT_DEADLINE
from tests.analyzer_helpers import FakeDocker, analyzer_settings, make_job

BACKEND = Path(__file__).resolve().parents[2]
SCAN = uuid.UUID("12345678-1234-1234-1234-123456789abc")
LIMITS = AnalyzerLimits(timeout_seconds=60, memory_mb=1024, cpus=1.5, pids=64, tmp_mb=128)


def _spec(claim="none", instance="px_ws") -> AnalyzerSpec:
    mounts = (MountSpec("bind", f"/ws/{SCAN}/src", "/artifact", "src", True, SCAN),)
    return AnalyzerSpec(
        SCAN, "analyze", "img:1", 1000, 1000, mounts, LIMITS, instance=instance, claim_token=claim
    )


def _refused(argv):
    with pytest.raises(AppError) as info:
        assert_create_hardened(argv)
    assert info.value.code == "sandbox_refused"


# ----------------------------------------------------------------------------- create argv
def test_command_carries_labels_deadline_and_cpu_limit():
    token = str(uuid.uuid4())
    argv = build_create_argv("docker", _spec(claim=token))
    assert assert_create_hardened(argv) == "analyze"
    assert f"--label={LABEL_SCAN}={SCAN}" in argv
    assert f"--label={LABEL_CLAIM}={token}" in argv
    assert f"--label={LABEL_INSTANCE}=px_ws" in argv
    assert argv[-6:] == ["--deadline", "60", "--cpu-seconds", "120", "--mode", "analyze"]


@pytest.mark.parametrize("key", [LABEL_SCAN, LABEL_CLAIM, LABEL_INSTANCE])
def test_each_label_is_required(key):
    argv = [a for a in build_create_argv("docker", _spec()) if not a.startswith(f"--label={key}=")]
    _refused(argv)


@pytest.mark.parametrize(
    "bad",
    [
        f"--label={LABEL_SCAN}=87654321-1234-1234-1234-123456789abc",  # not this container
        f"--label={LABEL_CLAIM}=anything",
        f"--label={LABEL_INSTANCE}=bad,instance",
        "--label=io.provenancex.role=worker",
    ],
)
def test_wrong_label_values_are_refused(bad):
    argv = build_create_argv("docker", _spec())
    key = bad.split("=", 2)[0] + "=" + bad.split("=", 2)[1]
    idx = next(i for i, a in enumerate(argv) if a.startswith(key + "="))
    argv[idx] = bad
    _refused(argv)


def test_unknown_or_duplicate_labels_are_refused():
    argv = build_create_argv("docker", _spec())
    _refused([*argv[:3], "--label=com.example.x=1", *argv[3:]])
    dup = next(a for a in argv if a.startswith(f"--label={LABEL_SCAN}="))
    _refused([*argv[:3], dup, *argv[3:]])


@pytest.mark.parametrize("deadline", ["0", "-1", "abc", str(10**9)])
def test_deadline_must_be_a_sane_positive_integer(deadline):
    argv = build_create_argv("docker", _spec())
    argv[argv.index("--deadline") + 1] = deadline
    _refused(argv)


def test_deadline_and_cpu_limit_cannot_be_dropped():
    argv = build_create_argv("docker", _spec())
    i = argv.index("--deadline")
    _refused(argv[:i] + argv[i + 2 :])
    j = argv.index("--cpu-seconds")
    _refused(argv[:j] + argv[j + 2 :])


# ----------------------------------------------------------------------------- runtime checks
@pytest.mark.parametrize("tamper", ["labels", "deadline", "restart"])
def test_runtime_drift_in_lifetime_settings_is_refused(tmp_path, monkeypatch, tamper):
    fake = FakeDocker(tmp_path, monkeypatch, tamper=[tamper])
    settings = analyzer_settings(tmp_path, fake.path)
    from app.analysis.docker_analyzer import DockerAnalyzer

    with pytest.raises(AppError) as info:
        DockerAnalyzer(settings).run(make_job(settings), "extract")
    assert info.value.code == "sandbox_refused"
    assert "start" not in fake.verbs()


def test_container_is_labelled_with_the_current_claim(tmp_path, monkeypatch):
    fake = FakeDocker(tmp_path, monkeypatch, start="silent")
    settings = analyzer_settings(tmp_path, fake.path, analyzer_instance="proj_a")
    job = make_job(settings)
    claim = ScanClaim(job.scan_id, uuid.uuid4())
    from app.analysis.docker_analyzer import DockerAnalyzer

    with claim_context(claim), pytest.raises(AppError):
        DockerAnalyzer(settings).run(job, "extract")  # "silent" output is invalid; fine here
    create = next(c for c in fake.calls() if c[0] == "create")
    assert f"--label={LABEL_CLAIM}={claim.token}" in create
    assert f"--label={LABEL_INSTANCE}=proj_a" in create
    assert fake.verbs()[-1] == "rm"


def test_lost_claim_stops_the_run_and_removes_the_container(tmp_path, monkeypatch):
    from app.analysis.docker_analyzer import DockerAnalyzer
    from app.pipeline.ownership import ClaimLost

    fake = FakeDocker(tmp_path, monkeypatch, start="sleep")
    settings = analyzer_settings(tmp_path, fake.path)
    job = make_job(settings)
    claim = ScanClaim(job.scan_id, uuid.uuid4())
    import threading

    threading.Timer(0.5, claim.lost.set).start()
    started = time.monotonic()
    with claim_context(claim), pytest.raises(ClaimLost):
        DockerAnalyzer(settings).run(job, "extract")
    assert time.monotonic() - started < 10  # well before the 20 s limit
    assert "kill" in fake.verbs() and fake.verbs()[-1] == "rm"


def test_a_lost_claim_never_creates_a_container(tmp_path, monkeypatch):
    from app.analysis.docker_analyzer import DockerAnalyzer
    from app.pipeline.ownership import ClaimLost

    fake = FakeDocker(tmp_path, monkeypatch)
    settings = analyzer_settings(tmp_path, fake.path)
    job = make_job(settings)
    claim = ScanClaim(job.scan_id, uuid.uuid4())
    claim.lost.set()
    with claim_context(claim), pytest.raises(ClaimLost):
        DockerAnalyzer(settings).run(job, "extract")
    assert "create" not in fake.verbs()


@pytest.mark.parametrize(
    ("exit_code", "flag"), [(EXIT_DEADLINE, "timed_out"), (EXIT_CPU_LIMIT, "cpu_limited")]
)
def test_self_imposed_limit_exits_are_reported(tmp_path, monkeypatch, exit_code, flag):
    from app.analysis.docker_analyzer import DockerAnalyzer

    fake = FakeDocker(tmp_path, monkeypatch, start="silent", exit_code=exit_code)
    settings = analyzer_settings(tmp_path, fake.path)
    with pytest.raises(AppError) as info:
        DockerAnalyzer(settings).run(make_job(settings), "extract")
    assert info.value.code == "sandbox_failed"
    assert info.value.details[flag] is True


# ----------------------------------------------------------------------------- worker limits
def _supervised(body: str, deadline: int, cpu: int | None) -> tuple[int, float]:
    script = textwrap.dedent(
        f"""
        import sys, time
        from app.sandbox_worker.__main__ import supervise
        code = supervise({deadline}, {cpu})
        if code is not None:
            sys.exit(code)
        {body}
        """
    )
    started = time.monotonic()
    done = subprocess.run(  # noqa: S603 - fixed argv, benign script
        [sys.executable, "-c", script], cwd=BACKEND, timeout=60, check=False
    )
    return done.returncode, time.monotonic() - started


def test_worker_stops_itself_at_the_deadline():
    code, took = _supervised("time.sleep(60)", deadline=1, cpu=None)
    assert code == EXIT_DEADLINE
    assert took < 15


def test_worker_stops_itself_at_the_cpu_limit():
    code, took = _supervised("while True: pass", deadline=50, cpu=1)
    assert code == EXIT_CPU_LIMIT
    assert took < 40


def test_worker_exit_code_passes_through():
    code, _ = _supervised("sys.exit(3)", deadline=30, cpu=30)
    assert code == 3


# ----------------------------------------------------------------------------- reconcile
NOW = utcnow()


def _container(state="running", claim="c1", scan=SCAN) -> AnalyzerContainer:
    return AnalyzerContainer("id1", "px-ana-x", state, "px_ws", scan, claim)


@pytest.mark.parametrize(
    ("scan", "state", "expected"),
    [
        (ScanOwnership(ScanStatus.RUNNING, "c1", NOW), "running", "keep"),
        (ScanOwnership(ScanStatus.RUNNING, "c2", NOW), "running", "remove"),  # replaced claim
        (ScanOwnership(ScanStatus.RUNNING, None, NOW), "running", "remove"),
        (ScanOwnership(ScanStatus.RUNNING, "c1", NOW - timedelta(hours=1)), "running", "remove"),
        (ScanOwnership(ScanStatus.FAILED, "c1", NOW), "running", "remove"),
        (ScanOwnership(ScanStatus.COMPLETED, "c1", NOW), "exited", "remove"),
        (None, "running", "keep"),  # unknown to this database and still running
        (None, "exited", "remove"),
    ],
)
def test_decide(scan, state, expected):
    assert decide(_container(state=state), scan, NOW, 120) == expected


class FakeDockerCli:
    """Answers `docker ps` with fixed lines and records `docker rm` calls."""

    def __init__(self, lines: list[str], ps_exit: int = 0):
        self.lines = lines
        self.ps_exit = ps_exit
        self.removed: list[str] = []
        self.gone: set[str] = set()

    def __call__(self, args):
        if args[0] == "ps":
            visible = [ln for ln in self.lines if ln.split("\t")[0] not in self.gone]
            return self.ps_exit, "\n".join(visible).encode()
        if args[:2] == ["rm", "--force"]:
            cid = args[2]
            if cid in self.gone:
                return 1, b""
            self.gone.add(cid)
            self.removed.append(cid)
            return 0, b""
        raise AssertionError(args)


def _line(cid, scan, claim, instance="px_ws", role="analyzer", state="running"):
    return "\t".join([cid, f"px-ana-{scan}-analyze", state, role, instance, str(scan), claim])


def _scan_row(session, status=ScanStatus.RUNNING, token=None, heartbeat=None):
    scan = Scan(
        id=uuid.uuid4(),
        artifact=Artifact(
            artifact_type=ArtifactType.SOFTWARE, name="x", source=ArtifactSource.UPLOAD
        ),
        status=status,
        scanner_version="0.1.0",
        claim_token=token,
        heartbeat_at=heartbeat or utcnow(),
        claimed_at=utcnow(),
    )
    session.add(scan)
    session.commit()
    return scan.id


def _settings(tmp_path, **kw):
    return Settings(
        _env_file=None,
        workspace_root=tmp_path / "workspaces",
        analyzer_workspace_volume="px_ws",
        **kw,
    )


def test_reconcile_removes_only_orphans_of_this_instance(session_factory, tmp_path):
    live_token = uuid.uuid4()
    with session_factory() as s:
        live = _scan_row(s, token=live_token)
        failed = _scan_row(s, status=ScanStatus.FAILED, token=uuid.uuid4())
        replaced = _scan_row(s, token=uuid.uuid4())
    cli = FakeDockerCli(
        [
            _line("c-live", live, str(live_token)),
            _line("c-failed", failed, "none", state="exited"),
            _line("c-replaced", replaced, str(uuid.uuid4())),
            # The ps filter would never return these; the reconciler re-checks anyway.
            _line("c-other-project", failed, "none", instance="other_ws"),
            _line("c-not-analyzer", failed, "none", role="db"),
        ]
    )
    reconciler = OrphanReconciler(_settings(tmp_path), cli)
    with session_factory() as s:
        report = reconciler.reconcile(s)
    assert sorted(cli.removed) == ["c-failed", "c-replaced"]
    assert report.kept == ["c-live"]
    # Idempotent: a second pass finds nothing more to do and does not fail.
    with session_factory() as s:
        again = reconciler.reconcile(s)
    assert again.removed == [] and again.kept == ["c-live"]


def test_reconcile_lists_with_both_filters(tmp_path, session_factory):
    seen = []

    def cli(args):
        seen.append(args)
        return 0, b""

    with session_factory() as s:
        OrphanReconciler(_settings(tmp_path, analyzer_instance="proj_b"), cli).reconcile(s)
    ps = seen[0]
    assert "label=io.provenancex.role=analyzer" in ps
    assert "label=io.provenancex.instance=proj_b" in ps


def test_concurrent_removal_is_harmless(session_factory, tmp_path):
    """Another runner removed the container between our `ps` and our `rm`."""
    with session_factory() as s:
        failed = _scan_row(s, status=ScanStatus.FAILED)

    def racing(args):
        if args[0] == "ps":
            return 0, _line("c1", failed, "none").encode()
        return 1, b""  # docker rm: no such container

    with session_factory() as s:
        report = OrphanReconciler(_settings(tmp_path), racing).reconcile(s)
    assert report.failed == ["c1"] and report.removed == []


def test_docker_unavailable_is_reported_not_raised(session_factory, tmp_path):
    with session_factory() as s:
        report = OrphanReconciler(_settings(tmp_path), FakeDockerCli([], ps_exit=1)).reconcile(s)
    assert report.error == "docker unavailable"


def test_reconcile_once_recovers_kills_and_cleans_workspaces(session_factory, tmp_path):
    settings = _settings(tmp_path)
    with session_factory() as s:
        queued = Scan(
            id=uuid.uuid4(),
            artifact=Artifact(
                artifact_type=ArtifactType.SOFTWARE, name="x", source=ArtifactSource.UPLOAD
            ),
            status=ScanStatus.QUEUED,
            scanner_version="0.1.0",
        )
        s.add(queued)
        s.commit()
        claim = claim_scan(s, queued.id, "runner-a")
        s.get(Scan, claim.scan_id).heartbeat_at = utcnow() - timedelta(minutes=10)
        s.commit()
        bystander = _scan_row(s, token=uuid.uuid4())  # another runner's live scan
    ws = create_workspace(settings.workspace_root, claim.scan_id)
    other_ws = create_workspace(settings.workspace_root, bystander)
    cli = FakeDockerCli([_line("c-orphan", claim.scan_id, str(claim.token))])
    recovered, report = reconcile_once(
        session_factory, settings, "runner-a", OrphanReconciler(settings, cli)
    )
    assert recovered == [claim.scan_id]
    assert cli.removed == ["c-orphan"]
    assert not ws.root.exists()
    assert other_ws.root.exists()
    with session_factory() as s:
        assert s.get(Scan, claim.scan_id).status == ScanStatus.FAILED
        assert s.get(Scan, bystander).status == ScanStatus.RUNNING
    # Repeating the pass is safe.
    recovered, _ = reconcile_once(
        session_factory, settings, "runner-a", OrphanReconciler(settings, cli)
    )
    assert recovered == []


def test_settings_reject_unsafe_runner_timing():
    with pytest.raises(ValueError):
        Settings(_env_file=None, runner_heartbeat_seconds=60, runner_stale_seconds=120)
    with pytest.raises(ValueError):
        Settings(_env_file=None, runner_max_scan_seconds=60)


def test_instance_label_defaults_to_the_workspace_volume():
    assert Settings(_env_file=None, analyzer_workspace_volume="vol_x").analyzer_instance_label == (
        "vol_x"
    )
    assert Settings(_env_file=None, analyzer_instance="i1").analyzer_instance_label == "i1"


def test_compose_runner_restarts_and_waits_for_a_full_scan():
    import yaml

    compose = yaml.safe_load((BACKEND.parent / "docker-compose.yml").read_text())
    runner = compose["services"]["scan-runner"]
    assert runner["restart"] == "unless-stopped"
    grace = runner["stop_grace_period"]
    minutes = int(grace.split(":-")[1].rstrip("m}")) if ":-" in grace else int(grace.rstrip("m"))
    max_scan = int(
        compose["services"]["api"]["environment"]["RUNNER_MAX_SCAN_SECONDS"]
        .split(":-")[1]
        .rstrip("}")
    )
    assert minutes * 60 > max_scan

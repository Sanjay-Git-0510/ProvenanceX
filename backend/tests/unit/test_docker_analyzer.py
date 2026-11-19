"""DockerAnalyzer with a fake Docker CLI: every failure fails closed, cleanup always runs."""

import pytest

from app.analysis.docker_analyzer import DockerAnalyzer
from app.core.errors import AppError
from tests.analyzer_helpers import (
    ISOLATED,
    FakeDocker,
    analyzer_settings,
    make_job,
    worker_output,
)


@pytest.fixture
def fake(tmp_path, monkeypatch):
    return FakeDocker(tmp_path, monkeypatch)


def _run(tmp_path, fake, mode="extract", *, upload=True, **overrides):
    settings = analyzer_settings(tmp_path, fake.path, **overrides)
    job = make_job(settings, upload=upload)
    return DockerAnalyzer(settings).run(job, mode), job


def _error(tmp_path, fake, mode="extract", **overrides) -> AppError:
    with pytest.raises(AppError) as info:
        _run(tmp_path, fake, mode, **overrides)
    return info.value


def test_extract_happy_path_verifies_then_cleans_up(tmp_path, fake):
    fake.configure(start="ok", output_file=str(worker_output(tmp_path / "out", "extract")))
    run, job = _run(tmp_path, fake)
    assert run.result.status == "ok"
    assert run.record["runtime_verified"] is True
    assert run.record["runtime"]["network"] == "none"
    assert run.record["isolation"] == ISOLATED
    # Order: stale removal, create, inspect, start, state, and removal again (always).
    verbs = fake.verbs()
    assert verbs[:2] == ["version", "image inspect"]
    verbs = verbs[1:]
    assert verbs[1:] == ["rm", "create", "inspect", "start", "inspect", "rm"]
    assert fake.calls()[-1] == ["rm", "-f", f"px-ana-{job.scan_id}-extract"]


def test_request_on_stdin_carries_no_secrets(tmp_path, fake, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:hunter2@db/x")
    fake.configure(start="ok", output_file=str(worker_output(tmp_path / "out", "analyze")))
    _run(tmp_path, fake, "analyze")
    request = fake.stdin()
    assert request["mode"] == "analyze" and request["format"].startswith("provenancex-analyzer")
    assert "hunter2" not in (fake.state / "stdin.json").read_text()
    assert "database_url" not in request["limits"]


def test_analyze_mounts_the_staging_volume_read_only(tmp_path, fake):
    fake.configure(start="ok", output_file=str(worker_output(tmp_path / "out", "analyze")))
    run, job = _run(tmp_path, fake, "analyze")
    create = next(c for c in fake.calls() if c[0] == "create")
    mounts = [a for a in create if a.startswith("--mount=")]
    assert (
        f"--mount=type=volume,src=px-stg-{job.scan_id},dst=/artifact,volume-nocopy,readonly"
        in mounts
    )
    assert not any("/out/src" in m for m in mounts)
    assert run.result.analysis.tree.file_count == 1


def test_volume_mode_uses_named_volume_subpaths(tmp_path, fake):
    fake.configure(start="ok", output_file=str(worker_output(tmp_path / "out", "extract")))
    _run(tmp_path, fake, analyzer_workspace_mount="volume", analyzer_workspace_volume="px_ws")
    create = next(c for c in fake.calls() if c[0] == "create")
    mounts = [a for a in create if a.startswith("--mount=")]
    workspace = [m for m in mounts if "src=px-stg-" not in m]
    assert workspace and all(m.startswith("--mount=type=volume,src=px_ws,") for m in workspace)
    assert any("volume-subpath=" in m and "/input" in m for m in workspace)
    # extract writes only into the kernel-capped staging volume, never the workspace.
    assert any("src=px-stg-" in m and "dst=/out/src" in m for m in mounts)


def test_missing_docker_is_unavailable(tmp_path, fake):
    err = _error(tmp_path, fake, analyzer_docker_path=str(tmp_path / "no-such-docker"))
    assert err.code == "sandbox_unavailable"
    assert "not processed" in err.message


def test_unreachable_daemon_is_unavailable(tmp_path, fake):
    fake.configure(daemon_exit=1)
    err = _error(tmp_path, fake)
    assert err.code == "sandbox_unavailable" and "socket" in err.message
    assert "create" not in fake.verbs()


def test_missing_image_is_unavailable_and_nothing_is_created(tmp_path, fake):
    fake.configure(image_exit=1)
    err = _error(tmp_path, fake)
    assert err.code == "sandbox_unavailable"
    assert "create" not in fake.verbs()


def test_create_failure_fails_and_cleans_up(tmp_path, fake):
    fake.configure(create_exit=125)
    err = _error(tmp_path, fake)
    assert err.code == "sandbox_failed"
    assert fake.verbs()[-1] == "rm" and "start" not in fake.verbs()


@pytest.mark.parametrize(
    "tamper",
    [
        "network",
        "readonly",
        "privileged",
        "capadd",
        "memory",
        "pids",
        "socket",
        "writable_artifact",
        "secret_env",
        "user",
    ],
)
def test_runtime_config_drift_is_refused_before_start(tmp_path, fake, tamper):
    fake.configure(tamper=[tamper], start="ok", output_file="/nonexistent")
    err = _error(tmp_path, fake)
    assert err.code == "sandbox_refused"
    assert "start" not in fake.verbs(), "the container must never start"
    assert fake.verbs()[-1] == "rm"


def test_timeout_kills_and_removes(tmp_path, fake):
    fake.configure(start="sleep")
    err = _error(tmp_path, fake, analyzer_extract_timeout_seconds=1, analyzer_host_grace_seconds=1)
    assert err.code == "sandbox_failed" and err.details["timed_out"] is True
    assert "kill" in fake.verbs() and fake.verbs()[-1] == "rm"


def test_oom_kill_fails(tmp_path, fake):
    fake.configure(start="silent", exit_code=137, oom_killed=True)
    err = _error(tmp_path, fake)
    assert err.code == "sandbox_failed" and err.details["oom_killed"] is True


def test_abnormal_exit_fails(tmp_path, fake):
    fake.configure(start="silent", exit_code=3)
    err = _error(tmp_path, fake)
    assert err.code == "sandbox_failed" and err.details["exit_code"] == 3


def test_oversized_output_is_discarded(tmp_path, fake):
    fake.configure(start="huge")
    err = _error(tmp_path, fake, analyzer_max_output_mb=1)
    assert err.code == "analyzer_output_invalid"
    assert fake.verbs()[-1] == "rm"


def test_invalid_json_is_discarded(tmp_path, fake):
    out = worker_output(tmp_path / "out", "extract", raw=b"{not json")
    fake.configure(start="ok", output_file=str(out))
    assert _error(tmp_path, fake).code == "analyzer_output_invalid"


def test_failed_self_check_is_refused(tmp_path, fake):
    out = worker_output(
        tmp_path / "out", "extract", isolation={**ISOLATED, "network_isolated": False}
    )
    fake.configure(start="ok", output_file=str(out))
    err = _error(tmp_path, fake)
    assert err.code == "sandbox_refused"
    assert err.details["failed_checks"] == ["network_isolated"]


def test_docker_result_claiming_inprocess_isolation_is_refused(tmp_path, fake):
    out = worker_output(tmp_path / "out", "extract", isolation_mode="inprocess_test")
    fake.configure(start="ok", output_file=str(out))
    assert _error(tmp_path, fake).code == "sandbox_refused"


def test_result_for_the_wrong_mode_is_discarded(tmp_path, fake):
    fake.configure(start="ok", output_file=str(worker_output(tmp_path / "out", "analyze")))
    assert _error(tmp_path, fake, "extract").code == "analyzer_output_invalid"


def test_worker_error_result_is_returned_for_the_pipeline(tmp_path, fake):
    error = {"code": "unsafe_archive", "message": "Path traversal in archive", "details": None}
    out = worker_output(tmp_path / "out", "extract", status="error", error=error)
    fake.configure(start="ok", output_file=str(out))
    run, _ = _run(tmp_path, fake)
    assert run.result.status == "error" and run.result.error.code == "unsafe_archive"

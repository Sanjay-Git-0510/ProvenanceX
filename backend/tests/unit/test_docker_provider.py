"""Docker provider against a fake `docker` executable. No real container is started."""

import json
import stat
import sys
import threading
import time
from unittest import mock
from uuid import uuid4

import pytest

from app.core.errors import AppError, ErrorCode
from app.scanners.sandbox.base import SandboxRequest, SandboxRun
from app.scanners.sandbox.docker_provider import DockerSandboxProvider
from app.scanners.sandbox.hardening import SandboxLimits

BUNDLE = b'{"format": "provenancex-trace-v1"}'
LIMITS = SandboxLimits(1, 64, 1.0, 16, 8, 8)
FAKE = """#!{python}
import pathlib, sys, time
here = pathlib.Path(__file__).parent
with (here / "calls").open("a") as log:
    log.write(" ".join(sys.argv[1:]) + "\\n")
mode = (here / "mode").read_text().strip()
command = sys.argv[1]
if command == "image":
    sys.exit(1 if mode == "noimage" else 0)
if command in ("kill", "rm"):
    sys.exit(0)
if mode == "ok":
    sys.stdout.write({bundle!r})
elif mode == "exit0_empty":
    pass
elif mode == "exit137_empty":
    sys.exit(137)
elif mode == "fail125":
    sys.stderr.write("docker: daemon error")
    sys.exit(125)
elif mode == "sleep":
    time.sleep(30)
elif mode == "stderr_flood":
    sys.stderr.write("y" * 200000)
    sys.stderr.flush()
    time.sleep(30)
elif mode == "ok_with_stderr":
    sys.stderr.write("short warning")
    sys.stdout.write({bundle!r})
elif mode == "flood":
    sys.stdout.write("x" * 200000)
    sys.stdout.flush()
    time.sleep(30)
"""


@pytest.fixture
def harness(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE.format(python=sys.executable, bundle=BUNDLE.decode()))
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    root = tmp_path / "ws"
    src = root / "scan" / "src"
    src.mkdir(parents=True)
    return bin_dir, docker, root, src


def run(harness, mode, **kw):
    bin_dir, docker, root, src = harness
    (bin_dir / "mode").write_text(mode)
    args = {"max_trace_bytes": 100_000, "grace_seconds": 1}
    provider = DockerSandboxProvider(str(docker), "img:1", LIMITS, **{**args, **kw})
    scan_id = uuid4()
    return provider.run(SandboxRequest(scan_id, src, root, "software")), scan_id


def harness_calls(harness):
    return (harness[0] / "calls").read_text().splitlines()


def test_successful_run_returns_the_bundle(harness):
    result, _ = run(harness, "ok")
    assert result.raw == BUNDLE and result.timed_out is False and result.source == "sandbox"


def test_run_uses_the_verified_command_and_always_cleans_up(harness):
    _, scan_id = run(harness, "ok")
    calls = harness_calls(harness)
    assert calls[0] == "image inspect img:1"
    run_call = next(c for c in calls if c.startswith("run "))
    assert "--network=none" in run_call and "--cap-drop=ALL" in run_call
    assert calls[-1] == f"rm -f px-sbx-{scan_id}"


def test_deadline_triggers_kill_and_cleanup(harness):
    result, scan_id = run(harness, "sleep")
    assert result.raw is None and result.timed_out is True
    calls = harness_calls(harness)
    assert f"kill px-sbx-{scan_id}" in calls and calls[-1] == f"rm -f px-sbx-{scan_id}"


def test_oversized_output_kills_and_is_a_trace_error(harness):
    with pytest.raises(AppError) as exc:
        run(harness, "flood", grace_seconds=10)
    assert exc.value.code == ErrorCode.SANDBOX_TRACE_ERROR
    calls = harness_calls(harness)
    assert any(c.startswith("kill ") for c in calls) and calls[-1].startswith("rm -f ")


@pytest.mark.parametrize("mode", ["exit0_empty", "exit137_empty"])
def test_missing_trace_is_a_trace_error_and_cleans_up(harness, mode):
    with pytest.raises(AppError) as exc:
        run(harness, mode)
    assert exc.value.code == ErrorCode.SANDBOX_TRACE_ERROR
    assert harness_calls(harness)[-1].startswith("rm -f ")


def test_docker_run_failure_does_not_leak_stderr(harness):
    with pytest.raises(AppError) as exc:
        run(harness, "fail125")
    assert exc.value.code == ErrorCode.SANDBOX_FAILED
    assert "daemon error" not in exc.value.message
    assert harness_calls(harness)[-1].startswith("rm -f ")


def test_missing_image_or_daemon_is_unavailable(harness):
    with pytest.raises(AppError) as exc:
        run(harness, "noimage")
    assert exc.value.code == ErrorCode.SANDBOX_UNAVAILABLE
    assert not any(c.startswith("run ") for c in harness_calls(harness))


def test_missing_docker_binary_is_unavailable(tmp_path):
    root = tmp_path / "ws"
    src = root / "s" / "src"
    src.mkdir(parents=True)
    provider = DockerSandboxProvider("no-such-docker-xyz", "img:1", LIMITS, 1000, 1)
    with pytest.raises(AppError) as exc:
        provider.run(SandboxRequest(uuid4(), src, root, "model"))
    assert exc.value.code == ErrorCode.SANDBOX_UNAVAILABLE


def test_bad_mount_source_starts_nothing(harness, tmp_path):
    bin_dir, docker, root, _ = harness
    (bin_dir / "mode").write_text("ok")
    outside = tmp_path / "outside"
    outside.mkdir()
    provider = DockerSandboxProvider(str(docker), "img:1", LIMITS, 1000, 1)
    with pytest.raises(AppError) as exc:
        provider.run(SandboxRequest(uuid4(), outside, root, "software"))
    assert exc.value.code == ErrorCode.SANDBOX_REFUSED
    assert not any(c.startswith("run ") for c in harness_calls(harness))


def test_oversized_stderr_kills_and_is_a_trace_error(harness):
    with pytest.raises(AppError) as exc:
        run(harness, "stderr_flood", grace_seconds=10, max_stderr_bytes=1000)
    assert exc.value.code == ErrorCode.SANDBOX_TRACE_ERROR and "stderr" in exc.value.message
    assert exc.value.details == {"max_bytes": 1000}
    calls = harness_calls(harness)
    assert any(c.startswith("kill ") for c in calls) and calls[-1].startswith("rm -f ")


def test_stderr_within_the_limit_does_not_affect_the_result(harness):
    result, _ = run(harness, "ok_with_stderr", max_stderr_bytes=1000)
    assert result.raw == BUNDLE


def _concurrent_provider(harness, limit, queue_timeout=30.0):
    bin_dir, docker, _, _ = harness
    (bin_dir / "mode").write_text("ok")
    return DockerSandboxProvider(
        str(docker),
        "img:1",
        LIMITS,
        100_000,
        1,
        max_concurrent=limit,
        queue_timeout_seconds=queue_timeout,
    )


def test_concurrency_limit_holds_across_provider_instances(harness):
    """The API builds a provider per request, so the limit must not be per instance."""
    limit = 3
    active, peak = [0], [0]
    lock = threading.Lock()

    def fake_execute(self, argv, name):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        return SandboxRun(BUNDLE, False, "sandbox")

    _, _, root, src = harness
    with mock.patch.object(DockerSandboxProvider, "_execute", fake_execute):
        threads = [
            threading.Thread(
                target=_concurrent_provider(harness, limit).run,
                args=(SandboxRequest(uuid4(), src, root, "software"),),
            )
            for _ in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
    assert peak[0] == limit


def test_queue_timeout_reports_unavailable_and_starts_nothing(harness):
    release = threading.Event()
    started = threading.Event()
    calls = []

    def blocking_execute(self, argv, name):
        calls.append(name)
        started.set()
        release.wait(timeout=30)
        return SandboxRun(BUNDLE, False, "sandbox")

    _, _, root, src = harness
    with mock.patch.object(DockerSandboxProvider, "_execute", blocking_execute):
        request = SandboxRequest(uuid4(), src, root, "software")
        holder = threading.Thread(target=_concurrent_provider(harness, 1).run, args=(request,))
        holder.start()
        assert started.wait(timeout=30)
        with pytest.raises(AppError) as exc:
            _concurrent_provider(harness, 1, queue_timeout=0.05).run(
                SandboxRequest(uuid4(), src, root, "software")
            )
        release.set()
        holder.join(timeout=30)
    assert exc.value.code == ErrorCode.SANDBOX_UNAVAILABLE and len(calls) == 1


def test_slot_is_released_after_a_failure(harness):
    _, _, root, src = harness

    def failing(self, argv, name):
        raise AppError(ErrorCode.SANDBOX_FAILED, "boom", 502)

    with mock.patch.object(DockerSandboxProvider, "_execute", failing):
        for _ in range(3):  # a leaked slot would make the second call wait, then fail differently
            with pytest.raises(AppError) as exc:
                _concurrent_provider(harness, 1, queue_timeout=0.05).run(
                    SandboxRequest(uuid4(), src, root, "software")
                )
            assert exc.value.code == ErrorCode.SANDBOX_FAILED


def test_environment_is_allowlisted(harness, monkeypatch):
    from app.scanners.sandbox import docker_provider as dp

    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    monkeypatch.setenv("BLOCKCHAIN_PRIVATE_KEY", "secret")
    env = dp._docker_env()
    assert "DATABASE_URL" not in env and "BLOCKCHAIN_PRIVATE_KEY" not in env
    assert json.dumps(env).count("secret") == 0

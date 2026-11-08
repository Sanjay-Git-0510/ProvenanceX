"""Live tests against the real Docker sandbox. Run with PROVENANCEX_SANDBOX_TESTS=1.

Needs the image: docker build -t provenancex-sandbox:0.1.0 docker/sandbox
Each probe (tests/fixtures/sandbox/probes/probes.py) runs through the real provider, with
the real hardened flags, as a setup.py target. It reports through its exit code.
"""

import json
import os
import shutil
import subprocess
import time
from uuid import uuid4

import pytest

from app.core.errors import AppError
from app.core.hashing import tree_digest
from app.scanners.sandbox.base import SandboxRequest
from app.scanners.sandbox.docker_provider import DockerSandboxProvider
from app.scanners.sandbox.hardening import (
    SandboxLimits,
    SandboxSpec,
    assert_hardened,
    build_docker_argv,
)
from app.scanners.sandbox.telemetry import SpikeThresholds, TraceLimits, parse_trace_bundle
from tests.conftest import FIXTURES
from tests.model_helpers import reduce_pickle, torch_zip_bytes, write

pytestmark = pytest.mark.sandbox

IMAGE = "provenancex-sandbox:0.1.0"
PROBES = FIXTURES / "sandbox" / "probes" / "probes.py"
# The defaults from app/core/config.py (512 MB, 128 pids, 1 CPU).
LIMITS = SandboxLimits(30, 512, 1.0, 128, 64, 32)
TRACE = TraceLimits(16 * 1024 * 1024, 200_000)
SPIKE = SpikeThresholds(0.9, 0.9, 0.9, 3)
ENFORCED, VIOLATED = 0, 77


def provider(limits=LIMITS, grace=20, clock=time.monotonic):
    return DockerSandboxProvider("docker", IMAGE, limits, 16 * 1024 * 1024, grace, clock)


def workspace(tmp_path):
    root = tmp_path / "workspaces"
    src = root / "scan" / "src"
    src.mkdir(parents=True)
    return root, src


def container_exists(scan_id) -> bool:
    out = subprocess.run(  # noqa: S603, S607 - test helper with fixed argv
        ["docker", "ps", "-a", "--filter", f"name=px-sbx-{scan_id}", "-q"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    return bool(out.stdout.strip())


def run_probe(tmp_path, name, limits=LIMITS, prov=None):
    root, src = workspace(tmp_path)
    shutil.copyfile(PROBES, src / "setup.py")
    (src / "PROBE").write_text(name)
    (src / "EXPECTED_UID").write_text(str(os.getuid()))
    scan_id = uuid4()
    run = (prov or provider(limits)).run(SandboxRequest(scan_id, src, root, "software"))
    return run, scan_id, src


def probe_code(tmp_path, name, limits=LIMITS):
    run, scan_id, _ = run_probe(tmp_path, name, limits)
    assert run.raw is not None, name
    bundle = json.loads(run.raw)
    assert not container_exists(scan_id)
    assert parse_trace_bundle(run.raw, TRACE, SPIKE).features["syscall_count"], "strace saw nothing"
    return bundle["meta"]["targets"][0]["exit_code"], bundle


# ------------------------------------------------------------------ boundaries
def test_strace_works_without_added_capabilities(tmp_path):
    code, bundle = probe_code(tmp_path, "capabilities")
    assert code == ENFORCED
    assert any("execve(" in line for line in bundle["strace_lines"])


def test_probe_connect_fails_enetunreach(tmp_path):
    assert probe_code(tmp_path, "network")[0] == ENFORCED


def test_probe_only_loopback_interface(tmp_path):
    assert probe_code(tmp_path, "interfaces")[0] == ENFORCED


def test_probe_write_to_artifact_fails_erofs(tmp_path):
    assert probe_code(tmp_path, "artifact_readonly")[0] == ENFORCED


def test_probe_cannot_write_outside_tmp_and_trace(tmp_path):
    assert probe_code(tmp_path, "writable_mounts")[0] == ENFORCED


def test_host_tree_digest_unchanged_after_run(tmp_path):
    root, src = workspace(tmp_path)
    shutil.copyfile(PROBES, src / "setup.py")
    (src / "PROBE").write_text("artifact_readonly")
    before = tree_digest(src).sha256
    provider().run(SandboxRequest(uuid4(), src, root, "software"))
    assert tree_digest(src).sha256 == before


@pytest.mark.parametrize(
    "name",
    [
        "ipv6_blocked",
        "vsock_blocked",
        "packet_socket_blocked",
        "raw_socket_blocked",
        "user_namespace_blocked",
        "io_uring_blocked",
        "ptrace_pid1_blocked",
    ],
)
def test_probe_blocked_path(tmp_path, name):
    assert probe_code(tmp_path, name)[0] == ENFORCED


def test_probe_euid_is_not_zero(tmp_path):
    assert probe_code(tmp_path, "non_root")[0] == ENFORCED


def test_probe_capeff_is_zero(tmp_path):
    assert probe_code(tmp_path, "capabilities")[0] == ENFORCED


def test_probe_nonewprivs_is_one(tmp_path):
    assert probe_code(tmp_path, "no_new_privileges")[0] == ENFORCED


def test_probe_default_seccomp_is_active(tmp_path):
    assert probe_code(tmp_path, "seccomp")[0] == ENFORCED


def test_probe_fork_loop_hits_eagain(tmp_path):
    code, bundle = probe_code(tmp_path, "fork_limit")
    assert code == ENFORCED
    assert bundle["meta"]["limits"]["pids"] == LIMITS.pids


def test_probe_allocation_is_oom_killed(tmp_path):
    code, bundle = probe_code(tmp_path, "memory_limit")
    assert code != VIOLATED and code in (-9, 137)
    assert bundle["meta"]["oom_kill_count"] >= 1  # the kernel's own count, not any SIGKILL
    assert bundle["meta"]["limits"]["memory_bytes"] == LIMITS.memory_mb * 1024 * 1024
    peak = max(s["memory_bytes"] for s in bundle["resource_samples"])
    assert peak <= LIMITS.memory_mb * 1024 * 1024


def test_probe_busy_loop_stays_near_limit(tmp_path):
    limits = SandboxLimits(30, 512, 0.5, 128, 64, 32)
    code, bundle = probe_code(tmp_path, "cpu_load", limits)
    assert code == ENFORCED and bundle["meta"]["limits"]["cpus"] == 0.5
    samples = bundle["resource_samples"]
    assert len(samples) >= 2
    first, last = samples[0], samples[-1]
    share = (last["cpu_usec"] - first["cpu_usec"]) / ((last["t"] - first["t"]) * 1_000_000)
    assert share <= 0.5 * 1.25, share  # three busy processes, half a core allowed


def test_probe_sleep_ends_within_timeout_plus_grace(tmp_path):
    limits = SandboxLimits(3, 512, 1.0, 128, 64, 32)
    begin = time.monotonic()
    run, scan_id, _ = run_probe(tmp_path, "sleep_forever", limits)
    assert time.monotonic() - begin < 3 + 20
    assert run.timed_out is False and run.raw is not None  # the supervisor reported it
    bundle = json.loads(run.raw)
    assert bundle["meta"]["timed_out"] is True and bundle["meta"]["exit_code"] is None
    assert not container_exists(scan_id)


@pytest.mark.parametrize("name", ["setsid_parent_waits", "setsid_parent_exits"])
def test_probe_setsid_detach_ends_within_timeout_plus_grace(tmp_path, name):
    limits = SandboxLimits(3, 512, 1.0, 128, 64, 32)
    begin = time.monotonic()
    run, scan_id, _ = run_probe(tmp_path, name, limits)
    assert time.monotonic() - begin < 3 + 20
    assert run.raw is not None and json.loads(run.raw)["meta"]["timed_out"] is True
    assert not container_exists(scan_id)


def test_probe_docker_sock_absent(tmp_path):
    assert probe_code(tmp_path, "docker_socket")[0] == ENFORCED


def test_no_container_left_after_success_timeout_and_kill(tmp_path):
    (tmp_path / "ok").mkdir()
    run, scan_id, _ = run_probe(tmp_path / "ok", "capabilities")
    assert run.raw and not container_exists(scan_id)

    # The host deadline fires while the container is still running, so `docker kill` is used.
    real_start = time.monotonic()
    jumps = lambda: time.monotonic() + (1000 if time.monotonic() - real_start > 4 else 0)  # noqa: E731
    (tmp_path / "kill").mkdir()
    run, scan_id, _ = run_probe(tmp_path / "kill", "sleep_forever", prov=provider(clock=jumps))
    assert run.raw is None and run.timed_out is True
    assert not container_exists(scan_id)


# ------------------------------------------------------------------ negative controls
def _drop(prefix):
    return lambda argv: [a for a in argv if not a.startswith(prefix)]


def _swap(prefix, value):
    return lambda argv: [value if a.startswith(prefix) else a for a in argv]


def _writable_artifact(argv):
    return [a[: -len(",readonly")] if a.startswith("--mount=") else a for a in argv]


@pytest.mark.parametrize(
    ("probe", "weaken"),
    [
        ("interfaces", _swap("--network", "--network=bridge")),
        ("artifact_readonly", _writable_artifact),
        ("writable_mounts", _drop("--ipc")),
        ("non_root", _swap("--user", "--user=0:0")),
        ("capabilities", _drop("--cap-drop")),
        ("no_new_privileges", _drop("--security-opt")),
    ],
    ids=["network", "artifact_mount", "ipc", "root", "cap_drop", "no_new_privileges"],
)
def test_negative_control_probe_detects_the_missing_boundary(tmp_path, probe, weaken):
    """Each probe must report a violation when its boundary is removed from a throwaway run."""
    root, src = workspace(tmp_path)
    shutil.copyfile(PROBES, src / "setup.py")
    (src / "PROBE").write_text(probe)
    (src / "EXPECTED_UID").write_text(str(os.getuid()))
    spec = SandboxSpec(uuid4(), IMAGE, src.resolve(), os.getuid(), os.getgid(), "software", LIMITS)
    argv = weaken(build_docker_argv("docker", spec))
    with pytest.raises(AppError):
        assert_hardened(argv)  # the product itself would refuse to launch this
    done = subprocess.run(argv, capture_output=True, timeout=90, check=False)  # noqa: S603
    assert json.loads(done.stdout)["meta"]["targets"][0]["exit_code"] == VIOLATED
    assert not container_exists(spec.scan_id)


# ------------------------------------------------------------------ the real targets
def test_pickle_target_runs_only_in_the_sandbox(tmp_path):
    root, src = workspace(tmp_path)
    host_canary = tmp_path / "HOST_CANARY"
    payload = reduce_pickle(os.mkdir, ("/tmp/px_pickle_ran",))  # noqa: S108
    write(src / "model.pkl", payload)
    write(src / "weights.pt", torch_zip_bytes(reduce_pickle(os.mkdir, (str(host_canary),))))
    run = provider().run(SandboxRequest(uuid4(), src, root, "model"))
    result = parse_trace_bundle(run.raw, TRACE, SPIKE)
    assert {t["kind"] for t in result.meta["targets"]} == {"pickle"}
    assert len(result.meta["targets"]) == 2
    assert "/tmp/px_pickle_ran" in result.write_samples  # noqa: S108
    assert not host_canary.exists()  # the host path does not exist inside the container


def test_auto_map_target_and_real_strace_network_parsing(tmp_path):
    root, src = workspace(tmp_path)
    write(src / "config.json", json.dumps({"auto_map": {"AutoModel": "modeling_x.Model"}}))
    write(
        src / "modeling_x.py",
        "import socket\ns = socket.socket()\n"
        "try:\n    s.connect(('93.184.216.34', 443))\nexcept OSError:\n    pass\n",
    )
    run = provider().run(SandboxRequest(uuid4(), src, root, "model"))
    result = parse_trace_bundle(run.raw, TRACE, SPIKE)
    assert result.meta["targets"][0]["kind"] == "auto_map"
    assert result.destinations["93.184.216.34:443"] == {"attempts": 1, "succeeded": 0}
    assert result.features["network_failed_count"] >= 1


def test_no_targets_runs_nothing(tmp_path):
    root, src = workspace(tmp_path)
    write(src / "README.md", "nothing to run")
    run = provider().run(SandboxRequest(uuid4(), src, root, "software"))
    result = parse_trace_bundle(run.raw, TRACE, SPIKE)
    assert result.meta["targets"] == [] and result.features["syscall_count"] is None


def test_end_to_end_scan_through_the_api(test_settings, session_factory, public_dns, tmp_path):
    from fastapi.testclient import TestClient

    from app.api.scans import get_session_factory
    from app.core.config import get_settings
    from app.main import create_app
    from tests.conftest import build_zip

    settings = test_settings.model_copy(update={"sandbox_provider": "docker"})
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    client = TestClient(app, raise_server_exceptions=False)
    source = "import socket\ntry:\n    socket.create_connection(('93.184.216.34', 443), 1)\n"
    source += "except OSError:\n    pass\n"
    data = build_zip([("setup.py", source)])
    resp = client.post("/api/v1/scans/software", files={"file": ("a.zip", data, "application/zip")})
    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["scan_id"]
    body = client.get(f"/api/v1/scans/{scan_id}").json()
    stage = body["stages"]["sandbox"]
    assert body["status"] == "completed" and stage["status"] == "completed", stage
    assert stage["source"] == "sandbox" and stage["is_mock"] is False
    assert stage["synthetic"] is False and stage["features"]["external_destination_count"] == 1
    trace = settings.workspace_root / scan_id / stage["trace_file"]
    assert oct(trace.stat().st_mode & 0o777) == "0o600"
    items = client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"category": "behavioral"}
    ).json()["items"]
    assert [i["identifier"] for i in items] == ["PX-BEHAV-EXTERNAL-CONNECT"]
    assert items[0]["source"] == "sandbox" and items[0]["is_mock"] is False

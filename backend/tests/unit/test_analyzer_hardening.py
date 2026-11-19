"""The analyzer `docker create` allowlist: every restriction is required, nothing else allowed."""

import uuid
from pathlib import Path

import pytest

from app.analysis.hardening import (
    AnalyzerLimits,
    AnalyzerSpec,
    MountSpec,
    assert_create_hardened,
    build_create_argv,
    resolve_workspace_dir,
)
from app.core.errors import AppError

SCAN = uuid.UUID("12345678-1234-1234-1234-123456789abc")
LIMITS = AnalyzerLimits(timeout_seconds=60, memory_mb=1024, cpus=1.0, pids=64, tmp_mb=128)


def _spec(mode="analyze", mounts=None, uid=1000) -> AnalyzerSpec:
    base = f"/ws/{SCAN}"
    if mounts is None:
        if mode == "analyze":
            mounts = (MountSpec("bind", f"{base}/src", "/artifact", "src", True, SCAN),)
        else:
            mounts = (
                MountSpec("bind", f"{base}/input", "/input", "input", True, SCAN),
                MountSpec("bind", f"{base}/src", "/out/src", "src", False, SCAN),
            )
    return AnalyzerSpec(SCAN, mode, "provenancex-analyzer:0.1.0", uid, uid, mounts, LIMITS)


def _refused(argv):
    with pytest.raises(AppError) as info:
        assert_create_hardened(argv)
    assert info.value.code == "sandbox_refused"


@pytest.mark.parametrize("mode", ["analyze", "extract"])
def test_built_command_passes(mode):
    argv = build_create_argv("docker", _spec(mode))
    assert assert_create_hardened(argv) == mode
    assert "--network=none" in argv and "--read-only" in argv and "--cap-drop=ALL" in argv


def test_volume_mounts_pass():
    m = (MountSpec("volume", "px_ws", "/artifact", "src", True, SCAN),)
    assert_create_hardened(build_create_argv("docker", _spec(mounts=m)))


def test_root_is_refused():
    with pytest.raises(AppError):
        build_create_argv("docker", _spec(uid=0))


@pytest.mark.parametrize(
    "flag",
    [
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=1024m",
        "--pull=never",
        "--ipc=none",
        "--log-driver=none",
        "--interactive",
    ],
)
def test_each_restriction_is_required(flag):
    argv = build_create_argv("docker", _spec())
    argv.remove(flag)
    _refused(argv)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("--network=none", "--network=host"),
        ("--network=none", "--network=bridge"),
        ("--cap-drop=ALL", "--cap-drop=NET_RAW"),
        ("--memory-swap=1024m", "--memory-swap=4096m"),
        ("--user=1000:1000", "--user=0:0"),
        ("--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m", "--tmpfs=/tmp:rw,size=128m"),
        ("--name=px-ana-12345678-1234-1234-1234-123456789abc-analyze", "--name=other"),
    ],
)
def test_altered_restrictions_are_refused(old, new):
    argv = build_create_argv("docker", _spec())
    argv[argv.index(old)] = new
    _refused(argv)


@pytest.mark.parametrize(
    "extra",
    [
        "--privileged",
        "--cap-add=SYS_ADMIN",
        "--env=DATABASE_URL=x",
        "--device=/dev/kvm",
        "--pid=host",
        "--volume=/:/host",
        "--security-opt=seccomp=unconfined",
        "-v",
    ],
)
def test_extra_flags_are_refused(extra):
    argv = build_create_argv("docker", _spec())
    argv.insert(3, extra)
    _refused(argv)


def test_docker_socket_anywhere_is_refused():
    argv = build_create_argv("docker", _spec())
    argv.insert(3, "--mount=type=bind,src=/var/run/docker.sock,dst=/artifact,readonly")
    _refused(argv)


def test_writable_artifact_mount_is_refused():
    m = (MountSpec("bind", f"/ws/{SCAN}/src", "/artifact", "src", False, SCAN),)
    _refused(build_create_argv("docker", _spec(mounts=m)))


def test_analyze_cannot_mount_a_writable_output():
    m = (
        MountSpec("bind", f"/ws/{SCAN}/src", "/artifact", "src", True, SCAN),
        MountSpec("bind", f"/ws/{SCAN}/src", "/out/src", "src", False, SCAN),
    )
    _refused(build_create_argv("docker", _spec(mounts=m)))


def test_extract_requires_both_mounts():
    m = (MountSpec("bind", f"/ws/{SCAN}/input", "/input", "input", True, SCAN),)
    _refused(build_create_argv("docker", _spec("extract", mounts=m)))


def test_mount_outside_a_scan_workspace_is_refused():
    argv = build_create_argv("docker", _spec())
    idx = next(i for i, a in enumerate(argv) if a.startswith("--mount="))
    argv[idx] = "--mount=type=bind,src=/etc,dst=/artifact,readonly"
    _refused(argv)


def test_command_after_image_is_fixed():
    argv = build_create_argv("docker", _spec())
    _refused([*argv, "--extra"])
    argv[-1] = "extract"  # mode no longer matches the name
    _refused(argv)


def test_workspace_dir_must_belong_to_this_scan(tmp_path):
    base = tmp_path / "ws"
    own = base / str(SCAN) / "src"
    own.mkdir(parents=True)
    other = base / str(uuid.uuid4()) / "src"
    other.mkdir(parents=True)
    resolve_workspace_dir(own, base, SCAN)
    with pytest.raises(AppError):
        resolve_workspace_dir(other, base, SCAN)
    link = base / str(SCAN) / "input"
    link.symlink_to(Path("/etc"))
    with pytest.raises(AppError):
        resolve_workspace_dir(link, base, SCAN)

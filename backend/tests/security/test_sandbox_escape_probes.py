"""assert_hardened against commands with a weakened or added restriction."""

from pathlib import Path
from uuid import UUID

import pytest

from app.core.errors import AppError, ErrorCode
from app.scanners.sandbox.hardening import (
    SandboxLimits,
    SandboxSpec,
    assert_hardened,
    build_docker_argv,
)

LIMITS = SandboxLimits(60, 512, 1.0, 128, 64, 32)
SCAN = UUID("12345678-1234-5678-1234-567812345678")


def good() -> list[str]:
    spec = SandboxSpec(
        SCAN, "provenancex-sandbox:0.1.0", Path("/data/ws/x/src"), 1000, 1000, "model", LIMITS
    )
    return build_docker_argv("docker", spec)


def refused(args):
    with pytest.raises(AppError) as exc:
        assert_hardened(args)
    assert exc.value.code == ErrorCode.SANDBOX_REFUSED


def replace(prefix: str, value: str | None) -> list[str]:
    args = good()
    index = next(i for i, a in enumerate(args) if a.startswith(prefix))
    if value is None:
        del args[index]
    else:
        args[index] = value
    return args


def with_flag(*flags: str) -> list[str]:
    args = good()
    return args[:2] + list(flags) + args[2:]


@pytest.mark.parametrize(
    "prefix",
    [
        "--rm",
        "--name",
        "--network",
        "--read-only",
        "--user",
        "--cap-drop",
        "--security-opt",
        "--pids-limit",
        "--memory=",
        "--memory-swap",
        "--cpus",
        "--mount",
        "--pull",
        "--ipc",
        "--ulimit",
    ],
)
def test_every_restriction_is_required(prefix):
    refused(replace(prefix, None))


def test_assert_hardened_rejects_other_network():
    for value in ("bridge", "host", "container:x", "default"):
        refused(replace("--network", f"--network={value}"))


def test_assert_hardened_rejects_cap_add():
    refused(with_flag("--cap-add=SYS_PTRACE"))
    refused(with_flag("--cap-add=ALL"))


def test_assert_hardened_rejects_privileged():
    refused(with_flag("--privileged"))


def test_assert_hardened_rejects_seccomp_unconfined():
    refused(replace("--security-opt", "--security-opt=seccomp=unconfined"))
    refused(with_flag("--security-opt=seccomp=unconfined"))
    refused(with_flag("--security-opt=apparmor=unconfined"))


def test_assert_hardened_rejects_extra_mount():
    refused(with_flag("--mount=type=bind,src=/etc,dst=/host,readonly"))
    refused(with_flag("--mount=type=volume,src=x,dst=/data"))


def test_assert_hardened_rejects_docker_sock():
    refused(with_flag("--mount=type=bind,src=/var/run/docker.sock,dst=/d"))
    refused(replace("--mount", "--mount=type=bind,src=/var/run/docker.sock,dst=/artifact,readonly"))
    refused(good() + ["/var/run/docker.sock"])


@pytest.mark.parametrize(
    "flag",
    [
        "-v",
        "-v=/:/host",
        "--volume=/:/host",
        "--volumes-from=x",
        "--device=/dev/sda",
        "--pid=host",
        "--uts=host",
        "--userns=host",
        "--cgroupns=host",
        "--env=SECRET=x",
        "-e=SECRET=x",
        "--env-file=.env",
        "--add-host=a:1.1.1.1",
        "--dns=1.1.1.1",
        "--publish=80:80",
        "--entrypoint=/bin/sh",
        "--workdir=/",
        "--group-add=0",
        "--unknown-flag=1",
    ],
)
def test_any_other_flag_is_refused(flag):
    refused(with_flag(flag))


def test_mount_must_be_readonly():
    refused(replace("--mount", "--mount=type=bind,src=/data/ws/x/src,dst=/artifact"))
    refused(replace("--mount", "--mount=type=bind,src=/data/ws/x/src,dst=/artifact,readonly=false"))
    refused(replace("--mount", "--mount=type=bind,src=/data/ws/x/src,dst=/,readonly"))
    refused(replace("--mount", "--mount=type=volume,src=/data,dst=/artifact,readonly"))


@pytest.mark.parametrize("user", ["0:0", "root", "0", "1000", "1000:0", "0:1000", "a:b"])
def test_user_must_be_numeric_and_non_root(user):
    refused(replace("--user", f"--user={user}"))


@pytest.mark.parametrize(
    ("prefix", "value"),
    [
        ("--cap-drop", "--cap-drop=NET_RAW"),
        ("--pids-limit", "--pids-limit=-1"),
        ("--pids-limit", "--pids-limit=0"),
        ("--memory=", "--memory=0"),
        ("--memory=", "--memory=1g"),
        ("--memory-swap", "--memory-swap=-1"),
        ("--memory-swap", "--memory-swap=1024m"),
        ("--cpus", "--cpus=0"),
        ("--cpus", "--cpus=abc"),
        ("--pull", "--pull=always"),
        ("--ipc", "--ipc=host"),
        ("--ipc", "--ipc=shareable"),
        ("--ulimit", "--ulimit=core=-1"),
        ("--name", "--name=other"),
    ],
)
def test_weakened_values_are_refused(prefix, value):
    refused(replace(prefix, value))


def test_duplicate_flags_are_refused():
    refused(with_flag("--network=none"))
    refused(with_flag("--network=host"))


@pytest.mark.parametrize(
    "tmpfs",
    [
        "--tmpfs=/etc:rw,noexec,nosuid,nodev,size=8m",
        "--tmpfs=/tmp:rw,nosuid,nodev,size=64m",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev",
        "--tmpfs=/tmp:rw,exec,nosuid,nodev,size=64m",
    ],
)
def test_tmpfs_is_exact(tmpfs):
    refused(replace("--tmpfs=/tmp", tmpfs))


def test_extra_tmpfs_is_refused():
    refused(with_flag("--tmpfs=/data:rw,noexec,nosuid,nodev,size=8m"))


@pytest.mark.parametrize(
    "tail",
    [
        [],
        ["sh", "-c", "id"],
        ["--kind", "software"],
        ["--kind", "evil", "--timeout", "5"],
        ["--kind", "software", "--timeout", "x"],
        ["--kind", "software", "--timeout", "5", "extra"],
    ],
)
def test_container_command_is_exact(tail):
    args = good()
    image_index = args.index("provenancex-sandbox:0.1.0")
    refused(args[: image_index + 1] + tail)


@pytest.mark.parametrize("args", [[], ["docker"], ["docker", "exec", "x"], ["docker", "create"]])
def test_only_docker_run_is_accepted(args):
    refused(args)

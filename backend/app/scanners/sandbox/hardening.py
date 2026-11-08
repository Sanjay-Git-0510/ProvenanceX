"""Builds and independently checks the `docker run` command (CLAUDE.md boundary 5).

`build_docker_argv` writes the command. `assert_hardened` re-parses it against an
allowlist before every launch and fails closed: an unknown flag, or a missing or altered
restriction, stops the container from starting. No setting can relax these rules.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from app.core.errors import AppError, ErrorCode

ARTIFACT_MOUNT = "/artifact"
MB = 1024 * 1024
TMPFS_OPTIONS = "rw,noexec,nosuid,nodev"
SOCKET_MARKER = "docker.sock"

_NAME_RE = re.compile(r"^px-sbx-[0-9a-f-]{36}$")
_USER_RE = re.compile(r"^[1-9]\d*:[1-9]\d*$")
_MEMORY_RE = re.compile(r"^\d+m$")
_TMPFS_RE = re.compile(rf"^(/tmp|/trace):{TMPFS_OPTIONS},size=\d+m$")
_MOUNT_RE = re.compile(rf"^type=bind,src=(/[^,]+),dst={ARTIFACT_MOUNT},readonly$")
_REQUIRED = {
    "--network": "none",
    "--cap-drop": "ALL",
    "--security-opt": "no-new-privileges",
    "--pull": "never",
    "--ipc": "none",
    "--ulimit": "core=0",
}
_VALUELESS = frozenset({"--rm", "--read-only"})
_REQUIRED_KEYS = frozenset(
    {
        *_REQUIRED,
        *_VALUELESS,
        "--name",
        "--user",
        "--pids-limit",
        "--memory",
        "--memory-swap",
        "--cpus",
        "--mount",
        "--tmpfs",
    }
)


@dataclass(frozen=True)
class SandboxLimits:
    timeout_seconds: int
    memory_mb: int
    cpus: float
    pids: int
    tmp_mb: int
    trace_tmp_mb: int


@dataclass(frozen=True)
class SandboxSpec:
    scan_id: UUID
    image: str
    src_dir: Path
    uid: int
    gid: int
    kind: str
    limits: SandboxLimits

    @property
    def name(self) -> str:
        return f"px-sbx-{self.scan_id}"


def _refuse(message: str, details: object = None) -> AppError:
    return AppError(ErrorCode.SANDBOX_REFUSED, message, 400, details)


def resolve_artifact_source(src_dir: Path, workspace_root: Path) -> tuple[Path, int, int]:
    """Validate the mount source. Returns (resolved path, owner uid, owner gid)."""
    root = workspace_root.resolve()
    if src_dir.is_symlink():
        raise _refuse("Artifact mount source is a symlink")
    resolved = src_dir.resolve()
    if not resolved.is_dir() or resolved == root or not resolved.is_relative_to(root):
        raise _refuse("Artifact mount source is outside the workspace")
    if "," in str(resolved) or SOCKET_MARKER in str(resolved):
        raise _refuse("Artifact mount source has a disallowed path")
    info = resolved.stat()
    if info.st_uid == 0 or info.st_gid == 0:
        raise _refuse("The sandbox never runs as root; the workspace is owned by root")
    return resolved, info.st_uid, info.st_gid


def build_docker_argv(docker: str, spec: SandboxSpec) -> list[str]:
    if spec.uid == 0 or spec.gid == 0:
        raise _refuse("The sandbox never runs as root")
    limits = spec.limits
    return [
        docker,
        "run",
        "--rm",
        f"--name={spec.name}",
        "--network=none",
        "--read-only",
        f"--user={spec.uid}:{spec.gid}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={limits.pids}",
        f"--memory={limits.memory_mb}m",
        f"--memory-swap={limits.memory_mb}m",
        f"--cpus={limits.cpus:g}",
        f"--mount=type=bind,src={spec.src_dir},dst={ARTIFACT_MOUNT},readonly",
        f"--tmpfs=/tmp:{TMPFS_OPTIONS},size={limits.tmp_mb}m",
        f"--tmpfs=/trace:{TMPFS_OPTIONS},size={limits.trace_tmp_mb}m",
        "--pull=never",
        "--ipc=none",
        "--ulimit=core=0",
        spec.image,
        "--kind",
        spec.kind,
        "--timeout",
        str(limits.timeout_seconds),
    ]


def _parse_flags(argv: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    if len(argv) < 3 or argv[1] != "run":
        raise _refuse("Not a docker run command")
    flags: dict[str, list[str]] = {}
    index = 2
    while index < len(argv) and argv[index].startswith("-"):
        key, sep, value = argv[index].partition("=")
        if not key.startswith("--"):
            raise _refuse("Short flags are not allowed", {"flag": key})
        if key in _VALUELESS:
            if sep:
                raise _refuse("Flag must not take a value", {"flag": key})
        elif key not in _REQUIRED_KEYS or not sep or not value:
            raise _refuse("Flag is not allowed", {"flag": key})
        flags.setdefault(key, []).append(value)
        index += 1
    return flags, argv[index:]


def assert_hardened(argv: list[str]) -> None:
    """Raise sandbox_refused unless `argv` has exactly the required restrictions."""
    if any(SOCKET_MARKER in token for token in argv):
        raise _refuse("The Docker socket must never be mounted")
    flags, rest = _parse_flags(argv)
    missing = _REQUIRED_KEYS - flags.keys()
    if missing:
        raise _refuse("Required sandbox restriction is missing", {"flags": sorted(missing)})
    for key, values in flags.items():
        if key == "--tmpfs":
            continue
        if len(values) != 1:
            raise _refuse("Flag may appear only once", {"flag": key})
    for key, wanted in _REQUIRED.items():
        if flags[key] != [wanted]:
            raise _refuse("Sandbox restriction has the wrong value", {"flag": key})

    if not _NAME_RE.match(flags["--name"][0]):
        raise _refuse("Invalid container name")
    if not _USER_RE.match(flags["--user"][0]):
        raise _refuse("The sandbox must run as a numeric non-root user")
    memory, swap = flags["--memory"][0], flags["--memory-swap"][0]
    if not _MEMORY_RE.match(memory) or memory != swap:
        raise _refuse("Memory limit must be set, with no swap")
    if not flags["--pids-limit"][0].isdigit() or int(flags["--pids-limit"][0]) <= 0:
        raise _refuse("A positive pids limit is required")
    try:
        cpus = float(flags["--cpus"][0])
    except ValueError as exc:
        raise _refuse("Invalid CPU limit") from exc
    if cpus <= 0:
        raise _refuse("A positive CPU limit is required")
    if not _MOUNT_RE.match(flags["--mount"][0]):
        raise _refuse("Only the read-only artifact mount is allowed")
    mounts = sorted(value.split(":", 1)[0] for value in flags["--tmpfs"])
    if mounts != ["/tmp", "/trace"] or not all(_TMPFS_RE.match(v) for v in flags["--tmpfs"]):  # noqa: S108
        raise _refuse("Only the size-limited /tmp and /trace tmpfs mounts are allowed")

    # After the flags: image, then exactly `--kind <kind> --timeout <seconds>`.
    if (
        len(rest) != 5
        or rest[1] != "--kind"
        or rest[2] not in ("software", "model")
        or rest[3] != "--timeout"
        or not rest[4].isdigit()
        or rest[0].startswith("-")
    ):
        raise _refuse("Unexpected sandbox command")

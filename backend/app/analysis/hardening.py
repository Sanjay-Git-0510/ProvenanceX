"""Hardening for analyzer containers, checked three times (CLAUDE.md boundary 5).

1. `build_create_argv` writes the `docker create` command.
2. `assert_create_hardened` re-parses that command against an allowlist. An unknown flag, or a
   missing or altered restriction, stops it before Docker is called.
3. `verify_runtime_config` checks the container that Docker actually created (`docker inspect`)
   before it is started, so a daemon default, a wrapper script or a changed CLI cannot silently
   weaken what was asked for.
No setting can relax these rules. The worker's own self-check inside the container is a fourth,
independent view (app/sandbox_worker/selfcheck.py).

Lifetime (audit finding M1): every container carries identifying labels (role, deployment
instance, scan id, claim token, mode) so the runner can find and remove orphans after a crash
(app/analysis/reconcile.py), and its command carries an in-container wall-clock deadline and a
CPU-time limit that the worker enforces on itself, so it stops even if the runner that started
it is gone.
"""

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from app.analysis.runtime_checks import common_hardening_problems
from app.analysis.staging import VOLUME_PREFIX
from app.core.errors import AppError, ErrorCode

MB = 1024 * 1024
SOCKET_MARKER = "docker.sock"
TMPFS_OPTIONS = "rw,noexec,nosuid,nodev"
ARTIFACT_DST = "/artifact"
INPUT_DST = "/input"
OUT_DST = "/out/src"
EVIDENCE_DST = "/evidence"

Mode = Literal["extract", "analyze", "sbom", "persist", "rehash", "hold"]
ENTRYPOINT = ["python", "-B", "-m", "app.sandbox_worker"]

LABEL_ROLE = "io.provenancex.role"
LABEL_INSTANCE = "io.provenancex.instance"
LABEL_SCAN = "io.provenancex.scan-id"
LABEL_CLAIM = "io.provenancex.claim"
LABEL_MODE = "io.provenancex.mode"
ROLE_ANALYZER = "analyzer"
NO_CLAIM = "none"
LABEL_KEYS = (LABEL_ROLE, LABEL_INSTANCE, LABEL_SCAN, LABEL_CLAIM, LABEL_MODE)
# Upper bounds for the worker's self-imposed limits (sanity, not policy).
MAX_DEADLINE_SECONDS = 24 * 3600
MAX_CPU_SECONDS = 10 * MAX_DEADLINE_SECONDS
MountKind = Literal["bind", "volume"]
# "scan" is the scan's whole workspace directory (rehash only, always read-only).
Subdir = Literal["src", "input", "staging", "scan"]

_NAME_RE = re.compile(r"^px-ana-[0-9a-f-]{36}-(extract|analyze|sbom|persist|rehash|hold)$")
_USER_RE = re.compile(r"^([1-9]\d*):([1-9]\d*)$")
_MEMORY_RE = re.compile(r"^(\d+)m$")
_TMPFS_RE = re.compile(rf"^/tmp:{TMPFS_OPTIONS},size=(\d+)m$")
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_BIND_RE = re.compile(rf"^type=bind,src=(/[^,]+/({_UUID})/(src|input)),dst=([a-z/]+)(,readonly)?$")
_VOLUME_RE = re.compile(
    rf"^type=volume,src=([A-Za-z0-9][A-Za-z0-9_.-]*),dst=([a-z/]+),"
    rf"volume-subpath=({_UUID})/(src|input)(,readonly)?$"
)
# The whole scan workspace (rehash mode), bind or volume form. Read-only is enforced per mode.
_SCAN_BIND_RE = re.compile(rf"^type=bind,src=(/[^,]+/({_UUID})),dst=([a-z/]+)(,readonly)?$")
_SCAN_VOLUME_RE = re.compile(
    rf"^type=volume,src=([A-Za-z0-9][A-Za-z0-9_.-]*),dst=([a-z/]+),"
    rf"volume-subpath=({_UUID})(,readonly)?$"
)
# The scan's own tmpfs staging volume (app/analysis/staging.py), mounted whole, never copied
# into from the image (volume-nocopy).
_STAGING_RE = re.compile(
    rf"^type=volume,src={VOLUME_PREFIX}({_UUID}),dst=([a-z/]+),volume-nocopy(,readonly)?$"
)
_REQUIRED = {
    "--network": "none",
    "--cap-drop": "ALL",
    "--security-opt": "no-new-privileges",
    "--pull": "never",
    "--ipc": "none",
    "--ulimit": "core=0",
    "--log-driver": "none",
}
_VALUELESS = frozenset({"--read-only", "--interactive"})
_SINGLE_VALUED = frozenset(
    {
        *_REQUIRED,
        "--name",
        "--user",
        "--pids-limit",
        "--memory",
        "--memory-swap",
        "--cpus",
        "--tmpfs",
    }
)
_REQUIRED_KEYS = frozenset({*_SINGLE_VALUED, *_VALUELESS, "--mount", "--label"})
# Which mounts each mode needs: destination -> (source, read-only?). "staging" is the scan's
# kernel-capped tmpfs volume; "src"/"input" are its persistent workspace directories.
#   extract  upload (ro) -> staging (rw)       analyze  staging (ro) [+ upload (ro)]
#   persist  staging (ro) -> workspace src (rw)  hold   staging (ro): keeps the tmpfs mounted
_MODE_MOUNTS: dict[str, dict[str, tuple[str, bool]]] = {
    "extract": {INPUT_DST: ("input", True), OUT_DST: ("staging", False)},
    "analyze": {ARTIFACT_DST: ("staging", True)},
    # sbom (audit finding M4): Syft alone, on the read-only staging tree, nothing else mounted.
    "sbom": {ARTIFACT_DST: ("staging", True)},
    "persist": {ARTIFACT_DST: ("staging", True), OUT_DST: ("src", False)},
    "hold": {ARTIFACT_DST: ("staging", True)},
    # rehash (/verify, audit finding M5): the kept evidence, read-only; hashes bytes only.
    "rehash": {EVIDENCE_DST: ("scan", True)},
}
_OPTIONAL_MOUNTS: dict[str, dict[str, tuple[str, bool]]] = {
    "analyze": {INPUT_DST: ("input", True)},
}
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_CLAIM_RE = re.compile(rf"^({_UUID}|{NO_CLAIM})$")
_SECRET_ENV_RE = re.compile(r"(?i)(database_url|secret|token|password|private_key|api_key)")


@dataclass(frozen=True)
class AnalyzerLimits:
    timeout_seconds: int
    memory_mb: int
    cpus: float
    pids: int
    tmp_mb: int
    cpu_grace_seconds: int = 30

    @property
    def deadline_seconds(self) -> int:
        """In-container wall-clock deadline: the worker stops itself at the run's time limit."""
        return self.timeout_seconds

    @property
    def cpu_seconds(self) -> int:
        """RLIMIT_CPU for the worker: what the CPU quota allows over the deadline, plus grace."""
        return math.ceil(self.cpus * self.timeout_seconds) + self.cpu_grace_seconds


@dataclass(frozen=True)
class MountSpec:
    """One mount. `source` is a host path (bind) or a volume name (volume).

    subdir "staging" is the scan's whole tmpfs staging volume (always kind "volume").
    """

    kind: MountKind
    source: str
    target: str
    subdir: Subdir
    read_only: bool
    scan_id: UUID

    def flag(self) -> str:
        ro = ",readonly" if self.read_only else ""
        if self.subdir == "staging":
            return f"--mount=type=volume,src={self.source},dst={self.target},volume-nocopy{ro}"
        if self.kind == "bind":
            return f"--mount=type=bind,src={self.source},dst={self.target}{ro}"
        if self.subdir == "scan":
            return (
                f"--mount=type=volume,src={self.source},dst={self.target},"
                f"volume-subpath={self.scan_id}{ro}"
            )
        return (
            f"--mount=type=volume,src={self.source},dst={self.target},"
            f"volume-subpath={self.scan_id}/{self.subdir}{ro}"
        )


@dataclass(frozen=True)
class AnalyzerSpec:
    scan_id: UUID
    mode: Mode
    image: str
    uid: int
    gid: int
    mounts: tuple[MountSpec, ...]
    limits: AnalyzerLimits
    instance: str = "provenancex_workspace"
    claim_token: str = NO_CLAIM

    @property
    def name(self) -> str:
        return f"px-ana-{self.scan_id}-{self.mode}"

    @property
    def labels(self) -> dict[str, str]:
        return {
            LABEL_ROLE: ROLE_ANALYZER,
            LABEL_INSTANCE: self.instance,
            LABEL_SCAN: str(self.scan_id),
            LABEL_CLAIM: self.claim_token,
            LABEL_MODE: self.mode,
        }

    @property
    def command(self) -> list[str]:
        """Arguments after the image. The mode stays last."""
        return [
            "--deadline",
            str(self.limits.deadline_seconds),
            "--cpu-seconds",
            str(self.limits.cpu_seconds),
            "--mode",
            self.mode,
        ]


def refuse(message: str, details: object = None) -> AppError:
    return AppError(ErrorCode.SANDBOX_REFUSED, message, 500, details)


def resolve_workspace_dir(path: Path, workspace_base: Path, scan_id: UUID) -> tuple[Path, int, int]:
    """Validate a per-scan mount source. Returns (resolved path, owner uid, owner gid)."""
    base = workspace_base.resolve()
    if path.is_symlink():
        raise refuse("Analyzer mount source is a symlink")
    resolved = path.resolve()
    if resolved.parent == base:  # the scan's whole workspace (rehash)
        if not resolved.is_dir() or resolved.name != str(scan_id):
            raise refuse("Analyzer mount source is not this scan's workspace")
    else:
        if not resolved.is_dir() or resolved.parent.parent != base:
            raise refuse("Analyzer mount source is outside the workspace")
        if resolved.parent.name != str(scan_id) or resolved.name not in ("src", "input"):
            raise refuse("Analyzer mount source is not this scan's workspace")
    if "," in str(resolved) or SOCKET_MARKER in str(resolved):
        raise refuse("Analyzer mount source has a disallowed path")
    info = resolved.stat()
    if info.st_uid == 0 or info.st_gid == 0:
        raise refuse("The analyzer never runs as root; the workspace is owned by root")
    return resolved, info.st_uid, info.st_gid


def build_create_argv(docker: str, spec: AnalyzerSpec) -> list[str]:
    if spec.uid == 0 or spec.gid == 0:
        raise refuse("The analyzer never runs as root")
    lim = spec.limits
    return [
        docker,
        "create",
        f"--name={spec.name}",
        "--network=none",
        "--read-only",
        f"--user={spec.uid}:{spec.gid}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={lim.pids}",
        f"--memory={lim.memory_mb}m",
        f"--memory-swap={lim.memory_mb}m",
        f"--cpus={lim.cpus:g}",
        *[m.flag() for m in spec.mounts],
        f"--tmpfs=/tmp:{TMPFS_OPTIONS},size={lim.tmp_mb}m",
        "--pull=never",
        "--ipc=none",
        "--ulimit=core=0",
        "--log-driver=none",
        *[f"--label={key}={value}" for key, value in spec.labels.items()],
        "--interactive",
        spec.image,
        *spec.command,
    ]


def _parse_flags(argv: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    if len(argv) < 3 or argv[1] != "create":
        raise refuse("Not a docker create command")
    flags: dict[str, list[str]] = {}
    index = 2
    while index < len(argv) and argv[index].startswith("-"):
        key, sep, value = argv[index].partition("=")
        if not key.startswith("--"):
            raise refuse("Short flags are not allowed", {"flag": key})
        if key in _VALUELESS:
            if sep:
                raise refuse("Flag must not take a value", {"flag": key})
        elif key not in _REQUIRED_KEYS or not sep or not value:
            raise refuse("Flag is not allowed", {"flag": key})
        flags.setdefault(key, []).append(value)
        index += 1
    return flags, argv[index:]


def _bind_under_root(source: str, workspace_root: str | None, rel: str) -> None:
    """A bind source must be exactly <WORKSPACE_ROOT>/<rel> (audit finding L4)."""
    if workspace_root is None:
        raise refuse("Bind mounts need the workspace root to be checked against")
    root = workspace_root.rstrip("/")
    if not root.startswith("/") or source != f"{root}/{rel}":
        raise refuse("Analyzer bind mount is outside WORKSPACE_ROOT")


def _parse_mount(value: str, workspace_root: str | None) -> tuple[str, str, bool, str]:
    """Return (destination, source kind, read-only, scan id) for an allowed mount value."""
    if m := _STAGING_RE.match(value):
        return m.group(2), "staging", m.group(3) is not None, m.group(1)
    if m := _BIND_RE.match(value):
        _bind_under_root(m.group(1), workspace_root, f"{m.group(2)}/{m.group(3)}")
        return m.group(4), m.group(3), m.group(5) is not None, m.group(2)
    if m := _VOLUME_RE.match(value):
        return m.group(2), m.group(4), m.group(5) is not None, m.group(3)
    if m := _SCAN_BIND_RE.match(value):
        _bind_under_root(m.group(1), workspace_root, m.group(2))
        return m.group(3), "scan", m.group(4) is not None, m.group(2)
    if m := _SCAN_VOLUME_RE.match(value):
        return m.group(2), "scan", m.group(4) is not None, m.group(3)
    raise refuse("Only per-scan workspace and staging mounts are allowed")


def _bounded_int(value: str, upper: int, what: str) -> int:
    if not value.isdigit() or not 0 < int(value) <= upper:
        raise refuse(f"Invalid analyzer {what}")
    return int(value)


def _parse_labels(values: list[str]) -> dict[str, str]:
    """Exactly the identifying labels, once each, with well-formed values."""
    labels: dict[str, str] = {}
    for value in values:
        key, sep, val = value.partition("=")
        if not sep or key not in LABEL_KEYS or key in labels:
            raise refuse("Unexpected analyzer label", {"label": key})
        labels[key] = val
    if set(labels) != set(LABEL_KEYS):
        raise refuse("An analyzer label is missing")
    if labels[LABEL_ROLE] != ROLE_ANALYZER:
        raise refuse("Invalid analyzer role label")
    if not _INSTANCE_RE.match(labels[LABEL_INSTANCE]):
        raise refuse("Invalid analyzer instance label")
    if not re.fullmatch(_UUID, labels[LABEL_SCAN]) or not _CLAIM_RE.match(labels[LABEL_CLAIM]):
        raise refuse("Invalid analyzer scan or claim label")
    return labels


def assert_create_hardened(argv: list[str], *, workspace_root: str | None = None) -> Mode:
    """Raise sandbox_refused unless `argv` has exactly the required restrictions.

    `workspace_root` is the resolved WORKSPACE_ROOT; every bind source must sit directly under
    it (audit finding L4). Without it, any bind mount is refused.
    """
    if any(SOCKET_MARKER in token for token in argv):
        raise refuse("The Docker socket must never be mounted")
    flags, rest = _parse_flags(argv)
    missing = _REQUIRED_KEYS - flags.keys()
    if missing:
        raise refuse("Required analyzer restriction is missing", {"flags": sorted(missing)})
    for key in _SINGLE_VALUED | _VALUELESS:
        if len(flags[key]) != 1:
            raise refuse("Flag may appear only once", {"flag": key})
    labels = _parse_labels(flags["--label"])
    for key, wanted in _REQUIRED.items():
        if flags[key] != [wanted]:
            raise refuse("Analyzer restriction has the wrong value", {"flag": key})
    name = _NAME_RE.match(flags["--name"][0])
    if not name:
        raise refuse("Invalid analyzer container name")
    if not _USER_RE.match(flags["--user"][0]):
        raise refuse("The analyzer must run as a numeric non-root user")
    memory, swap = flags["--memory"][0], flags["--memory-swap"][0]
    if not _MEMORY_RE.match(memory) or memory != swap:
        raise refuse("Memory limit must be set, with no swap")
    if not flags["--pids-limit"][0].isdigit() or int(flags["--pids-limit"][0]) <= 0:
        raise refuse("A positive pids limit is required")
    try:
        cpus = float(flags["--cpus"][0])
    except ValueError as exc:
        raise refuse("Invalid CPU limit") from exc
    if cpus <= 0:
        raise refuse("A positive CPU limit is required")
    if not _TMPFS_RE.match(flags["--tmpfs"][0]):
        raise refuse("Only the size-limited noexec /tmp tmpfs is allowed")

    if (
        len(rest) != 7
        or rest[0].startswith("-")
        or rest[1] != "--deadline"
        or rest[3] != "--cpu-seconds"
        or rest[5] != "--mode"
    ):
        raise refuse("Unexpected analyzer command")
    _bounded_int(rest[2], MAX_DEADLINE_SECONDS, "deadline")
    _bounded_int(rest[4], MAX_CPU_SECONDS, "CPU-time limit")
    mode = rest[6]
    if mode not in _MODE_MOUNTS or name.group(1) != mode:
        raise refuse("Unexpected analyzer mode")
    scan_in_name = flags["--name"][0][len("px-ana-") : len("px-ana-") + 36]
    if labels[LABEL_SCAN] != scan_in_name or labels[LABEL_MODE] != mode:
        raise refuse("Analyzer labels do not match the container")

    required = _MODE_MOUNTS[mode]
    allowed = {**required, **_OPTIONAL_MOUNTS.get(mode, {})}
    seen: set[str] = set()
    for value in flags["--mount"]:
        dst, subdir, read_only, mount_scan = _parse_mount(value, workspace_root)
        if mount_scan != scan_in_name:
            raise refuse("Analyzer mount belongs to another scan", {"target": dst})
        if dst in seen or dst not in allowed:
            raise refuse("Unexpected analyzer mount", {"target": dst})
        if allowed[dst] != (subdir, read_only):
            raise refuse("Analyzer mount has the wrong source or access mode", {"target": dst})
        seen.add(dst)
    if not set(required) <= seen:
        raise refuse("A required analyzer mount is missing")
    return mode  # type: ignore[return-value]


MountTuple = tuple[str, str, str, bool, str, bool]


def expected_mounts(mounts: tuple["MountSpec", ...]) -> set[MountTuple]:
    out = set()
    for m in mounts:
        staging = m.subdir == "staging"
        if m.kind != "volume" or staging:
            subpath = ""
        elif m.subdir == "scan":
            subpath = str(m.scan_id)
        else:
            subpath = f"{m.scan_id}/{m.subdir}"
        out.add((m.kind, m.source, m.target, m.read_only, subpath, staging))
    return out


# Docker Desktop (WSL 2) rewrites the source of a bind mount from a WSL distro into an opaque
# path when the same container also mounts a named volume. Only this exact form is accepted in
# place of the requested host path, and only for a bind the request contains (same target and
# access mode). Compose deployments use volume mode and have no binds at all.
DESKTOP_BIND_RE = re.compile(
    r"^/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/[A-Za-z0-9_.-]{1,64}/[0-9a-f]{64}$"
)
DESKTOP_BIND = "<docker-desktop-rewritten>"


def actual_mounts(host: dict[str, Any]) -> set[MountTuple]:
    out = set()
    for m in host.get("Mounts") or []:
        options = m.get("VolumeOptions") or {}
        source = str(m.get("Source"))
        if m.get("Type") == "bind" and DESKTOP_BIND_RE.match(source):
            source = DESKTOP_BIND
        out.add(
            (
                str(m.get("Type")),
                source,
                str(m.get("Target")),
                bool(m.get("ReadOnly")),
                str(options.get("Subpath") or ""),
                bool(options.get("NoCopy")),
            )
        )
    return out


def mounts_match(host: dict[str, Any], mounts: tuple["MountSpec", ...]) -> bool:
    """Exact match, except that a requested bind may appear in Docker Desktop's rewritten form."""
    expected = expected_mounts(mounts)
    actual = actual_mounts(host)
    relaxed = {(k, DESKTOP_BIND if k == "bind" else src, *rest) for k, src, *rest in expected}
    # Same number of mounts, and each one is either exactly as requested or a requested bind
    # in Docker Desktop's form (distinct targets, so no two actual mounts match one request).
    return len(actual) == len(expected) and all(
        a in expected or (a[0] == "bind" and a in relaxed) for a in actual
    )


def verify_runtime_config(inspected: Any, spec: AnalyzerSpec) -> dict[str, Any]:
    """Check the created container against `spec`. Returns the facts recorded on the scan."""
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        raise refuse("Unexpected docker inspect output")
    info = inspected[0]
    host = info.get("HostConfig") or {}
    config = info.get("Config") or {}
    lim = spec.limits
    problems: list[str] = []

    def check(ok: bool, what: str) -> None:
        if not ok:
            problems.append(what)

    check(host.get("NetworkMode") == "none", "network is not none")
    check(host.get("ReadonlyRootfs") is True, "root filesystem is writable")
    check(host.get("Privileged") is False, "container is privileged")
    check("ALL" in (host.get("CapDrop") or []), "capabilities are not dropped")
    check(not host.get("CapAdd"), "capabilities are added")
    check(
        any(
            o in ("no-new-privileges", "no-new-privileges:true")
            for o in host.get("SecurityOpt") or []
        ),
        "no-new-privileges is not set",
    )
    check(host.get("Memory") == lim.memory_mb * MB, "memory limit differs")
    check(host.get("MemorySwap") == lim.memory_mb * MB, "swap is allowed")
    check(host.get("PidsLimit") == lim.pids, "pids limit differs")
    check(host.get("NanoCpus") == round(lim.cpus * 1e9), "CPU limit differs")
    check(host.get("IpcMode") == "none", "IPC namespace is shared")
    check(host.get("PidMode") in ("", None), "PID namespace is shared")
    check(host.get("UsernsMode") in ("", None), "user namespace mode is overridden")
    check(host.get("UTSMode") in ("", None), "UTS namespace is shared")
    check(not host.get("Devices"), "devices are mapped")
    check(not host.get("Binds"), "legacy bind mounts are present")
    check(not host.get("VolumesFrom"), "volumes are inherited")
    check(
        host.get("Tmpfs") == {"/tmp": f"{TMPFS_OPTIONS},size={lim.tmp_mb}m"},  # noqa: S108
        "tmpfs differs",
    )
    check((host.get("LogConfig") or {}).get("Type") == "none", "container logging is on")
    check(mounts_match(host, spec.mounts), "mounts differ from the request")
    check(list(config.get("Entrypoint") or []) == ENTRYPOINT, "entrypoint is not the worker")
    check(config.get("User") == f"{spec.uid}:{spec.gid}", "user differs")
    labels = config.get("Labels") or {}
    check(all(labels.get(k) == v for k, v in spec.labels.items()), "identifying labels differ")
    check(list(config.get("Cmd") or []) == spec.command, "command (deadline, CPU limit) differs")
    check((host.get("RestartPolicy") or {}).get("Name") in (None, "", "no"), "restart policy set")
    check(not host.get("AutoRemove"), "auto-remove is set")
    env = config.get("Env") or []
    check(not any(_SECRET_ENV_RE.search(str(e).split("=", 1)[0]) for e in env), "secret-like env")
    blob = repr(info)
    check(SOCKET_MARKER not in blob, "the Docker socket is visible")
    problems.extend(common_hardening_problems(info))  # audit finding L3
    if problems:
        raise refuse(
            "The created analyzer container is not hardened as required", {"failed": problems}
        )
    return {
        "image_id": str(info.get("Image") or "")[:80],
        "network": "none",
        "read_only_rootfs": True,
        "cap_drop": "ALL",
        "no_new_privileges": True,
        "user": config.get("User"),
        "memory_mb": lim.memory_mb,
        "cpus": lim.cpus,
        "pids_limit": lim.pids,
        "tmp_mb": lim.tmp_mb,
        "timeout_seconds": lim.timeout_seconds,
        "deadline_seconds": lim.deadline_seconds,
        "cpu_seconds": lim.cpu_seconds,
    }

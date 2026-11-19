"""Hardening for fetcher containers, checked three times like the analyzer's.

1. `build_fetch_argv` writes the `docker create` command.
2. `assert_fetch_hardened` re-parses it against an allowlist. An unknown flag, or a missing or
   altered restriction, stops it before Docker is called.
3. `verify_fetch_runtime` checks the created container (`docker inspect`) and the fetch network
   (`docker network inspect`) before it starts.
The worker's own self-check inside the container (FETCHER_CHECKS) is a fourth, independent view;
it proves from inside that a direct internet connection and external DNS both fail.

Differences from the analyzer: the network is the internal fetch network (never `none`, never a
network with a route out), and the only mount is the scan's tmpfs staging volume, writable. There
is still no Docker socket, no host path, no `--env` (the proxy URL travels in the request on
stdin) and no secret.
"""

import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.analysis.hardening import (
    LABEL_CLAIM,
    LABEL_INSTANCE,
    LABEL_MODE,
    LABEL_ROLE,
    LABEL_SCAN,
    MAX_CPU_SECONDS,
    MAX_DEADLINE_SECONDS,
    NO_CLAIM,
    SOCKET_MARKER,
    TMPFS_OPTIONS,
    refuse,
)
from app.analysis.runtime_checks import common_hardening_problems
from app.analysis.staging import VOLUME_PREFIX

MB = 1024 * 1024
ROLE_FETCHER = "fetcher"
FETCH_MODE = "fetch"
OUT_DST = "/out/src"
ENTRYPOINT = ["python", "-B", "-m", "app.fetch_worker"]
LABEL_KEYS = (LABEL_ROLE, LABEL_INSTANCE, LABEL_SCAN, LABEL_CLAIM, LABEL_MODE)

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_NAME_RE = re.compile(rf"^px-fetch-({_UUID})$")
_USER_RE = re.compile(r"^([1-9]\d*):([1-9]\d*)$")
_MEMORY_RE = re.compile(r"^(\d+)m$")
_TMPFS_RE = re.compile(rf"^/tmp:{TMPFS_OPTIONS},size=(\d+)m$")
_NETWORK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_MOUNT_RE = re.compile(rf"^type=volume,src={VOLUME_PREFIX}({_UUID}),dst={OUT_DST},volume-nocopy$")
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_CLAIM_RE = re.compile(rf"^({_UUID}|{NO_CLAIM})$")
_SECRET_ENV_RE = re.compile(
    r"(?i)(database|secret|token|password|private_key|api_key|blockchain|nvd|docker)"
)
_FORBIDDEN_NETWORKS = frozenset({"none", "host", "bridge", "default", ""})
_REQUIRED = {
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
        "--network",
        "--user",
        "--pids-limit",
        "--memory",
        "--memory-swap",
        "--cpus",
        "--tmpfs",
        "--mount",
    }
)
_REQUIRED_KEYS = frozenset({*_SINGLE_VALUED, *_VALUELESS, "--label"})


@dataclass(frozen=True)
class FetcherLimits:
    timeout_seconds: int
    memory_mb: int
    cpus: float
    pids: int
    tmp_mb: int
    cpu_grace_seconds: int = 30

    @property
    def cpu_seconds(self) -> int:
        return int(self.cpus * self.timeout_seconds + 0.999) + self.cpu_grace_seconds


@dataclass(frozen=True)
class FetcherSpec:
    scan_id: UUID
    image: str
    network: str
    staging_volume: str
    uid: int
    gid: int
    limits: FetcherLimits
    instance: str
    claim_token: str = NO_CLAIM

    @property
    def name(self) -> str:
        return f"px-fetch-{self.scan_id}"

    @property
    def labels(self) -> dict[str, str]:
        return {
            LABEL_ROLE: ROLE_FETCHER,
            LABEL_INSTANCE: self.instance,
            LABEL_SCAN: str(self.scan_id),
            LABEL_CLAIM: self.claim_token,
            LABEL_MODE: FETCH_MODE,
        }

    @property
    def command(self) -> list[str]:
        return [
            "--deadline",
            str(self.limits.timeout_seconds),
            "--cpu-seconds",
            str(self.limits.cpu_seconds),
            "--mode",
            FETCH_MODE,
        ]

    @property
    def mount_flag(self) -> str:
        return f"--mount=type=volume,src={self.staging_volume},dst={OUT_DST},volume-nocopy"


def build_fetch_argv(docker: str, spec: FetcherSpec) -> list[str]:
    if spec.uid == 0 or spec.gid == 0:
        raise refuse("The fetcher never runs as root")
    lim = spec.limits
    return [
        docker,
        "create",
        f"--name={spec.name}",
        f"--network={spec.network}",
        "--read-only",
        f"--user={spec.uid}:{spec.gid}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={lim.pids}",
        f"--memory={lim.memory_mb}m",
        f"--memory-swap={lim.memory_mb}m",
        f"--cpus={lim.cpus:g}",
        spec.mount_flag,
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


def _bounded_int(value: str, upper: int, what: str) -> int:
    if not value.isdigit() or not 0 < int(value) <= upper:
        raise refuse(f"Invalid fetcher {what}")
    return int(value)


def assert_fetch_hardened(argv: list[str], expected_network: str) -> None:
    """Raise sandbox_refused unless `argv` has exactly the required restrictions."""
    if any(SOCKET_MARKER in token for token in argv):
        raise refuse("The Docker socket must never be mounted")
    flags, rest = _parse_flags(argv)
    missing = _REQUIRED_KEYS - flags.keys()
    if missing:
        raise refuse("Required fetcher restriction is missing", {"flags": sorted(missing)})
    for key in _SINGLE_VALUED | _VALUELESS:
        if len(flags[key]) != 1:
            raise refuse("Flag may appear only once", {"flag": key})
    for key, wanted in _REQUIRED.items():
        if flags[key] != [wanted]:
            raise refuse("Fetcher restriction has the wrong value", {"flag": key})
    name = _NAME_RE.match(flags["--name"][0])
    if not name:
        raise refuse("Invalid fetcher container name")
    scan = name.group(1)
    network = flags["--network"][0]
    if (
        network in _FORBIDDEN_NETWORKS
        or network != expected_network
        or not _NETWORK_RE.match(network)
        or network.startswith("container:")
    ):
        raise refuse("The fetcher must use the internal fetch network only")
    if not _USER_RE.match(flags["--user"][0]):
        raise refuse("The fetcher must run as a numeric non-root user")
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
    mount = _MOUNT_RE.match(flags["--mount"][0])
    if not mount or mount.group(1) != scan:
        raise refuse("The fetcher may mount only its own scan's staging volume")

    labels: dict[str, str] = {}
    for value in flags["--label"]:
        key, sep, val = value.partition("=")
        if not sep or key not in LABEL_KEYS or key in labels:
            raise refuse("Unexpected fetcher label", {"label": key})
        labels[key] = val
    if set(labels) != set(LABEL_KEYS):
        raise refuse("A fetcher label is missing")
    if (
        labels[LABEL_ROLE] != ROLE_FETCHER
        or labels[LABEL_MODE] != FETCH_MODE
        or labels[LABEL_SCAN] != scan
        or not _INSTANCE_RE.match(labels[LABEL_INSTANCE])
        or not _CLAIM_RE.match(labels[LABEL_CLAIM])
    ):
        raise refuse("Fetcher labels do not match the container")

    if (
        len(rest) != 7
        or rest[0].startswith("-")
        or rest[1] != "--deadline"
        or rest[3] != "--cpu-seconds"
        or rest[5:] != ["--mode", FETCH_MODE]
    ):
        raise refuse("Unexpected fetcher command")
    _bounded_int(rest[2], MAX_DEADLINE_SECONDS, "deadline")
    _bounded_int(rest[4], MAX_CPU_SECONDS, "CPU-time limit")


def verify_network(inspected: Any, expected: str) -> None:
    """The fetch network must be an internal bridge: Docker gives it no route out."""
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        raise refuse("The fetch network could not be inspected")
    net = inspected[0]
    problems = []
    if net.get("Name") != expected:
        problems.append("name differs")
    if net.get("Internal") is not True:
        problems.append("the network is not internal (it has a route to the internet)")
    if net.get("Driver") != "bridge":
        problems.append("driver is not bridge")
    if net.get("Attachable") is True and net.get("Scope") == "swarm":
        problems.append("swarm-attachable network")
    if problems:
        raise refuse("The fetch network is not isolated as required", {"failed": problems})


def verify_fetch_runtime(inspected: Any, spec: FetcherSpec) -> dict[str, Any]:
    """Check the created fetcher container against `spec`."""
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

    check(host.get("NetworkMode") == spec.network, "network is not the fetch network")
    networks = ((info.get("NetworkSettings") or {}).get("Networks")) or {}
    check(set(networks) <= {spec.network}, "attached to an unexpected network")
    check(host.get("ReadonlyRootfs") is True, "root filesystem is writable")
    check(host.get("Privileged") is False, "container is privileged")
    check("ALL" in (host.get("CapDrop") or []), "capabilities are not dropped")
    check(not host.get("CapAdd"), "capabilities are added")
    check(host.get("Memory") == lim.memory_mb * MB, "memory limit differs")
    check(host.get("MemorySwap") == lim.memory_mb * MB, "swap is allowed")
    check(host.get("PidsLimit") == lim.pids, "pids limit differs")
    check(host.get("NanoCpus") == round(lim.cpus * 1e9), "CPU limit differs")
    check(host.get("IpcMode") == "none", "IPC namespace is shared")
    check(host.get("PidMode") in ("", None), "PID namespace is shared")
    check(host.get("UsernsMode") in ("", None), "user namespace mode is overridden")
    check(host.get("UTSMode") in ("", None), "UTS namespace is shared")
    check(not host.get("Devices"), "devices are mapped")
    check(not host.get("Binds"), "bind mounts are present")
    check(not host.get("VolumesFrom"), "volumes are inherited")
    check(
        host.get("Tmpfs") == {"/tmp": f"{TMPFS_OPTIONS},size={lim.tmp_mb}m"},  # noqa: S108
        "tmpfs differs",
    )
    check((host.get("LogConfig") or {}).get("Type") == "none", "container logging is on")
    mounts = host.get("Mounts") or []
    check(
        len(mounts) == 1
        and mounts[0].get("Type") == "volume"
        and mounts[0].get("Source") == spec.staging_volume
        and mounts[0].get("Target") == OUT_DST
        and not mounts[0].get("ReadOnly")
        and (mounts[0].get("VolumeOptions") or {}).get("NoCopy") is True
        and not (mounts[0].get("VolumeOptions") or {}).get("Subpath"),
        "mounts differ from the request (only the staging volume is allowed)",
    )
    check(config.get("User") == f"{spec.uid}:{spec.gid}", "user differs")
    labels = config.get("Labels") or {}
    check(all(labels.get(k) == v for k, v in spec.labels.items()), "identifying labels differ")
    check(list(config.get("Cmd") or []) == spec.command, "command (deadline, CPU limit) differs")
    check(list(config.get("Entrypoint") or []) == ENTRYPOINT, "entrypoint is not the fetcher")
    check((host.get("RestartPolicy") or {}).get("Name") in (None, "", "no"), "restart policy set")
    check(not host.get("AutoRemove"), "auto-remove is set")
    env = config.get("Env") or []
    check(
        not any(_SECRET_ENV_RE.search(str(e).split("=", 1)[0]) for e in env),
        "secret-like environment variable",
    )
    check(
        not any(str(e).split("=", 1)[0].upper().endswith("_PROXY") for e in env),
        "proxy environment variables are set (the proxy is passed only in the request)",
    )
    check(SOCKET_MARKER not in repr(info), "the Docker socket is visible")
    problems.extend(common_hardening_problems(info))
    if problems:
        raise refuse(
            "The created fetcher container is not hardened as required", {"failed": problems}
        )
    return {
        "image_id": str(info.get("Image") or "")[:80],
        "network": spec.network,
        "network_internal": True,
        "read_only_rootfs": True,
        "cap_drop": "ALL",
        "no_new_privileges": True,
        "user": config.get("User"),
        "memory_mb": lim.memory_mb,
        "cpus": lim.cpus,
        "pids_limit": lim.pids,
        "tmp_mb": lim.tmp_mb,
        "timeout_seconds": lim.timeout_seconds,
        "cpu_seconds": lim.cpu_seconds,
        "staging_volume": spec.staging_volume,
    }

"""Hardening checks on `docker inspect` output shared by analyzer and fetcher containers.

Audit finding L3: the original verification covered network, root filesystem, capabilities,
no-new-privileges, memory, CPU, pids, namespaces, mounts, labels and logging, but not the runtime,
ulimits, OOM-kill setting, sysctls, /dev/shm size, masked and read-only /proc and /sys paths,
seccomp/AppArmor/SELinux overrides, the cgroup namespace or device requests. These are checked
here, against the values this daemon actually reports for a hardened container (Docker 29,
cgroup v2, runc, builtin seccomp profile).

Fail closed: a property that Docker always reports (Runtime, OomKillDisable, ShmSize,
MaskedPaths, ReadonlyPaths, Ulimits, CgroupnsMode, SecurityOpt, Privileged) is a failure when it
is missing or has an unexpected type. Properties that Docker omits when unset (Sysctls, Init,
Annotations, Capabilities) must be absent or empty.

Seccomp: `docker inspect` does not show the default profile, because it is implied. An explicit
override (`seccomp=unconfined`, a custom profile) does appear in SecurityOpt and is refused, and
each worker's self-check confirms from inside that the kernel applies a filter (Seccomp: 2).
"""

from typing import Any

# The defaults Docker applies to an unprivileged container. A privileged container, or one
# created with `--security-opt systempaths=unconfined`, has empty lists here.
REQUIRED_MASKED_PATHS = frozenset(
    {
        "/proc/kcore",
        "/proc/keys",
        "/proc/timer_list",
        "/proc/sched_debug",
        "/proc/acpi",
        "/proc/scsi",
        "/sys/firmware",
    }
)
REQUIRED_READONLY_PATHS = frozenset(
    {"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}
)
ALLOWED_RUNTIMES = frozenset({"runc"})
EXPECTED_ULIMITS = [{"Name": "core", "Hard": 0, "Soft": 0}]
MAX_SHM_BYTES = 64 * 1024 * 1024
_FORBIDDEN_SECURITY_OPTS = (
    "seccomp=unconfined",
    "seccomp:unconfined",
    "apparmor=unconfined",
    "apparmor:unconfined",
    "label=disable",
    "label:disable",
    "label=type:",
    "systempaths=unconfined",
)
_ALLOWED_SECURITY_OPTS = frozenset({"no-new-privileges", "no-new-privileges:true"})


def _missing(host: dict[str, Any], key: str) -> bool:
    return key not in host


def common_hardening_problems(info: dict[str, Any]) -> list[str]:
    """Return the L3 problems found in one container's inspect document (empty: all good)."""
    host = info.get("HostConfig")
    config = info.get("Config")
    if not isinstance(host, dict) or not isinstance(config, dict):
        return ["inspect output has no HostConfig/Config"]
    problems: list[str] = []

    def check(ok: bool, what: str) -> None:
        if not ok:
            problems.append(what)

    for key in (
        "Runtime",
        "OomKillDisable",
        "ShmSize",
        "MaskedPaths",
        "ReadonlyPaths",
        "Ulimits",
        "CgroupnsMode",
        "SecurityOpt",
        "Privileged",
    ):
        check(not _missing(host, key), f"{key} could not be verified")
    if problems:
        return problems

    check(host.get("Runtime") in ALLOWED_RUNTIMES, "container runtime is not runc")
    check(host.get("OomKillDisable") is False, "the OOM killer is disabled")
    check(host.get("Privileged") is False, "container is privileged")
    shm = host.get("ShmSize")
    check(
        isinstance(shm, int) and not isinstance(shm, bool) and 0 <= shm <= MAX_SHM_BYTES,
        "/dev/shm is larger than allowed",  # noqa: S108 - a message, not a path
    )
    masked = host.get("MaskedPaths")
    check(
        isinstance(masked, list) and REQUIRED_MASKED_PATHS <= set(masked),
        "sensitive /proc or /sys paths are not masked",
    )
    readonly = host.get("ReadonlyPaths")
    check(
        isinstance(readonly, list) and REQUIRED_READONLY_PATHS <= set(readonly),
        "/proc paths are not read-only",
    )
    check(host.get("Ulimits") == EXPECTED_ULIMITS, "ulimits differ (only core=0 is allowed)")
    check(host.get("CgroupnsMode") == "private", "cgroup namespace is not private")
    opts = host.get("SecurityOpt")
    check(isinstance(opts, list), "SecurityOpt could not be verified")
    if isinstance(opts, list):
        lowered = [str(o).lower() for o in opts]
        check(
            not any(o.startswith(_FORBIDDEN_SECURITY_OPTS) for o in lowered),
            "a seccomp, AppArmor, SELinux or systempaths restriction is disabled",
        )
        check(
            all(o in _ALLOWED_SECURITY_OPTS for o in lowered),
            "unexpected security options (custom seccomp or AppArmor profile?)",
        )
    for key in ("Sysctls", "Annotations", "Capabilities"):
        check(not host.get(key), f"{key} are set")
    check(host.get("Init") in (None, False), "an init process is injected")
    check(not host.get("PortBindings"), "ports are published")
    check(host.get("PublishAllPorts") in (None, False), "all ports are published")
    check(not host.get("ExtraHosts"), "extra hosts entries are set")
    check(not host.get("Links"), "container links are set")
    check(not host.get("DeviceRequests"), "devices (e.g. GPUs) are requested")
    check(not host.get("DeviceCgroupRules"), "device cgroup rules are set")
    check(not host.get("CgroupParent"), "a custom cgroup parent is set")
    oom_adj = host.get("OomScoreAdj")
    check(isinstance(oom_adj, int) and oom_adj >= 0, "the container is protected from OOM kills")
    check(host.get("Isolation") in (None, ""), "a non-default isolation is set")
    check(not host.get("GroupAdd"), "supplementary groups are added")
    check(not host.get("Dns") and not host.get("DnsSearch"), "custom DNS is set")
    check(not host.get("ContainerIDFile"), "a container id file is set")
    check(not host.get("VolumeDriver"), "a volume driver is set")
    check(not config.get("ExposedPorts"), "ports are exposed")
    check(not config.get("Healthcheck"), "a healthcheck command is set")
    check(config.get("Tty") in (None, False), "a TTY is allocated")
    return problems

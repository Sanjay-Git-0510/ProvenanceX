"""Isolation self-checks, run inside a sandbox container before any untrusted byte is touched.

The runner already verifies the container's runtime configuration with `docker inspect`. This is
the second, independent view from inside: what the kernel actually grants this process. A failed
check stops the worker before it reads the artifact (or, for the fetcher, before it opens a
connection), and the runner refuses any result whose report is not exactly right.

Audit finding L2: a report counts as passing only if it has EXACTLY the expected keys for its
role, and every value is the boolean True (not a truthy string or number). A missing, extra or
malformed check fails closed (`is_isolated`).

Standard library only.
"""

import errno
import os
import socket
from collections.abc import Iterable
from pathlib import Path

DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
_SECRET_MARKERS = ("DATABASE_URL", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY", "API_KEY")

ANALYZER_CHECKS = frozenset(
    {
        "non_root",
        "no_new_privileges",
        "capabilities_dropped",
        "rootfs_read_only",
        "network_isolated",
        "no_docker_socket",
        "seccomp_filtered",
        "no_secret_env",
    }
)
FETCHER_CHECKS = frozenset(
    {
        "non_root",
        "no_new_privileges",
        "capabilities_dropped",
        "rootfs_read_only",
        "single_interface",
        "no_docker_socket",
        "seccomp_filtered",
        "no_secret_env",
        "direct_egress_blocked",
        "external_dns_blocked",
    }
)
# A public address that is never contacted successfully: the fetch network has no route out.
EGRESS_PROBE = ("1.1.1.1", 443)
DNS_PROBE = "github.com"


def _status_fields() -> dict[str, str]:
    fields: dict[str, str] = {}
    try:
        text = Path("/proc/self/status").read_text(encoding="ascii", errors="replace")
    except OSError:
        return fields
    for line in text.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def _caps_empty(fields: dict[str, str]) -> bool:
    keys = ("CapEff", "CapPrm", "CapBnd", "CapAmb")
    try:
        return all(int(fields[k], 16) == 0 for k in keys)
    except (KeyError, ValueError):
        return False


def _rootfs_read_only() -> bool:
    try:
        return bool(os.statvfs("/").f_flag & os.ST_RDONLY)
    except OSError:
        return False


def _interfaces() -> set[str] | None:
    try:
        return {name for _, name in socket.if_nameindex()}
    except OSError:
        return None


def _network_isolated() -> bool:
    """Only the loopback interface may exist (Docker's --network=none)."""
    names = _interfaces()
    return names is not None and names <= {"lo"}


def _single_interface() -> bool:
    """Loopback plus exactly one interface: the internal fetch network, nothing else."""
    names = _interfaces()
    return names is not None and "lo" in names and len(names - {"lo"}) == 1


def _no_secret_env() -> bool:
    return not any(marker in key.upper() for key in os.environ for marker in _SECRET_MARKERS)


def _seccomp_filtered(fields: dict[str, str]) -> bool:
    """2 = SECCOMP_MODE_FILTER: Docker's seccomp profile is applied (not `unconfined`)."""
    return fields.get("Seccomp") == "2"


def _direct_egress_blocked() -> bool:
    """A direct TCP connection to a public address must fail: no route, refused or timeout."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect(EGRESS_PROBE)
    except OSError as exc:
        return exc.errno in (
            errno.ENETUNREACH,
            errno.EHOSTUNREACH,
            errno.ECONNREFUSED,
            errno.ETIMEDOUT,
            None,  # socket.timeout
        )
    else:
        return False
    finally:
        sock.close()


def _external_dns_blocked() -> bool:
    try:
        socket.getaddrinfo(DNS_PROBE, 443, type=socket.SOCK_STREAM)
    except OSError:
        return True
    return False


def _common(fields: dict[str, str]) -> dict[str, bool]:
    return {
        "non_root": os.getuid() != 0 and os.getgid() != 0 and os.geteuid() != 0,
        "no_new_privileges": fields.get("NoNewPrivs") == "1",
        "capabilities_dropped": _caps_empty(fields),
        "rootfs_read_only": _rootfs_read_only(),
        "no_docker_socket": not any(os.path.lexists(p) for p in DOCKER_SOCKETS),
        "seccomp_filtered": _seccomp_filtered(fields),
        "no_secret_env": _no_secret_env(),
    }


def isolation_report() -> dict[str, bool]:
    """The analyzer's report (keys: ANALYZER_CHECKS). Every value must be True."""
    fields = _status_fields()
    return {**_common(fields), "network_isolated": _network_isolated()}


def fetcher_isolation_report() -> dict[str, bool]:
    """The fetcher's report (keys: FETCHER_CHECKS). Every value must be True."""
    fields = _status_fields()
    return {
        **_common(fields),
        "single_interface": _single_interface(),
        "direct_egress_blocked": _direct_egress_blocked(),
        "external_dns_blocked": _external_dns_blocked(),
    }


def is_isolated(report: object, expected: Iterable[str] = ANALYZER_CHECKS) -> bool:
    """True only for a dict with exactly the expected keys, each mapped to the bool True."""
    wanted = frozenset(expected)
    if not isinstance(report, dict) or not wanted:
        return False
    if set(report) != wanted:
        return False
    return all(value is True for value in report.values())


def failed_checks(report: object, expected: Iterable[str] = ANALYZER_CHECKS) -> list[str]:
    """The checks that are missing, unexpected or not exactly True (for error details)."""
    wanted = frozenset(expected)
    if not isinstance(report, dict):
        return sorted(wanted)
    problems = {k for k in wanted if report.get(k) is not True}
    problems |= {f"unexpected:{k}" for k in report if k not in wanted}
    return sorted(str(p)[:64] for p in problems)

"""Isolation self-check, run inside the analyzer container before any artifact byte is read.

The runner already verifies the container's runtime configuration with `docker inspect`. This
is the second, independent view from inside: what the kernel actually grants this process. A
failed check stops the worker before it reads the artifact, and the runner refuses any result
that does not carry a fully passing report.
"""

import os
import socket
from pathlib import Path

DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")


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


def _network_isolated() -> bool:
    """Only the loopback interface may exist (Docker's --network=none)."""
    try:
        names = {name for _, name in socket.if_nameindex()}
    except OSError:
        return False
    return names <= {"lo"}


def isolation_report() -> dict[str, bool]:
    """Every value must be True for the run to count as isolated."""
    fields = _status_fields()
    return {
        "non_root": os.getuid() != 0 and os.getgid() != 0 and os.geteuid() != 0,
        "no_new_privileges": fields.get("NoNewPrivs") == "1",
        "capabilities_dropped": _caps_empty(fields),
        "rootfs_read_only": _rootfs_read_only(),
        "network_isolated": _network_isolated(),
        "no_docker_socket": not any(os.path.lexists(p) for p in DOCKER_SOCKETS),
    }


def is_isolated(report: dict[str, bool]) -> bool:
    return bool(report) and all(report.values())

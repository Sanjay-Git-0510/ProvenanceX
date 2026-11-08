# ruff: noqa: S108 - fixed container paths, used as test data
"""Benign boundary probes, run only inside the real sandbox by tests/integration.

The live tests copy this file to setup.py and write the probe name to PROBE. Exit codes:
  0   the boundary held
  77  the boundary is NOT enforced
Anything else is a probe failure. Nothing here touches anything outside the container.
"""

import ctypes
import errno
import os
import signal
import socket
import stat
import sys
import time
from pathlib import Path

ENFORCED, VIOLATED = 0, 77
HERE = Path(__file__).resolve().parent
# The only mounts a target may create files in. /dev/mqueue is in-memory and private.
ALLOWED_WRITABLE_MOUNTS = {"/tmp", "/trace", "/dev/mqueue"}


def status_field(name):
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(name + ":"):
            return line.split()[1]
    return None


def network():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        try:
            s.connect(("1.1.1.1", 80))
        except OSError as exc:
            return ENFORCED if exc.errno == errno.ENETUNREACH else VIOLATED
    return VIOLATED


def interfaces():
    return ENFORCED if os.listdir("/sys/class/net") == ["lo"] else VIOLATED


def artifact_readonly():
    try:
        (HERE / "written_by_probe").write_text("x")
    except OSError as exc:
        return ENFORCED if exc.errno == errno.EROFS else VIOLATED
    return VIOLATED


def mount_points():
    with open("/proc/self/mountinfo") as fh:
        for line in fh:
            yield line.split()[4].encode().decode("unicode_escape")


def writable_mounts():
    """Try to write to every mount the kernel reports, not a list chosen in advance."""
    written = set()
    for mount in mount_points():
        info = os.stat(mount)
        if stat.S_ISCHR(info.st_mode):
            continue  # masked paths bind /dev/null, which stores nothing
        is_dir = stat.S_ISDIR(info.st_mode)
        target = f"{mount.rstrip('/')}/px_probe" if is_dir else mount
        try:
            with open(target, "w" if is_dir else "a"):
                pass
        except OSError:
            continue
        written.add(mount)
        if is_dir:
            os.unlink(target)
    return ENFORCED if written == ALLOWED_WRITABLE_MOUNTS else VIOLATED


def _denied(action, *errnos):
    """ENFORCED if `action` fails with one of `errnos`, otherwise VIOLATED."""
    try:
        action()
    except OSError as exc:
        return ENFORCED if exc.errno in errnos else VIOLATED
    return VIOLATED


def ipv6_blocked():
    def connect():
        socket.create_connection(("2606:4700:4700::1111", 80), 2).close()

    return _denied(connect, errno.ENETUNREACH)


def vsock_blocked():
    return _denied(lambda: socket.socket(40, socket.SOCK_STREAM).close(), errno.EPERM)


def packet_socket_blocked():
    return _denied(lambda: socket.socket(17, socket.SOCK_RAW).close(), errno.EPERM)


def raw_socket_blocked():
    action = lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, 1).close()  # noqa: E731
    return _denied(action, errno.EPERM)


def user_namespace_blocked():
    return _denied(lambda: os.unshare(os.CLONE_NEWUSER), errno.EPERM)


def _syscall_errno(function, *args):
    ctypes.set_errno(0)
    result = function(*args)
    return result, ctypes.get_errno()


def io_uring_blocked():
    libc = ctypes.CDLL(None, use_errno=True)
    result, err = _syscall_errno(libc.syscall, 425, 1, 0)  # io_uring_setup
    return ENFORCED if result == -1 and err == errno.EPERM else VIOLATED


def ptrace_pid1_blocked():
    libc = ctypes.CDLL(None, use_errno=True)
    result, err = _syscall_errno(libc.ptrace, 16, 1, 0, 0)  # PTRACE_ATTACH
    return ENFORCED if result == -1 and err == errno.EPERM else VIOLATED


def non_root():
    expected = int((HERE / "EXPECTED_UID").read_text())
    return ENFORCED if os.geteuid() != 0 and os.geteuid() == expected else VIOLATED


def capabilities():
    fields = ("CapEff", "CapPrm", "CapBnd", "CapInh")
    return ENFORCED if all(int(status_field(f), 16) == 0 for f in fields) else VIOLATED


def no_new_privileges():
    return ENFORCED if status_field("NoNewPrivs") == "1" else VIOLATED


def seccomp():
    return ENFORCED if status_field("Seccomp") == "2" else VIOLATED


def fork_limit():
    children = []
    result = VIOLATED
    try:
        for _ in range(1000):
            pid = os.fork()
            if pid == 0:
                time.sleep(60)
                os._exit(0)
            children.append(pid)
    except OSError as exc:
        result = ENFORCED if exc.errno == errno.EAGAIN else 3
    for pid in children:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    return result


def memory_limit():
    held = []
    for _ in range(128):  # 2 GB in total, far above the limit used by the test
        block = bytearray(16 * 1024 * 1024)
        for offset in range(0, len(block), 4096):
            block[offset] = 1
        held.append(block)
    return VIOLATED


def cpu_load():
    children = []
    for _ in range(3):
        pid = os.fork()
        if pid == 0:
            end = time.monotonic() + 4
            while time.monotonic() < end:
                pass
            os._exit(0)
        children.append(pid)
    for pid in children:
        os.waitpid(pid, 0)
    return ENFORCED


def sleep_forever():
    time.sleep(600)
    return VIOLATED


def _detach():
    """Fork a child in its own session, outside the target's process group."""
    if os.fork() == 0:
        os.setsid()
        time.sleep(600)
        os._exit(0)


def setsid_parent_waits():
    _detach()
    time.sleep(600)
    return VIOLATED


def setsid_parent_exits():
    _detach()
    return ENFORCED


def docker_socket():
    paths = ("/var/run/docker.sock", "/run/docker.sock")
    return VIOLATED if any(os.path.exists(p) for p in paths) else ENFORCED


if __name__ == "__main__":
    name = (HERE / "PROBE").read_text().strip()
    sys.exit(globals()[name]())

"""In-container deadline and CPU-time supervisor shared by the analyzer and fetcher workers.

PID 1 forks. The child does the work under RLIMIT_CPU; the parent only waits. At the deadline
the parent kills the child and exits EXIT_DEADLINE, which stops the container and every process
left in its PID namespace, even when the runner that started it is gone (audit finding M1).
The work runs in a child because PID 1 of a namespace ignores signals it has no handler for.
Standard library only: it runs before any third-party import.
"""

import argparse
import os
import resource
import signal
import sys

from app.sandbox_worker.exitcodes import EXIT_CPU_LIMIT, EXIT_DEADLINE

CPU_HARD_MARGIN_SECONDS = 5  # SIGKILL this long after SIGXCPU, if SIGXCPU is ignored


def positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def _kill(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def supervise(deadline: int, cpu_seconds: int | None) -> int | None:
    """Fork. Returns None in the child (which then does the work), the exit code in the parent."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        signal.alarm(0)
        if cpu_seconds:
            resource.setrlimit(
                resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + CPU_HARD_MARGIN_SECONDS)
            )
        return None

    def expire(_signum: int, _frame: object) -> None:
        _kill(pid)
        os._exit(EXIT_DEADLINE)

    def stop(signum: int, _frame: object) -> None:
        _kill(pid)
        os._exit(128 + signum)

    signal.signal(signal.SIGALRM, expire)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.alarm(deadline)
    _, status = os.waitpid(pid, 0)
    signal.alarm(0)
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        return EXIT_CPU_LIMIT if sig == signal.SIGXCPU else 128 + sig
    return os.WEXITSTATUS(status)

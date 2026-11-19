"""Analyzer container entry point:
`python -B -m app.sandbox_worker --deadline S --cpu-seconds C --mode extract|analyze`.

Reads one WorkerRequest (JSON) from stdin, runs the isolation self-check, then the requested
mode against the fixed mount points, and prints exactly one WorkerResult (JSON) on stdout. It
exits 0 whenever it printed a result, including an error result; any other exit means the run
failed (for example, the kernel killed it at the memory limit).

Self-imposed limits (audit finding M1). With --deadline, the process forks: the child does the
work under RLIMIT_CPU (--cpu-seconds), and the parent (PID 1 of the container) only waits. At
the deadline the parent kills the child and exits EXIT_DEADLINE, which stops the container and,
with it, every process left in its PID namespace. This holds even when the runner that started
the container was killed and nothing on the host will ever stop it. The work runs in a child
because PID 1 of a namespace ignores signals it has no handler for, so a stuck PID 1 could
not be stopped by an alarm or by RLIMIT_CPU's SIGXCPU. Only the standard library is imported
before the deadline is armed; the analysis code (pydantic, parsers, Syft wrapper) is imported
by the child, inside the deadline.
"""

import argparse
import json
import os
import resource
import signal
import sys
from pathlib import Path
from typing import Any

from app.sandbox_worker.exitcodes import EXIT_CPU_LIMIT, EXIT_DEADLINE

# Fixed mount points. They are not taken from the request.
ARTIFACT_DIR = Path("/artifact")  # analyze: the src tree, read-only
INPUT_UPLOAD = Path("/input/upload.zip")  # extract and analyze: the raw upload, read-only
OUT_SRC = Path("/out/src")  # extract only: the per-scan src directory, writable
SCRATCH = Path("/tmp")  # noqa: S108 - size-limited noexec tmpfs
MAX_REQUEST_BYTES = 4 * 1024 * 1024
CPU_HARD_MARGIN_SECONDS = 5  # SIGKILL this long after SIGXCPU, if SIGXCPU is ignored


def _emit(result: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(result, allow_nan=False, separators=(",", ":")))
    sys.stdout.flush()


def _positive(value: str) -> int:
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deadline", type=_positive, default=None)
    parser.add_argument("--cpu-seconds", type=_positive, default=None)
    parser.add_argument("--mode", choices=("extract", "analyze"), required=True)
    args = parser.parse_args(argv)
    if args.deadline is not None:
        code = supervise(args.deadline, args.cpu_seconds)
        if code is not None:
            return code
    return run(args.mode)


def run(mode: str) -> int:
    # Imported here, after the deadline is armed (see the module docstring).
    from app.sandbox_worker.collect import run_analyze, run_extract, section_error
    from app.sandbox_worker.protocol import RESULT_FORMAT, WorkerRequest
    from app.sandbox_worker.selfcheck import is_isolated, isolation_report

    report = isolation_report()
    base: dict[str, Any] = {
        "format": RESULT_FORMAT,
        "mode": mode,
        "isolation_mode": "container",
        "isolation": report,
    }
    if not is_isolated(report):
        _emit(
            {
                **base,
                "status": "error",
                "error": {
                    "code": "sandbox_refused",
                    "message": "The analyzer container is not isolated; nothing was analyzed",
                    "details": {"failed_checks": sorted(k for k, v in report.items() if not v)},
                },
            }
        )
        return 0

    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request too large")
        request = WorkerRequest.model_validate_json(raw)
        if request.mode != mode:
            raise ValueError("request mode does not match --mode")
        if mode == "extract":
            run_extract(request, INPUT_UPLOAD, OUT_SRC)
            _emit({**base, "status": "ok"})
        else:
            analysis = run_analyze(request, ARTIFACT_DIR, INPUT_UPLOAD, SCRATCH)
            _emit({**base, "status": "ok", "analysis": analysis})
    except Exception as exc:  # noqa: BLE001 - reported as a structured error result
        _emit({**base, "status": "error", "error": section_error(exc)})
    return 0


if __name__ == "__main__":
    sys.exit(main())

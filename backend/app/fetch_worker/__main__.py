"""Fetcher container entry point:
`python -B -m app.fetch_worker --deadline S --cpu-seconds C --mode fetch`.

Reads one FetchRequest (JSON) from stdin, runs the fetcher isolation self-check (non-root,
no capabilities, no-new-privileges, read-only root, seccomp, no Docker socket, no secret-like
environment, exactly one network interface, and proof that a direct connection to the internet
and external DNS both fail), then downloads into the staging volume mounted at /out/src and
writes one framed FetchResult on stdout. Exit 0 whenever a result was written.

The deadline and CPU limit are enforced in the container (app/sandbox_worker/supervise.py),
so a hung download stops even if the runner that started it is gone. Only the standard library
is imported before the deadline is armed.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from app.analysis.framing import write_frames
from app.sandbox_worker.supervise import positive, supervise

OUT_SRC = Path("/out/src")  # the scan's tmpfs staging volume (kernel-capped)
MAX_REQUEST_BYTES = 256 * 1024


def _emit(result: dict[str, Any]) -> None:
    envelope = json.dumps(result, allow_nan=False, separators=(",", ":"), default=str).encode()
    write_frames(sys.stdout.buffer, envelope)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deadline", type=positive, default=None)
    parser.add_argument("--cpu-seconds", type=positive, default=None)
    parser.add_argument("--mode", choices=("fetch",), required=True)
    args = parser.parse_args(argv)
    if args.deadline is not None:
        code = supervise(args.deadline, args.cpu_seconds)
        if code is not None:
            return code
    return run()


def run() -> int:
    from app.fetch_worker.errors import section_error
    from app.fetch_worker.protocol import RESULT_FORMAT, FetchRequest
    from app.fetch_worker.run import run_fetch
    from app.sandbox_worker.selfcheck import (
        FETCHER_CHECKS,
        failed_checks,
        fetcher_isolation_report,
        is_isolated,
    )

    report = fetcher_isolation_report()
    base: dict[str, Any] = {
        "format": RESULT_FORMAT,
        "isolation_mode": "container",
        "isolation": report,
        "source": "github",
    }
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request too large")
        request = FetchRequest.model_validate_json(raw)
        base["source"] = request.source
    except Exception as exc:  # noqa: BLE001 - structured error result
        _emit({**base, "status": "error", "error": section_error(exc)})
        return 0
    if not is_isolated(report, FETCHER_CHECKS):
        _emit(
            {
                **base,
                "status": "error",
                "error": {
                    "code": "sandbox_refused",
                    "message": "The fetcher container is not isolated; nothing was downloaded",
                    "details": {"failed_checks": failed_checks(report, FETCHER_CHECKS)},
                },
            }
        )
        return 0
    try:
        out = run_fetch(request, OUT_SRC)
        _emit({**base, "status": "ok", **out})
    except Exception as exc:  # noqa: BLE001 - structured error result
        _emit({**base, "status": "error", "error": section_error(exc)})
    return 0


if __name__ == "__main__":
    sys.exit(main())

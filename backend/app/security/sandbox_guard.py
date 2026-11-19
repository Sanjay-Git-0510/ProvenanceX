"""Guards for the code paths that read or download untrusted artifact content.

`require_worker_context()` is the first call in every analyzer-worker entry point. It passes
only inside the analyzer container (the image sets PX_ANALYZER_WORKER=1 and Docker creates
/.dockerenv), or inside `inprocess_test_context()`, which the pytest-only in-process executor
opens. Anywhere else (the API, the scan-runner, a host shell) it raises sandbox_refused, so an
accidental call can never turn into host-side processing.
"""

import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from app.core.errors import AppError, ErrorCode

WORKER_ENV = "PX_ANALYZER_WORKER"
FETCH_WORKER_ENV = "PX_FETCH_WORKER"
_inprocess_test: ContextVar[bool] = ContextVar("px_inprocess_test", default=False)


def running_under_pytest() -> bool:
    return "pytest" in sys.modules and "PYTEST_CURRENT_TEST" in os.environ


def in_analyzer_container() -> bool:
    return os.environ.get(WORKER_ENV) == "1" and Path("/.dockerenv").exists()


def in_fetcher_container() -> bool:
    return os.environ.get(FETCH_WORKER_ENV) == "1" and Path("/.dockerenv").exists()


@contextmanager
def inprocess_test_context() -> Iterator[None]:
    """Allow worker code in this process. Refused outside a running pytest test."""
    if not running_under_pytest():
        raise AppError(
            ErrorCode.SANDBOX_REFUSED,
            "In-process analysis is available only inside the test suite",
            500,
        )
    token = _inprocess_test.set(True)
    try:
        yield
    finally:
        _inprocess_test.reset(token)


def require_worker_context() -> None:
    if in_analyzer_container():
        return
    if _inprocess_test.get() and running_under_pytest():
        return
    raise AppError(
        ErrorCode.SANDBOX_REFUSED,
        "Artifact content may only be processed inside the analyzer sandbox",
        500,
    )


def require_fetch_context() -> None:
    """First call of every download entry point (git clone, Hugging Face fetch, mock fetch).

    Passes only inside the fetcher container, or inside `inprocess_test_context()` in a running
    pytest test. The scan-runner and the API can therefore never download artifacts, even by
    accident (audit finding H1): there is no host-side download path to fall back to.
    """
    if in_fetcher_container():
        return
    if _inprocess_test.get() and running_under_pytest():
        return
    raise AppError(
        ErrorCode.SANDBOX_REFUSED,
        "Artifacts may only be downloaded inside the isolated fetcher container",
        500,
    )

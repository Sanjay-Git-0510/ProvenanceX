"""Structured error results for the fetcher (kept free of the analyzer's heavy imports)."""

import errno
import traceback
from typing import Any

from app.core.errors import AppError, ErrorCode
from app.security.archive import storage_limit_error


def section_error(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
        exc = storage_limit_error()
    if isinstance(exc, AppError):
        details = exc.details if isinstance(exc.details, dict | list | str | int | None) else None
        return {"code": str(exc.code), "message": exc.message[:2000], "details": details}
    # The traceback goes to stderr (captured, capped and logged by the runner), not the result.
    traceback.print_exception(exc)
    return {
        "code": str(ErrorCode.FETCH_FAILED),
        "message": f"The fetch failed ({exc.__class__.__name__})",
        "details": None,
    }

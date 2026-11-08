"""Structured API errors.

Every error response uses the envelope:
    {"error": {"code": str, "message": str, "details": object | null}}
"""

import logging
from enum import StrEnum
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


class ErrorCode(StrEnum):
    """Stable machine-readable error codes returned in the error envelope and stored on scans."""

    INVALID_INPUT = "invalid_input"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    INVALID_URL = "invalid_url"
    URL_NOT_ALLOWED = "url_not_allowed"
    PRIVATE_ADDRESS = "private_address"
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"
    INVALID_REVISION = "invalid_revision"
    ARTIFACT_TOO_LARGE = "artifact_too_large"
    TOO_MANY_FILES = "too_many_files"
    EMPTY_ARTIFACT = "empty_artifact"
    INVALID_ARCHIVE = "invalid_archive"
    UNSAFE_ARCHIVE = "unsafe_archive"
    UNSAFE_CONTENT = "unsafe_content"
    CLONE_FAILED = "clone_failed"
    CLONE_TIMEOUT = "clone_timeout"
    WORKSPACE_ERROR = "workspace_error"
    SBOM_TOOL_UNAVAILABLE = "sbom_tool_unavailable"
    SBOM_TIMEOUT = "sbom_timeout"
    SBOM_FAILED = "sbom_failed"
    SBOM_TOO_LARGE = "sbom_too_large"
    SBOM_PARSE_ERROR = "sbom_parse_error"
    VULN_SOURCE_UNAVAILABLE = "vuln_source_unavailable"
    VULN_SOURCE_ERROR = "vuln_source_error"
    HF_ACCESS_DENIED = "hf_access_denied"
    HF_NOT_FOUND = "hf_not_found"
    HF_UNAVAILABLE = "hf_unavailable"
    HF_ERROR = "hf_error"
    MODEL_PARSE_ERROR = "model_parse_error"
    DOWNLOAD_INTEGRITY_ERROR = "download_integrity_error"
    SANDBOX_TRACE_ERROR = "sandbox_trace_error"
    SCAN_NOT_FOUND = "scan_not_found"
    DATABASE_UNAVAILABLE = "database_unavailable"
    INTERNAL_ERROR = "internal_error"


class AppError(Exception):
    """Base class for expected, user-facing failures."""

    def __init__(
        self, code: str, message: str, status_code: int = 400, details: Any = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details


def error_body(code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


async def _app_error_handler(_: Request, exc: AppError) -> JSONResponse:
    logger.warning("AppError %s: %s", exc.code, exc.message)
    return JSONResponse(
        status_code=exc.status_code, content=error_body(exc.code, exc.message, exc.details)
    )


async def _http_error_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = "not_found" if exc.status_code == 404 else f"http_{exc.status_code}"
    return JSONResponse(status_code=exc.status_code, content=error_body(code, str(exc.detail)))


async def _validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        {"loc": list(e.get("loc", [])), "msg": e.get("msg"), "type": e.get("type")}
        for e in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content=error_body("validation_error", "Request validation failed", details),
    )


async def _unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
    # Log with traceback; never leak internals to the client.
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(
        status_code=500, content=error_body("internal_error", "An internal error occurred")
    )


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(Exception, _unhandled_error_handler)

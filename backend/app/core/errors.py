"""Structured API errors.

Every error response uses the envelope:
    {"error": {"code": str, "message": str, "details": object | null}}

This module has no web-framework imports, so the analyzer sandbox can use the error types
without FastAPI. The HTTP exception handlers live in app/core/error_handlers.py.
"""

from enum import StrEnum
from typing import Any


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
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    SANDBOX_FAILED = "sandbox_failed"
    SANDBOX_REFUSED = "sandbox_refused"
    ANALYZER_OUTPUT_INVALID = "analyzer_output_invalid"
    RUNNER_INTERRUPTED = "runner_interrupted"
    BLOCKCHAIN_DISABLED = "blockchain_disabled"
    CHAIN_REFUSED = "chain_refused"
    CHAIN_UNAVAILABLE = "chain_unavailable"
    ANCHOR_SCAN_NOT_COMPLETED = "anchor_scan_not_completed"
    ANCHOR_NO_DECISION = "anchor_no_decision"
    ANCHOR_MISSING_ARTIFACT_HASH = "anchor_missing_artifact_hash"
    ANCHOR_INVALID_HASH = "anchor_invalid_hash"
    ANCHOR_INVALID_RECORD = "anchor_invalid_record"
    ANCHOR_REFUSED_MOCK_EVIDENCE = "anchor_refused_mock_evidence"
    ANCHOR_ALREADY_EXISTS = "anchor_already_exists"
    ANCHOR_IN_PROGRESS = "anchor_in_progress"
    ANCHOR_CONFLICT = "anchor_conflict"
    RISK_NOT_COMPUTED = "risk_not_computed"
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


def register_error_handlers(app: Any) -> None:
    """Kept for existing imports; see app/core/error_handlers.py."""
    from app.core.error_handlers import install_error_handlers

    install_error_handlers(app)

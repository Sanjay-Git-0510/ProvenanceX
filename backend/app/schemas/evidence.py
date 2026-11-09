"""The /evidence response: a bounded, sanitized summary of what a scan collected.

Fields are allowlisted, so file contents, raw SBOMs, traces and finding details never enter it.
Artifact-derived text can still appear in allowlisted fields (names, titles, check evidence), so
every string also passes through `sanitize` before the response is returned.
"""

import re
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.db.models import FindingCategory, ScanStatus
from app.ml.feature_schema import FeatureValue
from app.risk.policy_config import RiskLayer
from app.schemas.risk import TrainingDataLabel
from app.schemas.scans import ArtifactRecord

MAX_TEXT = 1024
MAX_LIST_ITEMS = 20
MAX_CHECKS = 100
MAX_PAGE = 200
DEFAULT_PAGE = 50
REDACTED = "[redacted]"
TRUNCATED = "...[truncated]"

_HOST_ROOTS = (
    "home|root|app|tmp|var|etc|mnt|workspace|workspaces|usr|opt|srv|proc|run|dev|sys|bin|lib|Users"
)
_SENSITIVE = (
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S
    ),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bhf_[A-Za-z0-9]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b0x[0-9a-fA-F]{64}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@\S*"),
    re.compile(r"(?i)\bfile:/+\S*"),
    re.compile(r"\b[A-Za-z]:\\[^\s'\"]*"),
    re.compile(r"\\\\[^\s\\'\"]+\\[^\s'\"]*"),
    re.compile(rf"(?<![\w:.\-/])/(?:{_HOST_ROOTS})(?:/[^\s'\"]*)?(?![\w-])"),
)


class Sanitized(BaseModel):
    redacted_values: int = 0
    truncated_values: int = 0


def _clean_text(text: str, totals: Sanitized) -> str:
    cleaned = text
    for pattern in _SENSITIVE:
        cleaned = pattern.sub(REDACTED, cleaned)
    if cleaned != text:
        totals.redacted_values += 1
    if len(cleaned) > MAX_TEXT:
        totals.truncated_values += 1
        cleaned = cleaned[:MAX_TEXT] + TRUNCATED
    return cleaned


def sanitize(value: Any, totals: Sanitized) -> Any:
    """Redact host paths and secret-like strings, and cap the length of every string."""
    if isinstance(value, str):
        return _clean_text(value, totals)
    if isinstance(value, list):
        return [sanitize(item, totals) for item in value]
    if isinstance(value, dict):
        return {key: sanitize(item, totals) for key, item in value.items()}
    return value


class StageOut(BaseModel):
    name: str
    status: str | None
    provider: str | None = None
    source: str | None = None
    is_mock: bool = False
    started_at: str | None = None
    finished_at: str | None = None
    reason: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    incomplete_reasons: list[str] = []
    limitations: list[str] = []
    warnings: list[str] = []


class ScanErrorSummary(BaseModel):
    code: str | None
    message: str | None


class StateReason(BaseModel):
    code: str
    message: str


class FeatureOut(BaseModel):
    name: str
    layer: RiskLayer
    value: FeatureValue
    evaluated: bool
    null_reason: str | None = None


class FeatureVectorOut(BaseModel):
    status: str  # available | pending | not_computed
    reason: StateReason | None = None
    features: list[FeatureOut] = []


class FindingSummaryOut(BaseModel):
    finding_id: UUID
    category: FindingCategory
    identifier: str
    title: str | None
    severity: str
    cvss_score: float | None
    source: str
    is_mock: bool
    component_id: UUID | None


class ComponentSummaryOut(BaseModel):
    component_id: UUID
    name: str
    version: str | None
    component_type: str
    ecosystem: str | None
    purl: str | None
    source: str
    is_mock: bool


class Page(BaseModel):
    total: int
    limit: int
    offset: int
    has_more: bool


class FindingsSection(BaseModel):
    page: Page
    by_category: dict[str, int]
    by_severity: dict[str, int]
    by_source: dict[str, int]
    items: list[FindingSummaryOut]


class ComponentsSection(BaseModel):
    page: Page
    by_source: dict[str, int]
    items: list[ComponentSummaryOut]


class ProvenanceCheckSummary(BaseModel):
    name: str
    status: str
    evidence: str
    severity: str | None = None
    identifier: str | None = None


class ProvenanceSummary(BaseModel):
    """Null booleans mean "could not be determined", never "no"."""

    source_known: bool
    revision_pinned: bool
    resolved_commit: str | None
    signed: bool | None
    signature_files_present: bool
    provenance_present: bool
    hash_changed: bool | None
    previous_scan_id: UUID | None
    lineage_completeness: float | None
    source: str
    is_mock: bool
    checks: list[ProvenanceCheckSummary]
    checks_truncated: bool
    created_at: datetime


class HashValue(BaseModel):
    value: str | None
    reason: str | None = None


class Hashes(BaseModel):
    artifact_sha256: HashValue
    bom_sha256: HashValue
    provenance_record_sha256: HashValue
    sandbox_trace_sha256: HashValue


class ModelInfo(BaseModel):
    model_version: str | None
    ml_status: str | None


class MockFlags(BaseModel):
    contains_mock_evidence: bool
    mock_stages: list[str]
    mock_findings: int
    mock_components: int
    provenance_is_mock: bool


class EvidenceResponse(BaseModel):
    scan_id: UUID
    scan_status: ScanStatus
    scan_error: ScanErrorSummary | None
    scanner_version: str
    artifact: ArtifactRecord
    stages: list[StageOut]
    feature_vector: FeatureVectorOut
    findings: FindingsSection
    components: ComponentsSection
    provenance: ProvenanceSummary | None
    hashes: Hashes
    model: ModelInfo
    mock: MockFlags
    training_data: TrainingDataLabel
    sanitized: Sanitized

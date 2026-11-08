"""Findings API schemas.

CVSS (advisory severity), ML probability (Phase 5) and ProvenanceX risk (Phase 6) are
separate values. This response carries CVSS only, labeled as such.
"""

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel

from app.db.models import Finding, FindingCategory

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]


class CvssOut(BaseModel):
    """Advisory CVSS base score. This is not the ProvenanceX risk score."""

    score: float | None
    vector: str | None
    version: str | None
    source: str | None  # osv | nvd | mock | None


class FindingComponentOut(BaseModel):
    component_id: UUID | None
    name: str | None
    version: str | None
    purl: str | None
    ecosystem: str | None


class FindingOut(BaseModel):
    finding_id: UUID
    category: FindingCategory
    kind: str | None  # e.g. "known_vulnerability"
    identifier: str
    aliases: list[str]
    title: str | None
    severity: str
    severity_source: str | None
    cvss: CvssOut
    source: str
    is_mock: bool
    component: FindingComponentOut | None
    details: dict[str, Any]

    @classmethod
    def from_row(cls, f: Finding) -> "FindingOut":
        details = dict(f.details or {})
        comp = f.component
        pkg = details.get("package") or {}
        return cls(
            finding_id=f.id,
            category=f.category,
            kind=details.get("kind"),
            identifier=f.identifier,
            aliases=list(f.aliases or []),
            title=f.title,
            severity=f.severity,
            severity_source=f.severity_source,
            cvss=CvssOut(
                score=f.cvss_score,
                vector=f.cvss_vector,
                version=f.cvss_version,
                source=details.get("cvss_source"),
            ),
            source=f.source,
            is_mock=f.source == "mock",
            component=FindingComponentOut(
                component_id=comp.id if comp else f.component_id,
                name=comp.name if comp else pkg.get("name"),
                version=comp.version if comp else pkg.get("version"),
                purl=comp.purl if comp else pkg.get("purl"),
                ecosystem=comp.ecosystem if comp else None,
            )
            if comp or pkg
            else None,
            details=details,
        )


class FindingsResponse(BaseModel):
    scan_id: UUID
    total: int
    limit: int
    offset: int
    items: list[FindingOut]
    contains_mock: bool
    # Status of the vulnerability stage. "unavailable"/"error"/"skipped" means an empty
    # list is NOT evidence of "no vulnerabilities".
    stage: dict[str, Any] | None
    # Status of every stage that produces findings, keyed by finding category:
    # vulnerability -> vulnerabilities, static -> aibom, provenance -> provenance.
    stages: dict[str, Any] = {}

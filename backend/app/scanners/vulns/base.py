"""Vulnerability provider interface and normalized advisory records."""

from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from app.scanners.vulns.cvss import severity_rank


@dataclass(frozen=True)
class PackageQuery:
    """A package to look up. `ref` is the SBOM bom-ref, used to map results back."""

    ref: str
    purl: str  # normalized: no qualifiers or subpath, version included
    name: str
    version: str
    ecosystem: str | None


@dataclass(frozen=True)
class Advisory:
    """A known-vulnerability record, normalized across sources.

    `cvss_score` is the advisory's CVSS base score (computed from the vector, or supplied
    by NVD). `severity` is the CVSS band, or the advisory's own label when there is no
    usable CVSS. Neither one is a ProvenanceX risk score.
    """

    identifier: str
    aliases: tuple[str, ...]
    summary: str | None
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | NONE | UNKNOWN
    severity_source: str | None  # cvss_v3 | advisory | nvd | None
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    cvss_source: str | None  # osv | nvd | mock | None
    source: str  # osv | mock
    fixed_versions: tuple[str, ...] = ()
    affected_ranges: tuple[dict[str, Any], ...] = ()
    references: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    published: str | None = None
    modified: str | None = None
    other_vectors: tuple[str, ...] = ()
    merged_from: tuple[str, ...] = ()

    @property
    def all_ids(self) -> set[str]:
        return {self.identifier, *self.aliases}


@dataclass
class VulnLookupResult:
    by_ref: dict[str, list[Advisory]]
    source: str
    stats: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def partial(self) -> bool:
        return bool(self.warnings)


class VulnProvider(Protocol):
    name: str

    def lookup(self, packages: list[PackageQuery]) -> VulnLookupResult:
        """Look up known vulnerabilities. Raises AppError(VULN_SOURCE_*) when the source
        cannot be used at all. Partial results carry warnings instead."""
        ...


def _primary_order(adv: Advisory) -> tuple[int, int, str]:
    # Prefer advisories that have a computed CVSS score, then GHSA ids (curated), then CVE.
    prefix_rank = (
        0 if adv.identifier.startswith("GHSA-") else (1 if adv.identifier.startswith("CVE-") else 2)
    )
    return (0 if adv.cvss_score is not None else 1, prefix_rank, adv.identifier)


def merge_advisories(advisories: list[Advisory]) -> list[Advisory]:
    """Collapse records that describe the same vulnerability (linked through id/aliases).

    OSV often returns the same issue under several ids (GHSA-..., PYSEC-..., CVE-...).
    Counting each one separately would inflate vulnerable counts, so they are merged into
    one advisory. The best-scored record becomes the primary, and the other ids are kept
    as aliases. If the records disagree on the CVSS vector, the alternatives are kept.
    """
    parent: dict[int, int] = {}

    def find(i: int) -> int:
        while parent.setdefault(i, i) != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, adv in enumerate(advisories):
        find(i)
        for ident in adv.all_ids:
            if ident in owner:
                parent[find(i)] = find(owner[ident])
            else:
                owner[ident] = i

    groups: dict[int, list[Advisory]] = {}
    for i, adv in enumerate(advisories):
        groups.setdefault(find(i), []).append(adv)

    merged: list[Advisory] = []
    for members in groups.values():
        members.sort(key=_primary_order)
        primary = members[0]
        if len(members) == 1:
            merged.append(primary)
            continue
        ids: set[str] = set()
        vectors: list[str] = []
        fixed: list[str] = list(primary.fixed_versions)
        refs: list[str] = list(primary.references)
        cwes: list[str] = list(primary.cwe_ids)
        best_label = primary.severity
        for m in members:
            ids |= m.all_ids
            if m.cvss_vector and m.cvss_vector != primary.cvss_vector:
                vectors.append(m.cvss_vector)
            vectors.extend(v for v in m.other_vectors if v != primary.cvss_vector)
            fixed.extend(m.fixed_versions)
            refs.extend(m.references)
            cwes.extend(m.cwe_ids)
            if primary.cvss_score is None and severity_rank(m.severity) > severity_rank(best_label):
                best_label = m.severity
        merged.append(
            replace(
                primary,
                aliases=tuple(sorted(ids - {primary.identifier})),
                severity=best_label,
                severity_source=primary.severity_source
                if best_label == primary.severity
                else "advisory",
                other_vectors=tuple(dict.fromkeys(vectors)),
                fixed_versions=tuple(dict.fromkeys(fixed)),
                references=tuple(dict.fromkeys(refs))[:15],
                cwe_ids=tuple(dict.fromkeys(cwes)),
                merged_from=tuple(m.identifier for m in members),
            )
        )
    merged.sort(key=lambda a: (-(a.cvss_score or -1), a.identifier))
    return merged

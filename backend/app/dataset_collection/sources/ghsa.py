"""GitHub Advisory Database adapter (global advisories, CC-BY-4.0).

- `reviewed` advisories give known-vulnerable package versions (established ground truth).
- `malware` advisories give confirmed-malicious package names. They are kept as metadata only;
  nothing they name is ever downloaded or scanned.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from app.dataset_collection.sources.base import MetadataClient, SourceError

ADVISORIES_URL = "https://api.github.com/advisories"
PAGE_SIZE = 100
WINDOW_DAYS = 30


@dataclass(frozen=True)
class AffectedPackage:
    ecosystem: str
    name: str
    vulnerable_range: str | None
    first_patched: str | None


@dataclass(frozen=True)
class Advisory:
    ghsa_id: str
    cve_id: str | None
    type: str  # reviewed | malware | unreviewed
    summary: str
    published_at: str | None
    source_code_location: str | None
    html_url: str
    cvss_v3: float | None
    affected: tuple[AffectedPackage, ...]
    raw: dict[str, Any]  # the subset used for labels; hashed into source_record_sha256


def parse_advisory(doc: Any) -> Advisory | None:
    """Normalize one advisory, or None when it is withdrawn or malformed."""
    if not isinstance(doc, dict) or not isinstance(doc.get("ghsa_id"), str):
        return None
    if doc.get("withdrawn_at"):
        return None
    affected = []
    for vuln in doc.get("vulnerabilities") or []:
        pkg = vuln.get("package") if isinstance(vuln, dict) else None
        if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
            continue
        affected.append(
            AffectedPackage(
                ecosystem=str(pkg.get("ecosystem") or ""),
                name=pkg["name"],
                vulnerable_range=vuln.get("vulnerable_version_range"),
                first_patched=vuln.get("first_patched_version"),
            )
        )
    severities = doc.get("cvss_severities") if isinstance(doc.get("cvss_severities"), dict) else {}
    v3 = severities.get("cvss_v3") if isinstance(severities.get("cvss_v3"), dict) else {}
    score = v3.get("score")
    raw = {
        "ghsa_id": doc["ghsa_id"],
        "cve_id": doc.get("cve_id"),
        "type": doc.get("type"),
        "published_at": doc.get("published_at"),
        "source_code_location": doc.get("source_code_location"),
        "vulnerabilities": [a.__dict__ for a in affected],
    }
    return Advisory(
        ghsa_id=doc["ghsa_id"],
        cve_id=doc.get("cve_id") if isinstance(doc.get("cve_id"), str) else None,
        type=str(doc.get("type") or ""),
        summary=str(doc.get("summary") or "")[:300],
        published_at=doc.get("published_at"),
        source_code_location=doc.get("source_code_location") or None,
        html_url=str(doc.get("html_url") or f"https://github.com/advisories/{doc['ghsa_id']}"),
        cvss_v3=float(score) if isinstance(score, int | float) and score > 0 else None,
        affected=tuple(affected),
        raw=raw,
    )


def _page(client: MetadataClient, params: dict[str, str]) -> list[Advisory]:
    data = client.get(ADVISORIES_URL, params={**params, "per_page": str(PAGE_SIZE)})
    if not isinstance(data, list):
        raise SourceError("GHSA returned an unexpected response")
    return [a for a in (parse_advisory(d) for d in data) if a is not None]


def iter_advisories(
    client: MetadataClient,
    *,
    advisory_type: str,
    ecosystem: str,
    end: date,
    max_windows: int,
) -> Iterator[Advisory]:
    """Advisories published in 30-day windows going back from `end`, newest window first.

    One page per window keeps runs reproducible from the recorded parameters without cursors.
    """
    for i in range(max_windows):
        window_end = end - timedelta(days=i * WINDOW_DAYS)
        window_start = window_end - timedelta(days=WINDOW_DAYS - 1)
        params = {
            "type": advisory_type,
            "ecosystem": ecosystem,
            "published": f"{window_start.isoformat()}..{window_end.isoformat()}",
            "sort": "published",
            "direction": "desc",
        }
        yield from _page(client, params)


def advisories_affecting(client: MetadataClient, ecosystem: str, package: str) -> list[Advisory]:
    """Reviewed advisories that name this package (any version)."""
    return _page(client, {"type": "reviewed", "ecosystem": ecosystem, "affects": package})

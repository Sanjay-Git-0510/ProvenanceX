"""OSV (https://osv.dev) adapter: batch package lookup plus per-vulnerability details.

Flow:
1. POST /v1/querybatch with up to BATCH_SIZE purls, which returns vuln ids per package
2. GET /v1/vulns/{id} for each unique id (capped), which returns the full record
3. normalize the records into Advisory, then merge aliases per package
"""

import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from app.core.errors import AppError, ErrorCode
from app.scanners.vulns.base import Advisory, PackageQuery, VulnLookupResult, merge_advisories
from app.scanners.vulns.cvss import (
    cvss3_base_score,
    normalize_advisory_severity,
    severity_from_score,
)
from app.scanners.vulns.http import HttpError, JsonHttpClient

logger = logging.getLogger(__name__)

BATCH_SIZE = 1000  # OSV querybatch limit
_VULN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_REFERENCES = 10
_MAX_SUMMARY = 500


def normalize_query_purl(purl: str | None, version: str | None) -> str | None:
    """Strip qualifiers/subpath (Syft adds ?package-id=...). Requires a version."""
    if not purl or not version:
        return None
    base = purl.split("#", 1)[0].split("?", 1)[0]
    if "@" not in base.rsplit("/", 1)[-1]:
        return None
    return base


def _vectors(doc: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for entry in doc.get("severity") or []:
        if isinstance(entry, dict) and isinstance(entry.get("score"), str):
            out.append((str(entry.get("type", "")), entry["score"][:255]))
    return out


def _ranges(doc: dict[str, Any]) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...]]:
    ranges: list[dict[str, Any]] = []
    fixed: list[str] = []
    for affected in (doc.get("affected") or [])[:20]:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") if isinstance(affected.get("package"), dict) else {}
        for rng in (affected.get("ranges") or [])[:20]:
            if not isinstance(rng, dict):
                continue
            events = [e for e in (rng.get("events") or [])[:50] if isinstance(e, dict)]
            ranges.append(
                {
                    "package": pkg.get("name"),
                    "ecosystem": pkg.get("ecosystem"),
                    "type": rng.get("type"),
                    "events": events,
                }
            )
            fixed.extend(str(e["fixed"]) for e in events if "fixed" in e)
    return tuple(ranges), tuple(dict.fromkeys(fixed))


def normalize_osv(doc: dict[str, Any], source: str) -> Advisory:
    """Turn one OSV vulnerability record into an Advisory."""
    ident = str(doc.get("id", ""))[:128]
    aliases = tuple(str(a)[:128] for a in (doc.get("aliases") or [])[:50] if a and a != ident)

    score = vector = version = None
    other_vectors: list[str] = []
    for vtype, vec in _vectors(doc):
        if vtype == "CVSS_V3" and score is None:
            try:
                parsed = cvss3_base_score(vec)
            except ValueError:
                logger.info("Ignoring malformed CVSS vector on %s: %r", ident, vec[:80])
                other_vectors.append(vec)
                continue
            score, vector, version = parsed.base_score, parsed.vector, parsed.version
        else:
            other_vectors.append(vec)

    db_specific = (
        doc.get("database_specific") if isinstance(doc.get("database_specific"), dict) else {}
    )
    if score is not None:
        severity, severity_source = severity_from_score(score), "cvss_v3"
    elif (label := normalize_advisory_severity(db_specific.get("severity"))) is not None:
        severity, severity_source = label, "advisory"
    else:
        severity, severity_source = "UNKNOWN", None
    if vector is None and other_vectors:
        # Keep the v4/v2 vector for display even though it is not scored here.
        vector = other_vectors.pop(0)
        version = vector.split("/")[0].removeprefix("CVSS:") if vector.startswith("CVSS:") else None

    ranges, fixed = _ranges(doc)
    refs = tuple(
        str(r["url"])[:2048]
        for r in (doc.get("references") or [])[:_MAX_REFERENCES]
        if isinstance(r, dict) and r.get("url")
    )
    summary = doc.get("summary") or (doc.get("details") or "")[:_MAX_SUMMARY] or None
    cwes = db_specific.get("cwe_ids") if isinstance(db_specific.get("cwe_ids"), list) else []
    return Advisory(
        identifier=ident,
        aliases=aliases,
        summary=str(summary)[:_MAX_SUMMARY] if summary else None,
        severity=severity,
        severity_source=severity_source,
        cvss_score=score,
        cvss_vector=vector,
        cvss_version=version,
        cvss_source=source if score is not None else None,
        source=source,
        fixed_versions=fixed,
        affected_ranges=ranges,
        references=refs,
        cwe_ids=tuple(str(c)[:32] for c in cwes[:10]),
        published=doc.get("published"),
        modified=doc.get("modified"),
        other_vectors=tuple(other_vectors),
    )


def _source_error(exc: HttpError, what: str) -> AppError:
    unavailable = exc.kind in {"timeout", "network"} or exc.status in {429, 502, 503, 504}
    return AppError(
        ErrorCode.VULN_SOURCE_UNAVAILABLE if unavailable else ErrorCode.VULN_SOURCE_ERROR,
        f"OSV {what} failed: {exc}",
        503 if unavailable else 502,
        {"kind": exc.kind, "status": exc.status},
    )


class OsvProvider:
    name = "osv"

    def __init__(
        self,
        base_url: str,
        client_factory: Callable[[], JsonHttpClient],
        max_detail_lookups: int,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client_factory = client_factory
        self.max_detail_lookups = max_detail_lookups

    def _batch(
        self, client: JsonHttpClient, purls: list[str]
    ) -> tuple[dict[str, list[str]], list[str]]:
        """Return (vuln ids per purl, purls whose results OSV paginated/truncated)."""
        ids_by_purl: dict[str, list[str]] = {}
        paged: list[str] = []
        for start in range(0, len(purls), BATCH_SIZE):
            chunk = purls[start : start + BATCH_SIZE]
            payload = {"queries": [{"package": {"purl": p}} for p in chunk]}
            try:
                body = client.post_json(f"{self.base_url}/v1/querybatch", payload)
            except HttpError as exc:
                raise _source_error(exc, "querybatch") from exc
            results = body.get("results") if isinstance(body, dict) else None
            if not isinstance(results, list) or len(results) != len(chunk):
                raise AppError(
                    ErrorCode.VULN_SOURCE_ERROR, "OSV querybatch returned an unexpected shape", 502
                )
            for purl, result in zip(chunk, results, strict=True):
                vulns = result.get("vulns") if isinstance(result, dict) else None
                ids = [
                    str(v["id"])
                    for v in (vulns or [])
                    if isinstance(v, dict) and isinstance(v.get("id"), str)
                ]
                ids_by_purl[purl] = ids
                if isinstance(result, dict) and result.get("next_page_token"):
                    paged.append(purl)
        return ids_by_purl, paged

    def lookup(self, packages: list[PackageQuery]) -> VulnLookupResult:
        result = VulnLookupResult(by_ref={}, source="osv")
        purls = list(dict.fromkeys(p.purl for p in packages))
        stats = {"packages_queried": len(purls), "vuln_ids": 0, "details_fetched": 0}
        if not purls:
            result.stats = stats
            return result

        with self.client_factory() as client:
            ids_by_purl, paged = self._batch(client, purls)
            if paged:
                result.warnings.append(
                    f"OSV truncated results for {len(paged)} package(s); "
                    "some advisories may be missing"
                )
            unique_ids = list(dict.fromkeys(i for ids in ids_by_purl.values() for i in ids))
            stats["vuln_ids"] = len(unique_ids)
            if len(unique_ids) > self.max_detail_lookups:
                result.warnings.append(
                    f"{len(unique_ids)} advisories found; details fetched for the first "
                    f"{self.max_detail_lookups} only (OSV_MAX_DETAIL_LOOKUPS)"
                )
            details: dict[str, Advisory] = {}
            for vuln_id in unique_ids[: self.max_detail_lookups]:
                if not _VULN_ID_RE.match(vuln_id):
                    result.warnings.append(f"Skipped malformed advisory id {vuln_id[:40]!r}")
                    continue
                try:
                    doc = client.get_json(f"{self.base_url}/v1/vulns/{quote(vuln_id, safe='')}")
                except HttpError as exc:
                    if exc.kind in {"timeout", "network"} and not details:
                        raise _source_error(exc, "vulnerability detail") from exc
                    result.warnings.append(f"Could not fetch details for {vuln_id}: {exc.kind}")
                    continue
                if not isinstance(doc, dict) or doc.get("id") != vuln_id:
                    result.warnings.append(f"Unexpected detail record for {vuln_id}")
                    continue
                details[vuln_id] = normalize_osv(doc, source="osv")
            stats["details_fetched"] = len(details)

        for pkg in packages:
            advisories = [details[i] for i in ids_by_purl.get(pkg.purl, []) if i in details]
            if advisories:
                result.by_ref[pkg.ref] = merge_advisories(advisories)
        result.stats = stats
        return result

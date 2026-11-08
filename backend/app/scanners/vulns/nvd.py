"""NVD CVE API 2.0 adapter, used only to enrich advisories that have no CVSS score.

OSV is the primary package-to-vulnerability source. NVD has no reliable purl search,
so it is queried by CVE id only, for advisories where OSV gave no scorable CVSS v3
vector (for example v4-only records). Rate limits follow NVD guidance: about 6s between
requests without an API key and about 0.6s with one. The number of lookups per scan is
capped. The API key goes in the `apiKey` header and is never logged.
"""

import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from app.scanners.vulns.base import Advisory
from app.scanners.vulns.cvss import normalize_advisory_severity, severity_from_score
from app.scanners.vulns.http import HttpError, JsonHttpClient

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,12}$")
INTERVAL_NO_KEY_SECONDS = 6.0
INTERVAL_WITH_KEY_SECONDS = 0.6
# Preference order: newest CVSS version first, then the NVD "Primary" score over "Secondary".
_METRIC_KEYS = (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV40", "4.0"))


@dataclass(frozen=True)
class NvdCvss:
    cve_id: str
    score: float
    vector: str
    version: str
    severity: str


def parse_nvd_cvss(body: Any, cve_id: str) -> NvdCvss | None:
    """Extract the preferred CVSS metric for `cve_id` from an NVD CVE API 2.0 response."""
    if not isinstance(body, dict):
        return None
    for item in body.get("vulnerabilities") or []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or cve.get("id") != cve_id:
            continue
        metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
        for key, version in _METRIC_KEYS:
            entries = [m for m in metrics.get(key) or [] if isinstance(m, dict)]
            entries.sort(key=lambda m: 0 if m.get("type") == "Primary" else 1)
            for entry in entries:
                data = entry.get("cvssData") if isinstance(entry.get("cvssData"), dict) else {}
                score, vector = data.get("baseScore"), data.get("vectorString")
                if isinstance(score, int | float) and 0 <= score <= 10 and isinstance(vector, str):
                    label = normalize_advisory_severity(data.get("baseSeverity"))
                    return NvdCvss(
                        cve_id=cve_id,
                        score=float(score),
                        vector=vector[:255],
                        version=version,
                        severity=label or severity_from_score(float(score)),
                    )
    return None


class NvdEnricher:
    name = "nvd"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        client_factory: Callable[[], JsonHttpClient],
        max_lookups: int,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.base_url = base_url
        self._api_key = api_key
        self.client_factory = client_factory
        self.max_lookups = max_lookups
        self.interval = INTERVAL_WITH_KEY_SECONDS if api_key else INTERVAL_NO_KEY_SECONDS
        self.sleep = sleep
        self.clock = clock

    @staticmethod
    def _cve_for(adv: Advisory) -> str | None:
        for ident in (adv.identifier, *adv.aliases):
            if _CVE_RE.match(ident):
                return ident
        return None

    def enrich(
        self, by_ref: dict[str, list[Advisory]]
    ) -> tuple[dict[str, list[Advisory]], dict[str, int], list[str]]:
        """Fill in CVSS from NVD for unscored advisories. Returns (advisories, stats, warnings)."""
        wanted = list(
            dict.fromkeys(
                cve
                for advs in by_ref.values()
                for adv in advs
                if adv.cvss_score is None and (cve := self._cve_for(adv))
            )
        )
        stats = {"nvd_candidates": len(wanted), "nvd_lookups": 0, "nvd_enriched": 0}
        warnings: list[str] = []
        if not wanted or self.max_lookups == 0:
            if wanted:
                warnings.append("NVD enrichment skipped: NVD_MAX_LOOKUPS is 0")
            return by_ref, stats, warnings
        if len(wanted) > self.max_lookups:
            warnings.append(
                f"NVD enrichment limited to {self.max_lookups} of {len(wanted)} CVEs "
                "(NVD_MAX_LOOKUPS)"
            )

        found: dict[str, NvdCvss] = {}
        headers = {"apiKey": self._api_key} if self._api_key else None
        last_call: float | None = None
        with self.client_factory() as client:
            for cve_id in wanted[: self.max_lookups]:
                if last_call is not None:
                    wait = self.interval - (self.clock() - last_call)
                    if wait > 0:
                        self.sleep(wait)
                last_call = self.clock()
                stats["nvd_lookups"] += 1
                try:
                    body = client.get_json(self.base_url, params={"cveId": cve_id}, headers=headers)
                except HttpError as exc:
                    warnings.append(f"NVD lookup failed for {cve_id}: {exc.kind}")
                    if exc.kind in {"timeout", "network"} or exc.status in {403, 429}:
                        warnings.append("NVD enrichment stopped early")
                        break
                    continue
                parsed = parse_nvd_cvss(body, cve_id)
                if parsed:
                    found[cve_id] = parsed

        out: dict[str, list[Advisory]] = {}
        for ref, advs in by_ref.items():
            updated: list[Advisory] = []
            for adv in advs:
                cve = self._cve_for(adv) if adv.cvss_score is None else None
                nvd = found.get(cve) if cve else None
                if nvd:
                    stats["nvd_enriched"] += 1
                    extra = (adv.cvss_vector,) if adv.cvss_vector else ()
                    adv = replace(
                        adv,
                        cvss_score=nvd.score,
                        cvss_vector=nvd.vector,
                        cvss_version=nvd.version,
                        cvss_source="nvd",
                        severity=nvd.severity,
                        severity_source="nvd",
                        other_vectors=tuple(dict.fromkeys((*extra, *adv.other_vectors))),
                    )
                updated.append(adv)
            out[ref] = updated
        return out, stats, warnings

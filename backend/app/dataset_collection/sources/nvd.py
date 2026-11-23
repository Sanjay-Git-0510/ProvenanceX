"""NVD adapter: confirms that a CVE named by an advisory exists in NVD, and its status.

Used only to corroborate a label, never to create one. Calls are paced for the public rate
limit (5 requests per 30 seconds without a key) and capped by the collector.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass

from app.dataset_collection.sources.base import MetadataClient, SourceError

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PUBLIC_INTERVAL_SECONDS = 6.5


@dataclass(frozen=True)
class NvdStatus:
    cve_id: str
    found: bool
    vuln_status: str | None
    published: str | None


class NvdLookup:
    def __init__(
        self,
        client: MetadataClient,
        max_lookups: int,
        sleep: Callable[[float], None] = time.sleep,
        interval: float = PUBLIC_INTERVAL_SECONDS,
    ) -> None:
        self.client = client
        self.remaining = max_lookups
        self.sleep = sleep
        self.interval = interval
        self._cache: dict[str, NvdStatus] = {}
        self._first = True

    def status(self, cve_id: str) -> NvdStatus | None:
        """The NVD record status, or None when the lookup budget is spent."""
        if cve_id in self._cache:
            return self._cache[cve_id]
        if self.remaining <= 0:
            return None
        if not self._first:
            self.sleep(self.interval)
        self._first = False
        self.remaining -= 1
        data = self.client.get(NVD_URL, params={"cveId": cve_id})
        if not isinstance(data, dict):
            raise SourceError("NVD returned an unexpected response")
        items = data.get("vulnerabilities") or []
        cve = items[0].get("cve") if items and isinstance(items[0], dict) else None
        if not isinstance(cve, dict):
            result = NvdStatus(cve_id, False, None, None)
        else:
            result = NvdStatus(cve_id, True, cve.get("vulnStatus"), cve.get("published"))
        self._cache[cve_id] = result
        return result

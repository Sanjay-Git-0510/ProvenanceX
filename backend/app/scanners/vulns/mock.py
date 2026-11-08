"""Mock vulnerability provider: serves recorded OSV records, tagged source="mock".

The records are real public OSV advisories, recorded for the benign fixture packages
(see app/scanners/mock_data/README.md). Serving them is not a live lookup, so every
result is labeled mock. Packages missing from the recording return no advisories, and
the stats say how many packages were not covered.
"""

import json
from pathlib import Path

from app.scanners.vulns.base import PackageQuery, VulnLookupResult, merge_advisories
from app.scanners.vulns.osv import normalize_osv

MOCK_OSV_PATH = Path(__file__).resolve().parent.parent / "mock_data" / "osv_recorded.json"


class MockVulnProvider:
    name = "mock"

    def __init__(self, fixture_path: Path = MOCK_OSV_PATH) -> None:
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.index: dict[str, list[str]] = data["index"]
        self.vulns: dict[str, dict] = data["vulns"]

    def lookup(self, packages: list[PackageQuery]) -> VulnLookupResult:
        result = VulnLookupResult(by_ref={}, source="mock")
        not_recorded = 0
        for pkg in packages:
            if pkg.purl not in self.index:
                not_recorded += 1
                continue
            advisories = [
                normalize_osv(self.vulns[i], source="mock")
                for i in self.index[pkg.purl]
                if i in self.vulns
            ]
            if advisories:
                result.by_ref[pkg.ref] = merge_advisories(advisories)
        result.stats = {
            "packages_queried": len({p.purl for p in packages}),
            "packages_not_in_recording": not_recorded,
        }
        return result

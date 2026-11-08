"""Live OSV/NVD queries. Run with PROVENANCEX_NETWORK_TESTS=1."""

import pytest

from app.core.config import Settings
from app.pipeline.providers import build_providers
from app.scanners.vulns.base import PackageQuery

pytestmark = pytest.mark.network


def test_live_osv_known_advisory_for_old_requests():
    providers = build_providers(Settings(_env_file=None, nvd_enabled=False))
    q = PackageQuery("r", "pkg:pypi/requests@2.32.3", "requests", "2.32.3", "pypi")
    result = providers.vulns.lookup([q])
    ids = {i for a in result.by_ref["r"] for i in a.all_ids}
    assert "CVE-2024-47081" in ids  # fixed in requests 2.32.4
    assert all(a.source == "osv" for a in result.by_ref["r"])


def test_live_nvd_enrichment_single_cve():
    from app.scanners.vulns.base import Advisory

    providers = build_providers(Settings(_env_file=None, nvd_max_lookups=1))
    assert providers.nvd is not None
    adv = Advisory(
        "GHSA-x", ("CVE-2024-47081",), None, "UNKNOWN", None, None, None, None, None, "osv"
    )
    out, stats, _ = providers.nvd.enrich({"r": [adv]})
    assert stats["nvd_lookups"] == 1
    assert out["r"][0].cvss_score == 5.3 and out["r"][0].cvss_source == "nvd"

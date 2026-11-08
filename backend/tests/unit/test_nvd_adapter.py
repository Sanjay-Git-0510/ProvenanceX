import json

import httpx

from app.scanners.vulns.base import Advisory
from app.scanners.vulns.http import JsonHttpClient
from app.scanners.vulns.nvd import NvdEnricher, parse_nvd_cvss
from tests.conftest import FIXTURES

NVD_DOC = json.loads((FIXTURES / "vulns" / "nvd_CVE-2024-47081.json").read_text())


def _adv(ident="GHSA-x", aliases=("CVE-2024-47081",), score=None):
    return Advisory(ident, tuple(aliases), "s", "UNKNOWN", None, score, None, None, None, "osv")


def _enricher(handler, api_key="", max_lookups=10, sleeps=None):
    clock = iter(range(0, 10_000)).__next__

    def factory():
        return JsonHttpClient(
            timeout_seconds=1,
            max_retries=0,
            max_response_bytes=10**6,
            user_agent="t",
            transport=httpx.MockTransport(handler),
            sleep=lambda _s: None,
        )

    return NvdEnricher(
        "https://nvd.test/cves",
        api_key,
        factory,
        max_lookups,
        sleep=(sleeps.append if sleeps is not None else lambda _s: None),
        clock=lambda: float(clock()),
    )


def test_parse_recorded_nvd_record():
    parsed = parse_nvd_cvss(NVD_DOC, "CVE-2024-47081")
    assert parsed.score == 5.3 and parsed.version == "3.1" and parsed.severity == "MEDIUM"
    assert parsed.vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"


def test_parse_wrong_id_or_garbage():
    assert parse_nvd_cvss(NVD_DOC, "CVE-2000-0001") is None
    assert parse_nvd_cvss([], "CVE-2024-47081") is None
    assert (
        parse_nvd_cvss({"vulnerabilities": [{"cve": {"id": "CVE-1", "metrics": "x"}}]}, "CVE-1")
        is None
    )


def test_enrich_fills_unscored_and_sends_key_header():
    seen = []

    def handler(request):
        seen.append((request.url.params.get("cveId"), request.headers.get("apiKey")))
        return httpx.Response(200, json=NVD_DOC)

    by_ref = {"r": [_adv(), _adv("GHSA-scored", score=9.0)]}
    out, stats, warnings = _enricher(handler, api_key="k123").enrich(by_ref)
    enriched, untouched = out["r"]
    assert enriched.cvss_score == 5.3 and enriched.cvss_source == "nvd"
    assert enriched.severity == "MEDIUM" and enriched.severity_source == "nvd"
    assert untouched.cvss_score == 9.0  # already scored: no lookup
    assert seen == [("CVE-2024-47081", "k123")]
    assert stats == {"nvd_candidates": 1, "nvd_lookups": 1, "nvd_enriched": 1}
    assert warnings == []


def test_rate_limit_interval_without_key():
    sleeps = []
    advs = {"r": [_adv("A", ("CVE-2024-0001",)), _adv("B", ("CVE-2024-0002",))]}
    _enricher(lambda r: httpx.Response(200, json={}), sleeps=sleeps).enrich(advs)
    assert sleeps and sleeps[0] > 4  # ~6s spacing without an API key


def test_lookup_cap_and_zero():
    advs = {"r": [_adv(f"A{i}", (f"CVE-2024-000{i}",)) for i in range(3)]}
    _, stats, warnings = _enricher(lambda r: httpx.Response(200, json={}), max_lookups=1).enrich(
        advs
    )
    assert stats["nvd_lookups"] == 1 and any("NVD_MAX_LOOKUPS" in w for w in warnings)
    _, stats, warnings = _enricher(lambda r: httpx.Response(200, json={}), max_lookups=0).enrich(
        advs
    )
    assert stats["nvd_lookups"] == 0 and warnings


def test_no_cve_alias_means_no_lookup():
    calls = []
    _enricher(lambda r: calls.append(1) or httpx.Response(200, json={})).enrich(
        {"r": [_adv("GHSA-x", aliases=("PYSEC-1",))]}
    )
    assert calls == []


def test_rate_limited_stops_early_with_warning():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(403)

    advs = {"r": [_adv(f"A{i}", (f"CVE-2024-000{i}",)) for i in range(3)]}
    out, stats, warnings = _enricher(handler).enrich(advs)
    assert len(calls) == 1 and any("stopped early" in w for w in warnings)
    assert all(a.cvss_score is None for a in out["r"])

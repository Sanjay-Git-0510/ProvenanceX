"""OSV adapter, normalization and alias-merging tests, using recorded real OSV responses."""

import json

import httpx
import pytest

from app.core.errors import AppError, ErrorCode
from app.scanners.vulns.base import Advisory, PackageQuery, merge_advisories
from app.scanners.vulns.http import JsonHttpClient
from app.scanners.vulns.mock import MockVulnProvider
from app.scanners.vulns.osv import OsvProvider, normalize_osv, normalize_query_purl
from tests.conftest import FIXTURES

RECORDED = json.loads((FIXTURES / "vulns" / "osv_recorded.json").read_text())
REQUESTS = PackageQuery("ref-req", "pkg:pypi/requests@2.32.3", "requests", "2.32.3", "pypi")
FLASK = PackageQuery("ref-flask", "pkg:pypi/flask@3.0.3", "flask", "3.0.3", "pypi")
UNKNOWN = PackageQuery("ref-x", "pkg:pypi/nothing-here@0.0.1", "nothing-here", "0.0.1", "pypi")


def recorded_osv_handler(log=None, fail_details=False):
    """Serve querybatch + /v1/vulns/{id} from the recorded fixture."""

    def handler(request: httpx.Request) -> httpx.Response:
        if log is not None:
            log.append((request.method, request.url.path))
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            results = []
            for q in queries:
                ids = RECORDED["index"].get(q["package"]["purl"], [])
                results.append({"vulns": [{"id": i} for i in ids]} if ids else {})
            return httpx.Response(200, json={"results": results})
        if request.url.path.startswith("/v1/vulns/"):
            if fail_details:
                return httpx.Response(500)
            vid = request.url.path.rsplit("/", 1)[1]
            doc = RECORDED["vulns"].get(vid)
            return httpx.Response(200, json=doc) if doc else httpx.Response(404)
        return httpx.Response(404)

    return handler


def _provider(handler, max_details=500, retries=0):
    def factory():
        return JsonHttpClient(
            timeout_seconds=1,
            max_retries=retries,
            max_response_bytes=10**6,
            user_agent="t",
            transport=httpx.MockTransport(handler),
            sleep=lambda _s: None,
        )

    return OsvProvider("https://osv.test", factory, max_details)


# ------------------------------------------------------------------ query purl
@pytest.mark.parametrize(
    ("purl", "version", "expected"),
    [
        ("pkg:pypi/flask@3.0.3?package-id=abc", "3.0.3", "pkg:pypi/flask@3.0.3"),
        ("pkg:npm/%40scope/x@1.0.0#sub/path", "1.0.0", "pkg:npm/%40scope/x@1.0.0"),
        ("pkg:pypi/flask", "3.0.3", None),  # purl lacks version
        ("pkg:pypi/flask@3.0.3", None, None),
        (None, "1", None),
    ],
)
def test_normalize_query_purl(purl, version, expected):
    assert normalize_query_purl(purl, version) == expected


# ------------------------------------------------------------------ normalization
def test_normalize_scores_v3_and_keeps_v4_vector():
    adv = normalize_osv(RECORDED["vulns"]["GHSA-qwcr-r2fm-qrc7"], source="osv")
    assert adv.cvss_score == 7.5 and adv.cvss_version == "3.1"
    assert adv.severity == "HIGH" and adv.severity_source == "cvss_v3"
    assert adv.cvss_source == "osv"
    assert any(v.startswith("CVSS:4.0/") for v in adv.other_vectors)
    assert adv.fixed_versions  # fixed version present in the record
    assert "CVE-2024-45590" in adv.aliases


def test_normalize_v4_only_falls_back_to_advisory_label():
    adv = normalize_osv(RECORDED["vulns"]["GHSA-68rp-wp8r-4726"], source="osv")
    assert adv.cvss_score is None
    assert adv.cvss_vector.startswith("CVSS:4.0/") and adv.cvss_version == "4.0"
    assert adv.severity == "LOW" and adv.severity_source == "advisory"


def test_normalize_no_severity_is_unknown():
    adv = normalize_osv({"id": "OSV-1", "summary": "s"}, source="osv")
    assert adv.severity == "UNKNOWN" and adv.severity_source is None and adv.cvss_score is None


def test_normalize_malformed_vector_ignored():
    adv = normalize_osv(
        {"id": "X-1", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/garbage"}]}, "osv"
    )
    assert adv.cvss_score is None and adv.severity == "UNKNOWN"


# ------------------------------------------------------------------ merging
def test_merge_collapses_aliases_and_prefers_scored_record():
    docs = [RECORDED["vulns"][i] for i in ("GHSA-68rp-wp8r-4726", "PYSEC-2026-2151")]
    merged = merge_advisories([normalize_osv(d, "osv") for d in docs])
    assert len(merged) == 1
    m = merged[0]
    # GHSA has only a v4 vector; the PYSEC record carries a scorable v3 vector.
    assert m.identifier == "PYSEC-2026-2151" and m.cvss_score == 4.3
    assert {"GHSA-68rp-wp8r-4726", "CVE-2026-27205"} <= set(m.aliases)
    assert set(m.merged_from) == {"GHSA-68rp-wp8r-4726", "PYSEC-2026-2151"}


def test_merge_keeps_disagreeing_vectors():
    docs = [RECORDED["vulns"][i] for i in ("GHSA-gc5v-m9x4-r6x2", "PYSEC-2026-2275")]
    (m,) = merge_advisories([normalize_osv(d, "osv") for d in docs])
    assert m.identifier == "GHSA-gc5v-m9x4-r6x2"
    assert m.other_vectors  # PYSEC's different v3 vector preserved


def test_merge_transitive_alias_chain():
    def adv(i, aliases):
        return Advisory(i, tuple(aliases), None, "UNKNOWN", None, None, None, None, None, "osv")

    merged = merge_advisories([adv("A", ["B"]), adv("C", ["B"]), adv("D", [])])
    assert sorted(len(m.merged_from) or 1 for m in merged) == [1, 2]


# ------------------------------------------------------------------ provider
def test_lookup_maps_results_to_refs_and_merges():
    log = []
    result = _provider(recorded_osv_handler(log)).lookup([REQUESTS, FLASK, UNKNOWN])
    assert result.source == "osv" and not result.partial
    req_ids = {a.identifier for a in result.by_ref["ref-req"]}
    assert req_ids == {"GHSA-9hjg-9r4m-mvj7", "GHSA-gc5v-m9x4-r6x2"}  # 4 ids -> 2 issues
    assert len(result.by_ref["ref-flask"]) == 1
    assert "ref-x" not in result.by_ref
    assert result.stats["packages_queried"] == 3
    assert log[0] == ("POST", "/v1/querybatch")
    assert all(a.source == "osv" for advs in result.by_ref.values() for a in advs)


def test_lookup_empty_makes_no_requests():
    log = []
    result = _provider(recorded_osv_handler(log)).lookup([])
    assert result.by_ref == {} and log == []


def test_detail_cap_marks_partial():
    result = _provider(recorded_osv_handler(), max_details=1).lookup([REQUESTS])
    assert result.partial
    assert any("OSV_MAX_DETAIL_LOOKUPS" in w for w in result.warnings)


def test_detail_failures_become_warnings():
    result = _provider(recorded_osv_handler(fail_details=True)).lookup([REQUESTS])
    assert result.by_ref == {} and result.partial


def test_batch_unreachable_is_unavailable():
    def handler(request):
        raise httpx.ConnectError("down", request=request)

    with pytest.raises(AppError) as exc:
        _provider(handler).lookup([REQUESTS])
    assert exc.value.code == ErrorCode.VULN_SOURCE_UNAVAILABLE


def test_batch_bad_shape_is_error():
    with pytest.raises(AppError) as exc:
        _provider(lambda r: httpx.Response(200, json={"results": []})).lookup([REQUESTS])
    assert exc.value.code == ErrorCode.VULN_SOURCE_ERROR


def test_batch_400_is_error():
    with pytest.raises(AppError) as exc:
        _provider(lambda r: httpx.Response(400, json={})).lookup([REQUESTS])
    assert exc.value.code == ErrorCode.VULN_SOURCE_ERROR


def test_paged_results_warn():
    def handler(request):
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [], "next_page_token": "t"}]})
        return httpx.Response(404)

    assert _provider(handler).lookup([REQUESTS]).partial


def test_malformed_vuln_id_skipped():
    def handler(request):
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "../../etc"}]}]})
        raise AssertionError("detail must not be requested for a malformed id")

    result = _provider(handler).lookup([REQUESTS])
    assert result.partial and result.by_ref == {}


# ------------------------------------------------------------------ mock provider
def test_mock_provider_tags_mock_and_counts_unrecorded():
    result = MockVulnProvider().lookup([REQUESTS, UNKNOWN])
    assert result.source == "mock"
    assert all(a.source == "mock" for a in result.by_ref["ref-req"])
    assert result.stats["packages_not_in_recording"] == 1

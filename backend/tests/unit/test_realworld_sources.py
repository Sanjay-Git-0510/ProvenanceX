"""Metadata adapters (GHSA, OSV, NVD, GitHub, Hugging Face) against recorded real responses."""

import httpx
import pytest

from app.dataset_collection.sources import ghsa, github, huggingface, osv
from app.dataset_collection.sources.base import (
    MetadataClient,
    SourceError,
    age_days,
    in_range,
    parse_version,
    version_from_tag,
)
from app.dataset_collection.sources.nvd import NvdLookup
from tests.realworld_helpers import RECORDED, TODAY, router

GH = "GET api.github.com"


def client_for(routes, log=None, **kw):
    return MetadataClient(transport=router(routes, log), max_retries=0, sleep=lambda _: None, **kw)


# --- client safety ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/repos/a/b",
        "https://example.com/x",
        "https://api.github.com:8443/x",
        "https://user:pw@api.github.com/x",
        "https://127.0.0.1/x",
        "file:///etc/passwd",
    ],
)
def test_client_rejects_non_allowlisted_urls(url):
    log = []
    with client_for({}, log) as client, pytest.raises(SourceError):
        client.get(url)
    assert log == []


def test_token_is_sent_only_to_github():
    log = []
    routes = {f"{GH}/orgs/pallets": {"is_verified": True}, "GET huggingface.co/api/x": {}}
    token = "tok-123"  # noqa: S105 - fake value for the header check
    with client_for(routes, log, github_token=token) as client:
        client.get("https://api.github.com/orgs/pallets")
        client.get("https://huggingface.co/api/x")
    assert log[0].headers["authorization"] == f"Bearer {token}"
    assert "authorization" not in log[1].headers
    assert log[1].headers["user-agent"] == "provenancex-dataset-collector/1"


def test_redirects_are_not_followed():
    moved = httpx.Response(301, headers={"location": "https://evil.example/"})
    with client_for({f"{GH}/repos/a/b": moved}) as client, pytest.raises(SourceError, match="301"):
        github.repo_info(client, "a", "b")


def test_oversized_response_is_refused():
    big = httpx.Response(200, content=b"[" + b"0," * 5_000_000 + b"0]")
    with client_for({f"{GH}/repos/a/b/releases": big}) as client, pytest.raises(SourceError):
        github.releases(client, "a", "b")


# --- version helpers ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("version", "rng", "expected"),
    [
        ("11.1", "<= 11.1", True),
        ("11.2", "<= 11.1", False),
        ("1.2.0", ">= 1.0, < 1.4.2", True),
        ("1.4.2", ">= 1.0, < 1.4.2", False),
        ("0.9", ">= 1.0, < 1.4.2", False),
        ("1.0.15", "= 1.0.15", True),
        ("1.0.16", "= 1.0.15", False),
    ],
)
def test_in_range(version, rng, expected):
    assert in_range(parse_version(version), rng) is expected


@pytest.mark.parametrize("rng", ["", "~> 1.0", "< banana", ">= 1.0,, junk"])
def test_unparsable_range_is_none_not_a_guess(rng):
    assert in_range(parse_version("1.0"), rng) is None


@pytest.mark.parametrize(
    ("tag", "package", "expected"),
    [
        ("3.1.3", None, "3.1.3"),
        ("v2.0.1", None, "2.0.1"),
        ("create-vite@5.0.0", "create-vite", "5.0.0"),
        ("flask-3.0.0", "flask", "3.0.0"),
        ("nightly", None, None),
        ("release-candidate", None, None),
    ],
)
def test_version_from_tag(tag, package, expected):
    version = version_from_tag(tag, package)
    assert (str(version) if version else None) == expected


def test_age_days():
    assert age_days("2026-11-01T00:00:00Z", TODAY) == 21
    assert age_days("garbage", TODAY) is None
    assert age_days(None, TODAY) is None


# --- GHSA -------------------------------------------------------------------------------------


def test_parse_reviewed_advisory():
    adv = ghsa.parse_advisory(RECORDED["ghsa_reviewed"])
    assert adv.ghsa_id == "GHSA-53pm-wgxf-c6qf"
    assert adv.type == "reviewed"
    assert adv.source_code_location == "https://github.com/facelessuser/wcmatch"
    assert adv.affected[0].name == "wcmatch"
    assert adv.affected[0].vulnerable_range == "<= 11.1"
    assert adv.cvss_v3 == 5.9


def test_withdrawn_and_malformed_advisories_are_dropped():
    assert ghsa.parse_advisory({**RECORDED["ghsa_reviewed"], "withdrawn_at": "2026-01-01"}) is None
    assert ghsa.parse_advisory({"no": "id"}) is None
    assert ghsa.parse_advisory("text") is None


def test_iter_advisories_uses_dated_windows():
    log = []
    routes = {f"{GH}/advisories": [RECORDED["ghsa_malware"]]}
    with client_for(routes, log) as client:
        out = list(
            ghsa.iter_advisories(
                client, advisory_type="malware", ecosystem="npm", end=TODAY, max_windows=2
            )
        )
    assert len(out) == 2 and out[0].type == "malware"
    assert log[0].url.params["published"] == "2026-10-24..2026-11-22"
    assert log[1].url.params["published"] == "2026-09-24..2026-10-23"
    assert log[0].url.params["type"] == "malware"


# --- OSV / NVD ----------------------------------------------------------------------------------


def test_osv_query_collects_ids_and_aliases():
    log = []
    routes = {"POST api.osv.dev/v1/query": RECORDED["osv_wcmatch_11_1"]}
    with client_for(routes, log) as client:
        result = osv.query_version(client, "pip", "wcmatch", "11.1")
    assert result.ids == ("CVE-2026-132276", "GHSA-53pm-wgxf-c6qf")
    assert result.complete
    assert b'"ecosystem":"PyPI"' in log[0].content.replace(b" ", b"")


def test_osv_empty_result_for_clean_version():
    with client_for({"POST api.osv.dev/v1/query": RECORDED["osv_flask_3_1_3"]}) as client:
        assert osv.query_version(client, "pip", "flask", "3.1.3").ids == ()


def test_osv_unknown_ecosystem():
    with client_for({}) as client, pytest.raises(SourceError):
        osv.query_version(client, "cargo", "x", "1")


def test_osv_paging_stops_and_reports_incomplete():
    routes = {"POST api.osv.dev/v1/query": {"vulns": [], "next_page_token": "t"}}
    with client_for(routes) as client:
        assert osv.query_version(client, "pip", "x", "1").complete is False


def test_nvd_is_paced_cached_and_capped():
    sleeps = []
    with client_for({"GET services.nvd.nist.gov/rest/json/cves/2.0": RECORDED["nvd_cve"]}) as c:
        nvd = NvdLookup(c, max_lookups=2, sleep=sleeps.append, interval=6.5)
        first = nvd.status("CVE-2021-44228")
        assert first.found and first.vuln_status
        assert nvd.status("CVE-2021-44228") is first  # cached, no request
        nvd.status("CVE-2000-0001")
        assert nvd.status("CVE-2000-0002") is None  # budget spent
    assert sleeps == [6.5]


# --- GitHub -----------------------------------------------------------------------------------


def flask_routes():
    return {
        f"{GH}/repos/pallets/flask": RECORDED["github_repo"],
        f"{GH}/orgs/pallets": RECORDED["github_org"],
        f"{GH}/repos/pallets/flask/releases": RECORDED["github_releases"],
        f"{GH}/repos/pallets/flask/tags": RECORDED["github_tags"],
        f"{GH}/repos/pallets/flask/commits/{RECORDED['github_commit']['sha']}": RECORDED[
            "github_commit"
        ],
    }


def test_github_adapters_on_recorded_flask():
    with client_for(flask_routes()) as client:
        info = github.repo_info(client, "pallets", "flask")
        assert (info.owner_type, info.license, info.archived) == (
            "Organization",
            "BSD-3-Clause",
            False,
        )
        assert github.org_verified(client, "pallets") is True
        assert github.releases(client, "pallets", "flask")[0]["tag_name"] == "3.1.3"
        tags = dict(github.tags(client, "pallets", "flask"))
        sha = tags["3.1.3"]
        facts = github.commit_facts(client, "pallets", "flask", sha)
        assert facts.signature_verified is True


@pytest.mark.parametrize("name", ["../x", "a b", "", "x" * 101])
def test_github_rejects_bad_names(name):
    with client_for({}) as client, pytest.raises(SourceError):
        github.repo_info(client, name, "repo")


def test_parse_repo_url():
    assert github.parse_repo_url("https://github.com/a/b") == ("a", "b")
    assert github.parse_repo_url("https://github.com/a/b.git") == ("a", "b")
    assert github.parse_repo_url("https://gitlab.com/a/b") is None
    assert github.parse_repo_url("https://github.com/a/b/tree/main") is None
    assert github.parse_repo_url("") is None


# --- Hugging Face -------------------------------------------------------------------------------


def test_parse_hf_model():
    meta = huggingface.parse_repo(RECORDED["hf_model"], "model")
    assert meta.repo_id == "google-bert/bert-base-uncased"
    assert meta.scans_done is True and meta.files_with_issues == ()
    assert meta.license == "apache-2.0"
    assert not meta.is_adapter
    assert meta.raw["sha"] == meta.sha


def test_hf_adapter_detection_and_base_models():
    doc = {
        **RECORDED["hf_model"],
        "id": "someone/lora-x",
        "tags": ["peft", "base_model:google-bert/bert-base-uncased", "base_model:adapter:x/y"],
    }
    meta = huggingface.parse_repo(doc, "model")
    assert meta.is_adapter
    assert meta.base_models == ("google-bert/bert-base-uncased",)


def test_hf_invalid_ids_rejected():
    assert huggingface.parse_repo({"id": "../etc/passwd"}, "model") is None
    assert not huggingface.valid_repo_id("a/b/c")
    with client_for({}) as client, pytest.raises(SourceError):
        huggingface.repo_meta(client, "model", "../x")


def test_hf_org_verified_and_user_404():
    routes = {"GET huggingface.co/api/organizations/google-bert/overview": RECORDED["hf_org"]}
    with client_for(routes) as client:
        assert huggingface.org_verified(client, "google-bert") is False
        assert huggingface.org_verified(client, "some-user") is None


def test_hf_list_repos_passes_filters():
    log = []
    routes = {"GET huggingface.co/api/models": [{"id": "a/b"}, {"id": "bad id"}]}
    with client_for(routes, log) as client:
        assert huggingface.list_repos(client, "model", author="a", filter_tag="peft") == ["a/b"]
    assert log[0].url.params["filter"] == "peft"
    assert log[0].url.params["author"] == "a"


def test_hf_issue_levels_are_kept():
    doc = {
        **RECORDED["hf_model"],
        "securityRepoStatus": {
            "scansDone": True,
            "filesWithIssues": [{"path": "a.bin", "level": "unsafe"}, {"path": "b"}],
        },
    }
    meta = huggingface.parse_repo(doc, "model")
    assert meta.files_with_issues == (("a.bin", "unsafe"), ("b", "unspecified"))
    assert meta.issue_paths("unsafe") == ["a.bin"]

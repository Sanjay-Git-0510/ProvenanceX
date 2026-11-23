"""Label rules of the collector, using recorded real responses (no network).

Where a test needs a response that was not recorded (for example tags for a repository), the
test builds it inline and says so; those values only drive the rule under test.
"""

import copy

import httpx

from app.dataset_collection import collect
from app.dataset_collection.sources import ghsa
from app.ml.realworld.manifest import GroundTruth, RealLabel
from tests.realworld_helpers import RECORDED, make_ctx

GH = "GET api.github.com"
SHA = RECORDED["github_commit"]["sha"]
FLASK = collect.SoftwareSeed(repo="pallets/flask", ecosystem="pip", package="flask")


def flask_routes(**overrides):
    routes = {
        f"{GH}/repos/pallets/flask": RECORDED["github_repo"],
        f"{GH}/orgs/pallets": RECORDED["github_org"],
        f"{GH}/repos/pallets/flask/releases": RECORDED["github_releases"],
        f"{GH}/repos/pallets/flask/tags": RECORDED["github_tags"],
        f"{GH}/repos/pallets/flask/commits/{SHA}": RECORDED["github_commit"],
        f"{GH}/advisories": [],
        "POST api.osv.dev/v1/query": RECORDED["osv_flask_3_1_3"],
    }
    routes.update(overrides)
    return routes


def test_seed_meeting_all_criteria_is_benign_and_scannable():
    rec = collect.label_software_seed(make_ctx(flask_routes()), FLASK)
    assert rec.label == RealLabel.BENIGN
    assert rec.ground_truth_status == GroundTruth.CRITERIA_BASED
    assert rec.revision == SHA and rec.scan_eligible
    assert rec.sha256 is None and rec.sha256_status == "pending_scan"
    assert rec.family_id == "github:pallets/flask"
    assert rec.license == "BSD-3-Clause"
    assert "verified organization" in rec.label_justification
    assert rec.evidence["release_age_days"] >= 180


def test_seed_with_osv_advisory_is_known_vulnerable():
    osv = {"vulns": [{"id": "GHSA-test-0000-0000", "aliases": ["CVE-2026-0001"]}]}
    routes = flask_routes(**{"POST api.osv.dev/v1/query": osv})
    rec = collect.label_software_seed(make_ctx(routes), FLASK)
    assert rec.label == RealLabel.KNOWN_VULNERABLE
    assert rec.ground_truth_status == GroundTruth.ESTABLISHED
    assert rec.data_source == "osv"


def test_no_verified_publisher_and_unsigned_commit_is_unknown_not_benign():
    org = {"is_verified": False}
    commit = copy.deepcopy(RECORDED["github_commit"])
    commit["commit"]["verification"] = {"verified": False, "reason": "unsigned"}
    routes = flask_routes(
        **{f"{GH}/orgs/pallets": org, f"{GH}/repos/pallets/flask/commits/{SHA}": commit}
    )
    rec = collect.label_software_seed(make_ctx(routes), FLASK)
    assert rec.label == RealLabel.UNKNOWN
    assert rec.ground_truth_status == GroundTruth.NONE
    assert not rec.scan_eligible
    assert "not treated as benign" in rec.label_justification


def test_no_old_enough_release_is_unknown():
    releases = [{**r, "published_at": "2026-11-01T00:00:00Z"} for r in RECORDED["github_releases"]]
    routes = flask_routes(**{f"{GH}/repos/pallets/flask/releases": releases})
    rec = collect.label_software_seed(make_ctx(routes), FLASK)
    assert rec.label == RealLabel.UNKNOWN
    assert rec.revision is None


def test_incomplete_osv_result_is_unknown():
    routes = flask_routes(**{"POST api.osv.dev/v1/query": {"vulns": [], "next_page_token": "t"}})
    rec = collect.label_software_seed(make_ctx(routes), FLASK)
    assert rec.label == RealLabel.UNKNOWN


def wcmatch_routes():
    # Tags built inline for the rule under test; the advisory itself is recorded.
    tags = [
        {"name": "11.2", "commit": {"sha": "2" * 40}},
        {"name": "11.1", "commit": {"sha": "1" * 40}},
        {"name": "11.1rc1", "commit": {"sha": "3" * 40}},
        {"name": "10.0", "commit": {"sha": "0" * 40}},
    ]
    repo = {**RECORDED["github_repo"], "name": "wcmatch", "license": {"spdx_id": "MIT"}}
    return {
        f"{GH}/repos/facelessuser/wcmatch/tags": tags,
        f"{GH}/repos/facelessuser/wcmatch": repo,
        "POST api.osv.dev/v1/query": RECORDED["osv_wcmatch_11_1"],
    }


def test_ghsa_reviewed_advisory_picks_highest_vulnerable_tag():
    adv = ghsa.parse_advisory(RECORDED["ghsa_reviewed"])
    rec = collect.label_ghsa_vulnerable(make_ctx(wcmatch_routes()), adv, None)
    assert rec.label == RealLabel.KNOWN_VULNERABLE
    assert rec.revision == "1" * 40  # 11.1, not 11.2 (patched) or the 11.1rc1 prerelease
    assert rec.evidence["osv_corroborated"] is True
    assert rec.scan_eligible
    assert "dependencies may show no advisory" in rec.evidence["label_scope"]


def test_ghsa_advisory_without_github_source_is_skipped():
    doc = {**RECORDED["ghsa_reviewed"], "source_code_location": "https://gitlab.com/a/b"}
    adv = ghsa.parse_advisory(doc)
    assert collect.label_ghsa_vulnerable(make_ctx({}), adv, None) is None


def test_malware_advisory_is_metadata_only():
    adv = ghsa.parse_advisory(RECORDED["ghsa_malware"])
    log = []
    recs = collect.label_ghsa_malware(make_ctx({}, log), adv)
    assert recs and log == []  # no request at all
    for rec in recs:
        assert rec.label == RealLabel.CONFIRMED_MALICIOUS
        assert rec.artifact_type == "package"
        assert not rec.scan_eligible and rec.scan_url is None
        assert rec.family_id.startswith("pkg:npm/")


def hf_routes(model=None, org=None):
    return {
        "GET huggingface.co/api/models/google-bert/bert-base-uncased": model
        or RECORDED["hf_model"],
        "GET huggingface.co/api/organizations/google-bert/overview": org or RECORDED["hf_org"],
    }


def label(routes):
    ctx = make_ctx(routes)
    return collect.label_hf(
        ctx, "model", "google-bert/bert-base-uncased", collect.HfVerifiedCache(ctx)
    )


def test_hf_unverified_publisher_is_unknown():
    rec = label(hf_routes())  # recorded: google-bert isVerified is false
    assert rec.label == RealLabel.UNKNOWN and not rec.scan_eligible


def test_hf_verified_but_too_large_is_benign_not_scannable():
    rec = label(hf_routes(org={"isVerified": True}))
    assert rec.label == RealLabel.BENIGN
    assert not rec.scan_eligible  # recorded usedStorage is far above the 600 MB budget
    assert rec.evidence["fits_scan_budget"] is False


def test_hf_small_verified_repo_is_scannable():
    model = {**RECORDED["hf_model"], "usedStorage": 100 * 1024 * 1024}
    rec = label(hf_routes(model=model, org={"isVerified": True}))
    assert rec.label == RealLabel.BENIGN and rec.scan_eligible
    assert rec.scan_url == "https://huggingface.co/google-bert/bert-base-uncased"


def test_hf_flagged_files_are_suspicious_and_never_scanned():
    model = copy.deepcopy(RECORDED["hf_model"])
    model["securityRepoStatus"] = {
        "scansDone": True,
        "filesWithIssues": [{"path": "x.bin", "level": "unsafe"}],
    }
    rec = label(hf_routes(model=model, org={"isVerified": True}))
    assert rec.label == RealLabel.SUSPICIOUS
    assert rec.ground_truth_status == GroundTruth.THIRD_PARTY_FLAG
    assert not rec.scan_eligible


def test_hf_scan_not_done_is_unknown():
    model = {**RECORDED["hf_model"], "securityRepoStatus": {"scansDone": False}}
    rec = label(hf_routes(model=model, org={"isVerified": True}))
    assert rec.label == RealLabel.UNKNOWN


def test_source_failure_is_recorded_not_labeled():
    seeds = collect.Seeds(
        version=1,
        software=[FLASK],
        huggingface=collect.HfSeeds(global_lora_limit=0),
        ghsa=collect.GhsaSeeds(ecosystems=[]),
        nvd_max_lookups=0,
    )
    ctx = make_ctx({f"{GH}/repos/pallets/flask": httpx.Response(500)})
    assert collect.collect(ctx, seeds) == []
    assert ctx.errors and ctx.errors[0]["identifier"] == "pallets/flask"


def test_hf_caution_or_error_issues_are_unknown_not_suspicious_or_benign():
    # Levels as the Hub reports them (recorded 2026-11-22: README.md 'error',
    # training_args.bin 'caution').
    for level in ("caution", "error"):
        model = copy.deepcopy(RECORDED["hf_model"])
        model["securityRepoStatus"] = {
            "scansDone": True,
            "filesWithIssues": [{"path": "README.md", "level": level}],
        }
        rec = label(hf_routes(model=model, org={"isVerified": True}))
        assert rec.label == RealLabel.UNKNOWN
        assert level in rec.label_justification

"""Provenance/integrity rules (pipeline step 8). Pure functions, no database."""

from uuid import uuid4

import pytest

from app.pipeline.provenance_stage import _lineage_check
from app.provenance.checks import (
    RECORD_FORMAT,
    PriorScan,
    ProvenanceInputs,
    canonical_sha256,
    provenance_document,
    run_provenance_checks,
)

COMMIT_A, COMMIT_B = "a" * 40, "b" * 40
HASH_1, HASH_2 = "1" * 64, "2" * 64
URL = "https://huggingface.co/org/repo"


def inputs(**kw) -> ProvenanceInputs:
    base = {
        "source": "huggingface",
        "source_url": URL,
        "revision_requested": COMMIT_A,
        "resolved_commit": COMMIT_A,
        "artifact_sha256": HASH_1,
        "file_paths": ["config.json"],
        "artifact_type": "model",
    }
    return ProvenanceInputs(**{**base, **kw})


def check(result, name):
    matches = [c for c in result.checks if c.name == name]
    assert len(matches) == 1, f"{name}: {matches}"
    return matches[0]


def prior(commit=COMMIT_A, sha=HASH_1, manifest=None):
    return PriorScan(uuid4(), commit, sha, manifest)


# ------------------------------------------------------------------ source and revision
@pytest.mark.parametrize("source", ["github", "huggingface"])
def test_known_sources(source):
    r = run_provenance_checks(inputs(source=source))
    assert r.source_known is True and check(r, "source_known").status == "pass"


def test_upload_has_unknown_origin_and_no_revision():
    r = run_provenance_checks(
        inputs(source="upload", source_url=None, revision_requested=None, resolved_commit=None)
    )
    c = check(r, "source_known")
    assert r.source_known is False and c.status == "fail"
    assert c.identifier == "PX-PROV-SOURCE-UNKNOWN" and c.severity == "LOW"
    assert check(r, "revision_pinned").status == "unknown"  # not applicable, not a failure
    assert check(r, "resolved_commit").status == "unknown"
    assert r.resolved_commit is None


def test_full_commit_sha_is_pinned():
    r = run_provenance_checks(inputs())
    assert r.revision_pinned is True and check(r, "revision_pinned").status == "pass"
    assert check(r, "resolved_commit").status == "pass"


@pytest.mark.parametrize("revision", [None, "main", "v1.0", "abc1234"])
def test_unpinned_revisions_fail(revision):
    r = run_provenance_checks(inputs(revision_requested=revision))
    c = check(r, "revision_pinned")
    assert r.revision_pinned is False and c.status == "fail"
    assert c.identifier == "PX-PROV-REVISION-UNPINNED"


# ------------------------------------------------------------------ hash consistency
def test_no_prior_scan_is_unknown_never_false():
    r = run_provenance_checks(inputs())
    assert r.hash_changed is None and r.previous_scan_id is None
    assert check(r, "hash_consistency").status == "unknown"
    assert r.failed == [c for c in r.failed if c.name != "hash_consistency"]


def test_upload_is_never_compared_even_with_a_prior():
    r = run_provenance_checks(inputs(source="upload", source_url=None, prior=prior(sha=HASH_2)))
    assert r.hash_changed is None and r.previous_scan_id is None
    assert check(r, "hash_consistency").status == "unknown"


def test_matching_hash_passes():
    p = prior()
    r = run_provenance_checks(inputs(prior=p))
    assert r.hash_changed is False and r.previous_scan_id == p.scan_id
    assert check(r, "hash_consistency").status == "pass"


def test_changed_hash_on_same_commit_is_high_severity_failure():
    r = run_provenance_checks(inputs(prior=prior(sha=HASH_2)))
    c = check(r, "hash_consistency")
    assert r.hash_changed is True and c.status == "fail" and c.severity == "HIGH"
    assert c.identifier == "PX-PROV-HASH-CHANGED-SAME-COMMIT"
    assert c.data["previous_sha256"] == HASH_2


def test_changed_hash_on_new_commit_is_context_not_failure():
    r = run_provenance_checks(inputs(prior=prior(commit=COMMIT_B, sha=HASH_2)))
    assert r.hash_changed is True and check(r, "hash_consistency").status == "info"
    assert "hash_consistency" not in {c.name for c in r.failed}


def test_manifest_change_detected_when_local_hash_is_the_same():
    """A file too large to download changed: only the remote-listing digest differs."""
    r = run_provenance_checks(inputs(manifest_sha256=HASH_1, prior=prior(manifest=HASH_2)))
    assert r.hash_changed is True and check(r, "hash_consistency").status == "fail"


@pytest.mark.parametrize(("now", "before"), [(None, HASH_2), (HASH_1, None)])
def test_missing_manifest_on_either_side_is_not_a_change(now, before):
    r = run_provenance_checks(inputs(manifest_sha256=now, prior=prior(manifest=before)))
    assert r.hash_changed is False


def test_missing_commit_on_both_sides_is_not_same_commit():
    r = run_provenance_checks(inputs(resolved_commit=None, prior=prior(commit=None, sha=HASH_2)))
    assert check(r, "hash_consistency").status == "info"


# ------------------------------------------------------------------ signatures
@pytest.mark.parametrize(
    "path",
    ["model.sig", "a/b.asc", "x.sigstore", "x.sigstore.json", "IMAGE.COSIGN.BUNDLE"],
)
def test_signature_files_detected_but_signed_stays_unverified(path):
    r = run_provenance_checks(inputs(file_paths=[path]))
    assert r.signature_files == [path] and check(r, "signature_files").status == "pass"
    assert r.signed is None  # presence is never reported as a valid signature
    assert "not verified" in check(r, "signature_files").evidence


@pytest.mark.parametrize(
    "path",
    ["a.intoto.jsonl", "x.intoto.json", "b.slsa.json", "c.provenance.json", "d.att"]
    + ["provenance.json", "sub/attestation.json", "attestations.json"],
)
def test_attestation_files_detected(path):
    r = run_provenance_checks(inputs(file_paths=[path]))
    assert r.attestation_files == [path] and r.signature_files == []
    assert check(r, "provenance_attestation").status == "pass"


def test_missing_signatures_and_attestations_fail():
    r = run_provenance_checks(inputs())
    assert check(r, "signature_files").identifier == "PX-PROV-NO-SIGNATURE"
    assert check(r, "provenance_attestation").identifier == "PX-PROV-NO-ATTESTATION"
    assert r.signed is None
    assert any("not verified" in lim for lim in r.limitations)


def test_listed_files_are_capped():
    r = run_provenance_checks(inputs(file_paths=[f"f{i:03}.sig" for i in range(50)]))
    assert len(r.signature_files) == 20


# ------------------------------------------------------------------ Hugging Face integrity
def hf(path="a", **kw):
    base = {"path": path, "downloaded": False, "hash_verified": None, "status": "pending"}
    return {**base, **kw}


GOOD = {"downloaded": True, "hash_verified": True, "status": "downloaded"}


def hf_run(files, **kw):
    return run_provenance_checks(inputs(hf_files=files, hf_source="huggingface", **kw))


def test_verified_downloads_pass():
    r = hf_run([hf("a", **GOOD), hf("b", **GOOD)])
    c = check(r, "download_integrity")
    assert c.status == "pass" and "2" in c.evidence


def test_integrity_mismatch_is_high_severity_failure():
    r = hf_run([hf("a", **GOOD), hf("bad.bin", status="integrity_mismatch", hash_verified=False)])
    c = check(r, "download_integrity")
    assert c.status == "fail" and c.severity == "HIGH"
    assert c.identifier == "PX-PROV-DOWNLOAD-INTEGRITY" and c.data["files"] == ["bad.bin"]


@pytest.mark.parametrize(
    "files",
    [[], [hf("a", status="skipped")], [hf("a", downloaded=True, hash_verified=None)]],
)
def test_no_verified_downloads_is_unknown(files):
    assert check(hf_run(files), "download_integrity").status == "unknown"


def test_rejected_listing_entries_fail():
    r = hf_run([hf("a", **GOOD), hf("../evil", status="rejected")])
    c = check(r, "repository_listing")
    assert c.status == "fail" and c.identifier == "PX-PROV-UNSAFE-LISTING"
    assert c.data["files"] == ["../evil"]


@pytest.mark.parametrize("status", ["skipped", "failed"])
def test_not_downloaded_files_are_unknown_coverage(status):
    r = hf_run([hf("a", **GOOD), hf("big.bin", status=status)])
    c = check(r, "content_coverage")
    assert c.status == "unknown" and c.data["files"] == ["big.bin"]
    assert check(r, "download_integrity").status == "pass"


def test_mock_provider_never_claims_verification():
    r = run_provenance_checks(inputs(hf_files=[hf("a", **GOOD)], hf_source="mock"))
    c = check(r, "download_integrity")
    assert c.status == "unknown" and "Mock" in c.evidence
    assert not [x for x in r.checks if x.name in ("repository_listing", "content_coverage")]


def test_hf_checks_do_not_run_for_other_sources():
    r = run_provenance_checks(inputs(source="github"))
    assert not [c for c in r.checks if c.name == "download_integrity"]


# ------------------------------------------------------------------ lineage
def test_lineage_completeness_is_informational():
    r = run_provenance_checks(inputs(lineage_completeness=0.5))
    c = check(r, "lineage_completeness")
    assert c.status == "info" and c.data == {"value": 0.5} and r.lineage_completeness == 0.5


def test_lineage_completeness_absent_for_software():
    r = run_provenance_checks(inputs(source="github"))
    assert r.lineage_completeness is None
    assert not [c for c in r.checks if c.name == "lineage_completeness"]


def test_lineage_check_consistency_states():
    assert _lineage_check(None) is None
    assert _lineage_check({"suspicious_lineage": []}).status == "pass"
    flag = {"detail": "base model missing"}
    assert _lineage_check({"suspicious_lineage": [flag]}).status == "unknown"
    c = _lineage_check({"suspicious_lineage": [flag], "unexpected_parent_or_base_model": True})
    assert c.status == "fail" and c.identifier == "PX-PROV-LINEAGE-INCONSISTENT"
    assert c.severity == "MEDIUM" and "base model missing" in c.evidence


# ------------------------------------------------------------------ canonical record
def test_document_contains_the_evidence_and_ignores_key_order():
    inp = inputs(prior=prior())
    result = run_provenance_checks(inp)
    scan_id = uuid4()
    doc = provenance_document(scan_id, inp, result)
    assert doc["format"] == RECORD_FORMAT and doc["scan_id"] == str(scan_id)
    assert doc["signed"] is None and doc["previous_scan_id"] == str(result.previous_scan_id)
    assert {c["name"] for c in doc["checks"]} >= {"source_known", "hash_consistency"}
    raw, digest = canonical_sha256(doc)
    reordered = dict(reversed(list(doc.items())))
    assert canonical_sha256(reordered) == (raw, digest)


def test_any_evidence_change_changes_the_record_hash():
    inp = inputs()
    scan_id = uuid4()
    first = provenance_document(scan_id, inp, run_provenance_checks(inp))
    changed = inputs(artifact_sha256=HASH_2)
    second = provenance_document(scan_id, changed, run_provenance_checks(changed))
    assert canonical_sha256(first)[1] != canonical_sha256(second)[1]


def test_checks_never_claim_a_cvss_or_vulnerability():
    r = run_provenance_checks(inputs())
    assert all(
        set(c.to_dict()) == {"name", "status", "evidence", "severity", "identifier", "data"}
        for c in r.checks
    )

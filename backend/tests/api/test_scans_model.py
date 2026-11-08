"""API tests for Phase 3: POST /scans/model through evidence, graph and provenance.

They run on in-memory SQLite with the mock Hugging Face provider. Its output is a
synthetic fixture tagged source="mock", and these tests assert that the label survives
all the way to the API.
"""

import hashlib
import shutil
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.scans import get_scan_providers, get_session_factory
from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode
from app.main import create_app
from app.pipeline.model import hf_manifest_digest
from app.pipeline.providers import ScanProviders
from app.scanners.hf.base import HfFetchResult, HfFile
from app.scanners.sbom.mock import MockSbomProvider
from app.scanners.vulns.mock import MockVulnProvider
from app.security.url_validation import HfRepo
from tests.conftest import FIXTURES, build_zip, zip_dir
from tests.model_helpers import safetensors_bytes

URL = "/api/v1/scans/model"
HF_URL = "https://huggingface.co/org/lora"
COMMIT = "c" * 40


def post_url(client, url=HF_URL, **data):
    resp = client.post(URL, data={"source_url": url, **data})
    assert resp.status_code == 202, resp.text
    return client.get(f"/api/v1/scans/{resp.json()['scan_id']}").json()


def post_zip(client, data: bytes, name="model.zip", **form):
    resp = client.post(URL, data=form, files={"file": (name, data, "application/zip")})
    assert resp.status_code == 202, resp.text
    return client.get(f"/api/v1/scans/{resp.json()['scan_id']}").json()


def get(client, body, suffix, **params):
    return client.get(f"/api/v1/scans/{body['scan_id']}/{suffix}", params=params).json()


def client_with(test_settings, session_factory, hf, vulns=None) -> TestClient:
    providers = ScanProviders(
        sbom=MockSbomProvider(), vulns=vulns or MockVulnProvider(), nvd=None, hf=hf
    )
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    app.dependency_overrides[get_scan_providers] = lambda: providers
    return TestClient(app, raise_server_exceptions=False)


def checks(body) -> dict:
    return {c["name"]: c for c in body["provenance"]["checks"]}


def lora_zip(tmp_path: Path) -> bytes:
    root = tmp_path / "lora"
    shutil.copytree(FIXTURES / "model" / "lora_adapter", root)
    (root / "adapter_model.safetensors").write_bytes(safetensors_bytes())
    return zip_dir(root)


class StubHf:
    """A provider returning a canned, non-mock listing (to test real-source behaviour)."""

    name = "huggingface"

    def __init__(self, files=None, exc=None, commit=COMMIT):
        self.files, self.exc, self.commit, self.calls = files or {}, exc, commit, []

    def fetch(self, repo, revision, dest, limits):
        self.calls.append((repo, revision, limits))
        if self.exc:
            raise self.exc
        listing = []
        for path, data in self.files.items():
            if isinstance(data, HfFile):
                listing.append(data)
                continue
            target = dest / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            listing.append(
                HfFile(
                    path,
                    len(data),
                    "d" * 40,
                    digest,
                    downloaded=True,
                    local_sha256=digest,
                    hash_verified=True,
                    status="downloaded",
                )
            )
        return HfFetchResult("huggingface", repo, self.commit, listing, {"author": "org"})


# ------------------------------------------------------------------ mock provider, HF URL
@pytest.fixture
def mock_scan(scan_client):
    return scan_client, post_url(scan_client, artifact_type="lora")


def test_hf_scan_records_all_stages(mock_scan):
    _, body = mock_scan
    assert body["status"] == "completed", body
    assert body["error"] is None
    assert {k: v["status"] for k, v in body["stages"].items()} == {
        "aibom": "completed",
        "graph": "completed",
        "vulnerabilities": "completed",
        "provenance": "completed",
        "static": "completed",
        "sandbox": "skipped",
    }


def test_hf_artifact_identity(mock_scan):
    _, body = mock_scan
    artifact = body["artifact"]
    assert artifact["artifact_type"] == "lora" and artifact["source"] == "huggingface"
    assert artifact["source_url"] == HF_URL and artifact["name"] == "org/lora"
    assert len(artifact["sha256"]) == 64
    assert artifact["version"] == body["ingest"]["commit_sha"]


def test_mock_is_labeled_at_every_layer(mock_scan):
    client, body = mock_scan
    assert body["stages"]["aibom"]["source"] == "mock"
    assert body["stages"]["graph"]["source"] == "mock"
    assert body["stages"]["provenance"]["source"] == "mock"
    assert body["ingest"]["hf"]["source"] == "mock"
    assert body["provenance"]["is_mock"] is True and body["provenance"]["source"] == "mock"
    graph = get(client, body, "graph")
    assert graph["is_mock"] is True and graph["source"] == "mock"
    findings = get(client, body, "findings")
    assert findings["contains_mock"] is True
    assert findings["items"] and all(i["is_mock"] for i in findings["items"])


def test_mock_provider_never_claims_integrity_verification(mock_scan):
    _, body = mock_scan
    c = checks(body)["download_integrity"]
    assert c["status"] == "unknown" and "Mock" in c["evidence"]


def test_aibom_written_privately_and_hashed(mock_scan, test_settings):
    _, body = mock_scan
    path = test_settings.workspace_root / body["scan_id"] / "aibom.json"
    assert body["bom_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_provenance_record_is_hashed_off_chain(mock_scan, test_settings):
    _, body = mock_scan
    path = test_settings.workspace_root / body["scan_id"] / "provenance.json"
    assert body["provenance"]["record_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_lineage_graph_endpoint(mock_scan):
    client, body = mock_scan
    graph = get(client, body, "graph")
    assert graph["graph_kind"] == "lineage"
    keys = {n["key"]: n for n in graph["nodes"]}
    base = "model:hf-internal-testing/tiny-random-gpt2"
    dataset = "dataset:provenancex-fixtures/synthetic-instructions"
    assert base in keys and dataset in keys and graph["root_key"] in keys
    relations = {(e["source"], e["relation"], e["target"]) for e in graph["edges"]}
    assert (graph["root_key"], "fine_tuned_from", base) in relations
    assert (graph["root_key"], "trained_on", dataset) in relations
    assert {e["relation"] for e in graph["edges"]} >= {"bundled_with", "requires"}
    assert graph["features"]["adapter_present"] is True
    assert graph["features"]["base_model_count"] == 1
    assert graph["features"]["dataset_count"] == 1
    assert 0 <= graph["features"]["lineage_completeness"] <= 1


def test_only_pinned_runtime_deps_are_looked_up(scan_client):
    seen = []
    real = MockVulnProvider()

    class Recording:
        name = "mock"

        def lookup(self, packages):
            seen.extend(packages)
            return real.lookup(packages)

    settings = scan_client.app.dependency_overrides[get_settings]()
    factory = scan_client.app.dependency_overrides[get_session_factory]()
    from app.scanners.hf.mock import MockHfProvider

    client = client_with(settings, factory, MockHfProvider(), Recording())
    assert post_url(client)["status"] == "completed"
    assert [(q.name, q.version) for q in seen] == [("requests", "2.32.3")]


def test_provenance_findings_filter(mock_scan):
    client, body = mock_scan
    items = get(client, body, "findings", category="provenance")["items"]
    identifiers = {i["identifier"] for i in items}
    assert {
        "PX-PROV-REVISION-UNPINNED",
        "PX-PROV-NO-SIGNATURE",
        "PX-PROV-NO-ATTESTATION",
    } <= identifiers
    assert all(i["cvss"] is None or i["cvss"].get("score") is None for i in items)


def test_revision_is_recorded(scan_client):
    sha = "f" * 40
    body = post_url(scan_client, revision=sha)
    assert body["provenance"]["revision_pinned"] is True
    assert "PX-PROV-REVISION-UNPINNED" not in {
        i["identifier"] for i in get(scan_client, body, "findings", category="provenance")["items"]
    }


def test_rescan_compares_with_previous_scan(scan_client):
    first = post_url(scan_client)
    second = post_url(scan_client)
    assert first["provenance"]["hash_changed"] is None
    assert second["provenance"]["hash_changed"] is False
    assert second["provenance"]["previous_scan_id"] == first["scan_id"]
    assert checks(second)["hash_consistency"]["status"] == "pass"


# ------------------------------------------------------------------ artifact types
def test_dataset_url_is_always_a_dataset(scan_client):
    body = post_url(scan_client, "https://huggingface.co/datasets/org/data")
    assert body["artifact"]["artifact_type"] == "dataset"


def test_model_url_defaults_to_model(scan_client):
    assert post_url(scan_client)["artifact"]["artifact_type"] == "model"


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        ("https://huggingface.co/datasets/org/data", "model"),
        ("https://huggingface.co/datasets/org/data", "lora"),
        ("https://huggingface.co/org/repo", "dataset"),
    ],
)
def test_artifact_type_must_match_url(scan_client, url, kind):
    resp = scan_client.post(URL, data={"source_url": url, "artifact_type": kind})
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "invalid_input"


@pytest.mark.parametrize("kind", ["software", "container", "nonsense"])
def test_unsupported_artifact_type_is_a_validation_error(scan_client, kind):
    resp = scan_client.post(URL, data={"source_url": HF_URL, "artifact_type": kind})
    assert resp.status_code == 422


# ------------------------------------------------------------------ upload
@pytest.fixture
def upload_scan(scan_client, tmp_path):
    return scan_client, post_zip(scan_client, lora_zip(tmp_path), artifact_type="lora")


def test_upload_scan_evidence(upload_scan):
    client, body = upload_scan
    assert body["status"] == "completed", body
    assert body["artifact"]["source"] == "upload" and body["artifact"]["name"] == "model"
    assert body["artifact"]["source_url"] is None
    assert body["stages"]["aibom"]["source"] == "aibom"
    assert body["stages"]["aibom"]["model"]["serialization_types"] == {"safetensors": 1}
    assert body["ingest"]["hf"] is None


def test_upload_provenance_states_are_honest(upload_scan):
    _, body = upload_scan
    p = body["provenance"]
    assert p["source_known"] is False and p["is_mock"] is False
    assert p["signed"] is None and p["hash_changed"] is None and p["resolved_commit"] is None
    assert checks(body)["hash_consistency"]["status"] == "unknown"


def test_upload_lineage_comes_from_adapter_config(upload_scan):
    client, body = upload_scan
    graph = get(client, body, "graph")
    assert graph["graph_kind"] == "lineage" and graph["is_mock"] is False
    edges = [e for e in graph["edges"] if e["relation"] == "fine_tuned_from"]
    assert edges and edges[0]["target"] == "model:example-org/base-model-7b"


def test_no_pinned_deps_skips_vulnerability_stage(scan_client):
    body = post_zip(scan_client, build_zip([("model.safetensors", safetensors_bytes())]))
    stage = body["stages"]["vulnerabilities"]
    assert stage["status"] == "skipped" and "pinned" in stage["reason"]


def test_remote_code_model_is_flagged(scan_client):
    body = post_zip(scan_client, zip_dir(FIXTURES / "model" / "remote_code_model"))
    ids = {i["identifier"] for i in get(scan_client, body, "findings", category="static")["items"]}
    assert "PX-REMOTE-CODE-REQUIRED" in ids
    assert body["stages"]["aibom"]["model"]["custom_code"]["remote_code_required"] is True


def test_missing_input_is_rejected(scan_client):
    resp = scan_client.post(URL, data={})
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "invalid_input"


# ------------------------------------------------------------------ input validation
def test_both_inputs_rejected(scan_client, tmp_path):
    resp = scan_client.post(
        URL,
        data={"source_url": HF_URL},
        files={"file": ("m.zip", lora_zip(tmp_path), "application/zip")},
    )
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "invalid_input"


def test_non_zip_upload_rejected(scan_client):
    resp = scan_client.post(URL, files={"file": ("model.pkl", b"x", "application/octet-stream")})
    assert resp.status_code == 415
    assert resp.json()["error"]["code"] == "unsupported_media_type"


def test_oversized_upload_rejected(scan_client):
    resp = scan_client.post(
        URL, files={"file": ("m.zip", b"x" * (1024 * 1024 + 1), "application/zip")}
    )
    assert resp.status_code == 413 and resp.json()["error"]["code"] == "artifact_too_large"


@pytest.mark.parametrize("revision", ["--upload-pack=x", "../../etc", "a b"])
def test_invalid_revision_rejected(scan_client, revision):
    resp = scan_client.post(URL, data={"source_url": HF_URL, "revision": revision})
    assert resp.status_code == 400


def test_github_url_is_refused_on_the_model_endpoint(scan_client):
    resp = scan_client.post(URL, data={"source_url": "https://github.com/org/repo"})
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "url_not_allowed"


def test_invalid_upload_marks_scan_failed(scan_client):
    body = post_zip(scan_client, b"not a zip")
    assert body["status"] == "failed" and body["error"]["code"] == "invalid_archive"


def test_empty_zip_is_an_empty_artifact(scan_client):
    body = post_zip(scan_client, build_zip([]))
    assert body["status"] == "failed" and body["error"]["code"] == "empty_artifact"


def test_unknown_scan_404(scan_client):
    resp = scan_client.get(f"/api/v1/scans/{uuid.uuid4()}")
    assert resp.status_code == 404


# ------------------------------------------------------------------ provider failures
@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (AppError(ErrorCode.HF_ACCESS_DENIED, "gated", 403), "hf_access_denied"),
        (AppError(ErrorCode.HF_NOT_FOUND, "missing", 404), "hf_not_found"),
        (AppError(ErrorCode.HF_UNAVAILABLE, "down", 503), "hf_unavailable"),
        (AppError(ErrorCode.TOO_MANY_FILES, "many", 413), "too_many_files"),
    ],
)
def test_hub_errors_fail_the_scan_with_a_structured_error(
    test_settings, session_factory, public_dns, exc, code
):
    client = client_with(test_settings, session_factory, StubHf(exc=exc))
    body = post_url(client)
    assert body["status"] == "failed" and body["error"]["code"] == code
    assert body["provenance"] is None


def test_unexpected_provider_exception_is_internal_error(
    test_settings, session_factory, public_dns
):
    client = client_with(test_settings, session_factory, StubHf(exc=RuntimeError("secret detail")))
    body = post_url(client)
    assert body["status"] == "failed" and body["error"]["code"] == "internal_error"
    assert "secret detail" not in str(body["error"])


def test_missing_provider_is_unavailable_and_never_falls_back_to_mock(
    test_settings, session_factory, public_dns
):
    body = post_url(client_with(test_settings, session_factory, None))
    assert body["status"] == "failed" and body["error"]["code"] == "hf_unavailable"


# ------------------------------------------------------------------ real-source behaviour
def real_files() -> dict:
    return {
        "adapter_model.safetensors": safetensors_bytes(),
        "adapter_config.json": b'{"peft_type": "LORA", "base_model_name_or_path": "org/base"}',
    }


def test_non_mock_source_is_not_labeled_mock(test_settings, session_factory, public_dns):
    client = client_with(test_settings, session_factory, StubHf(real_files()))
    body = post_url(client)
    assert body["status"] == "completed", body
    assert body["provenance"]["is_mock"] is False and body["provenance"]["source"] == "provenancex"
    assert body["provenance"]["resolved_commit"] == COMMIT
    assert body["stages"]["aibom"]["source"] == "aibom"
    assert checks(body)["download_integrity"]["status"] == "pass"
    assert get(client, body, "graph")["is_mock"] is False


def test_limits_come_from_settings(test_settings, session_factory, public_dns):
    hf = StubHf(real_files())
    client = client_with(test_settings, session_factory, hf)
    post_url(client, revision="main")
    repo, revision, limits = hf.calls[0]
    assert repo == HfRepo("model", "org/lora") and revision == "main"
    assert limits.max_total_bytes == test_settings.max_artifact_size_mb * 1024 * 1024
    assert limits.max_file_bytes == test_settings.hf_max_file_mb * 1024 * 1024
    assert limits.max_files == min(test_settings.hf_max_files, test_settings.max_artifact_files)


def test_integrity_mismatch_becomes_a_high_provenance_finding(
    test_settings, session_factory, public_dns
):
    files = real_files()
    files["tampered.bin"] = HfFile(
        "tampered.bin",
        5,
        "d" * 40,
        "e" * 64,
        hash_verified=False,
        status="integrity_mismatch",
        reason="SHA-256 differs from the LFS listing",
    )
    client = client_with(test_settings, session_factory, StubHf(files))
    body = post_url(client)
    assert checks(body)["download_integrity"]["status"] == "fail"
    items = get(client, body, "findings", category="provenance")["items"]
    finding = next(i for i in items if i["identifier"] == "PX-PROV-DOWNLOAD-INTEGRITY")
    assert finding["severity"] == "HIGH" and finding["source"] == "provenancex"


def test_listed_but_undownloaded_weights_are_unverified(test_settings, session_factory, public_dns):
    files = real_files()
    files["huge.safetensors"] = HfFile(
        "huge.safetensors",
        10**10,
        "d" * 40,
        "e" * 64,
        status="skipped",
        reason="exceeds the per-file download cap",
    )
    client = client_with(test_settings, session_factory, StubHf(files))
    body = post_url(client)
    assert body["status"] == "completed", body
    assert checks(body)["content_coverage"]["status"] == "unknown"
    assert body["ingest"]["hf"]["counts"]["status_skipped"] == 1


def test_all_files_too_large_still_completes(test_settings, session_factory, public_dns):
    only_big = {"huge.bin": HfFile("huge.bin", 10**10, "d" * 40, "e" * 64, status="skipped")}
    client = client_with(test_settings, session_factory, StubHf(only_big))
    body = post_url(client)
    assert body["status"] == "completed", body
    assert checks(body)["download_integrity"]["status"] == "unknown"


def test_same_commit_with_changed_content_is_flagged(test_settings, session_factory, public_dns):
    client = client_with(test_settings, session_factory, StubHf(real_files()))
    first = post_url(client)
    tampered = real_files()
    tampered["adapter_config.json"] = b'{"peft_type": "LORA", "base_model_name_or_path": "x/y"}'
    client = client_with(test_settings, session_factory, StubHf(tampered))
    second = post_url(client)
    assert second["provenance"]["hash_changed"] is True
    assert second["provenance"]["previous_scan_id"] == first["scan_id"]
    assert checks(second)["hash_consistency"]["status"] == "fail"
    items = get(client, second, "findings", category="provenance")["items"]
    assert "PX-PROV-HASH-CHANGED-SAME-COMMIT" in {i["identifier"] for i in items}


def test_new_commit_with_changed_content_is_not_a_failure(
    test_settings, session_factory, public_dns
):
    client = client_with(test_settings, session_factory, StubHf(real_files()))
    post_url(client)
    changed = real_files()
    changed["adapter_config.json"] = b'{"peft_type": "LORA", "base_model_name_or_path": "x/y"}'
    client = client_with(test_settings, session_factory, StubHf(changed, commit="9" * 40))
    second = post_url(client)
    assert second["provenance"]["hash_changed"] is True
    assert checks(second)["hash_consistency"]["status"] == "info"


def test_manifest_digest_covers_files_that_were_not_downloaded():
    def result(sha):
        files = [HfFile("big.bin", 10, "d" * 40, sha, status="skipped")]
        return HfFetchResult("huggingface", HfRepo("model", "o/r"), COMMIT, files)

    assert hf_manifest_digest(result("1" * 64)) != hf_manifest_digest(result("2" * 64))
    assert hf_manifest_digest(result("1" * 64)) == hf_manifest_digest(result("1" * 64))


# ------------------------------------------------------------------ software root package (API)
def test_software_scan_merges_project_package_into_root(scan_client):
    """The mock SBOM lists demo-app@1.0.0; a matching package.json makes it the root."""
    data = build_zip([("package.json", '{"name": "demo-app", "version": "1.0.0"}')])
    resp = scan_client.post(
        "/api/v1/scans/software", files={"file": ("p.zip", data, "application/zip")}
    )
    assert resp.status_code == 202, resp.text
    body = scan_client.get(f"/api/v1/scans/{resp.json()['scan_id']}").json()
    assert body["stages"]["sbom"]["root_packages"], body["stages"]["sbom"]
    graph = get(scan_client, body, "graph")
    labels = {n["label"]: n for n in graph["nodes"]}
    assert "demo-app@1.0.0" not in labels
    assert graph["features"]["root_package_count"] == 1
    direct = [n for n in graph["nodes"] if n["attributes"].get("depth") == 1]
    assert direct

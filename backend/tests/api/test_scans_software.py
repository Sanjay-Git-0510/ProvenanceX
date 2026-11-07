"""API tests for POST /api/v1/scans/software and GET /api/v1/scans/{scan_id}.

These run on in-memory SQLite. Background tasks complete before TestClient returns,
so a GET right after the POST sees the final status.
"""

import hashlib
import shutil
import uuid

import pytest

from app.core.errors import AppError, ErrorCode
from app.core.hashing import tree_digest
from app.db.models import Artifact, Scan
from app.pipeline import software as software_pipeline
from app.scanners.git_fetch import CloneResult
from tests.conftest import SIMPLE_PROJECT, build_zip, zip_dir

URL = "/api/v1/scans/software"


def _upload(client, data: bytes, filename="project.zip", **form):
    return client.post(URL, files={"file": (filename, data, "application/zip")}, data=form)


def _get(client, scan_id):
    return client.get(f"/api/v1/scans/{scan_id}")


def _workspaces(settings):
    root = settings.workspace_root
    return sorted(p.name for p in root.iterdir()) if root.exists() else []


@pytest.fixture
def fake_clone(monkeypatch):
    """Replace the network clone with a copy of the fixture project."""
    calls = []

    def _clone(url, dest, revision, limits, **kwargs):
        calls.append({"url": url, "revision": revision})
        shutil.copytree(SIMPLE_PROJECT, dest, dirs_exist_ok=True)
        return CloneResult(commit_sha="c" * 40, revision=revision)

    monkeypatch.setattr(software_pipeline, "clone_repository", _clone)
    return calls


# ------------------------------------------------------------------ upload happy path
def test_upload_scan_completes_with_evidence(scan_client, test_settings):
    data = zip_dir(SIMPLE_PROJECT)
    resp = _upload(scan_client, data, filename="My Project v1.zip")
    assert resp.status_code == 202
    created = resp.json()
    assert created["status"] == "queued"

    body = _get(scan_client, created["scan_id"]).json()
    assert body["status"] == "completed", body
    assert body["error"] is None
    assert body["started_at"] and body["finished_at"]

    artifact = body["artifact"]
    assert artifact["artifact_id"] == created["artifact_id"]
    assert artifact["scan_id"] == created["scan_id"]
    assert artifact["artifact_type"] == "software"
    assert artifact["source"] == "upload"
    assert artifact["source_url"] is None
    assert artifact["name"] == "My_Project_v1"
    assert artifact["sha256"] == tree_digest(SIMPLE_PROJECT).sha256
    assert artifact["collected_at"]

    ingest = body["ingest"]
    assert ingest["archive_sha256"] == hashlib.sha256(data).hexdigest()
    assert ingest["file_count"] == 5
    assert ingest["tree_digest_version"] == "provenancex-tree-v1"
    assert ingest["commit_sha"] is None
    assert [m["path"] for m in ingest["manifests"]] == ["pyproject.toml", "requirements.txt"]

    # Workspace kept on success for later phases.
    assert _workspaces(test_settings) == [created["scan_id"]]


def test_same_content_same_sha_regardless_of_zip_order(scan_client):
    a = _upload(scan_client, zip_dir(SIMPLE_PROJECT)).json()["scan_id"]
    b = _upload(scan_client, zip_dir(SIMPLE_PROJECT, reverse=True)).json()["scan_id"]
    sha_a = _get(scan_client, a).json()["artifact"]["sha256"]
    sha_b = _get(scan_client, b).json()["artifact"]["sha256"]
    archive_a = _get(scan_client, a).json()["ingest"]["archive_sha256"]
    archive_b = _get(scan_client, b).json()["ingest"]["archive_sha256"]
    assert sha_a == sha_b
    assert archive_a != archive_b


def test_upload_with_explicit_name_and_revision(scan_client):
    resp = _upload(scan_client, zip_dir(SIMPLE_PROJECT), name="simple-app", revision="v0.1.0")
    body = _get(scan_client, resp.json()["scan_id"]).json()
    assert body["artifact"]["name"] == "simple-app"
    assert body["artifact"]["version"] == "v0.1.0"
    assert body["ingest"]["revision_requested"] == "v0.1.0"


# ------------------------------------------------------------------ GitHub URL path
def test_github_scan_completes(scan_client, fake_clone):
    resp = scan_client.post(URL, data={"source_url": "https://github.com/acme/widget.git"})
    assert resp.status_code == 202
    body = _get(scan_client, resp.json()["scan_id"]).json()
    assert body["status"] == "completed", body
    assert body["artifact"]["source"] == "github"
    assert body["artifact"]["source_url"] == "https://github.com/acme/widget"
    assert body["artifact"]["name"] == "acme/widget"
    assert body["artifact"]["version"] == "c" * 40
    assert body["artifact"]["sha256"] == tree_digest(SIMPLE_PROJECT).sha256
    assert body["ingest"]["commit_sha"] == "c" * 40
    assert body["ingest"]["archive_sha256"] is None
    assert fake_clone == [{"url": "https://github.com/acme/widget.git", "revision": None}]


def test_github_scan_passes_revision(scan_client, fake_clone):
    resp = scan_client.post(
        URL, data={"source_url": "https://github.com/acme/widget", "revision": "release/1.2"}
    )
    body = _get(scan_client, resp.json()["scan_id"]).json()
    assert fake_clone[0]["revision"] == "release/1.2"
    assert body["artifact"]["version"] == "release/1.2"


def test_clone_failure_recorded_and_workspace_removed(scan_client, test_settings, monkeypatch):
    def _fail(*args, **kwargs):
        raise AppError(ErrorCode.CLONE_FAILED, "git command failed", 502, {"returncode": 128})

    monkeypatch.setattr(software_pipeline, "clone_repository", _fail)
    resp = scan_client.post(URL, data={"source_url": "https://github.com/acme/widget"})
    body = _get(scan_client, resp.json()["scan_id"]).json()
    assert body["status"] == "failed"
    assert body["error"] == {
        "code": "clone_failed",
        "message": "git command failed",
        "details": {"returncode": 128},
    }
    assert body["artifact"]["sha256"] is None
    assert _workspaces(test_settings) == []


def test_unexpected_error_is_generic(scan_client, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(software_pipeline, "clone_repository", _boom)
    resp = scan_client.post(URL, data={"source_url": "https://github.com/acme/widget"})
    body = _get(scan_client, resp.json()["scan_id"]).json()
    assert body["status"] == "failed"
    assert body["error"]["code"] == "internal_error"
    assert "secret" not in str(body)


def test_dns_rechecked_before_clone(scan_client, fake_clone, monkeypatch):
    """If DNS turns private between request and clone, the pipeline refuses to clone."""
    from app.security import url_validation

    original = url_validation.resolve_host
    calls = {"n": 0}

    def flip(host):
        calls["n"] += 1
        return original(host) if calls["n"] == 1 else ["127.0.0.1"]

    monkeypatch.setattr(url_validation, "resolve_host", flip)
    resp = scan_client.post(URL, data={"source_url": "https://github.com/acme/widget"})
    body = _get(scan_client, resp.json()["scan_id"]).json()
    assert body["error"]["code"] == "private_address"
    assert fake_clone == []


# ------------------------------------------------------------------ failures inside the pipeline
def test_malicious_zip_fails_scan_and_cleans_up(scan_client, test_settings):
    resp = _upload(scan_client, build_zip([("ok.txt", "x"), ("../escape.txt", "x")]))
    assert resp.status_code == 202
    body = _get(scan_client, resp.json()["scan_id"]).json()
    assert body["status"] == "failed"
    assert body["error"]["code"] == "unsafe_archive"
    assert body["error"]["details"]["reason"] == "path traversal"
    assert _workspaces(test_settings) == []
    assert not (test_settings.workspace_root.parent / "escape.txt").exists()


def test_empty_zip_fails(scan_client):
    body = _get(scan_client, _upload(scan_client, build_zip([])).json()["scan_id"]).json()
    assert body["error"]["code"] == "empty_artifact"


def test_corrupt_zip_fails(scan_client):
    body = _get(scan_client, _upload(scan_client, b"PK\x03\x04garbage").json()["scan_id"]).json()
    assert body["error"]["code"] == "invalid_archive"


# ------------------------------------------------------------------ request validation
def test_oversize_upload_rejected_immediately(scan_client, session_factory, test_settings):
    data = b"x" * (test_settings.max_upload_mb * 1024 * 1024 + 1)
    resp = _upload(scan_client, data)
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "artifact_too_large"
    assert _workspaces(test_settings) == []
    with session_factory() as s:
        assert s.query(Scan).count() == 0 and s.query(Artifact).count() == 0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"data": {}},
        {"data": {"source_url": "   "}},
        {
            "data": {"source_url": "https://github.com/a/b"},
            "files": {"file": ("p.zip", b"PK", "application/zip")},
        },
    ],
    ids=["neither", "blank-url", "both"],
)
def test_exactly_one_source_required(scan_client, kwargs):
    resp = scan_client.post(URL, **kwargs)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_input"


def test_non_zip_upload_rejected(scan_client, test_settings):
    resp = _upload(scan_client, b"data", filename="project.tar.gz")
    assert resp.status_code == 415
    assert resp.json()["error"]["code"] == "unsupported_media_type"
    assert _workspaces(test_settings) == []


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://github.com/a/b", "url_not_allowed"),
        ("https://gitlab.com/a/b", "url_not_allowed"),
        ("https://github.com/a", "invalid_url"),
    ],
)
def test_bad_urls_rejected_without_side_effects(
    scan_client, session_factory, test_settings, url, code
):
    resp = scan_client.post(URL, data={"source_url": url})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == code
    with session_factory() as s:
        assert s.query(Scan).count() == 0
    assert _workspaces(test_settings) == []


def test_name_with_control_chars_rejected(scan_client):
    resp = _upload(scan_client, zip_dir(SIMPLE_PROJECT), name="bad\x07name")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_input"


def test_overlong_form_field_is_validation_error(scan_client):
    resp = scan_client.post(URL, data={"source_url": "https://github.com/a/" + "b" * 3000})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


# ------------------------------------------------------------------ GET
def test_get_unknown_scan(scan_client):
    resp = _get(scan_client, uuid.uuid4())
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "scan_not_found"


def test_get_invalid_scan_id(scan_client):
    resp = _get(scan_client, "not-a-uuid")
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"

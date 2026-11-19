"""Sandbox-only scanning: untrusted content is never processed on the host, and a missing or
broken sandbox fails the scan instead of falling back.

Spies replace every content-reading entry point. A test fails if any of them is called outside
the analyzer (the in-process test executor is the only path that may call them, and only when
a test explicitly selects it).
"""

import ast
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.analysis.inprocess import InProcessTestAnalyzer
from app.api.scans import get_scan_providers, get_session_factory
from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.main import create_app
from app.pipeline.providers import ScanProviders, build_providers
from app.sandbox_worker import collect
from app.sandbox_worker.protocol import WorkerLimits, WorkerRequest
from app.scanners.hf.mock import MockHfProvider
from app.scanners.sbom.mock import MockSbomProvider
from app.scanners.vulns.mock import MockVulnProvider
from tests.analyzer_helpers import FakeDocker
from tests.conftest import build_zip

APP = Path(__file__).resolve().parents[2] / "app"
SOFTWARE = "/api/v1/scans/software"
MODEL = "/api/v1/scans/model"
ZIP = build_zip([("main.py", "import os\nos.system('id')\n"), ("requirements.txt", "flask\n")])
MODEL_ZIP = build_zip([("config.json", '{"model_type": "gpt2"}'), ("README.md", "# m\n")])
# Every function that reads artifact content. None may run on the host.
CONTENT_FUNCTIONS = (
    "safe_extract_zip",
    "tree_digest",
    "list_tree_files",
    "detect_manifests",
    "detect_project_packages",
    "analyze_model",
    "analyze_artifact",
    "config_digest",
    "declared_versions",
)


@pytest.fixture
def content_spies(monkeypatch):
    """Fail loudly if any content-reading function is called (patched where the worker uses it)."""
    calls: list[str] = []

    def spy(name):
        def boom(*_a, **_k):
            calls.append(name)
            raise AssertionError(f"{name} ran on the host")

        return boom

    for name in CONTENT_FUNCTIONS:
        monkeypatch.setattr(collect, name, spy(name))
    monkeypatch.setattr("app.security.archive.safe_extract_zip", spy("archive.safe_extract_zip"))
    return calls


def _client(settings, session_factory, providers=None) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    if providers is not None:
        app.dependency_overrides[get_scan_providers] = lambda: providers
    return TestClient(app, raise_server_exceptions=False)


def _post(client, url, data=ZIP, **form):
    resp = client.post(url, files={"file": ("a.zip", data, "application/zip")}, data=form)
    assert resp.status_code == 202, resp.text
    return client.get(f"/api/v1/scans/{resp.json()['scan_id']}").json()


def _src_files(settings, scan_id) -> list[Path]:
    src = Path(settings.workspace_root) / scan_id / "src"
    return [p for p in src.rglob("*")] if src.exists() else []


# --------------------------------------------------------------------------- API only queues
def test_api_only_queues_in_runner_mode(test_settings, session_factory, public_dns, content_spies):
    settings = test_settings.model_copy(update={"scan_dispatch": "runner"})
    body = _post(_client(settings, session_factory), SOFTWARE)
    assert body["status"] == "queued"
    assert body["stages"] is None and body["sandbox"] is None
    assert body["artifact"]["sha256"] is None
    assert _src_files(settings, body["scan_id"]) == []  # nothing extracted
    assert content_spies == []


# --------------------------------------------------------------------------- fail closed
def _failed_closed(body, settings, content_spies):
    assert body["status"] == "failed", body
    assert body["error"]["code"] == "sandbox_unavailable"
    assert "not processed" in body["error"]["message"]
    assert body["stages"] is None  # no evidence stage ran
    assert body["artifact"]["sha256"] is None
    assert content_spies == []
    assert _src_files(settings, body["scan_id"]) == []


@pytest.mark.parametrize(("url", "data"), [(SOFTWARE, ZIP), (MODEL, MODEL_ZIP)])
def test_no_analyzer_fails_closed(
    test_settings, session_factory, public_dns, content_spies, url, data
):
    providers = ScanProviders(
        sbom=MockSbomProvider(), vulns=MockVulnProvider(), nvd=None, hf=MockHfProvider()
    )
    body = _post(_client(test_settings, session_factory, providers), url, data)
    _failed_closed(body, test_settings, content_spies)


@pytest.mark.parametrize(("url", "data"), [(SOFTWARE, ZIP), (MODEL, MODEL_ZIP)])
def test_docker_missing_fails_closed(
    test_settings, session_factory, public_dns, content_spies, tmp_path, url, data
):
    settings = test_settings.model_copy(
        update={"analyzer_provider": "docker", "analyzer_docker_path": str(tmp_path / "nope")}
    )
    body = _post(_client(settings, session_factory, build_providers(settings)), url, data)
    _failed_closed(body, settings, content_spies)
    run = body["sandbox"]["runs"][0]
    assert run["status"] == "failed" and run["error_code"] == "sandbox_unavailable"


def test_hf_model_with_docker_missing_fails_closed(
    test_settings, session_factory, public_dns, content_spies, tmp_path
):
    settings = test_settings.model_copy(
        update={"analyzer_provider": "docker", "analyzer_docker_path": str(tmp_path / "nope")}
    )
    client = _client(settings, session_factory, build_providers(settings))
    resp = client.post(MODEL, data={"source_url": "https://huggingface.co/mock/tiny-model"})
    assert resp.status_code == 202, resp.text
    body = client.get(f"/api/v1/scans/{resp.json()['scan_id']}").json()
    assert body["status"] == "failed" and body["error"]["code"] == "sandbox_unavailable"
    assert content_spies == []


def test_missing_analyzer_image_fails_closed(
    test_settings, session_factory, public_dns, content_spies, tmp_path, monkeypatch
):
    fake = FakeDocker(tmp_path, monkeypatch, image_exit=1)
    settings = test_settings.model_copy(
        update={"analyzer_provider": "docker", "analyzer_docker_path": str(fake.path)}
    )
    body = _post(_client(settings, session_factory, build_providers(settings)), SOFTWARE)
    _failed_closed(body, settings, content_spies)
    assert "analyzer image has not been built" in body["error"]["message"]
    assert "create" not in fake.verbs()


def test_untrusted_sandbox_output_fails_the_scan(
    test_settings, session_factory, public_dns, content_spies, tmp_path, monkeypatch
):
    out = tmp_path / "out.json"
    out.write_bytes(b'{"format": "provenancex-analyzer-result-v1", "garbage": true}')
    fake = FakeDocker(tmp_path, monkeypatch, start="ok", output_file=str(out))
    settings = test_settings.model_copy(
        update={"analyzer_provider": "docker", "analyzer_docker_path": str(fake.path)}
    )
    body = _post(_client(settings, session_factory, build_providers(settings)), SOFTWARE)
    assert body["status"] == "failed" and body["error"]["code"] == "analyzer_output_invalid"
    assert body["artifact"]["sha256"] is None
    assert content_spies == []


# --------------------------------------------------------------------------- guards
def test_worker_entry_points_refuse_to_run_on_the_host(tmp_path):
    zip_path = tmp_path / "upload.zip"
    zip_path.write_bytes(ZIP)
    out = tmp_path / "out"
    out.mkdir()
    limits = WorkerLimits(
        **{k: getattr(Settings(_env_file=None), k) for k in WorkerLimits.model_fields}
    )
    request = WorkerRequest(mode="extract", kind="software", has_upload=True, limits=limits)
    for call in (
        lambda: collect.run_extract(request, zip_path, out),
        lambda: collect.run_analyze(
            request.model_copy(update={"mode": "analyze"}), out, None, out, sbom_out=out / "s"
        ),
        lambda: collect.run_persist(request.model_copy(update={"mode": "persist"}), out, out),
        lambda: collect.rehash_tree(request, out),
    ):
        with pytest.raises(AppError) as info:
            call()
        assert info.value.code == "sandbox_refused"
    assert list(out.iterdir()) == []


def test_download_entry_points_refuse_to_run_on_the_host(tmp_path):
    """Audit finding H1: git clone and Hugging Face downloads never run in the runner or API."""
    from app.fetch_worker.protocol import FetchLimits, FetchRequest
    from app.fetch_worker.run import run_fetch
    from app.scanners.git_fetch import CloneLimits, clone_repository
    from app.scanners.hf.base import HfFetchLimits
    from app.scanners.hf.client import HuggingFaceProvider
    from app.security.url_validation import HfRepo

    dest = tmp_path / "dest"
    dest.mkdir()
    repo = HfRepo("model", "acme/tiny")
    hf_limits = HfFetchLimits(1024, 1024, 10, 10)
    provider = HuggingFaceProvider(
        timeout_seconds=1, max_retries=0, max_api_bytes=1024, user_agent="t"
    )
    request = FetchRequest(
        source="github",
        url="https://github.com/acme/widget",
        allowed_hosts=["github.com"],
        user_agent="t",
        limits=FetchLimits(
            max_total_bytes=1,
            max_files=1,
            max_file_bytes=1,
            timeout_seconds=1,
            hf_api_timeout_seconds=1,
            http_max_retries=0,
            max_api_bytes=1,
        ),
    )
    for call in (
        lambda: clone_repository("https://github.com/a/b.git", dest, None, CloneLimits(1, 1)),
        lambda: provider.fetch(repo, None, dest, hf_limits),
        lambda: MockHfProvider().fetch(repo, None, dest, hf_limits),
        lambda: run_fetch(request, dest),
    ):
        with pytest.raises(AppError) as info:
            call()
        assert info.value.code == "sandbox_refused"
    assert list(dest.iterdir()) == []


def test_inprocess_fetcher_cannot_be_built_outside_tests(monkeypatch):
    from app.fetch.inprocess import InProcessTestFetcher

    with pytest.raises(AppError):
        InProcessTestFetcher(Settings(_env_file=None))  # APP_ENV=development
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    with pytest.raises(AppError):
        InProcessTestFetcher(Settings(_env_file=None, app_env="test"))


_DOWNLOAD_FUNCTIONS = ("clone_repository", "run_fetch", "HuggingFaceProvider", "MockHfProvider")
# Only these modules may reach the download code: the fetcher worker, and the pytest-only
# in-process fetcher.
_DOWNLOAD_ALLOWED = {"fetch/inprocess.py"}


def test_runner_and_pipeline_never_download():
    for directory in ("api", "pipeline", "runner", "analysis", "fetch", "blockchain", "risk"):
        for path in sorted((APP / directory).glob("*.py")):
            rel = f"{directory}/{path.name}"
            if rel in _DOWNLOAD_ALLOWED:
                continue
            called = _calls(path) & set(_DOWNLOAD_FUNCTIONS)
            assert not called, f"{rel} calls {called}: downloads belong to the fetcher"
            for module, _ in _imports(ast.parse(path.read_text()), top_level_only=False):
                assert module not in (
                    "app.scanners.git_fetch",
                    "app.scanners.hf.client",
                    "app.scanners.hf.mock",
                    "app.fetch_worker.run",
                ), f"{rel} imports {module}"


def test_runner_image_has_no_git():
    dockerfile = (APP.parent / "Dockerfile").read_text()
    assert "install" in dockerfile
    for line in dockerfile.splitlines():
        if "apt-get install" in line:
            assert " git " not in f" {line} ", "the API/runner images must not ship git"


def test_inprocess_analyzer_cannot_be_built_outside_tests(monkeypatch):
    with pytest.raises(AppError):
        InProcessTestAnalyzer(Settings(_env_file=None))  # APP_ENV=development
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    with pytest.raises(AppError):
        InProcessTestAnalyzer(Settings(_env_file=None, app_env="test"))


# --------------------------------------------------------------------------- static checks
_CONTENT_MODULES = (
    "app.sandbox_worker",
    "app.analysis.inprocess",
    "app.security.archive",
    "app.scanners.model.aibom",
    "app.scanners.static.analyzer",
    "app.scanners.manifests",
    "app.pipeline.software",
    "app.pipeline.model",
    "app.runner",
)


def _imports(tree: ast.AST, *, top_level_only: bool) -> list[tuple[str, list[str]]]:
    nodes = tree.body if top_level_only else list(ast.walk(tree))
    found = []
    for node in nodes:
        if isinstance(node, ast.ImportFrom) and node.module:
            found.append((node.module, [a.name for a in node.names]))
        elif isinstance(node, ast.Import):
            found.extend((a.name, []) for a in node.names)
    return found


def test_api_modules_never_import_content_processing():
    for path in [*sorted((APP / "api").glob("*.py")), APP / "main.py"]:
        tree = ast.parse(path.read_text())
        for module, _ in _imports(tree, top_level_only=True):
            assert not module.startswith(_CONTENT_MODULES), f"{path.name} imports {module}"
        nested = [m for m in _imports(tree, top_level_only=False) if m[0].startswith("app.runner")]
        # The only exception: the test-only inline dispatch, imported lazily.
        assert nested in ([], [("app.runner.executor", ["run_inline_for_tests"])]), path.name


def _calls(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Call):
            fn = node.func
            names.add(fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", ""))
    return names


# Reached only through the analyzer. verification.py's re-hash of the kept tree is a
# documented exception until the verify job moves to the runner (Milestone C).
_DOCUMENTED_EXCEPTIONS = {("blockchain/verification.py", "tree_digest")}


def test_host_side_code_never_calls_content_functions():
    host_dirs = ("api", "pipeline", "runner", "risk", "blockchain", "analysis")
    for directory in host_dirs:
        for path in sorted((APP / directory).glob("*.py")):
            rel = f"{directory}/{path.name}"
            for name in _calls(path) & set(CONTENT_FUNCTIONS):
                assert (rel, name) in _DOCUMENTED_EXCEPTIONS, f"{rel} calls {name} on the host"


# --------------------------------------------------------------------------- records
def test_successful_scan_records_its_sandbox_runs(scan_client, test_settings):
    body = _post(scan_client, SOFTWARE)
    assert body["status"] == "completed", body["error"]
    runs = body["sandbox"]["runs"]
    # The in-process executor has no staging volume or holder; persist re-hashes the tree.
    assert [r["mode"] for r in runs] == ["extract", "analyze", "persist"]
    assert all(r["status"] == "ok" and r["provider"] == "inprocess_test" for r in runs)
    # The test executor isolates nothing, and says so.
    assert all(r["runtime_verified"] is False for r in runs)
    assert str(test_settings.workspace_root) not in json.dumps(body)


def test_tree_hash_equals_the_host_reference(scan_client, test_settings, tmp_path):
    """The analyzer's artifact hash is the same provenancex-tree-v1 digest as before."""
    from app.core.hashing import tree_digest

    body = _post(scan_client, SOFTWARE)
    reference = tmp_path / "ref"
    reference.mkdir()
    (reference / "main.py").write_text("import os\nos.system('id')\n")
    (reference / "requirements.txt").write_text("flask\n")
    assert body["artifact"]["sha256"] == tree_digest(reference).sha256
    assert body["ingest"]["file_count"] == 2

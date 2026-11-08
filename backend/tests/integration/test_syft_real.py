"""Real Syft runs on the benign fixtures.

Skipped with an explicit reason when Syft is not installed. CI installs a pinned Syft
and fails on any skip, so these always run there.
"""

import shutil

import pytest

from app.core.config import get_settings
from app.pipeline.providers import ScanProviders
from app.scanners.sbom.cyclonedx import parse_cyclonedx
from app.scanners.sbom.syft import SyftProvider
from app.scanners.vulns.mock import MockVulnProvider
from tests.api.test_scans_findings_graph import _client, _run_scan
from tests.conftest import FIXTURES, SIMPLE_PROJECT

pytestmark = pytest.mark.skipif(
    shutil.which(get_settings().syft_path) is None, reason="Syft is not installed (SYFT_PATH)"
)
NPM_PROJECT = FIXTURES / "software" / "npm_lock_project"


@pytest.fixture
def provider():
    return SyftProvider(get_settings().syft_path, 120, 50 * 1024 * 1024)


def _workspace(tmp_path, project):
    work = tmp_path / "ws"
    shutil.copytree(project, work / "src")
    return work / "src", work


def test_syft_npm_lockfile_yields_transitive_edges(provider, tmp_path):
    src, work = _workspace(tmp_path, NPM_PROJECT)
    result = provider.generate(src, work)
    assert result.source == "syft" and result.tool_version
    parsed = parse_cyclonedx(result.raw, max_bytes=10**8, max_components=10_000)
    names = {c.name for c in parsed.components}
    assert {"express", "body-parser", "qs"} <= names
    assert len(parsed.edges) >= 3
    assert not any(p.name == "sbom.syft.cdx.json" for p in work.iterdir())


def test_syft_requirements_txt(provider, tmp_path):
    src, work = _workspace(tmp_path, SIMPLE_PROJECT)
    parsed = parse_cyclonedx(
        provider.generate(src, work).raw, max_bytes=10**8, max_components=10_000
    )
    assert {("flask", "3.0.3"), ("requests", "2.32.3")} <= {
        (c.name, c.version) for c in parsed.components
    }


def test_planted_syft_config_in_artifact_is_ignored(provider, tmp_path):
    src, work = _workspace(tmp_path, SIMPLE_PROJECT)
    # If Syft loaded this config from the artifact, output would go to a different format.
    (src / ".syft.yaml").write_text('output: ["spdx-json"]\nquiet: false\n')
    raw = provider.generate(src, work).raw
    assert b'"bomFormat"' in raw  # still CycloneDX


def test_api_scan_with_real_syft(test_settings, session_factory, public_dns):
    settings = test_settings.model_copy(update={"sbom_provider": "syft"})
    providers = ScanProviders(
        sbom=SyftProvider(get_settings().syft_path, 120, 50 * 1024 * 1024),
        vulns=MockVulnProvider(),
        nvd=None,
    )
    client = _client(settings, session_factory, providers)
    body = _run_scan(client)
    sbom = body["stages"]["sbom"]
    assert sbom["status"] == "completed" and sbom["source"] == "syft" and sbom["tool_version"]
    assert body["component_count"] == 2
    graph = client.get(f"/api/v1/scans/{body['scan_id']}/graph").json()
    assert graph["is_mock"] is False
    assert graph["features"]["transitive_resolution"] == "none"
    findings = client.get(f"/api/v1/scans/{body['scan_id']}/findings").json()
    # Vulnerabilities came from the mock provider, so they stay labeled mock.
    assert findings["total"] >= 1 and all(i["is_mock"] for i in findings["items"])

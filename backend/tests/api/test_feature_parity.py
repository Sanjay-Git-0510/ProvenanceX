"""The live pipeline and the dataset generator must build the same features for the same input.

Each case runs a generator artifact through the real software or model pipeline. Only the
external tools are replaced: they return the same SBOM, advisories and trace the generator
parses, tagged as real sources so the features are kept. All of this data is synthetic.
"""

import hashlib
import io
import uuid
import zipfile
from dataclasses import dataclass

import numpy as np
import pytest

from app.core.config import Settings
from app.db.models import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    RiskDecision,
    Scan,
    ScanStatus,
)
from app.ml.dataset.generator import (
    RECIPE_STREAM,
    Availability,
    _collect_record,
    _cyclonedx,
    _scan_snapshot,
    _trace_bundle,
    artifact_digest,
)
from app.ml.dataset.tampering import RECIPES, VARIANTS, variant_applies
from app.ml.dataset.templates import baseline_state, build_family, older_release_state
from app.ml.preprocessing import fit_preprocessor, transform, transform_features
from app.pipeline.model import run_model_ingestion
from app.pipeline.providers import ScanProviders
from app.pipeline.software import run_software_ingestion
from app.pipeline.workspace import create_workspace
from app.provenance.checks import PriorScan
from app.risk import model_runtime
from app.scanners.hf.base import HfFetchResult, HfFile
from app.scanners.sandbox.base import SandboxRun
from app.scanners.sbom.base import SbomResult
from app.scanners.vulns.base import Advisory, VulnLookupResult

SEED = 7
ALL_COMPLETED = Availability(
    graph="completed",
    aibom="completed",
    vulnerabilities="completed",
    provenance="completed",
    static="completed",
    sandbox="completed",
    prior_available=True,
)
SOURCES = {
    "github": ArtifactSource.GITHUB,
    "huggingface": ArtifactSource.HUGGINGFACE,
    "upload": ArtifactSource.UPLOAD,
}


class FakeSbom:
    name = "syft"

    def __init__(self, raw):
        self.raw = raw

    def generate(self, src_dir, work_dir):
        return SbomResult(raw=self.raw, source="syft", tool_name="syft", tool_version="test")


class FakeVulns:
    name = "osv"

    def __init__(self, advisories):
        self.advisories = advisories

    def lookup(self, packages):
        by_ref = {}
        for package in packages:
            found = [a for a in self.advisories if a["component"] == package.name]
            if found:
                by_ref[package.ref] = [_advisory(i, a) for i, a in enumerate(found)]
        return VulnLookupResult(by_ref=by_ref, source="osv")


def _advisory(index, advisory):
    return Advisory(
        identifier=f"SYNTH-{index}",
        aliases=(),
        summary=None,
        severity="HIGH",
        severity_source=None,
        cvss_score=advisory["cvss"],
        cvss_vector=None,
        cvss_version=None,
        cvss_source=None,
        source="osv",
    )


class FakeSandbox:
    name = "docker"

    def __init__(self, raw):
        self.raw = raw

    def run(self, request):
        return SandboxRun(raw=self.raw, timed_out=False, source="sandbox")


class FakeHf:
    name = "hf"

    def __init__(self, state):
        self.state = state

    def fetch(self, repo, revision, dest, limits):
        files = []
        for rel, content in sorted(self.state.files.items()):
            path = dest / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            files.append(
                HfFile(
                    path=rel,
                    size=len(content),
                    git_oid=digest[:40],
                    lfs_sha256=None,
                    downloaded=True,
                    local_sha256=digest,
                    status="downloaded",
                )
            )
        return HfFetchResult(
            source="huggingface", repo=repo, commit_sha=self.state.commit, files=files
        )


@dataclass
class Clone:
    commit_sha: str


def _settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        workspace_root=tmp_path / "workspaces",
        nvd_enabled=False,
        model_path=tmp_path / "no-models",
    )


def _zip(state) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for rel, content in sorted(state.files.items()):
            archive.writestr(rel, content)
    return buffer.getvalue()


def _family(kind, source):
    for index in range(500):
        family = build_family(index, SEED)
        if family.artifact_type == kind and family.source == source:
            return family
    raise AssertionError(f"no {kind} family from {source}")


def _live_scan(family, variant_index, state, settings, session_factory, monkeypatch):
    """Run one artifact state through the real pipeline and return the stored decision."""

    def fake_clone(_url, dest, _revision, _limits):
        for rel, content in state.files.items():
            path = dest / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        return Clone(state.commit)

    monkeypatch.setattr("app.pipeline.software.clone_repository", fake_clone)
    rng = np.random.default_rng([SEED, family.index, variant_index, RECIPE_STREAM + 1])
    providers = ScanProviders(
        sbom=FakeSbom(_cyclonedx(state, family)),
        vulns=FakeVulns(state.advisories),
        nvd=None,
        hf=FakeHf(state),
        sandbox=FakeSandbox(_trace_bundle(state, rng)),
    )
    scan_id = uuid.uuid4()
    workspace = create_workspace(settings.workspace_root, scan_id)
    if family.is_upload:
        workspace.upload_path.write_bytes(_zip(state))
    with session_factory() as session:
        artifact = Artifact(
            artifact_type=ArtifactType(family.artifact_type),
            name=family.name,
            source=SOURCES[family.source],
            source_url=family.source_url,
        )
        session.add_all(
            [
                artifact,
                Scan(
                    id=scan_id,
                    artifact=artifact,
                    status=ScanStatus.QUEUED,
                    scanner_version="test",
                    revision_requested=state.revision,
                ),
            ]
        )
        session.commit()
    runner = run_software_ingestion if family.is_software else run_model_ingestion
    runner(scan_id, session_factory, settings, providers)
    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan.status == ScanStatus.COMPLETED, scan.error_message
        assert scan.stages["risk"]["status"] == "completed", scan.stages["risk"]
        session.expunge(scan)
        decision = session.query(RiskDecision).filter_by(scan_id=scan_id).one()
        return scan, decision


def _generated(family, variant_index, variant, state, prior, settings, directory):
    return _collect_record(
        family,
        variant_index,
        variant,
        state,
        prior,
        ALL_COMPLETED,
        SEED,
        settings,
        directory,
        "train",
    )


def _prior_state(family, kind):
    return baseline_state(family, SEED) if kind == "baseline" else older_release_state(family, SEED)


def _variants(family):
    return [(i, v) for i, v in enumerate(VARIANTS) if variant_applies(v, family)]


def _state(family, variant_index, variant):
    state = baseline_state(family, SEED).clone()
    rng = np.random.default_rng([SEED, family.index, variant_index, RECIPE_STREAM])
    for name in variant.recipes:
        RECIPES[name].apply(state, family, rng)
    return state


CASES = [
    ("software", "github"),
    ("software", "upload"),
    ("model", "huggingface"),
    ("lora", "huggingface"),
    ("model", "upload"),
]


@pytest.fixture(autouse=True)
def no_model_cache():
    model_runtime.clear_cache()
    yield
    model_runtime.clear_cache()


@pytest.mark.parametrize(("kind", "source"), CASES)
def test_live_features_match_the_generator(
    kind, source, tmp_path, session_factory, public_dns, monkeypatch
):
    family = _family(kind, source)
    settings = _settings(tmp_path)
    compared = 0
    records, live_rows = [], []
    for variant_index, variant in _variants(family):
        state = _state(family, variant_index, variant)
        prior = None
        if variant.prior != "none" and not family.is_upload:
            prior_state = _prior_state(family, variant.prior)
            _live_scan(family, variant_index, prior_state, settings, session_factory, monkeypatch)
            prior = (
                _scan_snapshot(prior_state, family, settings, tmp_path),
                PriorScan(
                    scan_id=uuid.uuid4(),
                    resolved_commit=prior_state.commit,
                    artifact_sha256=artifact_digest(prior_state),
                    manifest_sha256=None,
                ),
            )
        record = _generated(family, variant_index, variant, state, prior, settings, tmp_path)
        _, decision = _live_scan(
            family, variant_index, state, settings, session_factory, monkeypatch
        )
        live = decision.explanation["features"]
        diff = {
            name: (value, live[name])
            for name, value in record.features.items()
            if value != live[name] or type(value) is not type(live[name])
        }
        assert not diff, f"{variant.name}: (generator, live) {diff}"
        reasons = {k: str(v) for k, v in record.null_reasons.items()}
        assert reasons == decision.explanation["null_reasons"], variant.name
        records.append(record)
        live_rows.append(live)
        compared += 1
    assert compared > 0
    # Guards against a vacuous pass: the features under test must really have values.
    assert any(row["network_count"] is not None for row in live_rows)
    assert any(row["vulnerable_count"] for row in live_rows)
    if not family.is_upload:
        assert {row["hash_changed"] for row in live_rows} == {True, False}
    if source == "huggingface":
        assert {row["config_changed"] for row in live_rows} == {True, False}
    params = fit_preprocessor([r.model_copy(update={"split": "train"}) for r in records])
    encoded = transform_features(params, live_rows)
    np.testing.assert_array_equal(encoded, transform(params, records))

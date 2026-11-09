"""Build feature records by running the real parsers over synthetic artifacts.

Files are materialized in a temporary directory and only parsed: nothing is imported, loaded,
installed or run, the sandbox is not started, and the network is not used. SBOMs, advisories
and sandbox traces are generated, and the first and last of those go through the real parsers.

Stage failures and missing priors are drawn from a stream that never sees the label, so
missing evidence cannot leak it. A label is kept even if its evidence ended up unobserved;
`label_evidence_observable` records that case, and such a record stays a hard example.
"""

import hashlib
import json
import tempfile
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from app.core.config import Settings, get_settings
from app.graph.dependency_graph import build_dependency_graph
from app.graph.lineage_graph import build_lineage_graph
from app.ml.comparison import (
    ScanSnapshot,
    compare_snapshots,
    config_digest,
    declared_versions,
    graph_edges,
    max_centrality,
    version_consistency,
)
from app.ml.dataset.splits import SPLIT_FRACTIONS, assign_family_splits, find_family_leaks
from app.ml.dataset.tampering import RECIPES, VARIANTS, Variant, resolve_label, variant_applies
from app.ml.dataset.templates import (
    ArtifactState,
    Family,
    baseline_state,
    build_family,
    older_release_state,
)
from app.ml.feature_schema import (
    DATASET_FORMAT,
    NOT_EVALUATED_FEATURES,
    SYNTHETIC_GROUND_TRUTH,
    FeatureRecord,
    Label,
)
from app.ml.features import extract_features
from app.provenance.checks import PriorScan, ProvenanceInputs, run_provenance_checks
from app.scanners.model.aibom import ModelAnalysis, ModelContext, analyze_model
from app.scanners.sandbox.telemetry import SpikeThresholds, TraceLimits, parse_trace_bundle
from app.scanners.sbom.cyclonedx import ParsedSbom, parse_cyclonedx
from app.scanners.static.analyzer import StaticLimits, analyze_artifact

GENERATOR_VERSION = "1"
SYNTHETIC_NOTICE = (
    "SYNTHETIC DATA. Every record comes from generated fixtures and controlled tampering. Labels "
    "are true by construction, not observed in the wild. Results on this data do not measure "
    "real-world detection. No real malware was used, so malicious_known_bad has no records."
)
SYNTHETIC_SOURCE = "synthetic"
ROOT_REF = "root"
# The parser counts only publicly routable addresses. This is text in a generated trace; it is
# parsed and never contacted.
TRACE_PUBLIC_PREFIX = "93.184.216"
MB = 1024 * 1024
RECIPE_STREAM = 21
AVAILABILITY_STREAM = 22
# Research parameters for the simulated stage outcomes; recorded in the dataset metadata.
STAGE_FAILURE_RATES = {
    "sbom_or_graph_error": 0.03,
    "aibom_error": 0.02,
    "vulnerabilities_unavailable": 0.08,
    "provenance_error": 0.02,
    "static_partial": 0.05,
    "sandbox_not_run": 0.40,
    "sandbox_partial": 0.05,
    "sandbox_error": 0.03,
    "no_prior_scan": 0.25,
}


@dataclass(frozen=True)
class Availability:
    """Simulated outcome of each stage, decided without looking at the label."""

    graph: str
    aibom: str
    vulnerabilities: str
    provenance: str
    static: str
    sandbox: str | None  # None: the sandbox stage was not run
    prior_available: bool


def draw_availability(seed: int, family_index: int, variant_index: int) -> Availability:
    """Depends only on identifiers, so failures are independent of the label by construction."""
    rng = np.random.default_rng([seed, family_index, variant_index, AVAILABILITY_STREAM])
    rates = STAGE_FAILURE_RATES
    graph = "error" if rng.random() < rates["sbom_or_graph_error"] else "completed"
    aibom = "error" if rng.random() < rates["aibom_error"] else "completed"
    vuln = "unavailable" if rng.random() < rates["vulnerabilities_unavailable"] else "completed"
    provenance = "error" if rng.random() < rates["provenance_error"] else "completed"
    static = "partial" if rng.random() < rates["static_partial"] else "completed"
    roll = rng.random()
    sandbox: str | None = "completed"
    if roll < rates["sandbox_not_run"]:
        sandbox = None
    elif roll < rates["sandbox_not_run"] + rates["sandbox_partial"]:
        sandbox = "partial"
    elif roll < rates["sandbox_not_run"] + rates["sandbox_partial"] + rates["sandbox_error"]:
        sandbox = "error"
    prior_available = bool(rng.random() >= rates["no_prior_scan"])
    return Availability(graph, aibom, vuln, provenance, static, sandbox, prior_available)


def _static_limits(settings: Settings) -> StaticLimits:
    return StaticLimits(
        max_files=settings.static_max_files,
        max_file_bytes=settings.static_max_file_kb * 1024,
        max_total_bytes=settings.static_max_total_mb * MB,
        max_findings=settings.static_max_findings,
        max_compression_ratio=settings.max_compression_ratio,
        ratio_warn_fraction=settings.static_archive_ratio_warn_fraction,
    )


def _materialize(state: ArtifactState, directory: Path) -> Path:
    src = directory / f"src-{uuid.uuid4().hex}"
    for rel, content in state.files.items():
        path = src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return src


def artifact_digest(state: ArtifactState) -> str:
    digest = hashlib.sha256()
    for rel in sorted(state.files):
        digest.update(rel.encode() + b"\0" + state.files[rel] + b"\0")
    return digest.hexdigest()


def _cyclonedx(state: ArtifactState, family: Family) -> bytes:
    def ref(name: str, version: str) -> str:
        return f"pkg:{family.ecosystem}/{name}@{version}"

    refs = {name: ref(name, version) for name, version in state.components}
    children: dict[str, list[str]] = {}
    for parent, child in state.edges:
        children.setdefault(parent, []).append(refs[child])
    dependencies = [
        {"ref": ROOT_REF if parent == "root" else refs[parent], "dependsOn": sorted(kids)}
        for parent, kids in sorted(children.items())
    ]
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {"bom-ref": ROOT_REF, "type": "application", "name": family.name}
        },
        "components": [
            {"bom-ref": refs[n], "type": "library", "name": n, "version": v, "purl": refs[n]}
            for n, v in state.components
        ],
        "dependencies": dependencies,
    }
    return json.dumps(document, sort_keys=True).encode()


def _parse_sbom(state: ArtifactState, family: Family, settings: Settings) -> ParsedSbom:
    return parse_cyclonedx(
        _cyclonedx(state, family),
        max_bytes=64 * MB,
        max_components=settings.max_artifact_files,
    )


def _software_graph(state: ArtifactState, family: Family, settings: Settings) -> Any:
    sbom = _parse_sbom(state, family, settings)
    return build_dependency_graph(family.name, sbom.components, sbom.edges, root_ref=sbom.root_ref)


def _model_analysis(src: Path, family: Family, settings: Settings) -> ModelAnalysis:
    context = ModelContext(
        name=family.name,
        artifact_type=family.artifact_type,
        source=family.source,
        source_url=family.source_url,
        repo_id=family.repo_id,
    )
    return analyze_model(src, context, settings)


def _snapshot(src: Path, state: ArtifactState, graph: Any) -> ScanSnapshot:
    attested = any(path.endswith(".intoto.jsonl") for path in state.files)
    return ScanSnapshot(
        config_sha256=config_digest(src),
        edges=graph_edges(graph),
        max_centrality=max_centrality(graph),
        attestation_present=attested,
    )


def _scan_snapshot(
    state: ArtifactState, family: Family, settings: Settings, directory: Path
) -> ScanSnapshot:
    src = _materialize(state, directory)
    if family.is_software:
        graph = _software_graph(state, family, settings).graph
    else:
        analysis = _model_analysis(src, family, settings)
        graph = build_lineage_graph(
            family.name, family.artifact_type, analysis, family.repo_id
        ).graph
    return _snapshot(src, state, graph)


def _benign_trace_lines(rng: np.random.Generator) -> list[str]:
    pid = int(rng.integers(100, 900))
    lines = [f'{pid} 1700000000.0001 execve("/usr/local/bin/python", ["python"], 0x7f) = 0']
    for i in range(int(rng.integers(2, 30))):
        lines.append(
            f'{pid} 1700000000.{i + 2:04d} openat(AT_FDCWD, "/artifact/f{i}", O_RDONLY) = 3'
        )
    for i in range(int(rng.integers(0, 6))):
        lines.append(
            f'{pid} 1700000001.{i:04d} openat(AT_FDCWD, "/tmp/o{i}", O_WRONLY|O_CREAT, 0644) = 4'
        )
    if rng.random() < 0.15:  # some legitimate software probes the network
        lines.append(_connect_line(pid, f"{TRACE_PUBLIC_PREFIX}.10", 443))
    lines.append(f"{pid} 1700000002.0000 exit_group(0) = ?")
    return lines


def _connect_line(pid: int, address: str, port: int) -> str:
    return (
        f"{pid} 1700000001.5000 connect(6, {{sa_family=AF_INET, sin_port=htons({port}), "
        f'sin_addr=inet_addr("{address}")}}, 16) = -1 ENETUNREACH (Network is unreachable)'
    )


def _suspicious_trace_lines(rng: np.random.Generator) -> list[str]:
    lines = _benign_trace_lines(rng)[:-1]
    pid = 300
    for i in range(int(rng.integers(1, 5))):
        lines.append(_connect_line(pid, f"{TRACE_PUBLIC_PREFIX}.{20 + i}", 4444))
    if rng.random() < 0.7:
        lines.append(
            f'{pid} 1700000001.6000 openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) '
            "= -1 ENOENT (No such file or directory)"
        )
    if rng.random() < 0.7:
        lines.append(f'{pid} 1700000001.7000 execve("/bin/sh", ["sh", "-c", "id"], 0x7f) = 0')
    lines.append(f"{pid} 1700000002.0000 exit_group(0) = ?")
    return lines


def _trace_bundle(state: ArtifactState, rng: np.random.Generator) -> bytes:
    lines = (
        _suspicious_trace_lines(rng)
        if state.trace_kind == "suspicious"
        else _benign_trace_lines(rng)
    )
    bundle = {
        "format": "provenancex-trace-v1",
        "synthetic": True,
        "meta": {
            "exit_code": 0,
            "timed_out": False,
            "duration_seconds": 1.0,
            "targets": [],
            "limits": {"memory_bytes": 536870912, "pids": 128, "cpus": 1.0},
        },
        "strace_lines": lines,
        "resource_samples": [{"t": 0.5, "memory_bytes": 20000000, "pids": 2, "cpu_usec": 100000}],
    }
    return json.dumps(bundle).encode()


def _trace_features(state: ArtifactState, rng: np.random.Generator, settings: Settings) -> dict:
    result = parse_trace_bundle(
        _trace_bundle(state, rng),
        TraceLimits(settings.sandbox_max_trace_mb * MB, settings.sandbox_max_trace_lines),
        SpikeThresholds(
            settings.sandbox_spike_memory_fraction,
            settings.sandbox_spike_pids_fraction,
            settings.sandbox_spike_cpu_fraction,
            settings.sandbox_spike_cpu_min_intervals,
        ),
    )
    return result.features


def _vulnerability_summary(state: ArtifactState) -> dict[str, Any]:
    scores = [a["cvss"] for a in state.advisories if a["cvss"] is not None]
    return {
        "vulnerable_count": len({a["component"] for a in state.advisories}),
        "vulnerability_count": len(state.advisories),
        "cvss_max": max(scores) if scores else None,
    }


def _stage(status: str | None, **fields: Any) -> dict[str, Any] | None:
    if status is None:
        return None
    return {
        "status": status,
        "source": SYNTHETIC_SOURCE,
        **(fields if status == "completed" else {}),
    }


def _collect_record(
    family: Family,
    variant_index: int,
    variant: Variant,
    state: ArtifactState,
    prior: tuple[ScanSnapshot, PriorScan] | None,
    availability: Availability,
    seed: int,
    settings: Settings,
    directory: Path,
    split: str,
) -> FeatureRecord:
    src = _materialize(state, directory)
    trace_rng = np.random.default_rng([seed, family.index, variant_index, RECIPE_STREAM + 1])

    analysis = None
    pickle_flags: int | None = None
    auto_map_targets = 0
    stages: dict[str, Any] = {}
    if family.is_software:
        graph_obj = _software_graph(state, family, settings)
        features = dict(graph_obj.features)
        stages["sbom"] = _stage(availability.graph)
    else:
        analysis = _model_analysis(src, family, settings)
        graph_obj = build_lineage_graph(family.name, family.artifact_type, analysis, family.repo_id)
        features = dict(graph_obj.features)
        pickle_flags = sum(
            len(f.analysis["pickle"]["dangerous_globals"])
            for f in analysis.inventory
            if f.analysis.get("pickle") is not None
        )
        auto_map_targets = sum(len(m) for m in analysis.custom_code.auto_map.values())
        model = {
            "serialization_types": analysis.serialization_counts,
            "summary": analysis.aibom["summary"],
        }
        stages["aibom"] = _stage(availability.aibom, model=model)

    upstream_failed = (family.is_software and availability.graph != "completed") or (
        not family.is_software and availability.aibom != "completed"
    )
    if upstream_failed:
        stages["graph"] = _stage("skipped")
        stages["vulnerabilities"] = _stage("skipped")
    else:
        features.update(_vulnerability_summary(state))
        stages["graph"] = _stage("completed", features=features)
        stages["vulnerabilities"] = _stage(availability.vulnerabilities)
        if availability.vulnerabilities != "completed":
            for key in ("vulnerable_count", "vulnerability_count", "cvss_max"):
                features[key] = None

    prior_scan = prior[1] if prior else None
    inputs = ProvenanceInputs(
        source=family.source,
        source_url=family.source_url,
        revision_requested=state.revision,
        resolved_commit=None if family.is_upload else state.commit,
        artifact_sha256=artifact_digest(state),
        file_paths=sorted(state.files),
        artifact_type=family.artifact_type,
        lineage_completeness=graph_obj.features.get("lineage_completeness"),
        prior=prior_scan,
    )
    result = run_provenance_checks(inputs)
    provenance = {
        "source_known": result.source_known,
        "revision_pinned": result.revision_pinned,
        "provenance_present": bool(result.attestation_files),
        "signed": result.signed,
        "hash_changed": result.hash_changed,
        "lineage_completeness": result.lineage_completeness,
        "checks": [c.to_dict() for c in result.checks],
    }
    stages["provenance"] = _stage(availability.provenance)

    static = analyze_artifact(
        src,
        _static_limits(settings),
        auto_map_targets=auto_map_targets,
        pickle_dangerous_globals=pickle_flags,
    )
    stages["static"] = _stage(availability.static, features=static.features)
    sandbox_features = None
    if availability.sandbox == "completed":
        sandbox_features = _trace_features(state, trace_rng, settings)
    stages["sandbox"] = _stage(availability.sandbox, features=sandbox_features)
    if stages["sandbox"] is None:
        del stages["sandbox"]

    comparison = None
    if prior:
        current = _snapshot(src, state, graph_obj.graph)
        comparison = compare_snapshots(prior[0], current)
    versions = version_consistency(declared_versions(src, state.revision))
    extraction = extract_features(family.artifact_type, stages, provenance, comparison, versions)

    label = resolve_label(variant.recipes)
    observable = True
    for name in variant.recipes:
        recipe = RECIPES[name]
        if recipe.label == Label.BENIGN:
            continue
        needed = (stages.get(recipe.evidence_stage) or {}).get("status")
        observable = observable and needed == "completed" and (prior or not recipe.needs_prior)
    joined = "+".join(variant.recipes) or "clean"
    origin = "controlled_fixture" if label == Label.BENIGN else "controlled_tampering"
    label_source = f"{origin}:{joined}"
    return FeatureRecord(
        record_id=f"{family.family_id}:{variant.name}",
        family_id=family.family_id,
        artifact_type=family.artifact_type,
        variant=variant.name,
        applied_recipes=list(variant.recipes),
        label=label,
        label_source=label_source,
        ground_truth_status=SYNTHETIC_GROUND_TRUTH,
        synthetic=True,
        label_evidence_observable=bool(observable),
        split=split,
        features=extraction.features,
        null_reasons=extraction.null_reasons,
    )


def _family_records(
    family: Family, split: str, seed: int, settings: Settings, directory: Path
) -> list[FeatureRecord]:
    records: list[FeatureRecord] = []
    base = baseline_state(family, seed)
    snapshots: dict[str, tuple[ScanSnapshot, ArtifactState]] = {}
    for variant_index, variant in enumerate(VARIANTS):
        if not variant_applies(variant, family):
            continue
        state = base.clone()
        rng = np.random.default_rng([seed, family.index, variant_index, RECIPE_STREAM])
        for name in variant.recipes:
            RECIPES[name].apply(state, family, rng)

        availability = draw_availability(seed, family.index, variant_index)
        has_prior = availability.prior_available and not family.is_upload
        prior_kind = variant.prior if has_prior else "none"
        prior = None
        if prior_kind != "none":
            if prior_kind not in snapshots:
                source = base if prior_kind == "baseline" else older_release_state(family, seed)
                snapshots[prior_kind] = (
                    _scan_snapshot(source, family, settings, directory),
                    source,
                )
            snapshot, source = snapshots[prior_kind]
            prior_scan = PriorScan(
                scan_id=uuid.uuid5(uuid.NAMESPACE_URL, f"{family.family_id}:{prior_kind}"),
                resolved_commit=source.commit,
                artifact_sha256=artifact_digest(source),
                manifest_sha256=None,
            )
            prior = (snapshot, prior_scan)
        records.append(
            _collect_record(
                family,
                variant_index,
                variant,
                state,
                prior,
                availability,
                seed,
                settings,
                directory,
                split,
            )
        )
    return records


def generate_records(
    family_count: int, seed: int, settings: Settings | None = None
) -> list[FeatureRecord]:
    settings = settings or get_settings()
    families = [build_family(index, seed) for index in range(family_count)]
    splits = assign_family_splits({f.family_id: f.artifact_type for f in families}, seed)
    records: list[FeatureRecord] = []
    with tempfile.TemporaryDirectory(prefix="px-dataset-") as tmp:
        for family in families:
            records.extend(
                _family_records(family, splits[family.family_id], seed, settings, Path(tmp))
            )
    leaks = find_family_leaks((r.family_id, r.split) for r in records)
    if leaks:
        raise ValueError(f"Family split leakage: {sorted(leaks)[:5]}")
    return records


def dataset_metadata(
    records: list[FeatureRecord], seed: int, dataset_sha256: str
) -> dict[str, Any]:
    return {
        "format": DATASET_FORMAT,
        "generator_version": GENERATOR_VERSION,
        "synthetic": True,
        "notice": SYNTHETIC_NOTICE,
        "ground_truth_status": SYNTHETIC_GROUND_TRUTH,
        "seed": seed,
        "dataset_sha256": dataset_sha256,
        "record_count": len(records),
        "family_count": len({r.family_id for r in records}),
        "label_counts": dict(sorted(Counter(str(r.label) for r in records).items())),
        "split_counts": dict(sorted(Counter(r.split for r in records).items())),
        "split_fractions_by_family": SPLIT_FRACTIONS,
        "split_unit": "artifact_family",
        "artifact_type_counts": dict(sorted(Counter(r.artifact_type for r in records).items())),
        "variant_counts": dict(sorted(Counter(r.variant for r in records).items())),
        "label_evidence_unobservable": sum(not r.label_evidence_observable for r in records),
        "stage_failure_rates": STAGE_FAILURE_RATES,
        "not_evaluated_features": list(NOT_EVALUATED_FEATURES),
        "null_policy": "A null feature means not evaluated. Reasons are in null_reasons.",
        "execution": "Fixtures were parsed only. No artifact code ran; the sandbox was not used.",
        "advisories": "SYNTH-* advisories and CVSS values are generated, not real vulnerabilities.",
        "telemetry": "Sandbox traces are generated, then parsed by the real telemetry parser.",
    }


def write_dataset(records: list[FeatureRecord], seed: int, out_dir: Path) -> dict[str, Any]:
    """Write the records and metadata. Output is deterministic for a given seed."""
    out_dir.mkdir(parents=True, exist_ok=True)
    body = "".join(
        json.dumps(record.model_dump(mode="json"), sort_keys=True) + "\n" for record in records
    ).encode()
    (out_dir / "dataset.jsonl").write_bytes(body)
    metadata = dataset_metadata(records, seed, hashlib.sha256(body).hexdigest())
    (out_dir / "dataset_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return metadata

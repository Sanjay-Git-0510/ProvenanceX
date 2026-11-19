"""Cross-checks of the analyzer's evidence (audit finding M4). Runs in the scan-runner.

The analyzer parsed attacker-controlled bytes, so a parser exploit could rewrite its output to
look clean. Its schema (app/sandbox_worker/protocol.py) and the strict decoders
(app/analysis/codec.py) bound every value; these checks then require the sections to agree with
each other and with independently computed facts. Any contradiction fails the scan with
analyzer_output_invalid. Nothing here treats missing or unknown evidence as benign: a section
the analyzer reported as failed stays failed, and is only checked when it is present.

Checks:
  * the tree digests from separate containers (analyze, sbom, persist) are identical;
  * the listed file paths are well formed, unique and exactly tree.file_count many;
  * manifest, static-finding, not-analyzed and AI-BOM paths all lie inside that file list
    (AI-BOM files the source listed but that were not downloaded must lie outside it);
  * static findings have a known kind and never exceed that kind's feature count;
  * counts (static features, AI-BOM summary) never exceed what the tree and the lists allow,
    and the AI-BOM summary agrees with its own file list;
  * SBOM component locations (real Syft output) lie inside the tree (checked by the SBOM stage).
"""

from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any

from app.analysis.codec import model_analysis_from_aibom, static_from_dict
from app.core.errors import AppError, ErrorCode
from app.sandbox_worker.protocol import AnalysisOut, SbomRunOut, TreeOut
from app.scanners.static.rules import KIND_API, KIND_ARCHIVE, KIND_IMPORT, KIND_INSTALL

UPLOAD_LABEL = "(uploaded archive)"  # static findings about the raw upload, not a tree file
_NOT_ANALYZED_PATH_LIMIT = 512  # the static analyzer truncates these paths
# Each static finding kind is counted in exactly one feature (app/scanners/static/analyzer.py).
_KIND_FEATURE = {
    KIND_IMPORT: "dangerous_import_count",
    KIND_API: "suspicious_api_count",
    KIND_ARCHIVE: "archive_anomaly",
    KIND_INSTALL: "install_hook_count",
}


def contradiction(reason: str, **details: Any) -> AppError:
    return AppError(
        ErrorCode.ANALYZER_OUTPUT_INVALID,
        "The analyzer's evidence is contradictory; it was discarded",
        502,
        {"reason": reason, **{k: v for k, v in details.items() if v is not None}},
    )


def canonical(path: str) -> str:
    """Undecodable bytes become U+FFFD in some decoders and '?' in others."""
    return path.replace("�", "?")


def _well_formed(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return bool(path) and not path.startswith("/") and ".." not in parts and "\0" not in path


# --------------------------------------------------------------------------- trees
def check_same_tree(reference: TreeOut, other: TreeOut | None, source: str) -> None:
    """Two containers digested the same staged tree: everything must be identical."""
    if other is None or (other.sha256, other.file_count, other.total_bytes) != (
        reference.sha256,
        reference.file_count,
        reference.total_bytes,
    ):
        raise contradiction(
            f"the {source} tree digest differs from the analyzed tree",
            analyzed=reference.sha256,
            other=other.sha256 if other else None,
        )


def check_sbom_run(analysis: AnalysisOut, run: SbomRunOut) -> None:
    check_same_tree(analysis.tree, run.tree, "sbom")


# --------------------------------------------------------------------------- analysis
def _subset(paths: Iterable[str], files: set[str], what: str) -> None:
    for path in paths:
        if canonical(path) not in files:
            raise contradiction(f"{what} names a file that is not in the tree")


def _check_static(static: dict[str, Any], files: set[str], file_count: int) -> None:
    result = static_from_dict(static)  # strict typing; raises analyzer_output_invalid
    f = result.features
    _subset((g.file for g in result.findings if g.file != UPLOAD_LABEL), files, "a static finding")
    for entry in result.not_analyzed:
        path = canonical(entry.get("file", ""))
        truncated = len(path) >= _NOT_ANALYZED_PATH_LIMIT
        if path not in files and not (truncated and any(p.startswith(path) for p in files)):
            raise contradiction("a not-analyzed entry names a file that is not in the tree")
    if result.not_analyzed_count < len(result.not_analyzed):
        raise contradiction("not_analyzed_count is smaller than the listed entries")
    kinds = f["script_count"] + f["bytecode_count"] + f["native_binary_count"]
    if f["files_analyzed"] > file_count or kinds > file_count:
        raise contradiction("static counts exceed the number of files in the tree")
    if f["script_presence"] != (f["script_count"] > 0):
        raise contradiction("script_presence disagrees with script_count")
    if f["parse_errors"] > f["files_analyzed"]:
        raise contradiction("more parse errors than analyzed files")
    occurrences: dict[str, int] = {}
    for g in result.findings:
        if g.rule.kind not in _KIND_FEATURE:
            raise contradiction("a static finding has an unknown kind")
        occurrences[g.rule.kind] = occurrences.get(g.rule.kind, 0) + g.occurrences
    for kind, total in occurrences.items():
        if total > f[_KIND_FEATURE[kind]]:
            raise contradiction("static findings exceed their feature count", kind=kind)


def _check_aibom(doc: dict[str, Any], files: set[str], file_count: int) -> None:
    analysis = model_analysis_from_aibom(doc)  # strict typing; raises analyzer_output_invalid
    inventory = analysis.inventory
    local = [f for f in inventory if f.downloaded]
    remote = [f for f in inventory if not f.downloaded]
    _subset((f.path for f in local), files, "an AI-BOM file")
    if any(canonical(f.path) in files for f in remote):
        raise contradiction("an AI-BOM file is marked not downloaded but is in the tree")
    if len({f.path for f in inventory}) != len(inventory):
        raise contradiction("the AI-BOM lists a file twice")
    if len(local) > file_count:
        raise contradiction("the AI-BOM lists more downloaded files than the tree holds")
    _subset((c.path for c in analysis.configs), files, "an AI-BOM config")
    code = analysis.custom_code
    _subset(
        [*code.scripts, *code.bytecode, *code.native_binaries, *code.requirement_files],
        files,
        "the AI-BOM custom-code list",
    )
    _subset((r.file for r in code.requirements), files, "an AI-BOM requirement")
    _subset((str(a["config"]) for a in analysis.adapters), files, "an AI-BOM adapter")
    summary = doc["summary"]
    expected = {
        "file_count": len(inventory),
        "files_downloaded": len(local),
        "weight_file_count": sum(1 for f in inventory if f.category == "weights"),
        "custom_code_present": code.present,
    }
    for key, value in expected.items():
        if summary[key] != value:
            raise contradiction("the AI-BOM summary disagrees with its file list", field=key)
    if summary["file_type_count"] > max(len(inventory), 0):
        raise contradiction("the AI-BOM summary counts more file types than files")


def check_analysis(analysis: AnalysisOut) -> None:
    """Every section of one analyze result must agree with the tree (see module docstring)."""
    tree = analysis.tree
    paths = [canonical(p) for p in analysis.file_paths]
    files = set(paths)
    if len(paths) != tree.file_count or len(files) != len(paths):
        raise contradiction("the file list does not match the tree's file count")
    if not all(_well_formed(p) for p in paths):
        raise contradiction("the file list holds a malformed path")
    _subset((m.path for m in analysis.manifests), files, "a manifest")
    _subset((p.manifest for p in analysis.project_packages), files, "a project package")
    if analysis.static is not None:
        _check_static(analysis.static, files, tree.file_count)
    if analysis.aibom is not None:
        _check_aibom(analysis.aibom, files, tree.file_count)


# --------------------------------------------------------------------------- SBOM
def check_sbom_locations(locations: Iterable[str], file_paths: Iterable[str]) -> None:
    """Real Syft locations are '/<path in the scanned tree>'; each must be a tree file."""
    files = {canonical(p) for p in file_paths}
    for location in locations:
        if canonical(location.lstrip("/")) not in files:
            raise contradiction("an SBOM component location is outside the scanned tree")

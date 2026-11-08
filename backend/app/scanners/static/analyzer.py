"""Whole-artifact static analysis: walks the tree, applies the scanners, builds features.

Features that describe code which was not analyzed are never reported as a clean 0: the
result lists everything skipped, and the pipeline marks such a stage `partial`.
"""

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from app.core.hashing import list_tree_files
from app.scanners.manifests import SKIPPED_DIRS
from app.scanners.model.custom_code import (
    BYTECODE_EXTENSIONS,
    NATIVE_EXTENSIONS,
    SCRIPT_EXTENSIONS,
)
from app.scanners.static import archive_anomaly as archives
from app.scanners.static.install_hooks import scan_package_json, scan_setup_py
from app.scanners.static.python_ast import Hit, analyze_python
from app.scanners.static.rules import (
    ARCHIVE_NOT_INSPECTED,
    KIND_API,
    KIND_ARCHIVE,
    KIND_IMPORT,
    KIND_INSTALL,
    Rule,
)
from app.scanners.static.text_scan import scan_text

MAX_NOT_ANALYZED_LISTED = 50
MAX_LINES_PER_FINDING = 20
MAX_SYMBOLS_PER_FINDING = 20
MAX_NOTEBOOK_CELLS = 2000
_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyw": "python",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".bat": "batch",
    ".cmd": "batch",
    ".ps1": "powershell",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".ipynb": "notebook",
}
_ALL_SCRIPT_SUFFIXES = SCRIPT_EXTENSIONS | frozenset(_LANGUAGE_BY_SUFFIX)


@dataclass(frozen=True)
class StaticLimits:
    max_files: int
    max_file_bytes: int
    max_total_bytes: int
    max_findings: int
    max_compression_ratio: float
    ratio_warn_fraction: float


@dataclass
class GroupedFinding:
    """All occurrences of one rule in one file."""

    rule: Rule
    file: str
    occurrences: int = 0
    lines: list[int] = field(default_factory=list)
    cells: list[int] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)


@dataclass
class StaticResult:
    features: dict[str, Any]
    findings: list[GroupedFinding]
    findings_truncated: bool
    not_analyzed: list[dict[str, str]]
    not_analyzed_count: int
    limitations: list[str]


def _storable(text: str) -> str:
    """Replace NUL, control characters and lone surrogates, which PostgreSQL rejects."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def _language(rel: str, head: bytes) -> str | None:
    suffix = PurePosixPath(rel).suffix.lower()
    if suffix:
        return _LANGUAGE_BY_SUFFIX.get(suffix)
    if not head.startswith(b"#!"):
        return None
    shebang = head.split(b"\n", 1)[0].lower()
    if b"python" in shebang:
        return "python"
    if b"node" in shebang:
        return "javascript"
    if b"sh" in shebang:
        return "shell"
    return None


def _skipped(rel: str) -> bool:
    return any(part in SKIPPED_DIRS for part in PurePosixPath(rel).parts)


def _analyze_notebook(raw: bytes) -> tuple[list[Hit], int]:
    """Parse the code cells of an .ipynb. Returns (hits, parse error count)."""
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return [], 1
    cells = data.get("cells") if isinstance(data, dict) else None
    if not isinstance(cells, list):
        return [], 1
    hits: list[Hit] = []
    errors = 0
    for index, cell in enumerate(cells[:MAX_NOTEBOOK_CELLS]):
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        source = cell.get("source")
        if isinstance(source, list):
            source = "".join(s for s in source if isinstance(s, str))
        if not isinstance(source, str):
            continue
        # IPython magics and shell escapes are not Python syntax.
        cleaned = "\n".join(
            "" if line.lstrip().startswith(("%", "!")) else line for line in source.splitlines()
        )
        result = analyze_python(cleaned, cell=index)
        hits.extend(result.hits)
        errors += int(result.parse_error is not None)
    return hits, errors


def _read_head(path: Path) -> bytes:
    with path.open("rb") as fh:
        return fh.read(archives.HEAD_BYTES)


class _Accumulator:
    def __init__(self) -> None:
        self.groups: dict[tuple[str, str], GroupedFinding] = {}
        self.counts = {KIND_IMPORT: 0, KIND_API: 0, KIND_INSTALL: 0, KIND_ARCHIVE: 0}

    def add(self, rel: str, hits: Iterable[Hit]) -> None:
        for hit in hits:
            self.counts[hit.rule.kind] += 1
            group = self.groups.setdefault(
                (hit.rule.id, rel), GroupedFinding(rule=hit.rule, file=rel)
            )
            group.occurrences += 1
            if hit.line is not None and len(group.lines) < MAX_LINES_PER_FINDING:
                group.lines.append(hit.line)
            if hit.cell is not None and len(group.cells) < MAX_LINES_PER_FINDING:
                group.cells.append(hit.cell)
            symbol = _storable(hit.symbol)
            if symbol not in group.symbols and len(group.symbols) < MAX_SYMBOLS_PER_FINDING:
                group.symbols.append(symbol)


def analyze_artifact(
    src_dir: Path,
    limits: StaticLimits,
    *,
    upload_path: Path | None = None,
    max_tree_files: int | None = None,
    auto_map_targets: int = 0,
    pickle_dangerous_globals: int | None = None,
    undownloaded_files: int = 0,
) -> StaticResult:
    """Analyze the extracted artifact at `src_dir`. Artifact code is only read as text."""
    acc = _Accumulator()
    not_analyzed: list[dict[str, str]] = []
    not_analyzed_count = 0
    analyzed = parse_errors = script_count = bytecode_count = native_count = total_read = 0

    def skip(rel: str, reason: str) -> None:
        nonlocal not_analyzed_count
        not_analyzed_count += 1
        if len(not_analyzed) < MAX_NOT_ANALYZED_LISTED:
            not_analyzed.append({"file": rel[:512], "reason": reason})

    entries = list_tree_files(src_dir, max_files=max_tree_files)
    for raw_rel, path in entries:
        rel = os.fsdecode(raw_rel).encode("utf-8", "replace").decode("utf-8")
        if _skipped(rel):
            continue
        suffix = PurePosixPath(rel).suffix.lower()
        if suffix in BYTECODE_EXTENSIONS:
            bytecode_count += 1
        elif suffix in NATIVE_EXTENSIONS:
            native_count += 1
        if analyzed >= limits.max_files:
            skip(rel, "file budget reached")
            continue
        try:
            head = _read_head(path)
            size = path.stat().st_size
        except OSError as exc:
            skip(rel, f"unreadable ({exc.__class__.__name__})")
            continue
        analyzed += 1

        language = _language(rel, head)
        if suffix in _ALL_SCRIPT_SUFFIXES or language is not None:
            script_count += 1
        acc.add(rel, archives.check_identity(rel, head))
        if archives.is_zip_family(rel):
            acc.add(rel, archives.inspect_nested_zip(path, limits.max_compression_ratio))
        elif archives.is_opaque_archive(rel):
            acc.add(rel, [Hit(ARCHIVE_NOT_INSPECTED, PurePosixPath(rel).name[:120])])

        name = PurePosixPath(rel).name
        if language is None and name != "package.json":
            continue
        if size > limits.max_file_bytes:
            skip(rel, "file exceeds the per-file analysis limit")
            continue
        if total_read + size > limits.max_total_bytes:
            skip(rel, "total analysis budget reached")
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            skip(rel, f"unreadable ({exc.__class__.__name__})")
            continue
        total_read += len(raw)

        if name == "package.json":
            acc.add(rel, scan_package_json(raw))
            continue
        if name == "setup.py":
            acc.add(rel, scan_setup_py(raw))
        if language == "python":
            result = analyze_python(raw)
            acc.add(rel, result.hits)
            if result.parse_error is not None:
                parse_errors += 1
                acc.add(rel, scan_text(raw.decode("utf-8", "replace"), "python_unparsed"))
        elif language == "notebook":
            hits, errors = _analyze_notebook(raw)
            acc.add(rel, hits)
            parse_errors += errors
        elif language is not None:
            acc.add(rel, scan_text(raw.decode("utf-8", "replace"), language))

    if upload_path is not None and upload_path.is_file():
        acc.add(
            "(uploaded archive)",
            archives.inspect_upload_ratio(
                upload_path, limits.max_compression_ratio, limits.ratio_warn_fraction
            ),
        )

    limitations = [
        "Static rules show what code can do; a match is not evidence of malice.",
        "Python aliases are tracked per file without scopes; heavily obfuscated code can evade "
        "these rules.",
        "Nested tar, 7z and rar archives are flagged but not inspected.",
    ]
    if undownloaded_files:
        not_analyzed_count += undownloaded_files
        limitations.append(
            f"{undownloaded_files} listed file(s) were not downloaded, so they were not analyzed."
        )
    if parse_errors:
        limitations.append(
            f"{parse_errors} file(s) or notebook cell(s) could not be parsed; only text rules "
            "applied to unparseable Python files."
        )

    ordered = sorted(
        acc.groups.values(),
        key=lambda g: (_SEVERITY_ORDER.get(g.rule.severity, 3), g.file, g.rule.id),
    )
    features = {
        "dangerous_import_count": acc.counts[KIND_IMPORT],
        "suspicious_api_count": acc.counts[KIND_API],
        "script_presence": script_count > 0,
        "archive_anomaly": acc.counts[KIND_ARCHIVE],
        "script_count": script_count,
        "bytecode_count": bytecode_count,
        "native_binary_count": native_count,
        "files_analyzed": analyzed,
        "parse_errors": parse_errors,
        "install_hook_count": acc.counts[KIND_INSTALL] + auto_map_targets,
        "pickle_dangerous_global_count": pickle_dangerous_globals,
    }
    return StaticResult(
        features=features,
        findings=ordered[: limits.max_findings],
        findings_truncated=len(ordered) > limits.max_findings,
        not_analyzed=not_analyzed,
        not_analyzed_count=not_analyzed_count,
        limitations=limitations,
    )

"""Features that need a comparison: this scan against a prior one, or declared versions.

Artifact files are untrusted. They are only read as bounded JSON or TOML text, and links are
not followed. Anything that cannot be determined is None, never a clean result.
"""

import hashlib
import json
import logging
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import networkx as nx

from app.scanners.model.config_parse import is_config_path

logger = logging.getLogger(__name__)

MAX_MANIFEST_BYTES = 1024 * 1024
_RELEASE_TAG_RE = re.compile(r"^v?\d+\.\d+")


@dataclass(frozen=True)
class ScanSnapshot:
    """The parts of a scan that a later scan of the same source is compared against."""

    config_sha256: str | None
    edges: frozenset[tuple[str, str]]
    max_centrality: float | None
    attestation_present: bool | None


def _is_plain_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def config_digest(src_dir: Path) -> str | None:
    """A digest over every config file (path and content), or None when there are none."""
    digest = hashlib.sha256()
    found = False
    for path in sorted(src_dir.rglob("*")):
        rel = path.relative_to(src_dir).as_posix()
        if _is_plain_file(path) and is_config_path(rel):
            digest.update(rel.encode("utf-8", "replace") + b"\0" + path.read_bytes() + b"\0")
            found = True
    return digest.hexdigest() if found else None


def graph_edges(graph: nx.DiGraph) -> frozenset[tuple[str, str]]:
    """Edges by node label, so they compare by content across scans."""

    def label(node: str) -> str:
        return str(graph.nodes[node].get("label", node))

    return frozenset((label(u), label(v)) for u, v in graph.edges)


def max_centrality(graph: nx.DiGraph) -> float | None:
    values = [
        data["betweenness_centrality"]
        for _, data in graph.nodes(data=True)
        if "betweenness_centrality" in data
    ]
    return max(values) if values else None


def compare_snapshots(prior: ScanSnapshot, current: ScanSnapshot) -> dict[str, Any]:
    """Compare two scans of one source. A side that lacks the evidence yields None."""
    config_changed = None
    if prior.config_sha256 is not None and current.config_sha256 is not None:
        config_changed = prior.config_sha256 != current.config_sha256
    shift = None
    if prior.max_centrality is not None and current.max_centrality is not None:
        shift = round(abs(current.max_centrality - prior.max_centrality), 6)
    removed = None
    if prior.attestation_present is not None and current.attestation_present is not None:
        removed = prior.attestation_present and not current.attestation_present
    return {
        "config_changed": config_changed,
        "new_edge_count": len(current.edges - prior.edges),
        "centrality_shift": shift,
        "provenance_removed": removed,
    }


def _read_bounded(path: Path) -> bytes | None:
    if not _is_plain_file(path) or path.stat().st_size > MAX_MANIFEST_BYTES:
        return None
    return path.read_bytes()


def _json_version(path: Path, key: str) -> str | None:
    raw = _read_bounded(path)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        logger.warning("Could not read a version from %s: %s", path.name, type(exc).__name__)
        return None
    value = data.get(key) if isinstance(data, dict) else None
    return value if isinstance(value, str) and value else None


def _pyproject_version(path: Path) -> str | None:
    raw = _read_bounded(path)
    if raw is None:
        return None
    try:
        project = tomllib.loads(raw.decode("utf-8")).get("project")
    except (ValueError, RecursionError) as exc:
        logger.warning("Could not read a version from %s: %s", path.name, type(exc).__name__)
        return None
    value = project.get("version") if isinstance(project, dict) else None
    return value if isinstance(value, str) and value else None


def _normalize(version: str) -> str:
    return version.strip().lower().removeprefix("v")


def declared_versions(src_dir: Path, revision: str | None) -> dict[str, str]:
    """Every version the artifact declares, by where it was declared."""
    found = {
        "pyproject.toml": _pyproject_version(src_dir / "pyproject.toml"),
        "package.json": _json_version(src_dir / "package.json", "version"),
        "config.json": _json_version(src_dir / "config.json", "model_version"),
        "release_tag": revision if revision and _RELEASE_TAG_RE.match(revision) else None,
    }
    return {where: _normalize(value) for where, value in found.items() if value}


def version_consistency(versions: dict[str, str]) -> bool | None:
    """True when all declared versions agree; None when fewer than two can be compared."""
    if len(versions) < 2:
        return None
    return len(set(versions.values())) == 1

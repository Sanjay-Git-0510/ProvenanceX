"""Detection of dependency manifests and lockfiles, and of the project's own package.

Manifests are only listed here; Syft (Phase 2) parses them. `detect_project_packages`
reads the top-level package.json / pyproject.toml name and version, so the SBOM entry
for the project itself can be treated as the artifact root instead of a dependency.

The `.git` and `node_modules` directories are skipped, so vendored dependency trees do
not swamp the list. Phase 2's Syft scan covers installed dependencies. Symlinks are
never followed.
"""

import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

MAX_MANIFESTS = 1000
MAX_PROJECT_MANIFEST_BYTES = 1024 * 1024
SKIPPED_DIRS = frozenset({".git", "node_modules"})

# filename -> (ecosystem, kind). kind is one of: manifest | lockfile | container
_EXACT: dict[str, tuple[str, str]] = {
    "pyproject.toml": ("pypi", "manifest"),
    "setup.py": ("pypi", "manifest"),
    "setup.cfg": ("pypi", "manifest"),
    "Pipfile": ("pypi", "manifest"),
    "Pipfile.lock": ("pypi", "lockfile"),
    "poetry.lock": ("pypi", "lockfile"),
    "uv.lock": ("pypi", "lockfile"),
    "package.json": ("npm", "manifest"),
    "package-lock.json": ("npm", "lockfile"),
    "npm-shrinkwrap.json": ("npm", "lockfile"),
    "yarn.lock": ("npm", "lockfile"),
    "pnpm-lock.yaml": ("npm", "lockfile"),
    "go.mod": ("go", "manifest"),
    "go.sum": ("go", "lockfile"),
    "Cargo.toml": ("cargo", "manifest"),
    "Cargo.lock": ("cargo", "lockfile"),
    "pom.xml": ("maven", "manifest"),
    "build.gradle": ("gradle", "manifest"),
    "build.gradle.kts": ("gradle", "manifest"),
    "gradle.lockfile": ("gradle", "lockfile"),
    "Gemfile": ("rubygems", "manifest"),
    "Gemfile.lock": ("rubygems", "lockfile"),
    "composer.json": ("composer", "manifest"),
    "composer.lock": ("composer", "lockfile"),
    "packages.config": ("nuget", "manifest"),
    "packages.lock.json": ("nuget", "lockfile"),
    "Dockerfile": ("docker", "container"),
    "Containerfile": ("docker", "container"),
}
_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^requirements[\w.-]*\.txt$"), "pypi", "manifest"),
    (re.compile(r"^.+\.csproj$"), "nuget", "manifest"),
]


@dataclass(frozen=True)
class Manifest:
    path: str
    ecosystem: str
    kind: str


@dataclass(frozen=True)
class ManifestScan:
    manifests: list[Manifest]
    truncated: bool


def classify(filename: str) -> tuple[str, str] | None:
    """Return (ecosystem, kind) for a known manifest filename, else None."""
    if filename in _EXACT:
        return _EXACT[filename]
    for pattern, ecosystem, kind in _PATTERNS:
        if pattern.match(filename):
            return ecosystem, kind
    return None


def detect_manifests(root: Path, *, limit: int = MAX_MANIFESTS) -> ManifestScan:
    found: list[Manifest] = []
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIPPED_DIRS)
        current = Path(dirpath)
        for name in sorted(filenames):
            match = classify(name)
            if match is None or (current / name).is_symlink():
                continue
            if len(found) >= limit:
                truncated = True
                break
            rel = (current / name).relative_to(root).as_posix()
            found.append(Manifest(path=rel, ecosystem=match[0], kind=match[1]))
        if truncated:
            break
    found.sort(key=lambda m: m.path)
    return ManifestScan(manifests=found, truncated=truncated)


@dataclass(frozen=True)
class ProjectPackage:
    """The scanned project's own package, as declared by its top-level manifest."""

    ecosystem: str  # npm | pypi
    name: str
    version: str | None
    manifest: str


def normalize_package_name(ecosystem: str | None, name: str) -> str:
    """Comparable name: PEP 503 for PyPI, lowercase otherwise."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def _read_small(path: Path) -> bytes | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > MAX_PROJECT_MANIFEST_BYTES:
            return None
        return path.read_bytes()
    except OSError:
        return None


def _text(value: object) -> str | None:
    return value.strip()[:255] if isinstance(value, str) and value.strip() else None


def detect_project_packages(root: Path) -> list[ProjectPackage]:
    """Name/version of the project itself from top-level package.json and pyproject.toml.

    Malformed manifests are ignored (they are untrusted input, and Syft reports on them).
    """
    found: list[ProjectPackage] = []
    raw = _read_small(root / "package.json")
    if raw is not None:
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, ValueError, RecursionError):
            data = None
        if isinstance(data, dict) and (name := _text(data.get("name"))):
            found.append(ProjectPackage("npm", name, _text(data.get("version")), "package.json"))
    raw = _read_small(root / "pyproject.toml")
    if raw is not None:
        try:
            data = tomllib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
            data = None
        if isinstance(data, dict):
            project = data.get("project")
            tool = data.get("tool")
            poetry = tool.get("poetry") if isinstance(tool, dict) else None
            for table in (project, poetry):
                if isinstance(table, dict) and (name := _text(table.get("name"))):
                    found.append(
                        ProjectPackage("pypi", name, _text(table.get("version")), "pyproject.toml")
                    )
                    break
    return found

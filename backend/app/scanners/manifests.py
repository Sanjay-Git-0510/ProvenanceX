"""Detection of dependency manifests and lockfiles. This only lists them; Phase 2 parses them.

The `.git` and `node_modules` directories are skipped, so vendored dependency trees do
not swamp the list. Phase 2's Syft scan covers installed dependencies. Symlinks are
never followed.
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path

MAX_MANIFESTS = 1000
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

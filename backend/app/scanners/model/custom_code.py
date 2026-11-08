"""Custom-code presence in a model repository (listing only; app/scanners/static analyzes it).

Records:
- script files (*.py, shell, notebooks) and native binaries (*.so, *.dll, *.dylib)
- `auto_map` targets from configs, which make transformers import repo code when
  trust_remote_code=True
- pinned runtime requirements from requirements*.txt (`name==version` lines only)
Nothing is imported or executed.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from app.scanners.model.config_parse import ParsedConfig

SCRIPT_EXTENSIONS = frozenset({".py", ".pyw", ".sh", ".bash", ".bat", ".cmd", ".ps1", ".ipynb"})
BYTECODE_EXTENSIONS = frozenset({".pyc", ".pyo"})
NATIVE_EXTENSIONS = frozenset({".so", ".dll", ".dylib", ".exe", ".pyd"})
MAX_REQUIREMENTS_BYTES = 256 * 1024
MAX_REQUIREMENTS = 500
MAX_LISTED = 200

_REQ_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?"
_EXTRAS = r"(?:\[[A-Za-z0-9,._ -]{0,200}\])?"
_PIN_RE = re.compile(rf"^({_REQ_NAME}){_EXTRAS}\s*==\s*([A-Za-z0-9.+!_-]{{1,64}})$")
_NAME_RE = re.compile(rf"^({_REQ_NAME})")
_REQUIREMENTS_RE = re.compile(r"^requirements[\w.-]*\.txt$")


@dataclass(frozen=True)
class Requirement:
    name: str
    version: str | None  # None = not exactly pinned
    file: str


@dataclass
class CustomCode:
    scripts: list[str] = field(default_factory=list)
    bytecode: list[str] = field(default_factory=list)
    native_binaries: list[str] = field(default_factory=list)
    auto_map: dict[str, dict[str, str]] = field(default_factory=dict)  # config path -> map
    requirements: list[Requirement] = field(default_factory=list)
    requirement_files: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def present(self) -> bool:
        return bool(self.scripts or self.bytecode or self.native_binaries or self.auto_map)

    @property
    def remote_code_required(self) -> bool:
        return bool(self.auto_map)

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "remote_code_required": self.remote_code_required,
            "scripts": self.scripts,
            "bytecode": self.bytecode,
            "native_binaries": self.native_binaries,
            "auto_map": self.auto_map,
            "requirement_files": self.requirement_files,
            "requirements": [
                {"name": r.name, "version": r.version, "file": r.file} for r in self.requirements
            ],
            "truncated": self.truncated,
        }


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(raw: bytes, rel: str) -> list[Requirement]:
    out: list[Requirement] = []
    text = raw[:MAX_REQUIREMENTS_BYTES].decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.split(" #", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http:", "https:", "file:")):
            continue
        pinned = _PIN_RE.match(line)
        if pinned:
            out.append(Requirement(normalize_pypi_name(pinned.group(1)), pinned.group(2), rel))
        elif named := _NAME_RE.match(line):
            out.append(Requirement(normalize_pypi_name(named.group(1)), None, rel))
        if len(out) >= MAX_REQUIREMENTS:
            break
    return out


def detect_custom_code(
    src_dir: Path, rel_paths: list[str], configs: list[ParsedConfig]
) -> CustomCode:
    cc = CustomCode()
    for rel in rel_paths:
        suffix = PurePosixPath(rel).suffix.lower()
        bucket = (
            cc.scripts
            if suffix in SCRIPT_EXTENSIONS
            else cc.bytecode
            if suffix in BYTECODE_EXTENSIONS
            else cc.native_binaries
            if suffix in NATIVE_EXTENSIONS
            else None
        )
        if bucket is not None:
            if len(bucket) < MAX_LISTED:
                bucket.append(rel)
            else:
                cc.truncated = True
        name = PurePosixPath(rel).name
        if _REQUIREMENTS_RE.match(name) and rel.count("/") <= 1:
            path = src_dir / rel
            try:
                if path.stat().st_size <= MAX_REQUIREMENTS_BYTES:
                    cc.requirement_files.append(rel)
                    cc.requirements.extend(parse_requirements(path.read_bytes(), rel))
            except OSError:
                continue
    for cfg in configs:
        if cfg.auto_map:
            cc.auto_map[cfg.path] = cfg.auto_map
    return cc

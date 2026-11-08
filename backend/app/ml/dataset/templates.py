"""Synthetic artifact families: the clean state that tampering recipes start from.

A family is one fictional project or model. Its traits are drawn from a seeded generator, and
some traits deliberately overlap with tampered cases (benign tooling that uses subprocess, no
attestation, pickle weights), so that no single trait perfectly predicts a label.
"""

import copy
import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

SEEDS_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "ml" / "seeds"

# An empty dict in pickle protocol 2. It is written as bytes and only ever parsed.
BENIGN_PICKLE = b"\x80\x02}q\x00."
SOFTWARE_SHARE = 0.5
LORA_SHARE_OF_AI = 0.4
UPLOAD_SHARE = 0.1
ATTESTATION_SHARE = 0.5
TAG_SHARE = 0.6
TOOLING_SHARE = 0.25
CUSTOM_CODE_SHARE = 0.2
PICKLE_SHARE = 0.25
FULL_CARD_SHARE = 0.7
FAMILY_STREAM = 11


def read_seed(name: str, project: str) -> bytes:
    return (SEEDS_DIR / name).read_text(encoding="utf-8").replace("{{NAME}}", project).encode()


def fake_commit(*parts: object) -> str:
    return hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()[:40]


@dataclass(frozen=True)
class Family:
    index: int
    family_id: str
    name: str
    artifact_type: str  # software | model | lora
    ecosystem: str  # pypi | npm
    source: str  # github | huggingface | upload
    has_attestation: bool
    uses_tag: bool
    has_tooling: bool
    custom_code: bool
    pickle_weights: bool
    full_card: bool
    component_count: int
    major: int
    minor: int

    @property
    def is_software(self) -> bool:
        return self.artifact_type == "software"

    @property
    def is_upload(self) -> bool:
        return self.source == "upload"

    @property
    def version(self) -> str:
        return f"{self.major}.{self.minor}.0"

    @property
    def source_url(self) -> str | None:
        host = "github.com/synthetic" if self.source == "github" else "huggingface.co/synthetic"
        return None if self.is_upload else f"https://{host}/{self.name}"

    @property
    def repo_id(self) -> str | None:
        return None if self.is_software or self.is_upload else f"synthetic/{self.name}"


@dataclass
class ArtifactState:
    """Everything a variant can change. Recipes mutate a deep copy."""

    files: dict[str, bytes]
    components: list[tuple[str, str]]  # (name, version)
    edges: list[tuple[str, str]]  # (parent name or "root", child name)
    commit: str
    revision: str | None
    advisories: list[dict[str, Any]] = field(default_factory=list)
    trace_kind: str = "benign"

    def clone(self) -> "ArtifactState":
        return copy.deepcopy(self)


def build_family(index: int, seed: int) -> Family:
    rng = np.random.default_rng([seed, index, FAMILY_STREAM])
    is_software = rng.random() < SOFTWARE_SHARE
    artifact_type = "software"
    if not is_software:
        artifact_type = "lora" if rng.random() < LORA_SHARE_OF_AI else "model"
    ecosystem = str(rng.choice(["pypi", "npm"])) if is_software else "pypi"
    remote = "github" if is_software else "huggingface"
    return Family(
        index=index,
        family_id=f"family-{index:04d}",
        name=f"synth-{artifact_type}-{index:04d}",
        artifact_type=artifact_type,
        ecosystem=ecosystem,
        source="upload" if rng.random() < UPLOAD_SHARE else remote,
        has_attestation=bool(rng.random() < ATTESTATION_SHARE),
        uses_tag=bool(rng.random() < TAG_SHARE),
        has_tooling=bool(rng.random() < TOOLING_SHARE),
        custom_code=not is_software and bool(rng.random() < CUSTOM_CODE_SHARE),
        pickle_weights=not is_software and bool(rng.random() < PICKLE_SHARE),
        full_card=bool(rng.random() < FULL_CARD_SHARE),
        component_count=int(rng.integers(3, 25)) if is_software else int(rng.integers(2, 7)),
        major=int(rng.integers(1, 6)),
        minor=int(rng.integers(1, 12)),
    )


def safetensors_bytes() -> bytes:
    header = {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}
    raw = json.dumps(header).encode()
    return struct.pack("<Q", len(raw)) + raw + bytes(16)


def _components(family: Family, rng: np.random.Generator) -> list[tuple[str, str]]:
    base = int(rng.integers(0, 900))
    return [
        (f"synthlib-{base + i:04d}", f"{int(rng.integers(0, 5))}.{int(rng.integers(0, 20))}.0")
        for i in range(family.component_count)
    ]


def _edges(components: list[tuple[str, str]], rng: np.random.Generator) -> list[tuple[str, str]]:
    """Each package hangs off the root or an earlier package, giving varied depth."""
    edges: list[tuple[str, str]] = []
    for i, (name, _) in enumerate(components):
        if i == 0 or rng.random() < 0.4:
            edges.append(("root", name))
        else:
            edges.append((components[int(rng.integers(0, i))][0], name))
    return edges


def _software_files(family: Family, version: str, comps: list[tuple[str, str]]) -> dict[str, bytes]:
    package = family.name.replace("-", "_")
    files = {
        "README.md": f"# {family.name}\n\nSynthetic fixture project.\n".encode(),
        f"src/{package}/__init__.py": b'"""Synthetic fixture package."""\n',
        f"src/{package}/core.py": read_seed("benign_module.py.txt", family.name),
    }
    if family.ecosystem == "pypi":
        files["pyproject.toml"] = (
            f'[project]\nname = "{family.name}"\nversion = "{version}"\n'.encode()
        )
        files["requirements.txt"] = "".join(f"{n}=={v}\n" for n, v in comps).encode()
    else:
        manifest = {"name": family.name, "version": version}
        manifest["dependencies"] = {n: v for n, v in comps}
        files["package.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
    return files


def _model_card(family: Family, base_model: str) -> bytes:
    if not family.full_card:
        return f"# {family.name}\n\nSynthetic fixture model.\n".encode()
    return (
        "---\nlicense: apache-2.0\n"
        f"base_model: {base_model}\ndatasets:\n- synthetic/dataset-{family.index:04d}\n"
        "pipeline_tag: text-generation\nlibrary_name: transformers\nlanguage: en\n---\n"
        f"# {family.name}\n\nSynthetic fixture model.\n"
    ).encode()


def _model_files(family: Family, version: str, comps: list[tuple[str, str]]) -> dict[str, bytes]:
    base_model = f"synthetic/base-{family.index % 7}"
    config: dict[str, Any] = {
        "model_type": "synthetic",
        "model_version": version,
        "hidden_size": 64 + family.index % 8,
    }
    files = {
        "README.md": _model_card(family, base_model),
        "requirements.txt": "".join(f"{n}=={v}\n" for n, v in comps).encode(),
        "tokenizer_config.json": b'{"model_max_length": 512}',
    }
    if family.custom_code:
        files["modeling_custom.py"] = read_seed("benign_module.py.txt", family.name)
        config["auto_map"] = {"AutoModel": "modeling_custom.Item"}
    files["config.json"] = json.dumps(config, indent=2, sort_keys=True).encode()
    if family.artifact_type == "lora":
        adapter = {"peft_type": "LORA", "base_model_name_or_path": base_model, "r": 8}
        files["adapter_config.json"] = json.dumps(adapter, sort_keys=True).encode()
        files["adapter_model.safetensors"] = safetensors_bytes()
    elif family.pickle_weights:
        files["pytorch_model.pkl"] = BENIGN_PICKLE
    else:
        files["model.safetensors"] = safetensors_bytes()
    return files


def _build(family: Family, seed: int, older: bool) -> ArtifactState:
    # One stream for both releases, so the older release differs only where intended.
    rng = np.random.default_rng([seed, family.index, FAMILY_STREAM + 1])
    comps = _components(family, rng)
    edges = _edges(comps, rng)
    version = f"{family.major}.{family.minor - 1}.0" if older else family.version
    if older and len(comps) > 2:
        dropped = comps[-1][0]
        comps = comps[:-1]
        edges = [e for e in edges if dropped not in e]
    files = (
        _software_files(family, version, comps)
        if family.is_software
        else _model_files(family, version, comps)
    )
    if family.has_tooling:
        files["tools/dev_tool.py"] = read_seed("benign_tooling.py.txt", family.name)
    if family.has_attestation:
        files["release.intoto.jsonl"] = b'{"_type":"https://in-toto.io/Statement/v1"}\n'
        files["release.sig"] = b"synthetic-signature-placeholder\n"
    if older and "README.md" in files:
        files["README.md"] += b"\nPrevious release notes.\n"
    if older and "config.json" in files:
        config = json.loads(files["config.json"])
        config["hidden_size"] += 8
        files["config.json"] = json.dumps(config, indent=2, sort_keys=True).encode()
    commit = fake_commit(family.family_id, version)
    if family.is_upload:
        revision = None
    elif family.uses_tag:
        revision = f"v{version}"
    else:
        revision = commit
    return ArtifactState(files, comps, edges, commit, revision)


def baseline_state(family: Family, seed: int) -> ArtifactState:
    return _build(family, seed, older=False)


def older_release_state(family: Family, seed: int) -> ArtifactState:
    """The previous release: a legitimate new version changes hash, config and edges."""
    return _build(family, seed, older=True)

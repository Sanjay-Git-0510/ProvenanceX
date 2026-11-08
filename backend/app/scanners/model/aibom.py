"""AI-BOM assembly (pipeline step 5): files, formats, configs, adapters, lineage, deps.

`analyze_model` runs every parse-only analyzer over the workspace and returns a
ModelAnalysis. `ModelAnalysis.aibom` is the AI-BOM document (format
`provenancex-aibom-v1`). It is ProvenanceX-specific JSON whose concepts follow CycloneDX
ML-BOM where practical: model files, the model's framework and serialization, its
configuration, adapters, base models (`derived_from` / `fine_tuned_from`), datasets
(`trained_on`) and runtime dependencies.

Lineage comes only from what the artifact declares (adapter_config, model card, config).
Declared parents are not fetched or verified here.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.scanners.model.config_parse import ParsedConfig, is_config_path, parse_config_file
from app.scanners.model.custom_code import CustomCode, Requirement, detect_custom_code
from app.scanners.model.inventory import InventoryFile, RemoteOnlyFile, build_inventory
from app.scanners.model.model_card import ModelCard, card_from_api, parse_model_card
from app.scanners.model.pickle_scan import scan_pickle_file
from app.scanners.model.safetensors_header import parse_safetensors_header
from app.scanners.model.serialization import CODE_EXECUTING_FORMATS

AIBOM_FORMAT = "provenancex-aibom-v1"
MB = 1024 * 1024

_HUB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,95})?$")
_FINE_TUNE_RELATIONS = frozenset({"adapter", "finetune"})
_FORMAT_FRAMEWORKS = {
    "gguf": "gguf (llama.cpp)",
    "onnx": "onnx",
    "hdf5": "keras/tensorflow",
    "keras_zip": "keras",
    "tflite": "tflite",
    "msgpack": "flax",
    "pytorch_zip": "pytorch",
    "safetensors": "safetensors",
}


@dataclass
class ModelContext:
    """What the ingestion step learned about the artifact (beyond the local files)."""

    name: str
    artifact_type: str
    source: str
    source_url: str | None
    repo_id: str | None = None
    commit_sha: str | None = None
    remote_only: list[RemoteOnlyFile] = field(default_factory=list)
    remote_hashes: dict[str, str | None] = field(default_factory=dict)
    api_card_data: dict[str, Any] | None = None
    api_meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LineageRef:
    """A declared parent: base model or dataset."""

    ref_id: str
    relation: str  # fine_tuned_from | derived_from | trained_on
    origin: str  # adapter_config | model_card | config
    confidence: str = "declared"  # declared | weak
    revision: str | None = None
    declared_by: str | None = None  # file that declared it

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.ref_id,
            "relation": self.relation,
            "origin": self.origin,
            "confidence": self.confidence,
            "revision": self.revision,
            "declared_by": self.declared_by,
        }


@dataclass
class ModelAnalysis:
    inventory: list[InventoryFile]
    configs: list[ParsedConfig]
    card: ModelCard
    custom_code: CustomCode
    base_models: list[LineageRef]
    datasets: list[LineageRef]
    adapters: list[dict[str, Any]]
    frameworks: list[str]
    runtime_deps: list[Requirement]
    local_path_references: list[str]
    limitations: list[str]
    aibom: dict[str, Any] = field(default_factory=dict)

    @property
    def serialization_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.inventory:
            if f.category == "weights":
                key = f.serialization or "unknown"
                counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))


def _looks_like_hub_id(value: str) -> bool:
    return bool(_HUB_ID_RE.match(value)) and ".." not in value


def _add_ref(refs: list[LineageRef], ref: LineageRef) -> None:
    key = ref.ref_id.lower()
    if all(r.ref_id.lower() != key or r.relation != ref.relation for r in refs):
        refs.append(ref)


def _lineage(
    ctx: ModelContext, configs: list[ParsedConfig], card: ModelCard
) -> tuple[list[LineageRef], list[LineageRef], list[dict[str, Any]], list[str]]:
    bases: list[LineageRef] = []
    datasets: list[LineageRef] = []
    adapters: list[dict[str, Any]] = []
    local_refs: list[str] = []
    self_id = (ctx.repo_id or "").lower()

    for cfg in configs:
        if cfg.kind != "adapter" or not cfg.valid:
            continue
        base = cfg.fields.get("base_model_name_or_path")
        adapters.append(
            {
                "config": cfg.path,
                "peft_type": cfg.fields.get("peft_type"),
                "base_model": base,
                "base_revision": cfg.fields.get("revision"),
                "r": cfg.fields.get("r"),
                "lora_alpha": cfg.fields.get("lora_alpha"),
                "target_modules": cfg.fields.get("target_modules"),
                "task_type": cfg.fields.get("task_type"),
            }
        )
        if isinstance(base, str) and base:
            if _looks_like_hub_id(base):
                _add_ref(
                    bases,
                    LineageRef(
                        base,
                        "fine_tuned_from",
                        "adapter_config",
                        revision=cfg.fields.get("revision")
                        if isinstance(cfg.fields.get("revision"), str)
                        else None,
                        declared_by=cfg.path,
                    ),
                )
            else:
                local_refs.append(base[:256])

    relation_hint = str(card.metadata.get("base_model_relation") or "").lower()
    card_relation = "fine_tuned_from" if relation_hint in _FINE_TUNE_RELATIONS else "derived_from"
    if adapters and not relation_hint:
        card_relation = "fine_tuned_from"
    for base in card.metadata.get("base_model", []):
        if _looks_like_hub_id(base):
            _add_ref(bases, LineageRef(base, card_relation, "model_card", declared_by="README.md"))
        else:
            local_refs.append(base[:256])
    for ds in card.metadata.get("datasets", []):
        if _looks_like_hub_id(ds):
            _add_ref(datasets, LineageRef(ds, "trained_on", "model_card", declared_by="README.md"))

    declared = {b.ref_id.lower() for b in bases}
    for cfg in configs:
        if cfg.kind not in ("model", "pipeline") or not cfg.valid or cfg.path.count("/"):
            continue
        name = cfg.fields.get("_name_or_path")
        if not isinstance(name, str) or not name or name.lower() == self_id:
            continue
        if _looks_like_hub_id(name) and "/" in name:
            if name.lower() not in declared:
                _add_ref(
                    bases,
                    LineageRef(name, "derived_from", "config", "weak", declared_by=cfg.path),
                )
        elif name.startswith(("/", "./", "../", "~")) or "\\" in name:
            local_refs.append(name[:256])
    return bases, datasets, adapters, sorted(set(local_refs))


def _frameworks(
    configs: list[ParsedConfig], card: ModelCard, inventory: list[InventoryFile], ctx: ModelContext
) -> list[str]:
    found: set[str] = set()
    library = card.metadata.get("library_name") or ctx.api_meta.get("library_name")
    if isinstance(library, str) and library:
        found.add(library.lower()[:64])
    for cfg in configs:
        if cfg.kind == "model" and cfg.fields.get("transformers_version"):
            found.add("transformers")
        if cfg.kind == "adapter":
            found.add("peft")
        if cfg.kind == "pipeline":
            found.add("diffusers")
    for f in inventory:
        if f.serialization in _FORMAT_FRAMEWORKS and f.serialization_verified:
            found.add(_FORMAT_FRAMEWORKS[f.serialization])
    return sorted(found)


def _analyze_weights(src_dir: Path, inventory: list[InventoryFile], settings: Settings) -> None:
    for f in inventory:
        if not f.downloaded:
            continue
        path = src_dir / f.path
        if f.serialization == "safetensors":
            f.analysis["safetensors"] = parse_safetensors_header(path).to_dict()
        elif f.serialization in CODE_EXECUTING_FORMATS:
            f.analysis["pickle"] = scan_pickle_file(
                path,
                f.serialization,
                max_bytes=settings.pickle_max_mb * MB,
                max_opcodes=settings.pickle_max_opcodes,
            ).to_dict()


def analyze_model(src_dir: Path, ctx: ModelContext, settings: Settings) -> ModelAnalysis:
    inventory = build_inventory(
        src_dir,
        max_files=settings.max_artifact_files,
        remote_only=ctx.remote_only,
        remote_hashes=ctx.remote_hashes,
    )
    _analyze_weights(src_dir, inventory, settings)
    local = [f for f in inventory if f.downloaded]
    configs = [parse_config_file(src_dir / f.path, f.path) for f in local if is_config_path(f.path)]

    readme = next((f for f in local if f.path.lower() == "readme.md"), None)
    if readme is not None:
        card = parse_model_card(
            (src_dir / readme.path).read_bytes()[: settings.model_card_max_kb * 1024 + 1],
            max_bytes=settings.model_card_max_kb * 1024,
        )
    else:
        card = card_from_api(ctx.api_card_data)

    custom = detect_custom_code(src_dir, [f.path for f in local], configs)
    bases, datasets, adapters, local_refs = _lineage(ctx, configs, card)
    frameworks = _frameworks(configs, card, inventory, ctx)

    limitations: list[str] = []
    not_downloaded = [f for f in inventory if not f.downloaded]
    if not_downloaded:
        limitations.append(
            f"{len(not_downloaded)} file(s) were listed but not downloaded (size cap); they "
            "were not hashed locally or parsed, and their format is inferred from the name."
        )
    if any(f.serialization in ("onnx", "gguf", "hdf5", "tflite") for f in inventory):
        limitations.append(
            "ONNX/GGUF/HDF5/TFLite files are identified by magic bytes or extension only; "
            "their internals are not parsed."
        )
    if bases or datasets:
        limitations.append(
            "Lineage is declared by the artifact (adapter_config, model card, config). "
            "Declared parents are not fetched or verified."
        )

    analysis = ModelAnalysis(
        inventory=inventory,
        configs=configs,
        card=card,
        custom_code=custom,
        base_models=bases,
        datasets=datasets,
        adapters=adapters,
        frameworks=frameworks,
        runtime_deps=custom.requirements,
        local_path_references=local_refs,
        limitations=limitations,
    )
    analysis.aibom = build_aibom_document(ctx, analysis)
    return analysis


def build_aibom_document(ctx: ModelContext, a: ModelAnalysis) -> dict[str, Any]:
    weights = [f for f in a.inventory if f.category == "weights"]
    return {
        "format": AIBOM_FORMAT,
        "artifact": {
            "name": ctx.name,
            "artifact_type": ctx.artifact_type,
            "source": ctx.source,
            "source_url": ctx.source_url,
            "repo_id": ctx.repo_id,
            "commit_sha": ctx.commit_sha,
            "author": ctx.api_meta.get("author"),
            "last_modified": ctx.api_meta.get("last_modified"),
            "pipeline_tag": a.card.metadata.get("pipeline_tag") or ctx.api_meta.get("pipeline_tag"),
        },
        "frameworks": a.frameworks,
        "serialization_types": a.serialization_counts,
        "files": [f.to_dict() for f in a.inventory],
        "configs": [c.to_dict() for c in a.configs],
        "model_card": a.card.to_dict(),
        "adapters": a.adapters,
        "base_models": [b.to_dict() for b in a.base_models],
        "datasets": [d.to_dict() for d in a.datasets],
        "local_path_references": a.local_path_references,
        "custom_code": a.custom_code.to_dict(),
        "runtime_dependencies": [
            {"ecosystem": "pypi", "name": r.name, "version": r.version, "declared_in": r.file}
            for r in a.runtime_deps
        ],
        "summary": {
            "file_count": len(a.inventory),
            "files_downloaded": sum(1 for f in a.inventory if f.downloaded),
            "weight_file_count": len(weights),
            "file_type_count": len({f.serialization or f.category for f in a.inventory}),
            "code_executing_formats": sorted(
                {f.serialization for f in weights if f.serialization in CODE_EXECUTING_FORMATS}
            ),
            # Weights not downloaded whose extension allows pickle (unverified, by name).
            "unverified_possibly_pickle": sum(
                1 for f in weights if f.serialization == "pickle_or_pytorch"
            ),
            "custom_code_present": a.custom_code.present,
            "model_card_completeness": a.card.completeness if a.card.present else None,
            "license": a.card.metadata.get("license"),
        },
        "limitations": a.limitations,
    }

"""Parse model configuration files as data (JSON only). Nothing is imported or run.

Recognized files (at any depth up to MAX_CONFIG_DEPTH):
  config.json             transformers model config (model_type, architectures, auto_map)
  adapter_config.json     PEFT adapter (LoRA etc.): base model, rank, alpha, targets
  generation_config.json  presence only
  tokenizer_config.json   tokenizer class, auto_map
  model_index.json        diffusers pipeline (_class_name, version, components)
  preprocessor_config.json / processor_config.json  presence plus auto_map

`auto_map` entries name Python classes inside the repo. A transformers loader imports
them only with trust_remote_code=True, which is why their presence is recorded as
"custom code required".
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_CONFIG_BYTES = 1024 * 1024
MAX_CONFIG_DEPTH = 4
MAX_LIST_ITEMS = 64

CONFIG_FILENAMES = frozenset(
    {
        "config.json",
        "adapter_config.json",
        "generation_config.json",
        "tokenizer_config.json",
        "model_index.json",
        "preprocessor_config.json",
        "processor_config.json",
    }
)


@dataclass
class ParsedConfig:
    path: str
    kind: str  # model | adapter | generation | tokenizer | pipeline | processor
    valid: bool
    fields: dict[str, Any] = field(default_factory=dict)
    auto_map: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "valid": self.valid,
            "fields": self.fields,
            "auto_map": self.auto_map,
            "error": self.error,
        }


_KIND = {
    "config.json": "model",
    "adapter_config.json": "adapter",
    "generation_config.json": "generation",
    "tokenizer_config.json": "tokenizer",
    "model_index.json": "pipeline",
    "preprocessor_config.json": "processor",
    "processor_config.json": "processor",
}


def _short(value: Any, limit: int = 256) -> Any:
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, list):
        return [_short(v, limit) for v in value[:MAX_LIST_ITEMS] if not isinstance(v, dict | list)]
    return None


def _auto_map(data: dict[str, Any]) -> dict[str, str]:
    raw = data.get("auto_map")
    out: dict[str, str] = {}
    if isinstance(raw, dict):
        for key, value in list(raw.items())[:MAX_LIST_ITEMS]:
            # Values are "module.Class", ["module.Class", null], or "repo--module.Class".
            if isinstance(value, list):
                value = next((v for v in value if isinstance(v, str)), None)
            if isinstance(key, str) and isinstance(value, str):
                out[key[:128]] = value[:256]
    return out


def _extract(kind: str, data: dict[str, Any]) -> dict[str, Any]:
    keys: tuple[str, ...]
    if kind == "model":
        keys = (
            "model_type",
            "architectures",
            "_name_or_path",
            "torch_dtype",
            "transformers_version",
            "library_name",
        )
    elif kind == "adapter":
        keys = (
            "peft_type",
            "base_model_name_or_path",
            "revision",
            "r",
            "lora_alpha",
            "lora_dropout",
            "target_modules",
            "task_type",
            "inference_mode",
        )
    elif kind == "tokenizer":
        keys = ("tokenizer_class", "name_or_path")
    elif kind == "pipeline":
        keys = ("_class_name", "_diffusers_version", "_name_or_path")
    else:
        keys = ()
    fields = {k: _short(data[k]) for k in keys if k in data}
    if kind == "model":
        fields["quantization_config_present"] = "quantization_config" in data
    if kind == "pipeline":
        fields["components"] = sorted(
            k for k, v in data.items() if not k.startswith("_") and isinstance(v, list)
        )[:MAX_LIST_ITEMS]
    return fields


def parse_config_file(path: Path, rel: str) -> ParsedConfig:
    kind = _KIND.get(Path(rel).name, "other")
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            return ParsedConfig(rel, kind, False, error="config file exceeds 1 MB")
        data = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        return ParsedConfig(rel, kind, False, error=f"invalid JSON ({exc.__class__.__name__})")
    if not isinstance(data, dict):
        return ParsedConfig(rel, kind, False, error="config root is not a JSON object")
    return ParsedConfig(rel, kind, True, fields=_extract(kind, data), auto_map=_auto_map(data))


def is_config_path(rel: str) -> bool:
    parts = rel.split("/")
    return parts[-1] in CONFIG_FILENAMES and len(parts) <= MAX_CONFIG_DEPTH

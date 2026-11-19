"""Rebuild typed evidence objects from the analyzer's validated JSON.

The analyzer returns the AI-BOM document and the static result as JSON. These decoders turn
them back into the dataclasses the existing stages already consume, so the persistence code is
unchanged. Every field is type-checked; anything malformed raises analyzer_output_invalid
inside the stage that needed it (that stage fails; the scan does not silently accept it).
"""

from typing import Any

from app.core.errors import AppError, ErrorCode
from app.scanners.model.aibom import LineageRef, ModelAnalysis
from app.scanners.model.config_parse import ParsedConfig
from app.scanners.model.custom_code import CustomCode, Requirement
from app.scanners.model.inventory import InventoryFile
from app.scanners.model.model_card import ModelCard
from app.scanners.static.analyzer import GroupedFinding, StaticResult
from app.scanners.static.rules import Rule

_SEVERITIES = frozenset({"HIGH", "MEDIUM", "LOW", "INFO", "CRITICAL"})
# Upper bound for any count the analyzer reports (sanity, far above every real limit).
MAX_COUNT = 10_000_000
# The static feature vector: exactly these keys (audit finding M4).
STATIC_COUNT_FEATURES = frozenset(
    {
        "dangerous_import_count",
        "suspicious_api_count",
        "archive_anomaly",
        "script_count",
        "bytecode_count",
        "native_binary_count",
        "files_analyzed",
        "parse_errors",
        "install_hook_count",
    }
)
STATIC_FEATURES = STATIC_COUNT_FEATURES | {"script_presence", "pickle_dangerous_global_count"}
SUMMARY_KEYS = frozenset(
    {
        "file_count",
        "files_downloaded",
        "weight_file_count",
        "file_type_count",
        "code_executing_formats",
        "unverified_possibly_pickle",
        "custom_code_present",
        "model_card_completeness",
        "license",
    }
)
_MAX_DEPTH = 8
_MAX_CONFIG_LIST = 64


class _Bad(ValueError):
    pass


def _invalid(section: str) -> AppError:
    return AppError(
        ErrorCode.ANALYZER_OUTPUT_INVALID,
        f"The analyzer's {section} output failed validation",
        502,
        {"section": section},
    )


def _str(value: Any, *, optional: bool = False, limit: int = 4096) -> Any:
    if value is None and optional:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise _Bad("expected a string")
    return value


def _int(value: Any, *, optional: bool = False) -> Any:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _Bad("expected an integer")
    return value


def _count(value: Any, *, optional: bool = False) -> Any:
    """A non-negative, bounded integer."""
    value = _int(value, optional=optional)
    if value is not None and not 0 <= value <= MAX_COUNT:
        raise _Bad("count out of range")
    return value


def _size(value: Any) -> int:
    """A file size in bytes: non-negative (remote files may be far larger than MAX_COUNT)."""
    value = _int(value)
    if value < 0:
        raise _Bad("negative size")
    return value


def _json(value: Any, depth: int = 0) -> Any:
    """Plain, bounded-depth JSON (dicts with string keys, lists, scalars, finite numbers)."""
    if depth > _MAX_DEPTH:
        raise _Bad("nested too deeply")
    if isinstance(value, dict):
        for key, item in value.items():
            _str(key, limit=1024)
            _json(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _json(item, depth + 1)
    elif isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise _Bad("non-finite number")
    elif not (value is None or isinstance(value, str | int | bool)):
        raise _Bad("not JSON")
    return value


def _scalar(value: Any) -> Any:
    if isinstance(value, str):
        return _str(value, limit=256)
    if isinstance(value, float):
        return _json(value)
    if value is None or isinstance(value, bool | int):
        return value
    raise _Bad("expected a scalar")


def _config_value(value: Any) -> Any:
    """Config fields are bounded scalars or short lists of them (config_parse._short)."""
    if isinstance(value, list):
        if len(value) > _MAX_CONFIG_LIST:
            raise _Bad("config list too long")
        return [_scalar(v) for v in value]
    return _scalar(value)


def _features(value: Any) -> dict[str, Any]:
    features = _dict(value)
    if set(features) != STATIC_FEATURES:
        raise _Bad("unexpected static feature keys")
    for key in STATIC_COUNT_FEATURES:
        _count(features[key])
    _bool(features["script_presence"])
    _count(features["pickle_dangerous_global_count"], optional=True)
    return features


def _bool(value: Any, *, optional: bool = False) -> Any:
    if value is None and optional:
        return None
    if not isinstance(value, bool):
        raise _Bad("expected a boolean")
    return value


def _dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _Bad("expected an object")
    return value


def _list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise _Bad("expected a list")
    return value


def _strs(value: Any) -> list[str]:
    return [_str(v) for v in _list(value)]


# --------------------------------------------------------------------------- static
def static_from_dict(data: dict[str, Any]) -> StaticResult:
    try:
        findings = []
        for item in _list(data["findings"]):
            item = _dict(item)
            rule = _dict(item["rule"])
            severity = _str(rule["severity"], limit=16)
            if severity not in _SEVERITIES:
                raise _Bad("unknown severity")
            findings.append(
                GroupedFinding(
                    rule=Rule(
                        id=_str(rule["id"], limit=64),
                        kind=_str(rule["kind"], limit=64),
                        severity=severity,
                        title=_str(rule["title"], limit=256),
                    ),
                    file=_str(item["file"]),
                    occurrences=_count(item["occurrences"]),
                    lines=[_count(n) for n in _list(item["lines"])],
                    cells=[_count(n) for n in _list(item["cells"])],
                    symbols=_strs(item["symbols"]),
                )
            )
        not_analyzed = []
        for entry in _list(data["not_analyzed"]):
            entry = _dict(entry)
            not_analyzed.append({_str(k, limit=64): _str(v) for k, v in entry.items()})
        return StaticResult(
            features=_features(data["features"]),
            findings=findings,
            findings_truncated=_bool(data["findings_truncated"]),
            not_analyzed=not_analyzed,
            not_analyzed_count=_count(data["not_analyzed_count"]),
            limitations=_strs(data["limitations"]),
        )
    except (_Bad, KeyError, TypeError) as exc:
        raise _invalid("static analysis") from exc


# --------------------------------------------------------------------------- AI-BOM
def _inventory(d: dict[str, Any]) -> InventoryFile:
    return InventoryFile(
        path=_str(d["path"]),
        size=_size(d["size"]),
        category=_str(d["category"], limit=32),
        downloaded=_bool(d["downloaded"]),
        sha256=_str(d["sha256"], optional=True, limit=64),
        serialization=_str(d["serialization"], optional=True, limit=64),
        serialization_verified=_bool(d["serialization_verified"]),
        remote_sha256=_str(d.get("remote_sha256"), optional=True, limit=64),
        hash_verified=_bool(d.get("hash_verified"), optional=True),
        skip_reason=_str(d.get("skip_reason"), optional=True, limit=512),
        format_mismatch=_str(d.get("format_mismatch"), optional=True, limit=512),
        analysis=_json(_dict(d.get("analysis") or {})),
    )


def _config(d: dict[str, Any]) -> ParsedConfig:
    auto_map = {_str(k, limit=256): _str(v, limit=512) for k, v in _dict(d["auto_map"]).items()}
    return ParsedConfig(
        path=_str(d["path"]),
        kind=_str(d["kind"], limit=32),
        valid=_bool(d["valid"]),
        fields={_str(k, limit=256): _config_value(v) for k, v in _dict(d["fields"]).items()},
        auto_map=auto_map,
        error=_str(d.get("error"), optional=True, limit=2000),
    )


def _card(d: dict[str, Any]) -> ModelCard:
    completeness = d["completeness"]
    if isinstance(completeness, bool) or not isinstance(completeness, int | float):
        raise _Bad("completeness")
    if not 0 <= completeness <= 1:
        raise _Bad("completeness out of range")
    return ModelCard(
        present=_bool(d["present"]),
        source=_str(d.get("source"), optional=True, limit=32),
        metadata=_json(_dict(d["metadata"])),
        fields_present=_strs(d["fields_present"]),
        sections_present=_strs(d["sections_present"]),
        completeness=float(completeness),
        issues=_strs(d["issues"]),
    )


def _custom_code(d: dict[str, Any]) -> CustomCode:
    auto_map = {
        _str(path): {_str(k, limit=256): _str(v, limit=512) for k, v in _dict(m).items()}
        for path, m in _dict(d["auto_map"]).items()
    }
    requirements = [
        Requirement(
            name=_str(r["name"], limit=256),
            version=_str(r["version"], optional=True, limit=256),
            file=_str(r["file"]),
        )
        for r in (_dict(x) for x in _list(d["requirements"]))
    ]
    return CustomCode(
        scripts=_strs(d["scripts"]),
        bytecode=_strs(d["bytecode"]),
        native_binaries=_strs(d["native_binaries"]),
        auto_map=auto_map,
        requirements=requirements,
        requirement_files=_strs(d["requirement_files"]),
        truncated=_bool(d["truncated"]),
    )


def _lineage(d: dict[str, Any]) -> LineageRef:
    return LineageRef(
        ref_id=_str(d["id"], limit=1024),
        relation=_str(d["relation"], limit=64),
        origin=_str(d["origin"], limit=64),
        confidence=_str(d["confidence"], limit=32),
        revision=_str(d.get("revision"), optional=True, limit=256),
        declared_by=_str(d.get("declared_by"), optional=True),
    )


def _adapter(value: Any) -> dict[str, Any]:
    adapter = _json(_dict(value))
    _str(adapter["config"])  # the lineage graph keys nested adapters by their config path
    return adapter


def _summary(value: Any) -> None:
    summary = _dict(value)
    if set(summary) != SUMMARY_KEYS:
        raise _Bad("unexpected AI-BOM summary keys")
    for key in ("file_count", "files_downloaded", "weight_file_count", "file_type_count"):
        _count(summary[key])
    _count(summary["unverified_possibly_pickle"])
    _bool(summary["custom_code_present"])
    _strs(summary["code_executing_formats"])
    completeness = summary["model_card_completeness"]
    if completeness is not None and (
        isinstance(completeness, bool)
        or not isinstance(completeness, int | float)
        or not 0 <= completeness <= 1
    ):
        raise _Bad("model card completeness")
    _json(summary["license"])  # model-card metadata: a string, a list or absent
    if summary["files_downloaded"] > summary["file_count"]:
        raise _Bad("more downloaded files than files")
    if summary["weight_file_count"] > summary["file_count"]:
        raise _Bad("more weight files than files")


def model_analysis_from_aibom(doc: dict[str, Any]) -> ModelAnalysis:
    """Rebuild ModelAnalysis from the AI-BOM document (build_aibom_document's output)."""
    try:
        custom = _custom_code(_dict(doc["custom_code"]))
        analysis = ModelAnalysis(
            inventory=[_inventory(_dict(f)) for f in _list(doc["files"])],
            configs=[_config(_dict(c)) for c in _list(doc["configs"])],
            card=_card(_dict(doc["model_card"])),
            custom_code=custom,
            base_models=[_lineage(_dict(b)) for b in _list(doc["base_models"])],
            datasets=[_lineage(_dict(b)) for b in _list(doc["datasets"])],
            adapters=[_adapter(a) for a in _list(doc["adapters"])],
            frameworks=_strs(doc["frameworks"]),
            runtime_deps=custom.requirements,
            local_path_references=_strs(doc["local_path_references"]),
            limitations=_strs(doc["limitations"]),
        )
        _summary(doc["summary"])
        _str(doc["format"], limit=64)
    except (_Bad, KeyError, TypeError) as exc:
        raise _invalid("AI-BOM") from exc
    analysis.aibom = doc
    return analysis

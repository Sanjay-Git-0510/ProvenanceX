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
                    occurrences=_int(item["occurrences"]),
                    lines=[_int(n) for n in _list(item["lines"])],
                    cells=[_int(n) for n in _list(item["cells"])],
                    symbols=_strs(item["symbols"]),
                )
            )
        not_analyzed = []
        for entry in _list(data["not_analyzed"]):
            entry = _dict(entry)
            not_analyzed.append({_str(k, limit=64): _str(v) for k, v in entry.items()})
        return StaticResult(
            features=_dict(data["features"]),
            findings=findings,
            findings_truncated=_bool(data["findings_truncated"]),
            not_analyzed=not_analyzed,
            not_analyzed_count=_int(data["not_analyzed_count"]),
            limitations=_strs(data["limitations"]),
        )
    except (_Bad, KeyError, TypeError) as exc:
        raise _invalid("static analysis") from exc


# --------------------------------------------------------------------------- AI-BOM
def _inventory(d: dict[str, Any]) -> InventoryFile:
    return InventoryFile(
        path=_str(d["path"]),
        size=_int(d["size"]),
        category=_str(d["category"], limit=32),
        downloaded=_bool(d["downloaded"]),
        sha256=_str(d["sha256"], optional=True, limit=64),
        serialization=_str(d["serialization"], optional=True, limit=64),
        serialization_verified=_bool(d["serialization_verified"]),
        remote_sha256=_str(d.get("remote_sha256"), optional=True, limit=64),
        hash_verified=_bool(d.get("hash_verified"), optional=True),
        skip_reason=_str(d.get("skip_reason"), optional=True, limit=512),
        format_mismatch=_str(d.get("format_mismatch"), optional=True, limit=512),
        analysis=_dict(d.get("analysis") or {}),
    )


def _config(d: dict[str, Any]) -> ParsedConfig:
    auto_map = {_str(k, limit=256): _str(v, limit=512) for k, v in _dict(d["auto_map"]).items()}
    return ParsedConfig(
        path=_str(d["path"]),
        kind=_str(d["kind"], limit=32),
        valid=_bool(d["valid"]),
        fields=_dict(d["fields"]),
        auto_map=auto_map,
        error=_str(d.get("error"), optional=True, limit=2000),
    )


def _card(d: dict[str, Any]) -> ModelCard:
    completeness = d["completeness"]
    if isinstance(completeness, bool) or not isinstance(completeness, int | float):
        raise _Bad("completeness")
    return ModelCard(
        present=_bool(d["present"]),
        source=_str(d.get("source"), optional=True, limit=32),
        metadata=_dict(d["metadata"]),
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
    adapter = _dict(value)
    _str(adapter["config"])  # the lineage graph keys nested adapters by their config path
    return adapter


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
        _dict(doc["summary"])
        _str(doc["format"], limit=64)
    except (_Bad, KeyError, TypeError) as exc:
        raise _invalid("AI-BOM") from exc
    analysis.aibom = doc
    return analysis

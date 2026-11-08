"""CycloneDX JSON parser that produces normalized components and dependency edges.

The SBOM comes from a tool running on untrusted content, so it is treated as untrusted
input too:
- the size is checked before decoding, and deep nesting (RecursionError) is a parse error
- the component and dependency counts are capped before Pydantic validation
- string lengths are bounded by the schema
- edges to unknown refs, self-loops and duplicates are dropped and counted, not trusted
- `file` components (Syft lists manifest files as components) are kept out of the
  package list
"""

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.errors import AppError, ErrorCode

_PURL_RE = re.compile(r"^pkg:([a-zA-Z.+-][a-zA-Z0-9.+-]*)/[^\s]+$")
_MAX_PROPERTIES = 200
_MAX_LICENSES = 50
_MAX_DEPENDS_ON = 10000
# Ref prefixes ProvenanceX uses for its own graph keys (e.g. "artifact:root") and generated
# refs. SBOM refs that use them are renamed, so a crafted SBOM cannot impersonate the root.
RESERVED_REF_PREFIXES = ("artifact:", "provenancex:")


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class CdxProperty(_Model):
    name: str = Field(max_length=512)
    value: str | None = Field(default=None, max_length=8192)


class CdxLicense(_Model):
    id: str | None = Field(default=None, max_length=256)
    name: str | None = Field(default=None, max_length=1024)


class CdxLicenseChoice(_Model):
    license: CdxLicense | None = None
    expression: str | None = Field(default=None, max_length=2048)


class CdxComponent(_Model):
    bom_ref: str | None = Field(default=None, alias="bom-ref", max_length=2048)
    type: str = Field(max_length=64)
    name: str = Field(max_length=1024)
    version: str | None = Field(default=None, max_length=512)
    group: str | None = Field(default=None, max_length=1024)
    purl: str | None = Field(default=None, max_length=2048)
    cpe: str | None = Field(default=None, max_length=2048)
    licenses: list[CdxLicenseChoice] = Field(default_factory=list, max_length=_MAX_LICENSES)
    properties: list[CdxProperty] = Field(default_factory=list, max_length=_MAX_PROPERTIES)


class CdxDependency(_Model):
    ref: str = Field(max_length=2048)
    depends_on: list[str] = Field(
        default_factory=list, alias="dependsOn", max_length=_MAX_DEPENDS_ON
    )


class CdxMetadata(_Model):
    component: CdxComponent | None = None
    tools: Any = None


class CdxDocument(_Model):
    bom_format: Literal["CycloneDX"] = Field(alias="bomFormat")
    spec_version: str = Field(alias="specVersion", max_length=16)
    metadata: CdxMetadata | None = None
    components: list[CdxComponent] = Field(default_factory=list)
    dependencies: list[CdxDependency] = Field(default_factory=list)


@dataclass(frozen=True)
class ParsedComponent:
    bom_ref: str
    name: str
    version: str | None
    component_type: str
    purl: str | None
    ecosystem: str | None
    licenses: tuple[str, ...]
    cpe: str | None
    found_by: str | None
    locations: tuple[str, ...]


@dataclass
class ParsedSbom:
    spec_version: str
    root_ref: str | None
    root_name: str | None
    tools: list[str]
    components: list[ParsedComponent]
    edges: list[tuple[str, str]]
    stats: dict[str, int] = field(default_factory=dict)


def _parse_error(message: str, details: Any = None) -> AppError:
    return AppError(ErrorCode.SBOM_PARSE_ERROR, message, 422, details)


def purl_ecosystem(purl: str | None) -> str | None:
    """Package-URL type (e.g. 'pypi', 'npm'), or None if the purl is missing or malformed."""
    if not purl:
        return None
    match = _PURL_RE.match(purl)
    return match.group(1).lower() if match else None


def _licenses(choices: Iterable[CdxLicenseChoice]) -> tuple[str, ...]:
    out: list[str] = []
    for choice in choices:
        if choice.expression:
            out.append(choice.expression)
        elif choice.license and (choice.license.id or choice.license.name):
            out.append(choice.license.id or choice.license.name or "")
    return tuple(dict.fromkeys(out))


def _tool_names(tools: Any) -> list[str]:
    """CycloneDX 1.4 uses a list of tools; 1.5+ uses {"components": [...]}."""
    entries: Any = tools.get("components", []) if isinstance(tools, dict) else tools
    names: list[str] = []
    if isinstance(entries, list):
        for entry in entries[:20]:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                version = entry.get("version")
                names.append(
                    f"{entry['name'][:64]}@{str(version)[:32]}" if version else entry["name"][:64]
                )
    return names


def _normalize(comp: CdxComponent, bom_ref: str, stats: dict[str, int]) -> ParsedComponent:
    purl = comp.purl
    ecosystem = purl_ecosystem(purl)
    if purl and ecosystem is None:
        stats["invalid_purls"] += 1
        purl = None
    props = {p.name: p.value for p in comp.properties}
    locations = tuple(
        v for k, v in props.items() if k.startswith("syft:location:") and k.endswith(":path") and v
    )[:20]
    name = f"{comp.group}/{comp.name}" if comp.group and ecosystem != "maven" else comp.name
    return ParsedComponent(
        bom_ref=bom_ref,
        name=name[:1024],
        version=comp.version,
        component_type=comp.type,
        purl=purl,
        ecosystem=ecosystem,
        licenses=_licenses(comp.licenses),
        cpe=comp.cpe,
        found_by=props.get("syft:package:foundBy"),
        locations=locations,
    )


def parse_cyclonedx(raw: bytes, *, max_bytes: int, max_components: int) -> ParsedSbom:
    """Parse and normalize a CycloneDX JSON document. Raises AppError(SBOM_PARSE_ERROR)."""
    if len(raw) > max_bytes:
        raise AppError(
            ErrorCode.SBOM_TOO_LARGE,
            "SBOM exceeds the size limit",
            413,
            {"size_bytes": len(raw), "max_bytes": max_bytes},
        )
    try:
        data = json.loads(raw)
    except RecursionError as exc:
        raise _parse_error("SBOM JSON is nested too deeply") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise _parse_error("SBOM is not valid JSON", {"error": str(exc)[:200]}) from exc
    if not isinstance(data, dict):
        raise _parse_error("SBOM root must be a JSON object")

    for key, limit in (("components", max_components), ("dependencies", max_components)):
        value = data.get(key)
        if value is not None and not isinstance(value, list):
            raise _parse_error(f"SBOM '{key}' must be a list")
        if isinstance(value, list) and len(value) > limit:
            raise _parse_error(f"SBOM has too many {key}", {"count": len(value), "max": limit})

    try:
        doc = CdxDocument.model_validate(data)
    except ValidationError as exc:
        errors = [
            {"loc": [str(p) for p in e.get("loc", [])][:6], "msg": e.get("msg")}
            for e in exc.errors()[:5]
        ]
        raise _parse_error("SBOM does not match the CycloneDX schema", errors) from exc
    except RecursionError as exc:
        raise _parse_error("SBOM JSON is nested too deeply") from exc

    stats = {
        "raw_components": len(doc.components),
        "excluded_file_components": 0,
        "duplicate_refs": 0,
        "generated_refs": 0,
        "renamed_reserved_refs": 0,
        "invalid_purls": 0,
        "edges_declared": 0,
        "edges_unknown_ref": 0,
        "edges_self_loop": 0,
        "edges_duplicate": 0,
    }
    root = doc.metadata.component if doc.metadata else None
    root_ref = root.bom_ref if root else None

    components: list[ParsedComponent] = []
    seen: set[str] = set()
    renamed: dict[str, str] = {}
    for index, comp in enumerate(doc.components):
        if comp.type == "file":
            stats["excluded_file_components"] += 1
            continue
        bom_ref = comp.bom_ref
        if not bom_ref:
            bom_ref = f"provenancex:generated:{index}"
            stats["generated_refs"] += 1
        elif bom_ref.startswith(RESERVED_REF_PREFIXES) and bom_ref != root_ref:
            if bom_ref in renamed:
                stats["duplicate_refs"] += 1
                continue
            renamed[bom_ref] = f"provenancex:renamed:{index}"
            bom_ref = renamed[bom_ref]
            stats["renamed_reserved_refs"] += 1
        if bom_ref in seen or bom_ref == root_ref:
            stats["duplicate_refs"] += 1
            continue
        seen.add(bom_ref)
        components.append(_normalize(comp, bom_ref, stats))

    known = seen | ({root_ref} if root_ref else set())
    edges: list[tuple[str, str]] = []
    edge_set: set[tuple[str, str]] = set()
    for dep in doc.dependencies:
        source = renamed.get(dep.ref, dep.ref)
        for raw_target in dep.depends_on:
            target = renamed.get(raw_target, raw_target)
            stats["edges_declared"] += 1
            if source not in known or target not in known:
                stats["edges_unknown_ref"] += 1
                continue
            if source == target:
                stats["edges_self_loop"] += 1
                continue
            if (source, target) in edge_set:
                stats["edges_duplicate"] += 1
                continue
            edge_set.add((source, target))
            edges.append((source, target))

    return ParsedSbom(
        spec_version=doc.spec_version,
        root_ref=root_ref,
        root_name=root.name if root else None,
        tools=_tool_names(doc.metadata.tools if doc.metadata else None),
        components=components,
        edges=edges,
        stats=stats,
    )

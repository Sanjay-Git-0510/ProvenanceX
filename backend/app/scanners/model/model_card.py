"""Model card (README.md) parsing and completeness scoring.

The YAML front matter is parsed with yaml.SafeLoader (no Python object construction).
Before loading it, the event stream is checked: anchors/aliases are rejected (they enable
"billion laughs" expansion) and the event count is capped. Completeness is a research
heuristic: the fraction of the fields below that are present.
"""

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

MAX_FRONT_MATTER_BYTES = 64 * 1024
MAX_YAML_EVENTS = 20000

CARD_FIELDS = ("license", "base_model", "datasets", "language", "pipeline_tag", "library_name")
# (section name, heading pattern) for the body of the card.
CARD_SECTIONS = (
    ("intended_use", re.compile(r"^#+\s*.*\b(intended use|uses|usage|how to use)\b", re.I | re.M)),
    ("limitations", re.compile(r"^#+\s*.*\b(limitations?|bias|risks?)\b", re.I | re.M)),
    ("training", re.compile(r"^#+\s*.*\b(training|fine-?tuning)\b", re.I | re.M)),
    ("evaluation", re.compile(r"^#+\s*.*\b(evaluation|results|metrics)\b", re.I | re.M)),
)


@dataclass
class ModelCard:
    present: bool
    source: str | None = None  # readme | hf_api | None
    metadata: dict[str, Any] = field(default_factory=dict)
    fields_present: list[str] = field(default_factory=list)
    sections_present: list[str] = field(default_factory=list)
    completeness: float = 0.0
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "source": self.source,
            "metadata": self.metadata,
            "fields_present": self.fields_present,
            "sections_present": self.sections_present,
            "completeness": self.completeness,
            "completeness_fields": list(CARD_FIELDS) + [s for s, _ in CARD_SECTIONS],
            "issues": self.issues,
        }


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value[:256]]
    if isinstance(value, list):
        return [v[:256] for v in value[:64] if isinstance(v, str)]
    return []


def normalize_card_metadata(data: dict[str, Any]) -> dict[str, Any]:
    """Keep only the well-known, scalar/list fields, as bounded strings."""
    out: dict[str, Any] = {}
    for key in ("license", "pipeline_tag", "library_name", "base_model_relation", "license_name"):
        value = data.get(key)
        if isinstance(value, str):
            out[key] = value[:256]
        elif isinstance(value, list) and key == "license":
            out[key] = ", ".join(_as_list(value))
    for key in ("base_model", "datasets", "language", "tags"):
        values = _as_list(data.get(key))
        if values:
            out[key] = values
    return out


def _split_front_matter(text: str) -> tuple[str | None, str]:
    if not text.startswith("---"):
        return None, text
    match = re.match(r"^---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(\r?\n|$)", text, re.S)
    if not match:
        return None, text
    return match.group(1), text[match.end() :]


def _safe_yaml(front: str) -> tuple[dict[str, Any] | None, str | None]:
    if len(front.encode("utf-8")) > MAX_FRONT_MATTER_BYTES:
        return None, "front matter exceeds 64 KB"
    try:
        count = 0
        for event in yaml.parse(front, Loader=yaml.SafeLoader):
            count += 1
            if count > MAX_YAML_EVENTS:
                return None, "front matter has too many YAML events"
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                return None, "front matter uses YAML anchors/aliases (rejected)"
        data = yaml.load(front, Loader=yaml.SafeLoader)  # noqa: S506 - SafeLoader
    except yaml.YAMLError:
        return None, "front matter is not valid YAML"
    except RecursionError:
        return None, "front matter is nested too deeply"
    if data is None:
        return {}, None
    if not isinstance(data, dict):
        return None, "front matter is not a mapping"
    return data, None


def _score(card: ModelCard, body: str) -> None:
    card.fields_present = [f for f in CARD_FIELDS if card.metadata.get(f)]
    card.sections_present = [name for name, rx in CARD_SECTIONS if rx.search(body)]
    total = len(CARD_FIELDS) + len(CARD_SECTIONS)
    card.completeness = round((len(card.fields_present) + len(card.sections_present)) / total, 4)


def parse_model_card(raw: bytes | None, *, max_bytes: int) -> ModelCard:
    """Parse README.md bytes. `raw=None` means there is no README."""
    if raw is None:
        return ModelCard(present=False)
    card = ModelCard(present=True, source="readme")
    if len(raw) > max_bytes:
        card.issues.append(f"README exceeds {max_bytes} bytes; only the first part was read")
        raw = raw[:max_bytes]
    text = raw.decode("utf-8", errors="replace")
    front, body = _split_front_matter(text)
    if front is not None:
        data, issue = _safe_yaml(front)
        if issue:
            card.issues.append(issue)
        if data:
            card.metadata = normalize_card_metadata(data)
    _score(card, body)
    return card


def card_from_api(card_data: dict[str, Any] | None) -> ModelCard:
    """Fallback when the README was not downloaded: HF API `cardData` (front matter only)."""
    if not card_data:
        return ModelCard(present=False)
    card = ModelCard(present=True, source="hf_api", metadata=normalize_card_metadata(card_data))
    card.issues.append("README body not available; section checks could not run")
    _score(card, "")
    return card

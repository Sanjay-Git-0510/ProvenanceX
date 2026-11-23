"""Family assignment and deduplication for the real-world manifest.

A family groups everything that could leak between splits:
- software: one GitHub repository, whatever the revision (`github:owner/repo`)
- registry packages: one ecosystem package (`pkg:ecosystem/name`)
- Hugging Face models and LoRA adapters: the declared base model when there is one, else the
  repository itself (`hf:owner/name`), so a base model and its fine-tunes or adapters share a family
- Hugging Face datasets: the dataset repository (`hf-dataset:owner/name`)
"""

from collections.abc import Iterable
from dataclasses import dataclass, field

from app.ml.dataset.splits import find_family_leaks
from app.ml.realworld.manifest import LABEL_SEVERITY, ManifestRecord


def software_family(owner: str, repo: str) -> str:
    return f"github:{owner.lower()}/{repo.lower()}"


def package_family(ecosystem: str, name: str) -> str:
    return f"pkg:{ecosystem.lower()}/{name.lower()}"


def hf_family(kind: str, repo_id: str, base_models: Iterable[str] = ()) -> str:
    if kind == "dataset":
        return f"hf-dataset:{repo_id.lower()}"
    bases = sorted(b.lower() for b in base_models)
    return f"hf:{bases[0] if bases else repo_id.lower()}"


@dataclass
class DedupReport:
    input_count: int = 0
    duplicates_removed: int = 0
    label_conflicts: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "input_count": self.input_count,
            "duplicates_removed": self.duplicates_removed,
            "label_conflicts": self.label_conflicts,
        }


def _severity(record: ManifestRecord) -> int:
    return LABEL_SEVERITY.index(record.label)


def deduplicate(records: Iterable[ManifestRecord]) -> tuple[list[ManifestRecord], DedupReport]:
    """Keep one record per record_id (artifact type + identifier + revision).

    When duplicates disagree, the most severe label wins and the conflict is reported; a
    conflict never turns a record benign.
    """
    report = DedupReport()
    kept: dict[str, ManifestRecord] = {}
    for record in records:
        report.input_count += 1
        current = kept.get(record.record_id)
        if current is None:
            kept[record.record_id] = record
            continue
        report.duplicates_removed += 1
        if current.label != record.label:
            winner, loser = sorted((current, record), key=_severity)
            report.label_conflicts.append(
                {
                    "record_id": record.record_id,
                    "kept": f"{winner.label} ({winner.data_source})",
                    "dropped": f"{loser.label} ({loser.data_source})",
                }
            )
            kept[record.record_id] = winner
    return sorted(kept.values(), key=lambda r: r.record_id), report


def family_identity_conflicts(records: Iterable[ManifestRecord]) -> dict[str, set[str]]:
    """Identifiers that appear under more than one family (should be empty)."""
    families: dict[str, set[str]] = {}
    for record in records:
        families.setdefault(record.artifact_identifier.lower(), set()).add(record.family_id)
    return {ident: fams for ident, fams in families.items() if len(fams) > 1}


def split_leaks(records: Iterable[ManifestRecord], split_of: dict[str, str]) -> dict[str, set[str]]:
    """Families whose records were assigned to more than one split. `split_of` is by record_id."""
    return find_family_leaks((r.family_id, split_of[r.record_id]) for r in records)

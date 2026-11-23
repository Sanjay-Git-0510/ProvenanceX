"""Name what kind of evidence stands behind a result, so weak or missing evidence is never read
as tampering or malice, and absent evidence is never read as clean.

Only two states are confirmed: confirmed_tampering (a content hash contradicts the same commit or
the source's own listing) and dangerous_behavior (a hard BLOCK rule on code or behaviour, such as
pickle globals that can execute code). Even dangerous_behavior is not proof of intent. Every other
state is a reason to look closer (REVIEW), never a reason to BLOCK on its own.
"""

from enum import StrEnum

from app.ml.feature_schema import NullReason
from app.risk.policy_config import RULE_LAYERS, Decision, HardRule
from app.risk.types import EvidenceItem, LayerResult, LayerStatus, RiskInputs


class EvidenceState(StrEnum):
    CONFIRMED_TAMPERING = "confirmed_tampering"
    DANGEROUS_BEHAVIOR = "dangerous_behavior"
    KNOWN_VULNERABILITY = "known_vulnerability"
    WEAK_PROVENANCE = "weak_provenance"
    INTEGRITY_UNVERIFIED = "integrity_unverified"
    NO_PRIOR_SCAN = "no_prior_scan"
    MISSING_EVIDENCE = "missing_evidence"


CONFIRMED_STATES = frozenset({EvidenceState.CONFIRMED_TAMPERING, EvidenceState.DANGEROUS_BEHAVIOR})
TAMPERING_RULES = frozenset({"hash_consistency_failed", "download_integrity_failed"})

NOTES: dict[EvidenceState, str] = {
    EvidenceState.CONFIRMED_TAMPERING: "Content contradicts an earlier scan or the source's own "
    "hash listing.",
    EvidenceState.DANGEROUS_BEHAVIOR: "Code or behaviour that can execute or exfiltrate was "
    "observed. This is not proof of malicious intent.",
    EvidenceState.KNOWN_VULNERABILITY: "Known vulnerabilities in dependencies. Vulnerable does not "
    "mean malicious.",
    EvidenceState.WEAK_PROVENANCE: "Provenance is missing or weak. This is a reason to review, not "
    "evidence of tampering.",
    EvidenceState.INTEGRITY_UNVERIFIED: "Integrity could not be checked: neither pass nor fail.",
    EvidenceState.NO_PRIOR_SCAN: "No earlier scan to compare with, so change features are empty. "
    "This is not a change.",
    EvidenceState.MISSING_EVIDENCE: "Evidence was not collected or the stage failed. Missing "
    "evidence is not clean.",
}

# Feature values that mean "provenance is weak" (never tampering on their own).
_WEAK_PROVENANCE = (
    ("provenance_present", False),
    ("source_known", False),
    ("revision_pinned", False),
    ("version_consistency", False),
)
_IGNORED_REASONS = frozenset({NullReason.NOT_APPLICABLE, NullReason.NO_PRIOR_SCAN})


def _weak_provenance(inputs: RiskInputs) -> list[str]:
    items = [name for name, bad in _WEAK_PROVENANCE if inputs.features.get(name) is bad]
    lineage = inputs.features.get("lineage_completeness")
    if isinstance(lineage, int | float) and lineage < 0.5:
        items.append("lineage_completeness")
    return items


def _unverified_checks(inputs: RiskInputs) -> list[str]:
    return sorted(
        str(check.get("name"))
        for check in inputs.provenance_checks or ()
        if check.get("status") == "unknown"
    )


def _missing(layers: list[LayerResult]) -> list[str]:
    items = []
    for layer in layers:
        if layer.layer not in RULE_LAYERS or layer.status == LayerStatus.NOT_APPLICABLE:
            continue
        for name, reason in sorted(layer.not_evaluated.items()):
            if reason not in _IGNORED_REASONS and reason != NullReason.NO_DATA_SOURCE:
                items.append(f"{name} ({reason})")
    return items


def classify(
    inputs: RiskInputs, layers: list[LayerResult], fired: list[HardRule]
) -> list[EvidenceItem]:
    """One entry per state that applies, most serious first. Empty states are left out."""
    found: dict[EvidenceState, list[str]] = {
        EvidenceState.CONFIRMED_TAMPERING: [
            r.rule_id for r in fired if r.rule_id in TAMPERING_RULES
        ],
        EvidenceState.DANGEROUS_BEHAVIOR: [
            r.rule_id
            for r in fired
            if r.decision == Decision.BLOCK and r.rule_id not in TAMPERING_RULES
        ],
        EvidenceState.KNOWN_VULNERABILITY: (
            ["vulnerable_count"] if (inputs.features.get("vulnerable_count") or 0) > 0 else []
        ),
        EvidenceState.WEAK_PROVENANCE: _weak_provenance(inputs),
        EvidenceState.INTEGRITY_UNVERIFIED: _unverified_checks(inputs),
        EvidenceState.NO_PRIOR_SCAN: sorted(
            name
            for name, reason in inputs.null_reasons.items()
            if reason == NullReason.NO_PRIOR_SCAN and inputs.features.get(name) is None
        ),
        EvidenceState.MISSING_EVIDENCE: _missing(layers),
    }
    return [
        EvidenceItem(
            state=str(state),
            confirmed=state in CONFIRMED_STATES,
            items=items,
            note=NOTES[state],
        )
        for state, items in found.items()
        if items
    ]


def has_confirmed(items: list[EvidenceItem]) -> bool:
    return any(item.confirmed for item in items)

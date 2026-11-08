"""CVSS v3.x base-score calculation and qualitative severity bands.

This implements the FIRST CVSS v3.0/v3.1 specification formulas, so a score can be
derived from an advisory's vector string when the advisory does not include a numeric
score (OSV stores only vectors). CVSS v4.0 scoring needs the spec's macro-vector
lookup tables, so it is not computed here. v4 vectors are kept as-is with no score,
and NVD enrichment may supply one.

A CVSS score describes how severe a known vulnerability is. It is not the ProvenanceX
risk score.
"""

import math
from dataclasses import dataclass

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_ALLOWED = {
    "AV": _AV,
    "AC": _AC,
    "PR": _PR_UNCHANGED,
    "UI": _UI,
    "S": {"U": None, "C": None},
    "C": _CIA,
    "I": _CIA,
    "A": _CIA,
}

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")


@dataclass(frozen=True)
class CvssScore:
    version: str  # "3.0" | "3.1"
    vector: str
    base_score: float


def _roundup_31(value: float) -> float:
    """CVSS v3.1 Roundup (Appendix A), which avoids floating-point artifacts."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _roundup_30(value: float) -> float:
    return math.ceil(value * 10) / 10.0


def parse_cvss3_vector(vector: str) -> dict[str, str]:
    """Split and validate a CVSS:3.x vector. Raises ValueError if it is malformed."""
    if not isinstance(vector, str) or len(vector) > 200:
        raise ValueError("vector must be a short string")
    parts = vector.strip().split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        raise ValueError("not a CVSS v3 vector")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or key in metrics:
            raise ValueError(f"malformed or duplicate metric: {part!r}")
        metrics[key] = value
    for key in _REQUIRED:
        if key not in metrics or metrics[key] not in _ALLOWED[key]:
            raise ValueError(f"missing or invalid base metric {key}")
    return metrics


def cvss3_base_score(vector: str) -> CvssScore:
    """Compute the base score for a CVSS v3.0/v3.1 vector. Raises ValueError if invalid."""
    m = parse_cvss3_vector(vector)
    version = vector.split("/")[0].split(":")[1]
    roundup = _roundup_31 if version == "3.1" else _roundup_30
    changed = m["S"] == "C"
    pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        score = 0.0
    elif changed:
        score = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = roundup(min(impact + exploitability, 10))
    return CvssScore(version=version, vector=vector.strip(), base_score=score)


def severity_from_score(score: float | None) -> str:
    """Qualitative severity rating scale (CVSS v3.x spec, section 5)."""
    if score is None:
        return "UNKNOWN"
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


_ADVISORY_SEVERITY = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NONE": "NONE",
}


def normalize_advisory_severity(value: object) -> str | None:
    """Map advisory labels (GHSA uses MODERATE) onto the CVSS band names."""
    if not isinstance(value, str):
        return None
    return _ADVISORY_SEVERITY.get(value.strip().upper())


def severity_rank(severity: str | None) -> int:
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1}
    return order.get(severity or "", 0)

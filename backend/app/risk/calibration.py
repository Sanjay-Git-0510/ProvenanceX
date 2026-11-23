"""Empirical calibration analysis of the hand-set policy on REAL-WORLD rows.

Analysis only: nothing here changes the policy. The policy may be calibrated only when the
owner-approved sufficiency rule below holds, and BLOCK thresholds additionally need established
ground-truth malicious or tampered rows. Until then the report says exactly what is missing.

The real-world labels are benign vs known_vulnerable. Vulnerable is not malicious, so these rows
can say how often benign software is flagged for review, but nothing about BLOCK accuracy.
Rows are scored rule-only (no ML), from stored feature rows: findings and provenance checks are
not in the rows, so hard rules that need them are not evaluated (reported per row).
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from typing import Any

import numpy as np

from app.risk.policy import assess_risk
from app.risk.policy_config import DEFAULT_POLICY, POLICY_VERSION, PolicyConfig, RiskLayer
from app.risk.types import RiskAssessment, RiskInputs

CALIBRATION_FORMAT = "provenancex-policy-calibration-v1"
# Owner-approved (2026-11-23). Research parameters, not standards.
MIN_REAL_ROWS = 300
MIN_ROWS_PER_CLASS = 100
BLOCK_CLASSES = ("confirmed_malicious", "tampered")
REVIEW_SWEEP = (0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60)
BLOCK_SWEEP = (0.50, 0.60, 0.70, 0.80, 0.90)
WEIGHT_FACTORS = (0.8, 1.2)
POSITIVE = "known_vulnerable"
NEGATIVE = "benign"


def sufficiency(label_counts: dict[str, int]) -> dict[str, Any]:
    """Whether empirical calibration may be enabled, and the exact shortfall if not."""
    total = sum(label_counts.get(k, 0) for k in (NEGATIVE, POSITIVE))
    missing = []
    if total < MIN_REAL_ROWS:
        missing.append(
            f"{MIN_REAL_ROWS - total} more labelled real rows (have {total}, need {MIN_REAL_ROWS})"
        )
    for label in (NEGATIVE, POSITIVE):
        n = label_counts.get(label, 0)
        if n < MIN_ROWS_PER_CLASS:
            missing.append(
                f"{MIN_ROWS_PER_CLASS - n} more {label} rows (have {n}, need {MIN_ROWS_PER_CLASS})"
            )
    block_rows = sum(label_counts.get(k, 0) for k in BLOCK_CLASSES)
    block_missing = (
        []
        if block_rows
        else [
            "established ground-truth confirmed_malicious or tampered rows with scan "
            "features (have 0)"
        ]
    )
    return {
        "rule": {
            "min_real_rows": MIN_REAL_ROWS,
            "min_rows_per_class": MIN_ROWS_PER_CLASS,
            "block_requires": list(BLOCK_CLASSES),
        },
        "review_calibration_allowed": not missing,
        "block_calibration_allowed": not missing and not block_missing,
        "missing_for_review": missing,
        "missing_for_block": missing + block_missing,
    }


def _rates(labels: Sequence[str], flagged: Sequence[bool]) -> dict[str, Any]:
    pos = [f for lab, f in zip(labels, flagged, strict=True) if lab == POSITIVE]
    neg = [f for lab, f in zip(labels, flagged, strict=True) if lab == NEGATIVE]
    tp, fn = sum(pos), len(pos) - sum(pos)
    fp, tn = sum(neg), len(neg) - sum(neg)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "fpr": fp / len(neg) if neg else None,
        "fnr": fn / len(pos) if pos else None,
    }


def _bootstrap(labels: list[str], flagged: list[bool], resamples: int, seed: int) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    fprs, fnrs = [], []
    n = len(labels)
    for _ in range(resamples):
        idx = rng.integers(0, n, n)
        r = _rates([labels[i] for i in idx], [flagged[i] for i in idx])
        if r["fpr"] is not None:
            fprs.append(r["fpr"])
        if r["fnr"] is not None:
            fnrs.append(r["fnr"])

    def ci(values: list[float]) -> list[float] | None:
        if not values:
            return None
        return [round(float(np.percentile(values, q)), 3) for q in (2.5, 97.5)]

    return {"resamples": resamples, "fpr_95ci": ci(fprs), "fnr_95ci": ci(fnrs)}


def _assess(inputs: Sequence[RiskInputs], policy: PolicyConfig) -> list[RiskAssessment]:
    return [assess_risk(item, policy) for item in inputs]


def _decision_rates(labels: list[str], assessed: list[RiskAssessment]) -> dict[str, Any]:
    flagged = [a.decision != "ALLOW" for a in assessed]
    by_class: dict[str, Counter[str]] = {}
    for lab, a in zip(labels, assessed, strict=True):
        by_class.setdefault(lab, Counter())[a.decision] += 1
    return {
        "flag_means": "decision is REVIEW or BLOCK",
        **_rates(labels, flagged),
        "decisions_by_label": {k: dict(sorted(v.items())) for k, v in sorted(by_class.items())},
    }


def run_calibration(
    inputs: Sequence[RiskInputs],
    labels: Sequence[str],
    policy: PolicyConfig = DEFAULT_POLICY,
    *,
    resamples: int = 1000,
    seed: int = 42,
) -> dict[str, Any]:
    """Measure the current policy, threshold sweeps, weight changes and missing evidence."""
    if not inputs or len(inputs) != len(labels):
        raise ValueError("Calibration needs one label per input, and at least one input")
    if set(labels) - {NEGATIVE, POSITIVE}:
        raise ValueError("Only benign and known_vulnerable rows can be analysed here")
    labels = list(labels)
    base = _assess(inputs, policy)
    scores = [a.rule_only_score for a in base]
    flagged = [a.decision != "ALLOW" for a in base]

    review_sweep = []
    for t in REVIEW_SWEEP:
        flag_at = [s is not None and s >= t for s in scores]
        review_sweep.append(
            {
                "review_threshold": t,
                "flag_means": "rule-only score >= threshold",
                **_rates(labels, flag_at),
            }
        )
    block_sweep = []
    for t in BLOCK_SWEEP:
        counts = Counter(
            lab for lab, s in zip(labels, scores, strict=True) if s is not None and s >= t
        )
        block_sweep.append(
            {"block_threshold": t, "score_at_or_above_by_label": dict(sorted(counts.items()))}
        )

    weights = []
    for layer in RiskLayer:
        for factor in WEIGHT_FACTORS:
            changed = _assess(inputs, policy.with_scaled_weight(layer, factor))
            weights.append(
                {"layer": str(layer), "factor": factor, **_decision_rates(labels, changed)}
            )
    blend = [
        {
            "max_blend": min(1.0, policy.max_blend * f),
            **_decision_rates(
                labels, _assess(inputs, replace(policy, max_blend=min(1.0, policy.max_blend * f)))
            ),
        }
        for f in WEIGHT_FACTORS
    ]

    by_missing: dict[int, Counter[str]] = {}
    for lab, a in zip(labels, base, strict=True):
        by_missing.setdefault(len(a.not_evaluated_layers), Counter())[f"{lab}:{a.decision}"] += 1
    downgraded = sum(
        1 for a in base if any("too thin for a score-only BLOCK" in r for r in a.reasons)
    )
    rules_not_evaluated = Counter(r for a in base for r in a.hard_rules_not_evaluated)
    confidences = [a.confidence for a in base]

    return {
        "format": CALIBRATION_FORMAT,
        "policy_version": POLICY_VERSION,
        "rows": len(base),
        "label_counts": dict(sorted(Counter(labels).items())),
        "scoring": (
            "rule-only (ML excluded); hard rules needing findings or provenance checks are "
            "not evaluated"
        ),
        "current_policy": {
            "review_threshold": policy.review_threshold,
            "block_threshold": policy.block_threshold,
            **_decision_rates(labels, base),
            "bootstrap": _bootstrap(labels, flagged, resamples, seed),
        },
        "review_threshold_sweep": review_sweep,
        "block_threshold_sweep": block_sweep,
        "weight_changes": weights,
        "blend_changes": blend,
        "missing_evidence": {
            "decisions_by_not_evaluated_layer_count": {
                str(k): dict(sorted(v.items())) for k, v in sorted(by_missing.items())
            },
            "not_evaluated_layer_counts": dict(
                sorted(Counter(str(x) for a in base for x in a.not_evaluated_layers).items())
            ),
            "score_only_block_downgraded_to_review": downgraded,
            "hard_rules_not_evaluated": dict(sorted(rules_not_evaluated.items())),
            "confidence_min": min(confidences),
            "confidence_mean": sum(confidences) / len(confidences),
            "confidence_max": max(confidences),
        },
        "sufficiency": sufficiency(dict(Counter(labels))),
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def render_markdown(result: dict[str, Any], synthetic: dict[str, Any] | None) -> str:
    cur, suff, miss = result["current_policy"], result["sufficiency"], result["missing_evidence"]

    def yes(value: bool) -> str:
        return "yes" if value else "no"

    boot = cur["bootstrap"]
    lines = [
        f"# Policy calibration analysis: {result['policy_version']}",
        "",
        "**REAL-WORLD ROWS, ANALYSIS ONLY. The policy was not changed.** Labels are benign vs "
        "known_vulnerable software. Vulnerable is not malicious, so these rows say nothing about "
        "BLOCK accuracy. Rows are scored rule-only from stored feature rows; hard rules that need "
        "findings or provenance checks are not evaluated.",
        "",
        "## Can the policy be calibrated?",
        "",
        f"- REVIEW thresholds and weights: **{yes(suff['review_calibration_allowed'])}**",
        f"- BLOCK thresholds: **{yes(suff['block_calibration_allowed'])}**",
        f"- Rule: at least {suff['rule']['min_real_rows']} labelled real rows, at least "
        f"{suff['rule']['min_rows_per_class']} per class, and established ground-truth "
        f"{' or '.join(suff['rule']['block_requires'])} rows before calibrating BLOCK.",
        "",
        "Missing for BLOCK calibration:",
        "",
        *[f"- {m}" for m in suff["missing_for_block"]],
        "",
        *(
            [
                f"The current manifest has only {result['scan_eligible_in_manifest']} "
                "scan-eligible rows, so reaching the rule needs a new collection run, not only "
                "more retries.",
                "",
            ]
            if result.get("scan_eligible_in_manifest") is not None
            and result["scan_eligible_in_manifest"] < suff["rule"]["min_real_rows"]
            else []
        ),
        "`provenancex-policy-v2-handset` stays hand-set and uncalibrated.",
        "",
        "## Current policy on real rows",
        "",
        f"Rows: {result['rows']} {result['label_counts']}. A row is flagged when the decision is "
        "REVIEW or BLOCK; positive class = known_vulnerable.",
        "",
        "| FPR (benign flagged) | FNR (vulnerable allowed) | FPR 95% CI | FNR 95% CI |",
        "|---|---|---|---|",
        f"| {_pct(cur['fpr'])} | {_pct(cur['fnr'])} | {boot['fpr_95ci']} | {boot['fnr_95ci']} |",
        "",
        f"Decisions by label: {cur['decisions_by_label']}",
        "",
        "## REVIEW threshold trade-off (rule-only score)",
        "",
        "| Threshold | FPR | FNR | FP | FN |",
        "|---|---|---|---|---|",
        *[
            f"| {r['review_threshold']:.2f} | {_pct(r['fpr'])} | {_pct(r['fnr'])} "
            f"| {r['fp']} | {r['fn']} |"
            for r in result["review_threshold_sweep"]
        ],
        "",
        "## BLOCK threshold: rows at or above each score",
        "",
        "No row here is malicious, so any count is a would-be BLOCK of benign or merely vulnerable "
        "software (before the confidence and required-layer downgrade).",
        "",
        "| Threshold | Rows at or above, by label |",
        "|---|---|",
        *[
            f"| {r['block_threshold']:.2f} | {r['score_at_or_above_by_label'] or 'none'} |"
            for r in result["block_threshold_sweep"]
        ],
        "",
        "## Weight changes (one layer at a time)",
        "",
        "| Layer | Factor | FPR | FNR |",
        "|---|---|---|---|",
        *[
            f"| {r['layer']} | {r['factor']} | {_pct(r['fpr'])} | {_pct(r['fnr'])} |"
            for r in result["weight_changes"]
        ],
        *[
            f"| max_blend={r['max_blend']:.2f} | | {_pct(r['fpr'])} | {_pct(r['fnr'])} |"
            for r in result["blend_changes"]
        ],
        "",
        "## Missing-evidence behaviour",
        "",
        f"- Decisions by number of not-evaluated rule layers: "
        f"{result['missing_evidence']['decisions_by_not_evaluated_layer_count']}",
        f"- Not-evaluated layers: {result['missing_evidence']['not_evaluated_layer_counts']}",
        "- Score-only BLOCKs downgraded to REVIEW: "
        f"{miss['score_only_block_downgraded_to_review']}",
        f"- Hard rules not evaluated: {result['missing_evidence']['hard_rules_not_evaluated']}",
        f"- Confidence min / mean / max: {miss['confidence_min']:.2f} / "
        f"{miss['confidence_mean']:.2f} / {miss['confidence_max']:.2f}",
        "",
        "## Synthetic sensitivity analysis (separate, SYNTHETIC DATA)",
        "",
    ]
    if synthetic:
        lines += [
            "From `ml/reports/fusion_sensitivity.json`, computed on the synthetic validation "
            "split. It counts decision changes only and is not an accuracy measure. It is never "
            "combined with the real-world numbers above.",
            "",
            f"- Records: {synthetic.get('records')}; "
            f"baseline decisions: {synthetic.get('baseline_decisions')}",
        ]
    else:
        lines.append("No synthetic sensitivity report was found.")
    return "\n".join(lines) + "\n"

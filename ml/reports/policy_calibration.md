# Policy calibration analysis: provenancex-policy-v2-handset

**REAL-WORLD ROWS, ANALYSIS ONLY. The policy was not changed.** Labels are benign vs known_vulnerable software. Vulnerable is not malicious, so these rows say nothing about BLOCK accuracy. Rows are scored rule-only from stored feature rows; hard rules that need findings or provenance checks are not evaluated.

## Can the policy be calibrated?

- REVIEW thresholds and weights: **no**
- BLOCK thresholds: **no**
- Rule: at least 300 labelled real rows, at least 100 per class, and established ground-truth confirmed_malicious or tampered rows before calibrating BLOCK.

Missing for BLOCK calibration:

- 153 more labelled real rows (have 147, need 300)
- 76 more benign rows (have 24, need 100)
- established ground-truth confirmed_malicious or tampered rows with scan features (have 0)

The current manifest has only 152 scan-eligible rows, so reaching the rule needs a new collection run, not only more retries.

`provenancex-policy-v2-handset` stays hand-set and uncalibrated.

## Current policy on real rows

Rows: 147 {'benign': 24, 'known_vulnerable': 123}. A row is flagged when the decision is REVIEW or BLOCK; positive class = known_vulnerable.

| FPR (benign flagged) | FNR (vulnerable allowed) | FPR 95% CI | FNR 95% CI |
|---|---|---|---|
| 0.92 | 0.12 | [0.773, 1.0] | [0.068, 0.181] |

Decisions by label: {'benign': {'ALLOW': 2, 'BLOCK': 5, 'REVIEW': 17}, 'known_vulnerable': {'ALLOW': 15, 'BLOCK': 28, 'REVIEW': 80}}

## REVIEW threshold trade-off (rule-only score)

| Threshold | FPR | FNR | FP | FN |
|---|---|---|---|---|
| 0.20 | 0.96 | 0.12 | 23 | 15 |
| 0.25 | 0.96 | 0.14 | 23 | 17 |
| 0.30 | 0.92 | 0.15 | 22 | 19 |
| 0.35 | 0.92 | 0.16 | 22 | 20 |
| 0.40 | 0.79 | 0.22 | 19 | 27 |
| 0.45 | 0.67 | 0.32 | 16 | 39 |
| 0.50 | 0.62 | 0.35 | 15 | 43 |
| 0.55 | 0.46 | 0.46 | 11 | 56 |
| 0.60 | 0.33 | 0.51 | 8 | 63 |

## BLOCK threshold: rows at or above each score

No row here is malicious, so any count is a would-be BLOCK of benign or merely vulnerable software (before the confidence and required-layer downgrade).

| Threshold | Rows at or above, by label |
|---|---|
| 0.50 | {'benign': 15, 'known_vulnerable': 80} |
| 0.60 | {'benign': 8, 'known_vulnerable': 60} |
| 0.70 | {'benign': 6, 'known_vulnerable': 34} |
| 0.80 | none |
| 0.90 | none |

## Weight changes (one layer at a time)

| Layer | Factor | FPR | FNR |
|---|---|---|---|
| vulnerability | 0.8 | 0.92 | 0.12 |
| vulnerability | 1.2 | 0.92 | 0.12 |
| provenance_integrity | 0.8 | 0.92 | 0.12 |
| provenance_integrity | 1.2 | 0.92 | 0.12 |
| graph | 0.8 | 0.92 | 0.12 |
| graph | 1.2 | 0.92 | 0.12 |
| static | 0.8 | 0.92 | 0.12 |
| static | 1.2 | 0.92 | 0.12 |
| behavioral | 0.8 | 0.92 | 0.12 |
| behavioral | 1.2 | 0.92 | 0.12 |
| ai_specific | 0.8 | 0.92 | 0.12 |
| ai_specific | 1.2 | 0.92 | 0.12 |
| ml_supervised | 0.8 | 0.92 | 0.12 |
| ml_supervised | 1.2 | 0.92 | 0.12 |
| ml_anomaly | 0.8 | 0.92 | 0.12 |
| ml_anomaly | 1.2 | 0.92 | 0.12 |
| max_blend=0.40 | | 0.92 | 0.13 |
| max_blend=0.60 | | 0.92 | 0.11 |

## Missing-evidence behaviour

- Decisions by number of not-evaluated rule layers: {'3': {'benign:ALLOW': 2, 'benign:BLOCK': 5, 'benign:REVIEW': 14, 'known_vulnerable:ALLOW': 15, 'known_vulnerable:BLOCK': 28, 'known_vulnerable:REVIEW': 59}, '4': {'benign:REVIEW': 3, 'known_vulnerable:REVIEW': 19}, '5': {'known_vulnerable:REVIEW': 2}}
- Not-evaluated layers: {'behavioral': 147, 'ml_anomaly': 147, 'ml_supervised': 147, 'static': 20, 'vulnerability': 6}
- Score-only BLOCKs downgraded to REVIEW: 7
- Hard rules not evaluated: {'archive_anomaly': 20, 'critical_known_vulnerability': 74, 'external_destination': 147, 'hash_consistency_failed': 139, 'install_hook_present': 20, 'provenance_removed': 139, 'sensitive_access_with_external_destination': 147, 'shell_spawn': 147}
- Confidence min / mean / max: 0.39 / 0.64 / 0.80

## Synthetic sensitivity analysis (separate, SYNTHETIC DATA)

From `ml/reports/fusion_sensitivity.json`, computed on the synthetic validation split. It counts decision changes only and is not an accuracy measure. It is never combined with the real-world numbers above.

- Records: 348; baseline decisions: {'ALLOW': 95, 'BLOCK': 85, 'REVIEW': 168}

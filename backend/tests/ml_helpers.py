"""Builders for ML unit tests."""

from app.ml.feature_schema import FEATURE_NAMES, NOT_EVALUATED_FEATURES, FeatureRecord, NullReason


def record(label="benign", split="test", observable=True, reasons=None, recipes=(), **values):
    features = dict.fromkeys(FEATURE_NAMES)
    features.update(values)
    reasons = reasons or {}
    null_reasons = {
        name: reasons.get(
            name,
            NullReason.NO_DATA_SOURCE if name in NOT_EVALUATED_FEATURES else NullReason.STAGE_ERROR,
        )
        for name, value in features.items()
        if value is None
    }
    return FeatureRecord(
        record_id="r",
        family_id="f",
        artifact_type="software",
        variant="v",
        applied_recipes=list(recipes),
        label=label,
        label_source="controlled_fixture:clean",
        ground_truth_status="synthetic_by_construction",
        synthetic=True,
        label_evidence_observable=observable,
        split=split,
        features=features,
        null_reasons=null_reasons,
    )

"""The sensitivity analysis counts changed decisions and refuses anything but validation."""

import pytest

from app.risk.policy_config import RiskLayer
from app.risk.sensitivity import (
    BLEND_PARAMETER,
    SCALE_FACTORS,
    inputs_from_validation,
    render_markdown,
    run_sensitivity,
)
from tests.ml_helpers import record
from tests.risk_helpers import make_inputs, ml_outputs


def cases():
    return [
        make_inputs(ml=ml_outputs()),
        make_inputs(install_hook_count=1, ml=ml_outputs(0.1, 0.1)),
        make_inputs(source_known=False, version_consistency=False, ml=ml_outputs(0.7, 0.4)),
        make_inputs(dangerous_import_count=3, script_presence=True, ml=ml_outputs()),
    ]


@pytest.mark.parametrize("split", ["test", "train"])
def test_other_splits_are_refused(split):
    with pytest.raises(ValueError, match="validation"):
        inputs_from_validation([record(split=split)], [None])


def test_validation_records_are_accepted():
    built = inputs_from_validation([record(split="validation")], [ml_outputs()])
    assert built[0].ml is not None


def test_each_record_needs_one_output():
    with pytest.raises(ValueError, match="one ML output"):
        inputs_from_validation([record(split="validation")], [])


def test_every_parameter_is_moved_both_ways():
    result = run_sensitivity(cases())
    seen = {(row["parameter"], row["factor"]) for row in result["rows"]}
    names = [str(layer) for layer in RiskLayer] + [BLEND_PARAMETER]
    assert seen == {(name, factor) for name in names for factor in SCALE_FACTORS}


def test_ml_weights_change_no_decision():
    rows = run_sensitivity(cases())["rows"]
    ml = [r for r in rows if r["parameter"] in ("ml_supervised", "ml_anomaly")]
    assert ml
    assert all(row["decisions_changed"] == 0 for row in ml)


def test_counts_are_consistent():
    result = run_sensitivity(cases())
    assert sum(result["baseline_decisions"].values()) == result["records"]
    for row in result["rows"]:
        assert row["decisions_changed"] == sum(row["transitions"].values())
        assert row["share_changed"] == row["decisions_changed"] / result["records"]


def test_empty_input_is_refused():
    with pytest.raises(ValueError):
        run_sensitivity([])


def test_report_states_its_limits():
    text = render_markdown(run_sensitivity(cases()), "abc", "policy")
    assert "SYNTHETIC DATA, ANALYSIS ONLY" in text
    assert "does not use the test split" in text
    assert "not been tuned or validated" in text

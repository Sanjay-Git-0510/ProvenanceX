"""Real-world dataset collection tooling (network): metadata adapters, collector, scan step.

Kept outside `app/ml/` on purpose: ML code must stay free of network primitives
(tests/security/test_ml_dataset_safety.py). Nothing in the API, runner or risk stage imports
this package; only `ml/scripts/collect_realworld.py` and `scan_realworld.py` do.
"""

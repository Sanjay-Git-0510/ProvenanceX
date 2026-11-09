# ML scripts

Run with the backend virtualenv from the repository root.

```bash
backend/.venv/bin/python ml/scripts/generate_dataset.py --families 200 --seed 42
```

Writes `ml/data/dataset.jsonl` and `ml/data/dataset_metadata.json` (git-ignored). The output is
**synthetic**, and the same seed and dependency versions give byte-identical output.

Then train (needs the dataset above; never reads test records):

```bash
backend/.venv/bin/python ml/scripts/train_models.py --seed 42
```

Writes verified models to `ml/models/` (git-ignored).

Then evaluate (needs the dataset and models above):

```bash
backend/.venv/bin/python ml/scripts/evaluate_models.py
```

Writes `ml/reports/evaluation_report.md` and `.json`.

Then the fusion sensitivity analysis (validation split only, fits nothing):

```bash
backend/.venv/bin/python ml/scripts/fusion_sensitivity.py
```

Writes `ml/reports/fusion_sensitivity.md` and `.json`.

Dataset generation requires the seed templates in `backend/tests/fixtures/ml/seeds/`, so it runs from a source
checkout, not inside the API image (which excludes `tests/`).

# ML scripts

Run with the backend virtualenv from the repository root.

```bash
backend/.venv/bin/python ml/scripts/generate_dataset.py --families 200 --seed 42
```

Writes `ml/data/dataset.jsonl` and `ml/data/dataset_metadata.json` (git-ignored). The output is
**synthetic**, and the same seed and dependency versions give byte-identical output.

Requires the seed templates in `backend/tests/fixtures/ml/seeds/`, so it runs from a source
checkout, not inside the API image (which excludes `tests/`).

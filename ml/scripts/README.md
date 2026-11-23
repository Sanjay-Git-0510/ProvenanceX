# ML scripts

> The synthetic scripts (`generate_dataset`, `train_models`, `evaluate_models`, `fusion_sensitivity`)
> are for unit tests and demos only. Real-world scripts end in `_realworld.py`.

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

## Real-world dataset

Collect the manifest from public metadata (network; no artifact downloaded). `GITHUB_TOKEN` is
optional and sent only to api.github.com:

```bash
GITHUB_TOKEN=... backend/.venv/bin/python -I ml/scripts/collect_realworld.py
```

Writes `ml/data/realworld/manifest-realworld-v1.jsonl` and `.metadata.json`. Output changes with
the collection date, because advisories and repositories change.

Then the bounded scan step (needs the Compose stack: `make up`):

```bash
backend/.venv/bin/python -I ml/scripts/scan_realworld.py --max-scans 200
```

Writes `ml/data/realworld/features-realworld-v1.jsonl`. Re-running resumes; the 200 cap counts rows
already written.

Retry rows that failed (they move to `features-realworld-v1.attempts.jsonl`, nothing is deleted;
completed rows are never rescanned):

```bash
DOCKER_SOCKET_GID=1001 docker compose up -d --scale scan-runner=2   # this machine; see below
backend/.venv/bin/python -I ml/scripts/scan_realworld.py --retry-failed --concurrency 2 --per-scan-timeout 1900
```

- `DOCKER_SOCKET_GID`: when Docker Desktop's socket is not visible in WSL, `make up` falls back to
  `0` and every scan fails closed with `sandbox_unavailable`. Check the real gid with
  `docker compose exec scan-runner stat -c %g /var/run/docker.sock` (1001 here).
- Each runner replica runs one scan at a time; 2 replicas fit an 8 GB Docker VM (analyzer 1.5 GB +
  512 MB staging per active scan). Keep `--concurrency` equal to the replica count.
- `--per-scan-timeout` only stops waiting; the runner's own ceiling is `RUNNER_MAX_SCAN_SECONDS`
  (1800 s).
- Stop the run if every new scan fails (e.g. `clone_failed` from network stalls) and retry later.
- `artifact_too_large` and `too_many_files` are permanent (scan limits, fail closed); retrying them
  only repeats the failure. Manifest v1 has 5 such rows.

Then train and evaluate (offline; never reads the synthetic dataset):

```bash
backend/.venv/bin/python -I ml/scripts/train_realworld.py
```

Writes `ml/models/realworld/<type>/` only for types with enough data, and the
`ml/reports/realworld_*` reports. The model card states whether the runtime quality gates pass, i.e.
whether software scans will load the model.

Policy calibration analysis (offline, analysis only, never changes the policy):

```bash
backend/.venv/bin/python -I ml/scripts/calibrate_policy.py
```

Writes `ml/reports/policy_calibration.{md,json}`: the current policy measured on real rows, threshold
sweeps, and whether calibration is permitted yet (≥ 300 labelled rows, ≥ 100 per class; BLOCK also
needs established confirmed_malicious or tampered rows).

#!/usr/bin/env python3
"""Bounded scan step: run scan-eligible manifest records through the local ProvenanceX stack.

Needs the Compose stack (API + scan-runner with the sandbox enabled). Scans go through the
normal API, so every sandbox, network and timeout rule applies. Resumable; at most 200 rows.

    backend/.venv/bin/python ml/scripts/scan_realworld.py --max-scans 200
"""

import argparse
import json
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.dataset_collection.scan_client import (  # noqa: E402
    MAX_SCANS,
    ApiClient,
    archive_retryable,
    run_scans,
)
from app.ml.realworld.manifest import DATASET_VERSION, read_manifest  # noqa: E402

DATA_DIR = REPO_ROOT / "ml" / "data" / "realworld"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--manifest", type=Path, default=DATA_DIR / f"manifest-{DATASET_VERSION}.jsonl"
    )
    parser.add_argument("--out", type=Path, default=DATA_DIR / f"features-{DATASET_VERSION}.jsonl")
    parser.add_argument("--max-scans", type=int, default=MAX_SCANS)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--per-scan-timeout", type=float, default=2400.0)
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="archive rows that did not complete (to <out>.attempts.jsonl) and scan them again",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    records = read_manifest(args.manifest)
    if args.retry_failed:
        moved = archive_retryable(args.out, args.out.with_suffix(".attempts.jsonl"))
        print(json.dumps({"archived_for_retry": moved}))
    client = ApiClient(args.api)
    try:
        counts = run_scans(
            records,
            args.out,
            client,
            max_scans=args.max_scans,
            concurrency=args.concurrency,
            per_scan_timeout=args.per_scan_timeout,
        )
    finally:
        client.close()
    print(json.dumps(counts, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

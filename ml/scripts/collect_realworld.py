#!/usr/bin/env python3
"""Collect the REAL-WORLD dataset manifest from public metadata (no artifact is downloaded).

Run from the repository root with the backend virtualenv:
    GITHUB_TOKEN=... backend/.venv/bin/python ml/scripts/collect_realworld.py

GITHUB_TOKEN is optional but raises GitHub's rate limit; it is sent only to api.github.com.
Writes ml/data/realworld/manifest-realworld-v1.jsonl and its .metadata.json.
"""

import argparse
import json
import logging
import os
import sys
from datetime import UTC, date, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.dataset_collection.collect import Seeds, collect  # noqa: E402
from app.dataset_collection.sources.base import CollectionContext, Criteria, MetadataClient  # noqa: E402
from app.ml.realworld.dedup import deduplicate, family_identity_conflicts  # noqa: E402
from app.ml.realworld.manifest import write_manifest  # noqa: E402

DATA_DIR = REPO_ROOT / "ml" / "data" / "realworld"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=Path, default=DATA_DIR / "seeds-v1.json")
    parser.add_argument("--out", type=Path, default=DATA_DIR)
    parser.add_argument("--today", type=date.fromisoformat, default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    seeds = Seeds.model_validate_json(args.seeds.read_text(encoding="utf-8"))
    today = args.today or datetime.now(UTC).date()
    criteria = Criteria()
    with MetadataClient(github_token=os.environ.get("GITHUB_TOKEN")) as client:
        ctx = CollectionContext(client=client, today=today, criteria=criteria)
        records = collect(ctx, seeds)
        request_count = client.request_count
    kept, report = deduplicate(records)
    conflicts = family_identity_conflicts(kept)
    if conflicts:
        print(
            json.dumps({"family_identity_conflicts": sorted(conflicts)}),
            file=sys.stderr,
        )
        return 1
    metadata = write_manifest(
        kept,
        args.out,
        {
            "collection_date": today.isoformat(),
            "seeds_file": args.seeds.name,
            "seeds_version": seeds.version,
            "criteria": criteria.as_dict(),
            "dedup": report.as_dict(),
            "source_errors": ctx.errors,
            "request_count": request_count,
        },
    )
    keys = ("record_count", "family_count", "label_counts", "type_label_counts")
    summary = {k: metadata[k] for k in keys}
    summary["scan_eligible_count"] = metadata["scan_eligible_count"]
    summary["source_errors"] = len(ctx.errors)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

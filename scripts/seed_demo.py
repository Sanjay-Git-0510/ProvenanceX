#!/usr/bin/env python3
"""Seed the demo with benign fixtures, and print what the scans really produced.

Only the fixed list below is submitted. The BLOCK case is created in a temporary directory at
run time and is never committed: a few pickle opcode bytes holding a global reference and STOP,
with no call. Nothing here loads it, and the scanner only walks its opcodes with pickletools.

No decision is assumed. The results are wiring checks on synthetic fixtures, not detection results.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import ci_gate

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "backend" / "tests" / "fixtures" / "e2e"
DEFAULT_API_URL = "http://127.0.0.1:18080/api/v1"
COMMITTED_CASES = (
    ("software", "software_clean"),
    ("software", "software_risky_config"),
    ("model", "model_clean"),
    ("model", "model_risky_config"),
)
GENERATED_CASE = "model_dangerous_global"
INERT_GLOBAL_REFERENCE = b"cos\nsystem\n."
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
ANCHOR_WAIT_SECONDS = 60


def write_generated_case(parent: Path) -> Path:
    """Build the BLOCK case under a temporary directory. It is parsed by the scanner only."""
    root = parent / GENERATED_CASE
    shutil.copytree(FIXTURES / "model_clean", root)
    (root / "weights.pkl").write_bytes(INERT_GLOBAL_REFERENCE)
    return root


def wait_for_anchor(client: Any, scan_id: str, timeout: float, poll: float) -> str:
    """The anchor step runs just after the scan completes, so its status can lag briefly."""
    deadline = time.monotonic() + timeout
    status = "missing"
    while True:
        record = client.get(f"/scans/{scan_id}/blockchain").get("record")
        status = (record or {}).get("status") or "missing"
        if status in {"confirmed", "failed"} or time.monotonic() >= deadline:
            return ci_gate.identifier(status) or "unrecognized"
        time.sleep(poll)


def seed_case(client: Any, kind: str, root: Path, name: str, args: argparse.Namespace) -> dict:
    payload = ci_gate.zip_directory(root, MAX_ARCHIVE_BYTES)
    scan_id = client.submit(kind, name, payload)
    status = ci_gate.wait_for_scan(client, scan_id, args.timeout, args.poll)
    risk = client.get(f"/scans/{scan_id}/risk") if status == "completed" else {}
    decision = risk.get("decision") if isinstance(risk, dict) else None
    return {
        "name": name,
        "scan_id": scan_id,
        "status": status,
        "decision": decision if decision in {"ALLOW", "REVIEW", "BLOCK"} else None,
        "score": risk.get("risk_score") if isinstance(risk, dict) else None,
        "confidence": risk.get("confidence") if isinstance(risk, dict) else None,
        "not_evaluated": risk.get("not_evaluated_layers") if isinstance(risk, dict) else None,
        "anchor": wait_for_anchor(client, scan_id, args.anchor_wait, args.poll)
        if status == "completed"
        else "none",
    }


def run_cases(client: Any, args: argparse.Namespace) -> list[dict]:
    results = [
        seed_case(client, kind, FIXTURES / fixture, f"demo-{fixture}", args)
        for kind, fixture in COMMITTED_CASES
    ]
    with tempfile.TemporaryDirectory(prefix="provenancex-demo-") as temporary:
        root = write_generated_case(Path(temporary))
        results.append(seed_case(client, "model", root, f"demo-{GENERATED_CASE}", args))
    return results


def _layers(values: Any) -> str:
    if not isinstance(values, list):
        return "not reported"
    return ",".join(ci_gate.identifier(value) or "unrecognized" for value in values) or "none"


def print_results(results: list[dict]) -> None:
    ci_gate.safe_log("Results (wiring checks on synthetic fixtures, not detection results):")
    for row in results:
        score = ci_gate._number(row["score"], "not computed")
        confidence = ci_gate._number(row["confidence"], "not computed")
        ci_gate.safe_log(
            f"  {row['name']}: decision={row['decision'] or 'none'} score={score} "
            f"confidence={confidence} not_evaluated={_layers(row['not_evaluated'])} "
            f"anchor={row['anchor']} scan={row['scan_id']}"
        )


def succeeded(row: dict) -> bool:
    return (
        row["status"] == "completed"
        and row["decision"] is not None
        and row["anchor"] == "confirmed"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Seed the ProvenanceX demo")
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--poll", type=float, default=2)
    parser.add_argument("--anchor-wait", type=float, default=ANCHOR_WAIT_SECONDS)
    return parser


def main(argv: list[str] | None = None, client: Any = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        api = client or ci_gate.ApiClient(ci_gate.validate_api_url(args.api_url))
        results = run_cases(api, args)
    except ci_gate.GateError as exc:
        ci_gate.safe_log(f"Seeding failed: {exc.message}")
        return 1
    print_results(results)
    if not all(succeeded(row) for row in results):
        ci_gate.safe_log("Seeding failed: a scan did not finish with a decision and an anchor")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Bounded scan step: send scan-eligible manifest records through the normal ProvenanceX API.

The API queues each scan and the scan-runner runs it with all sandbox rules (isolated fetcher,
egress allowlist, no-network analyzers, timeouts, no host fallback). This module never touches
an artifact: it only submits a URL plus a pinned revision and reads back the stored evidence.

Safety rules:
- The API base must be a loopback address (the local stack).
- Only records with scan_eligible=True and a scannable label are submitted. Malicious and
  suspicious records are refused even if someone edits the manifest.
- MAX_SCANS (200) caps the total rows in the output file, across resumed runs.
- A row is usable for training only when the scan completed, a feature vector was stored and no
  stage used mock evidence.
"""

import ipaddress
import json
import logging
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.ml.realworld.manifest import SCANNABLE_LABELS, ManifestRecord

logger = logging.getLogger(__name__)

MAX_SCANS = 200
SUBMIT_RETRY_DELAYS = (15.0, 30.0, 60.0)  # seconds; transient DNS failures make the API answer 400
MAX_CONSECUTIVE_SUBMIT_ERRORS = 5
TERMINAL = frozenset({"completed", "failed"})
FEATURE_ROWS_FORMAT = "provenancex-realworld-features-v1"


class ScanStepError(Exception):
    """The scan step cannot run (bad configuration or an unusable API)."""


def check_api_base(api_base: str) -> str:
    parts = urlsplit(api_base)
    host = parts.hostname or ""
    if parts.scheme not in ("http", "https") or parts.path not in ("", "/"):
        raise ScanStepError("api_base must be like http://127.0.0.1:8000")
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ScanStepError("api_base must be a loopback address")
        except ValueError as exc:
            raise ScanStepError("api_base must be a loopback address") from exc
    return api_base.rstrip("/")


def refuse_unscannable(record: ManifestRecord) -> None:
    if not record.scan_eligible or record.label not in SCANNABLE_LABELS:
        raise ScanStepError(f"{record.record_id}: label {record.label} must never be scanned")
    if not record.scan_url or not record.revision:
        raise ScanStepError(f"{record.record_id}: no scan URL or pinned revision")


class ApiClient:
    def __init__(
        self, api_base: str, transport: httpx.BaseTransport | None = None, timeout: float = 30.0
    ) -> None:
        self.base = check_api_base(api_base)
        self._http = httpx.Client(timeout=timeout, follow_redirects=False, transport=transport)

    def close(self) -> None:
        self._http.close()

    def _json(self, response: httpx.Response) -> Any:
        if response.status_code >= 400:
            raise ScanStepError(f"API {response.request.url.path}: HTTP {response.status_code}")
        return response.json()

    def submit(self, record: ManifestRecord) -> str:
        refuse_unscannable(record)
        if record.artifact_type == "software":
            path, form = "/api/v1/scans/software", {}
        else:
            path, form = "/api/v1/scans/model", {"artifact_type": record.artifact_type}
        form.update(source_url=str(record.scan_url), revision=str(record.revision))
        data = self._json(self._http.post(self.base + path, data=form))
        return str(data["scan_id"])

    def scan(self, scan_id: str) -> dict[str, Any]:
        return self._json(self._http.get(f"{self.base}/api/v1/scans/{scan_id}"))

    def evidence(self, scan_id: str) -> dict[str, Any]:
        return self._json(self._http.get(f"{self.base}/api/v1/scans/{scan_id}/evidence"))


def balanced_selection(records: Iterable[ManifestRecord], limit: int) -> list[ManifestRecord]:
    """Round-robin over (artifact_type, label) groups, record_id order inside each group."""
    groups: dict[tuple[str, str], list[ManifestRecord]] = {}
    for record in sorted(records, key=lambda r: r.record_id):
        groups.setdefault((record.artifact_type, str(record.label)), []).append(record)
    queues = [groups[key] for key in sorted(groups)]
    out: list[ManifestRecord] = []
    while len(out) < limit and any(queues):
        for queue in queues:
            if queue and len(out) < limit:
                out.append(queue.pop(0))
    return out


def feature_row(
    record: ManifestRecord,
    scan_id: str,
    evidence: dict[str, Any] | None,
    status: str,
    error: str | None = None,
) -> dict[str, Any]:
    """One output row. Values are copied from the stored evidence, never filled in."""
    ev = evidence or {}
    vector = ev.get("feature_vector") or {}
    features = {f["name"]: f.get("value") for f in vector.get("features") or []}
    reasons = {
        f["name"]: f.get("null_reason")
        for f in vector.get("features") or []
        if f.get("value") is None
    }
    mock = ev.get("mock") or {}
    artifact = ev.get("artifact") or {}
    usable = (
        status == "completed"
        and vector.get("status") == "available"
        and not mock.get("contains_mock_evidence", True)
    )
    return {
        "format": FEATURE_ROWS_FORMAT,
        "dataset_version": record.dataset_version,
        "record_id": record.record_id,
        "family_id": record.family_id,
        "artifact_identifier": record.artifact_identifier,
        "artifact_type": record.artifact_type,
        "label": str(record.label),
        "ground_truth_status": str(record.ground_truth_status),
        "revision": record.revision,
        "scan_id": scan_id,
        "scan_status": status,
        "scanner_version": ev.get("scanner_version"),
        "sha256": artifact.get("sha256"),
        "feature_status": vector.get("status"),
        "features": features,
        "null_reasons": reasons,
        "stage_statuses": {s.get("name"): s.get("status") for s in ev.get("stages") or []},
        "contains_mock_evidence": mock.get("contains_mock_evidence"),
        "mock_stages": mock.get("mock_stages") or [],
        "error": error,
        "usable_for_training": usable,
        "collected_at": datetime.now(UTC).isoformat(),
    }


def existing_rows(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            rows[row["record_id"]] = row
    return rows


def archive_retryable(out_path: Path, archive_path: Path) -> int:
    """Move rows that did not complete to the archive file, so the next run retries them.

    The archive keeps every earlier attempt; nothing is deleted. Returns the rows moved.
    """
    rows = existing_rows(out_path)
    retry = [r for r in rows.values() if r.get("scan_status") != "completed"]
    if not retry:
        return 0
    with archive_path.open("a", encoding="utf-8") as archive:
        for row in retry:
            archive.write(json.dumps(row, sort_keys=True) + "\n")
    keep = [r for r in rows.values() if r.get("scan_status") == "completed"]
    out_path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in keep), "utf-8")
    return len(retry)


def run_scans(
    records: list[ManifestRecord],
    out_path: Path,
    client: ApiClient,
    *,
    max_scans: int = MAX_SCANS,
    concurrency: int = 2,
    per_scan_timeout: float = 2400.0,
    poll_interval: float = 10.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, int]:
    """Scan up to max_scans eligible records (resumable). Returns counts by outcome."""
    if not 1 <= max_scans <= MAX_SCANS:
        raise ScanStepError(f"max_scans must be between 1 and {MAX_SCANS}")
    if not 1 <= concurrency <= 4:
        raise ScanStepError("concurrency must be between 1 and 4")
    done = existing_rows(out_path)
    budget = max(0, max_scans - len(done))
    eligible = [r for r in records if r.scan_eligible and r.record_id not in done]
    for record in eligible:
        refuse_unscannable(record)
    queue = balanced_selection(eligible, budget)
    counts = {
        "submitted": 0,
        "completed": 0,
        "failed": 0,
        "timed_out": 0,
        "submit_error": 0,
        "not_attempted": 0,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    in_flight: dict[str, tuple[ManifestRecord, float]] = {}
    consecutive_submit_errors = 0

    with out_path.open("a", encoding="utf-8") as out:

        def write(row: dict[str, Any]) -> None:
            out.write(json.dumps(row, sort_keys=True) + "\n")
            out.flush()

        while queue or in_flight:
            while queue and len(in_flight) < concurrency:
                if consecutive_submit_errors >= MAX_CONSECUTIVE_SUBMIT_ERRORS:
                    logger.error("Stopping: %d submit errors in a row", consecutive_submit_errors)
                    counts["not_attempted"] = len(queue)
                    queue.clear()  # left unwritten, so a later run picks them up
                    break
                record = queue.pop(0)
                scan_id, error = None, None
                for delay in (*SUBMIT_RETRY_DELAYS, None):
                    try:
                        scan_id = client.submit(record)
                        break
                    except (ScanStepError, httpx.HTTPError, KeyError, ValueError) as exc:
                        error = exc
                        if delay is None:
                            break
                        logger.warning("Submit failed for %s (%s); retrying", record.record_id, exc)
                        sleep(delay)
                if scan_id is None:
                    logger.warning("Submit failed for %s: %s", record.record_id, error)
                    counts["submit_error"] += 1
                    consecutive_submit_errors += 1
                    write(feature_row(record, "", None, "submit_error", str(error)[:300]))
                    continue
                consecutive_submit_errors = 0
                counts["submitted"] += 1
                in_flight[scan_id] = (record, clock())
            if not in_flight:
                break
            sleep(poll_interval)
            for scan_id, (record, started) in list(in_flight.items()):
                try:
                    status = str(client.scan(scan_id).get("status"))
                except (ScanStepError, httpx.HTTPError, ValueError) as exc:
                    logger.warning("Status check failed for %s: %s", scan_id, exc)
                    status = "unknown"
                if status in TERMINAL:
                    try:
                        evidence, error = client.evidence(scan_id), None
                    except (ScanStepError, httpx.HTTPError, ValueError) as exc:
                        evidence, error = None, f"evidence unavailable: {exc}"[:300]
                    counts[status] += 1
                    write(feature_row(record, scan_id, evidence, status, error))
                    del in_flight[scan_id]
                elif clock() - started > per_scan_timeout:
                    counts["timed_out"] += 1
                    write(feature_row(record, scan_id, None, "timed_out", "scan step timeout"))
                    del in_flight[scan_id]
    return counts

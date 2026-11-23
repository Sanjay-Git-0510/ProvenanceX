"""Bounded scan step: loopback-only API, refusal of unscannable labels, cap, resume, mock rows."""

import json

import httpx
import pytest

from app.dataset_collection.scan_client import (
    MAX_SCANS,
    ApiClient,
    ScanStepError,
    balanced_selection,
    check_api_base,
    refuse_unscannable,
    run_scans,
)
from app.ml.realworld.manifest import GroundTruth, RealLabel
from tests.realworld_helpers import record


@pytest.mark.parametrize(
    "base", ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000/"]
)
def test_loopback_api_base_accepted(base):
    assert check_api_base(base).startswith("http")


@pytest.mark.parametrize(
    "base",
    ["http://10.0.0.5:8000", "https://example.com", "ftp://127.0.0.1", "http://127.0.0.1/api"],
)
def test_non_loopback_api_base_rejected(base):
    with pytest.raises(ScanStepError):
        check_api_base(base)


def test_malicious_record_is_refused_even_if_edited():
    rec = record(
        label=RealLabel.CONFIRMED_MALICIOUS,
        ground_truth_status=GroundTruth.ESTABLISHED,
        scan_eligible=False,
    )
    forced = rec.model_copy(update={"scan_eligible": True})  # bypasses validation on purpose
    with pytest.raises(ScanStepError, match="never be scanned"):
        refuse_unscannable(forced)


def recs(n, artifact_type="software"):
    return [
        record(
            artifact_identifier=f"github.com/o/r{i}",
            artifact_type=artifact_type,
            record_id=f"rw-{artifact_type}-{i:03d}",
            family_id=f"github:o/r{i}",
        )
        for i in range(n)
    ]


def test_balanced_selection_round_robins_groups():
    pool = recs(5) + recs(2, "model")
    chosen = balanced_selection(pool, 4)
    assert [r.artifact_type for r in chosen] == ["model", "software", "model", "software"]


class FakeApi:
    """Stands in for the local API. Scans finish after one poll."""

    def __init__(self, mock=False, fail_submit=False, never_finish=False):
        self.mock, self.fail_submit, self.never_finish = mock, fail_submit, never_finish
        self.submitted = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST":
            if self.fail_submit:
                return httpx.Response(400, json={"error": "bad"})
            form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
            self.submitted.append((path, form))
            return httpx.Response(202, json={"scan_id": f"s{len(self.submitted)}"})
        if path.endswith("/evidence"):
            return httpx.Response(
                200,
                json={
                    "scanner_version": "test",
                    "artifact": {"sha256": "a" * 64},
                    "stages": [{"name": "sbom", "status": "completed"}],
                    "feature_vector": {
                        "status": "available",
                        "features": [
                            {"name": "dependency_count", "value": 3},
                            {"name": "signed", "value": None, "null_reason": "no_data_source"},
                        ],
                    },
                    "mock": {"contains_mock_evidence": self.mock, "mock_stages": []},
                },
            )
        status = "running" if self.never_finish else "completed"
        return httpx.Response(200, json={"status": status})


def run(tmp_path, api, records, **kw):
    client = ApiClient("http://127.0.0.1:8000", transport=httpx.MockTransport(api))
    out = tmp_path / "features.jsonl"
    counts = run_scans(records, out, client, sleep=lambda _: None, poll_interval=0, **kw)
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    return counts, rows


def test_run_scans_writes_rows_from_stored_evidence(tmp_path):
    api = FakeApi()
    counts, rows = run(tmp_path, api, recs(3))
    assert counts["completed"] == 3
    assert api.submitted[0][0] == "/api/v1/scans/software"
    assert api.submitted[0][1]["revision"] == "22d924701a6ae2e4cd01e9a15bbaf3946094af65"
    row = rows[0]
    assert row["usable_for_training"] is True
    assert row["sha256"] == "a" * 64
    assert row["features"] == {"dependency_count": 3, "signed": None}
    assert row["null_reasons"] == {"signed": "no_data_source"}


def test_model_records_send_artifact_type(tmp_path):
    api = FakeApi()
    lora = recs(1, "lora")
    lora[0] = lora[0].model_copy(update={"scan_url": "https://huggingface.co/a/b"})
    run(tmp_path, api, lora)
    path, form = api.submitted[0]
    assert path == "/api/v1/scans/model" and form["artifact_type"] == "lora"


def test_mock_evidence_rows_are_not_usable(tmp_path):
    _, rows = run(tmp_path, FakeApi(mock=True), recs(1))
    assert rows[0]["usable_for_training"] is False


def test_unscannable_records_are_skipped(tmp_path):
    unknown = record(
        label=RealLabel.UNKNOWN, ground_truth_status=GroundTruth.NONE, scan_eligible=False
    )
    api = FakeApi()
    counts, rows = run(tmp_path, api, [unknown] + recs(1))
    assert counts["submitted"] == 1 and len(rows) == 1


def test_cap_counts_previous_rows_and_resume_skips_done(tmp_path):
    api = FakeApi()
    pool = recs(5)
    run(tmp_path, api, pool, max_scans=2)
    counts, rows = run(tmp_path, api, pool, max_scans=3)
    assert counts["submitted"] == 1  # only one more fits under the total cap of 3
    assert len(rows) == 3 and len({r["record_id"] for r in rows}) == 3


@pytest.mark.parametrize("value", [0, MAX_SCANS + 1])
def test_max_scans_bounds(tmp_path, value):
    with pytest.raises(ScanStepError):
        run(tmp_path, FakeApi(), recs(1), max_scans=value)


def test_submit_errors_are_recorded(tmp_path):
    counts, rows = run(tmp_path, FakeApi(fail_submit=True), recs(1))
    assert counts["submit_error"] == 1
    assert rows[0]["scan_status"] == "submit_error" and not rows[0]["usable_for_training"]


def test_scan_step_timeout(tmp_path):
    ticks = iter(range(0, 10_000, 1000))
    client = ApiClient(
        "http://127.0.0.1:8000", transport=httpx.MockTransport(FakeApi(never_finish=True))
    )
    out = tmp_path / "f.jsonl"
    counts = run_scans(
        recs(1),
        out,
        client,
        sleep=lambda _: None,
        poll_interval=0,
        per_scan_timeout=1500,
        clock=lambda: next(ticks),
    )
    assert counts["timed_out"] == 1
    assert json.loads(out.read_text())["scan_status"] == "timed_out"


def test_archive_retryable_keeps_history(tmp_path):
    from app.dataset_collection.scan_client import archive_retryable

    out, archive = tmp_path / "f.jsonl", tmp_path / "f.attempts.jsonl"
    rows = [
        {"record_id": "a", "scan_status": "completed"},
        {"record_id": "b", "scan_status": "failed"},
        {"record_id": "c", "scan_status": "submit_error"},
    ]
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert archive_retryable(out, archive) == 2
    assert [json.loads(x)["record_id"] for x in out.read_text().splitlines()] == ["a"]
    assert [json.loads(x)["record_id"] for x in archive.read_text().splitlines()] == ["b", "c"]
    assert archive_retryable(out, archive) == 0


def test_submit_retries_then_stops_after_consecutive_errors(tmp_path):
    api = FakeApi(fail_submit=True)
    counts, rows = run(tmp_path, api, recs(8))
    assert counts["submit_error"] == 5  # circuit breaker
    assert counts["not_attempted"] == 3
    assert len(rows) == 5  # the rest stay unwritten for the next run


def test_submit_recovers_after_transient_error(tmp_path):
    class Flaky(FakeApi):
        def __init__(self):
            super().__init__()
            self.posts = 0

        def __call__(self, request):
            if request.method == "POST":
                self.posts += 1
                if self.posts == 1:
                    return httpx.Response(400, json={"error": "dns"})
            return super().__call__(request)

    counts, rows = run(tmp_path, Flaky(), recs(1))
    assert counts["completed"] == 1 and counts["submit_error"] == 0

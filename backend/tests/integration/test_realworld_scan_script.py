"""Phase 4: ml/scripts/scan_realworld.py against a fake ProvenanceX API on 127.0.0.1.

The fake API is a tiny local HTTP server; no stack, sandbox or network is involved. run_scans is
wrapped so the script does not wait 10 s between polls; everything else (argument parsing,
--retry-failed archiving, the loopback check, the 200-row cap) is the real script.
"""

import importlib.util
import json
import sys
import threading
import uuid
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.dataset_collection import scan_client
from app.dataset_collection.scan_client import FEATURE_ROWS_FORMAT, ScanStepError
from app.ml.feature_schema import FEATURE_NAMES
from app.ml.realworld.manifest import DATASET_VERSION, write_manifest
from tests.conftest import FIXTURES
from tests.realworld_helpers import record

SCRIPT = FIXTURES.parents[2] / "ml" / "scripts" / "scan_realworld.py"


class FakeApi(BaseHTTPRequestHandler):
    """POST queues a scan; GET reports it completed; /evidence returns a mock-free vector."""

    submitted: list[str]

    def log_message(self, *args):  # keep test output quiet
        pass

    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = self.rfile.read(length).decode()
        self.server.submitted.append(form)
        self._send(202, {"scan_id": str(uuid.uuid4()), "status": "queued"})

    def do_GET(self):
        if self.path.endswith("/evidence"):
            self._send(
                200,
                {
                    "scanner_version": "test",
                    "artifact": {"sha256": "a" * 64},
                    "feature_vector": {
                        "status": "available",
                        "features": [
                            {"name": n, "value": 1 if n == "dependency_count" else None}
                            for n in FEATURE_NAMES
                        ],
                    },
                    "mock": {"contains_mock_evidence": False, "mock_stages": []},
                    "stages": [{"name": "fetch", "status": "completed"}],
                },
            )
        else:
            self._send(200, {"status": "completed"})


@pytest.fixture
def api():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeApi)
    server.submitted = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def load_script(monkeypatch):
    spec = importlib.util.spec_from_file_location("scan_realworld_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fast = partial(scan_client.run_scans, poll_interval=0, sleep=lambda _: None)
    monkeypatch.setattr(module, "run_scans", fast)
    return module


def setup_data(tmp_path, n):
    recs = [
        record(artifact_identifier=f"github.com/o/r{i}", family_id=f"github:o/r{i}")
        for i in range(n)
    ]
    write_manifest(recs, tmp_path, {})
    return sorted(recs, key=lambda r: r.record_id), tmp_path / f"manifest-{DATASET_VERSION}.jsonl"


def old_row(rec, status):
    return {
        "format": FEATURE_ROWS_FORMAT,
        "record_id": rec.record_id,
        "scan_status": status,
        "scan_id": "old",
        "error": "clone_failed" if status != "completed" else None,
    }


def rows(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def main(monkeypatch, module, *args):
    monkeypatch.setattr(sys, "argv", ["scan_realworld.py", *args])
    return module.main()


def test_retry_failed_resumes_and_archives(tmp_path, api, monkeypatch):
    recs, manifest = setup_data(tmp_path, 4)
    out = tmp_path / "features.jsonl"
    out.write_text(
        json.dumps(old_row(recs[0], "completed"))
        + "\n"
        + json.dumps(old_row(recs[1], "failed"))
        + "\n"
    )
    module = load_script(monkeypatch)
    api_url = f"http://127.0.0.1:{api.server_port}"
    args = ["--api", api_url, "--manifest", str(manifest), "--out", str(out)]
    assert main(monkeypatch, module, *args, "--retry-failed") == 0

    got = {r["record_id"]: r for r in rows(out)}
    assert set(got) == {r.record_id for r in recs}
    assert got[recs[0].record_id]["scan_id"] == "old"  # completed row kept, not rescanned
    assert len(api.submitted) == 3  # the failed row and the two never-attempted rows
    assert all(got[r.record_id]["usable_for_training"] for r in recs[1:])
    archive = rows(out.with_suffix(".attempts.jsonl"))
    assert [(a["record_id"], a["scan_status"]) for a in archive] == [(recs[1].record_id, "failed")]

    api.submitted.clear()
    assert main(monkeypatch, module, *args, "--retry-failed") == 0  # nothing left to do
    assert api.submitted == [] and len(rows(out)) == 4


def test_without_retry_failed_rows_are_not_rescanned(tmp_path, api, monkeypatch):
    recs, manifest = setup_data(tmp_path, 2)
    out = tmp_path / "features.jsonl"
    out.write_text(json.dumps(old_row(recs[0], "failed")) + "\n")
    module = load_script(monkeypatch)
    api_url = f"http://127.0.0.1:{api.server_port}"
    assert (
        main(monkeypatch, module, "--api", api_url, "--manifest", str(manifest), "--out", str(out))
        == 0
    )
    assert len(api.submitted) == 1 and not out.with_suffix(".attempts.jsonl").exists()


def test_max_scans_counts_rows_already_written(tmp_path, api, monkeypatch):
    recs, manifest = setup_data(tmp_path, 5)
    out = tmp_path / "features.jsonl"
    out.write_text("".join(json.dumps(old_row(r, "completed")) + "\n" for r in recs[:2]))
    module = load_script(monkeypatch)
    api_url = f"http://127.0.0.1:{api.server_port}"
    args = ["--api", api_url, "--manifest", str(manifest), "--out", str(out), "--max-scans", "3"]
    assert main(monkeypatch, module, *args) == 0
    assert len(api.submitted) == 1 and len(rows(out)) == 3


def test_cap_above_200_is_refused(tmp_path, api, monkeypatch):
    _, manifest = setup_data(tmp_path, 1)
    module = load_script(monkeypatch)
    api_url = f"http://127.0.0.1:{api.server_port}"
    args = ["--api", api_url, "--manifest", str(manifest), "--out", str(tmp_path / "o.jsonl")]
    with pytest.raises(ScanStepError, match="between 1 and 200"):
        main(monkeypatch, module, *args, "--max-scans", "201")
    assert api.submitted == []


@pytest.mark.parametrize(
    "url",
    ["http://10.0.0.5:8000", "http://example.com:8000", "http://192.168.1.2", "ftp://127.0.0.1"],
)
def test_non_loopback_api_is_refused_before_any_request(tmp_path, monkeypatch, url):
    _, manifest = setup_data(tmp_path, 1)
    out = tmp_path / "o.jsonl"
    module = load_script(monkeypatch)
    with pytest.raises(ScanStepError):
        main(monkeypatch, module, "--api", url, "--manifest", str(manifest), "--out", str(out))
    assert not out.exists()

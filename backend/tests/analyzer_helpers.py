"""Helpers for the analyzer-sandbox tests: a fake Docker CLI, jobs and canned worker results."""

import json
import os
import stat
import sys
import uuid
from pathlib import Path

from app.analysis.base import AnalysisJob
from app.core.config import Settings
from app.pipeline.workspace import create_workspace
from app.sandbox_worker.protocol import RESULT_FORMAT
from tests.conftest import FIXTURES

FAKE_DOCKER_SOURCE = FIXTURES / "sandbox" / "fake_docker.py"
ISOLATED = {
    "non_root": True,
    "no_new_privileges": True,
    "capabilities_dropped": True,
    "rootfs_read_only": True,
    "network_isolated": True,
    "no_docker_socket": True,
}


class FakeDocker:
    def __init__(self, tmp_path: Path, monkeypatch, **config) -> None:
        self.state = tmp_path / "fake-docker-state"
        self.state.mkdir()
        self.path = tmp_path / "fake-docker"
        self.path.write_text(f"#!{sys.executable}\n" + FAKE_DOCKER_SOURCE.read_text())
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("DOCKER_CONFIG", str(self.state))
        self.configure(**config)

    def configure(self, **config) -> None:
        (self.state / "fake.json").write_text(json.dumps(config))

    def calls(self) -> list[list[str]]:
        log = self.state / "calls.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    def verbs(self) -> list[str]:
        return [c[0] if c[0] != "image" else "image inspect" for c in self.calls()]

    def stdin(self) -> dict:
        return json.loads((self.state / "stdin.json").read_text())


def analyzer_settings(tmp_path: Path, docker: Path | str, **overrides) -> Settings:
    values = {
        "_env_file": None,
        "workspace_root": tmp_path / "workspaces",
        "analyzer_docker_path": str(docker),
        "analyzer_timeout_seconds": 20,
        "analyzer_extract_timeout_seconds": 20,
        "analyzer_host_grace_seconds": 5,
        "sbom_provider": "mock",
    }
    values.update(overrides)
    return Settings(**values)


def make_job(settings: Settings, *, kind: str = "software", upload: bool = True) -> AnalysisJob:
    scan_id = uuid.uuid4()
    workspace = create_workspace(settings.workspace_root, scan_id)
    if upload:
        workspace.upload_path.write_bytes(b"PK\x05\x06" + b"\0" * 18)
    return AnalysisJob(scan_id=scan_id, workspace=workspace, kind=kind, has_upload=upload)


def minimal_analysis() -> dict:
    return {
        "tree": {"sha256": "a" * 64, "file_count": 1, "total_bytes": 3},
        "file_paths": ["a.py"],
    }


def worker_output(
    path: Path,
    mode: str,
    *,
    status: str = "ok",
    isolation: dict | None = None,
    isolation_mode: str = "container",
    analysis: dict | None = None,
    error: dict | None = None,
    raw: bytes | None = None,
) -> Path:
    """Write a worker result for the fake `docker start` and return its path."""
    if raw is None:
        doc: dict = {
            "format": RESULT_FORMAT,
            "mode": mode,
            "status": status,
            "isolation_mode": isolation_mode,
            "isolation": ISOLATED if isolation is None else isolation,
        }
        if error is not None:
            doc["error"] = error
        if status == "ok" and mode == "analyze":
            doc["analysis"] = analysis or minimal_analysis()
        raw = json.dumps(doc).encode()
    path.write_bytes(raw)
    return path


def owned_by_current_user() -> bool:
    return os.getuid() != 0

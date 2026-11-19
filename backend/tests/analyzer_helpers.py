"""Helpers for the analyzer-sandbox tests: a fake Docker CLI, jobs and canned worker results."""

import io
import json
import os
import stat
import sys
import uuid
from pathlib import Path

from app.analysis.base import AnalysisJob
from app.analysis.framing import write_frames
from app.analysis.staging import volume_name
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
    "seccomp_filtered": True,
    "no_secret_env": True,
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
    return AnalysisJob(
        scan_id=scan_id,
        workspace=workspace,
        kind=kind,
        has_upload=upload,
        staging_volume=volume_name(scan_id),
    )


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
    persisted: dict | None = None,
    sbom: bytes | None = None,
    frame: bool = True,
) -> Path:
    """Write a framed worker result for the fake `docker start` and return its path.

    `raw` is written as the envelope (framed unless frame=False); `sbom` adds an SBOM frame.
    """
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
        if status == "ok" and mode == "persist":
            doc["persisted"] = persisted or minimal_analysis()["tree"]
        raw = json.dumps(doc).encode()
    if frame:
        buf = io.BytesIO()
        write_frames(buf, raw, io.BytesIO(sbom) if sbom is not None else None)
        raw = buf.getvalue()
    path.write_bytes(raw)
    return path


def owned_by_current_user() -> bool:
    return os.getuid() != 0


FETCHER_ISOLATED = {
    "non_root": True,
    "no_new_privileges": True,
    "capabilities_dropped": True,
    "rootfs_read_only": True,
    "single_interface": True,
    "no_docker_socket": True,
    "seccomp_filtered": True,
    "no_secret_env": True,
    "direct_egress_blocked": True,
    "external_dns_blocked": True,
}


def fetch_output(
    path: Path,
    *,
    source: str = "github",
    status: str = "ok",
    isolation: dict | None = None,
    error: dict | None = None,
    raw: bytes | None = None,
    frame: bool = True,
    **fields,
) -> Path:
    """Write a framed fetcher result for the fake `docker start`."""
    if raw is None:
        doc: dict = {
            "format": "provenancex-fetch-result-v1",
            "status": status,
            "isolation_mode": "container",
            "isolation": FETCHER_ISOLATED if isolation is None else isolation,
            "source": source,
        }
        if status == "ok" and source == "github":
            doc.update(
                commit_sha="c" * 40,
                git={"commit_sha": "c" * 40, "revision": None},
                file_count=1,
                total_bytes=3,
            )
        if error is not None:
            doc["error"] = error
        doc.update(fields)
        raw = json.dumps(doc).encode()
    if frame:
        buf = io.BytesIO()
        write_frames(buf, raw)
        raw = buf.getvalue()
    path.write_bytes(raw)
    return path

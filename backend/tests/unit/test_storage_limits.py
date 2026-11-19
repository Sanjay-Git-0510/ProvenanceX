"""Persistent workspace budget, the persist integrity check, and the memory-limited SBOM parser.

The kernel-enforced staging cap is proven on real Docker in tests/integration/test_fetcher_live.py
(write past the cap -> ENOSPC). These tests cover the host-side bookkeeping around it."""

import json
import uuid
from datetime import timedelta
from pathlib import Path

import pytest

from app.core.errors import AppError
from app.db.models import Artifact, ArtifactSource, ArtifactType, Scan, ScanStatus, utcnow
from app.pipeline.retention import ensure_workspace_room
from app.scanners.sbom.parse_child import parse_sbom_isolated
from tests.conftest import FIXTURES, zip_dir

MB = 1024 * 1024


def _scan(session_factory, status, finished_minutes_ago=0):
    with session_factory() as session:
        scan = Scan(
            id=uuid.uuid4(),
            artifact=Artifact(
                artifact_type=ArtifactType.SOFTWARE, name="x", source=ArtifactSource.UPLOAD
            ),
            scanner_version="test",
            status=status,
            finished_at=utcnow() - timedelta(minutes=finished_minutes_ago)
            if status in (ScanStatus.COMPLETED, ScanStatus.FAILED)
            else None,
        )
        session.add(scan)
        session.commit()
        return scan.id


def _tree(base: Path, scan_id, size: int) -> Path:
    src = base / str(scan_id) / "src"
    src.mkdir(parents=True)
    (src / "blob").write_bytes(b"x" * size)
    (base / str(scan_id) / "sbom.cdx.json").write_bytes(b"{}")
    return src


def test_oldest_finished_trees_are_pruned_first(test_settings, session_factory):
    settings = test_settings.model_copy(update={"workspace_max_total_mb": 3})
    base = settings.workspace_root
    oldest = _scan(session_factory, ScanStatus.COMPLETED, 60)
    newer = _scan(session_factory, ScanStatus.FAILED, 30)
    running = _scan(session_factory, ScanStatus.RUNNING)
    current = _scan(session_factory, ScanStatus.RUNNING)
    for sid in (oldest, newer, running):
        _tree(base, sid, MB)
    with session_factory() as session:
        pruned = ensure_workspace_room(session, settings, MB // 2, current)
    assert pruned == [oldest]
    assert list((base / str(oldest) / "src").iterdir()) == []
    assert (base / str(oldest) / "sbom.cdx.json").exists()  # small evidence is kept
    assert (base / str(newer) / "src" / "blob").exists()
    assert (base / str(running) / "src" / "blob").exists()  # never a running scan


def test_budget_that_cannot_be_met_fails(test_settings, session_factory):
    settings = test_settings.model_copy(update={"workspace_max_total_mb": 2})
    running = _scan(session_factory, ScanStatus.RUNNING)
    _tree(settings.workspace_root, running, MB + MB // 2)
    with session_factory() as session, pytest.raises(AppError) as info:
        ensure_workspace_room(session, settings, MB, uuid.uuid4())
    assert info.value.code == "workspace_budget_exceeded"
    with session_factory() as session, pytest.raises(AppError):
        ensure_workspace_room(session, settings, 3 * MB, uuid.uuid4())


def test_persisted_copy_that_differs_from_the_analysis_fails_the_scan(scan_client, monkeypatch):
    from app.analysis import inprocess

    monkeypatch.setattr(
        inprocess,
        "rehash_tree",
        lambda request, src: {"sha256": "0" * 64, "file_count": 1, "total_bytes": 1},
    )
    data = zip_dir(FIXTURES / "software" / "simple_python_project")
    resp = scan_client.post(
        "/api/v1/scans/software", files={"file": ("p.zip", data, "application/zip")}
    )
    body = scan_client.get(f"/api/v1/scans/{resp.json()['scan_id']}").json()
    assert body["status"] == "failed"
    assert body["error"]["code"] == "download_integrity_error"


# --------------------------------------------------------------------------- SBOM child
def _parse(path: Path, **kw):
    values = {
        "max_bytes": 50 * MB,
        "max_components": 50_000,
        "memory_mb": 512,
        "timeout_seconds": 60,
    }
    values.update(kw)
    return parse_sbom_isolated(path, **values)


def test_real_syft_fixture_parses_in_the_child():
    parsed = _parse(FIXTURES / "sbom" / "syft_requirements_only.cdx.json")
    assert parsed.components and parsed.spec_version


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (b"not json", "sbom_parse_error"),
        (b"[]", "sbom_parse_error"),
        (b'{"bomFormat": "SPDX"}', "sbom_parse_error"),
        (b"[" * 100_000 + b"]" * 100_000, "sbom_parse_error"),
    ],
)
def test_malformed_sboms_fail_structurally(tmp_path, content, code):
    path = tmp_path / "s.json"
    path.write_bytes(content)
    with pytest.raises(AppError) as info:
        _parse(path)
    assert info.value.code == code


def test_oversized_sbom_is_refused_by_size(tmp_path):
    path = tmp_path / "s.json"
    path.write_bytes(b" " * (2 * MB))
    with pytest.raises(AppError) as info:
        _parse(path, max_bytes=MB)
    assert info.value.code == "sbom_too_large"


def test_memory_bomb_is_contained_in_the_child(tmp_path):
    """~30 MB of empty objects expands to over 500 MB; only the child hits its limit."""
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": "a", "properties": [{}] * 400}] * 20_000,
    }
    path = tmp_path / "bomb.json"
    path.write_text(json.dumps(doc))
    assert path.stat().st_size > 20 * MB
    with pytest.raises(AppError) as info:
        _parse(path, memory_mb=192)
    assert info.value.code == "sbom_parse_error"
    assert "memory" in info.value.message


def test_component_cap_still_applies(tmp_path):
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": f"p{i}"} for i in range(20)],
    }
    path = tmp_path / "s.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(AppError):
        _parse(path, max_components=10)

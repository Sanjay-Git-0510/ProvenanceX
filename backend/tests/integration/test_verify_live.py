"""Live /verify jobs (Milestone C1, audit finding M5): the real `rehash` analyzer container.

Run with PROVENANCEX_SANDBOX_TESTS=1 after `make analyzer-image`. The Hardhat case additionally
needs PROVENANCEX_CHAIN_TESTS=1 and the variables listed in tests/integration/test_chain_live.py.
Every case anchors a scan, then answers a verification job exactly as the scan-runner does:
rehash container (network none, read-only scan mount, verified runtime) + chain comparison.
"""

import multiprocessing
import os
import signal
import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.analysis.docker_analyzer import DockerAnalyzer
from app.analysis.reconcile import OrphanReconciler
from app.blockchain.anchoring import anchor_scan
from app.blockchain.mock import MockChainProvider
from app.core.config import Settings
from app.core.hashing import sha256_file, tree_digest
from app.db.base import Base
from app.db.models import VerificationRun
from app.verification.executor import run_claimed_verification
from app.verification.jobs import claim_next_verification, enqueue, fail_stale_verifications
from tests.conftest import make_anchorable_scan, write_scan_evidence
from tests.live_helpers import ANALYZER_IMAGE, docker, image_present, state, unique

pytestmark = pytest.mark.sandbox


@pytest.fixture(scope="module", autouse=True)
def _image():
    if not image_present(ANALYZER_IMAGE):
        pytest.fail(f"{ANALYZER_IMAGE} is not built: make analyzer-image")


def _settings(tmp_path, **overrides) -> Settings:
    values = {
        "_env_file": None,
        "workspace_root": tmp_path / "ws",
        "analyzer_image": ANALYZER_IMAGE,
        "analyzer_instance": unique("pxver"),
        "scan_dispatch": "runner",
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def factory(tmp_path):
    """A file-backed SQLite database, so a forked child process can share it."""
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'db.sqlite'}")
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    engine.dispose()


def _anchored(factory, settings, chain):
    with factory() as session:
        scan_id = make_anchorable_scan(session)
        workspace = write_scan_evidence(session, scan_id, settings)
        anchor_scan(session, scan_id, chain, settings)
    return scan_id, workspace


def _answer(factory, settings, scan_id, chain):
    with factory() as session:
        enqueue(session, scan_id, settings)
        claim = claim_next_verification(session, "live")
    run_claimed_verification(claim, factory, settings, DockerAnalyzer(settings), chain)
    with factory() as session:
        return session.get(VerificationRun, claim.job_id)


def _no_containers(scan_id) -> bool:
    return docker("ps", "-aq", "--filter", f"name=px-ana-{scan_id}").stdout.strip() == ""


def test_untouched_evidence_verifies_in_a_verified_container(tmp_path, factory):
    settings, chain = _settings(tmp_path), MockChainProvider()
    scan_id, workspace = _anchored(factory, settings, chain)
    job = _answer(factory, settings, scan_id, chain)
    assert (job.status, job.state, job.reason_code) == ("completed", "VERIFIED", "verified")
    fields = {f["field"]: f for f in job.result["fields"]}
    assert fields["artifact_hash"]["recomputed"] == tree_digest(workspace.src_dir).sha256
    assert fields["bom_hash"]["recomputed"] == sha256_file(workspace.root / "sbom.cdx.json")
    (run,) = job.sandbox["runs"]
    assert run["mode"] == "rehash" and run["runtime_verified"] is True and run["exit_code"] == 0
    assert run["runtime"]["network"] == "none" and run["runtime"]["read_only_rootfs"] is True
    assert all(run["isolation"].values())
    assert _no_containers(scan_id)


@pytest.mark.parametrize("target", ["src/app.py", "sbom.cdx.json", "provenance.json"])
def test_one_changed_byte_is_a_mismatch(tmp_path, factory, target):
    settings, chain = _settings(tmp_path), MockChainProvider()
    scan_id, workspace = _anchored(factory, settings, chain)
    path = workspace.root / target
    data = bytearray(path.read_bytes())
    data[0] ^= 0x01
    path.write_bytes(bytes(data))
    job = _answer(factory, settings, scan_id, chain)
    assert (job.state, job.reason_code) == ("MISMATCH", "evidence_mismatch")


def test_a_file_swapped_for_a_symlink_is_a_mismatch(tmp_path, factory):
    settings, chain = _settings(tmp_path), MockChainProvider()
    scan_id, workspace = _anchored(factory, settings, chain)
    outside = tmp_path / "outside.json"
    outside.write_text('{"bomFormat":"CycloneDX"}')
    (workspace.root / "sbom.cdx.json").unlink()
    (workspace.root / "sbom.cdx.json").symlink_to(outside)
    job = _answer(factory, settings, scan_id, chain)
    assert job.state == "MISMATCH"
    bom = next(f for f in job.result["fields"] if f["field"] == "bom_hash")
    assert bom["status"] == "mismatch" and bom["recomputed"] is None


def test_a_deleted_tree_is_unknown(tmp_path, factory):
    settings, chain = _settings(tmp_path), MockChainProvider()
    scan_id, workspace = _anchored(factory, settings, chain)
    for path in workspace.src_dir.iterdir():
        path.unlink()
    workspace.src_dir.rmdir()
    job = _answer(factory, settings, scan_id, chain)
    assert (job.state, job.reason_code) == ("UNKNOWN", "offchain_evidence_unavailable")


def test_a_tree_over_the_file_cap_is_unknown(tmp_path, factory):
    settings, chain = _settings(tmp_path), MockChainProvider()
    scan_id, workspace = _anchored(factory, settings, chain)
    capped = settings.model_copy(update={"max_artifact_files": 1})
    (workspace.src_dir / "extra.py").write_text("x = 1\n")
    job = _answer(factory, capped, scan_id, chain)
    assert job.state == "UNKNOWN"


def _slow_settings(tmp_path, timeout):
    # A large file and a tiny CPU share make the rehash slow enough to time out or be killed.
    return _settings(
        tmp_path,
        analyzer_cpus=0.02,
        verify_rehash_timeout_seconds=timeout,
        analyzer_host_grace_seconds=5,
        verify_max_seconds=120,
    )


def _big(workspace, mb=96):
    with (workspace.src_dir / "big.bin").open("wb") as fh:
        fh.write(os.urandom(mb * 1024 * 1024))


def test_a_rehash_past_its_timeout_is_unknown(tmp_path, factory):
    settings, chain = _slow_settings(tmp_path, 5), MockChainProvider()
    scan_id, workspace = _anchored(factory, settings, chain)
    _big(workspace)  # also changes the tree, but the timeout must win: UNKNOWN, not VERIFIED
    started = time.monotonic()
    job = _answer(factory, settings, scan_id, chain)
    assert time.monotonic() - started < 60
    assert job.state == "UNKNOWN" and job.reason_code == "rehash_failed"
    assert _no_containers(scan_id)


def _child(db_path, settings_json, scan_id):  # runs in a forked process
    engine = create_engine(f"sqlite+pysqlite:///{db_path}")
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    settings = Settings.model_validate_json(settings_json)
    with factory() as session:
        claim = claim_next_verification(session, "doomed")
    run_claimed_verification(claim, factory, settings, DockerAnalyzer(settings), None)


def test_a_killed_runner_leaves_nothing_behind(tmp_path, factory):
    settings, chain = _slow_settings(tmp_path, 25), MockChainProvider()
    scan_id, workspace = _anchored(factory, settings, chain)
    _big(workspace)
    with factory() as session:
        enqueue(session, scan_id, settings)
    ctx = multiprocessing.get_context("fork")
    child = ctx.Process(
        target=_child, args=(tmp_path / "db.sqlite", settings.model_dump_json(), scan_id)
    )
    child.start()
    name = f"px-ana-{scan_id}-rehash"
    for _ in range(120):
        if (state(name) or {}).get("Running"):
            break
        time.sleep(0.25)
    assert (state(name) or {}).get("Running"), "the rehash container never started"
    os.kill(child.pid, signal.SIGKILL)
    child.join()
    # The container outlives the runner, then stops itself at its in-container deadline.
    for _ in range(90):
        if not (state(name) or {}).get("Running"):
            break
        time.sleep(1)
    assert not (state(name) or {}).get("Running")
    with factory() as session:
        (job_id,) = fail_stale_verifications(session, 0, 600)
        job = session.get(VerificationRun, job_id)
        assert (job.status, job.state, job.reason_code) == (
            "failed",
            "UNKNOWN",
            "verify_interrupted",
        )
        report = OrphanReconciler(settings).reconcile(session)
    assert report.removed and _no_containers(scan_id)


@pytest.mark.chain
def test_hardhat_anchor_verifies_then_detects_tampering(tmp_path, factory):
    from tests.integration.test_chain_live import _provider

    settings = _settings(
        tmp_path, blockchain_private_key=os.environ.get("BLOCKCHAIN_PRIVATE_KEY", "")
    )
    chain = _provider()
    scan_id, workspace = _anchored(factory, settings, chain)
    assert _answer(factory, settings, scan_id, chain).state == "VERIFIED"
    (workspace.src_dir / "app.py").write_text("print('changed')\n")
    assert _answer(factory, settings, scan_id, chain).state == "MISMATCH"
    stopped = _provider(url="http://127.0.0.1:9")  # nothing listens there
    assert _answer(factory, settings, scan_id, stopped).state == "UNKNOWN"

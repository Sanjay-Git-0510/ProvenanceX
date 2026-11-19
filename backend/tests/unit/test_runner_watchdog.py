"""Runner watchdog: a hung step is detected despite the heartbeat, only the hung scan is failed
and cleaned up, and a wedged runner exits so it can be restarted."""

import threading
import uuid

from app.core.config import Settings
from app.db.models import Artifact, ArtifactSource, ArtifactType, Scan, ScanStatus, utcnow
from app.pipeline.ownership import Heartbeat, ScanClaim, StepClock
from app.runner.watchdog import EXIT_WATCHDOG, Watchdog, fail_as_hung


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _settings(tmp_path, **overrides) -> Settings:
    values = {
        "_env_file": None,
        "workspace_root": tmp_path / "ws",
        "runner_watchdog_grace_seconds": 10,
        "runner_watchdog_exit_seconds": 1,
        "runner_heartbeat_seconds": 1,
    }
    values.update(overrides)
    return Settings(**values)


def _running(session_factory, token):
    with session_factory() as session:
        scan = Scan(
            id=uuid.uuid4(),
            artifact=Artifact(
                artifact_type=ArtifactType.SOFTWARE, name="x", source=ArtifactSource.GITHUB
            ),
            scanner_version="test",
            status=ScanStatus.RUNNING,
            claim_token=token,
            claimed_by="r1",
            claimed_at=utcnow(),
            heartbeat_at=utcnow(),
        )
        session.add(scan)
        session.commit()
        return scan.id


class FakeDocker:
    def __init__(self, ids: list[str]) -> None:
        self.ids = ids
        self.calls: list[list[str]] = []

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "ps":
            return 0, "\n".join(self.ids).encode()
        return 0, b""


def test_step_clock_reports_only_overdue_steps():
    clock = Clock()
    steps = StepClock(clock)
    assert steps.overdue(10) is None
    steps.begin("fetch:github", 100)
    clock.now += 105
    assert steps.overdue(10) is None  # within grace
    clock.now += 10
    assert steps.overdue(10) == "fetch:github"
    steps.end()
    assert steps.overdue(10) is None


def test_hung_step_is_detected_even_while_the_heartbeat_is_fresh(tmp_path, session_factory):
    clock = Clock()
    token = uuid.uuid4()
    claim = ScanClaim(_running(session_factory, token), token, "r1")
    claim.steps = StepClock(clock)
    dog = Watchdog(
        session_factory,
        claim,
        _settings(tmp_path),
        docker=FakeDocker([]),
        clock=clock,
        exit_fn=lambda c: None,
    )
    claim.steps.begin("fetch:huggingface", 60)
    clock.now += 65
    assert dog.check() is None
    clock.now += 10
    assert "fetch:huggingface" in dog.check()


def test_scan_over_the_ceiling_is_detected(tmp_path, session_factory):
    clock = Clock()
    token = uuid.uuid4()
    claim = ScanClaim(_running(session_factory, token), token, "r1")
    settings = _settings(tmp_path)
    dog = Watchdog(
        session_factory, claim, settings, docker=FakeDocker([]), clock=clock, exit_fn=lambda c: None
    )
    clock.now += settings.runner_max_scan_seconds + 11
    assert "RUNNER_MAX_SCAN_SECONDS" in dog.check()


def test_firing_fails_only_this_scan_and_removes_only_its_resources(tmp_path, session_factory):
    token, other_token = uuid.uuid4(), uuid.uuid4()
    scan_id = _running(session_factory, token)
    other_id = _running(session_factory, other_token)
    claim = ScanClaim(scan_id, token, "r1")
    docker = FakeDocker(["c-fetch-of-this-scan", "c-holder-of-this-scan"])
    exits: list[int] = []
    settings = _settings(tmp_path)
    (settings.workspace_root / str(scan_id)).mkdir(parents=True)
    dog = Watchdog(session_factory, claim, settings, docker=docker, exit_fn=exits.append)
    dog._done.set()  # the scan thread has already unwound  # noqa: SLF001
    dog.fire("sandbox step fetch:github is past its deadline")

    assert claim.lost.is_set()
    with session_factory() as session:
        hung = session.get(Scan, scan_id)
        other = session.get(Scan, other_id)
        assert hung.status == ScanStatus.FAILED
        assert hung.error_code == "runner_watchdog_timeout"
        assert hung.claim_token != token  # the old token can no longer write
        assert other.status == ScanStatus.RUNNING and other.claim_token == other_token
    ps = next(c for c in docker.calls if c[0] == "ps")
    assert f"label=io.provenancex.scan-id={scan_id}" in ps
    assert f"label=io.provenancex.claim={token}" in ps  # never another claim's containers
    removed = [c[-1] for c in docker.calls if c[:2] == ["rm", "--force"]]
    assert removed == ["c-fetch-of-this-scan", "c-holder-of-this-scan"]
    assert ["volume", "rm", "--force", f"px-stg-{scan_id}"] in docker.calls
    assert not (settings.workspace_root / str(scan_id)).exists()
    assert exits == []  # the scan thread unwound in time


def test_a_wedged_runner_exits_for_restart(tmp_path, session_factory):
    token = uuid.uuid4()
    claim = ScanClaim(_running(session_factory, token), token, "r1")
    exits: list[int] = []
    dog = Watchdog(
        session_factory, claim, _settings(tmp_path), docker=FakeDocker([]), exit_fn=exits.append
    )
    dog.fire("hung")
    assert exits == [EXIT_WATCHDOG]


def test_a_replaced_claim_is_never_overwritten(session_factory):
    token = uuid.uuid4()
    scan_id = _running(session_factory, uuid.uuid4())  # recovered elsewhere: another token
    assert fail_as_hung(session_factory, ScanClaim(scan_id, token), "hung") is False
    with session_factory() as session:
        assert session.get(Scan, scan_id).status == ScanStatus.RUNNING


def test_watchdog_thread_fires_by_itself(tmp_path, session_factory):
    clock = Clock()
    token = uuid.uuid4()
    claim = ScanClaim(_running(session_factory, token), token, "r1")
    claim.steps = StepClock(clock)
    fired = threading.Event()
    dog = Watchdog(
        session_factory,
        claim,
        _settings(tmp_path),
        docker=FakeDocker([]),
        clock=clock,
        exit_fn=lambda c: fired.set(),
        poll_seconds=0.05,
    )
    with dog:
        claim.steps.begin("analyzer:analyze", 1)
        clock.now += 100
        assert fired.wait(5)
    assert dog.fired and claim.lost.is_set()


def test_heartbeat_stops_renewing_once_the_claim_is_lost(session_factory):
    token = uuid.uuid4()
    scan_id = _running(session_factory, token)
    claim = ScanClaim(scan_id, token, "r1")
    with session_factory() as session:
        before = session.get(Scan, scan_id).heartbeat_at
    claim.lost.set()
    with Heartbeat(session_factory, claim, 0.05):
        threading.Event().wait(0.3)
    with session_factory() as session:
        assert session.get(Scan, scan_id).heartbeat_at == before

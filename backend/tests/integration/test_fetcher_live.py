"""Milestone B on real Docker: the isolated fetcher, its network, kernel-enforced staging limits,
and recovery. Run with PROVENANCEX_SANDBOX_TESTS=1 after `make sandbox-images` and
`docker build -f docker/egress-proxy/Dockerfile -t provenancex-egress-proxy:0.1.0 backend`.

Tests that also need the internet are marked `network` (PROVENANCEX_NETWORK_TESTS=1); everything
else runs offline. Every network, proxy, volume and container is created here with a random name
and instance label, and removed afterwards.
"""

import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
import uuid
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from app.analysis.base import AnalysisJob
from app.analysis.docker_analyzer import DockerAnalyzer
from app.analysis.reconcile import OrphanReconciler
from app.analysis.staging import DockerStaging
from app.core.config import Settings
from app.core.hashing import tree_digest
from app.db.models import Artifact, ArtifactSource, ArtifactType, Scan, ScanStatus, utcnow
from app.fetch.base import FetchJob, to_hf_result
from app.fetch.docker_fetcher import DockerFetcher
from app.pipeline.ownership import ClaimLost, claim_context
from app.pipeline.workspace import create_workspace
from app.runner.main import reconcile_once
from app.runner.queue import claim_scan
from app.runner.watchdog import Watchdog
from tests.analyzer_helpers import FETCHER_ISOLATED
from tests.conftest import build_zip
from tests.live_helpers import (
    ANALYZER_IMAGE,
    FETCHER_IMAGE,
    PROXY_IMAGE,
    FetchNet,
    docker,
    fetch_network,
    image_present,
    labelled,
    staged,
    state,
    throwaway_postgres,
    unique,
    volume_exists,
)

pytestmark = pytest.mark.sandbox
BACKEND = Path(__file__).resolve().parents[2]
HELLO_WORLD = "https://github.com/octocat/Hello-World"
HELLO_WORLD_COMMIT = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
TINY_GPT2 = "https://huggingface.co/sshleifer/tiny-gpt2"
TINY_GPT2_REVISION = "5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be"
MB = 1024 * 1024


@pytest.fixture(scope="module", autouse=True)
def _images():
    for image in (ANALYZER_IMAGE, FETCHER_IMAGE, PROXY_IMAGE):
        if not image_present(image):
            pytest.fail(f"{image} is not built (make sandbox-images; see module docstring)")


@pytest.fixture
def net():
    with fetch_network() as n:
        yield n


def _settings(tmp_path, network: str, **overrides) -> Settings:
    values = {
        "_env_file": None,
        "workspace_root": tmp_path / "ws",
        "fetcher_network": network,
        "analyzer_instance": unique("pxlive"),
        "sbom_provider": "syft",
        "git_clone_timeout_seconds": 120,
    }
    values.update(overrides)
    return Settings(**values)


def _job(settings, kind="software") -> AnalysisJob:
    scan_id = uuid.uuid4()
    return AnalysisJob(scan_id, create_workspace(settings.workspace_root, scan_id), kind, False)


def _fetch_job(job: AnalysisJob, source="github", url=HELLO_WORLD, revision=HELLO_WORLD_COMMIT):
    stat = job.workspace.src_dir.stat()  # the workspace owner: never root
    return FetchJob(
        job.scan_id, job.workspace, source, url, revision, job.staging_volume,
        stat.st_uid, stat.st_gid,
    )  # fmt: skip


# --------------------------------------------------------------------------- network isolation
def test_fetch_network_has_no_route_and_no_dns_but_reaches_the_proxy(net: FetchNet):
    probe = textwrap.dedent(
        """
        import socket
        def connect(addr):
            s = socket.socket(); s.settimeout(3)
            try:
                s.connect(addr); return "connected"
            except OSError as e:
                return type(e).__name__
            finally:
                s.close()
        def resolve(name):
            try:
                return socket.getaddrinfo(name, 443)[0][4][0]
            except OSError as e:
                return type(e).__name__
        print("direct_ip", connect(("1.1.1.1", 443)))
        print("direct_github", connect(("140.82.112.3", 443)))
        print("dns_github", resolve("github.com"))
        print("dns_metadata", resolve("metadata.google.internal"))
        print("metadata", connect(("169.254.169.254", 80)))
        print("proxy", connect(("egress-proxy", 3128)))
        """
    )
    out = net.run_on_fetch_net(probe)
    assert out.returncode == 0, out.stderr
    result = dict(line.split(" ", 1) for line in out.stdout.strip().splitlines())
    assert result["direct_ip"] != "connected"
    assert result["direct_github"] != "connected"
    assert result["metadata"] != "connected"
    assert result["dns_github"] == "gaierror"
    assert result["dns_metadata"] == "gaierror"
    assert result["proxy"] == "connected"


def test_proxy_cannot_reach_services_on_other_networks(net: FetchNet):
    """A stand-in 'postgres' on a backend network is invisible to the proxy and the fetcher."""
    backend_net = unique("pxlive-backend")
    db = unique("pxlive-db")
    try:
        docker("network", "create", backend_net, check=True)
        docker(
            "run", "-d", "--name", db, "--network", backend_net, "--network-alias", "postgres",
            "--entrypoint", "python", FETCHER_IMAGE, "-c",
            "import socket,time; s=socket.socket(); s.bind(('0.0.0.0',5432)); s.listen();"
            " time.sleep(120)",
            check=True,
        )  # fmt: skip
        ip = docker(
            "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", db
        ).stdout.strip()
        assert ip
        code = (
            "import socket\n"
            "for target in (('postgres', 5432), ('TARGET_IP', 5432)):\n"
            "    s = socket.socket(); s.settimeout(3)\n"
            "    try:\n"
            "        s.connect(target); print('REACHED', target)\n"
            "    except OSError as e:\n"
            "        print('blocked', type(e).__name__)\n"
        ).replace("TARGET_IP", ip)
        from_proxy = docker("exec", net.proxy, "python", "-c", code)
        assert "REACHED" not in from_proxy.stdout, from_proxy.stdout
        assert from_proxy.stdout.count("blocked") == 2
        from_fetch_net = net.run_on_fetch_net(code)
        assert (
            "REACHED" not in from_fetch_net.stdout and from_fetch_net.stdout.count("blocked") == 2
        )
        # And by name through the proxy: refused by policy.
        connect = net.run_on_fetch_net(
            "import socket; s=socket.create_connection(('egress-proxy',3128),5);"
            "s.sendall(b'CONNECT postgres:5432 HTTP/1.1\\r\\n\\r\\n'); print(s.recv(64))"
        )
        assert "403" in connect.stdout
    finally:
        docker("rm", "-f", db)
        docker("network", "rm", backend_net)


def test_fetcher_isolation_holds_and_unapproved_destinations_fail_safely(tmp_path):
    """The proxy allows only huggingface.co here, so a GitHub fetch must fail at the proxy.

    No internet is needed: the CONNECT is refused before any DNS lookup. The fetcher's own
    self-check (from inside, on the real kernel) and docker inspect must both pass.
    """
    with fetch_network("huggingface.co") as net:
        settings = _settings(tmp_path, net.fetch, git_clone_timeout_seconds=30)
        with staged(settings, _job(settings)) as job:
            run = DockerFetcher(settings).run(_fetch_job(job))
            listing = docker("run", "--rm", "--network", "none", "-v",
                             f"{job.staging_volume}:/s:ro", "--entrypoint", "ls",
                             FETCHER_IMAGE, "-A", "/s").stdout.split()  # fmt: skip
        events = net.proxy_logs()
    assert run.result.status == "error"
    assert run.result.error.code in ("clone_failed", "egress_denied")
    assert run.result.isolation == FETCHER_ISOLATED  # every check True, exactly these keys
    assert run.record["runtime_verified"] is True
    rt = run.record["runtime"]
    assert rt["network"] == net.fetch and rt["network_internal"] is True
    assert rt["read_only_rootfs"] and rt["cap_drop"] == "ALL" and rt["no_new_privileges"]
    assert rt["memory_mb"] == settings.fetcher_memory_mb and rt["pids_limit"] == 64
    assert any(
        e.get("host") == "github.com" and e.get("reason") == "host is not on the egress allowlist"
        for e in events
    ), events
    assert listing == []  # nothing was downloaded
    assert labelled(settings.analyzer_instance) == []
    assert labelled(settings.analyzer_instance, "volume") == []


# --------------------------------------------------------------------------- storage (L1)
def test_kernel_refuses_writes_past_the_staging_cap(tmp_path):
    """Write-beyond-cap on a real tmpfs staging volume: ENOSPC at 8 MiB, whatever the writer."""
    settings = _settings(tmp_path, "unused", staging_mb=8, max_artifact_size_mb=4)
    with staged(settings, _job(settings)) as job:
        writer = textwrap.dedent(
            """
            import errno, os
            written = 0
            try:
                with open('/s/big.bin', 'wb') as fh:
                    while True:
                        fh.write(b'x' * 1048576); fh.flush(); os.fsync(fh.fileno())
                        written += 1048576
            except OSError as e:
                print('ENOSPC' if e.errno == errno.ENOSPC else repr(e), written)
            st = os.statvfs('/s'); print('size', st.f_blocks * st.f_frsize)
            """
        )
        uid = job.workspace.src_dir.stat().st_uid
        out = docker(
            "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", f"{uid}:{uid}",
            "--mount", f"type=volume,src={job.staging_volume},dst=/s,volume-nocopy",
            "--entrypoint", "python", FETCHER_IMAGE, "-c", writer,
        )  # fmt: skip
        lines = out.stdout.split("\n")
        assert lines[0].startswith("ENOSPC"), out.stdout + out.stderr
        assert int(lines[0].split()[1]) <= 8 * MB
        assert int(lines[1].split()[1]) == 8 * MB
        volume = job.staging_volume
    assert not volume_exists(volume)  # cleanup after the block


def test_extraction_past_the_staging_cap_fails_even_if_the_app_limit_is_higher(tmp_path):
    """The application byte limit is set far above the tmpfs cap: only the kernel stops it."""
    settings = _settings(tmp_path, "unused", staging_mb=8, max_artifact_size_mb=8)
    settings = settings.model_copy(
        update={"max_artifact_size_mb": 256, "max_compression_ratio": 5000.0}
    )
    job = _job(settings)
    job.workspace.upload_path.write_bytes(build_zip([("zeros.bin", b"\0" * (32 * MB))]))
    job = replace(job, has_upload=True)
    with staged(settings, job) as held:
        run = DockerAnalyzer(settings).run(held, "extract")
    assert run.result.status == "error"
    assert run.result.error.code == "storage_limit_exceeded"
    assert list(job.workspace.src_dir.iterdir()) == []  # the persistent workspace is untouched


# --------------------------------------------------------------------------- lifecycle
def _tarpit_network():
    """A fetch network whose 'egress-proxy' accepts connections and never answers."""
    tag = unique("pxlive-tarpit")
    fetch, pit = f"{tag}_fetch", f"{tag}_pit"
    docker("network", "create", "--internal", fetch, check=True)
    docker(
        "run", "-d", "--name", pit, "--network", fetch, "--network-alias", "egress-proxy",
        "--read-only", "--cap-drop", "ALL", "--user", "65534:65534", "--entrypoint", "python",
        FETCHER_IMAGE, "-c",
        "import socket,time\ns=socket.socket(); s.bind(('0.0.0.0',3128)); s.listen(64)\n"
        "c=[]\nwhile True: c.append(s.accept())",
        check=True,
    )  # fmt: skip
    return fetch, pit


def _cleanup_tarpit(fetch, pit):
    docker("rm", "-f", pit)
    docker("network", "rm", fetch)


def test_hung_download_is_stopped_and_cleaned_up(tmp_path):
    fetch, pit = _tarpit_network()
    try:
        settings = _settings(tmp_path, fetch, git_clone_timeout_seconds=5,
                             fetcher_setup_seconds=5)  # fmt: skip
        started = time.monotonic()
        with staged(settings, _job(settings)) as job:
            run = DockerFetcher(settings).run(_fetch_job(job))
        took = time.monotonic() - started
        assert run.result.status == "error" and run.result.error.code == "clone_timeout"
        assert took < 40
        assert labelled(settings.analyzer_instance) == []
        assert labelled(settings.analyzer_instance, "volume") == []
    finally:
        _cleanup_tarpit(fetch, pit)


KILLED_RUNNER = textwrap.dedent(
    """
    import sys, uuid
    from dataclasses import replace
    from pathlib import Path
    from app.analysis.base import AnalysisJob
    from app.analysis.docker_analyzer import DockerAnalyzer
    from app.analysis.staging import DockerStaging
    from app.core.config import Settings
    from app.fetch.base import FetchJob
    from app.fetch.docker_fetcher import DockerFetcher
    from app.pipeline.ownership import ScanClaim, claim_context
    from app.pipeline.workspace import Workspace

    scan_id, token, root, instance, network = sys.argv[1:6]
    s = Settings(_env_file=None, workspace_root=Path(root), analyzer_instance=instance,
                 fetcher_network=network, git_clone_timeout_seconds=12, fetcher_setup_seconds=5,
                 fetcher_host_grace_seconds=60)
    sid = uuid.UUID(scan_id)
    claim = ScanClaim(sid, uuid.UUID(token))
    ws = Workspace(Path(root) / scan_id)
    job = AnalysisJob(sid, ws, "software", False)
    an = DockerAnalyzer(s)
    uid, gid = an.workspace_owner(job)
    vol = DockerStaging(s).create(sid, token, uid, gid)
    job = replace(job, staging_volume=vol.name)
    with claim_context(claim):
        an.start_holder(job)
        print("STARTING", flush=True)
        DockerFetcher(s).run(FetchJob(sid, ws, "github", "https://github.com/octocat/Hello-World",
                                      None, vol.name, uid, gid))
    """
)


def _running_scan(session_factory, runner_id="live-runner"):
    with session_factory() as s:
        scan = Scan(
            id=uuid.uuid4(),
            artifact=Artifact(
                artifact_type=ArtifactType.SOFTWARE, name="hello", source=ArtifactSource.GITHUB
            ),
            status=ScanStatus.QUEUED,
            scanner_version="0.1.0",
        )
        s.add(scan)
        s.commit()
        return claim_scan(s, scan.id, runner_id)


@pytest.fixture
def pg_session_factory():
    """Real PostgreSQL: "recovered exactly once" relies on its row locks. An in-memory SQLite
    connection shared by both reconciler threads interleaved their transactions under load, so
    both recovered the scan (the one failure of the first full live run on 2026-11-19)."""
    with throwaway_postgres() as factory:
        yield factory


def test_killed_runner_mid_download_is_recovered_concurrently(tmp_path, pg_session_factory):
    """SIGKILL the runner while its fetcher hangs; the fetcher stops by itself; two reconcilers
    racing each other remove the fetcher, the holder, the staging volume and the workspace once,
    and leave another scan's containers alone."""
    session_factory = pg_session_factory
    fetch, pit = _tarpit_network()
    instance = unique("pxlive")
    settings = _settings(tmp_path, fetch, analyzer_instance=instance,
                         runner_heartbeat_seconds=1, runner_stale_seconds=120)  # fmt: skip
    claim = _running_scan(session_factory)
    workspace = create_workspace(settings.workspace_root, claim.scan_id)
    # A bystander: a live claim of another scan in the same deployment must survive.
    other = _running_scan(session_factory, "other-runner")
    bystander = f"px-ana-{other.scan_id}-hold"
    docker(
        "create", "--name", bystander, "--label", "io.provenancex.role=analyzer",
        "--label", f"io.provenancex.instance={instance}",
        "--label", f"io.provenancex.scan-id={other.scan_id}",
        "--label", f"io.provenancex.claim={other.token}", ANALYZER_IMAGE, "--mode", "hold",
        check=True,
    )  # fmt: skip
    runner = subprocess.Popen(  # noqa: S603 - benign helper script
        [sys.executable, "-c", KILLED_RUNNER, str(claim.scan_id), str(claim.token),
         str(settings.workspace_root), instance, fetch],
        cwd=BACKEND, stdout=subprocess.PIPE, text=True, start_new_session=True,
    )  # fmt: skip
    fetcher = f"px-fetch-{claim.scan_id}"
    holder = f"px-ana-{claim.scan_id}-hold"
    volume = f"px-stg-{claim.scan_id}"
    try:
        assert runner.stdout.readline().startswith("STARTING")
        for _ in range(300):
            if (state(fetcher) or {}).get("Running"):
                break
            time.sleep(0.1)
        assert (state(fetcher) or {}).get("Running"), "the fetcher should be running"
        time.sleep(1.0)
        os.killpg(runner.pid, signal.SIGKILL)
        runner.wait(10)
        killed = time.monotonic()
        assert (state(fetcher) or {}).get("Running"), "the fetcher outlives its runner"
        while (state(fetcher) or {}).get("Running") and time.monotonic() - killed < 90:
            time.sleep(0.5)
        assert not (state(fetcher) or {}).get("Running"), "the fetcher must stop on its own"
        assert volume_exists(volume)

        with session_factory() as s:
            s.get(Scan, claim.scan_id).heartbeat_at = utcnow() - timedelta(seconds=30)
            s.commit()
        results = []

        def reconcile():
            results.append(
                reconcile_once(session_factory, settings, "live-runner",
                               OrphanReconciler(settings))
            )  # fmt: skip

        threads = [threading.Thread(target=reconcile) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        # A third, later pass sweeps up anything the race left for "next time".
        reconcile_once(session_factory, settings, "live-runner", OrphanReconciler(settings))
        assert state(fetcher) is None and state(holder) is None
        assert not volume_exists(volume)
        assert not workspace.root.exists()
        assert sum(len(r[0]) for r in results) == 1  # recovered exactly once
        assert all(r[1].error is None for r in results)
        with session_factory() as s:
            row = s.get(Scan, claim.scan_id)
            assert row.status == ScanStatus.FAILED and row.claim_token != claim.token
        assert state(bystander) is not None
    finally:
        if runner.poll() is None:
            os.killpg(runner.pid, signal.SIGKILL)
        docker("rm", "-f", fetcher, holder, bystander)
        docker("volume", "rm", "-f", volume)
        _cleanup_tarpit(fetch, pit)


def test_watchdog_stops_a_hung_fetch_and_cleans_up_only_its_scan(tmp_path, session_factory):
    fetch, pit = _tarpit_network()
    instance = unique("pxlive")
    settings = _settings(tmp_path, fetch, analyzer_instance=instance, git_clone_timeout_seconds=90,
                         runner_watchdog_exit_seconds=20)  # fmt: skip
    claim = _running_scan(session_factory)
    job = AnalysisJob(claim.scan_id, create_workspace(settings.workspace_root, claim.scan_id),
                      "software", False)  # fmt: skip
    other = _running_scan(session_factory, "other-runner")
    bystander = f"px-ana-{other.scan_id}-hold"
    docker(
        "create", "--name", bystander, "--label", "io.provenancex.role=analyzer",
        "--label", f"io.provenancex.instance={instance}",
        "--label", f"io.provenancex.scan-id={other.scan_id}",
        "--label", f"io.provenancex.claim={other.token}", ANALYZER_IMAGE, "--mode", "hold",
        check=True,
    )  # fmt: skip
    outcome: list[object] = []
    exits: list[int] = []
    try:
        an = DockerAnalyzer(settings)
        uid, gid = an.workspace_owner(job)
        vol = DockerStaging(settings).create(claim.scan_id, str(claim.token), uid, gid)
        job = replace(job, staging_volume=vol.name)
        with claim_context(claim):
            an.start_holder(job)

        def scan_thread():
            with claim_context(claim):
                try:
                    DockerFetcher(settings).run(_fetch_job(job))
                    outcome.append("returned")
                except ClaimLost:
                    outcome.append("claim_lost")

        worker = threading.Thread(target=scan_thread)
        worker.start()
        fetcher = f"px-fetch-{claim.scan_id}"
        for _ in range(300):
            if (state(fetcher) or {}).get("Running"):
                break
            time.sleep(0.1)
        dog = Watchdog(session_factory, claim, settings, exit_fn=exits.append)
        started = time.monotonic()
        errors: list[BaseException] = []

        def fire():
            try:
                dog.fire("test: hung download")
            except BaseException as exc:  # noqa: BLE001 - surfaced by the assert below
                errors.append(exc)

        firing = threading.Thread(target=fire)
        firing.start()
        worker.join(30)
        dog._done.set()  # the scan thread unwound  # noqa: SLF001
        firing.join(60)
        assert errors == []
        assert outcome == ["claim_lost"]
        assert time.monotonic() - started < 30
        assert state(fetcher) is None and state(f"px-ana-{claim.scan_id}-hold") is None
        assert not volume_exists(vol.name)
        assert state(bystander) is not None  # another scan's container is untouched
        with session_factory() as s:
            row = s.get(Scan, claim.scan_id)
            assert row.status == ScanStatus.FAILED
            assert row.error_code == "runner_watchdog_timeout"
            assert s.get(Scan, other.scan_id).status == ScanStatus.RUNNING
        assert exits == []
    finally:
        docker("rm", "-f", f"px-fetch-{claim.scan_id}", f"px-ana-{claim.scan_id}-hold", bystander)
        docker("volume", "rm", "-f", f"px-stg-{claim.scan_id}")
        _cleanup_tarpit(fetch, pit)


# --------------------------------------------------------------------------- real downloads
@pytest.mark.network
def test_real_github_fetch_matches_an_independent_hash(tmp_path, net):
    settings = _settings(tmp_path, net.fetch)
    analyzer = DockerAnalyzer(settings)
    with staged(settings, _job(settings)) as job:
        run = DockerFetcher(settings).run(_fetch_job(job))
        analysis = analyzer.run(job, "analyze").analysis
        persisted = analyzer.run(job, "persist").result.persisted
    assert run.result.status == "ok", run.result.error
    assert run.result.commit_sha == HELLO_WORLD_COMMIT
    assert run.result.isolation == FETCHER_ISOLATED
    # Independent reference: the same file fetched from GitHub by the test itself.
    readme = httpx.get(
        f"https://raw.githubusercontent.com/octocat/Hello-World/{HELLO_WORLD_COMMIT}/README",
        timeout=30,
    ).content
    reference = tmp_path / "reference"
    reference.mkdir()
    (reference / "README").write_bytes(readme)
    assert analysis.tree.sha256 == tree_digest(reference).sha256
    assert persisted.sha256 == analysis.tree.sha256
    assert tree_digest(job.workspace.src_dir).sha256 == analysis.tree.sha256
    assert not (job.workspace.src_dir / ".git").exists()  # git metadata never reaches analysis
    hosts = {e["host"] for e in net.proxy_logs() if e.get("outcome") == "tunneled"}
    assert hosts == {"github.com"}


@pytest.mark.network
def test_real_hugging_face_fetch_verifies_every_file(tmp_path, net):
    settings = _settings(tmp_path, net.fetch)
    with staged(settings, _job(settings, "model")) as job:
        run = DockerFetcher(settings).run(
            _fetch_job(job, "huggingface", TINY_GPT2, TINY_GPT2_REVISION)
        )
    assert run.result.status == "ok", run.result.error
    assert run.result.commit_sha == TINY_GPT2_REVISION
    hf = to_hf_result(run.result)
    assert {f.status for f in hf.files} == {"downloaded"}
    assert all(f.hash_verified for f in hf.files)
    # Independent reference: the Hub's own listing, fetched by the test itself.
    listing = httpx.get(
        f"https://huggingface.co/api/models/sshleifer/tiny-gpt2/tree/{TINY_GPT2_REVISION}",
        timeout=30,
    ).json()
    lfs = {e["path"]: e["lfs"]["oid"] for e in listing if e.get("lfs")}
    assert lfs and all(f.local_sha256 == lfs[f.path] for f in hf.files if f.path in lfs)
    hosts = {e["host"] for e in net.proxy_logs() if e.get("outcome") == "tunneled"}
    assert hosts <= {"huggingface.co", "us.aws.cdn.hf.co", "cas-bridge.xethub.hf.co"}
    assert "huggingface.co" in hosts


@pytest.mark.network
def test_download_larger_than_staging_is_refused_by_the_kernel(tmp_path, net):
    """tiny-gpt2 is ~4.5 MB; a 2 MiB tmpfs cannot hold it even with app limits raised."""
    settings = _settings(tmp_path, net.fetch, staging_mb=2, max_artifact_size_mb=2)
    settings = settings.model_copy(update={"max_artifact_size_mb": 256, "hf_max_file_mb": 256})
    with staged(settings, _job(settings, "model")) as job:
        run = DockerFetcher(settings).run(
            _fetch_job(job, "huggingface", TINY_GPT2, TINY_GPT2_REVISION)
        )
    hf = run.result.hf
    if run.result.status == "ok":
        # The HF client records per-file failures instead of failing the fetch.
        failed = [f for f in hf.files if f.status == "failed"]
        assert failed, "some file must have hit the kernel limit"
        assert sum(f.size for f in hf.files if f.downloaded) <= 2 * MB
    else:
        assert run.result.error.code == "storage_limit_exceeded"

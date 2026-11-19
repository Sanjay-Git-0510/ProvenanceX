"""Helpers for the real-Docker tests (PROVENANCEX_SANDBOX_TESTS=1): staging volumes with their
holder, an isolated fetch network with a real egress-proxy container, and docker CLI wrappers.

Every resource gets a random per-test name and an instance label of its own, so the tests never
touch a development stack (provenancex_*) or each other.
"""

import json
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace

from app.analysis.base import AnalysisJob
from app.analysis.docker_analyzer import DockerAnalyzer
from app.analysis.staging import DockerStaging
from app.core.config import Settings
from app.pipeline.ownership import ScanClaim, claim_context

DOCKER = shutil.which("docker") or "docker"
ANALYZER_IMAGE = "provenancex-analyzer:0.1.0"
FETCHER_IMAGE = "provenancex-fetcher:0.1.0"
PROXY_IMAGE = "provenancex-egress-proxy:0.1.0"
DEFAULT_ALLOWLIST = "github.com,huggingface.co,us.aws.cdn.hf.co,cas-bridge.xethub.hf.co"


def docker(*args: str, timeout: float = 120, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv
        [DOCKER, *args], capture_output=True, text=True, timeout=timeout, check=check
    )


def image_present(image: str) -> bool:
    return docker("image", "inspect", image).returncode == 0


def state(name: str) -> dict | None:
    done = docker("inspect", "--format", "{{json .State}}", name)
    return json.loads(done.stdout) if done.returncode == 0 else None


def volume_exists(name: str) -> bool:
    return docker("volume", "inspect", name).returncode == 0


def labelled(instance: str, kind: str = "ps") -> list[str]:
    if kind == "volume":
        out = docker("volume", "ls", "-q", "--filter", f"label=io.provenancex.instance={instance}")
    else:
        out = docker("ps", "-aq", "--filter", f"label=io.provenancex.instance={instance}")
    return out.stdout.split()


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


@contextmanager
def staged(
    settings: Settings, job: AnalysisJob, claim: ScanClaim | None = None
) -> Iterator[AnalysisJob]:
    """Create the scan's tmpfs staging volume and holder, yield the job, then remove both."""
    analyzer = DockerAnalyzer(settings)
    staging = DockerStaging(settings)
    uid, gid = analyzer.workspace_owner(job)
    token = str(claim.token) if claim else "none"
    volume = staging.create(job.scan_id, token, uid, gid)
    held = replace(job, staging_volume=volume.name)
    try:
        with claim_context(claim):
            analyzer.start_holder(held)
        yield held
    finally:
        analyzer.stop_holder(held)
        staging.remove(volume.name)


@dataclass
class FetchNet:
    """An internal fetch network whose only member besides fetchers is a real egress proxy."""

    fetch: str
    egress: str
    proxy: str

    def proxy_logs(self) -> list[dict]:
        out = docker("logs", self.proxy).stderr + docker("logs", self.proxy).stdout
        events = []
        for line in out.splitlines():
            start = line.find("{")
            if start >= 0:
                try:
                    events.append(json.loads(line[start:]))
                except ValueError:
                    continue
        return events

    def run_on_fetch_net(self, code: str, *, timeout: float = 60) -> subprocess.CompletedProcess:
        """Run Python in a throwaway hardened container on the fetch network (probes only)."""
        return docker(
            "run", "--rm", "--network", self.fetch, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", "65534:65534",
            "--entrypoint", "python", FETCHER_IMAGE, "-c", code,
            timeout=timeout,
        )  # fmt: skip


@contextmanager
def fetch_network(
    allowlist: str = DEFAULT_ALLOWLIST, *, proxy_env: dict[str, str] | None = None
) -> Iterator[FetchNet]:
    tag = unique("pxlive")
    net = FetchNet(fetch=f"{tag}_fetch", egress=f"{tag}_egress", proxy=f"{tag}_proxy")
    env = {"EGRESS_ALLOWED_HOSTS": allowlist, **(proxy_env or {})}
    try:
        docker("network", "create", "--internal", net.fetch, check=True)
        docker("network", "create", net.egress, check=True)
        env_args = [a for k, v in env.items() for a in ("-e", f"{k}={v}")]
        docker(
            "run", "-d", "--name", net.proxy, "--network", net.egress, "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534",
            "--memory", "128m", "--pids-limit", "64", *env_args, PROXY_IMAGE,
            check=True,
        )  # fmt: skip
        docker("network", "connect", "--alias", "egress-proxy", net.fetch, net.proxy, check=True)
        for _ in range(50):
            probe = docker(
                "exec", net.proxy, "python", "-B", "-m", "app.egress_proxy", "--healthcheck"
            )
            if probe.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("egress proxy did not become healthy")
        yield net
    finally:
        docker("rm", "-f", net.proxy)
        docker("network", "rm", net.fetch, net.egress)


@contextmanager
def throwaway_postgres() -> Iterator[object]:
    """A disposable postgres:16 container on a free loopback port; yields a sessionmaker.

    For live tests whose assertions depend on PostgreSQL row locks (FOR UPDATE SKIP LOCKED),
    which the suite's in-memory SQLite cannot provide.
    """
    import socket

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db import models  # noqa: F401 - registers the tables
    from app.db.base import Base

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    name = unique("pxlive-pg")
    docker(
        "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_USER=px", "-e", "POSTGRES_PASSWORD=px",
        "-e", "POSTGRES_DB=px", "-p", f"127.0.0.1:{port}:5432", "postgres:16",
        check=True,
    )  # fmt: skip
    engine = None
    try:
        engine = create_engine(f"postgresql+psycopg://px:px@127.0.0.1:{port}/px", pool_size=10)
        for _ in range(120):
            try:
                with engine.connect():
                    break
            except Exception:  # noqa: BLE001 - not ready yet
                time.sleep(0.5)
        Base.metadata.create_all(engine)
        yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    finally:
        if engine is not None:
            engine.dispose()
        docker("rm", "-f", name)

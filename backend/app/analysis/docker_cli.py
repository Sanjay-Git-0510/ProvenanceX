"""A minimal, allowlisted-environment runner for short Docker CLI commands.

Used for listing, inspecting and removing containers, volumes and networks. Every call is an
argv list (no shell) with a 30-second timeout and capped stdout. Failures return (None, b"")
or a non-zero code; callers decide whether that fails closed.
"""

import logging
import os
import subprocess
from collections.abc import Callable

from app.core.bounded import printable_excerpt

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT_SECONDS = 30
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
PASSTHROUGH_ENV = (
    "PATH",
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "XDG_RUNTIME_DIR",
    "TMPDIR",
)

DockerRunner = Callable[[list[str]], tuple[int | None, bytes]]


def docker_env() -> dict[str, str]:
    return {k: os.environ[k] for k in PASSTHROUGH_ENV if k in os.environ}


def make_docker_runner(docker_path: str, timeout: float = COMMAND_TIMEOUT_SECONDS) -> DockerRunner:
    def run(args: list[str]) -> tuple[int | None, bytes]:
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [docker_path, *args],
                env=docker_env(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("docker %s failed: %s", args[:2], exc.__class__.__name__)
            return None, b""
        if done.returncode != 0 and done.stderr:
            logger.warning("docker %s: %s", args[:2], printable_excerpt(done.stderr[:500]))
        return done.returncode, done.stdout[:MAX_OUTPUT_BYTES]

    return run

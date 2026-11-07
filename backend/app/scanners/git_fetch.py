"""Hardened shallow git fetch of a pre-validated repository URL.

Safety measures (CLAUDE.md security boundary 3):
- Depth-1, single-branch clone with no submodule recursion.
- Hooks disabled (core.hooksPath=/dev/null). Symlinks are checked out as plain files.
- HTTP redirects are off. Only the allowed protocol (https in production) is permitted.
- System and global git config are ignored. The child gets a minimal environment, never
  prompts for credentials, and skips LFS smudge.
- A hard wall-clock timeout applies, and the destination size is polled during the
  transfer. The whole process group is killed when either limit is exceeded.
"""

import logging
import os
import re
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import AppError, ErrorCode
from app.pipeline.workspace import directory_size
from app.security.revision import is_commit_sha

logger = logging.getLogger(__name__)

GIT_BIN = "git"
STDERR_TAIL_BYTES = 2000
_HEAD_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


@dataclass(frozen=True)
class CloneLimits:
    timeout_seconds: float
    max_bytes: int
    poll_interval: float = 0.5


@dataclass(frozen=True)
class CloneResult:
    commit_sha: str
    revision: str | None


def git_env(home: Path, allowed_protocol: str = "https") -> dict[str, str]:
    """Minimal environment for git. Nothing is inherited except PATH."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "LC_ALL": "C",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ALLOW_PROTOCOL": allowed_protocol,
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }


def git_base_command(allowed_protocol: str = "https") -> list[str]:
    """`git` with hardening `-c` options that apply to every subcommand."""
    settings = [
        f"core.hooksPath={os.devnull}",
        "core.symlinks=false",
        "core.fsmonitor=false",
        "core.protectNTFS=true",
        "core.protectHFS=true",
        "http.followRedirects=false",
        "protocol.allow=never",
        f"protocol.{allowed_protocol}.allow=always",
        "submodule.recurse=false",
        "credential.helper=",
    ]
    cmd = [GIT_BIN]
    for setting in settings:
        cmd += ["-c", setting]
    return cmd


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass  # already exited
    proc.wait()


def run_limited_command(
    cmd: list[str],
    *,
    env: dict[str, str],
    watch_dir: Path,
    deadline: float,
    max_bytes: int,
    poll_interval: float = 0.5,
    cwd: Path | None = None,
) -> None:
    """Run cmd and kill its process group on deadline or when watch_dir exceeds max_bytes."""
    with tempfile.TemporaryFile() as stderr_file:
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell, validated inputs
                cmd,
                env=env,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise AppError(ErrorCode.CLONE_FAILED, "git executable is not available", 502) from exc

        try:
            while True:
                try:
                    returncode = proc.wait(timeout=poll_interval)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() > deadline:
                    _kill_group(proc)
                    raise AppError(ErrorCode.CLONE_TIMEOUT, "Repository fetch timed out", 504)
                if directory_size(watch_dir) > max_bytes:
                    _kill_group(proc)
                    raise AppError(
                        ErrorCode.ARTIFACT_TOO_LARGE,
                        "Repository exceeds the size limit",
                        413,
                        {"max_bytes": max_bytes},
                    )
        finally:
            if proc.poll() is None:
                _kill_group(proc)

        if directory_size(watch_dir) > max_bytes:
            raise AppError(
                ErrorCode.ARTIFACT_TOO_LARGE,
                "Repository exceeds the size limit",
                413,
                {"max_bytes": max_bytes},
            )
        if returncode != 0:
            stderr_file.seek(0)
            tail = stderr_file.read()[-STDERR_TAIL_BYTES:].decode("utf-8", "replace").strip()
            logger.warning("git exited with %s: %s", returncode, tail)
            raise AppError(
                ErrorCode.CLONE_FAILED,
                "git command failed",
                502,
                {"returncode": returncode, "stderr": tail},
            )


def _rev_parse_head(base: list[str], dest: Path, env: dict[str, str], deadline: float) -> str:
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [*base, "-C", str(dest), "rev-parse", "HEAD"],
            env=env,
            capture_output=True,
            timeout=max(1.0, deadline - time.monotonic()),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AppError(ErrorCode.CLONE_TIMEOUT, "Repository fetch timed out", 504) from exc
    sha = result.stdout.decode("ascii", "replace").strip()
    if result.returncode != 0 or not _HEAD_SHA_RE.match(sha):
        raise AppError(ErrorCode.CLONE_FAILED, "Could not determine the fetched commit", 502)
    return sha


def clone_repository(
    url: str,
    dest: Path,
    revision: str | None,
    limits: CloneLimits,
    *,
    allowed_protocol: str = "https",
) -> CloneResult:
    """Fetch `url` at `revision` (or the default branch) into the empty directory `dest`.

    `url` must already have passed the URL validation in app.security. Tests pass
    allowed_protocol="file" to clone local fixture repositories.
    """
    if not url.startswith(f"{allowed_protocol}://"):
        raise AppError(ErrorCode.URL_NOT_ALLOWED, "Repository URL protocol not allowed", 400)
    if not dest.is_dir() or any(dest.iterdir()):
        raise AppError(ErrorCode.WORKSPACE_ERROR, "Clone destination must be empty", 500)

    env = git_env(dest.parent, allowed_protocol)
    base = git_base_command(allowed_protocol)
    deadline = time.monotonic() + limits.timeout_seconds

    def run(cmd: list[str]) -> None:
        run_limited_command(
            cmd,
            env=env,
            watch_dir=dest,
            deadline=deadline,
            max_bytes=limits.max_bytes,
            poll_interval=limits.poll_interval,
        )

    requested_sha = revision.lower() if revision and is_commit_sha(revision) else None
    if requested_sha:
        # A commit cannot be passed to `clone --branch`. Init, fetch that one commit, check it out.
        run([*base, "init", "--quiet", str(dest)])
        run(
            [
                *base,
                "-C",
                str(dest),
                "fetch",
                "--quiet",
                "--depth",
                "1",
                "--no-tags",
                "--no-recurse-submodules",
                url,
                requested_sha,
            ]
        )
        run([*base, "-C", str(dest), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
    else:
        cmd = [
            *base,
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--single-branch",
            "--no-recurse-submodules",
        ]
        if revision:
            cmd += ["--branch", revision]
        cmd += ["--", url, str(dest)]
        run(cmd)

    commit_sha = _rev_parse_head(base, dest, env, deadline)
    if requested_sha and commit_sha != requested_sha:
        raise AppError(
            ErrorCode.CLONE_FAILED, "Fetched commit does not match the requested commit", 502
        )
    return CloneResult(commit_sha=commit_sha, revision=revision)

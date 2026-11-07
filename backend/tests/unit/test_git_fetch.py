"""Tests for the hardened git fetcher.

Local tests clone a bare repository created in a temp dir over file://. Production only
permits https. The live github.com test is marked `network` and skipped by default.
"""

import os
import shutil
import subprocess

import pytest

from app.core.errors import AppError, ErrorCode
from app.scanners import git_fetch
from app.scanners.git_fetch import CloneLimits, clone_repository, git_base_command, git_env

requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
LIMITS = CloneLimits(timeout_seconds=30, max_bytes=5 * 1024 * 1024, poll_interval=0.05)


def _git(*args, cwd):
    subprocess.run(  # noqa: S603
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],  # noqa: S607
        cwd=cwd,
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )


def _rev(cwd, ref="HEAD"):
    return subprocess.run(  # noqa: S603
        ["git", "rev-parse", ref],  # noqa: S607
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def bare_repo(tmp_path):
    """A bare repo with two commits on main, tag v1 on the first, and a symlink."""
    work = tmp_path / "work"
    work.mkdir()
    _git("init", "--quiet", "-b", "main", cwd=work)
    (work / "app.py").write_text("print('v1')\n")
    _git("add", ".", cwd=work)
    _git("commit", "--quiet", "-m", "one", cwd=work)
    _git("tag", "v1", cwd=work)
    first = _rev(work)
    (work / "app.py").write_text("print('v2')\n")
    os.symlink("/etc/passwd", work / "link")
    _git("add", ".", cwd=work)
    _git("commit", "--quiet", "-m", "two", cwd=work)
    second = _rev(work)
    bare = tmp_path / "remote.git"
    _git("clone", "--quiet", "--bare", str(work), str(bare), cwd=tmp_path)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=bare)
    return {"url": f"file://{bare}", "first": first, "second": second}


@pytest.fixture
def dest(tmp_path):
    d = tmp_path / "ws" / "src"
    d.mkdir(parents=True)
    return d


def test_base_command_hardening():
    cmd = " ".join(git_base_command())
    for expected in [
        f"core.hooksPath={os.devnull}",
        "core.symlinks=false",
        "http.followRedirects=false",
        "protocol.allow=never",
        "protocol.https.allow=always",
        "submodule.recurse=false",
        "credential.helper=",
    ]:
        assert expected in cmd


def test_env_is_minimal(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/attacker")
    monkeypatch.setenv("GIT_SSH_COMMAND", "evil")
    env = git_env(tmp_path)
    assert "GIT_DIR" not in env and "GIT_SSH_COMMAND" not in env
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_ALLOW_PROTOCOL"] == "https"


def test_rejects_url_with_disallowed_protocol(dest):
    with pytest.raises(AppError) as exc:
        clone_repository("file:///tmp/x.git", dest, None, LIMITS)
    assert exc.value.code == ErrorCode.URL_NOT_ALLOWED


def test_rejects_non_empty_destination(dest):
    (dest / "x").write_text("x")
    with pytest.raises(AppError) as exc:
        clone_repository("https://github.com/a/b.git", dest, None, LIMITS)
    assert exc.value.code == ErrorCode.WORKSPACE_ERROR


def test_missing_git_binary(dest, monkeypatch):
    monkeypatch.setattr(git_fetch, "GIT_BIN", "definitely-not-git-xyz")
    with pytest.raises(AppError) as exc:
        clone_repository("https://github.com/a/b.git", dest, None, LIMITS)
    assert exc.value.code == ErrorCode.CLONE_FAILED
    assert "not available" in exc.value.message


@requires_git
def test_clone_default_branch(bare_repo, dest):
    result = clone_repository(bare_repo["url"], dest, None, LIMITS, allowed_protocol="file")
    assert result.commit_sha == bare_repo["second"]
    assert (dest / "app.py").read_text() == "print('v2')\n"
    # Shallow: only one commit present.
    assert (
        subprocess.run(  # noqa: S603
            ["git", "rev-list", "--count", "HEAD"],  # noqa: S607
            cwd=dest,
            capture_output=True,
            text=True,  # noqa: S607
        ).stdout.strip()
        == "1"
    )


@requires_git
def test_symlinks_checked_out_as_plain_files(bare_repo, dest):
    clone_repository(bare_repo["url"], dest, None, LIMITS, allowed_protocol="file")
    link = dest / "link"
    assert not link.is_symlink()
    assert link.read_text() == "/etc/passwd"


@requires_git
def test_clone_tag(bare_repo, dest):
    result = clone_repository(bare_repo["url"], dest, "v1", LIMITS, allowed_protocol="file")
    assert result.commit_sha == bare_repo["first"]
    assert (dest / "app.py").read_text() == "print('v1')\n"


@requires_git
def test_fetch_by_commit_sha(bare_repo, dest):
    sha = bare_repo["first"]
    result = clone_repository(bare_repo["url"], dest, sha.upper(), LIMITS, allowed_protocol="file")
    assert result.commit_sha == sha
    assert (dest / "app.py").read_text() == "print('v1')\n"


@requires_git
def test_unknown_branch_fails_with_stderr(bare_repo, dest):
    with pytest.raises(AppError) as exc:
        clone_repository(bare_repo["url"], dest, "no-such-branch", LIMITS, allowed_protocol="file")
    assert exc.value.code == ErrorCode.CLONE_FAILED
    assert "no-such-branch" in exc.value.details["stderr"]


@requires_git
def test_size_limit_enforced(bare_repo, dest):
    tiny = CloneLimits(timeout_seconds=30, max_bytes=100, poll_interval=0.05)
    with pytest.raises(AppError) as exc:
        clone_repository(bare_repo["url"], dest, None, tiny, allowed_protocol="file")
    assert exc.value.code == ErrorCode.ARTIFACT_TOO_LARGE


@pytest.mark.network
def test_live_github_clone(dest):
    result = clone_repository("https://github.com/octocat/Hello-World.git", dest, None, LIMITS)
    assert len(result.commit_sha) == 40
    assert (dest / "README").exists()

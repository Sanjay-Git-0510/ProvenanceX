"""Download one artifact into the staging directory. Runs only inside the fetcher container (or
the pytest-only in-process fetcher), never in the scan-runner or the API.

GitHub: hardened shallow clone through the egress proxy (app/scanners/git_fetch.py). After the
commit is confirmed, the `.git` directory is deleted: the tree digest excludes it anyway, and
the analyzer then never sees git metadata.

Hugging Face: the existing capped, hash-verified provider (app/scanners/hf/client.py) through
the proxy, with redirects limited to hosts on both the code's HF list and the egress allowlist.

Nothing downloaded is executed, imported or deserialized here.
"""

import os
import shutil
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.errors import AppError, ErrorCode
from app.fetch_worker.protocol import FetchRequest
from app.scanners.git_fetch import CloneLimits, clone_repository
from app.scanners.hf.base import HfFetchLimits, HfFetchResult, HfProvider
from app.security.sandbox_guard import require_fetch_context
from app.security.url_validation import validate_github_repo_url, validate_hf_repo_url

CloneFn = Callable[..., Any]


def tree_stats(root: Path) -> tuple[int, int]:
    """(regular files, bytes) under root, never following symlinks. Fails on special files."""
    files = total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            info = os.lstat(os.path.join(dirpath, name))
            if stat.S_ISLNK(info.st_mode) or not (
                stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
            ):
                raise AppError(
                    ErrorCode.UNSAFE_CONTENT,
                    "The download contains a symlink or special file",
                    400,
                    {"path": name[:256]},
                )
            if stat.S_ISREG(info.st_mode):
                files += 1
                total += info.st_size
    return files, total


def _fetch_github(request: FetchRequest, dest: Path, clone: CloneFn) -> dict[str, Any]:
    # Syntax only: the fetcher has no DNS for external names. The egress proxy resolves and
    # checks every address, and the runner already re-validated DNS before queuing the fetch.
    repo = validate_github_repo_url(request.url, check_dns=False)
    result = clone(
        repo.clone_url,
        dest,
        request.revision,
        CloneLimits(
            timeout_seconds=request.limits.timeout_seconds,
            max_bytes=request.limits.max_total_bytes,
        ),
        proxy_url=request.proxy_url,
    )
    git_dir = dest / ".git"
    if git_dir.is_symlink():
        raise AppError(ErrorCode.UNSAFE_CONTENT, "The .git entry is a symlink", 400)
    if git_dir.exists():
        shutil.rmtree(git_dir)
    return {
        "commit_sha": result.commit_sha,
        "git": {"commit_sha": result.commit_sha, "revision": result.revision},
    }


def _hf_provider(request: FetchRequest) -> HfProvider:
    if request.hf_provider == "mock":
        from app.scanners.hf.mock import MockHfProvider

        return MockHfProvider()
    from app.scanners.hf.client import HuggingFaceProvider

    return HuggingFaceProvider(
        timeout_seconds=request.limits.hf_api_timeout_seconds,
        max_retries=request.limits.http_max_retries,
        max_api_bytes=request.limits.max_api_bytes,
        user_agent=request.user_agent,
        check_dns=False,  # the proxy resolves and validates every destination
        proxy=request.proxy_url,
        allowed_hosts=frozenset(h.lower() for h in request.allowed_hosts),
    )


def _fetch_hf(request: FetchRequest, dest: Path, provider: HfProvider) -> dict[str, Any]:
    repo = validate_hf_repo_url(request.url, check_dns=False)
    limits = HfFetchLimits(
        max_total_bytes=request.limits.max_total_bytes,
        max_file_bytes=request.limits.max_file_bytes,
        max_files=request.limits.max_files,
        timeout_seconds=request.limits.timeout_seconds,
    )
    result: HfFetchResult = provider.fetch(repo, request.revision, dest, limits)
    return {
        "commit_sha": result.commit_sha,
        "hf": {
            "source": result.source,
            "repo_id": repo.repo_id,
            "repo_type": repo.repo_type,
            "files": [f.to_dict() for f in result.files],
            "meta": result.meta,
            "card_data": result.card_data,
            "warnings": result.warnings[:100],
        },
    }


def run_fetch(
    request: FetchRequest,
    dest: Path,
    *,
    hf_provider: HfProvider | None = None,
    clone: CloneFn | None = None,
) -> dict[str, Any]:
    """Fetch into the empty directory `dest`. Returns the result fields (status "ok").

    `hf_provider` and `clone` are test hooks for the in-process fetcher only; the container
    always builds them from the request.
    """
    require_fetch_context()
    if request.source == "github":
        out = _fetch_github(request, dest, clone or clone_repository)
    else:
        out = _fetch_hf(request, dest, hf_provider or _hf_provider(request))
    out["file_count"], out["total_bytes"] = tree_stats(dest)
    return out

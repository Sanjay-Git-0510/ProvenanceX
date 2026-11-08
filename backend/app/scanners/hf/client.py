"""Real Hugging Face provider: Hub API metadata plus a capped, verified file download.

Safety rules (CLAUDE.md boundaries 1-4, 8):
- Only https://huggingface.co is contacted directly. The host is fixed in code.
- Redirects are followed manually (at most MAX_REDIRECTS hops). Every hop must be https
  to an allowlisted HF host, and its addresses must be public (validate_hf_redirect_url).
- No token is sent, so only public, non-gated repositories can be scanned.
- Repository paths are validated like ZIP entry names (no traversal, absolute paths,
  backslashes or NUL). Files are written only below `dest`, with O_EXCL.
- LFS files larger than max_file_bytes, or past the total budget, are listed but not
  downloaded. Every download is streamed with a byte cap and a time budget.
- Downloaded content is verified against the Hub listing: SHA-256 for LFS files and the
  git blob SHA-1 for regular files. A mismatching file is deleted and recorded as an
  integrity mismatch (a provenance failure), never analyzed as if it were genuine.
- Nothing downloaded is executed or loaded.
"""

import hashlib
import json
import logging
import os
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import httpx

from app.core.errors import AppError, ErrorCode
from app.scanners.hf.base import HfFetchLimits, HfFetchResult, HfFile
from app.security.archive import normalize_member_name
from app.security.url_validation import HF_HOST, HfRepo, validate_hf_redirect_url

logger = logging.getLogger(__name__)

HF_BASE = f"https://{HF_HOST}"
MAX_REDIRECTS = 5
MAX_TREE_PAGES = 50
MAX_PATH_LENGTH = 512
MAX_PATH_DEPTH = 32
CHUNK_SIZE = 1024 * 1024
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LINK_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


class _DownloadError(Exception):
    def __init__(self, status: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def safe_repo_path(path: object) -> str | None:
    """Return the normalized relative path, or None if it is unsafe."""
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_LENGTH:
        return None
    try:
        rel = normalize_member_name(path)
    except AppError:
        return None
    if rel != path or rel.count("/") >= MAX_PATH_DEPTH or any(ord(c) < 32 for c in rel):
        return None
    return rel


class HuggingFaceProvider:
    name = "huggingface"

    def __init__(
        self,
        *,
        timeout_seconds: float,
        max_retries: int,
        max_api_bytes: int,
        user_agent: str,
        transport: httpx.BaseTransport | None = None,
        check_dns: bool = True,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.max_api_bytes = max_api_bytes
        self.user_agent = user_agent
        self.transport = transport
        self.check_dns = check_dns
        self.sleep = sleep
        self.clock = clock

    # ------------------------------------------------------------------ API (JSON)
    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            headers={"User-Agent": self.user_agent},
            transport=self.transport,
        )

    def _api(self, client: httpx.Client, url: str) -> tuple[Any, httpx.Headers]:
        """GET a Hub API URL (on huggingface.co) with bounded retries and a size cap."""
        last = "unavailable"
        for attempt in range(self.max_retries + 1):
            try:
                with client.stream("GET", url, headers={"Accept": "application/json"}) as resp:
                    status = resp.status_code
                    if status in (401, 403):
                        raise AppError(
                            ErrorCode.HF_ACCESS_DENIED,
                            "Repository is private, gated or does not exist "
                            "(only public repositories can be scanned)",
                            403,
                            {"status": status},
                        )
                    if status == 404:
                        raise AppError(
                            ErrorCode.HF_NOT_FOUND, "Repository or revision not found", 404
                        )
                    if 300 <= status < 400:
                        raise AppError(
                            ErrorCode.HF_ERROR,
                            "The Hub redirected this request (the repository may have moved); "
                            "scan its current URL",
                            502,
                            {"status": status},
                        )
                    if status in RETRY_STATUSES:
                        last = f"HTTP {status}"
                    elif status >= 400:
                        raise AppError(ErrorCode.HF_ERROR, f"Hub API returned HTTP {status}", 502)
                    else:
                        body = self._read_capped(resp, self.max_api_bytes)
                        try:
                            return json.loads(body), resp.headers
                        except (ValueError, RecursionError) as exc:
                            raise AppError(
                                ErrorCode.HF_ERROR, "Hub API returned invalid JSON", 502
                            ) from exc
            except httpx.TimeoutException:
                last = "timeout"
            except httpx.TransportError as exc:
                last = f"network error ({exc.__class__.__name__})"
            if attempt < self.max_retries:
                self.sleep(0.5 * (2**attempt))
        raise AppError(
            ErrorCode.HF_UNAVAILABLE, "Hugging Face Hub is unavailable", 503, {"last_error": last}
        )

    @staticmethod
    def _read_capped(resp: httpx.Response, limit: int) -> bytes:
        declared = resp.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise AppError(ErrorCode.HF_ERROR, "Hub API response exceeds the size limit", 502)
        chunks, total = [], 0
        for chunk in resp.iter_bytes():
            total += len(chunk)
            if total > limit:
                raise AppError(ErrorCode.HF_ERROR, "Hub API response exceeds the size limit", 502)
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _api_base(repo: HfRepo) -> str:
        kind = "datasets" if repo.repo_type == "dataset" else "models"
        return f"{HF_BASE}/api/{kind}/{repo.repo_id}"

    def _info(self, client: httpx.Client, repo: HfRepo, revision: str | None) -> dict[str, Any]:
        url = self._api_base(repo)
        if revision:
            url += f"/revision/{quote(revision, safe='')}"
        data, _ = self._api(client, url)
        if not isinstance(data, dict):
            raise AppError(ErrorCode.HF_ERROR, "Unexpected Hub API response", 502)
        if data.get("private") is True or data.get("disabled") is True:
            raise AppError(ErrorCode.HF_ACCESS_DENIED, "Repository is private or disabled", 403)
        if data.get("gated") not in (None, False):
            raise AppError(
                ErrorCode.HF_ACCESS_DENIED,
                "Repository is gated; gated repositories are not supported (no HF token is used)",
                403,
                {"gated": str(data.get("gated"))[:16]},
            )
        sha = data.get("sha")
        if not isinstance(sha, str) or not _SHA1_RE.match(sha):
            raise AppError(ErrorCode.HF_ERROR, "Hub API did not return a commit sha", 502)
        return data

    def _tree(
        self, client: httpx.Client, repo: HfRepo, sha: str, max_files: int
    ) -> list[dict[str, Any]]:
        first = f"{self._api_base(repo)}/tree/{sha}?recursive=true"
        prefix = urlsplit(first).path
        url: str | None = first
        entries: list[dict[str, Any]] = []
        for _ in range(MAX_TREE_PAGES):
            if url is None:
                break
            data, headers = self._api(client, url)
            if not isinstance(data, list):
                raise AppError(ErrorCode.HF_ERROR, "Unexpected Hub tree response", 502)
            entries.extend(e for e in data if isinstance(e, dict) and e.get("type") == "file")
            if len(entries) > max_files:
                raise AppError(
                    ErrorCode.TOO_MANY_FILES,
                    "Repository contains too many files",
                    413,
                    {"max_files": max_files},
                )
            url = None
            match = _LINK_NEXT_RE.search(headers.get("link", ""))
            if match:
                nxt = urljoin(first, match.group(1))
                parts = urlsplit(nxt)
                if parts.scheme != "https" or parts.hostname != HF_HOST or parts.path != prefix:
                    raise AppError(ErrorCode.HF_ERROR, "Unexpected tree pagination link", 502)
                url = nxt
        return entries

    # ------------------------------------------------------------------ files
    @staticmethod
    def _to_file(entry: dict[str, Any]) -> HfFile:
        size = entry.get("size")
        lfs = entry.get("lfs") if isinstance(entry.get("lfs"), dict) else None
        lfs_sha = lfs.get("oid") if lfs else None
        oid = entry.get("oid")
        path = safe_repo_path(entry.get("path"))
        f = HfFile(
            path=path or str(entry.get("path"))[:MAX_PATH_LENGTH],
            size=size if isinstance(size, int) and size >= 0 else 0,
            git_oid=oid if isinstance(oid, str) and _SHA1_RE.match(oid) else None,
            lfs_sha256=lfs_sha if isinstance(lfs_sha, str) and _SHA256_RE.match(lfs_sha) else None,
        )
        if path is None:
            f.status, f.reason = "rejected", "unsafe path in repository listing"
        elif not isinstance(size, int) or size < 0:
            f.status, f.reason = "rejected", "invalid size in repository listing"
        elif lfs is not None and f.lfs_sha256 is None:
            f.status, f.reason = "rejected", "LFS entry without a valid sha256"
        elif lfs is None and f.git_oid is None:
            f.status, f.reason = "rejected", "entry without a valid git object id"
        return f

    def _resolve_url(self, repo: HfRepo, sha: str, path: str) -> str:
        prefix = "datasets/" if repo.repo_type == "dataset" else ""
        return f"{HF_BASE}/{prefix}{repo.repo_id}/resolve/{sha}/{quote(path, safe='/')}"

    def _download(
        self, client: httpx.Client, url: str, f: HfFile, target: Path, deadline: float
    ) -> None:
        for _hop in range(MAX_REDIRECTS + 1):
            if self.clock() > deadline:
                raise _DownloadError("skipped", "download time budget exhausted")
            try:
                with client.stream("GET", url) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location")
                        if not location:
                            raise _DownloadError("failed", "redirect without a location")
                        nxt = urljoin(url, location)
                        try:
                            validate_hf_redirect_url(nxt, check_dns=self.check_dns)
                        except AppError as exc:
                            raise _DownloadError(
                                "rejected", f"redirect refused: {exc.message}"
                            ) from exc
                        url = nxt
                        continue
                    if resp.status_code != 200:
                        raise _DownloadError("failed", f"HTTP {resp.status_code}")
                    self._write(resp, f, target, deadline)
                    return
            except httpx.TimeoutException as exc:
                raise _DownloadError("failed", "download timed out") from exc
            except httpx.TransportError as exc:
                raise _DownloadError("failed", f"network error ({exc.__class__.__name__})") from exc
        raise _DownloadError("rejected", "too many redirects")

    def _write(self, resp: httpx.Response, f: HfFile, target: Path, deadline: float) -> None:
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1(f"blob {f.size}\0".encode(), usedforsecurity=False)
        written = 0
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in resp.iter_bytes(CHUNK_SIZE):
                    written += len(chunk)
                    if written > f.size:
                        raise _DownloadError(
                            "integrity_mismatch", "content is larger than the listed size"
                        )
                    if self.clock() > deadline:
                        raise _DownloadError("skipped", "download time budget exhausted")
                    sha256.update(chunk)
                    sha1.update(chunk)
                    out.write(chunk)
            if written != f.size:
                raise _DownloadError("integrity_mismatch", "content size differs from the listing")
            local = sha256.hexdigest()
            if f.lfs_sha256 is not None and local != f.lfs_sha256:
                raise _DownloadError("integrity_mismatch", "SHA-256 differs from the LFS listing")
            if f.lfs_sha256 is None and sha1.hexdigest() != f.git_oid:
                raise _DownloadError("integrity_mismatch", "git blob id differs from the listing")
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        f.local_sha256 = local
        f.hash_verified = True

    def fetch(
        self, repo: HfRepo, revision: str | None, dest: Path, limits: HfFetchLimits
    ) -> HfFetchResult:
        dest_root = dest.resolve()
        deadline = self.clock() + limits.timeout_seconds
        with self._client() as client:
            info = self._info(client, repo, revision)
            sha = info["sha"]
            files = [self._to_file(e) for e in self._tree(client, repo, sha, limits.max_files)]
            result = HfFetchResult(
                source="huggingface",
                repo=repo,
                commit_sha=sha,
                files=files,
                meta=_meta(info),
                card_data=info.get("cardData") if isinstance(info.get("cardData"), dict) else None,
            )
            seen: set[str] = set()
            total = 0
            # Small files first, so configs and cards are fetched before the budget runs out.
            for f in sorted(files, key=lambda x: (x.size, x.path)):
                if f.status == "rejected":
                    continue
                if f.path in seen:
                    f.status, f.reason = "rejected", "duplicate path in repository listing"
                    continue
                seen.add(f.path)
                target = (dest_root / f.path).resolve()
                if not target.is_relative_to(dest_root) or target == dest_root:
                    f.status, f.reason = "rejected", "path escapes the workspace"
                    continue
                if f.lfs_sha256 is not None and f.size > limits.max_file_bytes:
                    f.status, f.reason = "skipped", "exceeds the per-file download cap"
                    continue
                if total + f.size > limits.max_total_bytes:
                    f.status, f.reason = "skipped", "exceeds the total download budget"
                    continue
                try:
                    url = self._resolve_url(repo, sha, f.path)
                    self._download(client, url, f, target, deadline)
                except _DownloadError as exc:
                    f.status, f.reason = exc.status, exc.reason
                    if exc.status == "integrity_mismatch":
                        f.hash_verified = False
                    logger.warning("HF file %s not downloaded: %s", f.path, exc.reason)
                    continue
                f.downloaded, f.status = True, "downloaded"
                total += f.size
        failed = [f for f in files if f.status == "failed"]
        if failed:
            result.warnings.append(f"{len(failed)} file(s) failed to download")
        return result


def _meta(info: dict[str, Any]) -> dict[str, Any]:
    def text(key: str, limit: int = 256) -> str | None:
        value = info.get(key)
        return value[:limit] if isinstance(value, str) else None

    tags = info.get("tags")
    return {
        "repo_id": text("id"),
        "author": text("author"),
        "library_name": text("library_name"),
        "pipeline_tag": text("pipeline_tag"),
        "last_modified": text("lastModified"),
        "created_at": text("createdAt"),
        "tags": [t[:64] for t in tags[:50] if isinstance(t, str)] if isinstance(tags, list) else [],
        "downloads": info.get("downloads") if isinstance(info.get("downloads"), int) else None,
        "likes": info.get("likes") if isinstance(info.get("likes"), int) else None,
    }

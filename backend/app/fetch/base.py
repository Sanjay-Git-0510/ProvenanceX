"""The Fetcher interface, the fetch request builder and fetcher output validation.

`Fetcher.run` is the only way the pipeline downloads an artifact. There is deliberately no
host-side or "disabled" fetcher: without the fetcher container the scan fails. The in-process
fetcher exists only for the test suite (app/fetch/inprocess.py).
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import UUID

from pydantic import ValidationError

from app.analysis.framing import FrameError, check_json_budget
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.fetch_worker.protocol import FetchLimits, FetchRequest, FetchResult, Source
from app.pipeline.workspace import MB, Workspace
from app.scanners.hf.base import HfFetchResult, HfFile
from app.security.url_validation import HfRepo

logger = logging.getLogger(__name__)

ENVELOPE_MAX_CONTAINERS = 100_000
ENVELOPE_MAX_ITEMS = 1_000_000
ENVELOPE_MAX_DEPTH = 64


@dataclass(frozen=True)
class FetchJob:
    scan_id: UUID
    workspace: Workspace
    source: Source
    url: str
    revision: str | None
    # The scan's tmpfs staging volume; None only for the in-process test fetcher.
    staging_volume: str | None = None
    uid: int | None = None
    gid: int | None = None


@dataclass
class FetchRun:
    result: FetchResult
    record: dict[str, Any] = field(default_factory=dict)


class Fetcher(Protocol):
    name: str

    def run(self, job: FetchJob) -> FetchRun:
        """Download into the staging area. Raises AppError when no usable result exists."""
        ...


def build_fetch_request(settings: Settings, job: FetchJob, *, proxy: bool = True) -> FetchRequest:
    if job.source == "github":
        max_files = settings.max_artifact_files
    else:
        max_files = min(settings.hf_max_files, settings.max_artifact_files)
    return FetchRequest(
        source=job.source,
        url=job.url,
        revision=job.revision,
        hf_provider=settings.hf_provider,
        proxy_url=settings.fetcher_proxy_url if proxy else None,
        allowed_hosts=list(settings.egress_allowed_hosts),
        user_agent=f"ProvenanceX/{settings.scanner_version} (supply-chain scanner)",
        limits=FetchLimits(
            max_total_bytes=settings.max_artifact_size_mb * MB,
            max_files=max_files,
            max_file_bytes=settings.hf_max_file_mb * MB,
            timeout_seconds=(
                settings.git_clone_timeout_seconds
                if job.source == "github"
                else settings.hf_download_timeout_seconds
            ),
            hf_api_timeout_seconds=settings.hf_timeout_seconds,
            http_max_retries=settings.http_max_retries,
            max_api_bytes=settings.http_max_response_mb * MB,
        ),
    )


def fetch_output_invalid(reason: str) -> AppError:
    return AppError(
        ErrorCode.FETCH_OUTPUT_INVALID,
        "The fetcher returned output that failed validation; it was discarded",
        502,
        {"reason": reason},
    )


def parse_fetch_output(envelope: bytes, max_bytes: int, source: Source) -> FetchResult:
    """Validate the untrusted fetcher envelope. Raises fetch_output_invalid."""
    if not envelope:
        raise fetch_output_invalid("empty output")
    if len(envelope) > max_bytes:
        raise fetch_output_invalid("output exceeds the size limit")
    try:
        check_json_budget(
            envelope,
            max_containers=ENVELOPE_MAX_CONTAINERS,
            max_items=ENVELOPE_MAX_ITEMS,
            max_depth=ENVELOPE_MAX_DEPTH,
        )
        data = json.loads(envelope)
    except FrameError as exc:
        raise fetch_output_invalid(str(exc)) from exc
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise fetch_output_invalid("output is not valid JSON") from exc
    try:
        result = FetchResult.model_validate(data)
    except ValidationError as exc:
        logger.warning("Fetcher output failed schema validation: %s", exc.error_count())
        raise fetch_output_invalid("output does not match the result schema") from exc
    if result.source != source:
        raise fetch_output_invalid("output is for a different source")
    return result


def raise_if_fetch_error(result: FetchResult) -> None:
    err = result.error
    if result.status != "error" or err is None:
        return
    known = {str(c) for c in ErrorCode}
    code = err.code if err.code in known else str(ErrorCode.FETCH_FAILED)
    status = 500 if code in (ErrorCode.INTERNAL_ERROR, ErrorCode.SANDBOX_REFUSED) else 502
    raise AppError(code, err.message, status, err.details)


def to_hf_result(result: FetchResult) -> HfFetchResult:
    """Rebuild the pipeline's HfFetchResult from the validated fetcher manifest."""
    hf = result.hf
    if hf is None or result.commit_sha is None:
        raise fetch_output_invalid("missing Hugging Face evidence")
    files = []
    for f in hf.files:
        item = HfFile(
            path=f.path,
            size=f.size,
            git_oid=f.git_oid,
            lfs_sha256=f.lfs_sha256,
            downloaded=f.downloaded,
            local_sha256=f.local_sha256,
            hash_verified=f.hash_verified,
            status=f.status,
            reason=f.reason,
        )
        if item.downloaded and (item.status != "downloaded" or item.local_sha256 is None):
            raise fetch_output_invalid("a downloaded file has no verified hash")
        files.append(item)
    return HfFetchResult(
        source=hf.source,
        repo=HfRepo(repo_type=hf.repo_type, repo_id=hf.repo_id),
        commit_sha=result.commit_sha,
        files=files,
        meta=dict(hf.meta),
        card_data=dict(hf.card_data) if hf.card_data is not None else None,
        warnings=list(hf.warnings),
    )

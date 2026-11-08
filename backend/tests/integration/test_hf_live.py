"""Live Hugging Face Hub checks. Run with PROVENANCEX_NETWORK_TESTS=1.

They use small public test repositories. Downloaded files are only hashed and parsed.
"""

import re

import pytest

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.pipeline.providers import build_providers
from app.scanners.hf.base import HfFetchLimits
from app.scanners.model.aibom import ModelContext, analyze_model
from app.security.url_validation import validate_hf_repo_url

pytestmark = pytest.mark.network

TINY_MODEL = "https://huggingface.co/hf-internal-testing/tiny-random-gpt2"
MB = 1024 * 1024
LIMITS = HfFetchLimits(
    max_total_bytes=32 * MB, max_file_bytes=16 * MB, max_files=200, timeout_seconds=120
)


def provider():
    return build_providers(Settings(_env_file=None, hf_provider="hf", nvd_enabled=False)).hf


def test_live_fetch_verifies_downloads_and_never_exceeds_caps(tmp_path):
    repo = validate_hf_repo_url(TINY_MODEL)
    result = provider().fetch(repo, None, tmp_path, LIMITS)
    assert result.source == "huggingface"
    assert re.fullmatch(r"[0-9a-f]{40}", result.commit_sha)
    assert result.downloaded, result.files
    assert "config.json" in {f.path for f in result.downloaded}
    assert all(f.hash_verified is True for f in result.downloaded)
    assert not [f for f in result.files if f.status == "integrity_mismatch"]
    assert sum(f.size for f in result.downloaded) <= LIMITS.max_total_bytes
    for f in result.downloaded:
        assert (tmp_path / f.path).stat().st_size == f.size


def test_live_lfs_over_cap_is_listed_with_hub_hash_only(tmp_path):
    repo = validate_hf_repo_url(TINY_MODEL)
    limits = HfFetchLimits(
        max_total_bytes=32 * MB, max_file_bytes=1, max_files=200, timeout_seconds=120
    )
    result = provider().fetch(repo, None, tmp_path, limits)
    skipped = [f for f in result.files if f.lfs_sha256 and f.size > 1]
    assert skipped, "the fixture repository is expected to contain LFS weights"
    for f in skipped:
        assert f.status == "skipped" and not f.downloaded and f.hash_verified is None
        assert not (tmp_path / f.path).exists()


def test_live_analysis_builds_an_aibom_from_real_files(tmp_path):
    repo = validate_hf_repo_url(TINY_MODEL)
    result = provider().fetch(repo, None, tmp_path, LIMITS)
    ctx = ModelContext(
        name=repo.repo_id,
        artifact_type="model",
        source="huggingface",
        source_url=repo.canonical_url,
        repo_id=repo.repo_id,
        commit_sha=result.commit_sha,
        api_card_data=result.card_data,
        api_meta=result.meta,
    )
    analysis = analyze_model(tmp_path, ctx, Settings(_env_file=None))
    assert analysis.aibom["summary"]["file_count"] == len(result.files)
    assert analysis.inventory


def test_live_missing_repository_is_a_structured_error(tmp_path):
    repo = validate_hf_repo_url("https://huggingface.co/provenancex-does-not-exist/no-such-repo")
    with pytest.raises(AppError) as exc:
        provider().fetch(repo, None, tmp_path, LIMITS)
    # The Hub answers 401 for unknown repositories when the request has no token.
    assert exc.value.code in (ErrorCode.HF_ACCESS_DENIED, ErrorCode.HF_NOT_FOUND)

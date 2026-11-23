"""Read-only input limits for the UI's pre-scan checks.

The UI uses these to warn early (file too large, wrong host, bad revision). The server still
enforces every limit on submission; this endpoint only reports them. It exposes no secrets,
paths, RPC URLs or keys: only sizes, counts, host names and provider modes.
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.config import Settings, get_settings
from app.security.revision import MAX_REVISION_LENGTH
from app.security.url_validation import GITHUB_HOSTS, HF_HOSTS, MAX_URL_LENGTH

router = APIRouter(prefix="/limits", tags=["limits"])

SOFTWARE_TYPES = ("software",)
MODEL_TYPES = ("model", "lora", "dataset")


class SourceHosts(BaseModel):
    software: list[str]
    model: list[str]


class ArtifactTypes(BaseModel):
    software: list[str]
    model: list[str]


class LimitsResponse(BaseModel):
    """Limits the server enforces on scan submission, for display and early warnings."""

    max_upload_mb: int
    max_artifact_size_mb: int
    max_artifact_files: int
    max_url_length: int
    max_revision_length: int
    upload_extensions: list[str]
    allowed_hosts: SourceHosts
    artifact_types: ArtifactTypes
    sandbox_provider: Literal["disabled", "docker", "mock"]
    blockchain_provider: Literal["disabled", "web3", "mock"]
    blockchain_anchor_on_scan: bool


@router.get("", response_model=LimitsResponse)
def get_limits(settings: Annotated[Settings, Depends(get_settings)]) -> LimitsResponse:
    """Return the submission limits and which optional layers are switched on."""
    return LimitsResponse(
        max_upload_mb=settings.max_upload_mb,
        max_artifact_size_mb=settings.max_artifact_size_mb,
        max_artifact_files=settings.max_artifact_files,
        max_url_length=MAX_URL_LENGTH,
        max_revision_length=MAX_REVISION_LENGTH,
        upload_extensions=[".zip"],
        allowed_hosts=SourceHosts(software=sorted(GITHUB_HOSTS), model=sorted(HF_HOSTS)),
        artifact_types=ArtifactTypes(software=list(SOFTWARE_TYPES), model=list(MODEL_TYPES)),
        sandbox_provider=settings.sandbox_provider,
        blockchain_provider=settings.blockchain_provider,
        blockchain_anchor_on_scan=settings.blockchain_anchor_on_scan,
    )

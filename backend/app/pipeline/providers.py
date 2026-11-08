"""Builds the external-integration providers for a scan, based on settings.

Real providers are the default. Mocks are used only when configured explicitly
(SBOM_PROVIDER=mock / VULN_PROVIDER=mock / HF_PROVIDER=mock), never as a silent fallback
when a real tool is missing. A missing tool shows up as an `unavailable` stage instead.
"""

from collections.abc import Callable
from dataclasses import dataclass

import httpx

from app.core.config import Settings
from app.pipeline.workspace import MB
from app.scanners.hf.base import HfProvider
from app.scanners.hf.client import HuggingFaceProvider
from app.scanners.hf.mock import MockHfProvider
from app.scanners.sbom.base import SbomProvider
from app.scanners.sbom.mock import MockSbomProvider
from app.scanners.sbom.syft import SyftProvider
from app.scanners.vulns.base import VulnProvider
from app.scanners.vulns.http import JsonHttpClient
from app.scanners.vulns.mock import MockVulnProvider
from app.scanners.vulns.nvd import NvdEnricher
from app.scanners.vulns.osv import OsvProvider


@dataclass
class ScanProviders:
    sbom: SbomProvider
    vulns: VulnProvider
    nvd: NvdEnricher | None
    hf: HfProvider | None = None


def _client_factory(
    settings: Settings, timeout: float, transport: httpx.BaseTransport | None
) -> Callable[[], JsonHttpClient]:
    def factory() -> JsonHttpClient:
        return JsonHttpClient(
            timeout_seconds=timeout,
            max_retries=settings.http_max_retries,
            max_response_bytes=settings.http_max_response_mb * MB,
            user_agent=f"ProvenanceX/{settings.scanner_version} (supply-chain scanner)",
            transport=transport,
        )

    return factory


def build_providers(
    settings: Settings, transport: httpx.BaseTransport | None = None
) -> ScanProviders:
    sbom: SbomProvider
    if settings.sbom_provider == "mock":
        sbom = MockSbomProvider()
    else:
        sbom = SyftProvider(
            settings.syft_path, settings.syft_timeout_seconds, settings.max_sbom_mb * MB
        )

    vulns: VulnProvider
    nvd: NvdEnricher | None = None
    if settings.vuln_provider == "mock":
        vulns = MockVulnProvider()
    else:
        vulns = OsvProvider(
            settings.osv_api_base,
            _client_factory(settings, settings.osv_timeout_seconds, transport),
            settings.osv_max_detail_lookups,
        )
        if settings.nvd_enabled:
            nvd = NvdEnricher(
                settings.nvd_api_base,
                settings.nvd_api_key,
                _client_factory(settings, settings.nvd_timeout_seconds, transport),
                settings.nvd_max_lookups,
            )
    hf: HfProvider
    if settings.hf_provider == "mock":
        hf = MockHfProvider()
    else:
        hf = HuggingFaceProvider(
            timeout_seconds=settings.hf_timeout_seconds,
            max_retries=settings.http_max_retries,
            max_api_bytes=settings.http_max_response_mb * MB,
            user_agent=f"ProvenanceX/{settings.scanner_version} (supply-chain scanner)",
            transport=transport,
        )
    return ScanProviders(sbom=sbom, vulns=vulns, nvd=nvd, hf=hf)

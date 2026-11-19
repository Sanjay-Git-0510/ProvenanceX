"""Builds the external-integration providers for a scan, based on settings.

Real providers are the default. Mocks are used only when configured explicitly
(SBOM_PROVIDER=mock / VULN_PROVIDER=mock / HF_PROVIDER=mock), never as a silent fallback
when a real tool is missing. A missing tool shows up as an `unavailable` stage instead.

Downloads (GitHub, Hugging Face, including HF_PROVIDER=mock) happen only in the isolated fetcher
container (`fetcher`). The runner holds no download client: `hf` is set only by tests, which
hand it to the pytest-only in-process fetcher.
"""

from collections.abc import Callable
from dataclasses import dataclass

import httpx

from app.analysis.base import ContentAnalyzer
from app.analysis.factory import build_analyzer
from app.blockchain.base import ChainProvider
from app.blockchain.mock import MockChainProvider
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.fetch.base import Fetcher
from app.fetch.factory import build_fetcher
from app.pipeline.workspace import MB
from app.scanners.hf.base import HfProvider
from app.scanners.sandbox.base import SandboxProvider
from app.scanners.sandbox.docker_provider import DockerSandboxProvider
from app.scanners.sandbox.hardening import SandboxLimits
from app.scanners.sandbox.mock import MockSandboxProvider
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
    # Test hook only: the HF provider the in-process test fetcher uses. Never used by the
    # runner itself; production builds leave it None.
    hf: HfProvider | None = None
    sandbox: SandboxProvider | None = None  # None: SANDBOX_PROVIDER=disabled
    chain: ChainProvider | None = None  # None: BLOCKCHAIN_PROVIDER=disabled
    # The isolated analyzer every content-reading step runs in. None is never a fallback:
    # require_analyzer() fails the scan with sandbox_unavailable.
    analyzer: ContentAnalyzer | None = None
    # The isolated fetcher that downloads GitHub and Hugging Face artifacts. None is never a
    # fallback: require_fetcher() fails the scan.
    fetcher: Fetcher | None = None


def require_fetcher(providers: ScanProviders) -> Fetcher:
    if providers.fetcher is None:
        raise AppError(
            ErrorCode.SANDBOX_UNAVAILABLE,
            "No isolated fetcher is configured; the artifact was not downloaded",
            503,
        )
    return providers.fetcher


def require_analyzer(providers: ScanProviders) -> ContentAnalyzer:
    if providers.analyzer is None:
        raise AppError(
            ErrorCode.SANDBOX_UNAVAILABLE,
            "No analyzer sandbox is configured; the artifact was not processed",
            503,
        )
    return providers.analyzer


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


def _sandbox(settings: Settings) -> SandboxProvider | None:
    if settings.sandbox_provider == "mock":
        return MockSandboxProvider()
    if settings.sandbox_provider == "docker":
        return DockerSandboxProvider(
            settings.sandbox_docker_path,
            settings.sandbox_image,
            SandboxLimits(
                timeout_seconds=settings.sandbox_timeout_seconds,
                memory_mb=settings.sandbox_memory_mb,
                cpus=settings.sandbox_cpus,
                pids=settings.sandbox_pids_limit,
                tmp_mb=settings.sandbox_tmp_mb,
                trace_tmp_mb=settings.sandbox_trace_tmp_mb,
            ),
            settings.sandbox_max_trace_mb * MB,
            settings.sandbox_host_grace_seconds,
            max_stderr_bytes=settings.sandbox_max_stderr_kb * 1024,
            max_concurrent=settings.sandbox_max_concurrent,
            queue_timeout_seconds=settings.sandbox_queue_timeout_seconds,
        )
    return None


# One ledger per process, so that anchors outlive a single request.
_mock_chain = MockChainProvider()


def build_chain_provider(settings: Settings) -> ChainProvider | None:
    """Configuration is checked when the chain is used, so it can never break a scan."""
    if settings.blockchain_provider == "mock":
        return _mock_chain
    if settings.blockchain_provider == "web3":
        # Imported here so that web3 loads only when the real chain is selected.
        from app.blockchain.web3_provider import Web3ChainProvider

        return Web3ChainProvider(
            settings.blockchain_rpc_url,
            settings.blockchain_contract_address,
            settings.blockchain_private_key,
            settings.blockchain_timeout_seconds,
        )
    return None


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
    return ScanProviders(
        sbom=sbom,
        vulns=vulns,
        nvd=nvd,
        hf=None,
        sandbox=_sandbox(settings),
        chain=build_chain_provider(settings),
        analyzer=build_analyzer(settings),
        fetcher=build_fetcher(settings, _engine_or_none(settings)),
    )


def _engine_or_none(settings: Settings):  # noqa: ANN202 - Engine | None
    """The engine used for cross-runner admission locks (PostgreSQL advisory locks)."""
    if settings.fetcher_provider != "docker":
        return None
    from app.db.database import get_engine

    return get_engine()

"""Builds the configured Fetcher. There is no host-side or disabled option."""

from sqlalchemy.engine import Engine

from app.core.config import Settings
from app.fetch.base import Fetcher


def build_fetcher(settings: Settings, engine: Engine | None = None) -> Fetcher:
    if settings.fetcher_provider == "inprocess_test":
        # Imported lazily so production code paths never load the in-process fetcher.
        from app.fetch.inprocess import InProcessTestFetcher

        return InProcessTestFetcher(settings)
    from app.fetch.docker_fetcher import DockerFetcher

    return DockerFetcher(settings, engine=engine)

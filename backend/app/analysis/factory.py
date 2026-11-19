"""Builds the configured ContentAnalyzer. There is no disabled or host-side option."""

from app.analysis.base import ContentAnalyzer
from app.core.config import Settings


def build_analyzer(settings: Settings) -> ContentAnalyzer:
    if settings.analyzer_provider == "inprocess_test":
        # Imported lazily so production code paths never load the in-process executor.
        from app.analysis.inprocess import InProcessTestAnalyzer

        return InProcessTestAnalyzer(settings)
    from app.analysis.docker_analyzer import DockerAnalyzer

    return DockerAnalyzer(settings)

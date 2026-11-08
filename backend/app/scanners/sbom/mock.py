"""Mock SBOM provider: returns a recorded Syft SBOM, tagged source="mock".

It ignores the scanned content entirely. It exists so the API and UI can be developed and
tested without Syft. Its output must never be presented as a real scan result.
"""

from pathlib import Path

from app.scanners.sbom.base import SbomResult

MOCK_SBOM_PATH = Path(__file__).resolve().parent.parent / "mock_data" / "mock_sbom.cdx.json"


class MockSbomProvider:
    name = "mock"

    def __init__(self, fixture_path: Path = MOCK_SBOM_PATH) -> None:
        self.fixture_path = fixture_path

    def generate(self, src_dir: Path, work_dir: Path) -> SbomResult:  # noqa: ARG002
        return SbomResult(
            raw=self.fixture_path.read_bytes(),
            source="mock",
            tool_name="mock-sbom",
            tool_version=None,
        )

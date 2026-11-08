"""Mock sandbox provider: a synthetic recorded bundle, tagged source="mock".

Used only with SANDBOX_PROVIDER=mock. It is never a fallback when Docker is missing. It
runs nothing and returns the same bundle for every artifact.
"""

from pathlib import Path

from app.scanners.sandbox.base import SandboxRequest, SandboxRun

MOCK_TRACE_PATH = Path(__file__).resolve().parent.parent / "mock_data" / "sandbox_trace.json"


class MockSandboxProvider:
    name = "mock"

    def __init__(self, trace_path: Path = MOCK_TRACE_PATH) -> None:
        self.trace_path = trace_path

    def run(self, request: SandboxRequest) -> SandboxRun:  # noqa: ARG002
        return SandboxRun(self.trace_path.read_bytes(), False, "mock")

"""Turns parsed telemetry into category="behavioral" findings.

These are observed-behavior signals with ProvenanceX rule severities and no CVSS. They
are not known vulnerabilities. Each kind produces at most one finding per scan.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.db.models import Finding, FindingCategory
from app.scanners.sandbox.telemetry import TelemetryResult


@dataclass(frozen=True)
class BehaviorSignal:
    identifier: str
    kind: str
    severity: str
    title: str
    evidence: dict[str, Any]


def build_behavior_signals(result: TelemetryResult) -> list[BehaviorSignal]:
    signals: list[BehaviorSignal] = []
    if result.destinations:
        total = result.features["external_destination_count"]
        signals.append(
            BehaviorSignal(
                "PX-BEHAV-EXTERNAL-CONNECT",
                "external_connection_attempt",
                "HIGH",
                f"Attempted to reach {total} public network destination(s)",
                {"destinations": result.destinations, "total": total},
            )
        )
    if result.sensitive_paths:
        signals.append(
            BehaviorSignal(
                "PX-BEHAV-SENSITIVE-FILE",
                "sensitive_file_access",
                "HIGH",
                f"Tried to open {len(result.sensitive_paths)} sensitive path(s)",
                {"paths": result.sensitive_paths},
            )
        )
    if result.shell_spawns:
        tools = ", ".join(sorted(result.shell_spawns))
        signals.append(
            BehaviorSignal(
                "PX-BEHAV-SHELL-SPAWN",
                "shell_spawn",
                "MEDIUM",
                f"Started a shell or network tool: {tools}",
                {"tools": result.shell_spawns},
            )
        )
    if result.features["resource_spike"]:
        signals.append(
            BehaviorSignal(
                "PX-BEHAV-RESOURCE-SPIKE",
                "resource_spike",
                "LOW",
                "Resource use reached a sandbox limit: " + ", ".join(result.spike_reasons),
                {
                    "reasons": result.spike_reasons,
                    "peak_memory_bytes": result.features["peak_memory_bytes"],
                    "peak_pids": result.features["peak_pids"],
                },
            )
        )
    return signals


def behavior_finding(
    scan_id: UUID, source: str, signal: BehaviorSignal, *, synthetic: bool = False
) -> Finding:
    return Finding(
        scan_id=scan_id,
        component_id=None,
        category=FindingCategory.BEHAVIORAL,
        identifier=signal.identifier,
        aliases=[],
        title=signal.title[:512],
        severity=signal.severity,
        severity_source="provenancex_rule",
        cvss_score=None,
        cvss_vector=None,
        cvss_version=None,
        source=source,
        details={"kind": signal.kind, "synthetic": synthetic, **signal.evidence},
    )

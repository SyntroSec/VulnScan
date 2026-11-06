"""Shared data models for the vulnerability scanner engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Risk rating for findings and executive summaries."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def rank(self) -> int:
        order: dict[Severity, int] = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return order[self]


@dataclass(slots=True)
class PortResult:
    """Result of probing a single TCP/UDP port."""

    port: int
    protocol: str
    state: str
    service: str | None = None
    banner: str | None = None
    latency_ms: float | None = None


@dataclass(slots=True)
class HostResult:
    """Discovery and port-scan outcome for one target host."""

    host: str
    alive: bool
    hostname: str | None = None
    open_ports: list[PortResult] = field(default_factory=list)
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    """Normalized vulnerability / misconfiguration finding."""

    finding_id: str
    title: str
    severity: Severity
    host: str
    description: str
    evidence: str
    remediation: str
    plugin_id: str
    port: int | None = None
    protocol: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


@dataclass(slots=True)
class ScanSession:
    """Aggregated results from a full scan run."""

    session_id: str
    started_at: str
    finished_at: str | None = None
    targets: list[str] = field(default_factory=list)
    hosts: list[HostResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "targets": self.targets,
            "hosts": [h.to_dict() for h in self.hosts],
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
            "summary": {
                "hosts_alive": sum(1 for h in self.hosts if h.alive),
                "hosts_total": len(self.hosts),
                "open_ports": sum(len(h.open_ports) for h in self.hosts),
                "findings_total": len(self.findings),
                "by_severity": {
                    sev.value: sum(1 for f in self.findings if f.severity == sev)
                    for sev in Severity
                },
            },
        }

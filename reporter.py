"""Consolidate scan findings into structured JSON and Markdown reports."""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from models import Finding, HostResult, ScanSession, Severity

logger = logging.getLogger(__name__)

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


class ReportGenerator:
    """Merge network, plugin, and credentialed findings into exportable reports."""

    def __init__(self, session: ScanSession) -> None:
        self.session = session

    @classmethod
    def from_components(
        cls,
        *,
        session_id: str,
        started_at: str,
        targets: list[str],
        hosts: list[HostResult],
        plugin_findings: list[Finding],
        credentialed_findings: list[Finding] | None = None,
        errors: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ReportGenerator:
        findings = list(plugin_findings) + list(credentialed_findings or [])
        findings.sort(key=lambda f: (-f.severity.rank, f.host, f.finding_id))
        session = ScanSession(
            session_id=session_id,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            targets=targets,
            hosts=hosts,
            findings=findings,
            errors=list(errors or []),
            metadata=dict(metadata or {}),
        )
        return cls(session)

    def to_json_dict(self) -> dict[str, Any]:
        return self.session.to_dict()

    def write_json(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_json_dict()
        output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        logger.info("Wrote JSON report: %s", output)
        return output

    def render_markdown(self) -> str:
        data = self.to_json_dict()
        summary = data["summary"]
        lines: list[str] = []
        lines.append("# Vulnerability Scan Executive Summary")
        lines.append("")
        lines.append(f"- **Session ID:** `{self.session.session_id}`")
        lines.append(f"- **Started:** {self.session.started_at}")
        lines.append(f"- **Finished:** {self.session.finished_at or 'n/a'}")
        lines.append(f"- **Targets:** {', '.join(self.session.targets) or 'n/a'}")
        lines.append(
            f"- **Hosts alive:** {summary['hosts_alive']} / {summary['hosts_total']}"
        )
        lines.append(f"- **Open ports:** {summary['open_ports']}")
        lines.append(f"- **Findings:** {summary['findings_total']}")
        lines.append("")
        lines.append("## Risk Distribution")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sev in SEVERITY_ORDER:
            lines.append(f"| {sev.value} | {summary['by_severity'].get(sev.value, 0)} |")
        lines.append("")

        lines.append("## Executive Narrative")
        lines.append("")
        lines.append(self._executive_narrative(summary))
        lines.append("")

        lines.append("## Host Inventory")
        lines.append("")
        if not self.session.hosts:
            lines.append("_No hosts scanned._")
        else:
            lines.append("| Host | Hostname | Alive | Open Ports | Services |")
            lines.append("|---|---|---|---|---|")
            for host in self.session.hosts:
                ports = ", ".join(
                    f"{p.port}/{p.protocol}" for p in host.open_ports if p.state == "open"
                ) or "-"
                services = ", ".join(
                    sorted(
                        {
                            p.service
                            for p in host.open_ports
                            if p.state == "open" and p.service
                        }
                    )
                ) or "-"
                lines.append(
                    f"| `{host.host}` | {host.hostname or '-'} | "
                    f"{'yes' if host.alive else 'no'} | {ports} | {services} |"
                )
        lines.append("")

        lines.append("## Findings")
        lines.append("")
        if not self.session.findings:
            lines.append("_No findings reported._")
        else:
            for severity in SEVERITY_ORDER:
                group = [f for f in self.session.findings if f.severity == severity]
                if not group:
                    continue
                lines.append(f"### {severity.value} ({len(group)})")
                lines.append("")
                for finding in group:
                    location = finding.host
                    if finding.port is not None:
                        location = f"{finding.host}:{finding.port}/{finding.protocol or 'tcp'}"
                    cves = ", ".join(finding.cve_ids) if finding.cve_ids else "n/a"
                    lines.append(f"#### {finding.title}")
                    lines.append("")
                    lines.append(f"- **ID:** `{finding.finding_id}`")
                    lines.append(f"- **Plugin:** `{finding.plugin_id}`")
                    lines.append(f"- **Location:** `{location}`")
                    lines.append(f"- **CVE(s):** {cves}")
                    lines.append(f"- **Detected:** {finding.detected_at}")
                    lines.append("")
                    lines.append("**Description**")
                    lines.append("")
                    lines.append(finding.description or "_No description._")
                    lines.append("")
                    lines.append("**Evidence**")
                    lines.append("")
                    lines.append("```")
                    lines.append(finding.evidence or "")
                    lines.append("```")
                    lines.append("")
                    lines.append("**Remediation**")
                    lines.append("")
                    lines.append(finding.remediation or "_No remediation provided._")
                    lines.append("")
                    if finding.references:
                        lines.append("**References**")
                        lines.append("")
                        for ref in finding.references:
                            lines.append(f"- {ref}")
                        lines.append("")

        if self.session.errors:
            lines.append("## Errors / Warnings")
            lines.append("")
            for err in self.session.errors:
                lines.append(f"- {err}")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(
            "_Generated by the local Vulnerability Scanner engine. "
            "Use only on systems you are authorized to assess._"
        )
        lines.append("")
        return "\n".join(lines)

    def write_markdown(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.render_markdown(), encoding="utf-8")
        logger.info("Wrote Markdown report: %s", output)
        return output

    def write_all(self, directory: str | Path, *, basename: str | None = None) -> dict[str, Path]:
        out_dir = Path(directory)
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = basename or f"scan_{self.session.session_id}"
        json_path = self.write_json(out_dir / f"{stem}.json")
        md_path = self.write_markdown(out_dir / f"{stem}.md")
        return {"json": json_path, "markdown": md_path}

    @staticmethod
    def _executive_narrative(summary: dict[str, Any]) -> str:
        by_sev: dict[str, int] = summary.get("by_severity", {})
        critical = by_sev.get(Severity.CRITICAL.value, 0)
        high = by_sev.get(Severity.HIGH.value, 0)
        medium = by_sev.get(Severity.MEDIUM.value, 0)
        total = summary.get("findings_total", 0)
        alive = summary.get("hosts_alive", 0)

        if total == 0:
            return (
                f"The assessment covered {alive} live host(s) and did not produce "
                "plugin or credentialed findings at the configured rule depth. "
                "Continue monitoring and expand coverage as needed."
            )

        priority = "routine hardening"
        if critical:
            priority = "immediate remediation of Critical issues"
        elif high:
            priority = "prompt remediation of High-severity exposure"
        elif medium:
            priority = "scheduled remediation of Medium-severity findings"

        return (
            f"The scan identified **{total}** finding(s) across **{alive}** live host(s), "
            f"including **{critical}** Critical and **{high}** High. "
            f"Recommended focus: {priority}. "
            "Validate each finding in context before applying changes in production."
        )


def severity_histogram(findings: list[Finding]) -> Counter[str]:
    return Counter(f.severity.value for f in findings)

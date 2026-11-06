"""Example dynamic Python plugin: flag cleartext remote-admin protocols."""

from __future__ import annotations

from models import Finding, HostResult, Severity
from plugin_engine import VulnerabilityPlugin


class CleartextRemoteAdminPlugin(VulnerabilityPlugin):
    """Detect Telnet and unencrypted FTP exposure."""

    plugin_id = "example_cleartext_remote_admin"
    name = "Cleartext Remote Admin Protocols"
    description = "Example plugin loaded dynamically from the plugins directory."

    def check_prerequisites(self, host: HostResult) -> bool:
        return any(
            p.state == "open" and p.port in {21, 23}
            for p in host.open_ports
        )

    def run_check(self, host: HostResult) -> list[Finding]:
        findings: list[Finding] = []
        for port in host.open_ports:
            if port.state != "open" or port.port not in {21, 23}:
                continue
            proto = "FTP" if port.port == 21 else "Telnet"
            findings.append(
                self.format_finding(
                    finding_id=f"EXAMPLE-CLEARTEXT-{port.port}",
                    title=f"Cleartext {proto} Service Exposed",
                    severity=Severity.CRITICAL if port.port == 23 else Severity.HIGH,
                    host=host.host,
                    description=(
                        f"{proto} transmits credentials and session data without "
                        "transport encryption."
                    ),
                    evidence=port.banner or f"Open {proto.lower()} on tcp/{port.port}",
                    remediation=(
                        "Disable the cleartext service and replace it with SSH/SFTP "
                        "or another encrypted alternative."
                    ),
                    port=port.port,
                    protocol=port.protocol,
                    references=["https://www.cisa.gov/news-events/alerts"],
                )
            )
        return findings

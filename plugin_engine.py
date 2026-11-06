"""Dynamic plugin loader and vulnerability / misconfiguration check engine."""

from __future__ import annotations

import importlib.util
import json
import logging
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Final

import yaml

from models import Finding, HostResult, PortResult, Severity

logger = logging.getLogger(__name__)


class VulnerabilityPlugin(ABC):
    """Base class for all vulnerability / misconfiguration plugins."""

    plugin_id: str = "base"
    name: str = "Base Plugin"
    description: str = ""

    def check_prerequisites(self, host: HostResult) -> bool:
        """Return True when the host exposes enough surface for this plugin."""
        return host.alive and bool(host.open_ports)

    @abstractmethod
    def run_check(self, host: HostResult) -> list[Finding]:
        """Execute the security check and return zero or more findings."""

    def format_finding(
        self,
        *,
        finding_id: str,
        title: str,
        severity: Severity,
        host: str,
        description: str,
        evidence: str,
        remediation: str,
        port: int | None = None,
        protocol: str | None = None,
        cve_ids: Sequence[str] | None = None,
        references: Sequence[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """Normalize plugin output into a shared Finding dataclass."""
        return Finding(
            finding_id=finding_id,
            title=title,
            severity=severity,
            host=host,
            description=description,
            evidence=evidence,
            remediation=remediation,
            plugin_id=self.plugin_id,
            port=port,
            protocol=protocol,
            cve_ids=list(cve_ids or []),
            references=list(references or []),
            metadata=dict(metadata or {}),
        )


class SignatureRulePlugin(VulnerabilityPlugin):
    """Evaluate YAML/JSON banner and service signature rules."""

    plugin_id = "signature_rules"
    name = "Signature Rule Engine"
    description = "Matches discovered banners/services against declarative signatures."

    def __init__(self, rules: Sequence[dict[str, Any]]) -> None:
        self.rules = list(rules)

    def check_prerequisites(self, host: HostResult) -> bool:
        return host.alive and any(p.state == "open" for p in host.open_ports)

    def run_check(self, host: HostResult) -> list[Finding]:
        findings: list[Finding] = []
        for port in host.open_ports:
            if port.state != "open":
                continue
            for rule in self.rules:
                finding = self._evaluate_rule(host, port, rule)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _evaluate_rule(
        self,
        host: HostResult,
        port: PortResult,
        rule: dict[str, Any],
    ) -> Finding | None:
        match = rule.get("match", {})
        services = {s.lower() for s in match.get("services", [])}
        ports = set(match.get("ports", []))
        banner = port.banner or ""
        service = (port.service or "").lower()

        if ports and port.port not in ports:
            return None
        if services and service not in services:
            return None

        banner_regex = match.get("banner_regex")
        if banner_regex:
            try:
                if not re.search(banner_regex, banner, flags=re.IGNORECASE | re.MULTILINE):
                    return None
            except re.error as exc:
                logger.error("Invalid banner_regex in rule %s: %s", rule.get("id"), exc)
                return None

        missing_patterns: list[str] = list(match.get("banner_missing_regex", []))
        if missing_patterns:
            # Fire when ANY listed security signal is absent (misconfiguration)
            absent = []
            for pattern in missing_patterns:
                try:
                    if not re.search(pattern, banner, flags=re.IGNORECASE | re.MULTILINE):
                        absent.append(pattern)
                except re.error as exc:
                    logger.error("Invalid banner_missing_regex in %s: %s", rule.get("id"), exc)
                    return None
            # Require at least half of the headers missing to reduce noise on tiny banners
            if not banner.startswith("HTTP/"):
                return None
            if len(absent) < max(1, len(missing_patterns) // 2):
                return None
            evidence_extra = f"Missing patterns: {', '.join(absent)}"
        else:
            evidence_extra = ""

        severity = _parse_severity(rule.get("severity", "Info"))
        evidence = banner[:500] if banner else f"service={service} port={port.port}"
        if evidence_extra:
            evidence = f"{evidence}\n{evidence_extra}"

        return self.format_finding(
            finding_id=str(rule.get("id", "SIG-UNKNOWN")),
            title=str(rule.get("title", "Signature match")),
            severity=severity,
            host=host.host,
            description=str(rule.get("description", "")).strip(),
            evidence=evidence,
            remediation=str(rule.get("remediation", "")).strip(),
            port=port.port,
            protocol=port.protocol,
            references=list(rule.get("references", [])),
            metadata={"rule_id": rule.get("id"), "service": service},
        )


class SMBv1StatusPlugin(VulnerabilityPlugin):
    """Detect SMBv1-capable negotiate responses from banner grabber hints."""

    plugin_id = "smb_v1_status"
    name = "SMBv1 Status Check"
    description = "Flags hosts whose SMB negotiate response indicates SMBv1 capability."

    def check_prerequisites(self, host: HostResult) -> bool:
        return any(
            p.state == "open" and p.port in {139, 445} and (p.service or "").lower() == "smb"
            for p in host.open_ports
        )

    def run_check(self, host: HostResult) -> list[Finding]:
        findings: list[Finding] = []
        for port in host.open_ports:
            if port.port not in {139, 445} or port.state != "open":
                continue
            banner = port.banner or ""
            if "SMBv1_capable" in banner or "negotiate_response=SMBv1" in banner:
                findings.append(
                    self.format_finding(
                        finding_id="PLUGIN-SMBV1-ENABLED",
                        title="SMBv1 Negotiate Capability Detected",
                        severity=Severity.HIGH,
                        host=host.host,
                        description=(
                            "The SMB service responded to a legacy SMBv1 negotiate request. "
                            "SMBv1 is deprecated and associated with wormable malware families."
                        ),
                        evidence=banner,
                        remediation=(
                            "Disable SMBv1 on Windows (Disable-WindowsOptionalFeature) or Samba "
                            "(min protocol = SMB2). Enforce SMB signing where practical."
                        ),
                        port=port.port,
                        protocol=port.protocol,
                        references=[
                            "https://learn.microsoft.com/en-us/windows-server/"
                            "storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
                        ],
                        metadata={"check": "smbv1_negotiate"},
                    )
                )
            elif (port.service or "").lower() == "smb":
                findings.append(
                    self.format_finding(
                        finding_id="PLUGIN-SMB-EXPOSED-INFO",
                        title="SMB Service Reachable",
                        severity=Severity.INFO,
                        host=host.host,
                        description="SMB is reachable; SMBv1 capability was not confirmed from the banner.",
                        evidence=banner or "SMB open without SMBv1 marker",
                        remediation="Ensure SMBv1 is disabled and access is network-restricted.",
                        port=port.port,
                        protocol=port.protocol,
                    )
                )
        return findings


class ExposedManagementInterfacePlugin(VulnerabilityPlugin):
    """Detect common admin / management HTTP interfaces on non-standard ports."""

    plugin_id = "exposed_mgmt_interfaces"
    name = "Exposed Management Interfaces"
    description = "Identifies likely administrative UIs on management ports."

    _MGMT_PORTS: Final[set[int]] = {8080, 8443, 9090, 10000, 8834, 9443, 8161, 5601}
    _HINTS: Final[re.Pattern[str]] = re.compile(
        r"(admin|dashboard|manager|phpmyadmin|tomcat|jenkins|nessus|grafana|"
        r"prometheus|kibana|weblogic|cockpit|portainer)",
        re.IGNORECASE,
    )

    def check_prerequisites(self, host: HostResult) -> bool:
        return any(p.state == "open" and p.port in self._MGMT_PORTS for p in host.open_ports)

    def run_check(self, host: HostResult) -> list[Finding]:
        findings: list[Finding] = []
        for port in host.open_ports:
            if port.state != "open" or port.port not in self._MGMT_PORTS:
                continue
            banner = port.banner or ""
            service = (port.service or "").lower()
            hinted = bool(self._HINTS.search(banner))
            severity = Severity.HIGH if hinted else Severity.MEDIUM
            title = (
                "Administrative Interface Indicators on Management Port"
                if hinted
                else "Service Listening on Common Management Port"
            )
            findings.append(
                self.format_finding(
                    finding_id=f"PLUGIN-MGMT-{port.port}",
                    title=title,
                    severity=severity,
                    host=host.host,
                    description=(
                        f"Port {port.port}/tcp is commonly used for management consoles "
                        f"(detected service: {service or 'unknown'})."
                    ),
                    evidence=banner[:500] or f"Open management port {port.port}",
                    remediation=(
                        "Restrict management interfaces to trusted networks or localhost, "
                        "enforce MFA, and avoid exposing admin UIs to untrusted segments."
                    ),
                    port=port.port,
                    protocol=port.protocol,
                    metadata={"hint_matched": hinted},
                )
            )
        return findings


class DefaultHTTPHeadersPlugin(VulnerabilityPlugin):
    """Flag missing security headers and verbose Server/X-Powered-By values."""

    plugin_id = "http_default_headers"
    name = "HTTP Header Hardening Check"
    description = "Evaluates HTTP banners for disclosure and missing security headers."

    _REQUIRED: Final[tuple[str, ...]] = (
        r"(?i)strict-transport-security:",
        r"(?i)x-content-type-options:",
        r"(?i)x-frame-options:",
        r"(?i)content-security-policy:",
    )

    def check_prerequisites(self, host: HostResult) -> bool:
        return any(
            p.state == "open"
            and (p.service or "").lower() in {"http", "https"}
            and (p.banner or "").startswith("HTTP/")
            for p in host.open_ports
        )

    def run_check(self, host: HostResult) -> list[Finding]:
        findings: list[Finding] = []
        for port in host.open_ports:
            banner = port.banner or ""
            service = (port.service or "").lower()
            if port.state != "open" or service not in {"http", "https"} or not banner.startswith("HTTP/"):
                continue

            missing = [
                pattern for pattern in self._REQUIRED if not re.search(pattern, banner)
            ]
            if missing and service == "https":
                findings.append(
                    self.format_finding(
                        finding_id="PLUGIN-HTTP-MISSING-HEADERS",
                        title="Missing HTTP Security Headers",
                        severity=Severity.LOW,
                        host=host.host,
                        description=(
                            "Recommended security headers were not observed in the HTTP response."
                        ),
                        evidence=f"Missing: {', '.join(missing)}\n{banner[:400]}",
                        remediation=(
                            "Add HSTS, X-Content-Type-Options, X-Frame-Options (or CSP "
                            "frame-ancestors), and Content-Security-Policy."
                        ),
                        port=port.port,
                        protocol=port.protocol,
                    )
                )
            elif missing and service == "http":
                # HSTS is not applicable on cleartext HTTP; still flag framing/MIME headers
                cleartext_required = [
                    p
                    for p in missing
                    if "strict-transport-security" not in p
                ]
                if cleartext_required:
                    findings.append(
                        self.format_finding(
                            finding_id="PLUGIN-HTTP-MISSING-HEADERS-CLEARTEXT",
                            title="Missing HTTP Security Headers (Cleartext)",
                            severity=Severity.LOW,
                            host=host.host,
                            description=(
                                "Cleartext HTTP is missing framing/MIME-sniffing protections. "
                                "Prefer redirecting clients to HTTPS."
                            ),
                            evidence=f"Missing: {', '.join(cleartext_required)}\n{banner[:400]}",
                            remediation="Terminate TLS and emit a full secure header set.",
                            port=port.port,
                            protocol=port.protocol,
                        )
                    )

            server_match = re.search(r"(?i)^server:\s*(.+)$", banner, flags=re.MULTILINE)
            powered = re.search(r"(?i)^x-powered-by:\s*(.+)$", banner, flags=re.MULTILINE)
            if server_match or powered:
                evidence_bits = []
                if server_match:
                    evidence_bits.append(f"Server: {server_match.group(1).strip()}")
                if powered:
                    evidence_bits.append(f"X-Powered-By: {powered.group(1).strip()}")
                findings.append(
                    self.format_finding(
                        finding_id="PLUGIN-HTTP-VERSION-DISCLOSURE",
                        title="Web Server Version Disclosure",
                        severity=Severity.MEDIUM,
                        host=host.host,
                        description=(
                            "HTTP headers disclose web server or framework technology details."
                        ),
                        evidence="\n".join(evidence_bits),
                        remediation="Suppress Server and X-Powered-By headers at the edge proxy.",
                        port=port.port,
                        protocol=port.protocol,
                    )
                )
        return findings


class OpenDatabasePortPlugin(VulnerabilityPlugin):
    """Informational/high findings for databases listening on default ports."""

    plugin_id = "open_database_ports"
    name = "Exposed Database Ports"
    description = "Highlights database services reachable from the scan segment."

    _DB_PORTS: Final[dict[int, str]] = {
        1433: "Microsoft SQL Server",
        1521: "Oracle",
        3306: "MySQL/MariaDB",
        5432: "PostgreSQL",
        6379: "Redis",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }

    def check_prerequisites(self, host: HostResult) -> bool:
        return any(p.state == "open" and p.port in self._DB_PORTS for p in host.open_ports)

    def run_check(self, host: HostResult) -> list[Finding]:
        findings: list[Finding] = []
        for port in host.open_ports:
            if port.state != "open" or port.port not in self._DB_PORTS:
                continue
            product = self._DB_PORTS[port.port]
            severity = Severity.CRITICAL if port.port in {6379, 9200, 27017} else Severity.HIGH
            findings.append(
                self.format_finding(
                    finding_id=f"PLUGIN-DB-{port.port}",
                    title=f"Exposed Database Service: {product}",
                    severity=severity,
                    host=host.host,
                    description=(
                        f"{product} appears reachable on tcp/{port.port}. Unauthenticated or "
                        "weakly authenticated data stores are a frequent breach cause."
                    ),
                    evidence=port.banner or f"Open port {port.port}/tcp ({product})",
                    remediation=(
                        "Bind databases to private interfaces, require authentication/TLS, "
                        "and firewall access to application tiers only."
                    ),
                    port=port.port,
                    protocol=port.protocol,
                )
            )
        return findings


class PluginEngine:
    """Load declarative signatures and Python plugins, then execute checks."""

    def __init__(
        self,
        *,
        signature_path: str | Path | None = None,
        plugin_dir: str | Path | None = None,
        extra_plugins: Sequence[VulnerabilityPlugin] | None = None,
    ) -> None:
        self.signature_path = Path(signature_path) if signature_path else None
        self.plugin_dir = Path(plugin_dir) if plugin_dir else None
        self._plugins: list[VulnerabilityPlugin] = []
        self._load_builtin_plugins()
        if self.signature_path:
            self._load_signature_plugin(self.signature_path)
        if self.plugin_dir and self.plugin_dir.is_dir():
            self._load_python_plugins(self.plugin_dir)
        if extra_plugins:
            self._plugins.extend(extra_plugins)

    @property
    def plugins(self) -> list[VulnerabilityPlugin]:
        return list(self._plugins)

    def _load_builtin_plugins(self) -> None:
        self._plugins.extend(
            [
                SMBv1StatusPlugin(),
                ExposedManagementInterfacePlugin(),
                DefaultHTTPHeadersPlugin(),
                OpenDatabasePortPlugin(),
            ]
        )

    def _load_signature_plugin(self, path: Path) -> None:
        if not path.exists():
            logger.warning("Signature file not found: %s", path)
            return
        try:
            raw = path.read_text(encoding="utf-8")
            if path.suffix.lower() in {".yaml", ".yml"}:
                data = yaml.safe_load(raw)
            else:
                data = json.loads(raw)
            rules = list(data.get("rules", [])) if isinstance(data, dict) else []
            self._plugins.append(SignatureRulePlugin(rules))
            logger.info("Loaded %d signature rule(s) from %s", len(rules), path)
        except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
            logger.error("Failed to load signatures from %s: %s", path, exc)

    def _load_python_plugins(self, directory: Path) -> None:
        for file_path in sorted(directory.glob("*.py")):
            if file_path.name.startswith("_"):
                continue
            try:
                module = _import_module_from_path(file_path)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed importing plugin %s: %s", file_path, exc)
                continue
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, VulnerabilityPlugin)
                    and attr is not VulnerabilityPlugin
                    and not getattr(attr, "__abstractmethods__", frozenset())
                ):
                    try:
                        instance = attr()
                        self._plugins.append(instance)
                        logger.info("Loaded Python plugin %s from %s", instance.plugin_id, file_path)
                    except Exception as exc:  # noqa: BLE001
                        logger.error("Could not instantiate %s: %s", attr_name, exc)

    def run(self, hosts: Sequence[HostResult]) -> list[Finding]:
        """Run all loaded plugins against discovered hosts."""
        findings: list[Finding] = []
        for host in hosts:
            if not host.alive:
                continue
            for plugin in self._plugins:
                try:
                    if not plugin.check_prerequisites(host):
                        continue
                    produced = plugin.run_check(host)
                    for finding in produced:
                        findings.append(finding)
                    if produced:
                        logger.info(
                            "%s on %s -> %d finding(s)",
                            plugin.plugin_id,
                            host.host,
                            len(produced),
                        )
                except Exception as exc:  # noqa: BLE001 — never abort the whole run
                    logger.exception(
                        "Plugin %s failed on %s: %s", plugin.plugin_id, host.host, exc
                    )
        # Stable, severity-desc ordering
        findings.sort(key=lambda f: (-f.severity.rank, f.host, f.finding_id))
        return findings


def _import_module_from_path(path: Path) -> Any:
    module_name = f"dynamic_plugin_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _parse_severity(value: str | Severity) -> Severity:
    if isinstance(value, Severity):
        return value
    normalized = str(value).strip().capitalize()
    try:
        return Severity(normalized)
    except ValueError:
        mapping = {s.name: s for s in Severity}
        return mapping.get(str(value).strip().upper(), Severity.INFO)


def load_signatures(path: str | Path) -> list[dict[str, Any]]:
    """Utility for callers that want raw signature dictionaries."""
    file_path = Path(path)
    raw = file_path.read_text(encoding="utf-8")
    if file_path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    if not isinstance(data, dict):
        return []
    rules = data.get("rules", [])
    return list(rules) if isinstance(rules, Iterable) else []

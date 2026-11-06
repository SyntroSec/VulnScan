#!/usr/bin/env python3
"""CLI entry point for the local Vulnerability Scanner engine."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from credentialed_scanner import CredentialError, CredentialedSSHScanner
from models import Finding, HostResult
from plugin_engine import PluginEngine
from reporter import ReportGenerator
from scanner_core import (
    DEFAULT_TCP_PORTS,
    DEFAULT_UDP_PORTS,
    AsyncNetworkScanner,
    configure_logging,
    parse_port_list,
)

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent
DEFAULT_SIGNATURES = ROOT / "plugins" / "signatures.yaml"
DEFAULT_CVE_RULES = ROOT / "rules" / "cve_database.json"
DEFAULT_REPORT_DIR = ROOT / "reports"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description=(
            "Production-ready local vulnerability scanner: async discovery/port scan, "
            "plugin checks, optional SSH credentialed CVE audit, JSON/Markdown reports, "
            "and a FastAPI web dashboard."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-t",
        "--targets",
        nargs="+",
        required=False,
        help="Targets: IPs, hostnames, or CIDR ranges (max 1024 hosts per CIDR).",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=None,
        help="TCP ports to scan, e.g. '22,80,443' or '1-1024'. Default: common ports.",
    )
    parser.add_argument(
        "--udp-ports",
        default=None,
        help="UDP ports to probe, e.g. '53,123,161'. Default: none (use 'default' for built-ins).",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=200,
        help="Max concurrent network operations.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="TCP connect timeout in seconds.",
    )
    parser.add_argument(
        "--banner-timeout",
        type=float,
        default=2.0,
        help="Banner grab timeout in seconds.",
    )
    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        help="Skip aliveness discovery and scan all expanded targets.",
    )
    parser.add_argument(
        "--no-banners",
        action="store_true",
        help="Disable service banner grabbing.",
    )
    parser.add_argument(
        "--no-plugins",
        action="store_true",
        help="Skip plugin / signature vulnerability checks.",
    )
    parser.add_argument(
        "--signatures",
        default=str(DEFAULT_SIGNATURES),
        help="Path to YAML/JSON signature rules.",
    )
    parser.add_argument(
        "--plugin-dir",
        default=str(ROOT / "plugins"),
        help="Directory for extra Python plugin modules.",
    )
    parser.add_argument(
        "--credentialed",
        action="store_true",
        help="Run authenticated SSH compliance audit (credentials from env/.env).",
    )
    parser.add_argument(
        "--ssh-host",
        default=None,
        help="Override SSH_HOST for credentialed audit.",
    )
    parser.add_argument(
        "--prompt-creds",
        action="store_true",
        help="Interactively prompt for missing SSH credentials.",
    )
    parser.add_argument(
        "--cve-rules",
        default=str(DEFAULT_CVE_RULES),
        help="Local CVE/ruleset JSON for credentialed package comparison.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=str(DEFAULT_REPORT_DIR),
        help="Directory for JSON and Markdown reports.",
    )
    parser.add_argument(
        "--basename",
        default=None,
        help="Report filename stem (default: scan_<session_id>).",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch the FastAPI web dashboard (Uvicorn) instead of a CLI scan.",
    )
    parser.add_argument(
        "--web-host",
        default="127.0.0.1",
        help="Bind host for --web mode.",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=8000,
        help="Bind port for --web mode.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity.",
    )
    return parser


def _resolve_tcp_ports(spec: str | None) -> list[int]:
    if spec is None:
        return list(DEFAULT_TCP_PORTS)
    return parse_port_list(spec)


def _resolve_udp_ports(spec: str | None) -> list[int]:
    if spec is None:
        return []
    if spec.strip().lower() == "default":
        return list(DEFAULT_UDP_PORTS)
    return parse_port_list(spec)


async def run_scan(args: argparse.Namespace) -> int:
    started_at = datetime.now(timezone.utc).isoformat()
    session_id = uuid.uuid4().hex[:12]
    errors: list[str] = []

    try:
        tcp_ports = _resolve_tcp_ports(args.ports)
        udp_ports = _resolve_udp_ports(args.udp_ports)
    except ValueError as exc:
        logger.error("Invalid port specification: %s", exc)
        return 2

    scanner = AsyncNetworkScanner(
        concurrency=args.concurrency,
        connect_timeout=args.timeout,
        banner_timeout=args.banner_timeout,
    )

    logger.info("Session %s starting against %s", session_id, ", ".join(args.targets))
    try:
        hosts: list[HostResult] = await scanner.scan_network(
            args.targets,
            tcp_ports=tcp_ports,
            udp_ports=udp_ports,
            grab_banners=not args.no_banners,
            skip_discovery=args.skip_discovery,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Network scan failed: %s", exc)
        errors.append(str(exc))
        hosts = []

    plugin_findings: list[Finding] = []
    if not args.no_plugins and hosts:
        engine = PluginEngine(
            signature_path=args.signatures,
            plugin_dir=args.plugin_dir,
        )
        logger.info("Running %d plugin(s)", len(engine.plugins))
        try:
            plugin_findings = engine.run(hosts)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Plugin engine failed: %s", exc)
            errors.append(f"plugin_engine: {exc}")

    credentialed_findings: list[Finding] = []
    inventory_meta: dict[str, object] = {}
    if args.credentialed:
        try:
            creds = CredentialedSSHScanner.load_credentials_from_env(
                host_override=args.ssh_host,
                prompt_if_missing=args.prompt_creds,
            )
            with CredentialedSSHScanner(creds, cve_rules_path=args.cve_rules) as audit:
                inventory, credentialed_findings = audit.audit()
                inventory_meta = {
                    "credentialed_host": inventory.host,
                    "kernel": inventory.kernel,
                    "package_count": len(inventory.packages),
                    "inventory_errors": inventory.errors,
                }
                logger.info(
                    "Credentialed audit produced %d finding(s)",
                    len(credentialed_findings),
                )
        except CredentialError as exc:
            logger.error("Credentialed scan aborted: %s", exc)
            errors.append(f"credentialed: {exc}")
        except Exception as exc:  # noqa: BLE001
            logger.exception("Credentialed scan failed: %s", exc)
            errors.append(f"credentialed: {exc}")

    reporter = ReportGenerator.from_components(
        session_id=session_id,
        started_at=started_at,
        targets=list(args.targets),
        hosts=hosts,
        plugin_findings=plugin_findings,
        credentialed_findings=credentialed_findings,
        errors=errors,
        metadata={
            "tcp_ports": tcp_ports,
            "udp_ports": udp_ports,
            "concurrency": args.concurrency,
            "plugins_enabled": not args.no_plugins,
            "credentialed": args.credentialed,
            **inventory_meta,
        },
    )
    paths = reporter.write_all(args.output_dir, basename=args.basename)

    summary = reporter.to_json_dict()["summary"]
    print()
    print(f"Session:   {session_id}")
    print(f"Alive:     {summary['hosts_alive']}/{summary['hosts_total']}")
    print(f"Findings:  {summary['findings_total']}")
    for sev, count in summary["by_severity"].items():
        if count:
            print(f"  {sev}: {count}")
    print(f"JSON:      {paths['json']}")
    print(f"Markdown:  {paths['markdown']}")

    if summary["by_severity"].get("Critical", 0) or summary["by_severity"].get("High", 0):
        return 1
    if errors and not hosts:
        return 2
    return 0


def run_web_server(args: argparse.Namespace) -> int:
    from web_server import run_web

    logger.info(
        "Starting VulnScan Console at http://%s:%d",
        args.web_host,
        args.web_port,
    )
    run_web(host=args.web_host, port=args.web_port, log_level=args.log_level)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    configure_logging(args.log_level)

    logger.warning(
        "Authorized-use only: scan systems you own or have explicit permission to test."
    )

    if args.web:
        try:
            return run_web_server(args)
        except KeyboardInterrupt:
            logger.error("Web server interrupted")
            return 130

    if not args.targets:
        parser.error("--targets/-t is required unless --web is set")

    try:
        return asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130


if __name__ == "__main__":
    sys.exit(main())

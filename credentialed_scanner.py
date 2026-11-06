"""Authenticated SSH compliance audit and local CVE ruleset comparison."""

from __future__ import annotations

import getpass
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from models import Finding, Severity

logger = logging.getLogger(__name__)

try:
    import paramiko
except ImportError:  # pragma: no cover - dependency may be installed later
    paramiko = None  # type: ignore[assignment]


@dataclass(slots=True)
class SSHCredentials:
    """SSH authentication material loaded from env / .env / interactive input."""

    host: str
    port: int = 22
    username: str = ""
    password: str | None = None
    private_key_path: str | None = None
    private_key_passphrase: str | None = None
    timeout: float = 15.0


@dataclass(slots=True)
class PackageInfo:
    name: str
    version: str
    manager: str


@dataclass(slots=True)
class SystemInventory:
    host: str
    uname: str = ""
    kernel: str = ""
    os_release: str = ""
    packages: list[PackageInfo] = field(default_factory=list)
    raw_commands: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "uname": self.uname,
            "kernel": self.kernel,
            "os_release": self.os_release,
            "packages": [
                {"name": p.name, "version": p.version, "manager": p.manager}
                for p in self.packages
            ],
            "errors": self.errors,
        }


class CredentialError(RuntimeError):
    """Raised when credentials are missing or authentication fails."""


class CredentialedSSHScanner:
    """Collect host inventory over SSH and compare packages to a local CVE DB."""

    def __init__(
        self,
        credentials: SSHCredentials,
        *,
        cve_rules_path: str | Path | None = None,
    ) -> None:
        if paramiko is None:
            raise RuntimeError(
                "paramiko is required for credentialed scans. "
                "Install dependencies: pip install -r requirements.txt"
            )
        self.credentials = credentials
        self.cve_rules_path = Path(cve_rules_path) if cve_rules_path else None
        self._client: Any | None = None

    # ------------------------------------------------------------------ #
    # Credential helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def load_credentials_from_env(
        *,
        host_override: str | None = None,
        prompt_if_missing: bool = False,
    ) -> SSHCredentials:
        """Read SSH settings from environment variables (optionally via python-dotenv)."""
        try:
            from dotenv import load_dotenv

            load_dotenv(override=False)
        except ImportError:
            logger.debug("python-dotenv not installed; using process environment only")

        host = host_override or os.getenv("SSH_HOST", "").strip()
        port = int(os.getenv("SSH_PORT", "22"))
        username = os.getenv("SSH_USERNAME", "").strip()
        password = os.getenv("SSH_PASSWORD") or None
        key_path = os.getenv("SSH_PRIVATE_KEY_PATH") or None
        passphrase = os.getenv("SSH_PRIVATE_KEY_PASSPHRASE") or None

        if prompt_if_missing:
            if not host:
                host = input("SSH host: ").strip()
            if not username:
                username = input("SSH username: ").strip()
            if not password and not key_path:
                use_key = input("Use private key? [y/N]: ").strip().lower() == "y"
                if use_key:
                    key_path = input("Private key path: ").strip() or None
                    if key_path:
                        entered = getpass.getpass("Key passphrase (empty if none): ")
                        passphrase = entered or None
                else:
                    password = getpass.getpass("SSH password: ")

        if not host or not username:
            raise CredentialError(
                "SSH_HOST and SSH_USERNAME are required (env, .env, or interactive prompt)."
            )
        if not password and not key_path:
            raise CredentialError(
                "Provide SSH_PASSWORD or SSH_PRIVATE_KEY_PATH for authentication."
            )

        return SSHCredentials(
            host=host,
            port=port,
            username=username,
            password=password,
            private_key_path=key_path,
            private_key_passphrase=passphrase,
        )

    # ------------------------------------------------------------------ #
    # Connection / command execution
    # ------------------------------------------------------------------ #

    def connect(self) -> None:
        assert paramiko is not None
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs: dict[str, Any] = {
            "hostname": self.credentials.host,
            "port": self.credentials.port,
            "username": self.credentials.username,
            "timeout": self.credentials.timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }

        if self.credentials.private_key_path:
            key = self._load_private_key(
                self.credentials.private_key_path,
                self.credentials.private_key_passphrase,
            )
            connect_kwargs["pkey"] = key
        else:
            connect_kwargs["password"] = self.credentials.password

        try:
            logger.info(
                "Connecting via SSH to %s@%s:%d",
                self.credentials.username,
                self.credentials.host,
                self.credentials.port,
            )
            client.connect(**connect_kwargs)
            self._client = client
        except Exception as exc:  # noqa: BLE001
            client.close()
            raise CredentialError(f"SSH authentication/connection failed: {exc}") from exc

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None

    def __enter__(self) -> CredentialedSSHScanner:
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @staticmethod
    def _load_private_key(path: str, passphrase: str | None) -> Any:
        assert paramiko is not None
        key_path = Path(path).expanduser()
        if not key_path.exists():
            raise CredentialError(f"Private key not found: {key_path}")
        loaders = (
            paramiko.Ed25519Key,
            paramiko.RSAKey,
            paramiko.ECDSAKey,
        )
        last_error: Exception | None = None
        for loader in loaders:
            try:
                return loader.from_private_key_file(
                    str(key_path),
                    password=passphrase,
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
        # DSSKey may not exist on newer paramiko — attempt dynamically
        dss = getattr(paramiko, "DSSKey", None)
        if dss is not None:
            try:
                return dss.from_private_key_file(str(key_path), password=passphrase)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
        raise CredentialError(f"Unable to load private key {key_path}: {last_error}")

    def run_command(self, command: str, *, timeout: float = 30.0) -> tuple[str, str, int]:
        if self._client is None:
            raise RuntimeError("SSH client is not connected")
        try:
            _stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            code = stdout.channel.recv_exit_status()
            return out, err, code
        except Exception as exc:  # noqa: BLE001
            logger.error("Command failed (%s): %s", command, exc)
            return "", str(exc), 1

    # ------------------------------------------------------------------ #
    # Inventory collection
    # ------------------------------------------------------------------ #

    def collect_inventory(self) -> SystemInventory:
        inventory = SystemInventory(host=self.credentials.host)

        uname_out, uname_err, uname_code = self.run_command("uname -a")
        inventory.raw_commands["uname"] = uname_out.strip()
        if uname_code == 0:
            inventory.uname = uname_out.strip()
            inventory.kernel = _extract_kernel(uname_out)
        else:
            inventory.errors.append(f"uname failed: {uname_err.strip() or uname_out}")

        os_out, os_err, os_code = self.run_command(
            "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || true"
        )
        inventory.raw_commands["os_release"] = os_out.strip()
        if os_code == 0 and os_out.strip():
            inventory.os_release = os_out.strip()
        elif os_err.strip():
            inventory.errors.append(f"os-release: {os_err.strip()}")

        packages = self._collect_packages()
        inventory.packages = packages
        logger.info(
            "Collected inventory from %s: kernel=%s packages=%d",
            inventory.host,
            inventory.kernel or "unknown",
            len(packages),
        )
        return inventory

    def _collect_packages(self) -> list[PackageInfo]:
        # Prefer dpkg, fall back to rpm
        dpkg_out, _dpkg_err, dpkg_code = self.run_command(
            "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null"
        )
        if dpkg_code == 0 and dpkg_out.strip():
            return _parse_dpkg(dpkg_out)

        rpm_out, _rpm_err, rpm_code = self.run_command(
            "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null"
        )
        if rpm_code == 0 and rpm_out.strip():
            return _parse_rpm(rpm_out)

        logger.warning("No dpkg/rpm package listing available on %s", self.credentials.host)
        return []

    # ------------------------------------------------------------------ #
    # CVE / ruleset comparison
    # ------------------------------------------------------------------ #

    def load_cve_rules(self, path: str | Path | None = None) -> list[dict[str, Any]]:
        rules_path = Path(path) if path else self.cve_rules_path
        if rules_path is None:
            raise FileNotFoundError("No CVE rules path configured")
        if not rules_path.exists():
            raise FileNotFoundError(f"CVE rules file not found: {rules_path}")
        data = json.loads(rules_path.read_text(encoding="utf-8"))
        rules = data.get("rules", []) if isinstance(data, dict) else []
        if not isinstance(rules, list):
            raise ValueError("CVE rules must be a list under the 'rules' key")
        logger.info("Loaded %d CVE rule(s) from %s", len(rules), rules_path)
        return rules

    def compare_packages(
        self,
        inventory: SystemInventory,
        rules: list[dict[str, Any]] | None = None,
    ) -> list[Finding]:
        rule_list = rules if rules is not None else self.load_cve_rules()
        package_index = _build_package_index(inventory.packages)
        findings: list[Finding] = []

        for rule in rule_list:
            matches = _matching_packages(package_index, rule)
            for pkg in matches:
                baseline = str(rule.get("vulnerable_below", "")).strip()
                if not baseline:
                    continue
                if not version_is_vulnerable(pkg.version, baseline):
                    continue
                severity = _parse_severity(rule.get("severity", "Medium"))
                findings.append(
                    Finding(
                        finding_id=str(rule.get("id", "CVE-LOCAL-UNKNOWN")),
                        title=str(rule.get("title", "Vulnerable package")),
                        severity=severity,
                        host=inventory.host,
                        description=str(rule.get("description", "")).strip(),
                        evidence=(
                            f"package={pkg.name} installed={pkg.version} "
                            f"manager={pkg.manager} vulnerable_below={baseline}"
                        ),
                        remediation=str(rule.get("remediation", "")).strip(),
                        plugin_id="credentialed_cve_audit",
                        cve_ids=list(rule.get("cve_ids", [])),
                        references=list(rule.get("references", [])),
                        metadata={
                            "package": pkg.name,
                            "installed_version": pkg.version,
                            "vulnerable_below": baseline,
                            "kernel": inventory.kernel,
                        },
                    )
                )

        # Kernel string check against kernel rules (even if package name differs)
        kernel_rules = [
            r for r in rule_list if "kernel" in str(r.get("id", "")).lower()
            or any("kernel" in n for n in r.get("package_names", []))
        ]
        if inventory.kernel:
            for rule in kernel_rules:
                baseline = str(rule.get("vulnerable_below", "")).strip()
                if baseline and version_is_vulnerable(inventory.kernel, baseline):
                    # Avoid duplicate if already reported via package match
                    already = any(
                        f.finding_id == rule.get("id") and "kernel=" in f.evidence
                        for f in findings
                    )
                    if already:
                        continue
                    if any(f.finding_id == rule.get("id") for f in findings):
                        continue
                    findings.append(
                        Finding(
                            finding_id=str(rule.get("id", "CVE-LOCAL-KERNEL")),
                            title=str(rule.get("title", "Kernel below baseline")),
                            severity=_parse_severity(rule.get("severity", "High")),
                            host=inventory.host,
                            description=str(rule.get("description", "")).strip(),
                            evidence=f"kernel={inventory.kernel} vulnerable_below={baseline}",
                            remediation=str(rule.get("remediation", "")).strip(),
                            plugin_id="credentialed_cve_audit",
                            cve_ids=list(rule.get("cve_ids", [])),
                            references=list(rule.get("references", [])),
                            metadata={"kernel": inventory.kernel},
                        )
                    )

        findings.sort(key=lambda f: (-f.severity.rank, f.finding_id))
        return findings

    def audit(self) -> tuple[SystemInventory, list[Finding]]:
        """Connect (if needed), collect inventory, and return CVE findings."""
        owned_connection = self._client is None
        try:
            if owned_connection:
                self.connect()
            inventory = self.collect_inventory()
            try:
                findings = self.compare_packages(inventory)
            except FileNotFoundError as exc:
                inventory.errors.append(str(exc))
                findings = []
            return inventory, findings
        finally:
            if owned_connection:
                self.close()


# ---------------------------------------------------------------------- #
# Parsing / version helpers
# ---------------------------------------------------------------------- #


def _extract_kernel(uname_a: str) -> str:
    parts = uname_a.split()
    # Linux <hostname> <kernel> ...
    if len(parts) >= 3:
        return parts[2]
    return uname_a.strip()


def _parse_dpkg(output: str) -> list[PackageInfo]:
    packages: list[PackageInfo] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        packages.append(PackageInfo(name=name.strip(), version=version.strip(), manager="dpkg"))
    return packages


def _parse_rpm(output: str) -> list[PackageInfo]:
    packages: list[PackageInfo] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        packages.append(PackageInfo(name=name.strip(), version=version.strip(), manager="rpm"))
    return packages


def _build_package_index(packages: list[PackageInfo]) -> dict[str, list[PackageInfo]]:
    index: dict[str, list[PackageInfo]] = {}
    for pkg in packages:
        index.setdefault(pkg.name.lower(), []).append(pkg)
    return index


def _matching_packages(
    index: dict[str, list[PackageInfo]],
    rule: dict[str, Any],
) -> list[PackageInfo]:
    names = [str(n).lower() for n in rule.get("package_names", [])]
    prefix = bool(rule.get("package_name_prefix", False))
    matched: list[PackageInfo] = []
    if not names:
        return matched
    if prefix:
        for pkg_name, pkgs in index.items():
            if any(pkg_name.startswith(n) for n in names):
                matched.extend(pkgs)
    else:
        for name in names:
            matched.extend(index.get(name, []))
    return matched


def _normalize_version(version: str) -> tuple[int | str, ...]:
    """Split versions into comparable tuples (numeric parts preferred)."""
    cleaned = version.strip()
    # Drop Debian epoch
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[1]
    # Drop common trailing revision markers for coarse compare
    cleaned = cleaned.replace("~", "-")
    parts = re.split(r"[^0-9A-Za-z]+", cleaned)
    tokens: list[int | str] = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            tokens.append(int(part))
        else:
            # Extract leading digits from tokens like 9p1 / 6p1
            match = re.match(r"(\d+)(.*)", part)
            if match:
                tokens.append(int(match.group(1)))
                if match.group(2):
                    tokens.append(match.group(2))
            else:
                tokens.append(part.lower())
    return tuple(tokens)


def version_is_vulnerable(installed: str, vulnerable_below: str) -> bool:
    """Return True when installed version is strictly older than the baseline."""
    left = _normalize_version(installed)
    right = _normalize_version(vulnerable_below)
    # Compare element-wise with type-safe fallbacks
    for a, b in zip(left, right):
        if type(a) is type(b):
            if a < b:
                return True
            if a > b:
                return False
            continue
        # Mixed types: compare string forms
        if str(a) < str(b):
            return True
        if str(a) > str(b):
            return False
    return len(left) < len(right)


def _parse_severity(value: str | Severity) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).strip().capitalize())
    except ValueError:
        return Severity.INFO

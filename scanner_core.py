"""Asynchronous network discovery, port scanning, and banner grabbing."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import time
from collections.abc import Sequence
from typing import Final

from models import HostResult, PortResult

logger = logging.getLogger(__name__)

DEFAULT_TCP_PORTS: Final[tuple[int, ...]] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    8834,
    9090,
    9200,
    27017,
)

DEFAULT_UDP_PORTS: Final[tuple[int, ...]] = (53, 123, 161, 500, 1900)

WELL_KNOWN_SERVICES: Final[dict[int, str]] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
    8834: "nessus",
    9090: "http",
    9200: "elasticsearch",
    27017: "mongodb",
}


class AsyncNetworkScanner:
    """Async host discovery and TCP/UDP port scanner with banner grabbing."""

    def __init__(
        self,
        *,
        concurrency: int = 200,
        connect_timeout: float = 1.5,
        banner_timeout: float = 2.0,
        discovery_ports: Sequence[int] | None = None,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        self.concurrency = concurrency
        self.connect_timeout = connect_timeout
        self.banner_timeout = banner_timeout
        self.discovery_ports: tuple[int, ...] = tuple(
            discovery_ports or (80, 443, 22, 445, 3389, 135)
        )
        self._semaphore = asyncio.Semaphore(concurrency)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def discover_hosts(self, targets: Sequence[str]) -> list[HostResult]:
        """Expand CIDR/hostname targets and probe for aliveness."""
        hosts = self.expand_targets(targets)
        logger.info("Discovering %d host(s) with concurrency=%d", len(hosts), self.concurrency)
        tasks = [self._probe_host_alive(host) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        discovered: list[HostResult] = []
        for host, result in zip(hosts, results, strict=True):
            if isinstance(result, Exception):
                logger.warning("Discovery error for %s: %s", host, result)
                discovered.append(
                    HostResult(host=host, alive=False, errors=[str(result)])
                )
            else:
                discovered.append(result)
        alive = sum(1 for h in discovered if h.alive)
        logger.info("Discovery complete: %d/%d alive", alive, len(discovered))
        return discovered

    async def scan_host(
        self,
        host: str,
        *,
        tcp_ports: Sequence[int] | None = None,
        udp_ports: Sequence[int] | None = None,
        grab_banners: bool = True,
    ) -> HostResult:
        """Scan TCP/UDP ports on a single host and optionally grab banners."""
        tcp_list = list(tcp_ports or DEFAULT_TCP_PORTS)
        udp_list = list(udp_ports or ())
        result = HostResult(host=host, alive=True)
        result.hostname = await self._resolve_hostname(host)

        logger.info(
            "Scanning %s (tcp=%d udp=%d banners=%s)",
            host,
            len(tcp_list),
            len(udp_list),
            grab_banners,
        )

        tcp_tasks = [self._scan_tcp_port(host, port) for port in tcp_list]
        udp_tasks = [self._scan_udp_port(host, port) for port in udp_list]
        port_results = await asyncio.gather(
            *(tcp_tasks + udp_tasks), return_exceptions=True
        )

        open_ports: list[PortResult] = []
        for item in port_results:
            if isinstance(item, Exception):
                result.errors.append(str(item))
                continue
            if item is not None and item.state == "open":
                open_ports.append(item)

        if grab_banners and open_ports:
            banner_tasks = [
                self._enrich_with_banner(host, port_result)
                for port_result in open_ports
                if port_result.protocol == "tcp"
            ]
            enriched = await asyncio.gather(*banner_tasks, return_exceptions=True)
            finalized: list[PortResult] = []
            udp_only = [p for p in open_ports if p.protocol == "udp"]
            finalized.extend(udp_only)
            for item in enriched:
                if isinstance(item, Exception):
                    result.errors.append(str(item))
                elif item is not None:
                    finalized.append(item)
            open_ports = finalized

        open_ports.sort(key=lambda p: (p.protocol, p.port))
        result.open_ports = open_ports
        logger.info(
            "Host %s: %d open port(s)", host, len(result.open_ports)
        )
        return result

    async def scan_network(
        self,
        targets: Sequence[str],
        *,
        tcp_ports: Sequence[int] | None = None,
        udp_ports: Sequence[int] | None = None,
        grab_banners: bool = True,
        skip_discovery: bool = False,
    ) -> list[HostResult]:
        """Discover live hosts (optional) then scan ports on each alive host."""
        if skip_discovery:
            hosts = [
                HostResult(host=h, alive=True, hostname=await self._resolve_hostname(h))
                for h in self.expand_targets(targets)
            ]
        else:
            hosts = await self.discover_hosts(targets)

        alive_hosts = [h for h in hosts if h.alive]
        if not alive_hosts:
            logger.warning("No live hosts found")
            return hosts

        scanned: list[HostResult] = []
        for host_result in alive_hosts:
            try:
                detailed = await self.scan_host(
                    host_result.host,
                    tcp_ports=tcp_ports,
                    udp_ports=udp_ports,
                    grab_banners=grab_banners,
                )
                # Preserve discovery hostname if scan did not resolve one
                if not detailed.hostname:
                    detailed.hostname = host_result.hostname
                scanned.append(detailed)
            except Exception as exc:  # noqa: BLE001 — isolate per-host failures
                logger.exception("Scan failed for %s", host_result.host)
                host_result.errors.append(str(exc))
                scanned.append(host_result)

        # Include dead hosts for completeness
        dead = [h for h in hosts if not h.alive]
        return scanned + dead

    @staticmethod
    def expand_targets(targets: Sequence[str]) -> list[str]:
        """Expand hostnames, IPs, and CIDR ranges into individual host strings."""
        expanded: list[str] = []
        seen: set[str] = set()
        for raw in targets:
            token = raw.strip()
            if not token:
                continue
            try:
                network = ipaddress.ip_network(token, strict=False)
                # Cap very large ranges to avoid accidental /8 scans
                if network.num_addresses > 1024:
                    raise ValueError(
                        f"CIDR {token} expands to {network.num_addresses} hosts "
                        "(max 1024). Narrow the range."
                    )
                for ip in network.hosts() if network.num_addresses > 1 else [network.network_address]:
                    value = str(ip)
                    if value not in seen:
                        seen.add(value)
                        expanded.append(value)
                continue
            except ValueError as exc:
                # Not a network — treat as single host unless it was an oversized CIDR
                if "max 1024" in str(exc):
                    raise
            if token not in seen:
                seen.add(token)
                expanded.append(token)
        return expanded

    # ------------------------------------------------------------------ #
    # Discovery / port probes
    # ------------------------------------------------------------------ #

    async def _probe_host_alive(self, host: str) -> HostResult:
        """Mark a host alive if any discovery port accepts a TCP connection."""
        hostname = await self._resolve_hostname(host)
        for port in self.discovery_ports:
            open_port = await self._scan_tcp_port(host, port)
            if open_port is not None and open_port.state == "open":
                return HostResult(host=host, alive=True, hostname=hostname)
        # Fallback: attempt a short TCP connect to an ephemeral high port — if
        # we get RST quickly the host is typically alive; timeout = unknown/down.
        try:
            async with self._semaphore:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, 65535),
                    timeout=min(self.connect_timeout, 0.8),
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
                return HostResult(host=host, alive=True, hostname=hostname)
        except (TimeoutError, OSError, asyncio.CancelledError):
            return HostResult(host=host, alive=False, hostname=hostname)

    async def _scan_tcp_port(self, host: str, port: int) -> PortResult | None:
        async with self._semaphore:
            started = time.perf_counter()
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.connect_timeout,
                )
                latency = (time.perf_counter() - started) * 1000.0
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
                service = WELL_KNOWN_SERVICES.get(port)
                return PortResult(
                    port=port,
                    protocol="tcp",
                    state="open",
                    service=service,
                    latency_ms=round(latency, 2),
                )
            except TimeoutError:
                return PortResult(port=port, protocol="tcp", state="filtered")
            except ConnectionRefusedError:
                return PortResult(port=port, protocol="tcp", state="closed")
            except OSError as exc:
                logger.debug("TCP %s:%d OSError: %s", host, port, exc)
                return PortResult(port=port, protocol="tcp", state="error")
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.debug("TCP %s:%d unexpected: %s", host, port, exc)
                return PortResult(port=port, protocol="tcp", state="error")

    async def _scan_udp_port(self, host: str, port: int) -> PortResult | None:
        """Best-effort UDP probe. Open|filtered when no ICMP unreachable is seen."""
        async with self._semaphore:
            loop = asyncio.get_running_loop()
            sock: socket.socket | None = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                payload = self._udp_probe_payload(port)
                await loop.sock_sendto(sock, payload, (host, port))
                try:
                    data, _addr = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 2048),
                        timeout=self.connect_timeout,
                    )
                    service = WELL_KNOWN_SERVICES.get(port, "unknown")
                    banner = data[:128].decode("latin-1", errors="replace")
                    return PortResult(
                        port=port,
                        protocol="udp",
                        state="open",
                        service=service,
                        banner=banner or None,
                    )
                except TimeoutError:
                    # No response — commonly open|filtered for UDP
                    return PortResult(
                        port=port,
                        protocol="udp",
                        state="open|filtered",
                        service=WELL_KNOWN_SERVICES.get(port),
                    )
            except OSError as exc:
                logger.debug("UDP %s:%d OSError: %s", host, port, exc)
                return PortResult(port=port, protocol="udp", state="error")
            finally:
                if sock is not None:
                    sock.close()

    @staticmethod
    def _udp_probe_payload(port: int) -> bytes:
        if port == 53:
            # Minimal DNS A query for example.com
            return bytes.fromhex(
                "123401000001000000000000076578616d706c6503636f6d0000010001"
            )
        if port == 123:
            # NTP client mode request
            return b"\x1b" + (b"\x00" * 47)
        if port == 161:
            # SNMPv1 get-request for sysDescr (public)
            return bytes.fromhex(
                "302902010004067075626c6963a01c02044a1b2c3d020100020100300e300c"
                "06082b060102010101000500"
            )
        return b"\x00"

    # ------------------------------------------------------------------ #
    # Banner grabbing / service identification
    # ------------------------------------------------------------------ #

    async def _enrich_with_banner(self, host: str, port_result: PortResult) -> PortResult:
        banner, service = await self.grab_banner(host, port_result.port)
        if banner:
            port_result.banner = banner
        if service:
            port_result.service = service
        elif port_result.service is None:
            port_result.service = WELL_KNOWN_SERVICES.get(port_result.port, "unknown")
        return port_result

    async def grab_banner(self, host: str, port: int) -> tuple[str | None, str | None]:
        """Grab a service banner and classify common protocols."""
        classifiers = (
            self._banner_ssh,
            self._banner_ftp,
            self._banner_http,
            self._banner_smb,
            self._banner_rdp,
            self._banner_generic,
        )
        for classifier in classifiers:
            try:
                banner, service = await classifier(host, port)
                if banner or service:
                    return banner, service
            except TimeoutError:
                continue
            except OSError as exc:
                logger.debug("Banner %s:%d (%s) OSError: %s", host, port, classifier.__name__, exc)
                continue
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "Banner %s:%d (%s) failed: %s",
                    host,
                    port,
                    classifier.__name__,
                    exc,
                )
                continue
        return None, WELL_KNOWN_SERVICES.get(port)

    async def _open_stream(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        async with self._semaphore:
            return await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.connect_timeout,
            )

    async def _read_some(
        self,
        reader: asyncio.StreamReader,
        *,
        limit: int = 1024,
        timeout: float | None = None,
    ) -> bytes:
        return await asyncio.wait_for(
            reader.read(limit),
            timeout=timeout or self.banner_timeout,
        )

    async def _banner_ssh(self, host: str, port: int) -> tuple[str | None, str | None]:
        if port not in {22, 2222} and WELL_KNOWN_SERVICES.get(port) != "ssh":
            # Still try if caller asked — cheap probe
            pass
        reader, writer = await self._open_stream(host, port)
        try:
            data = await self._read_some(reader)
            text = data.decode("latin-1", errors="replace").strip()
            if text.upper().startswith("SSH-"):
                return text.splitlines()[0][:300], "ssh"
            return None, None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _banner_ftp(self, host: str, port: int) -> tuple[str | None, str | None]:
        if port not in {21, 2121}:
            return None, None
        reader, writer = await self._open_stream(host, port)
        try:
            data = await self._read_some(reader)
            text = data.decode("latin-1", errors="replace").strip()
            if re.match(r"^220\b", text):
                return text.splitlines()[0][:300], "ftp"
            return None, None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _banner_http(self, host: str, port: int) -> tuple[str | None, str | None]:
        http_ports = {80, 8080, 8000, 8888, 9090, 10000, 8834}
        https_hint = port in {443, 8443, 9443}
        if port not in http_ports and not https_hint and WELL_KNOWN_SERVICES.get(port) not in {
            "http",
            "https",
            "nessus",
        }:
            return None, None

        # Plain HTTP probe (also works for many TLS-offload / cleartext admin ports).
        # For TLS ports we still attempt cleartext first; failures fall through.
        reader, writer = await self._open_stream(host, port)
        try:
            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: NessusLocalScanner/1.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            writer.write(request)
            await writer.drain()
            data = await self._read_some(reader, limit=2048)
            text = data.decode("latin-1", errors="replace")
            if text.startswith("HTTP/"):
                # Keep status line + interesting headers
                lines = text.split("\r\n")
                keep: list[str] = []
                for line in lines[:30]:
                    lower = line.lower()
                    if (
                        line.startswith("HTTP/")
                        or lower.startswith("server:")
                        or lower.startswith("x-powered-by:")
                        or lower.startswith("www-authenticate:")
                        or lower.startswith("strict-transport-security:")
                        or lower.startswith("x-frame-options:")
                        or lower.startswith("x-content-type-options:")
                        or lower.startswith("content-security-policy:")
                        or lower.startswith("location:")
                    ):
                        keep.append(line)
                banner = "\n".join(keep)[:800]
                service = "https" if https_hint else "http"
                return banner, service
            return None, None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _banner_smb(self, host: str, port: int) -> tuple[str | None, str | None]:
        if port not in {445, 139}:
            return None, None
        reader, writer = await self._open_stream(host, port)
        try:
            # Minimal SMB1 Negotiate Protocol Request (detect presence / dialect hints)
            smb_negotiate = bytes.fromhex(
                "00000054"  # NetBIOS length
                "ff534d4272"  # SMB header: SMB + Negotiate
                "00000000001800480000000000000000000000000000"
                "fffffffe00000000000b00024e54204c4d20302e313200"
                "02534d4220322e3030320002534d4220322e3f3f3f00"
            )
            writer.write(smb_negotiate)
            await writer.drain()
            data = await self._read_some(reader, limit=512)
            if not data:
                return None, None
            text = data.decode("latin-1", errors="replace")
            if b"SMB" in data or b"\xffSMB" in data or b"\xfeSMB" in data:
                dialect = "SMBv2+" if b"\xfeSMB" in data else "SMB"
                # Attempt to extract Samba / Windows hints from payload
                hint_match = re.search(r"(Samba[^\x00]{0,40}|Windows[^\x00]{0,40})", text)
                detail = hint_match.group(1) if hint_match else dialect
                # SMBv1 negotiate response often still begins with \xffSMB
                if data[4:8] == b"\xffSMB":
                    detail = f"{detail}; negotiate_response=SMBv1_capable"
                return f"SMB service detected ({detail})", "smb"
            return None, None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _banner_rdp(self, host: str, port: int) -> tuple[str | None, str | None]:
        if port != 3389:
            return None, None
        reader, writer = await self._open_stream(host, port)
        try:
            # X.224 Connection Request (RDP connection initiation)
            packet = bytes.fromhex(
                "030000130ee00000000000010008000b000000"
            )
            writer.write(packet)
            await writer.drain()
            data = await self._read_some(reader, limit=256)
            if data.startswith(b"\x03\x00"):
                return "RDP X.224 connection confirm received", "rdp"
            return None, None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _banner_generic(self, host: str, port: int) -> tuple[str | None, str | None]:
        reader, writer = await self._open_stream(host, port)
        try:
            # Read unsolicited banner first (SMTP, FTP, SSH, Telnet, Redis, etc.)
            try:
                data = await self._read_some(reader, limit=512, timeout=min(1.0, self.banner_timeout))
            except TimeoutError:
                # Nudge with CRLF for line-oriented services
                writer.write(b"\r\n")
                await writer.drain()
                data = await self._read_some(reader, limit=512)

            if not data:
                return None, WELL_KNOWN_SERVICES.get(port)

            text = data.decode("latin-1", errors="replace").strip()
            first = text.splitlines()[0][:300] if text else None
            service = self._classify_banner_text(first or "", port)
            return first, service
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _classify_banner_text(banner: str, port: int) -> str:
        upper = banner.upper()
        if upper.startswith("SSH-"):
            return "ssh"
        if re.match(r"^220\b", banner):
            return "ftp" if port in {21, 2121} else "smtp"
        if banner.startswith("HTTP/"):
            return "https" if port in {443, 8443} else "http"
        if "TELNET" in upper or banner.lower().startswith("login:"):
            return "telnet"
        if banner.startswith("+OK"):
            return "pop3"
        if banner.startswith("* OK"):
            return "imap"
        if banner.startswith("-ERR") or "REDIS" in upper:
            return "redis"
        return WELL_KNOWN_SERVICES.get(port, "unknown")

    @staticmethod
    async def _resolve_hostname(host: str) -> str | None:
        try:
            ipaddress.ip_address(host)
            loop = asyncio.get_running_loop()
            try:
                hostname, _aliases, _ips = await asyncio.wait_for(
                    loop.getnameinfo((host, 0), 0),
                    timeout=1.0,
                )
                # getnameinfo may echo the IP back when no PTR exists
                if hostname and hostname != host:
                    return hostname
                return None
            except Exception:  # noqa: BLE001
                return None
        except ValueError:
            # Already a hostname
            return host


def parse_port_list(spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or mixed '22,80,8000-8010' into unique sorted ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Invalid port range: {token}")
            ports.update(range(start, end + 1))
        else:
            value = int(token)
            if value < 1 or value > 65535:
                raise ValueError(f"Invalid port: {value}")
            ports.add(value)
    return sorted(ports)


def configure_logging(level: str = "INFO") -> None:
    """Configure structured console logging for the scanner engine."""
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )

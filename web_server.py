"""FastAPI web dashboard and REST/SSE API for the vulnerability scanner."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator

from models import Finding, HostResult, Severity
from plugin_engine import PluginEngine
from reporter import ReportGenerator
from scanner_core import (
    DEFAULT_TCP_PORTS,
    DEFAULT_UDP_PORTS,
    AsyncNetworkScanner,
    parse_port_list,
)

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent
REPORT_DIR = ROOT / "reports"
SIGNATURES_PATH = ROOT / "plugins" / "signatures.yaml"
PLUGIN_DIR = ROOT / "plugins"
TEMPLATES_DIR = ROOT / "templates"
STATIC_DIR = ROOT / "static"

ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]


class ScanStartRequest(BaseModel):
    """Payload for launching a new background scan."""

    targets: list[str] = Field(..., min_length=1)
    ports: str | None = Field(
        default=None,
        description="TCP port list/ranges, e.g. '22,80,443' or '1-1024'.",
    )
    udp_ports: str | None = Field(
        default=None,
        description="UDP ports, 'default' for built-ins, or explicit list.",
    )
    concurrency: int = Field(default=200, ge=1, le=2000)
    timeout: float = Field(default=1.5, gt=0.1, le=30.0)
    banner_timeout: float = Field(default=2.0, gt=0.1, le=30.0)
    skip_discovery: bool = False
    grab_banners: bool = True
    run_plugins: bool = True

    @field_validator("targets")
    @classmethod
    def _clean_targets(cls, value: list[str]) -> list[str]:
        cleaned = [t.strip() for t in value if t and t.strip()]
        if not cleaned:
            raise ValueError("At least one target is required")
        return cleaned


class ScanManager:
    """In-memory registry of active and completed scans with SSE fan-out."""

    def __init__(self, report_dir: Path = REPORT_DIR) -> None:
        self.report_dir = report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self._scans: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._subscribers: dict[str, list[asyncio.Queue[dict[str, Any]]]] = {}
        self._load_persisted_reports()

    def _load_persisted_reports(self) -> None:
        for path in sorted(self.report_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Skipping bad report %s: %s", path, exc)
                continue
            session_id = str(data.get("session_id") or path.stem)
            if session_id in self._scans:
                continue
            summary = data.get("summary") or {}
            self._scans[session_id] = {
                "scan_id": session_id,
                "status": "completed",
                "progress": 100,
                "phase": "completed",
                "message": "Loaded from disk",
                "targets": list(data.get("targets") or []),
                "started_at": data.get("started_at"),
                "finished_at": data.get("finished_at"),
                "hosts": data.get("hosts") or [],
                "findings": data.get("findings") or [],
                "errors": data.get("errors") or [],
                "metadata": data.get("metadata") or {},
                "summary": summary,
                "report_path": str(path),
                "source": "disk",
            }

    async def list_scans(self) -> list[dict[str, Any]]:
        async with self._lock:
            items = [self._public_summary(s) for s in self._scans.values()]
        items.sort(key=lambda s: s.get("started_at") or "", reverse=True)
        return items

    async def get_scan(self, scan_id: str) -> dict[str, Any]:
        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                raise KeyError(scan_id)
            return self._public_detail(scan)

    async def start_scan(self, request: ScanStartRequest) -> dict[str, Any]:
        scan_id = uuid.uuid4().hex[:12]
        started_at = datetime.now(timezone.utc).isoformat()
        record: dict[str, Any] = {
            "scan_id": scan_id,
            "status": "queued",
            "progress": 0,
            "phase": "queued",
            "message": "Scan queued",
            "targets": list(request.targets),
            "started_at": started_at,
            "finished_at": None,
            "hosts": [],
            "findings": [],
            "errors": [],
            "metadata": {
                "ports": request.ports,
                "udp_ports": request.udp_ports,
                "concurrency": request.concurrency,
                "timeout": request.timeout,
                "grab_banners": request.grab_banners,
                "run_plugins": request.run_plugins,
                "skip_discovery": request.skip_discovery,
            },
            "summary": {
                "hosts_alive": 0,
                "hosts_total": 0,
                "open_ports": 0,
                "findings_total": 0,
                "by_severity": {s.value: 0 for s in Severity},
            },
            "report_path": None,
            "source": "live",
            "host_status": [],
            "_task": None,
        }
        async with self._lock:
            self._scans[scan_id] = record
            self._subscribers.setdefault(scan_id, [])

        task = asyncio.create_task(self._run_scan(scan_id, request), name=f"scan-{scan_id}")
        record["_task"] = task
        await self._emit(
            scan_id,
            {
                "event": "queued",
                "scan_id": scan_id,
                "status": "queued",
                "progress": 0,
                "phase": "queued",
                "message": "Scan queued",
            },
        )
        return self._public_summary(record)

    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        async with self._lock:
            if scan_id not in self._scans:
                raise KeyError(scan_id)
            queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
            self._subscribers.setdefault(scan_id, []).append(queue)
            snapshot = self._progress_payload(self._scans[scan_id])

        yield snapshot
        try:
            while True:
                event = await queue.get()
                yield event
                if event.get("status") in {"completed", "failed", "cancelled"}:
                    break
        finally:
            async with self._lock:
                subs = self._subscribers.get(scan_id, [])
                if queue in subs:
                    subs.remove(queue)

    async def _emit(self, scan_id: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                return
            for key in ("status", "progress", "phase", "message"):
                if key in payload:
                    scan[key] = payload[key]
            if "host_status" in payload:
                scan["host_status"] = payload["host_status"]
            if "summary" in payload:
                scan["summary"] = payload["summary"]
            subscribers = list(self._subscribers.get(scan_id, []))
            event = self._progress_payload(scan)
            event.update({k: v for k, v in payload.items() if k.startswith("event") or k == "event"})

        for queue in subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    _ = queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    pass

    async def _update(self, scan_id: str, **fields: Any) -> None:
        payload = dict(fields)
        if "event" not in payload:
            payload["event"] = "progress"
        await self._emit(scan_id, payload)

    async def _run_scan(self, scan_id: str, request: ScanStartRequest) -> None:
        errors: list[str] = []
        hosts: list[HostResult] = []
        findings: list[Finding] = []

        try:
            await self._update(
                scan_id,
                event="started",
                status="running",
                progress=2,
                phase="starting",
                message="Initializing scanner",
            )

            try:
                tcp_ports = (
                    list(DEFAULT_TCP_PORTS)
                    if request.ports is None
                    else parse_port_list(request.ports)
                )
                if request.udp_ports is None:
                    udp_ports: list[int] = []
                elif request.udp_ports.strip().lower() == "default":
                    udp_ports = list(DEFAULT_UDP_PORTS)
                else:
                    udp_ports = parse_port_list(request.udp_ports)
            except ValueError as exc:
                raise RuntimeError(f"Invalid port specification: {exc}") from exc

            scanner = AsyncNetworkScanner(
                concurrency=request.concurrency,
                connect_timeout=request.timeout,
                banner_timeout=request.banner_timeout,
            )

            await self._update(
                scan_id,
                progress=8,
                phase="discovery",
                message="Discovering live hosts",
            )

            if request.skip_discovery:
                expanded = scanner.expand_targets(request.targets)
                discovered = [
                    HostResult(host=h, alive=True, hostname=await scanner._resolve_hostname(h))
                    for h in expanded
                ]
            else:
                discovered = await scanner.discover_hosts(request.targets)

            host_status = [
                {
                    "host": h.host,
                    "alive": h.alive,
                    "state": "alive" if h.alive else "down",
                    "open_ports": 0,
                    "hostname": h.hostname,
                }
                for h in discovered
            ]
            await self._update(
                scan_id,
                progress=20,
                phase="discovery",
                message=f"Discovery complete: {sum(1 for h in discovered if h.alive)}/{len(discovered)} alive",
                host_status=host_status,
                summary={
                    "hosts_alive": sum(1 for h in discovered if h.alive),
                    "hosts_total": len(discovered),
                    "open_ports": 0,
                    "findings_total": 0,
                    "by_severity": {s.value: 0 for s in Severity},
                },
            )

            alive_hosts = [h for h in discovered if h.alive]
            dead_hosts = [h for h in discovered if not h.alive]
            scanned: list[HostResult] = []

            if not alive_hosts:
                hosts = discovered
                await self._update(
                    scan_id,
                    progress=70,
                    phase="scanning",
                    message="No live hosts found",
                    host_status=host_status,
                )
            else:
                for index, host_result in enumerate(alive_hosts):
                    pct = 20 + int((index / max(len(alive_hosts), 1)) * 50)
                    await self._update(
                        scan_id,
                        progress=pct,
                        phase="scanning",
                        message=f"Scanning {host_result.host} ({index + 1}/{len(alive_hosts)})",
                        host_status=host_status,
                    )
                    try:
                        detailed = await scanner.scan_host(
                            host_result.host,
                            tcp_ports=tcp_ports,
                            udp_ports=udp_ports,
                            grab_banners=request.grab_banners,
                        )
                        if not detailed.hostname:
                            detailed.hostname = host_result.hostname
                        scanned.append(detailed)
                        for entry in host_status:
                            if entry["host"] == detailed.host:
                                entry["state"] = "scanned"
                                entry["alive"] = True
                                entry["open_ports"] = len(
                                    [p for p in detailed.open_ports if p.state == "open"]
                                )
                                entry["hostname"] = detailed.hostname
                                break
                    except Exception as exc:  # noqa: BLE001
                        logger.exception("Host scan failed for %s", host_result.host)
                        host_result.errors.append(str(exc))
                        errors.append(f"{host_result.host}: {exc}")
                        scanned.append(host_result)
                        for entry in host_status:
                            if entry["host"] == host_result.host:
                                entry["state"] = "error"
                                break

                hosts = scanned + dead_hosts

            open_ports = sum(
                len([p for p in h.open_ports if p.state == "open"]) for h in hosts
            )
            await self._update(
                scan_id,
                progress=75,
                phase="plugins",
                message="Running vulnerability plugins",
                host_status=host_status,
                summary={
                    "hosts_alive": sum(1 for h in hosts if h.alive),
                    "hosts_total": len(hosts),
                    "open_ports": open_ports,
                    "findings_total": 0,
                    "by_severity": {s.value: 0 for s in Severity},
                },
            )

            if request.run_plugins and hosts:
                engine = PluginEngine(
                    signature_path=SIGNATURES_PATH,
                    plugin_dir=PLUGIN_DIR,
                )
                try:
                    # Offload sync plugin execution so the event loop stays responsive
                    findings = await asyncio.to_thread(engine.run, hosts)
                except Exception as exc:  # noqa: BLE001
                    logger.exception("Plugin engine failed")
                    errors.append(f"plugin_engine: {exc}")

            by_severity = {s.value: 0 for s in Severity}
            for finding in findings:
                by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1

            await self._update(
                scan_id,
                progress=90,
                phase="reporting",
                message="Writing reports",
                summary={
                    "hosts_alive": sum(1 for h in hosts if h.alive),
                    "hosts_total": len(hosts),
                    "open_ports": open_ports,
                    "findings_total": len(findings),
                    "by_severity": by_severity,
                },
            )

            reporter = ReportGenerator.from_components(
                session_id=scan_id,
                started_at=str(self._scans[scan_id]["started_at"]),
                targets=list(request.targets),
                hosts=hosts,
                plugin_findings=findings,
                errors=errors,
                metadata={
                    "tcp_ports": tcp_ports,
                    "udp_ports": udp_ports,
                    "concurrency": request.concurrency,
                    "source": "web_dashboard",
                    "grab_banners": request.grab_banners,
                    "run_plugins": request.run_plugins,
                },
            )
            paths = await asyncio.to_thread(
                reporter.write_all,
                self.report_dir,
                basename=f"scan_{scan_id}",
            )
            payload = reporter.to_json_dict()
            finished_at = payload.get("finished_at") or datetime.now(timezone.utc).isoformat()

            async with self._lock:
                scan = self._scans[scan_id]
                scan["status"] = "completed"
                scan["progress"] = 100
                scan["phase"] = "completed"
                scan["message"] = "Scan completed"
                scan["finished_at"] = finished_at
                scan["hosts"] = payload.get("hosts") or []
                scan["findings"] = payload.get("findings") or []
                scan["errors"] = payload.get("errors") or []
                scan["summary"] = payload.get("summary") or {}
                scan["metadata"] = payload.get("metadata") or {}
                scan["report_path"] = str(paths["json"])
                scan["host_status"] = host_status

            await self._emit(
                scan_id,
                {
                    "event": "completed",
                    "status": "completed",
                    "progress": 100,
                    "phase": "completed",
                    "message": f"Completed with {len(findings)} finding(s)",
                    "summary": payload.get("summary"),
                    "host_status": host_status,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Background scan %s failed", scan_id)
            finished_at = datetime.now(timezone.utc).isoformat()
            async with self._lock:
                scan = self._scans.get(scan_id)
                if scan is not None:
                    scan["status"] = "failed"
                    scan["progress"] = 100
                    scan["phase"] = "failed"
                    scan["message"] = str(exc)
                    scan["finished_at"] = finished_at
                    scan["errors"] = list(scan.get("errors") or []) + [str(exc)]
            await self._emit(
                scan_id,
                {
                    "event": "failed",
                    "status": "failed",
                    "progress": 100,
                    "phase": "failed",
                    "message": str(exc),
                },
            )

    @staticmethod
    def _severity_bucket(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        buckets: dict[str, list[dict[str, Any]]] = {
            s.value: [] for s in Severity
        }
        for finding in findings:
            sev = finding.get("severity", Severity.INFO.value)
            buckets.setdefault(sev, []).append(finding)
        return buckets

    def _public_summary(self, scan: dict[str, Any]) -> dict[str, Any]:
        return {
            "scan_id": scan["scan_id"],
            "status": scan["status"],
            "progress": scan.get("progress", 0),
            "phase": scan.get("phase"),
            "message": scan.get("message"),
            "targets": scan.get("targets") or [],
            "started_at": scan.get("started_at"),
            "finished_at": scan.get("finished_at"),
            "summary": scan.get("summary") or {},
            "errors": scan.get("errors") or [],
            "source": scan.get("source"),
            "report_path": scan.get("report_path"),
        }

    def _public_detail(self, scan: dict[str, Any]) -> dict[str, Any]:
        findings = list(scan.get("findings") or [])
        detail = self._public_summary(scan)
        detail.update(
            {
                "hosts": scan.get("hosts") or [],
                "findings": findings,
                "findings_by_severity": self._severity_bucket(findings),
                "host_status": scan.get("host_status") or [],
                "metadata": scan.get("metadata") or {},
            }
        )
        return detail

    def _progress_payload(self, scan: dict[str, Any]) -> dict[str, Any]:
        return {
            "event": "progress",
            "scan_id": scan["scan_id"],
            "status": scan["status"],
            "progress": scan.get("progress", 0),
            "phase": scan.get("phase"),
            "message": scan.get("message"),
            "summary": scan.get("summary") or {},
            "host_status": scan.get("host_status") or [],
            "errors": scan.get("errors") or [],
        }


def create_app() -> FastAPI:
    """Application factory used by uvicorn and `main.py --web`."""
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        title="VulnScan Console",
        description="Local vulnerability scanner web dashboard",
        version="1.0.0",
    )
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    manager = ScanManager()
    app.state.manager = manager

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "index.html",
            {"app_name": "VulnScan Console"},
        )

    @app.get("/api/scans")
    async def list_scans() -> dict[str, Any]:
        scans = await manager.list_scans()
        return {"count": len(scans), "scans": scans}

    @app.post("/api/scan/start", status_code=202)
    async def start_scan(body: ScanStartRequest) -> dict[str, Any]:
        try:
            # Validate target expansion early for clearer API errors
            AsyncNetworkScanner.expand_targets(body.targets)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        scan = await manager.start_scan(body)
        return {"ok": True, "scan": scan}

    @app.get("/api/scan/{scan_id}")
    async def get_scan(scan_id: str) -> dict[str, Any]:
        try:
            return await manager.get_scan(scan_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}") from exc

    @app.get("/api/plugins")
    async def list_plugins() -> dict[str, Any]:
        engine = PluginEngine(
            signature_path=SIGNATURES_PATH,
            plugin_dir=PLUGIN_DIR,
        )
        plugins: list[dict[str, Any]] = []
        for plugin in engine.plugins:
            entry: dict[str, Any] = {
                "plugin_id": plugin.plugin_id,
                "name": plugin.name,
                "description": plugin.description,
                "type": type(plugin).__name__,
            }
            rules = getattr(plugin, "rules", None)
            if isinstance(rules, list):
                entry["signature_count"] = len(rules)
                entry["signatures"] = [
                    {
                        "id": r.get("id"),
                        "title": r.get("title"),
                        "severity": r.get("severity"),
                    }
                    for r in rules
                    if isinstance(r, dict)
                ]
            plugins.append(entry)
        return {"count": len(plugins), "plugins": plugins}

    @app.get("/api/scan/{scan_id}/events")
    async def scan_events(scan_id: str) -> StreamingResponse:
        try:
            await manager.get_scan(scan_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}") from exc

        async def event_generator() -> AsyncIterator[str]:
            try:
                async for payload in manager.subscribe(scan_id):
                    data = json.dumps(payload, ensure_ascii=False)
                    yield f"event: {payload.get('event', 'progress')}\ndata: {data}\n\n"
            except asyncio.CancelledError:
                return

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/health")
    async def health(verbose: bool = Query(default=False)) -> dict[str, Any]:
        payload: dict[str, Any] = {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}
        if verbose:
            scans = await manager.list_scans()
            payload["scans"] = len(scans)
        return payload

    return app


app = create_app()


def run_web(host: str = "127.0.0.1", port: int = 8000, log_level: str = "info") -> None:
    """Block and serve the dashboard with uvicorn."""
    import uvicorn

    uvicorn.run(
        "web_server:app",
        host=host,
        port=port,
        log_level=log_level.lower(),
        reload=False,
    )

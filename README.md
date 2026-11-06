# VulnScan (Local Vulnerability Assessment Scanner)

VulnScan is a modern, modular, Python-based vulnerability assessment scanner designed as a lightweight local alternative for authorized network and host security checks. It combines an asynchronous scanning engine with YAML/Python signature plugins, optional SSH credentialed audits, structured reporting, and a real-time FastAPI web dashboard.

> **Authorized use only.** Scan systems you own or have explicit written permission to assess.

## Features

- **Asynchronous port scanning** — asyncio-based host discovery, TCP/UDP probing, and service banner grabbing with configurable concurrency
- **YAML/Python signature plugins** — declarative banner rules plus extensible `VulnerabilityPlugin` checks for common misconfigurations
- **Local credentialed audit** — Paramiko SSH inventory collection (`dpkg`/`rpm`) compared against a local CVE ruleset
- **Real-time Web GUI** — dark-mode FastAPI dashboard with SSE live progress, severity charts, and expandable findings
- **CLI + reports** — argparse entry point with JSON and Markdown executive summaries (Critical / High / Medium / Low / Info)

## Requirements

- Python 3.11+
- Dependencies listed in `requirements.txt`

## Installation

```bash
pip install -r requirements.txt
```

Optional: copy `.env.example` to `.env` and fill in `SSH_*` values if you plan to run credentialed audits.

## Usage

### CLI mode

```bash
python main.py -t <target_ip>
```

Examples:

```bash
# Common TCP ports against a single host
python main.py -t 192.168.1.10

# CIDR range with custom ports
python main.py -t 192.168.1.0/24 -p 22,80,443,445,3389

# Include default UDP probes and write reports to a folder
python main.py -t 10.0.0.5 --udp-ports default -o reports

# Credentialed SSH package/CVE audit (credentials from .env)
python main.py -t 10.0.0.5 --credentialed
```

Reports are written under `reports/` as both `.json` and `.md`.

### Web UI mode

```bash
python main.py --web
```

Then open **http://127.0.0.1:8000**

Optional bind settings:

```bash
python main.py --web --web-host 127.0.0.1 --web-port 8000
```

From the dashboard you can launch scans, watch live SSE progress, browse history, inspect severity charts, and expand finding details (CVE, description, evidence).

## Project Structure

```text
nessus/
├── main.py                  # CLI entry point (+ --web launcher)
├── web_server.py            # FastAPI REST API, SSE, dashboard backend
├── scanner_core.py          # Async discovery, port scan, banner grabber
├── plugin_engine.py         # Plugin loader + vulnerability checks
├── credentialed_scanner.py  # SSH inventory + local CVE comparison
├── reporter.py              # JSON / Markdown report generation
├── models.py                # Shared typed data models
├── requirements.txt         # Python dependencies
├── .env.example             # Sample environment variables
├── LICENSE                  # MIT License
├── README.md                # This file
├── plugins/
│   ├── signatures.yaml      # Declarative banner / misconfig rules
│   └── example_cleartext_proto.py
├── rules/
│   └── cve_database.json    # Local package CVE baselines
├── templates/
│   └── index.html           # Web dashboard template
├── static/
│   ├── app.js               # Dashboard frontend logic + Chart.js
│   └── app.css              # Dark-mode styles
└── reports/                 # Generated scan outputs
```

## API Overview (Web Mode)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/scans` | List past and active scans |
| `POST` | `/api/scan/start` | Start a background scan |
| `GET` | `/api/scan/{scan_id}` | Fetch scan detail and findings |
| `GET` | `/api/scan/{scan_id}/events` | SSE live progress stream |
| `GET` | `/api/plugins` | List loaded YAML/Python plugins |

Interactive OpenAPI docs are available at `/docs` when the web server is running.

## Extending Plugins

1. Add declarative rules to `plugins/signatures.yaml`, or
2. Drop a Python module into `plugins/` that subclasses `VulnerabilityPlugin` and implements `check_prerequisites()`, `run_check()`, and uses `format_finding()`.

## License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 Umid Guluzada

# ReconX

> **Intelligent Recon Automation Platform**

ReconX is a modular reconnaissance automation platform built to orchestrate security discovery workflows through a queue-based worker architecture.

The current version focuses on a reliable backend foundation for automated reconnaissance, including target management, asynchronous scan jobs, HTTP discovery, DNS resolution, TCP port discovery, persistent results, and API-based result retrieval.

---

## 🚀 Architecture

```text
                         ┌──────────────────────┐
                         │       FastAPI        │
                         │      REST API        │
                         └──────────┬───────────┘
                                    │
                                    │ Create Scan
                                    ▼
                         ┌──────────────────────┐
                         │        SQLite        │
                         │   Targets / Scans    │
                         └──────────┬───────────┘
                                    │
                                    │ Queue Scan ID
                                    ▼
                         ┌──────────────────────┐
                         │        Valkey        │
                         │    recon_jobs Queue  │
                         └──────────┬───────────┘
                                    │
                                   BLPOP
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │        Worker        │
                         │      scanner.py      │
                         └──────────┬───────────┘
                                    │
               ┌────────────────────┼────────────────────┐
               │                    │                    │
               ▼                    ▼                    ▼
       ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
       │  HTTP Probe  │     │  DNS Probe   │     │  Port Probe  │
       └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   ▼
                         ┌──────────────────────┐
                         │    Result Service    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    scan_results      │
                         │       SQLite         │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         GET /scans/{id}/results



✨ Current Features
🎯 Target Management

Create, retrieve, and delete reconnaissance targets.

POST   /targets/
GET    /targets/
GET    /targets/{target_id}
DELETE /targets/{target_id}
⚙️ Scan Management

Create asynchronous scan jobs and retrieve scan information.

POST /scans/
GET  /scans/
GET  /scans/{scan_id}
GET  /scans/{scan_id}/results
🧵 Queue-Based Processing

Scan requests are pushed into a Valkey queue instead of being processed directly inside the API request.

FastAPI
   ↓
SQLite
   ↓
Valkey
   ↓
Worker

This keeps API request handling separate from reconnaissance execution and provides a foundation for future worker scaling.

🌐 HTTP Discovery

The HTTP probe collects:

HTTP status code
Content-Type
Server header
Final URL
🔎 DNS Discovery

The DNS probe resolves hostnames and stores discovered IP addresses.

🔌 TCP Port Discovery

The port probe checks a controlled set of TCP ports and records open ports.

💾 Persistent Results

Every discovered value is associated with the scan that produced it.

Target
  ↓
Scan
  ↓
Scan Result
🏗️ Project Structure
reconX/
│
├── backend/
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── targets.py
│   │   └── scans.py
│   │
│   ├── recon/
│   │   ├── __init__.py
│   │   ├── http_probe.py
│   │   ├── dns_probe.py
│   │   └── port_probe.py
│   │
│   ├── workers/
│   │   ├── __init__.py
│   │   └── scanner.py
│   │
│   ├── database.py
│   ├── main.py
│   ├── models.py
│   ├── queue.py
│   └── result_service.py
│
├── .gitignore
└── README.md
🛠️ Tech Stack
Component	Technology
Language	Python
API	FastAPI
ORM	SQLAlchemy
Database	SQLite
Queue	Valkey
Worker	Python
API Docs	Swagger / OpenAPI
Version Control	Git + GitHub
🔄 Scan Lifecycle

A scan follows this lifecycle:

queued
  ↓
running
  ↓
completed

If an execution error occurs:

queued
  ↓
running
  ↓
failed
🔥 Example Workflow
1. Create a target
POST /targets/
{
  "domain": "127.0.0.1:9000"
}
2. Create a scan
POST /scans/
{
  "target_id": 2
}

The API places the scan ID into Valkey:

recon_jobs
└── 10
3. Worker processes the scan
[WORKER] Scan 10 started
[WORKER] Target: 127.0.0.1:9000
[WORKER] Scan 10 completed
4. Retrieve results
GET /scans/10/results

Example:

[
  {
    "scan_id": 10,
    "result_type": "http_status",
    "value": "200"
  },
  {
    "scan_id": 10,
    "result_type": "content_type",
    "value": "text/html; charset=utf-8"
  },
  {
    "scan_id": 10,
    "result_type": "server",
    "value": "SimpleHTTP/0.6 Python/3.13.13"
  },
  {
    "scan_id": 10,
    "result_type": "final_url",
    "value": "http://127.0.0.1:9000"
  },
  {
    "scan_id": 10,
    "result_type": "dns",
    "value": "127.0.0.1"
  },
  {
    "scan_id": 10,
    "result_type": "open_port",
    "value": "9000"
  }
]
🧪 Local Development
Clone the repository
git clone https://github.com/satarup-mondal/reconX.git
cd reconX
Create virtual environment
python -m venv .venv
source .venv/bin/activate
Install dependencies
pip install fastapi uvicorn sqlalchemy redis
Start Valkey

Make sure Valkey is installed and running.

Verify:

valkey-cli ping

Expected:

PONG
Start the API
python -m uvicorn backend.main:app --reload

API:

http://127.0.0.1:8000

Swagger:

http://127.0.0.1:8000/docs
Start the worker

In another terminal:

source .venv/bin/activate


python -c "from backend.workers.scanner import run_worker; run_worker()"

Expected:

[WORKER] Waiting for jobs...
🧩 Design Principles
Modularity

Recon capabilities are separated into independent modules so new discovery functionality can be added without rewriting the entire worker.

Asynchronous Execution

Recon jobs are processed outside the API request path.

Persistence

Results remain queryable after a scan completes.

Scalability

The Valkey + worker architecture provides a foundation for running multiple workers later.

Security

Recon capabilities are intended for authorized security testing and controlled lab environments.

🗺️ Roadmap
Phase 1 — Backend Foundation
 FastAPI application
 Target management
 Scan management
 SQLite persistence
 Valkey queue
 Dedicated worker
 Result persistence
 Results API
Phase 2 — Recon Engine
 HTTP discovery
 DNS discovery
 TCP port discovery
 Technology fingerprinting
 Service identification
 Subdomain discovery
 Asset correlation
 Modular scan profiles
Phase 3 — Platform
 Authentication
 Authorization
 Structured result schemas
 Retry handling
 Failure recovery
 Worker concurrency
 Job prioritization
 Structured logging
 API pagination
Phase 4 — Web Interface
 Web dashboard
 Target management UI
 Scan launch interface
 Live scan status
 Result explorer
 Asset visualization
 Scan history
 Interactive recon graphs
Phase 5 — Production
 PostgreSQL
 Docker
 Docker Compose
 CI/CD
 Metrics
 Monitoring
 Horizontal worker scaling
 Kubernetes deployment
🔐 Security & Legal

ReconX is intended for:

Authorized penetration testing
Security research
Internal security assessments
CTFs and lab environments
Systems you own or have explicit permission to test

Do not use the platform against systems without authorization.

📊 Current Status

🚧 Active Development

Current milestone:

API
 ↓
SQLite
 ↓
Valkey
 ↓
Worker
 ↓
HTTP + DNS + Port Discovery
 ↓
Persistent Results
 ↓
Results API

The current version focuses on the backend reconnaissance engine.

A dedicated dashboard and richer visualization layer will be added in a later phase.

👨‍💻 Author

Satarup Mondal

GitHub:
https://github.com/satarup-mondal


# ReconX

### Intelligent Recon Automation Platform

ReconX is a modular reconnaissance platform built around an asynchronous job pipeline.

It takes a target, creates a scan job, pushes it into a queue, processes it through dedicated workers, runs reconnaissance modules, and stores structured results for later analysis.

> **Current focus:** building a reliable backend reconnaissance engine.  
> **UI / dashboard:** planned for the next phase.

---

<p align="center">

![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-ORM-D71F00?style=for-the-badge)
![Valkey](https://img.shields.io/badge/Valkey-Job%20Queue-DC382D?style=for-the-badge)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active%20Development-F59E0B?style=for-the-badge)

</p>

---

## Why ReconX?

Most reconnaissance tooling is built as a collection of commands.

ReconX is being designed as a **platform**.

The goal is to create a system where reconnaissance modules can be executed through a common pipeline, queued as jobs, processed asynchronously, and stored as structured data.

```text
                Target
                  │
                  ▼
             Create Scan
                  │
                  ▼
              FastAPI
                  │
                  ▼
             Valkey Queue
                  │
                  ▼
               Worker
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
      HTTP       DNS       Ports
        │         │         │
        └─────────┼─────────┘
                  ▼
            Result Service
                  │
                  ▼
             scan_results
                  │
                  ▼
             Results API

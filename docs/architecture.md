# SAP Shield Architecture

## Overview

SAP Shield is a modular insider threat detection platform for SAP systems. It follows a pipeline architecture where data flows through four stages: extraction, normalization, detection, and presentation.

## Data Flow

```
SAP System / Simulator
        │
        ▼
  ┌─────────────┐
  │  Connector   │   Extracts raw activity data
  │  (RFC/OData/ │   from SAP or generates simulated data
  │   File/Sim)  │
  └──────┬───────┘
         │
         ▼
  ┌─────────────┐
  │  Pipeline    │   Normalizes events into SAPEvent model,
  │  (Ingest +   │   enriches with context (sensitivity, time
  │   Enrich)    │   flags), and stores in database
  └──────┬───────┘
         │
         ▼
  ┌─────────────┐
  │  Detection   │   Three parallel engines:
  │  Engine      │   1. ML anomaly scoring vs baselines
  │              │   2. Transaction sequence analysis
  │              │   3. YAML-configurable rule engine
  └──────┬───────┘
         │
         ▼
  ┌─────────────┐
  │  API +       │   FastAPI REST endpoints
  │  Dashboard   │   Single-page dashboard UI
  └─────────────┘
```

## Component Details

### Connectors

All connectors implement `BaseConnector` and produce `SAPEvent` objects:

- **RFC Connector**: Uses PyRFC to connect via SAP RFC protocol. Reads security audit log (SM20) and change documents. Requires SAP NW RFC SDK.
- **OData Connector**: Connects to S/4HANA or BTP via OData APIs. Uses `httpx` for async HTTP.
- **File Connector**: Ingests CSV exports from SAP. Supports flexible column mapping and multiple timestamp formats.
- **Simulator**: Generates realistic activity data with configurable user profiles and injectable threat scenarios. No SAP system required.

### Pipeline

- **Ingestion**: Polls the connector on a configurable interval, normalizes events, and pushes them through enrichment to storage.
- **Enrichment**: Adds derived context — transaction sensitivity classification, business hours flags, table sensitivity, and volume indicators.
- **Storage**: SQLAlchemy-based async backend supporting SQLite (default) and PostgreSQL. Stores events, alerts, and user baselines.

### Detection Engine

Three parallel detection strategies, combined by the orchestrator:

1. **Behavioral Baselining + Anomaly Scoring**: Builds per-user statistical profiles (transaction patterns, time patterns, volume norms, known IPs). New events are scored across multiple dimensions (volume, temporal, transaction, network, sensitivity) with configurable weights.

2. **Sequence Analysis**: Maintains a sliding window of recent transactions per user. Matches against known attack patterns (privilege escalation sequences, data exfiltration patterns, etc.).

3. **Rule Engine**: YAML-driven rules with conditions and scoring multipliers. Easy to add new detection rules without code changes.

### Alert Lifecycle

```
Event → Detection → Score > Threshold? → Alert Created (status: open)
                                              │
                                              ▼
                                    Dashboard / API
                                              │
                                    ┌─────────┼─────────┐
                                    ▼         ▼         ▼
                              Investigating  Resolved  False Positive
```

## Technology Stack

- **Language**: Python 3.10+
- **API**: FastAPI + Uvicorn
- **ML**: NumPy, SciPy, scikit-learn
- **Database**: SQLAlchemy (async) + SQLite/PostgreSQL
- **SAP**: PyRFC (optional), httpx for OData
- **Deployment**: Docker, Docker Compose
- **CI**: GitHub Actions

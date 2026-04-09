# 🛡️ SAP Shield

**Open-source insider threat detection for SAP — built for organizations that can't afford enterprise SIEM tools.**

SAP Shield monitors user activity in SAP systems and uses AI/ML to detect behavioral anomalies that may indicate insider threats: data exfiltration, privilege abuse, unauthorized access, and more.

---

## Why SAP Shield?

Most insider threat detection platforms cost six figures and require dedicated security teams. SAP Shield brings the same capabilities to small and medium businesses:

- **Zero cost** — fully open-source under Apache 2.0
- **No SAP system required to try it** — built-in data simulator lets you explore in minutes
- **Lightweight** — runs on a single machine with Docker
- **AI-powered** — ML-based behavioral baselining with low false-positive rates
- **Real-time** — continuous monitoring with instant alerting

---

## Quick Start (< 5 minutes)

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/sap-shield.git
cd sap-shield

# Start everything with Docker
docker compose up --build

# Open the dashboard
# http://localhost:3000
```

That's it. The simulator generates realistic SAP activity data with injected threats, so you can see SAP Shield in action immediately.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   SAP Shield                        │
├──────────┬──────────┬──────────┬────────────────────┤
│Connectors│ Pipeline │Detection │    Dashboard       │
│          │          │ Engine   │                    │
│ • RFC    │ • Ingest │ • ML     │ • Alert viewer     │
│ • OData  │ • Normal │   models │ • User profiles    │
│ • File   │ • Enrich │ • Rule   │ • Risk scores      │
│ • Sim    │ • Store  │   engine │ • Trend charts     │
└────┬─────┴────┬─────┴────┬─────┴────────┬───────────┘
     │          │          │              │
     ▼          ▼          ▼              ▼
  SAP System  SQLite/   Alert Queue   REST API
              Postgres
```

### Components

| Component | Description |
|-----------|-------------|
| **Connectors** | Extract audit logs, change documents, and user activity from SAP (or simulated data) |
| **Pipeline** | Normalize, enrich, and store activity events |
| **Detection Engine** | ML-based anomaly detection + configurable rule engine |
| **REST API** | Query alerts, user risk scores, and system status |
| **Dashboard** | Web UI for investigating threats and monitoring activity |
| **Simulator** | Generate realistic SAP activity data with injected threat scenarios |

---

## Detection Scenarios (v0.1)

| Scenario | Description | Method |
|----------|-------------|--------|
| 🔴 Mass Data Export | User downloads abnormal volumes of sensitive data | Statistical outlier detection |
| 🟠 Privilege Escalation | Unusual authorization changes or role assignments | Rule-based + sequence analysis |
| 🟡 Off-Hours Access | Critical transactions executed outside business hours | Time-window anomaly detection |
| 🔴 Ghost Account Activity | Dormant or service accounts suddenly becoming active | Baseline deviation scoring |
| 🟠 Transaction Hopping | User accesses unusual combination of transactions | Graph-based behavior modeling |

---

## Project Structure

```
sap-shield/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── setup.py
├── config/
│   ├── default.yaml          # Default configuration
│   └── detection_rules.yaml  # Configurable detection rules
├── connectors/
│   ├── __init__.py
│   ├── base.py               # Base connector interface
│   ├── rfc_connector.py      # SAP RFC connector (PyRFC)
│   ├── odata_connector.py    # SAP OData API connector
│   └── file_connector.py     # File-based log ingestion
├── simulator/
│   ├── __init__.py
│   ├── generator.py          # Activity data generator
│   ├── profiles.py           # User behavior profiles
│   └── threat_scenarios.py   # Injected threat patterns
├── pipeline/
│   ├── __init__.py
│   ├── ingestion.py          # Event ingestion and normalization
│   ├── enrichment.py         # Context enrichment (user, role, data sensitivity)
│   └── storage.py            # Storage backend (SQLite / PostgreSQL)
├── detection/
│   ├── __init__.py
│   ├── engine.py             # Main detection orchestrator
│   ├── models/
│   │   ├── __init__.py
│   │   ├── baseline.py       # User behavior baselining
│   │   ├── anomaly.py        # Anomaly scoring models
│   │   └── sequence.py       # Transaction sequence analysis
│   └── rules/
│       ├── __init__.py
│       └── rule_engine.py    # Configurable rule-based detection
├── api/
│   ├── __init__.py
│   ├── app.py                # FastAPI application
│   └── routes.py             # API endpoints
├── dashboard/
│   └── index.html            # Single-page dashboard
├── tests/
│   ├── ...
├── docs/
│   ├── architecture.md
│   ├── sap-configuration.md
│   ├── detection-logic.md
│   └── deployment.md
├── scripts/
│   └── seed_data.py          # Generate sample data
└── .github/
    └── workflows/
        └── ci.yml            # GitHub Actions CI
```

---

## Configuration

SAP Shield is configured via `config/default.yaml`:

```yaml
# SAP Connection (not needed for simulator mode)
sap:
  connector: simulator   # Options: rfc, odata, file, simulator
  # rfc_config:
  #   ashost: sap-server.company.com
  #   sysnr: "00"
  #   client: "100"

# Detection tuning
detection:
  sensitivity: medium     # low, medium, high
  baseline_days: 30       # Days of history for behavioral baseline
  alert_threshold: 0.75   # Risk score threshold (0.0 - 1.0)

# Storage
storage:
  backend: sqlite         # Options: sqlite, postgresql
  sqlite_path: ./data/sapshield.db
```

---

## Production Deployment

When you're ready to connect to a real SAP system:

1. Install SAP NW RFC SDK and PyRFC (see [docs/sap-configuration.md](docs/sap-configuration.md))
2. Update `config/default.yaml` with your SAP connection details
3. Switch storage to PostgreSQL for scale
4. Deploy with Docker or Kubernetes

---

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| **v0.1** | Core detection engine, simulator, basic dashboard | 🟢 Current |
| **v0.2** | Enhanced ML models, more SAP connectors, SIEM export | 🔵 Planned |
| **v0.3** | Real-time streaming pipeline, Kafka integration | 🔵 Planned |
| **v0.4** | Multi-tenant SaaS deployment option | 🔵 Planned |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

## Disclaimer

SAP Shield is a security monitoring tool. It should be deployed in compliance with your organization's privacy policies and applicable labor/data protection laws. Always inform employees about monitoring in accordance with local regulations.

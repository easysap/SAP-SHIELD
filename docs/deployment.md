# Deployment Guide

## Quick Start (Demo Mode)

No SAP system or database required:

```bash
git clone https://github.com/YOUR_USERNAME/sap-shield.git
cd sap-shield
docker compose up --build
```

Open http://localhost:3000 to see the dashboard.

## Local Development

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m api.app
```

## Production Deployment

### 1. Switch to PostgreSQL

```yaml
storage:
  backend: postgresql
  postgresql:
    host: your-db-host
    port: 5432
    database: sapshield
    user: sapshield
    password: "${DB_PASSWORD}"
```

### 2. Configure SAP Connection

See [sap-configuration.md](sap-configuration.md) for details on connecting to your SAP system.

### 3. Environment Variables

```bash
export SAP_PASSWORD=your_sap_password
export DB_PASSWORD=your_db_password
export LOG_LEVEL=INFO
```

### 4. Docker Production

```bash
docker compose -f docker-compose.yml up -d
```

### 5. Kubernetes (Optional)

A Helm chart is planned for v0.2. For now, you can deploy the Docker image with standard Kubernetes manifests for the API service and a PostgreSQL StatefulSet.

## Monitoring SAP Shield Itself

- Health endpoint: `GET /api/health`
- Stats endpoint: `GET /api/stats`
- Logs: stdout (structured via loguru)

## Data Retention

Configure in `config/default.yaml`:

```yaml
storage:
  retention:
    events_days: 90
    alerts_days: 365
    baselines_days: 180
```

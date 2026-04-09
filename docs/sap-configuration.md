# SAP System Configuration Guide

This guide explains how to connect SAP Shield to a real SAP system.

## Prerequisites

- SAP system (ECC 6.0+ or S/4HANA)
- A service user account with read access to security logs
- Network connectivity between SAP Shield and the SAP system

## Option 1: RFC Connection (Recommended)

### Install SAP NW RFC SDK

1. Download the SAP NetWeaver RFC SDK from the SAP Support Portal (requires S-user)
2. Extract to `/usr/local/sap/nwrfcsdk`
3. Set environment variables:

```bash
export SAPNWRFC_HOME=/usr/local/sap/nwrfcsdk
export LD_LIBRARY_PATH=$SAPNWRFC_HOME/lib:$LD_LIBRARY_PATH
```

### Install PyRFC

```bash
pip install pyrfc
```

### SAP System Configuration

Create a service user in SAP (transaction SU01) with these authorizations:

- `S_RFC` — RFC access
- `S_TABU_DIS` — Table display (for audit log tables)
- `S_USER_GRP` — User group read access
- `S_ADMI_FCD` — Read security audit log

Enable the Security Audit Log in your SAP system:
1. Transaction SM19 — configure audit profile
2. Enable logging for: dialog logon, RFC/CPIC logon, transaction starts, report starts, and table access

### SAP Shield Configuration

```yaml
sap:
  connector: rfc
  rfc_config:
    ashost: sap-server.company.com
    sysnr: "00"
    client: "100"
    user: SHIELD_SVC
    passwd: "${SAP_PASSWORD}"
    lang: EN
```

Set the password via environment variable:
```bash
export SAP_PASSWORD=your_password_here
```

## Option 2: OData Connection (S/4HANA)

For S/4HANA systems with OData services enabled:

```yaml
sap:
  connector: odata
  odata_config:
    base_url: https://sap-server:443/sap/opu/odata/sap
    auth_type: basic
    username: SHIELD_SVC
    password: "${SAP_PASSWORD}"
```

Ensure these OData services are active:
- `/sap/opu/odata/sap/API_SECURITY_AUDIT_LOG`
- `/sap/opu/odata/sap/API_CHANGE_DOCUMENT`

## Option 3: File-Based Ingestion

Export logs from SAP and place them in a watched directory:

```yaml
sap:
  connector: file
  file_config:
    watch_directory: ./data/sap_logs
    file_pattern: "*.csv"
    archive_processed: true
```

Expected CSV format:
```csv
timestamp,user,event_type,transaction,table,record_count,ip,sensitivity
2026-03-15 10:30:00,JSMITH,transaction,FB01,,0,192.168.1.10,NORMAL
2026-03-15 10:35:00,JSMITH,table_read,SE16N,KNA1,5000,192.168.1.10,HIGH
```

## Verifying Connection

After configuring, start SAP Shield and check the health endpoint:

```bash
curl http://localhost:8000/api/health
```

You should see `"status": "healthy"` with your connector type listed.

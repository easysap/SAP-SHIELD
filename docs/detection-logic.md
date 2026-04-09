# Detection Logic

SAP Shield uses three complementary detection strategies.

## 1. ML-Based Anomaly Detection

### Behavioral Baselining

For each monitored user, SAP Shield builds a statistical profile of normal behavior across these dimensions:

- **Volume**: Average and standard deviation of records accessed per event, events per hour, events per day
- **Timing**: Typical active hours, weekday patterns, session start/end times
- **Transactions**: Frequency distribution of transaction codes used, set of "typical" transactions (top 80%)
- **Network**: Set of known source IP addresses
- **Data access**: Tables commonly accessed

Baselines are built over a configurable rolling window (default: 30 days) and require a minimum number of events (default: 100) before being considered reliable.

### Anomaly Scoring

Each new event is scored across five dimensions, each producing a 0.0-1.0 component score:

| Component | Weight | What it measures |
|-----------|--------|-----------------|
| Volume | 30% | Z-score of record count vs user baseline |
| Temporal | 25% | Activity outside established patterns |
| Transaction | 25% | Use of unfamiliar transaction codes |
| Network | 10% | Access from unknown IP addresses |
| Sensitivity | 10% | Inherent sensitivity of data accessed |

The weighted combination produces an overall risk score. Events exceeding the alert threshold (default: 0.75) generate alerts.

## 2. Transaction Sequence Analysis

Maintains a sliding window of recent transactions per user and matches against known attack patterns:

| Pattern | Sequence | Risk |
|---------|----------|------|
| Self-privilege escalation | SU01 → PFCG | High |
| Data harvesting | SE16N → SE16N → SE16N | Medium |
| Cover tracks | SM20 → SM21 | Medium |
| Code injection | SE38 → SE80 | High |
| Payment fraud | FK01 → F110 | High |

Matching uses subsequence detection with confidence scoring. Time proximity is also checked — patterns must occur within a configurable window (default: 60 minutes).

## 3. Configurable Rule Engine

YAML-defined rules in `config/detection_rules.yaml` provide explicit detection logic. Each rule specifies:

- **Conditions**: Field-level checks that must all pass
- **Scoring**: Base score with conditional multipliers
- **Severity**: Classification level

Rules are evaluated independently of ML models and can be added or tuned without code changes.

## Tuning Recommendations

- **Start with `sensitivity: medium`** and observe false positive rates
- **Increase `baseline_window_days`** if your users have variable schedules
- **Adjust `alert_threshold`** — lower catches more but creates more noise
- **Use `max_alerts_per_user_per_day`** to prevent alert fatigue
- **Review and tune rule multipliers** based on your environment

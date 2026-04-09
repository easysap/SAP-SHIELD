"""Detection Engine — orchestrates ML models and rule engine for threat detection."""

import uuid
from datetime import datetime
from typing import Optional
from loguru import logger

from connectors.base import SAPEvent
from detection.models.baseline import BaselineEngine
from detection.models.anomaly import AnomalyScorer
from detection.models.sequence import SequenceAnalyzer
from .rule_engine import RuleEngine


class DetectionResult:
    """Combined detection result for an event."""

    def __init__(
        self,
        event: SAPEvent,
        risk_score: float,
        is_threat: bool,
        alerts: list[dict],
    ):
        self.event = event
        self.risk_score = risk_score
        self.is_threat = is_threat
        self.alerts = alerts


class DetectionEngine:
    """
    Main detection orchestrator.

    Combines:
    - ML-based anomaly scoring against user baselines
    - Transaction sequence analysis
    - Configurable rule-based detection

    Each event flows through all three engines, and the highest-confidence
    signal triggers an alert.
    """

    def __init__(self, config: dict):
        self.config = config
        det_cfg = config.get("detection", {})
        self.alert_threshold = det_cfg.get("alert_threshold", 0.75)
        self.max_alerts_per_user_day = det_cfg.get("max_alerts_per_user_per_day", 10)

        # Initialize sub-engines
        self.baseline = BaselineEngine(config)
        self.scorer = AnomalyScorer(config)
        self.sequence = SequenceAnalyzer(config)
        self.rules = RuleEngine()

        # Alert rate limiting
        self._daily_alert_counts: dict[str, int] = {}
        self._alert_date: Optional[str] = None

    def process_event(self, event: SAPEvent) -> DetectionResult:
        """
        Run an event through the full detection pipeline.

        Returns a DetectionResult with risk score and any triggered alerts.
        """
        alerts = []

        # 1. Update baseline with this event
        self.baseline.update([event])

        # 2. ML anomaly scoring
        profile = self.baseline.get_profile(event.user)
        anomaly = self.scorer.score_event(event, profile)

        if anomaly.is_anomalous:
            alerts.append({
                "alert_id": f"ML-{uuid.uuid4().hex[:12]}",
                "timestamp": event.timestamp,
                "user": event.user,
                "rule_id": "ML_ANOMALY",
                "rule_name": "ML Anomaly Detection",
                "severity": self._score_to_severity(anomaly.overall_score),
                "risk_score": anomaly.overall_score,
                "description": "; ".join(anomaly.reasons),
                "evidence": [
                    {
                        "event_id": event.event_id,
                        "components": anomaly.components,
                        "reasons": anomaly.reasons,
                    }
                ],
            })

        # 3. Sequence analysis
        seq_alerts = self.sequence.analyze(event)
        for sa in seq_alerts:
            alerts.append({
                "alert_id": f"SEQ-{uuid.uuid4().hex[:12]}",
                "timestamp": event.timestamp,
                "user": sa.user,
                "rule_id": f"SEQ_{sa.pattern_name.upper()}",
                "rule_name": f"Sequence: {sa.description}",
                "severity": "high" if sa.confidence > 0.8 else "medium",
                "risk_score": sa.confidence,
                "description": (
                    f"Suspicious transaction sequence detected: {sa.pattern_name}. "
                    f"{sa.description}. "
                    f"Transactions: {' -> '.join(sa.transactions)}"
                ),
                "evidence": [
                    {
                        "pattern": sa.pattern_name,
                        "transactions": sa.transactions,
                        "confidence": sa.confidence,
                    }
                ],
            })

        # 4. Rule engine
        rule_matches = self.rules.evaluate(event)
        for rm in rule_matches:
            if rm.final_score >= self.alert_threshold:
                alerts.append({
                    "alert_id": f"RULE-{uuid.uuid4().hex[:12]}",
                    "timestamp": event.timestamp,
                    "user": event.user,
                    "rule_id": rm.rule_id,
                    "rule_name": rm.rule_name,
                    "severity": rm.severity,
                    "risk_score": rm.final_score,
                    "description": (
                        f"Rule triggered: {rm.rule_name}. "
                        f"Conditions: {', '.join(rm.matched_conditions)}"
                    ),
                    "evidence": [
                        {
                            "rule_id": rm.rule_id,
                            "conditions": rm.matched_conditions,
                            "multipliers": rm.applied_multipliers,
                            "base_score": rm.base_score,
                            "final_score": rm.final_score,
                        }
                    ],
                })

        # Rate-limit alerts per user per day
        alerts = self._rate_limit_alerts(alerts)

        # Calculate overall risk score
        risk_score = max(
            (a["risk_score"] for a in alerts), default=anomaly.overall_score
        )

        return DetectionResult(
            event=event,
            risk_score=risk_score,
            is_threat=len(alerts) > 0,
            alerts=alerts,
        )

    def process_batch(self, events: list[SAPEvent]) -> list[DetectionResult]:
        """Process a batch of events through detection."""
        results = []
        for event in events:
            result = self.process_event(event)
            results.append(result)
        return results

    def _score_to_severity(self, score: float) -> str:
        if score >= 0.9:
            return "critical"
        elif score >= 0.75:
            return "high"
        elif score >= 0.5:
            return "medium"
        return "low"

    def _rate_limit_alerts(self, alerts: list[dict]) -> list[dict]:
        """Apply per-user daily alert rate limiting."""
        today = datetime.now().strftime("%Y-%m-%d")

        # Reset counters on new day
        if self._alert_date != today:
            self._daily_alert_counts = {}
            self._alert_date = today

        filtered = []
        for alert in alerts:
            user = alert["user"]
            count = self._daily_alert_counts.get(user, 0)

            if count < self.max_alerts_per_user_day:
                filtered.append(alert)
                self._daily_alert_counts[user] = count + 1
            else:
                logger.debug(
                    f"Rate-limited alert for {user} "
                    f"({count}/{self.max_alerts_per_user_day})"
                )

        return filtered

    @property
    def stats(self) -> dict:
        return {
            "baselined_users": len(self.baseline.profiles),
            "loaded_rules": len(self.rules.rules),
            "alert_threshold": self.alert_threshold,
        }

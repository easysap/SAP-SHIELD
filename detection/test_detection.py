"""Tests for the detection engine."""

import pytest
from datetime import datetime
from connectors.base import SAPEvent, EventType
from detection.models.baseline import BaselineEngine, UserBehaviorProfile
from detection.models.anomaly import AnomalyScorer
from detection.models.sequence import SequenceAnalyzer
from detection.rules.rule_engine import RuleEngine
from detection.engine import DetectionEngine


class TestBaselineEngine:
    def _make_event(self, user="TEST001", tcode="FB01", hour=10, records=50):
        return SAPEvent(
            event_id=f"E-{id(user)}-{hour}",
            timestamp=datetime(2026, 3, 15, hour, 30),
            user=user,
            event_type=EventType.TRANSACTION_START,
            transaction=tcode,
            record_count=records,
            source_ip="192.168.1.10",
            raw_data={"enrichment": {}},
        )

    def test_update_creates_profile(self):
        engine = BaselineEngine()
        events = [self._make_event(hour=h) for h in range(8, 18)]
        engine.update(events)
        profile = engine.get_profile("TEST001")
        assert profile is not None
        assert profile.event_count == 10

    def test_typical_transactions_tracked(self):
        engine = BaselineEngine()
        events = [self._make_event(tcode="FB01") for _ in range(20)]
        events += [self._make_event(tcode="FB03") for _ in range(5)]
        engine.update(events)
        profile = engine.get_profile("TEST001")
        assert "FB01" in profile.typical_transactions

    def test_is_baselined_requires_min_events(self):
        engine = BaselineEngine({"detection": {"min_baseline_events": 50}})
        events = [self._make_event() for _ in range(30)]
        engine.update(events)
        assert not engine.is_baselined("TEST001")

        events2 = [self._make_event() for _ in range(30)]
        engine.update(events2)
        assert engine.is_baselined("TEST001")


class TestAnomalyScorer:
    def _make_profile(self):
        p = UserBehaviorProfile(user="TEST001")
        p.event_count = 500
        p.avg_record_reads = 100.0
        p.std_record_reads = 30.0
        p.typical_transactions = {"FB01", "FB02", "FB03"}
        p.active_hours = {"9": 100, "10": 120, "11": 90, "14": 80, "15": 70}
        p.known_ips = {"192.168.1.10", "192.168.1.11"}
        return p

    def _make_event(self, records=50, hour=10, tcode="FB01", ip="192.168.1.10"):
        return SAPEvent(
            event_id="E-test",
            timestamp=datetime(2026, 3, 15, hour, 30),
            user="TEST001",
            event_type=EventType.TABLE_READ,
            transaction=tcode,
            record_count=records,
            source_ip=ip,
            raw_data={"enrichment": {
                "outside_business_hours": hour < 8 or hour > 18,
                "is_weekend": False,
                "transaction_sensitivity": "NORMAL",
                "table_sensitivity": "NORMAL",
            }},
        )

    def test_normal_event_low_score(self):
        scorer = AnomalyScorer()
        profile = self._make_profile()
        event = self._make_event(records=80)
        result = scorer.score_event(event, profile)
        assert result.overall_score < 0.5

    def test_high_volume_raises_score(self):
        scorer = AnomalyScorer()
        profile = self._make_profile()
        event = self._make_event(records=50000)
        result = scorer.score_event(event, profile)
        assert result.overall_score > 0.3
        assert any("volume" in r.lower() for r in result.reasons)

    def test_unknown_ip_raises_score(self):
        scorer = AnomalyScorer()
        profile = self._make_profile()
        event = self._make_event(ip="10.99.99.99")
        result = scorer.score_event(event, profile)
        assert result.components.get("network", 0) > 0

    def test_new_transaction_raises_score(self):
        scorer = AnomalyScorer()
        profile = self._make_profile()
        event = self._make_event(tcode="SU01")
        result = scorer.score_event(event, profile)
        assert result.components.get("transaction", 0) > 0

    def test_no_baseline_still_scores(self):
        scorer = AnomalyScorer()
        event = self._make_event(records=100000)
        result = scorer.score_event(event, None)
        assert result.overall_score > 0


class TestSequenceAnalyzer:
    def _make_event(self, user, tcode, minute=0):
        return SAPEvent(
            event_id=f"E-{tcode}-{minute}",
            timestamp=datetime(2026, 3, 15, 10, minute),
            user=user,
            event_type=EventType.TRANSACTION_START,
            transaction=tcode,
            raw_data={},
        )

    def test_detects_privilege_escalation_sequence(self):
        analyzer = SequenceAnalyzer()
        alerts = []
        for i, tcode in enumerate(["FB01", "SU01", "PFCG", "FB03"]):
            result = analyzer.analyze(self._make_event("USER1", tcode, i))
            alerts.extend(result)
        assert any("privilege" in a.pattern_name for a in alerts)

    def test_no_alert_on_normal_sequence(self):
        analyzer = SequenceAnalyzer()
        alerts = []
        for i, tcode in enumerate(["FB01", "FB02", "FB03", "FBL3N"]):
            result = analyzer.analyze(self._make_event("USER2", tcode, i))
            alerts.extend(result)
        assert len(alerts) == 0

    def test_diversity_score(self):
        analyzer = SequenceAnalyzer()
        for i, tcode in enumerate(["FB01", "VA01", "ME21N", "SU01", "PA30"]):
            analyzer.analyze(self._make_event("USER3", tcode, i))
        diversity = analyzer.get_user_activity_diversity("USER3")
        assert diversity == 1.0  # All unique


class TestDetectionEngine:
    @pytest.fixture
    def engine(self):
        config = {
            "detection": {
                "sensitivity": "medium",
                "baseline_window_days": 30,
                "min_baseline_events": 10,
                "alert_threshold": 0.75,
                "max_alerts_per_user_per_day": 10,
                "models": {
                    "statistical": {"std_dev_threshold": 3.0},
                    "sequence": {"window_size": 20},
                },
            }
        }
        return DetectionEngine(config)

    def test_process_normal_event(self, engine):
        event = SAPEvent(
            event_id="E-1",
            timestamp=datetime(2026, 3, 15, 10, 0),
            user="NORM001",
            event_type=EventType.TRANSACTION_START,
            transaction="FB01",
            record_count=50,
            raw_data={"enrichment": {}},
        )
        result = engine.process_event(event)
        assert result is not None
        assert result.risk_score >= 0

    def test_process_batch(self, engine):
        events = [
            SAPEvent(
                event_id=f"E-{i}",
                timestamp=datetime(2026, 3, 15, 10, i),
                user="BATCH001",
                event_type=EventType.TRANSACTION_START,
                transaction="FB01",
                raw_data={"enrichment": {}},
            )
            for i in range(10)
        ]
        results = engine.process_batch(events)
        assert len(results) == 10

    def test_stats_available(self, engine):
        stats = engine.stats
        assert "baselined_users" in stats
        assert "loaded_rules" in stats
        assert "alert_threshold" in stats

"""Tests for the pipeline module."""

import pytest
from datetime import datetime

from connectors.base import SAPEvent, EventType
from pipeline.enrichment import EventEnricher
from pipeline.storage import StorageBackend


class TestEventEnricher:
    def _make_event(self, tcode=None, table=None, hour=10, records=50):
        return SAPEvent(
            event_id="E-enrich-test",
            timestamp=datetime(2026, 3, 15, hour, 30),
            user="ENRICH01",
            event_type=EventType.TRANSACTION_START,
            transaction=tcode,
            table_name=table,
            record_count=records,
            raw_data={},
        )

    def test_enriches_transaction_sensitivity(self):
        enricher = EventEnricher()
        event = enricher.enrich(self._make_event(tcode="SU01"))
        ctx = event.raw_data["enrichment"]
        assert ctx["transaction_sensitivity"] == "CRITICAL"

    def test_normal_transaction_sensitivity(self):
        enricher = EventEnricher()
        event = enricher.enrich(self._make_event(tcode="FB01"))
        ctx = event.raw_data["enrichment"]
        assert ctx["transaction_sensitivity"] == "NORMAL"

    def test_enriches_time_flags(self):
        enricher = EventEnricher()
        event = enricher.enrich(self._make_event(hour=3))
        ctx = event.raw_data["enrichment"]
        assert ctx["outside_business_hours"] is True
        assert ctx["hour_of_day"] == 3

    def test_business_hours_flag(self):
        enricher = EventEnricher()
        event = enricher.enrich(self._make_event(hour=14))
        ctx = event.raw_data["enrichment"]
        assert ctx["outside_business_hours"] is False

    def test_sensitive_table_detection(self):
        enricher = EventEnricher()
        event = enricher.enrich(self._make_event(table="PA0008"))
        ctx = event.raw_data["enrichment"]
        assert ctx["table_sensitivity"] == "HIGH"
        assert event.data_sensitivity == "HIGH"

    def test_high_volume_flag(self):
        enricher = EventEnricher()
        event = enricher.enrich(self._make_event(records=15000))
        ctx = event.raw_data["enrichment"]
        assert ctx["high_volume"] is True

    def test_extreme_volume_flag(self):
        enricher = EventEnricher()
        event = enricher.enrich(self._make_event(records=60000))
        ctx = event.raw_data["enrichment"]
        assert ctx["extreme_volume"] is True


class TestStorageBackend:
    @pytest.fixture
    def storage(self, tmp_path):
        config = {
            "storage": {
                "backend": "sqlite",
                "sqlite_path": str(tmp_path / "test.db"),
            }
        }
        return StorageBackend(config)

    @pytest.mark.asyncio
    async def test_initialize(self, storage):
        await storage.initialize()

    @pytest.mark.asyncio
    async def test_store_and_retrieve_events(self, storage):
        await storage.initialize()

        events = [
            SAPEvent(
                event_id=f"E-store-{i}",
                timestamp=datetime(2026, 3, 15, 10, i),
                user="STORE01",
                event_type=EventType.TRANSACTION_START,
                transaction="FB01",
                raw_data={},
            )
            for i in range(5)
        ]
        count = await storage.store_events(events)
        assert count == 5

        retrieved = await storage.get_events(user="STORE01")
        assert len(retrieved) == 5

    @pytest.mark.asyncio
    async def test_store_and_retrieve_alert(self, storage):
        await storage.initialize()

        alert = {
            "alert_id": "A-test-001",
            "timestamp": datetime(2026, 3, 15, 10, 0),
            "user": "ALERT01",
            "rule_id": "TEST_RULE",
            "rule_name": "Test Rule",
            "severity": "high",
            "risk_score": 0.85,
            "description": "Test alert",
            "evidence": [{"detail": "test"}],
        }
        await storage.store_alert(alert)

        alerts = await storage.get_alerts(user="ALERT01")
        assert len(alerts) == 1
        assert alerts[0]["risk_score"] == 0.85

    @pytest.mark.asyncio
    async def test_update_alert_status(self, storage):
        await storage.initialize()

        alert = {
            "alert_id": "A-status-001",
            "timestamp": datetime(2026, 3, 15, 10, 0),
            "user": "STATUS01",
            "rule_id": "TEST_RULE",
            "risk_score": 0.9,
        }
        await storage.store_alert(alert)

        success = await storage.update_alert_status(
            "A-status-001", "resolved", "ADMIN"
        )
        assert success is True

        alerts = await storage.get_alerts(user="STATUS01")
        assert alerts[0]["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_dashboard_stats(self, storage):
        await storage.initialize()
        stats = await storage.get_dashboard_stats()
        assert "total_events" in stats
        assert "total_alerts" in stats
        assert "open_alerts" in stats

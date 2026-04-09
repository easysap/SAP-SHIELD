"""Tests for the API endpoints."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock
from api.app import app
from api.routes import init_routes


@pytest.fixture
def client():
    mock_storage = AsyncMock()
    mock_storage.get_dashboard_stats.return_value = {
        "total_events": 1500,
        "total_alerts": 25,
        "open_alerts": 8,
        "critical_alerts": 3,
        "unique_users": 42,
    }
    mock_storage.get_alerts.return_value = [
        {
            "alert_id": "A-001",
            "timestamp": "2026-03-15T10:00:00",
            "user": "TEST001",
            "rule_id": "ML_ANOMALY",
            "rule_name": "ML Anomaly Detection",
            "severity": "high",
            "risk_score": 0.85,
            "description": "Unusual volume",
            "evidence": [],
            "status": "open",
        }
    ]
    mock_storage.get_events.return_value = []
    mock_storage.update_alert_status.return_value = True

    mock_detection = MagicMock()
    mock_detection.stats = {
        "baselined_users": 42,
        "loaded_rules": 5,
        "alert_threshold": 0.75,
    }
    mock_detection.baseline.get_profile.return_value = None
    mock_detection.baseline.is_baselined.return_value = False

    mock_pipeline = MagicMock()
    mock_pipeline.stats = {
        "total_ingested": 1500,
        "running": True,
    }

    init_routes(mock_storage, mock_detection, mock_pipeline)
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "0.1.0"


class TestStatsEndpoint:
    def test_stats_returns_counts(self, client):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_events"] == 1500
        assert data["open_alerts"] == 8


class TestAlertsEndpoint:
    def test_list_alerts(self, client):
        response = client.get("/api/alerts")
        assert response.status_code == 200
        alerts = response.json()
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "high"

    def test_update_alert_status(self, client):
        response = client.patch(
            "/api/alerts/A-001",
            json={"status": "resolved", "resolved_by": "ADMIN"},
        )
        assert response.status_code == 200


class TestEventsEndpoint:
    def test_list_events(self, client):
        response = client.get("/api/events")
        assert response.status_code == 200

    def test_filter_by_user(self, client):
        response = client.get("/api/events?user=TEST001")
        assert response.status_code == 200

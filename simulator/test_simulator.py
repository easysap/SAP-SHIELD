"""Tests for the simulator module."""

import pytest
import asyncio
from datetime import datetime

from simulator.generator import SimulatorConnector
from simulator.profiles import generate_user_profiles, UserProfile, Department
from simulator.threat_scenarios import (
    MassDataExport,
    PrivilegeEscalation,
    OffHoursAccess,
    GhostAccount,
    TransactionHopping,
    SCENARIO_REGISTRY,
)


class TestUserProfiles:
    def test_generate_default_count(self):
        profiles = generate_user_profiles()
        assert len(profiles) == 50

    def test_generate_custom_count(self):
        profiles = generate_user_profiles(num_users=10)
        assert len(profiles) == 10

    def test_profiles_have_required_fields(self):
        profiles = generate_user_profiles(5)
        for p in profiles:
            assert p.username
            assert p.department in Department
            assert p.role
            assert len(p.typical_transactions) > 0
            assert p.avg_events_per_hour > 0

    def test_profiles_have_diversity(self):
        profiles = generate_user_profiles(50)
        departments = {p.department for p in profiles}
        assert len(departments) >= 3  # At least 3 departments represented


class TestThreatScenarios:
    def _make_user(self) -> UserProfile:
        return UserProfile(
            username="TEST001",
            department=Department.FINANCE,
            role="FI_USER",
            typical_transactions=["FB01", "FB02"],
            avg_events_per_hour=10.0,
        )

    def test_mass_data_export_generates_events(self):
        scenario = MassDataExport()
        events = scenario.generate(self._make_user(), datetime.now())
        assert len(events) >= 8
        assert all(e.record_count > 0 for e in events)
        assert all(e.raw_data.get("injected") for e in events)

    def test_privilege_escalation_generates_sequence(self):
        scenario = PrivilegeEscalation()
        events = scenario.generate(self._make_user(), datetime.now())
        assert len(events) == 5
        transactions = [e.transaction for e in events]
        assert "SU01" in transactions
        assert "PFCG" in transactions

    def test_off_hours_generates_off_hours_events(self):
        scenario = OffHoursAccess()
        events = scenario.generate(self._make_user(), datetime.now())
        assert len(events) >= 5
        # Events should be in early morning hours
        for e in events:
            assert e.timestamp.hour <= 6 or e.timestamp.hour >= 22

    def test_ghost_account_starts_with_login(self):
        scenario = GhostAccount()
        events = scenario.generate(self._make_user(), datetime.now())
        assert events[0].event_type.value == "LOGIN"

    def test_transaction_hopping_has_diversity(self):
        scenario = TransactionHopping()
        events = scenario.generate(self._make_user(), datetime.now())
        unique_tx = {e.transaction for e in events}
        assert len(unique_tx) >= 5

    def test_all_scenarios_registered(self):
        assert len(SCENARIO_REGISTRY) == 5
        for name in ["mass_data_export", "privilege_escalation", "off_hours_access",
                      "ghost_account", "transaction_hopping"]:
            assert name in SCENARIO_REGISTRY


class TestSimulatorConnector:
    @pytest.fixture
    def config(self):
        return {
            "simulator": {
                "num_users": 10,
                "events_per_minute": 20,
                "threat_injection_rate": 0.05,
                "scenarios": ["mass_data_export", "off_hours_access"],
            }
        }

    @pytest.mark.asyncio
    async def test_connect_creates_users(self, config):
        sim = SimulatorConnector(config)
        await sim.connect()
        assert len(sim.users) == 10
        assert sim.is_connected

    @pytest.mark.asyncio
    async def test_fetch_events_returns_events(self, config):
        sim = SimulatorConnector(config)
        await sim.connect()
        events = await sim.fetch_events(limit=100)
        assert len(events) > 0
        assert len(events) <= 100

    @pytest.mark.asyncio
    async def test_events_have_required_fields(self, config):
        sim = SimulatorConnector(config)
        await sim.connect()
        events = await sim.fetch_events(limit=50)
        for e in events:
            assert e.event_id
            assert e.timestamp
            assert e.user
            assert e.event_type

    @pytest.mark.asyncio
    async def test_disconnect(self, config):
        sim = SimulatorConnector(config)
        await sim.connect()
        await sim.disconnect()
        assert not sim.is_connected

    @pytest.mark.asyncio
    async def test_health_check(self, config):
        sim = SimulatorConnector(config)
        await sim.connect()
        assert await sim.health_check() is True
        await sim.disconnect()
        assert await sim.health_check() is False

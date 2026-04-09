#!/usr/bin/env python3
"""Generate sample data for testing SAP Shield without running the full pipeline."""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.generator import SimulatorConnector
from pipeline.enrichment import EventEnricher
from pipeline.storage import StorageBackend
from detection.engine import DetectionEngine
from loguru import logger


async def main():
    config = {
        "simulator": {
            "num_users": 50,
            "events_per_minute": 60,
            "threat_injection_rate": 0.03,
            "scenarios": [
                "mass_data_export",
                "privilege_escalation",
                "off_hours_access",
                "ghost_account",
                "transaction_hopping",
            ],
        },
        "storage": {
            "backend": "sqlite",
            "sqlite_path": "./data/sapshield.db",
        },
        "detection": {
            "sensitivity": "medium",
            "baseline_window_days": 30,
            "min_baseline_events": 20,
            "alert_threshold": 0.70,
            "max_alerts_per_user_per_day": 50,
            "models": {
                "statistical": {"std_dev_threshold": 3.0},
                "sequence": {"window_size": 20, "min_sequence_length": 3},
                "isolation_forest": {"contamination": 0.05, "n_estimators": 200},
            },
        },
    }

    logger.info("Initializing components...")
    connector = SimulatorConnector(config)
    storage = StorageBackend(config)
    enricher = EventEnricher()
    detection = DetectionEngine(config)

    await connector.connect()
    await storage.initialize()

    total_events = 0
    total_alerts = 0
    num_batches = 10
    batch_size = 500

    logger.info(f"Generating {num_batches * batch_size} events across {num_batches} batches...")

    for batch in range(num_batches):
        events = await connector.fetch_events(limit=batch_size)
        enriched = [enricher.enrich(e) for e in events]
        await storage.store_events(enriched)

        # Run detection
        results = detection.process_batch(enriched)
        batch_alerts = 0
        for result in results:
            for alert in result.alerts:
                await storage.store_alert(alert)
                batch_alerts += 1

        total_events += len(events)
        total_alerts += batch_alerts

        threats = sum(1 for e in events if e.raw_data.get("injected"))
        logger.info(
            f"Batch {batch + 1}/{num_batches}: "
            f"{len(events)} events ({threats} threats), "
            f"{batch_alerts} alerts"
        )

    stats = await storage.get_dashboard_stats()
    logger.info(f"\nSeeding complete!")
    logger.info(f"  Total events: {stats['total_events']}")
    logger.info(f"  Total alerts: {stats['total_alerts']}")
    logger.info(f"  Open alerts:  {stats['open_alerts']}")
    logger.info(f"  Critical:     {stats['critical_alerts']}")
    logger.info(f"  Users:        {stats['unique_users']}")
    logger.info(f"\nDatabase: ./data/sapshield.db")
    logger.info(f"Run 'python -m api.app' to start the server.")


if __name__ == "__main__":
    asyncio.run(main())

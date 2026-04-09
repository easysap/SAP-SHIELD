"""Event ingestion and normalization pipeline."""

import asyncio
from datetime import datetime
from typing import Optional
from loguru import logger

from connectors.base import BaseConnector, SAPEvent
from pipeline.enrichment import EventEnricher
from pipeline.storage import StorageBackend


class IngestionPipeline:
    """
    Orchestrates the flow: Connector -> Normalize -> Enrich -> Store.

    Runs as a continuous loop, polling the connector for new events
    and pushing them through the pipeline.
    """

    def __init__(
        self,
        connector: BaseConnector,
        storage: StorageBackend,
        enricher: Optional[EventEnricher] = None,
        poll_interval: int = 10,
    ):
        self.connector = connector
        self.storage = storage
        self.enricher = enricher or EventEnricher()
        self.poll_interval = poll_interval
        self._running = False
        self._last_fetch: Optional[datetime] = None
        self._total_ingested = 0

    async def start(self) -> None:
        """Start the continuous ingestion loop."""
        logger.info("Starting ingestion pipeline...")
        await self.connector.connect()
        await self.storage.initialize()
        self._running = True

        while self._running:
            try:
                events = await self.connector.fetch_events(
                    since=self._last_fetch,
                    limit=1000,
                )

                if events:
                    enriched = [self.enricher.enrich(e) for e in events]
                    await self.storage.store_events(enriched)
                    self._last_fetch = max(e.timestamp for e in events)
                    self._total_ingested += len(events)

                    logger.info(
                        f"Ingested {len(events)} events "
                        f"(total: {self._total_ingested})"
                    )

            except Exception as e:
                logger.error(f"Ingestion error: {e}")

            await asyncio.sleep(self.poll_interval)

    async def stop(self) -> None:
        """Stop the ingestion loop."""
        self._running = False
        await self.connector.disconnect()
        logger.info(
            f"Ingestion pipeline stopped. "
            f"Total events ingested: {self._total_ingested}"
        )

    async def ingest_batch(self, events: list[SAPEvent]) -> int:
        """Manually ingest a batch of events (for testing or file import)."""
        enriched = [self.enricher.enrich(e) for e in events]
        await self.storage.store_events(enriched)
        self._total_ingested += len(enriched)
        return len(enriched)

    @property
    def stats(self) -> dict:
        return {
            "total_ingested": self._total_ingested,
            "last_fetch": self._last_fetch.isoformat() if self._last_fetch else None,
            "running": self._running,
            "connector_type": type(self.connector).__name__,
        }

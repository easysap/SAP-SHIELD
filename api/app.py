"""SAP Shield — main application entry point."""

import asyncio
import yaml
from pathlib import Path
from contextlib import asynccontextmanager
from loguru import logger
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from connectors.base import BaseConnector
from simulator.generator import SimulatorConnector
from pipeline.ingestion import IngestionPipeline
from pipeline.enrichment import EventEnricher
from pipeline.storage import StorageBackend
from detection.engine import DetectionEngine
from api.routes import router, init_routes


def load_config(path: str = "config/default.yaml") -> dict:
    """Load configuration from YAML file."""
    config_path = Path(path)
    if not config_path.exists():
        logger.warning(f"Config not found: {path}, using defaults")
        return {}

    with open(config_path) as f:
        return yaml.safe_load(f)


def create_connector(config: dict) -> BaseConnector:
    """Create the appropriate connector based on config."""
    connector_type = config.get("sap", {}).get("connector", "simulator")

    if connector_type == "simulator":
        return SimulatorConnector(config)
    elif connector_type == "rfc":
        from connectors.rfc_connector import RFCConnector
        return RFCConnector(config.get("sap", {}))
    elif connector_type == "odata":
        from connectors.odata_connector import ODataConnector
        return ODataConnector(config.get("sap", {}))
    elif connector_type == "file":
        from connectors.file_connector import FileConnector
        return FileConnector(config.get("sap", {}))
    else:
        raise ValueError(f"Unknown connector type: {connector_type}")


# Global references
_pipeline_task = None
_detection_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    global _pipeline_task, _detection_task

    config = load_config()
    logger.info("Starting SAP Shield v0.1.0")

    # Initialize components
    connector = create_connector(config)
    storage = StorageBackend(config)
    enricher = EventEnricher()
    detection = DetectionEngine(config)

    pipeline = IngestionPipeline(
        connector=connector,
        storage=storage,
        enricher=enricher,
        poll_interval=config.get("sap", {}).get("poll_interval_seconds", 10),
    )

    # Inject into routes
    init_routes(storage, detection, pipeline)

    # Start background tasks
    async def run_pipeline():
        await pipeline.start()

    async def run_detection_loop():
        """Continuously process new events through detection."""
        await storage.initialize()
        last_check = None

        while True:
            try:
                events = await storage.get_events(since=last_check, limit=200)
                if events:
                    # Convert back to minimal objects for detection
                    from connectors.base import SAPEvent, EventType
                    from datetime import datetime as dt

                    for evt_dict in events:
                        evt = SAPEvent(
                            event_id=evt_dict["event_id"],
                            timestamp=dt.fromisoformat(evt_dict["timestamp"]),
                            user=evt_dict["user"],
                            event_type=EventType(evt_dict["event_type"]),
                            transaction=evt_dict.get("transaction"),
                            table_name=evt_dict.get("table_name"),
                            record_count=evt_dict.get("record_count", 0),
                            data_sensitivity=evt_dict.get("data_sensitivity", "NORMAL"),
                            source_ip=evt_dict.get("source_ip"),
                        )
                        result = detection.process_event(evt)

                        for alert in result.alerts:
                            await storage.store_alert(alert)
                            logger.warning(
                                f"ALERT [{alert['severity'].upper()}] "
                                f"{alert['rule_name']} — "
                                f"User: {alert['user']} — "
                                f"Score: {alert['risk_score']:.2f}"
                            )

                    last_check = dt.fromisoformat(events[0]["timestamp"])

            except Exception as e:
                logger.error(f"Detection loop error: {e}")

            await asyncio.sleep(5)

    _pipeline_task = asyncio.create_task(run_pipeline())
    _detection_task = asyncio.create_task(run_detection_loop())

    logger.info("SAP Shield is running")
    yield

    # Shutdown
    logger.info("Shutting down SAP Shield...")
    _pipeline_task.cancel()
    _detection_task.cancel()
    await pipeline.stop()


# Create FastAPI app
app = FastAPI(
    title="SAP Shield",
    description="Open-source insider threat detection for SAP systems",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount API routes
app.include_router(router, prefix="/api")

# Serve dashboard
dashboard_dir = Path(__file__).parent.parent / "dashboard"
if dashboard_dir.exists():
    @app.get("/")
    async def serve_dashboard():
        return FileResponse(dashboard_dir / "index.html")


def main():
    """CLI entry point."""
    import uvicorn
    config = load_config()
    host = config.get("app", {}).get("host", "0.0.0.0")
    port = config.get("app", {}).get("port", 8000)

    uvicorn.run(
        "api.app:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()

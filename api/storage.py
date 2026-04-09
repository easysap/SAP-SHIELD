"""Storage backend — SQLite (default) and PostgreSQL support."""

import json
import os
from datetime import datetime, timedelta
from typing import Optional
from loguru import logger

import sqlalchemy as sa
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Boolean
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

Base = declarative_base()


class EventRecord(Base):
    __tablename__ = "events"

    event_id = Column(String(64), primary_key=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    user = Column(String(40), index=True, nullable=False)
    event_type = Column(String(30), index=True, nullable=False)
    transaction = Column(String(20), index=True)
    program = Column(String(100))
    table_name = Column(String(60), index=True)
    record_count = Column(Integer, default=0)
    client = Column(String(3), default="100")
    terminal = Column(String(40))
    source_ip = Column(String(45))
    data_sensitivity = Column(String(10), default="NORMAL")
    raw_data = Column(Text)  # JSON
    ingested_at = Column(DateTime, default=datetime.utcnow)


class AlertRecord(Base):
    __tablename__ = "alerts"

    alert_id = Column(String(64), primary_key=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    user = Column(String(40), index=True, nullable=False)
    rule_id = Column(String(50), index=True, nullable=False)
    rule_name = Column(String(100))
    severity = Column(String(10), index=True)
    risk_score = Column(Float, nullable=False)
    description = Column(Text)
    evidence = Column(Text)  # JSON: list of event_ids and details
    status = Column(String(20), default="open", index=True)  # open, investigating, resolved, false_positive
    resolved_by = Column(String(40))
    resolved_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)


class UserBaseline(Base):
    __tablename__ = "user_baselines"

    user = Column(String(40), primary_key=True)
    baseline_data = Column(Text)  # JSON: statistical profile
    event_count = Column(Integer, default=0)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    last_updated = Column(DateTime, default=datetime.utcnow)


class StorageBackend:
    """Async storage backend supporting SQLite and PostgreSQL."""

    def __init__(self, config: dict):
        storage_cfg = config.get("storage", {})
        backend = storage_cfg.get("backend", "sqlite")

        if backend == "sqlite":
            db_path = storage_cfg.get("sqlite_path", "./data/sapshield.db")
            os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
            self.db_url = f"sqlite+aiosqlite:///{db_path}"
        elif backend == "postgresql":
            pg = storage_cfg.get("postgresql", {})
            self.db_url = (
                f"postgresql+asyncpg://{pg.get('user')}:{pg.get('password')}"
                f"@{pg.get('host', 'localhost')}:{pg.get('port', 5432)}"
                f"/{pg.get('database', 'sapshield')}"
            )
        else:
            raise ValueError(f"Unsupported storage backend: {backend}")

        self.engine = create_async_engine(self.db_url, echo=False)
        self.async_session = sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

    async def initialize(self) -> None:
        """Create tables if they don't exist."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info(f"Storage initialized: {self.db_url}")

    async def store_events(self, events: list) -> int:
        """Store a batch of SAPEvent objects."""
        async with self.async_session() as session:
            async with session.begin():
                for event in events:
                    record = EventRecord(
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        user=event.user,
                        event_type=event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type),
                        transaction=event.transaction,
                        program=event.program,
                        table_name=event.table_name,
                        record_count=event.record_count,
                        client=event.client,
                        terminal=event.terminal,
                        source_ip=event.source_ip,
                        data_sensitivity=event.data_sensitivity,
                        raw_data=json.dumps(event.raw_data),
                    )
                    await session.merge(record)
        return len(events)

    async def store_alert(self, alert: dict) -> None:
        """Store a detection alert."""
        async with self.async_session() as session:
            async with session.begin():
                record = AlertRecord(
                    alert_id=alert["alert_id"],
                    timestamp=alert["timestamp"],
                    user=alert["user"],
                    rule_id=alert["rule_id"],
                    rule_name=alert.get("rule_name", ""),
                    severity=alert.get("severity", "medium"),
                    risk_score=alert["risk_score"],
                    description=alert.get("description", ""),
                    evidence=json.dumps(alert.get("evidence", [])),
                )
                await session.merge(record)

    async def get_events(
        self,
        user: Optional[str] = None,
        since: Optional[datetime] = None,
        event_type: Optional[str] = None,
        limit: int = 500,
    ) -> list[dict]:
        """Query stored events with optional filters."""
        async with self.async_session() as session:
            query = sa.select(EventRecord).order_by(EventRecord.timestamp.desc())

            if user:
                query = query.where(EventRecord.user == user)
            if since:
                query = query.where(EventRecord.timestamp >= since)
            if event_type:
                query = query.where(EventRecord.event_type == event_type)

            query = query.limit(limit)
            result = await session.execute(query)
            rows = result.scalars().all()

            return [
                {
                    "event_id": r.event_id,
                    "timestamp": r.timestamp.isoformat(),
                    "user": r.user,
                    "event_type": r.event_type,
                    "transaction": r.transaction,
                    "table_name": r.table_name,
                    "record_count": r.record_count,
                    "data_sensitivity": r.data_sensitivity,
                    "source_ip": r.source_ip,
                }
                for r in rows
            ]

    async def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        user: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query alerts with optional filters."""
        async with self.async_session() as session:
            query = sa.select(AlertRecord).order_by(AlertRecord.timestamp.desc())

            if status:
                query = query.where(AlertRecord.status == status)
            if severity:
                query = query.where(AlertRecord.severity == severity)
            if user:
                query = query.where(AlertRecord.user == user)

            query = query.limit(limit)
            result = await session.execute(query)
            rows = result.scalars().all()

            return [
                {
                    "alert_id": r.alert_id,
                    "timestamp": r.timestamp.isoformat(),
                    "user": r.user,
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "severity": r.severity,
                    "risk_score": r.risk_score,
                    "description": r.description,
                    "evidence": json.loads(r.evidence) if r.evidence else [],
                    "status": r.status,
                }
                for r in rows
            ]

    async def update_alert_status(
        self, alert_id: str, status: str, resolved_by: Optional[str] = None
    ) -> bool:
        async with self.async_session() as session:
            async with session.begin():
                result = await session.execute(
                    sa.select(AlertRecord).where(AlertRecord.alert_id == alert_id)
                )
                alert = result.scalar_one_or_none()
                if not alert:
                    return False
                alert.status = status
                if resolved_by:
                    alert.resolved_by = resolved_by
                    alert.resolved_at = datetime.utcnow()
                return True

    async def get_user_baseline(self, user: str) -> Optional[dict]:
        async with self.async_session() as session:
            result = await session.execute(
                sa.select(UserBaseline).where(UserBaseline.user == user)
            )
            row = result.scalar_one_or_none()
            if row:
                return {
                    "user": row.user,
                    "baseline_data": json.loads(row.baseline_data) if row.baseline_data else {},
                    "event_count": row.event_count,
                    "first_seen": row.first_seen.isoformat() if row.first_seen else None,
                    "last_seen": row.last_seen.isoformat() if row.last_seen else None,
                }
            return None

    async def save_user_baseline(self, user: str, baseline: dict) -> None:
        async with self.async_session() as session:
            async with session.begin():
                record = UserBaseline(
                    user=user,
                    baseline_data=json.dumps(baseline.get("baseline_data", {})),
                    event_count=baseline.get("event_count", 0),
                    first_seen=baseline.get("first_seen"),
                    last_seen=baseline.get("last_seen"),
                    last_updated=datetime.utcnow(),
                )
                await session.merge(record)

    async def get_dashboard_stats(self) -> dict:
        """Get summary statistics for the dashboard."""
        async with self.async_session() as session:
            # Total events
            total_events = await session.execute(
                sa.select(sa.func.count(EventRecord.event_id))
            )
            # Total alerts
            total_alerts = await session.execute(
                sa.select(sa.func.count(AlertRecord.alert_id))
            )
            # Open alerts
            open_alerts = await session.execute(
                sa.select(sa.func.count(AlertRecord.alert_id)).where(
                    AlertRecord.status == "open"
                )
            )
            # Critical alerts
            critical_alerts = await session.execute(
                sa.select(sa.func.count(AlertRecord.alert_id)).where(
                    AlertRecord.severity == "critical"
                )
            )
            # Unique users
            unique_users = await session.execute(
                sa.select(sa.func.count(sa.distinct(EventRecord.user)))
            )

            return {
                "total_events": total_events.scalar() or 0,
                "total_alerts": total_alerts.scalar() or 0,
                "open_alerts": open_alerts.scalar() or 0,
                "critical_alerts": critical_alerts.scalar() or 0,
                "unique_users": unique_users.scalar() or 0,
            }

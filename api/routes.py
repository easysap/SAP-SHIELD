"""API route definitions."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel

router = APIRouter()

# These will be injected by the app
_storage = None
_detection = None
_pipeline = None


def init_routes(storage, detection, pipeline):
    global _storage, _detection, _pipeline
    _storage = storage
    _detection = detection
    _pipeline = pipeline


# --- Response Models ---

class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    pipeline: dict
    detection: dict


class StatsResponse(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    unique_users: int


class AlertUpdate(BaseModel):
    status: str  # open, investigating, resolved, false_positive
    resolved_by: Optional[str] = None


# --- Endpoints ---

@router.get("/health", response_model=HealthResponse)
async def health():
    """System health check."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        uptime_seconds=0,
        pipeline=_pipeline.stats if _pipeline else {},
        detection=_detection.stats if _detection else {},
    )


@router.get("/stats")
async def dashboard_stats():
    """Get dashboard summary statistics."""
    if not _storage:
        raise HTTPException(status_code=503, detail="Storage not initialized")
    return await _storage.get_dashboard_stats()


@router.get("/alerts")
async def list_alerts(
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    user: Optional[str] = Query(None, description="Filter by username"),
    limit: int = Query(100, ge=1, le=1000),
):
    """List detection alerts with optional filters."""
    if not _storage:
        raise HTTPException(status_code=503, detail="Storage not initialized")
    return await _storage.get_alerts(
        status=status, severity=severity, user=user, limit=limit
    )


@router.patch("/alerts/{alert_id}")
async def update_alert(alert_id: str, update: AlertUpdate):
    """Update alert status (investigate, resolve, mark false positive)."""
    if not _storage:
        raise HTTPException(status_code=503, detail="Storage not initialized")

    success = await _storage.update_alert_status(
        alert_id=alert_id,
        status=update.status,
        resolved_by=update.resolved_by,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "updated", "alert_id": alert_id}


@router.get("/events")
async def list_events(
    user: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    since: Optional[str] = Query(None, description="ISO datetime"),
    limit: int = Query(500, ge=1, le=5000),
):
    """Query stored events."""
    if not _storage:
        raise HTTPException(status_code=503, detail="Storage not initialized")

    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid datetime format")

    return await _storage.get_events(
        user=user, since=since_dt, event_type=event_type, limit=limit
    )


@router.get("/users/{username}/baseline")
async def get_user_baseline(username: str):
    """Get a user's behavioral baseline profile."""
    if not _detection:
        raise HTTPException(status_code=503, detail="Detection not initialized")

    profile = _detection.baseline.get_profile(username)
    if not profile:
        raise HTTPException(status_code=404, detail="No baseline for this user")

    return profile.to_dict()


@router.get("/users/{username}/risk")
async def get_user_risk(username: str):
    """Get current risk assessment for a user."""
    if not _storage or not _detection:
        raise HTTPException(status_code=503, detail="System not initialized")

    profile = _detection.baseline.get_profile(username)
    alerts = await _storage.get_alerts(user=username, status="open", limit=20)

    risk_score = 0.0
    if alerts:
        risk_score = max(a["risk_score"] for a in alerts)

    return {
        "user": username,
        "risk_score": risk_score,
        "open_alerts": len(alerts),
        "is_baselined": _detection.baseline.is_baselined(username),
        "event_count": profile.event_count if profile else 0,
        "recent_alerts": alerts[:5],
    }

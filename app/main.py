from pathlib import Path
import os
from typing import Literal, Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.database import (
    initialize_database,
    get_dashboard_summary,
    get_recent_traffic,
    get_recent_alerts,
    get_all_devices,
    get_recent_system_events,
    get_alert_by_id,
    update_alert_status,
    get_alert_activity,
    get_dashboard_analytics,
    get_packet_stats,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = BASE_DIR / "dashboard"

app = FastAPI(
    title="Embedded Linux Network IDS",
    description="Network Security Monitoring and Intrusion Detection API",
    version="2.1.0"
)


class AlertStatusUpdate(BaseModel):
    status: Literal[
        "NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"
    ]
    actor: str = Field(default="analyst", min_length=1, max_length=80)
    notes: Optional[str] = None
    resolution: Optional[str] = None


@app.on_event("startup")
def startup_event():
    initialize_database()


app.mount(
    "/static",
    StaticFiles(directory=str(DASHBOARD_DIR)),
    name="static"
)


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/api/packet-stats")
def packet_stats():
    return get_packet_stats()


@app.get("/api/summary")
def dashboard_summary():
    return get_dashboard_summary()


@app.get("/api/analytics")
def dashboard_analytics():
    return get_dashboard_analytics()


@app.get("/api/traffic")
def traffic_data(limit: int = Query(default=50, ge=1, le=500)):
    return get_recent_traffic(limit)


@app.get("/api/alerts")
def alert_data(
    limit: int = Query(default=50, ge=1, le=500),
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
):
    alerts = get_recent_alerts(limit)

    if status:
        alerts = [
            alert for alert in alerts
            if alert.get("status", "").upper() == status.upper()
        ]

    if severity:
        alerts = [
            alert for alert in alerts
            if alert.get("severity", "").upper() == severity.upper()
        ]

    return alerts


@app.get("/api/alerts/{alert_id}")
def alert_detail(alert_id: int):
    alert = get_alert_by_id(alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return alert


@app.patch("/api/alerts/{alert_id}/status")
def change_alert_status(
    alert_id: int,
    update: AlertStatusUpdate
):
    try:
        alert = update_alert_status(
            alert_id=alert_id,
            status=update.status,
            actor=update.actor,
            notes=update.notes,
            resolution=update.resolution,
        )

        if alert is None:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        return {
            "message": "Alert status updated successfully",
            "alert": alert
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.get("/api/alerts/{alert_id}/activity")
def alert_activity(alert_id: int):
    alert = get_alert_by_id(alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return get_alert_activity(alert_id)


@app.get("/api/devices")
def device_data():
    return get_all_devices()


@app.get("/api/events")
def event_data(limit: int = Query(default=50, ge=1, le=500)):
    return get_recent_system_events(limit)


@app.get("/api/system-status")
def system_status():
    """Report local service state without inferring it from old log entries."""
    capture_running = False
    proc = Path("/proc")
    if proc.exists():
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                command = (entry / "cmdline").read_bytes().replace(b"\\x00", b" ").decode(errors="ignore")
                if "app.capture" in command and int(entry.name) != os.getpid():
                    capture_running = True
                    break
            except (OSError, ValueError):
                continue
    return {
        "api": "operational",
        "capture_running": capture_running,
        "detection_engine": "available",
        "database": "connected"
    }

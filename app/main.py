


from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.database import (
    initialize_database,
    get_dashboard_summary,
    get_recent_traffic,
    get_recent_alerts,
    get_all_devices,
    get_recent_system_events
)

BASE_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = BASE_DIR / "dashboard"

app = FastAPI(
    title="Embedded Linux Network IDS",
    description="Network Security Monitoring and Intrusion Detection API",
    version="1.0.0"
)


@app.on_event("startup")
def startup_event():
    initialize_database()


# Serve dashboard CSS and JavaScript
app.mount(
    "/static",
    StaticFiles(directory=str(DASHBOARD_DIR)),
    name="static"
)


# Serve dashboard homepage
@app.get("/", include_in_schema=False)
def home():
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.get("/api/summary")
def dashboard_summary():
    return get_dashboard_summary()


@app.get("/api/traffic")
def traffic_data(limit: int = Query(default=50, ge=1, le=500)):
    return get_recent_traffic(limit)


@app.get("/api/alerts")
def alert_data(limit: int = Query(default=50, ge=1, le=500)):
    return get_recent_alerts(limit)


@app.get("/api/devices")
def device_data():
    return get_all_devices()


@app.get("/api/events")
def event_data(limit: int = Query(default=50, ge=1, le=500)):
    return get_recent_system_events(limit)


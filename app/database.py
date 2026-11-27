

import sqlite3
import json
from pathlib import Path
from datetime import datetime

# Database location
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "traffic.db"


def get_connection():
    """Create a connection to the SQLite database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    connection = get_connection()

    try:
        cursor = connection.cursor()

        # Traffic table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                src_port TEXT,
                dst_port TEXT,
                tcp_flags TEXT,
                packet_length INTEGER
            )
        """)

        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL
            )
        """)

        # Devices table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                mac_address TEXT,
                hostname TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)

        # System events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)

        # Live packet counters for the current capture session
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packet_stats (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                packets_received INTEGER NOT NULL DEFAULT 0,
                packets_examined INTEGER NOT NULL DEFAULT 0,
                capture_started_at TEXT
            )
        """)

        cursor.execute("""
            INSERT OR IGNORE INTO packet_stats
                (id, packets_received, packets_examined, capture_started_at)
            VALUES (1, 0, 0, NULL)
        """)

        connection.commit()

    finally:
        connection.close()

    print(f"Database initialized: {DB_PATH}") 



def insert_packet(packet_data):
    """Insert one captured packet into the database."""
    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO traffic (
                timestamp, src_ip, dst_ip, protocol,
                src_port, dst_port, tcp_flags, packet_length
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            packet_data["timestamp"],
            packet_data["src_ip"],
            packet_data["dst_ip"],
            packet_data["protocol"],
            str(packet_data["src_port"]),
            str(packet_data["dst_port"]),
            packet_data["tcp_flags"],
            packet_data["packet_length"]
        ))

        cursor.execute("""
            UPDATE packet_stats
            SET packets_received = packets_received + 1
            WHERE id = 1
        """)

        connection.commit()

    finally:
        connection.close()


def reset_packet_stats():
    """Start a new capture session with zeroed packet counters."""
    connection = get_connection()
    try:
        connection.execute("""
            UPDATE packet_stats
            SET packets_received = 0,
                packets_examined = 0,
                capture_started_at = ?
            WHERE id = 1
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))
        connection.commit()
    finally:
        connection.close()


def increment_packets_examined():
    """Increment the number of packets successfully examined by the IDS."""
    connection = get_connection()
    try:
        connection.execute("""
            UPDATE packet_stats
            SET packets_examined = packets_examined + 1
            WHERE id = 1
        """)
        connection.commit()
    finally:
        connection.close()


def get_packet_stats():
    """Return packet counters for the current capture session."""
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT packets_received, packets_examined, capture_started_at
            FROM packet_stats
            WHERE id = 1
        """).fetchone()

        if row is None:
            return {
                "packets_received": 0,
                "packets_examined": 0,
                "examination_rate": 0.0,
                "capture_started_at": None
            }

        received = row["packets_received"]
        examined = row["packets_examined"]
        rate = (examined / received * 100) if received else 0.0

        return {
            "packets_received": received,
            "packets_examined": examined,
            "examination_rate": round(rate, 2),
            "capture_started_at": row["capture_started_at"]
        }
    finally:
        connection.close()


def insert_alert(alert_data):
    """Insert an IDS alert with evidence and lifecycle metadata."""
    connection = get_connection()

    try:
        cursor = connection.cursor()
        timestamp = alert_data["timestamp"]

        evidence = alert_data.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}

        cursor.execute("""
            INSERT INTO alerts (
                timestamp, source_ip, destination_ip,
                alert_type, severity, description,
                status, evidence_json, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'NEW', ?, ?)
        """, (
            timestamp,
            alert_data["source_ip"],
            alert_data["destination_ip"],
            alert_data["alert_type"],
            alert_data["severity"],
            alert_data["description"],
            json.dumps(evidence),
            timestamp
        ))

        alert_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO alert_activity
                (alert_id, timestamp, actor, action, details)
            VALUES (?, ?, 'SYSTEM', 'CREATED', ?)
        """, (
            alert_id,
            timestamp,
            "Alert generated by IDS detection engine"
        ))

        connection.commit()
        return alert_id

    finally:
        connection.close()


def get_alert_by_id(alert_id):
    """Retrieve one alert with decoded evidence and its activity."""
    connection = get_connection()

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()

        if row is None:
            return None

        alert = dict(row)

        try:
            alert["evidence"] = json.loads(
                alert.get("evidence_json") or "{}"
            )
        except (TypeError, json.JSONDecodeError):
            alert["evidence"] = {}

        cursor.execute("""
            SELECT id, timestamp, actor, action, details
            FROM alert_activity
            WHERE alert_id = ?
            ORDER BY id DESC
        """, (alert_id,))

        alert["activity"] = [
            dict(item) for item in cursor.fetchall()
        ]

        return alert

    finally:
        connection.close()


def update_alert_status(
    alert_id,
    status,
    actor="analyst",
    notes=None,
    resolution=None
):
    """Update an alert lifecycle state and record the action."""

    allowed_statuses = {
        "NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"
    }

    if status not in allowed_statuses:
        raise ValueError("Invalid alert status")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,)
        )

        existing = cursor.fetchone()
        if existing is None:
            return None

        if status == "RESOLVED" and not resolution:
            raise ValueError("A resolution description is required")

        cursor.execute("""
            UPDATE alerts
            SET status = ?,
                acknowledged_at = CASE
                    WHEN ? IN ('ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED')
                    THEN COALESCE(acknowledged_at, ?)
                    ELSE acknowledged_at
                END,
                acknowledged_by = CASE
                    WHEN ? IN ('ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED')
                    THEN COALESCE(acknowledged_by, ?)
                    ELSE acknowledged_by
                END,
                investigation_notes = CASE
                    WHEN ? IS NOT NULL THEN ?
                    ELSE investigation_notes
                END,
                resolved_at = CASE
                    WHEN ? = 'RESOLVED' THEN ?
                    ELSE resolved_at
                END,
                resolved_by = CASE
                    WHEN ? = 'RESOLVED' THEN ?
                    ELSE resolved_by
                END,
                resolution = CASE
                    WHEN ? IS NOT NULL THEN ?
                    ELSE resolution
                END,
                updated_at = ?
            WHERE id = ?
        """, (
            status,
            status, timestamp,
            status, actor,
            notes, notes,
            status, timestamp,
            status, actor,
            resolution, resolution,
            timestamp,
            alert_id
        ))

        cursor.execute("""
            INSERT INTO alert_activity
                (alert_id, timestamp, actor, action, details)
            VALUES (?, ?, ?, ?, ?)
        """, (
            alert_id,
            timestamp,
            actor,
            status,
            resolution or notes or f"Status changed to {status}"
        ))

        connection.commit()
        return get_alert_by_id(alert_id)

    finally:
        connection.close()


def get_alert_activity(alert_id):
    """Retrieve the audit history for one alert."""
    connection = get_connection()

    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT id, alert_id, timestamp, actor, action, details
            FROM alert_activity
            WHERE alert_id = ?
            ORDER BY id DESC
        """, (alert_id,))

        return [dict(row) for row in cursor.fetchall()]

    finally:
        connection.close()


def update_device(ip_address, mac_address=None, hostname=None):
    """Insert a new device or update an existing device's last_seen."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO devices (
                ip_address,
                mac_address,
                hostname,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?)

            ON CONFLICT(ip_address)
            DO UPDATE SET
                mac_address = COALESCE(
                    excluded.mac_address,
                    devices.mac_address
                ),
                hostname = COALESCE(
                    excluded.hostname,
                    devices.hostname
                ),
                last_seen = excluded.last_seen
        """, (
            ip_address,
            mac_address,
            hostname,
            timestamp,
            timestamp
        ))

        connection.commit()

    finally:
        connection.close()


def log_system_event(event_type, severity, message):
    """Store a system event in the database."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO system_events (
                timestamp,
                event_type,
                severity,
                message
            )
            VALUES (?, ?, ?, ?)
        """, (
            timestamp,
            event_type,
            severity,
            message
        ))

        connection.commit()

    finally:
        connection.close()



def get_recent_traffic(limit=50):
    """Retrieve the most recently captured packets."""
    connection = get_connection()

    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT * FROM traffic
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        return [dict(row) for row in cursor.fetchall()]

    finally:
        connection.close()


def get_recent_alerts(limit=50):
    """Retrieve the most recent IDS alerts."""
    connection = get_connection()

    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT * FROM alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        alerts = [dict(row) for row in cursor.fetchall()]

        for alert in alerts:
            try:
                alert["evidence"] = json.loads(
                    alert.get("evidence_json") or "{}"
                )
            except (TypeError, json.JSONDecodeError):
                alert["evidence"] = {}

        return alerts

    finally:
        connection.close()


def get_all_devices():
    """Retrieve all discovered network devices."""
    connection = get_connection()

    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT * FROM devices
            ORDER BY last_seen DESC
        """)

        return [dict(row) for row in cursor.fetchall()]

    finally:
        connection.close()


def get_recent_system_events(limit=50):
    """Retrieve the most recent system events."""
    connection = get_connection()

    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT * FROM system_events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        return [dict(row) for row in cursor.fetchall()]

    finally:
        connection.close()


def get_dashboard_summary():
    """Retrieve overall database statistics."""
    connection = get_connection()

    try:
        cursor = connection.cursor()

        summary = {}

        tables = {
            "total_packets": "traffic",
            "total_alerts": "alerts",
            "total_devices": "devices",
            "total_system_events": "system_events"
        }

        for key, table in tables.items():
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            summary[key] = cursor.fetchone()[0]

        return summary

    finally:
        connection.close()


def get_dashboard_analytics():
    """Return aggregate values used by the SOC dashboard."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        severity_rows = cursor.execute(
            "SELECT UPPER(severity) AS severity, COUNT(*) AS count "
            "FROM alerts GROUP BY UPPER(severity)"
        ).fetchall()
        status_rows = cursor.execute(
            "SELECT UPPER(COALESCE(status, 'NEW')) AS status, COUNT(*) AS count "
            "FROM alerts GROUP BY UPPER(COALESCE(status, 'NEW'))"
        ).fetchall()
        protocol_rows = cursor.execute(
            "SELECT UPPER(protocol) AS protocol, COUNT(*) AS count "
            "FROM (SELECT protocol FROM traffic ORDER BY id DESC LIMIT 1000) "
            "GROUP BY UPPER(protocol)"
        ).fetchall()
        top_sources = cursor.execute(
            "SELECT source_ip, COUNT(*) AS count "
            "FROM alerts GROUP BY source_ip ORDER BY count DESC LIMIT 5"
        ).fetchall()
        recent_alert_count = cursor.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE datetime(timestamp) >= datetime('now', 'localtime', '-24 hours')"
        ).fetchone()[0]
        total_alerts = cursor.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]
        critical_high = cursor.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE UPPER(severity) IN ('CRITICAL', 'HIGH') "
            "AND UPPER(COALESCE(status, 'NEW')) != 'RESOLVED'"
        ).fetchone()[0]
        open_incidents = cursor.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE UPPER(COALESCE(status, 'NEW')) != 'RESOLVED'"
        ).fetchone()[0]
        new_alerts = cursor.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE UPPER(COALESCE(status, 'NEW')) = 'NEW'"
        ).fetchone()[0]
        return {
            "severity": {row["severity"]: row["count"] for row in severity_rows},
            "status": {row["status"]: row["count"] for row in status_rows},
            "protocols": {row["protocol"]: row["count"] for row in protocol_rows},
            "top_sources": [dict(row) for row in top_sources],
            "alerts_last_24h": recent_alert_count,
            "total_alerts": total_alerts,
            "critical_high_open": critical_high,
            "open_incidents": open_incidents,
            "new_alerts": new_alerts,
            "threats_blocked": 0
        }
    finally:
        connection.close()

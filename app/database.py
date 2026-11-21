

import sqlite3
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

        connection.commit()

    finally:
        connection.close()



def insert_alert(alert_data):
    """Insert an IDS alert into the database."""
    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO alerts (
                timestamp,
                source_ip,
                destination_ip,
                alert_type,
                severity,
                description
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            alert_data["timestamp"],
            alert_data["source_ip"],
            alert_data["destination_ip"],
            alert_data["alert_type"],
            alert_data["severity"],
            alert_data["description"]
        ))

        connection.commit()

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

        return [dict(row) for row in cursor.fetchall()]

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

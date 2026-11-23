
import sqlite3

DB_NAME = "network_discovery.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            status TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            severity TEXT,
            message TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            service TEXT,
            version TEXT,
            risk TEXT,
            scan_time TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def save_device(device):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO devices
        (ip, mac, hostname, status, first_seen, last_seen)
        VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
        ON CONFLICT(ip) DO UPDATE SET
        mac=excluded.mac,
        hostname=excluded.hostname,
        status=excluded.status,
        last_seen=datetime('now')
    """, (
        device.get("ip"),
        device.get("mac"),
        device.get("hostname"),
        device.get("status")
    ))

    conn.commit()
    conn.close()


def save_alert(alert):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (time, severity, message)
        VALUES (?, ?, ?)
    """, (
        alert.get("time"),
        alert.get("severity"),
        alert.get("message")
    ))

    conn.commit()
    conn.close()


def save_port_scan(ip, port, service, version, risk):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO port_scans
        (ip, port, service, version, risk)
        VALUES (?, ?, ?, ?, ?)
    """, (ip, port, service, version, risk))

    conn.commit()
    conn.close()


def get_port_scans():
    conn = get_connection()
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT * FROM port_scans
        ORDER BY id DESC
    """).fetchall()

    conn.close()
    return [dict(row) for row in rows]


def get_devices():
    conn = get_connection()
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT * FROM devices ORDER BY last_seen DESC
    """).fetchall()

    conn.close()
    return [dict(row) for row in rows]


def get_alerts():
    conn = get_connection()
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT * FROM alerts ORDER BY id DESC
    """).fetchall()

    conn.close()
    return [dict(row) for row in rows]

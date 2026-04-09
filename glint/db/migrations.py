import sqlite3


def create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS scans (
            id              TEXT PRIMARY KEY,
            created_at      TEXT NOT NULL,
            ip_address      TEXT NOT NULL,
            user_agent      TEXT NOT NULL,
            composite_score REAL NOT NULL,
            risk_level      TEXT NOT NULL,
            raw_payload     TEXT NOT NULL,
            result_json     TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id          TEXT PRIMARY KEY,
            scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            dimension   TEXT NOT NULL,
            severity    TEXT NOT NULL,
            finding_key TEXT NOT NULL,
            title       TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence    TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
    """)
    conn.commit()

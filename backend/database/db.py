import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "cybercheck.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                normalized_url TEXT,
                domain TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                findings_json TEXT,
                impersonated_brand TEXT,
                source TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

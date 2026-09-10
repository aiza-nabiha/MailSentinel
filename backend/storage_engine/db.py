"""
backend/storage_engine/db.py

Single shared entry point for opening the database. Every other
script (ingest.py, integrate.py, and later Person 4/5 code) should
import get_connection() from here instead of calling sqlite3.connect
directly -- keeps the schema application in exactly one place.
"""

import sqlite3
from pathlib import Path

THIS_DIR = Path(__file__).parent
SCHEMA_PATH = THIS_DIR / "schema.sql"

# Default DB location: backend/storage_engine/phishing.db
DEFAULT_DB_PATH = THIS_DIR / "phishing.db"


def get_connection(db_path=None):
    """Opens (and creates if needed) the SQLite DB, applying schema.sql every time.
    CREATE TABLE IF NOT EXISTS means this is safe to call repeatedly."""
    db_path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(str(db_path))
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    return conn


def next_email_id(conn):
    """Assigns email_XXXX sequentially based on current row count."""
    row = conn.execute("SELECT COUNT(*) FROM emails").fetchone()
    return f"email_{row[0] + 1:04d}"


if __name__ == "__main__":
    # Quick smoke test: open the DB, print every table that exists.
    conn = get_connection()
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    print(f"[+] DB ready at {DEFAULT_DB_PATH}")
    print(f"[+] Tables: {[t[0] for t in tables]}")
    conn.close()
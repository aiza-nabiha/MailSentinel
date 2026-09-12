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
    """Assigns email_XXXX sequentially based on current row count.
    NOTE: does not check for duplicates -- use get_or_create_email_id
    instead when ingesting from a file path, to avoid double-counting
    the same .eml as two different emails."""
    row = conn.execute("SELECT COUNT(*) FROM emails").fetchone()
    return f"email_{row[0] + 1:04d}"


def get_or_create_email_id(conn, raw_eml_path):
    """Returns the existing email_id for this exact file path if it was
    already ingested/integrated before, otherwise assigns a new one.
    Prevents the same .eml file from being stored as two separate emails
    when ingest.py and integrate.py both process it."""
    row = conn.execute(
        "SELECT email_id FROM emails WHERE raw_eml_path = ?", (str(raw_eml_path),)
    ).fetchone()
    if row:
        return row[0], True  # (email_id, already_existed)
    return next_email_id(conn), False


def get_or_create_user(conn, user_id):
    """
    Ensures a row exists in `users` for this Gmail address, and updates
    last_seen_at either way. user_id is expected to be the Gmail address
    from the sidebar's Session.getActiveUser().getEmail() call.
    Returns the user_id unchanged (for convenience in calling code).
    """
    if not user_id:
        return None
    row = conn.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row:
        conn.execute("UPDATE users SET last_seen_at = datetime('now') WHERE user_id = ?", (user_id,))
    else:
        conn.execute("INSERT INTO users (user_id) VALUES (?)", (user_id,))
    return user_id


def get_emails_for_user(conn, user_id, limit=50):
    """
    Returns this user's analyzed emails, most recent first -- this is
    what a 'past analyses' view in the sidebar would call.
    """
    return conn.execute(
        """SELECT email_id, subject, from_header, overall_risk_score, verdict, ingested_at
           FROM emails WHERE user_id = ? ORDER BY ingested_at DESC LIMIT ?""",
        (user_id, limit),
    ).fetchall()


def archive_raw_email(conn, email_id, user_id, raw_content, headers_dict):
    """
    Encrypts and permanently stores the full raw email + headers for
    future model retraining. This is separate from the live analysis
    tables (emails, domain_intel, etc.) -- those store DERIVED signals
    for the app to use today; this table stores the RAW material for
    training tomorrow. Requires DB_ENCRYPTION_KEY to be set -- raises
    if encryption isn't configured, rather than silently storing
    raw PII unencrypted.
    """
    from crypto import encrypt_field
    import json

    encrypted_content = encrypt_field(raw_content)
    encrypted_headers = encrypt_field(json.dumps(headers_dict)) if headers_dict else None

    conn.execute(
        """INSERT OR REPLACE INTO raw_email_archive
           (email_id, user_id, encrypted_raw_content, encrypted_headers_json)
           VALUES (?, ?, ?, ?)""",
        (email_id, user_id, encrypted_content, encrypted_headers),
    )


def export_training_corpus(conn, user_id=None, limit=None):
    """
    Decrypts and yields the raw archive for future retraining.
    Pass user_id to export just one user's data, or leave it None
    for the full corpus across all users. This is the ONLY function
    that should ever call decrypt_field on the archive -- keep
    decrypted content out of logs/prints when you use this for real.
    """
    from crypto import decrypt_field
    import json

    query = "SELECT email_id, user_id, encrypted_raw_content, encrypted_headers_json, archived_at FROM raw_email_archive"
    params = ()
    if user_id:
        query += " WHERE user_id = ?"
        params = (user_id,)
    query += " ORDER BY archived_at DESC"
    if limit:
        query += " LIMIT ?"
        params = params + (limit,)

    for row in conn.execute(query, params).fetchall():
        yield {
            "email_id": row[0],
            "user_id": row[1],
            "raw_content": decrypt_field(row[2]),
            "headers": json.loads(decrypt_field(row[3])) if row[3] else None,
            "archived_at": row[4],
        }


if __name__ == "__main__":
    # Quick smoke test: open the DB, print every table that exists.
    conn = get_connection()
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    print(f"[+] DB ready at {DEFAULT_DB_PATH}")
    print(f"[+] Tables: {[t[0] for t in tables]}")
    conn.close()
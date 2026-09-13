import sqlite3
from pathlib import Path

THIS_DIR = Path(__file__).parent
SCHEMA_PATH = THIS_DIR / "schema.sql"
DEFAULT_DB_PATH = THIS_DIR / "phishing.db"

def get_connection(db_path=None):
    db_path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(str(db_path))
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    return conn

def next_email_id(conn):
    row = conn.execute("SELECT COUNT(*) FROM emails").fetchone()
    return f"email_{row[0] + 1:04d}"

def get_or_create_email_id(conn, raw_eml_path):
    row = conn.execute("SELECT email_id FROM emails WHERE raw_eml_path = ?", (str(raw_eml_path),)).fetchone()
    if row:
        return row[0], True
    return next_email_id(conn), False

def get_or_create_user(conn, user_id):
    if not user_id:
        return None
    row = conn.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row:
        conn.execute("UPDATE users SET last_seen_at = datetime('now') WHERE user_id = ?", (user_id,))
    else:
        conn.execute("INSERT INTO users (user_id) VALUES (?)", (user_id,))
    return user_id

def get_emails_for_user(conn, user_id, limit=50):
    return conn.execute(
        """SELECT email_id, subject, from_header, overall_risk_score, verdict, ingested_at
           FROM emails WHERE user_id = ? ORDER BY ingested_at DESC LIMIT ?""",
        (user_id, limit),
    ).fetchall()

def archive_raw_email(conn, email_id, user_id, raw_content, headers_dict):
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
            "email_id": row[0], "user_id": row[1], "raw_content": decrypt_field(row[2]),
            "headers": json.loads(decrypt_field(row[3])) if row[3] else None, "archived_at": row[4],
        }

def log_access(conn, endpoint, user_id, ip_address, status_code, detail=None, email_id=None):
    conn.execute(
        """INSERT INTO access_log (endpoint, email_id, user_id, ip_address, status_code, detail)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (endpoint, email_id, user_id, ip_address, status_code, detail),
    )
    conn.commit()


def get_trigger_metadata(conn, email_id):
    """
    Returns who triggered this specific investigation's analysis --
    the Gmail account (user_id), the requester's IP address, and when.
    This is the audit trail for "who ran this and from where," kept
    separate from the analysis results themselves.
    """
    return conn.execute(
        """SELECT user_id, ip_address, logged_at FROM access_log
           WHERE email_id = ? AND endpoint = '/analyze' AND status_code = 200
           ORDER BY logged_at ASC LIMIT 1""",
        (email_id,),
    ).fetchone()


def get_raw_archive_for_email(conn, email_id):
    """
    Decrypts and returns the ONE archived raw email + headers for a
    single email_id -- used when a report needs to show its own full
    original content, as opposed to export_training_corpus() which
    bulk-exports many records for retraining. Returns None if nothing
    is archived for this email_id.
    """
    from crypto import decrypt_field
    import json
    row = conn.execute(
        "SELECT encrypted_raw_content, encrypted_headers_json FROM raw_email_archive WHERE email_id = ?",
        (email_id,),
    ).fetchone()
    if not row:
        return None
    return {
        "raw_content": decrypt_field(row[0]),
        "headers": json.loads(decrypt_field(row[1])) if row[1] else None,
    }
"""
backend/storage_engine/db.py

POSTGRES VERSION -- was SQLite (sqlite3 stdlib). Connects via
DATABASE_URL instead of a file path.

A ConnWrapper class keeps the exact same call shape the rest of the
codebase already uses everywhere -- conn.execute(sql, params).fetchone()
/ .fetchall() -- so api.py, integrate.py, ingest.py and
threat_correlation_engine.py didn't need a full rewrite of every call
site, just their SQL placeholders (? -> %s) and a couple of
SQLite-only constructs (INSERT OR REPLACE, datetime('now')).
"""

import os
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

load_dotenv()

THIS_DIR = Path(__file__).parent
SCHEMA_PATH = THIS_DIR / "schema.sql"

DATABASE_URL = os.environ.get("DATABASE_URL")


class ConnWrapper:
    """
    Thin adapter over a real psycopg2 connection so call sites can
    keep doing conn.execute(sql, params).fetchone()/.fetchall(), the
    same shape sqlite3.Connection.execute() gave them. Every call
    opens a fresh cursor -- fine at this app's scale (one connection
    per request, short-lived).
    """

    def __init__(self, pg_conn):
        self._conn = pg_conn

    def execute(self, sql, params=None):
        cur = self._conn.cursor()
        cur.execute(sql, params or ())
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def cursor(self):
        return self._conn.cursor()


def get_connection(db_path=None):
    """
    db_path is kept as a parameter for backward compatibility with
    call sites that still pass one (old --db CLI flags, the
    migration script pointing at a specific URL) -- if given, it's
    used AS the Postgres connection string instead of DATABASE_URL.
    A bare SQLite file path here will simply fail to connect; there
    is no SQLite fallback anymore.
    """
    url = db_path or DATABASE_URL
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set in .env -- cannot connect to Postgres.\n"
            "Add a line like:\n"
            "  DATABASE_URL=postgresql://user:password@host:5432/mailsentinel"
        )

    pg_conn = psycopg2.connect(url)
    with pg_conn.cursor() as cur:
        with open(SCHEMA_PATH) as f:
            cur.execute(f.read())
    pg_conn.commit()

    return ConnWrapper(pg_conn)


def next_email_id(conn):
    row = conn.execute("SELECT COUNT(*) FROM emails").fetchone()
    return f"email_{row[0] + 1:04d}"


def get_or_create_email_id(conn, raw_eml_path):
    row = conn.execute(
        "SELECT email_id FROM emails WHERE raw_eml_path = %s", (str(raw_eml_path),)
    ).fetchone()
    if row:
        return row[0], True
    return next_email_id(conn), False


def get_or_create_user(conn, user_id):
    if not user_id:
        return None
    row = conn.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,)).fetchone()
    if row:
        conn.execute("UPDATE users SET last_seen_at = now() WHERE user_id = %s", (user_id,))
    else:
        conn.execute("INSERT INTO users (user_id) VALUES (%s)", (user_id,))
    return user_id


def get_emails_for_user(conn, user_id, limit=50):
    return conn.execute(
        """SELECT email_id, subject, from_header, overall_risk_score, verdict, ingested_at
           FROM emails WHERE user_id = %s ORDER BY ingested_at DESC LIMIT %s""",
        (user_id, limit),
    ).fetchall()


def archive_raw_email(conn, email_id, user_id, raw_content, headers_dict):
    from crypto import encrypt_field
    import json
    encrypted_content = encrypt_field(raw_content)
    encrypted_headers = encrypt_field(json.dumps(headers_dict)) if headers_dict else None
    conn.execute(
        """INSERT INTO raw_email_archive
               (email_id, user_id, encrypted_raw_content, encrypted_headers_json)
           VALUES (%s, %s, %s, %s)
           ON CONFLICT (email_id) DO UPDATE SET
               user_id = EXCLUDED.user_id,
               encrypted_raw_content = EXCLUDED.encrypted_raw_content,
               encrypted_headers_json = EXCLUDED.encrypted_headers_json,
               archived_at = now()""",
        (email_id, user_id, encrypted_content, encrypted_headers),
    )


def export_training_corpus(conn, user_id=None, limit=None):
    from crypto import decrypt_field
    import json
    query = "SELECT email_id, user_id, encrypted_raw_content, encrypted_headers_json, archived_at FROM raw_email_archive"
    params = []
    if user_id:
        query += " WHERE user_id = %s"
        params.append(user_id)
    query += " ORDER BY archived_at DESC"
    if limit:
        query += " LIMIT %s"
        params.append(limit)
    for row in conn.execute(query, tuple(params)).fetchall():
        yield {
            "email_id": row[0], "user_id": row[1], "raw_content": decrypt_field(row[2]),
            "headers": json.loads(decrypt_field(row[3])) if row[3] else None, "archived_at": row[4],
        }


def log_access(conn, endpoint, user_id, ip_address, status_code, detail=None, email_id=None):
    conn.execute(
        """INSERT INTO access_log (endpoint, email_id, user_id, ip_address, status_code, detail)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (endpoint, email_id, user_id, ip_address, status_code, detail),
    )
    conn.commit()


def get_trigger_metadata(conn, email_id):
    """
    Returns who triggered this specific investigation's analysis --
    the Gmail account (user_id), the requester's IP address, and when.
    """
    return conn.execute(
        """SELECT user_id, ip_address, logged_at FROM access_log
           WHERE email_id = %s AND endpoint = '/analyze' AND status_code = 200
           ORDER BY logged_at ASC LIMIT 1""",
        (email_id,),
    ).fetchone()


def get_raw_archive_for_email(conn, email_id):
    """
    Decrypts and returns the ONE archived raw email + headers for a
    single email_id. Returns None if nothing is archived for it.
    """
    from crypto import decrypt_field
    import json
    row = conn.execute(
        "SELECT encrypted_raw_content, encrypted_headers_json FROM raw_email_archive WHERE email_id = %s",
        (email_id,),
    ).fetchone()
    if not row:
        return None
    return {
        "raw_content": decrypt_field(row[0]),
        "headers": json.loads(decrypt_field(row[1])) if row[1] else None,
    }
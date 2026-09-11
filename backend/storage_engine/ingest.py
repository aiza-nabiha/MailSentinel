"""
backend/storage_engine/ingest.py

Bulk-loads every .eml in a directory into the `emails` table with
just the basic headers. This has ZERO dependency on anyone else's
module -- safe to run right now, on any .eml files you have.

Usage (from backend/storage_engine/):
    python ingest.py --eml-dir ../../data/test_emails
"""

import argparse
import email
from email import policy
import os

from db import get_connection, get_or_create_email_id


def parse_basic_headers(filepath):
    with open(filepath, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    return {
        "subject": msg.get("Subject", ""),
        "from_header": msg.get("From", ""),
        "to_header": msg.get("To", ""),
        "date_header": msg.get("Date", ""),
    }


def ingest_dir(eml_dir, db_path=None):
    conn = get_connection(db_path)

    eml_files = sorted(f for f in os.listdir(eml_dir) if f.lower().endswith(".eml"))
    if not eml_files:
        print(f"[!] No .eml files found in {eml_dir}")
        return

    inserted = 0
    for fname in eml_files:
        filepath = os.path.join(eml_dir, fname)
        try:
            fields = parse_basic_headers(filepath)
        except Exception as e:
            print(f"  [skip] {fname}: {e}")
            continue

        email_id, already_existed = get_or_create_email_id(conn, filepath)
        if already_existed:
            print(f"  [skip] {fname} already ingested as {email_id}")
            continue

        conn.execute(
            """INSERT INTO emails (email_id, raw_eml_path, subject, from_header, to_header, date_header)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (email_id, filepath, fields["subject"], fields["from_header"],
             fields["to_header"], fields["date_header"]),
        )
        conn.commit()
        inserted += 1
        print(f"  [ok] {fname} -> {email_id}  (subject: {fields['subject'][:50]!r})")

    print(f"\n[+] Ingested {inserted}/{len(eml_files)} emails")
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--eml-dir", required=True)
    parser.add_argument("--db", default=None)
    args = parser.parse_args()
    ingest_dir(args.eml_dir, args.db)
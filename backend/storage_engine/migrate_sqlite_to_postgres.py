"""
backend/storage_engine/migrate_sqlite_to_postgres.py

ONE-OFF script. Copies every row out of the OLD phishing.db (SQLite)
into the NEW Postgres database, table by table, preserving email_ids
so nothing in the frontend/Gmail add-on breaks.

Does NOT migrate the old campaigns / campaign_members / graph_edges
tables -- that correlation system is retired. After migrating, run
threat_correlation_engine.py once over your migrated data if you want
campaign relationships rebuilt for historical emails (see the note at
the bottom of this file).

Usage (from backend/storage_engine/, after DATABASE_URL is set in .env
and you've run the new schema.sql at least once, e.g. via
`python3 -c "from db import get_connection; get_connection().close()"`):

    python3 migrate_sqlite_to_postgres.py --sqlite phishing.db

Safe to re-run: every insert uses ON CONFLICT DO NOTHING, so already-
migrated rows are skipped, not duplicated.
"""

import argparse
import sqlite3

from db import get_connection


TABLES_IN_DEPENDENCY_ORDER = [
    # (table_name, column_list) -- order matters: FK parents first.
    ("users", ["user_id", "first_seen_at", "last_seen_at"]),
    ("emails", ["email_id", "user_id", "raw_eml_path", "ingested_at", "subject",
                "from_header", "to_header", "date_header", "overall_risk_score",
                "verdict", "campaign_id"]),
    ("classifier_results", ["email_id", "phishing_score", "verdict", "reasons_json",
                             "extracted_urls_json", "source", "url_intelligence_json",
                             "sender_features_json", "email_structure_json"]),
    ("header_results", ["email_id", "spf_result", "spf_domain", "dkim_json",
                         "dmarc_result", "dmarc_domain", "dmarc_policy",
                         "received_chain_json", "raw_auth_results_json"]),
    ("domain_intel", ["email_id", "domain", "age_days", "tls_issuer", "tls_status",
                       "cert_shared_with_json", "found_on_lists_json", "risk_score",
                       "risk_level", "risk_reasons_json", "whois_json", "dns_json",
                       "tls_json", "reputation_json"]),
    ("fingerprints", ["email_id", "structural_hash", "skeleton_type",
                       "typosquat_matches_json", "targeted_brands_json",
                       "style_colors_json", "style_fonts_json", "style_alt_texts_json"]),
    ("infrastructure_risk", ["email_id", "risk_score", "risk_level", "reasons_json",
                              "evidence_json", "reliable_hop_json", "received_chain_json"]),
    ("raw_email_archive", ["email_id", "user_id", "encrypted_raw_content",
                            "encrypted_headers_json", "archived_at"]),
    ("access_log", ["endpoint", "email_id", "user_id", "ip_address", "status_code",
                     "detail", "logged_at"]),
]

# domain_intel and access_log had SQLite AUTOINCREMENT `id` columns we
# deliberately don't carry over -- the new Postgres tables generate
# fresh BIGSERIAL ids on insert. Nothing references those old ids by
# value anywhere in the app, so this is safe.
SKIP_SOURCE_COLUMN = {"domain_intel": "id", "access_log": "id"}


def table_exists_in_sqlite(sqlite_conn, table_name):
    row = sqlite_conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
    ).fetchone()
    return row is not None


def migrate_table(sqlite_conn, pg_conn, table_name, columns):
    if not table_exists_in_sqlite(sqlite_conn, table_name):
        print(f"  [--] {table_name}: not present in source SQLite db, skipping")
        return 0

    source_columns = [c for c in columns if c != SKIP_SOURCE_COLUMN.get(table_name)]
    placeholders = ", ".join(source_columns)
    rows = sqlite_conn.execute(f"SELECT {placeholders} FROM {table_name}").fetchall()

    if not rows:
        print(f"  [--] {table_name}: 0 rows, nothing to migrate")
        return 0

    pg_placeholders = ", ".join(["%s"] * len(source_columns))
    col_list = ", ".join(source_columns)

    # Conflict target: email_id if the table has one and it's unique
    # enough (PK or PK-like), otherwise just DO NOTHING with no target
    # (Postgres requires ON CONFLICT DO NOTHING with no target to be
    # valid for any unique-violation, which is what we want here).
    conflict_clause = "ON CONFLICT DO NOTHING"

    inserted = 0
    cur = pg_conn.cursor()
    for row in rows:
        try:
            cur.execute(
                f"INSERT INTO {table_name} ({col_list}) VALUES ({pg_placeholders}) {conflict_clause}",
                tuple(row),
            )
            inserted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        except Exception as e:
            print(f"  [!] {table_name}: failed to insert a row ({e}) -- skipping it")
            pg_conn.rollback()
            continue

    pg_conn.commit()
    print(f"  [ok] {table_name}: migrated {inserted}/{len(rows)} rows")
    return inserted


def migrate(sqlite_path):
    print(f"[*] Opening source SQLite db: {sqlite_path}")
    sqlite_conn = sqlite3.connect(sqlite_path)

    print("[*] Opening destination Postgres db (via DATABASE_URL)")
    pg_conn = get_connection()

    print("\n[*] Migrating tables in dependency order:\n")
    total = 0
    for table_name, columns in TABLES_IN_DEPENDENCY_ORDER:
        total += migrate_table(sqlite_conn, pg_conn, table_name, columns)

    sqlite_conn.close()
    pg_conn.close()

    print(f"\n[+] Done. {total} total rows migrated.")
    print(
        "\n[i] Note: the old campaigns/campaign_members/graph_edges tables "
        "were NOT migrated -- that correlation engine is retired. If you "
        "want campaign relationships rebuilt for this historical data "
        "under the new threat_correlation_engine, re-run it over your "
        "past investigations, e.g. by re-POSTing each archived raw email "
        "through /analyze, or by writing a small backfill script that "
        "loads each investigation's stored domain_intel/fingerprints rows "
        "and calls threat_correlation_engine.correlate() directly."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sqlite", required=True, help="Path to the old phishing.db file")
    args = parser.parse_args()
    migrate(args.sqlite)
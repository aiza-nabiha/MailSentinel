"""
backend/storage_engine/integrate.py

Combines Person 2's header/auth parser and Person 3's domain
pipeline into one email_id-keyed record, persisted via db.py.

Usage (from backend/storage_engine/):
    python integrate.py --eml ../../data/test_emails/example.eml

If Person 3's pipeline module isn't importable yet (missing files,
or no network access for WHOIS/DNS/TLS lookups), this still runs --
it just stores header/auth data and skips domain_intel, so you're
never blocked waiting on another module.
"""

import argparse
import json
import sys
from pathlib import Path

from db import get_connection, next_email_id

THIS_DIR = Path(__file__).parent
sys.path.append(str(THIS_DIR.parent / "header_auth_engine"))
sys.path.append(str(THIS_DIR.parent / "infrastructure_engine"))

try:
    from header_parser import build_email_data
except ImportError as e:
    print(f"[!] header_parser not importable: {e}")
    build_email_data = None

try:
    from pipeline import run_pipeline
except ImportError as e:
    print(f"[!] pipeline (Person 3) not importable yet -- domain_intel will be skipped: {e}")
    run_pipeline = None


def insert_email_record(conn, email_id, eml_path, header_data, pipeline_data):
    meta = header_data.get("email_metadata", {}) if header_data else {}
    risk_score, verdict = None, None
    if pipeline_data and "overall_verdict" in pipeline_data:
        risk_score = pipeline_data["overall_verdict"].get("highest_risk_score")
        verdict = pipeline_data["overall_verdict"].get("highest_risk_level")

    conn.execute(
        """INSERT OR REPLACE INTO emails
           (email_id, raw_eml_path, subject, from_header, to_header, date_header,
            overall_risk_score, verdict)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (email_id, eml_path, meta.get("subject"), meta.get("from"), meta.get("to"),
         meta.get("date"), risk_score, verdict),
    )

    if header_data:
        auth = header_data.get("authentication", {})
        conn.execute(
            """INSERT OR REPLACE INTO header_results
               (email_id, spf_result, spf_domain, dkim_json, dmarc_result, dmarc_domain,
                dmarc_policy, received_chain_json, raw_auth_results_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (email_id, auth.get("spf", {}).get("result"), auth.get("spf", {}).get("domain"),
             json.dumps(auth.get("dkim", [])), auth.get("dmarc", {}).get("result"),
             auth.get("dmarc", {}).get("domain"), auth.get("dmarc", {}).get("policy"),
             json.dumps(header_data.get("received_chain", [])),
             json.dumps(header_data.get("authentication_results", []))),
        )

    if pipeline_data:
        conn.execute("DELETE FROM domain_intel WHERE email_id = ?", (email_id,))
        for domain, ddata in pipeline_data.get("domains", {}).items():
            risk = ddata.get("risk", {})
            whois = ddata.get("whois", {})
            tls = ddata.get("tls", {})
            reputation = ddata.get("reputation", {})
            conn.execute(
                """INSERT INTO domain_intel
                   (email_id, domain, age_days, tls_issuer, tls_status, cert_shared_with_json,
                    found_on_lists_json, risk_score, risk_level, risk_reasons_json,
                    whois_json, dns_json, tls_json, reputation_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (email_id, domain, whois.get("domain_age", {}).get("days"),
                 tls.get("issuer"), tls.get("status"), json.dumps(tls.get("cert_shared_with", [])),
                 json.dumps(reputation.get("found_on_lists", [])),
                 risk.get("risk_score"), risk.get("risk_level"), json.dumps(risk.get("reasons", [])),
                 json.dumps(whois), json.dumps(ddata.get("dns", {})), json.dumps(tls), json.dumps(reputation)),
            )


def run(eml_path, db_path=None):
    conn = get_connection(db_path)
    email_id = next_email_id(conn)
    print(f"[*] Assigned {email_id} -> {eml_path}")

    header_data = build_email_data(eml_path) if build_email_data else None
    if header_data:
        print("[*] Person 2 header parsing: OK")

    pipeline_data = run_pipeline(eml_path) if run_pipeline else None
    if pipeline_data:
        print("[*] Person 3 domain pipeline: OK")

    insert_email_record(conn, email_id, eml_path, header_data, pipeline_data)
    conn.commit()
    print(f"[+] {email_id} stored.")
    conn.close()
    return email_id


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--eml", required=True)
    parser.add_argument("--db", default=None)
    args = parser.parse_args()
    run(args.eml, args.db)
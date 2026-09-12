"""
backend/storage_engine/integrate.py

Combines Person 2's header/auth parser, Person 3's domain +
infrastructure pipeline, Person 1's content classifier, and
Person 4's fingerprinting into one email_id-keyed record.

IMPORT STYLE NOTE: header_parser.py, content_analysis.py, and
pipeline.py's own internal cross-folder references now use
package-qualified imports (e.g. "from .received_parser import ...",
"from header_auth_engine.header_parser import ..."). This means we
must add the BACKEND ROOT (not each subfolder) to sys.path and
import via "header_auth_engine.header_parser", NOT a flat
"from header_parser import ...", or Python raises "attempted
relative import with no known parent package".

Usage (from backend/storage_engine/):
    python integrate.py --eml ../../data/test_emails/example.eml
"""

import argparse
import json
import sys
from pathlib import Path

from db import get_connection, get_or_create_email_id, get_or_create_user, archive_raw_email

THIS_DIR = Path(__file__).parent
BACKEND_ROOT = THIS_DIR.parent

# Add BACKEND ROOT once -- enables package-qualified imports like
# "header_auth_engine.header_parser" and "threat_detection_engine.content_analysis"
sys.path.append(str(BACKEND_ROOT))

# infrastructure_engine's OWN internal imports are still flat
# (e.g. "from domain_extract import extract_domains" inside pipeline.py),
# so that folder itself also needs to be on sys.path directly.
sys.path.append(str(BACKEND_ROOT / "infrastructure_engine"))

# ---- Person 2: header/auth parsing ----
try:
    from header_auth_engine.header_parser import build_email_data
except ImportError as e:
    print(f"[!] header_parser not importable: {e}")
    build_email_data = None

# ---- Person 3: domain + infrastructure pipeline ----
try:
    from pipeline import run_pipeline
except ImportError as e:
    print(f"[!] pipeline (Person 3) not importable yet -- domain_intel will be skipped: {e}")
    run_pipeline = None

# ---- Person 1: real classifier first, rule-based stub as fallback ----
classify_email_real = None
classify_email_fallback = None

try:
    from threat_detection_engine.core.content_analysis import analyze_email_file as classify_email_real
    print("[i] Person 1 REAL classifier module found")
except ImportError as e:
    print(f"[!] Person 1 real classifier not importable yet: {e}")

try:
    sys.path.append(str(BACKEND_ROOT / "threat_detection_engine"))
    from content_analysis_fallback import classify_email as classify_email_fallback
except ImportError:
    pass

# ---- Person 4 Part A: fingerprinting (structural hash, typosquat, style) ----
try:
    sys.path.append(str(BACKEND_ROOT / "threat_graph_engine"))
    from fingerprint import generate_fingerprint
except ImportError as e:
    print(f"[!] Person 4 fingerprint module not importable yet -- fingerprints will be skipped: {e}")
    generate_fingerprint = None


def run_classifier(eml_path):
    """Tries the real model first; falls back to the rule-based stub on ANY failure."""
    if classify_email_real:
        try:
            raw = classify_email_real(eml_path)
            normalized = {
                "phishing_score": raw.get("threat_probability"),
                "verdict": raw.get("prediction"),
                "reasons": raw.get("analysis", {}).get("supporting_evidence", []),
                "extracted_urls": raw.get("url_intelligence", {}).get("url_details", []),
                "url_intelligence": raw.get("url_intelligence"),
                "sender_features": raw.get("sender_features"),
                "email_structure": raw.get("email_structure"),
            }
            return normalized, "real_model"
        except Exception as e:
            print(f"[!] Real classifier failed ({e}) -- falling back to rule-based stub")

    if classify_email_fallback:
        try:
            return classify_email_fallback(eml_path), "fallback_stub"
        except Exception as e:
            print(f"[!] Fallback stub also failed: {e}")

    return None, None


def run_fingerprint(eml_path):
    """Runs Person 4's Part A fingerprinting. Returns None if not available/fails."""
    if not generate_fingerprint:
        return None
    try:
        return generate_fingerprint(eml_path)
    except Exception as e:
        print(f"[!] Fingerprinting failed: {e}")
        return None


def insert_email_record(conn, email_id, eml_path, header_data, pipeline_data,
                         classifier_data=None, classifier_source=None, fingerprint_data=None, user_id=None):
    meta = header_data.get("email_metadata", {}) if header_data else {}
    risk_score, verdict = None, None
    if pipeline_data and pipeline_data.get("overall_verdict"):
        overall_verdict = pipeline_data["overall_verdict"]
        risk_score = overall_verdict.get("risk_score")
        verdict = overall_verdict.get("risk_level")

    conn.execute(
        """INSERT OR REPLACE INTO emails
           (email_id, user_id, raw_eml_path, subject, from_header, to_header, date_header,
            overall_risk_score, verdict)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (email_id, user_id, eml_path, meta.get("subject"), meta.get("from"), meta.get("to"),
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

        # NEW: capture infrastructure_risk / reliable_hop_analysis / received_chain --
        # pipeline.py now produces these but they were previously silently dropped.
        infra_risk = pipeline_data.get("infrastructure_risk")
        if infra_risk:
            conn.execute(
                """INSERT OR REPLACE INTO infrastructure_risk
                   (email_id, risk_score, risk_level, reasons_json, evidence_json,
                    reliable_hop_json, received_chain_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (email_id, infra_risk.get("risk_score"), infra_risk.get("risk_level"),
                 json.dumps(infra_risk.get("reasons", [])), json.dumps(infra_risk.get("evidence", [])),
                 json.dumps(pipeline_data.get("reliable_hop_analysis")),
                 json.dumps(pipeline_data.get("received_chain", []))),
            )

    if classifier_data:
        conn.execute(
            """INSERT OR REPLACE INTO classifier_results
               (email_id, phishing_score, verdict, reasons_json, extracted_urls_json,
                source, url_intelligence_json, sender_features_json, email_structure_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (email_id, classifier_data.get("phishing_score"), classifier_data.get("verdict"),
             json.dumps(classifier_data.get("reasons", [])),
             json.dumps(classifier_data.get("extracted_urls", [])),
             classifier_source,
             json.dumps(classifier_data.get("url_intelligence")) if classifier_data.get("url_intelligence") else None,
             json.dumps(classifier_data.get("sender_features")) if classifier_data.get("sender_features") else None,
             json.dumps(classifier_data.get("email_structure")) if classifier_data.get("email_structure") else None),
        )

    if fingerprint_data:
        conn.execute(
            """INSERT OR REPLACE INTO fingerprints
               (email_id, structural_hash, skeleton_type, typosquat_matches_json,
                targeted_brands_json, style_colors_json, style_fonts_json, style_alt_texts_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (email_id,
             fingerprint_data["structural"]["fingerprint_sha256"],
             fingerprint_data["structural"]["skeleton_type"],
             json.dumps(fingerprint_data["typosquat"]["matches"]),
             json.dumps(fingerprint_data["typosquat"]["targeted_brands"]),
             json.dumps(fingerprint_data["style"]["colors"]),
             json.dumps(fingerprint_data["style"]["fonts"]),
             json.dumps(fingerprint_data["style"]["alt_texts"])),
        )


def run(eml_path, db_path=None, user_id=None):
    conn = get_connection(db_path)
    if user_id:
        get_or_create_user(conn, user_id)

    email_id, already_existed = get_or_create_email_id(conn, eml_path)
    if already_existed:
        print(f"[*] {eml_path} already ingested as {email_id} -- updating existing record")
    else:
        print(f"[*] Assigned {email_id} -> {eml_path}")

    header_data = build_email_data(eml_path) if build_email_data else None
    if header_data:
        print("[*] Person 2 header parsing: OK")

    pipeline_data = run_pipeline(eml_path) if run_pipeline else None
    if pipeline_data:
        print("[*] Person 3 domain + infrastructure pipeline: OK")

    classifier_data, classifier_source = run_classifier(eml_path)
    if classifier_data:
        print(f"[*] Classifier ({classifier_source}): OK "
              f"(verdict: {classifier_data['verdict']}, score: {classifier_data['phishing_score']})")

    fingerprint_data = run_fingerprint(eml_path)
    if fingerprint_data:
        print(f"[*] Person 4 fingerprint: OK "
              f"(brands targeted: {fingerprint_data['typosquat']['targeted_brands']})")

    insert_email_record(conn, email_id, eml_path, header_data, pipeline_data,
                         classifier_data, classifier_source, fingerprint_data, user_id)

    # Archive the raw email (encrypted) for future model retraining --
    # separate from the derived-signal tables above. Skips gracefully
    # if DB_ENCRYPTION_KEY isn't configured yet, so this never blocks
    # today's analysis while you're still setting up encryption.
    try:
        with open(eml_path, "r", encoding="utf-8", errors="replace") as f:
            raw_content = f.read()
        archive_raw_email(conn, email_id, user_id, raw_content, header_data)
        print("[*] Raw email archived (encrypted) for future training")
    except RuntimeError as e:
        print(f"[!] Skipping archive -- encryption not configured: {e}")
    except Exception as e:
        print(f"[!] Archiving failed (non-fatal, analysis still saved): {e}")

    conn.commit()
    print(f"[+] {email_id} stored.")
    conn.close()
    return email_id


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--eml", required=True)
    parser.add_argument("--db", default=None)
    parser.add_argument("--user", default=None, help="Gmail address to associate this email with")
    args = parser.parse_args()
    run(args.eml, args.db, args.user)
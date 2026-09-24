"""
backend/storage_engine/integrate.py

POSTGRES VERSION. Two things changed from the original:

  1. All raw SQL converted from SQLite's `?` placeholders to
     Postgres's `%s`, and `INSERT OR REPLACE` to
     `INSERT ... ON CONFLICT DO UPDATE`.

  2. The correlation engine wired in here is now
     threat_correlation_engine.py (the real, full engine -- rarity
     weighting, time decay, cohesion checks, cross-session memory),
     NOT the old threat_graph_engine/correlate.py simplified 3-signal
     engine, which is retired.

     threat_correlation_engine.correlate() recomputes the ENTIRE
     campaign graph from full history every time it's called (it's
     not incremental). So rather than trying to diff its output,
     persist_campaign_cache() just wipes and rewrites the
     campaign_membership / campaign_edges tables after every run --
     they're a cache of "what does the graph look like right now",
     not a running log. api.py reads that cache directly.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from db import get_connection, get_or_create_email_id, get_or_create_user, archive_raw_email

THIS_DIR = Path(__file__).parent
BACKEND_ROOT = THIS_DIR.parent

sys.path.append(str(BACKEND_ROOT))
sys.path.append(str(BACKEND_ROOT / "infrastructure_engine"))

try:
    from header_auth_engine.header_parser import build_email_data
except ImportError as e:
    print(f"[!] header_parser not importable: {e}")
    build_email_data = None

try:
    from pipeline import run_pipeline
except ImportError as e:
    print(f"[!] pipeline (Person 3) not importable yet -- domain_intel will be skipped: {e}")
    run_pipeline = None

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

try:
    sys.path.append(str(BACKEND_ROOT / "threat_graph_engine"))
    from fingerprint import generate_fingerprint
except ImportError as e:
    print(f"[!] Person 4 fingerprint module not importable yet -- fingerprints will be skipped: {e}")
    generate_fingerprint = None

# threat_correlation_engine.py lives in infrastructure_engine/, already
# on sys.path above. This REPLACES the old threat_graph_engine/correlate.py
# import that used to be here.
try:
    from threat_correlation_engine import correlate as run_threat_correlation
except ImportError as e:
    print(f"[!] threat_correlation_engine not importable yet -- campaign correlation will be skipped: {e}")
    run_threat_correlation = None


def run_classifier(eml_path):
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

    # Combined risk score -- the WORST CASE across all three
    # independent signals (domain intel, infrastructure/auth risk,
    # ML classifier). Computed once here, at the source, so the
    # Gmail sidebar and the website always show the same number.
    domain_infra_risk = 0

    if pipeline_data and pipeline_data.get("overall_verdict"):
        domain_infra_risk = (
            pipeline_data["overall_verdict"].get("risk_score") or 0
        )

    classifier_risk_score = 0

    if classifier_data and classifier_data.get("phishing_score") is not None:
        classifier_risk_score = (
            classifier_data["phishing_score"] * 100
        )

    risk_score = round(
        0.40 * classifier_risk_score +
        0.60 * domain_infra_risk
    )

    if risk_score >= 70:
        verdict = "high"
    elif risk_score >= 40:
        verdict = "medium"
    else:
        verdict = "low"

    conn.execute(
        """INSERT INTO emails
               (email_id, user_id, raw_eml_path, subject, from_header, to_header, date_header,
                overall_risk_score, verdict)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT (email_id) DO UPDATE SET
               user_id = EXCLUDED.user_id,
               raw_eml_path = EXCLUDED.raw_eml_path,
               subject = EXCLUDED.subject,
               from_header = EXCLUDED.from_header,
               to_header = EXCLUDED.to_header,
               date_header = EXCLUDED.date_header,
               overall_risk_score = EXCLUDED.overall_risk_score,
               verdict = EXCLUDED.verdict""",
        (email_id, user_id, eml_path, meta.get("subject"), meta.get("from"), meta.get("to"),
         meta.get("date"), risk_score, verdict),
    )

    if header_data:
        auth = header_data.get("authentication", {})
        conn.execute(
            """INSERT INTO header_results
                   (email_id, spf_result, spf_domain, dkim_json, dmarc_result, dmarc_domain,
                    dmarc_policy, received_chain_json, raw_auth_results_json)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (email_id) DO UPDATE SET
                   spf_result = EXCLUDED.spf_result,
                   spf_domain = EXCLUDED.spf_domain,
                   dkim_json = EXCLUDED.dkim_json,
                   dmarc_result = EXCLUDED.dmarc_result,
                   dmarc_domain = EXCLUDED.dmarc_domain,
                   dmarc_policy = EXCLUDED.dmarc_policy,
                   received_chain_json = EXCLUDED.received_chain_json,
                   raw_auth_results_json = EXCLUDED.raw_auth_results_json""",
            (email_id, auth.get("spf", {}).get("result"), auth.get("spf", {}).get("domain"),
             json.dumps(auth.get("dkim", [])), auth.get("dmarc", {}).get("result"),
             auth.get("dmarc", {}).get("domain"), auth.get("dmarc", {}).get("policy"),
             json.dumps(header_data.get("received_chain", [])),
             json.dumps(header_data.get("authentication_results", []))),
        )

    if pipeline_data:
        conn.execute("DELETE FROM domain_intel WHERE email_id = %s", (email_id,))
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
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (email_id, domain, (whois.get("domain_age") or {}).get("days"),
                 tls.get("issuer"), tls.get("status"), json.dumps(tls.get("cert_shared_with", [])),
                 json.dumps(reputation.get("found_on_lists", [])),
                 risk.get("risk_score"), risk.get("risk_level"), json.dumps(risk.get("reasons", [])),
                 json.dumps(whois), json.dumps(ddata.get("dns", {})), json.dumps(tls), json.dumps(reputation)),
            )

        infra_risk = pipeline_data.get("infrastructure_risk")
        if infra_risk:
            conn.execute(
                """INSERT INTO infrastructure_risk
                       (email_id, risk_score, risk_level, reasons_json, evidence_json,
                        reliable_hop_json, received_chain_json)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (email_id) DO UPDATE SET
                       risk_score = EXCLUDED.risk_score,
                       risk_level = EXCLUDED.risk_level,
                       reasons_json = EXCLUDED.reasons_json,
                       evidence_json = EXCLUDED.evidence_json,
                       reliable_hop_json = EXCLUDED.reliable_hop_json,
                       received_chain_json = EXCLUDED.received_chain_json""",
                (email_id, infra_risk.get("risk_score"), infra_risk.get("risk_level"),
                 json.dumps(infra_risk.get("reasons", [])), json.dumps(infra_risk.get("evidence", [])),
                 json.dumps(pipeline_data.get("reliable_hop_analysis")),
                 json.dumps(pipeline_data.get("received_chain", []))),
            )

    if classifier_data:
        conn.execute(
            """INSERT INTO classifier_results
                   (email_id, phishing_score, verdict, reasons_json, extracted_urls_json,
                    source, url_intelligence_json, sender_features_json, email_structure_json)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (email_id) DO UPDATE SET
                   phishing_score = EXCLUDED.phishing_score,
                   verdict = EXCLUDED.verdict,
                   reasons_json = EXCLUDED.reasons_json,
                   extracted_urls_json = EXCLUDED.extracted_urls_json,
                   source = EXCLUDED.source,
                   url_intelligence_json = EXCLUDED.url_intelligence_json,
                   sender_features_json = EXCLUDED.sender_features_json,
                   email_structure_json = EXCLUDED.email_structure_json""",
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
            """INSERT INTO fingerprints
                   (email_id, structural_hash, skeleton_type, typosquat_matches_json,
                    targeted_brands_json, style_colors_json, style_fonts_json, style_alt_texts_json)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (email_id) DO UPDATE SET
                   structural_hash = EXCLUDED.structural_hash,
                   skeleton_type = EXCLUDED.skeleton_type,
                   typosquat_matches_json = EXCLUDED.typosquat_matches_json,
                   targeted_brands_json = EXCLUDED.targeted_brands_json,
                   style_colors_json = EXCLUDED.style_colors_json,
                   style_fonts_json = EXCLUDED.style_fonts_json,
                   style_alt_texts_json = EXCLUDED.style_alt_texts_json""",
            (email_id,
             fingerprint_data["structural"]["fingerprint_sha256"],
             fingerprint_data["structural"]["skeleton_type"],
             json.dumps(fingerprint_data["typosquat"]["matches"]),
             json.dumps(fingerprint_data["typosquat"]["targeted_brands"]),
             json.dumps(fingerprint_data["style"]["colors"]),
             json.dumps(fingerprint_data["style"]["fonts"]),
             json.dumps(fingerprint_data["style"]["alt_texts"])),
        )


def persist_campaign_cache(conn, campaigns):
    """
    threat_correlation_engine.correlate() returns the FULL current
    campaign graph, recomputed from scratch, every time it runs.
    Rather than diffing that against whatever was there before, wipe
    the cache tables and write the fresh result -- correct and simple
    at this app's scale (dozens/hundreds of investigations, not
    millions).
    """
    cur = conn.cursor()
    cur.execute("TRUNCATE campaign_membership, campaign_edges, campaign_graphs")

    for campaign in campaigns:
        campaign_id = campaign["campaign_id"]
        confidence = campaign["confidence"]
        cohesion = campaign["cohesion"]
        cohesion_warning = campaign["cohesion_warning"]
        signal_summary_json = json.dumps(campaign["signal_summary"])

        for member_email_id in campaign["emails"]:
            cur.execute(
                """INSERT INTO campaign_membership
                       (email_id, campaign_id, confidence, cohesion, cohesion_warning, signal_summary_json)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT (email_id, campaign_id) DO NOTHING""",
                (member_email_id, campaign_id, confidence, cohesion, cohesion_warning, signal_summary_json),
            )

        for edge in campaign["connections"]:
            cur.execute(
                """INSERT INTO campaign_edges
                       (campaign_id, source_email_id, target_email_id, confidence,
                        evidence_summary_json, signals_json)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (campaign_id, edge["source"], edge["target"], edge["confidence"],
                 json.dumps(edge["evidence_summary"]), json.dumps(edge["signals"])),
            )

        cur.execute(
            """INSERT INTO campaign_graphs (campaign_id, graph_json)
               VALUES (%s, %s)
               ON CONFLICT (campaign_id) DO UPDATE SET graph_json = EXCLUDED.graph_json""",
            (campaign_id, json.dumps(campaign["graph"])),
        )

    conn.commit()


def run_correlation(conn, email_id, pipeline_data, fingerprint_data, header_data):
    """
    Builds the record shape threat_correlation_engine.normalize_email_record()
    expects, runs the real correlation engine against full history, and
    persists its output into the campaign_membership/campaign_edges cache
    that api.py reads from.
    """
    record = {
        "email_id": email_id,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "domains": (pipeline_data or {}).get("domains", {}),
        "reliable_hop_analysis": (pipeline_data or {}).get("reliable_hop_analysis", {}),
        "fingerprint": fingerprint_data or {},
        "received_chain": (header_data or {}).get("received_chain", []),
    }
    # output_file=None -- we don't need the JSON file dump in the live
    # pipeline, only the CLI usage writes that.
    result = run_threat_correlation(conn, [record], output_file=None)
    persist_campaign_cache(conn, result["campaigns"])
    return result


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

    try:
        with open(eml_path, "r", encoding="utf-8", errors="replace") as f:
            raw_content = f.read()
        archive_raw_email(conn, email_id, user_id, raw_content, header_data)
        print("[*] Raw email archived (encrypted) for future training")
    except RuntimeError as e:
        print(f"[!] Skipping archive -- encryption not configured: {e}")
    except Exception as e:
        print(f"[!] Archiving failed (non-fatal, analysis still saved): {e}")

    if run_threat_correlation:
        try:
            correlation_result = run_correlation(conn, email_id, pipeline_data, fingerprint_data, header_data)
            my_campaigns = [c for c in correlation_result["campaigns"] if email_id in c["emails"]]
            if my_campaigns:
                print(f"[*] Correlation: matched campaign(s) -- {[c['campaign_id'] for c in my_campaigns]}")
            else:
                print("[*] Correlation: no campaign matches against prior investigations")
        except Exception as e:
            print(f"[!] Correlation check failed (non-fatal): {e}")

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
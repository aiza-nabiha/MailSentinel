"""
backend/storage_engine/api.py

Bridge between the Gmail Add-on / website and the pipeline.
"""

import hmac
import os
import tempfile
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from db import get_connection, get_emails_for_user, log_access, get_trigger_metadata, get_raw_archive_for_email
from integrate import run as run_integration

load_dotenv()

app = Flask(__name__)

# CORS: the Gmail plugin calls this API from Apps Script's SERVER
# (UrlFetchApp) -- browsers never restrict that, no CORS needed there.
# The website's React frontend calls this API from JAVASCRIPT RUNNING
# IN THE BROWSER, which IS restricted by CORS by default. Without this,
# the browser silently blocks every fetch() call even though curl/Postman
# work fine. Allowing all origins for the demo; tighten before real use.
CORS(app, resources={r"/*": {"origins": "*"}})

limiter = Limiter(get_remote_address, app=app, default_limits=["100 per hour"], storage_uri="memory://")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

ALLOWED_EML_DIR = (Path(__file__).parent.parent.parent / "data").resolve()
API_SECRET_KEY = os.environ.get("API_SECRET_KEY")


def _require_api_key():
    if not API_SECRET_KEY:
        return jsonify({"error": "Server misconfigured: API_SECRET_KEY not set"}), 500
    provided = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(provided, API_SECRET_KEY):
        return jsonify({"error": "Unauthorized -- missing or invalid X-API-Key header"}), 401
    return None


def _resolve_safe_eml_path(user_supplied_path):
    candidate = (ALLOWED_EML_DIR / user_supplied_path).resolve()
    if not str(candidate).startswith(str(ALLOWED_EML_DIR)):
        return None
    return candidate


def _build_investigation_result(conn, email_id, include_raw_content=False):
    email_row = conn.execute(
        "SELECT email_id, subject, from_header, overall_risk_score, verdict, ingested_at FROM emails WHERE email_id = ?",
        (email_id,),
    ).fetchone()
    if not email_row:
        return None

    domain_rows = conn.execute(
        """SELECT domain, risk_score, risk_level, risk_reasons_json, age_days, tls_issuer,
                  tls_status, found_on_lists_json, whois_json, dns_json, tls_json, reputation_json
           FROM domain_intel WHERE email_id = ?""",
        (email_id,),
    ).fetchall()
    header_row = conn.execute(
        "SELECT spf_result, dmarc_result, dmarc_policy, received_chain_json FROM header_results WHERE email_id = ?",
        (email_id,),
    ).fetchone()
    classifier_row = conn.execute(
        """SELECT phishing_score, verdict, reasons_json, source, url_intelligence_json
           FROM classifier_results WHERE email_id = ?""",
        (email_id,),
    ).fetchone()
    fingerprint_row = conn.execute(
        """SELECT structural_hash, skeleton_type, typosquat_matches_json, targeted_brands_json
           FROM fingerprints WHERE email_id = ?""",
        (email_id,),
    ).fetchone()
    infra_row = conn.execute(
        """SELECT risk_score, risk_level, reasons_json, evidence_json, reliable_hop_json, received_chain_json
           FROM infrastructure_risk WHERE email_id = ?""",
        (email_id,),
    ).fetchone()

    import json as _json

    # Pick the single highest-risk domain to surface as the "headline" domain --
    # the website's UI is built around one primary domain, not a flat list.
    domains_parsed = []
    for d in domain_rows:
        domains_parsed.append({
            "domain": d[0], "risk_score": d[1], "risk_level": d[2],
            "reasons": _json.loads(d[3]) if d[3] else [],
            "age_days": d[4], "tls_issuer": d[5], "tls_status": d[6],
            "found_on_lists": _json.loads(d[7]) if d[7] else [],
            "whois": _json.loads(d[8]) if d[8] else {},
            "dns": _json.loads(d[9]) if d[9] else {},
            "tls": _json.loads(d[10]) if d[10] else {},
            "reputation": _json.loads(d[11]) if d[11] else {},
        })
    highest_risk = max(domains_parsed, key=lambda x: x["risk_score"] or 0) if domains_parsed else None

    trigger = get_trigger_metadata(conn, email_id)

    # Real correlation data -- which other stored investigations share
    # infrastructure with this one, and how (see correlate.py).
    campaign_row = conn.execute(
        "SELECT campaign_id FROM campaign_members WHERE email_id = ?", (email_id,)
    ).fetchone()
    campaign_correlation = None
    if campaign_row:
        campaign_id = campaign_row[0]
        member_rows = conn.execute(
            "SELECT email_id FROM campaign_members WHERE campaign_id = ? AND email_id != ?",
            (campaign_id, email_id),
        ).fetchall()
        edge_rows = conn.execute(
            "SELECT node_a, node_b, edge_type FROM graph_edges WHERE node_a = ? OR node_b = ?",
            (email_id, email_id),
        ).fetchall()
        campaign_correlation = {
            "campaign_id": campaign_id,
            "matched_investigations": len(member_rows),
            "matches": [
                {
                    "email_id": r[0],
                    "signals": [e[2] for e in edge_rows if email_id in (e[0], e[1]) and r[0] in (e[0], e[1])],
                }
                for r in member_rows
            ],
        }

    result = {
        "email_id": email_row[0],
        "subject": email_row[1],
        "from_header": email_row[2],
        "overall_risk_score": email_row[3],
        "verdict": email_row[4],
        "analyzed_at": email_row[5],
        "header_auth": {
            "spf": header_row[0] if header_row else None,
            "dmarc": header_row[1] if header_row else None,
            "dmarc_policy": header_row[2] if header_row else None,
            "received_chain": _json.loads(header_row[3]) if header_row and header_row[3] else [],
        },
        "classifier": {
            "phishing_score": classifier_row[0] if classifier_row else None,
            "verdict": classifier_row[1] if classifier_row else None,
            "reasons": _json.loads(classifier_row[2]) if classifier_row and classifier_row[2] else [],
            "source": classifier_row[3] if classifier_row else None,
        },
        "fingerprint": {
            "structural_hash": fingerprint_row[0] if fingerprint_row else None,
            "skeleton_type": fingerprint_row[1] if fingerprint_row else None,
            "typosquat_matches": _json.loads(fingerprint_row[2]) if fingerprint_row and fingerprint_row[2] else [],
            "targeted_brands": _json.loads(fingerprint_row[3]) if fingerprint_row and fingerprint_row[3] else [],
        },
        "infrastructure_risk": {
            "risk_score": infra_row[0] if infra_row else None,
            "risk_level": infra_row[1] if infra_row else None,
            "reasons": _json.loads(infra_row[2]) if infra_row and infra_row[2] else [],
            "evidence": _json.loads(infra_row[3]) if infra_row and infra_row[3] else [],
            "reliable_hop": _json.loads(infra_row[4]) if infra_row and infra_row[4] else None,
            "received_chain": _json.loads(infra_row[5]) if infra_row and infra_row[5] else [],
        },
        "domains": domains_parsed,
        "highest_risk_domain": highest_risk,
        "campaign_correlation": campaign_correlation,  # real data, or None if no matches found
        "triggered_by": {
            "user_id": trigger[0] if trigger else None,
            "ip_address": trigger[1] if trigger else None,
            "triggered_at": trigger[2] if trigger else None,
        },
    }

    if include_raw_content:
        archive = get_raw_archive_for_email(conn, email_id)
        result["raw_email"] = archive  # {"raw_content": ..., "headers": ...} or None

    return result


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/analyze", methods=["POST"])
@limiter.limit("20 per minute")
def analyze():
    auth_error = _require_api_key()
    if auth_error:
        conn = get_connection()
        log_access(conn, "/analyze", None, get_remote_address(), 401, "auth failed")
        conn.close()
        return auth_error

    data = request.get_json(silent=True) or {}
    eml_path_raw = data.get("eml_path")
    raw_eml = data.get("raw_eml")
    user_id = data.get("user_id")

    if not eml_path_raw and not raw_eml:
        return jsonify({"error": "Provide either eml_path or raw_eml"}), 400

    temporary_path = None

    if raw_eml:
        if not isinstance(raw_eml, str):
            return jsonify({"error": "raw_eml must be a string"}), 400
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".eml", delete=False, encoding="utf-8")
        handle.write(raw_eml)
        handle.close()
        temporary_path = handle.name
        target_path = Path(temporary_path)
    else:
        if not isinstance(eml_path_raw, str):
            return jsonify({"error": "eml_path must be a string"}), 400
        target_path = _resolve_safe_eml_path(eml_path_raw)
        if target_path is None:
            return jsonify({"error": "Invalid eml_path -- must stay within the data/ directory"}), 400
        if not target_path.exists():
            return jsonify({"error": f"File not found: {eml_path_raw}"}), 404

    try:
        email_id = run_integration(str(target_path), user_id=user_id)
    except Exception as e:
        print(f"[!] Pipeline error: {e}")
        log_conn = get_connection()
        log_access(log_conn, "/analyze", user_id, get_remote_address(), 500, str(e)[:200])
        log_conn.close()
        return jsonify({"error": "Analysis failed -- check server logs"}), 500
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass

    conn = get_connection()
    ip_address = get_remote_address()
    log_access(conn, "/analyze", user_id, ip_address, 200, email_id=email_id)
    result = _build_investigation_result(conn, email_id, include_raw_content=True)
    conn.close()

    return jsonify(result), 200


@app.route("/investigation/<email_id>", methods=["GET"])
def get_investigation(email_id):
    """
    Fetches a PAST investigation by email_id, no re-analysis. This is
    what the WEBSITE calls when the Gmail plugin's "View Full
    Investigation" link opens it with that email_id in the URL.

    Pass ?full=true to also include the decrypted raw email content
    and headers -- kept opt-in rather than always-on, since decrypting
    full email content is a more sensitive operation than the derived
    risk/analysis data returned by default.
    """
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    include_raw = request.args.get("full", "").lower() in ("true", "1", "yes")

    conn = get_connection()
    result = _build_investigation_result(conn, email_id, include_raw_content=include_raw)
    conn.close()

    if result is None:
        return jsonify({"error": f"No investigation found for email_id: {email_id}"}), 404

    return jsonify(result), 200


@app.route("/history", methods=["GET"])
@limiter.limit("30 per minute")
def history():
    auth_error = _require_api_key()
    if auth_error:
        conn = get_connection()
        log_access(conn, "/history", request.args.get("user_id"), get_remote_address(), 401, "auth failed")
        conn.close()
        return auth_error

    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"error": "Missing required query param: user_id"}), 400

    conn = get_connection()
    rows = get_emails_for_user(conn, user_id)
    log_access(conn, "/history", user_id, get_remote_address(), 200)
    conn.close()

    return jsonify({
        "user_id": user_id,
        "emails": [
            {"email_id": r[0], "subject": r[1], "from_header": r[2],
             "overall_risk_score": r[3], "verdict": r[4], "ingested_at": r[5]}
            for r in rows
        ]
    }), 200


if __name__ == "__main__":
    if not API_SECRET_KEY:
        print("[!] WARNING: API_SECRET_KEY is not set in .env -- endpoints will refuse all requests.")
        print("    Add this line to your .env file:")
        print("    API_SECRET_KEY=choose_any_long_random_string_here")

    app.run(debug=False, port=5001, host="127.0.0.1")
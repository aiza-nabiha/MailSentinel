"""
backend/storage_engine/api.py

POSTGRES VERSION. Changes from the original:
  - All `?` placeholders -> `%s`.
  - campaign_correlation now reads from campaign_membership /
    campaign_edges (the threat_correlation_engine.py cache tables)
    instead of the old campaigns / campaign_members / graph_edges
    tables written by the retired threat_graph_engine/correlate.py.
    Response shape kept backward-compatible (matched_investigations,
    matches[].signals) with a couple of extra fields (confidence,
    cohesion) added since the real engine actually computes those.
"""

import hmac
import os
import tempfile
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from db import get_connection, get_emails_for_user, log_access, get_trigger_metadata, get_raw_archive_for_email
from integrate import run as run_integration

load_dotenv()

app = Flask(__name__)

FRONTEND_DIST = Path(__file__).parent.parent.parent / "frontend" / "dist"


@app.route("/debug/dashboard-path", methods=["GET"])
def debug_dashboard_path():
    exists = FRONTEND_DIST.exists()
    contents = []
    if exists:
        try:
            contents = [str(p.name) for p in FRONTEND_DIST.iterdir()]
        except Exception as e:
            contents = [f"error listing: {e}"]
    return jsonify({
        "computed_path": str(FRONTEND_DIST),
        "exists": exists,
        "contents": contents,
        "cwd": str(Path.cwd()),
    })


@app.route("/dashboard", defaults={"path": ""})
@app.route("/dashboard/", defaults={"path": ""})
@app.route("/dashboard/<path:path>")
def serve_dashboard(path):
    target = FRONTEND_DIST / path if path else None
    if target and target.is_file():
        return send_from_directory(FRONTEND_DIST, path)
    return send_from_directory(FRONTEND_DIST, "index.html")


# The built index.html references root-level paths (/assets/..., /favicon.svg)
# rather than /dashboard-prefixed ones, so those need their own routes.
@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(FRONTEND_DIST / "assets", filename)


@app.route("/favicon.svg")
def serve_favicon():
    return send_from_directory(FRONTEND_DIST, "favicon.svg")


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
        "SELECT email_id, subject, from_header, overall_risk_score, verdict, ingested_at FROM emails WHERE email_id = %s",
        (email_id,),
    ).fetchone()
    if not email_row:
        return None

    domain_rows = conn.execute(
        """SELECT domain, risk_score, risk_level, risk_reasons_json, age_days, tls_issuer,
                  tls_status, found_on_lists_json, whois_json, dns_json, tls_json, reputation_json
           FROM domain_intel WHERE email_id = %s""",
        (email_id,),
    ).fetchall()
    header_row = conn.execute(
        "SELECT spf_result, dmarc_result, dmarc_policy, received_chain_json FROM header_results WHERE email_id = %s",
        (email_id,),
    ).fetchone()
    classifier_row = conn.execute(
        """SELECT phishing_score, verdict, reasons_json, source, url_intelligence_json
           FROM classifier_results WHERE email_id = %s""",
        (email_id,),
    ).fetchone()
    fingerprint_row = conn.execute(
        """SELECT structural_hash, skeleton_type, typosquat_matches_json, targeted_brands_json
           FROM fingerprints WHERE email_id = %s""",
        (email_id,),
    ).fetchone()
    infra_row = conn.execute(
        """SELECT risk_score, risk_level, reasons_json, evidence_json, reliable_hop_json, received_chain_json
           FROM infrastructure_risk WHERE email_id = %s""",
        (email_id,),
    ).fetchone()

    import json as _json

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

    # Real correlation data, now from threat_correlation_engine.py's
    # cache tables (see integrate.py's persist_campaign_cache()).
    campaign_row = conn.execute(
        """SELECT campaign_id, confidence, cohesion, cohesion_warning, signal_summary_json
           FROM campaign_membership WHERE email_id = %s LIMIT 1""",
        (email_id,),
    ).fetchone()
    campaign_correlation = None
    if campaign_row:
        campaign_id, confidence, cohesion, cohesion_warning, signal_summary_json = campaign_row
        member_rows = conn.execute(
            "SELECT email_id FROM campaign_membership WHERE campaign_id = %s AND email_id != %s",
            (campaign_id, email_id),
        ).fetchall()
        edge_rows = conn.execute(
            """SELECT source_email_id, target_email_id, confidence, signals_json FROM campaign_edges
               WHERE campaign_id = %s AND (source_email_id = %s OR target_email_id = %s)""",
            (campaign_id, email_id, email_id),
        ).fetchall()

        graph_row = conn.execute(
            "SELECT graph_json FROM campaign_graphs WHERE campaign_id = %s",
            (campaign_id,),
        ).fetchone()
        campaign_graph = _json.loads(graph_row[0]) if graph_row and graph_row[0] else None

        def _edge_info_for(other_email_id):
            types = []
            edge_confidence = None
            for source_id, target_id, edge_conf, signals_json in edge_rows:
                if other_email_id in (source_id, target_id) and email_id in (source_id, target_id):
                    edge_confidence = edge_conf
                    for s in (_json.loads(signals_json) if signals_json else []):
                        types.append(s.get("type"))
            return types, edge_confidence

        matches = []
        for r in member_rows:
            signal_types, edge_confidence = _edge_info_for(r[0])
            matches.append({"email_id": r[0], "signals": signal_types, "confidence": edge_confidence})

        campaign_correlation = {
            "campaign_id": campaign_id,
            "confidence": confidence,
            "cohesion": cohesion,
            "cohesion_warning": cohesion_warning,
            "matched_investigations": len(member_rows),
            "matches": matches,
            "graph": campaign_graph,
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
        "campaign_correlation": campaign_correlation,
        "triggered_by": {
            "user_id": trigger[0] if trigger else None,
            "ip_address": trigger[1] if trigger else None,
            "triggered_at": trigger[2] if trigger else None,
        },
    }

    if include_raw_content:
        archive = get_raw_archive_for_email(conn, email_id)
        result["raw_email"] = archive

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
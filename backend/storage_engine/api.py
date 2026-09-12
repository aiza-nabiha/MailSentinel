"""
backend/storage_engine/api.py (SECURITY-HARDENED, FULL DATA, MERGED)

The bridge between the Gmail Add-on sidebar and your pipeline.

Accepts EITHER:
  - {"eml_path": "test_emails/example.eml"}  -- for local testing, path-restricted to data/
  - {"raw_eml": "<full .eml text>"}          -- for the real sidebar, which sends the
    currently-open Gmail message's content directly (it has no server-side file path)

Security:
  1. Path traversal fix -- eml_path is restricted to a whitelisted directory.
  2. API key check -- caller must send a shared secret header.
  3. Debug mode OFF, bound to localhost only.
  4. raw_eml is written to a secure temp file and ALWAYS deleted after processing,
     even if analysis fails -- never left sitting on disk.
  5. Input validation -- rejects malformed/missing fields cleanly.

Setup (one-time):
    pip3 install flask python-dotenv
    Add to your .env file:
        API_SECRET_KEY=choose_any_long_random_string_here

Run it:
    python3 api.py
Then it's live at http://127.0.0.1:5001

Test it (path mode):
    curl -X POST http://localhost:5001/analyze \\
      -H "Content-Type: application/json" \\
      -H "X-API-Key: <your key>" \\
      -d '{"eml_path": "test_emails/example.eml"}'

Test it (raw_eml mode -- what the sidebar actually uses):
    curl -X POST http://localhost:5001/analyze \\
      -H "Content-Type: application/json" \\
      -H "X-API-Key: <your key>" \\
      -d '{"raw_eml": "From: test@example.com\\nSubject: Hi\\n\\nBody text"}'
"""

import os
import tempfile
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from db import get_connection
from integrate import run as run_integration

load_dotenv()

app = Flask(__name__)

ALLOWED_EML_DIR = (Path(__file__).parent.parent.parent / "data").resolve()
API_SECRET_KEY = os.environ.get("API_SECRET_KEY")


def _require_api_key():
    if not API_SECRET_KEY:
        return jsonify({"error": "Server misconfigured: API_SECRET_KEY not set"}), 500
    provided = request.headers.get("X-API-Key")
    if provided != API_SECRET_KEY:
        return jsonify({"error": "Unauthorized -- missing or invalid X-API-Key header"}), 401
    return None


def _resolve_safe_eml_path(user_supplied_path):
    candidate = (ALLOWED_EML_DIR / user_supplied_path).resolve()
    if not str(candidate).startswith(str(ALLOWED_EML_DIR)):
        return None
    return candidate


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/analyze", methods=["POST"])
def analyze():
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}
    eml_path_raw = data.get("eml_path")
    raw_eml = data.get("raw_eml")

    if not eml_path_raw and not raw_eml:
        return jsonify({"error": "Provide either eml_path or raw_eml"}), 400

    temporary_path = None

    if raw_eml:
        if not isinstance(raw_eml, str):
            return jsonify({"error": "raw_eml must be a string"}), 400
        # Sidebar case: no server-side file path exists -- write the email
        # content to a secure temp file, always cleaned up in the finally block.
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".eml", delete=False, encoding="utf-8"
        )
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
        email_id = run_integration(str(target_path))
    except Exception as e:
        print(f"[!] Pipeline error: {e}")
        return jsonify({"error": "Analysis failed -- check server logs"}), 500
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass

    conn = get_connection()

    email_row = conn.execute(
        "SELECT email_id, subject, from_header, overall_risk_score, verdict FROM emails WHERE email_id = ?",
        (email_id,),
    ).fetchone()

    domain_rows = conn.execute(
        "SELECT domain, risk_score, risk_level, risk_reasons_json FROM domain_intel WHERE email_id = ?",
        (email_id,),
    ).fetchall()

    header_row = conn.execute(
        "SELECT spf_result, dmarc_result, dmarc_policy FROM header_results WHERE email_id = ?",
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
        """SELECT risk_score, risk_level, reasons_json, evidence_json
           FROM infrastructure_risk WHERE email_id = ?""",
        (email_id,),
    ).fetchone()

    conn.close()

    result = {
        "email_id": email_row[0],
        "subject": email_row[1],
        "from_header": email_row[2],
        "overall_risk_score": email_row[3],
        "verdict": email_row[4],
        "header_auth": {
            "spf": header_row[0] if header_row else None,
            "dmarc": header_row[1] if header_row else None,
            "dmarc_policy": header_row[2] if header_row else None,
        },
        "classifier": {
            "phishing_score": classifier_row[0] if classifier_row else None,
            "verdict": classifier_row[1] if classifier_row else None,
            "reasons": classifier_row[2] if classifier_row else None,
            "source": classifier_row[3] if classifier_row else None,
        },
        "fingerprint": {
            "structural_hash": fingerprint_row[0] if fingerprint_row else None,
            "skeleton_type": fingerprint_row[1] if fingerprint_row else None,
            "typosquat_matches": fingerprint_row[2] if fingerprint_row else None,
            "targeted_brands": fingerprint_row[3] if fingerprint_row else None,
        },
        "infrastructure_risk": {
            "risk_score": infra_row[0] if infra_row else None,
            "risk_level": infra_row[1] if infra_row else None,
            "reasons": infra_row[2] if infra_row else None,
        },
        "domains": [
            {"domain": d[0], "risk_score": d[1], "risk_level": d[2], "reasons": d[3]}
            for d in domain_rows
        ],
    }
    return jsonify(result), 200


if __name__ == "__main__":
    if not API_SECRET_KEY:
        print("[!] WARNING: API_SECRET_KEY is not set in .env -- /analyze will refuse all requests.")
        print("    Add this line to your .env file:")
        print("    API_SECRET_KEY=choose_any_long_random_string_here")

    app.run(debug=False, port=5001, host="127.0.0.1")
"""
backend/storage_engine/api.py

The bridge between the (future) Gmail Add-on / plugin and your
existing pipeline. Wraps integrate.py's logic behind one HTTP
endpoint so anything that can make a POST request can trigger
analysis -- no more shelling out to a script.

Run it:
    python3 api.py
Then it's live at http://localhost:5000

Test it (from another terminal):
    curl -X POST http://localhost:5000/analyze \
      -H "Content-Type: application/json" \
      -d '{"eml_path": "../../data/test_emails/example.eml"}'

Install requirement (one-time):
    pip3 install flask
"""

from flask import Flask, request, jsonify
import os
import tempfile
from db import get_connection
from integrate import run as run_integration

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    """Quick check the server is alive -- hit this first when testing."""
    return jsonify({"status": "ok"})


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Expects JSON: {"eml_path": "path/to/email.eml"}

    Runs the SAME pipeline as integrate.py (Person 2 header parsing +
    Person 3 domain intel), stores it in the DB, and returns the
    combined result as JSON -- this is what the Gmail Add-on sidebar
    would call after the user clicks "Analyze this email".
    """
    data = request.get_json(silent=True) or {}
    eml_path = data.get("eml_path")
    raw_eml = data.get("raw_eml")

    if not eml_path and not raw_eml:
        return jsonify({"error": "Provide either eml_path or raw_eml"}), 400

    temporary_path = None
    if raw_eml:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".eml", delete=False, encoding="utf-8")
        handle.write(raw_eml)
        handle.close()
        temporary_path = handle.name
        eml_path = temporary_path

    try:
        email_id = run_integration(eml_path)
    except FileNotFoundError:
        return jsonify({"error": f"File not found: {eml_path}"}), 404
    except Exception as e:
        return jsonify({"error": f"Pipeline failed: {e}"}), 500
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass

    # Pull back the freshly-stored record to return to the caller
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
    conn.close()

    print("DEBUG email_row:", email_row)
    print("DEBUG header_row:", header_row)

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
        "domains": [
            {"domain": d[0], "risk_score": d[1], "risk_level": d[2], "reasons": d[3]}
            for d in domain_rows
        ],
    }
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(debug=True, port=5001)

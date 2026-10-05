"""
backend/ml_service/app.py

Standalone ML service -- hosts ONLY the content classifier so its RAM
(scikit-learn + pandas + the TF-IDF model, roughly 200 MB) lives in its
own Render instance instead of competing with Flask/Postgres/DNS/JARM
work in the main backend's 512 MB.

The main backend (storage_engine/integrate.py) POSTs the raw .eml bytes
to /classify and gets back the exact same dict that
content_analysis.analyze_email_file() returns locally. If ML_SERVICE_URL
is NOT set on the main backend it keeps loading the model in-process,
so local development is unchanged.

Run on Render with:
    gunicorn backend.ml_service.app:app --timeout 60 --max-requests 100 --max-requests-jitter 20
Required env var:  ML_SERVICE_TOKEN   (shared secret, same value on the main backend)
"""

import hmac
import json
import os
import sys
import tempfile
from pathlib import Path

# Same trick the main backend uses: put backend/ on sys.path so the
# engines import by their bare package names.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import numpy as np
from flask import Flask, Response, jsonify, request

from threat_detection_engine.core.content_analysis import (
    analyze_email_file,
    get_content_analyzer,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024  # 15 MB .eml cap

ML_SERVICE_TOKEN = os.environ.get("ML_SERVICE_TOKEN", "")

# Load the model once at boot so the first /classify isn't slow.
try:
    get_content_analyzer()
    print("[i] ML service: content classifier loaded")
except Exception as _preload_error:  # pragma: no cover
    print(f"[!] ML service: classifier preload failed: {_preload_error}")


def _json_default(obj):
    """Make numpy scalars/arrays JSON-safe (belt and braces)."""
    if isinstance(obj, np.generic):
        return obj.item()
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, (set, tuple)):
        return list(obj)
    raise TypeError(f"Not JSON serializable: {type(obj).__name__}")


@app.route("/health")
def health():
    # Also what the keep-alive cron pings.
    return jsonify({"status": "ok"})


@app.route("/classify", methods=["POST"])
def classify():
    if not ML_SERVICE_TOKEN:
        return jsonify({"error": "ML_SERVICE_TOKEN is not configured"}), 503

    supplied = request.headers.get("X-ML-Token", "")
    if not hmac.compare_digest(supplied.encode(), ML_SERVICE_TOKEN.encode()):
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_data()
    if not data:
        return jsonify({"error": "empty request body"}), 400

    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
        tmp.write(data)
        path = tmp.name

    try:
        result = analyze_email_file(path)
    except Exception as e:
        print(f"[!] ML service: classification failed: {e}")
        return jsonify({"error": f"classification failed: {e}"}), 500
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    return Response(
        json.dumps(result, default=_json_default),
        mimetype="application/json",
    )
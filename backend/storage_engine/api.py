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


import sys

import hmac

import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from flask import Flask, request, jsonify
from flask import session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv

from auth.google_auth import init_google_oauth
from authlib.integrations.base_client.errors import OAuthError
import tempfile
from functools import wraps
from pathlib import Path
from itsdangerous import URLSafeTimedSerializer, BadData

from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .db import (
    get_connection,
    get_emails_for_user,
    get_or_create_user,
    log_access,
    get_trigger_metadata,
    get_raw_archive_for_email,
)
from .integrate import run as run_integration

load_dotenv()

app = Flask(__name__)

# FRONTEND_URL is where OAuth and add-on magic links redirect back to,
# and the one origin CORS trusts with credentials (cookies). Was
# hardcoded to http://127.0.0.1:5173 before, which only ever worked
# for local dev -- a deployed frontend (Vercel, etc.) was silently
# never going to get a session cookie.
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://127.0.0.1:5173")

CORS(
    app,
    supports_credentials=True,
    origins=[FRONTEND_URL]
)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# Cross-site cookies (frontend and backend on different origins, e.g.
# Vercel + Render) need SameSite=None + Secure. Locally over http that
# combination makes browsers drop the cookie entirely, so only turn it
# on once FLASK_ENV=production is set.
IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"
app.config.update(
    SESSION_COOKIE_SAMESITE="None" if IS_PRODUCTION else "Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
)
oauth = init_google_oauth(app)

# Signs short-lived "addon session" tokens -- see mint_addon_session_token()
# and /auth/addon-session below. These let the Gmail/Outlook add-ins hand
# a browser tab straight into a logged-in website session, without the
# user re-doing Google OAuth, by trusting the identity the mail platform
# itself already verified (Session.getActiveUser() in Apps Script,
# Office.context.mailbox.userProfile.emailAddress in Outlook).
_addon_token_serializer = URLSafeTimedSerializer(app.secret_key)
ADDON_TOKEN_SALT = "addon-magic-link"
ADDON_TOKEN_MAX_AGE_SECONDS = 600  # 10 minutes -- just long enough to click through


def mint_addon_session_token(email, email_id=None):
    return _addon_token_serializer.dumps({"email": email, "email_id": email_id}, salt=ADDON_TOKEN_SALT)

# Load the ML content-classifier model once, at process startup,
# instead of on the first incoming request. Without this, the first
# /analyze call after a cold start/restart pays both the container
# boot cost and the ~7MB model deserialization cost back-to-back,
# which is exactly when latency (and memory headroom) matters most.
try:
    from threat_detection_engine.core.content_analysis import (
        get_content_analyzer,
    )

    get_content_analyzer()
except Exception as _preload_error:  # pragma: no cover
    print(f"[!] Content classifier preload failed: {_preload_error}")

@app.route("/auth/google")
def google_login():
    redirect_uri = url_for("google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():

    try:
        token = oauth.google.authorize_access_token()
    except OAuthError as e:
        # Covers MismatchingStateError and similar OAuth handshake
        # failures. Two real causes, neither one a bug in the happy
        # path:
        #   1. Bot/scanner traffic hitting this callback URL directly
        #      with made-up query params -- there's no real session
        #      behind it, so it will always fail this check. Harmless,
        #      just noisy in the logs.
        #   2. A genuine user who started the Google login flow twice
        #      (e.g. double-clicked "Login with Google", or went back
        #      and retried) -- the second attempt overwrites the
        #      `state` stored for the first one, so whichever tab
        #      finishes first mismatches.
        # Previously this raised uncaught and crashed with a bare 500.
        # Now it just sends the user back to try logging in again
        # instead of showing a broken error page.
        print(f"[!] Google OAuth callback failed: {e}")
        return redirect(f"{FRONTEND_URL}?login_error=1")

    userinfo = token.get("userinfo")

    if not userinfo:
        return "Google authentication failed.", 401

    session["user"] = {
        "email": userinfo.get("email"),
        "name": userinfo.get("name"),
        "picture": userinfo.get("picture")
    }
    session.permanent = True

    # Register/touch the user row now, at login time, rather than
    # waiting for their first /analyze -- so /history works even
    # before they've analyzed anything.
    conn = get_connection()
    get_or_create_user(conn, userinfo["email"])
    conn.commit()
    conn.close()

    return redirect(FRONTEND_URL)


@app.route("/auth/me")
def auth_me():
    user = session.get("user")

    if not user:
        return jsonify({"authenticated": False})

    return jsonify({
        "authenticated": True,
        "user": user
    })


@app.route("/auth/logout")
def auth_logout():
    session.clear()
    return redirect(FRONTEND_URL)


@app.route("/auth/addon-session", methods=["GET"])
def auth_addon_session():
    """
    Landing point for the "VIEW FULL INVESTIGATION" / "Open full
    report" link the add-ins put in their results -- the token was
    minted by mint_addon_session_token() right after /analyze ran for
    that same email address, so verifying it here is equivalent to a
    login: it sets the same session cookie google_callback() would,
    scoped to that one mailbox's identity, then hands the browser off
    to the normal website (now logged in, History included).
    """
    token = request.args.get("token", "")
    try:
        data = _addon_token_serializer.loads(
            token, salt=ADDON_TOKEN_SALT, max_age=ADDON_TOKEN_MAX_AGE_SECONDS
        )
    except BadData:
        return "This link has expired. Re-run the analysis from the add-in.", 401

    email = data.get("email")
    if not email:
        return "Invalid link.", 400

    session["user"] = {"email": email, "name": email, "picture": None}
    session.permanent = True

    conn = get_connection()
    get_or_create_user(conn, email)
    conn.commit()
    conn.close()

    email_id = data.get("email_id")
    target = f"{FRONTEND_URL}?investigation={email_id}" if email_id else FRONTEND_URL
    return redirect(target)


def login_required(view_fn):
    """
    Pulls the signed-in user's email out of the Flask session (set by
    google_callback, or by auth_addon_session on the add-in's behalf)
    and passes it to the view as the first positional arg. This is
    the ONLY source of truth for "who is this" for website-facing
    reads -- a user_id in the request body/query is never trusted,
    because that just lets anyone read/write any other user's data by
    passing a different email.
    """
    @wraps(view_fn)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not user or not user.get("email"):
            return jsonify({"error": "Not signed in"}), 401
        return view_fn(user["email"], *args, **kwargs)
    return wrapper


def identity_required(view_fn):
    """
    Like login_required, but also accepts a second trust channel for
    /analyze: a valid X-API-Key (a secret only our own Gmail/Outlook
    add-ins hold) plus a user_id in the request body. That user_id is
    trusted ONLY because it comes from the mail platform's own
    already-authenticated identity (never typed in by a browser user)
    -- see GmailEmailAnalyzer.gs and taskpane.js. Passes
    (user_id, source) to the view, where source is "session" or
    "addon", so /analyze knows whether to mint a magic-link token.
    """
    @wraps(view_fn)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if user and user.get("email"):
            return view_fn(user["email"], "session", *args, **kwargs)

        provided_key = request.headers.get("X-API-Key", "")
        if API_SECRET_KEY and hmac.compare_digest(provided_key, API_SECRET_KEY):
            data = request.get_json(silent=True) or {}
            addon_user_id = data.get("user_id")
            if addon_user_id and isinstance(addon_user_id, str):
                return view_fn(addon_user_id, "addon", *args, **kwargs)

        return jsonify({"error": "Not signed in"}), 401
    return wrapper


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


def _build_investigation_result(conn, email_id, include_raw_content=False, requesting_user_id=None):
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
        """SELECT phishing_score, verdict, reasons_json, source,
                url_intelligence_json, threat_contributions_json
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
        # Correlation detection itself stays GLOBAL -- the same
        # campaign hitting several different accounts is real signal
        # strength, so threat_correlation_engine.py matches across
        # everyone's investigations, not just this user's own. But
        # what gets SHOWN here is split: full detail (which email,
        # what signals) only for matches inside this user's own
        # account; anything belonging to another user collapses into
        # just a count, with no email_id or user identity exposed.
        member_rows = conn.execute(
            """SELECT cm.email_id, e.user_id FROM campaign_membership cm
               JOIN emails e ON e.email_id = cm.email_id
               WHERE cm.campaign_id = %s AND cm.email_id != %s""",
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
        other_accounts = set()
        for matched_email_id, owner_user_id in member_rows:
            if requesting_user_id is not None and owner_user_id == requesting_user_id:
                signal_types, edge_confidence = _edge_info_for(matched_email_id)
                matches.append({"email_id": matched_email_id, "signals": signal_types, "confidence": edge_confidence})
            else:
                other_accounts.add(owner_user_id)

        campaign_correlation = {
            "campaign_id": campaign_id,
            "confidence": confidence,
            "cohesion": cohesion,
            "cohesion_warning": cohesion_warning,
            "matched_investigations": len(member_rows),
            # Your own other investigations in this campaign -- full
            # detail, same shape as before.
            "matches": matches,
            # Signal strength from OTHER accounts, with zero
            # identifying detail -- no email_id, no user_id, just a
            # count, so one user can never see who else got hit.
            "other_accounts_affected": len(other_accounts),
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
        "threat_contributions": (
            _json.loads(classifier_row[5])
            if classifier_row and classifier_row[5]
            else {
                "items": [],
                "total_percentage": 0,
            }
        ),
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
@identity_required
def analyze(user_id, identity_source):
    auth_error = _require_api_key()
    if auth_error:
        conn = get_connection()
        log_access(conn, "/analyze", user_id, get_remote_address(), 401, "auth failed")
        conn.close()
        return auth_error

    data = request.get_json(silent=True) or {}
    eml_path_raw = data.get("eml_path")
    raw_eml = data.get("raw_eml")
    # user_id comes from identity_required -- the website session for
    # a manual upload, or a user_id an add-in read from the mail
    # platform's own verified identity. Never a value a browser user
    # could just type into the request body themselves.

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
    result = _build_investigation_result(conn, email_id, include_raw_content=True, requesting_user_id=user_id)
    conn.close()

    if identity_source == "addon":
        # The add-in has no browser session of its own to show this
        # report in -- hand it a one-click link that logs the
        # eventual browser tab into this same mailbox's account (see
        # /auth/addon-session) and lands directly on this investigation,
        # with that account's full history available right after.
        token = mint_addon_session_token(user_id, email_id=email_id)
        result["report_url"] = f"{request.url_root.rstrip('/')}/auth/addon-session?token={token}"

    return jsonify(result), 200


@app.route("/investigation/<email_id>", methods=["GET"])
@login_required
def get_investigation(user_id, email_id):
    auth_error = _require_api_key()
    if auth_error:
        return auth_error

    include_raw = request.args.get("full", "").lower() in ("true", "1", "yes")

    conn = get_connection()
    owner_row = conn.execute(
        "SELECT user_id FROM emails WHERE email_id = %s", (email_id,)
    ).fetchone()
    if owner_row is None:
        conn.close()
        return jsonify({"error": f"No investigation found for email_id: {email_id}"}), 404
    if owner_row[0] != user_id:
        # Exists, but belongs to someone else -- 404 instead of 403 so
        # this doesn't confirm to a guesser that the email_id is real.
        log_access(conn, "/investigation", user_id, get_remote_address(), 404, "not owner", email_id=email_id)
        conn.close()
        return jsonify({"error": f"No investigation found for email_id: {email_id}"}), 404

    result = _build_investigation_result(conn, email_id, include_raw_content=include_raw, requesting_user_id=user_id)
    conn.close()

    return jsonify(result), 200


@app.route("/history", methods=["GET"])
@limiter.limit("30 per minute")
@login_required
def history(user_id):
    auth_error = _require_api_key()
    if auth_error:
        conn = get_connection()
        log_access(conn, "/history", user_id, get_remote_address(), 401, "auth failed")
        conn.close()
        return auth_error

    # user_id comes from the session, not a query param -- otherwise
    # anyone could pass ?user_id=someone-else@gmail.com and read their
    # history.

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
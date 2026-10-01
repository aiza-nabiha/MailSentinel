# ==========================================================
# RISK ASSESSMENT
# ==========================================================

def get_ml_assessment(probability):
    """
    Convert model probability into a readable risk band.

    These are model-based risk bands, not verified
    real-world probabilities of maliciousness.
    """

    try:
        probability = float(probability)
    except (TypeError, ValueError):
        probability = 0.0

    probability = max(
        0.0,
        min(1.0, probability),
    )

    if probability < 0.30:
        risk_level = "Very low"

    elif probability < 0.50:
        risk_level = "Low"

    elif probability < 0.70:
        risk_level = "Medium"

    elif probability < 0.85:
        risk_level = "High"

    else:
        risk_level = "Very high"

    return {
        "probability": round(probability, 4),
        "risk_level": risk_level,
        "percentage": round(probability * 100, 2),
    }


# ==========================================================
# MARKETING CONTEXT
# ==========================================================

MARKETING_SIGNALS = {
    "unsubscribe": (
        "unsubscribe",
        "opt out",
        "opt-out",
    ),

    "preferences": (
        "manage preferences",
        "update preferences",
        "email preferences",
    ),

    "newsletter": (
        "newsletter",
        "weekly newsletter",
        "monthly newsletter",
    ),

    "event": (
        "webinar",
        "register here",
        "save your spot",
        "join us",
        "you will learn",
        "save your seat",
    ),

    "marketing": (
        "marketing",
        "promotional",
        "special offer",
        "new product",
        "product update",
        "view in browser",
    ),
}


def detect_marketing_context(text):
    """
    Identify common marketing-related language.

    Marketing signals are contextual clues only.
    They do not establish that an email is legitimate.
    """

    text = str(text or "").lower()

    detected_signals = []

    for category, phrases in MARKETING_SIGNALS.items():
        matched = any(
            phrase in text
            for phrase in phrases
        )

        if matched:
            detected_signals.append(category)

    return {
        "is_marketing_style": (
            len(detected_signals) >= 2
        ),

        "marketing_signal_count": len(
            detected_signals
        ),

        "marketing_signals": detected_signals,
    }


# ==========================================================
# EVIDENCE HELPERS
# ==========================================================

def _safe_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(value):
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _add_evidence(
    evidence,
    title,
    description,
    severity="info",
):
    evidence.append(
        {
            "title": title,
            "description": description,
            "severity": severity,
        }
    )


# ==========================================================
# SUPPORTING EVIDENCE
# ==========================================================

def generate_supporting_evidence(features):
    """
    Generate evidence from extracted email features.
    """

    features = features or {}

    evidence = []

    # ------------------------------------------------------
    # Credential-related language
    # ------------------------------------------------------

    credential_count = _safe_int(
        features.get("credential_count")
    )

    if credential_count > 0:
        _add_evidence(
            evidence,
            "Account or credential-related language",
            (
                f"Found {credential_count} credential-related "
                "keyword occurrence(s). Review any requests "
                "to sign in, verify an account, or provide "
                "authentication information."
            ),
            "warning",
        )

    # ------------------------------------------------------
    # Link mismatch
    # ------------------------------------------------------

    mismatch_count = _safe_int(
        features.get("link_mismatch_count")
    )

    if mismatch_count > 0:
        _add_evidence(
            evidence,
            "Displayed link and destination differ",
            (
                f"Found {mismatch_count} link(s) where the "
                "displayed URL domain differs from the "
                "actual destination domain."
            ),
            "high",
        )

    # ------------------------------------------------------
    # IP-based URLs
    # ------------------------------------------------------

    ip_url_count = _safe_int(
        features.get("ip_url_count")
    )

    if ip_url_count > 0:
        _add_evidence(
            evidence,
            "IP-address-based URL",
            (
                f"Found {ip_url_count} URL(s) using an IP "
                "address as the hostname instead of a "
                "conventional domain name."
            ),
            "warning",
        )

    # ------------------------------------------------------
    # Urgency
    # ------------------------------------------------------

    urgency_count = _safe_int(
        features.get("urgency_count")
    )

    if urgency_count > 0:
        _add_evidence(
            evidence,
            "Urgency-related language",
            (
                f"Found {urgency_count} urgency-related "
                "keyword occurrence(s)."
            ),
            "warning",
        )

    # ------------------------------------------------------
    # URL shorteners
    # ------------------------------------------------------

    shortener_count = _safe_int(
        features.get("shortener_count")
    )

    if shortener_count > 0:
        _add_evidence(
            evidence,
            "Shortened URLs",
            (
                f"Found {shortener_count} shortened URL(s). "
                "The final destination may not be apparent "
                "from the shortened link."
            ),
            "info",
        )

    # ------------------------------------------------------
    # Attachments
    # ------------------------------------------------------

    attachment_count = _safe_int(
        features.get("attachment_count")
    )

    if attachment_count > 0:
        _add_evidence(
            evidence,
            "Email attachment present",
            (
                f"Found {attachment_count} attachment(s). "
                "Review the file type and sender before "
                "opening."
            ),
            "info",
        )

    # ------------------------------------------------------
    # Financial language
    # ------------------------------------------------------

    financial_count = _safe_int(
        features.get("financial_count")
    )

    if financial_count > 0:
        _add_evidence(
            evidence,
            "Financial-related language",
            (
                f"Found {financial_count} financial-related "
                "keyword occurrence(s)."
            ),
            "info",
        )

    # ------------------------------------------------------
    # Non-ASCII characters
    # ------------------------------------------------------

    non_ascii_count = _safe_int(
        features.get("non_ascii_count")
    )

    if non_ascii_count > 0:
        _add_evidence(
            evidence,
            "Non-ASCII characters present",
            (
                f"Found {non_ascii_count} non-ASCII "
                "character(s). These can occur in ordinary "
                "multilingual emails as well as deceptive "
                "text, so context matters."
            ),
            "info",
        )

    # ------------------------------------------------------
    # Tracking URLs
    # ------------------------------------------------------

    tracking_count = _safe_int(
        features.get("tracking_url_count")
    )

    if tracking_count > 0:
        _add_evidence(
            evidence,
            "Tracking-related URLs",
            (
                f"Found {tracking_count} URL(s) with "
                "tracking-related parameters or paths."
            ),
            "info",
        )

    # ------------------------------------------------------
    # Redirect URLs
    # ------------------------------------------------------

    redirect_count = _safe_int(
        features.get("redirect_url_count")
    )

    if redirect_count > 0:
        _add_evidence(
            evidence,
            "Redirect-related URLs",
            (
                f"Found {redirect_count} URL(s) containing "
                "redirect-related query parameters."
            ),
            "info",
        )

    # ------------------------------------------------------
    # No strong evidence
    # ------------------------------------------------------

    strong_count = (
        credential_count
        + mismatch_count
        + ip_url_count
    )

    if strong_count == 0:
        _add_evidence(
            evidence,
            "No strong content indicators detected",
            (
                "The current feature extraction did not "
                "identify credential-related language, "
                "displayed-link mismatches, or IP-based URLs. "
                "This does not establish that the email is safe."
            ),
            "info",
        )

    return evidence


# ==========================================================
# EMAIL CONTEXT
# ==========================================================

def generate_context(
    features,
    sender_features=None,
    marketing_context=None,
):
    """
    Generate contextual observations about the email.
    """

    features = features or {}
    sender_features = sender_features or {}

    context = []

    # ------------------------------------------------------
    # Marketing language
    # ------------------------------------------------------

    marketing_context = marketing_context or {}

    if marketing_context.get("is_marketing_style"):
        signals = marketing_context.get(
            "marketing_signals",
            [],
        )

        context.append(
            {
                "title": "Marketing-style language detected",
                "description": (
                    "The message contains multiple common "
                    "marketing-related signals: "
                    + ", ".join(signals)
                    + ". This is context, not proof of legitimacy."
                ),
            }
        )

    # ------------------------------------------------------
    # URL count
    # ------------------------------------------------------

    url_count = _safe_int(
        features.get("url_count")
    )

    if url_count > 0:
        context.append(
            {
                "title": "URLs found",
                "description": (
                    f"The message contains {url_count} "
                    "unique URL(s) extracted from its text "
                    "and HTML links."
                ),
            }
        )

    # ------------------------------------------------------
    # Tracking
    # ------------------------------------------------------

    tracking_count = _safe_int(
        features.get("tracking_url_count")
    )

    if tracking_count > 0:
        context.append(
            {
                "title": "Tracking information",
                "description": (
                    f"{tracking_count} URL(s) contain "
                    "tracking-related parameters or paths. "
                    "Tracking is common in legitimate "
                    "mailing systems and is not conclusive."
                ),
            }
        )

    # ------------------------------------------------------
    # Redirects
    # ------------------------------------------------------

    redirect_count = _safe_int(
        features.get("redirect_url_count")
    )

    if redirect_count > 0:
        context.append(
            {
                "title": "Redirect-related parameters",
                "description": (
                    f"{redirect_count} URL(s) contain "
                    "redirect-related parameters."
                ),
            }
        )

    # ------------------------------------------------------
    # Long URLs
    # ------------------------------------------------------

    long_url_count = _safe_int(
        features.get("long_url_count")
    )

    if long_url_count > 0:
        context.append(
            {
                "title": "Long URLs",
                "description": (
                    f"{long_url_count} URL(s) have a length "
                    "of at least 150 characters. Long URLs "
                    "may contain tracking or encoded data."
                ),
            }
        )

    # ------------------------------------------------------
    # Return-Path mismatch
    # ------------------------------------------------------

    return_path_mismatch = _safe_int(
        sender_features.get("return_path_mismatch")
    )

    if return_path_mismatch:
        return_domain = sender_features.get(
            "return_path_domain",
            "",
        )

        from_domain = sender_features.get(
            "from_domain",
            "",
        )

        context.append(
            {
                "title": "Return-Path domain differs",
                "description": (
                    f"The From domain ({from_domain}) differs "
                    f"from the Return-Path domain "
                    f"({return_domain}). Mailing services "
                    "and email infrastructure can legitimately "
                    "use separate domains. Review with other "
                    "authentication and content signals."
                ),
            }
        )

    # ------------------------------------------------------
    # Reply-To mismatch
    # ------------------------------------------------------

    reply_to_mismatch = _safe_int(
        sender_features.get("reply_to_mismatch")
    )

    if reply_to_mismatch:
        reply_domain = sender_features.get(
            "reply_to_domain",
            "",
        )

        from_domain = sender_features.get(
            "from_domain",
            "",
        )

        context.append(
            {
                "title": "Reply-To domain differs",
                "description": (
                    f"The From domain ({from_domain}) differs "
                    f"from the Reply-To domain ({reply_domain}). "
                    "This may be intentional, but the reply "
                    "destination should be reviewed."
                ),
            }
        )

    # ------------------------------------------------------
    # HTML
    # ------------------------------------------------------

    if _safe_int(features.get("html_part_present")):
        context.append(
            {
                "title": "HTML content present",
                "description": (
                    "The email contains an HTML body. "
                    "HTML formatting is common in both "
                    "legitimate and malicious emails."
                ),
            }
        )

    # ------------------------------------------------------
    # Attachments
    # ------------------------------------------------------

    attachment_count = _safe_int(
        features.get("attachment_count")
    )

    if attachment_count > 0:
        context.append(
            {
                "title": "Attachments present",
                "description": (
                    f"The email contains {attachment_count} "
                    "attachment(s)."
                ),
            }
        )

    return context


# ==========================================================
# FINAL ASSESSMENT
# ==========================================================

def generate_final_assessment(
    probability,
    features,
    sender_features=None,
    marketing_context=None,
):
    """
    Generate a cautious, explainable assessment.

    The ML probability is treated as a model score.
    Marketing context never overrides the score or
    independently establishes email legitimacy.
    """

    probability = _safe_float(probability)

    features = features or {}
    sender_features = sender_features or {}
    marketing_context = marketing_context or {}

    credential_count = _safe_int(
        features.get("credential_count")
    )

    mismatch_count = _safe_int(
        features.get("link_mismatch_count")
    )

    ip_url_count = _safe_int(
        features.get("ip_url_count")
    )

    strong_indicators = (
        credential_count > 0
        or mismatch_count > 0
        or ip_url_count > 0
    )

    # ------------------------------------------------------
    # High model score
    # ------------------------------------------------------

    if probability >= 0.70:
        return (
            "The email has a high model-assessed phishing "
            "risk. Review the identified indicators, "
            "sender information, authentication results, "
            "and URL destinations before interacting "
            "with the message."
        )

    # ------------------------------------------------------
    # Medium model score
    # ------------------------------------------------------

    if probability >= 0.50:
        return (
            "The email has a medium-to-elevated model score. "
            "Review its links, sender metadata, authentication "
            "results, and any requests for sensitive "
            "information before taking action."
        )

    # ------------------------------------------------------
    # Lower model score with indicators
    # ------------------------------------------------------

    if strong_indicators:
        return (
            "The model score is below the phishing threshold, "
            "but one or more potentially relevant indicators "
            "were detected. A lower model score does not "
            "rule out phishing. Review the evidence before "
            "interacting with the email."
        )

    # ------------------------------------------------------
    # Marketing-style email
    # ------------------------------------------------------

    if marketing_context.get("is_marketing_style"):
        return (
            "The message contains marketing-style language "
            "and has a lower model score. These observations "
            "do not independently verify the sender or "
            "establish that the email is legitimate. "
            "Review the sender and destinations before "
            "interacting with links."
        )

    # ------------------------------------------------------
    # Default
    # ------------------------------------------------------

    return (
        "The model assigned a lower phishing score and "
        "the current content features did not identify "
        "the selected strong indicators. This is not a "
        "guarantee of safety. Verify unexpected requests "
        "and links independently."
    )


# ==========================================================
# COMPLETE ANALYSIS
# ==========================================================

def generate_analysis(
    probability,
    features,
    sender_features=None,
):
    """
    Generate the structured explanation used by
    content_analysis.py.
    """

    features = features or {}
    sender_features = sender_features or {}

    marketing_context = detect_marketing_context(
        ""
    )

    # Callers can provide content in the feature dictionary.
    analysis_text = features.get(
        "analysis_text",
        "",
    )

    if analysis_text:
        marketing_context = detect_marketing_context(
            analysis_text
        )

    ml_assessment = get_ml_assessment(
        probability
    )

    evidence = generate_supporting_evidence(
        features
    )

    context = generate_context(
        features,
        sender_features,
        marketing_context,
    )

    final_assessment = generate_final_assessment(
        probability,
        features,
        sender_features,
        marketing_context,
    )

    return {
        "ml_assessment": ml_assessment,
        "supporting_evidence": evidence,
        "context": context,
        "marketing_context": marketing_context,
        "final_assessment": final_assessment,
    }
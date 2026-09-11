def get_ml_assessment(threat_probability):

    if threat_probability < 0.30:
        return "Very low risk"

    elif threat_probability < 0.50:
        return "Low risk"

    elif threat_probability < 0.70:
        return "Medium risk"

    elif threat_probability < 0.85:
        return "High risk"

    else:
        return "Very high risk"


def generate_supporting_evidence(features):

    strong_indicators = []
    supporting_indicators = []
    clean_checks = []

    credential_count = features.get(
        "credential_count",
        0
    )

    if credential_count > 0:

        strong_indicators.append(
            f"⚠ Credential/account verification language detected "
            f"({credential_count} signal(s))"
        )

    else:

        clean_checks.append(
            "✓ No credential/account request detected"
        )

    link_mismatch_count = features.get(
        "link_mismatch_count",
        0
    )

    if link_mismatch_count > 0:

        strong_indicators.append(
            f"⚠ Link-domain mismatch detected "
            f"({link_mismatch_count} link(s))"
        )

    else:

        clean_checks.append(
            "✓ No link-domain mismatch detected"
        )

    ip_url_count = features.get(
        "ip_url_count",
        0
    )

    if ip_url_count > 0:

        strong_indicators.append(
            f"⚠ IP-based URL detected "
            f"({ip_url_count} URL(s))"
        )

    else:

        clean_checks.append(
            "✓ No IP-based URL detected"
        )

    shortener_count = features.get(
        "shortener_count",
        0
    )

    if shortener_count > 0:

        supporting_indicators.append(
            f"⚠ URL shortener(s) detected "
            f"({shortener_count})"
        )

    else:

        clean_checks.append(
            "✓ No URL shortener detected"
        )

    urgency_count = features.get(
        "urgency_count",
        0
    )

    if urgency_count > 0:

        supporting_indicators.append(
            f"⚠ Urgency language detected "
            f"({urgency_count} signal(s))"
        )

    else:

        clean_checks.append(
            "✓ No urgency language detected"
        )

    if (
        urgency_count > 0
        and credential_count > 0
    ):

        strong_indicators.append(
            "⚠ Urgency combined with credential/account language"
        )

    else:

        clean_checks.append(
            "✓ No urgency + credential combination detected"
        )

    attachment_count = features.get(
        "attachment_count",
        0
    )

    if attachment_count > 0:

        supporting_indicators.append(
            f"⚠ Attachment(s) detected "
            f"({attachment_count})"
        )

    else:

        clean_checks.append(
            "✓ No attachment detected"
        )

    financial_count = features.get(
        "financial_count",
        0
    )

    if financial_count > 0:

        supporting_indicators.append(
            f"⚠ Financial/payment language detected "
            f"({financial_count} signal(s))"
        )

    else:

        clean_checks.append(
            "✓ No financial/payment language detected"
        )

    non_ascii_count = features.get(
        "non_ascii_count",
        0
    )

    if non_ascii_count > 0:

        supporting_indicators.append(
            f"⚠ Non-ASCII characters detected "
            f"({non_ascii_count})"
        )

    else:

        clean_checks.append(
            "✓ No unusual non-ASCII characters detected"
        )

    evidence = []

    if strong_indicators:

        evidence.append(
            "Strong risk indicators:"
        )

        evidence.extend(
            strong_indicators
        )

    if supporting_indicators:

        evidence.append(
            "Supporting indicators:"
        )

        evidence.extend(
            supporting_indicators
        )

    if clean_checks:

        evidence.append(
            "Checks with no observed signal:"
        )

        evidence.extend(
            clean_checks
        )

    return evidence


def detect_marketing_context(content):

    text = " ".join(
        [
            str(content.get("subject", "")),
            str(content.get("combined_text", "")),
            str(content.get("html_text", ""))
        ]
    ).lower()

    marketing_signals = [
        "unsubscribe",
        "manage preferences",
        "webinar",
        "register here",
        "save your spot",
        "join us",
        "you will learn",
        "newsletter",
        "marketing",
        "view in browser",
        "update preferences",
        "opt out"
    ]

    detected_signals = []

    for signal in marketing_signals:

        if signal in text:

            detected_signals.append(
                signal
            )

    return detected_signals


def generate_context(content, features):

    context = []

    marketing_signals = detect_marketing_context(
        content
    )

    if len(marketing_signals) >= 2:

        context.append(
            "• Marketing-style email"
        )

    url_count = features.get(
        "url_count",
        0
    )

    tracking_url_count = features.get(
        "tracking_url_count",
        0
    )

    redirect_url_count = features.get(
        "redirect_url_count",
        0
    )

    long_url_count = features.get(
        "long_url_count",
        0
    )

    if tracking_url_count > 0:

        context.append(
            f"• {tracking_url_count} tracking URL(s)"
        )

    elif url_count > 0:

        context.append(
            f"• {url_count} embedded URLs"
        )

    if redirect_url_count > 0:

        context.append(
            f"• {redirect_url_count} redirect URL(s)"
        )

    if long_url_count > 0:

        context.append(
            f"• {long_url_count} long URL(s)"
        )

    sender_features = content.get(
        "sender_features",
        {}
    )

    if sender_features.get(
        "return_path_mismatch"
    ) == 1:

        context.append(
            "• Return-Path uses external email infrastructure"
        )

    if features.get(
        "html_part_present",
        0
    ) == 1:

        context.append(
            "• HTML-formatted email"
        )

    attachment_count = features.get(
        "attachment_count",
        0
    )

    if attachment_count > 0:

        context.append(
            f"• {attachment_count} attachment(s)"
        )

    return context


def generate_final_assessment(
    threat_probability,
    features,
    content
):

    marketing_signals = detect_marketing_context(
        content
    )

    strong_phishing_signal = (

        features.get(
            "link_mismatch_count",
            0
        ) > 0

        or

        features.get(
            "ip_url_count",
            0
        ) > 0

        or

        (
            features.get(
                "credential_count",
                0
            ) > 0

            and

            features.get(
                "urgency_count",
                0
            ) > 0
        )
    )

    if (
        threat_probability < 0.50
        and not strong_phishing_signal
        and len(marketing_signals) >= 2
    ):

        return (
            "Likely legitimate marketing email"
        )

    if (
        threat_probability < 0.50
        and not strong_phishing_signal
    ):

        return (
            "No strong phishing indicators detected"
        )

    if threat_probability >= 0.70:

        return (
            "Potentially malicious email "
            "requiring further investigation"
        )

    return (
        "Suspicious email — further investigation recommended"
    )


def generate_analysis(
    threat_probability,
    features,
    content
):

    return {
        "ml_assessment":
            get_ml_assessment(
                threat_probability
            ),

        "supporting_evidence":
            generate_supporting_evidence(
                features
            ),

        "context":
            generate_context(
                content,
                features
            ),

        "assessment":
            generate_final_assessment(
                threat_probability,
                features,
                content
            )
    }
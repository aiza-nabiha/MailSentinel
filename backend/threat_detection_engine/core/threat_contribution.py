"""
Threat contribution calculator.

This module converts the outputs of the existing detection engines
into a presentation-level contribution breakdown.

IMPORTANT:
- These are NOT probabilities.
- These are NOT raw SHAP values.
- They represent relative contribution of detected evidence.
- Existing engine scores are consumed rather than replaced.
"""

from typing import Any, Dict, List


FACTOR_KEYS = [
    "content_ml",
    "domain_infrastructure",
]

FACTOR_LABELS = {
    "content_ml": "Content / ML analysis",
    "domain_infrastructure": "Domain & infrastructure",
}

def _clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    """Keep a numeric value inside a safe range."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return minimum

    return max(minimum, min(value, maximum))


def _authentication_strength(authentication: Dict[str, Any]) -> float:
    """
    Convert existing SPF/DKIM/DMARC results into an evidence strength.

    This mirrors the project's existing authentication-risk logic
    without replacing the infrastructure risk scorer.
    """

    if not authentication:
        return 0.0

    strength = 0.0

    # SPF
    spf = authentication.get("spf", {}) or {}
    spf_result = str(spf.get("result", "")).lower()

    if spf_result == "fail":
        strength += 15.0
    elif spf_result == "softfail":
        strength += 15.0
    elif spf_result in {"neutral", "none"}:
        strength += 5.0

    # DKIM
    dkim_entries = authentication.get("dkim", []) or []

    if isinstance(dkim_entries, dict):
        dkim_entries = [dkim_entries]

    dkim_results = [
        str(entry.get("result", "")).lower()
        for entry in dkim_entries
        if isinstance(entry, dict)
    ]

    if any(result == "fail" for result in dkim_results):
        strength += 20.0
    elif dkim_results and not any(
        result == "pass" for result in dkim_results
    ):
        strength += 10.0

    # DMARC
    dmarc = authentication.get("dmarc", {}) or {}
    dmarc_result = str(dmarc.get("result", "")).lower()

    if dmarc_result == "fail":
        strength += 25.0
    elif dmarc_result in {"none", "neutral"}:
        strength += 5.0

    return _clamp(strength)


def _url_strength(url_intelligence: Dict[str, Any]) -> float:
    """
    Estimate URL-related evidence from the URL intelligence already
    produced by the content analyzer.

    This intentionally does not create a new URL ML model.
    """

    if not url_intelligence:
        return 0.0

    strength = 0.0

    url_count = int(url_intelligence.get("url_count", 0) or 0)
    ip_url_count = int(url_intelligence.get("ip_url_count", 0) or 0)
    shortener_count = int(
        url_intelligence.get("shortener_count", 0) or 0
    )
    long_url_count = int(
        url_intelligence.get("long_url_count", 0) or 0
    )
    tracking_url_count = int(
        url_intelligence.get("tracking_url_count", 0) or 0
    )
    redirect_url_count = int(
        url_intelligence.get("redirect_url_count", 0) or 0
    )

    # URL presence is evidence, but intentionally modest.
    if url_count > 0:
        strength += min(url_count * 2.0, 10.0)

    # Higher-risk structural URL indicators.
    strength += min(ip_url_count * 12.0, 30.0)
    strength += min(shortener_count * 8.0, 20.0)
    strength += min(long_url_count * 4.0, 12.0)
    strength += min(tracking_url_count * 2.0, 8.0)
    strength += min(redirect_url_count * 5.0, 15.0)

    return _clamp(strength)


def _qr_ocr_strength(url_intelligence: Dict[str, Any]) -> float:
    """
    QR/OCR contribution based on evidence extracted from images.

    Presence of extracted URLs is treated as stronger evidence than
    image presence alone.
    """

    if not url_intelligence:
        return 0.0

    qr_urls = url_intelligence.get("qr_urls", []) or []
    ocr_urls = url_intelligence.get("ocr_urls", []) or []
    image_url_count = int(
        url_intelligence.get("image_url_count", 0) or 0
    )

    strength = 0.0

    if qr_urls:
        strength += min(len(qr_urls) * 20.0, 50.0)

    if ocr_urls:
        strength += min(len(ocr_urls) * 12.0, 30.0)

    if image_url_count and not (qr_urls or ocr_urls):
        strength += 5.0

    return _clamp(strength)


def _attachment_strength(email_structure: Dict[str, Any]) -> float:
    """
    Attachment evidence.

    Attachment presence is kept separate from content/ML so the UI
    can explicitly show the attachment factor.
    """

    if not email_structure:
        return 0.0

    attachment_count = int(
        email_structure.get("attachment_count", 0) or 0
    )

    if attachment_count <= 0:
        return 0.0

    return _clamp(min(attachment_count * 10.0, 40.0))


def _classifier_risk_score(content_result: Dict[str, Any]) -> float:
    """
    Return the classifier's phishing risk as a 0-100 score.

    This is the model risk signal only. No frontend-facing SHAP
    values or separate contribution heuristics are calculated here.
    """
    if not content_result:
        return 0.0

    probability = content_result.get("threat_probability")

    try:
        probability = float(probability)
    except (TypeError, ValueError):
        return 0.0

    probability = max(0.0, min(probability, 1.0))
    return probability * 100.0


def calculate_threat_contributions(
    content_result: Dict[str, Any] = None,
    domain_infra_risk: float = 0.0,
    **_unused: Any,
) -> Dict[str, Any]:
    """
    Explain the final threat score using the same two primary
    risk signals used by storage_engine.integrate.

    Final score:
        40% classifier risk
        60% domain/infrastructure risk

    The returned values are score points, not independent evidence
    percentages. Their sum matches the final threat score.
    """

    classifier_risk_score = _classifier_risk_score(content_result)

    try:
        domain_infra_risk = float(domain_infra_risk or 0.0)
    except (TypeError, ValueError):
        domain_infra_risk = 0.0

    domain_infra_risk = max(
        0.0,
        min(domain_infra_risk, 100.0),
    )

    ml_impact = classifier_risk_score * 0.40
    domain_infra_impact = domain_infra_risk * 0.60

    final_score = round(
        ml_impact + domain_infra_impact
    )

    # Convert the two weighted values into integer display points
    # while guaranteeing that they add up exactly to final_score.
    ml_floor = int(ml_impact)
    infra_floor = int(domain_infra_impact)

    remainder = final_score - ml_floor - infra_floor

    ml_contribution = ml_floor
    infra_contribution = infra_floor

    if remainder > 0:
        ml_fraction = ml_impact - ml_floor
        infra_fraction = domain_infra_impact - infra_floor

        if ml_fraction >= infra_fraction:
            ml_contribution += remainder
        else:
            infra_contribution += remainder

    items = [
        {
            "key": "content_ml",
            "label": FACTOR_LABELS["content_ml"],
            "percentage": ml_contribution,
        },
        {
            "key": "domain_infrastructure",
            "label": FACTOR_LABELS["domain_infrastructure"],
            "percentage": infra_contribution,
        },
    ]

    return {
        "items": items,
        "total_percentage": sum(
            item["percentage"] for item in items
        ),
    }

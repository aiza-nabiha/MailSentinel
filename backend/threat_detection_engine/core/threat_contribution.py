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
    "url_analysis",
    "email_authentication",
    "infrastructure_reputation",
    "qr_ocr",
    "attachments",
]


FACTOR_LABELS = {
    "content_ml": "Content / ML analysis",
    "url_analysis": "URL analysis",
    "email_authentication": "Email authentication",
    "infrastructure_reputation": "Infrastructure / domain reputation",
    "qr_ocr": "QR / OCR analysis",
    "attachments": "Attachment analysis",
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


def _content_ml_strength(content_result: Dict[str, Any]) -> float:
    """
    Convert the existing calibrated ML threat probability into
    positive threat evidence strength.

    0.50 is the current classifier decision threshold.
    Below 0.50 contributes no positive phishing evidence.

    SHAP remains internal explainability information and is not
    directly converted into a percentage here.
    """

    probability = float(
        content_result.get("threat_probability", 0.0) or 0.0
    )

    probability = _clamp(probability, 0.0, 1.0)

    if probability <= 0.50:
        return 0.0

    # Maps:
    # 0.50 -> 0
    # 0.75 -> 50
    # 1.00 -> 100
    return _clamp((probability - 0.50) * 200.0, 0.0, 100.0)


def _infrastructure_strength(
    infrastructure_result: Dict[str, Any],
    domain_result: Dict[str, Any] = None,
) -> float:
    """
    Consume the existing infrastructure/domain risk scores.

    No new infrastructure scoring is performed here.
    """

    infrastructure_result = infrastructure_result or {}
    domain_result = domain_result or {}

    infrastructure_score = float(
        infrastructure_result.get("risk_score", 0.0) or 0.0
    )

    domain_score = float(
        domain_result.get("risk_score", 0.0) or 0.0
    )

    # Use the strongest existing infrastructure/domain signal,
    # matching the project's existing philosophy of not diluting
    # a strong malicious-domain signal.
    return _clamp(max(infrastructure_score, domain_score))


def _normalize_contributions(raw_scores: Dict[str, float]) -> Dict[str, int]:
    """
    Normalize positive evidence strengths into integer percentages
    whose total is exactly 100.

    Uses largest-remainder rounding so the displayed values never
    accidentally add up to 99 or 101.
    """

    positive = {
        key: max(float(value), 0.0)
        for key, value in raw_scores.items()
    }

    total = sum(positive.values())

    if total <= 0:
        return {key: 0 for key in FACTOR_KEYS}

    exact = {
        key: (value / total) * 100.0
        for key, value in positive.items()
    }

    floors = {
        key: int(value)
        for key, value in exact.items()
    }

    remainder = 100 - sum(floors.values())

    fractions = sorted(
        FACTOR_KEYS,
        key=lambda key: exact[key] - floors[key],
        reverse=True,
    )

    for key in fractions[:remainder]:
        floors[key] += 1

    return floors


def calculate_threat_contributions(
    content_result: Dict[str, Any] = None,
    url_intelligence: Dict[str, Any] = None,
    authentication: Dict[str, Any] = None,
    infrastructure_result: Dict[str, Any] = None,
    domain_result: Dict[str, Any] = None,
    email_structure: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Calculate the presentation-level detection contribution breakdown.

    Returns a backend-friendly structure that the frontend can render
    directly without knowing anything about SHAP or engine internals.
    """

    content_result = content_result or {}

    if url_intelligence is None:
        url_intelligence = content_result.get(
            "url_intelligence",
            {},
        )

    if email_structure is None:
        email_structure = content_result.get(
            "email_structure",
            {},
        )

    raw_scores = {
        "content_ml": _content_ml_strength(content_result),

        "url_analysis": _url_strength(
            url_intelligence
        ),

        "email_authentication": _authentication_strength(
            authentication or {}
        ),

        "infrastructure_reputation": _infrastructure_strength(
            infrastructure_result or {},
            domain_result or {},
        ),

        "qr_ocr": _qr_ocr_strength(
            url_intelligence
        ),

        "attachments": _attachment_strength(
            email_structure
        ),
    }

    contributions = _normalize_contributions(raw_scores)

    contribution_list: List[Dict[str, Any]] = [
        {
            "key": key,
            "label": FACTOR_LABELS[key],
            "percentage": contributions[key],
        }
        for key in FACTOR_KEYS
    ]

    return {
        "contributions": contributions,
        "items": contribution_list,
        "raw_evidence": raw_scores,
        "total_percentage": sum(contributions.values()),
    }

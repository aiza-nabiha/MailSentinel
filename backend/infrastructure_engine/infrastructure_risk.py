"""
B4 - Final Infrastructure Risk Assessment

Combines:
- Trusted-hop analysis
- IP intelligence
- SPF / DKIM / DMARC
"""

def _score_ip_intelligence(ip_data):
    score = 0
    reasons = []

    if not ip_data:
        return 0, reasons

    reputation = ip_data.get("reputation", {})

    if reputation.get("status") == "success":
        abuse_score = reputation.get("abuse_score")

        if abuse_score is not None:
            if abuse_score >= 80:
                score += 40
                reasons.append(
                    f"IP has very high AbuseIPDB score ({abuse_score})"
                )
            elif abuse_score >= 50:
                score += 25
                reasons.append(
                    f"IP has elevated AbuseIPDB score ({abuse_score})"
                )
            elif abuse_score >= 20:
                score += 10
                reasons.append(
                    f"IP has some AbuseIPDB risk ({abuse_score})"
                )

    return score, reasons


def _score_hop_reliability(hop_data):
    score = 0
    reasons = []

    if not hop_data:
        return 0, reasons

    reliability = str(
        hop_data.get("reliability", "")
    ).upper()

    confidence = hop_data.get("confidence", 0)

    if reliability == "SUSPICIOUS":
        score += 30
        reasons.append(
            "Earliest observable infrastructure is suspicious"
        )

    elif reliability == "UNKNOWN":
        score += 10
        reasons.append(
            "Earliest observable infrastructure could not be fully trusted"
        )

    elif reliability == "LIKELY_TRUSTED":
        if confidence < 0.5:
            score += 5
            reasons.append(
                "Infrastructure is only weakly classified as likely trusted"
            )

    return score, reasons


def _authentication_evidence(authentication):
    evidence = []

    if not authentication:
        return evidence

    # SPF
    spf = authentication.get("spf", {})
    spf_result = str(
        spf.get("result", "unknown")
    ).upper()

    evidence.append(f"SPF: {spf_result}")

    # DKIM
    dkim_entries = authentication.get("dkim", [])

    if isinstance(dkim_entries, dict):
        dkim_entries = [dkim_entries]

    dkim_results = []

    for entry in dkim_entries:
        if isinstance(entry, dict):
            result = str(
                entry.get("result", "unknown")
            ).upper()
            dkim_results.append(result)

    if dkim_results:
        evidence.append(
            f"DKIM: {', '.join(dkim_results)}"
        )
    else:
        evidence.append("DKIM: UNKNOWN")

    # DMARC
    dmarc = authentication.get("dmarc", {})
    dmarc_result = str(
        dmarc.get("result", "unknown")
    ).upper()

    evidence.append(f"DMARC: {dmarc_result}")

    return evidence


def _score_authentication(authentication):
    score = 0
    reasons = []

    if not authentication:
        return 0, reasons

    # SPF
    spf = authentication.get("spf", {})
    spf_result = str(
        spf.get("result", "")
    ).lower()

    if spf_result in {"fail", "softfail"}:
        score += 15
        reasons.append(
            f"SPF result is {spf_result}"
        )

    elif spf_result in {"neutral", "none"}:
        score += 5
        reasons.append(
            f"SPF result is {spf_result}"
        )

    # DKIM
    dkim_entries = authentication.get("dkim", [])

    if isinstance(dkim_entries, dict):
        dkim_entries = [dkim_entries]

    dkim_results = [
        str(entry.get("result", "")).lower()
        for entry in dkim_entries
        if isinstance(entry, dict)
    ]

    if any(result == "fail" for result in dkim_results):
        score += 20
        reasons.append("DKIM authentication failed")

    elif not any(result == "pass" for result in dkim_results):
        score += 10
        reasons.append("No successful DKIM authentication")

    # DMARC
    dmarc = authentication.get("dmarc", {})
    dmarc_result = str(
        dmarc.get("result", "")
    ).lower()

    if dmarc_result == "fail":
        score += 25
        reasons.append("DMARC authentication failed")

    elif dmarc_result in {"none", "neutral"}:
        score += 5
        reasons.append(
            f"DMARC result is {dmarc_result}"
        )

    return score, reasons


def assess_infrastructure(
    reliable_hop_analysis=None,
    ip_intelligence=None,
    authentication=None
):
    """
    Final infrastructure-level assessment.

    The identified IP is the earliest reliable
    observable infrastructure, not necessarily
    the attacker's IP.
    """

    total_score = 0
    reasons = []

    # 1. Hop reliability
    hop_score, hop_reasons = _score_hop_reliability(
        reliable_hop_analysis
    )

    total_score += hop_score
    reasons.extend(hop_reasons)

    # 2. IP intelligence
    ip_score, ip_reasons = _score_ip_intelligence(
        ip_intelligence
    )

    total_score += ip_score
    reasons.extend(ip_reasons)

    # 3. Authentication
    auth_score, auth_reasons = _score_authentication(
        authentication
    )

    total_score += auth_score
    reasons.extend(auth_reasons)

    # 4. Positive evidence
    evidence = []

    if reliable_hop_analysis:
        reliability = reliable_hop_analysis.get(
            "reliability"
        )

        if reliability:
            evidence.append(
                f"Hop reliability: {reliability}"
            )

        if reliable_hop_analysis.get("ip"):
            evidence.append(
                f"Observable IP: {reliable_hop_analysis['ip']}"
            )

        if reliable_hop_analysis.get("hostname"):
            evidence.append(
                f"Hostname: {reliable_hop_analysis['hostname']}"
            )

    if ip_intelligence:
        ipinfo = ip_intelligence.get("ipinfo", {})

        if ipinfo.get("status") == "success":
            if ipinfo.get("asn"):
                evidence.append(
                    f"ASN: {ipinfo['asn']}"
                )

            if ipinfo.get("as_name"):
                evidence.append(
                    f"Organization: {ipinfo['as_name']}"
                )

            if ipinfo.get("country"):
                evidence.append(
                    f"Country: {ipinfo['country']}"
                )

        reputation = ip_intelligence.get(
            "reputation", {}
        )

        if reputation.get("status") == "success":
            evidence.append(
                f"AbuseIPDB score: "
                f"{reputation.get('abuse_score', 'unknown')}"
            )

            evidence.append(
                f"AbuseIPDB reports: "
                f"{reputation.get('total_reports', 'unknown')}"
            )

    evidence.extend(
        _authentication_evidence(authentication)
    )

    total_score = min(total_score, 100)

    if total_score >= 60:
        level = "high"
    elif total_score >= 25:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": total_score,
        "risk_level": level,
        "reasons": reasons,
        "evidence": evidence
    }
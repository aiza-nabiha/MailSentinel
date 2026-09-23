"""
Combines WHOIS, TLS, reputation, IP intelligence, hop reliability,
and SPF/DKIM/DMARC authentication signals into risk scores.

This file used to be two separate files (risk_scorer.py and
infrastructure_risk.py) -- merged into one so there's a single
place to look for all risk-scoring logic, and one function
(compute_final_risk) that combines both into ONE final score per
email instead of two separate ones.

compute_risk() and assess_infrastructure() keep their exact original
names and signatures, so nothing that already calls them needs to
change -- only pipeline.py's import line needs to point here now
instead of at the old infrastructure_risk.py file.
"""


# ==================================================================
# DOMAIN-LEVEL SCORING (WHOIS, TLS, reputation, cert reuse)
# ==================================================================
#
# This is deliberately where "noise" domains (facebook.com,
# google.com, etc.) get naturally deprioritized -- NOT via a
# hardcoded exclusion list, but because they genuinely score as
# low-risk on real evidence (old domain, trusted cert issuer,
# clean reputation).
# ==================================================================

def _score_domain_age(whois_data):
    """
    Newly-registered domains are one of the strongest phishing
    signals available. A domain registered 5 days ago claiming
    to be your bank is a massive red flag; one registered 9
    years ago is not.
    """

    age_days = (whois_data.get("domain_age") or {}).get("days")

    if age_days is None:
        # Unknown age (WHOIS lookup failed/privacy-protected)
        # is itself mildly suspicious but not damning on its own.
        return 5, "Domain age could not be verified"

    if age_days < 7:
        return 40, f"Domain registered only {age_days} days ago"

    if age_days < 30:
        return 30, f"Domain registered only {age_days} days ago"

    if age_days < 180:
        return 10, f"Domain is relatively new ({age_days} days old)"

    return 0, None


def _score_tls(tls_data):
    """
    TLS signals: very-soon-to-expire certs and free/low-verification
    issuers are mild signals (not damning alone -- lots of
    legitimate small sites use Let's Encrypt), but combined with
    other flags they add up.
    """

    points = 0
    reasons = []

    days_left = tls_data.get("days_until_expiry")

    if days_left is not None and days_left < 3:
        points += 10
        reasons.append(f"Certificate expires in {days_left} days")

    issuer = (tls_data.get("issuer") or "").lower()

    LOW_VERIFICATION_ISSUERS = {"let's encrypt", "zerossl"}

    if any(li in issuer for li in LOW_VERIFICATION_ISSUERS):
        points += 5
        reasons.append(f"Free/low-verification certificate issuer ({tls_data.get('issuer')})")

    if tls_data.get("status") == "failed":
        points += 15
        reasons.append("Could not establish a valid TLS connection")

    return points, "; ".join(reasons) if reasons else None


def _score_reputation(reputation_data):
    """
    Direct hits against known threat-intel feeds are the strongest
    possible signal -- if PhishTank or Spamhaus DBL has already
    flagged this domain, that outweighs everything else.

    Matches the real output shape of check_domain_reputation():
        {"reputation": "high risk"/"clean", "found_on_lists": [...],
         "details": {"phishtank": {...}, "spamhaus": {...}}}
    """

    found_on_lists = reputation_data.get("found_on_lists", [])
    spamhaus_reasons = (
        reputation_data
        .get("details", {})
        .get("spamhaus", {})
        .get("reasons", [])
    )

    points = 0
    reasons = []

    if found_on_lists:
        points += 50
        reasons.append(f"Found on threat blocklist(s): {', '.join(found_on_lists)}")

    if spamhaus_reasons:
        points += 15
        reasons.append(f"Spamhaus classification: {', '.join(spamhaus_reasons)}")

    return points, "; ".join(reasons) if reasons else None


def _score_infrastructure_reuse(domain, all_domains_in_investigation):
    """
    If this domain shares a TLS certificate fingerprint or
    nameserver with another SUSPICIOUS domain already seen in
    this same investigation (or a past one, since TLS results
    persist across runs), that's a real correlation signal --
    this is the bridge into Person 4's correlation engine.
    """

    this_domain_data = all_domains_in_investigation.get(domain, {})
    shared_cert_domains = this_domain_data.get("tls", {}).get("cert_shared_with", [])

    if shared_cert_domains:
        return 15, f"Shares TLS certificate with: {', '.join(shared_cert_domains)}"

    return 0, None


def compute_risk(domain, domain_data, all_domains_in_investigation=None):
    """
    domain_data is expected to look like:
        {
            "whois": {...},        # from whois_lookup.py
            "tls": {...},          # from tls_lookup.py
            "reputation": {...},   # from reputation.py
        }

    all_domains_in_investigation (optional) is the FULL merged dict
    of every domain checked in this run, needed only for the
    infrastructure-reuse check.
    """

    all_domains_in_investigation = all_domains_in_investigation or {}

    total_score = 0
    reasons = []

    age_pts, age_reason = _score_domain_age(domain_data.get("whois", {}))
    total_score += age_pts
    if age_reason:
        reasons.append(age_reason)

    tls_pts, tls_reason = _score_tls(domain_data.get("tls", {}))
    total_score += tls_pts
    if tls_reason:
        reasons.append(tls_reason)

    rep_pts, rep_reason = _score_reputation(domain_data.get("reputation", {}))
    total_score += rep_pts
    if rep_reason:
        reasons.append(rep_reason)

    reuse_pts, reuse_reason = _score_infrastructure_reuse(
        domain, all_domains_in_investigation
    )
    total_score += reuse_pts
    if reuse_reason:
        reasons.append(reuse_reason)

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
        "reasons": reasons
    }


# ==================================================================
# INFRASTRUCTURE-LEVEL SCORING (IP, hop reliability, SPF/DKIM/DMARC)
# (moved in from infrastructure_risk.py -- names/logic unchanged)
# ==================================================================

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


# ==================================================================
# COMBINED FINAL SCORE -- domain risk + infrastructure risk, merged
# into ONE verdict. Wire this into pipeline.py whenever you're
# ready to replace the two separate scores with one; until then,
# compute_risk() and assess_infrastructure() still work exactly as
# they did before, independently.
# ==================================================================

CORROBORATION_THRESHOLD = 25
CORROBORATION_BONUS = 10


def compute_final_risk(
    domain_data_by_domain,
    reliable_hop_analysis=None,
    ip_intelligence=None,
    authentication=None
):
    """
    domain_data_by_domain: dict mapping each domain found in the
    email to its {"whois", "tls", "reputation"} data.

    Returns ONE final score for the whole email, built from
    whichever single domain looks worst plus the infrastructure/
    auth signal -- not an average, since one bad domain shouldn't
    get diluted by several clean ones (facebook.com links, tracking
    pixels, etc.) sitting in the same email.
    """

    domain_data_by_domain = domain_data_by_domain or {}

    domain_scores = {
        domain: compute_risk(domain, data, domain_data_by_domain)
        for domain, data in domain_data_by_domain.items()
    }

    worst_domain = None
    worst_domain_result = None

    for domain, result in domain_scores.items():
        if (
            worst_domain_result is None
            or result["risk_score"] > worst_domain_result["risk_score"]
        ):
            worst_domain = domain
            worst_domain_result = result

    domain_score = (
        worst_domain_result["risk_score"] if worst_domain_result else 0
    )

    infra_result = assess_infrastructure(
        reliable_hop_analysis=reliable_hop_analysis,
        ip_intelligence=ip_intelligence,
        authentication=authentication
    )

    infra_score = infra_result["risk_score"]

    base_score = max(domain_score, infra_score)

    corroborated = (
        domain_score >= CORROBORATION_THRESHOLD
        and infra_score >= CORROBORATION_THRESHOLD
    )

    bonus = CORROBORATION_BONUS if corroborated else 0

    final_score = min(base_score + bonus, 100)

    reasons = []

    if worst_domain_result:
        for reason in worst_domain_result["reasons"]:
            reasons.append(f"[Domain: {worst_domain}] {reason}")

    for reason in infra_result["reasons"]:
        reasons.append(f"[Infrastructure] {reason}")

    if corroborated:
        reasons.append(
            "Both domain evidence and infrastructure/authentication "
            "evidence independently indicate risk -- corroborating signals"
        )

    if final_score >= 60:
        level = "high"
    elif final_score >= 25:
        level = "medium"
    else:
        level = "low"

    return {
        "final_risk_score": final_score,
        "final_risk_level": level,
        "reasons": reasons,
        "evidence": infra_result.get("evidence", []),
        "breakdown": {
            "worst_domain": worst_domain,
            "domain_score": domain_score,
            "infrastructure_score": infra_score,
            "all_domain_scores": domain_scores
        }
    }


# ==================================================================
# STANDALONE TESTING
# ==================================================================

if __name__ == "__main__":

    domain_data = {
        "sbi-verify123.xyz": {
            "whois": {"domain_age": {"days": 4}},
            "tls": {
                "days_until_expiry": 60,
                "issuer": "Let's Encrypt",
                "status": "success",
                "cert_shared_with": []
            },
            "reputation": {
                "found_on_lists": ["PhishTank"],
                "details": {"spamhaus": {"reasons": []}}
            }
        },
        "facebook.com": {
            "whois": {"domain_age": {"days": 8000}},
            "tls": {
                "days_until_expiry": 300,
                "issuer": "DigiCert",
                "status": "success",
                "cert_shared_with": []
            },
            "reputation": {
                "found_on_lists": [],
                "details": {"spamhaus": {"reasons": []}}
            }
        }
    }

    authentication = {
        "spf": {"result": "fail"},
        "dkim": [{"result": "fail"}],
        "dmarc": {"result": "fail"}
    }

    ip_intelligence = {
        "reputation": {"status": "success", "abuse_score": 85},
        "ipinfo": {
            "status": "success",
            "asn": "AS12345",
            "as_name": "Cheap Hosting Ltd",
            "country": "XX"
        }
    }

    reliable_hop_analysis = {
        "reliability": "SUSPICIOUS",
        "ip": "203.0.113.7",
        "hostname": "bulk-mailer-node7.cheaphost.net"
    }

    result = compute_final_risk(
        domain_data,
        reliable_hop_analysis=reliable_hop_analysis,
        ip_intelligence=ip_intelligence,
        authentication=authentication
    )

    print(f"\nFINAL RISK SCORE: {result['final_risk_score']}/100 "
          f"({result['final_risk_level'].upper()})")

    print("\nReasons:")
    for r in result["reasons"]:
        print(f"  - {r}")

    print(f"\nWorst domain: {result['breakdown']['worst_domain']} "
          f"(score {result['breakdown']['domain_score']})")
    print(f"Infrastructure score: {result['breakdown']['infrastructure_score']}")
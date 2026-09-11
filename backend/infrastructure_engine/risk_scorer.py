"""
Combines WHOIS, TLS, and reputation signals into a single risk
verdict per domain. This is deliberately where "noise" domains
(facebook.com, google.com, etc.) get naturally deprioritized --
NOT via a hardcoded exclusion list, but because they genuinely
score as low-risk on real evidence (old domain, trusted cert
issuer, clean reputation).
"""


# ==================================================================
# INDIVIDUAL SIGNAL SCORERS
# Each returns (points, reason) -- reason is only included in the
# output if points > 0, so the final report only shows what
# actually contributed to the risk.
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


# ==================================================================
# COMBINED SCORER
# ==================================================================

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
# STANDALONE TESTING
# ==================================================================

if __name__ == "__main__":
    # Example: a freshly-registered domain with a bad reputation
    example = {
        "whois": {"domain_age": {"days": 4}},
        "tls": {"days_until_expiry": 60, "issuer": "Let's Encrypt", "status": "success", "cert_shared_with": []},
        "reputation": {"abuse_score": 80, "total_reports": 6, "found_on_lists": ["PhishTank"]},
    }

    result = compute_risk("sbi-verify123.xyz", example)

    print(f"\nDomain: sbi-verify123.xyz")
    print(f"Risk Score: {result['risk_score']}/100 ({result['risk_level'].upper()})")
    print("\nReasons:")
    for r in result["reasons"]:
        print(f"  - {r}")
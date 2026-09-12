import csv
import io
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


REQUEST_TIMEOUT = 10

PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.csv"
PHISHTANK_LOCAL_CACHE = "phishtank_feed.csv"
PHISHTANK_CACHE_MAX_AGE_SECONDS = 3600

SPAMHAUS_DBL_ZONE = "dbl.spamhaus.org"


# ==================================================================
# SPAMHAUS DBL RETURN CODES
# ==================================================================

SPAMHAUS_CODES = {
    "127.0.1.2": "spam domain",
    "127.0.1.4": "phishing domain",
    "127.0.1.5": "malware domain",
    "127.0.1.6": "botnet C2 domain",
    "127.0.1.102": "abused legit spam",
    "127.0.1.103": "abused legit phishing",
    "127.0.1.104": "abused legit malware",
    "127.0.1.105": "abused legit botnet C2",
}


# ==================================================================
# NORMALIZATION
# ==================================================================

def _normalize_url(url):
    """
    Normalize a URL for exact PhishTank comparison.

    Important:
    We DO NOT reduce the URL to a domain here.

    Path B requires URL-level intelligence.
    """

    if not url:
        return ""

    url = url.strip()

    if not url:
        return ""

    # Add a scheme if the extracted URL does not have one.
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlsplit(url)

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower().rstrip(".")

    if not hostname:
        return ""

    # Preserve the path/query because PhishTank is URL-level.
    path = parsed.path or "/"

    normalized = f"{scheme}://{hostname}{path}"

    if parsed.query:
        normalized += f"?{parsed.query}"

    return normalized


def _extract_hostname(url):
    """
    Extract only the hostname from a URL.
    """

    if not url:
        return ""

    try:

        if not url.lower().startswith(("http://", "https://")):
            url = "http://" + url

        hostname = urlsplit(url).hostname

        if hostname:
            return hostname.lower().rstrip(".")

    except Exception:
        pass

    return ""


# ==================================================================
# PHISHTANK FEED
# ==================================================================

def _download_phishtank_feed():
    """
    Download the current PhishTank feed and cache it locally.
    """

    response = requests.get(
        PHISHTANK_FEED_URL,
        timeout=REQUEST_TIMEOUT,
        headers={
            "User-Agent": "MailSentinel/1.0"
        }
    )

    response.raise_for_status()

    with open(
        PHISHTANK_LOCAL_CACHE,
        "w",
        encoding="utf-8"
    ) as f:
        f.write(response.text)

    return response.text


def _load_phishtank_urls():
    """
    Load phishing URLs from the PhishTank feed.

    IMPORTANT:
    This stores URLs, NOT just domains.

    That preserves the URL-level evidence required by Path B.
    """

    needs_download = True

    if os.path.exists(PHISHTANK_LOCAL_CACHE):

        age = (
            time.time()
            - os.path.getmtime(PHISHTANK_LOCAL_CACHE)
        )

        if age <= PHISHTANK_CACHE_MAX_AGE_SECONDS:
            needs_download = False

    if needs_download:

        try:

            csv_text = _download_phishtank_feed()

        except requests.exceptions.RequestException:

            # Use existing cache if available.
            if os.path.exists(PHISHTANK_LOCAL_CACHE):

                with open(
                    PHISHTANK_LOCAL_CACHE,
                    "r",
                    encoding="utf-8"
                ) as f:
                    csv_text = f.read()

            else:

                raise

    else:

        with open(
            PHISHTANK_LOCAL_CACHE,
            "r",
            encoding="utf-8"
        ) as f:
            csv_text = f.read()

    phishing_urls = set()

    reader = csv.DictReader(
        io.StringIO(csv_text)
    )

    for row in reader:

        url = row.get("url", "").strip()

        if not url:
            continue

        normalized_url = _normalize_url(url)

        if normalized_url:
            phishing_urls.add(normalized_url)

    return phishing_urls


# ==================================================================
# PHISHTANK URL CHECK
# ==================================================================

def check_url_phishtank(url):
    """
    Check an EXACT URL against PhishTank.

    This is the primary Path-B PhishTank signal.

    A match means the actual observed URL appears in
    the PhishTank feed.

    It does NOT mean that every URL on the same domain
    is malicious.
    """

    normalized_url = _normalize_url(url)

    if not normalized_url:

        return {
            "source": "PhishTank",
            "status": "error",
            "listed": False,
            "match_type": None,
            "error": "Invalid URL"
        }

    try:

        phishing_urls = _load_phishtank_urls()

        exact_match = (
            normalized_url in phishing_urls
        )

        return {
            "source": "PhishTank",
            "status": "success",
            "listed": exact_match,
            "match_type": (
                "exact_url"
                if exact_match
                else None
            ),
            "url": normalized_url
        }

    except Exception as e:

        return {
            "source": "PhishTank",
            "status": "error",
            "listed": False,
            "match_type": None,
            "url": normalized_url,
            "error": str(e)
        }


# ==================================================================
# DOMAIN CONTEXT FROM PHISHTANK
# ==================================================================

def check_domain_phishtank_context(domain):
    """
    Determine whether PhishTank contains URLs hosted on this domain.

    IMPORTANT:

    This is NOT an exact malicious-domain verdict.

    It is only contextual evidence:

        domain
           ↓
        PhishTank contains a phishing URL under this host
           ↓
        contextual association

    This is intentionally weaker than an exact URL match.
    """

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    if not domain:

        return {
            "source": "PhishTank",
            "status": "error",
            "listed": False,
            "match_type": None,
            "error": "Invalid domain"
        }

    try:

        phishing_urls = _load_phishtank_urls()

        matching_urls = []

        for phishing_url in phishing_urls:

            hostname = _extract_hostname(
                phishing_url
            )

            if hostname == domain:

                matching_urls.append(
                    phishing_url
                )

        return {
            "source": "PhishTank",
            "status": "success",

            # This means contextual association,
            # NOT an exact URL match.
            "listed": bool(matching_urls),

            "match_type": (
                "domain_context"
                if matching_urls
                else None
            ),

            "matching_url_count": len(
                matching_urls
            )
        }

    except Exception as e:

        return {
            "source": "PhishTank",
            "status": "error",
            "listed": False,
            "match_type": None,
            "error": str(e)
        }


# ==================================================================
# SPAMHAUS DBL
# ==================================================================

def check_spamhaus(domain):
    """
    Query Spamhaus DBL through DNS.

    NXDOMAIN / NoAnswer:
        Domain is not listed.

    127.0.1.x:
        Domain is listed.

    Timeout / other failure:
        Intelligence unavailable.
    """

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    if not DNS_AVAILABLE:

        return {
            "source": "Spamhaus DBL",
            "status": "error",
            "listed": False,
            "error": "dnspython is not installed"
        }

    query = (
        f"{domain}.{SPAMHAUS_DBL_ZONE}"
    )

    try:

        answers = dns.resolver.resolve(
            query,
            "A",
            lifetime=REQUEST_TIMEOUT
        )

        return_codes = [
            str(rdata)
            for rdata in answers
        ]

        listed_codes = [
            code
            for code in return_codes
            if code.startswith("127.0.1.")
        ]

        if not listed_codes:

            return {
                "source": "Spamhaus DBL",
                "status": "success",
                "listed": False
            }

        reasons = [
            SPAMHAUS_CODES.get(
                code,
                f"listed ({code})"
            )
            for code in listed_codes
        ]

        return {
            "source": "Spamhaus DBL",
            "status": "success",
            "listed": True,
            "return_codes": listed_codes,
            "reasons": reasons
        }

    except dns.resolver.NXDOMAIN:

        return {
            "source": "Spamhaus DBL",
            "status": "success",
            "listed": False
        }

    except dns.resolver.NoAnswer:

        return {
            "source": "Spamhaus DBL",
            "status": "success",
            "listed": False
        }

    except dns.resolver.Timeout:

        return {
            "source": "Spamhaus DBL",
            "status": "error",
            "listed": False,
            "error": "Spamhaus DNS lookup timed out"
        }

    except Exception as e:

        return {
            "source": "Spamhaus DBL",
            "status": "error",
            "listed": False,
            "error": str(e)
        }


# ==================================================================
# URL-LEVEL REPUTATION
# ==================================================================

def check_url_reputation(url):
    """
    PATH B — URL LEVEL

    Email
      ↓
    URL
      ↓
    PhishTank exact URL check

    This should be used when the pipeline has the actual
    URLs extracted from the email.
    """

    phishtank_result = check_url_phishtank(url)

    if phishtank_result.get("listed"):

        reputation = "high risk"

    elif phishtank_result.get("status") == "error":

        reputation = "unknown"

    else:

        reputation = "clean"

    return {
        "url": _normalize_url(url),

        "reputation": reputation,

        "found_on_lists": (
            ["PhishTank"]
            if phishtank_result.get("listed")
            else []
        ),

        "sources_checked": [
            "PhishTank"
        ],

        "details": {
            "phishtank": phishtank_result
        }
    }


# ==================================================================
# DOMAIN-LEVEL REPUTATION
# ==================================================================

def check_domain_reputation(domain):
    """
    PATH B — DOMAIN LEVEL

    Email
      ↓
    Domain
      ↓
    Spamhaus DBL + contextual PhishTank evidence

    IMPORTANT:

    A PhishTank domain association is NOT treated as an
    exact URL match.

    Exact URL matching belongs to check_url_reputation().
    """

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    phishtank_context = (
        check_domain_phishtank_context(domain)
    )

    spamhaus_result = check_spamhaus(domain)

    found_on_lists = []
    contextual_sources = []

    # Spamhaus is a domain-level blocklist.
    if spamhaus_result.get("listed"):

        found_on_lists.append(
            "Spamhaus DBL"
        )

    # PhishTank domain association is contextual evidence only.
    if phishtank_context.get("listed"):
        contextual_sources.append("PhishTank")

    # --------------------------------------------------------------
    # Determine domain reputation
    # --------------------------------------------------------------

    if spamhaus_result.get("listed"):

        reputation = "high risk"

    else:

        source_errors = []

        if (
            phishtank_context.get("status")
            == "error"
        ):
            source_errors.append(
                "PhishTank"
            )

        if (
            spamhaus_result.get("status")
            == "error"
        ):
            source_errors.append(
                "Spamhaus DBL"
            )

        if source_errors:

            reputation = "unknown"

        else:

            reputation = "clean"

    evidence = []

    if spamhaus_result.get("listed"):
        evidence.append({
            "source": "Spamhaus DBL",
            "type": "domain_blocklist",
            "severity": "high",
            "details": spamhaus_result.get("reasons", [])
        })

    if phishtank_context.get("listed"):
        evidence.append({
            "source": "PhishTank",
            "type": "domain_context",
            "severity": "contextual",
            "matching_url_count": phishtank_context.get(
                "matching_url_count",
                0
            )
        })

    if not evidence:
        evidence.append({
            "source": "Reputation checks",
            "type": "no_known_reputation_match",
            "severity": "informational"
        })

    sources_checked = []

    if phishtank_context.get("status") == "success":
        sources_checked.append("PhishTank")

    if spamhaus_result.get("status") == "success":
        sources_checked.append("Spamhaus DBL")    

    return {
        "domain": domain,

        "reputation": reputation,

        "found_on_lists": found_on_lists,

        "contextual_sources": contextual_sources,

        "evidence": evidence,

        "sources_checked": sources_checked,

        "details": {

            # Contextual evidence only.
            "phishtank": phishtank_context,

            # Actual domain-level reputation.
            "spamhaus": spamhaus_result
        }
    }


# ==================================================================
# PULL DOMAINS FROM DNS RESULTS
# ==================================================================

def get_domains_from_dns_results(
    dns_results_file="dns_results.json"
):
    """
    Extract domains from dns_lookup.py output.
    """

    with open(
        dns_results_file,
        "r",
        encoding="utf-8"
    ) as f:

        dns_results = json.load(f)

    domains = set()

    for entry in dns_results:

        domain = entry.get("domain")

        if domain:

            domains.add(
                domain
                .strip()
                .lower()
                .rstrip(".")
            )

    return sorted(domains)


# ==================================================================
# INVESTIGATE DOMAIN REPUTATION
# ==================================================================

def investigate_domain_reputation(
    dns_results_file="dns_results.json"
):
    """
    Run domain-level reputation checks.

    This function remains compatible with the
    existing DNS-results workflow.
    """

    print("\n" + "=" * 60)
    print("DOMAIN REPUTATION")
    print("=" * 60)

    domains = get_domains_from_dns_results(
        dns_results_file
    )

    print(
        f"\nDiscovered domains: {len(domains)}"
    )

    results = []

    for domain in domains:

        print("\n" + "-" * 60)
        print(f"Domain: {domain}")
        print("-" * 60)

        result = check_domain_reputation(
            domain
        )

        results.append(result)

        print(
            f"Reputation: "
            f"{result['reputation']}"
        )

        print(
            f"Found on: "
            f"{result['found_on_lists'] or 'none'}"
        )

        phishtank = (
            result["details"]
            .get("phishtank", {})
        )

        if phishtank.get("match_type") == "domain_context":

            print(
                "PhishTank: "
                "contextual domain association"
            )

    output = {

        "investigation": {

            "observed_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "source": dns_results_file,

            "intelligence_providers": [
                "PhishTank",
                "Spamhaus DBL"
            ]
        },

        "domains": results
    }

    with open(
        "domain_reputation_results.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            indent=4
        )

    print(
        "\n\nDomain reputation saved to:"
    )

    print(
        "domain_reputation_results.json"
    )

    return output


# ==================================================================
# STANDALONE TEST
# ==================================================================

if __name__ == "__main__":

    print("\nDomain Reputation Tester")
    print("=" * 60)

    test_type = input(
        "Check (1) URL or (2) Domain: "
    ).strip()

    value = input(
        "Enter URL/domain: "
    ).strip()

    if not value:

        print("[-] No value provided.")

    elif test_type == "1":

        result = check_url_reputation(
            value
        )

        print(
            "\n" +
            json.dumps(
                result,
                indent=4
            )
        )

    else:

        result = check_domain_reputation(
            value
        )

        print(
            "\n" +
            json.dumps(
                result,
                indent=4
            )
        )
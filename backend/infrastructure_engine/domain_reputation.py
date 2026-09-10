import csv
import io
import json
import os
import time
from datetime import datetime, timezone

import requests

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


REQUEST_TIMEOUT = 10

PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.csv"
PHISHTANK_LOCAL_CACHE = "phishtank_feed.csv"
PHISHTANK_CACHE_MAX_AGE_SECONDS = 3600  # refresh hourly, matches PhishTank's own update cycle

SPAMHAUS_DBL_ZONE = "dbl.spamhaus.org"

# Spamhaus DBL return codes -> what they mean
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
# PHISHTANK
# ==================================================================

def _download_phishtank_feed():
    """
    Download the PhishTank free CSV feed and cache it locally.
    Free feed has no key requirement but is rate-limited, so we
    cache for an hour (PhishTank's own refresh interval) instead
    of hitting it on every domain check.
    """

    response = requests.get(
        PHISHTANK_FEED_URL,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": "phishtank/mailsentinel"}
    )

    response.raise_for_status()

    with open(PHISHTANK_LOCAL_CACHE, "w", encoding="utf-8") as f:
        f.write(response.text)

    return response.text


def _load_phishtank_domains():
    """
    Return a set of domains currently listed in the PhishTank feed.
    Downloads a fresh copy only if the local cache is missing or stale.
    """

    needs_download = True

    if os.path.exists(PHISHTANK_LOCAL_CACHE):
        age = time.time() - os.path.getmtime(PHISHTANK_LOCAL_CACHE)
        needs_download = age > PHISHTANK_CACHE_MAX_AGE_SECONDS

    if needs_download:
        try:
            csv_text = _download_phishtank_feed()
        except requests.exceptions.RequestException:
            # fall back to whatever is cached, even if stale
            if os.path.exists(PHISHTANK_LOCAL_CACHE):
                with open(PHISHTANK_LOCAL_CACHE, "r", encoding="utf-8") as f:
                    csv_text = f.read()
            else:
                return set()
    else:
        with open(PHISHTANK_LOCAL_CACHE, "r", encoding="utf-8") as f:
            csv_text = f.read()

    domains = set()

    reader = csv.DictReader(io.StringIO(csv_text))

    for row in reader:
        url = row.get("url", "")

        # crude host extraction, good enough since we only need the domain
        host = (
            url
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .split(":")[0]
            .lower()
        )

        if host:
            domains.add(host)

    return domains


def check_phishtank(domain):
    """
    Check a single domain against the cached PhishTank feed.
    """

    try:
        listed_domains = _load_phishtank_domains()

        return {
            "source": "PhishTank",
            "status": "success",
            "listed": domain.lower() in listed_domains
        }

    except Exception as e:
        return {
            "source": "PhishTank",
            "status": "error",
            "listed": False,
            "error": str(e)
        }


# ==================================================================
# SPAMHAUS DBL
# ==================================================================

def check_spamhaus(domain):
    """
    Query Spamhaus's free Domain Block List (DBL) via DNS.
    A domain is listed if <domain>.dbl.spamhaus.org resolves to
    a 127.0.1.x address. NXDOMAIN just means "not listed".
    """

    if not DNS_AVAILABLE:
        return {
            "source": "Spamhaus DBL",
            "status": "error",
            "listed": False,
            "error": "dnspython not installed"
        }

    query = f"{domain}.{SPAMHAUS_DBL_ZONE}"

    try:
        answers = dns.resolver.resolve(query, "A")

        return_codes = [str(rdata) for rdata in answers]

        reasons = [
            SPAMHAUS_CODES.get(code, f"listed ({code})")
            for code in return_codes
        ]

        return {
            "source": "Spamhaus DBL",
            "status": "success",
            "listed": True,
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

    except Exception as e:
        return {
            "source": "Spamhaus DBL",
            "status": "error",
            "listed": False,
            "error": str(e)
        }


# ==================================================================
# MERGE INTO ONE RISK OBJECT
# ==================================================================

def check_domain_reputation(domain):
    """
    Check one domain against every source and merge into a single
    risk object, matching the {domain, reputation, found_on_lists}
    shape from the project spec.
    """

    domain = domain.strip().lower()

    phishtank_result = check_phishtank(domain)
    spamhaus_result = check_spamhaus(domain)

    found_on_lists = []

    if phishtank_result.get("listed"):
        found_on_lists.append("PhishTank")

    if spamhaus_result.get("listed"):
        found_on_lists.append("Spamhaus DBL")

    return {
        "domain": domain,
        "reputation": "high risk" if found_on_lists else "clean",
        "found_on_lists": found_on_lists,
        "sources_checked": ["PhishTank", "Spamhaus DBL"],
        "details": {
            "phishtank": phishtank_result,
            "spamhaus": spamhaus_result
        }
    }


# ==================================================================
# PULL DOMAINS + RUN INVESTIGATION
# ==================================================================

def get_domains_from_dns_results(dns_results_file="dns_results.json"):
    """
    Extract domains to check from dns_lookup.py's output, which is
    a plain list of {"domain": ..., "records": {...}} objects.
    """

    with open(dns_results_file, "r", encoding="utf-8") as f:
        dns_results = json.load(f)

    domains = set()

    for entry in dns_results:
        domain = entry.get("domain")

        if domain:
            domains.add(domain.lower())

    return sorted(domains)


def investigate_domain_reputation(dns_results_file="dns_results.json"):
    """
    Run domain reputation checks for every domain found in the
    DNS lookup results, and save a final artifact.
    """

    print("\n" + "=" * 60)
    print("DOMAIN REPUTATION")
    print("=" * 60)

    domains = get_domains_from_dns_results(dns_results_file)

    print(f"\nDiscovered domains: {len(domains)}")

    results = []

    for domain in domains:
        print("\n" + "-" * 60)
        print(f"Domain: {domain}")
        print("-" * 60)

        result = check_domain_reputation(domain)
        results.append(result)

        print(f"Reputation: {result['reputation']}")
        print(f"Found on: {result['found_on_lists'] or 'none'}")

    output = {
        "investigation": {
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "source": dns_results_file,
            "intelligence_providers": ["PhishTank", "Spamhaus DBL"]
        },
        "domains": results
    }

    with open("domain_reputation_results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)

    print("\n\nDomain reputation saved to:")
    print("domain_reputation_results.json")

    return output


# ==================================================================
# STANDALONE TEST
# ==================================================================

if __name__ == "__main__":

    test_domain = input("Enter domain to check: ").strip()

    if not test_domain:
        print("[-] No domain provided.")
    else:
        result = check_domain_reputation(test_domain)
        print("\n" + json.dumps(result, indent=4))
import json
import os
import ipaddress
from datetime import datetime, timezone
from dotenv import load_dotenv

import requests

load_dotenv()

ABUSEIPDB_API_KEY=os.getenv("ABUSEIPDB_API_KEY")

if not ABUSEIPDB_API_KEY:
    raise RuntimeError("ABUSEIPDB_API_KEY is not configured")


ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"

REQUEST_TIMEOUT = 10

DEFAULT_MAX_AGE_DAYS = 90


def is_valid_ip(value):
    """
    Check whether a value is a valid IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


def get_ip_addresses(
    infrastructure_file="infrastructure_results.json"
):
    """
    Extract IP addresses from the infrastructure analyzer output.
    """

    with open(
        infrastructure_file,
        "r",
        encoding="utf-8"
    ) as f:

        infrastructure = json.load(f)

    ip_addresses = set()

    for entity in infrastructure.get("entities", []):

        entity_type = entity.get("type")
        value = entity.get("value")

        if entity_type in ("ipv4", "ipv6") and value:

            if is_valid_ip(value):

                ip_addresses.add(value)

    return sorted(ip_addresses)


def check_ip_reputation(
    ip_address,
    api_key,
    max_age_days=DEFAULT_MAX_AGE_DAYS
):
    """
    Check an IP address against AbuseIPDB.
    """

    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days
    }

    try:

        response = requests.get(
            ABUSEIPDB_API,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 429:

            return {
                "ip": ip_address,
                "status": "rate_limited",
                "source": "AbuseIPDB",
                "error": "API rate limit exceeded"
            }

        if response.status_code == 401:

            return {
                "ip": ip_address,
                "status": "unauthorized",
                "source": "AbuseIPDB",
                "error": "Invalid API key"
            }

        response.raise_for_status()

        response_data = response.json()

        data = response_data.get("data", {})

        return {
            "ip": ip_address,
            "status": "success",
            "source": "AbuseIPDB",

            "abuse_confidence_score": data.get(
                "abuseConfidenceScore"
            ),

            "total_reports": data.get(
                "totalReports"
            ),

            "num_distinct_users": data.get(
                "numDistinctUsers"
            ),

            "last_reported_at": data.get(
                "lastReportedAt"
            ),

            "country_code": data.get(
                "countryCode"
            ),

            "country_name": data.get(
                "countryName"
            ),

            "isp": data.get(
                "isp"
            ),

            "domain": data.get(
                "domain"
            ),

            "usage_type": data.get(
                "usageType"
            ),

            "is_public": data.get(
                "isPublic"
            ),

            "is_whitelisted": data.get(
                "isWhitelisted"
            ),

            "is_tor": data.get(
                "isTor"
            ),

            "hostnames": data.get(
                "hostnames",
                []
            )
        }

    except requests.exceptions.Timeout:

        return {
            "ip": ip_address,
            "status": "error",
            "source": "AbuseIPDB",
            "error": "Request timed out"
        }

    except requests.exceptions.RequestException as e:

        return {
            "ip": ip_address,
            "status": "error",
            "source": "AbuseIPDB",
            "error": str(e)
        }

    except ValueError:

        return {
            "ip": ip_address,
            "status": "error",
            "source": "AbuseIPDB",
            "error": "Invalid JSON response"
        }


def investigate_threats(
    infrastructure_file="infrastructure_results.json"
):

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:

        raise RuntimeError(
            "ABUSEIPDB_API_KEY environment variable "
            "is not set."
        )

    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE")
    print("=" * 60)

    ip_addresses = get_ip_addresses(
        infrastructure_file
    )

    print(
        f"\nDiscovered IP addresses: "
        f"{len(ip_addresses)}"
    )

    results = []

    for ip in ip_addresses:

        print("\n" + "-" * 60)
        print(f"IP: {ip}")
        print("-" * 60)

        result = check_ip_reputation(
            ip,
            api_key
        )

        results.append(result)

        if result["status"] == "success":

            print(
                f"Abuse Confidence: "
                f"{result.get('abuse_confidence_score')}"
            )

            print(
                f"Total Reports: "
                f"{result.get('total_reports')}"
            )

            print(
                f"Distinct Reporters: "
                f"{result.get('num_distinct_users')}"
            )

            print(
                f"Last Reported: "
                f"{result.get('last_reported_at')}"
            )

            print(
                f"Usage Type: "
                f"{result.get('usage_type')}"
            )

            print(
                f"Country: "
                f"{result.get('country_name')}"
            )

            print(
                f"ISP: "
                f"{result.get('isp')}"
            )

            print(
                f"Tor: "
                f"{result.get('is_tor')}"
            )

        else:

            print(
                f"[-] Threat intelligence lookup failed: "
                f"{result.get('error')}"
            )

    output = {

        "investigation": {

            "observed_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "source": infrastructure_file,

            "intelligence_provider": "AbuseIPDB",

            "lookback_days": DEFAULT_MAX_AGE_DAYS
        },

        "ips": results
    }

    with open(
        "threat_intelligence_results.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            indent=4
        )

    print(
        "\n\nThreat intelligence saved to:"
    )

    print(
        "threat_intelligence_results.json"
    )

    return output


if __name__ == "__main__":

    investigate_threats()
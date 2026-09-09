import json
import os
import ipaddress
from datetime import datetime, timezone
from dotenv import load_dotenv

import requests

load_dotenv()

IPINFO_TOKEN=os.getenv("IPINFO_TOKEN")

if not IPINFO_TOKEN:
    raise RuntimeError("IPINFO_TOKEN is not configured")


IPINFO_API = "https://api.ipinfo.io/lite"

REQUEST_TIMEOUT = 10


def is_valid_ip(value):
    """
    Check whether a value is a valid IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


def get_ip_addresses(infrastructure_file="infrastructure_results.json"):
    """
    Extract all IPv4 and IPv6 addresses from the
    infrastructure analyzer output.
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


def lookup_ip(ip_address, token):
    """
    Query IPinfo for intelligence about one IP address.
    """

    url = f"{IPINFO_API}/{ip_address}"

    params = {
        "token": token
    }

    try:

        response = requests.get(
            url,
            params=params,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 404:

            return {
                "ip": ip_address,
                "status": "not_found",
                "source": "IPinfo",
                "error": "IP address not found"
            }

        response.raise_for_status()

        data = response.json()

        return {
            "ip": ip_address,
            "status": "success",
            "source": "IPinfo",

            "asn": data.get("asn"),
            "as_name": data.get("as_name"),
            "as_domain": data.get("as_domain"),

            "country_code": data.get("country_code"),
            "country": data.get("country"),

            "continent_code": data.get("continent_code"),
            "continent": data.get("continent")
        }

    except requests.exceptions.Timeout:

        return {
            "ip": ip_address,
            "status": "error",
            "source": "IPinfo",
            "error": "Request timed out"
        }

    except requests.exceptions.RequestException as e:

        return {
            "ip": ip_address,
            "status": "error",
            "source": "IPinfo",
            "error": str(e)
        }

    except ValueError:

        return {
            "ip": ip_address,
            "status": "error",
            "source": "IPinfo",
            "error": "Invalid JSON response"
        }


def investigate_ips(
    infrastructure_file="infrastructure_results.json"
):

    token = os.getenv("IPINFO_TOKEN")

    if not token:

        raise RuntimeError(
            "IPINFO_TOKEN environment variable is not set."
        )

    print("\n" + "=" * 60)
    print("IP INTELLIGENCE")
    print("=" * 60)

    ip_addresses = get_ip_addresses(
        infrastructure_file
    )

    print(
        f"\nDiscovered IP addresses: "
        f"{len(ip_addresses)}"
    )

    if not ip_addresses:

        print("\n[-] No IP addresses found.")

        return {
            "investigation": {
                "observed_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "source": "infrastructure_results.json"
            },
            "ips": []
        }

    results = []

    for ip in ip_addresses:

        print("\n" + "-" * 60)
        print(f"IP: {ip}")
        print("-" * 60)

        result = lookup_ip(
            ip,
            token
        )

        results.append(result)

        if result["status"] == "success":

            print(
                f"ASN: "
                f"{result.get('asn')}"
            )

            print(
                f"Organization: "
                f"{result.get('as_name')}"
            )

            print(
                f"ASN Domain: "
                f"{result.get('as_domain')}"
            )

            print(
                f"Country: "
                f"{result.get('country')}"
            )

            print(
                f"Continent: "
                f"{result.get('continent')}"
            )

        else:

            print(
                f"[-] Lookup failed: "
                f"{result.get('error')}"
            )

    output = {
        "investigation": {
            "observed_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "source": infrastructure_file,

            "intelligence_provider": "IPinfo"
        },

        "ips": results
    }

    with open(
        "ip_intelligence_results.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            indent=4
        )

    print(
        "\n\nIP intelligence saved to:"
    )

    print(
        "ip_intelligence_results.json"
    )

    return output


if __name__ == "__main__":

    investigate_ips()
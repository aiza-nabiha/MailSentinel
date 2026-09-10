import json
import os
import ipaddress
import socket
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from hop_analyzer import find_earliest_reliable_node


load_dotenv()

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

IPINFO_API = "https://api.ipinfo.io/lite"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"

REQUEST_TIMEOUT = 10
CACHE_FILE = "ip_intelligence_cache.json"


def is_valid_ip(value):
    """
    Check whether a value is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_public_ip(value):
    """
    Check whether an IP is publicly routable.
    """
    try:
        address = ipaddress.ip_address(value)

        return not (
            address.is_private
            or address.is_loopback
            or address.is_reserved
            or address.is_link_local
        )

    except ValueError:
        return False


def load_cache():
    """
    Load cached IP intelligence results.
    """
    if not os.path.exists(CACHE_FILE):
        return {}

    try:
        with open(
            CACHE_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            return json.load(f)

    except (OSError, ValueError):
        return {}


def save_cache(cache):
    """
    Save IP intelligence results to cache.
    """
    try:
        with open(
            CACHE_FILE,
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                cache,
                f,
                indent=4
            )
    except OSError:
        pass


def get_ip_addresses(
    infrastructure_file="infrastructure_results.json"
):
    """
    Extract public IPv4 and IPv6 addresses from
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

        if entity_type not in ("ipv4", "ipv6"):
            continue

        if not value:
            continue

        if not is_valid_ip(value):
            continue

        if not is_public_ip(value):
            continue

        ip_addresses.add(value)

    return sorted(ip_addresses)


def lookup_ipinfo(ip_address, token):
    """
    Query IPinfo for ASN and geographic infrastructure
    information.
    """

    if not token:
        return {
            "status": "skipped",
            "source": "IPinfo",
            "error": "IPINFO_TOKEN is not configured"
        }

    url = f"{IPINFO_API}/{ip_address}"

    try:

        response = requests.get(
            url,
            params={"token": token},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "source": "IPinfo",
                "error": "IP address not found"
            }

        response.raise_for_status()

        data = response.json()

        return {
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
            "status": "error",
            "source": "IPinfo",
            "error": "Request timed out"
        }

    except requests.exceptions.RequestException as e:

        return {
            "status": "error",
            "source": "IPinfo",
            "error": str(e)
        }

    except ValueError:

        return {
            "status": "error",
            "source": "IPinfo",
            "error": "Invalid JSON response"
        }


def lookup_reverse_dns(ip_address):
    """
    Perform reverse DNS lookup for an IP address.
    """

    try:

        hostname, _, _ = socket.gethostbyaddr(ip_address)

        return {
            "status": "success",
            "hostname": hostname,
            "source": "DNS"
        }

    except socket.herror:

        return {
            "status": "not_found",
            "hostname": None,
            "source": "DNS"
        }

    except socket.gaierror:

        return {
            "status": "not_found",
            "hostname": None,
            "source": "DNS"
        }

    except OSError as e:

        return {
            "status": "error",
            "hostname": None,
            "source": "DNS",
            "error": str(e)
        }


def lookup_reputation(ip_address, api_key):
    """
    Query AbuseIPDB for IP reputation.
    """

    if not api_key:
        return {
            "status": "skipped",
            "source": "AbuseIPDB",
            "error": "ABUSEIPDB_API_KEY is not configured"
        }

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:

        response = requests.get(
            ABUSEIPDB_API,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        data = response.json().get(
            "data",
            {}
        )

        abuse_score = data.get(
            "abuseConfidenceScore"
        )

        total_reports = data.get(
            "totalReports"
        )

        return {
            "status": "success",
            "source": "AbuseIPDB",
            "abuse_score": abuse_score,
            "total_reports": total_reports,
            "risk_flag": (
                abuse_score is not None
                and abuse_score > 50
            )
        }

    except requests.exceptions.Timeout:

        return {
            "status": "error",
            "source": "AbuseIPDB",
            "error": "Request timed out"
        }

    except requests.exceptions.RequestException as e:

        return {
            "status": "error",
            "source": "AbuseIPDB",
            "error": str(e)
        }

    except ValueError:

        return {
            "status": "error",
            "source": "AbuseIPDB",
            "error": "Invalid JSON response"
        }



def investigate_ip(
    ip_address,
    cache,
    ipinfo_token,
    abuseipdb_api_key
):
    """
    Build complete intelligence for one public IP.
    """

    if not is_public_ip(ip_address):

        return {
            "ip": ip_address,
            "status": "skipped",
            "error": "IP is not publicly routable"
        }

    if ip_address in cache:
        cached = cache[ip_address]
        cached["cached"] = True
        return cached

    ipinfo_result = lookup_ipinfo(
        ip_address,
        ipinfo_token
    )

    reverse_dns_result = lookup_reverse_dns(
        ip_address
    )

    reputation_result = lookup_reputation(
        ip_address,
        abuseipdb_api_key
    )

    result = {
        "ip": ip_address,
        "status": "success",
        "cached": False,

        "ipinfo": ipinfo_result,

        "reverse_dns": reverse_dns_result,

        "reputation": reputation_result
    }

    cache[ip_address] = result

    return result

def investigate_reliable_hop(hop_data):
    """
    Find the earliest reliable observable hop and
    enrich its IP using the IP intelligence module.
    """

    reliable_node = find_earliest_reliable_node(hop_data)

    if not reliable_node:
        return {
            "status": "not_found",
            "message": "No reliable observable hop found",
            "ip_intelligence": None
        }

    ip = reliable_node["ip"]

    cache = load_cache()

    intelligence = investigate_ip(
        ip,
        cache,
        IPINFO_TOKEN,
        ABUSEIPDB_API_KEY
    )

    save_cache(cache)

    return {
        "status": "success",
        "earliest_reliable_node": reliable_node,
        "ip_intelligence": intelligence
    }

def investigate_ips(
    infrastructure_file="infrastructure_results.json"
):
    """
    Investigate all public IPs found in the
    infrastructure analyzer output.
    """

    cache = load_cache()

    ip_addresses = get_ip_addresses(
        infrastructure_file
    )

    print("\n" + "=" * 60)
    print("IP INTELLIGENCE")
    print("=" * 60)

    print(
        f"\nPublic IP addresses discovered: "
        f"{len(ip_addresses)}"
    )

    results = []

    for ip in ip_addresses:

        print("\n" + "-" * 60)
        print(f"IP: {ip}")
        print("-" * 60)

        result = investigate_ip(
            ip,
            cache,
            IPINFO_TOKEN,
            ABUSEIPDB_API_KEY
        )

        results.append(result)

        if result.get("cached"):

            print("[+] Result loaded from cache")

        ipinfo = result.get(
            "ipinfo",
            {}
        )

        if ipinfo.get("status") == "success":

            print(
                f"ASN: "
                f"{ipinfo.get('asn')}"
            )

            print(
                f"Organization: "
                f"{ipinfo.get('as_name')}"
            )

            print(
                f"Country: "
                f"{ipinfo.get('country')}"
            )

        reverse_dns = result.get(
            "reverse_dns",
            {}
        )

        if reverse_dns.get("hostname"):

            print(
                f"Reverse DNS: "
                f"{reverse_dns.get('hostname')}"
            )

        reputation = result.get(
            "reputation",
            {}
        )

        if reputation.get("status") == "success":

            print(
                f"Abuse Score: "
                f"{reputation.get('abuse_score')}"
            )

            print(
                f"Total Reports: "
                f"{reputation.get('total_reports')}"
            )

    save_cache(cache)

    output = {
        "investigation": {
            "observed_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "source": infrastructure_file,

            "intelligence_providers": [
                "IPinfo",
                "DNS",
                "AbuseIPDB"
            ]
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

    mock_hop_data = {
        "hops": [
            {
                "ip": "8.8.8.10",
                "hostname": "suspicious1.example",
                "evidence": {
                    "dns_consistent": False,
                    "authentication_consistent": False,
                    "known_infrastructure": False
                }
            },
            {
                "ip": "8.8.8.20",
                "hostname": "suspicious2.example",
                "evidence": {
                    "dns_consistent": False,
                    "authentication_consistent": False,
                    "known_infrastructure": False
                }
            },
            {
                "ip": "8.8.8.30",
                "hostname": "relay.example.net",
                "evidence": {
                    "dns_consistent": True,
                    "authentication_consistent": True,
                    "known_infrastructure": True
                }
            }
        ]
    }

    result = investigate_reliable_hop(mock_hop_data)

    print("\n--- Reliable Hop + IP Intelligence ---")
    print(json.dumps(result, indent=4))
import requests


SHODAN_INTERNETDB_API = "https://internetdb.shodan.io"

REQUEST_TIMEOUT = 10

# Ports that are rarely legitimate on a mail-sending host and are
# worth calling out explicitly when Shodan sees them exposed.
SUSPICIOUS_PORT_NOTES = {
    23: "Telnet exposed (legacy, often a compromised IoT/router device)",
    3389: "RDP exposed (common ransomware/compromise entry point)",
    445: "SMB exposed (common lateral-movement / worm vector)",
    8080: "Alternate HTTP exposed (sometimes an admin panel or proxy)",
    8443: "Alternate HTTPS exposed (sometimes an admin panel)",
    9000: "Admin panel port commonly used by phishing kits"
}


def lookup_shodan_internetdb(ip_address):
    """
    Query Shodan InternetDB for exposed ports, hostnames,
    CPEs and known CVEs on a public IP.

    InternetDB is a free, key-less Shodan endpoint intended
    for exactly this kind of passive lookup, so there is no
    API key to configure here.
    """

    url = f"{SHODAN_INTERNETDB_API}/{ip_address}"

    try:

        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "source": "Shodan InternetDB",
                "error": "No Shodan data for this IP"
            }

        response.raise_for_status()

        data = response.json()

        ports = data.get("ports", []) or []

        notable_ports = [
            {
                "port": port,
                "note": SUSPICIOUS_PORT_NOTES[port]
            }
            for port in ports
            if port in SUSPICIOUS_PORT_NOTES
        ]

        vulns = data.get("vulns", []) or []

        return {
            "status": "success",
            "source": "Shodan InternetDB",
            "ip": data.get("ip", ip_address),
            "ports": ports,
            "hostnames": data.get("hostnames", []) or [],
            "cpes": data.get("cpes", []) or [],
            "tags": data.get("tags", []) or [],
            "vulns": vulns,
            "notable_ports": notable_ports,
            "risk_flag": bool(notable_ports) or bool(vulns)
        }

    except requests.exceptions.Timeout:

        return {
            "status": "error",
            "source": "Shodan InternetDB",
            "error": "Request timed out"
        }

    except requests.exceptions.RequestException as e:

        return {
            "status": "error",
            "source": "Shodan InternetDB",
            "error": str(e)
        }

    except ValueError:

        return {
            "status": "error",
            "source": "Shodan InternetDB",
            "error": "Invalid JSON response"
        }


if __name__ == "__main__":

    import json

    # 8.8.8.8 is Google DNS -- used only to sanity-check that
    # the endpoint and parsing work end to end.
    result = lookup_shodan_internetdb("8.8.8.8")

    print(json.dumps(result, indent=4))
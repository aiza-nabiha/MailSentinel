import requests
from datetime import datetime, timezone


IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"

REQUEST_TIMEOUT = 10


def get_rdap_server(domain):
    """
    Find the correct RDAP server for the domain's TLD
    using the IANA RDAP bootstrap registry.
    """

    tld = domain.rstrip(".").split(".")[-1].lower()

    try:
        response = requests.get(
            IANA_RDAP_BOOTSTRAP,
            timeout=REQUEST_TIMEOUT,
            headers={
                "Accept": "application/json"
            }
        )

        response.raise_for_status()

        data = response.json()

        for service in data.get("services", []):

            if len(service) != 2:
                continue

            tlds, urls = service

            normalized_tlds = [
                str(tld_value).lower()
                for tld_value in tlds
            ]

            if tld in normalized_tlds:

                if urls:
                    return urls[0]

    except (
        requests.exceptions.RequestException,
        ValueError,
        KeyError,
        IndexError,
        TypeError
    ):
        pass

    return None


def get_event_date(data, event_type):
    """
    Extract a specific event date from RDAP.
    """

    for event in data.get("events", []):

        if event.get("eventAction") == event_type:
            return event.get("eventDate")

    return None


def get_registrar(data):
    """
    Extract registrar name from RDAP entities.
    """

    for entity in data.get("entities", []):

        if "registrar" not in entity.get("roles", []):
            continue

        vcard_array = entity.get("vcardArray", [])

        if len(vcard_array) < 2:
            continue

        for item in vcard_array[1]:

            if len(item) >= 4 and item[0] == "fn":
                return item[3]

    return None


def get_nameservers(data):
    """
    Extract nameservers from RDAP response.
    """

    nameservers = []

    for nameserver in data.get("nameservers", []):

        name = nameserver.get("ldhName")

        if name:
            nameservers.append(
                name.rstrip(".")
            )

    return nameservers


def calculate_domain_age(creation_date):
    """
    Calculate domain age using the registration date.
    """

    if not creation_date:
        return None

    try:

        created = datetime.fromisoformat(
            creation_date.replace("Z", "+00:00")
        )

        now = datetime.now(timezone.utc)

        age_days = (now - created).days

        age_years = round(
            age_days / 365.25,
            2
        )

        return {
            "days": age_days,
            "years": age_years
        }

    except (
        ValueError,
        TypeError
    ):
        return None


def extract_whois(domain):
    """
    Extract domain registration information using RDAP.

    The correct RDAP server is automatically determined
    from the domain's TLD.
    """

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    result = {
        "domain": domain,
        "status": "failed",
        "source": None,
        "rdap_server": None,
        "registrar": None,
        "creation_date": None,
        "updated_date": None,
        "expiration_date": None,
        "domain_age": None,
        "domain_status": [],
        "name_servers": [],
        "error": None
    }

    # -----------------------------------------
    # Find RDAP server
    # -----------------------------------------

    rdap_server = get_rdap_server(domain)

    if not rdap_server:

        result["error"] = (
            "No RDAP server found for domain TLD"
        )

        return result

    result["rdap_server"] = rdap_server

    # -----------------------------------------
    # Build RDAP URL
    # -----------------------------------------

    rdap_url = (
        rdap_server.rstrip("/")
        + "/domain/"
        + domain
    )

    # -----------------------------------------
    # Query RDAP
    # -----------------------------------------

    try:

        response = requests.get(
            rdap_url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "Accept": "application/rdap+json"
            }
        )

        response.raise_for_status()

        data = response.json()

        # -----------------------------------------
        # Registrar
        # -----------------------------------------

        result["registrar"] = get_registrar(data)

        # -----------------------------------------
        # Registration dates
        # -----------------------------------------

        result["creation_date"] = get_event_date(
            data,
            "registration"
        )

        result["updated_date"] = get_event_date(
            data,
            "last changed"
        )

        result["expiration_date"] = get_event_date(
            data,
            "expiration"
        )

        # -----------------------------------------
        # Domain status
        # -----------------------------------------

        result["domain_status"] = data.get(
            "status",
            []
        )

        # -----------------------------------------
        # Nameservers
        # -----------------------------------------

        result["name_servers"] = get_nameservers(
            data
        )

        # -----------------------------------------
        # Domain age
        # -----------------------------------------

        result["domain_age"] = calculate_domain_age(
            result["creation_date"]
        )

        result["source"] = "RDAP"
        result["status"] = "success"

    except requests.exceptions.Timeout:

        result["error"] = "RDAP request timed out"

    except requests.exceptions.HTTPError as e:

        result["error"] = f"RDAP HTTP error: {e}"

    except requests.exceptions.RequestException as e:

        result["error"] = f"RDAP request failed: {e}"

    except ValueError:

        result["error"] = (
            "Invalid JSON response from RDAP"
        )

    except Exception as e:

        result["error"] = (
            f"Unexpected error: {e}"
        )

    return result


# -------------------------------------------------
# Standalone testing
# -------------------------------------------------

if __name__ == "__main__":

    domain = input(
        "Enter domain: "
    ).strip()

    if not domain:

        print("[-] No domain provided.")

    else:

        print("\n" + "=" * 60)
        print(f"WHOIS / RDAP: {domain}")
        print("=" * 60)

        print("\n[*] Finding RDAP server...")

        result = extract_whois(domain)

        if result["status"] == "success":

            print(
                "\n[+] RDAP extraction successful"
            )

            print(
                f"\nRDAP Server: "
                f"{result['rdap_server']}"
            )

            print(
                f"Registrar: "
                f"{result['registrar']}"
            )

            print(
                f"Creation Date: "
                f"{result['creation_date']}"
            )

            print(
                f"Updated Date: "
                f"{result['updated_date']}"
            )

            print(
                f"Expiration Date: "
                f"{result['expiration_date']}"
            )

            if result["domain_age"]:

                print(
                    f"Domain Age: "
                    f"{result['domain_age']['years']} years "
                    f"({result['domain_age']['days']} days)"
                )

            print("\nDomain Status:")

            for status in result["domain_status"]:
                print(f"  {status}")

            print("\nName Servers:")

            for ns in result["name_servers"]:
                print(f"  {ns}")

        else:

            print(
                f"\n[-] Extraction failed: "
                f"{result['error']}"
            )
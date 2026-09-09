import json
from datetime import datetime, timezone


DNS_FILE = "dns_results.json"
WHOIS_FILE = "whois_results.json"
OUTPUT_FILE = "infrastructure_results.json"


# ============================================================
# Utility Functions
# ============================================================

def clean_value(value):
    """
    Clean DNS values for consistent storage.
    """

    if not isinstance(value, str):
        return value

    return value.strip().strip('"').rstrip(".")


def get_observed_time():
    """
    Return the time at which the investigation was performed.
    """

    return datetime.now(timezone.utc).isoformat()


# ============================================================
# Parse MX Records
# ============================================================

def parse_mx_records(records):
    """
    Convert MX records such as:

        1 aspmx.l.google.com.

    into structured data.
    """

    result = []

    for record in records:

        parts = record.strip().rstrip(".").split()

        if len(parts) >= 2:

            try:
                priority = int(parts[0])
            except ValueError:
                priority = None

            mail_server = parts[1].rstrip(".")

            result.append({
                "priority": priority,
                "host": mail_server
            })

        else:

            result.append({
                "priority": None,
                "host": record.rstrip(".")
            })

    return result


# ============================================================
# Parse SOA Records
# ============================================================

def parse_soa_record(record):
    """
    Convert an SOA record into structured fields.

    Example:

    ns55.domaincontrol.com.
    dns.jomax.net.
    2026082500
    28800
    7200
    604800
    600
    """

    parts = record.strip().rstrip(".").split()

    if len(parts) < 7:
        return {
            "raw": record
        }

    try:
        serial = int(parts[2])
    except ValueError:
        serial = parts[2]

    try:
        refresh = int(parts[3])
    except ValueError:
        refresh = parts[3]

    try:
        retry = int(parts[4])
    except ValueError:
        retry = parts[4]

    try:
        expire = int(parts[5])
    except ValueError:
        expire = parts[5]

    try:
        minimum_ttl = int(parts[6])
    except ValueError:
        minimum_ttl = parts[6]

    return {
        "primary_nameserver": clean_value(parts[0]),
        "responsible_mailbox": clean_value(parts[1]),
        "serial": serial,
        "refresh": refresh,
        "retry": retry,
        "expire": expire,
        "minimum_ttl": minimum_ttl
    }


# ============================================================
# DNS Evidence Analyzer
# ============================================================

def analyze_dns_entry(entry, observed_at):

    domain = entry.get("domain")

    records = entry.get(
        "records",
        {}
    )

    analysis = {

        "domain": domain,

        "observed_at": observed_at,

        "ip_addresses": {
            "ipv4": records.get("A", []),
            "ipv6": records.get("AAAA", [])
        },

        "mail_servers": parse_mx_records(
            records.get("MX", [])
        ),

        "name_servers": [
            clean_value(value)
            for value in records.get("NS", [])
        ],

        "canonical_names": [
            clean_value(value)
            for value in records.get("CNAME", [])
        ],

        "txt_records": [
            clean_value(value)
            for value in records.get("TXT", [])
        ],

        "srv_records": [
            clean_value(value)
            for value in records.get("SRV", [])
        ],

        "caa_records": [
            clean_value(value)
            for value in records.get("CAA", [])
        ],

        "soa": [],

        "relationships": []
    }


    # --------------------------------------------------------
    # SOA
    # --------------------------------------------------------

    for soa in records.get("SOA", []):

        analysis["soa"].append(
            parse_soa_record(soa)
        )


    # --------------------------------------------------------
    # Domain → IP relationships
    # --------------------------------------------------------

    for ip in analysis["ip_addresses"]["ipv4"]:

        analysis["relationships"].append({
            "source": domain,
            "relationship": "RESOLVES_TO",
            "target": ip,
            "evidence": "DNS A record"
        })


    for ip in analysis["ip_addresses"]["ipv6"]:

        analysis["relationships"].append({
            "source": domain,
            "relationship": "RESOLVES_TO",
            "target": ip,
            "evidence": "DNS AAAA record"
        })


    # --------------------------------------------------------
    # Domain → CNAME relationships
    # --------------------------------------------------------

    for cname in analysis["canonical_names"]:

        analysis["relationships"].append({
            "source": domain,
            "relationship": "CNAME",
            "target": cname,
            "evidence": "DNS CNAME record"
        })


    # --------------------------------------------------------
    # Domain → Mail Server relationships
    # --------------------------------------------------------

    for mail_server in analysis["mail_servers"]:

        host = mail_server.get("host")

        if host:

            analysis["relationships"].append({
                "source": domain,
                "relationship": "MAIL_SERVER",
                "target": host,
                "priority": mail_server.get("priority"),
                "evidence": "DNS MX record"
            })


    # --------------------------------------------------------
    # Domain → Nameserver relationships
    # --------------------------------------------------------

    for nameserver in analysis["name_servers"]:

        analysis["relationships"].append({
            "source": domain,
            "relationship": "NAMESERVER",
            "target": nameserver,
            "evidence": "DNS NS record"
        })


    return analysis


# ============================================================
# WHOIS / RDAP Integration
# ============================================================

def attach_registration_data(
    infrastructure,
    whois_results
):

    for whois in whois_results:

        domain = whois.get("domain")

        if not domain:
            continue

        if domain not in infrastructure:
            continue

        infrastructure[domain]["registration"] = {

            "status": whois.get(
                "status"
            ),

            "source": whois.get(
                "source"
            ),

            "registrar": whois.get(
                "registrar"
            ),

            "creation_date": whois.get(
                "creation_date"
            ),

            "updated_date": whois.get(
                "updated_date"
            ),

            "expiration_date": whois.get(
                "expiration_date"
            ),

            "domain_age": whois.get(
                "domain_age"
            ),

            "domain_status": whois.get(
                "domain_status",
                []
            ),

            "name_servers": whois.get(
                "name_servers",
                []
            )
        }


# ============================================================
# Build Global Relationship Graph
# ============================================================

def build_relationship_graph(infrastructure):

    relationships = []

    for domain, data in infrastructure.items():

        for relationship in data.get(
            "relationships",
            []
        ):

            relationships.append(
                relationship
            )


    return relationships


# ============================================================
# Build Entity Inventory
# ============================================================

def build_entities(
    infrastructure,
    relationships
):

    entities = {}

    def add_entity(
        value,
        entity_type,
        source
    ):

        if not value:
            return

        key = f"{entity_type}:{value}"

        if key not in entities:

            entities[key] = {
                "value": value,
                "type": entity_type,
                "sources": []
            }

        if source not in entities[key]["sources"]:

            entities[key]["sources"].append(
                source
            )


    # --------------------------------------------------------
    # Domains and their observed infrastructure
    # --------------------------------------------------------

    for domain, data in infrastructure.items():

        add_entity(
            domain,
            "domain",
            "DNS"
        )

        for ip in data["ip_addresses"]["ipv4"]:

            add_entity(
                ip,
                "ipv4",
                "DNS A"
            )

        for ip in data["ip_addresses"]["ipv6"]:

            add_entity(
                ip,
                "ipv6",
                "DNS AAAA"
            )

        for cname in data["canonical_names"]:

            add_entity(
                cname,
                "hostname",
                "DNS CNAME"
            )

        for mail in data["mail_servers"]:

            add_entity(
                mail["host"],
                "mail_server",
                "DNS MX"
            )

        for ns in data["name_servers"]:

            add_entity(
                ns,
                "nameserver",
                "DNS NS"
            )


        # ----------------------------------------------------
        # Registration entities
        # ----------------------------------------------------

        registration = data.get(
            "registration"
        )

        if registration:

            registrar = registration.get(
                "registrar"
            )

            if registrar:

                add_entity(
                    registrar,
                    "registrar",
                    "RDAP"
                )


    # --------------------------------------------------------
    # Return clean list
    # --------------------------------------------------------

    return list(
        entities.values()
    )


# ============================================================
# Main
# ============================================================

def analyze_infrastructure():

    print("\n" + "=" * 60)
    print("INFRASTRUCTURE EVIDENCE ANALYZER")
    print("=" * 60)


    observed_at = get_observed_time()


    # ========================================================
    # Load DNS
    # ========================================================

    print("\n[*] Loading DNS results...")

    with open(
        DNS_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        dns_results = json.load(f)


    # ========================================================
    # Load WHOIS
    # ========================================================

    print("[*] Loading RDAP results...")

    with open(
        WHOIS_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        whois_results = json.load(f)


    # ========================================================
    # Analyze DNS
    # ========================================================

    print("[*] Building infrastructure evidence...")

    infrastructure = {}


    for entry in dns_results:

        domain = entry.get("domain")

        if not domain:
            continue

        infrastructure[domain] = analyze_dns_entry(
            entry,
            observed_at
        )


    # ========================================================
    # Attach RDAP
    # ========================================================

    print("[*] Attaching registration intelligence...")

    attach_registration_data(
        infrastructure,
        whois_results
    )


    # ========================================================
    # Build relationships
    # ========================================================

    relationships = build_relationship_graph(
        infrastructure
    )


    # ========================================================
    # Build entities
    # ========================================================

    entities = build_entities(
        infrastructure,
        relationships
    )


    # ========================================================
    # Final Result
    # ========================================================

    result = {

        "investigation": {
            "observed_at": observed_at,

            "dns_source": DNS_FILE,

            "rdap_source": WHOIS_FILE
        },

        "entities": entities,

        "relationships": relationships,

        "domains": infrastructure
    }


    # ========================================================
    # Save
    # ========================================================

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            result,
            f,
            indent=4
        )


    # ========================================================
    # Summary
    # ========================================================

    print("\n[+] Infrastructure analysis completed")

    print(
        f"[+] Entities discovered: "
        f"{len(entities)}"
    )

    print(
        f"[+] Relationships discovered: "
        f"{len(relationships)}"
    )

    print(
        f"[+] Results saved to: "
        f"{OUTPUT_FILE}"
    )


    # ========================================================
    # Relationship Preview
    # ========================================================

    print("\n" + "=" * 60)
    print("OBSERVED RELATIONSHIPS")
    print("=" * 60)

    for relationship in relationships:

        print(
            f"{relationship['source']} "
            f"--[{relationship['relationship']}]--> "
            f"{relationship['target']}"
        )


    return result


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    analyze_infrastructure()
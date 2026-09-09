import json
import re


DNS_FILE = "dns_results.json"
WHOIS_FILE = "whois_results.json"
OUTPUT_FILE = "infrastructure_results.json"


# ============================================================
# Provider Detection Rules
# ============================================================

MX_PROVIDERS = {
    "google": [
        "google.com",
        "googlemail.com",
        "aspmx.l.google.com"
    ],
    "microsoft": [
        "outlook.com",
        "protection.outlook.com",
        "mail.protection.outlook.com"
    ],
    "zoho": [
        "zoho.com",
        "zoho.eu"
    ],
    "proton": [
        "protonmail.ch",
        "protonmail.com"
    ]
}


CNAME_PROVIDERS = {
    "hubspot": [
        "hubspot.net",
        "hubspot.com"
    ],
    "cloudflare": [
        "cloudflare.net",
        "cloudflare.com"
    ],
    "aws_cloudfront": [
        "cloudfront.net"
    ],
    "amazon": [
        "amazonaws.com"
    ],
    "vercel": [
        "vercel.app"
    ],
    "netlify": [
        "netlify.app",
        "netlify.com"
    ]
}


TXT_PROVIDERS = {
    "google": [
        "google-site-verification",
        "include:_spf.google.com"
    ],
    "microsoft": [
        "MS=",
        "spf.protection.outlook.com"
    ],
    "atlassian": [
        "atlassian-domain-verification"
    ],
    "anthropic": [
        "anthropic-domain-verification"
    ],
    "box": [
        "box-domain-verification"
    ],
    "cisco": [
        "ciscocidomainverification"
    ],
    "apple": [
        "apple-domain-verification"
    ],
    "hubspot": [
        "hubspotemail.net",
        "hubspot"
    ],
    "virtru": [
        "virtru-site-verify"
    ]
}


# ============================================================
# Utility Functions
# ============================================================

def clean_hostname(value):
    """
    Remove DNS trailing dot and surrounding whitespace/quotes.
    """

    return value.strip().strip('"').rstrip(".").lower()


def detect_provider(value, rules):
    """
    Detect providers from a DNS value.
    Returns a list because one record can indicate
    more than one provider.
    """

    value = value.lower()

    detected = []

    for provider, patterns in rules.items():

        for pattern in patterns:

            if pattern.lower() in value:
                detected.append(provider)
                break

    return detected


# ============================================================
# Analyze DNS
# ============================================================

def analyze_dns(dns_results):

    analysis = {}

    for entry in dns_results:

        domain = entry["domain"]

        records = entry.get("records", {})

        domain_analysis = {

            "domain": domain,

            "ip_addresses": {
                "ipv4": records.get("A", []),
                "ipv6": records.get("AAAA", [])
            },

            "email_providers": [],

            "hosting_and_infrastructure": [],

            "third_party_services": [],

            "nameservers": [],

            "cname_relationships": [],

            "spf": [],

            "other_txt": []
        }

        # ----------------------------------------------------
        # A / AAAA
        # ----------------------------------------------------

        # Already stored above.
        # These are useful later for IP intelligence.


        # ----------------------------------------------------
        # MX
        # ----------------------------------------------------

        mx_records = records.get("MX", [])

        for mx in mx_records:

            providers = detect_provider(
                mx,
                MX_PROVIDERS
            )

            for provider in providers:

                if provider not in domain_analysis["email_providers"]:
                    domain_analysis["email_providers"].append(
                        provider
                    )


        # ----------------------------------------------------
        # CNAME
        # ----------------------------------------------------

        cname_records = records.get("CNAME", [])

        for cname in cname_records:

            target = clean_hostname(cname)

            providers = detect_provider(
                target,
                CNAME_PROVIDERS
            )

            relationship = {
                "source": domain,
                "type": "CNAME",
                "target": target,
                "detected_providers": providers
            }

            domain_analysis["cname_relationships"].append(
                relationship
            )

            for provider in providers:

                if provider not in domain_analysis["hosting_and_infrastructure"]:
                    domain_analysis["hosting_and_infrastructure"].append(
                        provider
                    )


        # ----------------------------------------------------
        # NS
        # ----------------------------------------------------

        nameservers = records.get("NS", [])

        domain_analysis["nameservers"] = [
            clean_hostname(ns)
            for ns in nameservers
        ]


        # ----------------------------------------------------
        # TXT
        # ----------------------------------------------------

        txt_records = records.get("TXT", [])

        for txt in txt_records:

            cleaned_txt = txt.strip().strip('"')

            # SPF
            if cleaned_txt.lower().startswith("v=spf1"):

                domain_analysis["spf"].append(
                    cleaned_txt
                )

            # Provider detection
            providers = detect_provider(
                cleaned_txt,
                TXT_PROVIDERS
            )

            if providers:

                for provider in providers:

                    if provider not in domain_analysis["third_party_services"]:
                        domain_analysis["third_party_services"].append(
                            provider
                        )

            else:

                domain_analysis["other_txt"].append(
                    cleaned_txt
                )


        analysis[domain] = domain_analysis


    return analysis


# ============================================================
# Add WHOIS / RDAP Information
# ============================================================

def merge_whois_information(
    infrastructure,
    whois_results
):

    for whois in whois_results:

        domain = whois.get("domain")

        if domain not in infrastructure:
            continue

        infrastructure[domain]["registration"] = {

            "registrar": whois.get("registrar"),

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
            )
        }


# ============================================================
# Build Infrastructure Relationships
# ============================================================

def build_relationships(infrastructure):

    relationships = []

    for domain, data in infrastructure.items():

        # ----------------------------------------------------
        # CNAME relationships
        # ----------------------------------------------------

        for cname in data.get(
            "cname_relationships",
            []
        ):

            relationships.append({
                "source": cname["source"],
                "relationship": "CNAME",
                "target": cname["target"]
            })


        # ----------------------------------------------------
        # Email provider relationships
        # ----------------------------------------------------

        for provider in data.get(
            "email_providers",
            []
        ):

            relationships.append({
                "source": domain,
                "relationship": "EMAIL_PROVIDER",
                "target": provider
            })


        # ----------------------------------------------------
        # Third-party service relationships
        # ----------------------------------------------------

        for provider in data.get(
            "third_party_services",
            []
        ):

            relationships.append({
                "source": domain,
                "relationship": "USES_SERVICE",
                "target": provider
            })


        # ----------------------------------------------------
        # Hosting relationships
        # ----------------------------------------------------

        for provider in data.get(
            "hosting_and_infrastructure",
            []
        ):

            relationships.append({
                "source": domain,
                "relationship": "HOSTED_OR_DEPLOYED_ON",
                "target": provider
            })


    return relationships


# ============================================================
# Main Analyzer
# ============================================================

def analyze_infrastructure():

    print("\n" + "=" * 60)
    print("INFRASTRUCTURE INTELLIGENCE ANALYZER")
    print("=" * 60)


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

    print("[*] Loading WHOIS/RDAP results...")

    with open(
        WHOIS_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        whois_results = json.load(f)


    # ========================================================
    # Analyze DNS
    # ========================================================

    print("[*] Analyzing DNS infrastructure...")

    infrastructure = analyze_dns(
        dns_results
    )


    # ========================================================
    # Merge WHOIS
    # ========================================================

    print("[*] Adding domain registration intelligence...")

    merge_whois_information(
        infrastructure,
        whois_results
    )


    # ========================================================
    # Build relationships
    # ========================================================

    print("[*] Building infrastructure relationships...")

    relationships = build_relationships(
        infrastructure
    )


    # ========================================================
    # Final output
    # ========================================================

    final_result = {

        "domains": infrastructure,

        "relationships": relationships

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
            final_result,
            f,
            indent=4
        )


    print("\n[+] Infrastructure analysis completed")

    print(
        f"[+] Results saved to: {OUTPUT_FILE}"
    )


    # ========================================================
    # Console Summary
    # ========================================================

    print("\n" + "=" * 60)
    print("INFRASTRUCTURE SUMMARY")
    print("=" * 60)


    for domain, data in infrastructure.items():

        print(f"\nDomain: {domain}")


        if data["ip_addresses"]["ipv4"]:

            print("\nIPv4:")

            for ip in data["ip_addresses"]["ipv4"]:
                print(f"  {ip}")


        if data["ip_addresses"]["ipv6"]:

            print("\nIPv6:")

            for ip in data["ip_addresses"]["ipv6"]:
                print(f"  {ip}")


        if data["email_providers"]:

            print("\nEmail Providers:")

            for provider in data["email_providers"]:
                print(f"  {provider}")


        if data["hosting_and_infrastructure"]:

            print("\nHosting / Infrastructure:")

            for provider in data["hosting_and_infrastructure"]:
                print(f"  {provider}")


        if data["third_party_services"]:

            print("\nThird-Party Services:")

            for provider in data["third_party_services"]:
                print(f"  {provider}")


        if data["cname_relationships"]:

            print("\nCNAME Relationships:")

            for relationship in data["cname_relationships"]:

                print(
                    f"  {relationship['source']} "
                    f"→ {relationship['target']}"
                )


        registration = data.get(
            "registration"
        )

        if registration:

            print("\nRegistration:")

            print(
                f"  Registrar: "
                f"{registration['registrar']}"
            )

            print(
                f"  Creation: "
                f"{registration['creation_date']}"
            )

            if registration["domain_age"]:

                print(
                    f"  Age: "
                    f"{registration['domain_age']['years']} years"
                )


    print("\n" + "=" * 60)
    print("RELATIONSHIPS")
    print("=" * 60)

    for relationship in relationships:

        print(
            f"{relationship['source']} "
            f"--[{relationship['relationship']}]--> "
            f"{relationship['target']}"
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    analyze_infrastructure()
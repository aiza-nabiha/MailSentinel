import json
import dns.resolver
import tldextract

from domain_extract import extract_domains
from whois_lookup import extract_whois


RECORD_TYPES = [
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "CAA",
    "SRV"
]


def get_dns_records(domain):

    result = {
        "domain": domain,
        "records": {}
    }

    resolver = dns.resolver.Resolver()

    resolver.timeout = 3
    resolver.lifetime = 5

    for record_type in RECORD_TYPES:

        try:

            answers = resolver.resolve(
                domain,
                record_type
            )

            records = []

            for answer in answers:
                records.append(str(answer))

            if records:
                result["records"][record_type] = records

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.resolver.NoMetaqueries
        ):
            continue

        except Exception as e:

            print(
                f"[!] Error checking "
                f"{domain} ({record_type}): {e}"
            )

    return result


def get_registrable_domain(domain):

    """
    Convert a hostname/subdomain into its registrable domain.

    Examples:

        info.tigergraph.com
        -> tigergraph.com

        mail.google.com
        -> google.com

        example.co.uk
        -> example.co.uk
    """

    extracted = tldextract.extract(domain)

    if not extracted.domain or not extracted.suffix:
        return None

    return f"{extracted.domain}.{extracted.suffix}".lower()


def investigate_email(eml_path):

    # ==========================================
    # 1. Extract domains from email
    # ==========================================

    domains = extract_domains(eml_path)

    print("\nExtracted Domains:")
    print("------------------")

    for domain in domains:
        print(domain)

    # ==========================================
    # 2. DNS investigation
    # ==========================================

    dns_results = []

    for domain in domains:

        print("\n" + "=" * 60)
        print(f"DOMAIN: {domain}")
        print("=" * 60)

        dns_data = get_dns_records(domain)

        dns_results.append(dns_data)

        for record_type, values in dns_data["records"].items():

            print(f"\n{record_type}:")

            for value in values:
                print(f"  {value}")

    # ==========================================
    # 3. Save DNS results
    # ==========================================

    with open(
        "dns_results.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            dns_results,
            f,
            indent=4
        )

    print("\n\nDNS investigation saved to:")
    print("dns_results.json")

    # ==========================================
    # 4. Normalize domains for RDAP
    # ==========================================

    registrable_domains = set()

    for domain in domains:

        registrable = get_registrable_domain(domain)

        if registrable:
            registrable_domains.add(
                registrable
            )

    print("\nRegistrable Domains:")
    print("--------------------")

    for domain in sorted(registrable_domains):
        print(domain)

    # ==========================================
    # 5. RDAP / WHOIS investigation
    # ==========================================

    whois_results = []

    for domain in sorted(registrable_domains):

        print("\n" + "=" * 60)
        print(f"WHOIS / RDAP: {domain}")
        print("=" * 60)

        whois_data = extract_whois(domain)

        whois_results.append(whois_data)

        if whois_data["status"] == "success":

            print("\n[+] RDAP extraction successful")

            print(
                f"Registrar: "
                f"{whois_data['registrar']}"
            )

            print(
                f"Creation Date: "
                f"{whois_data['creation_date']}"
            )

            print(
                f"Updated Date: "
                f"{whois_data['updated_date']}"
            )

            print(
                f"Expiration Date: "
                f"{whois_data['expiration_date']}"
            )

            if whois_data["domain_age"]:

                print(
                    f"Domain Age: "
                    f"{whois_data['domain_age']['years']} years "
                    f"({whois_data['domain_age']['days']} days)"
                )

        else:

            print(
                f"[-] RDAP extraction failed: "
                f"{whois_data['error']}"
            )

    # ==========================================
    # 6. Save WHOIS results
    # ==========================================

    with open(
        "whois_results.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            whois_results,
            f,
            indent=4
        )

    print("\n\nWHOIS investigation saved to:")
    print("whois_results.json")

    return {
        "domains": domains,
        "dns_results": dns_results,
        "registrable_domains": sorted(
            registrable_domains
        ),
        "whois_results": whois_results
    }


if __name__ == "__main__":

    eml_file = "example.eml"

    investigate_email(eml_file)
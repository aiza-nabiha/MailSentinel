"""
Pipeline: takes a single .eml file and runs it through every
Person 3 module, producing ONE combined JSON object per email.
This is the file Person 4 (correlation engine) and Person 5
(dashboard) should consume -- they should never need to open
dns_results.json, whois_results.json, tls_results.json, etc.
separately.
"""

import json
import re
from datetime import datetime, timezone

import sys
import os

BACKEND_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

sys.path.insert(0, BACKEND_PATH)

from header_auth_engine.received_parser import parse_received_chain
from ip_intelligence import investigate_reliable_hop
from infrastructure_risk import assess_infrastructure

from domain_extract import extract_domains
from whois_lookup import extract_whois
from dns_lookup import get_dns_records, get_registrable_domain
from domain_reputation import check_domain_reputation
from tls_lookup import extract_tls
from risk_scorer import compute_risk


# ==================================================================
# PER-DOMAIN INVESTIGATION
# ==================================================================

def investigate_domain(domain):
    """
    Runs every lookup for a single domain and returns one combined
    dict. Risk is NOT computed here -- it needs to see ALL domains
    at once (for the infrastructure-reuse check), so that happens
    in a second pass after every domain has been looked up.
    """

    domain_record = {
    "domain": domain,
    "whois": {},
    "dns": {},
    "tls": {},
    "reputation": {},
    }

    # ---- DNS (run on the exact domain/subdomain as extracted) ----
    try:
        domain_record["dns"] = get_dns_records(domain) or {}
    except Exception as e:
        domain_record["dns"] = {"error": str(e)}

    # ---- WHOIS/RDAP (must run on the REGISTRABLE domain --
    #      subdomains like info.tigergraph.com will fail RDAP) ----
    try:
        registrable = get_registrable_domain(domain) or domain
        domain_record["whois"] = extract_whois(registrable) or {}
    except Exception as e:
        domain_record["whois"] = {"error": str(e)}

    # ---- TLS (run on the exact domain as extracted) ----
    try:
        domain_record["tls"] = extract_tls(domain) or {}
    except Exception as e:
        domain_record["tls"] = {"error": str(e)}

    # ---- Reputation (checks the domain directly, no IP needed) ----
    try:
        domain_record["reputation"] = check_domain_reputation(domain) or {}
    except Exception as e:
        domain_record["reputation"] = {"error": str(e)}

    return domain_record


# ==================================================================
# FULL EMAIL PIPELINE
# ==================================================================

def run_pipeline(eml_path):
    """
    Main entry point: give it an .eml file path, get back ONE
    combined investigation object covering every domain found in
    that email, fully enriched and risk-scored.
    """

    # ---- Step 1: extract every domain from the email ----
    domains = extract_domains(eml_path)

    # ---- Step 1B: Received-chain + IP intelligence investigation ----
    received_chain = []

    try:
        with open(eml_path, "r", encoding="utf-8", errors="replace") as f:
            email_content = f.read()

        received_headers = re.findall(
            r"^Received:.*?(?=\n\S|\Z)",
            email_content,
            re.IGNORECASE | re.MULTILINE | re.DOTALL
        )

        received_chain = parse_received_chain(received_headers)

    except Exception as e:
        print(f"[!] Received-chain parsing failed: {e}")

    hop_data = {
        "hops": [
            {
                "hop_index": hop.get("hop", index),
                "ip": hop.get("from_ip"),
                "hostname": hop.get("from_host"),
                "evidence": {}
            }
            for index, hop in enumerate(received_chain, start=1)
            if hop.get("from_ip")
        ]
    }

    reliable_hop_result = investigate_reliable_hop(hop_data)
        # ---- Step 4: Final Infrastructure Risk Assessment ----

    authentication = {}

    try:
        from header_auth_engine.header_parser import build_email_data

        parsed_headers = build_email_data(eml_path)

        authentication = parsed_headers.get(
            "authentication",
            {}
        )

    except Exception as e:
        print(f"[!] Authentication parsing failed: {e}")

    earliest_node = (
        reliable_hop_result.get("earliest_reliable_node")
        if isinstance(reliable_hop_result, dict)
        else None
    )

    ip_intelligence = (
        reliable_hop_result.get("ip_intelligence", {})
        if isinstance(reliable_hop_result, dict)
        else {}
    )

    infrastructure_risk = assess_infrastructure(
        reliable_hop_analysis=reliable_hop_result.get(
            "earliest_reliable_node", {}
        ),
        ip_intelligence=reliable_hop_result.get(
            "ip_intelligence", {}
        ),
        authentication=authentication
    )

    if not domains:
        return {
            "eml_path": eml_path,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "domains": {},
            "warning": "No domains extracted from this email"
        }

    # ---- Step 2: investigate each domain independently ----
    all_domains_data = {}
    for domain in domains:
        print(f"[*] Investigating {domain}...")
        all_domains_data[domain] = investigate_domain(domain)

    # ---- Step 3: compute risk for each domain, now that ALL
    #      domains are known (needed for infrastructure-reuse check) ----
    for domain in domains:
        risk_result = compute_risk(
            domain,
            all_domains_data[domain],
            all_domains_in_investigation=all_domains_data
        )
        all_domains_data[domain]["risk"] = risk_result

    # ---- Step 4: figure out the overall email-level verdict ----
    highest_risk_domain = max(
        all_domains_data.items(),
        key=lambda item: item[1]["risk"]["risk_score"]
    )

    overall_result = {
        "eml_path": eml_path,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "domains_analyzed": len(domains),
        "received_chain": received_chain,
        "reliable_hop_analysis": reliable_hop_result,
        "infrastructure_risk": infrastructure_risk,
        "domains": all_domains_data,
        "overall_verdict": {
            "highest_risk_domain": highest_risk_domain[0],
            "highest_risk_score": highest_risk_domain[1]["risk"]["risk_score"],
            "highest_risk_level": highest_risk_domain[1]["risk"]["risk_level"],
        }
    }

    return overall_result


# ==================================================================
# SAVE + STANDALONE TESTING
# ==================================================================

def save_pipeline_result(result, output_path="pipeline_output.json"):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, default=str)
    print(f"\n[+] Saved combined result to {output_path}")


if __name__ == "__main__":

    eml_file = input("Enter path to .eml file: ").strip()

    print(f"\nRunning full pipeline on: {eml_file}\n")

    result = run_pipeline(eml_file)

    print("\n" + "=" * 60)
    print("OVERALL VERDICT")
    print("=" * 60)
    print(json.dumps(result["overall_verdict"], indent=2))

    save_pipeline_result(result)
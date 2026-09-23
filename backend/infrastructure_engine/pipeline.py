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
from concurrent.futures import ThreadPoolExecutor, as_completed


# ==================================================================
# PATH SETUP
# ==================================================================

BACKEND_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

sys.path.insert(0, BACKEND_PATH)

GRAPH_ENGINE_PATH = os.path.join(
    BACKEND_PATH,
    "threat_graph_engine"
)

if GRAPH_ENGINE_PATH not in sys.path:
    sys.path.insert(0, GRAPH_ENGINE_PATH)


# ==================================================================
# IMPORTS
# ==================================================================

from header_auth_engine.received_parser import parse_received_chain

from ip_intelligence import investigate_reliable_hop



from domain_extract import extract_domains
from domain_extract import extract_urls

from whois_lookup import extract_whois

from dns_lookup import (
    get_dns_records,
    get_registrable_domain
)

from domain_reputation import (
    check_domain_reputation,
    check_url_reputation
)

from tls_lookup import extract_tls

from risk_scorer import compute_risk, assess_infrastructure

from fingerprint import generate_fingerprint


# ==================================================================
# PER-DOMAIN INVESTIGATION
# ==================================================================

def investigate_domain(domain):
    """
    Runs every lookup for a single domain and returns one combined
    dict.

    Risk is NOT computed here because infrastructure-reuse checking
    needs all domains to be known first.
    """

    domain_record = {
        "domain": domain,
        "whois": {},
        "dns": {},
        "tls": {},
        "reputation": {}
    }

    # --------------------------------------------------------------
    # DNS
    # --------------------------------------------------------------

    try:
        domain_record["dns"] = (
            get_dns_records(domain) or {}
        )

    except Exception as e:
        domain_record["dns"] = {
            "error": str(e)
        }

    # --------------------------------------------------------------
    # WHOIS / RDAP
    # --------------------------------------------------------------

    try:
        registrable = (
            get_registrable_domain(domain)
            or domain
        )

        domain_record["whois"] = (
            extract_whois(registrable) or {}
        )

    except Exception as e:
        domain_record["whois"] = {
            "error": str(e)
        }

    # --------------------------------------------------------------
    # TLS
    # --------------------------------------------------------------

    try:
        domain_record["tls"] = (
            extract_tls(domain) or {}
        )

    except Exception as e:
        domain_record["tls"] = {
            "error": str(e)
        }

    # --------------------------------------------------------------
    # Reputation
    # --------------------------------------------------------------

    try:
        domain_record["reputation"] = (
            check_domain_reputation(domain) or {}
        )

    except Exception as e:
        domain_record["reputation"] = {
            "error": str(e)
        }

    return domain_record


# ==================================================================
# FULL EMAIL PIPELINE
# ==================================================================

def run_pipeline(eml_path):
    """
    Main entry point.

    Give it an .eml file path and get back ONE combined investigation
    object covering every domain found in that email.
    """

    # --------------------------------------------------------------
    # Email ID
    # --------------------------------------------------------------

    email_id = os.path.splitext(
        os.path.basename(eml_path)
    )[0]

    print(f"\n[*] Starting pipeline for {eml_path}")

    # --------------------------------------------------------------
    # Step 1: Extract domains and URLs
    # --------------------------------------------------------------

    domains = extract_domains(eml_path)
    urls = extract_urls(eml_path)

    print(f"[*] Domains found: {len(domains)}")
    print(f"[*] URLs found: {len(urls)}")

    # --------------------------------------------------------------
    # Step 1A: Exact URL reputation checks
    # --------------------------------------------------------------

    url_reputation = []

    if urls:

        with ThreadPoolExecutor(
            max_workers=min(8, len(urls))
        ) as executor:

            future_to_url = {
                executor.submit(
                    check_url_reputation,
                    url
                ): url

                for url in urls
            }

            for future in as_completed(
                future_to_url
            ):

                url = future_to_url[future]

                try:

                    result = future.result()

                    url_reputation.append(
                        result
                    )

                except Exception as e:

                    print(
                        f"[!] URL reputation failed "
                        f"for {url}: {e}"
                    )

                    url_reputation.append({
                        "url": url,
                        "status": "error",
                        "error": str(e)
                    })

    # --------------------------------------------------------------
    # Step 1B: Fingerprint generation
    # --------------------------------------------------------------

    fingerprint = {}

    try:

        fingerprint = (
            generate_fingerprint(eml_path)
            or {}
        )

        print("[*] Fingerprint generation: OK")

    except Exception as e:

        print(
            f"[!] Fingerprint generation failed: {e}"
        )

        fingerprint = {}

    # --------------------------------------------------------------
    # Step 1C: Received-chain + IP intelligence investigation
    # --------------------------------------------------------------

    received_chain = []

    try:

        with open(
            eml_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as f:

            email_content = f.read()

        received_headers = re.findall(
            r"^Received:.*?(?=\n\S|\Z)",
            email_content,
            re.IGNORECASE | re.MULTILINE | re.DOTALL
        )

        received_chain = (
            parse_received_chain(
                received_headers
            )
        )

        print(
            f"[*] Received-chain parsing: "
            f"{len(received_chain)} hops"
        )

    except Exception as e:

        print(
            f"[!] Received-chain parsing failed: {e}"
        )

    # --------------------------------------------------------------
    # Build hop data for Person 2
    # --------------------------------------------------------------

    hop_data = {
        "hops": [

            {
                "hop_index": hop.get(
                    "hop",
                    index
                ),

                "ip": hop.get(
                    "from_ip"
                ),

                "hostname": hop.get(
                    "from_host"
                ),

                "evidence": {}
            }

            for index, hop in enumerate(
                received_chain,
                start=1
            )

            if hop.get("from_ip")
        ]
    }

    # --------------------------------------------------------------
    # Person 2: reliable hop + IP intelligence
    # --------------------------------------------------------------

    try:

        reliable_hop_result = (
            investigate_reliable_hop(
                hop_data
            )
        )

        print(
            "[*] Person 2 IP intelligence: OK"
        )

    except Exception as e:

        print(
            f"[!] IP intelligence failed: {e}"
        )

        reliable_hop_result = {
            "status": "unavailable",
            "error": str(e),
            "earliest_reliable_node": {},
            "ip_intelligence": {}
        }

    # --------------------------------------------------------------
    # Step 1D: Authentication parsing
    # --------------------------------------------------------------

    authentication = {}

    try:

        from header_auth_engine.header_parser import (
            build_email_data
        )

        parsed_headers = (
            build_email_data(eml_path)
        )

        authentication = (
            parsed_headers.get(
                "authentication",
                {}
            )
        )

        print(
            "[*] Authentication parsing: OK"
        )

    except Exception as e:

        print(
            f"[!] Authentication parsing failed: {e}"
        )

    # --------------------------------------------------------------
    # Step 1E: Final Infrastructure Risk Assessment
    # --------------------------------------------------------------

    if isinstance(
        reliable_hop_result,
        dict
    ):

        try:

            infrastructure_risk = (
                assess_infrastructure(
                    reliable_hop_analysis=
                        reliable_hop_result.get(
                            "earliest_reliable_node",
                            {}
                        ),

                    ip_intelligence=
                        reliable_hop_result.get(
                            "ip_intelligence",
                            {}
                        ),

                    authentication=
                        authentication
                )
            )

        except Exception as e:

            print(
                f"[!] Infrastructure risk failed: {e}"
            )

            infrastructure_risk = {
                "status": "unavailable",
                "risk_score": 0,
                "reasons": [
                    str(e)
                ]
            }

    else:

        infrastructure_risk = {
            "status": "unavailable",
            "risk_score": 0,
            "reasons": [
                "Reliable hop analysis unavailable"
            ]
        }

    # --------------------------------------------------------------
    # No domains case
    # --------------------------------------------------------------

    if not domains:

        return {
            "email_id": email_id,

            "eml_path": eml_path,

            "observed_at":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "domains_analyzed": 0,

            "received_chain":
                received_chain,

            "reliable_hop_analysis":
                reliable_hop_result,

            "infrastructure_risk":
                infrastructure_risk,

            "fingerprint":
                fingerprint,

            "urls":
                urls,

            "url_reputation":
                url_reputation,

            "domains": {},

            "warning":
                "No domains extracted from this email"
        }

    # --------------------------------------------------------------
    # Step 2: Investigate every domain in parallel
    # --------------------------------------------------------------

    all_domains_data = {}

    with ThreadPoolExecutor(
        max_workers=min(8, len(domains))
    ) as executor:

        future_to_domain = {

            executor.submit(
                investigate_domain,
                domain
            ): domain

            for domain in domains
        }

        for future in as_completed(
            future_to_domain
        ):

            domain = future_to_domain[
                future
            ]

            try:

                all_domains_data[
                    domain
                ] = future.result()

                print(
                    f"[*] Finished investigating "
                    f"{domain}"
                )

            except Exception as e:

                print(
                    f"[!] Investigation failed "
                    f"for {domain}: {e}"
                )

                all_domains_data[
                    domain
                ] = {

                    "domain": domain,

                    "whois": {},

                    "dns": {},

                    "tls": {},

                    "reputation": {},

                    "error": str(e)
                }

    # --------------------------------------------------------------
    # Step 3: Compute risk for every domain
    #
    # IMPORTANT:
    # This stays sequential because compute_risk needs ALL domain
    # data for infrastructure-reuse detection.
    # --------------------------------------------------------------

    for domain in domains:

        try:

            risk_result = compute_risk(
                domain,

                all_domains_data[
                    domain
                ],

                all_domains_in_investigation=
                    all_domains_data
            )

            all_domains_data[
                domain
            ]["risk"] = risk_result

        except Exception as e:

            print(
                f"[!] Risk calculation failed "
                f"for {domain}: {e}"
            )

            all_domains_data[
                domain
            ]["risk"] = {

                "risk_score": 0,

                "risk_level": "unknown",

                "reasons": [
                    str(e)
                ]
            }

    # --------------------------------------------------------------
    # Step 4: Overall email-level verdict
    # --------------------------------------------------------------

    highest_risk_domain = max(
        all_domains_data.items(),

        key=lambda item:
            item[1]
            .get("risk", {})
            .get("risk_score", 0)
    )

    domain_scores = [

        item[1]
        .get("risk", {})
        .get("risk_score", 0)

        for item in
        all_domains_data.items()
    ]

    max_domain_score = max(
        domain_scores,
        default=0
    )

    # --------------------------------------------------------------
    # Start with infrastructure risk
    # --------------------------------------------------------------

    overall_score = (
        infrastructure_risk.get(
            "risk_score",
            0
        )
    )

    overall_reasons = []

    if infrastructure_risk.get(
        "reasons"
    ):

        reasons = infrastructure_risk[
            "reasons"
        ]

        if isinstance(
            reasons,
            list
        ):

            overall_reasons.extend(
                reasons
            )

        else:

            overall_reasons.append(
                str(reasons)
            )

    # --------------------------------------------------------------
    # High-risk domain
    # --------------------------------------------------------------

    if max_domain_score >= 60:

        overall_score = max(
            overall_score,
            max_domain_score
        )

        overall_reasons.append(
            "High-risk domain detected: "
            f"{highest_risk_domain[0]}"
        )

    # --------------------------------------------------------------
    # Medium-risk domain
    # --------------------------------------------------------------

    elif max_domain_score >= 25:

        overall_score = max(
            overall_score,
            max_domain_score
        )

        overall_reasons.append(
            "Medium-risk embedded domain detected: "
            f"{highest_risk_domain[0]}"
        )

    # --------------------------------------------------------------
    # Clamp score
    # --------------------------------------------------------------

    overall_score = min(
        max(
            overall_score,
            0
        ),
        100
    )

    # --------------------------------------------------------------
    # Overall level
    # --------------------------------------------------------------

    if overall_score >= 60:

        overall_level = "high"

    elif overall_score >= 25:

        overall_level = "medium"

    else:

        overall_level = "low"

    # --------------------------------------------------------------
    # Final combined result
    # --------------------------------------------------------------

    overall_result = {

        "email_id":
            email_id,

        "eml_path":
            eml_path,

        "observed_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "domains_analyzed":
            len(domains),

        "received_chain":
            received_chain,

        "reliable_hop_analysis":
            reliable_hop_result,

        "infrastructure_risk":
            infrastructure_risk,

        "fingerprint":
            fingerprint,

        "urls":
            urls,

        "url_reputation":
            url_reputation,

        "domains":
            all_domains_data,

        "overall_verdict": {

            "risk_score":
                overall_score,

            "risk_level":
                overall_level,

            "highest_risk_domain":
                highest_risk_domain[0],

            "highest_risk_score":
                highest_risk_domain[1]
                .get("risk", {})
                .get("risk_score", 0),

            "reasons":
                overall_reasons
        }
    }

    print(
        f"[*] Pipeline completed: "
        f"{overall_level} risk "
        f"({overall_score})"
    )

    return overall_result


# ==================================================================
# SAVE + STANDALONE TESTING
# ==================================================================

def save_pipeline_result(
    result,
    output_path="pipeline_output.json"
):

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            result,
            f,
            indent=4,
            default=str
        )

    print(
        f"\n[+] Saved combined result "
        f"to {output_path}"
    )


# ==================================================================
# STANDALONE EXECUTION
# ==================================================================

if __name__ == "__main__":

    eml_file = input(
        "Enter path to .eml file: "
    ).strip()

    print(
        f"\nRunning full pipeline on: "
        f"{eml_file}\n"
    )

    result = run_pipeline(
        eml_file
    )

    print(
        "\n" + "=" * 60
    )

    print(
        "OVERALL VERDICT"
    )

    print(
        "=" * 60
    )

    print(
        json.dumps(
            result.get(
                "overall_verdict",
                {}
            ),
            indent=2
        )
    )

    save_pipeline_result(
        result
    )
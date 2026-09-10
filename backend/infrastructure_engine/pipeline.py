import json
import sys
from datetime import datetime, timezone

from dns_lookup import investigate_email
from infrastructure_analyzer import analyze_infrastructure
from ip_intelligence import investigate_ips
from threat_intelligence import investigate_threats
from domain_reputation import investigate_domain_reputation
from tls_lookup import extract_tls


def run_pipeline(eml_path):
    """
    Run the complete email investigation pipeline.

    Flow:
        EML
        ↓
        Domain + DNS + RDAP
        ↓
        Infrastructure Analysis
        ↓
        IP Intelligence
        ↓
        Threat Intelligence
        ↓
        Domain Reputation
        ↓
        TLS Certificate Analysis
        ↓
        Final Investigation Artifact
    """

    print("\n" + "=" * 70)
    print("        DIGITAL SAFETY COPILOT - INVESTIGATION PIPELINE")
    print("=" * 70)

    print(f"\n[+] Input email: {eml_path}")

    # ==========================================================
    # 1. DOMAIN + DNS + RDAP
    # ==========================================================

    print("\n" + "-" * 70)
    print("[1/6] Domain, DNS & RDAP Investigation")
    print("-" * 70)

    email_result = investigate_email(eml_path)

    print("\n[+] Domain, DNS and RDAP investigation completed")

    # ==========================================================
    # 2. INFRASTRUCTURE ANALYSIS
    # ==========================================================

    print("\n" + "-" * 70)
    print("[2/6] Infrastructure Analysis")
    print("-" * 70)

    infrastructure_result = analyze_infrastructure()

    print("\n[+] Infrastructure analysis completed")

    # ==========================================================
    # 3. IP INTELLIGENCE
    # ==========================================================

    print("\n" + "-" * 70)
    print("[3/6] IP Intelligence")
    print("-" * 70)

    ip_result = investigate_ips(
        "infrastructure_results.json"
    )

    print("\n[+] IP intelligence completed")

    # ==========================================================
    # 4. THREAT INTELLIGENCE
    # ==========================================================

    print("\n" + "-" * 70)
    print("[4/6] Threat Intelligence")
    print("-" * 70)

    threat_result = investigate_threats(
        "infrastructure_results.json"
    )

    print("\n[+] Threat intelligence completed")

    # ==========================================================
    # 5. DOMAIN REPUTATION
    # ==========================================================

    print("\n" + "-" * 70)
    print("[5/6] Domain Reputation")
    print("-" * 70)

    domain_reputation_result = investigate_domain_reputation(
        "dns_results.json"
    )

    print("\n[+] Domain reputation completed")

    # ==========================================================
    # 6. TLS CERTIFICATE ANALYSIS
    # ==========================================================

    print("\n" + "-" * 70)
    print("[6/6] TLS Certificate Analysis")
    print("-" * 70)

    tls_results = [
        extract_tls(domain)
        for domain in email_result.get("domains", [])
    ]

    print("\n[+] TLS certificate analysis completed")

    # ==========================================================
    # BUILD FINAL INVESTIGATION ARTIFACT
    # ==========================================================

    print("\n" + "-" * 70)
    print("Building final investigation artifact")
    print("-" * 70)

    final_result = {
        "investigation": {
            "observed_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "source": eml_path
        },

        "domains": email_result.get(
            "domains",
            []
        ),

        "registrable_domains": email_result.get(
            "registrable_domains",
            []
        ),

        "infrastructure": infrastructure_result,

        "ip_intelligence": ip_result.get(
            "ips",
            []
        ),

        "threat_intelligence": threat_result.get(
            "ips",
            []
        ),

        "domain_reputation": domain_reputation_result.get(
            "domains",
            []
        ),

        "tls_certificates": tls_results
    }

    # ==========================================================
    # SAVE FINAL RESULT
    # ==========================================================

    output_file = "final_investigation.json"

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            final_result,
            f,
            indent=4
        )

    print("\n[+] Final investigation saved to:")
    print(f"    {output_file}")

    print("\n" + "=" * 70)
    print("              INVESTIGATION COMPLETE")
    print("=" * 70)

    return final_result


# ==============================================================
# MAIN
# ==============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print("\nUsage:")
        print("  python pipeline.py <email_file>")

        print("\nExample:")
        print("  python pipeline.py example.eml")

        sys.exit(1)

    email_file = sys.argv[1]

    try:

        run_pipeline(email_file)

    except FileNotFoundError as e:

        print("\n[ERROR] File not found:")
        print(f"        {e}")

        sys.exit(1)

    except Exception as e:

        print("\n[ERROR] Pipeline failed:")
        print(f"        {e}")

        sys.exit(1)
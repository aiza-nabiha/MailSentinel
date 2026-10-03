"""
JARM fingerprinting: identifies a server's TLS software stack by
sending crafted Client Hello packets and hashing the response
pattern. Unlike a certificate fingerprint, this survives certificate
reissuance and even a full IP change, as long as the same underlying
server software/configuration is still running -- exactly the
evasion case (cert + IP rotation together) that certificate-based
correlation alone cannot catch.

IMPORTANT: this requires raw TLS socket probing, not a normal HTTPS
request. Some networks (corporate firewalls, some sandboxed/proxied
environments) intercept or block this. ALWAYS run
sanity_check_network() first on the actual deployment network before
relying on this module -- if every domain returns the same hash,
the network is intercepting TLS and results will be meaningless.
"""

from jarm.scanner.scanner import Scanner


DEFAULT_PORT = 443


# ==================================================================
# NETWORK SANITY CHECK -- run this FIRST, before any integration work
# ==================================================================

def sanity_check_network():
    """
    Confirms raw JARM TLS probing actually works correctly on the
    current network. If multiple unrelated, well-known domains all
    return the SAME hash, the network is intercepting/proxying TLS
    connections, and JARM results here cannot be trusted.
    """

    test_sites = ["google.com", "github.com", "cloudflare.com"]
    results = {}

    print("Running JARM network sanity check...")

    for site in test_sites:
        try:
            hash_result, _, _ = Scanner.scan(site, DEFAULT_PORT)
            results[site] = hash_result
            print(f"  {site}: {hash_result}")
        except Exception as e:
            print(f"  {site}: ERROR - {e}")
            results[site] = None

    successful = [v for v in results.values() if v]

    if len(successful) < 2:
        print("\n[-] Not enough successful scans to validate. "
              "Raw TLS probing may be BLOCKED on this network.")
        return False

    if len(set(successful)) == 1:
        print("\n[-] WARNING: All domains returned the SAME hash.")
        print("    This network is likely intercepting/proxying TLS.")
        print("    JARM results will be unreliable here -- try a")
        print("    different network, personal hotspot, or cloud VM.")
        return False

    print("\n[+] Results differ correctly -- JARM is working properly on this network.")
    return True


# ==================================================================
# MAIN ENTRY POINT
# ==================================================================

def extract_jarm(domain, port=DEFAULT_PORT):
    """
    Fetch the JARM fingerprint for a domain/IP. Returns the same
    result shape as your other lookup modules (status/error pattern
    matching tls_lookup.py, whois_lookup.py, etc.).
    """

    domain = domain.strip().lower()

    result = {
        "domain": domain,
        "port": port,
        "status": "failed",
        "jarm_hash": None,
        "error": None,
    }

    try:
        jarm_hash, resolved_target, resolved_port = Scanner.scan(domain, port)

        if not jarm_hash or jarm_hash == "0" * 62:
            result["error"] = "No JARM hash returned (server may not respond to TLS probes)"
            return result

        result["jarm_hash"] = jarm_hash
        result["status"] = "success"

    except Exception as e:
        result["error"] = f"JARM scan failed: {e}"

    return result


# ==================================================================
# STANDALONE TESTING
# ==================================================================

if __name__ == "__main__":

    network_ok = sanity_check_network()

    if not network_ok:
        print("\n[!] Fix network issues above before continuing.")
    else:
        domain = input("\nEnter domain to fingerprint: ").strip()

        if domain:
            result = extract_jarm(domain)
            print(f"\nDomain: {result['domain']}")
            print(f"Status: {result['status']}")
            if result["status"] == "success":
                print(f"JARM Hash: {result['jarm_hash']}")
            else:
                print(f"Error: {result['error']}")
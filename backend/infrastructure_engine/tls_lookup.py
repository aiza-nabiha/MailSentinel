import hashlib
import json
import os
import socket
import ssl
from datetime import datetime, timezone


REQUEST_TIMEOUT = 10
DEFAULT_PORT = 443

TLS_RESULTS_FILE = "tls_results.json"


# ==================================================================
# CORE CERTIFICATE FETCH
# ==================================================================

def _fetch_certificate(domain, port=DEFAULT_PORT):
    """
    Open a TLS connection to the domain and pull back its certificate,
    both as a parsed dict (issuer, dates, SANs) and raw DER bytes
    (for fingerprinting).
    """

    context = ssl.create_default_context()

    with socket.create_connection(
        (domain, port),
        timeout=REQUEST_TIMEOUT
    ) as sock:

        with context.wrap_socket(
            sock,
            server_hostname=domain
        ) as ssock:

            cert_dict = ssock.getpeercert()
            cert_der = ssock.getpeercert(binary_form=True)

            return cert_dict, cert_der


def _parse_name(name_tuple):
    """
    ssl's getpeercert() returns issuer/subject as a tuple of tuples
    of tuples, e.g. ((('countryName', 'US'),), (('organizationName',
    'DigiCert Inc'),), ...). Flatten it into a plain dict.
    """

    flat = {}

    for rdn in name_tuple or ():
        for key, value in rdn:
            flat[key] = value

    return flat


def _get_san_domains(cert_dict):
    """
    Extract Subject Alternative Names (the other domains this same
    certificate covers) from the parsed certificate.
    """

    sans = []

    for entry_type, value in cert_dict.get("subjectAltName", ()):
        if entry_type == "DNS":
            sans.append(value.lower())

    return sans


def _fingerprint(cert_der):
    """
    SHA-256 fingerprint of the raw certificate. Two domains sharing
    this exact value are served by the literal same certificate --
    a strong infrastructure-reuse signal.
    """

    return hashlib.sha256(cert_der).hexdigest()


def _days_until(date_str):
    """
    getpeercert() dates come back like 'Jun  1 12:00:00 2026 GMT'.
    """

    try:
        expiry = datetime.strptime(
            date_str,
            "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        return (expiry - datetime.now(timezone.utc)).days

    except (ValueError, TypeError):
        return None


# ==================================================================
# PERSISTENCE + REUSE TRACKING ACROSS DOMAINS
# ==================================================================

def _load_all_results():
    """
    Load every previously saved TLS result (across all past runs),
    as a plain list of result dicts.
    """

    if not os.path.exists(TLS_RESULTS_FILE):
        return []

    with open(TLS_RESULTS_FILE, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return []

    return data.get("domains", [])


def _symmetrize_cert_sharing(all_results):
    """
    Recompute cert_shared_with for EVERY saved domain based on the
    full current set of fingerprints, so the relationship is always
    bidirectional -- if B shares a cert with A, A also shows B.
    This is recalculated fresh every time, so nothing goes stale.
    """

    fp_to_domains = {}

    for entry in all_results:
        fp = entry.get("fingerprint_sha256")
        if fp:
            fp_to_domains.setdefault(fp, []).append(entry["domain"])

    for entry in all_results:
        fp = entry.get("fingerprint_sha256")
        if fp:
            entry["cert_shared_with"] = [
                d for d in fp_to_domains.get(fp, [])
                if d != entry["domain"]
            ]

    return all_results


def _save_result(new_entry):
    """
    Insert or update this domain's result in the persisted file.
    If the domain was already checked before, REPLACE its old
    record instead of appending a duplicate. Then re-symmetrize
    cert_shared_with across everything before writing.
    """

    all_results = _load_all_results()

    # replace existing entry for this domain if present, else append
    replaced = False
    for i, entry in enumerate(all_results):
        if entry.get("domain") == new_entry["domain"]:
            all_results[i] = new_entry
            replaced = True
            break

    if not replaced:
        all_results.append(new_entry)

    all_results = _symmetrize_cert_sharing(all_results)

    output = {
        "investigation": {
            "observed_at": datetime.now(timezone.utc).isoformat()
        },
        "domains": all_results
    }

    with open(TLS_RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)

    # return this domain's freshly-symmetrized entry so the caller
    # gets the correct cert_shared_with value immediately
    for entry in all_results:
        if entry["domain"] == new_entry["domain"]:
            return entry

    return new_entry


# ==================================================================
# MAIN ENTRY POINT
# ==================================================================

def extract_tls(domain, port=DEFAULT_PORT):
    """
    Fetch and analyze a domain's TLS certificate: issuer, validity
    window, which other domains it covers (SANs), and whether its
    exact fingerprint has been seen on a different domain before
    (a reuse/shared-infrastructure signal, tracked across ALL past
    runs, not just this batch).
    """

    domain = domain.strip().lower()

    result = {
        "domain": domain,
        "status": "failed",
        "issuer": None,
        "valid_from": None,
        "valid_to": None,
        "days_until_expiry": None,
        "san_domains": [],
        "fingerprint_sha256": None,
        "cert_shared_with": [],
        "error": None
    }

    try:
        cert_dict, cert_der = _fetch_certificate(domain, port)

        issuer = _parse_name(cert_dict.get("issuer"))

        result["issuer"] = (
            issuer.get("organizationName")
            or issuer.get("commonName")
        )

        result["valid_from"] = cert_dict.get("notBefore")
        result["valid_to"] = cert_dict.get("notAfter")
        result["days_until_expiry"] = _days_until(
            cert_dict.get("notAfter")
        )

        result["san_domains"] = _get_san_domains(cert_dict)
        result["fingerprint_sha256"] = _fingerprint(cert_der)
        result["status"] = "success"

        # persist (adds/replaces this domain) and get back the
        # correctly symmetrized cert_shared_with for THIS domain
        result = _save_result(result)

    except socket.timeout:
        result["error"] = "Connection timed out"

    except socket.gaierror:
        result["error"] = "Could not resolve domain"

    except ConnectionRefusedError:
        result["error"] = "Connection refused (port 443 likely closed)"

    except ssl.SSLError as e:
        result["error"] = f"TLS/SSL error: {e}"

    except Exception as e:
        result["error"] = f"Unexpected error: {e}"

    return result


# ==================================================================
# STANDALONE TESTING
# ==================================================================

if __name__ == "__main__":

    domain = input("Enter domain: ").strip()

    if not domain:
        print("[-] No domain provided.")
    else:
        print("\n" + "=" * 60)
        print(f"TLS CERTIFICATE: {domain}")
        print("=" * 60)

        result = extract_tls(domain)

        if result["status"] == "success":
            print(f"\nIssuer: {result['issuer']}")
            print(f"Valid From: {result['valid_from']}")
            print(f"Valid To: {result['valid_to']}")
            print(f"Days Until Expiry: {result['days_until_expiry']}")

            print("\nCovers Domains (SAN):")
            for san in result["san_domains"]:
                print(f"  {san}")

            print(f"\nFingerprint (SHA-256): {result['fingerprint_sha256']}")

            if result["cert_shared_with"]:
                print(
                    f"\n[!] Certificate REUSED on: "
                    f"{result['cert_shared_with']}"
                )
            else:
                print("\nNo cert reuse detected against prior domains.")

        else:
            print(f"\n[-] Extraction failed: {result['error']}")
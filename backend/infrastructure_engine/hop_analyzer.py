import ipaddress


def is_public_ip(ip):
    """
    Check whether an IP address is publicly routable.
    """
    try:
        address = ipaddress.ip_address(ip)

        return not (
            address.is_private
            or address.is_loopback
            or address.is_reserved
            or address.is_link_local
        )

    except ValueError:
        return False


def extract_public_hops(data):
    """
    Extract valid public IPs from Person A's hop output.
    """
    hops = data.get("hops", [])
    public_hops = []

    for index, hop in enumerate(hops, start=1):
        ip = hop.get("ip")
        hostname = hop.get("hostname")

        if not ip:
            continue

        if is_public_ip(ip):
            public_hops.append({
                "hop_index": index,
                "ip": ip,
                "hostname": hostname,
                "evidence": hop.get("evidence", {})
            })

    return public_hops


def analyze_hops(data):
    """
    Analyze all hops and return public hop information.
    """
    hops = data.get("hops", [])
    public_hops = extract_public_hops(data)

    return {
        "total_hops": len(hops),
        "public_hop_count": len(public_hops),
        "public_hops": public_hops
    }


def assess_hop_reliability(hop):
    """
    Assess hop reliability using basic infrastructure evidence.
    """

    score = 0
    reasons = []

    ip = hop.get("ip")
    hostname = hop.get("hostname")
    evidence = hop.get("evidence", {})

    # Public IP
    if is_public_ip(ip):
        score += 30
        reasons.append("Public IP address")
    else:
        reasons.append("IP is not publicly routable")

    # Hostname availability
    if hostname:
        score += 20
        reasons.append("Hostname is available")
    else:
        reasons.append("Hostname is unavailable")

    # Basic hostname structure
    if hostname and "." in hostname:
        score += 10
        reasons.append("Hostname has valid domain structure")

    # DNS consistency
    if evidence.get("dns_consistent") is True:
        score += 15
        reasons.append("DNS is consistent")
    elif evidence.get("dns_consistent") is False:
        score -= 15
        reasons.append("DNS is inconsistent")

    # Authentication consistency
    if evidence.get("authentication_consistent") is True:
        score += 15
        reasons.append("Authentication evidence is consistent")
    elif evidence.get("authentication_consistent") is False:
        score -= 15
        reasons.append("Authentication evidence is inconsistent")

    # Known infrastructure
    if evidence.get("known_infrastructure") is True:
        score += 10
        reasons.append("Infrastructure is known")
    elif evidence.get("known_infrastructure") is False:
        score -= 10
        reasons.append("Infrastructure is unknown")

    # Keep score between 0 and 100
    score = max(0, min(score, 100))

    # Reliability classification
    if score >= 70:
        reliability = "TRUSTED"
    elif score >= 50:
        reliability = "LIKELY_TRUSTED"
    elif score >= 30:
        reliability = "UNKNOWN"
    else:
        reliability = "SUSPICIOUS"

    return {
        "hop_index": hop.get("hop_index"),
        "ip": ip,
        "hostname": hostname,
        "score": score,
        "reliability": reliability,
        "reasons": reasons
    }


def analyze_hop_reliability(data):
    """
    Assess the reliability of all public hops.
    """
    public_hops = extract_public_hops(data)

    assessed_hops = []

    for hop in public_hops:
        assessment = assess_hop_reliability(hop)
        assessed_hops.append(assessment)

    return assessed_hops


def find_earliest_reliable_node(data):
    """
    Find the earliest reliable observable infrastructure
    from the ordered public hops.
    """
    assessed_hops = analyze_hop_reliability(data)

    for hop in assessed_hops:
        if hop["reliability"] in ["TRUSTED", "LIKELY_TRUSTED"]:
            return {
                "hop_index": hop["hop_index"],
                "ip": hop["ip"],
                "hostname": hop["hostname"],
                "confidence": hop["score"] / 100,
                "reliability": hop["reliability"],
                "reasons": hop["reasons"]
            }

    return None


# MOCK DATA FOR TEST
if __name__ == "__main__":

    mock_data = {
        "hops": [
            {
                "ip": "8.8.8.10",
                "hostname": "suspicious1.example",
                "evidence": {
                    "dns_consistent": False,
                    "authentication_consistent": False,
                    "known_infrastructure": False
                }
            },
            {
                "ip": "8.8.8.20",
                "hostname": "suspicious2.example",
                "evidence": {
                    "dns_consistent": False,
                    "authentication_consistent": False,
                    "known_infrastructure": False
                }
            },
            {
                "ip": "8.8.8.30",
                "hostname": "relay.example.net",
                "evidence": {
                    "dns_consistent": True,
                    "authentication_consistent": True,
                    "known_infrastructure": True
                }
            },
            {
                "ip": "8.8.8.40",
                "hostname": "mail.example.com",
                "evidence": {
                    "dns_consistent": True,
                    "authentication_consistent": True,
                    "known_infrastructure": True
                }
            }
        ]
    }

    print("\n--- Hop Analysis ---")

    result = analyze_hops(mock_data)
    print(result)

    print("\n--- Hop Reliability ---")

    reliability_result = analyze_hop_reliability(mock_data)

    for hop in reliability_result:
        print(hop)

    print("\n--- Earliest Reliable Node ---")

    earliest_node = find_earliest_reliable_node(mock_data)

    print(earliest_node)
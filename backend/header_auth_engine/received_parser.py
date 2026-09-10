import ipaddress
import re

def extract_ip(header):
    # Find possible IPv4/IPv6 addresses in the header
    candidates = re.findall(
        r'\[([^\]]+)\]|(?<![\w.])([0-9a-fA-F:]+(?:\.[0-9a-fA-F:]+)*)',
        header
    )

    for bracketed, unbracketed in candidates:
        candidate = bracketed or unbracketed

        try:
            ip = ipaddress.ip_address(candidate)
            return str(ip)
        except ValueError:
            continue

    return None

def extract_from_host(header):
    match = re.search(
        r"\bfrom\s+([^\s(]+)",
        header,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None

def extract_by_host(header):
    match = re.search(
        r"\bby\s+([^\s;]+)",
        header,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None

def extract_timestamp(header):
    match = re.search(
        r";\s*(.+)$",
        header,
        re.DOTALL
    )

    if match:
        return " ".join(match.group(1).split())

    return None

def parse_received_header(header, hop_number):
    from_host = extract_from_host(header)
    from_ip = None
    if from_host:
        # Only extract an IP when the Received header
        # actually contains a "from" host.
        from_section = header.split("by", 1)[0]
        from_ip = extract_ip(from_section)

    return {
        "hop": hop_number,
        "raw": header,
        "from_host": from_host,
        "from_ip": from_ip,
        "by_host": extract_by_host(header),
        "timestamp": extract_timestamp(header)
    }

def parse_received_chain(received_headers):
    return [
        parse_received_header(header, index)
        for index, header in enumerate(received_headers, start=1)
    ]
"""
backend/threat_graph_engine/correlate.py

Minimal, real correlation engine -- Person 4's "Part B" scaled down
to what's buildable in the time remaining. Finds connections between
THIS email and every other already-analyzed email, using data
that's already stored:

  1. Same structural template (fingerprints.structural_hash) --
     exact HTML/text skeleton reuse.
  2. Shared TLS certificate (domain_intel.cert_shared_with_json) --
     two different domains served by the literal same certificate.
  3. Shared relay infrastructure (header_results.received_chain_json)
     -- same mail relay hostname used to send both emails. This is
     the exact signal generate_synthetic_campaign.py rigs on purpose.

No graph library, no ML clustering -- just SQL queries against
data you already have. This is real correlation, not a mock, just
a smaller version of the original "NetworkX graph" vision.
"""

import json


def _get_relay_hosts(conn, email_id):
    """
    Only collects from_host (the SENDER-side relay each hop claims
    to be from) -- NOT by_host, which is typically the RECIPIENT's
    own mail server and would trivially match across any two emails
    sent to the same test inbox, producing a meaningless "match".
    """
    row = conn.execute(
        "SELECT received_chain_json FROM header_results WHERE email_id = ?", (email_id,)
    ).fetchone()
    if not row or not row[0]:
        return set()
    chain = json.loads(row[0])
    hosts = set()
    for hop in chain:
        if hop.get("from_host"):
            hosts.add(hop["from_host"])
    return hosts


def _get_shared_cert_domains(conn, email_id):
    """Returns the set of domain names that THIS email's domains share a TLS cert with."""
    rows = conn.execute(
        "SELECT domain, cert_shared_with_json FROM domain_intel WHERE email_id = ?", (email_id,)
    ).fetchall()
    shared = set()
    for domain, cert_json in rows:
        if cert_json:
            for other_domain in json.loads(cert_json):
                shared.add(other_domain)
    return shared


def _get_own_domains(conn, email_id):
    rows = conn.execute("SELECT domain FROM domain_intel WHERE email_id = ?", (email_id,)).fetchall()
    return {r[0] for r in rows}


def _get_structural_hash(conn, email_id):
    row = conn.execute("SELECT structural_hash FROM fingerprints WHERE email_id = ?", (email_id,)).fetchone()
    return row[0] if row else None


def find_correlations(conn, email_id):
    """
    Compares this email against every OTHER already-stored email and
    returns which ones share infrastructure, and how.
    """
    my_relay_hosts = _get_relay_hosts(conn, email_id)
    my_shared_cert_domains = _get_shared_cert_domains(conn, email_id)
    my_own_domains = _get_own_domains(conn, email_id)
    my_structural_hash = _get_structural_hash(conn, email_id)

    other_email_ids = [
        r[0] for r in conn.execute(
            "SELECT email_id FROM emails WHERE email_id != ?", (email_id,)
        ).fetchall()
    ]

    matches = []
    for other_id in other_email_ids:
        signals = []

        # Signal 1: same structural template
        other_hash = _get_structural_hash(conn, other_id)
        if my_structural_hash and other_hash and my_structural_hash == other_hash:
            signals.append({"type": "structural_template", "detail": "Identical HTML/text skeleton"})

        # Signal 2: shared relay host
        other_relay_hosts = _get_relay_hosts(conn, other_id)
        shared_hosts = my_relay_hosts & other_relay_hosts
        for host in shared_hosts:
            signals.append({"type": f"shared_relay_host:{host}", "detail": f"Both routed through {host}"})

        # Signal 3: shared TLS certificate (this email's domain matches something the OTHER email's cert-sharing list names, or vice versa)
        other_own_domains = _get_own_domains(conn, other_id)
        other_shared_cert_domains = _get_shared_cert_domains(conn, other_id)
        cert_overlap = (my_own_domains & other_shared_cert_domains) | (other_own_domains & my_shared_cert_domains)
        for domain in cert_overlap:
            signals.append({"type": "shared_tls_certificate", "detail": f"Certificate also covers {domain}"})

        if signals:
            matches.append({"email_id": other_id, "signals": signals})

    return matches


def record_correlations(conn, email_id):
    """
    Runs find_correlations() and persists the result into
    campaigns/campaign_members/graph_edges. If this email matches
    an existing campaign, joins it; otherwise creates a new one
    (only once at least one real match exists).
    Returns the same match list find_correlations() returned, so
    the caller can also return it directly in the API response.
    """
    import hashlib
    from datetime import datetime, timezone

    matches = find_correlations(conn, email_id)
    if not matches:
        return matches

    # Find if any matched email already belongs to a campaign
    matched_ids = [m["email_id"] for m in matches]
    existing_campaign = None
    for other_id in matched_ids:
        row = conn.execute(
            "SELECT campaign_id FROM campaign_members WHERE email_id = ? LIMIT 1", (other_id,)
        ).fetchone()
        if row:
            existing_campaign = row[0]
            break

    if existing_campaign:
        campaign_id = existing_campaign
    else:
        campaign_id = "campaign_" + hashlib.sha256(
            (email_id + "".join(sorted(matched_ids))).encode()
        ).hexdigest()[:10]
        conn.execute(
            "INSERT OR IGNORE INTO campaigns (campaign_id, confidence, linked_via_json) VALUES (?, ?, ?)",
            (campaign_id, min(1.0, 0.5 + 0.15 * len(matches)), json.dumps([s["type"] for m in matches for s in m["signals"]])),
        )

    # Add every involved email (this one + all matches) to the campaign
    all_involved = set(matched_ids) | {email_id}
    for eid in all_involved:
        conn.execute(
            "INSERT OR IGNORE INTO campaign_members (campaign_id, email_id) VALUES (?, ?)",
            (campaign_id, eid),
        )
        conn.execute("UPDATE emails SET campaign_id = ? WHERE email_id = ?", (campaign_id, eid))

    # Record each matched signal as a graph edge
    for m in matches:
        for signal in m["signals"]:
            conn.execute(
                "INSERT INTO graph_edges (node_a, node_b, edge_type, weight) VALUES (?, ?, ?, ?)",
                (email_id, m["email_id"], signal["type"], 1.0),
            )

    return matches
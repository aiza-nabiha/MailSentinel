"""
backend/infrastructure_engine/threat_correlation_engine.py

POSTGRES VERSION. This engine used to own a completely separate
SQLite file (correlation.db) that nothing else in the app ever
touched -- it only ran standalone via its CLI. It is now the LIVE
correlation engine, wired into integrate.py, sharing the same
Postgres database and connection as everything else.

Changes from the original:
  - No more init_database() / DATABASE_FILE / its own sqlite3.connect.
    Schema for investigations / infrastructure_observations /
    fingerprint_observations now lives in the shared schema.sql and
    is created by db.get_connection(). This module just uses a conn
    handed to it.
  - correlate() now takes `conn` as its first argument instead of
    opening (and closing) its own connection -- the caller (integrate.py,
    or this file's own CLI block) owns the connection's lifecycle.
  - All `?` placeholders -> `%s` (psycopg2).
  - `INSERT OR REPLACE` (SQLite-only) -> `INSERT ... ON CONFLICT DO UPDATE`.
  - The old PRAGMA table_info() schema-migration check is gone -- it
    existed only to patch up SQLite databases created by an earlier
    version of this file; a fresh Postgres schema doesn't need it.

Everything else -- the actual correlation logic (rarity weighting,
time decay, known-large-provider discount, fingerprint commonality
discount, cluster cohesion, confidence scoring) -- is unchanged.
"""

import json
import math
import os
import sys
from collections import Counter
from datetime import datetime, timezone

import networkx as nx

# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
GRAPH_ENGINE_DIR = os.path.join(BACKEND_DIR, "threat_graph_engine")
STORAGE_ENGINE_DIR = os.path.join(BACKEND_DIR, "storage_engine")

if GRAPH_ENGINE_DIR not in sys.path:
    sys.path.insert(0, GRAPH_ENGINE_DIR)
if STORAGE_ENGINE_DIR not in sys.path:
    sys.path.insert(0, STORAGE_ENGINE_DIR)

from fingerprint import compare_fingerprints

OUTPUT_FILE = os.path.join(BASE_DIR, "correlation_results.json")


# ============================================================
# CONFIGURATION (unchanged)
# ============================================================

FINGERPRINT_SIMILARITY_THRESHOLD = 0.88

HISTORY_LOOKBACK_LIMIT = 5000

NEVER_FREQUENCY_GATED = {"domain", "ip", "fingerprint"}

KNOWN_LARGE_PROVIDERS = {
    "nameserver": {
        "domaincontrol.com", "cloudflare.com", "googledomains.com",
        "awsdns", "azure-dns", "dns.namecheaphosting.com",
    },
    "mail_server": {
        "google.com", "outlook.com", "protection.outlook.com",
        "pphosted.com", "mimecast.com",
    },
    "asn": {
        "as16509", "as8075", "as15169", "as13335", "as14618", "as16276",
    },
    "cname": {
        "cloudfront.net", "azureedge.net", "github.io", "herokuapp.com",
    },
}

MAX_SIGNAL_SCORE = {
    "same_ip": 1.00,
    "same_domain": 0.95,
    "same_fingerprint": 0.95,
    "similar_fingerprint": 0.80,
    "same_asn": 0.55,
    "same_nameserver": 0.65,
    "same_mail_server": 0.50,
    "same_cname": 0.50,
    "same_relay_host": 0.65,
}

CAMPAIGN_EDGE_THRESHOLD = 55.0
MIN_CLUSTER_COHESION = 0.6
DECAY_HALF_LIFE_DAYS = 120


# ============================================================
# DATABASE (Postgres, shared connection)
# ============================================================

def record_observation(conn, value, value_type, observed_at):
    if not value:
        return
    cursor = conn.cursor()
    cursor.execute(
        "SELECT observation_count FROM infrastructure_observations WHERE value = %s AND value_type = %s",
        (value, value_type),
    )
    row = cursor.fetchone()
    if row:
        cursor.execute(
            "UPDATE infrastructure_observations SET observation_count = observation_count + 1, last_seen = %s "
            "WHERE value = %s AND value_type = %s",
            (observed_at, value, value_type),
        )
    else:
        cursor.execute(
            "INSERT INTO infrastructure_observations (value, value_type, first_seen, last_seen, observation_count) "
            "VALUES (%s, %s, %s, %s, 1)",
            (value, value_type, observed_at, observed_at),
        )
    conn.commit()


def get_observation(conn, value, value_type):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT observation_count, last_seen FROM infrastructure_observations WHERE value = %s AND value_type = %s",
        (value, value_type),
    )
    row = cursor.fetchone()
    if not row:
        return {"frequency": 0, "last_seen": None}
    return {"frequency": max(0, int(row[0])), "last_seen": row[1]}


def load_historical_emails(conn, exclude_ids=None):
    """
    Pulls every previously-recorded investigation back out of the
    database so NEW emails can be compared against emails seen in
    earlier runs/sessions, not just against each other in this batch.
    """
    exclude_ids = exclude_ids or set()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT email_id, observed_at, infrastructure_json, asns_json, fingerprint_json "
        "FROM investigations ORDER BY observed_at DESC LIMIT %s",
        (HISTORY_LOOKBACK_LIMIT,),
    )
    rows = cursor.fetchall()

    emails = []
    for email_id, observed_at, infra_json, asns_json, fp_json in rows:
        if email_id in exclude_ids:
            continue
        infra_raw = json.loads(infra_json)
        infrastructure = {k: set(v) for k, v in infra_raw.items()}
        for required_field in ("domains", "ips", "nameservers", "mail_servers", "cnames", "relay_hosts"):
            infrastructure.setdefault(required_field, set())
        emails.append({
            "email_id": email_id,
            "observed_at": observed_at.isoformat() if hasattr(observed_at, "isoformat") else observed_at,
            "infrastructure": infrastructure,
            "asns": set(json.loads(asns_json)),
            "fingerprint": json.loads(fp_json),
            "is_historical": True,
        })
    return emails


def persist_investigation(conn, email):
    cursor = conn.cursor()
    infra_serializable = {k: sorted(v) for k, v in email["infrastructure"].items()}
    cursor.execute(
        """INSERT INTO investigations
               (email_id, observed_at, infrastructure_json, asns_json, fingerprint_json)
           VALUES (%s, %s, %s, %s, %s)
           ON CONFLICT (email_id) DO UPDATE SET
               observed_at = EXCLUDED.observed_at,
               infrastructure_json = EXCLUDED.infrastructure_json,
               asns_json = EXCLUDED.asns_json,
               fingerprint_json = EXCLUDED.fingerprint_json""",
        (
            email["email_id"],
            email["observed_at"],
            json.dumps(infra_serializable),
            json.dumps(sorted(email["asns"])),
            json.dumps(email.get("fingerprint", {})),
        ),
    )
    conn.commit()


# ============================================================
# TIME DECAY (unchanged)
# ============================================================

def time_decay_factor(last_seen_iso):
    if not last_seen_iso:
        return 1.0
    try:
        if hasattr(last_seen_iso, "isoformat"):
            last_seen = last_seen_iso
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
        else:
            last_seen = datetime.fromisoformat(str(last_seen_iso).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return 1.0

    now = datetime.now(timezone.utc)
    age_days = max(0.0, (now - last_seen).total_seconds() / 86400.0)
    return 0.5 ** (age_days / DECAY_HALF_LIFE_DAYS)


# ============================================================
# RARITY / DISCOUNT MODEL (unchanged)
# ============================================================

def infrastructure_weight(conn, value, value_type):
    if value_type in NEVER_FREQUENCY_GATED:
        return 1.0

    known_set = KNOWN_LARGE_PROVIDERS.get(value_type, set())
    for known in known_set:
        if known in value:
            return 0.05

    obs = get_observation(conn, value, value_type)
    frequency = obs["frequency"]
    decay = time_decay_factor(obs["last_seen"])

    if frequency == 0:
        return 1.0 * decay

    weight = 1.0 / math.log2(frequency + 2)
    return round(max(0.15, min(1.0, weight * decay)), 4)


# ============================================================
# JSON / NORMALIZATION HELPERS (unchanged)
# ============================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_hostname(value):
    if value is None:
        return None
    value = str(value).strip().lower().rstrip(".")
    return value or None


def normalize_ip(value):
    if value is None:
        return None
    value = str(value).strip()
    return value or None


# ============================================================
# INFRASTRUCTURE EXTRACTION (unchanged)
# ============================================================

def extract_relay_hosts(received_chain):
    hosts = set()
    if not isinstance(received_chain, list):
        return hosts
    for hop in received_chain:
        if isinstance(hop, dict) and hop.get("from_host"):
            host = normalize_hostname(hop["from_host"])
            if host:
                hosts.add(host)
    return hosts


def extract_infrastructure(data):
    result = {
        "domains": set(), "ips": set(), "asns": set(),
        "nameservers": set(), "mail_servers": set(), "cnames": set(),
        "relay_hosts": set(),
    }
    if not isinstance(data, dict):
        return result

    domains = data.get("domains", {})
    if not isinstance(domains, dict):
        return result

    for domain, info in domains.items():
        if not isinstance(info, dict):
            continue

        domain_normalized = normalize_hostname(domain)
        if domain_normalized:
            result["domains"].add(domain_normalized)

        dns = info.get("dns", {})
        if isinstance(dns, dict):
            records = dns.get("records", {})
            if isinstance(records, dict):
                for ip in ensure_list(records.get("A")):
                    ip = normalize_ip(ip)
                    if ip:
                        result["ips"].add(ip)
                for ip in ensure_list(records.get("AAAA")):
                    ip = normalize_ip(ip)
                    if ip:
                        result["ips"].add(ip)
                for mx in ensure_list(records.get("MX")):
                    if not mx:
                        continue
                    if isinstance(mx, dict):
                        host = mx.get("host") or mx.get("exchange") or mx.get("hostname")
                        host = normalize_hostname(host)
                        if host:
                            result["mail_servers"].add(host)
                    elif isinstance(mx, str):
                        parts = mx.split()
                        if parts:
                            host = normalize_hostname(parts[-1])
                            if host:
                                result["mail_servers"].add(host)
                for ns in ensure_list(records.get("NS")):
                    ns = normalize_hostname(ns)
                    if ns:
                        result["nameservers"].add(ns)
                for cname in ensure_list(records.get("CNAME")):
                    cname = normalize_hostname(cname)
                    if cname:
                        result["cnames"].add(cname)

        ip_addresses = info.get("ip_addresses", {})
        if isinstance(ip_addresses, dict):
            for ip in ensure_list(ip_addresses.get("ipv4")):
                ip = normalize_ip(ip)
                if ip:
                    result["ips"].add(ip)
            for ip in ensure_list(ip_addresses.get("ipv6")):
                ip = normalize_ip(ip)
                if ip:
                    result["ips"].add(ip)

        for ns in ensure_list(info.get("name_servers")):
            ns = normalize_hostname(ns)
            if ns:
                result["nameservers"].add(ns)

        for mx in ensure_list(info.get("mail_servers")):
            if isinstance(mx, dict):
                host = mx.get("host") or mx.get("exchange") or mx.get("hostname")
                host = normalize_hostname(host)
                if host:
                    result["mail_servers"].add(host)
            elif isinstance(mx, str):
                mx = normalize_hostname(mx)
                if mx:
                    result["mail_servers"].add(mx)

        for cname in ensure_list(info.get("canonical_names")):
            cname = normalize_hostname(cname)
            if cname:
                result["cnames"].add(cname)

    return result


def extract_ip_intelligence(data):
    asns = set()
    if not isinstance(data, dict):
        return asns
    for item in data.get("ips", []):
        if not isinstance(item, dict):
            continue
        asn = item.get("asn")
        if asn:
            asns.add(str(asn).strip().lower())
        ipinfo = item.get("ipinfo", {})
        if isinstance(ipinfo, dict):
            asn = ipinfo.get("asn")
            if asn:
                asns.add(str(asn).strip().lower())
    ipinfo = data.get("ipinfo", {})
    if isinstance(ipinfo, dict):
        asn = ipinfo.get("asn")
        if asn:
            asns.add(str(asn).strip().lower())
    return asns


def normalize_fingerprint(fingerprint):
    if not isinstance(fingerprint, dict):
        return {}
    return fingerprint


# ============================================================
# FINGERPRINT COMMONALITY
# ============================================================

def fingerprint_hash_key(fingerprint):
    if not fingerprint:
        return None
    return json.dumps(fingerprint.get("structural_hash") or fingerprint, sort_keys=True)[:200]


def record_fingerprint_observation(conn, fingerprint, domain, observed_at):
    key = fingerprint_hash_key(fingerprint)
    if not key or not domain:
        return
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO fingerprint_observations (fp_key, domain, observed_at)
           VALUES (%s, %s, %s)
           ON CONFLICT (fp_key, domain) DO UPDATE SET observed_at = EXCLUDED.observed_at""",
        (key, domain, observed_at),
    )
    conn.commit()


def fingerprint_distinct_domain_count(conn, fingerprint):
    key = fingerprint_hash_key(fingerprint)
    if not key:
        return 0
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT domain) FROM fingerprint_observations WHERE fp_key = %s", (key,))
    row = cursor.fetchone()
    return row[0] if row else 0


def fingerprint_commonality_discount(conn, fingerprint):
    distinct = fingerprint_distinct_domain_count(conn, fingerprint)
    if distinct <= 3:
        return 1.0
    return round(max(0.10, 1.0 / math.log2(distinct + 1)), 4)


# ============================================================
# INFRASTRUCTURE SIGNAL BUILDER (unchanged)
# ============================================================

def build_infrastructure_signals(email_a, email_b, conn):
    signals = []
    infra_a = email_a["infrastructure"]
    infra_b = email_b["infrastructure"]

    families = [
        ("domains", "domain", "same_domain", "Identical domain observed in both emails"),
        ("ips", "ip", "same_ip", "Same IP infrastructure observed"),
        ("nameservers", "nameserver", "same_nameserver", "Both emails use the same nameserver"),
        ("mail_servers", "mail_server", "same_mail_server", "Both emails use the same mail infrastructure"),
        ("cnames", "cname", "same_cname", "Both emails resolve through the same canonical host"),
        ("relay_hosts", "relay_host", "same_relay_host", "Both emails routed through the same mail relay"),
    ]

    for field, value_type, signal_type, reason in families:
        common_values = infra_a[field] & infra_b[field]
        for value in sorted(common_values):
            weight = infrastructure_weight(conn, value, value_type)
            base = MAX_SIGNAL_SCORE[signal_type]
            score = round(base * weight, 4)

            signals.append({
                "type": signal_type,
                "value": value,
                "score": score,
                "weight_applied": weight,
                "correlation_eligible": score > 0,
                "reason": reason if weight >= 0.3 else f"{reason} (heavily discounted -- widely shared infrastructure)",
            })

    common_asns = email_a["asns"] & email_b["asns"]
    for asn in sorted(common_asns):
        weight = infrastructure_weight(conn, asn, "asn")
        score = round(MAX_SIGNAL_SCORE["same_asn"] * weight, 4)
        signals.append({
            "type": "same_asn",
            "value": asn,
            "score": score,
            "weight_applied": weight,
            "correlation_eligible": score > 0,
            "reason": "Both emails use the same ASN" if weight >= 0.3 else "Shared ASN, but a large/common provider",
        })

    return signals


def build_fingerprint_signals(email_a, email_b, conn):
    signals = []
    fp_a = normalize_fingerprint(email_a.get("fingerprint"))
    fp_b = normalize_fingerprint(email_b.get("fingerprint"))
    if not fp_a or not fp_b:
        return signals

    comparison = compare_fingerprints(fp_a, fp_b)
    structural_match = comparison.get("structural_match", False)
    shared_brands = comparison.get("shared_targeted_brands", [])

    try:
        style_similarity = float(comparison.get("style_overall_similarity") or 0.0)
    except (TypeError, ValueError):
        style_similarity = 0.0

    commonality_discount = min(
        fingerprint_commonality_discount(conn, fp_a),
        fingerprint_commonality_discount(conn, fp_b),
    )

    if structural_match:
        score = round(MAX_SIGNAL_SCORE["same_fingerprint"] * commonality_discount, 4)
        signals.append({
            "type": "same_fingerprint",
            "value": 1.0,
            "score": score,
            "similarity": 1.0,
            "shared_targeted_brands": shared_brands,
            "commonality_discount": commonality_discount,
            "correlation_eligible": score > 0,
            "reason": "Identical structural fingerprint" if commonality_discount >= 0.5
                      else "Identical structure, but shape is common across many unrelated senders",
        })
        return signals

    if style_similarity >= FINGERPRINT_SIMILARITY_THRESHOLD:
        score = round(MAX_SIGNAL_SCORE["similar_fingerprint"] * style_similarity * commonality_discount, 4)
        signals.append({
            "type": "similar_fingerprint",
            "value": round(style_similarity, 4),
            "score": score,
            "similarity": round(style_similarity, 4),
            "shared_targeted_brands": shared_brands,
            "commonality_discount": commonality_discount,
            "correlation_eligible": score > 0,
            "reason": "Highly similar email structure",
        })
    elif shared_brands and style_similarity > 0:
        signals.append({
            "type": "fingerprint_support",
            "value": round(style_similarity, 4),
            "score": 0.0,
            "similarity": round(style_similarity, 4),
            "shared_targeted_brands": shared_brands,
            "correlation_eligible": False,
            "reason": "Shared impersonated brand with supporting style similarity",
        })

    return signals


def compare_emails(email_a, email_b, conn):
    signals = []
    signals.extend(build_infrastructure_signals(email_a, email_b, conn))
    signals.extend(build_fingerprint_signals(email_a, email_b, conn))
    return signals


# ============================================================
# EVIDENCE GROUPING / CONFIDENCE (unchanged)
# ============================================================

def group_meaningful_signals(signals):
    groups = {}
    family_mapping = {
        "same_ip": "ip", "same_domain": "domain", "same_nameserver": "nameserver",
        "same_mail_server": "mail_server", "same_cname": "cname", "same_asn": "asn",
        "same_fingerprint": "fingerprint", "similar_fingerprint": "fingerprint",
        "same_relay_host": "relay_host",
    }
    for signal in signals:
        score = float(signal.get("score", 0))
        if score <= 0:
            continue
        family = family_mapping.get(signal.get("type"))
        if not family:
            continue
        groups.setdefault(family, []).append(signal)
    return groups


def calculate_confidence(signals):
    groups = group_meaningful_signals(signals)
    if not groups:
        return 0.0

    family_scores = []
    for family, family_signals in groups.items():
        strongest = max(family_signals, key=lambda s: float(s.get("score", 0)))
        score = max(0.0, min(1.0, float(strongest.get("score", 0))))
        family_scores.append(score)

    probability_not_linked = 1.0
    for score in family_scores:
        probability_not_linked *= (1.0 - score)

    return round((1.0 - probability_not_linked) * 100, 2)


def summarize_correlation(signals):
    meaningful = [s for s in signals if float(s.get("score", 0)) > 0]
    contextual = [s for s in signals if float(s.get("score", 0)) <= 0]
    families = group_meaningful_signals(meaningful)

    return {
        "evidence_families": sorted(families.keys()),
        "meaningful_signal_count": len(meaningful),
        "contextual_signal_count": len(contextual),
        "fingerprint_evidence_present": any(
            s.get("type") in {"same_fingerprint", "similar_fingerprint"} for s in meaningful
        ),
    }


# ============================================================
# GRAPH (unchanged)
# ============================================================

def is_known_large_provider(value, value_type):
    known_set = KNOWN_LARGE_PROVIDERS.get(value_type, set())
    return any(known in value for known in known_set)


MAX_NODES_PER_TYPE_PER_EMAIL = 6


def build_correlation_graph(new_emails, historical_emails, conn):
    graph = nx.Graph()
    all_emails = new_emails + historical_emails

    for email in all_emails:
        graph.add_node(email["email_id"], node_type="email",
                        is_historical=email.get("is_historical", False))

    for email in all_emails:
        email_id = email["email_id"]
        infra = email["infrastructure"]

        collapsed_counts = Counter()

        for kind, field in [("ip", "ips"), ("domain", "domains"), ("nameserver", "nameservers"),
                             ("mail_server", "mail_servers"), ("cname", "cnames"),
                             ("relay_host", "relay_hosts")]:

            values = sorted(infra[field])
            shown = 0

            for value in values:
                if kind != "domain" and is_known_large_provider(value, kind):
                    collapsed_counts[kind] += 1
                    continue

                if kind != "domain" and shown >= MAX_NODES_PER_TYPE_PER_EMAIL:
                    collapsed_counts[kind] += 1
                    continue

                node_id = f"{kind}:{value}"
                graph.add_node(node_id, node_type=kind, value=value)
                graph.add_edge(email_id, node_id, relationship=f"observed_{kind}")
                shown += 1

        asns = sorted(email["asns"])
        shown_asns = 0
        for asn in asns:
            if is_known_large_provider(asn, "asn"):
                collapsed_counts["asn"] += 1
                continue
            if shown_asns >= MAX_NODES_PER_TYPE_PER_EMAIL:
                collapsed_counts["asn"] += 1
                continue
            node_id = f"asn:{asn}"
            graph.add_node(node_id, node_type="asn", value=asn)
            graph.add_edge(email_id, node_id, relationship="observed_asn")
            shown_asns += 1

        if collapsed_counts:
            summary_id = f"collapsed_infrastructure_summary:{email_id}"
            graph.add_node(
                summary_id, node_type="collapsed_infrastructure_summary",
                value=dict(collapsed_counts),
                note="Additional infrastructure not individually shown -- either a known "
                     "large provider (can never contribute a correlation edge) or beyond "
                     f"the per-email display cap ({MAX_NODES_PER_TYPE_PER_EMAIL} per type). "
                     "Full data is still used for correlation matching; this only affects "
                     "what's rendered here.",
            )
            graph.add_edge(email_id, summary_id, relationship="observed_additional_infrastructure")

    pairs = []
    for i in range(len(new_emails)):
        for j in range(i + 1, len(new_emails)):
            pairs.append((new_emails[i], new_emails[j]))
    for new_email in new_emails:
        for hist_email in historical_emails:
            pairs.append((new_email, hist_email))

    for email_a, email_b in pairs:
        signals = compare_emails(email_a, email_b, conn)
        meaningful = [s for s in signals if float(s.get("score", 0)) > 0]
        if not meaningful:
            continue

        confidence = calculate_confidence(meaningful)
        if confidence < CAMPAIGN_EDGE_THRESHOLD:
            continue

        summary = summarize_correlation(signals)
        graph.add_edge(
            email_a["email_id"], email_b["email_id"],
            relationship="correlated_email", confidence=confidence,
            evidence_summary=summary, signals=signals,
        )

    return graph


# ============================================================
# CAMPAIGN CLUSTERING (unchanged)
# ============================================================

def build_campaigns(graph):
    email_nodes = [n for n, d in graph.nodes(data=True) if d.get("node_type") == "email"]

    email_graph = nx.Graph()
    email_graph.add_nodes_from(email_nodes)

    for source, target, data in graph.edges(data=True):
        if data.get("relationship") != "correlated_email":
            continue
        if graph.nodes[source].get("node_type") != "email" or graph.nodes[target].get("node_type") != "email":
            continue
        email_graph.add_edge(source, target, **data)

    campaigns = []
    for index, component in enumerate(nx.connected_components(email_graph), start=1):
        nodes = sorted(component)
        if len(nodes) < 2:
            continue

        subgraph = email_graph.subgraph(nodes)
        edges = []
        for source, target, data in subgraph.edges(data=True):
            edges.append({
                "source": source, "target": target,
                "confidence": data.get("confidence", 0),
                "evidence_summary": data.get("evidence_summary", {}),
                "signals": data.get("signals", []),
            })

        possible_pairs = len(nodes) * (len(nodes) - 1) / 2
        cohesion = round(len(edges) / possible_pairs, 4) if possible_pairs else 1.0

        all_signals = []
        for edge in edges:
            all_signals.extend(edge["signals"])
        signal_types = Counter(
            s["type"] for s in all_signals if float(s.get("score", 0)) > 0
        )

        campaign_confidence = round(sum(e["confidence"] for e in edges) / len(edges), 2) if edges else 0.0

        campaigns.append({
            "campaign_id": f"campaign-{index:03d}",
            "emails": nodes,
            "email_count": len(nodes),
            "confidence": campaign_confidence,
            "cohesion": cohesion,
            "cohesion_warning": cohesion < MIN_CLUSTER_COHESION,
            "signal_summary": dict(signal_types),
            "connections": edges,
        })

    return campaigns


def serialize_graph(graph):
    nodes = [{"id": n, **d} for n, d in graph.nodes(data=True)]
    edges = [{"source": s, "target": t, **d} for s, t, d in graph.edges(data=True)]
    return {"nodes": nodes, "edges": edges}


# ============================================================
# RECORD OBSERVATIONS (unchanged ordering: happens AFTER correlation)
# ============================================================

def record_current_observations(conn, emails):
    for email in emails:
        timestamp = email["observed_at"]
        infra = email["infrastructure"]
        for value in infra["domains"]:
            record_observation(conn, value, "domain", timestamp)
        for value in infra["ips"]:
            record_observation(conn, value, "ip", timestamp)
        for value in infra["nameservers"]:
            record_observation(conn, value, "nameserver", timestamp)
        for value in infra["mail_servers"]:
            record_observation(conn, value, "mail_server", timestamp)
        for value in infra["cnames"]:
            record_observation(conn, value, "cname", timestamp)
        for value in email["asns"]:
            record_observation(conn, value, "asn", timestamp)

        for domain in infra["domains"]:
            record_fingerprint_observation(conn, email.get("fingerprint", {}), domain, timestamp)


# ============================================================
# MAIN ENGINE
# ============================================================

def normalize_email_record(record, observed_at, index):
    email_id = record.get("email_id") or f"email-{index:03d}"

    infrastructure_source = record.get("infrastructure", {})
    if not infrastructure_source:
        infrastructure_source = {"domains": record.get("domains", {})}
    infrastructure = extract_infrastructure(infrastructure_source)
    infrastructure["relay_hosts"] = extract_relay_hosts(record.get("received_chain", []))

    ip_intelligence = record.get("ip_intelligence", {})
    if not ip_intelligence:
        reliable_hop = record.get("reliable_hop_analysis", {})
        if isinstance(reliable_hop, dict):
            ip_intelligence = reliable_hop.get("ip_intelligence", {})
    asns = extract_ip_intelligence(ip_intelligence)

    fingerprint = normalize_fingerprint(record.get("fingerprint", {}))

    return {
        "email_id": email_id,
        "observed_at": record.get("observed_at", observed_at),
        "infrastructure": infrastructure,
        "asns": asns,
        "fingerprint": fingerprint,
        "is_historical": False,
    }


def correlate(conn, email_records, output_file=OUTPUT_FILE):
    """
    Takes an already-open Postgres connection (a db.ConnWrapper) --
    the caller (integrate.py, or this file's own CLI block) owns
    opening and closing it. Does NOT close conn.
    """
    observed_at = datetime.now(timezone.utc).isoformat()

    new_emails = [
        normalize_email_record(record, observed_at, i + 1)
        for i, record in enumerate(email_records)
        if isinstance(record, dict)
    ]

    new_ids = {e["email_id"] for e in new_emails}
    historical_emails = load_historical_emails(conn, exclude_ids=new_ids)

    graph = build_correlation_graph(new_emails, historical_emails, conn)
    campaigns = build_campaigns(graph)

    result = {
        "investigation": {
            "observed_at": observed_at,
            "engine": "MailSentinel Threat Correlation Engine",
            "engine_version": "3.0",
            "new_email_count": len(new_emails),
            "historical_email_count": len(historical_emails),
            "correlation_method": [
                "cross-session comparison against full investigation history",
                "known-large-provider discount for shared infrastructure categories",
                "corpus-reuse diminishing-returns weighting (never hard-gated for domain/ip/fingerprint)",
                "time-decayed historical weighting",
                "fingerprint commonality discount via distinct-domain reuse count",
                "evidence-family aggregation",
                "independent-evidence confidence scoring",
                "cluster cohesion validation",
            ],
        },
        "campaigns": campaigns,
        "graph": serialize_graph(graph),
    }

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4, ensure_ascii=False)

    # Record AFTER correlating, so this batch can't inflate its own
    # frequency/rarity mid-comparison.
    for email in new_emails:
        persist_investigation(conn, email)
    record_current_observations(conn, new_emails)

    return result


# ============================================================
# CLI (standalone usage -- opens its own connection)
# ============================================================

def load_email_records(path):
    data = load_json(path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("emails"), list):
            return data["emails"]
        return [data]
    raise ValueError("Unsupported investigation JSON format")


if __name__ == "__main__":
    import argparse

    from db import get_connection

    parser = argparse.ArgumentParser(description="MailSentinel Threat Correlation Engine")
    parser.add_argument("input", nargs="+", help="One or more investigation JSON files")
    parser.add_argument("--output", default=OUTPUT_FILE, help="Output correlation JSON file")
    args = parser.parse_args()

    records = []
    for input_file in args.input:
        records.extend(load_email_records(input_file))

    cli_conn = get_connection()
    result = correlate(cli_conn, records, args.output)
    cli_conn.close()

    print("\n" + "=" * 70)
    print("THREAT CORRELATION ENGINE")
    print("=" * 70)
    print(f"\nNew emails analysed: {result['investigation']['new_email_count']}")
    print(f"Compared against {result['investigation']['historical_email_count']} historical investigations")
    print(f"Campaigns discovered: {len(result['campaigns'])}")

    for campaign in result["campaigns"]:
        print(f"\n{campaign['campaign_id']}")
        print(f"  Emails: {', '.join(campaign['emails'])}")
        print(f"  Confidence: {campaign['confidence']}%")
        print(f"  Cohesion: {campaign['cohesion']}" + (" [LOW COHESION WARNING]" if campaign["cohesion_warning"] else ""))
        print(f"  Signals: {campaign['signal_summary']}")

    print(f"\n[+] Saved to:\n    {args.output}")
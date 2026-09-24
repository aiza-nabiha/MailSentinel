const array = (value) => Array.isArray(value) ? value : [];
const level = (value) => {
  const normalized = String(value || "low").toLowerCase();
  return normalized === "high" || normalized === "threat" ? "High" : normalized === "medium" ? "Medium" : "Safe";
};

export function mapApiResponseToReportShape(api) {
  const domains = Array.isArray(api.domains) ? api.domains : Object.values(api.domains || {});
  const primary = api.highest_risk_domain || domains[0] || {};
  const infrastructureReasons = array(api.infrastructure_risk?.reasons);
  const reasons = infrastructureReasons.concat(array(api.classifier?.reasons)).slice(0, 6).map((reason, index) => ({
    id: `signal-${index}`,
    icon: index % 2 ? "◈" : "✦",
    title: typeof reason === "string" ? reason : reason.title || reason.reason || "Risk signal detected",
    source: index < infrastructureReasons.length ? "Infrastructure analysis" : "Content analysis",
    detail: typeof reason === "string" ? reason : reason.detail || reason.reason || "Evidence recorded during analysis.",
  }));

  const reliableHop = api.infrastructure_risk?.reliable_hop || null;
  const reliableHopNode = reliableHop?.earliest_reliable_node || {};
  const ipinfo = reliableHop?.ip_intelligence?.ipinfo || {};

  const matches = array(api.campaign_correlation?.matches);
  const nodes = [{ id: "email", x: 450, y: 220, icon: "📧", label: "This email", core: true }, ...(primary.domain ? [{ id: "domain", x: 265, y: 135, icon: "🌐", label: primary.domain }] : []), ...matches.map((match, index) => ({ id: match.email_id, x: 700 + (index % 2) * 95, y: 130 + index * 105, icon: "📧", label: match.email_id }))];
  const edges = [...(primary.domain ? [{ a: "email", b: "domain", type: "verified", confidence: 1, reason: "Domain observed in this investigation" }] : []), ...matches.map((match) => ({ a: "email", b: match.email_id, type: "corroborated", confidence: match.confidence ?? 0.8, reason: array(match.signals).join(", ") || "Shared campaign infrastructure" }))];
  const received = array(api.header_auth?.received_chain || api.infrastructure_risk?.received_chain);

  return {
    investigation_id: api.email_id || "pending", analyzed_at: api.analyzed_at || api.observed_at || null,
    risk_score: Math.round(api.overall_risk_score || api.infrastructure_risk?.risk_score || 0), risk_level: level(api.verdict || api.infrastructure_risk?.risk_level),
    threat_label: api.classifier?.verdict === "threat" ? "Credential phishing" : "Email investigation", url: array(api.urls)[0] || array(api.url_reputation)[0]?.url || null,
    reasons, infrastructure_evidence: array(api.infrastructure_risk?.evidence),
    domain_info: primary.domain ? {
      domain: primary.domain,
      ip: reliableHopNode.ip || primary.dns?.records?.A?.[0] || primary.ip || null,
      asn: ipinfo.asn || null,
      hosting: ipinfo.as_name || null,
      country: ipinfo.country || null,
      registrar: primary.whois?.registrar || null,
      created: primary.whois?.domain_age?.creation_date || primary.whois?.creation_date || null,
      age_days: primary.age_days ?? null,
      tls_issuer: primary.tls_issuer || null,
      tls_status: primary.tls_status || null,
      found_on_lists: array(primary.found_on_lists),
      reputation: primary.reputation || null,
    } : null,
    relay_path: received.map((hop, index) => {
      const isReliableHop = reliableHopNode.ip && hop.from_ip && hop.from_ip === reliableHopNode.ip;
      const abuseScore = reliableHop?.ip_intelligence?.reputation?.abuse_score;
      return {
        label: `Hop ${index + 1}`,
        sub: hop.from_host || hop.hostname || hop.from_ip || "Unknown host",
        verified: Boolean(hop.verified),
        trusted: Boolean(hop.trusted),
        ip: hop.from_ip || "—",
        location: isReliableHop ? (ipinfo.country || "Unknown") : (hop.location || "Unknown"),
        hosting: isReliableHop ? (ipinfo.as_name || "Unknown") : (hop.hosting || "Unknown"),
        note: isReliableHop ? `Reliable hop (${reliableHopNode.reliability || "assessed"})${abuseScore != null ? ` · AbuseIPDB score ${abuseScore}` : ""}` : (hop.note || "Received header observation"),
      };
    }),
    campaign_correlation: api.campaign_correlation ? {
      matched_investigations: matches.length,
      confidence: api.campaign_correlation.confidence ?? null,
      cohesion: api.campaign_correlation.cohesion ?? null,
      cohesion_warning: api.campaign_correlation.cohesion_warning ?? null,
      campaign_id: api.campaign_correlation.campaign_id || null,
      nodes, edges,
    } : null,
    fingerprint: api.fingerprint ? {
      structural_hash: api.fingerprint.structural_hash || null,
      skeleton_type: api.fingerprint.skeleton_type || null,
      typosquat_matches: array(api.fingerprint.typosquat_matches),
      targeted_brands: array(api.fingerprint.targeted_brands),
    } : null,
    triggered_by: api.triggered_by ? {
      user_id: api.triggered_by.user_id || null,
      ip_address: api.triggered_by.ip_address || null,
      triggered_at: api.triggered_by.triggered_at || null,
    } : null,
  };
}

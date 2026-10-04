const array = (value) => Array.isArray(value) ? value : [];

const signalLabels = {
  same_ip: "Same Sending IP",
  same_domain: "Same Domain",
  same_nameserver: "Shared Nameservers",
  same_mail_server: "Shared Mail Server",
  same_cname: "Shared CNAME",
  same_asn: "Same Hosting Network (ASN)",
  same_relay_host: "Same Relay Server",
  same_jarm: "Shared TLS Fingerprint (JARM)",
  same_fingerprint: "Identical Email Template",
  similar_fingerprint: "Similar Email Style",
};

// Turns a correlation "signal" (a plain string, or an object like
// {type, detail/reason}) into readable text -- used both here and in
// CampaignGraph.jsx so both places describe a shared-infrastructure
// match the same way.
export function correlationSignalLabel(signal) {
  const type = typeof signal === "string" ? signal : signal?.type;
  const label = signalLabels[type] || type || "Shared campaign infrastructure";
  const detail = typeof signal === "object" ? signal?.detail || signal?.reason : null;
  return detail ? `${label}: ${detail}` : label;
}

// Postgres stores ingested_at/analyzed_at as TIMESTAMPTZ (UTC), and the
// frontend was displaying that raw string straight from the backend
// with no conversion -- so everyone saw the UTC time, not their own
// local time (e.g. ~5.5 hours behind for IST). new Date(...).toLocaleString()
// with no explicit timeZone option converts to whatever timezone the
// VIEWER'S OWN browser is in, so this is correct for every teammate
// wherever they are, not hardcoded to one timezone.
export function formatTimestamp(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value; // unparseable -- show raw rather than hide it
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
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
  // match.signals items are objects ({type, detail/reason, ...}), not
  // plain strings -- Array.join() on objects silently stringifies each
  // one to "[object Object]" instead of throwing, so this rendered as
  // garbage text rather than crashing. Route through correlationSignalLabel
  // (defined above) the same way CampaignGraph.jsx already does.
  const edges = [...(primary.domain ? [{ a: "email", b: "domain", type: "verified", confidence: 1, reason: "Domain observed in this investigation" }] : []), ...matches.map((match) => ({ a: "email", b: match.email_id, type: "corroborated", confidence: match.confidence ?? 0.8, reason: array(match.signals).map(correlationSignalLabel).join(", ") || "Shared campaign infrastructure" }))];
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
      // matched_investigations is the backend's real total (your own
      // matches + other accounts' matches combined) -- NOT matches.length,
      // which only covers your own (full-detail) matches now that
      // cross-user matches are anonymized into other_accounts_affected.
      matched_investigations: api.campaign_correlation.matched_investigations ?? matches.length,
      your_matches: matches.length,
      other_accounts_affected: api.campaign_correlation.other_accounts_affected ?? 0,
      confidence: api.campaign_correlation.confidence ?? null,
      cohesion: api.campaign_correlation.cohesion ?? null,
      cohesion_warning: api.campaign_correlation.cohesion_warning ?? null,
      campaign_id: api.campaign_correlation.campaign_id || null,
      nodes, edges,
      graph: api.campaign_correlation.graph || null,
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
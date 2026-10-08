const array = (value) => Array.isArray(value) ? value : [];
const object = (value) =>
  value && typeof value === "object" && !Array.isArray(value) ? value : {};
const text = (value) =>
  typeof value === "string" && value.trim() ? value.trim() : null;
const firstText = (...values) => values.map(text).find(Boolean) || null;

const authenticationStatus = (value) => {
  const values = Array.isArray(value) ? value : [value];
  const results = values
    .map((item) => {
      const result = typeof item === "object" && item !== null
        ? item.result
        : item;
      if (typeof result !== "string" || !result.trim()) return null;
      const normalized = result.trim();
      return /^(pass|fail|none|unknown)$/i.test(normalized)
        ? normalized.toUpperCase()
        : normalized;
    })
    .filter(Boolean);
  return results.length ? results.join(", ") : null;
};

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
  const reliableHopNode = object(reliableHop?.earliest_reliable_node);
  const ipIntelligence = object(reliableHop?.ip_intelligence);
  const ipinfo = object(ipIntelligence.ipinfo);
  const ipapiIs = object(ipIntelligence.ipapi_is);
  const ipapiCompany = object(ipapiIs.company);
  const ipapiAsn = object(ipapiIs.asn);
  const iplocate = object(ipIntelligence.iplocate);
  const reverseDns = object(ipIntelligence.reverse_dns);
  const shodan = ipIntelligence.shodan || api.shodan || null;
  const ip = firstText(
    reliableHopNode.ip,
    ipIntelligence.ip,
    primary.dns?.records?.A?.[0],
    primary.ip,
  );
  const asn = firstText(ipinfo.asn, ipapiAsn.org, ipapiAsn.descr);
  const hosting =
    firstText(ipinfo.as_name, ipapiCompany.name) ||
    (ipapiIs.is_hosting === true || ipapiIs.is_datacenter === true
      ? "Hosting / datacenter"
      : iplocate.is_hosting === true
        ? "Hosting provider"
        : null);
  const country = firstText(ipinfo.country, ipapiIs.country);
  const reverseHostname = firstText(reverseDns.hostname);
  const hasInfrastructure = Boolean(ip || asn || hosting || country);

  const matches = array(api.campaign_correlation?.matches);
  const nodes = [{ id: "email", x: 450, y: 220, icon: "📧", label: "This email", core: true }, ...(primary.domain ? [{ id: "domain", x: 265, y: 135, icon: "🌐", label: primary.domain }] : []), ...matches.map((match, index) => ({ id: match.email_id, x: 700 + (index % 2) * 95, y: 130 + index * 105, icon: "📧", label: match.email_id }))];
  // match.signals items are objects ({type, detail/reason, ...}), not
  // plain strings -- Array.join() on objects silently stringifies each
  // one to "[object Object]" instead of throwing, so this rendered as
  // garbage text rather than crashing. Route through correlationSignalLabel
  // (defined above) the same way CampaignGraph.jsx already does.
  const edges = [...(primary.domain ? [{ a: "email", b: "domain", type: "verified", confidence: 1, reason: "Domain observed in this investigation" }] : []), ...matches.map((match) => ({ a: "email", b: match.email_id, type: "corroborated", confidence: match.confidence ?? 0.8, reason: array(match.signals).map(correlationSignalLabel).join(", ") || "Shared campaign infrastructure" }))];
  const headerChain = array(api.header_auth?.received_chain).filter(
    (hop) => hop && typeof hop === "object" && !Array.isArray(hop),
  );
  const received = headerChain.length
    ? headerChain
    : array(api.infrastructure_risk?.received_chain).filter(
        (hop) => hop && typeof hop === "object" && !Array.isArray(hop),
      );

  return {
    investigation_id: api.email_id || "pending",
    analyzed_at: api.analyzed_at || api.observed_at || null,
    risk_score: Math.round(
      api.overall_risk_score ?? api.infrastructure_risk?.risk_score ?? 0,
    ),
    threat_contributions: api.threat_contributions
      ? {
          items: array(api.threat_contributions.items),
          total_percentage: api.threat_contributions.total_percentage ?? null,
        }
      : null,
    risk_level: level(api.verdict || api.infrastructure_risk?.risk_level),
    threat_label:
      api.classifier?.verdict === "threat"
        ? "Credential phishing"
        : "Email investigation",
    authentication: {
      spf: authenticationStatus(api.header_auth?.spf),
      dkim: authenticationStatus(api.header_auth?.dkim),
      dmarc: authenticationStatus(api.header_auth?.dmarc),
    },
    url: array(api.urls)[0] || array(api.url_reputation)[0]?.url || null,
    reasons,
    infrastructure_evidence: array(api.infrastructure_risk?.evidence),
    domain_info: (primary.domain || hasInfrastructure)
      ? {
          domain: primary.domain || null,
          ip,
          asn,
          hosting,
          country,
          registrar: primary.whois?.registrar || null,
          created:
            primary.whois?.domain_age?.creation_date ||
            primary.whois?.creation_date ||
            null,
          age_days: primary.age_days ?? null,
          tls_issuer: primary.tls_issuer || null,
          tls_status: primary.tls_status || null,
          tls_days_until_expiry: primary.tls?.days_until_expiry ?? null,
          tls_valid_to: primary.tls?.valid_to || null,
          tls_san_domains: array(primary.tls?.san_domains),
          tls_fingerprint_sha256: primary.tls?.fingerprint_sha256 || null,
          cert_shared_with: array(primary.tls?.cert_shared_with),
          nameservers: array(primary.dns?.records?.NS),
          mail_servers: array(primary.dns?.records?.MX),
          jarm: primary.jarm || primary.tls?.jarm || null,
          found_on_lists: array(primary.found_on_lists),
          reputation: primary.reputation || null,
        }
      : null,
    url_reputation: array(api.url_reputation)
      .filter((item) => item && typeof item === "object")
      .map((item) => ({
        url: item.url || null,
        reputation: item.reputation || null,
        found_on_lists: array(item.found_on_lists),
        sources_checked: array(item.sources_checked),
      })),
    shodan: shodan
      ? {
          status: shodan.status || null,
          ports: array(shodan.ports),
          hostnames: array(shodan.hostnames),
          cpes: array(shodan.cpes),
          tags: array(shodan.tags),
          vulns: array(shodan.vulns),
          notable_ports: array(shodan.notable_ports),
          risk_flag: shodan.risk_flag || null,
        }
      : null,
    relay_path: received.map((hop, index) => {
      const reliableIp = text(reliableHopNode.ip);
      const reliableHostname = text(reliableHopNode.hostname);
      const isReliableHop = Boolean(
        (reliableIp && hop.from_ip === reliableIp) ||
        (reliableHostname &&
          text(hop.from_host)?.toLowerCase() === reliableHostname.toLowerCase()),
      );
      const abuseScore = ipIntelligence.reputation?.abuse_score;
      return {
        label: `Hop ${hop.hop ?? index + 1}`,
        sub:
          hop.from_host ||
          hop.hostname ||
          (isReliableHop && reverseHostname) ||
          hop.from_ip ||
          "Unknown host",
        verified: Boolean(hop.verified),
        trusted: Boolean(hop.trusted),
        reliable: isReliableHop,
        ip: hop.from_ip || (isReliableHop && reliableIp) || "Not available",
        location: isReliableHop
          ? [firstText(ipapiIs.city), country].filter(Boolean).join(", ") ||
            "Not available"
          : firstText(hop.location) || "Not available",
        reverseDns: isReliableHop ? reverseHostname : null,
        hosting: isReliableHop
          ? hosting || "Not available"
          : firstText(hop.hosting) || "Not available",
        note: isReliableHop
          ? `Reliable hop (${text(reliableHopNode.reliability) || "assessed"})${abuseScore != null ? ` · AbuseIPDB score ${abuseScore}` : ""}`
          : text(hop.note) || "Received header observation",
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
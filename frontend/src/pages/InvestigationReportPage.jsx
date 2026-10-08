import { useState } from "react";
import RiskGauge from "../components/RiskGauge";
import EvidenceCard from "../components/EvidenceCard";
import RelayPath from "../components/RelayPath";
import CampaignGraph from "../components/CampaignGraph";
import {
  correlationSignalLabel,
  formatTimestamp,
  mapApiResponseToReportShape,
} from "../utils/mapApiResponse";

const value = (item, fallback = "Not available") => item ?? fallback;
const authenticationClass = (result) => {
  const results =
    typeof result === "string"
      ? result.split(",").map((item) => item.trim().toLowerCase())
      : [];
  if (results.includes("fail")) return "fail";
  return results.length && results.every((item) => item === "pass")
    ? "pass"
    : "unknown";
};
// classifier.reasons items can be a plain string OR an object shaped
// {title, description, severity} (the SVM classifier's supporting_evidence
// format) -- rendering one of those objects directly as a React child
// crashes with "Objects are not valid as a React child" (minified error
// #31). This always reduces a reason, of either shape, to plain text.
const reasonText = (reason) => {
  if (!reason) return null;
  if (typeof reason === "string") return reason;
  return reason.title || reason.description || reason.reason || null;
};
const urlReputationStatus = (item) => {
  const reputation =
    typeof item.reputation === "string"
      ? item.reputation.toLowerCase()
      : String(
          item.reputation?.status || item.reputation?.label || "",
        ).toLowerCase();
  if (
    item.found_on_lists.length > 0 ||
    ["listed", "blacklisted", "blocklisted"].includes(reputation)
  ) {
    return "listed";
  }
  if (/suspicious|malicious|threat|phish|unsafe|dangerous/.test(reputation)) {
    return "suspicious";
  }
  if (/clean|safe|trusted|good|low_risk/.test(reputation)) {
    return "clean";
  }
  return "unknown";
};
const Status = ({ label, result }) => (
  <div className="auth-row">
    <span>{label}</span>
    <b className={authenticationClass(result)}>{value(result)}</b>
  </div>
);

export default function InvestigationReportPage({
  apiResponse,
  onNewInvestigation,
}) {
  const [tab, setTab] = useState("Overview");
  if (!apiResponse)
    return (
      <main className="report report-empty">
        <p>No investigation data available. Try analyzing an email first.</p>
      </main>
    );
  const data = mapApiResponseToReportShape(apiResponse);
  const domain = data.domain_info;
  const auth = apiResponse.header_auth || {};
  const authentication = data.authentication;
  const triggeredBy = data.triggered_by;
  const correlationMatches = Array.isArray(
    apiResponse.campaign_correlation?.matches,
  )
    ? apiResponse.campaign_correlation.matches
    : [];
  const tabs = [
    "Overview",
    "Email",
    "Headers",
    "URLs & Domains",
    "Infrastructure",
    "Fingerprint",
    "Correlation",
  ];
  const attackNodes = [
    ["EMAIL", apiResponse.from_header || "Sender unavailable", "Observed"],
    ["URL", data.url || "No URL observed", data.url ? "Observed" : null],
    [
      "DOMAIN",
      domain?.domain || "No domain observed",
      domain?.domain ? "Observed" : null,
    ],
    ["IP", domain?.ip || "No resolved IP", domain?.ip ? "Observed" : null],
    [
      "ASN / HOST",
      domain?.asn || domain?.hosting || "No host data",
      domain?.asn || domain?.hosting ? "Observed" : null,
    ],
    [
      "RELATED CASES",
      data.campaign_correlation
        ? `${data.campaign_correlation.matched_investigations} related`
        : "No matches found",
      data.campaign_correlation ? "Correlated" : null,
    ],
  ];
  const rawPhishingScore = apiResponse.classifier?.phishing_score;
  const contentFinding =
    rawPhishingScore != null
      ? `${(rawPhishingScore <= 1 ? rawPhishingScore * 100 : rawPhishingScore).toFixed(1)}% phishing score`
      : "No content score returned";
  const infraFinding = data.infrastructure_evidence.length
    ? `${data.infrastructure_evidence.length} infrastructure indicators`
    : domain?.domain
      ? `Domain: ${domain.domain}`
      : domain?.ip
        ? `IP: ${domain.ip}`
      : "No infrastructure indicators returned";
  const jarm = domain?.jarm;
  const jarmStatusClass =
    jarm?.status === "error"
      ? "error"
      : jarm?.status === "success"
        ? "success"
        : "neutral";
  const jarmStatusText =
    jarm?.status === "skipped"
      ? "JARM check skipped (low risk)"
      : jarm?.status === "error"
        ? `JARM check failed${jarm.error ? `: ${jarm.error}` : ""}`
        : jarm?.status === "success"
          ? jarm.jarm_hash || "JARM check completed"
          : "Not available";
  const shodan = data.shodan;
  const domainRecords = Array.isArray(apiResponse.domains)
    ? apiResponse.domains
    : Object.values(apiResponse.domains || {});
  const threatContributionItems = data.threat_contributions?.items || [];
  const threatContributionTotal = data.threat_contributions?.total_percentage;
  const urlIntelligence =
    apiResponse.url_intelligence ||
    apiResponse.classifier?.url_intelligence ||
    {};
  const qrUrls = Array.isArray(urlIntelligence.qr_urls)
    ? urlIntelligence.qr_urls
    : Array.isArray(apiResponse.qr_urls)
      ? apiResponse.qr_urls
      : null;
  const ocrUrls = Array.isArray(urlIntelligence.ocr_urls)
    ? urlIntelligence.ocr_urls
    : Array.isArray(apiResponse.ocr_urls)
      ? apiResponse.ocr_urls
      : null;
  const imageUrlCount =
    urlIntelligence.image_url_count ?? apiResponse.image_url_count ?? null;
  const emailStructure =
    apiResponse.email_structure ||
    apiResponse.classifier?.email_structure ||
    {};
  const attachmentCount =
    emailStructure.attachment_count ??
    apiResponse.attachment_count ??
    (Array.isArray(apiResponse.attachments)
      ? apiResponse.attachments.length
      : null);
  const hasShodanFindings =
    shodan?.status === "success" &&
    (shodan.ports.length > 0 ||
      shodan.vulns.length > 0 ||
      shodan.notable_ports.length > 0);

  return (
    <main className="report investigation-report">
      <div className="breadcrumb">
        <button onClick={onNewInvestigation}>← Investigations</button>
        <span className="mono">
          CASE #{String(data.investigation_id).slice(-8).toUpperCase()}
        </span>
        <span>{formatTimestamp(data.analyzed_at) || "Date unavailable"}</span>
        {triggeredBy && (
          <span className="mono">
            Triggered by {value(triggeredBy.user_id, "unknown user")} ·{" "}
            {value(triggeredBy.ip_address, "unknown IP")} ·{" "}
            {value(triggeredBy.triggered_at, "unknown time")}
          </span>
        )}
      </div>
      <section className="case-header">
        <div className="case-gauge">
          <RiskGauge score={data.risk_score} level={data.risk_level} />
        </div>
        <div className="case-copy">
          <div className={`risk-label ${data.risk_level.toLowerCase()}`}>
            {data.risk_level.toUpperCase()} RISK
          </div>
          <h1>{data.threat_label}</h1>
          <div className="mail-metadata">
            <div>
              <small>SUBJECT</small>
              <strong>{value(apiResponse.subject)}</strong>
            </div>
            <div>
              <small>FROM</small>
              <strong className="mono">{value(apiResponse.from_header)}</strong>
            </div>
          </div>
        </div>
        <div className="case-actions">
          <button className="export-button" onClick={() => window.print()}>
            Export report
          </button>
          <button className="new-report-button" onClick={() => setTab("Email")}>
            View raw email
          </button>
        </div>
      </section>
      <nav className="investigation-tabs">
        {tabs.map((name) => (
          <button
            className={tab === name ? "active" : ""}
            onClick={() => setTab(name)}
            key={name}
          >
            {name}
          </button>
        ))}
      </nav>
      {tab === "Overview" && (
        <>
          <section className="summary-grid">
            <article>
              <small>CONTENT</small>
              <strong>{contentFinding}</strong>
              <p>
                {reasonText(apiResponse.classifier?.reasons?.[0]) ||
                  "No content finding available."}
              </p>
            </article>
            <article>
              <small>AUTHENTICATION</small>
              <Status label="SPF" result={authentication.spf} />
              <Status label="DKIM" result={authentication.dkim} />
              <Status label="DMARC" result={authentication.dmarc} />
            </article>
            <article>
              <small>INFRASTRUCTURE</small>
              <strong className="mono">
                {domain?.domain || "No domain observed"}
              </strong>
              {data.infrastructure_evidence.length ? (
                <ul className="infra-evidence-list">
                  {data.infrastructure_evidence.map((item, index) => (
                    <li key={`${item}-${index}`}>{item}</li>
                  ))}
                </ul>
              ) : (
                <p>{infraFinding}</p>
              )}
            </article>
            <article>
              <small>CORRELATION</small>
              <strong>
                {data.campaign_correlation
                  ? `${data.campaign_correlation.matched_investigations} related investigations`
                  : "No related cases"}
              </strong>
              <p>
                {data.campaign_correlation
                  ? `Confidence ${value(data.campaign_correlation.confidence, "n/a")} · Cohesion ${value(data.campaign_correlation.cohesion, "n/a")}`
                  : "No campaign correlation returned."}
              </p>
            </article>
          </section>
          <section className="section attack-section">
            <div className="section-head">
              <div>
                <div className="section-kicker">INVESTIGATION CHAIN</div>
                <div className="section-title">Attack path</div>
              </div>
              <div className="section-sub">
                Connections reflect observed analysis data.
              </div>
            </div>
            <div className="attack-path">
              {attackNodes.map(([title, detail, status], index) => (
                <div className="attack-step" key={title}>
                  <article>
                    <small>{title}</small>
                    <strong className="mono">{detail}</strong>
                    {status && <span>{status}</span>}
                  </article>
                  {index < attackNodes.length - 1 && <i>↓</i>}
                </div>
              ))}
            </div>
          </section>
          <section className="section threat-analysis-section">
            <div className="section-head">
              <div>
                <div className="section-kicker">THREAT SCORE CONTRIBUTION</div>
                <div className="section-title">
                  🛡️ Threat Score Contribution
                </div>
                <p className="threat-contribution-explanation">
                  The contribution breakdown shows how the primary risk signals
                  contribute to the overall threat score.
                </p>
              </div>
              <div className="final-risk">
                <small>OVERALL THREAT SCORE</small>
                <b>
                  {data.risk_score}
                  <em>/ 100</em>
                </b>
              </div>
            </div>
            {threatContributionItems.length > 0 ? (
              <ul className="threat-contribution-list">
                {threatContributionItems.map((item, index) => (
                  <li
                    className="threat-contribution-item"
                    key={item.key || `${item.label || "factor"}-${index}`}
                  >
                    <div className="threat-contribution-row">
                      <span>
                        {item.key === "content_ml"
                          ? "🧠 "
                          : item.key === "domain_infrastructure"
                            ? "🌐 "
                            : ""}
                        {item.label || "Threat factor"}
                      </span>
                      <strong>
                        {item.percentage == null
                          ? "Not available"
                          : item.percentage}
                      </strong>
                    </div>
                    <div
                      className="threat-contribution-track"
                      role="img"
                      aria-label={`${item.label || "Threat factor"} contribution`}
                    >
                      <div
                        className="threat-contribution-bar"
                        style={{
                          width:
                            typeof item.percentage === "number" &&
                            Number.isFinite(item.percentage)
                              ? `${item.percentage}%`
                              : "0%",
                        }}
                      />
                    </div>
                  </li>
                ))}
                <li className="threat-contribution-total">
                  <span>Total</span>
                  <strong>
                    {threatContributionTotal == null
                      ? "Not available"
                      : threatContributionTotal}
                  </strong>
                </li>
              </ul>
            ) : (
              <p className="empty-state">
                Threat contribution data unavailable.
              </p>
            )}
          </section>
          <section className="section forensic-evidence-section">
            <div className="section-head">
              <div>
                <div className="section-kicker">FORENSIC EVIDENCE</div>
                <div className="section-title">
                  Supporting investigation evidence
                </div>
              </div>
            </div>
            <div className="summary-grid forensic-evidence-grid">
              <article>
                <small>🔗 URL INTELLIGENCE</small>
                {data.url_reputation.length > 0 ? (
                  <ul>
                    {data.url_reputation.map((item, index) => (
                      <li key={`${item.url || "url"}-${index}`}>
                        {item.url || "URL unavailable"}
                        {item.found_on_lists.length > 0 &&
                          ` — listed on ${item.found_on_lists.join(", ")}`}
                      </li>
                    ))}
                  </ul>
                ) : Array.isArray(apiResponse.urls) &&
                  apiResponse.urls.length > 0 ? (
                  <ul>
                    {apiResponse.urls.map((url, index) => (
                      <li key={`${url}-${index}`}>{url}</li>
                    ))}
                  </ul>
                ) : (
                  <p>No URL intelligence returned.</p>
                )}
              </article>
              <article>
                <small>🔐 EMAIL AUTHENTICATION</small>
                <Status label="SPF" result={authentication.spf} />
                <Status label="DKIM" result={authentication.dkim} />
                <Status label="DMARC" result={authentication.dmarc} />
              </article>
              <article>
                <small>🌐 DOMAIN INTELLIGENCE</small>
                {domain?.domain ? (
                  <>
                    <strong>{domain.domain}</strong>
                    <p>
                      {[
                        domain.reputation?.reputation,
                        domain.age_days != null
                          ? `${domain.age_days} days old`
                          : null,
                        domain.tls_status ? `TLS ${domain.tls_status}` : null,
                      ]
                        .filter(Boolean)
                        .join(" · ") ||
                        "Additional domain details unavailable."}
                    </p>
                  </>
                ) : (
                  <p>No domain intelligence returned.</p>
                )}
              </article>
              <article>
                <small>🖥️ IP / INFRASTRUCTURE INTELLIGENCE</small>
                {domain?.ip ||
                domain?.asn ||
                domain?.hosting ||
                domain?.country ||
                data.infrastructure_evidence.length ? (
                  <>
                    <div className="infra-summary">
                      <div>
                        <small>IP ADDRESS</small>
                        <strong className="mono">{value(domain?.ip)}</strong>
                      </div>
                      <div>
                        <small>ASN</small>
                        <strong className="mono">{value(domain?.asn)}</strong>
                      </div>
                      <div>
                        <small>HOSTING / ORGANIZATION</small>
                        <strong>{value(domain?.hosting)}</strong>
                      </div>
                      <div>
                        <small>COUNTRY</small>
                        <strong>{value(domain?.country)}</strong>
                      </div>
                    </div>
                    {data.infrastructure_evidence.length > 0 ? (
                      <ul>
                        {data.infrastructure_evidence.map((item, index) => (
                          <li key={`${item}-${index}`}>{item}</li>
                        ))}
                      </ul>
                    ) : (
                      <p>Infrastructure evidence details unavailable.</p>
                    )}
                  </>
                ) : (
                  <p>No IP / infrastructure intelligence returned.</p>
                )}
              </article>
              <article>
                <small>📷 QR / OCR</small>
                {qrUrls || ocrUrls || imageUrlCount != null ? (
                  <>
                    {qrUrls && <p>QR URLs: {qrUrls.length}</p>}
                    {ocrUrls && <p>OCR URLs: {ocrUrls.length}</p>}
                    {imageUrlCount != null && (
                      <p>QR / OCR image URLs: {imageUrlCount}</p>
                    )}
                    {[...(qrUrls || []), ...(ocrUrls || [])].length > 0 && (
                      <ul>
                        {[...(qrUrls || []), ...(ocrUrls || [])].map(
                          (url, index) => (
                            <li key={`${url}-${index}`}>{url}</li>
                          ),
                        )}
                      </ul>
                    )}
                  </>
                ) : (
                  <p>QR / OCR results not returned.</p>
                )}
              </article>
              <article>
                <small>📎 ATTACHMENTS</small>
                {attachmentCount != null ? (
                  <strong>
                    {attachmentCount === 0
                      ? "No attachments detected"
                      : `${attachmentCount} attachment${attachmentCount === 1 ? "" : "s"} detected`}
                  </strong>
                ) : (
                  <p>Attachment details not returned.</p>
                )}
              </article>
            </div>
          </section>
          <section className="section">
            <div className="section-head">
              <div>
                <div className="section-kicker">EVIDENCE-BASED VERDICT</div>
                <div className="section-title">Why this score?</div>
              </div>
              <div className="final-risk">
                <small>FINAL RISK</small>
                <b>
                  {data.risk_score}
                  <em>/100</em>
                </b>
              </div>
            </div>
            <div className="score-layout">
              <div className="score-categories">
                <div>
                  <small>CONTENT ANALYSIS</small>
                  <strong>{contentFinding}</strong>
                </div>
                <div>
                  <small>URL INTELLIGENCE</small>
                  <strong>{data.url || "No URL intelligence returned"}</strong>
                </div>
                <div>
                  <small>AUTHENTICATION</small>
                  <strong>
                    SPF {value(authentication.spf)} · DKIM{" "}
                    {value(authentication.dkim)} · DMARC{" "}
                    {value(authentication.dmarc)}
                  </strong>
                </div>
                <div>
                  <small>INFRASTRUCTURE</small>
                  <strong>{infraFinding}</strong>
                </div>
              </div>
              <div className="evidence-grid">
                {data.reasons.length ? (
                  data.reasons.map((reason) => (
                    <EvidenceCard reason={reason} key={reason.id} />
                  ))
                ) : (
                  <p className="empty-state">
                    No discrete evidence items were returned for this analysis.
                  </p>
                )}
              </div>
            </div>
          </section>
          <section className="section">
            <div className="section-head">
              <div>
                <div className="section-kicker">MAIL ROUTING FORENSICS</div>
                <div className="section-title">Forensic relay trace</div>
              </div>
              <div className="section-sub">
                Received headers only — click a hop for details.
              </div>
            </div>
            {data.relay_path.length ? (
              <>
                <RelayPath hops={data.relay_path} />
                <div className="hop-table">
                  <div className="hop-table-header">
                    <span>HOP</span>
                    <span>HOST</span>
                    <span>IP</span>
                    <span>STATUS</span>
                  </div>
                  {data.relay_path.map((hop) => (
                    <div key={hop.label}>
                      <span>{hop.label}</span>
                      <span className="mono">{hop.sub}</span>
                      <span className="mono">{hop.ip}</span>
                      <span>
                        {hop.trusted
                          ? "Trusted boundary"
                          : hop.verified
                            ? "Verified"
                            : "Observed"}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="empty-state">
                No parsed Received-hop chain was returned.
              </div>
            )}
          </section>
          <section className="section">
            <div className="section-head">
              <div>
                <div className="section-kicker">DOMAIN INTELLIGENCE</div>
                <div className="section-title">
                  Registration, TLS & reputation
                </div>
              </div>
            </div>
            {domain?.domain ? (
              <>
                <div className="score-categories">
                  <div>
                    <small>REGISTRAR</small>
                    <strong>{value(domain.registrar)}</strong>
                  </div>
                  <div>
                    <small>DOMAIN AGE</small>
                    <strong>
                      {domain.age_days != null
                        ? `${domain.age_days} days`
                        : "Not available"}
                    </strong>
                  </div>
                  <div>
                    <small>TLS ISSUER / STATUS</small>
                    <strong>
                      {value(domain.tls_issuer)} · {value(domain.tls_status)}
                    </strong>
                  </div>
                  <div>
                    <small>CERTIFICATE EXPIRES</small>
                    <strong>
                      {domain.tls_days_until_expiry != null
                        ? `${domain.tls_days_until_expiry} days`
                        : value(domain.tls_valid_to)}
                    </strong>
                  </div>
                  {domain.cert_shared_with.length > 0 && (
                    <div className="important-signal cert-shared">
                      <small>SHARED CERTIFICATE WITH</small>
                      <strong>{domain.cert_shared_with.join(", ")}</strong>
                    </div>
                  )}
                  <div>
                    <small>JARM</small>
                    <strong className={`jarm-status ${jarmStatusClass}`}>
                      {jarmStatusText}
                    </strong>
                  </div>
                  <div>
                    <small>ASN / HOSTING</small>
                    <strong>
                      {domain.asn || domain.hosting
                        ? `${value(domain.asn, "")} ${value(domain.hosting, "")}`.trim()
                        : "Not available"}
                    </strong>
                  </div>
                  <div>
                    <small>COUNTRY</small>
                    <strong>{value(domain.country)}</strong>
                  </div>
                  <div>
                    <small>BLOCKLIST HITS</small>
                    <strong>
                      {domain.found_on_lists?.length
                        ? domain.found_on_lists.join(", ")
                        : "None"}
                    </strong>
                  </div>
                </div>
                <div className="infrastructure-identifiers">
                  <div className="section-kicker">
                    INFRASTRUCTURE IDENTIFIERS
                  </div>
                  <div>
                    <small>Nameservers</small>
                    <span className="mono">
                      {domain.nameservers.length
                        ? domain.nameservers.join(", ")
                        : "Not available"}
                    </span>
                  </div>
                  <div>
                    <small>Mail Server (MX)</small>
                    <span className="mono">
                      {domain.mail_servers.length
                        ? domain.mail_servers.join(", ")
                        : "Not available"}
                    </span>
                  </div>
                  <div>
                    <small>ASN</small>
                    <span className="mono">{value(domain.asn)}</span>
                  </div>
                  <div>
                    <small>TLS Fingerprint</small>
                    <span className="mono">
                      {domain.tls_fingerprint_sha256
                        ? `${domain.tls_fingerprint_sha256.slice(0, 16)}${domain.tls_fingerprint_sha256.length > 16 ? "..." : ""}`
                        : "Not available"}
                    </span>
                  </div>
                </div>
              </>
            ) : (
              <div className="empty-state">
                No domain intelligence was returned for this investigation.
              </div>
            )}
          </section>
          {hasShodanFindings && (
            <section className="section exposed-infrastructure">
              <div className="section-head">
                <div>
                  <div className="section-kicker">HOST EXPOSURE</div>
                  <div className="section-title">Exposed Infrastructure</div>
                </div>
              </div>
              <div className="shodan-findings">
                {shodan.ports.length > 0 && (
                  <div className="shodan-finding">
                    <small>OPEN PORTS</small>
                    <div className="shodan-port-list">
                      {shodan.ports.map((port, index) => (
                        <span className="shodan-port" key={`${port}-${index}`}>
                          {typeof port === "object"
                            ? (port.port ?? JSON.stringify(port))
                            : port}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {shodan.notable_ports.length > 0 && (
                  <div className="shodan-finding">
                    <small>NOTABLE PORTS</small>
                    <ul className="shodan-notable-ports">
                      {shodan.notable_ports.map((item, index) => (
                        <li key={`${item.port}-${index}`}>
                          <strong>{item.port ?? "Port"}</strong>
                          <span>{item.note || "Notable exposed service"}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {shodan.vulns.length > 0 && (
                  <div className="shodan-finding">
                    <small>KNOWN VULNERABILITIES</small>
                    <div className="shodan-vulnerability-list">
                      {shodan.vulns.map((vulnerability, index) => (
                        <span
                          className="shodan-vulnerability"
                          key={`${vulnerability}-${index}`}
                        >
                          {typeof vulnerability === "string"
                            ? vulnerability
                            : vulnerability.cve ||
                              vulnerability.id ||
                              JSON.stringify(vulnerability)}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {shodan.tags.length > 0 && (
                  <div className="shodan-finding">
                    <small>HOST TAGS</small>
                    <div className="shodan-port-list">
                      {shodan.tags.map((tag, index) => (
                        <span className="shodan-tag" key={`${tag}-${index}`}>
                          {typeof tag === "string" ? tag : JSON.stringify(tag)}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}
          <section className="section campaign-section">
            <div className="section-head">
              <div>
                <div className="section-kicker">CAMPAIGN INTELLIGENCE</div>
                <div className="section-title">Infrastructure correlation</div>
              </div>
            </div>
            {data.campaign_correlation ? (
              <>
                <div className="corr-banner">
                  Matched{" "}
                  <strong>
                    {data.campaign_correlation.matched_investigations} related
                    investigations
                  </strong>{" "}
                  from real stored correlation data. Confidence{" "}
                  {value(data.campaign_correlation.confidence, "n/a")} ·
                  Cohesion {value(data.campaign_correlation.cohesion, "n/a")}
                  {data.campaign_correlation.cohesion_warning
                    ? ` · ⚠ ${data.campaign_correlation.cohesion_warning}`
                    : ""}
                </div>
                {data.campaign_correlation.other_accounts_affected > 0 && (
                  <div className="corr-banner corr-banner-cross-account">
                    ⚠ This same campaign infrastructure was also seen on{" "}
                    <strong>
                      {data.campaign_correlation.other_accounts_affected} other
                      MailSentinel account
                      {data.campaign_correlation.other_accounts_affected === 1
                        ? ""
                        : "s"}
                    </strong>{" "}
                    — details are not shown to protect those accounts' privacy,
                    but the shared infrastructure strengthens this verdict.
                  </div>
                )}
                <CampaignGraph
                  nodes={data.campaign_correlation.nodes}
                  edges={data.campaign_correlation.edges}
                  graph={data.campaign_correlation.graph}
                />
              </>
            ) : (
              <div className="empty-state">
                No campaign matches were returned for this investigation.
              </div>
            )}
          </section>
        </>
      )}
      {tab === "Fingerprint" && (
        <section className="section detail-tab">
          <div className="section-kicker">FINGERPRINT</div>
          <div className="section-title">
            Content fingerprint & brand targeting
          </div>
          {data.fingerprint ? (
            <div className="score-categories">
              <div>
                <small>STRUCTURAL HASH</small>
                <strong className="mono">
                  {value(data.fingerprint.structural_hash)}
                </strong>
              </div>
              <div>
                <small>SKELETON TYPE</small>
                <strong>{value(data.fingerprint.skeleton_type)}</strong>
              </div>
              <div>
                <small>TARGETED BRANDS</small>
                <strong>
                  {data.fingerprint.targeted_brands.length
                    ? data.fingerprint.targeted_brands.join(", ")
                    : "None detected"}
                </strong>
              </div>
              <div>
                <small>TYPOSQUAT MATCHES</small>
                {data.fingerprint.typosquat_matches.length ? (
                  <ul>
                    {data.fingerprint.typosquat_matches.map((m, i) => (
                      <li key={i} className="mono">
                        {typeof m === "string"
                          ? m
                          : `${m.domain || "?"} → mimics "${m.matched_brand || "?"}" (matched "${m.matched_chunk || "?"}", edit distance ${m.edit_distance ?? "?"})`}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <strong>None detected</strong>
                )}
              </div>
            </div>
          ) : (
            <div className="empty-state">
              No fingerprint data was returned for this investigation.
            </div>
          )}
        </section>
      )}
      {tab === "Email" && (
        <section className="section detail-tab">
          <div className="section-kicker">EMAIL</div>
          <div className="section-title">Raw email</div>
          {apiResponse.raw_email ? (
            <pre>
              {typeof apiResponse.raw_email === "string"
                ? apiResponse.raw_email
                : apiResponse.raw_email.raw_content ||
                  JSON.stringify(apiResponse.raw_email, null, 2)}
            </pre>
          ) : (
            <div className="empty-state">
              Raw email content was not returned for this investigation (fetch
              with ?full=true, or it may not be archived).
            </div>
          )}
        </section>
      )}
      {tab === "URLs & Domains" && (
        <section className="section detail-tab url-domain-tab">
          <div className="section-kicker">URLS & DOMAINS</div>
          <div className="section-title">Per-link reputation</div>
          {data.url_reputation.length ? (
            <ul className="url-reputation-list">
              {data.url_reputation.map((item, index) => {
                const status = urlReputationStatus(item);
                return (
                  <li key={`${item.url || "url"}-${index}`}>
                    <span className="mono">
                      {item.url || "URL unavailable"}
                    </span>
                    <span className={`status-pill ${status}`}>
                      {status === "unknown" ? "unrated" : status}
                    </span>
                    {item.found_on_lists.length > 0 && (
                      <small>Found on: {item.found_on_lists.join(", ")}</small>
                    )}
                    {item.sources_checked.length > 0 && (
                      <small>
                        Sources checked: {item.sources_checked.join(", ")}
                      </small>
                    )}
                  </li>
                );
              })}
            </ul>
          ) : (
            <div className="empty-state">
              No URL reputation data was returned.
            </div>
          )}
          <div className="section-title">Domains observed</div>
          {domainRecords.length ? (
            <ul className="observed-domains-list">
              {domainRecords.map((item, index) => {
                const name = typeof item === "string" ? item : item?.domain;
                return name ? (
                  <li className="mono" key={`${name}-${index}`}>
                    {name}
                  </li>
                ) : null;
              })}
            </ul>
          ) : (
            <div className="empty-state">No domain records were returned.</div>
          )}
        </section>
      )}
      {tab === "Correlation" && (
        <section className="section detail-tab">
          <div className="section-kicker">CORRELATION</div>
          <div className="section-title">
            Infrastructure correlation signals
          </div>
          {correlationMatches.length ? (
            <ul className="correlation-match-list">
              {correlationMatches.map((match, index) => (
                <li key={`${match.email_id || "match"}-${index}`}>
                  <strong className="mono">
                    {match.email_id || "Related investigation"}
                  </strong>
                  {Array.isArray(match.signals) && match.signals.length > 0 ? (
                    <ul className="correlation-signal-list">
                      {match.signals.map((signal, signalIndex) => (
                        <li key={`${signal?.type || signal}-${signalIndex}`}>
                          {correlationSignalLabel(signal)}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p>No individual signals were returned for this match.</p>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty-state">
              No individual campaign matches were returned for this
              investigation.
            </div>
          )}
        </section>
      )}
      {tab !== "Overview" &&
        tab !== "Fingerprint" &&
        tab !== "Email" &&
        tab !== "URLs & Domains" &&
        tab !== "Correlation" && (
          <section className="section detail-tab">
            <div className="section-kicker">{tab.toUpperCase()}</div>
            <div className="section-title">Detailed {tab.toLowerCase()}</div>
            <pre>
              {JSON.stringify(
                tab === "Headers"
                  ? auth
                  : tab === "Infrastructure"
                    ? apiResponse.infrastructure_risk
                    : {
                        subject: apiResponse.subject,
                        from: apiResponse.from_header,
                      },
                null,
                2,
              )}
            </pre>
          </section>
        )}
    </main>
  );
}

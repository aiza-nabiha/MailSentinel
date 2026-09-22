import RiskGauge from "../components/RiskGauge";
import EvidenceCard from "../components/EvidenceCard";
import RelayPath from "../components/RelayPath";
import CampaignGraph from "../components/CampaignGraph";
import mockData from "../data/mockInvestigation.json";

export default function InvestigationReportPage({ onNewInvestigation, campaignCorrelation }) {
  // Replace this fixture with the resolved API response when the endpoint is available.
  const data = mockData;
  const campaign = campaignCorrelation || data.campaign_correlation;
  const matchedInvestigations = campaignCorrelation
    ? Math.max(0, (campaignCorrelation.investigation?.historical_email_count || 0))
    : campaign.matched_investigations;

  const riskColor = data.risk_level === "High" ? "var(--high)" : data.risk_level === "Medium" ? "var(--medium)" : "var(--safe)";

  return (
    <main className="report">
      <div className="report-context"><span className="context-status">● LIVE ANALYSIS</span><span>MAILSENTINEL / INVESTIGATION #{data.investigation_id.slice(-6).toUpperCase()}</span><button className="new-report-button" onClick={onNewInvestigation}>+ New</button><button className="export-button" onClick={() => window.print()}>↓ Download investigation report</button></div>
      <div className="report-nav"><a href="#verdict">Verdict</a><a href="#evidence">Evidence <b>04</b></a><a href="#trace">Relay trace</a><a href="#campaign">Campaign graph</a></div>
        <section className="hero" id="verdict">
          <div className="report-hero-layout">
          <div className="hero-inner">
            <RiskGauge score={data.risk_score} level={data.risk_level} />
            <div>
              <div className="risk-chip" style={{ background: `${riskColor}22`, color: riskColor, border: `1px solid ${riskColor}55` }}>
                <span className="dot" style={{ background: riskColor }} /> {data.risk_level.toUpperCase()} RISK
              </div>
              <div className="hero-domain">Highest-risk domain: <span className="mono" style={{ color: riskColor }}>{data.highest_risk_domain}</span></div>
              <p className="hero-summary">{data.summary}</p>
            </div>
          </div>
          <aside className="threat-brief"><div className="brief-label">THREAT BRIEF</div><div className="brief-title">Credential phishing</div><p>Sender impersonation and a newly registered login domain indicate an active credential-harvesting attempt.</p><div className="brief-meta"><span>AUTH <b>3 failures</b></span><span>DOMAIN <b>4 days old</b></span><span>LINKS <b>2 campaign matches</b></span></div></aside>
          </div>
        </section>

        <section className="section" id="evidence">
          <div className="section-head">
            <div><div className="section-kicker">MODEL REASONING</div><div className="section-title">Why this score?</div></div>
            <div className="section-sub">Tap a reason for the underlying evidence</div>
          </div>
          <div className="evidence-grid">
            {data.reasons.map((r) => <EvidenceCard key={r.id} reason={r} />)}
          </div>
        </section>

        <section className="section infra-section">
          <div className="section-head">
            <div><div className="section-kicker">INFRASTRUCTURE INTELLIGENCE</div><div className="section-title">Domain & infrastructure</div></div>
            <div className="section-sub">{data.domain_info.domain}</div>
          </div>
          <div className="infra-layout">
            <div className="age-callout">
              <div className="label">⚠ DOMAIN AGE</div>
              <div className="value">{data.domain_info.domain_age_days} DAYS OLD</div>
              <div className="note">Registered {data.domain_info.registered_on} via {data.domain_info.registrar}</div>
            </div>
            <div className="stat-grid">
              <div className="stat-card"><div className="stat-label">TLS issuer</div><div className="stat-value mono">{data.domain_info.tls_issuer}</div></div>
              <div className="stat-card"><div className="stat-label">TLS expiry</div><div className="stat-value mono">{data.domain_info.tls_expiry}</div></div>
              <div className="stat-card"><div className="stat-label">Reputation</div><div className="stat-value risk-high">{data.domain_info.reputation}</div></div>
              <div className="stat-card"><div className="stat-label">Blocklists</div><div className="stat-value risk-med">{data.domain_info.blocklist_hits} listed</div></div>
              <div className="stat-card"><div className="stat-label">IP address</div><div className="stat-value mono">{data.domain_info.ip}</div></div>
              <div className="stat-card"><div className="stat-label">ASN</div><div className="stat-value mono">{data.domain_info.asn}</div></div>
              <div className="stat-card"><div className="stat-label">Location</div><div className="stat-value mono">{data.domain_info.location}</div></div>
              <div className="stat-card"><div className="stat-label">Hosting</div><div className="stat-value mono">{data.domain_info.hosting}</div></div>
            </div>
          </div>
        </section>

        <section className="section" id="trace">
          <div className="section-head">
            <div><div className="section-kicker">MAIL ROUTING FORENSICS</div><div className="section-title">Relay path</div></div>
            <div className="section-sub">Tap a hop for details</div>
          </div>
          <RelayPath hops={data.relay_path} />
        </section>

        <section className="section campaign-section" id="campaign">
          <div className="section-head">
            <div><div className="section-kicker">LINK ANALYSIS</div><div className="section-title">Campaign correlation</div></div>
            <div className="section-sub">Hover a connection for the reason</div>
          </div>
          <div className="corr-banner">
            <div>Matched <strong>{matchedInvestigations} prior investigations</strong> against this infrastructure.</div>
            <div className="legend">
              <div className="legend-item"><span className="legend-line" /> Verified</div>
              <div className="legend-item"><span className="legend-line corroborated" /> Corroborated</div>
              <div className="legend-item"><span className="legend-line inferred" /> AI-inferred</div>
            </div>
          </div>
          <CampaignGraph nodes={campaign.nodes} edges={campaign.edges} graph={campaignCorrelation?.graph} />
        </section>
    </main>
  );
}

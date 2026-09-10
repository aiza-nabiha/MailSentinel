PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS emails (
    email_id        TEXT PRIMARY KEY,
    raw_eml_path    TEXT NOT NULL,
    ingested_at     TEXT NOT NULL DEFAULT (datetime('now')),
    subject         TEXT,
    from_header     TEXT,
    to_header       TEXT,
    date_header     TEXT,
    overall_risk_score REAL,
    verdict         TEXT,
    campaign_id     TEXT
);

CREATE TABLE IF NOT EXISTS classifier_results (
    email_id        TEXT PRIMARY KEY REFERENCES emails(email_id),
    phishing_score  REAL,
    verdict         TEXT,
    reasons_json    TEXT,
    extracted_urls_json TEXT
);

CREATE TABLE IF NOT EXISTS header_results (
    email_id        TEXT PRIMARY KEY REFERENCES emails(email_id),
    spf_result      TEXT,
    spf_domain      TEXT,
    dkim_json       TEXT,
    dmarc_result    TEXT,
    dmarc_domain    TEXT,
    dmarc_policy    TEXT,
    received_chain_json TEXT,
    raw_auth_results_json TEXT
);

CREATE TABLE IF NOT EXISTS domain_intel (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id        TEXT REFERENCES emails(email_id),
    domain          TEXT NOT NULL,
    age_days        INTEGER,
    tls_issuer      TEXT,
    tls_status      TEXT,
    cert_shared_with_json TEXT,
    found_on_lists_json TEXT,
    risk_score      REAL,
    risk_level      TEXT,
    risk_reasons_json TEXT,
    whois_json      TEXT,
    dns_json        TEXT,
    tls_json        TEXT,
    reputation_json TEXT
);

CREATE TABLE IF NOT EXISTS fingerprints (
    email_id        TEXT PRIMARY KEY REFERENCES emails(email_id),
    structural_hash TEXT,
    typosquat_matches_json TEXT,
    style_signature TEXT
);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id     TEXT PRIMARY KEY,
    confidence      REAL,
    linked_via_json TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS campaign_members (
    campaign_id     TEXT REFERENCES campaigns(campaign_id),
    email_id        TEXT REFERENCES emails(email_id),
    PRIMARY KEY (campaign_id, email_id)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_a          TEXT NOT NULL,
    node_b          TEXT NOT NULL,
    edge_type       TEXT NOT NULL,
    weight          REAL
);

CREATE INDEX IF NOT EXISTS idx_domain_email ON domain_intel(email_id);
CREATE INDEX IF NOT EXISTS idx_campaign_members_email ON campaign_members(email_id);
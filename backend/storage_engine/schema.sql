-- SIH 26106 -- backend/storage_engine/schema.sql
-- Run automatically by db.py -- you don't need to run this by hand.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id         TEXT PRIMARY KEY,   -- the Gmail address from Session.getActiveUser().getEmail()
    first_seen_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS emails (
    email_id        TEXT PRIMARY KEY,
    user_id         TEXT REFERENCES users(user_id),
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
    phishing_score  REAL,       -- maps to threat_probability (real model) or phishing_score (fallback)
    verdict         TEXT,       -- maps to prediction (real model) or verdict (fallback)
    reasons_json    TEXT,
    extracted_urls_json TEXT,
    source          TEXT,       -- 'real_model' or 'fallback_stub' -- lets you know which one ran
    url_intelligence_json TEXT, -- only populated by the real model
    sender_features_json TEXT,  -- only populated by the real model
    email_structure_json TEXT   -- only populated by the real model
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
    skeleton_type   TEXT,
    typosquat_matches_json TEXT,
    targeted_brands_json TEXT,
    style_colors_json TEXT,
    style_fonts_json TEXT,
    style_alt_texts_json TEXT
);

CREATE TABLE IF NOT EXISTS infrastructure_risk (
    email_id        TEXT PRIMARY KEY REFERENCES emails(email_id),
    risk_score      REAL,
    risk_level      TEXT,
    reasons_json    TEXT,
    evidence_json   TEXT,
    reliable_hop_json TEXT,
    received_chain_json TEXT
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

CREATE TABLE IF NOT EXISTS raw_email_archive (
    email_id            TEXT PRIMARY KEY REFERENCES emails(email_id),
    user_id             TEXT REFERENCES users(user_id),
    encrypted_raw_content TEXT NOT NULL,   -- full raw .eml text, Fernet-encrypted
    encrypted_headers_json TEXT,           -- complete header dump, Fernet-encrypted
    archived_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_archive_user ON raw_email_archive(user_id);
CREATE INDEX IF NOT EXISTS idx_domain_email ON domain_intel(email_id);
CREATE INDEX IF NOT EXISTS idx_campaign_members_email ON campaign_members(email_id);
CREATE INDEX IF NOT EXISTS idx_emails_user ON emails(user_id);
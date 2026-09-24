-- SIH 26106 -- backend/storage_engine/schema.sql
-- POSTGRES VERSION. Replaces the old SQLite schema.sql.
--
-- Two things merged into one schema here that used to live in two
-- separate SQLite files:
--   1. The original app schema (users/emails/.../access_log) --
--      previously phishing.db.
--   2. threat_correlation_engine.py's own tables (investigations,
--      infrastructure_observations, fingerprint_observations) --
--      previously a separate correlation.db that nothing else ever
--      touched. Now one database, one source of truth.
--
-- Retired entirely: campaigns / campaign_members / graph_edges (the
-- old correlate.py's tables). Replaced by campaign_membership /
-- campaign_edges below, which are a cache of threat_correlation_engine's
-- real output instead of the old simplified 3-signal engine's output.

CREATE TABLE IF NOT EXISTS users (
    user_id         TEXT PRIMARY KEY,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS emails (
    email_id        TEXT PRIMARY KEY,
    user_id         TEXT REFERENCES users(user_id),
    raw_eml_path    TEXT NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
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
    extracted_urls_json TEXT,
    source          TEXT,
    url_intelligence_json TEXT,
    sender_features_json TEXT,
    email_structure_json TEXT
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
    id              BIGSERIAL PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS raw_email_archive (
    email_id            TEXT PRIMARY KEY REFERENCES emails(email_id),
    user_id             TEXT REFERENCES users(user_id),
    encrypted_raw_content TEXT NOT NULL,
    encrypted_headers_json TEXT,
    archived_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_log (
    id              BIGSERIAL PRIMARY KEY,
    endpoint        TEXT NOT NULL,
    email_id        TEXT REFERENCES emails(email_id),
    user_id         TEXT,
    ip_address      TEXT,
    status_code     INTEGER,
    detail          TEXT,
    logged_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_access_log_email ON access_log(email_id);
CREATE INDEX IF NOT EXISTS idx_archive_user ON raw_email_archive(user_id);
CREATE INDEX IF NOT EXISTS idx_domain_email ON domain_intel(email_id);
CREATE INDEX IF NOT EXISTS idx_emails_user ON emails(user_id);


-- ============================================================
-- threat_correlation_engine.py's own tables
-- (previously an entirely separate correlation.db -- now here)
-- ============================================================

-- Cross-session memory of every infrastructure value ever seen,
-- used for the rarity/frequency discount.
CREATE TABLE IF NOT EXISTS infrastructure_observations (
    value               TEXT NOT NULL,
    value_type          TEXT NOT NULL,
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    observation_count   INTEGER DEFAULT 1,
    PRIMARY KEY (value, value_type)
);

-- Full per-email investigation snapshot the engine needs to reload
-- and compare NEW emails against every PAST one -- this is what
-- makes cross-session campaign memory work at all.
CREATE TABLE IF NOT EXISTS investigations (
    email_id             TEXT PRIMARY KEY REFERENCES emails(email_id),
    observed_at          TIMESTAMPTZ NOT NULL,
    infrastructure_json  TEXT NOT NULL,
    asns_json            TEXT NOT NULL,
    fingerprint_json     TEXT NOT NULL,
    risk_level           TEXT
);

-- Tracks how many DISTINCT sender domains have produced a given
-- structural fingerprint shape, for the commonality discount
-- (widely-used legit template vs. a phishing kit reused across a
-- handful of victims).
CREATE TABLE IF NOT EXISTS fingerprint_observations (
    fp_key       TEXT NOT NULL,
    domain       TEXT NOT NULL,
    observed_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (fp_key, domain)
);


-- ============================================================
-- Campaign result cache
-- ============================================================
-- threat_correlation_engine.correlate() recomputes the ENTIRE
-- campaign graph from full history on every call -- it is not
-- incremental, and campaign_id numbering ("campaign-001", ...) is
-- not stable across calls (it's just connected-component order).
-- So rather than trying to keep a stable campaign_id over time,
-- these two tables are a CACHE of the most recent correlate() run's
-- output, fully replaced (TRUNCATE + reinsert) every time /analyze
-- runs. api.py reads these directly instead of recomputing the graph
-- on every GET /investigation/<id>.

CREATE TABLE IF NOT EXISTS campaign_membership (
    email_id            TEXT REFERENCES emails(email_id),
    campaign_id         TEXT NOT NULL,
    confidence          REAL,
    cohesion            REAL,
    cohesion_warning    BOOLEAN,
    signal_summary_json TEXT,
    computed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (email_id, campaign_id)
);

CREATE TABLE IF NOT EXISTS campaign_edges (
    id                      BIGSERIAL PRIMARY KEY,
    campaign_id             TEXT NOT NULL,
    source_email_id         TEXT NOT NULL,
    target_email_id         TEXT NOT NULL,
    confidence               REAL,
    evidence_summary_json    TEXT,
    signals_json             TEXT
);

CREATE TABLE IF NOT EXISTS campaign_graphs (
    campaign_id TEXT PRIMARY KEY,
    graph_json  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaign_membership_email ON campaign_membership(email_id);
CREATE INDEX IF NOT EXISTS idx_campaign_edges_source ON campaign_edges(source_email_id);
CREATE INDEX IF NOT EXISTS idx_campaign_edges_target ON campaign_edges(target_email_id);
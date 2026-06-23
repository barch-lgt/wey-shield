-- Wey Shield — Supabase Schema
-- Run this in Supabase SQL editor (Europe region)
-- Enables RLS for multi-tenant client isolation

-- ── Extensions ─────────────────────────────────────────────────────────── --
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Operational Tables ─────────────────────────────────────────────────── --

CREATE TABLE IF NOT EXISTS scan_jobs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id       TEXT NOT NULL,
    targets         JSONB NOT NULL,
    scan_type       TEXT DEFAULT 'standard',
    language        TEXT DEFAULT 'en',
    status          TEXT DEFAULT 'queued',
    scope_token     TEXT NOT NULL,
    authorisation_id TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error           TEXT
);

CREATE TABLE IF NOT EXISTS scan_results (
    job_id          UUID PRIMARY KEY REFERENCES scan_jobs(id) ON DELETE CASCADE,
    profiles_data   JSONB,    -- TargetProfile per target (OS, ports, services)
    recon_data      JSONB,    -- Nmap / Subfinder / Httpx output
    vuln_data       JSONB,    -- Nuclei findings
    dragon_data     JSONB,    -- Patient Dragon verification results
    chaos_data      JSONB,    -- Micro-Chaos stress test results
    ai_summary      JSONB,    -- Multilingual AI interpretation
    completed_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_steps (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id          UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
    step            TEXT NOT NULL,    -- profiling | recon | vuln_scan | dragon | chaos | ai
    data            JSONB,
    logged_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_records (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id           TEXT NOT NULL,
    targets             JSONB NOT NULL,
    approved            BOOLEAN DEFAULT FALSE,
    verification_method TEXT,
    reason              TEXT,
    approved_at         TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- ── Training Archive (Immutable — never delete) ─────────────────────────── --
-- This is Wey Shield's long-term brain.
-- Every scan goes here. Every client feedback signal goes here.
-- When enough data accumulates → fine-tune a dedicated security model.

CREATE TABLE IF NOT EXISTS training_archive (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id                  UUID REFERENCES scan_jobs(id),
    client_id_anon          TEXT,       -- SHA256 hashed — privacy preserving
    language                TEXT,
    scan_type               TEXT,
    system_environment      TEXT,       -- linux | windows | aws | iot | web | unknown
    targets_count           INT,
    raw_scan_payload        JSONB,      -- Everything: recon, vulns, dragon, chaos
    ai_prompt_version       TEXT,       -- Which prompt version generated this
    ai_output               JSONB,      -- The AI's full interpretation
    finding_count           INT,
    critical_count          INT,
    risk_score              INT,
    model_used              TEXT,
    -- These fields filled in after client feedback:
    client_feedback_score   INT,        -- 1-5 stars
    false_positives         JSONB,      -- Finding IDs marked as FP
    improvement_notes       TEXT,
    outcome_label           TEXT,       -- 'high_quality' | 'needs_review'
    created_at              TIMESTAMPTZ DEFAULT NOW()
);

-- ── Row Level Security ──────────────────────────────────────────────────── --
-- Clients can only ever see their own data. No exceptions.

ALTER TABLE scan_jobs    ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_steps   ENABLE ROW LEVEL SECURITY;

CREATE POLICY client_isolation_jobs ON scan_jobs
    FOR ALL USING (client_id = current_setting('app.current_client_id', TRUE));

CREATE POLICY client_isolation_results ON scan_results
    FOR ALL USING (
        job_id IN (
            SELECT id FROM scan_jobs
            WHERE client_id = current_setting('app.current_client_id', TRUE)
        )
    );

CREATE POLICY client_isolation_steps ON scan_steps
    FOR ALL USING (
        job_id IN (
            SELECT id FROM scan_jobs
            WHERE client_id = current_setting('app.current_client_id', TRUE)
        )
    );

-- ── Indexes ─────────────────────────────────────────────────────────────── --
CREATE INDEX IF NOT EXISTS idx_scan_jobs_client  ON scan_jobs (client_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status  ON scan_jobs (status);
CREATE INDEX IF NOT EXISTS idx_training_language ON training_archive (language);
CREATE INDEX IF NOT EXISTS idx_training_env      ON training_archive (system_environment);
CREATE INDEX IF NOT EXISTS idx_training_label    ON training_archive (outcome_label);

-- Initial SNEX schema
-- Version: 1
-- Description: Core tables for all SNEX services

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Accounts table
CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending_verification',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    passkey_credential_id BYTEA,
    backup_phrase_hash BYTEA,
    double_verification_index BYTEA,
    of_age_flag BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_accounts_email ON accounts(email);
CREATE INDEX idx_accounts_status ON accounts(status);

-- Passkey credentials
CREATE TABLE passkey_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    aaguid BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_passkey_account ON passkey_credentials(account_id);

-- Tenants
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending_verification',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    governance_key_version INTEGER NOT NULL DEFAULT 0,
    minimum_anonymity_set INTEGER NOT NULL DEFAULT 30,
    reporting_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    voting_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    level_c_enabled BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_tenants_status ON tenants(status);

-- Tenant members
CREATE TABLE tenant_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    reporting_authorised BOOLEAN NOT NULL DEFAULT FALSE,
    voting_authorised BOOLEAN NOT NULL DEFAULT FALSE,
    level_c_authorised BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    UNIQUE(tenant_id, account_id)
);

CREATE INDEX idx_tenant_members_tenant ON tenant_members(tenant_id);
CREATE INDEX idx_tenant_members_account ON tenant_members(account_id);

-- Governance keys
CREATE TABLE governance_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    public_key BYTEA NOT NULL,
    threshold INTEGER NOT NULL,
    total_shares INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_governance_keys_tenant ON governance_keys(tenant_id, active);

-- Identity providers
CREATE TABLE identity_providers (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    endpoint VARCHAR(500) NOT NULL,
    supported_attributes JSONB NOT NULL DEFAULT '[]',
    cost_per_verification DECIMAL(10,2) NOT NULL DEFAULT 0,
    retention_period_days INTEGER NOT NULL DEFAULT 365,
    double_verification_capable BOOLEAN NOT NULL DEFAULT FALSE,
    assisted_route_available BOOLEAN NOT NULL DEFAULT FALSE,
    liability_certified BOOLEAN NOT NULL DEFAULT FALSE,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Verification records
CREATE TABLE verification_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    provider_id VARCHAR(255) NOT NULL REFERENCES identity_providers(id),
    verification_process_ref VARCHAR(500) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    attestation BYTEA,
    blinded_commitment BYTEA,
    of_age_attribute BOOLEAN NOT NULL DEFAULT FALSE,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_verification_account ON verification_records(account_id);
CREATE INDEX idx_verification_status ON verification_records(status);

-- Person credentials
CREATE TABLE person_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    schema_id VARCHAR(255) NOT NULL,
    issuer_pk BYTEA NOT NULL,
    subject BYTEA NOT NULL,
    attributes JSONB NOT NULL DEFAULT '[]',
    signature BYTEA NOT NULL,
    epoch BIGINT NOT NULL,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX idx_person_cred_account_epoch ON person_credentials(account_id, epoch);

-- Membership credentials
CREATE TABLE membership_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    schema_id VARCHAR(255) NOT NULL,
    issuer_pk BYTEA NOT NULL,
    subject BYTEA NOT NULL,
    attributes JSONB NOT NULL DEFAULT '[]',
    signature BYTEA NOT NULL,
    epoch BIGINT NOT NULL,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX idx_membership_cred_account_epoch ON membership_credentials(account_id, epoch);
CREATE INDEX idx_membership_cred_tenant_epoch ON membership_credentials(tenant_id, epoch);

-- Issuance events
CREATE TABLE issuance_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    epoch BIGINT NOT NULL,
    credential_type VARCHAR(50) NOT NULL,
    commitment BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_issuance_epoch ON issuance_events(epoch);

-- Pseudonym registrations
CREATE TABLE pseudonym_registrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pseudonym BYTEA NOT NULL UNIQUE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    epoch BIGINT NOT NULL,
    lifetime_index INTEGER NOT NULL,
    state VARCHAR(50) NOT NULL DEFAULT 'provisional',
    established_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    blocked_at TIMESTAMPTZ,
    terminated_at TIMESTAMPTZ,
    block_reason TEXT,
    establishment_nullifier BYTEA NOT NULL,
    pair_tag BYTEA NOT NULL,
    reporting_authorised BOOLEAN NOT NULL DEFAULT FALSE,
    voting_authorised BOOLEAN NOT NULL DEFAULT FALSE,
    epoch_confirmed BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_pseudo_tenant_epoch ON pseudonym_registrations(tenant_id, epoch);
CREATE INDEX idx_pseudo_state ON pseudonym_registrations(state);

-- Batches
CREATE TABLE batches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    establishments JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at TIMESTAMPTZ,
    release_threshold INTEGER NOT NULL
);

-- Epoch confirmations
CREATE TABLE epoch_confirmations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pseudonym BYTEA NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    epoch BIGINT NOT NULL,
    person_credential JSONB NOT NULL,
    membership_credential JSONB NOT NULL,
    zero_knowledge_proof BYTEA,
    confirmed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_epoch_conf_pseudo_epoch ON epoch_confirmations(pseudonym, epoch);

-- Terminated pseudonyms
CREATE TABLE terminated_pseudonyms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pseudonym_hash BYTEA NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    terminated_epoch BIGINT NOT NULL,
    lifetime_index INTEGER NOT NULL,
    terminated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_terminated_tenant_epoch ON terminated_pseudonyms(tenant_id, terminated_epoch);

-- Snapshots
CREATE TABLE snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    epoch BIGINT NOT NULL,
    ballot_id UUID,
    merkle_root BYTEA NOT NULL,
    leaves JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_snapshot_tenant_epoch ON snapshots(tenant_id, epoch);

-- Ballots
CREATE TABLE ballots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    opens_at TIMESTAMPTZ NOT NULL,
    closes_at TIMESTAMPTZ NOT NULL,
    epoch BIGINT NOT NULL,
    snapshot_root BYTEA NOT NULL,
    snapshot_size INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(50) NOT NULL DEFAULT 'upcoming',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tier VARCHAR(50) NOT NULL DEFAULT 'tier1_consultative'
);

CREATE INDEX idx_ballot_tenant_status ON ballots(tenant_id, status);

-- Vote registers
CREATE TABLE vote_registers (
    ballot_id UUID PRIMARY KEY REFERENCES ballots(id) ON DELETE CASCADE,
    entries JSONB NOT NULL DEFAULT '{}',
    finalized BOOLEAN NOT NULL DEFAULT FALSE,
    anchored_at TIMESTAMPTZ
);

-- Nullifiers
CREATE TABLE nullifiers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    nullifier BYTEA NOT NULL,
    domain VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload_hash BYTEA NOT NULL,
    epoch BIGINT NOT NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    ballot_id UUID REFERENCES ballots(id) ON DELETE SET NULL,
    report_window BIGINT,
    UNIQUE(nullifier, domain)
);

CREATE INDEX idx_nullifier_domain ON nullifiers(domain);

-- Reports
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_handle BYTEA NOT NULL UNIQUE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    reporting_office_id UUID NOT NULL,
    rate_limit_tag BYTEA NOT NULL,
    content BYTEA NOT NULL,
    case_key_wrapped BYTEA NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    epoch BIGINT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'submitted'
);

CREATE INDEX idx_report_tenant ON reports(tenant_id);

-- Cases
CREATE TABLE cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_handle BYTEA NOT NULL UNIQUE,
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    reporting_office_id UUID NOT NULL,
    case_key BYTEA NOT NULL,
    case_key_wrapped_for_officer BYTEA,
    case_key_wrapped_for_reporter BYTEA NOT NULL,
    role_key_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    handed_over_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    retention_expires_at TIMESTAMPTZ
);

CREATE INDEX idx_case_tenant ON cases(tenant_id);

-- Mailboxes
CREATE TABLE mailboxes (
    case_handle BYTEA PRIMARY KEY,
    mailbox_access BYTEA NOT NULL,
    messages JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ
);

-- Admission journal
CREATE TABLE admission_journal (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    nullifier BYTEA NOT NULL,
    domain VARCHAR(50) NOT NULL,
    payload_hash BYTEA NOT NULL,
    payload_reference TEXT,
    epoch BIGINT NOT NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed BOOLEAN NOT NULL DEFAULT TRUE,
    tombstone BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_admission_epoch_tenant ON admission_journal(epoch, tenant_id);

-- Retention records
CREATE TABLE retention_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    data_id VARCHAR(255) NOT NULL UNIQUE,
    retention_class VARCHAR(50) NOT NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    person_key_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    destruction_deadline TIMESTAMPTZ,
    state VARCHAR(50) NOT NULL DEFAULT 'active',
    legal_holds JSONB NOT NULL DEFAULT '[]',
    backup_generations JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX idx_retention_class ON retention_records(retention_class);
CREATE INDEX idx_retention_state ON retention_records(state);

-- Deletion journal
CREATE TABLE deletion_journal (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    data_id VARCHAR(255) NOT NULL,
    retention_class VARCHAR(50) NOT NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    person_key_id VARCHAR(255),
    destroyed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    destroyed_by VARCHAR(255) NOT NULL,
    key_material_hash BYTEA NOT NULL,
    backup_generations_affected JSONB NOT NULL DEFAULT '[]'
);

-- Audit chain
CREATE TABLE audit_chain (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sequence BIGINT NOT NULL UNIQUE,
    previous_hash BYTEA NOT NULL,
    hash BYTEA NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    component VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    epoch BIGINT,
    batch_id UUID
);

CREATE INDEX idx_audit_chain_sequence ON audit_chain(sequence);

-- Anchored hashes
CREATE TABLE anchored_hashes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    chain_head BYTEA NOT NULL,
    anchor_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    anchor_service VARCHAR(255) NOT NULL,
    anchor_proof BYTEA
);

-- Security critical events
CREATE TABLE security_critical_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data JSONB NOT NULL DEFAULT '{}',
    anchored BOOLEAN NOT NULL DEFAULT FALSE
);

-- Rate limit windows
CREATE TABLE rate_limit_windows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    window_start BIGINT NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rln_limit INTEGER NOT NULL DEFAULT 3,
    used_slots JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_rate_limit_window ON rate_limit_windows(window_start, tenant_id);

-- Level C rooms
CREATE TABLE level_c_rooms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES accounts(id),
    rule_set JSONB NOT NULL,
    mls_group_id BYTEA,
    mls_epoch BIGINT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_level_c_tenant ON level_c_rooms(tenant_id);

-- Level C members
CREATE TABLE level_c_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    room_id UUID NOT NULL REFERENCES level_c_rooms(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    devices JSONB NOT NULL DEFAULT '[]',
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by UUID NOT NULL REFERENCES accounts(id),
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    UNIQUE(room_id, account_id)
);

-- Device backups
CREATE TABLE device_backups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    recovery_phrase_hash BYTEA NOT NULL,
    mls_private_keys BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

-- Recovery backups
CREATE TABLE recovery_backups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    recovery_phrase_hash BYTEA NOT NULL,
    backup_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reporting offices
CREATE TABLE reporting_offices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    role_key_id UUID NOT NULL,
    case_key_rotation_days INTEGER NOT NULL DEFAULT 30,
    handover_period_hours INTEGER NOT NULL DEFAULT 24,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

-- External intake reports
CREATE TABLE external_intake_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    content BYTEA NOT NULL,
    proof_of_work BYTEA,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verification_level VARCHAR(50) NOT NULL DEFAULT 'unverified',
    assigned_office_id UUID
);

-- Tenant audit log
CREATE TABLE tenant_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL,
    actor VARCHAR(100) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details JSONB NOT NULL DEFAULT '{}',
    batch_id UUID,
    epoch BIGINT
);

CREATE INDEX idx_tenant_audit_tenant ON tenant_audit_log(tenant_id);

-- Transparency report
CREATE TABLE transparency_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    orders_received INTEGER NOT NULL DEFAULT 0,
    orders_complied INTEGER NOT NULL DEFAULT 0,
    orders_challenged INTEGER NOT NULL DEFAULT 0,
    openings_requested INTEGER NOT NULL DEFAULT 0,
    openings_performed INTEGER NOT NULL DEFAULT 0,
    openings_declined INTEGER NOT NULL DEFAULT 0,
    recoveries INTEGER NOT NULL DEFAULT 0,
    relay_changes INTEGER NOT NULL DEFAULT 0,
    subprocessor_changes INTEGER NOT NULL DEFAULT 0,
    build_up_mode_activations INTEGER NOT NULL DEFAULT 0,
    anchor_count INTEGER NOT NULL DEFAULT 0,
    anchor_gaps INTEGER NOT NULL DEFAULT 0,
    published_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Update triggers
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_accounts_updated_at BEFORE UPDATE ON accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
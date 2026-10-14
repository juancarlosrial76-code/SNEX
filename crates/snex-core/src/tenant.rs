use snex_crypto::hashing::Hash;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use strum::{EnumString, Display, AsRefStr};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum TenantStatus {
    Active,
    Suspended,
    Terminated,
    PendingVerification,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum TenantRole {
    Owner,
    Admin,
    Member,
    ReportingOfficer,
    VotingOfficer,
    Auditor,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub status: TenantStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub governance_key_version: u32,
    pub minimum_anonymity_set: u32,
    pub reporting_enabled: bool,
    pub voting_enabled: bool,
    pub level_c_enabled: bool,
    pub retention_config: RetentionConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetentionConfig {
    pub member_data_days: u32,
    pub room_content_days: u32,
    pub report_retention_days: u32,
    pub vote_proof_retention_days: u32,
    pub audit_log_retention_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            member_data_days: 90,
            room_content_days: 365,
            report_retention_days: 730,
            vote_proof_retention_days: 30,
            audit_log_retention_days: 730,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantMember {
    pub tenant_id: Uuid,
    pub account_id: Uuid,
    pub role: TenantRole,
    pub joined_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub reporting_authorised: bool,
    pub voting_authorised: bool,
    pub level_c_authorised: bool,
    pub status: MemberStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum MemberStatus {
    Active,
    Suspended,
    Left,
    Pending,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceKey {
    pub tenant_id: Uuid,
    pub version: u32,
    pub public_key: Vec<u8>,
    pub threshold: u32,
    pub total_shares: u32,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantConfiguration {
    pub tenant_id: Uuid,
    pub minimum_anonymity_set: u32,
    pub re_release_waiting_period_days: u32,
    pub publication_cohort_size: u32,
    pub max_establishment_period_hours: u32,
    pub min_establishment_jitter_hours: u32,
    pub rln_limit_per_window: u32,
    pub report_window_hours: u32,
    pub max_failed_establishment_attempts: u32,
    pub batch_release_threshold_min: u32,
    pub batch_release_threshold_max: u32,
}

impl Default for TenantConfiguration {
    fn default() -> Self {
        Self {
            minimum_anonymity_set: 30,
            re_release_waiting_period_days: 7,
            publication_cohort_size: 5,
            max_establishment_period_hours: 72,
            min_establishment_jitter_hours: 1,
            rln_limit_per_window: 3,
            report_window_hours: 24,
            max_failed_establishment_attempts: 2,
            batch_release_threshold_min: 8,
            batch_release_threshold_max: 12,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantAuditEntry {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub action: AuditAction,
    pub actor: Actor,
    pub timestamp: DateTime<Utc>,
    pub details: serde_json::Value,
    pub batch_id: Option<Uuid>,
    pub epoch: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum AuditAction {
    TenantCreated,
    TenantSuspended,
    TenantTerminated,
    MemberAdded,
    MemberRemoved,
    MemberRoleChanged,
    MemberReportingAuthorised,
    MemberVotingAuthorised,
    GovernanceKeyRotated,
    ConfigurationChanged,
    LegalHoldPlaced,
    LegalHoldLifted,
    DataExported,
    DataSubjectRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum Actor {
    System,
    TenantAdmin,
    PlatformOperator,
    LegalCoordination,
    SecurityOfficer,
    Automated,
}

impl Tenant {
    pub fn new(name: String, display_name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            display_name,
            status: TenantStatus::PendingVerification,
            created_at: now,
            updated_at: now,
            governance_key_version: 0,
            minimum_anonymity_set: 30,
            reporting_enabled: false,
            voting_enabled: false,
            level_c_enabled: false,
            retention_config: RetentionConfig::default(),
        }
    }

    pub fn activate(&mut self) {
        self.status = TenantStatus::Active;
        self.updated_at = Utc::now();
    }

    pub fn suspend(&mut self) {
        self.status = TenantStatus::Suspended;
        self.updated_at = Utc::now();
    }

    pub fn terminate(&mut self) {
        self.status = TenantStatus::Terminated;
        self.updated_at = Utc::now();
    }

    pub fn can_use_anonymous_functions(&self) -> bool {
        self.status == TenantStatus::Active && (self.reporting_enabled || self.voting_enabled)
    }
}

impl TenantMember {
    pub fn new(tenant_id: Uuid, account_id: Uuid, role: TenantRole) -> Self {
        Self {
            tenant_id,
            account_id,
            role,
            joined_at: Utc::now(),
            verified_at: None,
            reporting_authorised: false,
            voting_authorised: false,
            level_c_authorised: false,
            status: MemberStatus::Pending,
        }
    }

    pub fn authorise_reporting(&mut self) {
        self.reporting_authorised = true;
    }

    pub fn authorise_voting(&mut self) {
        self.voting_authorised = true;
    }

    pub fn authorise_level_c(&mut self) {
        self.level_c_authorised = true;
    }

    pub fn verify(&mut self) {
        self.verified_at = Some(Utc::now());
        self.status = MemberStatus::Active;
    }

    pub fn leave(&mut self) {
        self.status = MemberStatus::Left;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_lifecycle() {
        let mut tenant = Tenant::new("test-tenant".into(), "Test Tenant".into());
        assert_eq!(tenant.status, TenantStatus::PendingVerification);
        tenant.activate();
        assert_eq!(tenant.status, TenantStatus::Active);
        tenant.suspend();
        assert_eq!(tenant.status, TenantStatus::Suspended);
    }

    #[test]
    fn test_member_authorisation() {
        let tenant_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();
        let mut member = TenantMember::new(tenant_id, account_id, TenantRole::Member);
        assert!(!member.reporting_authorised);
        member.authorise_reporting();
        assert!(member.reporting_authorised);
    }
}
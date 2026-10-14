use snex_crypto::{
    nullifiers::{Nullifier, OperationSecret, CaseHandle, MailboxBaseSecret, MailboxAccess, RecoveryCode},
    key_hierarchy::Dek,
    encryption::EncryptedData,
    bbs::BbsCredential,
};
use crate::{epoch::Epoch, pseudonym::PseudonymFunction, error::{CoreError, Result}};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use strum::{EnumString, Display, AsRefStr};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub id: Uuid,
    pub case_handle: CaseHandle,
    pub tenant_id: Uuid,
    pub reporting_office_id: Uuid,
    pub rate_limit_tag: Nullifier,
    pub content: EncryptedData,
    pub case_key_wrapped: Vec<u8>,
    pub submitted_at: DateTime<Utc>,
    pub epoch: Epoch,
    pub status: ReportStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum ReportStatus {
    Submitted,
    HandedOver,
    InProgress,
    Replied,
    Closed,
    Deleted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportingOffice {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub role_key_id: Uuid,
    pub case_key_rotation_days: u32,
    pub handover_period_hours: u32,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Case {
    pub id: Uuid,
    pub case_handle: CaseHandle,
    pub report_id: Uuid,
    pub tenant_id: Uuid,
    pub reporting_office_id: Uuid,
    pub case_key: Dek,
    pub case_key_wrapped_for_officer: Option<Vec<u8>>,
    pub case_key_wrapped_for_reporter: Vec<u8>,
    pub role_key_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub handed_over_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub status: CaseStatus,
    pub retention_expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum CaseStatus {
    Open,
    HandedOver,
    InProgress,
    AwaitingReply,
    Closed,
    Deleted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reply {
    pub id: Uuid,
    pub case_id: Uuid,
    pub content: EncryptedData,
    pub sent_by: ReplySender,
    pub sent_at: DateTime<Utc>,
    pub read_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum ReplySender {
    Reporter,
    Officer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mailbox {
    pub case_handle: CaseHandle,
    pub mailbox_access: MailboxAccess,
    pub messages: Vec<MailboxMessage>,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailboxMessage {
    pub id: Uuid,
    pub content: EncryptedData,
    pub direction: MessageDirection,
    pub sent_at: DateTime<Utc>,
    pub read_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum MessageDirection {
    Incoming,
    Outgoing,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitWindow {
    pub window_start: u64,
    pub window_end: u64,
    pub tenant_id: Uuid,
    pub rln_limit: u32,
    pub used_slots: HashMap<Nullifier, u32>,
}

impl RateLimitWindow {
    pub fn new(window_start: u64, tenant_id: Uuid, rln_limit: u32) -> Self {
        let window_seconds = 24 * 3600;
        Self {
            window_start,
            window_end: window_start + window_seconds,
            tenant_id,
            rln_limit,
            used_slots: HashMap::new(),
        }
    }

    pub fn check_and_consume(&mut self, tag: &Nullifier) -> Result<()> {
        let used = self.used_slots.entry(*tag).or_insert(0);
        if *used >= self.rln_limit {
            return Err(CoreError::RateLimitExceeded);
        }
        *used += 1;
        Ok(())
    }

    pub fn is_in_window(&self, timestamp: u64) -> bool {
        timestamp >= self.window_start && timestamp < self.window_end
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportWindowSchedule {
    pub report_window_hours: u32,
    pub epoch_boundary_aligned: bool,
}

impl Default for ReportWindowSchedule {
    fn default() -> Self {
        Self {
            report_window_hours: 24,
            epoch_boundary_aligned: true,
        }
    }
}

impl ReportWindowSchedule {
    pub fn current_window_start(&self) -> u64 {
        let now = Utc::now().timestamp() as u64;
        let window_seconds = self.report_window_hours as u64 * 3600;
        (now / window_seconds) * window_seconds
    }

    pub fn window_for_timestamp(&self, timestamp: u64) -> u64 {
        let window_seconds = self.report_window_hours as u64 * 3600;
        (timestamp / window_seconds) * window_seconds
    }

    pub fn windows_per_epoch(&self) -> u64 {
        let epoch_seconds = 180 * 24 * 3600;
        let window_seconds = self.report_window_hours as u64 * 3600;
        epoch_seconds / window_seconds
    }
}

impl Report {
    pub fn new(
        tenant_id: Uuid,
        reporting_office_id: Uuid,
        rate_limit_tag: Nullifier,
        content: EncryptedData,
        case_key_wrapped: Vec<u8>,
        epoch: Epoch,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            case_handle: CaseHandle::generate(),
            tenant_id,
            reporting_office_id,
            rate_limit_tag,
            content,
            case_key_wrapped,
            submitted_at: Utc::now(),
            epoch,
            status: ReportStatus::Submitted,
        }
    }
}

impl Case {
    pub fn new(
        report: &Report,
        case_key: Dek,
        case_key_wrapped_for_officer: Vec<u8>,
        case_key_wrapped_for_reporter: Vec<u8>,
        role_key_id: Uuid,
    ) -> Self {
        let retention_days = 730;
        let expires = Utc::now() + chrono::Duration::days(retention_days as i64);
        
        Self {
            id: Uuid::new_v4(),
            case_handle: report.case_handle,
            report_id: report.id,
            tenant_id: report.tenant_id,
            reporting_office_id: report.reporting_office_id,
            case_key,
            case_key_wrapped_for_officer: Some(case_key_wrapped_for_officer),
            case_key_wrapped_for_reporter,
            role_key_id,
            created_at: Utc::now(),
            handed_over_at: None,
            closed_at: None,
            status: CaseStatus::Open,
            retention_expires_at: Some(expires),
        }
    }

    pub fn handover(&mut self, new_officer_key: Vec<u8>) {
        self.handed_over_at = Some(Utc::now());
        self.status = CaseStatus::HandedOver;
        self.case_key_wrapped_for_officer = Some(new_officer_key);
    }

    pub fn close(&mut self) {
        self.closed_at = Some(Utc::now());
        self.status = CaseStatus::Closed;
    }
}

impl Mailbox {
    pub fn new(case_handle: CaseHandle, mailbox_access: MailboxAccess) -> Self {
        Self {
            case_handle,
            mailbox_access,
            messages: Vec::new(),
            created_at: Utc::now(),
            last_accessed_at: None,
        }
    }

    pub fn add_message(&mut self, message: MailboxMessage) {
        self.messages.push(message);
    }

    pub fn get_unread(&self) -> Vec<&MailboxMessage> {
        self.messages.iter().filter(|m| m.read_at.is_none()).collect()
    }
}

impl Reply {
    pub fn new(case_id: Uuid, content: EncryptedData, sent_by: ReplySender) -> Self {
        Self {
            id: Uuid::new_v4(),
            case_id,
            content,
            sent_by,
            sent_at: Utc::now(),
            read_at: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportingCircleConfig {
    pub allow_external_intake: bool,
    pub external_intake_proof_of_work_difficulty: u32,
    pub reporting_officer_roles: Vec<String>,
    pub conflict_of_interest_substitutes: HashMap<Uuid, Uuid>,
}

impl Default for ReportingCircleConfig {
    fn default() -> Self {
        Self {
            allow_external_intake: true,
            external_intake_proof_of_work_difficulty: 100000,
            reporting_officer_roles: vec!["reporting_officer".into(), "compliance_officer".into()],
            conflict_of_interest_substitutes: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalIntakeReport {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub content: EncryptedData,
    pub proof_of_work: Vec<u8>,
    pub submitted_at: DateTime<Utc>,
    pub verification_level: ExternalVerificationLevel,
    pub assigned_office_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum ExternalVerificationLevel {
    Unverified,
    ProofOfWork,
    AccessToken,
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_crypto::nullifiers::OperationSecret;

    #[test]
    fn test_rate_limit_window() {
        let mut window = RateLimitWindow::new(0, Uuid::new_v4(), 3);
        let op_secret = OperationSecret::generate();
        let tag = op_secret.derive_rate_limit_tag(0, b"tenant");
        
        for i in 0..3 {
            window.check_and_consume(&tag).unwrap();
        }
        
        assert!(window.check_and_consume(&tag).is_err());
    }

    #[test]
    fn test_report_window_schedule() {
        let schedule = ReportWindowSchedule::default();
        let window_start = schedule.current_window_start();
        assert_eq!(schedule.window_for_timestamp(window_start + 3600), window_start);
        assert_eq!(schedule.window_for_timestamp(window_start + 24 * 3600), window_start + 24 * 3600);
    }

    #[test]
    fn test_case_lifecycle() {
        let op_secret = OperationSecret::generate();
        let tag = op_secret.derive_rate_limit_tag(0, b"tenant");
        let report = Report::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            tag,
            EncryptedData(vec![]),
            vec![],
            Epoch::current(),
        );
        
        let case_key = Dek::generate();
        let mut case = Case::new(&report, case_key, vec![], vec![], Uuid::new_v4());
        assert_eq!(case.status, CaseStatus::Open);
        
        case.handover(vec![]);
        assert_eq!(case.status, CaseStatus::HandedOver);
        
        case.close();
        assert_eq!(case.status, CaseStatus::Closed);
    }
}
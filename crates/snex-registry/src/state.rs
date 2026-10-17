use snex_core::{
    voting::{Vote, VoteRegister, VoteValue},
    reporting::{Report, Case, Reply, RateLimitWindow},
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{Nullifier, OperationSecret, CaseHandle, MailboxAccess},
    key_hierarchy::Dek,
    encryption::EncryptedData,
    hashing::Hash,
};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryState {
    pub nullifiers: HashMap<NullifierDomain, HashMap<Nullifier, NullifierEntry>>,
    pub block_list: HashMap<NullifierDomain, HashSet<Nullifier>>,
    pub termination_list: HashMap<Uuid, HashMap<Hash, TerminatedEntry>>,
    pub admission_journal: Vec<AdmissionJournalEntry>,
    pub vote_registers: HashMap<Uuid, VoteRegister>,
    pub reports: HashMap<Uuid, Report>,
    pub cases: HashMap<Uuid, Case>,
    pub mailboxes: HashMap<CaseHandle, Mailbox>,
    pub rate_limit_windows: HashMap<u64, HashMap<Uuid, RateLimitWindow>>,
    pub current_epoch: Epoch,
    pub lease_token: Option<LeaseToken>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NullifierDomain {
    Vote,
    Report,
    Establishment,
    RateLimit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierEntry {
    pub nullifier: Nullifier,
    pub domain: NullifierDomain,
    pub created_at: DateTime<Utc>,
    pub payload_hash: Hash,
    pub epoch: Epoch,
    pub tenant_id: Option<Uuid>,
    pub ballot_id: Option<Uuid>,
    pub report_window: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TerminatedEntry {
    pub pseudonym_hash: Hash,
    pub tenant_id: Uuid,
    pub terminated_epoch: Epoch,
    pub lifetime_index: u32,
    pub terminated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionJournalEntry {
    pub id: Uuid,
    pub nullifier: Nullifier,
    pub domain: NullifierDomain,
    pub payload_hash: Hash,
    pub payload_reference: Option<String>,
    pub epoch: Epoch,
    pub tenant_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub confirmed: bool,
    pub tombstone: bool,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDirection {
    Incoming,
    Outgoing,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseToken {
    pub instance_id: Uuid,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub fencing_token: u64,
}

impl RegistryState {
    pub fn new() -> Self {
        Self {
            nullifiers: HashMap::new(),
            block_list: HashMap::new(),
            termination_list: HashMap::new(),
            admission_journal: Vec::new(),
            vote_registers: HashMap::new(),
            reports: HashMap::new(),
            cases: HashMap::new(),
            mailboxes: HashMap::new(),
            rate_limit_windows: HashMap::new(),
            current_epoch: Epoch::current(),
            lease_token: None,
        }
    }

    pub fn check_nullifier(&self, domain: NullifierDomain, nullifier: &Nullifier) -> bool {
        self.nullifiers.get(&domain)
            .map(|map| map.contains_key(nullifier))
            .unwrap_or(false)
    }

    pub fn register_nullifier(&mut self, domain: NullifierDomain, entry: NullifierEntry) -> Result<()> {
        if self.check_nullifier(domain, &entry.nullifier) {
            return Err(CoreError::InvalidStateTransition("Nullifier already registered".into()));
        }
        
        self.nullifiers.entry(domain).or_default().insert(entry.nullifier, entry.clone());
        
        self.admission_journal.push(AdmissionJournalEntry {
            id: Uuid::new_v4(),
            nullifier: entry.nullifier,
            domain,
            payload_hash: entry.payload_hash,
            payload_reference: None,
            epoch: entry.epoch,
            tenant_id: entry.tenant_id,
            created_at: Utc::now(),
            confirmed: true,
            tombstone: false,
        });
        
        Ok(())
    }

    pub fn register_vote(&mut self, vote: &Vote) -> Result<()> {
        let nullifier = vote.nullifier;
        let domain = NullifierDomain::Vote;
        
        if self.check_nullifier(domain, &nullifier) {
            return Err(CoreError::DoubleVote);
        }
        
        let register = self.vote_registers.entry(vote.ballot_id).or_insert_with(|| {
            snex_core::voting::VoteRegister::new(vote.ballot_id)
        });
        
        register.add_vote(vote)?;
        
        self.register_nullifier(domain, NullifierEntry {
            nullifier,
            domain,
            created_at: vote.cast_at,
            payload_hash: vote.vote_hash,
            epoch: Epoch::current(),
            tenant_id: None,
            ballot_id: Some(vote.ballot_id),
            report_window: None,
        })?;
        
        Ok(())
    }

    pub fn register_report(&mut self, report: &Report, case: &Case) -> Result<()> {
        let nullifier = report.rate_limit_tag;
        let domain = NullifierDomain::Report;
        
        if self.check_nullifier(domain, &nullifier) {
            return Err(CoreError::DoubleReport);
        }
        
        let window_start = snex_core::reporting::ReportWindowSchedule::default().current_window_start();
        let windows = self.rate_limit_windows.entry(window_start).or_default();
        let window = windows.entry(report.tenant_id).or_insert_with(|| {
            snex_core::reporting::RateLimitWindow::new(window_start, report.tenant_id, 3)
        });
        window.check_and_consume(&nullifier)?;
        
        self.reports.insert(report.id, report.clone());
        self.cases.insert(case.id, case.clone());
        
        let mailbox = Mailbox {
            case_handle: report.case_handle,
            mailbox_access: snex_crypto::nullifiers::MailboxAccess([0u8; 32]),
            messages: Vec::new(),
            created_at: Utc::now(),
            last_accessed_at: None,
        };
        self.mailboxes.insert(report.case_handle, mailbox);
        
        self.register_nullifier(domain, NullifierEntry {
            nullifier,
            domain,
            created_at: report.submitted_at,
            payload_hash: Hash([0u8; 32]),
            epoch: report.epoch,
            tenant_id: Some(report.tenant_id),
            ballot_id: None,
            report_window: Some(window_start),
        })?;
        
        Ok(())
    }

    pub fn add_reply(&mut self, case_id: Uuid, reply: &snex_core::reporting::Reply) -> Result<()> {
        let case = self.cases.get_mut(&case_id)
            .ok_or(CoreError::NotFound("Case not found".into()))?;
        
        if let Some(mailbox) = self.mailboxes.get_mut(&case.case_handle) {
            mailbox.messages.push(MailboxMessage {
                id: reply.id,
                content: reply.content.clone(),
                direction: match reply.sent_by {
                    snex_core::reporting::ReplySender::Reporter => MessageDirection::Incoming,
                    snex_core::reporting::ReplySender::Officer => MessageDirection::Outgoing,
                },
                sent_at: reply.sent_at,
                read_at: reply.read_at,
            });
            mailbox.last_accessed_at = Some(Utc::now());
        }
        
        Ok(())
    }

    pub fn get_mailbox(&self, case_handle: &CaseHandle) -> Option<&Mailbox> {
        self.mailboxes.get(case_handle)
    }

    pub fn get_mailbox_mut(&mut self, case_handle: &CaseHandle) -> Option<&mut Mailbox> {
        self.mailboxes.get_mut(case_handle)
    }

    pub fn handover_case(&mut self, case_id: Uuid, new_officer_key: Vec<u8>) -> Result<()> {
        let case = self.cases.get_mut(&case_id)
            .ok_or(CoreError::NotFound("Case not found".into()))?;
        case.handover(new_officer_key);
        Ok(())
    }

    pub fn close_case(&mut self, case_id: Uuid) -> Result<()> {
        let case = self.cases.get_mut(&case_id)
            .ok_or(CoreError::NotFound("Case not found".into()))?;
        case.close();
        Ok(())
    }

    pub fn add_to_block_list(&mut self, domain: NullifierDomain, nullifier: Nullifier) {
        self.block_list.entry(domain).or_default().insert(nullifier);
    }

    pub fn is_blocked(&self, domain: NullifierDomain, nullifier: &Nullifier) -> bool {
        self.block_list.get(&domain)
            .map(|set| set.contains(nullifier))
            .unwrap_or(false)
    }

    pub fn add_termination(&mut self, tenant_id: Uuid, entry: TerminatedEntry) {
        self.termination_list.entry(tenant_id).or_default().insert(entry.pseudonym_hash, entry);
    }

    pub fn is_terminated(&self, tenant_id: Uuid, pseudonym_hash: &Hash) -> bool {
        self.termination_list.get(&tenant_id)
            .map(|map| map.contains_key(pseudonym_hash))
            .unwrap_or(false)
    }

    pub fn acquire_lease(&mut self, instance_id: Uuid, duration_seconds: u64) -> bool {
        let now = Utc::now();
        let expires = now + chrono::Duration::seconds(duration_seconds as i64);
        
        if let Some(lease) = &self.lease_token {
            if lease.expires_at > now && lease.instance_id != instance_id {
                return false;
            }
        }
        
        let fencing_token = self.lease_token.as_ref().map(|l| l.fencing_token + 1).unwrap_or(1);
        self.lease_token = Some(LeaseToken {
            instance_id,
            granted_at: now,
            expires_at: expires,
            fencing_token,
        });
        true
    }

    pub fn renew_lease(&mut self, instance_id: Uuid, duration_seconds: u64) -> bool {
        if let Some(lease) = &mut self.lease_token {
            if lease.instance_id == instance_id && lease.expires_at > Utc::now() {
                lease.expires_at = Utc::now() + chrono::Duration::seconds(duration_seconds as i64);
                return true;
            }
        }
        false
    }

    pub fn check_fencing_token(&self, token: u64) -> bool {
        self.lease_token.as_ref().map(|l| l.fencing_token == token).unwrap_or(false)
    }

    pub fn finalize_vote_register(&mut self, ballot_id: Uuid) {
        if let Some(register) = self.vote_registers.get_mut(&ballot_id) {
            register.finalize();
        }
    }
}

pub type SharedRegistryState = Arc<RwLock<RegistryState>>;

use std::sync::Arc;
use std::collections::HashSet;
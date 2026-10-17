use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use snex_core::{
    voting::{Vote, VoteRegister, VoteValue},
    reporting::{Report, Case, Reply, RateLimitWindow},
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{Nullifier, CaseHandle, MailboxAccess},
    hash::Hash,
    encryption::EncryptedData,
};

pub struct RegistryDatabase {
    pool: PgPool,
}

impl RegistryDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn register_nullifier(&self, entry: &snex_core::registry::NullifierEntry) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO nullifiers (id, nullifier, domain, created_at, payload_hash, epoch, tenant_id, ballot_id, report_window)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (nullifier, domain) DO NOTHING
            "#,
            Uuid::new_v4(),
            entry.nullifier.as_bytes(),
            entry.domain.to_string(),
            entry.created_at,
            entry.payload_hash.as_bytes(),
            entry.epoch.0 as i64,
            entry.tenant_id,
            entry.ballot_id,
            entry.report_window.map(|w| w as i64),
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn check_nullifier(&self, domain: &str, nullifier: &Nullifier) -> Result<bool> {
        let row = sqlx::query!(
            r#"
            SELECT 1 FROM nullifiers WHERE domain = $1 AND nullifier = $2
            "#,
            domain,
            nullifier.as_bytes(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(row.is_some())
    }

    pub async fn store_vote_register(&self, register: &VoteRegister) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO vote_registers (ballot_id, entries, finalized, anchored_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (ballot_id) DO UPDATE SET entries = $2, finalized = $3, anchored_at = $4
            "#,
            register.ballot_id,
            serde_json::to_value(&register.entries).unwrap(),
            register.finalized,
            register.anchored_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn get_vote_register(&self, ballot_id: Uuid) -> Result<Option<VoteRegister>> {
        let row = sqlx::query!(
            r#"
            SELECT ballot_id, entries, finalized, anchored_at
            FROM vote_registers WHERE ballot_id = $1
            "#,
            ballot_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(row.map(|r| VoteRegister {
            ballot_id: r.ballot_id,
            entries: serde_json::from_value(r.entries).unwrap_or_default(),
            finalized: r.finalized,
            anchored_at: r.anchored_at,
        }))
    }

    pub async fn store_report(&self, report: &Report) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO reports (id, case_handle, tenant_id, reporting_office_id, rate_limit_tag, content, case_key_wrapped, submitted_at, epoch, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            report.id,
            report.case_handle.as_bytes(),
            report.tenant_id,
            report.reporting_office_id,
            report.rate_limit_tag.as_bytes(),
            report.content.0,
            report.case_key_wrapped,
            report.submitted_at,
            report.epoch.0 as i64,
            report.status.to_string(),
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn store_case(&self, case: &Case) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO cases (id, case_handle, report_id, tenant_id, reporting_office_id, case_key, case_key_wrapped_for_officer, case_key_wrapped_for_reporter, role_key_id, created_at, handed_over_at, closed_at, status, retention_expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
            case.id,
            case.case_handle.as_bytes(),
            case.report_id,
            case.tenant_id,
            case.reporting_office_id,
            case.case_key.0.as_ref(),
            case.case_key_wrapped_for_officer,
            case.case_key_wrapped_for_reporter,
            case.role_key_id,
            case.created_at,
            case.handed_over_at,
            case.closed_at,
            case.status.to_string(),
            case.retention_expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn store_mailbox(&self, mailbox: &snex_core::registry::Mailbox) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO mailboxes (case_handle, mailbox_access, messages, created_at, last_accessed_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (case_handle) DO UPDATE SET messages = $3, last_accessed_at = $5
            "#,
            mailbox.case_handle.as_bytes(),
            mailbox.mailbox_access.as_bytes(),
            serde_json::to_value(&mailbox.messages).unwrap(),
            mailbox.created_at,
            mailbox.last_accessed_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn get_mailbox(&self, case_handle: &CaseHandle) -> Result<Option<snex_core::registry::Mailbox>> {
        let row = sqlx::query!(
            r#"
            SELECT case_handle, mailbox_access, messages, created_at, last_accessed_at
            FROM mailboxes WHERE case_handle = $1
            "#,
            case_handle.as_bytes(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(row.map(|r| snex_core::registry::Mailbox {
            case_handle: CaseHandle::from_slice(&r.case_handle).unwrap(),
            mailbox_access: MailboxAccess::from_slice(&r.mailbox_access).unwrap(),
            messages: serde_json::from_value(r.messages).unwrap_or_default(),
            created_at: r.created_at,
            last_accessed_at: r.last_accessed_at,
        }))
    }

    pub async fn add_admission_journal_entry(&self, entry: &snex_core::registry::AdmissionJournalEntry) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO admission_journal (id, nullifier, domain, payload_hash, payload_reference, epoch, tenant_id, created_at, confirmed, tombstone)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            entry.id,
            entry.nullifier.as_bytes(),
            entry.domain.to_string(),
            entry.payload_hash.as_bytes(),
            entry.payload_reference,
            entry.epoch.0 as i64,
            entry.tenant_id,
            entry.created_at,
            entry.confirmed,
            entry.tombstone,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn get_admission_journal(&self, epoch: Epoch, tenant_id: Option<Uuid>) -> Result<Vec<snex_core::registry::AdmissionJournalEntry>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, nullifier, domain, payload_hash, payload_reference, epoch, tenant_id, created_at, confirmed, tombstone
            FROM admission_journal WHERE epoch = $1 AND (tenant_id = $2 OR $2 IS NULL)
            ORDER BY created_at
            "#,
            epoch.0 as i64,
            tenant_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| snex_core::registry::AdmissionJournalEntry {
            id: r.id,
            nullifier: Nullifier::from_slice(&r.nullifier).unwrap(),
            domain: r.domain.parse().unwrap(),
            payload_hash: Hash::from_slice(&r.payload_hash).unwrap(),
            payload_reference: r.payload_reference,
            epoch: Epoch(r.epoch as u64),
            tenant_id: r.tenant_id,
            created_at: r.created_at,
            confirmed: r.confirmed,
            tombstone: r.tombstone,
        }).collect())
    }

    pub async fn store_termination(&self, tenant_id: Uuid, entry: &snex_core::registry::TerminatedEntry) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO terminated_pseudonyms (id, pseudonym_hash, tenant_id, terminated_epoch, lifetime_index, terminated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::new_v4(),
            entry.pseudonym_hash.as_bytes(),
            tenant_id,
            entry.terminated_epoch.0 as i64,
            entry.lifetime_index as i32,
            entry.terminated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn get_terminations(&self, tenant_id: Uuid, epoch: Epoch) -> Result<Vec<snex_core::registry::TerminatedEntry>> {
        let rows = sqlx::query!(
            r#"
            SELECT pseudonym_hash, tenant_id, terminated_epoch, lifetime_index, terminated_at
            FROM terminated_pseudonyms WHERE tenant_id = $1 AND terminated_epoch = $2
            "#,
            tenant_id,
            epoch.0 as i64,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| snex_core::registry::TerminatedEntry {
            pseudonym_hash: Hash::from_slice(&r.pseudonym_hash).unwrap(),
            tenant_id: r.tenant_id,
            terminated_epoch: Epoch(r.terminated_epoch as u64),
            lifetime_index: r.lifetime_index as u32,
            terminated_at: r.terminated_at,
        }).collect())
    }
}

impl snex_crypto::nullifiers::Nullifier {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, snex_crypto::error::CryptoError> {
        if bytes.len() != 32 {
            return Err(snex_crypto::error::CryptoError::InvalidParameter("Nullifier must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

impl snex_crypto::nullifiers::CaseHandle {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, snex_crypto::error::CryptoError> {
        if bytes.len() != 32 {
            return Err(snex_crypto::error::CryptoError::InvalidParameter("CaseHandle must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

impl snex_crypto::nullifiers::MailboxAccess {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, snex_crypto::error::CryptoError> {
        if bytes.len() != 32 {
            return Err(snex_crypto::error::CryptoError::InvalidParameter("MailboxAccess must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

impl snex_crypto::hashing::Hash {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, snex_crypto::error::CryptoError> {
        if bytes.len() != 32 {
            return Err(snex_crypto::error::CryptoError::InvalidParameter("Hash must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}
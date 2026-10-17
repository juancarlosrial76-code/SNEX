use sqlx::{PgPool, Row};
use uuid::Uuid;
use crate::state::{AdmissionJournalEntry, Mailbox, NullifierDomain, NullifierEntry, TerminatedEntry};
use snex_core::{
    voting::VoteRegister,
    reporting::{Report, Case},
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{Nullifier, CaseHandle, MailboxAccess, Pseudonym},
    hashing::Hash,
    error::CryptoError,
};

#[derive(Clone)]
pub struct RegistryDatabase {
    pool: PgPool,
}

fn db_err(e: sqlx::Error) -> CoreError {
    CoreError::Database(e.to_string())
}

fn domain_to_str(domain: NullifierDomain) -> &'static str {
    match domain {
        NullifierDomain::Vote => "vote",
        NullifierDomain::Report => "report",
        NullifierDomain::Establishment => "establishment",
        NullifierDomain::RateLimit => "rate_limit",
    }
}

fn domain_from_str(s: &str) -> Result<NullifierDomain> {
    match s {
        "vote" => Ok(NullifierDomain::Vote),
        "report" => Ok(NullifierDomain::Report),
        "establishment" => Ok(NullifierDomain::Establishment),
        "rate_limit" => Ok(NullifierDomain::RateLimit),
        other => Err(CoreError::Database(format!("unknown nullifier domain: {other}"))),
    }
}

fn to_array32(bytes: &[u8], what: &str) -> Result<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidParameter(format!("{what} must be 32 bytes")).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

pub(crate) fn nullifier_from_slice(bytes: &[u8]) -> Result<Nullifier> {
    Ok(Nullifier(to_array32(bytes, "Nullifier")?))
}

pub(crate) fn case_handle_from_slice(bytes: &[u8]) -> Result<CaseHandle> {
    Ok(CaseHandle(to_array32(bytes, "CaseHandle")?))
}

pub(crate) fn mailbox_access_from_slice(bytes: &[u8]) -> Result<MailboxAccess> {
    Ok(MailboxAccess(to_array32(bytes, "MailboxAccess")?))
}

pub(crate) fn pseudonym_from_slice(bytes: &[u8]) -> Result<Pseudonym> {
    Ok(Pseudonym(to_array32(bytes, "Pseudonym")?))
}

pub(crate) fn case_handle_from_hex(s: &str) -> Result<CaseHandle> {
    let bytes = hex::decode(s)
        .map_err(|e| CryptoError::Deserialization(e.to_string()))?;
    case_handle_from_slice(&bytes)
}

pub(crate) fn case_handle_to_hex(handle: &CaseHandle) -> String {
    hex::encode(handle.0)
}

pub(crate) fn hash_from_slice(bytes: &[u8]) -> Result<Hash> {
    Ok(Hash(to_array32(bytes, "Hash")?))
}

impl RegistryDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn register_nullifier(&self, entry: &NullifierEntry) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO nullifiers (id, nullifier, domain, created_at, payload_hash, epoch, tenant_id, ballot_id, report_window)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (nullifier, domain) DO NOTHING
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(entry.nullifier.as_bytes().as_slice())
        .bind(domain_to_str(entry.domain))
        .bind(entry.created_at)
        .bind(entry.payload_hash.as_bytes().as_slice())
        .bind(entry.epoch.0 as i64)
        .bind(entry.tenant_id)
        .bind(entry.ballot_id)
        .bind(entry.report_window.map(|w| w as i64))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(())
    }

    pub async fn check_nullifier(&self, domain: &str, nullifier: &Nullifier) -> Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT 1 FROM nullifiers WHERE domain = $1 AND nullifier = $2
            "#,
        )
        .bind(domain)
        .bind(nullifier.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(row.is_some())
    }

    pub async fn store_vote_register(&self, register: &VoteRegister) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO vote_registers (ballot_id, entries, finalized, anchored_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (ballot_id) DO UPDATE SET entries = $2, finalized = $3, anchored_at = $4
            "#,
        )
        .bind(register.ballot_id)
        .bind(serde_json::to_value(&register.entries).unwrap())
        .bind(register.finalized)
        .bind(register.anchored_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(())
    }

    pub async fn get_vote_register(&self, ballot_id: Uuid) -> Result<Option<VoteRegister>> {
        let row = sqlx::query(
            r#"
            SELECT ballot_id, entries, finalized, anchored_at
            FROM vote_registers WHERE ballot_id = $1
            "#,
        )
        .bind(ballot_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        row.map(|r| -> Result<VoteRegister> {
            Ok(VoteRegister {
                ballot_id: r.try_get("ballot_id").map_err(db_err)?,
                entries: serde_json::from_value(r.try_get("entries").map_err(db_err)?).unwrap_or_default(),
                finalized: r.try_get("finalized").map_err(db_err)?,
                anchored_at: r.try_get("anchored_at").map_err(db_err)?,
            })
        })
        .transpose()
    }

    pub async fn store_report(&self, report: &Report) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO reports (id, case_handle, tenant_id, reporting_office_id, rate_limit_tag, content, case_key_wrapped, submitted_at, epoch, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(report.id)
        .bind(report.case_handle.as_bytes().as_slice())
        .bind(report.tenant_id)
        .bind(report.reporting_office_id)
        .bind(report.rate_limit_tag.as_bytes().as_slice())
        .bind(&report.content.0)
        .bind(&report.case_key_wrapped)
        .bind(report.submitted_at)
        .bind(report.epoch.0 as i64)
        .bind(report.status.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(())
    }

    pub async fn store_case(&self, case: &Case) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO cases (id, case_handle, report_id, tenant_id, reporting_office_id, case_key, case_key_wrapped_for_officer, case_key_wrapped_for_reporter, role_key_id, created_at, handed_over_at, closed_at, status, retention_expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
        )
        .bind(case.id)
        .bind(case.case_handle.as_bytes().as_slice())
        .bind(case.report_id)
        .bind(case.tenant_id)
        .bind(case.reporting_office_id)
        .bind(case.case_key.0.as_ref() as &[u8])
        .bind(&case.case_key_wrapped_for_officer)
        .bind(&case.case_key_wrapped_for_reporter)
        .bind(case.role_key_id)
        .bind(case.created_at)
        .bind(case.handed_over_at)
        .bind(case.closed_at)
        .bind(case.status.to_string())
        .bind(case.retention_expires_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(())
    }

    pub async fn store_mailbox(&self, mailbox: &Mailbox) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO mailboxes (case_handle, mailbox_access, messages, created_at, last_accessed_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (case_handle) DO UPDATE SET messages = $3, last_accessed_at = $5
            "#,
        )
        .bind(mailbox.case_handle.as_bytes().as_slice())
        .bind(mailbox.mailbox_access.as_bytes().as_slice())
        .bind(serde_json::to_value(&mailbox.messages).unwrap())
        .bind(mailbox.created_at)
        .bind(mailbox.last_accessed_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(())
    }

    pub async fn get_mailbox(&self, case_handle: &CaseHandle) -> Result<Option<Mailbox>> {
        let row = sqlx::query(
            r#"
            SELECT case_handle, mailbox_access, messages, created_at, last_accessed_at
            FROM mailboxes WHERE case_handle = $1
            "#,
        )
        .bind(case_handle.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        row.map(|r| -> Result<Mailbox> {
            let case_handle: Vec<u8> = r.try_get("case_handle").map_err(db_err)?;
            let mailbox_access: Vec<u8> = r.try_get("mailbox_access").map_err(db_err)?;
            Ok(Mailbox {
                case_handle: case_handle_from_slice(&case_handle)?,
                mailbox_access: mailbox_access_from_slice(&mailbox_access)?,
                messages: serde_json::from_value(r.try_get("messages").map_err(db_err)?).unwrap_or_default(),
                created_at: r.try_get("created_at").map_err(db_err)?,
                last_accessed_at: r.try_get("last_accessed_at").map_err(db_err)?,
            })
        })
        .transpose()
    }

    pub async fn add_admission_journal_entry(&self, entry: &AdmissionJournalEntry) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO admission_journal (id, nullifier, domain, payload_hash, payload_reference, epoch, tenant_id, created_at, confirmed, tombstone)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(entry.id)
        .bind(entry.nullifier.as_bytes().as_slice())
        .bind(domain_to_str(entry.domain))
        .bind(entry.payload_hash.as_bytes().as_slice())
        .bind(&entry.payload_reference)
        .bind(entry.epoch.0 as i64)
        .bind(entry.tenant_id)
        .bind(entry.created_at)
        .bind(entry.confirmed)
        .bind(entry.tombstone)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(())
    }

    pub async fn get_admission_journal(&self, epoch: Epoch, tenant_id: Option<Uuid>) -> Result<Vec<AdmissionJournalEntry>> {
        let rows = sqlx::query(
            r#"
            SELECT id, nullifier, domain, payload_hash, payload_reference, epoch, tenant_id, created_at, confirmed, tombstone
            FROM admission_journal WHERE epoch = $1 AND (tenant_id = $2 OR $2 IS NULL)
            ORDER BY created_at
            "#,
        )
        .bind(epoch.0 as i64)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        rows.into_iter()
            .map(|r| -> Result<AdmissionJournalEntry> {
                let nullifier: Vec<u8> = r.try_get("nullifier").map_err(db_err)?;
                let domain: String = r.try_get("domain").map_err(db_err)?;
                let payload_hash: Vec<u8> = r.try_get("payload_hash").map_err(db_err)?;
                let epoch: i64 = r.try_get("epoch").map_err(db_err)?;
                Ok(AdmissionJournalEntry {
                    id: r.try_get("id").map_err(db_err)?,
                    nullifier: nullifier_from_slice(&nullifier)?,
                    domain: domain_from_str(&domain)?,
                    payload_hash: hash_from_slice(&payload_hash)?,
                    payload_reference: r.try_get("payload_reference").map_err(db_err)?,
                    epoch: Epoch(epoch as u64),
                    tenant_id: r.try_get("tenant_id").map_err(db_err)?,
                    created_at: r.try_get("created_at").map_err(db_err)?,
                    confirmed: r.try_get("confirmed").map_err(db_err)?,
                    tombstone: r.try_get("tombstone").map_err(db_err)?,
                })
            })
            .collect()
    }

    pub async fn store_termination(&self, tenant_id: Uuid, entry: &TerminatedEntry) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO terminated_pseudonyms (id, pseudonym_hash, tenant_id, terminated_epoch, lifetime_index, terminated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(entry.pseudonym_hash.as_bytes().as_slice())
        .bind(tenant_id)
        .bind(entry.terminated_epoch.0 as i64)
        .bind(entry.lifetime_index as i32)
        .bind(entry.terminated_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(())
    }

    pub async fn get_terminations(&self, tenant_id: Uuid, epoch: Epoch) -> Result<Vec<TerminatedEntry>> {
        let rows = sqlx::query(
            r#"
            SELECT pseudonym_hash, tenant_id, terminated_epoch, lifetime_index, terminated_at
            FROM terminated_pseudonyms WHERE tenant_id = $1 AND terminated_epoch = $2
            "#,
        )
        .bind(tenant_id)
        .bind(epoch.0 as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        rows.into_iter()
            .map(|r| -> Result<TerminatedEntry> {
                let pseudonym_hash: Vec<u8> = r.try_get("pseudonym_hash").map_err(db_err)?;
                let terminated_epoch: i64 = r.try_get("terminated_epoch").map_err(db_err)?;
                let lifetime_index: i32 = r.try_get("lifetime_index").map_err(db_err)?;
                Ok(TerminatedEntry {
                    pseudonym_hash: hash_from_slice(&pseudonym_hash)?,
                    tenant_id: r.try_get("tenant_id").map_err(db_err)?,
                    terminated_epoch: Epoch(terminated_epoch as u64),
                    lifetime_index: lifetime_index as u32,
                    terminated_at: r.try_get("terminated_at").map_err(db_err)?,
                })
            })
            .collect()
    }
}

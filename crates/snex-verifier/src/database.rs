use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use snex_core::{
    pseudonym::{PseudonymRegistration, Batch, EpochConfirmation, TerminatedPseudonym},
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{Nullifier, Pseudonym},
    hash::Hash,
};

pub struct VerifierDatabase {
    pool: PgPool,
}

impl VerifierDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn store_registration(&self, reg: &PseudonymRegistration) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO pseudonym_registrations (id, pseudonym, tenant_id, epoch, lifetime_index, state, established_at, activated_at, blocked_at, terminated_at, block_reason, establishment_nullifier, pair_tag, reporting_authorised, voting_authorised, epoch_confirmed)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            "#,
            reg.id,
            reg.pseudonym.as_bytes(),
            reg.tenant_id,
            reg.epoch.0 as i64,
            reg.lifetime_index as i32,
            reg.state.to_string(),
            reg.established_at,
            reg.activated_at,
            reg.blocked_at,
            reg.terminated_at,
            reg.block_reason,
            reg.establishment_nullifier.as_bytes(),
            reg.pair_tag.as_bytes(),
            reg.reporting_authorised,
            reg.voting_authorised,
            reg.epoch_confirmed,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn get_registration(&self, pseudonym: &Pseudonym) -> Result<Option<PseudonymRegistration>> {
        let row = sqlx::query!(
            r#"
            SELECT id, pseudonym, tenant_id, epoch, lifetime_index, state, established_at, activated_at, blocked_at, terminated_at, block_reason, establishment_nullifier, pair_tag, reporting_authorised, voting_authorised, epoch_confirmed
            FROM pseudonym_registrations WHERE pseudonym = $1
            "#,
            pseudonym.as_bytes(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(row.map(|r| PseudonymRegistration {
            id: r.id,
            pseudonym: Pseudonym::from_slice(&r.pseudonym).unwrap(),
            tenant_id: r.tenant_id,
            epoch: Epoch(r.epoch as u64),
            lifetime_index: r.lifetime_index as u32,
            state: r.state.parse().unwrap(),
            established_at: r.established_at,
            activated_at: r.activated_at,
            blocked_at: r.blocked_at,
            terminated_at: r.terminated_at,
            block_reason: r.block_reason,
            establishment_nullifier: Nullifier::from_slice(&r.establishment_nullifier).unwrap(),
            pair_tag: Nullifier::from_slice(&r.pair_tag).unwrap(),
            reporting_authorised: r.reporting_authorised,
            voting_authorised: r.voting_authorised,
            epoch_confirmed: r.epoch_confirmed,
        }))
    }

    pub async fn store_batch(&self, batch: &Batch) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO batches (id, establishments, created_at, released_at, release_threshold)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            batch.id,
            serde_json::to_value(&batch.establishments).unwrap(),
            batch.created_at,
            batch.released_at,
            batch.release_threshold as i32,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn store_epoch_confirmation(&self, confirmation: &EpochConfirmation) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO epoch_confirmations (id, pseudonym, tenant_id, epoch, person_credential, membership_credential, zero_knowledge_proof, confirmed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            Uuid::new_v4(),
            confirmation.pseudonym.as_bytes(),
            confirmation.tenant_id,
            confirmation.epoch.0 as i64,
            serde_json::to_value(&confirmation.person_credential).unwrap(),
            serde_json::to_value(&confirmation.membership_credential).unwrap(),
            confirmation.zero_knowledge_proof,
            Utc::now(),
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn store_terminated_pseudonym(&self, terminated: &TerminatedPseudonym) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO terminated_pseudonyms (id, pseudonym_hash, tenant_id, terminated_epoch, lifetime_index)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::new_v4(),
            terminated.pseudonym_hash.as_bytes(),
            terminated.tenant_id,
            terminated.terminated_epoch.0 as i64,
            terminated.lifetime_index as i32,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn get_terminated_pseudonyms(&self, tenant_id: Uuid, epoch: Epoch) -> Result<Vec<TerminatedPseudonym>> {
        let rows = sqlx::query!(
            r#"
            SELECT pseudonym_hash, tenant_id, terminated_epoch, lifetime_index
            FROM terminated_pseudonyms WHERE tenant_id = $1 AND terminated_epoch = $2
            "#,
            tenant_id,
            epoch.0 as i64,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| TerminatedPseudonym {
            pseudonym_hash: Hash::from_slice(&r.pseudonym_hash).unwrap(),
            tenant_id: r.tenant_id,
            terminated_epoch: Epoch(r.terminated_epoch as u64),
            lifetime_index: r.lifetime_index as u32,
        }).collect())
    }

    pub async fn get_snapshot(&self, snapshot_id: Uuid) -> Result<Option<snex_core::voting::Snapshot>> {
        let row = sqlx::query!(
            r#"
            SELECT id, tenant_id, epoch, ballot_id, merkle_root, leaves, created_at
            FROM snapshots WHERE id = $1
            "#,
            snapshot_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(row.map(|r| snex_core::voting::Snapshot {
            id: r.id,
            tenant_id: r.tenant_id,
            epoch: Epoch(r.epoch as u64),
            ballot_id: r.ballot_id,
            merkle_root: Hash::from_slice(&r.merkle_root).unwrap(),
            leaves: serde_json::from_value(r.leaves).unwrap_or_default(),
            created_at: r.created_at,
        }))
    }

    pub async fn store_snapshot(&self, snapshot: &snex_core::voting::Snapshot) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO snapshots (id, tenant_id, epoch, ballot_id, merkle_root, leaves, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            snapshot.id,
            snapshot.tenant_id,
            snapshot.epoch.0 as i64,
            snapshot.ballot_id,
            snapshot.merkle_root.as_bytes(),
            serde_json::to_value(&snapshot.leaves).unwrap(),
            snapshot.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn store_counter(&self, tenant_id: Uuid, epoch: Epoch, function: snex_core::pseudonym::PseudonymFunction, count: u32) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO pseudonym_counters (tenant_id, epoch, function, count)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, epoch, function) DO UPDATE SET count = $4
            "#,
            tenant_id,
            epoch.0 as i64,
            function.to_string(),
            count as i32,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn get_counter(&self, tenant_id: Uuid, epoch: Epoch, function: snex_core::pseudonym::PseudonymFunction) -> Result<u32> {
        let row = sqlx::query!(
            r#"
            SELECT count FROM pseudonym_counters WHERE tenant_id = $1 AND epoch = $2 AND function = $3
            "#,
            tenant_id,
            epoch.0 as i64,
            function.to_string(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(row.map(|r| r.count as u32).unwrap_or(0))
    }
}

impl snex_crypto::nullifiers::Pseudonym {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, snex_crypto::error::CryptoError> {
        if bytes.len() != 32 {
            return Err(snex_crypto::error::CryptoError::InvalidParameter("Pseudonym must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
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
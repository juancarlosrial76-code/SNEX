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
    hashing::Hash,
};

#[derive(Clone)]
pub struct VerifierDatabase {
    pool: PgPool,
}

impl VerifierDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn store_registration(&self, reg: &PseudonymRegistration) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO pseudonym_registrations (id, pseudonym, tenant_id, epoch, lifetime_index, state, established_at, activated_at, blocked_at, terminated_at, block_reason, establishment_nullifier, pair_tag, reporting_authorised, voting_authorised, epoch_confirmed)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            "#)
            .bind(reg.id)
            .bind(&reg.pseudonym.as_bytes()[..])
            .bind(reg.tenant_id)
            .bind(reg.epoch.0 as i64)
            .bind(reg.lifetime_index as i32)
            .bind(reg.state.to_string())
            .bind(reg.established_at)
            .bind(reg.activated_at)
            .bind(reg.blocked_at)
            .bind(reg.terminated_at)
            .bind(&reg.block_reason)
            .bind(&reg.establishment_nullifier.as_bytes()[..])
            .bind(&reg.pair_tag.as_bytes()[..])
            .bind(reg.reporting_authorised)
            .bind(reg.voting_authorised)
            .bind(reg.epoch_confirmed)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn get_registration(&self, pseudonym: &Pseudonym) -> Result<Option<PseudonymRegistration>> {
        let row = sqlx::query(r#"
            SELECT id, pseudonym, tenant_id, epoch, lifetime_index, state, established_at, activated_at, blocked_at, terminated_at, block_reason, establishment_nullifier, pair_tag, reporting_authorised, voting_authorised, epoch_confirmed
            FROM pseudonym_registrations WHERE pseudonym = $1
            "#)
            .bind(&pseudonym.as_bytes()[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let r = match row {
            Some(r) => r,
            None => return Ok(None),
        };
        let pseudonym: Vec<u8> = r.try_get("pseudonym").map_err(db_err)?;
        let state: String = r.try_get("state").map_err(db_err)?;
        let epoch: i64 = r.try_get("epoch").map_err(db_err)?;
        let lifetime_index: i32 = r.try_get("lifetime_index").map_err(db_err)?;
        let establishment_nullifier: Vec<u8> = r.try_get("establishment_nullifier").map_err(db_err)?;
        let pair_tag: Vec<u8> = r.try_get("pair_tag").map_err(db_err)?;
        Ok(Some(PseudonymRegistration {
            id: r.try_get("id").map_err(db_err)?,
            pseudonym: pseudonym_from_slice(&pseudonym)?,
            tenant_id: r.try_get("tenant_id").map_err(db_err)?,
            epoch: Epoch(epoch as u64),
            lifetime_index: lifetime_index as u32,
            state: state
                .parse()
                .map_err(|_| CoreError::Database(format!("unknown pseudonym state: {state}")))?,
            established_at: r.try_get("established_at").map_err(db_err)?,
            activated_at: r.try_get("activated_at").map_err(db_err)?,
            blocked_at: r.try_get("blocked_at").map_err(db_err)?,
            terminated_at: r.try_get("terminated_at").map_err(db_err)?,
            block_reason: r.try_get("block_reason").map_err(db_err)?,
            establishment_nullifier: nullifier_from_slice(&establishment_nullifier)?,
            pair_tag: nullifier_from_slice(&pair_tag)?,
            reporting_authorised: r.try_get("reporting_authorised").map_err(db_err)?,
            voting_authorised: r.try_get("voting_authorised").map_err(db_err)?,
            epoch_confirmed: r.try_get("epoch_confirmed").map_err(db_err)?,
        }))
    }

    pub async fn store_batch(&self, batch: &Batch) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO batches (id, establishments, created_at, released_at, release_threshold)
            VALUES ($1, $2, $3, $4, $5)
            "#)
            .bind(batch.id)
            .bind(serde_json::to_value(&batch.establishments).map_err(ser_err)?)
            .bind(batch.created_at)
            .bind(batch.released_at)
            .bind(batch.release_threshold as i32)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn store_epoch_confirmation(&self, confirmation: &EpochConfirmation) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO epoch_confirmations (id, pseudonym, tenant_id, epoch, person_credential, membership_credential, zero_knowledge_proof, confirmed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#)
            .bind(Uuid::new_v4())
            .bind(&confirmation.pseudonym.as_bytes()[..])
            .bind(confirmation.tenant_id)
            .bind(confirmation.epoch.0 as i64)
            .bind(serde_json::to_value(&confirmation.person_credential).map_err(ser_err)?)
            .bind(serde_json::to_value(&confirmation.membership_credential).map_err(ser_err)?)
            .bind(&confirmation.zero_knowledge_proof)
            .bind(Utc::now())
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn store_terminated_pseudonym(&self, terminated: &TerminatedPseudonym) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO terminated_pseudonyms (id, pseudonym_hash, tenant_id, terminated_epoch, lifetime_index)
            VALUES ($1, $2, $3, $4, $5)
            "#)
            .bind(Uuid::new_v4())
            .bind(&terminated.pseudonym_hash.as_bytes()[..])
            .bind(terminated.tenant_id)
            .bind(terminated.terminated_epoch.0 as i64)
            .bind(terminated.lifetime_index as i32)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn get_terminated_pseudonyms(&self, tenant_id: Uuid, epoch: Epoch) -> Result<Vec<TerminatedPseudonym>> {
        let rows = sqlx::query(r#"
            SELECT pseudonym_hash, tenant_id, terminated_epoch, lifetime_index
            FROM terminated_pseudonyms WHERE tenant_id = $1 AND terminated_epoch = $2
            "#)
            .bind(tenant_id)
            .bind(epoch.0 as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        rows.into_iter()
            .map(|r| {
                let hash: Vec<u8> = r.try_get("pseudonym_hash").map_err(db_err)?;
                let terminated_epoch: i64 = r.try_get("terminated_epoch").map_err(db_err)?;
                let lifetime_index: i32 = r.try_get("lifetime_index").map_err(db_err)?;
                Ok(TerminatedPseudonym {
                    pseudonym_hash: hash_from_slice(&hash)?,
                    tenant_id: r.try_get("tenant_id").map_err(db_err)?,
                    terminated_epoch: Epoch(terminated_epoch as u64),
                    lifetime_index: lifetime_index as u32,
                })
            })
            .collect()
    }

    pub async fn get_snapshot(&self, snapshot_id: Uuid) -> Result<Option<snex_core::voting::Snapshot>> {
        let row = sqlx::query(r#"
            SELECT id, tenant_id, epoch, ballot_id, merkle_root, leaves, created_at
            FROM snapshots WHERE id = $1
            "#)
            .bind(snapshot_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let r = match row {
            Some(r) => r,
            None => return Ok(None),
        };
        let epoch: i64 = r.try_get("epoch").map_err(db_err)?;
        let merkle_root: Vec<u8> = r.try_get("merkle_root").map_err(db_err)?;
        let leaves: serde_json::Value = r.try_get("leaves").map_err(db_err)?;
        Ok(Some(snex_core::voting::Snapshot {
            id: r.try_get("id").map_err(db_err)?,
            tenant_id: r.try_get("tenant_id").map_err(db_err)?,
            epoch: Epoch(epoch as u64),
            ballot_id: r.try_get("ballot_id").map_err(db_err)?,
            merkle_root: hash_from_slice(&merkle_root)?,
            leaves: serde_json::from_value(leaves).unwrap_or_default(),
            created_at: r.try_get("created_at").map_err(db_err)?,
        }))
    }

    pub async fn store_snapshot(&self, snapshot: &snex_core::voting::Snapshot) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO snapshots (id, tenant_id, epoch, ballot_id, merkle_root, leaves, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#)
            .bind(snapshot.id)
            .bind(snapshot.tenant_id)
            .bind(snapshot.epoch.0 as i64)
            .bind(snapshot.ballot_id)
            .bind(&snapshot.merkle_root.as_bytes()[..])
            .bind(serde_json::to_value(&snapshot.leaves).map_err(ser_err)?)
            .bind(snapshot.created_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn store_counter(&self, tenant_id: Uuid, epoch: Epoch, function: snex_core::pseudonym::PseudonymFunction, count: u32) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO pseudonym_counters (tenant_id, epoch, function, count)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, epoch, function) DO UPDATE SET count = $4
            "#)
            .bind(tenant_id)
            .bind(epoch.0 as i64)
            .bind(function.to_string())
            .bind(count as i32)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn get_counter(&self, tenant_id: Uuid, epoch: Epoch, function: snex_core::pseudonym::PseudonymFunction) -> Result<u32> {
        let row = sqlx::query(r#"
            SELECT count FROM pseudonym_counters WHERE tenant_id = $1 AND epoch = $2 AND function = $3
            "#)
            .bind(tenant_id)
            .bind(epoch.0 as i64)
            .bind(function.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        match row {
            Some(r) => {
                let count: i32 = r.try_get("count").map_err(db_err)?;
                Ok(count as u32)
            }
            None => Ok(0),
        }
    }
}

fn bytes32(bytes: &[u8], what: &str) -> Result<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(CoreError::from(snex_crypto::error::CryptoError::InvalidParameter(
            format!("{what} must be 32 bytes"),
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

/// Freie Funktionen statt inherent impl auf Fremdtypen (E0116).
pub(crate) fn pseudonym_from_slice(bytes: &[u8]) -> Result<Pseudonym> {
    Ok(Pseudonym(bytes32(bytes, "Pseudonym")?))
}

pub(crate) fn nullifier_from_slice(bytes: &[u8]) -> Result<Nullifier> {
    Ok(Nullifier(bytes32(bytes, "Nullifier")?))
}

pub(crate) fn hash_from_slice(bytes: &[u8]) -> Result<Hash> {
    Ok(Hash(bytes32(bytes, "Hash")?))
}

fn db_err<E: std::fmt::Display>(e: E) -> CoreError {
    CoreError::Database(e.to_string())
}

fn ser_err<E: std::fmt::Display>(e: E) -> CoreError {
    CoreError::Serialization(e.to_string())
}

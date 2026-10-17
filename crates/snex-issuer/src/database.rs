use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sqlx::types::Json;
use snex_core::{identity::Account, epoch::Epoch, tenant::Tenant, error::{CoreError, Result}};
use snex_crypto::{
    bbs::BbsCredential,
    commitments::Commitment,
    key_hierarchy::MasterKey,
    hashing::Hash,
};

pub struct IssuerDatabase {
    pool: PgPool,
}

impl IssuerDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_account(&self, account: &Account) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO accounts (id, email, display_name, status, created_at, updated_at, passkey_credential_id, backup_phrase_hash, double_verification_index, of_age_flag)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#)
            .bind(account.id)
            .bind(&account.email)
            .bind(&account.display_name)
            .bind(account.status.to_string())
            .bind(account.created_at)
            .bind(account.updated_at)
            .bind(&account.passkey_credential_id)
            .bind(account.backup_phrase_hash.as_ref().map(|h| h.as_bytes().to_vec()))
            .bind(account.double_verification_index.as_ref().map(|h| h.as_bytes().to_vec()))
            .bind(account.of_age_flag)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn get_account(&self, account_id: Uuid) -> Result<Option<Account>> {
        let row = sqlx::query(r#"
            SELECT id, email, display_name, status, created_at, updated_at, last_login_at, passkey_credential_id, backup_phrase_hash, double_verification_index, of_age_flag
            FROM accounts WHERE id = $1
            "#)
            .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let r = match row {
            Some(r) => r,
            None => return Ok(None),
        };
        let status: String = r.try_get("status").map_err(db_err)?;
        let backup: Option<Vec<u8>> = r.try_get("backup_phrase_hash").map_err(db_err)?;
        let dvi: Option<Vec<u8>> = r.try_get("double_verification_index").map_err(db_err)?;
        Ok(Some(Account {
            id: r.try_get("id").map_err(db_err)?,
            email: r.try_get("email").map_err(db_err)?,
            display_name: r.try_get("display_name").map_err(db_err)?,
            status: status
                .parse()
                .map_err(|_| CoreError::Database(format!("unknown account status: {status}")))?,
            created_at: r.try_get("created_at").map_err(db_err)?,
            updated_at: r.try_get("updated_at").map_err(db_err)?,
            last_login_at: r.try_get("last_login_at").map_err(db_err)?,
            passkey_credential_id: r.try_get("passkey_credential_id").map_err(db_err)?,
            backup_phrase_hash: backup.map(|b| hash_from_slice(&b)).transpose()?,
            double_verification_index: dvi.map(|b| hash_from_slice(&b)).transpose()?,
            of_age_flag: r.try_get("of_age_flag").map_err(db_err)?,
        }))
    }

    pub async fn update_account(&self, account: &Account) -> Result<()> {
        sqlx::query(r#"
            UPDATE accounts SET email = $2, display_name = $3, status = $4, updated_at = $5, last_login_at = $6, passkey_credential_id = $7, backup_phrase_hash = $8, double_verification_index = $9, of_age_flag = $10
            WHERE id = $1
            "#)
            .bind(account.id)
            .bind(&account.email)
            .bind(&account.display_name)
            .bind(account.status.to_string())
            .bind(account.updated_at)
            .bind(account.last_login_at)
            .bind(&account.passkey_credential_id)
            .bind(account.backup_phrase_hash.as_ref().map(|h| h.as_bytes().to_vec()))
            .bind(account.double_verification_index.as_ref().map(|h| h.as_bytes().to_vec()))
            .bind(account.of_age_flag)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn store_person_credential(&self, account_id: Uuid, credential: &BbsCredential) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO person_credentials (id, account_id, schema_id, issuer_pk, subject, attributes, signature, epoch, issued_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#)
            .bind(Uuid::new_v4())
            .bind(account_id)
            .bind(&credential.schema_id)
            .bind(&credential.issuer.key)
            .bind(&credential.subject)
            .bind(Json(&credential.attributes))
            .bind(&credential.signature.signature)
            .bind(credential.epoch as i64)
            .bind(credential.issued_at as i64)
            .bind(credential.expires_at as i64)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn store_membership_credential(&self, account_id: Uuid, credential: &BbsCredential, tenant_id: Uuid) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO membership_credentials (id, account_id, tenant_id, schema_id, issuer_pk, subject, attributes, signature, epoch, issued_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#)
            .bind(Uuid::new_v4())
            .bind(account_id)
            .bind(tenant_id)
            .bind(&credential.schema_id)
            .bind(&credential.issuer.key)
            .bind(&credential.subject)
            .bind(Json(&credential.attributes))
            .bind(&credential.signature.signature)
            .bind(credential.epoch as i64)
            .bind(credential.issued_at as i64)
            .bind(credential.expires_at as i64)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn store_governance_key(&self, governance_key: &snex_core::tenant::GovernanceKey) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO governance_keys (id, tenant_id, version, public_key, threshold, total_shares, created_at, rotated_at, active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#)
            .bind(Uuid::new_v4())
            .bind(governance_key.tenant_id)
            .bind(governance_key.version as i32)
            .bind(&governance_key.public_key)
            .bind(governance_key.threshold as i32)
            .bind(governance_key.total_shares as i32)
            .bind(governance_key.created_at)
            .bind(governance_key.rotated_at)
            .bind(governance_key.active)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn get_latest_governance_key(&self, tenant_id: Uuid) -> Result<Option<snex_core::tenant::GovernanceKey>> {
        let row = sqlx::query(r#"
            SELECT id, tenant_id, version, public_key, threshold, total_shares, created_at, rotated_at, active
            FROM governance_keys WHERE tenant_id = $1 AND active = true ORDER BY version DESC LIMIT 1
            "#)
            .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let r = match row {
            Some(r) => r,
            None => return Ok(None),
        };
        let version: i32 = r.try_get("version").map_err(db_err)?;
        let threshold: i32 = r.try_get("threshold").map_err(db_err)?;
        let total_shares: i32 = r.try_get("total_shares").map_err(db_err)?;
        Ok(Some(snex_core::tenant::GovernanceKey {
            tenant_id: r.try_get("tenant_id").map_err(db_err)?,
            version: version as u32,
            public_key: r.try_get("public_key").map_err(db_err)?,
            threshold: threshold as u32,
            total_shares: total_shares as u32,
            created_at: r.try_get("created_at").map_err(db_err)?,
            rotated_at: r.try_get("rotated_at").map_err(db_err)?,
            active: r.try_get("active").map_err(db_err)?,
        }))
    }

    pub async fn store_verification_record(&self, record: &snex_core::identity::VerificationRecord) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO verification_records (id, account_id, provider_id, verification_process_ref, status, attestation, blinded_commitment, of_age_attribute, requested_at, completed_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#)
            .bind(record.id)
            .bind(record.account_id)
            .bind(&record.provider_id)
            .bind(&record.verification_process_ref)
            .bind(record.status.to_string())
            .bind(&record.attestation)
            .bind(record.blinded_commitment.as_ref().map(|c| c.to_bytes().to_vec()))
            .bind(record.of_age_attribute)
            .bind(record.requested_at)
            .bind(record.completed_at)
            .bind(record.expires_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn store_issuance_event(&self, account_id: Uuid, epoch: Epoch, credential_type: &str, commitment: &Commitment) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO issuance_events (id, account_id, epoch, credential_type, commitment, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#)
            .bind(Uuid::new_v4())
            .bind(account_id)
            .bind(epoch.0 as i64)
            .bind(credential_type)
            .bind(commitment.to_bytes().to_vec())
            .bind(Utc::now())
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        
        Ok(())
    }

    pub async fn get_account_credentials(&self, account_id: Uuid, epoch: Epoch) -> Result<Vec<BbsCredential>> {
        let rows = sqlx::query(r#"
            SELECT schema_id, issuer_pk, subject, attributes, signature, epoch, issued_at, expires_at
            FROM person_credentials WHERE account_id = $1 AND epoch = $2
            "#)
            .bind(account_id)
            .bind(epoch.0 as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        rows.into_iter()
            .map(|r| {
                let attributes: Json<Vec<Vec<u8>>> = r.try_get("attributes").map_err(db_err)?;
                let epoch: i64 = r.try_get("epoch").map_err(db_err)?;
                let issued_at: i64 = r.try_get("issued_at").map_err(db_err)?;
                let expires_at: i64 = r.try_get("expires_at").map_err(db_err)?;
                Ok(BbsCredential {
                    schema_id: r.try_get("schema_id").map_err(db_err)?,
                    issuer: snex_crypto::bbs::BbsPublicKey { key: r.try_get("issuer_pk").map_err(db_err)? },
                    subject: r.try_get("subject").map_err(db_err)?,
                    attributes: attributes.0,
                    signature: snex_crypto::bbs::BbsSignature { signature: r.try_get("signature").map_err(db_err)? },
                    epoch: epoch as u64,
                    issued_at: issued_at as u64,
                    expires_at: expires_at as u64,
                })
            })
            .collect()
    }
}

/// Baut einen `Hash` aus einem 32-Byte-Slice (Fremdtyp, daher freie Funktion statt inherent impl).
fn hash_from_slice(bytes: &[u8]) -> Result<Hash> {
    if bytes.len() != 32 {
        return Err(CoreError::from(snex_crypto::error::CryptoError::InvalidParameter(
            "Hash must be 32 bytes".into(),
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(Hash(arr))
}

fn db_err<E: std::fmt::Display>(e: E) -> CoreError {
    CoreError::Database(e.to_string())
}

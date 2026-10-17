use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use snex_core::{identity::Account, epoch::Epoch, tenant::Tenant, error::{CoreError, Result}};
use snex_crypto::{
    bbs::BbsCredential,
    commitments::Commitment,
    key_hierarchy::MasterKey,
    hash::Hash,
};

pub struct IssuerDatabase {
    pool: PgPool,
}

impl IssuerDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_account(&self, account: &Account) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO accounts (id, email, display_name, status, created_at, updated_at, passkey_credential_id, backup_phrase_hash, double_verification_index, of_age_flag)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            account.id,
            account.email,
            account.display_name,
            account.status.to_string(),
            account.created_at,
            account.updated_at,
            account.passkey_credential_id,
            account.backup_phrase_hash.map(|h| h.0.to_vec()),
            account.double_verification_index.map(|h| h.0.to_vec()),
            account.of_age_flag,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn get_account(&self, account_id: Uuid) -> Result<Option<Account>> {
        let row = sqlx::query!(
            r#"
            SELECT id, email, display_name, status, created_at, updated_at, last_login_at, passkey_credential_id, backup_phrase_hash, double_verification_index, of_age_flag
            FROM accounts WHERE id = $1
            "#,
            account_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(row.map(|r| Account {
            id: r.id,
            email: r.email,
            display_name: r.display_name,
            status: r.status.parse().unwrap(),
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_login_at: r.last_login_at,
            passkey_credential_id: r.passkey_credential_id,
            backup_phrase_hash: r.backup_phrase_hash.map(|b| Hash::from_slice(&b).unwrap()),
            double_verification_index: r.double_verification_index.map(|b| Hash::from_slice(&b).unwrap()),
            of_age_flag: r.of_age_flag,
        }))
    }

    pub async fn update_account(&self, account: &Account) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE accounts SET email = $2, display_name = $3, status = $4, updated_at = $5, last_login_at = $6, passkey_credential_id = $7, backup_phrase_hash = $8, double_verification_index = $9, of_age_flag = $10
            WHERE id = $1
            "#,
            account.id,
            account.email,
            account.display_name,
            account.status.to_string(),
            account.updated_at,
            account.last_login_at,
            account.passkey_credential_id,
            account.backup_phrase_hash.map(|h| h.0.to_vec()),
            account.double_verification_index.map(|h| h.0.to_vec()),
            account.of_age_flag,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn store_person_credential(&self, account_id: Uuid, credential: &BbsCredential) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO person_credentials (id, account_id, schema_id, issuer_pk, subject, attributes, signature, epoch, issued_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            Uuid::new_v4(),
            account_id,
            credential.schema_id,
            credential.issuer.key,
            credential.subject,
            credential.attributes,
            credential.signature.signature,
            credential.epoch as i64,
            credential.issued_at as i64,
            credential.expires_at as i64,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn store_membership_credential(&self, account_id: Uuid, credential: &BbsCredential, tenant_id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO membership_credentials (id, account_id, tenant_id, schema_id, issuer_pk, subject, attributes, signature, epoch, issued_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            Uuid::new_v4(),
            account_id,
            tenant_id,
            credential.schema_id,
            credential.issuer.key,
            credential.subject,
            credential.attributes,
            credential.signature.signature,
            credential.epoch as i64,
            credential.issued_at as i64,
            credential.expires_at as i64,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn store_governance_key(&self, governance_key: &snex_core::tenant::GovernanceKey) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO governance_keys (id, tenant_id, version, public_key, threshold, total_shares, created_at, rotated_at, active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            Uuid::new_v4(),
            governance_key.tenant_id,
            governance_key.version as i32,
            governance_key.public_key,
            governance_key.threshold as i32,
            governance_key.total_shares as i32,
            governance_key.created_at,
            governance_key.rotated_at,
            governance_key.active,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn get_latest_governance_key(&self, tenant_id: Uuid) -> Result<Option<snex_core::tenant::GovernanceKey>> {
        let row = sqlx::query!(
            r#"
            SELECT id, tenant_id, version, public_key, threshold, total_shares, created_at, rotated_at, active
            FROM governance_keys WHERE tenant_id = $1 AND active = true ORDER BY version DESC LIMIT 1
            "#,
            tenant_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(row.map(|r| snex_core::tenant::GovernanceKey {
            tenant_id: r.tenant_id,
            version: r.version as u32,
            public_key: r.public_key,
            threshold: r.threshold as u32,
            total_shares: r.total_shares as u32,
            created_at: r.created_at,
            rotated_at: r.rotated_at,
            active: r.active,
        }))
    }

    pub async fn store_verification_record(&self, record: &snex_core::identity::VerificationRecord) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO verification_records (id, account_id, provider_id, verification_process_ref, status, attestation, blinded_commitment, of_age_attribute, requested_at, completed_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            record.id,
            record.account_id,
            record.provider_id,
            record.verification_process_ref,
            record.status.to_string(),
            record.attestation,
            record.blinded_commitment.as_ref().map(|c| c.to_bytes().to_vec()),
            record.of_age_attribute,
            record.requested_at,
            record.completed_at,
            record.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn store_issuance_event(&self, account_id: Uuid, epoch: Epoch, credential_type: &str, commitment: &Commitment) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO issuance_events (id, account_id, epoch, credential_type, commitment, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::new_v4(),
            account_id,
            epoch.0 as i64,
            credential_type,
            commitment.to_bytes().to_vec(),
            Utc::now(),
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn get_account_credentials(&self, account_id: Uuid, epoch: Epoch) -> Result<Vec<BbsCredential>> {
        let rows = sqlx::query!(
            r#"
            SELECT schema_id, issuer_pk, subject, attributes, signature, epoch, issued_at, expires_at
            FROM person_credentials WHERE account_id = $1 AND epoch = $2
            "#,
            account_id,
            epoch.0 as i64,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| BbsCredential {
            schema_id: r.schema_id,
            issuer: snex_crypto::bbs::BbsPublicKey { key: r.issuer_pk },
            subject: r.subject,
            attributes: r.attributes,
            signature: snex_crypto::bbs::BbsSignature { signature: r.signature },
            epoch: r.epoch as u64,
            issued_at: r.issued_at as u64,
            expires_at: r.expires_at as u64,
        }).collect())
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
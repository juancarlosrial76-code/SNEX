use snex_core::{
    identity::{Account, VerificationRecord, AccountSecrets, CredentialPair},
    epoch::Epoch,
    tenant::{Tenant, GovernanceKey},
    config::AppConfig,
    error::{CoreError, Result},
};
use snex_crypto::{
    bbs::{BbsSecretKey, BbsPublicKey, BbsCredential, CanonicalCredentialProfile, blind_issue, verify_blind_issuance},
    commitments::{CommitmentKey, Commitment, PedersenCommitment, BlindedCommitment},
    nullifiers::{OperationSecret, PseudonymSecret},
    key_hierarchy::{MasterKey, KeyHierarchy},
    hashing::Hash,
};
use crate::state::{IssuerState, SharedIssuerState, CredentialType, PendingIssuance};
use crate::database::IssuerDatabase;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

pub struct IssuerService {
    pub state: SharedIssuerState,
    pub database: IssuerDatabase,
    pub config: AppConfig,
}

impl IssuerService {
    pub fn new(config: AppConfig, database: IssuerDatabase) -> Result<Self> {
        let master_key = MasterKey::generate();
        let issuer_sk = BbsSecretKey::generate();
        let state = Arc::new(RwLock::new(IssuerState::new(config.clone(), master_key, issuer_sk)));
        
        Ok(Self { state, database, config })
    }

    pub async fn initialize(&self) -> Result<()> {
        self.start_epoch_rotation_task().await;
        Ok(())
    }

    async fn start_epoch_rotation_task(&self) {
        let state = self.state.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                
                let mut state = state.write().await;
                let now = Utc::now();
                let current_epoch = Epoch::current();
                
                if current_epoch > state.epoch_state.epoch {
                    info!("Rotating epoch from {} to {}", state.epoch_state.epoch, current_epoch);
                    if let Err(e) = state.rotate_epoch() {
                        error!("Failed to rotate epoch: {}", e);
                    }
                    
                    state.issuance_cohort.epoch = current_epoch;
                    state.epoch_state = snex_core::epoch::EpochState::new(current_epoch, config.issuer.minimum_cohort_size);
                }
            }
        });
    }

    pub async fn create_account(&self, email: String, display_name: String) -> Result<Account> {
        let mut state = self.state.write().await;
        let account = state.create_account(email, display_name)?;
        self.database.create_account(&account).await?;
        Ok(account)
    }

    pub async fn start_verification(&self, account_id: Uuid, provider_id: String, verification_ref: String) -> Result<VerificationRecord> {
        let mut state = self.state.write().await;
        let record = state.register_verification(account_id, provider_id, verification_ref)?;
        self.database.store_verification_record(&record).await?;
        Ok(record)
    }

    pub async fn complete_verification(
        &self,
        record_id: Uuid,
        attestation: Vec<u8>,
        blinded_commitment: Commitment,
        of_age: bool,
    ) -> Result<VerificationRecord> {
        let mut state = self.state.write().await;
        let record = state.complete_verification(record_id, attestation, blinded_commitment, of_age)?;
        self.database.store_verification_record(&record).await?;
        Ok(record)
    }

    pub async fn request_person_credential(
        &self,
        account_id: Uuid,
        blinded_commitment: Commitment,
        attributes: Vec<Vec<u8>>,
    ) -> Result<BbsCredential> {
        let mut state = self.state.write().await;
        let credential = state.issue_person_credential(account_id, &blinded_commitment, attributes)?;
        
        self.database.store_person_credential(account_id, &credential).await?;
        self.database.store_issuance_event(account_id, state.epoch_state.epoch, "person", &blinded_commitment).await?;
        
        Ok(credential)
    }

    pub async fn request_membership_credential(
        &self,
        account_id: Uuid,
        tenant_id: Uuid,
        blinded_commitment: Commitment,
        attributes: Vec<Vec<u8>>,
        reporting_authorised: bool,
        voting_authorised: bool,
    ) -> Result<BbsCredential> {
        let mut state = self.state.write().await;
        let credential = state.issue_membership_credential(
            account_id, tenant_id, &blinded_commitment, attributes, 
            reporting_authorised, voting_authorised
        )?;
        
        self.database.store_membership_credential(account_id, &credential, tenant_id).await?;
        self.database.store_issuance_event(account_id, state.epoch_state.epoch, "membership", &blinded_commitment).await?;
        
        Ok(credential)
    }

    pub async fn advance_issue_next_epoch(&self, account_id: Uuid) -> Result<OperationSecret> {
        let mut state = self.state.write().await;
        let op_secret = state.advance_issue_next_epoch(account_id)?;
        Ok(op_secret)
    }

    pub async fn get_credential_pair(&self, account_id: Uuid, tenant_id: Uuid, epoch: Epoch) -> Result<CredentialPair> {
        let state = self.state.read().await;
        
        let person_creds = state.get_person_credentials(account_id);
        let membership_creds = state.get_membership_credentials(account_id);
        
        let person_cred = person_creds.iter()
            .find(|c| c.epoch == epoch.0)
            .ok_or(CoreError::NotFound("Person credential not found".into()))?;
        
        let membership_cred = membership_creds.iter()
            .find(|c| c.epoch == epoch.0)
            .ok_or(CoreError::NotFound("Membership credential not found".into()))?;
        
        let secrets = state.get_account_secrets(account_id)
            .ok_or(CoreError::NotFound("Account secrets not found".into()))?;
        
        let pseudo_secret = &secrets.pseudonym_secret;
        let commitment_key = CommitmentKey::generate();
        let commitment = BlindedCommitment::new(
            snex_crypto::commitments::random_scalar(),
            snex_crypto::commitments::random_blinding(),
            &commitment_key,
        ).commitment;
        
        Ok(CredentialPair {
            person: snex_core::identity::PersonCredential {
                credential: (*person_cred).clone(),
                issued_at: Utc::now(),
                expires_at: Utc::now() + Duration::days(3 * 180),
            },
            membership: snex_core::identity::MembershipCredential {
                credential: (*membership_cred).clone(),
                tenant_id,
                governance_key_version: 1,
                reporting_authorised: true,
                voting_authorised: true,
                issued_at: Utc::now(),
                expires_at: Utc::now() + Duration::days(3 * 180),
            },
            commitment,
            commitment_key,
        })
    }

    pub async fn close_cohort(&self) -> Result<()> {
        let mut state = self.state.write().await;
        state.close_cohort();
        Ok(())
    }

    pub async fn activate_grace(&self) -> Result<()> {
        let mut state = self.state.write().await;
        state.activate_grace();
        Ok(())
    }

    pub async fn get_epoch_state(&self) -> snex_core::epoch::EpochState {
        let state = self.state.read().await;
        state.epoch_state.clone()
    }

    pub async fn get_issuance_cohort(&self) -> crate::state::IssuanceCohort {
        let state = self.state.read().await;
        state.issuance_cohort.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_core::config::AppConfig;
    use sqlx::PgPool;

    #[tokio::test]
    async fn test_issuer_service() {
        let config = AppConfig::default();
        let pool = PgPool::connect("postgresql://localhost/snex_test").await.unwrap();
        let database = IssuerDatabase::new(pool);
        let service = IssuerService::new(config, database).unwrap();
        
        let account = service.create_account("test@example.com".into(), "Test User".into()).await.unwrap();
        assert!(!account.id.is_nil());
    }
}
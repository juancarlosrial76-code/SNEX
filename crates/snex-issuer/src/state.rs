use snex_core::{
    identity::{Account, VerificationRecord, IdentityProvider, AccountSecrets, CredentialPair, PersonCredential, MembershipCredential},
    epoch::{Epoch, EpochState, CredentialLifetime},
    tenant::{Tenant, TenantMember, GovernanceKey, TenantRole},
    config::AppConfig,
    error::{CoreError, Result},
};
use snex_crypto::{
    bbs::{BbsSecretKey, BbsPublicKey, BbsCredential, CanonicalCredentialProfile, blind_issue},
    commitments::{CommitmentKey, Commitment, PedersenCommitment},
    nullifiers::{OperationSecret, PseudonymSecret},
    key_hierarchy::{MasterKey, KeyHierarchy},
    hash::Hash,
};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerState {
    pub accounts: HashMap<Uuid, Account>,
    pub account_secrets: HashMap<Uuid, AccountSecrets>,
    pub verification_records: HashMap<Uuid, VerificationRecord>,
    pub identity_providers: HashMap<String, IdentityProvider>,
    pub person_credentials: HashMap<Uuid, Vec<BbsCredential>>,
    pub membership_credentials: HashMap<Uuid, Vec<BbsCredential>>,
    pub governance_keys: HashMap<Uuid, Vec<GovernanceKey>>,
    pub epoch_state: EpochState,
    pub issuance_cohort: IssuanceCohort,
    pub master_key: MasterKey,
    pub key_hierarchy: KeyHierarchy,
    pub issuer_sk: BbsSecretKey,
    pub config: AppConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuanceCohort {
    pub epoch: Epoch,
    pub pending_issuances: Vec<PendingIssuance>,
    pub closed: bool,
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingIssuance {
    pub account_id: Uuid,
    pub credential_type: CredentialType,
    pub commitment: Commitment,
    pub attributes: Vec<Vec<u8>>,
    pub requested_at: DateTime<Utc>,
    pub tenant_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    Person,
    Membership,
}

impl IssuerState {
    pub fn new(config: AppConfig, master_key: MasterKey, issuer_sk: BbsSecretKey) -> Self {
        let epoch = Epoch::current();
        let min_cohort = config.issuer.minimum_cohort_size;
        
        let mut hierarchy = KeyHierarchy::new(master_key.clone());
        
        Self {
            accounts: HashMap::new(),
            account_secrets: HashMap::new(),
            verification_records: HashMap::new(),
            identity_providers: HashMap::new(),
            person_credentials: HashMap::new(),
            membership_credentials: HashMap::new(),
            governance_keys: HashMap::new(),
            epoch_state: EpochState::new(epoch, min_cohort),
            issuance_cohort: IssuanceCohort {
                epoch,
                pending_issuances: Vec::new(),
                closed: false,
                closed_at: None,
            },
            master_key,
            key_hierarchy: hierarchy,
            issuer_sk,
            config,
        }
    }

    pub fn create_account(&mut self, email: String, display_name: String) -> Result<Account> {
        let account = Account::new(email, display_name);
        self.accounts.insert(account.id, account.clone());
        
        let secrets = AccountSecrets::generate();
        self.account_secrets.insert(account.id, secrets);
        
        Ok(account)
    }

    pub fn register_verification(
        &mut self,
        account_id: Uuid,
        provider_id: String,
        verification_ref: String,
    ) -> Result<VerificationRecord> {
        let account = self.accounts.get_mut(&account_id)
            .ok_or(CoreError::NotFound("Account not found".into()))?;
        
        let record = VerificationRecord {
            id: Uuid::new_v4(),
            account_id,
            provider_id,
            verification_process_ref: verification_ref,
            status: snex_core::identity::VerificationStatus::Pending,
            attestation: None,
            blinded_commitment: None,
            of_age_attribute: false,
            requested_at: Utc::now(),
            completed_at: None,
            expires_at: None,
        };
        
        self.verification_records.insert(record.id, record.clone());
        Ok(record)
    }

    pub fn complete_verification(
        &mut self,
        record_id: Uuid,
        attestation: Vec<u8>,
        blinded_commitment: Commitment,
        of_age: bool,
    ) -> Result<VerificationRecord> {
        let record = self.verification_records.get_mut(&record_id)
            .ok_or(CoreError::NotFound("Verification record not found".into()))?;
        
        record.status = snex_core::identity::VerificationStatus::Verified;
        record.attestation = Some(attestation);
        record.blinded_commitment = Some(blinded_commitment);
        record.of_age_attribute = of_age;
        record.completed_at = Some(Utc::now());
        
        let account = self.accounts.get_mut(&record.account_id)
            .ok_or(CoreError::NotFound("Account not found".into()))?;
        account.of_age_flag = of_age;
        account.mark_verified();
        
        Ok(record.clone())
    }

    pub fn issue_person_credential(
        &mut self,
        account_id: Uuid,
        blinded_commitment: &Commitment,
        attributes: Vec<Vec<u8>>,
    ) -> Result<BbsCredential> {
        let account = self.accounts.get(&account_id)
            .ok_or(CoreError::NotFound("Account not found".into()))?;
        
        let epoch = self.epoch_state.epoch;
        let (credential, _signature) = blind_issue(&self.issuer_sk, blinded_commitment, &attributes, epoch.0)?;
        
        self.person_credentials.entry(account_id).or_default().push(credential.clone());
        
        self.epoch_state.issuance_cohort_size += 1;
        self.issuance_cohort.pending_issuances.push(PendingIssuance {
            account_id,
            credential_type: CredentialType::Person,
            commitment: *blinded_commitment,
            attributes,
            requested_at: Utc::now(),
            tenant_id: None,
        });
        
        Ok(credential)
    }

    pub fn issue_membership_credential(
        &mut self,
        account_id: Uuid,
        tenant_id: Uuid,
        blinded_commitment: &Commitment,
        attributes: Vec<Vec<u8>>,
        reporting_authorised: bool,
        voting_authorised: bool,
    ) -> Result<BbsCredential> {
        let governance_key = self.get_latest_governance_key(tenant_id)
            .ok_or(CoreError::NotFound("Governance key not found".into()))?;
        
        let epoch = self.epoch_state.epoch;
        let (credential, _signature) = blind_issue(&self.issuer_sk, blinded_commitment, &attributes, epoch.0)?;
        
        let membership_cred = BbsCredential {
            schema_id: "SNEX_MembershipCredential_v1".into(),
            issuer: governance_key.public_key.clone().into(),
            subject: blinded_commitment.to_bytes().to_vec(),
            attributes,
            signature: credential.signature,
            epoch: epoch.0,
            issued_at: Utc::now().timestamp() as u64,
            expires_at: (Utc::now() + Duration::days(3 * 180)).timestamp() as u64,
        };
        
        self.membership_credentials.entry(account_id).or_default().push(membership_cred.clone());
        
        self.epoch_state.issuance_cohort_size += 1;
        self.issuance_cohort.pending_issuances.push(PendingIssuance {
            account_id,
            credential_type: CredentialType::Membership,
            commitment: *blinded_commitment,
            attributes: vec![],
            requested_at: Utc::now(),
            tenant_id: Some(tenant_id),
        });
        
        Ok(membership_cred)
    }

    pub fn advance_issue_next_epoch(&mut self, account_id: Uuid) -> Result<OperationSecret> {
        let secrets = self.account_secrets.get_mut(&account_id)
            .ok_or(CoreError::NotFound("Account secrets not found".into()))?;
        
        let next_epoch = secrets.current_epoch + 1;
        let op_secret = OperationSecret::generate();
        secrets.add_operation_secret(op_secret.clone(), next_epoch);
        
        Ok(op_secret)
    }

    pub fn rotate_epoch(&mut self) -> Result<()> {
        if self.issuance_cohort.closed {
            self.epoch_state.epoch = self.epoch_state.epoch.next();
            self.epoch_state = EpochState::new(self.epoch_state.epoch, self.config.issuer.minimum_cohort_size);
            self.issuance_cohort = IssuanceCohort {
                epoch: self.epoch_state.epoch,
                pending_issuances: Vec::new(),
                closed: false,
                closed_at: None,
            };
            
            for secrets in self.account_secrets.values_mut() {
                secrets.rotate_epoch();
            }
        }
        Ok(())
    }

    pub fn close_cohort(&mut self) {
        self.issuance_cohort.closed = true;
        self.issuance_cohort.closed_at = Some(Utc::now());
        self.epoch_state.close_cohort();
    }

    pub fn activate_grace(&mut self) {
        self.epoch_state.activate_grace(self.config.issuer.grace_period_days);
    }

    pub fn add_governance_key(&mut self, tenant_id: Uuid, governance_key: GovernanceKey) {
        self.governance_keys.entry(tenant_id).or_default().push(governance_key);
    }

    pub fn get_latest_governance_key(&self, tenant_id: Uuid) -> Option<&GovernanceKey> {
        self.governance_keys.get(&tenant_id)?.last()
    }

    pub fn get_account_secrets(&self, account_id: Uuid) -> Option<&AccountSecrets> {
        self.account_secrets.get(&account_id)
    }

    pub fn get_person_credentials(&self, account_id: Uuid) -> Vec<&BbsCredential> {
        self.person_credentials.get(&account_id).map(|v| v.iter().collect()).unwrap_or_default()
    }

    pub fn get_membership_credentials(&self, account_id: Uuid) -> Vec<&BbsCredential> {
        self.membership_credentials.get(&account_id).map(|v| v.iter().collect()).unwrap_or_default()
    }
}

pub type SharedIssuerState = std::sync::Arc<RwLock<IssuerState>>;

#[cfg(test)]
mod tests {
    use super::*;
    use snex_core::config::AppConfig;
    use snex_crypto::key_hierarchy::MasterKey;
    use snex_crypto::bbs::BbsSecretKey;

    #[test]
    fn test_issuer_state() {
        let config = AppConfig::default();
        let master_key = MasterKey::generate();
        let issuer_sk = BbsSecretKey::generate();
        
        let state = IssuerState::new(config, master_key, issuer_sk);
        assert_eq!(state.epoch_state.epoch.0, Epoch::current().0);
    }
}
use snex_crypto::{
    bbs::{BbsPublicKey, BbsCredential, BbsSecretKey, CanonicalCredentialProfile},
    nullifiers::{OperationSecret, PseudonymSecret, Pseudonym, MailboxBaseSecret, CaseHandle, RecoveryCode},
    commitments::{CommitmentKey, Commitment, PedersenCommitment},
    hash::Hash,
};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use strum::{EnumString, Display, AsRefStr};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum AccountStatus {
    Active,
    Suspended,
    Terminated,
    PendingVerification,
    LostDevice,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub status: AccountStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub passkey_credential_id: Option<Vec<u8>>,
    pub backup_phrase_hash: Option<Hash>,
    pub double_verification_index: Option<Hash>,
    pub of_age_flag: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub id: Uuid,
    pub account_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub aaguid: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum VerificationStatus {
    Pending,
    Verified,
    Failed,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub id: Uuid,
    pub account_id: Uuid,
    pub provider_id: String,
    pub verification_process_ref: String,
    pub status: VerificationStatus,
    pub attestation: Option<Vec<u8>>,
    pub blinded_commitment: Option<Commitment>,
    pub of_age_attribute: bool,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub supported_attributes: Vec<String>,
    pub cost_per_verification: f64,
    pub retention_period_days: u32,
    pub double_verification_capable: bool,
    pub assisted_route_available: bool,
    pub liability_certified: bool,
    pub active: bool,
}

impl Account {
    pub fn new(email: String, display_name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            email,
            display_name,
            status: AccountStatus::PendingVerification,
            created_at: now,
            updated_at: now,
            last_login_at: None,
            passkey_credential_id: None,
            backup_phrase_hash: None,
            double_verification_index: None,
            of_age_flag: false,
        }
    }

    pub fn set_passkey(&mut self, credential_id: Vec<u8>) {
        self.passkey_credential_id = Some(credential_id);
        self.updated_at = Utc::now();
    }

    pub fn set_backup_phrase(&mut self, phrase_hash: Hash) {
        self.backup_phrase_hash = Some(phrase_hash);
        self.updated_at = Utc::now();
    }

    pub fn set_double_verification_index(&mut self, index: Hash) {
        self.double_verification_index = Some(index);
        self.updated_at = Utc::now();
    }

    pub fn mark_verified(&mut self) {
        self.status = AccountStatus::Active;
        self.updated_at = Utc::now();
    }

    pub fn report_device_loss(&mut self) {
        self.status = AccountStatus::LostDevice;
        self.updated_at = Utc::now();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize)]
pub struct AccountSecrets {
    pub pseudonym_secret: PseudonymSecret,
    pub operation_secrets: Vec<OperationSecret>,
    pub mailbox_base_secret: MailboxBaseSecret,
    pub recovery_code: RecoveryCode,
    pub current_epoch: u64,
    pub next_epoch_secret: Option<OperationSecret>,
}

impl AccountSecrets {
    pub fn generate() -> Self {
        let now = Utc::now().timestamp() as u64;
        let epoch = now / (180 * 24 * 3600);
        let pseudo_secret = PseudonymSecret::generate();
        let op_secret = OperationSecret::generate();
        let mailbox_base = pseudo_secret.derive_mailbox_base_secret();
        let recovery = RecoveryCode::generate();
        Self {
            pseudonym_secret: pseudo_secret,
            operation_secrets: vec![op_secret],
            mailbox_base_secret: mailbox_base,
            recovery_code: recovery,
            current_epoch: epoch,
            next_epoch_secret: None,
        }
    }

    pub fn get_operation_secret(&self, epoch: u64) -> Option<&OperationSecret> {
        self.operation_secrets.iter().find(|s| {
            // In real implementation, we'd track epoch per secret
            true
        })
    }

    pub fn add_operation_secret(&mut self, secret: OperationSecret, epoch: u64) {
        if epoch > self.current_epoch {
            self.next_epoch_secret = Some(secret);
        } else {
            self.operation_secrets.push(secret);
        }
    }

    pub fn rotate_epoch(&mut self) {
        if let Some(next) = self.next_epoch_secret.take() {
            self.operation_secrets.push(next);
            self.current_epoch += 1;
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipCredential {
    pub credential: BbsCredential,
    pub tenant_id: Uuid,
    pub governance_key_version: u32,
    pub reporting_authorised: bool,
    pub voting_authorised: bool,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl MembershipCredential {
    pub fn is_valid_for_epoch(&self, epoch: u64) -> bool {
        self.credential.is_valid_for_epoch(epoch)
    }

    pub fn authorises_reporting(&self) -> bool {
        self.reporting_authorised
    }

    pub fn authorises_voting(&self) -> bool {
        self.voting_authorised
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersonCredential {
    pub credential: BbsCredential,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialPair {
    pub person: PersonCredential,
    pub membership: MembershipCredential,
    pub commitment: Commitment,
    pub commitment_key: CommitmentKey,
}

impl CredentialPair {
    pub fn verify(&self, person_pk: &BbsPublicKey, membership_pk: &BbsPublicKey) -> bool {
        self.person.credential.verify(person_pk).unwrap_or(false)
            && self.membership.credential.verify(membership_pk).unwrap_or(false)
            && self.person.credential.subject == self.membership.credential.subject
    }

    pub fn epoch(&self) -> u64 {
        self.person.credential.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_crypto::commitments::CommitmentKey;

    #[test]
    fn test_account_creation() {
        let account = Account::new("test@example.com".into(), "Test User".into());
        assert_eq!(account.status, AccountStatus::PendingVerification);
        assert!(!account.of_age_flag);
    }

    #[test]
    fn test_account_secrets_generation() {
        let secrets = AccountSecrets::generate();
        assert_eq!(secrets.operation_secrets.len(), 1);
        assert!(secrets.next_epoch_secret.is_none());
    }
}
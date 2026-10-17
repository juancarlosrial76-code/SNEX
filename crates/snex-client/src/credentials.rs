use snex_core::{
    identity::{Account, AccountSecrets, CredentialPair, PersonCredential, MembershipCredential, VerificationRecord},
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    bbs::{BbsCredential, BbsPublicKey, CanonicalCredentialProfile, blind_issue},
    commitments::{CommitmentKey, Commitment, PedersenCommitment, BlindedCommitment},
    nullifiers::{OperationSecret, PseudonymSecret, Pseudonym, Nullifier, CaseHandle, MailboxBaseSecret, RecoveryCode},
    hashing::Hash,
};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use zeroize::{Zeroize, Zeroizing};

pub struct CredentialManager {
    account_secrets: AccountSecrets,
}

impl CredentialManager {
    pub fn new(account_secrets: AccountSecrets) -> Self {
        Self { account_secrets }
    }

    pub fn generate_blinded_commitment(&self, value: snex_crypto::commitments::Scalar) -> BlindedCommitment {
        let blinding = snex_crypto::commitments::random_blinding();
        let key = CommitmentKey::generate();
        BlindedCommitment::new(value, blinding, &key)
    }

    pub fn derive_pseudonym(&self, tenant_id: &[u8], lifetime_index: u32) -> Pseudonym {
        self.account_secrets.pseudonym_secret.derive_pseudonym(tenant_id, lifetime_index)
    }

    pub fn get_operation_secret(&self, epoch: Epoch) -> Option<&OperationSecret> {
        self.account_secrets.get_operation_secret(epoch.0)
    }

    pub fn derive_establishment_nullifier(&self, epoch: Epoch, tenant_id: &[u8], index: u32) -> Option<Nullifier> {
        self.get_operation_secret(epoch).map(|s| s.derive_establishment_nullifier(epoch.0, tenant_id, index))
    }

    pub fn derive_vote_nullifier(&self, ballot_id: &[u8]) -> Option<Nullifier> {
        let epoch = Epoch::current();
        self.get_operation_secret(epoch).map(|s| s.derive_vote_nullifier(ballot_id))
    }

    pub fn derive_report_nullifier(&self, report_window: u64, slot: u32) -> Option<Nullifier> {
        let epoch = Epoch::current();
        self.get_operation_secret(epoch).map(|s| s.derive_report_nullifier(report_window, slot))
    }

    pub fn derive_rate_limit_tag(&self, window: u64, tenant_id: &[u8]) -> Option<Nullifier> {
        let epoch = Epoch::current();
        self.get_operation_secret(epoch).map(|s| s.derive_rate_limit_tag(window, tenant_id))
    }

    pub fn derive_pair_tag(&self, epoch: Epoch, tenant_id: &[u8]) -> Option<Nullifier> {
        self.get_operation_secret(epoch).map(|s| s.derive_pair_tag(epoch.0, tenant_id))
    }

    pub fn derive_case_handle(&self) -> CaseHandle {
        CaseHandle::generate()
    }

    pub fn derive_mailbox_access(&self, case_handle: &CaseHandle) -> snex_crypto::nullifiers::MailboxAccess {
        self.account_secrets.mailbox_base_secret.derive_mailbox_access(case_handle)
    }

    pub fn get_recovery_code(&self) -> RecoveryCode {
        self.account_secrets.recovery_code
    }

    pub fn advance_issue_next_epoch(&mut self) -> OperationSecret {
        let next_epoch = self.account_secrets.current_epoch + 1;
        let op_secret = OperationSecret::generate();
        self.account_secrets.add_operation_secret(op_secret.clone(), next_epoch);
        op_secret
    }

    pub fn rotate_epoch(&mut self) {
        self.account_secrets.rotate_epoch();
    }

    pub fn verify_credential_pair(&self, pair: &CredentialPair, person_pk: &BbsPublicKey, membership_pk: &BbsPublicKey) -> bool {
        pair.verify(person_pk, membership_pk)
    }

    pub fn is_credential_valid_for_epoch(&self, credential: &BbsCredential, epoch: Epoch) -> bool {
        credential.is_valid_for_epoch(epoch.0)
    }
}

pub fn create_credential_pair(
    person_credential: BbsCredential,
    membership_credential: BbsCredential,
    commitment_key: CommitmentKey,
) -> CredentialPair {
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let commitment = BlindedCommitment::new(value, blinding, &commitment_key).commitment;
    
    CredentialPair {
        person: PersonCredential {
            credential: person_credential,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(3 * 180),
        },
        membership: MembershipCredential {
            credential: membership_credential,
            tenant_id: Uuid::nil(),
            governance_key_version: 1,
            reporting_authorised: true,
            voting_authorised: true,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(3 * 180),
        },
        commitment,
        commitment_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_crypto::nullifiers::{PseudonymSecret, OperationSecret};

    #[test]
    fn test_credential_manager() {
        let secrets = AccountSecrets::generate();
        let manager = CredentialManager::new(secrets);
        
        let pseudonym = manager.derive_pseudonym(b"tenant1", 0);
        assert!(!pseudonym.as_bytes().iter().all(|&b| b == 0));
    }
}